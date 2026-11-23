//! BLAKE2s (RFC 7693): the only hash function WireGuard uses.
//!
//! WireGuard needs three shapes of it (whitepaper §5.4):
//!
//! * `Hash(input)` — plain BLAKE2s with 32-byte output: [`Blake2s256`] /
//!   [`hash`].
//! * `Mac(key, input)` — *keyed* BLAKE2s with 16-byte output: [`Blake2sMac`]
//!   / [`mac`].
//! * `Hmac(key, input)` — plain BLAKE2s-256 wrapped in the HMAC
//!   construction: see [`crate::crypto::kdf`].
//!
//! The implementation is streaming (so concatenations like
//! `Hash(a ∥ b ∥ c)` never need a scratch buffer), allocation-free and
//! panic-free.

use crate::crypto::bytes;
use crate::crypto::ct;

/// BLAKE2s initialization vector (RFC 7693 §2.6; the SHA-256 IV).
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Message word schedule (RFC 7693 §2.7).
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The G mixing function (RFC 7693 §3.1) on the working vector.
#[cfg_attr(debug_assertions, inline)]
#[cfg_attr(not(debug_assertions), inline(always))]
#[allow(clippy::indexing_slicing)] // PANIC-FREEDOM: `a`..`d` are the
// literals 0..16 that `round` passes, into an array of sixteen.
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// Round `R` of the compression function: its row of the message schedule
/// is a constant of the function, so in an optimised build — where this is
/// inlined ten times over — every step knows which message word it takes,
/// and no index is loaded, masked and used at run time.
#[cfg_attr(debug_assertions, inline)]
#[cfg_attr(not(debug_assertions), inline(always))]
#[allow(clippy::indexing_slicing)] // PANIC-FREEDOM: the indices are
// literals < 16 into a row of sixteen, and entries of that row masked to
// 0..16 into the sixteen message words. (The mask changes nothing — every
// SIGMA entry is already < 16 — but it shows the compiler that, so no
// bounds check and no panic path is emitted.) `R` out of range does not
// compile.
fn round<const R: usize>(v: &mut [u32; 16], m: &[u32; 16]) {
    let s: &[usize; 16] = const { &SIGMA[R] };
    g(v, 0, 4, 8, 12, m[s[0] & 15], m[s[1] & 15]);
    g(v, 1, 5, 9, 13, m[s[2] & 15], m[s[3] & 15]);
    g(v, 2, 6, 10, 14, m[s[4] & 15], m[s[5] & 15]);
    g(v, 3, 7, 11, 15, m[s[6] & 15], m[s[7] & 15]);
    g(v, 0, 5, 10, 15, m[s[8] & 15], m[s[9] & 15]);
    g(v, 1, 6, 11, 12, m[s[10] & 15], m[s[11] & 15]);
    g(v, 2, 7, 8, 13, m[s[12] & 15], m[s[13] & 15]);
    g(v, 3, 4, 9, 14, m[s[14] & 15], m[s[15] & 15]);
}

/// The compression function F (RFC 7693 §3.2).
///
/// The ten rounds are ten instances of [`round`], each with its row of the
/// message schedule built in. In an optimised build they are all inlined
/// here and the working vector lives in registers as far as there are
/// any: a fifth off the time of a compression — which is what a rejected
/// handshake message costs — for about four kilobytes of code. In an
/// unoptimised build they stay ten small functions, and this one's frame
/// stays small.
///
/// The message words and the working vector may hold key material (a
/// keyed hash's key block, an HMAC pad block, a chaining value) and are
/// wiped before returning.
///
/// That reaches the two arrays. It does not reach the words of the
/// working vector that the compiler parks in this function's frame while
/// the rounds run — sixteen words and a message schedule are more than
/// the registers of most machines — and those slots have no name. So
/// this function is never inlined: it says in `low` where its frame ends
/// ([`ct::stack_mark`]), and whoever called it overwrites that frame when
/// it has returned ([`scrub_after_compress`]).
#[inline(never)]
fn compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool, low: &mut usize) {
    // Said first, and through a reference: a value carried to the end
    // would take a register from the rounds.
    *low = (*low).min(ct::stack_mark());
    let mut m = [0u32; 16];
    bytes::load_le32(m.iter_mut(), block);

    let mut v = [0u32; 16];
    for (vi, word) in v.iter_mut().zip(h.iter().chain(IV.iter())) {
        *vi = *word;
    }
    let [.., v12, v13, v14, _] = &mut v;
    *v12 ^= t as u32;
    *v13 ^= (t >> 32) as u32;
    if last {
        *v14 = !*v14;
    }

    round::<0>(&mut v, &m);
    round::<1>(&mut v, &m);
    round::<2>(&mut v, &m);
    round::<3>(&mut v, &m);
    round::<4>(&mut v, &m);
    round::<5>(&mut v, &m);
    round::<6>(&mut v, &m);
    round::<7>(&mut v, &m);
    round::<8>(&mut v, &m);
    round::<9>(&mut v, &m);

    let [lo @ .., _, _, _, _, _, _, _, _] = &v;
    let [_, _, _, _, _, _, _, _, hi @ ..] = &v;
    for ((word, a), b) in h.iter_mut().zip(lo).zip(hi) {
        *word ^= a ^ b;
    }
    ct::wipe_words(&mut m);
    ct::wipe_words(&mut v);
}

/// What [`ct::scrub_frame`] overwrites at once after [`compress`], in
/// 64-bit words: its frame — saved registers, the two arrays, the parked
/// words — is under this in an optimised build (a test below says so).
const COMPRESS_FRAME: usize = 56;

/// How far beneath [`compress`]'s own frame the overwriting reaches.
/// Nothing is there in an optimised build, where the rounds are part of
/// `compress`; in a build with debug assertions they are functions of
/// their own (see [`round`]), with frames beneath it.
#[cfg(not(debug_assertions))]
const BELOW_COMPRESS: usize = 0;
#[cfg(debug_assertions)]
const BELOW_COMPRESS: usize = 512;

/// Overwrite the frames of the [`compress`] calls a function has just
/// made (`low`: where the deepest of them ended; `usize::MAX`: there was
/// none). Always inlined — it has to be called from the frame that
/// called `compress`.
#[inline(always)]
fn scrub_after_compress(low: usize) {
    if low != usize::MAX {
        ct::scrub_frame::<COMPRESS_FRAME>(low.saturating_sub(BELOW_COMPRESS));
    }
}

/// Shared streaming core for both output lengths.
#[derive(Clone)]
struct Core {
    h: [u32; 8],
    /// Bytes fed to `compress` so far.
    t: u64,
    buf: [u8; 64],
    /// Valid prefix of `buf`, `0..=64`.
    buf_len: usize,
}

impl Core {
    /// The state for `out_len` bytes of output and a key of `key_len`
    /// bytes, before any input — and before the key itself — has been
    /// absorbed. Both lengths must be `<= 32`; the public wrappers
    /// guarantee it. Holds nothing secret.
    fn start(out_len: usize, key_len: usize) -> Self {
        let mut h = IV;
        let h0 = h.first_mut();
        if let Some(h0) = h0 {
            *h0 ^= 0x0101_0000 ^ ((key_len as u32) << 8) ^ (out_len as u32);
        }
        Self {
            h,
            t: 0,
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    /// Keyed mode: the key, zero-padded to a full block, becomes the first
    /// message block (RFC 7693 §2.9). Written straight into the state, so
    /// the key is never part of a value that is returned or moved.
    fn absorb_key(&mut self, key: &[u8]) {
        if !key.is_empty() {
            for (d, s) in self.buf.iter_mut().zip(key.iter()) {
                *d = *s;
            }
            self.buf_len = 64;
        }
    }

    /// [`Core::absorb_key`] for a key of any length: one longer than the
    /// 32 bytes the keyed hash takes is hashed down to 32 first, and those
    /// are the key. (Whoever made the state with [`Core::start`] said so:
    /// a key length of 32.)
    #[inline(always)]
    fn absorb_any_key(&mut self, key: &[u8]) {
        if key.len() > 32 {
            self.absorb_hashed(key);
        } else {
            self.absorb_key(key);
        }
    }

    /// The digest of a key that is too long is a key: it is computed into
    /// a place of its own, copied from there into the buffer, and wiped.
    #[cold]
    #[inline(never)]
    fn absorb_hashed(&mut self, key: &[u8]) {
        let mut digest = [0u8; 32];
        hash_into(&[key], &mut digest);
        self.absorb_key(&digest);
        ct::wipe_array(&mut digest);
    }

    /// A keyed state as a value, for the tests. (The library itself never
    /// has one that is returned or moved with a key in it: see
    /// [`Blake2sMac`].) `out_len` and `key.len()` must both be `<= 32`.
    #[cfg(test)]
    fn new(out_len: usize, key: &[u8]) -> Self {
        let mut core = Self::start(out_len, key.len());
        core.absorb_key(key);
        core
    }

    #[inline(always)]
    fn update(&mut self, mut data: &[u8]) {
        let mut low = usize::MAX;
        while !data.is_empty() {
            if self.buf_len == 64 {
                // Only compress a buffered block once we know more input
                // follows: the final block must go through `compress` with
                // the `last` flag instead.
                self.t = self.t.wrapping_add(64);
                compress(&mut self.h, &self.buf, self.t, false, &mut low);
                self.buf_len = 0;
            }
            let space = self.buf.get_mut(self.buf_len..).unwrap_or(&mut []);
            let take = space.len().min(data.len());
            for (d, s) in space.iter_mut().zip(data.iter()) {
                *d = *s;
            }
            self.buf_len = self.buf_len.saturating_add(take);
            data = data.get(take..).unwrap_or(&[]);
        }
        scrub_after_compress(low);
    }

    /// Finish: write the first `out.len()` bytes of the digest (at most
    /// 32) and wipe the state where it lies.
    #[inline(always)]
    fn finalize_into(&mut self, out: &mut [u8]) {
        self.t = self.t.wrapping_add(self.buf_len as u64);
        for b in self.buf.get_mut(self.buf_len..).unwrap_or(&mut []) {
            *b = 0;
        }
        let mut low = usize::MAX;
        compress(&mut self.h, &self.buf, self.t, true, &mut low);
        // Whole words — and, were `out` ever not a multiple of four
        // bytes long, the first bytes of one more.
        let mut rest = out;
        for word in self.h.iter() {
            let part = rest.len().min(4);
            let Some((chunk, tail)) = core::mem::take(&mut rest).split_at_mut_checked(part) else {
                break;
            };
            bytes::copy(chunk, &word.to_le_bytes());
            rest = tail;
        }
        self.wipe();
        scrub_after_compress(low);
    }

    /// Zero the state: it may have absorbed secret material (keys,
    /// chaining values).
    fn wipe(&mut self) {
        ct::wipe_words(&mut self.h);
        ct::wipe(&mut self.buf);
        self.buf_len = 0;
        self.t = 0;
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        // Whether or not `finalize` ran: a hasher abandoned mid-stream on
        // an error path leaves nothing behind either.
        self.wipe();
    }
}

/// Streaming BLAKE2s with 32-byte output — WireGuard's `Hash()`.
#[derive(Clone)]
pub struct Blake2s256 {
    core: Core,
}

impl Blake2s256 {
    /// Start a new unkeyed 32-byte-output hash.
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: Core::start(32, 0),
        }
    }

    /// Absorb `data`; returns `&mut self` so concatenated inputs chain
    /// naturally.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.core.update(data);
        self
    }

    /// Finish and return the 32-byte digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.core.finalize_into(&mut out);
        out
    }

    /// Finish, writing the digest to `out` and wiping the hasher in
    /// place. For digests that are themselves secret: the value is never
    /// returned, so no copy of it is left in a return slot. The hasher
    /// must not be used afterwards (it would hash from a zeroed state).
    pub fn finalize_into(&mut self, out: &mut [u8; 32]) {
        self.core.finalize_into(out);
    }
}

impl Default for Blake2s256 {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Blake2s256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print absorbed (possibly secret) state.
        f.write_str("Blake2s256 { .. }")
    }
}

/// Streaming *keyed* BLAKE2s with 16-byte output — WireGuard's
/// `Mac(key, input)`.
///
/// The key is borrowed when the hasher is made and goes into it with the
/// first input (or at the end, if there is none) — into the place where
/// the hasher is by then. Until that moment the hasher holds nothing of
/// the key, so it can be returned and moved like any value. (A
/// constructor that handed back a hasher with the key already inside
/// would leave a copy of the key wherever the compiler built that value
/// before moving it: such a copy belongs to nothing and is never wiped.)
/// From its first input on the hasher holds the key, and then a state
/// that is worth as much, until it is finished or dropped: both wipe it
/// where it lies.
#[derive(Clone)]
pub struct Blake2sMac<'k> {
    core: Core,
    /// The key, until it has gone into `core`.
    key: Option<&'k [u8]>,
}

impl<'k> Blake2sMac<'k> {
    /// Start a keyed MAC. WireGuard uses 32-byte keys (`mac1`) and 16-byte
    /// keys (`mac2`/cookies); any length up to 32 is accepted. Longer keys
    /// are hashed down to 32 bytes first (defensive totality — the protocol
    /// never does this).
    #[must_use]
    pub fn new(key: &'k [u8]) -> Self {
        Self {
            core: Core::start(16, key.len().min(32)),
            key: Some(key),
        }
    }

    /// The key goes in, if it has not yet: where the hasher is now.
    #[inline(always)]
    fn key_in(&mut self) {
        if let Some(key) = self.key.take() {
            self.core.absorb_any_key(key);
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.key_in();
        self.core.update(data);
        self
    }

    /// Finish and return the 16-byte tag.
    ///
    /// The tag comes back by value: for a tag that is a secret, use
    /// [`Blake2sMac::finalize_into`].
    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        let mut out = [0u8; 16];
        self.finalize_into(&mut out);
        out
    }

    /// Finish, writing the tag to `out` and wiping the hasher in place.
    /// The hasher must not be used afterwards (it would hash from a
    /// zeroed state, without a key).
    pub fn finalize_into(&mut self, out: &mut [u8; 16]) {
        self.key_in();
        self.core.finalize_into(out);
    }
}

impl core::fmt::Debug for Blake2sMac<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Blake2sMac { .. }")
    }
}

/// One-shot `Hash(parts[0] ∥ parts[1] ∥ …)` (whitepaper `Hash`).
///
/// The digest comes back by value: for a digest that is a secret, use
/// [`hash_into`] (see the notes on what a call leaves behind in
/// [`crate::crypto`]).
#[must_use]
pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hash_into(parts, &mut out);
    out
}

/// As [`hash`], writing the digest to `out` — for digests of secret input,
/// which are then never returned by value.
pub fn hash_into(parts: &[&[u8]], out: &mut [u8; 32]) {
    let mut core = Core::start(32, 0);
    for part in parts {
        core.update(part);
    }
    core.finalize_into(out);
}

/// One-shot `Mac(key, parts[0] ∥ parts[1] ∥ …)` (whitepaper `Mac`).
///
/// Keys longer than 32 bytes are hashed down first, as [`Blake2sMac::new`]
/// does (the protocol never has one).
///
/// The tag comes back by value: for a tag that is a secret, use
/// [`mac_into`].
#[must_use]
pub fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut out = [0u8; 16];
    mac_into(key, parts, &mut out);
    out
}

/// The eight state words of a [`mac`] once its key has gone in.
///
/// Keyed BLAKE2s begins by compressing the key, zero-padded to a block.
/// For a key that is used again and again that first compression always
/// leaves the same state; with it kept, [`mac_keyed`] costs one
/// compression less — two instead of three for the `mac1` of a handshake
/// initiation, which is what a receiver computes for every initiation it
/// is sent, forged ones included.
///
/// The state is worth exactly what the key is worth: whoever has it can
/// compute the MAC of any message. WireGuard's `mac1` keys are hashes of
/// public keys, so nothing is given away by keeping theirs.
pub fn mac_key_state(key: &[u8; 32], state: &mut [u32; 8]) {
    let mut core = Core::start(16, key.len());
    core.absorb_key(key);
    // What `update` does with the key block once it knows that a message
    // follows.
    core.t = 64;
    let mut low = usize::MAX;
    compress(&mut core.h, &core.buf, core.t, false, &mut low);
    for (d, s) in state.iter_mut().zip(core.h.iter()) {
        *d = *s;
    }
    scrub_after_compress(low);
    // `core`, with the key block in its buffer, is wiped as it is dropped.
}

/// `Mac(key, parts[0] ∥ parts[1] ∥ …)`, given the `state` that
/// [`mac_key_state`] computed for `key`: the same tag as
/// [`mac_into`]`(key, …)`, for one compression less.
///
/// (The key is still needed for an empty message: there the key block is
/// also the last block, which is compressed differently, so the state is
/// of no use.)
pub fn mac_keyed(key: &[u8; 32], state: &[u32; 8], parts: &[&[u8]], out: &mut [u8; 16]) {
    if parts.iter().all(|part| part.is_empty()) {
        return mac_into(key, parts, out);
    }
    // The state goes word by word into the place it is used from (and
    // wiped in): a copy of the whole of it, as a value, would be a second
    // one.
    let mut core = Core {
        h: [0u32; 8],
        t: 64,
        buf: [0u8; 64],
        buf_len: 0,
    };
    for (d, s) in core.h.iter_mut().zip(state.iter()) {
        *d = *s;
    }
    for part in parts {
        core.update(part);
    }
    core.finalize_into(out);
}

/// As [`mac`], writing the tag to `out` — for a tag that is itself a
/// secret (a cookie is one), which is then never returned by value.
pub fn mac_into(key: &[u8], parts: &[&[u8]], out: &mut [u8; 16]) {
    // The key goes straight into the state it is used from.
    let mut core = Core::start(16, key.len().min(32));
    core.absorb_any_key(key);
    for part in parts {
        core.update(part);
    }
    core.finalize_into(out);
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::string_slice,
        clippy::panic
    )]
    use super::*;
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// In an optimised build the frame that is overwritten at once after
    /// `compress` covers `compress`'s own: the slower scrub is not needed.
    /// (With debug assertions the rounds are functions beneath it, and
    /// the slow way is taken on purpose.)
    #[test]
    fn the_compression_frame_is_overwritten_in_one_go() {
        let before = ct::tests::DEEP_FRAMES.with(core::cell::Cell::get);
        let key = [0x42u8; 32];
        let long: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut digest = [0u8; 32];
        hash_into(&[&key, &long], &mut digest);
        let mut tag = [0u8; 16];
        mac_into(&key, &[&long], &mut tag);
        let mut state = [0u32; 8];
        mac_key_state(&key, &mut state);
        mac_keyed(&key, &state, &[&long[..116]], &mut tag);
        let mut streaming = Blake2s256::new();
        streaming.update(&long).update(&key);
        streaming.finalize_into(&mut digest);
        if cfg!(debug_assertions) {
            return;
        }
        assert_eq!(ct::tests::DEEP_FRAMES.with(core::cell::Cell::get), before);
    }

    #[test]
    fn rfc7693_abc() {
        // RFC 7693 Appendix B.
        let digest = hash(&[b"abc"]);
        assert_eq!(
            digest.as_slice(),
            unhex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        );
    }

    #[test]
    fn empty_input() {
        let digest = hash(&[]);
        assert_eq!(
            digest.as_slice(),
            unhex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        );
    }

    #[test]
    fn official_kat_keyed() {
        // First two entries of the official BLAKE2s keyed test vectors
        // (https://github.com/BLAKE2/BLAKE2, blake2s-kat): key = 00..1f,
        // message = empty and [0x00].
        let key: Vec<u8> = (0u8..32).collect();
        let m = Blake2s256_keyed(&key);
        let d0 = m.finalize();
        assert_eq!(
            d0.as_slice(),
            unhex("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49")
        );
        let mut m = Blake2s256_keyed(&key);
        m.core.update(&[0u8]);
        assert_eq!(
            m.finalize().as_slice(),
            unhex("40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1")
        );
    }

    /// Keyed BLAKE2s with 32-byte output, only needed to check the official
    /// KAT (the protocol itself only uses keyed-16).
    #[allow(non_snake_case)]
    fn Blake2s256_keyed(key: &[u8]) -> Blake2s256 {
        Blake2s256 {
            core: Core::new(32, key),
        }
    }

    #[test]
    fn incremental_equals_oneshot_at_every_split() {
        // 0..=200-byte messages, split at every possible position, plus
        // byte-at-a-time feeding: all must agree with the one-shot digest.
        let msg: Vec<u8> = (0..200u16).map(|i| (i as u8).wrapping_mul(31)).collect();
        for len in [0usize, 1, 31, 32, 63, 64, 65, 127, 128, 129, 200] {
            let oneshot = hash(&[&msg[..len]]);
            for split in 0..=len {
                let mut h = Blake2s256::new();
                h.update(&msg[..split]).update(&msg[split..len]);
                assert_eq!(h.finalize(), oneshot, "len={len} split={split}");
            }
            let mut h = Blake2s256::new();
            for b in &msg[..len] {
                h.update(core::slice::from_ref(b));
            }
            assert_eq!(h.finalize(), oneshot, "byte-at-a-time len={len}");
        }
    }

    #[test]
    fn mac_is_keyed_and_16_bytes() {
        let t1 = mac(&[1u8; 32], &[b"hello"]);
        let t2 = mac(&[2u8; 32], &[b"hello"]);
        let t3 = mac(&[1u8; 32], &[b"hellp"]);
        assert_ne!(t1, t2);
        assert_ne!(t1, t3);
        // 16-byte keyed output must NOT be a truncation of the 32-byte
        // keyed output (the parameter block differs).
        let mut k32 = Blake2s256_keyed(&[1u8; 32]);
        k32.update(b"hello");
        assert_ne!(&k32.finalize()[..16], t1.as_slice());
        // Multi-part == concatenated.
        assert_eq!(mac(&[1u8; 32], &[b"he", b"llo"]), t1);
    }

    /// A MAC from the kept state of its key is the MAC: every message
    /// length around the block boundaries, split into parts every way
    /// that matters, and the empty message (where the key block is the
    /// last block and the state cannot be used).
    #[test]
    fn a_prepared_key_gives_the_same_mac() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x5a);
        let mut state = [0u32; 8];
        mac_key_state(&key, &mut state);
        // The state is the hasher's after the key block, not something
        // trivially related to the key.
        assert_ne!(state, [0u32; 8]);
        let data: Vec<u8> = (0..300u32).map(|i| (i * 31 + 7) as u8).collect();
        for len in (0..=200).chain([255, 256, 257, 300]) {
            let msg = &data[..len];
            let expected = mac(&key, &[msg]);
            let mut got = [0xeeu8; 16];
            mac_keyed(&key, &state, &[msg], &mut got);
            assert_eq!(got, expected, "len={len}");
            // In parts, with empty ones among them.
            for cut in [0, 1, len / 2, len.saturating_sub(1), len] {
                let cut = cut.min(len);
                let mut got = [0xeeu8; 16];
                mac_keyed(&key, &state, &[&msg[..cut], &[], &msg[cut..]], &mut got);
                assert_eq!(got, expected, "len={len} cut={cut}");
            }
        }
        // No parts at all, and only empty ones.
        for parts in [&[][..], &[&[][..]][..], &[&[][..], &[][..]][..]] {
            let mut got = [0xeeu8; 16];
            mac_keyed(&key, &state, parts, &mut got);
            assert_eq!(got, mac(&key, &[]));
        }
        // Another key, another state; and a state is not interchangeable.
        let other = [0x11u8; 32];
        let mut other_state = [0u32; 8];
        mac_key_state(&other, &mut other_state);
        assert_ne!(other_state, state);
        let mut got = [0u8; 16];
        mac_keyed(&key, &other_state, &[b"x"], &mut got);
        assert_eq!(got, mac(&other, &[b"x"]), "the state is what is used");
        // The official keyed vector for a 32-byte key and a one-byte
        // message `00` (BLAKE2s-128 keyed is not in the reference KATs, so
        // this goes through the 32-byte-output hasher's key path instead:
        // same key block, same compression).
        let kat_key: Vec<u8> = (0..32u8).collect();
        let mut st = [0u32; 8];
        mac_key_state(kat_key.as_slice().try_into().unwrap(), &mut st);
        let mut direct = Core::new(16, &kat_key);
        direct.update(&[0]);
        let mut a = [0u8; 16];
        direct.finalize_into(&mut a);
        let mut b = [0u8; 16];
        mac_keyed(kat_key.as_slice().try_into().unwrap(), &st, &[&[0]], &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn the_streaming_mac_equals_the_one_shot() {
        let msg: Vec<u8> = (0..150u8).collect();
        for key_len in [0usize, 1, 16, 31, 32, 33, 64, 100] {
            let key: Vec<u8> = (0..key_len as u8)
                .map(|i| i.wrapping_mul(7) ^ 0x5a)
                .collect();
            for len in [0usize, 1, 63, 64, 65, 150] {
                let want = mac(&key, &[&msg[..len]]);
                let mut whole = Blake2sMac::new(&key);
                whole.update(&msg[..len]);
                assert_eq!(whole.finalize(), want, "key {key_len}, message {len}");
                if len == 0 {
                    // No input at all: the key block is also the last.
                    assert_eq!(Blake2sMac::new(&key).finalize(), want, "key {key_len}");
                }
                // In two pieces, with a copy taken before the key has
                // gone in and one after.
                for split in [0, len / 2, len] {
                    let fresh = Blake2sMac::new(&key);
                    let mut first = fresh.clone();
                    first.update(&msg[..split]);
                    let mut second = first.clone();
                    second.update(&msg[split..len]);
                    let mut tag = [0u8; 16];
                    second.finalize_into(&mut tag);
                    assert_eq!(tag, want, "key {key_len}, message {len}, split {split}");
                }
            }
        }
    }

    #[test]
    fn the_streaming_mac_has_nothing_of_the_key_until_its_first_input() {
        let key = [0xa7u8; 32];
        let mut m = Blake2sMac::new(&key);
        assert!(m.core.buf.iter().all(|b| *b == 0));
        assert_eq!(m.core.buf_len, 0);
        // Only the key's length is in the state: the parameter block.
        assert_eq!(m.core.h, Core::start(16, 32).h);
        m.update(&[]);
        assert_eq!(m.core.buf[..32], key);
        assert_eq!(m.core.buf_len, 64);
        // And finishing wipes it where it lies.
        let mut tag = [0u8; 16];
        m.finalize_into(&mut tag);
        assert!(m.core.buf.iter().all(|b| *b == 0));
        assert!(m.core.h.iter().all(|w| *w == 0));
        assert_eq!(tag, mac(&key, &[]));
    }

    #[test]
    fn long_keys_are_hashed_down_not_panicking() {
        let long_key = [0xabu8; 100];
        let t = mac(&long_key, &[b"x"]);
        let reduced = hash(&[&long_key]);
        assert_eq!(t, mac(&reduced, &[b"x"]));
    }

    #[test]
    fn counter_crosses_block_boundaries() {
        // Exactly 64 and 128 bytes exercise the "hold last block back"
        // logic; compare against splits to ensure t-accounting matches.
        let msg = [0x5au8; 128];
        for len in [63, 64, 65, 127, 128] {
            let oneshot = hash(&[&msg[..len]]);
            let mut h = Blake2s256::new();
            h.update(&msg[..len / 2]).update(&msg[len / 2..len]);
            assert_eq!(h.finalize(), oneshot);
        }
    }
}
