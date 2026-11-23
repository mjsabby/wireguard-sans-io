//! ChaCha20 stream cipher (RFC 8439) and HChaCha20
//! (draft-irtf-cfrg-xchacha), the cores of WireGuard's two AEADs.

use crate::crypto::bytes;
use crate::crypto::ct;

/// "expand 32-byte k", the ChaCha constant words.
const C0: u32 = 0x6170_7865;
const C1: u32 = 0x3320_646e;
const C2: u32 = 0x7962_2d32;
const C3: u32 = 0x6b20_6574;

/// Little-endian words of `bytes`, written over `words` (as many as both
/// hold).
#[inline(always)]
fn load_words<'a>(words: impl Iterator<Item = &'a mut u32>, bytes: &[u8]) {
    bytes::load_le32(words, bytes);
}

/// The ChaCha input state: constants, key, and four more words (counter
/// and nonce for ChaCha20, the 16-byte input for HChaCha20). The key is
/// loaded straight into the state, which is the one place it is wiped
/// from afterwards.
#[inline(always)]
fn init_state(state: &mut [u32; 16], key: &[u8; 32], tail: [u32; 4]) {
    let mut words = state.iter_mut();
    for (w, c) in words.by_ref().take(4).zip([C0, C1, C2, C3]) {
        *w = c;
    }
    load_words(words.by_ref().take(8), key);
    for (w, t) in words.zip(tail) {
        *w = t;
    }
}

/// The 20-round ChaCha permutation on a full state, *without* the final
/// feed-forward addition. Shared verbatim by the block function and
/// HChaCha20.
///
/// The rounds keep sixteen words in play. A machine with fewer registers
/// than that (x86-64 has fifteen to give) parks some of them in the stack
/// frame of whatever function this is compiled into, and no statement
/// here can name those slots to wipe them. So this — like everything
/// else in this file that touches the state — is always inlined, into
/// one of the few `…_worker` functions below, which never are: each of
/// those says where its frame ends, and the function that called it
/// overwrites that frame once it has returned ([`ct::scrub_frame`]).
#[inline(always)]
fn permute(state: &[u32; 16]) -> [u32; 16] {
    let [
        mut x0,
        mut x1,
        mut x2,
        mut x3,
        mut x4,
        mut x5,
        mut x6,
        mut x7,
        mut x8,
        mut x9,
        mut x10,
        mut x11,
        mut x12,
        mut x13,
        mut x14,
        mut x15,
    ] = *state;

    macro_rules! qr {
        ($a:ident, $b:ident, $c:ident, $d:ident) => {
            $a = $a.wrapping_add($b);
            $d = ($d ^ $a).rotate_left(16);
            $c = $c.wrapping_add($d);
            $b = ($b ^ $c).rotate_left(12);
            $a = $a.wrapping_add($b);
            $d = ($d ^ $a).rotate_left(8);
            $c = $c.wrapping_add($d);
            $b = ($b ^ $c).rotate_left(7);
        };
    }

    // 10 double rounds = 20 rounds.
    for _ in 0..10 {
        qr!(x0, x4, x8, x12);
        qr!(x1, x5, x9, x13);
        qr!(x2, x6, x10, x14);
        qr!(x3, x7, x11, x15);
        qr!(x0, x5, x10, x15);
        qr!(x1, x6, x11, x12);
        qr!(x2, x7, x8, x13);
        qr!(x3, x4, x9, x14);
    }

    [
        x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
    ]
}

/// The keystream block for a prepared input state: permutation plus
/// feed-forward (RFC 8439 §2.3).
#[inline(always)]
fn keystream_block(state: &[u32; 16], out: &mut [u8; 64]) {
    let mut worked = permute(state);
    // For the feed-forward, read the input state back through a reference
    // the optimiser knows nothing about. It knows what was stored in
    // `state` — the key — and would otherwise keep those words at hand
    // across the permutation instead of reading them again: in registers,
    // spilled to stack slots that no wipe of `state` reaches.
    let state = core::hint::black_box(state);
    bytes::store_le32(
        out,
        worked
            .iter()
            .zip(state.iter())
            .map(|(w, s)| w.wrapping_add(*s)),
    );
    // The permuted state is as good as the key to anyone who also knows
    // the keystream (it is the keystream minus the input state).
    ct::wipe_words(&mut worked);
}

/// The three nonce words.
#[inline(always)]
fn nonce_words(nonce: &[u8; 12]) -> [u32; 3] {
    let mut n = [0u32; 3];
    load_words(n.iter_mut(), nonce);
    n
}

/// One 64-byte keystream block (RFC 8439 §2.3), by value — for tests;
/// [`block_into`] writes it in place.
#[must_use]
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut out = [0u8; 64];
    block_into(key, counter, nonce, &mut out);
    out
}

/// As [`block`], writing the keystream to `out`: for a block that is used
/// as key material (the AEAD's one-time authenticator key), which is then
/// never returned by value.
pub fn block_into(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
    let mut low = usize::MAX;
    block_worker(key, counter, nonce, out, &mut low);
    ct::scrub_frame::<WORKER_FRAME>(low);
}

/// What [`ct::scrub_frame`] overwrites at once beneath a function that
/// has called one of the workers, in 64-bit words: their frames — an
/// input state, a block of keystream, the parked words, saved registers —
/// are under this in an optimised build (a test below says so).
const WORKER_FRAME: usize = 64;

/// [`block_into`]'s work, in a frame of its own (see [`permute`]).
/// Says, in `low`, where that frame ends.
#[inline(never)]
fn block_worker(
    key: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
    out: &mut [u8; 64],
    low: &mut usize,
) {
    // Where this frame ends — said first, and through a reference: a
    // value carried to the end would take a register from the rounds.
    *low = ct::stack_mark();
    let [n0, n1, n2] = nonce_words(nonce);
    let mut state = [0u32; 16];
    init_state(&mut state, key, [counter, n0, n1, n2]);
    keystream_block(&state, out);
    ct::wipe_words(&mut state);
}

/// XOR the ChaCha20 keystream into `data` in place, starting at block
/// `counter` (RFC 8439 §2.4). Encryption and decryption are the same
/// operation.
///
/// The 32-bit block counter wraps around silently. RFC 8439 limits a
/// message to 2³² blocks (256 GiB) precisely so that this never happens;
/// nothing here enforces the limit, and no datagram comes anywhere near
/// it.
pub fn xor_in_place(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    if !data.is_empty() {
        let mut low = usize::MAX;
        xor_worker(key, counter, nonce, data, &mut low);
        ct::scrub_frame::<WORKER_FRAME>(low);
    }
}

/// [`xor_in_place`]'s work, in a frame of its own (see [`permute`]).
/// Says, in `low`, where that frame ends.
#[inline(never)]
fn xor_worker(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8], low: &mut usize) {
    *low = ct::stack_mark();
    let [n0, n1, n2] = nonce_words(nonce);
    // One input state for the whole message — only the counter word
    // changes from block to block — wiped once at the end, together with
    // the last keystream block.
    let mut state = [0u32; 16];
    init_state(&mut state, key, [counter, n0, n1, n2]);
    let mut ks = [0u8; 64];
    xor_blocks(&mut state, &mut ks, data);
    ct::wipe(&mut ks);
    ct::wipe_words(&mut state);
}

/// XOR the keystream of `state` into `data`, block by block, counting
/// the state's block counter up; `ks` is where each block of keystream
/// is put, and holds the last one afterwards.
#[inline(always)]
fn xor_blocks(state: &mut [u32; 16], ks: &mut [u8; 64], data: &mut [u8]) {
    let mut rest = data;
    while !rest.is_empty() {
        let part = rest.len().min(64);
        let Some((chunk, tail)) = core::mem::take(&mut rest).split_at_mut_checked(part) else {
            break;
        };
        keystream_block(state, ks);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
        if let Some(ctr) = state.get_mut(12) {
            *ctr = ctr.wrapping_add(1);
        }
        rest = tail;
    }
}

/// A ChaCha20 keystream backend.
///
/// This is the seam where SIMD plugs in: the core provides only
/// [`Scalar`] (this module's safe, RFC-validated implementation); the
/// `wireguard-chacha-simd` crate provides AVX2/NEON backends that
/// produce the **identical** keystream. The default crypto provider,
/// [`crate::InTree`], takes the backend as a type parameter
/// (`InTree<C>`, [`Scalar`] by default), and [`crate::Device`] and
/// [`crate::Tunnel`] are generic over the provider — so the core stays
/// `#![forbid(unsafe_code)]` and zero-dependency while embedders that
/// want SIMD instantiate `Device<InTree<simd::Best>>`.
///
/// # Contract
///
/// `apply_keystream(k, n, c, buf)` MUST be byte-identical to
/// [`xor_in_place`]`(k, c, n, buf)` for every input. The simd crate's
/// test suite enforces this against [`Scalar`] across all tail-boundary
/// lengths.
pub trait ChaChaImpl: Send + Sync + 'static {
    /// XOR the RFC 8439 keystream into `buf` in place.
    fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]);

    /// Everything an AEAD seal needs of the keystream, in one call: the
    /// first half of block 0 — the one-time authenticator key (RFC 8439
    /// §2.6) — written to `otk`, and blocks 1 onwards XORed into `buf`.
    ///
    /// A backend that computes several blocks at a time overrides this to
    /// make block 0 one of them, instead of paying for a block of its own
    /// on every packet. The provided implementation is a scalar block 0
    /// followed by [`ChaChaImpl::apply_keystream`].
    ///
    /// An override takes on the contract of both parts: `otk` MUST equal
    /// [`one_time_key_into`]'s output and `buf` what `apply_keystream`
    /// with counter 1 produces. The authenticator key then comes from the
    /// backend — a backend that got block 0 wrong would authenticate
    /// under the wrong key — so the simd crate's tests check both outputs
    /// against the scalar code at every length.
    #[inline]
    fn seal_keystream(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8], otk: &mut [u8; 32]) {
        one_time_key_into(key, nonce, otk);
        Self::apply_keystream(key, nonce, 1, buf);
    }

    /// The receiving side of [`ChaChaImpl::seal_keystream`]: derive the
    /// one-time key, ask `verify` whether the ciphertext in `buf`
    /// authenticates under it, and only if it does XOR blocks 1 onwards
    /// into `buf`. Returns the verdict. When it is `false`, `buf` MUST be
    /// as it was passed in, and no keystream for it may remain anywhere.
    ///
    /// The key handed to `verify` MUST be wiped before returning.
    #[inline]
    fn open_keystream<F: FnOnce(&[u8; 32], &[u8]) -> bool>(
        key: &[u8; 32],
        nonce: &[u8; 12],
        buf: &mut [u8],
        verify: F,
    ) -> bool {
        let mut otk = [0u8; 32];
        one_time_key_into(key, nonce, &mut otk);
        let ok = verify(&otk, buf);
        ct::wipe_array(&mut otk);
        if ok {
            Self::apply_keystream(key, nonce, 1, buf);
        }
        ok
    }

    /// Backend name for diagnostics/benchmarks.
    fn name() -> &'static str;
}

/// The AEAD's one-time authenticator key: the first 32 bytes of keystream
/// block 0 (RFC 8439 §2.6), written to `otk`. The block it comes from is
/// wiped before returning.
pub fn one_time_key_into(key: &[u8; 32], nonce: &[u8; 12], otk: &mut [u8; 32]) {
    let mut low = usize::MAX;
    one_time_key_worker(key, nonce, otk, &mut low);
    ct::scrub_frame::<WORKER_FRAME>(low);
}

/// [`one_time_key_into`]'s work, in a frame of its own (see
/// [`permute`]). Says, in `low`, where that frame ends.
#[inline(never)]
fn one_time_key_worker(key: &[u8; 32], nonce: &[u8; 12], otk: &mut [u8; 32], low: &mut usize) {
    *low = ct::stack_mark();
    let [n0, n1, n2] = nonce_words(nonce);
    let mut state = [0u32; 16];
    init_state(&mut state, key, [0, n0, n1, n2]);
    let mut block = [0u8; 64];
    keystream_block(&state, &mut block);
    for (d, s) in otk.iter_mut().zip(block.iter()) {
        *d = *s;
    }
    ct::wipe_array(&mut block);
    ct::wipe_words(&mut state);
}

/// Everything a seal needs, in one frame of its own (see [`permute`]):
/// block 0's first half to `otk`, blocks 1 onwards into `buf`. Says, in
/// `low`, where that frame ends.
#[inline(never)]
fn seal_worker(
    key: &[u8; 32],
    nonce: &[u8; 12],
    buf: &mut [u8],
    otk: &mut [u8; 32],
    low: &mut usize,
) {
    *low = ct::stack_mark();
    let [n0, n1, n2] = nonce_words(nonce);
    let mut state = [0u32; 16];
    init_state(&mut state, key, [0, n0, n1, n2]);
    let mut ks = [0u8; 64];
    keystream_block(&state, &mut ks);
    for (d, s) in otk.iter_mut().zip(ks.iter()) {
        *d = *s;
    }
    if let Some(ctr) = state.get_mut(12) {
        *ctr = 1;
    }
    xor_blocks(&mut state, &mut ks, buf);
    ct::wipe(&mut ks);
    ct::wipe_words(&mut state);
}

/// The safe-Rust scalar backend — exactly [`xor_in_place`]. This is the
/// correctness oracle every other backend is tested against and the
/// default of [`crate::InTree`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Scalar;

impl ChaChaImpl for Scalar {
    #[inline]
    fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        xor_in_place(key, counter, nonce, buf);
    }

    /// As the provided implementation, in one piece: block 0 and the
    /// stream come out of one worker, whose frame is overwritten once.
    #[inline]
    fn seal_keystream(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8], otk: &mut [u8; 32]) {
        let mut low = usize::MAX;
        seal_worker(key, nonce, buf, otk, &mut low);
        ct::scrub_frame::<WORKER_FRAME>(low);
    }

    /// As the provided implementation; the frames of the one or two
    /// workers it takes are overwritten once, at the end.
    #[inline]
    fn open_keystream<F: FnOnce(&[u8; 32], &[u8]) -> bool>(
        key: &[u8; 32],
        nonce: &[u8; 12],
        buf: &mut [u8],
        verify: F,
    ) -> bool {
        let mut otk = [0u8; 32];
        let (mut low, mut lower) = (usize::MAX, usize::MAX);
        one_time_key_worker(key, nonce, &mut otk, &mut low);
        let ok = verify(&otk, buf);
        ct::wipe_array(&mut otk);
        if ok && !buf.is_empty() {
            xor_worker(key, 1, nonce, buf, &mut lower);
        }
        ct::scrub_frame::<WORKER_FRAME>(low.min(lower));
        ok
    }

    fn name() -> &'static str {
        "scalar"
    }
}

/// HChaCha20 (draft-irtf-cfrg-xchacha §2.2): derive a subkey from a key
/// and a 16-byte nonce; the building block of XChaCha20-Poly1305.
///
/// The subkey comes back by value, which leaves a copy wherever the
/// caller moves it on from; [`hchacha20_into`] writes it in place.
#[must_use]
pub fn hchacha20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hchacha20_into(key, input, &mut out);
    out
}

/// As [`hchacha20`], writing the subkey to `out`. The input state and
/// the permuted state are wiped before returning: HChaCha20 adds nothing
/// back at the end, so the permuted state *is* the key to anyone who
/// runs the rounds backwards.
pub fn hchacha20_into(key: &[u8; 32], input: &[u8; 16], out: &mut [u8; 32]) {
    let mut low = usize::MAX;
    hchacha20_worker(key, input, out, &mut low);
    ct::scrub_frame::<WORKER_FRAME>(low);
}

/// [`hchacha20_into`]'s work, in a frame of its own (see [`permute`]).
/// Says, in `low`, where that frame ends.
#[inline(never)]
fn hchacha20_worker(key: &[u8; 32], input: &[u8; 16], out: &mut [u8; 32], low: &mut usize) {
    *low = ct::stack_mark();
    let mut n = [0u32; 4];
    load_words(n.iter_mut(), input);
    let mut state = [0u32; 16];
    init_state(&mut state, key, n);
    let mut worked = permute(&state);
    ct::wipe_words(&mut state);
    // Output = working words 0..4 and 12..16, no feed-forward — word by
    // word from where they are, not by way of a second array.
    bytes::store_le32(
        out,
        worked.iter().take(4).chain(worked.iter().skip(12)).copied(),
    );
    ct::wipe_words(&mut worked);
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
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn rfc_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    /// In an optimised build the frame that is overwritten at once after
    /// a worker covers every worker's frame: the slower, self-sizing
    /// scrub is never needed. (A build with less optimisation has larger
    /// frames and takes the slow way where it must; that is right, and
    /// not what this is about.)
    #[test]
    fn the_workers_frames_are_overwritten_in_one_go() {
        let key = rfc_key();
        let nonce = [7u8; 12];
        let before = ct::tests::DEEP_FRAMES.with(core::cell::Cell::get);
        let mut block = [0u8; 64];
        block_into(&key, 1, &nonce, &mut block);
        let mut otk = [0u8; 32];
        one_time_key_into(&key, &nonce, &mut otk);
        let mut subkey = [0u8; 32];
        hchacha20_into(&key, &[9u8; 16], &mut subkey);
        for len in [1usize, 63, 64, 65, 1420, 4097] {
            let mut data = std::vec![0x42u8; len];
            xor_in_place(&key, 1, &nonce, &mut data);
            Scalar::seal_keystream(&key, &nonce, &mut data, &mut otk);
            assert!(Scalar::open_keystream(&key, &nonce, &mut data, |_, _| true));
            assert!(!Scalar::open_keystream(&key, &nonce, &mut data, |_, _| {
                false
            }));
        }
        if cfg!(debug_assertions) {
            return;
        }
        assert_eq!(ct::tests::DEEP_FRAMES.with(core::cell::Cell::get), before);
    }

    /// The scalar backend's own combined calls are the provided ones:
    /// the one-time key is block 0's first half, the stream starts at
    /// block 1, and a refused open leaves the buffer alone.
    #[test]
    fn the_scalar_combined_calls_equal_their_parts() {
        let key = rfc_key();
        let nonce = [3u8; 12];
        let block0 = block(&key, 0, &nonce);
        for len in [0usize, 1, 31, 64, 65, 300, 1420] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let mut want = plain.clone();
            xor_in_place(&key, 1, &nonce, &mut want);

            let mut sealed = plain.clone();
            let mut otk = [0xeeu8; 32];
            Scalar::seal_keystream(&key, &nonce, &mut sealed, &mut otk);
            assert_eq!(otk[..], block0[..32], "one-time key, {len} bytes");
            assert_eq!(sealed, want, "stream, {len} bytes");

            let mut seen = [0u8; 32];
            let mut opened = sealed.clone();
            assert!(Scalar::open_keystream(
                &key,
                &nonce,
                &mut opened,
                |otk, ct| {
                    seen = *otk;
                    ct == &sealed[..]
                }
            ));
            assert_eq!(seen[..], block0[..32]);
            assert_eq!(opened, plain, "opened, {len} bytes");

            let mut refused = sealed.clone();
            assert!(!Scalar::open_keystream(
                &key,
                &nonce,
                &mut refused,
                |_, _| false
            ));
            assert_eq!(refused, sealed, "a refused open touched the buffer");
        }
    }

    #[test]
    fn rfc8439_block_function() {
        // RFC 8439 §2.3.2.
        let key = rfc_key();
        let nonce: [u8; 12] = unhex("000000090000004a00000000").try_into().unwrap();
        let ks = block(&key, 1, &nonce);
        let expected = unhex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(ks.as_slice(), expected);
    }

    #[test]
    fn rfc8439_encryption() {
        // RFC 8439 §2.4.2: the "sunscreen" plaintext, counter starts at 1.
        let key = rfc_key();
        let nonce: [u8; 12] = unhex("000000000000004a00000000").try_into().unwrap();
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
        let mut data = plaintext.to_vec();
        xor_in_place(&key, 1, &nonce, &mut data);
        let expected = unhex(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );
        assert_eq!(data, expected);
        // Round-trip.
        xor_in_place(&key, 1, &nonce, &mut data);
        assert_eq!(data.as_slice(), plaintext);
    }

    #[test]
    fn keystream_continuity_across_chunking() {
        // Encrypting in one call must equal encrypting in pieces with
        // manually advanced counters.
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let mut whole = [0xa5u8; 256];
        xor_in_place(&key, 5, &nonce, &mut whole);
        let mut parts = [0xa5u8; 256];
        let (a, b) = parts.split_at_mut(64);
        let (b, c) = b.split_at_mut(128);
        xor_in_place(&key, 5, &nonce, a);
        xor_in_place(&key, 6, &nonce, b);
        xor_in_place(&key, 8, &nonce, c);
        assert_eq!(whole, parts);
    }

    #[test]
    fn hchacha20_consistent_with_block_function() {
        // Independent structural check: by construction, HChaCha20(k, n)
        // equals the ChaCha20 working state (block output minus the
        // feed-forward of the input state) at words 0..4 and 12..16, where
        // the 16-byte input supplies words 12..16 (counter ∥ nonce). This
        // pins HChaCha20 to the RFC-validated block function.
        let key = rfc_key();
        let input: [u8; 16] = unhex("000000090000004a0000000031415927")
            .try_into()
            .unwrap();
        let counter = u32::from_le_bytes(input[0..4].try_into().unwrap());
        let nonce: [u8; 12] = input[4..16].try_into().unwrap();
        let blk = block(&key, counter, &nonce);

        let key_w = {
            let mut w = [0u32; 8];
            for (wi, c) in w.iter_mut().zip(key.chunks_exact(4)) {
                *wi = u32::from_le_bytes(c.try_into().unwrap());
            }
            w
        };
        let input_state: [u32; 16] = [
            C0,
            C1,
            C2,
            C3,
            key_w[0],
            key_w[1],
            key_w[2],
            key_w[3],
            key_w[4],
            key_w[5],
            key_w[6],
            key_w[7],
            counter,
            u32::from_le_bytes(input[4..8].try_into().unwrap()),
            u32::from_le_bytes(input[8..12].try_into().unwrap()),
            u32::from_le_bytes(input[12..16].try_into().unwrap()),
        ];
        let mut expected = [0u8; 32];
        for (i, slot) in [0usize, 1, 2, 3, 12, 13, 14, 15].iter().enumerate() {
            let word = u32::from_le_bytes(blk[slot * 4..slot * 4 + 4].try_into().unwrap())
                .wrapping_sub(input_state[*slot]);
            expected[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(hchacha20(&key, &input), expected);
    }

    #[test]
    fn hchacha20_draft_vector() {
        // draft-irtf-cfrg-xchacha-03 §2.2.1 (verified against
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt).
        let key = rfc_key();
        let input: [u8; 16] = unhex("000000090000004a0000000031415927")
            .try_into()
            .unwrap();
        let expected = unhex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
        assert_eq!(hchacha20(&key, &input).as_slice(), expected);
    }
}
