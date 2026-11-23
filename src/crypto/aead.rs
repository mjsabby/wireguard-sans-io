//! ChaCha20-Poly1305 (RFC 8439 §2.8) and XChaCha20-Poly1305
//! (draft-irtf-cfrg-xchacha) AEADs — whitepaper `Aead()` and `Xaead()`.
//!
//! Decryption is strictly *verify-then-decrypt*: the Poly1305 tag is
//! checked (in constant time) over the ciphertext before a single byte of
//! plaintext is produced, so a forgery can never leave attacker-controlled
//! bytes in the caller's buffer.
//!
//! Each operation comes in two shapes:
//!
//! * **in place** ([`seal_in_place`], [`open_in_place`], and the `x…`
//!   variants) — one buffer, no copy. This is what the protocol code uses,
//!   through [`crate::crypto::CryptoProvider`];
//! * **copying** ([`seal`], [`open`], [`xseal`], [`xopen`]) — separate input
//!   and output, for callers whose input is immutable.
//!
//! The keystream comes from a [`ChaChaImpl`] backend. The ChaCha20-Poly1305
//! functions have the plain name (uses [`Scalar`], the safe-Rust path) and
//! a `_with::<C>` form for callers that supply a SIMD backend; the
//! XChaCha20 variants, used only for 16-byte cookies, are always scalar.
//! Poly1305 is always the in-tree implementation; only the keystream is
//! pluggable at this level — including, for a backend that overrides
//! [`ChaChaImpl::seal_keystream`], the block the one-time authenticator
//! key is taken from.
//!
//! Nothing that authenticates is left behind: the one-time key is wiped
//! before a function returns, and so is the tag *computed* while opening —
//! for a forgery that tag is exactly what the forger was missing.

use core::fmt;

use crate::Error;
use crate::crypto::bytes;
use crate::crypto::chacha20::{self, ChaChaImpl, Scalar};
use crate::crypto::ct;
use crate::crypto::poly1305::Poly1305;

/// Poly1305 tag length appended to every ciphertext.
pub const TAG_LEN: usize = 16;
/// AEAD key length.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length (whitepaper `Xaead` uses a 24-byte
/// nonce).
pub const XNONCE_LEN: usize = 24;
/// The longest plaintext one call can encrypt (and the longest ciphertext,
/// tag aside, one can accept): 2³² − 1 keystream blocks of 64 bytes, a
/// little under 256 GiB (RFC 8439 §2.8).
///
/// ChaCha20's block counter has 32 bits, and block 0 makes the Poly1305
/// key. A longer message would wrap the counter and use that block, and
/// then the ones after it, a second time. Every function here refuses
/// such a message instead — [`Error::MessageTooLong`] when sealing,
/// [`OpenError::AuthFailure`] when opening (nothing that long can have
/// been sealed). No datagram comes anywhere near it, and on a 32-bit
/// target no slice can.
pub const MAX_MESSAGE_LEN: u64 = (u32::MAX as u64) * 64;

/// Is a message of `len` bytes no longer than `limit`?
const fn within(len: usize, limit: u64) -> bool {
    // `usize` is at most 64 bits wide on every target Rust has.
    (len as u64) <= limit
}

/// Why an AEAD open failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenError {
    /// The input is shorter than a tag or the tag does not verify. Nothing
    /// was written.
    AuthFailure,
    /// The separate output buffer of a copying open cannot hold the
    /// plaintext. Nothing was written. (Never returned by the in-place
    /// functions.)
    BufferTooSmall,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuthFailure => "authentication failed",
            Self::BufferTooSmall => "output buffer too small",
        })
    }
}

impl core::error::Error for OpenError {}

/// Build the 12-byte nonce WireGuard uses for handshake and transport
/// AEADs: 32 bits of zeros followed by the little-endian counter
/// (whitepaper §5.4).
#[must_use]
pub fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let [c0, c1, c2, c3, c4, c5, c6, c7] = counter.to_le_bytes();
    [0, 0, 0, 0, c0, c1, c2, c3, c4, c5, c6, c7]
}

/// Copy `src` into `dst` if the lengths match exactly.
fn copy_exact(dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
    if dst.len() != src.len() {
        return Err(Error::Internal);
    }
    bytes::copy(dst, src);
    Ok(())
}

/// Poly1305 tag over `aad` and `ciphertext` per RFC 8439 §2.8: both parts
/// zero-padded to 16 bytes, followed by their lengths as little-endian
/// 64-bit words.
///
/// The tag is written to `tag` and the authenticator's state is built,
/// used and wiped where it stands: nothing is passed or returned by
/// value, so there is one copy of the tag and none of the key.
///
/// With `MARK`, returns where the stack ends beneath the frames the tag
/// was computed in (see [`tag_matches`]); without, `usize::MAX`.
fn compute_tag<const MARK: bool>(
    otk: &[u8; 32],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &mut [u8; TAG_LEN],
) -> usize {
    let mut mac = Poly1305::blank();
    mac.rekey(otk);
    // An empty part contributes nothing, not even padding.
    if !aad.is_empty() {
        mac.update_padded(aad);
    }
    if !ciphertext.is_empty() {
        mac.update_padded(ciphertext);
    }
    // The two lengths are one aligned block.
    let mut lens = [0u8; 16];
    if let Some(aad_len) = lens.first_chunk_mut::<8>() {
        *aad_len = (aad.len() as u64).to_le_bytes();
    }
    if let Some(ct_len) = lens.last_chunk_mut::<8>() {
        *ct_len = (ciphertext.len() as u64).to_le_bytes();
    }
    mac.update(&lens);
    if MARK {
        mac.finalize_into_marked(tag)
    } else {
        mac.finalize_into(tag);
        usize::MAX
    }
}

/// How far below the frame a tag was put together in the stack is
/// overwritten after a mismatch: room for what that frame calls where
/// the optimiser has not folded it in.
const BELOW_TAG: usize = 512;

/// Does `tag` authenticate `ciphertext` under the one-time key `otk`?
/// Constant time in the comparison.
///
/// The tag computed for the comparison is wiped: for a forgery it is the
/// one thing the forger did not have. And when it did not match, so is
/// the stack it was computed on, down to where that computation went —
/// an optimising compiler leaves nothing of it there, one that does not
/// leaves the words it was assembled from. (After a match there is
/// nothing to hide: the tag is in the datagram.)
fn tag_matches(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8], tag: &[u8; TAG_LEN]) -> bool {
    let mut expected = [0u8; TAG_LEN];
    let low = compute_tag::<true>(otk, aad, ciphertext, &mut expected);
    let ok = ct::ct_eq(&expected, tag);
    ct::wipe_array(&mut expected);
    if !ok {
        ct::scrub_stack_to(low.saturating_sub(BELOW_TAG));
    }
    ok
}

/// Encrypt `plaintext` with `aad`, writing `ciphertext ∥ tag` into `out`.
///
/// Returns the number of bytes written (`plaintext.len() + TAG_LEN`).
///
/// # Errors
/// [`Error::BufferTooSmall`] if `out` cannot hold the result;
/// [`Error::MessageTooLong`] beyond [`MAX_MESSAGE_LEN`].
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    seal_with::<Scalar>(key, nonce, aad, plaintext, out)
}

/// As [`seal`], with an explicit [`ChaChaImpl`] backend.
///
/// # Errors
/// As [`seal`].
pub fn seal_with<C: ChaChaImpl>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let total = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(Error::BufferTooSmall)?;
    let out = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;
    let (ct_part, _tag_part) = out
        .split_at_mut_checked(plaintext.len())
        .ok_or(Error::Internal)?;
    copy_exact(ct_part, plaintext)?;
    seal_in_place_with::<C>(key, nonce, aad, plaintext.len(), out)
}

/// Verify and decrypt `ciphertext ∥ tag` with `aad`, writing the plaintext
/// into `out`. Returns the plaintext length.
///
/// # Errors
/// * [`OpenError::AuthFailure`] if the input is shorter than a tag or the
///   tag does not verify — `out` is untouched in both cases.
/// * [`OpenError::BufferTooSmall`] if `out` cannot hold the plaintext.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    out: &mut [u8],
) -> Result<usize, OpenError> {
    open_with::<Scalar>(key, nonce, aad, ciphertext_and_tag, out)
}

/// As [`open`], with an explicit [`ChaChaImpl`] backend. The
/// verify-then-decrypt guarantee is unchanged: the tag is computed over
/// the *ciphertext* (no backend involved) and compared before the
/// backend ever runs, so a buggy backend cannot turn a forgery into
/// accepted plaintext — at worst it garbles already-authenticated data.
///
/// # Errors
/// As [`open`].
pub fn open_with<C: ChaChaImpl>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    out: &mut [u8],
) -> Result<usize, OpenError> {
    open_limited::<C>(key, nonce, aad, ciphertext_and_tag, out, MAX_MESSAGE_LEN)
}

/// [`open_with`], for messages up to `limit` bytes. (The limit is a
/// parameter so that the tests can reach it.)
fn open_limited<C: ChaChaImpl>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    out: &mut [u8],
    limit: u64,
) -> Result<usize, OpenError> {
    let (ciphertext, tag) = ciphertext_and_tag
        .split_last_chunk::<TAG_LEN>()
        .ok_or(OpenError::AuthFailure)?;
    if !within(ciphertext.len(), limit) {
        return Err(OpenError::AuthFailure);
    }
    let out = out
        .get_mut(..ciphertext.len())
        .ok_or(OpenError::BufferTooSmall)?;
    // The input is immutable here, so the backend's combined call (which
    // works in place) does not apply: scalar block 0, verify, then copy.
    let mut otk = [0u8; 32];
    chacha20::one_time_key_into(key, nonce, &mut otk);
    let ok = tag_matches(&otk, aad, ciphertext, tag);
    ct::wipe_array(&mut otk);
    if !ok {
        return Err(OpenError::AuthFailure);
    }
    // Equal lengths by construction: `out` was sliced to the ciphertext's
    // length just above.
    for (d, s) in out.iter_mut().zip(ciphertext.iter()) {
        *d = *s;
    }
    C::apply_keystream(key, nonce, 1, out);
    Ok(ciphertext.len())
}

/// Encrypt `buf[..pt_len]` in place and append the tag at
/// `buf[pt_len..pt_len + TAG_LEN]`: the zero-copy variant used for
/// transport data, where plaintext is staged directly in the outgoing
/// datagram buffer.
///
/// # Errors
/// [`Error::BufferTooSmall`] if `buf` is shorter than `pt_len + TAG_LEN`;
/// [`Error::MessageTooLong`] if `pt_len` exceeds [`MAX_MESSAGE_LEN`].
pub fn seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt_len: usize,
    buf: &mut [u8],
) -> Result<usize, Error> {
    seal_in_place_with::<Scalar>(key, nonce, aad, pt_len, buf)
}

/// As [`seal_in_place`], with an explicit [`ChaChaImpl`] backend. This is
/// the transport hot path — the one place backend choice matters.
///
/// # Errors
/// As [`seal_in_place`].
pub fn seal_in_place_with<C: ChaChaImpl>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt_len: usize,
    buf: &mut [u8],
) -> Result<usize, Error> {
    seal_in_place_limited::<C>(key, nonce, aad, pt_len, buf, MAX_MESSAGE_LEN)
}

/// [`seal_in_place_with`], for messages up to `limit` bytes.
fn seal_in_place_limited<C: ChaChaImpl>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt_len: usize,
    buf: &mut [u8],
    limit: u64,
) -> Result<usize, Error> {
    if !within(pt_len, limit) {
        return Err(Error::MessageTooLong);
    }
    let total = pt_len.checked_add(TAG_LEN).ok_or(Error::BufferTooSmall)?;
    let buf = buf.get_mut(..total).ok_or(Error::BufferTooSmall)?;
    let (ct_part, tag_part) = buf.split_at_mut_checked(pt_len).ok_or(Error::Internal)?;

    let tag = tag_part
        .first_chunk_mut::<TAG_LEN>()
        .ok_or(Error::Internal)?;
    let mut otk = [0u8; 32];
    C::seal_keystream(key, nonce, ct_part, &mut otk);
    let _ = compute_tag::<false>(&otk, aad, ct_part, tag);
    ct::wipe_array(&mut otk);
    Ok(total)
}

/// Verify `buf` (`ciphertext ∥ tag`) and decrypt it **in place**. On
/// success the plaintext is `buf[..n]` for the returned `n`
/// (`buf.len() − TAG_LEN`); the trailing tag bytes are left as they were.
///
/// # Errors
/// [`OpenError::AuthFailure`] if `buf` is shorter than a tag or the tag
/// does not verify. `buf` is then byte-for-byte unchanged: it still holds
/// the ciphertext, never attacker-chosen plaintext.
pub fn open_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<usize, OpenError> {
    open_in_place_with::<Scalar>(key, nonce, aad, buf)
}

/// As [`open_in_place`], with an explicit [`ChaChaImpl`] backend. The tag
/// is verified before the backend runs.
///
/// # Errors
/// As [`open_in_place`].
pub fn open_in_place_with<C: ChaChaImpl>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<usize, OpenError> {
    open_in_place_limited::<C>(key, nonce, aad, buf, MAX_MESSAGE_LEN)
}

/// [`open_in_place_with`], for messages up to `limit` bytes.
fn open_in_place_limited<C: ChaChaImpl>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    limit: u64,
) -> Result<usize, OpenError> {
    let (ciphertext, tag) = buf
        .split_last_chunk_mut::<TAG_LEN>()
        .ok_or(OpenError::AuthFailure)?;
    if !within(ciphertext.len(), limit) {
        return Err(OpenError::AuthFailure);
    }
    // The backend derives the one-time key, the closure decides, and only
    // then is keystream applied.
    let tag: &[u8; TAG_LEN] = tag;
    if !C::open_keystream(key, nonce, ciphertext, |otk, ciphertext| {
        tag_matches(otk, aad, ciphertext, tag)
    }) {
        return Err(OpenError::AuthFailure);
    }
    Ok(ciphertext.len())
}

/// `Xaead` encryption: XChaCha20-Poly1305 with a 24-byte nonce.
///
/// # Errors
/// As [`seal`].
pub fn xseal(
    key: &[u8; 32],
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut subkey = [0u8; 32];
    let sub_nonce = xchacha_derive(key, nonce, &mut subkey);
    let r = seal(&subkey, &sub_nonce, aad, plaintext, out);
    ct::wipe_array(&mut subkey);
    r
}

/// `Xaead` decryption.
///
/// # Errors
/// As [`open`].
pub fn xopen(
    key: &[u8; 32],
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    out: &mut [u8],
) -> Result<usize, OpenError> {
    let mut subkey = [0u8; 32];
    let sub_nonce = xchacha_derive(key, nonce, &mut subkey);
    let r = open(&subkey, &sub_nonce, aad, ciphertext_and_tag, out);
    ct::wipe_array(&mut subkey);
    r
}

/// `Xaead` encryption in place; see [`seal_in_place`].
///
/// # Errors
/// As [`seal_in_place`].
pub fn xseal_in_place(
    key: &[u8; 32],
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    pt_len: usize,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let mut subkey = [0u8; 32];
    let sub_nonce = xchacha_derive(key, nonce, &mut subkey);
    let r = seal_in_place(&subkey, &sub_nonce, aad, pt_len, buf);
    ct::wipe_array(&mut subkey);
    r
}

/// `Xaead` decryption in place; see [`open_in_place`].
///
/// # Errors
/// As [`open_in_place`].
pub fn xopen_in_place(
    key: &[u8; 32],
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<usize, OpenError> {
    let mut subkey = [0u8; 32];
    let sub_nonce = xchacha_derive(key, nonce, &mut subkey);
    let r = open_in_place(&subkey, &sub_nonce, aad, buf);
    ct::wipe_array(&mut subkey);
    r
}

/// HChaCha20 subkey, written to `subkey` (which the caller wipes), and
/// the derived 12-byte nonce (4 zero bytes ∥ last 8 nonce bytes) per
/// draft-irtf-cfrg-xchacha §2.3.
fn xchacha_derive(key: &[u8; 32], nonce: &[u8; XNONCE_LEN], subkey: &mut [u8; 32]) -> [u8; 12] {
    let mut hin = [0u8; 16];
    for (d, s) in hin.iter_mut().zip(nonce.iter()) {
        *d = *s;
    }
    chacha20::hchacha20_into(key, &hin, subkey);
    let mut sub_nonce = [0u8; 12];
    for (d, s) in sub_nonce.iter_mut().skip(4).zip(nonce.iter().skip(16)) {
        *d = *s;
    }
    sub_nonce
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
    use std::vec;
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const SUNSCREEN: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

    /// RFC 8439 §2.8: a message is at most 2³² − 1 blocks. One byte more
    /// would wrap the block counter and reuse the block the Poly1305 key
    /// came from. Buffers of 256 GiB are not to be had in a test, so the
    /// limit is checked where it is a number, and the refusal where the
    /// limit is a parameter.
    #[test]
    fn the_message_length_limit_is_enforced() {
        assert_eq!(MAX_MESSAGE_LEN, 274_877_906_880);
        // The last block of a message of the maximum length is block
        // 2³² − 1: the counter does not wrap.
        assert_eq!(1 + (MAX_MESSAGE_LEN - 1) / 64, u64::from(u32::MAX));
        #[cfg(target_pointer_width = "64")]
        {
            assert!(within(MAX_MESSAGE_LEN as usize, MAX_MESSAGE_LEN));
            assert!(!within(MAX_MESSAGE_LEN as usize + 1, MAX_MESSAGE_LEN));
            assert!(!within(usize::MAX, MAX_MESSAGE_LEN));
        }
        assert!(within(0, MAX_MESSAGE_LEN) && within(65_535, MAX_MESSAGE_LEN));

        // With the limit as a parameter: exactly at it everything works,
        // one byte over nothing does — and nothing is touched.
        let (key, nonce, aad) = ([7u8; 32], [9u8; 12], b"aad".as_slice());
        const LIMIT: u64 = 100;
        for len in [0usize, 1, 99, 100, 101, 164, 500] {
            let fits = len as u64 <= LIMIT;
            let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut sealed = plaintext.clone();
            sealed.extend_from_slice(&[0xEE; TAG_LEN]);
            let before = sealed.clone();
            let r = seal_in_place_limited::<Scalar>(&key, &nonce, aad, len, &mut sealed, LIMIT);
            if fits {
                assert_eq!(r, Ok(len + TAG_LEN), "len {len}");
            } else {
                assert_eq!(r, Err(Error::MessageTooLong), "len {len}");
                assert_eq!(sealed, before, "len {len}: buffer touched");
            }

            // A genuine ciphertext of that length (sealed without the
            // test's limit).
            let mut genuine = plaintext.clone();
            genuine.extend_from_slice(&[0; TAG_LEN]);
            seal_in_place(&key, &nonce, aad, len, &mut genuine).unwrap();
            let mut copy = genuine.clone();
            let r = open_in_place_limited::<Scalar>(&key, &nonce, aad, &mut copy, LIMIT);
            let mut out = vec![0xAA; len];
            let r2 = open_limited::<Scalar>(&key, &nonce, aad, &genuine, &mut out, LIMIT);
            if fits {
                assert_eq!((r, r2), (Ok(len), Ok(len)), "len {len}");
                assert_eq!(&copy[..len], &plaintext[..]);
                assert_eq!(out, plaintext);
            } else {
                assert_eq!(r, Err(OpenError::AuthFailure), "len {len}");
                assert_eq!(r2, Err(OpenError::AuthFailure), "len {len}");
                assert_eq!(copy, genuine, "len {len}: buffer touched");
                assert_eq!(out, vec![0xAA; len], "len {len}: output touched");
            }
        }
    }

    #[test]
    fn rfc8439_aead_vector() {
        // RFC 8439 §2.8.2.
        let key: [u8; 32] =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let mut out = [0u8; 256];
        let n = seal(&key, &nonce, &aad, SUNSCREEN, &mut out).unwrap();
        assert_eq!(n, SUNSCREEN.len() + 16);
        let expected_ct = unhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let expected_tag = unhex("1ae10b594f09e26a7e902ecbd0600691");
        assert_eq!(&out[..SUNSCREEN.len()], expected_ct.as_slice());
        assert_eq!(&out[SUNSCREEN.len()..n], expected_tag.as_slice());

        // And the inverse direction.
        let mut pt = [0u8; 256];
        let m = open(&key, &nonce, &aad, &out[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], SUNSCREEN);
    }

    #[test]
    fn roundtrip_various_lengths() {
        let key = [0x42u8; 32];
        for len in 0..130usize {
            let nonce = nonce_from_counter(len as u64);
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let aad = [0xaau8; 7];
            let mut sealed = vec![0u8; len + TAG_LEN];
            let n = seal(&key, &nonce, &aad, &pt, &mut sealed).unwrap();
            assert_eq!(n, len + TAG_LEN);
            let mut opened = vec![0u8; len];
            let m = open(&key, &nonce, &aad, &sealed, &mut opened).unwrap();
            assert_eq!(m, len);
            assert_eq!(opened, pt);
        }
    }

    #[test]
    fn forgery_rejected_and_output_untouched() {
        let key = [7u8; 32];
        let nonce = nonce_from_counter(1);
        let mut sealed = [0u8; 64 + TAG_LEN];
        let n = seal(&key, &nonce, b"aad", &[0x55u8; 64], &mut sealed).unwrap();
        // Flip every single bit; every mutation must fail and must leave
        // the output buffer exactly as it was.
        for byte in 0..n {
            for bit in 0..8 {
                let mut corrupt = sealed;
                corrupt[byte] ^= 1 << bit;
                let mut out = [0xeeu8; 64];
                let r = open(&key, &nonce, b"aad", &corrupt[..n], &mut out);
                assert_eq!(r, Err(OpenError::AuthFailure), "byte {byte} bit {bit}");
                assert_eq!(out, [0xeeu8; 64], "output dirtied at byte {byte} bit {bit}");
            }
        }
        // Wrong AAD, wrong nonce, wrong key: all rejected.
        let mut out = [0u8; 64];
        assert_eq!(
            open(&key, &nonce, b"aax", &sealed[..n], &mut out),
            Err(OpenError::AuthFailure)
        );
        assert_eq!(
            open(&key, &nonce_from_counter(2), b"aad", &sealed[..n], &mut out),
            Err(OpenError::AuthFailure)
        );
        assert_eq!(
            open(&[8u8; 32], &nonce, b"aad", &sealed[..n], &mut out),
            Err(OpenError::AuthFailure)
        );
    }

    #[test]
    fn truncated_inputs_rejected() {
        let key = [7u8; 32];
        let nonce = nonce_from_counter(1);
        let mut sealed = [0u8; 32 + TAG_LEN];
        let n = seal(&key, &nonce, &[], &[0x55u8; 32], &mut sealed).unwrap();
        let mut out = [0u8; 64];
        for keep in 0..n {
            let r = open(&key, &nonce, &[], &sealed[..keep], &mut out);
            assert!(r.is_err(), "truncation to {keep} accepted");
        }
        // Empty and sub-tag-length inputs.
        assert_eq!(
            open(&key, &nonce, &[], &[], &mut out),
            Err(OpenError::AuthFailure)
        );
        assert_eq!(
            open(&key, &nonce, &[], &[0u8; 15], &mut out),
            Err(OpenError::AuthFailure)
        );
    }

    #[test]
    fn buffer_too_small_is_reported_not_panicked() {
        let key = [1u8; 32];
        let nonce = nonce_from_counter(0);
        let mut tiny = [0u8; 8];
        assert_eq!(
            seal(&key, &nonce, &[], &[0u8; 16], &mut tiny),
            Err(Error::BufferTooSmall)
        );
        let mut sealed = [0u8; 16 + TAG_LEN];
        seal(&key, &nonce, &[], &[0u8; 16], &mut sealed).unwrap();
        let mut tiny = [0u8; 8];
        assert_eq!(
            open(&key, &nonce, &[], &sealed, &mut tiny),
            Err(OpenError::BufferTooSmall)
        );
    }

    #[test]
    fn empty_plaintext_is_just_a_tag() {
        // Keepalives are AEAD(key, counter, ε, ε): 16 bytes on the wire.
        let key = [3u8; 32];
        let nonce = nonce_from_counter(9);
        let mut sealed = [0u8; TAG_LEN];
        let n = seal(&key, &nonce, &[], &[], &mut sealed).unwrap();
        assert_eq!(n, TAG_LEN);
        let mut out = [0u8; 0];
        assert_eq!(open(&key, &nonce, &[], &sealed, &mut out), Ok(0));
    }

    #[test]
    fn xaead_roundtrip_and_nonce_separation() {
        let key = [0x99u8; 32];
        let mut n1 = [0u8; 24];
        let mut n2 = [0u8; 24];
        n2[23] = 1;
        let mut a = [0u8; 32 + TAG_LEN];
        let mut b = [0u8; 32 + TAG_LEN];
        xseal(&key, &n1, b"ad", &[0x11u8; 32], &mut a).unwrap();
        xseal(&key, &n2, b"ad", &[0x11u8; 32], &mut b).unwrap();
        assert_ne!(a, b, "different nonces must give different ciphertexts");
        // Differences confined to the HChaCha16-byte prefix also matter.
        n1[0] ^= 1;
        let mut c = [0u8; 32 + TAG_LEN];
        xseal(&key, &n1, b"ad", &[0x11u8; 32], &mut c).unwrap();
        assert_ne!(b, c);

        let mut out = [0u8; 32];
        let m = xopen(&key, &n1, b"ad", &c, &mut out).unwrap();
        assert_eq!(m, 32);
        assert_eq!(out, [0x11u8; 32]);
        // Cross-nonce decryption fails.
        assert_eq!(
            xopen(&key, &n2, b"ad", &c, &mut out),
            Err(OpenError::AuthFailure)
        );
    }

    #[test]
    fn xchacha_draft_aead_vector() {
        // draft-irtf-cfrg-xchacha-03 §A.3.1 (same plaintext/AAD as the RFC
        // 8439 vector, 24-byte nonce 40..57, key 80..9f).
        let key: [u8; 32] =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; 24] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let mut out = [0u8; 256];
        let n = xseal(&key, &nonce, &aad, SUNSCREEN, &mut out).unwrap();
        let expected_ct = unhex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e",
        );
        let expected_tag = unhex("c0875924c1c7987947deafd8780acf49");
        assert_eq!(&out[..SUNSCREEN.len()], expected_ct.as_slice());
        assert_eq!(&out[SUNSCREEN.len()..n], expected_tag.as_slice());
    }

    #[test]
    fn seal_in_place_matches_seal() {
        let key = [0x21u8; 32];
        for len in [0usize, 1, 15, 16, 17, 64, 200] {
            let nonce = nonce_from_counter(len as u64);
            let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let mut copied = vec![0u8; len + TAG_LEN];
            let n1 = seal(&key, &nonce, b"ad", &pt, &mut copied).unwrap();
            let mut inplace = vec![0u8; len + TAG_LEN];
            inplace[..len].copy_from_slice(&pt);
            let n2 = seal_in_place(&key, &nonce, b"ad", len, &mut inplace).unwrap();
            assert_eq!(n1, n2);
            assert_eq!(copied, inplace, "len={len}");
            // And it opens.
            let mut out = vec![0u8; len];
            assert_eq!(open(&key, &nonce, b"ad", &inplace, &mut out), Ok(len));
            assert_eq!(out, pt);
        }
        // Too-small buffer reports, not panics.
        let mut tiny = [0u8; 10];
        assert_eq!(
            seal_in_place(&key, &nonce_from_counter(0), &[], 8, &mut tiny),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn open_in_place_matches_open_and_leaves_forgeries_untouched() {
        let key = [0x31u8; 32];
        for len in [0usize, 1, 15, 16, 17, 64, 200, 1420] {
            let nonce = nonce_from_counter(len as u64 + 3);
            let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(13)).collect();
            let mut sealed = vec![0u8; len + TAG_LEN];
            seal(&key, &nonce, b"ad", &pt, &mut sealed).unwrap();

            // Genuine: decrypts in place to the same bytes `open` produces.
            let mut buf = sealed.clone();
            assert_eq!(open_in_place(&key, &nonce, b"ad", &mut buf), Ok(len));
            assert_eq!(&buf[..len], pt.as_slice(), "len={len}");
            let mut copied = vec![0u8; len];
            assert_eq!(open(&key, &nonce, b"ad", &sealed, &mut copied), Ok(len));
            assert_eq!(copied, pt);

            // Forged (one bit anywhere): rejected, buffer byte-for-byte
            // unchanged — still ciphertext, never plaintext.
            for byte in [0, len / 2, len + TAG_LEN - 1] {
                let mut forged = sealed.clone();
                forged[byte] ^= 0x10;
                let before = forged.clone();
                assert_eq!(
                    open_in_place(&key, &nonce, b"ad", &mut forged),
                    Err(OpenError::AuthFailure),
                    "len={len} byte={byte}"
                );
                assert_eq!(forged, before, "forgery modified the buffer");
            }
        }
        // Shorter than a tag: rejected, not panicked.
        let mut short = [0u8; TAG_LEN - 1];
        assert_eq!(
            open_in_place(&key, &nonce_from_counter(0), &[], &mut short),
            Err(OpenError::AuthFailure)
        );
        let mut empty = [0u8; 0];
        assert_eq!(
            open_in_place(&key, &nonce_from_counter(0), &[], &mut empty),
            Err(OpenError::AuthFailure)
        );
    }

    #[test]
    fn xaead_in_place_matches_copying() {
        let key = [0x99u8; 32];
        let nonce = [0x24u8; 24];
        let mut copied = [0u8; 16 + TAG_LEN];
        xseal(
            &key,
            &nonce,
            b"mac1mac1mac1mac1",
            &[0x5au8; 16],
            &mut copied,
        )
        .unwrap();
        let mut inplace = [0u8; 16 + TAG_LEN];
        inplace[..16].fill(0x5a);
        assert_eq!(
            xseal_in_place(&key, &nonce, b"mac1mac1mac1mac1", 16, &mut inplace),
            Ok(32)
        );
        assert_eq!(copied, inplace);
        assert_eq!(
            xopen_in_place(&key, &nonce, b"mac1mac1mac1mac1", &mut inplace),
            Ok(16)
        );
        assert_eq!(&inplace[..16], &[0x5au8; 16]);
        // Wrong AAD: rejected and untouched.
        let mut again = copied;
        assert_eq!(
            xopen_in_place(&key, &nonce, b"MAC1mac1mac1mac1", &mut again),
            Err(OpenError::AuthFailure)
        );
        assert_eq!(again, copied);
    }

    #[test]
    fn nonce_from_counter_layout() {
        assert_eq!(nonce_from_counter(0), [0u8; 12]);
        assert_eq!(
            nonce_from_counter(0x0102_0304_0506_0708),
            [0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(
            nonce_from_counter(u64::MAX),
            [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    /// A backend whose combined calls are its own: the scalar keystream,
    /// reached by a different route, with every call counted.
    struct Combined;
    static COMBINED_SEALS: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    static COMBINED_OPENS: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    impl ChaChaImpl for Combined {
        fn apply_keystream(_: &[u8; 32], _: &[u8; 12], _: u32, _: &mut [u8]) {
            panic!("the in-place AEAD must go through the combined calls");
        }
        fn seal_keystream(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8], otk: &mut [u8; 32]) {
            COMBINED_SEALS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Scalar::seal_keystream(key, nonce, buf, otk);
        }
        fn open_keystream<F: FnOnce(&[u8; 32], &[u8]) -> bool>(
            key: &[u8; 32],
            nonce: &[u8; 12],
            buf: &mut [u8],
            verify: F,
        ) -> bool {
            COMBINED_OPENS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Scalar::open_keystream(key, nonce, buf, verify)
        }
        fn name() -> &'static str {
            "combined"
        }
    }

    /// The in-place AEAD takes the one-time key and the keystream from the
    /// backend's combined calls — one call per packet, which is what lets
    /// a SIMD backend make block 0 part of its first stride — and the
    /// result is the same bytes.
    #[test]
    fn the_in_place_aead_uses_the_backends_combined_calls() {
        use core::sync::atomic::Ordering::Relaxed;
        let key = [0x42u8; 32];
        let nonce = nonce_from_counter(7);
        for len in [0usize, 1, 16, 63, 64, 65, 300, 1420] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let mut want = vec![0u8; len + TAG_LEN];
            seal(&key, &nonce, b"aad", &plain, &mut want).unwrap();

            let (seals, opens) = (COMBINED_SEALS.load(Relaxed), COMBINED_OPENS.load(Relaxed));
            let mut buf = vec![0u8; len + TAG_LEN];
            buf[..len].copy_from_slice(&plain);
            seal_in_place_with::<Combined>(&key, &nonce, b"aad", len, &mut buf).unwrap();
            assert_eq!(buf, want, "len={len}");
            assert_eq!(COMBINED_SEALS.load(Relaxed), seals + 1);

            // A forgery: refused, and the buffer is as it arrived.
            let mut forged = buf.clone();
            forged[len] ^= 1;
            let before = forged.clone();
            assert_eq!(
                open_in_place_with::<Combined>(&key, &nonce, b"aad", &mut forged),
                Err(OpenError::AuthFailure)
            );
            assert_eq!(forged, before);

            assert_eq!(
                open_in_place_with::<Combined>(&key, &nonce, b"aad", &mut buf),
                Ok(len)
            );
            assert_eq!(&buf[..len], &plain[..]);
            assert_eq!(COMBINED_OPENS.load(Relaxed), opens + 2);
        }
    }

    /// A backend that is a keystream and nothing else: its combined
    /// calls are the ones the trait provides.
    struct KeystreamOnly;
    impl ChaChaImpl for KeystreamOnly {
        fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
            chacha20::xor_in_place(key, counter, nonce, buf);
        }
        fn name() -> &'static str {
            "keystream only"
        }
    }

    fn combined_calls_equal_their_parts<C: ChaChaImpl>() {
        let key = [0x17u8; 32];
        let nonce = nonce_from_counter(99);
        let mut block0 = [0u8; 64];
        chacha20::block_into(&key, 0, &nonce, &mut block0);
        for len in [0usize, 5, 64, 129, 1000] {
            let mut a = vec![0xa5u8; len];
            let mut b = a.clone();
            let mut otk = [0u8; 32];
            C::seal_keystream(&key, &nonce, &mut a, &mut otk);
            assert_eq!(otk, block0[..32]);
            Scalar::apply_keystream(&key, &nonce, 1, &mut b);
            assert_eq!(a, b);
            // Opening: the verdict decides whether anything is touched.
            let sealed = a.clone();
            let mut seen = [0u8; 32];
            assert!(!C::open_keystream(&key, &nonce, &mut a, |otk, ct| {
                seen = *otk;
                assert_eq!(ct, &sealed[..]);
                false
            }));
            assert_eq!(seen, block0[..32]);
            assert_eq!(a, sealed);
            assert!(C::open_keystream(&key, &nonce, &mut a, |_, _| true));
            assert_eq!(a, vec![0xa5u8; len]);
        }
    }

    /// The combined calls are the two steps they replace: the ones the
    /// trait provides, and the scalar backend's own.
    #[test]
    fn the_default_combined_calls_equal_their_parts() {
        combined_calls_equal_their_parts::<KeystreamOnly>();
        combined_calls_equal_their_parts::<Scalar>();
        // And an AEAD on top of the provided ones is the same AEAD.
        let key = [0x33u8; 32];
        let nonce = nonce_from_counter(7);
        for len in [0usize, 31, 300] {
            let plain = vec![0x5au8; len];
            let mut with_default = vec![0u8; len + TAG_LEN];
            let mut with_scalar = vec![0u8; len + TAG_LEN];
            seal_with::<KeystreamOnly>(&key, &nonce, b"aad", &plain, &mut with_default).unwrap();
            seal_with::<Scalar>(&key, &nonce, b"aad", &plain, &mut with_scalar).unwrap();
            assert_eq!(with_default, with_scalar);
            let n = open_in_place_with::<KeystreamOnly>(&key, &nonce, b"aad", &mut with_default)
                .unwrap();
            assert_eq!(with_default[..n], plain[..]);
        }
    }
}
