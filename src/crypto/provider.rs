//! The cryptographic seam: every primitive the protocol uses, behind one
//! trait.
//!
//! [`crate::Device`] and [`crate::Tunnel`] are generic over a
//! [`CryptoProvider`]. The default, [`InTree`], is this crate's own
//! safe-Rust implementation (no dependencies, no `unsafe`). An embedder who
//! wants an audited, formally verified, or hardware-backed implementation
//! supplies another type and nothing else in the protocol code changes.
//!
//! The seam sits at the level the protocol is specified at — `DH`, `Hash`,
//! `Mac`, `Hmac`, `Aead`, `Xaead` (whitepaper §5.4) — rather than at a
//! cipher's internals, so a provider can use a fused or accelerated AEAD
//! as a unit.

use core::fmt;
use core::marker::PhantomData;

use crate::Error;
use crate::crypto::chacha20::{ChaChaImpl, Scalar};
use crate::crypto::{aead, blake2s, kdf, x25519};

/// The primitives WireGuard is built from (whitepaper §5.4).
///
/// All functions are associated functions: a provider is a type, not a
/// value, so selecting one costs nothing at run time.
///
/// # Contract
///
/// An implementation MUST be byte-for-byte equivalent to the named
/// standard algorithm, MUST NOT panic, and MUST treat keys and
/// Diffie-Hellman inputs in constant time. The verify-then-decrypt rule is
/// part of the contract: [`open_in_place`](Self::open_in_place) and
/// [`xopen_in_place`](Self::xopen_in_place) MUST leave `buf` unchanged when
/// they return `None`.
///
/// # Secret outputs
///
/// The functions whose result can be a secret — [`x25519`](Self::x25519),
/// [`hash`](Self::hash) (the handshake hashes secret input),
/// [`mac`](Self::mac) (a cookie is a MAC) and [`hmac`](Self::hmac) — write
/// it through an `out` parameter instead of returning it: the protocol
/// code points `out` at the one place the value is kept and later wiped,
/// so no second copy is left behind in a return slot. An implementation
/// SHOULD likewise wipe whatever working state of its own held key
/// material.
pub trait CryptoProvider: 'static {
    /// A short name for diagnostics and benchmarks.
    fn name() -> &'static str;

    /// `DH-Generate`'s public half: the X25519 public key for `secret`
    /// (RFC 7748; the scalar is clamped by the function).
    fn x25519_public(secret: &[u8; 32]) -> [u8; 32];

    /// `DH(secret, public)`: X25519 (RFC 7748; the scalar is clamped by the
    /// function), written to `out`. Returns `false` when the result is the
    /// all-zero value — `public` was a low-order point — which callers
    /// must treat as a failure. The comparison with zero must be constant
    /// time.
    #[must_use]
    fn x25519(secret: &[u8; 32], public: &[u8; 32], out: &mut [u8; 32]) -> bool;

    /// `Hash(parts[0] ∥ parts[1] ∥ …)`: BLAKE2s-256 (RFC 7693), written to
    /// `out`.
    fn hash(parts: &[&[u8]], out: &mut [u8; 32]);

    /// `Mac(key, parts[0] ∥ …)`: keyed BLAKE2s with a 16-byte output,
    /// written to `out`. `key` is 32 bytes (`mac1`, cookies) or 16 bytes
    /// (`mac2`).
    fn mac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 16]);

    /// Prepare a 32-byte [`mac`](Self::mac) key that is going to be used
    /// many times: `state` is eight words to fill with whatever makes
    /// [`mac_prepared`](Self::mac_prepared) cheaper than `mac` — for
    /// BLAKE2s, its state after the key block. A provider that has no use
    /// for it leaves both methods as they are.
    ///
    /// The protocol prepares the two `mac1` keys, once each: its own when
    /// a device is created and a peer's when a tunnel is. They are hashes
    /// of public keys, so `state` is not handled as a secret (it is copied
    /// freely and not wiped). Do not put anything into it that would be
    /// one if the key were not.
    fn mac_prepare(key: &[u8; 32], state: &mut [u32; 8]) {
        let _ = (key, state);
    }

    /// `Mac(key, parts[0] ∥ …)` for a key that went through
    /// [`mac_prepare`](Self::mac_prepare), which filled `state`. MUST
    /// write exactly what [`mac`](Self::mac) writes for the same key and
    /// parts — which is what it does unless overridden.
    fn mac_prepared(key: &[u8; 32], state: &[u32; 8], parts: &[&[u8]], out: &mut [u8; 16]) {
        let _ = state;
        Self::mac(key, parts, out);
    }

    /// `Hmac(key, parts[0] ∥ …)`: HMAC (RFC 2104) over BLAKE2s-256, written
    /// to `out`. The `Kdf_n` chain is built from this.
    fn hmac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 32]);

    /// `Aead` encryption, in place: ChaCha20-Poly1305 (RFC 8439) with the
    /// nonce `0³² ∥ LE64(counter)`. Encrypts `buf[..pt_len]` and writes the
    /// 16-byte tag at `buf[pt_len..pt_len + 16]`. Returns `pt_len + 16`.
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] if `buf` is shorter than `pt_len + 16`;
    /// [`Error::MessageTooLong`] if `pt_len` exceeds what RFC 8439 allows
    /// ([`crate::crypto::aead::MAX_MESSAGE_LEN`]) — an implementation must
    /// refuse that, not wrap its block counter.
    fn seal_in_place(
        key: &[u8; 32],
        counter: u64,
        aad: &[u8],
        pt_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error>;

    /// `Aead` decryption, in place. `buf` is `ciphertext ∥ tag`. On success
    /// returns `Some(n)` with the plaintext in `buf[..n]`
    /// (`n = buf.len() − 16`). Returns `None` — with `buf` unchanged — if
    /// `buf` is shorter than a tag or the tag does not verify.
    fn open_in_place(key: &[u8; 32], counter: u64, aad: &[u8], buf: &mut [u8]) -> Option<usize>;

    /// `Xaead` encryption, in place: XChaCha20-Poly1305 with a 24-byte
    /// nonce. Same layout as [`seal_in_place`](Self::seal_in_place).
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] if `buf` is shorter than `pt_len + 16`.
    fn xseal_in_place(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        pt_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error>;

    /// `Xaead` decryption, in place. Same contract as
    /// [`open_in_place`](Self::open_in_place).
    fn xopen_in_place(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Option<usize>;
}

/// The default provider: this crate's own safe-Rust primitives.
///
/// The type parameter selects the ChaCha20 keystream backend used for the
/// AEAD. The default, [`Scalar`], keeps everything inside
/// `#![forbid(unsafe_code)]`; the `wireguard-chacha-simd` crate supplies
/// AVX2 and NEON backends that produce the identical keystream
/// (`InTree<wireguard_chacha_simd::Best>`). Poly1305, BLAKE2s and X25519
/// are always the in-tree scalar code.
///
/// The handshake's AEADs always take the scalar keystream, so handshake
/// secrets never pass through a SIMD backend whatever `C` is. They are
/// the AEADs that have associated data (the transcript hash) and at most
/// [`InTree::<C>::SCALAR_BELOW`] bytes of plaintext (the largest is the
/// 32-byte static key), and that is how they are told from transport
/// data, which has none. Transport packets that small take the scalar
/// keystream too, unless `C` has a kernel for them
/// ([`ChaChaImpl::SMALL_PACKETS`]).
pub struct InTree<C: ChaChaImpl = Scalar>(PhantomData<C>);

impl<C: ChaChaImpl> InTree<C> {
    /// Plaintexts up to this many bytes use the scalar keystream: with
    /// associated data — the handshake's — regardless of `C`, and without
    /// — transport packets — unless `C` asks for them
    /// ([`ChaChaImpl::SMALL_PACKETS`]).
    pub const SCALAR_BELOW: usize = 64;

    /// Is an AEAD over `len` bytes of plaintext with the associated data
    /// `aad` the scalar keystream's?
    fn scalar(aad: &[u8], len: usize) -> bool {
        len <= Self::SCALAR_BELOW && (!C::SMALL_PACKETS || !aad.is_empty())
    }
}

impl<C: ChaChaImpl> fmt::Debug for InTree<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InTree<{}>", C::name())
    }
}

impl<C: ChaChaImpl> Clone for InTree<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: ChaChaImpl> Copy for InTree<C> {}

impl<C: ChaChaImpl> Default for InTree<C> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<C: ChaChaImpl> CryptoProvider for InTree<C> {
    fn name() -> &'static str {
        C::name()
    }

    fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
        x25519::x25519_base(secret)
    }

    fn x25519(secret: &[u8; 32], public: &[u8; 32], out: &mut [u8; 32]) -> bool {
        x25519::shared_secret_into(secret, public, out)
    }

    fn hash(parts: &[&[u8]], out: &mut [u8; 32]) {
        blake2s::hash_into(parts, out);
    }

    fn mac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 16]) {
        blake2s::mac_into(key, parts, out);
    }

    fn mac_prepare(key: &[u8; 32], state: &mut [u32; 8]) {
        blake2s::mac_key_state(key, state);
    }

    fn mac_prepared(key: &[u8; 32], state: &[u32; 8], parts: &[&[u8]], out: &mut [u8; 16]) {
        blake2s::mac_keyed(key, state, parts, out);
    }

    fn hmac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 32]) {
        kdf::hmac_into(key, parts, out);
    }

    fn seal_in_place(
        key: &[u8; 32],
        counter: u64,
        aad: &[u8],
        pt_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        let nonce = aead::nonce_from_counter(counter);
        if Self::scalar(aad, pt_len) {
            aead::seal_in_place(key, &nonce, aad, pt_len, buf)
        } else {
            aead::seal_in_place_with::<C>(key, &nonce, aad, pt_len, buf)
        }
    }

    fn open_in_place(key: &[u8; 32], counter: u64, aad: &[u8], buf: &mut [u8]) -> Option<usize> {
        let nonce = aead::nonce_from_counter(counter);
        if Self::scalar(aad, buf.len().saturating_sub(aead::TAG_LEN)) {
            aead::open_in_place(key, &nonce, aad, buf).ok()
        } else {
            aead::open_in_place_with::<C>(key, &nonce, aad, buf).ok()
        }
    }

    fn xseal_in_place(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        pt_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        // Cookie replies only: 16 bytes of plaintext, always scalar.
        aead::xseal_in_place(key, nonce, aad, pt_len, buf)
    }

    fn xopen_in_place(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Option<usize> {
        aead::xopen_in_place(key, nonce, aad, buf).ok()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use std::vec;

    type P = InTree;

    #[test]
    fn in_tree_provider_is_the_in_tree_primitives() {
        let secret = [7u8; 32];
        let public = P::x25519_public(&[9u8; 32]);
        assert_eq!(P::x25519_public(&secret), x25519::x25519_base(&secret));
        let mut out = [0xeeu8; 32];
        assert!(P::x25519(&secret, &public, &mut out));
        assert_eq!(out, x25519::x25519(&secret, &public));
        // Low-order point: reported as a failure, and `out` is all-zero.
        assert!(!P::x25519(&secret, &[0u8; 32], &mut out));
        assert_eq!(out, [0u8; 32]);
        let mut out = [0xeeu8; 32];
        P::hash(&[b"ab", b"c"], &mut out);
        assert_eq!(out, blake2s::hash(&[b"abc"]));
        let mut tag = [0xeeu8; 16];
        P::mac(&[1u8; 32], &[b"x"], &mut tag);
        assert_eq!(tag, blake2s::mac(&[1u8; 32], &[b"x"]));
        let mut out = [0xeeu8; 32];
        P::hmac(&[1u8; 32], &[b"x"], &mut out);
        assert_eq!(out, kdf::hmac(&[1u8; 32], &[b"x"]));
        assert_eq!(P::name(), "scalar");
    }

    /// A provider that leaves the prepared-key methods alone: `mac` is
    /// what they come down to.
    struct Plain;
    impl CryptoProvider for Plain {
        fn name() -> &'static str {
            "plain"
        }
        fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
            P::x25519_public(secret)
        }
        fn x25519(secret: &[u8; 32], public: &[u8; 32], out: &mut [u8; 32]) -> bool {
            P::x25519(secret, public, out)
        }
        fn hash(parts: &[&[u8]], out: &mut [u8; 32]) {
            P::hash(parts, out);
        }
        fn mac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 16]) {
            P::mac(key, parts, out);
        }
        fn hmac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 32]) {
            P::hmac(key, parts, out);
        }
        fn seal_in_place(
            key: &[u8; 32],
            counter: u64,
            aad: &[u8],
            pt_len: usize,
            buf: &mut [u8],
        ) -> Result<usize, Error> {
            P::seal_in_place(key, counter, aad, pt_len, buf)
        }
        fn open_in_place(
            key: &[u8; 32],
            counter: u64,
            aad: &[u8],
            buf: &mut [u8],
        ) -> Option<usize> {
            P::open_in_place(key, counter, aad, buf)
        }
        fn xseal_in_place(
            key: &[u8; 32],
            nonce: &[u8; 24],
            aad: &[u8],
            pt_len: usize,
            buf: &mut [u8],
        ) -> Result<usize, Error> {
            P::xseal_in_place(key, nonce, aad, pt_len, buf)
        }
        fn xopen_in_place(
            key: &[u8; 32],
            nonce: &[u8; 24],
            aad: &[u8],
            buf: &mut [u8],
        ) -> Option<usize> {
            P::xopen_in_place(key, nonce, aad, buf)
        }
    }

    #[test]
    fn a_prepared_mac_key_is_the_same_mac_with_or_without_a_provider_that_prepares() {
        let key = [0x3cu8; 32];
        for msg in [&b""[..], b"x", &[0x55u8; 60], &[0xaau8; 116], &[1u8; 200]] {
            let mut plain = [0u8; 16];
            P::mac(&key, &[msg], &mut plain);

            // The in-tree provider prepares…
            let mut state = [0u32; 8];
            P::mac_prepare(&key, &mut state);
            assert_ne!(state, [0u32; 8]);
            let mut tag = [0xeeu8; 16];
            P::mac_prepared(&key, &state, &[msg], &mut tag);
            assert_eq!(tag, plain, "len={}", msg.len());

            // …one that does not leaves the state alone and computes the
            // plain MAC.
            let mut untouched = [0u32; 8];
            Plain::mac_prepare(&key, &mut untouched);
            assert_eq!(untouched, [0u32; 8]);
            let mut tag = [0xeeu8; 16];
            Plain::mac_prepared(&key, &untouched, &[msg], &mut tag);
            assert_eq!(tag, plain, "len={}", msg.len());
        }
    }

    #[test]
    fn aead_roundtrip_through_the_provider_at_both_sides_of_the_scalar_cutoff() {
        let key = [0x42u8; 32];
        for len in [0usize, 12, 32, 64, 65, 200, 1420] {
            let pt = vec![0xa5u8; len];
            let mut buf = vec![0u8; len + 16];
            buf[..len].copy_from_slice(&pt);
            assert_eq!(P::seal_in_place(&key, 5, b"h", len, &mut buf), Ok(len + 16));
            // Same bytes as the plain AEAD.
            let mut reference = vec![0u8; len + 16];
            aead::seal(
                &key,
                &aead::nonce_from_counter(5),
                b"h",
                &pt,
                &mut reference,
            )
            .unwrap();
            assert_eq!(buf, reference, "len={len}");
            // Wrong counter: rejected, buffer unchanged.
            let before = buf.clone();
            assert_eq!(P::open_in_place(&key, 6, b"h", &mut buf), None);
            assert_eq!(buf, before);
            assert_eq!(P::open_in_place(&key, 5, b"h", &mut buf), Some(len));
            assert_eq!(&buf[..len], pt.as_slice());
        }
        let mut tiny = [0u8; 8];
        assert_eq!(
            P::seal_in_place(&key, 0, &[], 8, &mut tiny),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn xaead_roundtrip_through_the_provider() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let mut buf = [0u8; 32];
        buf[..16].fill(0x33);
        assert_eq!(
            P::xseal_in_place(&key, &nonce, b"aad", 16, &mut buf),
            Ok(32)
        );
        let sealed = buf;
        assert_eq!(P::xopen_in_place(&key, &nonce, b"aaD", &mut buf), None);
        assert_eq!(buf, sealed);
        assert_eq!(P::xopen_in_place(&key, &nonce, b"aad", &mut buf), Some(16));
        assert_eq!(&buf[..16], &[0x33u8; 16]);
    }
}
