//! Typed key material.
//!
//! Distinct types for static secrets, public keys and pre-shared keys make
//! it impossible to pass one where another is expected. Secret-bearing
//! types redact their `Debug` output and wipe themselves on drop (best
//! effort, see [`crate::crypto::ct::wipe`]).

use core::fmt;

use crate::crypto::x25519;
use crate::crypto::{CryptoProvider, InTree, ct};
use crate::entropy::EntropySource;
use crate::error::Error;

/// Render 32 bytes as lowercase hex (for `PublicKey`'s Debug only —
/// public information by definition).
fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

/// A WireGuard interface's static Curve25519 private key.
#[derive(Clone)]
pub struct StaticSecret([u8; 32]);

impl StaticSecret {
    /// Generate a fresh private key: 32 bytes from `rng`, clamped as RFC
    /// 7748 §5 prescribes (which is bit masking, not a computation any
    /// [`CryptoProvider`] would do differently).
    ///
    /// Nothing of the key is left behind in this function's own frames —
    /// nor, as far as they lie on the stack beneath it, in the entropy
    /// source's. The value itself still travels to wherever the caller
    /// keeps it, and each move leaves the bytes where they were (see
    /// `EMBEDDER_OBLIGATIONS.md` §10).
    ///
    /// # Errors
    /// [`Error::EntropyFailure`] if `rng` fails.
    pub fn generate(rng: &mut dyn EntropySource) -> Result<Self, Error> {
        let mut scrub = ct::ScrubOnDrop::new();
        Self::generate_by_value(rng, scrub.low())
    }

    /// [`Self::generate`]'s work, in a frame that is overwritten once the
    /// key has been handed over.
    #[inline(never)]
    fn generate_by_value(rng: &mut dyn EntropySource, low: &mut usize) -> Result<Self, Error> {
        *low = ct::stack_mark();
        let mut generated = Ok(Self([0u8; 32]));
        let drawn = match &mut generated {
            Ok(secret) => {
                let drawn = rng.fill(&mut secret.0);
                x25519::clamp_in_place(&mut secret.0);
                drawn
            }
            Err(_) => Ok(()),
        };
        if drawn.is_err() {
            // Dropping what was there wipes whatever the source wrote.
            generated = Err(Error::EntropyFailure);
        }
        generated
    }

    /// Wrap an existing 32-byte private key (e.g. from `wg genkey`).
    /// Clamping is applied internally wherever the key is used, so both
    /// clamped and unclamped encodings work.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The corresponding public key, computed with the in-tree X25519.
    ///
    /// A key on its own knows no [`CryptoProvider`]. Where the scalar
    /// multiplication has to be the provider's — the reason for having one
    /// may be exactly that — use [`StaticSecret::public_key_with`], or
    /// read the key from the device ([`crate::Device::public_key`], which
    /// asks its provider).
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.public_key_with::<InTree>()
    }

    /// The corresponding public key, computed by the provider `P`.
    #[must_use]
    pub fn public_key_with<P: CryptoProvider>(&self) -> PublicKey {
        PublicKey(P::x25519_public(&self.0))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// No key: what a key that is about to be [`set`](Self::set) starts
    /// as.
    pub(crate) const BLANK: Self = Self([0u8; 32]);

    /// Make this key a copy of `other`, byte by byte and in place: the
    /// way a key gets into a [`crate::Device`] or a [`crate::Tunnel`]
    /// without a copy of it being made on the way.
    pub(crate) fn set(&mut self, other: &Self) {
        ct::copy_secret(&mut self.0, &other.0);
    }
}

impl From<[u8; 32]> for StaticSecret {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for StaticSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StaticSecret(REDACTED)")
    }
}

impl Drop for StaticSecret {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.0);
    }
}

/// A peer's static Curve25519 public key.
///
/// Public keys are what a peer table is keyed by (see
/// [`crate::Device::identify`]), so they hash and order like the 32 bytes
/// they are. None of that is constant time, and need not be: the key is
/// public.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wrap an existing 32-byte public key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

/// An optional pre-shared 256-bit key (whitepaper §5.2).
///
/// The all-zero default is exactly the protocol's "no PSK" mode (`Q = 0³²`).
#[derive(Clone, Default)]
pub struct PresharedKey([u8; 32]);

impl PresharedKey {
    /// Wrap an existing 32-byte pre-shared key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh random PSK (the `wg genpsk` operation).
    ///
    /// # Errors
    /// [`Error::EntropyFailure`] if `rng` fails.
    pub fn generate(rng: &mut dyn EntropySource) -> Result<Self, Error> {
        // As `StaticSecret::generate`.
        let mut scrub = ct::ScrubOnDrop::new();
        Self::generate_by_value(rng, scrub.low())
    }

    #[inline(never)]
    fn generate_by_value(rng: &mut dyn EntropySource, low: &mut usize) -> Result<Self, Error> {
        *low = ct::stack_mark();
        let mut generated = Ok(Self([0u8; 32]));
        let drawn = match &mut generated {
            Ok(key) => rng.fill(&mut key.0),
            Err(_) => Ok(()),
        };
        if drawn.is_err() {
            generated = Err(Error::EntropyFailure);
        }
        generated
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// No key (the protocol's "no PSK").
    pub(crate) const BLANK: Self = Self([0u8; 32]);

    /// Make this key a copy of `other`, byte by byte and in place.
    pub(crate) fn set(&mut self, other: &Self) {
        ct::copy_secret(&mut self.0, &other.0);
    }
}

impl From<[u8; 32]> for PresharedKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresharedKey(REDACTED)")
    }
}

impl Drop for PresharedKey {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::testing::{DeterministicRng, FailingRng};
    use std::format;

    #[test]
    fn public_key_derivation_matches_rfc7748() {
        // RFC 7748 §6.1 Alice keypair.
        let secret = StaticSecret::from_bytes([
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ]);
        let public = secret.public_key();
        assert_eq!(
            public.as_bytes(),
            &[
                0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
                0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
                0xaa, 0x9b, 0x4e, 0x6a
            ]
        );
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let mut rng = DeterministicRng::new(7);
        let secret = StaticSecret::generate(&mut rng).unwrap();
        let psk = PresharedKey::generate(&mut rng).unwrap();
        assert_eq!(format!("{secret:?}"), "StaticSecret(REDACTED)");
        assert_eq!(format!("{psk:?}"), "PresharedKey(REDACTED)");
        // Public keys are not secret and print fully.
        let rendered = format!("{:?}", secret.public_key());
        assert!(rendered.starts_with("PublicKey(") && rendered.len() > 70);
    }

    #[test]
    fn generation_uses_and_propagates_entropy() {
        let mut rng = DeterministicRng::new(7);
        let a = StaticSecret::generate(&mut rng).unwrap();
        let b = StaticSecret::generate(&mut rng).unwrap();
        assert_ne!(a.public_key(), b.public_key());
        assert_eq!(
            StaticSecret::generate(&mut FailingRng).map(|_| ()),
            Err(Error::EntropyFailure)
        );
        assert_eq!(
            PresharedKey::generate(&mut FailingRng).map(|_| ()),
            Err(Error::EntropyFailure)
        );
    }

    /// A source that fails after writing part of what it was asked for
    /// gives no key — and what it wrote is not handed out.
    #[test]
    fn a_failed_draw_gives_no_key() {
        struct HalfThenFail;
        impl EntropySource for HalfThenFail {
            fn fill(&mut self, buf: &mut [u8]) -> Result<(), crate::EntropyError> {
                let half = buf.len() / 2;
                for b in buf.iter_mut().take(half) {
                    *b = 0xee;
                }
                Err(crate::EntropyError)
            }
        }
        assert!(matches!(
            StaticSecret::generate(&mut HalfThenFail),
            Err(Error::EntropyFailure)
        ));
        assert!(matches!(
            PresharedKey::generate(&mut HalfThenFail),
            Err(Error::EntropyFailure)
        ));
    }

    #[test]
    fn generated_keys_are_clamped_and_set_copies_them() {
        let mut rng = DeterministicRng::new(9);
        for _ in 0..16 {
            let secret = StaticSecret::generate(&mut rng).unwrap();
            let bytes = *secret.as_bytes();
            assert_eq!(bytes, x25519::clamp_scalar(bytes));
            let mut copy = StaticSecret::BLANK;
            copy.set(&secret);
            assert_eq!(copy.as_bytes(), &bytes);
        }
        // The same bytes the source hands out, in the same order as
        // before: 32 for a key, 32 for a pre-shared key.
        let mut a = DeterministicRng::new(10);
        let mut b = DeterministicRng::new(10);
        let secret = StaticSecret::generate(&mut a).unwrap();
        let psk = PresharedKey::generate(&mut a).unwrap();
        let (first, second) = (b.gen32().unwrap(), b.gen32().unwrap());
        assert_eq!(secret.as_bytes(), &x25519::clamp_scalar(first));
        assert_eq!(psk.as_bytes(), &second);
        let mut copy = PresharedKey::BLANK;
        copy.set(&psk);
        assert_eq!(copy.as_bytes(), &second);
    }

    #[test]
    fn default_psk_is_all_zero() {
        assert_eq!(PresharedKey::default().as_bytes(), &[0u8; 32]);
    }
}
