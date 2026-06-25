//! Pluggable ChaCha20 keystream backends for [`wireguard_sans_io`].
//!
//! **Hard requirements** — there is no runtime feature detection and
//! no fallback:
//!
//! * `x86_64`: **AVX2 is required.** Build with
//!   `RUSTFLAGS="-C target-feature=+avx2"` (or
//!   `-C target-cpu=x86-64-v3` / `native`). The workspace's
//!   `.cargo/config.toml` sets this by default. Building without it is
//!   a compile error; running the resulting binary on a pre-AVX2 CPU
//!   is therefore impossible.
//! * `aarch64`: NEON is part of the architecture baseline; nothing to
//!   configure.
//! * anything else: [`Best`] = [`Scalar`].
//!
//! | backend | width | arch |
//! |---|---|---|
//! | [`Scalar`] | 1 block | re-export of the core's safe oracle |
//! | [`Avx2`] | 4 blocks | x86_64 (128-bit lanes) |
//! | [`Avx2x8`] | 8 blocks | x86_64 (256-bit lanes — ring-class) |
//! | [`Neon`] | 4 blocks | aarch64 (128-bit is the arch width, incl. SVE2 on Tensor G4) |
//! | [`Best`] | — | `Avx2x8` on x86_64, `Neon` on aarch64, `Scalar` otherwise — pure `cfg`, zero dispatch |
//!
//! All backends are validated against [`Scalar`] on RFC 8439 §2.4.2
//! and on random inputs at every length across the stride boundaries.
//!
//! # Safety boundary
//!
//! `lib.rs` is `#![deny(unsafe_code)]`. The entire `unsafe` surface is
//! `avx2.rs::{four_blocks, eight_blocks}` and `neon.rs::four_blocks`,
//! each taking fixed-size arrays in and writing to a stack `[u8; N]`
//! at fixed offsets. The AVX2 safety obligation ("the CPU has AVX2")
//! is discharged at **compile time** by the `compile_error!` below.

#![deny(unsafe_code)]
// This crate documents arch-conditional backends ([`Neon`] on aarch64,
// [`Avx2`]/[`Avx2x8`] on x86_64); rustdoc only sees one arch at a time,
// so cross-arch intra-doc links are intentionally unresolved on any
// given build host. The links that *do* resolve stay clickable.
#![allow(rustdoc::broken_intra_doc_links)]

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "aarch64")]
mod neon;

#[cfg(target_arch = "x86_64")]
pub use avx2::{Avx2, Avx2x8};
#[cfg(target_arch = "aarch64")]
pub use neon::Neon;

/// Re-export of the core's trait.
pub use wireguard_sans_io::ChaChaImpl;
/// Re-export of the core's safe scalar backend (the correctness oracle).
pub use wireguard_sans_io::Scalar;

// Hard floor: refuse to build on x86_64 without AVX2. This is what
// makes the `unsafe { eight_blocks(...) }` calls sound without a
// runtime check — the binary simply cannot exist for a non-AVX2 CPU.
// `not(doc)`: rustdoc does not inherit `[target.*] rustflags` from
// `.cargo/config.toml`, so `cargo doc` would otherwise trip this even
// in a correctly-configured workspace; rustdoc emits no object code,
// so the safety obligation it discharges does not apply there.
#[cfg(all(target_arch = "x86_64", not(target_feature = "avx2"), not(doc)))]
compile_error!(
    "wireguard-chacha-simd requires AVX2 on x86_64. \
     Build with RUSTFLAGS=\"-C target-feature=+avx2\" \
     (or -C target-cpu=x86-64-v3 / native). \
     The workspace .cargo/config.toml sets this by default."
);

/// The compile-time-selected backend for this target: [`Avx2x8`] on
/// x86_64, [`Neon`] on aarch64, [`Scalar`] otherwise. No `OnceLock`,
/// no fn-pointer, no CPUID — just a `cfg` alias that monomorphises
/// directly into the AEAD.
#[cfg(target_arch = "x86_64")]
pub type Best = Avx2x8;
/// The compile-time-selected backend for this target: [`Avx2x8`] on
/// x86_64, [`Neon`] on aarch64, [`Scalar`] otherwise. No `OnceLock`,
/// no fn-pointer, no CPUID — just a `cfg` alias that monomorphises
/// directly into the AEAD.
#[cfg(target_arch = "aarch64")]
pub type Best = Neon;
/// The compile-time-selected backend for this target: [`Avx2x8`] on
/// x86_64, [`Neon`] on aarch64, [`Scalar`] otherwise. No `OnceLock`,
/// no fn-pointer, no CPUID — just a `cfg` alias that monomorphises
/// directly into the AEAD.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub type Best = Scalar;

// ---------------------------------------------------------------------------
// Shared helpers for the SIMD backends (no unsafe).
// ---------------------------------------------------------------------------

/// ChaCha constants "expand 32-byte k" as four u32 words.
pub(crate) const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Load 8 little-endian u32 key words.
pub(crate) fn key_words(key: &[u8; 32]) -> [u32; 8] {
    let mut w = [0u32; 8];
    for (wi, chunk) in w.iter_mut().zip(key.chunks_exact(4)) {
        *wi = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    w
}

/// Load 3 little-endian u32 nonce words.
pub(crate) fn nonce_words(nonce: &[u8; 12]) -> [u32; 3] {
    let mut w = [0u32; 3];
    for (wi, chunk) in w.iter_mut().zip(nonce.chunks_exact(4)) {
        *wi = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    w
}

/// XOR `ks[..buf.len()]` into `buf` — the partial-tail helper.
#[inline(always)]
pub(crate) fn xor_tail(buf: &mut [u8], ks: &[u8]) {
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn check_rfc8439<C: ChaChaImpl>() {
        let key = rfc_key();
        let nonce: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
        let mut buf = plaintext.to_vec();
        C::apply_keystream(&key, &nonce, 1, &mut buf);
        let mut ref_buf = plaintext.to_vec();
        Scalar::apply_keystream(&key, &nonce, 1, &mut ref_buf);
        assert_eq!(buf, ref_buf, "{}: RFC 8439 §2.4.2 mismatch", C::name());
        C::apply_keystream(&key, &nonce, 1, &mut buf);
        assert_eq!(&buf[..], &plaintext[..]);
    }

    fn check_vs_scalar<C: ChaChaImpl>() {
        let mut state = 0x1234_5678u64;
        let mut next = || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) as u8
        };
        for len in [
            0usize, 1, 63, 64, 65, 127, 128, 191, 192, 255, 256, 257, 300, 383, 384, 511, 512, 513,
            767, 768, 1024, 1280, 1350, 1420, 4096,
        ] {
            let mut key = [0u8; 32];
            key.iter_mut().for_each(|b| *b = next());
            let mut nonce = [0u8; 12];
            nonce.iter_mut().for_each(|b| *b = next());
            let counter = u32::from(next()) | (u32::from(next()) << 8);
            let plain: Vec<u8> = (0..len).map(|_| next()).collect();

            let mut a = plain.clone();
            C::apply_keystream(&key, &nonce, counter, &mut a);
            let mut b = plain.clone();
            Scalar::apply_keystream(&key, &nonce, counter, &mut b);
            assert_eq!(a, b, "{}: mismatch at len={len} ctr={counter}", C::name());
        }
    }

    #[test]
    fn scalar_rfc8439() {
        check_rfc8439::<Scalar>();
    }

    #[test]
    fn best_matches_scalar() {
        check_rfc8439::<Best>();
        check_vs_scalar::<Best>();
        eprintln!("Best = {}", Best::name());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_matches_scalar() {
        check_rfc8439::<Avx2>();
        check_vs_scalar::<Avx2>();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2x8_matches_scalar() {
        check_rfc8439::<Avx2x8>();
        check_vs_scalar::<Avx2x8>();
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn neon_matches_scalar() {
        check_rfc8439::<Neon>();
        check_vs_scalar::<Neon>();
    }
}
