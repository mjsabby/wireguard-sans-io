//! Pluggable ChaCha20 keystream backends for [`wireguard_sans_io`].
//!
//! | backend | blocks per stride | where |
//! |---|---|---|
//! | [`Scalar`] | 1 | everywhere: re-export of the core's safe oracle |
//! | [`Avx2x8`] | 8 | x86_64 builds with AVX2 enabled for the whole program |
//! | [`Detect`] | 32, 8 or 1 | x86_64, any build: the AVX-512 kernels, the AVX2 kernel or `Scalar`, as the CPU allows |
//! | [`Neon`] | 4 | aarch64 |
//! | [`Best`] | — | see below |
//!
//! All backends are validated against [`Scalar`] — the keystream at every
//! length across the stride boundaries, and the combined calls an AEAD
//! makes ([`ChaChaImpl::seal_keystream`], [`ChaChaImpl::open_keystream`])
//! including the one-time key they hand out — and `Scalar` against RFC
//! 8439 §2.4.2.
//!
//! # What [`Best`] is
//!
//! * `x86_64`: [`Detect`], which asks the CPU when the program runs. One
//!   build runs on every x86_64 CPU and uses the widest keystream there
//!   is: AVX-512 (two interleaved sixteen-block states; needs Rust 1.89
//!   to build, and a CPU from the generations that keep their clock for
//!   512-bit code), AVX2, or the scalar code. A check costs a cached flag
//!   per call; there is none for a feature the build already requires.
//! * `aarch64`: [`Neon`]; NEON is part of the architecture baseline.
//! * anything else: [`Scalar`].
//!
//! [`Avx2x8`] is the AVX2 kernel without any check, for a program that
//! is built for AVX2 and wants exactly that.
//!
//! # Secrets
//!
//! A backend sees the cipher key. What it unpacks of it and every stack
//! buffer that held keystream are zeroed before a call returns — and so
//! is the stack frame of the kernel itself. A kernel keeps the cipher
//! state in vector registers, and there are never quite enough of them:
//! the compiler parks some in the kernel's frame, words of the key among
//! them (the same word in every lane), and words of keystream. No
//! statement in the kernel can name those slots; its caller overwrites
//! the whole frame once the last stride is done (`clear_frames`).
//! `scripts/check_secret_residue.sh` searches the stack for the key and
//! the keystream word by word after calls of every backend that runs on
//! the machine it is run on. What is in the registers themselves when a
//! call returns stays there until the next vector code overwrites it.
//!
//! # Safety boundary
//!
//! `lib.rs` is `#![deny(unsafe_code)]`. The entire `unsafe` surface is in
//! `avx2.rs`, `avx512.rs` and `neon.rs`: the block kernels, each taking
//! fixed-size arrays and reading and writing them at fixed offsets, and
//! the calls into them. What makes a call sound is stated at each one:
//! the target feature enabled for the build (`cfg`), or found by a check
//! on the line before.

#![deny(unsafe_code)]
// This crate documents arch-conditional backends ([`Neon`] on aarch64,
// [`Avx2x8`]/[`Detect`] on x86_64); rustdoc only sees one arch (and one
// set of target features) at a time, so some intra-doc links are
// intentionally unresolved on any given build. The links that *do*
// resolve stay clickable.
#![allow(rustdoc::broken_intra_doc_links)]

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(all(target_arch = "x86_64", wg_avx512))]
mod avx512;
#[cfg(target_arch = "aarch64")]
mod neon;

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub use avx2::Avx2x8;
#[cfg(target_arch = "x86_64")]
pub use avx2::Detect;
#[cfg(target_arch = "aarch64")]
pub use neon::Neon;

/// Re-export of the core's trait.
pub use wireguard_sans_io::ChaChaImpl;
/// Re-export of the core's safe scalar backend (the correctness oracle).
pub use wireguard_sans_io::Scalar;

/// The best backend for this target (see the crate documentation):
/// [`Detect`] here, which asks the CPU.
#[cfg(target_arch = "x86_64")]
pub type Best = Detect;
/// The best backend for this target (see the crate documentation):
/// [`Neon`] here, a plain `cfg` alias.
#[cfg(target_arch = "aarch64")]
pub type Best = Neon;
/// The best backend for this target (see the crate documentation):
/// [`Scalar`] here.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub type Best = Scalar;

// ---------------------------------------------------------------------------
// Shared helpers for the SIMD backends (no unsafe).
// ---------------------------------------------------------------------------

/// ChaCha constants "expand 32-byte k" as four u32 words.
pub(crate) const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Load the key into `kw` as eight little-endian words. In place — the
/// caller wipes `kw`, and there is no second array that held them on the
/// way (a function that returned the words would have one).
#[inline(always)]
pub(crate) fn load_key_words(key: &[u8; 32], kw: &mut [u32; 8]) {
    for (wi, chunk) in kw.iter_mut().zip(key.chunks_exact(4)) {
        *wi = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
}

/// Load 3 little-endian u32 nonce words.
pub(crate) fn nonce_words(nonce: &[u8; 12]) -> [u32; 3] {
    let mut w = [0u32; 3];
    for (wi, chunk) in w.iter_mut().zip(nonce.chunks_exact(4)) {
        *wi = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    w
}

/// Overwrite the stack that keystream kernels have used: everything from
/// just beneath the caller's frame down to `low`, the lowest
/// [`ct::stack_mark`] a kernel took (`usize::MAX`: no kernel ran, nothing
/// to do).
///
/// The kernels are never inlined, so the registers they park — see the
/// crate documentation — lie in frames of their own beneath the function
/// that called them, and that function calls this one next: a function
/// whose own frame is `WORDS` 64-bit words of zeros, in the same place.
/// `WORDS` is chosen per backend to cover its kernels' frames in an
/// optimised build, with room to spare. Should a kernel's frame reach
/// deeper than that all the same — another compiler — `low` says so, and
/// the core's self-sizing scrub does the rest, more slowly.
///
/// In a build with `opt-level` 0 or 1 it is the core's scrub from the
/// start ([`scrub_deep`]).
///
/// [`ct::stack_mark`]: wireguard_sans_io::crypto::ct::stack_mark
#[inline(always)]
pub(crate) fn clear_frames<const WORDS: usize>(low: usize) {
    if low != usize::MAX {
        #[cfg(not(wg_low_opt))]
        clear_frames_now::<WORDS>(low);
        #[cfg(wg_low_opt)]
        scrub_deep(low);
    }
}

/// [`clear_frames`] in a build with `opt-level` 0 or 1. There the
/// compiler does not inline the vector intrinsics: each is a call, with a
/// frame beneath the kernel's that `low` knows nothing of, and a
/// kernel's own frame is several times the size it has in an optimised
/// build. So the core's scrub overwrites everything from the caller's
/// frame down to [`BELOW_KERNEL`] bytes beneath `low` — slowly, in a
/// build that is not about speed. (Always inlined: the scrub has to start
/// right beneath the function that called the kernel.) That covers
/// `opt-level = 1`. Without any optimisation the kernels' frames are
/// tens of kilobytes, more than the scrub will overwrite.
#[cfg(wg_low_opt)]
#[inline(always)]
pub(crate) fn scrub_deep(low: usize) {
    wireguard_sans_io::crypto::ct::scrub_stack_to(low.saturating_sub(BELOW_KERNEL));
}

/// How far beneath a kernel's frame [`scrub_deep`] reaches: the frames
/// of intrinsics that were not inlined.
#[cfg(wg_low_opt)]
const BELOW_KERNEL: usize = 8 * 1024;

#[cfg(not(wg_low_opt))]
#[inline(never)]
fn clear_frames_now<const WORDS: usize>(low: usize) {
    let frame = [0u64; WORDS];
    let lowest = core::ptr::from_ref(core::hint::black_box(&frame)) as usize;
    clear_below(low, lowest);
}

/// The rest of [`clear_frames`], for a function whose frame of zeros
/// starts at the address `lowest`: if the kernels went deeper than that,
/// the core's scrub overwrites what is left.
#[cfg(not(wg_low_opt))]
#[inline]
pub(crate) fn clear_below(low: usize, lowest: usize) {
    if low < lowest {
        #[cfg(test)]
        tests::SLOW_CLEARS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        wireguard_sans_io::crypto::ct::scrub_stack_to(low);
    }
}

/// XOR `ks[..buf.len()]` into `buf` — the partial-tail helper.
#[inline(always)]
pub(crate) fn xor_tail(buf: &mut [u8], ks: &[u8]) {
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
}

/// What every backend has to pass, for the tests here and in the
/// backends' own modules.
#[cfg(test)]
pub(crate) mod check {
    use super::*;

    pub(crate) fn rfc_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    /// RFC 8439 §2.4.2, by way of the scalar code (which a test below
    /// holds to the RFC's own bytes).
    pub(crate) fn rfc8439<C: ChaChaImpl>() {
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

    /// Deterministic bytes.
    fn stream(seed: u64) -> impl FnMut() -> u8 {
        let mut state = seed;
        move || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) as u8
        }
    }

    /// Every length up to a 32-block stride and a tail — which is every
    /// combination of stride and tail any backend distinguishes, on both
    /// sides of each boundary — the sizes of real packets, and longer
    /// buffers that take several strides.
    pub(crate) fn lengths() -> impl Iterator<Item = usize> {
        (0usize..=2300).chain([4096, 4097, 4096 + 129, 6143, 6144, 6145, 9000, 65_536 + 77])
    }

    /// The keystream, from an arbitrary block counter — including
    /// counters that wrap inside a stride.
    pub(crate) fn vs_scalar<C: ChaChaImpl>() {
        let mut next = stream(0x1234_5678);
        for len in lengths() {
            let mut key = [0u8; 32];
            key.iter_mut().for_each(|b| *b = next());
            let mut nonce = [0u8; 12];
            nonce.iter_mut().for_each(|b| *b = next());
            let counter = match len % 5 {
                0 => u32::MAX - u32::from(next() % 40),
                1 => u32::from(next()),
                _ => u32::from_le_bytes([next(), next(), next(), next()]),
            };
            let plain: Vec<u8> = (0..len).map(|_| next()).collect();

            let mut a = plain.clone();
            C::apply_keystream(&key, &nonce, counter, &mut a);
            let mut b = plain.clone();
            Scalar::apply_keystream(&key, &nonce, counter, &mut b);
            assert!(a == b, "{}: mismatch at len={len} ctr={counter}", C::name());
        }
    }

    /// The combined calls of an AEAD: the one-time key is the first half
    /// of block 0, the stream starts at block 1, an open shows the
    /// ciphertext to `verify`, decrypts only on `true` and otherwise
    /// leaves the buffer as it was.
    pub(crate) fn combined_calls<C: ChaChaImpl>() {
        let mut next = stream(0xfeed_f00d);
        for len in lengths() {
            let mut key = [0u8; 32];
            key.iter_mut().for_each(|b| *b = next());
            let mut nonce = [0u8; 12];
            nonce.iter_mut().for_each(|b| *b = next());
            let plain: Vec<u8> = (0..len).map(|_| next()).collect();
            let block0 = wireguard_sans_io::crypto::chacha20::block(&key, 0, &nonce);

            let mut sealed = plain.clone();
            let mut otk = [0xeeu8; 32];
            C::seal_keystream(&key, &nonce, &mut sealed, &mut otk);
            assert!(
                otk[..] == block0[..32],
                "{}: one-time key at len={len}",
                C::name()
            );
            let mut want = plain.clone();
            Scalar::apply_keystream(&key, &nonce, 1, &mut want);
            assert!(sealed == want, "{}: sealed stream at len={len}", C::name());

            let mut seen = [0u8; 32];
            let mut opened = sealed.clone();
            assert!(C::open_keystream(&key, &nonce, &mut opened, |otk, ct| {
                seen = *otk;
                ct == &sealed[..]
            }));
            assert!(
                seen[..] == block0[..32],
                "{}: key shown to verify at len={len}",
                C::name()
            );
            assert!(opened == plain, "{}: opened at len={len}", C::name());

            let mut refused = sealed.clone();
            assert!(!C::open_keystream(&key, &nonce, &mut refused, |_, _| false));
            assert!(
                refused == sealed,
                "{}: a refused open touched the buffer, len={len}",
                C::name()
            );
        }
    }

    pub(crate) fn all<C: ChaChaImpl>() {
        rfc8439::<C>();
        vs_scalar::<C>();
        combined_calls::<C>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// How often [`clear_frames`] found a kernel's frame deeper than the
    /// one it overwrites at once, and had the core's scrub do the rest.
    pub(crate) static SLOW_CLEARS: AtomicUsize = AtomicUsize::new(0);

    /// In an optimised build — the only kind this crate is for — the
    /// frame `clear_frames` overwrites at once covers the kernels of
    /// every backend here, at every length. (A build with `opt-level` 0
    /// or 1 takes the slow way on purpose, and counts nothing.)
    #[test]
    fn kernel_frames_are_cleared_in_one_go() {
        check::all::<Best>();
        #[cfg(target_arch = "x86_64")]
        check::all::<Detect>();
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        check::all::<Avx2x8>();
        assert_eq!(SLOW_CLEARS.load(Ordering::Relaxed), 0);
    }

    /// The scalar backend against the RFC itself (§2.4.2) — it is what
    /// every other backend is compared with, so it has to be right by
    /// something other than its own word.
    #[test]
    fn scalar_rfc8439() {
        let key = check::rfc_key();
        let nonce: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut buf = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it."
            .to_vec();
        Scalar::apply_keystream(&key, &nonce, 1, &mut buf);
        let expected = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d";
        let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
        check::all::<Scalar>();
    }

    #[test]
    fn best_matches_scalar() {
        check::all::<Best>();
        eprintln!("Best = {}", Best::name());
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    #[test]
    fn avx2x8_matches_scalar() {
        check::all::<Avx2x8>();
    }

    /// The run-time choice: right whichever way it goes on this CPU, and
    /// its name says which way that was.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn detect_matches_scalar() {
        check::all::<Detect>();
        let expected = if Detect::avx512_in_use() {
            "avx512-16/32way (detected)"
        } else if Detect::avx2_available() {
            "avx2-8way (detected)"
        } else {
            "scalar (no avx2)"
        };
        assert_eq!(Detect::name(), expected);
        eprintln!("Detect = {}", Detect::name());
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn neon_matches_scalar() {
        check::all::<Neon>();
    }
}
