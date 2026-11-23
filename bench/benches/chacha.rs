//! ChaCha20 keystream backends side by side: the scalar code, the AVX2
//! kernel called directly, whatever the CPU has as found at run time
//! (AVX-512, AVX2 or scalar), NEON — all producing the identical RFC 8439
//! keystream — and, as the reference for a whole AEAD, ring (BoringTun's
//! backend) next to this library's AEAD with the best keystream.
//!
//! `cargo bench --bench chacha` (from `bench/`)
//!
//! The `avx2-8way` line exists in a build that enables AVX2 for the whole
//! program (this repository's `.cargo/config.toml` does). `detect` exists
//! in every x86_64 build; on a CPU without AVX-512 it is the same 8-way
//! kernel behind a run-time check, and comparing the two shows what the
//! check costs.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use wireguard_chacha_simd::{Best, ChaChaImpl, Scalar};

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use wireguard_chacha_simd::Avx2x8;
#[cfg(target_arch = "x86_64")]
use wireguard_chacha_simd::Detect;
#[cfg(target_arch = "aarch64")]
use wireguard_chacha_simd::Neon;
use wireguard_sans_io::crypto::aead;

const KEY: [u8; 32] = [0x42; 32];
const NONCE: [u8; 12] = [0x24; 12];

/// ring's raw ChaCha20 is not public, but its ChaCha20-Poly1305 is:
/// `LessSafeKey::seal_in_place_separate_tag`, which is what BoringTun's
/// data path calls. Reported as the `ring-aead` line.
fn ring_chacha20poly1305_seal(buf: &mut [u8]) {
    use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &KEY).unwrap());
    let _tag = key
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(NONCE), Aad::from(&[]), buf)
        .unwrap();
}

fn bench_keystream(c: &mut Criterion) {
    eprintln!("host: {} / Best = {}", std::env::consts::ARCH, Best::name());

    let mut g = c.benchmark_group("chacha20_keystream");
    for &len in &[64usize, 256, 1024, 1280, 1350, 1420, 4096, 16384] {
        g.throughput(Throughput::Bytes(len as u64));

        // Scalar (the safe-Rust core).
        g.bench_with_input(BenchmarkId::new("scalar", len), &len, |b, &len| {
            let mut buf = vec![0u8; len];
            b.iter(|| Scalar::apply_keystream(&KEY, &NONCE, 1, &mut buf));
        });

        // The AVX2 kernel called directly: only in a build that enables
        // AVX2 for the whole program.
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        g.bench_with_input(BenchmarkId::new("avx2-8way", len), &len, |b, &len| {
            let mut buf = vec![0u8; len];
            b.iter(|| Avx2x8::apply_keystream(&KEY, &NONCE, 1, &mut buf));
        });

        // What the CPU has, found when the program runs (any x86_64
        // build): `Detect::name()` says which that is here.
        #[cfg(target_arch = "x86_64")]
        g.bench_with_input(BenchmarkId::new("detect", len), &len, |b, &len| {
            let mut buf = vec![0u8; len];
            b.iter(|| Detect::apply_keystream(&KEY, &NONCE, 1, &mut buf));
        });

        // NEON 4-way (aarch64 only).
        #[cfg(target_arch = "aarch64")]
        g.bench_with_input(BenchmarkId::new("neon-4way", len), &len, |b, &len| {
            let mut buf = vec![0u8; len];
            b.iter(|| Neon::apply_keystream(&KEY, &NONCE, 1, &mut buf));
        });

        // Best: whichever of the above this build selects.
        g.bench_with_input(BenchmarkId::new("best", len), &len, |b, &len| {
            let mut buf = vec![0u8; len];
            b.iter(|| Best::apply_keystream(&KEY, &NONCE, 1, &mut buf));
        });

        // ring's ChaCha20-Poly1305 seal (BoringTun's actual data path).
        // This includes Poly1305 — ring's keystream alone is not a public
        // API — so the line to compare it with is the next one, not the
        // keystreams above.
        g.bench_with_input(BenchmarkId::new("ring-aead", len), &len, |b, &len| {
            let mut buf = vec![0u8; len];
            b.iter(|| ring_chacha20poly1305_seal(&mut buf));
        });

        // This library's ChaCha20-Poly1305 seal with the best keystream:
        // what `wireguard-embed`'s data path calls.
        g.bench_with_input(BenchmarkId::new("aead-best", len), &len, |b, &len| {
            let mut buf = vec![0u8; len + aead::TAG_LEN];
            b.iter(|| aead::seal_in_place_with::<Best>(&KEY, &NONCE, &[], len, &mut buf).unwrap());
        });
    }
    g.finish();
}

criterion_group!(benches, bench_keystream);
criterion_main!(benches);
