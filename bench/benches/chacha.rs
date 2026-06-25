//! ChaCha20 keystream backend shoot-out: scalar vs AVX2-4way vs
//! NEON-4way vs ring (BoringTun's backend), all producing the identical
//! RFC 8439 keystream.
//!
//! `cargo bench -p wireguard-bench --bench chacha`

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use wireguard_chacha_simd::{Best, ChaChaImpl, Scalar};

#[cfg(target_arch = "aarch64")]
use wireguard_chacha_simd::Neon;
#[cfg(target_arch = "x86_64")]
use wireguard_chacha_simd::{Avx2, Avx2x8};

const KEY: [u8; 32] = [0x42; 32];
const NONCE: [u8; 12] = [0x24; 12];

/// ring's raw ChaCha20 isn't public, but its ChaCha20-Poly1305 is — and
/// for an apples-to-apples *keystream* number we can subtract the
/// Poly1305 cost. Simpler and fairer: just benchmark ring's
/// `LessSafeKey::seal_in_place_separate_tag` (what BoringTun's data path
/// actually calls) and report it as the "ring (AEAD)" reference line.
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

        // AVX2 4-way and 8-way (x86_64; AVX2 is a build requirement).
        #[cfg(target_arch = "x86_64")]
        {
            g.bench_with_input(BenchmarkId::new("avx2-4way", len), &len, |b, &len| {
                let mut buf = vec![0u8; len];
                b.iter(|| Avx2::apply_keystream(&KEY, &NONCE, 1, &mut buf));
            });
            g.bench_with_input(BenchmarkId::new("avx2-8way", len), &len, |b, &len| {
                let mut buf = vec![0u8; len];
                b.iter(|| Avx2x8::apply_keystream(&KEY, &NONCE, 1, &mut buf));
            });
        }

        // NEON 4-way (aarch64 only).
        #[cfg(target_arch = "aarch64")]
        g.bench_with_input(BenchmarkId::new("neon-4way", len), &len, |b, &len| {
            let mut buf = vec![0u8; len];
            b.iter(|| Neon::apply_keystream(&KEY, &NONCE, 1, &mut buf));
        });

        // Best (runtime dispatch — should equal the SIMD line above).
        g.bench_with_input(BenchmarkId::new("best", len), &len, |b, &len| {
            let mut buf = vec![0u8; len];
            b.iter(|| Best::apply_keystream(&KEY, &NONCE, 1, &mut buf));
        });

        // ring's ChaCha20-Poly1305 seal (BoringTun's actual data path).
        // This includes Poly1305, so it's a slight handicap for ring —
        // but it's the number that matters for the WireGuard transport
        // gap, and ring's keystream alone isn't a public API.
        g.bench_with_input(BenchmarkId::new("ring-aead", len), &len, |b, &len| {
            let mut buf = vec![0u8; len];
            b.iter(|| ring_chacha20poly1305_seal(&mut buf));
        });
    }
    g.finish();
}

criterion_group!(benches, bench_keystream);
criterion_main!(benches);
