//! How fast the in-tree primitives are next to the implementations the
//! differential tests compare them with, on this machine (same compiler
//! flags, one core):
//!
//!   cargo run --release --example crypto_speed
use std::hint::black_box;
use std::time::Instant;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use wireguard_sans_io::crypto::{aead, blake2s, x25519};

fn bench(name: &str, iters: u64, mut f: impl FnMut()) {
    for _ in 0..iters / 10 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = t.elapsed().as_nanos() as f64 / iters as f64;
    println!("{name:<52} {ns:>10.1} ns/op");
}

fn main() {
    let k = [7u8; 32];
    let u = x25519::x25519_base(&[9u8; 32]);
    bench("x25519 (in-tree, variable base)", 20_000, || {
        black_box(x25519::x25519(black_box(&k), black_box(&u)));
    });
    bench(
        "x25519 (x25519-dalek 2 / curve25519-dalek 4)",
        20_000,
        || {
            black_box(x25519_dalek::x25519(black_box(k), black_box(u)));
        },
    );
    bench("x25519 base point (in-tree, table)", 20_000, || {
        black_box(x25519::x25519_base(black_box(&k)));
    });
    bench("x25519 base point (dalek, Edwards table)", 20_000, || {
        let s = x25519_dalek::StaticSecret::from(black_box(k));
        black_box(x25519_dalek::PublicKey::from(&s));
    });
    for len in [64usize, 1424] {
        let mut buf = vec![0u8; len + 16];
        let nonce = [1u8; 12];
        bench(
            &format!("chacha20poly1305 seal {len} B (in-tree scalar)"),
            2_000_000,
            || {
                aead::seal_in_place(&k, &nonce, &[], len, black_box(&mut buf)).unwrap();
            },
        );
        bench(
            &format!("chacha20poly1305 seal {len} B (in-tree + SIMD keystream)"),
            2_000_000,
            || {
                aead::seal_in_place_with::<wireguard_chacha_simd::Best>(
                    &k,
                    &nonce,
                    &[],
                    len,
                    black_box(&mut buf),
                )
                .unwrap();
            },
        );
        let c = chacha20poly1305::ChaCha20Poly1305::new(&k.into());
        let mut data = vec![0u8; len];
        bench(
            &format!("chacha20poly1305 seal {len} B (RustCrypto, AVX2)"),
            2_000_000,
            || {
                black_box(
                    c.encrypt_in_place_detached((&nonce).into(), &[], black_box(&mut data))
                        .unwrap(),
                );
            },
        );
    }
    let msg = [3u8; 116];
    bench("blake2s keyed MAC, 116 B (in-tree)", 3_000_000, || {
        black_box(blake2s::mac(&k, &[black_box(&msg)]));
    });
    use blake2::digest::Mac;
    bench(
        "blake2s keyed MAC, 116 B (RustCrypto blake2)",
        3_000_000,
        || {
            let mut m = <blake2::Blake2sMac<blake2::digest::consts::U16> as blake2::digest::KeyInit>::new_from_slice(&k).unwrap();
            m.update(black_box(&msg));
            black_box(m.finalize().into_bytes());
        },
    );
}
