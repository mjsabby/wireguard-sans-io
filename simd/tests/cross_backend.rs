//! Cross-backend protocol correctness: a `Tunnel<Scalar>` and a
//! `Tunnel<Best>` (= `Avx2x8` on x86_64, `Neon` on aarch64) complete a
//! handshake and exchange transport data in BOTH directions.
//!
//! This is the strongest correctness check the SIMD code can have:
//! it proves byte-for-byte wire-format equivalence with the
//! scalar path through the *entire* protocol stack (handshake, AEAD,
//! padding, replay), not just the keystream in isolation.

use wireguard_chacha_simd::Best;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    ChaChaImpl, Config, Encapsulated, Now, PollOutput, Received, Scalar, StaticSecret, Tunnel,
};

fn now() -> Now {
    Now::new(0, 1_700_000_000, 0)
}

/// Run a full handshake (A initiates) + bidirectional transport at
/// every interesting payload length, with A on backend `CA` and B on
/// backend `CB`.
fn cross_backend_roundtrip<CA: ChaChaImpl, CB: ChaChaImpl>() {
    let mut rng = DeterministicRng::new(0xc0ffee);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();

    let mut a = Tunnel::<CA>::with_backend(Config::new(a_key, b_pub)).unwrap();
    let mut b = Tunnel::<CB>::with_backend(Config::new(b_key, a_pub)).unwrap();

    let (mut wa, mut wb) = ([0u8; 4096], [0u8; 4096]);

    // Handshake: A → init → B → resp → A → keepalive → B.
    let init = match a.encapsulate(now(), b"", &mut wa, &mut rng).unwrap() {
        Encapsulated::HandshakeInitiation(w) => w.to_vec(),
        other => panic!("expected init, got {other:?}"),
    };
    let resp = match b
        .decapsulate(now(), b"r", false, &init, &mut wb, &mut rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("expected resp, got {other:?}"),
    };
    match a
        .decapsulate(now(), b"r", false, &resp, &mut wa, &mut rng)
        .unwrap()
    {
        Received::HandshakeComplete => {}
        other => panic!("expected complete, got {other:?}"),
    }
    let ka = match a.poll(now(), &mut wa, &mut rng).unwrap() {
        PollOutput::Send(w, _) => w.to_vec(),
        other => panic!("expected keepalive, got {other:?}"),
    };
    match b
        .decapsulate(now(), b"r", false, &ka, &mut wb, &mut rng)
        .unwrap()
    {
        Received::Keepalive => {}
        other => panic!("expected keepalive, got {other:?}"),
    }
    assert!(a.is_established() && b.is_established());

    // Transport, both directions, at lengths spanning the SIMD stride
    // seams (4-block = 256, 8-block = 512) and the WireGuard padding
    // boundary (16) and MTUs.
    for len in [
        0usize, 1, 15, 16, 17, 63, 64, 65, 127, 128, 255, 256, 257, 384, 511, 512, 513, 1024, 1280,
        1350, 1420, 2000,
    ] {
        let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();

        // A (CA) encrypts → B (CB) decrypts.
        let wire = match a.encapsulate(now(), &payload, &mut wa, &mut rng).unwrap() {
            Encapsulated::Transport(w) => w.to_vec(),
            other => panic!("len={len}: {other:?}"),
        };
        match b
            .decapsulate(now(), b"r", false, &wire, &mut wb, &mut rng)
            .unwrap()
        {
            Received::Data(d) => {
                assert_eq!(
                    &d[..len],
                    &payload[..],
                    "{}→{} len={len}: payload mismatch",
                    CA::name(),
                    CB::name()
                );
                assert!(
                    d[len..].iter().all(|&b| b == 0),
                    "{}→{} len={len}: non-zero padding",
                    CA::name(),
                    CB::name()
                );
            }
            Received::Keepalive if len == 0 => {}
            other => panic!("{}→{} len={len}: {other:?}", CA::name(), CB::name()),
        }

        // B (CB) encrypts → A (CA) decrypts.
        let wire = match b.encapsulate(now(), &payload, &mut wb, &mut rng).unwrap() {
            Encapsulated::Transport(w) => w.to_vec(),
            other => panic!("len={len}: {other:?}"),
        };
        match a
            .decapsulate(now(), b"r", false, &wire, &mut wa, &mut rng)
            .unwrap()
        {
            Received::Data(d) => {
                assert_eq!(&d[..len], &payload[..]);
                assert!(d[len..].iter().all(|&b| b == 0));
            }
            Received::Keepalive if len == 0 => {}
            other => panic!("{}→{} len={len}: {other:?}", CB::name(), CA::name()),
        }
    }
}

#[test]
fn scalar_to_best() {
    eprintln!("Scalar ↔ {} ({})", Best::name(), std::env::consts::ARCH);
    cross_backend_roundtrip::<Scalar, Best>();
}

#[test]
fn best_to_scalar() {
    cross_backend_roundtrip::<Best, Scalar>();
}

#[test]
fn best_to_best() {
    cross_backend_roundtrip::<Best, Best>();
}

#[cfg(target_arch = "x86_64")]
#[test]
fn avx2_4way_to_8way() {
    use wireguard_chacha_simd::{Avx2, Avx2x8};
    cross_backend_roundtrip::<Avx2, Avx2x8>();
    cross_backend_roundtrip::<Avx2x8, Avx2>();
}

/// Bit-flip storm on `Tunnel<Best>`-encrypted transport: every
/// single-bit corruption must be rejected by `Tunnel<Scalar>` (proves
/// the SIMD path produces correctly-tagged ciphertext, not just
/// "decryptable by itself" ciphertext).
#[test]
fn simd_ciphertext_is_authenticated_by_scalar() {
    let mut rng = DeterministicRng::new(0xfee1dead);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();
    let mut a = Tunnel::<Best>::with_backend(Config::new(a_key, b_pub)).unwrap();
    let mut b = Tunnel::<Scalar>::with_backend(Config::new(b_key, a_pub)).unwrap();

    // Establish.
    let (mut wa, mut wb) = ([0u8; 2048], [0u8; 2048]);
    let init = match a.encapsulate(now(), b"", &mut wa, &mut rng).unwrap() {
        Encapsulated::HandshakeInitiation(w) => w.to_vec(),
        _ => panic!(),
    };
    let resp = match b
        .decapsulate(now(), b"r", false, &init, &mut wb, &mut rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        _ => panic!(),
    };
    a.decapsulate(now(), b"r", false, &resp, &mut wa, &mut rng)
        .unwrap();
    let ka = match a.poll(now(), &mut wa, &mut rng).unwrap() {
        PollOutput::Send(w, _) => w.to_vec(),
        _ => panic!(),
    };
    b.decapsulate(now(), b"r", false, &ka, &mut wb, &mut rng)
        .unwrap();

    // SIMD-encrypted payload; flip every bit; scalar receiver must
    // reject every one and never write the output buffer.
    let wire = match a
        .encapsulate(now(), &[0xab; 200], &mut wa, &mut rng)
        .unwrap()
    {
        Encapsulated::Transport(w) => w.to_vec(),
        _ => panic!(),
    };
    for byte in 0..wire.len() {
        for bit in 0..8 {
            let mut bad = wire.clone();
            bad[byte] ^= 1 << bit;
            let mut out = [0xee; 256];
            let r = b.decapsulate(now(), b"r", false, &bad, &mut out, &mut rng);
            assert!(r.is_err(), "byte {byte} bit {bit} accepted");
            assert!(
                out.iter().all(|&x| x == 0xee),
                "byte {byte} bit {bit}: output dirtied"
            );
        }
    }
    // Pristine still works.
    match b
        .decapsulate(now(), b"r", false, &wire, &mut wb, &mut rng)
        .unwrap()
    {
        Received::Data(d) => assert_eq!(&d[..200], &[0xab; 200]),
        other => panic!("{other:?}"),
    }
}
