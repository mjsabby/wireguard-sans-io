//! Does the path a function takes through its code depend on a secret?
//!
//! `scripts/check_constant_flow.sh` runs this program under an emulator
//! that counts the basic blocks it executes, once per secret, and
//! compares the counts: a function whose branches do not depend on the
//! secret executes the same blocks whatever the secret is. Unlike a
//! timing measurement this is exact and repeatable — one block more shows
//! — and it does not care how busy the machine is.
//!
//! ```text
//! constant_flow <operation> <n>     n = 0..: which secret
//! constant_flow list                the operations
//! ```
//!
//! What it shows and what it does not: control flow. A function can take
//! the same path and still take different time — through an instruction
//! whose duration depends on its operands (a division; a multiplication
//! on some small processors: see `src/crypto/mod.rs`), or through memory
//! it reads at a secret-dependent address. Neither occurs in the code
//! measured here on the targets this is run for, but neither is what this
//! program would find.
//!
//! Every operation is run with the secret computed the same way, so that
//! the difference between two runs is the operation's alone; the
//! operation `none` computes the secret and does nothing with it.

use std::hint::black_box;
use std::net::SocketAddr;

use wireguard_chacha_simd::Best;
use wireguard_probes::Recorded;
use wireguard_sans_io::crypto::{aead, blake2s, chacha20, ct, kdf, poly1305, siphash, x25519};
use wireguard_sans_io::{
    ChaChaImpl, Device, Incoming, PeerConfig, PeerId, PollOutput, PresharedKey, Received,
    StaticSecret, Ticks, Tunnel, WallClock,
};

/// Secret number `n`, `len` bytes of it: the extremes first (all zero,
/// all one, the two alternating patterns), then pseudo-random strings.
///
/// Made the same way whichever it is — no branch here depends on `n` —
/// so that what differs between two runs is only what the operation does
/// with it.
fn secret(n: u64, len: usize) -> Vec<u8> {
    const PATTERNS: [u8; 4] = [0x00, 0xff, 0x55, 0xaa];
    // All ones for a pseudo-random secret, zero for one of the patterns.
    let random = 0u8.wrapping_sub(u8::from(n >= 4));
    let pattern = PATTERNS[(n & 3) as usize] & !random;
    let mut state = n.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            // (Behind `black_box`: an optimiser that sees `random` is a
            // constant for the whole loop writes two loops, one for each
            // kind of secret — which is a branch on the kind.)
            ((state >> 56) as u8 & black_box(random)) | black_box(pattern)
        })
        .collect()
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes[..N].try_into().unwrap()
}

/// Something public, the same in every run.
fn public<const N: usize>(tag: u8) -> [u8; N] {
    core::array::from_fn(|i| tag ^ (i as u8).wrapping_mul(37))
}

/// The operations: name, what is secret in it, and the code.
type Operation = (&'static str, &'static str, fn(u64));

const OPERATIONS: &[Operation] = &[
    ("none", "nothing: the baseline", |_| {}),
    // ---- the controls: these MUST depend on the secret --------------------
    (
        "control-early-exit",
        "CONTROL (must vary): a comparison that stops at the first difference",
        |n| {
            let a = public::<32>(1);
            let mut b = a;
            b[(n as usize * 5) % 32] ^= 1;
            let mut equal = true;
            for (x, y) in a.iter().zip(b.iter()) {
                if black_box(*x) != black_box(*y) {
                    equal = false;
                    break;
                }
            }
            black_box(equal);
        },
    ),
    (
        "control-branch-on-bits",
        "CONTROL (must vary): a loop that branches on each bit of the secret",
        |n| {
            let key = secret(n, 32);
            let mut acc = 1u64;
            for byte in &key {
                for bit in 0..8 {
                    acc = acc.wrapping_mul(acc);
                    if black_box(byte >> bit) & 1 == 1 {
                        acc = black_box(acc).wrapping_mul(3);
                    }
                }
            }
            black_box(acc);
        },
    ),
    // ---- curve ---------------------------------------------------------------
    ("x25519", "the scalar", |n| {
        let mut out = [0u8; 32];
        x25519::x25519_into(
            &array(&secret(n, 32)),
            &x25519::x25519_base(&public(2)),
            &mut out,
        );
        black_box(out);
    }),
    (
        "x25519-base",
        "the scalar (the public key of a private key)",
        |n| {
            black_box(x25519::x25519_base(&array(&secret(n, 32))));
        },
    ),
    (
        "shared-secret",
        "the scalar, and whether the result is all zero",
        |n| {
            // The peer's "public key" is the secret's choice too: zero (the
            // result is then all zero, and refused), a point of low order
            // (the same), or a real one. Chosen without a branch.
            let real = x25519::x25519_base(&public(3));
            let keep = 0u8.wrapping_sub(u8::from(n % 3 == 2));
            let mut peer: [u8; 32] = real.map(|byte| byte & keep);
            peer[0] |= u8::from(n % 3 == 1);
            let mut out = [0u8; 32];
            black_box(x25519::shared_secret_into(
                &array(&secret(n, 32)),
                &peer,
                &mut out,
            ));
        },
    ),
    // ---- symmetric primitives ---------------------------------------------------
    ("chacha20", "the key", |n| {
        let mut data = public::<200>(4);
        chacha20::xor_in_place(&array(&secret(n, 32)), 1, &public(5), &mut data);
        black_box(data);
    }),
    (
        "chacha20-simd",
        "the key (the keystream `wireguard-embed` uses)",
        |n| {
            let mut data = public::<1400>(4);
            Best::apply_keystream(&array(&secret(n, 32)), &public(5), 1, &mut data);
            black_box(data);
        },
    ),
    ("poly1305-key", "the one-time key", |n| {
        black_box(poly1305::poly1305(
            &array(&secret(n, 32)),
            &public::<100>(6),
        ));
    }),
    ("poly1305-message", "the message", |n| {
        black_box(poly1305::poly1305(&public(7), &secret(n, 100)));
    }),
    ("blake2s", "the message", |n| {
        black_box(blake2s::hash(&[&secret(n, 100)]));
    }),
    ("blake2s-mac", "the key", |n| {
        black_box(blake2s::mac(&secret(n, 32), &[&public::<116>(8)]));
    }),
    ("hmac", "the key and the message", |n| {
        black_box(kdf::hmac(&secret(n, 32), &[&secret(n + 100, 32)]));
    }),
    ("kdf3", "the chaining key and the input", |n| {
        black_box(kdf::kdf3(&array(&secret(n, 32)), &secret(n + 100, 32)));
    }),
    ("siphash", "the key", |n| {
        let key: [u8; 16] = array(&secret(n, 16));
        black_box(siphash::siphash24(&key, &public::<9>(9)));
        black_box(siphash::siphash24_3(siphash::key_words(&key), [1, 2, 3]));
    }),
    // ---- the AEAD ------------------------------------------------------------------
    ("aead-seal", "the key and the plaintext", |n| {
        let mut out = [0u8; 116];
        aead::seal(
            &array(&secret(n, 32)),
            &public(10),
            &public::<32>(11),
            &secret(n + 100, 100),
            &mut out,
        )
        .unwrap();
        black_box(out);
    }),
    ("aead-open", "the key and the plaintext", |n| {
        let key: [u8; 32] = array(&secret(n, 32));
        let mut sealed = [0u8; 116];
        aead::seal(&key, &public(10), &[], &secret(n + 100, 100), &mut sealed).unwrap();
        let mut opened = [0u8; 100];
        aead::open(&key, &public(10), &[], &sealed, &mut opened).unwrap();
        black_box(opened);
    }),
    (
        "aead-open-forged",
        "where a forged tag differs from the right one",
        |n| {
            let key = public::<32>(12);
            let mut sealed = [0u8; 116];
            aead::seal(&key, &public(10), &[], &public::<100>(13), &mut sealed).unwrap();
            // One byte of the tag wrong: which one is the "secret" (the
            // right tag is what the forger is after).
            sealed[100 + (n as usize * 5) % 16] ^= 0x40;
            let mut opened = [0u8; 100];
            black_box(aead::open(&key, &public(10), &[], &sealed, &mut opened).is_err());
        },
    ),
    (
        "aead-open-forged-simd",
        "the same, in place, with the SIMD keystream",
        |n| {
            let key = public::<32>(12);
            let mut buf = [0u8; 1416];
            aead::seal_in_place_with::<Best>(&key, &public(10), &[], 1400, &mut buf).unwrap();
            buf[1400 + (n as usize * 5) % 16] ^= 0x40;
            black_box(aead::open_in_place_with::<Best>(&key, &public(10), &[], &mut buf).is_err());
        },
    ),
    // ---- comparisons -----------------------------------------------------------------
    (
        "ct-eq-16",
        "where two 16-byte strings differ (a MAC, a tag)",
        |n| {
            let a = public::<16>(14);
            let mut b = a;
            // (Secret 0: no difference at all.)
            b[(n as usize * 5) % 16] ^= u8::from(n > 0);
            black_box(ct::ct_eq(black_box(&a), black_box(&b)));
        },
    ),
    ("ct-eq-32", "where two 32-byte strings differ", |n| {
        let a = public::<32>(15);
        let mut b = a;
        // (Secret 0: no difference at all.)
        b[(n as usize * 5) % 32] ^= u8::from(n > 0);
        black_box(ct::ct_eq(black_box(&a), black_box(&b)));
    }),
    (
        "ct-is-zero",
        "which byte of a 32-byte string is not zero",
        |n| {
            let mut a = [0u8; 32];
            // (Secret 0: all zero.)
            a[(n as usize * 5) % 32] = u8::from(n > 0);
            black_box(ct::ct_is_zero(black_box(&a)));
        },
    ),
    // ---- the protocol ---------------------------------------------------------------------
    (
        "receive-bad-mac1",
        "where a wrong mac1 differs from the right one",
        |n| {
            let (mut device, _tunnel, _rng, mut init) = responder_with_initiation(7);
            init[116 + (n as usize * 5) % 16] ^= 0x10;
            black_box(matches!(
                device.receive(Ticks::from_secs(1), peer_addr(), false, &mut init),
                Incoming::Dropped(_)
            ));
        },
    ),
    (
        "receive-bad-mac2",
        "where a wrong mac2 differs from the right one, under load",
        |n| {
            let (mut device, _tunnel, _rng, mut init) = responder_with_initiation(7);
            // Any sixteen bytes are a wrong mac2: there is no cookie. The
            // one the device computes is the secret; how the two differ
            // is up to the sender.
            init[132..148].copy_from_slice(&secret(n + 4, 16));
            black_box(matches!(
                device.receive(Ticks::from_secs(1), peer_addr(), true, &mut init),
                Incoming::CookieRequired(_)
            ));
        },
    ),
    (
        "handshake",
        "both static keys, the pre-shared key and all entropy",
        |n| {
            // Everything secret comes from `n`; everything else is the
            // same in every run.
            let a_key: [u8; 32] = array(&secret(n, 32));
            let b_key: [u8; 32] = array(&secret(n + 100, 32));
            let psk: [u8; 32] = array(&secret(n + 200, 32));
            let mut rng = Recorded::new(n);
            let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
            let now = Ticks::from_secs(1);
            let id = PeerId::new(0).unwrap();
            let a_secret = StaticSecret::from_bytes(a_key);
            let b_secret = StaticSecret::from_bytes(b_key);
            let (a_pub, b_pub) = (a_secret.public_key(), b_secret.public_key());
            let mut a_dev = Device::new(a_secret, wall, &mut rng).unwrap();
            let mut b_dev = Device::new(b_secret, wall, &mut rng).unwrap();
            let mut config = PeerConfig::new(b_pub);
            config.psk = PresharedKey::from_bytes(psk);
            config.endpoint = Some(peer_addr());
            let mut a: Tunnel = a_dev.tunnel(id, config, &mut rng).unwrap();
            let mut config = PeerConfig::new(a_pub);
            config.psk = PresharedKey::from_bytes(psk);
            let mut b: Tunnel = b_dev.tunnel(id, config, &mut rng).unwrap();

            let mut out = [0u8; 256];
            let mut wire = [0u8; 256];
            a.request_handshake(now);
            let mut init = match a.poll(now, &mut out, &mut rng).unwrap() {
                PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
                other => panic!("{other:?}"),
            };
            let mut response = match b_dev
                .receive_for(
                    &mut b,
                    now,
                    own_addr(),
                    false,
                    &mut init,
                    &mut out,
                    &mut rng,
                )
                .unwrap()
                .received
            {
                Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
                other => panic!("{other:?}"),
            };
            let handled = a_dev
                .receive_for(
                    &mut a,
                    now,
                    peer_addr(),
                    false,
                    &mut response,
                    &mut out,
                    &mut rng,
                )
                .unwrap();
            assert!(matches!(handled.received, Received::HandshakeComplete));
            // One packet each way: the transport keys at work.
            let payload = secret(n + 300, 100);
            let len = match a.encapsulate(now, &payload, &mut wire).unwrap() {
                wireguard_sans_io::Encapsulated::Transport(tx) => tx.datagram.len(),
                other => panic!("{other:?}"),
            };
            let handled = b_dev
                .receive_for(
                    &mut b,
                    now,
                    own_addr(),
                    false,
                    &mut wire[..len],
                    &mut out,
                    &mut rng,
                )
                .unwrap();
            assert!(matches!(handled.received, Received::Data(_)));
            let len = match b.encapsulate(now, &payload, &mut wire).unwrap() {
                wireguard_sans_io::Encapsulated::Transport(tx) => tx.datagram.len(),
                other => panic!("{other:?}"),
            };
            let handled = a_dev
                .receive_for(
                    &mut a,
                    now,
                    peer_addr(),
                    false,
                    &mut wire[..len],
                    &mut out,
                    &mut rng,
                )
                .unwrap();
            assert!(matches!(handled.received, Received::Data(_)));
        },
    ),
];

fn own_addr() -> SocketAddr {
    "192.0.2.1:51820".parse().unwrap()
}

fn peer_addr() -> SocketAddr {
    "192.0.2.2:51820".parse().unwrap()
}

/// A device, a tunnel for a peer, and a genuine initiation from that
/// peer — all from fixed keys and a fixed entropy stream.
fn responder_with_initiation(seed: u64) -> (Device, Tunnel, Recorded, Vec<u8>) {
    let mut rng = Recorded::new(seed);
    let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
    let id = PeerId::new(0).unwrap();
    let ours = StaticSecret::from_bytes(public(20));
    let theirs = StaticSecret::from_bytes(public(21));
    let (our_public, their_public) = (ours.public_key(), theirs.public_key());
    let device = Device::new(ours, wall, &mut rng).unwrap();
    let tunnel = device
        .tunnel(id, PeerConfig::new(their_public), &mut rng)
        .unwrap();
    let their_device = Device::new(theirs, wall, &mut rng).unwrap();
    let mut config = PeerConfig::new(our_public);
    config.endpoint = Some(own_addr());
    let mut their_tunnel: Tunnel = their_device.tunnel(id, config, &mut rng).unwrap();
    let now = Ticks::from_secs(1);
    their_tunnel.request_handshake(now);
    let mut out = [0u8; 256];
    let init = match their_tunnel.poll(now, &mut out, &mut rng).unwrap() {
        PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
        other => panic!("{other:?}"),
    };
    (device, tunnel, rng, init)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let name = args.get(1).map(String::as_str).unwrap_or("list");
    if name == "list" {
        for (name, what, _) in OPERATIONS {
            println!("{name}\t{what}");
        }
        return;
    }
    let n: u64 = args.get(2).and_then(|n| n.parse().ok()).unwrap_or(0);
    // The secrets are made before anything is run, whatever is run: the
    // baseline pays for that too.
    black_box(secret(n, 32));
    let Some((_, _, run)) = OPERATIONS.iter().find(|(known, _, _)| *known == name) else {
        eprintln!("no such operation: {name}");
        std::process::exit(2);
    };
    run(black_box(n));
}
