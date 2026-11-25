//! The in-tree primitives against independent implementations
//! (RustCrypto, dalek, siphasher) on random and on awkward inputs, and
//! against Project Wycheproof's vectors.
//!
//! The core has known answers of its own (`tests/known_answers.rs`, the
//! RFC vectors in the unit tests); those say that it computes the right
//! thing for the inputs someone wrote down. These say that it computes
//! what everyone else computes for a few hundred thousand inputs nobody
//! chose — every length up to several strides of the SIMD keystream,
//! every block-counter position that matters, the carries Poly1305 has
//! at its limits, non-canonical and low-order curve points.
//!
//! `AUDIT_ITERS` scales the random parts (default 20,000 cases each).

use blake2::digest::{FixedOutput, KeyInit, Mac, Update};
use chacha20poly1305::aead::{Aead, Payload};
use wireguard_sans_io::crypto::chacha20::ChaChaImpl;
use wireguard_sans_io::crypto::{aead, blake2s, kdf, poly1305, siphash, x25519};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{EntropySource, Scalar};

type Simd = wireguard_chacha_simd::Best;

fn iters() -> usize {
    std::env::var("AUDIT_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000)
}

/// Cases that agreed and cases that did not. A test that compared
/// nothing has not passed either.
struct Tally {
    name: &'static str,
    ok: u64,
    bad: u64,
}

impl Tally {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            ok: 0,
            bad: 0,
        }
    }

    fn check(&mut self, cond: bool, what: impl FnOnce() -> String) {
        if cond {
            self.ok += 1;
        } else {
            self.bad += 1;
            if self.bad <= 5 {
                println!("  MISMATCH [{}]: {}", self.name, what());
            }
        }
    }

    fn done(self) {
        println!(
            "{:<66} {:>8} ok {:>4} MISMATCH",
            self.name, self.ok, self.bad
        );
        assert_eq!(self.bad, 0, "{}", self.name);
        assert!(self.ok > 0, "{}: nothing was compared", self.name);
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rnd(rng: &mut DeterministicRng, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rng.fill(&mut v).unwrap();
    v
}

fn rnd_array<const N: usize>(rng: &mut DeterministicRng) -> [u8; N] {
    let mut v = [0u8; N];
    rng.fill(&mut v).unwrap();
    v
}

// ---------------------------------------------------------------- AEAD

/// Sealing with the scalar and with the SIMD keystream gives RustCrypto's
/// bytes at every length up to a few strides and at random ones beyond;
/// opening gives the plaintext back; and one flipped bit anywhere is
/// rejected with nothing written to the buffer.
#[test]
fn chacha20poly1305_agrees_with_rustcrypto() {
    use chacha20poly1305::ChaCha20Poly1305;
    let iters = iters();
    let mut rng = DeterministicRng::new(0xd1ff);
    let mut t_seal = Tally::new("chacha20poly1305 seal (scalar) vs RustCrypto");
    let mut t_simd = Tally::new("chacha20poly1305 seal_in_place (SIMD) vs RustCrypto");
    let mut t_open = Tally::new("chacha20poly1305 open_in_place scalar+SIMD round trip");
    let mut t_forge = Tally::new("chacha20poly1305 forgeries rejected, buffer untouched");
    let lens: Vec<usize> = (0..=2200usize)
        .chain((0..iters).map(|i| (i * 7919) % 70_000))
        .collect();
    for (i, len) in lens.iter().copied().enumerate() {
        if len > 4096 && i % 16 != 0 {
            continue;
        }
        let key: [u8; 32] = rnd_array(&mut rng);
        let nonce: [u8; 12] = rnd_array(&mut rng);
        let aad = rnd(&mut rng, (i * 31) % 67);
        let pt = rnd(&mut rng, len);
        let reference = ChaCha20Poly1305::new(&key.into())
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut out = vec![0u8; len + 16];
        aead::seal(&key, &nonce, &aad, &pt, &mut out).unwrap();
        t_seal.check(out == reference, || format!("len {len}"));

        let mut buf = vec![0u8; len + 16];
        buf[..len].copy_from_slice(&pt);
        aead::seal_in_place_with::<Simd>(&key, &nonce, &aad, len, &mut buf).unwrap();
        t_simd.check(buf == reference, || format!("len {len}"));

        let mut a = reference.clone();
        let mut b = reference.clone();
        let ra = aead::open_in_place_with::<Scalar>(&key, &nonce, &aad, &mut a);
        let rb = aead::open_in_place_with::<Simd>(&key, &nonce, &aad, &mut b);
        t_open.check(
            ra == Ok(len) && rb == Ok(len) && a[..len] == pt[..] && b[..len] == pt[..],
            || format!("len {len}"),
        );

        // One flipped bit anywhere: rejected, and nothing written.
        let mut forged = reference.clone();
        let at = (i * 2_654_435_761) % forged.len();
        forged[at] ^= 1 << (i % 8);
        let before = forged.clone();
        let r1 = aead::open_in_place_with::<Simd>(&key, &nonce, &aad, &mut forged);
        let untouched = forged == before;
        let r2 = aead::open_in_place_with::<Scalar>(&key, &nonce, &aad, &mut forged);
        t_forge.check(
            r1.is_err() && r2.is_err() && untouched && forged == before,
            || format!("len {len} flip at {at}"),
        );
    }
    t_seal.done();
    t_simd.done();
    t_open.done();
    t_forge.done();
}

/// The raw keystream of both backends, started at the block counters
/// that matter (0, 1, just short of wrapping, anywhere), against
/// RustCrypto's `chacha20`.
#[test]
fn chacha20_keystream_agrees_with_rustcrypto() {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    let mut rng = DeterministicRng::new(0xd200);
    let mut t = Tally::new("chacha20 keystream scalar+SIMD vs RustCrypto (IETF)");
    for i in 0..iters().min(6000) {
        let key: [u8; 32] = rnd_array(&mut rng);
        let nonce: [u8; 12] = rnd_array(&mut rng);
        let len = (i * 37) % 2600;
        let counter: u32 = match i % 5 {
            0 => 0,
            1 => 1,
            2 => u32::MAX - 60,
            3 => (i as u32).wrapping_mul(0x9e37_79b9) >> 4,
            _ => 8,
        };
        let data = rnd(&mut rng, len);
        // RustCrypto refuses to run past the end of the keystream.
        let blocks = (len as u64).div_ceil(64);
        if u64::from(counter) + blocks > u64::from(u32::MAX) {
            continue;
        }
        let mut reference = data.clone();
        let mut c = chacha20::ChaCha20::new(&key.into(), &nonce.into());
        c.seek(u64::from(counter) * 64);
        c.apply_keystream(&mut reference);
        let mut a = data.clone();
        let mut b = data.clone();
        Scalar::apply_keystream(&key, &nonce, counter, &mut a);
        Simd::apply_keystream(&key, &nonce, counter, &mut b);
        t.check(a == reference && b == reference, || {
            format!("len {len} counter {counter}")
        });
    }
    t.done();
}

/// XChaCha20-Poly1305 — what cookie replies are sealed with.
#[test]
fn xchacha20poly1305_agrees_with_rustcrypto() {
    use chacha20poly1305::XChaCha20Poly1305;
    let mut rng = DeterministicRng::new(0xd201);
    let mut t = Tally::new("xchacha20poly1305 seal/open vs RustCrypto");
    for i in 0..iters().min(5000) {
        let key: [u8; 32] = rnd_array(&mut rng);
        let nonce: [u8; 24] = rnd_array(&mut rng);
        let aad = rnd(&mut rng, i % 40);
        let pt = rnd(&mut rng, i % 200);
        let reference = XChaCha20Poly1305::new(&key.into())
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut out = vec![0u8; pt.len() + 16];
        aead::xseal(&key, &nonce, &aad, &pt, &mut out).unwrap();
        let mut back = reference.clone();
        let opened = aead::xopen_in_place(&key, &nonce, &aad, &mut back);
        t.check(
            out == reference && opened == Ok(pt.len()) && back[..pt.len()] == pt[..],
            || format!("case {i}"),
        );
    }
    t.done();
}

// ------------------------------------------------------------ Poly1305

/// One-shot, streamed in ragged pieces, and padded — on random messages
/// and on the carry-heavy corners: all-ones blocks, the largest `r`,
/// `s = 2^128 - 1`.
#[test]
fn poly1305_agrees_with_rustcrypto() {
    use ::poly1305::universal_hash::{KeyInit as _, UniversalHash};
    let mut rng = DeterministicRng::new(0xd202);
    let mut t = Tally::new("poly1305 one-shot + streaming + padded vs RustCrypto");
    for i in 0..iters() {
        let mut key: [u8; 32] = rnd_array(&mut rng);
        let len = match i % 6 {
            0 => i % 70,
            1 => 16 * (i % 40),
            _ => (i * 13) % 3000,
        };
        let mut msg = rnd(&mut rng, len);
        match i % 7 {
            0 => msg.fill(0xff),
            1 => key[..16].fill(0xff),
            2 => key[16..].fill(0xff),
            3 => {
                key.fill(0xff);
                msg.fill(0xff);
            }
            4 => msg.iter_mut().for_each(|b| *b = 0xfb),
            _ => {}
        }
        // RustCrypto: `update_padded` pads the tail with zeros,
        // `compute_unpadded` is the one-shot function of RFC 8439.
        let mut reference = ::poly1305::Poly1305::new((&key).into());
        reference.update_padded(&msg);
        let ref_padded = reference.finalize();
        let ref_plain = ::poly1305::Poly1305::new((&key).into()).compute_unpadded(&msg);

        let ours = poly1305::poly1305(&key, &msg);
        let mut s = poly1305::Poly1305::new(&key);
        let mut rest: &[u8] = &msg;
        let mut step = 1 + i % 23;
        while !rest.is_empty() {
            let n = step.min(rest.len());
            s.update(&rest[..n]);
            rest = &rest[n..];
            step = step * 5 % 37 + 1;
        }
        let streamed = s.finalize();
        let mut p = poly1305::Poly1305::new(&key);
        p.update_padded(&msg);
        let padded = p.finalize();
        t.check(
            ours[..] == ref_plain[..] && streamed == ours && padded[..] == ref_padded[..],
            || format!("len {len} case {i} key {}", hex(&key)),
        );
    }
    t.done();
}

// ------------------------------------------------------------- BLAKE2s

/// The hash, the keyed 16-byte MAC at several key lengths, the
/// prepared-state form `mac1` is made with, and HMAC-BLAKE2s at key
/// lengths on both sides of the block size.
#[test]
fn blake2s_and_hmac_agree_with_rustcrypto() {
    let mut rng = DeterministicRng::new(0xd203);
    let mut t = Tally::new("blake2s-256 / keyed-128 / HMAC / prepared mac vs RustCrypto");
    for i in 0..iters() {
        let len = match i % 4 {
            0 => i % 200,
            1 => 64 * (i % 9),
            _ => (i * 17) % 1500,
        };
        let msg = rnd(&mut rng, len);
        let split = if len == 0 { 0 } else { i % len };
        let (m1, m2) = msg.split_at(split);

        let mut h = blake2::Blake2s256::default();
        Update::update(&mut h, &msg);
        let ref_hash = h.finalize_fixed();
        let ours = blake2s::hash(&[m1, m2]);

        let keylen = [32usize, 16, 1, 31][i % 4];
        let key = rnd(&mut rng, keylen);
        let mut m =
            <blake2::Blake2sMac<blake2::digest::consts::U16> as KeyInit>::new_from_slice(&key)
                .unwrap();
        Mac::update(&mut m, &msg);
        let ref_mac = m.finalize().into_bytes();
        let our_mac = blake2s::mac(&key, &[m1, m2]);

        let key32: [u8; 32] = rnd_array(&mut rng);
        let mut state = [0u32; 8];
        blake2s::mac_key_state(&key32, &mut state);
        let mut prepared = [0u8; 16];
        blake2s::mac_keyed(&key32, &state, &[m1, m2], &mut prepared);
        let plain = blake2s::mac(&key32, &[&msg]);

        let hkey = rnd(&mut rng, [32usize, 64, 65, 0, 100][i % 5]);
        let mut hm =
            <hmac::SimpleHmac<blake2::Blake2s256> as KeyInit>::new_from_slice(&hkey).unwrap();
        Mac::update(&mut hm, &msg);
        let ref_hmac = hm.finalize().into_bytes();
        let our_hmac = kdf::hmac(&hkey, &[m1, m2]);

        t.check(
            ours[..] == ref_hash[..]
                && our_mac[..] == ref_mac[..]
                && prepared == plain
                && our_hmac[..] == ref_hmac[..],
            || format!("len {len} keylen {keylen} case {i}"),
        );
    }
    t.done();
}

// ------------------------------------------------------------- SipHash

/// SipHash-2-4, which session indices are made routable with.
#[test]
fn siphash_agrees_with_siphasher() {
    use std::hash::Hasher;
    let mut rng = DeterministicRng::new(0xd204);
    let mut t = Tally::new("siphash-2-4 vs siphasher");
    for i in 0..iters() {
        let key: [u8; 16] = rnd_array(&mut rng);
        let msg = rnd(&mut rng, i % 80);
        let mut h = siphasher::sip::SipHasher24::new_with_key(&key);
        h.write(&msg);
        t.check(siphash::siphash24(&key, &msg) == h.finish(), || {
            format!("len {}", msg.len())
        });
    }
    t.done();
}

// -------------------------------------------------------------- X25519

/// The ladder and the fixed-base table against dalek, on random scalars
/// and points and on the corners: the all-zero and all-ones scalar, the
/// ignored top bit, non-canonical coordinates (p and a little more),
/// small points.
#[test]
fn x25519_agrees_with_dalek() {
    let mut rng = DeterministicRng::new(0xd205);
    let mut t = Tally::new("x25519 ladder + fixed-base vs x25519-dalek (random + corners)");
    for i in 0..iters() {
        let mut k: [u8; 32] = rnd_array(&mut rng);
        let mut u: [u8; 32] = rnd_array(&mut rng);
        match i % 9 {
            0 => k = [0u8; 32],
            1 => k = [0xffu8; 32],
            2 => u[31] |= 0x80,
            3 => {
                u = [0xff; 32];
                u[0] = 0xed + (i % 19) as u8;
                u[31] = 0x7f;
            }
            4 => {
                u = [0u8; 32];
                u[0] = (i % 256) as u8;
            }
            _ => {}
        }
        let reference = x25519_dalek::x25519(k, u);
        let ours = x25519::x25519(&k, &u);
        let ref_base = x25519_dalek::x25519(k, x25519_dalek::X25519_BASEPOINT_BYTES);
        let base = x25519::x25519_base(&k);
        let via_ladder = x25519::x25519(&k, &x25519::BASEPOINT);
        t.check(
            ours == reference && base == ref_base && via_ladder == ref_base,
            || format!("k {} u {}", hex(&k), hex(&u)),
        );
    }
    t.done();
}

// ---------------------------------------------------------- Wycheproof

/// Every X25519 vector gives the expected shared secret — and the
/// all-zero ones (low-order points) are exactly those `shared_secret`
/// refuses.
#[test]
fn x25519_passes_the_wycheproof_vectors() {
    let mut t = Tally::new("x25519 Wycheproof vectors (low-order, twist, non-canonical, edge)");
    let set = wycheproof::xdh::TestSet::load(wycheproof::xdh::TestName::X25519).unwrap();
    let mut zero_refused = 0;
    for group in &set.test_groups {
        for test in &group.tests {
            let (Ok(k), Ok(u)) = (
                <[u8; 32]>::try_from(&test.private_key[..]),
                <[u8; 32]>::try_from(&test.public_key[..]),
            ) else {
                continue;
            };
            let ours = x25519::x25519(&k, &u);
            let checked = x25519::shared_secret(&k, &u);
            let zero = test.shared_secret.iter().all(|b| *b == 0);
            zero_refused += u32::from(zero && checked.is_err());
            t.check(
                ours[..] == test.shared_secret[..] && checked.is_err() == zero,
                || format!("tc {} ({})", test.tc_id, test.comment),
            );
        }
    }
    println!("  (all-zero shared secrets refused by shared_secret(): {zero_refused})");
    assert!(
        zero_refused > 0,
        "the vectors have low-order points in them"
    );
    t.done();
}

/// Every ChaCha20-Poly1305 vector with this construction's nonce size:
/// valid ones open to the plaintext (and seal to the ciphertext) with
/// both keystreams, the others are rejected with the buffer untouched.
#[test]
fn chacha20poly1305_passes_the_wycheproof_vectors() {
    use wycheproof::TestResult;
    use wycheproof::aead::{TestName, TestSet};
    let mut t = Tally::new("chacha20poly1305 Wycheproof vectors (scalar + SIMD)");
    let set = TestSet::load(TestName::ChaCha20Poly1305).unwrap();
    for group in &set.test_groups {
        for test in &group.tests {
            let (Ok(key), Ok(nonce)) = (
                <[u8; 32]>::try_from(&test.key[..]),
                <[u8; 12]>::try_from(&test.nonce[..]),
            ) else {
                continue; // other nonce sizes: not this construction
            };
            let mut ct_tag = test.ct.to_vec();
            ct_tag.extend_from_slice(&test.tag);
            let mut a = ct_tag.clone();
            let mut b = ct_tag.clone();
            let ra = aead::open_in_place_with::<Scalar>(&key, &nonce, &test.aad, &mut a);
            let rb = aead::open_in_place_with::<Simd>(&key, &nonce, &test.aad, &mut b);
            let ok = if test.result == TestResult::Valid {
                let n = test.pt.len();
                let mut sealed = vec![0u8; n + 16];
                let _ = aead::seal(&key, &nonce, &test.aad, &test.pt, &mut sealed);
                ra == Ok(n)
                    && rb == Ok(n)
                    && a[..n] == test.pt[..]
                    && b[..n] == test.pt[..]
                    && sealed == ct_tag
            } else {
                ra.is_err() && rb.is_err() && a == ct_tag && b == ct_tag
            };
            t.check(ok, || {
                format!("tc {} ({}) {:?}", test.tc_id, test.comment, test.result)
            });
        }
    }
    t.done();
}

/// The same for XChaCha20-Poly1305.
#[test]
fn xchacha20poly1305_passes_the_wycheproof_vectors() {
    use wycheproof::TestResult;
    use wycheproof::aead::{TestName, TestSet};
    let mut t = Tally::new("xchacha20poly1305 Wycheproof vectors");
    let set = TestSet::load(TestName::XChaCha20Poly1305).unwrap();
    for group in &set.test_groups {
        for test in &group.tests {
            let (Ok(key), Ok(nonce)) = (
                <[u8; 32]>::try_from(&test.key[..]),
                <[u8; 24]>::try_from(&test.nonce[..]),
            ) else {
                continue;
            };
            let mut ct_tag = test.ct.to_vec();
            ct_tag.extend_from_slice(&test.tag);
            let mut a = ct_tag.clone();
            let r = aead::xopen_in_place(&key, &nonce, &test.aad, &mut a);
            let ok = if test.result == TestResult::Valid {
                r == Ok(test.pt.len()) && a[..test.pt.len()] == test.pt[..]
            } else {
                r.is_err() && a == ct_tag
            };
            t.check(ok, || format!("tc {} ({})", test.tc_id, test.comment));
        }
    }
    t.done();
}
