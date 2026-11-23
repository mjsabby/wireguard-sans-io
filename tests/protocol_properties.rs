//! Regression and property tests for protocol-level behaviour.
//!
//! Each test below either documents a known limitation, verifies that a
//! hypothesised attack does not work, or locks in a correctness property.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

mod common;
use common::{Polled, Rx, S, Tx, a_addr, new_pair};
use core::num::NonZeroU16;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{DropReason, EntropySource, consts, padded_len, transport_datagram_len};

// ============================================================================
// Transport padding is MTU-clamped.
//
// Whitepaper §5.4.6: zero-pad "to the closest multiple of 16 that does
// not exceed the maximum transmission unit". `PeerConfig::mtu` /
// `Tunnel::set_mtu()` supply that cap, and `padded_len()` is the kernel's
// `calculate_skb_padding` (and wireguard-go's `calculatePaddingSize`)
// byte for byte, for every (len, mtu) pair — including payloads larger
// than the MTU, which the kernel pads by their last `len % mtu` bytes.
//
// Any regression that reintroduces over-MTU padding fails here.
// ============================================================================
#[test]
fn padding_clamped_to_mtu_matches_kernel() {
    // drivers/net/wireguard/send.c, calculate_skb_padding, transliterated:
    // returns the padding; the padded length is `len` plus that.
    fn kernel_padding(len: u32, mtu: u32) -> u32 {
        let mut last_unit = len;
        if mtu == 0 {
            return last_unit.next_multiple_of(16) - last_unit;
        }
        if last_unit > mtu {
            last_unit %= mtu;
        }
        let padded_size = mtu.min(last_unit.next_multiple_of(16));
        padded_size - last_unit
    }
    // Exhaustive over a band of MTUs (16-aligned and not) × every payload
    // length up to three times the MTU.
    for mtu in [
        1usize, 15, 16, 17, 576, 1280, 1350, 1412, 1420, 1438, 1440, 1476, 1500, 9000, 65535,
    ] {
        let mtu_nz = NonZeroU16::new(mtu as u16);
        for len in 0..=3 * mtu + 17 {
            let ours = padded_len(len, mtu_nz);
            let theirs = len + kernel_padding(len as u32, mtu as u32) as usize;
            assert_eq!(
                ours, theirs,
                "mtu={mtu} len={len}: padded_len={ours}, kernel={theirs}"
            );
            assert!(ours >= len, "padding must never truncate");
            assert!(ours - len < 16, "never a whole block of padding");
            if len <= mtu {
                assert!(ours <= mtu, "mtu={mtu} len={len}: padded {ours} > MTU");
            }
        }
    }
    // Without an MTU (the kernel's `mtu == 0`): plain alignment.
    for len in 0..5000usize {
        assert_eq!(
            padded_len(len, None),
            len + kernel_padding(len as u32, 0) as usize
        );
    }
    // Concrete: the PPPoE-1492 case that motivated the MTU clamp.
    assert_eq!(
        padded_len(1412, NonZeroU16::new(1412)),
        1412,
        "1412 on MTU 1412 → no padding (was 1424 pre-fix)"
    );
    // `mtu = None` preserves the unclamped behaviour.
    assert_eq!(padded_len(1412, None), 1424);
    assert_eq!(transport_datagram_len(1412), 1424 + 32);
    // The arithmetic cannot overflow, and still never truncates.
    for len in [usize::MAX, usize::MAX - 1, usize::MAX - 15, usize::MAX - 16] {
        for mtu in [None, NonZeroU16::new(1), NonZeroU16::new(1500)] {
            assert!(padded_len(len, mtu) >= len, "{len} {mtu:?}");
        }
    }
    let _ = transport_datagram_len(usize::MAX);
    assert_eq!(transport_datagram_len(0), 32); // keepalive
    assert_eq!(transport_datagram_len(1), 48);
    assert_eq!(transport_datagram_len(16), 48);
    assert_eq!(transport_datagram_len(17), 64);
}

/// End-to-end through `Tunnel::encapsulate` with a configured MTU.
#[test]
fn encapsulate_never_exceeds_configured_mtu() {
    for mtu in [1350u16, 1412, 1420, 1500] {
        let mut p = new_pair(0x6d_0001 ^ u64::from(mtu));
        p.a.tunnel.set_mtu(NonZeroU16::new(mtu));
        assert_eq!(p.a.tunnel.mtu(), NonZeroU16::new(mtu));
        p.establish();
        for len in (1usize..=usize::from(mtu)).rev().take(20).chain([28, 576]) {
            let wire = p.seal_from_a(&vec![0x33u8; len]);
            assert!(
                wire.len() <= usize::from(mtu) + 32,
                "mtu={mtu} len={len}: wire={} > {}+32",
                wire.len(),
                mtu
            );
            // Receiver decrypts the (possibly non-16-aligned) plaintext.
            let got = p.open_at_b(&wire);
            assert_eq!(&got[..len], vec![0x33u8; len].as_slice());
            assert!(got[len..].iter().all(|&b| b == 0), "padding must be zero");
        }
        // The in-place path applies the same clamp.
        let now = p.clock.now();
        let len = usize::from(mtu) - 3;
        let mut buf = vec![0x33u8; len + 64];
        match p.a.tunnel.encapsulate_in_place(now, &mut buf, len).unwrap() {
            wireguard_sans_io::Encapsulated::Transport(tx) => {
                assert_eq!(tx.datagram.len(), usize::from(mtu) + 32);
            }
            other => panic!("{other:?}"),
        }
        // A runtime change is honoured immediately; None removes the cap.
        p.a.tunnel.set_mtu(None);
        assert_eq!(
            p.seal_from_a(&vec![0x33u8; len]).len(),
            len.div_ceil(16) * 16 + 32
        );
    }
}

// ============================================================================
// WireGuard has NO protocol-level MTU negotiation or backoff. The library
// cannot generate ICMP Frag-Needed, cannot relay outer-path PMTU to the
// inner stack, and cannot fragment. All MTU handling is the embedder's
// responsibility. This test documents what the library DOES guarantee at
// the boundaries.
// ============================================================================
#[test]
fn mtu_is_embedder_responsibility() {
    let mut p = new_pair(0x6d_7531);
    p.establish();

    // (a) Receive side accepts ANY datagram size ≥ 32 (no MTU on receive)
    //     and needs no buffer sized for it: decryption is in place.
    for inner in [0usize, 1, 1500, 9000, 60000] {
        let payload = vec![0x5Au8; inner];
        let wire = p.seal_from_a(&payload);
        match p.deliver_to_b(&wire).rx {
            Rx::Data(d) => assert_eq!(&d[..inner], &payload[..]),
            Rx::Keepalive => assert_eq!(inner, 0),
            other => panic!("{other:?}"),
        }
    }

    // (b) Send side imposes NO upper bound (will happily emit a 64 KiB
    //     datagram if asked) — embedder must clamp.
    let now = p.clock.now();
    let big = vec![0u8; 65000];
    assert!(matches!(p.a.send(now, &big), Tx::Transport(w) if w.len() == 65008 + 32));
}

// ============================================================================
// Anyone who sees a handshake message of ours and knows the peer's public
// key can make a cookie reply for it (the XAEAD key is
// Hash(LABEL_COOKIE‖peer_pub), public; the AAD is the on-wire mac1). What
// that buys is bounded by one rule — one cookie reply per message we sent,
// as in the kernel:
//
// * a forgery that arrives AFTER the genuine reply (or the genuine reply
//   again) is dropped: it cannot replace the cookie, however often and
//   however late it is sent;
// * a forgery that wins the race is stored instead of the genuine reply.
//   That costs one more round of the cookie dance — what an attacker in
//   that position gets by dropping the genuine reply.
// ============================================================================
#[test]
fn a_cookie_reply_is_accepted_once_per_message_sent() {
    use wireguard_sans_io::consts::{LABEL_COOKIE, REKEY_TIMEOUT};
    use wireguard_sans_io::crypto::{aead, blake2s};

    /// A cookie reply for `initiation` carrying a garbage cookie, as an
    /// eavesdropper who knows B's public key would make it.
    fn forge(initiation: &[u8], responder_public: &[u8; 32], receiver_index: &[u8]) -> Vec<u8> {
        let mac1: [u8; 16] = initiation[116..132].try_into().unwrap();
        let key = blake2s::hash(&[LABEL_COOKIE, responder_public]);
        let nonce = [0xEEu8; 24];
        let mut enc = [0u8; 32];
        aead::xseal(&key, &nonce, &mac1, &[0xAAu8; 16], &mut enc).unwrap();
        let mut forged = vec![0u8; 64];
        forged[0] = 3;
        forged[4..8].copy_from_slice(receiver_index);
        forged[8..32].copy_from_slice(&nonce);
        forged[32..64].copy_from_slice(&enc);
        forged
    }
    /// A's next retransmission, and what B — under load throughout — makes
    /// of it.
    fn retransmit(p: &mut common::Pair) -> Rx {
        let later = p.clock.advance(REKEY_TIMEOUT + 400_000_000);
        let init = match p.a.poll(later, &mut p.rng) {
            Polled::Transmit(w, _, _) => w,
            other => panic!("{other:?}"),
        };
        p.b.recv_from(later, a_addr(), true, &init, &mut p.rng).rx
    }

    for forgery_first in [false, true] {
        let mut p = new_pair(0x6d_7601);
        let now = p.clock.now();
        let b_public = *p.b.device.public_key().as_bytes();
        let init1 = p.a_initiates();
        // B (under load) sends a real cookie reply.
        let real = match p.b.recv_from(now, a_addr(), true, &init1, &mut p.rng).rx {
            Rx::CookieReply(w) => w,
            other => panic!("{other:?}"),
        };
        let forged = forge(&init1, &b_public, &real[4..8]);

        if forgery_first {
            // The attacker wins the race: the forgery is stored, and the
            // genuine reply is the one that comes too late.
            assert_eq!(p.deliver_to_a(&forged).rx, Rx::CookieStored);
            assert_eq!(
                p.deliver_to_a(&real).rx,
                Rx::Dropped(DropReason::NoPendingHandshake)
            );
            // The retransmission carries a mac2 made from the forged
            // cookie: B answers with a cookie reply again, not a response —
            // one extra round, as if the genuine reply had been dropped.
            let real2 = match retransmit(&mut p) {
                Rx::CookieReply(w) => w,
                other => panic!("{other:?}"),
            };
            // The attacker is gone: the next reply is stored, and the
            // next initiation is answered.
            assert_eq!(p.deliver_to_a(&real2).rx, Rx::CookieStored);
            assert!(matches!(retransmit(&mut p), Rx::Response(_)));
        } else {
            // The genuine reply arrives first. Everything after it is
            // dropped: the forgery, sent at leisure and from anywhere, and
            // the genuine reply again.
            assert_eq!(p.deliver_to_a(&real).rx, Rx::CookieStored);
            for _ in 0..3 {
                for late in [&forged, &real] {
                    assert_eq!(
                        p.a.recv_from(now, common::x_addr(), false, late, &mut p.rng)
                            .rx,
                        Rx::Dropped(DropReason::NoPendingHandshake)
                    );
                }
            }
            assert_eq!(p.a.tunnel.stats().cookies_received, 1);
            // So the retransmission carries the genuine cookie, and B —
            // still under load — answers it.
            assert!(
                matches!(retransmit(&mut p), Rx::Response(_)),
                "a late forgery replaced the genuine cookie"
            );
        }
    }
}

// ============================================================================
// A cookie reply answers the handshake message it names. Once that
// handshake is over, a recording of the reply is good for nothing — not
// even with a live index written into it (the index is not authenticated).
// ============================================================================
#[test]
fn a_recorded_cookie_reply_is_useless_once_its_handshake_is_over() {
    let mut p = new_pair(0x6d_7603);
    let now = p.clock.now();
    let init1 = p.a_initiates();
    let reply = match p.b.recv_from(now, a_addr(), true, &init1, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("{other:?}"),
    };
    // The reply is held back. The handshake completes without it: B is no
    // longer under load when A retransmits.
    let later = p
        .clock
        .advance(wireguard_sans_io::consts::REKEY_TIMEOUT + 400_000_000);
    let init2 = match p.a.poll(later, &mut p.rng) {
        Polled::Transmit(w, _, _) => w,
        other => panic!("{other:?}"),
    };
    let resp = match p.deliver_to_b(&init2).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let _ = p.a.drain(later, &mut p.rng);
    // The index of A's session now in use (the response names it).
    let a_live_index: [u8; 4] = resp[8..12].try_into().unwrap();

    // The recording now, as it was, and with A's live session index in it.
    let mut rewritten = reply.clone();
    rewritten[4..8].copy_from_slice(&a_live_index);
    for datagram in [&reply, &rewritten, &rewritten] {
        let rx =
            p.a.recv_from(later, common::x_addr(), false, datagram, &mut p.rng)
                .rx;
        assert!(
            matches!(rx, Rx::Dropped(DropReason::UnknownIndex)),
            "a stale cookie reply was not dropped: {rx:?}"
        );
    }
    assert_eq!(p.a.tunnel.stats().cookies_received, 0);
    p.assert_roundtrip_a_to_b(b"still fine");
}

// ============================================================================
// A 65 KB transport datagram with a valid receiver index but forged tag
// costs ONE Poly1305 over the ciphertext and nothing else (no ChaCha20
// decryption, no replay-window mutation, no plaintext anywhere).
// Quantifies the worst-case on-path transport DoS.
// ============================================================================
#[test]
fn oversize_forged_transport_costs_only_poly1305() {
    let mut p = new_pair(0x6d_7602);
    p.establish();
    // Learn B's session index by capturing one real datagram A→B.
    let real = p.seal_from_a(b"probe");
    let recv_idx: [u8; 4] = real[4..8].try_into().unwrap();
    p.open_at_b(&real); // counter 1 consumed, greatest=1

    let now = p.clock.now();
    let mut forged = vec![0u8; 65535];
    forged[0] = 4;
    forged[4..8].copy_from_slice(&recv_idx);
    forged[8..16].copy_from_slice(&5u64.to_le_bytes()); // new counter

    let t0 = std::time::Instant::now();
    let (info, after) = p.b.recv_in_place(now, a_addr(), &forged, &mut p.rng);
    let dt = t0.elapsed();
    eprintln!("65 KB forged transport: {dt:?} → {:?}", info.rx);
    assert_eq!(info.rx, Rx::Dropped(DropReason::AuthFailure));
    assert_eq!(after, forged, "buffer modified on auth failure");
    assert_eq!(p.b.tunnel.stats().auth_failures, 1);
    // Replay window NOT advanced: counter 5 is still acceptable.
    let real5 = {
        // Burn counters 2..=4 on A.
        for _ in 0..3 {
            let _ = p.seal_from_a(b"x");
        }
        p.seal_from_a(b"five")
    };
    assert_eq!(&real5[8..16], &5u64.to_le_bytes());
    assert!(matches!(p.deliver_to_b(&real5).rx, Rx::Data(_)));
}

// ============================================================================
// The receive path never reports a local fault for anything a peer can
// send: thousands of randomized genuine packets, replays and forgeries —
// every one is an `Ok`.
// ============================================================================
#[test]
fn receive_path_never_reports_a_local_fault() {
    let mut p = new_pair(0x6d_7603);
    p.establish();
    let mut rng = DeterministicRng::new(0xACCE);
    for round in 0..10_000u32 {
        let mut len = [0u8; 2];
        rng.fill(&mut len).unwrap();
        let len = (u16::from_le_bytes(len) % 200) as usize;
        let mut wire = p.seal_from_a(&vec![0x33u8; len]);
        match round % 5 {
            1 => wire[20] ^= 1,                                        // forged body
            2 => wire.truncate(wire.len() - 1),                        // truncated
            3 => wire[8..16].copy_from_slice(&u64::MAX.to_le_bytes()), // counter out of range
            _ => {}
        }
        let now = p.clock.now();
        let first = p.b.try_recv_from(now, a_addr(), false, &wire, &mut p.rng);
        assert!(first.is_ok(), "round {round}: {first:?}");
        // …and its replay.
        let again = p.b.try_recv_from(now, a_addr(), false, &wire, &mut p.rng);
        assert!(
            matches!(again.map(|i| i.rx), Ok(Rx::Dropped(_))),
            "round {round}"
        );
    }
}

// ============================================================================
// `next_wake()` ⇔ `poll()` invariant holds with persistent keepalive set
// and a rekey that has to wait for the pacing deadline.
// ============================================================================
#[test]
fn next_wake_poll_invariant_with_paced_rekey() {
    let mut p = common::new_pair_with(0x6d_7604, None, Some(25));
    p.establish();
    // A rekey attempt toward a silent peer starts at 119 s…
    p.clock.advance(119 * S);
    let _ = p.a_initiates();
    // …so that when the send path asks for a rekey at 120 s, the request
    // has to wait for the pacing deadline.
    p.clock.advance(S);
    let _ = p.seal_from_a(b"trigger rekey");
    let mut polls = 0u32;
    while p.clock.mono_ns <= 1000 * S {
        let Some(wake) = p.a.tunnel.next_wake() else {
            break;
        };
        let now = p.clock.set(wake);
        // `drain` asserts: Idle ⇒ next_wake strictly in the future.
        let _ = p.a.drain(now, &mut p.rng);
        polls += 1;
        assert!(polls < 2000, "busy loop: {polls} wake-ups in 1000 s");
    }
    assert!(polls > 10, "the tunnel did keep working ({polls} wake-ups)");
}

// ============================================================================
// REJECT_AFTER_MESSAGES on RECEIVE is enforced before any cryptographic
// work (cheap reject), and the value matches the kernel exactly
// (2^64 − 2^13 − 1, NOT 2^64 − 2^13).
// ============================================================================
#[test]
fn reject_after_messages_exact_value_and_cheap_reject() {
    assert_eq!(
        consts::REJECT_AFTER_MESSAGES,
        u64::MAX - (1u64 << 13),
        "must equal 2^64 − 2^13 − 1"
    );
    assert_eq!(consts::REJECT_AFTER_MESSAGES, 0xffff_ffff_ffff_dfff);

    let mut p = new_pair(0x6d_7606);
    p.establish();
    let real = p.seal_from_a(b"x");
    let mut forged = real.clone();
    forged[8..16].copy_from_slice(&consts::REJECT_AFTER_MESSAGES.to_le_bytes());
    let now = p.clock.now();
    let (info, after) = p.b.recv_in_place(now, a_addr(), &forged, &mut p.rng);
    assert_eq!(info.rx, Rx::Dropped(DropReason::Expired));
    assert_eq!(after, forged);
    assert_eq!(
        p.b.tunnel.stats().auth_failures,
        0,
        "counter-limit reject must be pre-AEAD"
    );
    // One below the limit is not rejected for its counter (it is a
    // forgery, so the AEAD rejects it).
    forged[8..16].copy_from_slice(&(consts::REJECT_AFTER_MESSAGES - 1).to_le_bytes());
    assert_eq!(
        p.deliver_to_b(&forged).rx,
        Rx::Dropped(DropReason::AuthFailure)
    );
}
