//! Fuzz the initiator's intake: a tunnel with an initiation in flight
//! receives what the fuzzer has built — from raw bytes, or from the
//! genuine handshake response or a genuine cookie reply with bytes
//! flipped — optionally with `mac1` recomputed (as anyone who knows our
//! public key can).
//!
//! The outcome is predicted independently from the bytes alone and must
//! match exactly, through both receive paths (on twin instances). The
//! shared harness checks the buffer discipline on every delivery.
#![no_main]

#[path = "../../tests/common/mod.rs"]
mod common;

use arbitrary::Arbitrary;
use common::{Polled, Rx, a_addr, b_addr, new_pair};
use libfuzzer_sys::fuzz_target;
use wireguard_sans_io::consts::LABEL_MAC1;
use wireguard_sans_io::crypto::blake2s;
use wireguard_sans_io::{SendReason, Ticks};

#[derive(Arbitrary, Debug)]
enum Base {
    Raw(Vec<u8>),
    GenuineResponse,
    GenuineCookieReply,
}

#[derive(Arbitrary, Debug)]
struct Input {
    under_load: bool,
    /// From the peer's address, or from somewhere else.
    from_peer: bool,
    base: Base,
    /// Byte flips: (position, xor).
    flips: Vec<(u16, u8)>,
    /// Recompute `mac1` after the flips.
    fix_mac1: bool,
}

/// What must come out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Dropped,
    CookieReply,
    Complete,
    CookieStored,
}

fuzz_target!(|input: Input| {
    if input.flips.len() > 64 {
        return;
    }
    let now = Ticks::from_secs(1);
    let src = if input.from_peer {
        b_addr()
    } else {
        "203.0.113.9:9".parse().unwrap()
    };

    let outcomes = [false, true].map(|routed| {
        let mut p = new_pair(0x1717);
        let a_public = p.a.device.public_key();
        let initiation = p.a.initiate(now, &mut p.rng);
        let retransmit_at = p.a.tunnel.next_wake().expect("an attempt is running");
        // What the peer would genuinely answer: a response — or, were it
        // under load, a cookie reply. (Each from its own copy of B: a
        // second delivery of the initiation would be a replay.)
        let genuine_cookie_reply = {
            let mut q = new_pair(0x1717);
            let twin = q.a.initiate(now, &mut q.rng);
            assert_eq!(twin, initiation, "the twins are deterministic");
            match q.b.recv_from(now, a_addr(), true, &twin, &mut q.rng).rx {
                Rx::CookieReply(reply) => reply,
                other => panic!("{other:?}"),
            }
        };
        let genuine_response = match p
            .b
            .recv_from(now, a_addr(), false, &initiation, &mut p.rng)
            .rx
        {
            Rx::Response(response) => response,
            other => panic!("{other:?}"),
        };

        // Build the datagram.
        let mut datagram = match &input.base {
            Base::Raw(bytes) => bytes.clone(),
            Base::GenuineResponse => genuine_response.clone(),
            Base::GenuineCookieReply => genuine_cookie_reply.clone(),
        };
        if !datagram.is_empty() {
            for (position, xor) in &input.flips {
                let position = usize::from(*position) % datagram.len();
                datagram[position] ^= xor;
            }
        }
        let mac1_at = match (datagram.len(), datagram.get(..4)) {
            (148, Some([1, 0, 0, 0])) => Some(116),
            (92, Some([2, 0, 0, 0])) => Some(60),
            _ => None,
        };
        let key = blake2s::hash(&[LABEL_MAC1, a_public.as_bytes()]);
        if let (true, Some(at)) = (input.fix_mac1, mac1_at) {
            let mac1 = blake2s::mac(&key, &[&datagram[..at]]);
            datagram[at..at + 16].copy_from_slice(&mac1);
        }
        let mac1_valid = mac1_at
            .is_some_and(|at| blake2s::mac(&key, &[&datagram[..at]]) == datagram[at..at + 16]);

        // Predict.
        let expected = if mac1_at.is_some() {
            if !mac1_valid {
                Outcome::Dropped
            } else if input.under_load {
                // No cookie was ever issued by A, so no mac2 can be valid.
                Outcome::CookieReply
            } else if datagram.len() == 92 && datagram[8..60] == genuine_response[8..60] {
                // The index of our initiation, the responder's ephemeral
                // and the final AEAD are the peer's. As with an
                // initiation, the *sender* index (bytes 4..8) is covered
                // by `mac1` alone, so a response in which it was changed
                // — by someone in the path who knows our public key — is
                // still accepted; the session it creates addresses the
                // peer by an index the peer does not have and is replaced
                // when the dead-peer timer starts the next handshake.
                Outcome::Complete
            } else {
                Outcome::Dropped
            }
        } else if datagram == genuine_cookie_reply {
            Outcome::CookieStored
        } else {
            Outcome::Dropped
        };

        let info =
            p.a.try_recv(now, src, input.under_load, &datagram, &mut p.rng, routed)
                .expect("hostile input must never be a local fault");
        let got = match &info.rx {
            Rx::Dropped(_) => Outcome::Dropped,
            Rx::CookieReply(reply) => {
                assert_eq!((reply.len(), reply[0]), (64, 3));
                Outcome::CookieReply
            }
            Rx::HandshakeComplete => Outcome::Complete,
            Rx::CookieStored => Outcome::CookieStored,
            other => panic!("impossible outcome for an initiator with no session: {other:?}"),
        };
        assert_eq!(got, expected, "routed={routed} mac1_valid={mac1_valid}");

        if got == Outcome::Complete {
            assert!(info.session_established);
            assert!(p.a.tunnel.is_established(now));
            // The response is authenticated: the endpoint follows it.
            assert_eq!(p.a.tunnel.endpoint(), Some(src));
            assert_eq!(info.endpoint_changed, src != b_addr());
        } else {
            // Nothing else may complete the handshake, move the endpoint
            // or touch the attempt that is running.
            assert!(!info.session_established && !info.endpoint_changed);
            assert!(!p.a.tunnel.is_established(now));
            assert_eq!(p.a.tunnel.endpoint(), Some(b_addr()));
            assert_eq!(p.a.tunnel.next_wake(), Some(retransmit_at));
            // The attempt goes on: the retransmission is still due, and
            // carries a mac2 exactly if a cookie was stored.
            match p.a.poll(retransmit_at, &mut p.rng) {
                Polled::Transmit(retry, SendReason::HandshakeRetransmit, dst) => {
                    assert_eq!(dst, b_addr());
                    let has_mac2 = retry[132..148] != [0u8; 16];
                    assert_eq!(has_mac2, got == Outcome::CookieStored);
                }
                other => panic!("the handshake in flight was lost: {other:?}"),
            }
        }
        got
    });
    assert_eq!(outcomes[0], outcomes[1], "the two receive paths disagree");
});
