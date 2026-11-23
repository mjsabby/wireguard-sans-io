//! Fuzz the responder's intake: a device and tunnel that receive a
//! handshake initiation the fuzzer has built — from raw bytes, or from the
//! peer's genuine initiation with bytes flipped — optionally with `mac1`
//! recomputed (as anyone who knows our public key can), optionally with a
//! valid cookie (as anyone who can receive at their source address can).
//!
//! Without the recomputed `mac1` every input dies at the first check and
//! nothing behind it is ever reached; with it, the Diffie-Hellman, the two
//! AEADs, the timestamp check and the cookie machinery are all in play.
//!
//! The outcome is predicted independently from the bytes alone (is it
//! shaped like a handshake message? is its `mac1` valid? is it, apart from
//! `mac2`, the genuine initiation?) and must match exactly — through the
//! single-call receive path and through the two-step routing path, on
//! twin instances. The shared harness checks the buffer discipline on
//! every delivery.
#![no_main]

#[path = "../../tests/common/mod.rs"]
mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use arbitrary::Arbitrary;
use common::{Opts, Rx, new_pair_opts};
use libfuzzer_sys::fuzz_target;
use wireguard_sans_io::consts::{LABEL_COOKIE, LABEL_MAC1};
use wireguard_sans_io::crypto::{aead, blake2s};
use wireguard_sans_io::{PublicKey, Ticks};

#[derive(Arbitrary, Debug)]
enum Base {
    Raw(Vec<u8>),
    GenuineInitiation,
}

#[derive(Arbitrary, Debug)]
struct Input {
    under_load: bool,
    v6: bool,
    ip: [u8; 16],
    port: u16,
    base: Base,
    /// Byte flips: (position, xor).
    flips: Vec<(u16, u8)>,
    /// Recompute `mac1` after the flips.
    fix_mac1: bool,
    cookie: Cookie,
}

/// What the sender does about `mac2`.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum Cookie {
    /// Nothing: `mac2` is whatever the bytes say.
    None,
    /// Obtains a cookie for its source address and computes `mac2` with
    /// it: the one case in which a loaded responder goes on.
    Valid,
    /// Computes `mac2` with a cookie that was issued to another address.
    ForAnotherAddress,
    /// A valid `mac2` with one bit flipped.
    Corrupted(u8),
}

/// What must come out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Dropped,
    CookieReply,
    Response,
}

/// `(mac1 offset, total length)` if `datagram` is shaped like a handshake
/// message.
fn handshake_shape(datagram: &[u8]) -> Option<usize> {
    match (datagram.len(), datagram.get(..4)) {
        (148, Some([1, 0, 0, 0])) => Some(116),
        (92, Some([2, 0, 0, 0])) => Some(60),
        _ => None,
    }
}

fn mac1_key(public: &PublicKey) -> [u8; 32] {
    blake2s::hash(&[LABEL_MAC1, public.as_bytes()])
}

fuzz_target!(|input: Input| {
    if input.flips.len() > 64 {
        return;
    }
    let src = if input.v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(input.ip)), input.port)
    } else {
        let [a, b, c, d, ..] = input.ip;
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), input.port)
    };
    let now = Ticks::from_secs(1);

    // Twin instances: one per receive path.
    let outcomes = [false, true].map(|routed| {
        // B is the responder under test and does not know where A is.
        let mut p = new_pair_opts(
            0xf00d,
            Opts {
                b_without_endpoint: true,
                ..Opts::default()
            },
        );
        let b_public = p.b.device.public_key();
        let genuine = p.a.initiate(now, &mut p.rng);

        // Build the datagram.
        let mut datagram = match &input.base {
            Base::Raw(bytes) => bytes.clone(),
            Base::GenuineInitiation => genuine.clone(),
        };
        if !datagram.is_empty() {
            for (position, xor) in &input.flips {
                let position = usize::from(*position) % datagram.len();
                datagram[position] ^= xor;
            }
        }
        let shape = handshake_shape(&datagram);
        if let (true, Some(at)) = (input.fix_mac1, shape) {
            let mac1 = blake2s::mac(&mac1_key(&b_public), &[&datagram[..at]]);
            datagram[at..at + 16].copy_from_slice(&mac1);
        }
        let mac1_valid = shape.is_some_and(|at| {
            blake2s::mac(&mac1_key(&b_public), &[&datagram[..at]]) == datagram[at..at + 16]
        });
        // A cookie can only be had for a message whose mac1 is valid: the
        // loaded responder answers it with a cookie reply, which whoever
        // is at the address it was sent to can open.
        let mut has_cookie = false;
        if let (true, true, Some(at)) = (input.cookie != Cookie::None, mac1_valid, shape) {
            let elsewhere: SocketAddr = "203.0.113.200:2".parse().unwrap();
            let cookie_for = match input.cookie {
                Cookie::ForAnotherAddress if src != elsewhere => elsewhere,
                _ => src,
            };
            let Rx::CookieReply(reply) =
                p.b.try_recv(now, cookie_for, true, &datagram, &mut p.rng, routed)
                    .expect("never a local fault")
                    .rx
            else {
                panic!("a loaded responder must answer a valid mac1 with a cookie");
            };
            assert_eq!((reply.len(), reply[0]), (64, 3));
            let key = blake2s::hash(&[LABEL_COOKIE, b_public.as_bytes()]);
            let nonce: [u8; 24] = reply[8..32].try_into().unwrap();
            let mut cookie = [0u8; 16];
            aead::xopen(
                &key,
                &nonce,
                &datagram[at..at + 16],
                &reply[32..64],
                &mut cookie,
            )
            .expect("the cookie reply opens for the message that provoked it");
            let mut mac2 = blake2s::mac(&cookie, &[&datagram[..at + 16]]);
            if let Cookie::Corrupted(bit) = input.cookie {
                mac2[usize::from(bit >> 3) % 16] ^= 1 << (bit & 7);
            }
            datagram[at + 16..at + 32].copy_from_slice(&mac2);
            // Only a cookie issued to this very address, used intact,
            // proves anything.
            has_cookie = cookie_for == src && !matches!(input.cookie, Cookie::Corrupted(_));
        }

        // Predict. "Genuine" means: the handshake payload — ephemeral,
        // encrypted static key, encrypted timestamp — is the peer's. The
        // sender index in front of it is not part of the Noise transcript;
        // only `mac1` covers it, and `mac1` can be recomputed by anyone
        // who knows our public key. An initiation whose index was changed
        // that way is still accepted (by every implementation: it is how
        // the protocol is defined); the response then goes to an index
        // the initiator does not have, and its handshake times out — a
        // denial of service that takes an attacker in the path, who could
        // as well have dropped the datagram.
        let is_genuine = datagram.len() == 148 && datagram[8..116] == genuine[8..116];
        let expected = if !mac1_valid {
            Outcome::Dropped
        } else if input.under_load && !has_cookie {
            Outcome::CookieReply
        } else if is_genuine {
            Outcome::Response
        } else {
            // A forged body, or a handshake response nobody asked for.
            Outcome::Dropped
        };

        let info =
            p.b.try_recv(now, src, input.under_load, &datagram, &mut p.rng, routed)
                .expect("hostile input must never be a local fault");
        let got = match &info.rx {
            Rx::Dropped(_) => Outcome::Dropped,
            Rx::CookieReply(reply) => {
                assert_eq!((reply.len(), reply[0]), (64, 3));
                Outcome::CookieReply
            }
            Rx::Response(response) => {
                assert_eq!((response.len(), response[0]), (92, 2));
                Outcome::Response
            }
            other => panic!("impossible outcome for a responder with no session: {other:?}"),
        };
        assert_eq!(
            got, expected,
            "routed={routed} mac1_valid={mac1_valid} has_cookie={has_cookie} genuine={is_genuine}"
        );
        assert!(!info.session_established);
        if got == Outcome::Response {
            // Only an authenticated initiation teaches B where A is.
            assert!(info.endpoint_changed);
            assert_eq!(p.b.tunnel.endpoint(), Some(src));
            assert!(p.b.tunnel.next_wake().is_some());
        } else {
            assert!(!info.endpoint_changed);
            assert_eq!(p.b.tunnel.endpoint(), None);
            assert_eq!(p.b.tunnel.next_wake(), None, "hostile input armed a timer");
        }
        got
    });
    assert_eq!(outcomes[0], outcomes[1], "the two receive paths disagree");
});
