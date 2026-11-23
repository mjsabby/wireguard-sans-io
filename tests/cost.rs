//! What each kind of datagram costs the receiver — counted, not timed.
//!
//! WireGuard's defence against CPU exhaustion (whitepaper §5.3) rests on
//! what an unauthenticated sender can make us compute. These tests pin
//! that down operation by operation with a counting crypto provider
//! ([`common::counting`]): how many Curve25519 scalar multiplications, how
//! many AEADs, at which step. A wall-clock measurement of the same thing
//! changes with the load on the machine; a count does not.
//!
//! The second half is about *where* the expensive step sits in the API:
//! between [`Device::receive`] and [`Device::identify`] there is room for
//! the embedder's per-source limit, and the tests show that a limit placed
//! there cannot be turned against a peer by someone forging its address.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use common::counting::{Counting, Counts, spent};
use common::{Pair, Polled, Rx, Side, a_addr, b_addr, new_counting_pair, x_addr};
use wireguard_sans_io::consts::{LABEL_COOKIE, LABEL_MAC1};
use wireguard_sans_io::crypto::{aead, blake2s};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    DropReason, EntropySource, Incoming, PublicKey, Received, SendReason, Ticks,
};

type CPair = Pair<Counting>;
type CSide = Side<Counting>;

/// A handshake initiation with a random body and a valid `mac1` for
/// `responder`: what anyone who knows the responder's public key can send.
fn forged_initiation(responder: &PublicKey, rng: &mut DeterministicRng) -> Vec<u8> {
    let mut msg = vec![0u8; 148];
    rng.fill(&mut msg[..116]).unwrap();
    msg[..4].copy_from_slice(&[1, 0, 0, 0]);
    let mac1_key = blake2s::hash(&[LABEL_MAC1, responder.as_bytes()]);
    let mac1 = blake2s::mac(&mac1_key, &[&msg[..116]]);
    msg[116..132].copy_from_slice(&mac1);
    msg
}

/// Give `msg` (an initiation with a valid `mac1`) a valid `mac2` for
/// `src`, the way a sender that really is at `src` gets one: provoke a
/// cookie reply from the loaded responder and open it.
fn add_cookie(
    msg: &mut [u8],
    responder: &mut CSide,
    src: SocketAddr,
    now: Ticks,
    rng: &mut DeterministicRng,
) {
    let Rx::CookieReply(reply) = responder.recv_from(now, src, true, msg, rng).rx else {
        panic!("a loaded responder answers a cookie-less initiation with a cookie");
    };
    let cookie_key = blake2s::hash(&[LABEL_COOKIE, responder.device.public_key().as_bytes()]);
    let nonce: [u8; 24] = reply[8..32].try_into().unwrap();
    let mut cookie = [0u8; 16];
    let n = aead::xopen(
        &cookie_key,
        &nonce,
        &msg[116..132],
        &reply[32..64],
        &mut cookie,
    )
    .unwrap();
    assert_eq!(n, 16);
    let mac2 = blake2s::mac(&cookie, &[&msg[..132]]);
    msg[132..148].copy_from_slice(&mac2);
}

/// A's initiation, as the first datagram of a handshake.
fn initiation_from_a(p: &mut CPair) -> Vec<u8> {
    let now = p.clock.now();
    p.a.initiate(now, &mut p.rng)
}

#[test]
fn creating_a_device_and_a_tunnel() {
    let _ = spent();
    let p = new_counting_pair(1);
    let setup = spent();
    // Two devices: one public key each. Two tunnels: one static-static
    // Diffie-Hellman each, computed once and kept.
    assert_eq!(setup.x25519_public, 2);
    assert_eq!(setup.x25519, 2);
    drop(p);
}

/// The static key and the provider. A device asks its provider for its
/// own public key, and `StaticSecret::public_key_with` asks the provider
/// it is given; `StaticSecret::public_key` — a key on its own knows no
/// provider — is the in-tree computation, as its documentation says.
#[test]
fn static_key_operations_use_the_provider_they_are_given() {
    use wireguard_sans_io::{Device, StaticSecret};
    let mut rng = DeterministicRng::new(3);
    let secret = StaticSecret::generate(&mut rng).unwrap();
    let _ = spent();
    let in_tree = secret.public_key();
    assert_eq!(spent(), Counts::default(), "the provider was asked");
    let one_public_key = Counts {
        x25519_public: 1,
        ..Counts::default()
    };
    assert_eq!(secret.public_key_with::<Counting>(), in_tree);
    assert_eq!(spent(), one_public_key);
    let device =
        Device::<Counting>::with_provider(secret.clone(), common::wall(), &mut rng).unwrap();
    assert_eq!(spent().x25519_public, 1);
    assert_eq!(device.public_key(), in_tree);
}

/// `Device::receive` is the door every datagram comes through, and it
/// never does a Diffie-Hellman operation — whatever arrives, with or
/// without load.
#[test]
fn device_receive_costs_at_most_a_few_keyed_hashes() {
    let mut p = new_counting_pair(2);
    let now = p.clock.now();
    let b_pub = p.b.device.public_key();
    let mut rng = DeterministicRng::new(22);

    // Material: a genuine initiation, a forged one, the response to the
    // genuine one, a cookie reply, transport data, and noise.
    let genuine = initiation_from_a(&mut p);
    let forged = forged_initiation(&b_pub, &mut rng);
    let Rx::Response(response) = p.b.recv_from(now, a_addr(), false, &genuine, &mut p.rng).rx
    else {
        panic!("B answers")
    };
    let Rx::CookieReply(cookie_reply) = p.b.recv_from(now, x_addr(), true, &forged, &mut p.rng).rx
    else {
        panic!("B is under load")
    };
    assert_eq!(p.deliver_to_a(&response).rx, Rx::HandshakeComplete);
    let transport = p.seal_from_a(b"payload");
    let mut noise = vec![0u8; 148];
    rng.fill(&mut noise).unwrap();
    noise[..4].copy_from_slice(&[1, 0, 0, 0]);

    let _ = spent();
    for under_load in [false, true] {
        for (what, datagram, to_a) in [
            ("genuine initiation", &genuine, false),
            ("forged initiation", &forged, false),
            ("noise shaped like an initiation", &noise, false),
            ("handshake response", &response, true),
            ("cookie reply", &cookie_reply, true),
            ("transport data", &transport, false),
        ] {
            let side = if to_a { &mut p.a } else { &mut p.b };
            let mut copy = datagram.clone();
            let incoming = side.device.receive(now, x_addr(), under_load, &mut copy);
            let cost = spent();
            assert!(
                cost.only_macs(),
                "{what} (under_load={under_load}): {incoming:?} cost {cost:?}"
            );
            // mac1, and under load the cookie check: a cookie and the mac2
            // it gives, for the one secret that is honoured.
            let limit = if under_load { 3 } else { 1 };
            assert!(cost.mac <= limit, "{what}: {} MACs", cost.mac);
        }
    }
}

/// The expensive step of receiving an initiation, on its own: exactly one
/// X25519, whether the initiation is genuine or forged.
#[test]
fn identifying_an_initiation_costs_exactly_one_x25519() {
    let mut p = new_counting_pair(3);
    let now = p.clock.now();
    let b_pub = p.b.device.public_key();
    let mut rng = DeterministicRng::new(33);

    let mut genuine = initiation_from_a(&mut p);
    let Incoming::Initiation(mut init) = p.b.device.receive(now, a_addr(), false, &mut genuine)
    else {
        panic!("expected an initiation")
    };
    let _ = spent();
    assert_eq!(p.b.device.identify(&mut init), Ok(p.a.device.public_key()));
    let cost = spent();
    assert_eq!((cost.x25519, cost.x25519_public), (1, 0), "{cost:?}");
    assert_eq!((cost.open, cost.seal), (1, 0), "the encrypted static key");
    // Asking again does not do the work again.
    assert_eq!(p.b.device.identify(&mut init), Ok(p.a.device.public_key()));
    assert_eq!(spent(), Counts::default());

    // A forgery costs the same one X25519 before it fails.
    let mut forged = forged_initiation(&b_pub, &mut rng);
    let Incoming::Initiation(mut init) = p.b.device.receive(now, x_addr(), false, &mut forged)
    else {
        panic!("a forged mac1 passes the door")
    };
    let _ = spent();
    assert_eq!(p.b.device.identify(&mut init), Err(DropReason::AuthFailure));
    let cost = spent();
    assert_eq!((cost.x25519, cost.x25519_public), (1, 0), "{cost:?}");
    assert_eq!(cost.open, 1);
    assert_eq!(init.peer_public(), None);
}

/// The rest of the responder's side: two more X25519 and one key
/// generation — but only for an initiation that has authenticated.
#[test]
fn accepting_an_initiation_costs_three_more_scalar_multiplications() {
    let mut p = new_counting_pair(4);
    let now = p.clock.now();
    let mut genuine = initiation_from_a(&mut p);
    let Incoming::Initiation(mut init) = p.b.device.receive(now, a_addr(), false, &mut genuine)
    else {
        panic!("expected an initiation")
    };
    p.b.device.identify(&mut init).unwrap();
    let _ = spent();
    let mut out = [0u8; 128];
    let handled =
        p.b.tunnel
            .handle_initiation(now, &init, &mut out, &mut p.rng)
            .unwrap();
    assert!(matches!(handled.received, Received::HandshakeResponse(_)));
    let cost = spent();
    // The responder's ephemeral public key, `ee` and `se`. (`ss` was
    // computed when the tunnel was created.)
    assert_eq!((cost.x25519, cost.x25519_public), (2, 1), "{cost:?}");
    // The timestamp is opened, the empty payload sealed.
    assert_eq!((cost.open, cost.seal), (1, 1), "{cost:?}");
}

/// With one peer there is nobody to look up, and the tunnel identifies the
/// initiation itself — for the same total.
#[test]
fn a_tunnel_that_identifies_the_initiation_itself_pays_the_same() {
    let mut p = new_counting_pair(5);
    let now = p.clock.now();
    let genuine = initiation_from_a(&mut p);
    let _ = spent();
    let info = p.b.recv_from(now, a_addr(), false, &genuine, &mut p.rng);
    assert!(matches!(info.rx, Rx::Response(_)));
    let cost = spent();
    assert_eq!((cost.x25519, cost.x25519_public), (3, 1), "{cost:?}");
    assert_eq!(cost.scalar_mults(), 4, "as the reference implementations");
}

/// An initiation from a key that is not a configured peer (but whose
/// sender knows our public key): one X25519 to find that out, and nothing
/// after it — in particular not a second Diffie-Hellman, as a naive
/// "decrypt everything, then compare" order would spend. BoringTun and the
/// kernel behave the same.
#[test]
fn an_initiation_from_an_unknown_key_costs_one_x25519_in_total() {
    let mut p = new_counting_pair(6);
    let now = p.clock.now();
    let b_pub = p.b.device.public_key();
    let (m_key, m_pub) = common::keypair(&mut p.rng);
    let mut mallory: CSide = common::side_with(
        m_key,
        b_pub,
        x_addr(),
        Some(b_addr()),
        None,
        None,
        &mut p.rng,
    );
    let init = mallory.initiate(now, &mut p.rng);

    // The single-call path.
    let _ = spent();
    assert_eq!(
        p.b.recv_from(now, x_addr(), false, &init, &mut p.rng).rx,
        Rx::Dropped(DropReason::UnknownPeer)
    );
    let cost = spent();
    assert_eq!((cost.x25519, cost.x25519_public), (1, 0), "{cost:?}");
    assert_eq!(cost.open, 1, "only the static key was decrypted: {cost:?}");

    // The same through the two-step path: all of it is in `identify`, and
    // the tunnel that is (wrongly) handed the initiation spends nothing.
    let mut copy = init.clone();
    let Incoming::Initiation(mut initiation) = p.b.device.receive(now, x_addr(), false, &mut copy)
    else {
        panic!("expected an initiation")
    };
    assert_eq!(p.b.device.identify(&mut initiation), Ok(m_pub));
    let _ = spent();
    let mut out = [0u8; 128];
    let handled =
        p.b.tunnel
            .handle_initiation(now, &initiation, &mut out, &mut p.rng)
            .unwrap();
    assert!(matches!(
        handled.received,
        Received::Dropped(DropReason::UnknownPeer)
    ));
    let cost = spent();
    assert_eq!(cost, Counts::default(), "rejected by comparing two keys");
}

/// A replayed initiation is recognised by its timestamp, which costs the
/// identification and one more AEAD — not the response.
#[test]
fn a_replayed_initiation_costs_no_response() {
    let mut p = new_counting_pair(7);
    let now = p.clock.now();
    let genuine = initiation_from_a(&mut p);
    assert!(matches!(
        p.b.recv_from(now, a_addr(), false, &genuine, &mut p.rng).rx,
        Rx::Response(_)
    ));
    let _ = spent();
    assert_eq!(
        p.b.recv_from(now, a_addr(), false, &genuine, &mut p.rng).rx,
        Rx::Dropped(DropReason::ReplayedTimestamp)
    );
    let cost = spent();
    assert_eq!((cost.x25519, cost.x25519_public), (1, 0), "{cost:?}");
    assert_eq!((cost.open, cost.seal), (2, 0), "{cost:?}");
}

/// The initiator's side: two scalar multiplications to send, two to
/// complete.
#[test]
fn the_initiator_pays_four_scalar_multiplications() {
    let mut p = new_counting_pair(8);
    let now = p.clock.now();
    let _ = spent();
    let init = initiation_from_a(&mut p);
    let cost = spent();
    // The ephemeral public key and `es`.
    assert_eq!((cost.x25519, cost.x25519_public), (1, 1), "{cost:?}");
    assert_eq!(cost.seal, 2, "static key and timestamp");

    let Rx::Response(response) = p.b.recv_from(now, a_addr(), false, &init, &mut p.rng).rx else {
        panic!("B answers")
    };
    let _ = spent();
    assert_eq!(p.deliver_to_a(&response).rx, Rx::HandshakeComplete);
    let cost = spent();
    // `ee` and `se`.
    assert_eq!((cost.x25519, cost.x25519_public), (2, 0), "{cost:?}");
    assert_eq!(cost.open, 1);
}

/// A handshake response only costs Diffie-Hellman operations when it
/// answers the initiation the tunnel has in flight.
#[test]
fn a_response_costs_diffie_hellman_only_for_the_initiation_in_flight() {
    let mut p = new_counting_pair(9);
    let now = p.clock.now();
    let init = initiation_from_a(&mut p);
    let Rx::Response(response) = p.b.recv_from(now, a_addr(), false, &init, &mut p.rng).rx else {
        panic!("B answers")
    };
    let a_pub = p.a.device.public_key();
    let remac = |msg: &mut [u8]| {
        let mac1_key = blake2s::hash(&[LABEL_MAC1, a_pub.as_bytes()]);
        let mac1 = blake2s::mac(&mac1_key, &[&msg[..60]]);
        msg[60..76].copy_from_slice(&mac1);
    };

    // Someone who knows A's public key but not the index of its
    // handshake: rejected without any work.
    let mut wrong_index = response.clone();
    wrong_index[8] ^= 0x55;
    remac(&mut wrong_index);
    let _ = spent();
    assert_eq!(
        p.deliver_to_a(&wrong_index).rx,
        Rx::Dropped(DropReason::NoPendingHandshake)
    );
    let cost = spent();
    assert!(cost.only_macs() && cost.mac == 1, "{cost:?}");

    // Someone who has seen A's initiation go by, and so knows the index:
    // the two X25519 are spent before the forgery is detected. This is
    // inherent in the protocol, and the handshake in flight survives it.
    let mut forged = response.clone();
    forged[44] ^= 1;
    remac(&mut forged);
    let _ = spent();
    assert_eq!(
        p.deliver_to_a(&forged).rx,
        Rx::Dropped(DropReason::AuthFailure)
    );
    let cost = spent();
    assert_eq!((cost.x25519, cost.x25519_public), (2, 0), "{cost:?}");
    assert_eq!(p.deliver_to_a(&response).rx, Rx::HandshakeComplete);
}

/// Under load a handshake message without a valid cookie is answered with
/// a cookie reply: a few keyed hashes and one small AEAD, never a
/// Diffie-Hellman operation.
#[test]
fn under_load_a_message_without_a_cookie_costs_no_diffie_hellman() {
    let mut p = new_counting_pair(10);
    let now = p.clock.now();
    let b_pub = p.b.device.public_key();
    let mut rng = DeterministicRng::new(1010);
    // The first cookie ever draws the cookie secret; measure after that.
    let first = forged_initiation(&b_pub, &mut rng);
    assert!(matches!(
        p.b.recv_from(now, x_addr(), true, &first, &mut rng).rx,
        Rx::CookieReply(_)
    ));
    let _ = spent();
    for _ in 0..100 {
        let forged = forged_initiation(&b_pub, &mut rng);
        assert!(matches!(
            p.b.recv_from(now, x_addr(), true, &forged, &mut rng).rx,
            Rx::CookieReply(_)
        ));
    }
    let cost = spent();
    assert_eq!(cost.scalar_mults(), 0, "{cost:?}");
    assert_eq!((cost.hash, cost.hmac, cost.seal, cost.open), (0, 0, 0, 0));
    assert_eq!(cost.xseal, 100, "one cookie sealed per reply");
    // Per message: mac1; the cookie check against the secret in use (the
    // cookie and the mac2 it gives); the cookie that goes into the reply.
    assert_eq!(cost.mac, 100 * 4);
    assert_eq!(p.b.tunnel.stats().handshakes_responded, 0);
}

/// How long a cookie is good for, and what checking one costs. A secret
/// makes cookies for `COOKIE_LIFETIME` and is honoured for
/// `COOKIE_SECRET_GRACE` more; the one before it is tried only while it is
/// still honoured, which is the first moments after a rotation.
#[test]
fn a_cookie_is_checked_against_the_secrets_still_honoured_and_no_others() {
    use wireguard_sans_io::consts::{COOKIE_LIFETIME, COOKIE_SECRET_GRACE};
    let mut p = new_counting_pair(11);
    let b_pub = p.b.device.public_key();
    let mut rng = DeterministicRng::new(1111);
    let t0 = p.clock.now();

    // Is `msg` let through the door as proven to come from `x_addr`, and
    // how many MACs did that take?
    let at_the_door = |p: &mut CPair, at: Ticks, msg: &[u8]| {
        let mut copy = msg.to_vec();
        let _ = spent();
        let proven = match p.b.device.receive(at, x_addr(), true, &mut copy) {
            Incoming::Initiation(init) => init.source_verified(),
            Incoming::CookieRequired(_) => false,
            other => panic!("{other:?}"),
        };
        (proven, spent().mac)
    };

    // The first secret, drawn at t0, and a cookie from it.
    let mut first = forged_initiation(&b_pub, &mut rng);
    add_cookie(&mut first, &mut p.b, x_addr(), t0, &mut rng);
    // One secret so far: mac1, the cookie, the mac2.
    assert_eq!(at_the_door(&mut p, t0, &first), (true, 3));

    // A lifetime later the next cookie comes from a new secret…
    let rotation = t0.add_nanos(COOKIE_LIFETIME);
    let mut second = forged_initiation(&b_pub, &mut rng);
    add_cookie(&mut second, &mut p.b, x_addr(), rotation, &mut rng);
    // …and for the grace both are honoured: the old cookie still passes,
    // at the price of trying two secrets.
    let last = rotation.add_nanos(COOKIE_SECRET_GRACE - 1);
    assert_eq!(at_the_door(&mut p, last, &first), (true, 5));
    assert_eq!(at_the_door(&mut p, last, &second), (true, 5));
    // Then the old secret is gone, and so is the cost of trying it.
    let after = rotation.add_nanos(COOKIE_SECRET_GRACE);
    assert_eq!(at_the_door(&mut p, after, &first), (false, 3));
    assert_eq!(at_the_door(&mut p, after, &second), (true, 3));

    // Nothing is minted for a long time (no load): the second secret is
    // honoured until a lifetime and the grace after it was drawn, then no
    // cookie is good, and none is computed.
    let end = rotation.add_nanos(COOKIE_LIFETIME + COOKIE_SECRET_GRACE);
    assert_eq!(
        at_the_door(&mut p, Ticks::from_nanos(end.nanos() - 1), &second),
        (true, 3)
    );
    assert_eq!(at_the_door(&mut p, end, &second), (false, 1));
}

/// Transport data costs one AEAD when it authenticates, and nothing at all
/// when it is a replay or addressed to no session.
#[test]
fn transport_data_costs_one_aead_or_nothing() {
    let mut p = new_counting_pair(11);
    p.establish();
    let wire = p.seal_from_a(b"hello world");
    let _ = spent();
    p.open_at_b(&wire);
    let cost = spent();
    assert_eq!(
        cost,
        Counts {
            open: 1,
            ..Counts::default()
        }
    );
    // The replay is rejected by the counter, before the AEAD.
    for _ in 0..1000 {
        assert_eq!(p.deliver_to_b(&wire).rx, Rx::Dropped(DropReason::Replay));
    }
    assert_eq!(spent(), Counts::default());
    // A guessed index likewise.
    let mut guessed = wire.clone();
    guessed[4] ^= 0xff;
    assert_eq!(
        p.deliver_to_b(&guessed).rx,
        Rx::Dropped(DropReason::UnknownIndex)
    );
    assert_eq!(spent(), Counts::default());
    // A forged body for a live index and a fresh counter: one AEAD (the
    // tag check), which fails.
    let mut forged = p.seal_from_a(b"another");
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let _ = spent();
    assert_eq!(
        p.deliver_to_b(&forged).rx,
        Rx::Dropped(DropReason::AuthFailure)
    );
    assert_eq!(
        spent(),
        Counts {
            open: 1,
            ..Counts::default()
        }
    );
}

// ---- the place for a per-source limit -------------------------------------

/// A minimal per-source allowance, as an embedder would keep it: so many
/// expensive operations per source address, refilled over time (not
/// modelled here: the tests are about one instant).
struct Allowance {
    burst: u32,
    left: HashMap<IpAddr, u32>,
}

impl Allowance {
    fn new(burst: u32) -> Self {
        Self {
            burst,
            left: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: IpAddr) -> bool {
        let left = self.left.entry(ip).or_insert(self.burst);
        if *left == 0 {
            return false;
        }
        *left -= 1;
        true
    }
}

/// The receive path of an embedder with a per-source limit: `receive`,
/// then — only for a source a cookie has proven — the limit, then
/// `identify`, then the tunnel. Returns what became of the datagram.
fn receive_with_limit(
    side: &mut CSide,
    limit: &mut Allowance,
    now: Ticks,
    src: SocketAddr,
    under_load: bool,
    datagram: &[u8],
    rng: &mut DeterministicRng,
) -> &'static str {
    let mut copy = datagram.to_vec();
    let mut out = [0u8; 128];
    match side.device.receive(now, src, under_load, &mut copy) {
        Incoming::Initiation(mut init) => {
            if init.source_verified() && !limit.allow(init.src().ip()) {
                return "limited";
            }
            if side.device.identify(&mut init).is_err() {
                return "not identified";
            }
            match side
                .tunnel
                .handle_initiation(now, &init, &mut out, rng)
                .unwrap()
                .received
            {
                Received::HandshakeResponse(_) => "answered",
                _ => "dropped by the tunnel",
            }
        }
        Incoming::CookieRequired(challenge) => {
            side.device
                .cookie_reply(now, &challenge, &mut out, rng)
                .unwrap();
            "cookie"
        }
        Incoming::ForPeer(..) => "routed",
        _ => "dropped",
    }
}

/// `source_verified` is true exactly for a handshake message that carried
/// a valid cookie while we were under load.
#[test]
fn an_initiation_says_whether_a_cookie_proved_its_source() {
    let mut p = new_counting_pair(12);
    let now = p.clock.now();
    let mut init = initiation_from_a(&mut p);

    // Not under load: nothing was checked, so nothing is proven.
    let mut copy = init.clone();
    let Incoming::Initiation(initiation) = p.b.device.receive(now, a_addr(), false, &mut copy)
    else {
        panic!("expected an initiation")
    };
    assert!(!initiation.source_verified());
    assert_eq!(initiation.src(), a_addr());

    // Under load, without a cookie: it does not get this far.
    let mut copy = init.clone();
    assert!(matches!(
        p.b.device.receive(now, a_addr(), true, &mut copy),
        Incoming::CookieRequired(_)
    ));

    // Under load, with the cookie for its address: proven.
    add_cookie(&mut init, &mut p.b, a_addr(), now, &mut p.rng);
    let mut copy = init.clone();
    let Incoming::Initiation(initiation) = p.b.device.receive(now, a_addr(), true, &mut copy)
    else {
        panic!("a valid cookie passes the gate")
    };
    assert!(initiation.source_verified());

    // The same message from another address: the cookie is not for it.
    let mut copy = init.clone();
    assert!(matches!(
        p.b.device.receive(now, x_addr(), true, &mut copy),
        Incoming::CookieRequired(_)
    ));

    // A handshake response says the same about itself.
    let mut q = new_counting_pair(13);
    let init = initiation_from_a(&mut q);
    let Rx::Response(mut response) = q.b.recv_from(now, a_addr(), false, &init, &mut q.rng).rx
    else {
        panic!("B answers")
    };
    let Incoming::ForPeer(_, packet) = q.a.device.receive(now, b_addr(), false, &mut response)
    else {
        panic!("a response is routed")
    };
    assert!(packet.is_handshake() && !packet.source_verified());
    let mut data = {
        assert_eq!(q.deliver_to_a(&response).rx, Rx::HandshakeComplete);
        q.seal_from_a(b"x")
    };
    let Incoming::ForPeer(_, packet) = q.b.device.receive(now, a_addr(), true, &mut data) else {
        panic!("transport data is routed")
    };
    assert!(!packet.is_handshake() && !packet.source_verified());
}

/// The attack a limiter *in front of* `receive` invites: forge the
/// victim's source address and use up its allowance. With the limit where
/// it belongs, forged datagrams never reach it — they carry no cookie for
/// the address they claim — so the victim's own handshake goes through.
#[test]
fn a_forged_source_address_cannot_use_up_a_peers_allowance() {
    let mut p = new_counting_pair(14);
    let now = p.clock.now();
    let b_pub = p.b.device.public_key();
    let mut rng = DeterministicRng::new(1414);
    let mut limit = Allowance::new(5);

    // 2000 forgeries claiming to come from A's address, while B is under
    // load. Each is answered with a cookie (sent to A, who ignores it).
    let _ = spent();
    for _ in 0..2000 {
        let forged = forged_initiation(&b_pub, &mut rng);
        assert_eq!(
            receive_with_limit(&mut p.b, &mut limit, now, a_addr(), true, &forged, &mut rng),
            "cookie"
        );
    }
    assert_eq!(
        spent().scalar_mults(),
        0,
        "the flood bought no Diffie-Hellman"
    );
    assert!(limit.left.is_empty(), "the limit was never consulted");

    // A's own initiation, with the cookie it obtained for its address.
    let mut genuine = initiation_from_a(&mut p);
    add_cookie(&mut genuine, &mut p.b, a_addr(), now, &mut p.rng);
    assert_eq!(
        receive_with_limit(
            &mut p.b,
            &mut limit,
            now,
            a_addr(),
            true,
            &genuine,
            &mut p.rng
        ),
        "answered"
    );
}

/// The other attack: a sender with a real address and a real cookie
/// repeats one message as fast as it can. Without a limit every copy
/// costs an X25519; with one, a burst does.
#[test]
fn a_cookie_holder_gets_only_its_allowance_of_diffie_hellman() {
    let mut p = new_counting_pair(15);
    let now = p.clock.now();
    let b_pub = p.b.device.public_key();
    let mut rng = DeterministicRng::new(1515);
    let mut limit = Allowance::new(5);

    // The attacker is at `x_addr` and holds a cookie for it.
    let mut flood = forged_initiation(&b_pub, &mut rng);
    add_cookie(&mut flood, &mut p.b, x_addr(), now, &mut rng);

    let _ = spent();
    let mut outcomes: HashMap<&str, u32> = HashMap::new();
    for _ in 0..1000 {
        let outcome =
            receive_with_limit(&mut p.b, &mut limit, now, x_addr(), true, &flood, &mut rng);
        *outcomes.entry(outcome).or_default() += 1;
    }
    assert_eq!(outcomes.get("not identified"), Some(&5));
    assert_eq!(outcomes.get("limited"), Some(&995));
    assert_eq!(spent().x25519, 5, "five X25519 for a thousand datagrams");

    // Nobody else is affected: A, at its own address, is answered.
    let mut genuine = initiation_from_a(&mut p);
    add_cookie(&mut genuine, &mut p.b, a_addr(), now, &mut p.rng);
    assert_eq!(
        receive_with_limit(
            &mut p.b,
            &mut limit,
            now,
            a_addr(),
            true,
            &genuine,
            &mut p.rng
        ),
        "answered"
    );

    // For comparison, the single-call path has no place for the limit:
    // every copy costs its X25519.
    let _ = spent();
    for _ in 0..100 {
        assert_eq!(
            p.b.recv_from(now, x_addr(), true, &flood, &mut rng).rx,
            Rx::Dropped(DropReason::AuthFailure)
        );
    }
    assert_eq!(spent().x25519, 100);
}

/// The whole exchange, counted: a handshake and one packet each way.
#[test]
fn a_complete_handshake_costs_eight_scalar_multiplications() {
    let mut p = new_counting_pair(16);
    let _ = spent();
    p.establish();
    let cost = spent();
    assert_eq!(cost.scalar_mults(), 8, "{cost:?}");
    assert_eq!((cost.x25519, cost.x25519_public), (6, 2));
    // Poll once more: nothing left to do, nothing spent.
    let now = p.clock.now();
    assert_eq!(p.a.poll(now, &mut p.rng), Polled::Idle);
    assert_eq!(spent(), Counts::default());
    let _ = SendReason::Keepalive;
}
