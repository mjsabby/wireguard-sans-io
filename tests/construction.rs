//! Making devices and tunnels: by value, and in place.
//!
//! `Device::new` and `Device::tunnel` return what they make, and the
//! caller moves it to where it is kept. `Device::new_in` and
//! `Device::tunnel_in` make it there. Both ways must give the same device
//! and the same tunnel; the difference is in what is left behind on the
//! way (`scripts/check_secret_residue.sh`) and in how much stack it takes
//! (`scripts/check_no_std.sh` reports it), neither of which a test in
//! this language can see.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::num::NonZeroU16;

use common::{a_addr, b_addr, id, wall};
use wireguard_sans_io::testing::{DeterministicRng, FailingRng};
use wireguard_sans_io::{
    Device, EntropySource, Error, PeerConfig, PollOutput, PresharedKey, PublicKey, StaticSecret,
    Ticks, Tunnel,
};

fn config(peer: PublicKey) -> PeerConfig {
    let mut config = PeerConfig::new(peer);
    config.psk = PresharedKey::from_bytes([0x5a; 32]);
    config.endpoint = Some(b_addr());
    config.mtu = NonZeroU16::new(1420);
    config.persistent_keepalive = NonZeroU16::new(25);
    config
}

/// The first initiation a tunnel sends: everything that went into making
/// the tunnel — the static key, the peer's key, the pre-shared key's
/// absence from this message aside, the index key, the order of its
/// indices — shows in these 148 bytes.
fn first_initiation(tunnel: &mut Tunnel, rng: &mut dyn EntropySource) -> Vec<u8> {
    let now = Ticks::from_secs(1);
    tunnel.request_handshake(now);
    let mut out = [0u8; 256];
    match tunnel.poll(now, &mut out, rng).unwrap() {
        PollOutput::Transmit(tx, _) => {
            assert_eq!(tx.dst, b_addr());
            tx.datagram.to_vec()
        }
        other => panic!("{other:?}"),
    }
}

/// A responder for `initiator`'s messages that knows the pre-shared key:
/// it answers only if the tunnel under test has all three of the static
/// key, the peer key and the pre-shared key right.
fn responder_accepts(responder: &StaticSecret, initiator: PublicKey, initiation: &[u8]) -> bool {
    let mut rng = DeterministicRng::new(0xbeef);
    let device = Device::new(responder.clone(), wall(), &mut rng).unwrap();
    let mut peer = config(initiator);
    peer.endpoint = None;
    let mut tunnel = device.tunnel(id(1), peer, &mut rng).unwrap();
    let mut device = device;
    let mut datagram = initiation.to_vec();
    let mut out = [0u8; 256];
    matches!(
        device
            .receive_for(
                &mut tunnel,
                Ticks::from_secs(1),
                a_addr(),
                false,
                &mut datagram,
                &mut out,
                &mut rng
            )
            .map(|handled| handled.received),
        Ok(wireguard_sans_io::Received::HandshakeResponse(_))
    )
}

#[test]
fn in_place_and_by_value_make_the_same_device_and_the_same_tunnel() {
    let mut keys = DeterministicRng::new(0xc0de);
    let ours = StaticSecret::generate(&mut keys).unwrap();
    let theirs = StaticSecret::generate(&mut keys).unwrap();
    let peer = theirs.public_key();

    // By value.
    let mut rng = DeterministicRng::new(77);
    let device = Device::new(ours.clone(), wall(), &mut rng).unwrap();
    let mut tunnel = device.tunnel(id(9), config(peer), &mut rng).unwrap();
    let by_value = first_initiation(&mut tunnel, &mut rng);

    // In place, from the same entropy.
    let mut rng = DeterministicRng::new(77);
    let mut device_slot = None;
    let device_in = Device::new_in(&mut device_slot, &ours, wall(), &mut rng).unwrap();
    assert_eq!(device_in.public_key(), device.public_key());
    assert_eq!(device_in.public_key(), ours.public_key());
    let mut tunnel_slot = None;
    let tunnel_in = device_in
        .tunnel_in(&mut tunnel_slot, id(9), &config(peer), &mut rng)
        .unwrap();
    assert_eq!(tunnel_in.peer_public(), peer);
    assert_eq!(tunnel_in.endpoint(), Some(b_addr()));
    let in_place = first_initiation(tunnel_in, &mut rng);

    // Byte for byte the same message: same keys, same index key, same
    // order of indices, same ephemeral.
    assert_eq!(in_place, by_value);
    // And a message the peer accepts — which takes the static key, the
    // peer's key and the pre-shared key.
    assert!(responder_accepts(&theirs, ours.public_key(), &in_place));
    // (The check can fail: not with another pre-shared key in the tunnel.)
    let mut other = config(peer);
    other.psk = PresharedKey::from_bytes([0x5b; 32]);
    let mut wrong_psk = None;
    let wrong = device_in
        .tunnel_in(&mut wrong_psk, id(9), &other, &mut rng)
        .unwrap();
    let initiation = first_initiation(wrong, &mut rng);
    // The initiation itself does not depend on the pre-shared key; the
    // response does, so the responder still answers…
    assert!(responder_accepts(&theirs, ours.public_key(), &initiation));
    // …and a tunnel with another *static* key is not answered.
    let stranger = StaticSecret::generate(&mut keys).unwrap();
    let mut stranger_device = None;
    let stranger_device =
        Device::new_in(&mut stranger_device, &stranger, wall(), &mut rng).unwrap();
    let mut stranger_tunnel = None;
    let stranger_tunnel = stranger_device
        .tunnel_in(&mut stranger_tunnel, id(9), &config(peer), &mut rng)
        .unwrap();
    let initiation = first_initiation(stranger_tunnel, &mut rng);
    assert!(!responder_accepts(&theirs, ours.public_key(), &initiation));

    // The slots hold what was made in them.
    assert!(device_slot.is_some() && tunnel_slot.is_some());
}

/// Both ends made in place complete a handshake and carry data — with the
/// pre-shared key, which only the second handshake message proves.
#[test]
fn two_ends_made_in_place_talk_to_each_other() {
    let mut rng = DeterministicRng::new(0x1a);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let (mut a_dev, mut b_dev, mut a_tun, mut b_tun) = (None, None, None, None);
    let a_dev = Device::new_in(&mut a_dev, &a_key, wall(), &mut rng).unwrap();
    let b_dev = Device::new_in(&mut b_dev, &b_key, wall(), &mut rng).unwrap();
    let a = a_dev
        .tunnel_in(&mut a_tun, id(1), &config(b_key.public_key()), &mut rng)
        .unwrap();
    let mut b_config = config(a_key.public_key());
    b_config.endpoint = None;
    let b = b_dev
        .tunnel_in(&mut b_tun, id(2), &b_config, &mut rng)
        .unwrap();

    let now = Ticks::from_secs(1);
    let mut initiation = first_initiation(a, &mut rng);
    let mut out = [0u8; 256];
    let mut response = match b_dev
        .receive_for(b, now, a_addr(), false, &mut initiation, &mut out, &mut rng)
        .unwrap()
        .received
    {
        wireguard_sans_io::Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
        other => panic!("{other:?}"),
    };
    let mut out = [0u8; 256];
    let handled = a_dev
        .receive_for(a, now, b_addr(), false, &mut response, &mut out, &mut rng)
        .unwrap();
    assert!(matches!(
        handled.received,
        wireguard_sans_io::Received::HandshakeComplete
    ));
    assert!(a.is_established(now));
}

#[test]
fn the_slot_is_emptied_first_and_is_empty_after_an_error() {
    let mut rng = DeterministicRng::new(0x51);
    let ours = StaticSecret::generate(&mut rng).unwrap();
    let theirs = StaticSecret::generate(&mut rng).unwrap().public_key();
    let mut device_slot = None;
    let device = Device::new_in(&mut device_slot, &ours, wall(), &mut rng).unwrap();

    let mut slot = None;
    // Our own key as the peer's, a low-order point, no entropy: each is
    // refused, and each leaves the slot empty — also when a tunnel was in
    // it before.
    for refill in [false, true] {
        for (what, peer, expected) in [
            ("our own key", ours.public_key(), Error::InvalidPublicKey),
            (
                "a low-order point",
                PublicKey::from_bytes([0u8; 32]),
                Error::InvalidPublicKey,
            ),
        ] {
            if refill {
                device
                    .tunnel_in(&mut slot, id(1), &config(theirs), &mut rng)
                    .unwrap();
            }
            let got = device
                .tunnel_in(&mut slot, id(1), &config(peer), &mut rng)
                .map(|_| ());
            assert_eq!(got, Err(expected), "{what}");
            assert!(slot.is_none(), "{what}");
            // The by-value constructor says the same.
            assert_eq!(
                device.tunnel(id(1), config(peer), &mut rng).map(|_| ()),
                Err(expected),
                "{what}"
            );
        }
        if refill {
            device
                .tunnel_in(&mut slot, id(1), &config(theirs), &mut rng)
                .unwrap();
        }
        let got = device
            .tunnel_in(&mut slot, id(1), &config(theirs), &mut FailingRng)
            .map(|_| ());
        assert_eq!(got, Err(Error::EntropyFailure));
        assert!(slot.is_none());
        assert_eq!(
            device
                .tunnel(id(1), config(theirs), &mut FailingRng)
                .map(|_| ()),
            Err(Error::EntropyFailure)
        );
    }

    // The same for a device.
    let mut other = None;
    Device::new_in(&mut other, &ours, wall(), &mut rng).unwrap();
    assert!(other.is_some());
    assert_eq!(
        Device::new_in(&mut other, &ours, wall(), &mut FailingRng).map(|_| ()),
        Err(Error::EntropyFailure)
    );
    assert!(other.is_none());
    assert_eq!(
        Device::new(ours.clone(), wall(), &mut FailingRng).map(|_| ()),
        Err(Error::EntropyFailure)
    );

    // A slot that already holds a tunnel gets the new one: the old one is
    // gone (its peer is not the slot's peer any more).
    let third = StaticSecret::generate(&mut rng).unwrap().public_key();
    device
        .tunnel_in(&mut slot, id(1), &config(theirs), &mut rng)
        .unwrap();
    let replaced = device
        .tunnel_in(&mut slot, id(2), &config(third), &mut rng)
        .unwrap();
    assert_eq!(replaced.peer_public(), third);
}
