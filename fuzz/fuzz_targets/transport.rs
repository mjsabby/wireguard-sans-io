//! Fuzz transport intake on an established pair: arbitrary mutations of a
//! genuine datagram plus pure garbage, against live session state.
#![no_main]

use std::net::SocketAddr;

use libfuzzer_sys::fuzz_target;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    Device, Encapsulated, PeerConfig, PeerId, PollOutput, Received, StaticSecret, Ticks, Tunnel,
    WallClock,
};

struct Side {
    device: Device,
    tunnel: Tunnel,
    addr: SocketAddr,
}

fn establish() -> (Side, Side, DeterministicRng) {
    let mut rng = DeterministicRng::new(0xe57ab);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let (a_pub, b_pub) = (a_key.public_key(), b_key.public_key());
    let a_addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
    let b_addr: SocketAddr = "192.0.2.2:51820".parse().unwrap();
    let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
    let side = |key, peer, addr, peer_addr, rng: &mut DeterministicRng| {
        let device = Device::new(key, wall, rng).unwrap();
        let mut cfg = PeerConfig::new(peer);
        cfg.endpoint = Some(peer_addr);
        let tunnel = device.tunnel(PeerId::new(0).unwrap(), cfg, rng).unwrap();
        Side {
            device,
            tunnel,
            addr,
        }
    };
    let mut a = side(a_key, b_pub, a_addr, b_addr, &mut rng);
    let mut b = side(b_key, a_pub, b_addr, a_addr, &mut rng);

    let now = Ticks::ZERO;
    let mut out = [0u8; 128];
    let poll = |s: &mut Side, rng: &mut DeterministicRng| {
        let mut buf = [0u8; 256];
        match s.tunnel.poll(now, &mut buf, rng).unwrap() {
            PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
            other => unreachable!("{other:?}"),
        }
    };
    a.tunnel.request_handshake(now);
    let mut init = poll(&mut a, &mut rng);
    let mut resp = match b
        .device
        .receive_for(
            &mut b.tunnel,
            now,
            a.addr,
            false,
            &mut init,
            &mut out,
            &mut rng,
        )
        .unwrap()
        .received
    {
        Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
        other => unreachable!("{other:?}"),
    };
    let mut out = [0u8; 128];
    a.device
        .receive_for(
            &mut a.tunnel,
            now,
            b.addr,
            false,
            &mut resp,
            &mut out,
            &mut rng,
        )
        .unwrap();
    let mut confirm = poll(&mut a, &mut rng);
    b.device
        .receive_for(
            &mut b.tunnel,
            now,
            a.addr,
            false,
            &mut confirm,
            &mut out,
            &mut rng,
        )
        .unwrap();
    assert!(a.tunnel.is_established(now) && b.tunnel.is_established(now));
    (a, b, rng)
}

fuzz_target!(|input: (u16, &[u8])| {
    let (mutation_seed, fuzz_bytes) = input;
    let (mut a, mut b, mut rng) = establish();
    let now = Ticks::from_nanos(1_000_000);
    // An address that is not A's: nothing below may make B roam to it
    // unless the datagram is genuine.
    let elsewhere: SocketAddr = "203.0.113.9:9".parse().unwrap();

    // 1. A genuine datagram with fuzzer-chosen byte splices applied.
    let mut wire = [0u8; 256];
    let genuine = match a
        .tunnel
        .encapsulate(now, b"payload under test", &mut wire)
        .unwrap()
    {
        Encapsulated::Transport(tx) => tx.datagram.to_vec(),
        other => unreachable!("{other:?}"),
    };
    let mut mutated = genuine.clone();
    for (i, &byte) in fuzz_bytes.iter().enumerate() {
        let pos = (usize::from(mutation_seed) + i * 7) % mutated.len();
        mutated[pos] ^= byte;
    }
    let mut copy = mutated.clone();
    let mut out = [0xEEu8; 128];
    // (delivered payload, endpoint changed) — owned, so the buffers can
    // be inspected afterwards.
    let (delivered, moved) = {
        let handled = b
            .device
            .receive_for(
                &mut b.tunnel,
                now,
                elsewhere,
                false,
                &mut copy,
                &mut out,
                &mut rng,
            )
            .expect("never a local fault");
        let delivered = match handled.received {
            Received::Data(d) => Some(d.to_vec()),
            Received::Dropped(_) => None,
            other => panic!("unexpected outcome for a transport datagram: {other:?}"),
        };
        (delivered, handled.endpoint_changed)
    };
    assert!(out.iter().all(|&x| x == 0xEE), "transport wrote to `out`");
    if mutated == genuine {
        let d = delivered.expect("genuine datagram rejected");
        assert_eq!(&d[..18], b"payload under test");
        assert!(moved);
        assert_eq!(b.tunnel.endpoint(), Some(elsewhere));
    } else {
        assert!(delivered.is_none(), "a mutated datagram was accepted");
        assert_eq!(copy, mutated, "buffer modified on reject");
        assert!(!moved);
        assert_eq!(
            b.tunnel.endpoint(),
            Some(a.addr),
            "a forgery moved the endpoint"
        );
    }

    // 2. The raw fuzz input as a datagram in both directions. It must be
    //    dropped — with one legitimate exception: libFuzzer can learn the
    //    genuine datagram from the comparison above and present it here
    //    verbatim. If it was not already delivered in step 1, B accepts
    //    that one (it IS genuine); a second copy is a replay.
    let genuine_still_fresh = mutated != genuine;
    for (side, is_b) in [(&mut a, false), (&mut b, true)] {
        let before = side.tunnel.endpoint();
        let mut copy = fuzz_bytes.to_vec();
        let mut out = [0u8; 128];
        let dropped = {
            let handled = side
                .device
                .receive_for(
                    &mut side.tunnel,
                    now,
                    elsewhere,
                    false,
                    &mut copy,
                    &mut out,
                    &mut rng,
                )
                .expect("never a local fault");
            matches!(handled.received, Received::Dropped(_))
        };
        if dropped {
            assert_eq!(copy, fuzz_bytes);
            assert_eq!(side.tunnel.endpoint(), before);
        } else {
            assert!(
                is_b && genuine_still_fresh && fuzz_bytes == genuine.as_slice(),
                "raw fuzz input was accepted"
            );
        }
    }
});
