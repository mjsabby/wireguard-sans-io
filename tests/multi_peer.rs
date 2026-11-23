//! One device, many peers: routing, cost, index privacy, shared cookie
//! state, and per-peer isolation — all through the two-step public path
//! an embedder with a peer table uses (`Device::receive`, then
//! `Tunnel::handle` / `Tunnel::handle_initiation`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

mod common;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use common::{Polled, Rx, RxInfo, S, Side, Tx, b_addr, id, wall};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    Device, DropReason, EntropySource, Incoming, PeerConfig, PeerId, PublicKey, Received,
    SendReason, StaticSecret, Ticks, Tunnel,
};

fn server_addr() -> SocketAddr {
    b_addr()
}

fn client_addr(i: usize) -> SocketAddr {
    format!("198.51.100.{}:{}", i % 250 + 1, 20_000 + i)
        .parse()
        .unwrap()
}

/// What an embedder with a peer table builds around a `Device`: the
/// tunnels in a `Vec` indexed by `PeerId`, and a map from public key to
/// that index for handshake initiations.
struct Server {
    device: Device,
    peers: Vec<Tunnel>,
    by_key: HashMap<[u8; 32], usize>,
}

impl Server {
    fn new(n: usize, rng: &mut DeterministicRng) -> (Self, Vec<StaticSecret>) {
        let (key, _) = common::keypair(rng);
        let device = Device::new(key, wall(), rng).unwrap();
        let mut peers = Vec::new();
        let mut by_key = HashMap::new();
        let mut client_keys = Vec::new();
        for i in 0..n {
            let (client_key, client_pub) = common::keypair(rng);
            peers.push(
                device
                    .tunnel(id(i as u32), PeerConfig::new(client_pub), rng)
                    .unwrap(),
            );
            by_key.insert(*client_pub.as_bytes(), i);
            client_keys.push(client_key);
        }
        (
            Self {
                device,
                peers,
                by_key,
            },
            client_keys,
        )
    }

    fn public(&self) -> PublicKey {
        self.device.public_key()
    }

    /// The receive path: one device call, one table lookup, one tunnel
    /// call. Returns which peer (if any) the datagram was dispatched to.
    fn receive(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        under_load: bool,
        datagram: &[u8],
        rng: &mut dyn EntropySource,
    ) -> (Option<usize>, RxInfo) {
        let mut copy = datagram.to_vec();
        let mut out = [0u8; 128];
        let dropped = RxInfo::dropped;
        match self.device.receive(now, src, under_load, &mut copy) {
            Incoming::Initiation(mut init) => {
                assert_eq!(init.src(), src);
                let public = match self.device.identify(&mut init) {
                    Ok(public) => public,
                    Err(reason) => return (None, dropped(reason)),
                };
                let Some(&peer) = self.by_key.get(public.as_bytes()) else {
                    return (None, dropped(DropReason::UnknownPeer));
                };
                let handled = self.peers[peer]
                    .handle_initiation(now, &init, &mut out, rng)
                    .unwrap();
                (Some(peer), RxInfo::from_handled(&handled))
            }
            Incoming::ForPeer(peer_id, packet) => {
                let peer = peer_id.get() as usize;
                let Some(tunnel) = self.peers.get_mut(peer) else {
                    return (None, dropped(DropReason::UnknownIndex));
                };
                let handled = tunnel.handle(now, src, packet).unwrap();
                (Some(peer), RxInfo::from_handled(&handled))
            }
            Incoming::CookieRequired(challenge) => {
                let reply = self
                    .device
                    .cookie_reply(now, &challenge, &mut out, rng)
                    .unwrap();
                assert_eq!(reply.dst, src);
                (None, RxInfo::cookie_reply(&reply))
            }
            Incoming::Dropped(reason) => (None, dropped(reason)),
            other => panic!("unhandled {other:?}"),
        }
    }
}

fn client(
    key: StaticSecret,
    server_pub: PublicKey,
    addr: SocketAddr,
    rng: &mut DeterministicRng,
) -> Side {
    common::side(key, server_pub, addr, Some(server_addr()), None, None, rng)
}

/// Full handshake between `client` and its server-side tunnel.
fn establish(
    server: &mut Server,
    client: &mut Side,
    expect_peer: usize,
    now: Ticks,
    rng: &mut DeterministicRng,
) {
    let init = client.initiate(now, rng);
    let (peer, info) = server.receive(now, client.addr, false, &init, rng);
    assert_eq!(peer, Some(expect_peer), "initiation routed by public key");
    let resp = match info.rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        client.recv_from(now, server_addr(), false, &resp, rng).rx,
        Rx::HandshakeComplete
    );
    let confirm = match client.poll(now, rng) {
        Polled::Transmit(w, SendReason::Keepalive, _) => w,
        other => panic!("{other:?}"),
    };
    let (peer, info) = server.receive(now, client.addr, false, &confirm, rng);
    assert_eq!(
        peer,
        Some(expect_peer),
        "transport routed by receiver index"
    );
    assert_eq!(info.rx, Rx::Keepalive);
    assert!(info.session_established);
}

/// The headline property: routing a handshake initiation costs ONE X25519
/// at the device, whatever the number of peers, and involves no tunnel but
/// the right one.
#[test]
fn initiation_routing_cost_is_independent_of_peer_count() {
    for n in [1usize, 64, 1000] {
        let mut rng = DeterministicRng::new(0x3000 + n as u64);
        let (mut server, keys) = Server::new(n, &mut rng);
        let now = Ticks::ZERO;
        // The LAST configured peer initiates (worst case for any scan).
        let who = n - 1;
        let mut c = client(
            keys[who].clone(),
            server.public(),
            client_addr(who),
            &mut rng,
        );
        let init = c.initiate(now, &mut rng);

        let (peer, info) = server.receive(now, c.addr, false, &init, &mut rng);
        assert_eq!(peer, Some(who));
        assert!(matches!(info.rx, Rx::Response(_)));

        // Exactly one initiation got past the MAC checks…
        assert_eq!(server.device.stats().initiations, 1);
        // …and no other tunnel was touched in any way.
        for (i, tunnel) in server.peers.iter().enumerate() {
            let stats = tunnel.stats();
            if i == who {
                assert_eq!(stats.handshakes_responded, 1);
                assert_eq!(tunnel.endpoint(), Some(c.addr));
            } else {
                assert_eq!(stats, Default::default(), "peer {i} was disturbed");
                assert_eq!(tunnel.endpoint(), None);
                assert_eq!(tunnel.next_wake(), None);
            }
        }
    }
    // That is the whole of it: the initiation was offered to one tunnel —
    // the one its key names — and to no other, whatever their number. What
    // the work costs is counted, in cryptographic operations, by
    // `tests/cost.rs`; nothing here is timed. (This test used to compare
    // wall-clock times, and failed now and then on a machine that had
    // other things to do.)
}

#[test]
fn every_message_type_reaches_exactly_its_own_tunnel() {
    let mut rng = DeterministicRng::new(0x3001);
    let n = 8;
    let (mut server, keys) = Server::new(n, &mut rng);
    let now = Ticks::ZERO;
    let mut clients: Vec<Side> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| client(k.clone(), server.public(), client_addr(i), &mut rng))
        .collect();

    // Everyone connects, in a scrambled order.
    for i in [5usize, 0, 7, 2, 1, 6, 3, 4] {
        establish(&mut server, &mut clients[i], i, now, &mut rng);
    }
    // Client → server data lands in the right tunnel and nowhere else.
    for (i, c) in clients.iter_mut().enumerate() {
        let payload = format!("hello from client {i}");
        let wire = match c.send(now, payload.as_bytes()) {
            Tx::Transport(w) => w,
            other => panic!("{other:?}"),
        };
        let (peer, info) = server.receive(now, c.addr, false, &wire, &mut rng);
        assert_eq!(peer, Some(i));
        match info.rx {
            Rx::Data(d) => assert_eq!(&d[..payload.len()], payload.as_bytes()),
            other => panic!("{other:?}"),
        }
    }
    for (i, tunnel) in server.peers.iter().enumerate() {
        let s = tunnel.stats();
        assert_eq!(s.rx_transport, 2, "peer {i}: its keepalive and its data");
        assert_eq!(s.auth_failures, 0, "peer {i}");
        assert_eq!(tunnel.endpoint(), Some(client_addr(i)));
    }
    // Server → client: each tunnel addresses its own client.
    for (i, tunnel) in server.peers.iter_mut().enumerate() {
        let mut buf = [0u8; 128];
        let wire = match tunnel.encapsulate(now, b"reply", &mut buf).unwrap() {
            wireguard_sans_io::Encapsulated::Transport(tx) => {
                assert_eq!(tx.dst, client_addr(i));
                tx.datagram.to_vec()
            }
            other => panic!("{other:?}"),
        };
        // The right client decrypts it; every other client rejects it.
        for (j, c) in clients.iter_mut().enumerate() {
            let rx = c.recv_from(now, server_addr(), false, &wire, &mut rng).rx;
            if i == j {
                assert!(matches!(rx, Rx::Data(_)));
            } else {
                assert!(
                    matches!(rx, Rx::Dropped(_)),
                    "client {j} accepted {i}'s packet"
                );
            }
        }
    }
}

/// A datagram dispatched to the wrong tunnel (an embedder bug, or a
/// stale table) is refused by that tunnel before any cryptography.
#[test]
fn a_tunnel_refuses_packets_addressed_to_another_peer() {
    let mut rng = DeterministicRng::new(0x3002);
    let (mut server, keys) = Server::new(2, &mut rng);
    let now = Ticks::ZERO;
    let mut c0 = client(keys[0].clone(), server.public(), client_addr(0), &mut rng);
    let mut c1 = client(keys[1].clone(), server.public(), client_addr(1), &mut rng);
    establish(&mut server, &mut c0, 0, now, &mut rng);
    establish(&mut server, &mut c1, 1, now, &mut rng);

    let Tx::Transport(wire) = c0.send(now, b"for tunnel 0") else {
        panic!()
    };
    // Route by hand to the WRONG tunnel.
    let mut copy = wire.clone();
    let Incoming::ForPeer(peer_id, packet) = server.device.receive(now, c0.addr, false, &mut copy)
    else {
        panic!()
    };
    assert_eq!(peer_id, id(0));
    let handled = server.peers[1].handle(now, c0.addr, packet).unwrap();
    assert!(matches!(
        handled.received,
        wireguard_sans_io::Received::Dropped(DropReason::UnknownIndex)
    ));
    assert_eq!(server.peers[1].stats().auth_failures, 0);
    assert_eq!(
        server.peers[1].endpoint(),
        Some(c1.addr),
        "no roaming either"
    );

    // The same for an initiation handed to the wrong peer's tunnel.
    let later = Ticks::from_secs(6);
    let init = c0.initiate(later, &mut rng);
    let mut copy = init.clone();
    let Incoming::Initiation(mut pending) = server.device.receive(later, c0.addr, false, &mut copy)
    else {
        panic!()
    };
    assert_eq!(
        server.device.identify(&mut pending).unwrap(),
        server.peers[0].peer_public()
    );
    let mut out = [0u8; 128];
    let handled = server.peers[1]
        .handle_initiation(later, &pending, &mut out, &mut rng)
        .unwrap();
    assert!(matches!(
        handled.received,
        wireguard_sans_io::Received::Dropped(DropReason::UnknownPeer)
    ));
    assert_eq!(server.peers[1].endpoint(), Some(c1.addr));
    assert_eq!(server.peers[1].stats().handshakes_responded, 1);
}

/// An initiation from an identity the server has no peer for costs the
/// device's one X25519 and touches no tunnel.
/// `DeviceStats::routed` counts what [`Device::receive`] routed to a peer
/// by its receiver index — and nothing else: not an initiation (which
/// names its peer by key, not by index), not a datagram that was dropped,
/// and nothing that went through `Device::receive_for`, which has one
/// tunnel and nothing to route. An embedder with a single peer reads this
/// counter to check that its data path does not pay for routing.
#[test]
fn routed_counts_what_was_routed_by_index_and_nothing_else() {
    let mut p = common::new_pair(91);
    let now = p.clock.now();
    let routed = |side: &common::Side| side.device.stats().routed;

    // The handshake, through the routed path: the initiation is not
    // routed by index, the response and the confirming keepalive are.
    let init = p.a_initiates();
    let resp = match p.b.recv_routed(now, p.a.addr, false, &init, &mut p.rng).rx {
        common::Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(routed(&p.b), 0, "an initiation carries no index of ours");
    let done = p.a.recv_routed(now, p.b.addr, false, &resp, &mut p.rng);
    assert_eq!(done.rx, common::Rx::HandshakeComplete);
    assert_eq!(routed(&p.a), 1);

    // Transport data, routed: one each.
    for n in 1..=5u64 {
        let common::Tx::Transport(w) = p.a.send(now, b"data") else {
            panic!("no session");
        };
        let got = p.b.recv_routed(now, p.a.addr, false, &w, &mut p.rng);
        assert!(matches!(got.rx, common::Rx::Data(_)), "{:?}", got.rx);
        assert_eq!(routed(&p.b), n);
    }
    // The single-call path does the same work without routing.
    for _ in 0..5 {
        let common::Tx::Transport(w) = p.a.send(now, b"data") else {
            panic!("no session");
        };
        let got = p.b.recv_from(now, p.a.addr, false, &w, &mut p.rng);
        assert!(matches!(got.rx, common::Rx::Data(_)), "{:?}", got.rx);
    }
    assert_eq!(routed(&p.b), 5, "receive_for does not route");
    // What is dropped before routing is not counted.
    let _ =
        p.b.recv_routed(now, p.a.addr, false, &[4u8; 20], &mut p.rng);
    let _ =
        p.b.recv_routed(now, p.a.addr, false, &[1u8; 148], &mut p.rng);
    assert_eq!(routed(&p.b), 5);
}

/// An initiation from someone who knows the server's public key but is
/// not one of its peers. The library says who the sender claims to be —
/// and that is all it does: no tunnel is touched, because there is none
/// to hand the initiation to. And a tunnel that is handed it anyway, by
/// an embedder whose table is wrong, refuses it itself.
#[test]
fn an_initiation_from_a_stranger_touches_no_tunnel() {
    let mut rng = DeterministicRng::new(0x3003);
    let (mut server, _keys) = Server::new(16, &mut rng);
    let (stranger_key, stranger_public) = common::keypair(&mut rng);
    let mut stranger = client(stranger_key, server.public(), client_addr(99), &mut rng);
    let init = stranger.initiate(Ticks::ZERO, &mut rng);
    let untouched = |server: &Server| {
        server.peers.iter().all(|t| {
            t.stats() == Default::default() && t.endpoint().is_none() && t.next_wake().is_none()
        })
    };
    assert!(untouched(&server));

    // What the library reports, step by step.
    let mut copy = init.clone();
    let mut out = [0u8; 128];
    match server
        .device
        .receive(Ticks::ZERO, stranger.addr, false, &mut copy)
    {
        Incoming::Initiation(mut initiation) => {
            // It passed `mac1` (the stranger knows our public key), and
            // identification names a key nobody here has.
            assert_eq!(server.device.identify(&mut initiation), Ok(stranger_public));
            assert!(!server.by_key.contains_key(stranger_public.as_bytes()));
            assert!(untouched(&server), "identifying is not accepting");
            // Handed to the wrong tunnel all the same: refused, by the
            // tunnel, with nothing sent and nothing learned.
            let wrong = &mut server.peers[5];
            let handled = wrong
                .handle_initiation(Ticks::ZERO, &initiation, &mut out, &mut rng)
                .unwrap();
            assert!(
                matches!(handled.received, Received::Dropped(DropReason::UnknownPeer)),
                "{:?}",
                handled.received
            );
            assert!(!handled.endpoint_changed && !handled.session_established);
            assert_eq!(out, [0u8; 128], "nothing was written");
            assert_eq!(wrong.endpoint(), None);
            assert_eq!(wrong.next_wake(), None);
            assert_eq!(wrong.stats().handshakes_responded, 0);
        }
        other => panic!("{other:?}"),
    }
    // The harness around the device (a peer table, as an embedder has
    // one) therefore dispatches it to nobody.
    let (peer, _) = server.receive(Ticks::ZERO, stranger.addr, false, &init, &mut rng);
    assert_eq!(peer, None);
    assert_eq!(server.device.stats().initiations, 2);
}

/// Session indices are a keyed permutation of (peer, slot): on the wire
/// they neither reveal which peer they belong to nor link one peer's
/// sessions to each other.
#[test]
fn indices_on_the_wire_do_not_identify_the_peer() {
    let mut rng = DeterministicRng::new(0x3004);
    let (mut server, keys) = Server::new(4, &mut rng);
    let mut clients: Vec<Side> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| client(k.clone(), server.public(), client_addr(i), &mut rng))
        .collect();

    // Collect the server's index (the `sender` field of its responses)
    // over 60 handshakes per peer.
    let mut indices: Vec<Vec<u32>> = vec![Vec::new(); 4];
    for round in 0..60u64 {
        let now = Ticks::from_secs(round * 6);
        for (i, c) in clients.iter_mut().enumerate() {
            let init = c.initiate(now, &mut rng);
            let (_, info) = server.receive(now, c.addr, false, &init, &mut rng);
            let Rx::Response(resp) = info.rx else {
                panic!()
            };
            indices[i].push(u32::from_le_bytes(resp[4..8].try_into().unwrap()));
            let _ = c.recv_from(now, server_addr(), false, &resp, &mut rng);
        }
    }
    // All 240 are distinct.
    let all: HashSet<u32> = indices.iter().flatten().copied().collect();
    assert_eq!(all.len(), 240);
    for (peer, list) in indices.iter().enumerate() {
        // No stable bits: each of the four bytes takes many values within
        // one peer (a `peer << n | counter` layout would freeze some).
        for byte in 0..4 {
            let distinct: HashSet<u8> = list.iter().map(|v| v.to_le_bytes()[byte]).collect();
            assert!(
                distinct.len() >= 40,
                "peer {peer}: byte {byte} of its indices takes only {} values",
                distinct.len()
            );
        }
        // Consecutive indices are not consecutive numbers.
        let adjacent = list
            .windows(2)
            .filter(|w| w[0].abs_diff(w[1]) < 1 << 12)
            .count();
        assert!(
            adjacent <= 1,
            "peer {peer}: {adjacent} near-consecutive indices"
        );
        // On average, two of this peer's indices differ in about half of
        // their bits — as do two indices of different peers.
        let same: u32 = list.windows(2).map(|w| (w[0] ^ w[1]).count_ones()).sum();
        let mean_same = f64::from(same) / (list.len() - 1) as f64;
        assert!(
            (13.0..19.0).contains(&mean_same),
            "peer {peer}: {mean_same:.1}"
        );
    }
}

/// After a restart the device has a new index key: datagrams addressed to
/// the old device's sessions decode to arbitrary peers and are refused.
#[test]
fn indices_from_another_device_instance_are_refused() {
    let mut rng = DeterministicRng::new(0x3005);
    let (mut server, keys) = Server::new(4, &mut rng);
    let now = Ticks::ZERO;
    let mut c = client(keys[2].clone(), server.public(), client_addr(2), &mut rng);
    establish(&mut server, &mut c, 2, now, &mut rng);
    let Tx::Transport(wire) = c.send(now, b"to the old instance") else {
        panic!()
    };

    // "Restart": same static key and peers, fresh entropy.
    let mut rng2 = DeterministicRng::new(0x9999);
    let server_key = {
        let mut r = DeterministicRng::new(0x3005);
        common::keypair(&mut r).0
    };
    let device = Device::new(server_key, wall(), &mut rng2).unwrap();
    assert_eq!(device.public_key(), server.public());
    let peers: Vec<Tunnel> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            device
                .tunnel(id(i as u32), PeerConfig::new(k.public_key()), &mut rng2)
                .unwrap()
        })
        .collect();
    let mut restarted = Server {
        device,
        peers,
        by_key: server.by_key.clone(),
    };
    let (_, info) = restarted.receive(now, c.addr, false, &wire, &mut rng2);
    assert_eq!(info.rx, Rx::Dropped(DropReason::UnknownIndex));
    // The client's dead-peer detection then re-handshakes with the new
    // instance, which works.
    let later = Ticks::from_secs(16);
    let (wires, _) = c.drain(later, &mut rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
    let (peer, info) = restarted.receive(later, c.addr, false, &wires[0].0, &mut rng2);
    assert_eq!(peer, Some(2));
    assert!(matches!(info.rx, Rx::Response(_)));
}

/// Arbitrary receiver indices decode to *some* well-formed peer id; an
/// embedder's table lookup simply misses, or the tunnel refuses.
#[test]
fn garbage_indices_decode_to_well_formed_peer_ids() {
    let mut rng = DeterministicRng::new(0x3006);
    let (mut server, _) = Server::new(3, &mut rng);
    let mut seen_ids = HashSet::new();
    for _ in 0..5000 {
        let mut dg = vec![0u8; 48];
        rng.fill(&mut dg).unwrap();
        dg[0] = 4;
        dg[1..4].fill(0);
        let mut copy = dg.clone();
        match server
            .device
            .receive(Ticks::ZERO, client_addr(0), false, &mut copy)
        {
            Incoming::ForPeer(peer_id, _) => {
                assert!(peer_id.get() <= PeerId::MAX);
                seen_ids.insert(peer_id.get());
            }
            other => panic!("{other:?}"),
        }
        let (_, info) = server.receive(Ticks::ZERO, client_addr(0), false, &dg, &mut rng);
        assert_eq!(info.rx, Rx::Dropped(DropReason::UnknownIndex));
    }
    assert!(seen_ids.len() > 4900, "ids are spread over the whole space");
    assert!(server.peers.iter().all(|t| t.stats().auth_failures == 0));
}

/// The cookie secret belongs to the device: a cookie is valid for a
/// source address whichever peer uses it, and the device's load gate
/// protects every peer at once.
#[test]
fn cookie_state_is_shared_by_all_peers() {
    let mut rng = DeterministicRng::new(0x3007);
    let (mut server, keys) = Server::new(3, &mut rng);
    let mut clients: Vec<Side> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| client(k.clone(), server.public(), client_addr(i), &mut rng))
        .collect();
    let now = Ticks::ZERO;

    // Under load every peer's first initiation is answered with a cookie
    // and no Diffie-Hellman is done.
    let mut cookies = Vec::new();
    for c in clients.iter_mut() {
        let init = c.initiate(now, &mut rng);
        let (peer, info) = server.receive(now, c.addr, true, &init, &mut rng);
        assert_eq!(peer, None, "no tunnel is involved in the cookie path");
        let Rx::CookieReply(reply) = info.rx else {
            panic!()
        };
        cookies.push(reply);
    }
    assert_eq!(server.device.stats().initiations, 0);
    assert_eq!(server.device.stats().cookies_sent, 3);

    // Each client stores its cookie and retries; the loaded server now
    // processes each one.
    let later = Ticks::from_secs(6);
    for (i, c) in clients.iter_mut().enumerate() {
        assert_eq!(
            c.recv_from(now, server_addr(), false, &cookies[i], &mut rng)
                .rx,
            Rx::CookieStored
        );
        let retry = match c.poll(later, &mut rng) {
            Polled::Transmit(w, SendReason::HandshakeRetransmit, _) => w,
            other => panic!("{other:?}"),
        };
        // From another client's address the cookie proves nothing…
        let other_addr = client_addr((i + 1) % 3);
        let (_, info) = server.receive(later, other_addr, true, &retry, &mut rng);
        assert!(
            matches!(info.rx, Rx::CookieReply(_)),
            "client {i} from a foreign address"
        );
        // …from its own it is accepted.
        let (peer, info) = server.receive(later, c.addr, true, &retry, &mut rng);
        assert_eq!(peer, Some(i));
        assert!(matches!(info.rx, Rx::Response(_)));
    }
    assert_eq!(server.device.stats().initiations, 3);
}

/// Tunnels do not borrow the device: they can be moved to other threads
/// and driven independently, as a multi-queue embedder would.
#[test]
fn tunnels_and_devices_are_plain_send_sync_values() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<Device>();
    assert_send_sync::<Tunnel>();

    let mut rng = DeterministicRng::new(0x3008);
    let (mut server, keys) = Server::new(2, &mut rng);
    let now = Ticks::ZERO;
    let mut c0 = client(keys[0].clone(), server.public(), client_addr(0), &mut rng);
    establish(&mut server, &mut c0, 0, now, &mut rng);
    // The server-side tunnel for peer 0 goes to a worker thread and keeps
    // working there without the device.
    let mut tunnel = server.peers.remove(0);
    let wire = std::thread::spawn(move || {
        let mut buf = [0u8; 128];
        match tunnel.encapsulate(now, b"from a worker", &mut buf).unwrap() {
            wireguard_sans_io::Encapsulated::Transport(tx) => tx.datagram.to_vec(),
            other => panic!("{other:?}"),
        }
    })
    .join()
    .unwrap();
    assert!(matches!(
        c0.recv_from(now, server_addr(), false, &wire, &mut rng).rx,
        Rx::Data(_)
    ));
}

/// A long-running multi-peer server under mixed traffic: every payload
/// reaches the application of exactly the peer it was sent by, endpoints
/// follow each client individually, and the server's timers are driven
/// per peer.
#[test]
fn many_peers_mixed_traffic_and_roaming() {
    let mut rng = DeterministicRng::new(0x3009);
    let n = 12;
    let (mut server, keys) = Server::new(n, &mut rng);
    let mut clients: Vec<Side> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| client(k.clone(), server.public(), client_addr(i), &mut rng))
        .collect();
    let mut delivered = vec![0usize; n];
    let mut sent = vec![0usize; n];

    for tick in 0..400u64 {
        let now = Ticks::from_nanos(tick * S / 2);
        // Some clients roam now and then.
        if tick % 37 == 0 {
            let i = (tick / 37) as usize % n;
            clients[i].addr = format!("203.0.113.{}:{}", i + 1, 30_000 + tick)
                .parse()
                .unwrap();
        }
        // In-flight datagrams: (to_server, client index, bytes).
        let mut wires: Vec<(bool, usize, Vec<u8>)> = Vec::new();
        for (i, c) in clients.iter_mut().enumerate() {
            if (tick + i as u64) % 3 == 0 {
                let payload = format!("c{i} t{tick}");
                sent[i] += 1;
                if let Tx::Transport(w) = c.send(now, payload.as_bytes()) {
                    wires.push((true, i, w));
                } else {
                    sent[i] -= 1; // no session yet: the app would retry
                }
            }
            for (w, _) in c.drain(now, &mut rng).0 {
                wires.push((true, i, w));
            }
        }
        for (i, tunnel) in server.peers.iter_mut().enumerate() {
            let mut buf = [0u8; 256];
            while let wireguard_sans_io::PollOutput::Transmit(tx, _) =
                tunnel.poll(now, &mut buf, &mut rng).unwrap()
            {
                assert_eq!(
                    tx.dst, clients[i].addr,
                    "peer {i}: timer traffic misaddressed"
                );
                wires.push((false, i, tx.datagram.to_vec()));
            }
        }
        while let Some((to_server, i, w)) = wires.pop() {
            if to_server {
                let src = clients[i].addr;
                let (peer, info) = server.receive(now, src, false, &w, &mut rng);
                match info.rx {
                    Rx::Data(d) => {
                        assert_eq!(peer, Some(i));
                        assert!(d.starts_with(format!("c{i} t").as_bytes()));
                        delivered[i] += 1;
                    }
                    Rx::Response(r) => wires.push((false, i, r)),
                    Rx::Keepalive | Rx::Dropped(_) => {}
                    other => panic!("{other:?}"),
                }
                if peer == Some(i) {
                    assert_eq!(
                        server.peers[i].endpoint(),
                        Some(src),
                        "peer {i} did not roam"
                    );
                }
            } else {
                let _ = clients[i].recv_from(now, server_addr(), false, &w, &mut rng);
            }
        }
    }
    for i in 0..n {
        assert!(sent[i] > 100, "client {i} sent {}", sent[i]);
        assert_eq!(delivered[i], sent[i], "client {i}");
    }
}
