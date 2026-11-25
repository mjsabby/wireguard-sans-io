//! What a data packet costs the receiver when it has many peers: the
//! server's tunnels do not fit the cache, and packets arrive from peers in
//! random order.
//!
//!   many_peers <scalar|simd> <peers> <payload> <rounds>
//!
//! Prints `iters=<n> ns_per_op=<x>`; `scripts/perf_many_peers.sh` runs it
//! under `perf stat` for the cache and TLB misses a packet takes.

use std::hint::black_box;
use std::time::Instant;

use wireguard_audit::{PerfCtl, addr};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    CryptoProvider, Device, Encapsulated, InTree, Incoming, PeerConfig, PeerId, PollOutput,
    Received, StaticSecret, Ticks, Tunnel, WallClock,
};

type Simd = InTree<wireguard_chacha_simd::Best>;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let peers: usize = a[2].parse().unwrap();
    let payload: usize = a[3].parse().unwrap();
    let rounds: usize = a[4].parse().unwrap();
    match a[1].as_str() {
        "scalar" => run::<InTree>(peers, payload, rounds),
        "simd" => run::<Simd>(peers, payload, rounds),
        other => panic!("{other}"),
    }
}

fn run<P: CryptoProvider>(peers: usize, payload_len: usize, rounds: usize) {
    let mut ctl = PerfCtl::new();
    let mut rng = DeterministicRng::new(0x9ee5);
    let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
    let t = Ticks::from_nanos(1_000);
    let server_key = StaticSecret::generate(&mut rng).unwrap();
    let server_pub = server_key.public_key();
    let mut server = Device::<P>::with_provider(server_key, wall, &mut rng).unwrap();
    let mut tunnels: Vec<Tunnel<P>> = Vec::with_capacity(peers);
    let mut clients: Vec<(Device<P>, Tunnel<P>)> = Vec::with_capacity(peers);
    let src = addr(9, 4000);
    let t_setup = Instant::now();
    for i in 0..peers {
        let key = StaticSecret::generate(&mut rng).unwrap();
        let id = PeerId::new(i as u32).unwrap();
        tunnels.push(
            server
                .tunnel(id, PeerConfig::new(key.public_key()), &mut rng)
                .unwrap(),
        );
        let mut cfg = PeerConfig::new(server_pub);
        cfg.endpoint = Some(addr(1, 51820));
        let dev = Device::<P>::with_provider(key, wall, &mut rng).unwrap();
        let tun = dev.tunnel(PeerId::new(0).unwrap(), cfg, &mut rng).unwrap();
        clients.push((dev, tun));
    }
    let mut buf = [0u8; 256];
    let mut out = [0u8; 256];
    for i in 0..peers {
        let (cdev, ctun) = &mut clients[i];
        ctun.request_handshake(t);
        let mut init = match ctun.poll(t, &mut buf, &mut rng).unwrap() {
            PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
            other => panic!("{other:?}"),
        };
        let mut resp = match server.receive(t, src, false, &mut init) {
            Incoming::Initiation(init) => {
                match tunnels[i]
                    .handle_initiation(t, &init, &mut out, &mut rng)
                    .unwrap()
                    .received
                {
                    Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        };
        let h = cdev
            .receive_for(
                ctun,
                t,
                addr(1, 51820),
                false,
                &mut resp,
                &mut out,
                &mut rng,
            )
            .unwrap();
        assert!(matches!(h.received, Received::HandshakeComplete));
        let mut ka = match ctun.poll(t, &mut buf, &mut rng).unwrap() {
            PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
            other => panic!("{other:?}"),
        };
        match server.receive(t, src, false, &mut ka) {
            Incoming::ForPeer(id, pkt) => {
                assert_eq!(id.get() as usize, i);
                let h = tunnels[i].handle(t, src, pkt).unwrap();
                assert!(matches!(h.received, Received::Keepalive));
            }
            other => panic!("{other:?}"),
        }
    }
    eprintln!(
        "setup: {peers} peers in {:.1}s; server tunnels = {:.1} MiB ({} B each)",
        t_setup.elapsed().as_secs_f64(),
        (peers * size_of::<Tunnel<P>>()) as f64 / (1 << 20) as f64,
        size_of::<Tunnel<P>>()
    );

    let payload = vec![0xddu8; payload_len];
    let stride = payload_len + 64;
    // Everything is encrypted first: one packet from every peer per
    // round, each round in a fresh random order, so that the counted
    // region is the receive path alone.
    let total = peers * (rounds + 1);
    let mut wire = vec![0u8; total * stride];
    let mut order: Vec<u32> = (0..peers as u32).collect();
    let mut dgram_len = 0;
    for round in 0..rounds + 1 {
        for i in (1..peers).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            order.swap(i, j);
        }
        for (slot, &p) in order.iter().enumerate() {
            let at = (round * peers + slot) * stride;
            let chunk = &mut wire[at..at + stride];
            dgram_len = match clients[p as usize]
                .1
                .encapsulate(t, &payload, chunk)
                .unwrap()
            {
                Encapsulated::Transport(tx) => tx.datagram.len(),
                other => panic!("{other:?}"),
            };
        }
    }
    drop(clients);
    let mut receive = |from: usize, to: usize| {
        for slot in from..to {
            let d = &mut wire[slot * stride..slot * stride + dgram_len];
            match server.receive(t, src, false, d) {
                Incoming::ForPeer(id, pkt) => {
                    // The embedder's table: a Vec indexed by peer id.
                    let Some(tunnel) = tunnels.get_mut(id.get() as usize) else {
                        panic!("no peer")
                    };
                    match tunnel.handle(t, src, pkt).unwrap().received {
                        Received::Data(p) => {
                            black_box(p);
                        }
                        other => panic!("{other:?}"),
                    }
                }
                other => panic!("{other:?}"),
            }
        }
    };
    receive(0, peers); // round 0 warms up
    ctl.enable();
    let t0 = Instant::now();
    receive(peers, total);
    let ns = t0.elapsed().as_nanos();
    ctl.disable();
    let ops = (total - peers) as u64;
    println!("iters={ops} ns_per_op={:.2}", ns as f64 / ops as f64);
}
