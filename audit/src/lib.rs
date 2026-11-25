//! What the harnesses in this crate share: datagrams an attacker can
//! make, two ends with a session between them, and the pipe to `perf
//! stat` that lets a run count its measured region and nothing else.

use std::io::{Read, Write};
use std::net::SocketAddr;

use wireguard_sans_io::crypto::blake2s;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    CryptoProvider, Device, EntropySource, PeerConfig, PeerId, PollOutput, PublicKey, Received,
    StaticSecret, Ticks, Tunnel, WallClock,
};

/// The other end of `perf stat -D -1 --control fd:…`: counting starts
/// disabled, and the measured program says when its region begins and
/// ends. Without the two environment variables (a run without `perf`)
/// this does nothing.
pub struct PerfCtl {
    ctl: Option<std::fs::File>,
    ack: Option<std::fs::File>,
}

impl Default for PerfCtl {
    fn default() -> Self {
        Self::new()
    }
}

impl PerfCtl {
    /// Open the FIFOs named by `PERF_CTL_FIFO` and `PERF_ACK_FIFO`, if
    /// they are set.
    pub fn new() -> Self {
        let ctl = std::env::var("PERF_CTL_FIFO")
            .ok()
            .map(|p| std::fs::OpenOptions::new().write(true).open(p).unwrap());
        let ack = std::env::var("PERF_ACK_FIFO")
            .ok()
            .map(|p| std::fs::OpenOptions::new().read(true).open(p).unwrap());
        Self { ctl, ack }
    }

    fn cmd(&mut self, c: &str) {
        if let Some(f) = &mut self.ctl {
            f.write_all(c.as_bytes()).unwrap();
            if let Some(a) = &mut self.ack {
                // "ack\n"
                let mut b = [0u8; 4];
                a.read_exact(&mut b).unwrap();
            }
        }
    }

    /// Start counting.
    pub fn enable(&mut self) {
        self.cmd("enable\n");
    }

    /// Stop counting.
    pub fn disable(&mut self) {
        self.cmd("disable\n");
    }
}

/// `192.0.2.a:port`.
pub fn addr(a: u8, port: u16) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, a], port))
}

/// The key `mac1` of a message to `responder` is made with: a hash of a
/// label and the public key, so anyone who knows the public key has it.
pub fn mac1_key(responder: &PublicKey) -> [u8; 32] {
    blake2s::hash(&[b"mac1----", responder.as_bytes()])
}

/// A 148-byte handshake initiation with a valid `mac1` for `responder`
/// and random contents otherwise: what anyone who knows the public key
/// can send.
pub fn forged_initiation(responder: &PublicKey, rng: &mut DeterministicRng) -> [u8; 148] {
    let mut m = [0u8; 148];
    rng.fill(&mut m[4..116]).unwrap();
    m[0] = 1;
    let mac = blake2s::mac(&mac1_key(responder), &[&m[..116]]);
    m[116..132].copy_from_slice(&mac);
    m
}

/// A 92-byte handshake response with a valid `mac1` for `initiator`,
/// addressed to `receiver_index`, random otherwise.
pub fn forged_response(
    initiator: &PublicKey,
    receiver_index: u32,
    rng: &mut DeterministicRng,
) -> [u8; 92] {
    let mut m = [0u8; 92];
    rng.fill(&mut m[4..60]).unwrap();
    m[0] = 2;
    m[8..12].copy_from_slice(&receiver_index.to_le_bytes());
    let mac = blake2s::mac(&mac1_key(initiator), &[&m[..60]]);
    m[60..76].copy_from_slice(&mac);
    m
}

/// One end: a device and its single tunnel.
pub struct Side<P: CryptoProvider> {
    /// The local identity.
    pub device: Device<P>,
    /// The one peer.
    pub tunnel: Tunnel<P>,
    /// The device's public key.
    pub public: PublicKey,
}

impl<P: CryptoProvider> Side<P> {
    /// An end with the static key `key` and the peer `peer`.
    pub fn new(
        key: StaticSecret,
        peer: PublicKey,
        peer_addr: Option<SocketAddr>,
        id: u32,
        rng: &mut DeterministicRng,
    ) -> Self {
        let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
        let public = key.public_key();
        let device = Device::<P>::with_provider(key, wall, rng).unwrap();
        let mut cfg = PeerConfig::new(peer);
        cfg.endpoint = peer_addr;
        let tunnel = device.tunnel(PeerId::new(id).unwrap(), cfg, rng).unwrap();
        Self {
            device,
            tunnel,
            public,
        }
    }

    /// What the tunnel has to send at `t`, if anything.
    pub fn poll(&mut self, t: Ticks, rng: &mut DeterministicRng) -> Option<Vec<u8>> {
        let mut buf = [0u8; 256];
        match self.tunnel.poll(t, &mut buf, rng).unwrap() {
            PollOutput::Transmit(tx, _) => Some(tx.datagram.to_vec()),
            _ => None,
        }
    }
}

/// A and B with a session each way. A is the initiator and sits at
/// 192.0.2.1:51820, B at 192.0.2.2:51820.
pub fn established_pair<P: CryptoProvider>(rng: &mut DeterministicRng) -> (Side<P>, Side<P>) {
    let a_key = StaticSecret::generate(rng).unwrap();
    let b_key = StaticSecret::generate(rng).unwrap();
    let (a_pub, b_pub) = (a_key.public_key(), b_key.public_key());
    let mut a = Side::<P>::new(a_key, b_pub, Some(addr(2, 51820)), 0, rng);
    let mut b = Side::<P>::new(b_key, a_pub, Some(addr(1, 51820)), 0, rng);
    handshake(&mut a, &mut b, Ticks::ZERO, rng);
    (a, b)
}

/// One full handshake A → B at `t`, confirmed by A's keepalive.
pub fn handshake<P: CryptoProvider>(
    a: &mut Side<P>,
    b: &mut Side<P>,
    t: Ticks,
    rng: &mut DeterministicRng,
) {
    let mut out = [0u8; 128];
    a.tunnel.request_handshake(t);
    // (An expiry notification may come first.)
    let mut init = (0..4).find_map(|_| a.poll(t, rng)).expect("initiation");
    let mut resp = match b
        .device
        .receive_for(
            &mut b.tunnel,
            t,
            addr(1, 51820),
            false,
            &mut init,
            &mut out,
            rng,
        )
        .unwrap()
        .received
    {
        Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
        other => panic!("{other:?}"),
    };
    let mut out = [0u8; 128];
    let h = a
        .device
        .receive_for(
            &mut a.tunnel,
            t,
            addr(2, 51820),
            false,
            &mut resp,
            &mut out,
            rng,
        )
        .unwrap();
    assert!(matches!(h.received, Received::HandshakeComplete), "{h:?}");
    let mut confirm = a.poll(t, rng).expect("keepalive");
    let h = b
        .device
        .receive_for(
            &mut b.tunnel,
            t,
            addr(1, 51820),
            false,
            &mut confirm,
            &mut out,
            rng,
        )
        .unwrap();
    assert!(matches!(h.received, Received::Keepalive), "{h:?}");
}
