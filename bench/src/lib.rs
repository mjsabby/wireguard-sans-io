//! Shared fixtures for the comparative benchmarks: build matched
//! `wireguard-embed` and BoringTun tunnel pairs from the same key
//! material, run them through identical handshake/transport flows.
//!
//! All code here is benchmark scaffolding — the production-usable layer
//! is `wireguard-embed` itself.

#![allow(clippy::missing_panics_doc)]

use std::net::SocketAddr;

use rand_core::{OsRng, RngCore};

pub use boringtun;
pub use wireguard_embed;

/// One pair of 32-byte keypairs + a fake IPv4 packet of `payload_len`
/// total bytes (header + body), shared by both implementations so the
/// comparison is byte-for-byte fair.
pub struct Fixture {
    pub a_priv: [u8; 32],
    pub b_priv: [u8; 32],
    pub a_pub: [u8; 32],
    pub b_pub: [u8; 32],
    pub packet: Vec<u8>,
}

impl Fixture {
    pub fn new(payload_len: usize) -> Self {
        let mut a_priv = [0u8; 32];
        let mut b_priv = [0u8; 32];
        OsRng.fill_bytes(&mut a_priv);
        OsRng.fill_bytes(&mut b_priv);
        let a_pub = *wireguard_sans_io::StaticSecret::from_bytes(a_priv)
            .public_key()
            .as_bytes();
        let b_pub = *wireguard_sans_io::StaticSecret::from_bytes(b_priv)
            .public_key()
            .as_bytes();
        let mut packet = vec![0u8; payload_len];
        // Minimal IPv4 header so both impls' padding-trim engages.
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
        for (i, b) in packet[20..].iter_mut().enumerate() {
            *b = i as u8;
        }
        Self {
            a_priv,
            b_priv,
            a_pub,
            b_pub,
            packet,
        }
    }
}

// ---------------------------------------------------------------------------
// wireguard-embed harness
// ---------------------------------------------------------------------------

/// An established `wireguard-embed` tunnel pair (A initiates).
pub struct EmbedPair {
    pub a: wireguard_embed::Tunn,
    pub b: wireguard_embed::Tunn,
    /// The address A's datagrams "come from" (what B is told on receive).
    pub a_addr: SocketAddr,
    /// The address B's datagrams "come from"; A's configured endpoint.
    pub b_addr: SocketAddr,
    pub buf_a: Vec<u8>,
    pub buf_b: Vec<u8>,
}

impl EmbedPair {
    pub fn new(fx: &Fixture) -> Self {
        use wireguard_embed::{RateLimiter, Tunn, TunnResult};
        use wireguard_sans_io::{PublicKey, StaticSecret};
        let a_addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let b_addr: SocketAddr = "192.0.2.2:51820".parse().unwrap();
        let rl = std::sync::Arc::new(RateLimiter::new(1_000_000)); // benches: never under_load
        // A is configured with B's endpoint; B learns A's from the handshake.
        let mut a = Tunn::new(
            StaticSecret::from_bytes(fx.a_priv),
            PublicKey::from_bytes(fx.b_pub),
            None,
            None,
            Some(b_addr),
            Some(rl.clone()),
        )
        .unwrap();
        let mut b = Tunn::new(
            StaticSecret::from_bytes(fx.b_priv),
            PublicKey::from_bytes(fx.a_pub),
            None,
            None,
            None,
            Some(rl),
        )
        .unwrap();
        let mut buf_a = vec![0u8; 2048];
        let mut buf_b = vec![0u8; 2048];

        let init = match a.format_handshake_initiation(&mut buf_a) {
            TunnResult::WriteToNetwork(w, _) => w.to_vec(),
            r => panic!("init: {r:?}"),
        };
        let resp = match b.decapsulate(a_addr, &init, &mut buf_b) {
            TunnResult::WriteToNetwork(w, _) => w.to_vec(),
            r => panic!("resp: {r:?}"),
        };
        let ka = match a.decapsulate(b_addr, &resp, &mut buf_a) {
            TunnResult::WriteToNetwork(w, _) => w.to_vec(),
            r => panic!("ka: {r:?}"),
        };
        match b.decapsulate(a_addr, &ka, &mut buf_b) {
            TunnResult::Done => {}
            r => panic!("ka recv: {r:?}"),
        }
        assert!(a.is_established() && b.is_established());
        Self {
            a,
            b,
            a_addr,
            b_addr,
            buf_a,
            buf_b,
        }
    }

    /// One-way: encrypt at A, decrypt at B (the copying `decapsulate`,
    /// the like-for-like counterpart of BoringTun's). Returns plaintext
    /// length.
    pub fn roundtrip(&mut self, packet: &[u8]) -> usize {
        use wireguard_embed::TunnResult;
        // Copied out, exactly as `BoringPair::roundtrip` does, so both
        // sides of the comparison pay for the same allocation.
        let wire = match self.a.encapsulate(packet, &mut self.buf_a) {
            TunnResult::WriteToNetwork(w, _) => w.to_vec(),
            r => panic!("encap: {r:?}"),
        };
        match self.b.decapsulate(self.a_addr, &wire, &mut self.buf_b) {
            TunnResult::WriteToTunnel(d) => d.len(),
            r => panic!("decap: {r:?}"),
        }
    }

    /// One-way: encrypt at A, decrypt at B **in place**, in the buffer
    /// the datagram was written to — the receive path the async driver
    /// uses. Unlike [`EmbedPair::roundtrip`] nothing is copied or
    /// allocated, so this is not a like-for-like line against BoringTun
    /// (whose API has no in-place receive); it shows what the copy costs.
    /// Returns plaintext length.
    pub fn roundtrip_in_place(&mut self, packet: &[u8]) -> usize {
        use wireguard_embed::TunnResult;
        let n = match self.a.encapsulate(packet, &mut self.buf_a) {
            TunnResult::WriteToNetwork(w, _) => w.len(),
            r => panic!("encap: {r:?}"),
        };
        match self
            .b
            .decapsulate_in_place(self.a_addr, &mut self.buf_a[..n], &mut self.buf_b)
        {
            TunnResult::WriteToTunnel(d) => d.len(),
            r => panic!("decap: {r:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// BoringTun harness
// ---------------------------------------------------------------------------

/// An established BoringTun tunnel pair (A initiates).
pub struct BoringPair {
    pub a: boringtun::noise::Tunn,
    pub b: boringtun::noise::Tunn,
    pub buf_a: Vec<u8>,
    pub buf_b: Vec<u8>,
}

impl BoringPair {
    pub fn new(fx: &Fixture) -> Self {
        use boringtun::noise::{Tunn, TunnResult, rate_limiter::RateLimiter};
        let a_sk = x25519_dalek::StaticSecret::from(fx.a_priv);
        let b_sk = x25519_dalek::StaticSecret::from(fx.b_priv);
        let a_pk = x25519_dalek::PublicKey::from(fx.a_pub);
        let b_pk = x25519_dalek::PublicKey::from(fx.b_pub);
        // Huge limit so cookies never engage during the benchmark.
        let rl_a = std::sync::Arc::new(RateLimiter::new(&a_pk, 1_000_000));
        let rl_b = std::sync::Arc::new(RateLimiter::new(&b_pk, 1_000_000));
        let mut a = Tunn::new(a_sk, b_pk, None, None, 0, Some(rl_a));
        let mut b = Tunn::new(b_sk, a_pk, None, None, 1, Some(rl_b));
        let mut buf_a = vec![0u8; 2048];
        let mut buf_b = vec![0u8; 2048];

        let init = match a.format_handshake_initiation(&mut buf_a, false) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            r => panic!("init: {r:?}"),
        };
        let resp = match b.decapsulate(None, &init, &mut buf_b) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            r => panic!("resp: {r:?}"),
        };
        let ka = match a.decapsulate(None, &resp, &mut buf_a) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            r => panic!("ka: {r:?}"),
        };
        match b.decapsulate(None, &ka, &mut buf_b) {
            TunnResult::Done => {}
            r => panic!("ka recv: {r:?}"),
        }
        Self { a, b, buf_a, buf_b }
    }

    pub fn roundtrip(&mut self, packet: &[u8]) -> usize {
        use boringtun::noise::TunnResult;
        let wire = match self.a.encapsulate(packet, &mut self.buf_a) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            r => panic!("encap: {r:?}"),
        };
        match self.b.decapsulate(None, &wire, &mut self.buf_b) {
            TunnResult::WriteToTunnelV4(d, _) | TunnResult::WriteToTunnelV6(d, _) => d.len(),
            r => panic!("decap: {r:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Full-handshake fixtures (rebuilt every iteration)
// ---------------------------------------------------------------------------

pub fn embed_full_handshake(fx: &Fixture) {
    let _ = EmbedPair::new(fx);
}

pub fn boring_full_handshake(fx: &Fixture) {
    let _ = BoringPair::new(fx);
}
