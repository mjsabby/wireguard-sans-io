//! Shared fixtures for the comparative benchmarks: build matched
//! `wireguard-embed` and BoringTun tunnel pairs from the same key
//! material, run them through identical handshake/transport flows.
//!
//! All code here is benchmark scaffolding — the production-usable layer
//! is `wireguard-embed` itself.

#![allow(clippy::missing_panics_doc)]

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
    pub buf_a: Vec<u8>,
    pub buf_b: Vec<u8>,
}

impl EmbedPair {
    pub fn new(fx: &Fixture) -> Self {
        use wireguard_embed::{RateLimiter, Tunn, TunnResult};
        use wireguard_sans_io::{PublicKey, StaticSecret};
        let rl = std::sync::Arc::new(RateLimiter::new(1_000_000)); // benches: never under_load
        let mut a = Tunn::new(
            StaticSecret::from_bytes(fx.a_priv),
            PublicKey::from_bytes(fx.b_pub),
            None,
            None,
            Some(rl.clone()),
        )
        .unwrap();
        let mut b = Tunn::new(
            StaticSecret::from_bytes(fx.b_priv),
            PublicKey::from_bytes(fx.a_pub),
            None,
            None,
            Some(rl),
        )
        .unwrap();
        let mut buf_a = vec![0u8; 2048];
        let mut buf_b = vec![0u8; 2048];

        let init = match a.format_handshake_initiation(&mut buf_a) {
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
        assert!(a.is_established() && b.is_established());
        Self { a, b, buf_a, buf_b }
    }

    /// One-way: encrypt at A, decrypt at B. Returns plaintext length.
    pub fn roundtrip(&mut self, packet: &[u8]) -> usize {
        use wireguard_embed::TunnResult;
        let wire = match self.a.encapsulate(packet, &mut self.buf_a) {
            TunnResult::WriteToNetwork(w) => w,
            r => panic!("encap: {r:?}"),
        };
        // SAFETY-of-benchmark: wire borrows buf_a; copy to avoid aliasing
        // with buf_b. (Buffer-pool work will let us measure zero-copy.)
        let wire = wire.to_vec();
        match self.b.decapsulate(None, &wire, &mut self.buf_b) {
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
