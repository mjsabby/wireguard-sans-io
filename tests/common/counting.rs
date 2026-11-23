//! A crypto provider that counts what it is asked to do.
//!
//! What a datagram costs the receiver is a security property (whitepaper
//! §5.3: an attacker must not be able to make us do Diffie-Hellman
//! operations cheaply). Timing it is a poor way to test that — a busy
//! machine changes the answer. Counting the operations is exact:
//! [`Counting`] is the default provider with a counter in front of every
//! primitive, and [`spent`] reads the counters.
//!
//! The counters are per thread, and the test harness runs every test on
//! its own thread, so tests do not see each other's work. Call [`spent`]
//! once before the part of a test that is being measured.
#![allow(dead_code)]

use std::cell::Cell;

use wireguard_sans_io::{CryptoProvider, Error, InTree};

/// The provider that does the work.
type Inner = InTree;

/// How often each primitive ran.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// `DH(secret, public)`.
    pub x25519: u32,
    /// Public key from a private key (also one scalar multiplication).
    pub x25519_public: u32,
    pub hash: u32,
    pub mac: u32,
    pub hmac: u32,
    pub seal: u32,
    pub open: u32,
    pub xseal: u32,
    pub xopen: u32,
}

impl Counts {
    /// Curve25519 scalar multiplications: the expensive operation, some
    /// 20 µs each where everything else is well under a microsecond.
    pub fn scalar_mults(&self) -> u32 {
        self.x25519 + self.x25519_public
    }

    /// Nothing but (at most) keyed hashes: the cost class of a datagram
    /// that is rejected at the door.
    pub fn only_macs(&self) -> bool {
        Self { mac: 0, ..*self } == Self::default()
    }
}

thread_local! {
    static COUNTS: Cell<Counts> = const { Cell::new(Counts {
        x25519: 0,
        x25519_public: 0,
        hash: 0,
        mac: 0,
        hmac: 0,
        seal: 0,
        open: 0,
        xseal: 0,
        xopen: 0,
    }) };
}

fn count(bump: impl FnOnce(&mut Counts)) {
    COUNTS.with(|counts| {
        let mut c = counts.get();
        bump(&mut c);
        counts.set(c);
    });
}

/// What this thread's devices and tunnels have spent since the last call.
pub fn spent() -> Counts {
    COUNTS.with(Cell::take)
}

/// The default provider, counted.
pub struct Counting;

impl CryptoProvider for Counting {
    fn name() -> &'static str {
        "counting"
    }
    fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
        count(|c| c.x25519_public += 1);
        Inner::x25519_public(secret)
    }
    fn x25519(secret: &[u8; 32], public: &[u8; 32], out: &mut [u8; 32]) -> bool {
        count(|c| c.x25519 += 1);
        Inner::x25519(secret, public, out)
    }
    fn hash(parts: &[&[u8]], out: &mut [u8; 32]) {
        count(|c| c.hash += 1);
        Inner::hash(parts, out);
    }
    fn mac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 16]) {
        count(|c| c.mac += 1);
        Inner::mac(key, parts, out);
    }
    // Preparing a key is not counted: it happens when a device or a tunnel
    // is created, never for a datagram. A MAC with a prepared key is a
    // MAC.
    fn mac_prepare(key: &[u8; 32], state: &mut [u32; 8]) {
        Inner::mac_prepare(key, state);
    }
    fn mac_prepared(key: &[u8; 32], state: &[u32; 8], parts: &[&[u8]], out: &mut [u8; 16]) {
        count(|c| c.mac += 1);
        Inner::mac_prepared(key, state, parts, out);
    }
    fn hmac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 32]) {
        count(|c| c.hmac += 1);
        Inner::hmac(key, parts, out);
    }
    fn seal_in_place(
        key: &[u8; 32],
        counter: u64,
        aad: &[u8],
        pt_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        count(|c| c.seal += 1);
        Inner::seal_in_place(key, counter, aad, pt_len, buf)
    }
    fn open_in_place(key: &[u8; 32], counter: u64, aad: &[u8], buf: &mut [u8]) -> Option<usize> {
        count(|c| c.open += 1);
        Inner::open_in_place(key, counter, aad, buf)
    }
    fn xseal_in_place(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        pt_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        count(|c| c.xseal += 1);
        Inner::xseal_in_place(key, nonce, aad, pt_len, buf)
    }
    fn xopen_in_place(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Option<usize> {
        count(|c| c.xopen += 1);
        Inner::xopen_in_place(key, nonce, aad, buf)
    }
}
