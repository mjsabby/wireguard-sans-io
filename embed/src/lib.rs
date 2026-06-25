//! `wireguard-embed`: a std + alloc driver around the
//! [`wireguard_sans_io`] no_std core, giving you BoringTun-style
//! ergonomics (built-in clock, OS RNG, rate limiter, packet queue) while
//! every byte on the wire still comes from the panic-free,
//! zero-unsafe core.
//!
//! # What this crate adds on top of the core
//!
//! | Concern | `wireguard-sans-io` core | this crate |
//! |---|---|---|
//! | clock | caller passes [`Now`] | reads `Instant`/`SystemTime` |
//! | entropy | caller passes `&mut dyn EntropySource` | OS RNG via `getrandom` |
//! | rate limit / `under_load` | caller decides | built-in [`RateLimiter`] (BoringTun heuristic) |
//! | packet queue while no session | caller retries | internal `VecDeque`, drained on completion |
//! | padding trim on receive | caller calls `ip_packet_len` | done for you |
//! | `remote` cookie binding | caller encodes | `SocketAddr` → fixed 18-byte encoding |
//! | buffer management | caller-provided slices | [`SlabPool`] + RAII [`PooledBuf`]: bounded freelist of `Box<[u8]>` slabs (stable address ⇒ io_uring/RIO-ready); steady-state data path is allocation-free |
//! | async runtime | n/a | feature `async`: `tokio::AsyncTunn` — `select!` loop over `UdpSocket` + `next_wake()` + two `mpsc<PooledBuf>` channels for the TUN side |
//!
//! # SIMD
//!
//! [`Tunn`] always uses [`Backend`] = [`simd::Best`] for the transport
//! ChaCha20 keystream — AVX2 8-way on x86_64, NEON 4-way on aarch64,
//! the scalar path elsewhere. The core stays
//! `#![forbid(unsafe_code)]`; all `unsafe` is confined to the
//! `wireguard-chacha-simd` crate and validated against the scalar
//! oracle. To pin a specific backend, construct
//! [`Tunnel`]`<C>::with_backend` directly via the core API.
//!
//! # API shape (BoringTun-compatible-ish)
//!
//! ```ignore
//! let mut tunn = Tunn::new(static_private, peer_public, None, None, rate_limiter);
//! match tunn.encapsulate(ip_packet, &mut dst) { ... }
//! match tunn.decapsulate(Some(src_addr), datagram, &mut dst) { ... }
//! match tunn.update_timers(&mut dst) { ... }       // call once/sec, or:
//! let wake = tunn.next_wake();                     // sleep exactly
//! ```
//!
//! Dropping back to the core API for anything this layer doesn't expose:
//! [`Tunn::core`] / [`Tunn::core_mut`].

#![forbid(unsafe_code)]

mod buffer;
mod rate_limiter;
mod rng;

#[cfg(feature = "async")]
pub mod tokio;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use wireguard_sans_io::{
    Config, Encapsulated, Error, Now, PollOutput, PresharedKey, PublicKey, Received, StaticSecret,
    Tunnel, ip_packet_len, peek,
};

pub use buffer::{BufferPool, MAX_DATAGRAM, NoPool, PooledBuf, SlabPool};
pub use rate_limiter::RateLimiter;
pub use rng::OsEntropy;
pub use wireguard_chacha_simd as simd;
pub use wireguard_sans_io as core;
pub use wireguard_sans_io::{ChaChaImpl, PacketKind, Stats};

/// The ChaCha20 backend [`Tunn`] uses: runtime-selected best available
/// (AVX2-8way on x86_64 with AVX2, NEON-4way on aarch64, scalar
/// elsewhere). Callers wanting a specific backend can construct
/// [`Tunnel`]`<C>` directly via the core API.
pub type Backend = wireguard_chacha_simd::Best;

/// Max packets queued while no session is established (BoringTun: 256).
pub const MAX_QUEUE_DEPTH: usize = 256;

/// Result of [`Tunn::encapsulate`] / [`Tunn::decapsulate`] /
/// [`Tunn::update_timers`] — mirrors BoringTun's `TunnResult`.
#[derive(Debug)]
pub enum TunnResult<'a> {
    /// Nothing to do.
    Done,
    /// An error occurred; the datagram (if any) was dropped silently.
    Err(Error),
    /// Send this datagram to the peer's UDP endpoint. After a handshake
    /// completes, **call [`Tunn::decapsulate`] again with an empty
    /// datagram** to drain the packet queue (BoringTun convention).
    WriteToNetwork(&'a [u8]),
    /// Deliver this decrypted IP packet to the local TUN interface.
    /// Padding has been trimmed via the inner IP length field.
    WriteToTunnel(&'a [u8]),
}

/// A WireGuard tunnel to a single peer, with std conveniences.
///
/// Thin owner around [`wireguard_sans_io::Tunnel`]. All wire-format work
/// happens in the core; this layer supplies time, entropy, rate-limit
/// state, the not-yet-established packet queue, and `SocketAddr` plumbing.
pub struct Tunn {
    inner: Tunnel<Backend>,
    rate_limiter: Arc<RateLimiter>,
    pool: Arc<SlabPool>,
    packet_queue: VecDeque<PooledBuf>,
    rng: OsEntropy,
    /// Monotonic-clock epoch: `Now.ticks` = `Instant::now() - epoch`.
    epoch: Instant,
    /// Set after a handshake completes so the next empty-datagram
    /// `decapsulate` call drains the queue (BoringTun convention).
    queue_drainable: bool,
}

impl std::fmt::Debug for Tunn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunn")
            .field("inner", &self.inner)
            .field("queued", &self.packet_queue.len())
            .finish()
    }
}

impl Tunn {
    /// Create a tunnel.
    ///
    /// `rate_limiter` is shared per *interface* (one `Arc` across all
    /// peers on the same UDP socket); pass `None` to get a private
    /// limiter at the BoringTun default of 10 handshakes/second.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] for a self-peering or low-order peer
    /// key.
    pub fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Result<Self, Error> {
        Self::with_pool(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            rate_limiter,
            SlabPool::for_wireguard(),
        )
    }

    /// As [`Tunn::new`], with an explicit buffer pool — share one
    /// `Arc<SlabPool>` across every `Tunn` (and the async driver, and
    /// your TUN reader) on the same interface so the whole data path
    /// draws from one freelist.
    ///
    /// # Errors
    /// As [`Tunn::new`].
    pub fn with_pool(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        rate_limiter: Option<Arc<RateLimiter>>,
        pool: Arc<SlabPool>,
    ) -> Result<Self, Error> {
        let mut config = Config::new(static_private, peer_static_public);
        if let Some(psk) = preshared_key {
            config.psk = PresharedKey::from_bytes(psk);
        }
        config.persistent_keepalive = persistent_keepalive.and_then(std::num::NonZeroU16::new);
        Ok(Self {
            inner: Tunnel::<Backend>::with_backend(config)?,
            rate_limiter: rate_limiter
                .unwrap_or_else(|| Arc::new(RateLimiter::new(RateLimiter::DEFAULT_LIMIT))),
            pool,
            packet_queue: VecDeque::new(),
            rng: OsEntropy,
            epoch: Instant::now(),
            queue_drainable: false,
        })
    }

    /// The buffer pool this tunnel queues into. Hand this to your socket
    /// reader / TUN reader so everything shares one freelist.
    #[must_use]
    pub fn pool(&self) -> &Arc<SlabPool> {
        &self.pool
    }

    /// Current [`Now`] reading: monotonic nanoseconds since this tunnel's
    /// construction, plus the wall clock.
    #[must_use]
    pub fn now(&self) -> Now {
        let mono = Instant::now()
            .saturating_duration_since(self.epoch)
            .as_nanos();
        let mono = u64::try_from(mono).unwrap_or(u64::MAX);
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Now::new(mono, wall.as_secs(), wall.subsec_nanos())
    }

    /// Encrypt one IP packet from the TUN interface into `dst`.
    ///
    /// If no session exists, the packet is **queued** (up to
    /// [`MAX_QUEUE_DEPTH`]) and a handshake initiation is returned
    /// instead. After the handshake completes, call [`Tunn::decapsulate`]
    /// with an empty datagram repeatedly to drain the queue.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let now = self.now();
        match self.inner.encapsulate(now, src, dst, &mut self.rng) {
            Ok(Encapsulated::Transport(w)) => TunnResult::WriteToNetwork(w),
            Ok(Encapsulated::HandshakeInitiation(w)) => {
                self.queue_packet(src);
                TunnResult::WriteToNetwork(w)
            }
            Err(Error::NotEstablished) => {
                self.queue_packet(src);
                TunnResult::Done
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Process a UDP datagram from the network.
    ///
    /// `src_addr` feeds the cookie subsystem (IP-ownership proof under
    /// load). Passing `None` disables `mac2` checking — only do that on a
    /// trusted link.
    ///
    /// **BoringTun convention:** call this again with an *empty* datagram
    /// after a `WriteToNetwork` result to drain the packet queue, until
    /// `Done`.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<SocketAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            return self.drain_queue_step(dst);
        }

        // Rate-limit handshake messages BEFORE the core sees them. The
        // counter is bumped only for types 1/2 (peek is borrow-only).
        let under_load = match peek(datagram) {
            Ok(PacketKind::HandshakeInitiation { .. })
            | Ok(PacketKind::HandshakeResponse { .. }) => self.rate_limiter.note_handshake(),
            _ => false,
        };

        let remote = src_addr.map(encode_addr);
        let remote_slice: &[u8] = remote.as_ref().map_or(&[], |r| r.as_slice());
        let now = self.now();

        // Two-phase: first reduce the core's borrow-of-`dst` result to a
        // length/discriminant that doesn't borrow `dst`, then act on it.
        // (The borrow checker otherwise keeps `dst` exclusively borrowed
        // for the whole match, blocking the HandshakeComplete arm's
        // follow-up poll.)
        enum Step {
            Tunnel(usize),
            Network(usize),
            HandshakeComplete,
            Done,
            Err(Error),
        }
        let step = match self.inner.decapsulate(
            now,
            remote_slice,
            under_load && src_addr.is_some(),
            datagram,
            dst,
            &mut self.rng,
        ) {
            Ok(Received::Data(d)) => {
                // Trim WireGuard's 16-byte zero padding via the IP length
                // header. Non-IP payloads are returned as-is.
                Step::Tunnel(ip_packet_len(d).unwrap_or(d.len()))
            }
            Ok(Received::Reply(w)) => Step::Network(w.len()),
            Ok(Received::HandshakeComplete) => Step::HandshakeComplete,
            Ok(Received::Keepalive) | Ok(Received::CookieStored) => Step::Done,
            Err(e) => Step::Err(e),
        };
        match step {
            Step::Tunnel(n) => TunnResult::WriteToTunnel(dst.get(..n).unwrap_or(&[])),
            Step::Network(n) => TunnResult::WriteToNetwork(dst.get(..n).unwrap_or(&[])),
            Step::HandshakeComplete => {
                self.queue_drainable = true;
                // Hand back the confirming keepalive immediately so the
                // responder can use the session; the caller then drains
                // the queue with empty-datagram calls.
                match self.inner.poll(now, dst, &mut self.rng) {
                    Ok(PollOutput::Send(w, _)) => {
                        let n = w.len();
                        TunnResult::WriteToNetwork(dst.get(..n).unwrap_or(&[]))
                    }
                    _ => self.drain_queue_step(dst),
                }
            }
            Step::Done => TunnResult::Done,
            Step::Err(e) => TunnResult::Err(e),
        }
    }

    /// Timer tick (BoringTun's `update_timers`): call periodically (once
    /// per second is fine) **or** whenever [`Tunn::next_wake`] falls due.
    /// Returns at most one action; loop until `Done`.
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        // Maintain the rate limiter on the same cadence (BoringTun does
        // this from update_timers too).
        self.rate_limiter.maybe_reset();
        let now = self.now();
        match self.inner.poll(now, dst, &mut self.rng) {
            Ok(PollOutput::Send(w, _)) => TunnResult::WriteToNetwork(w),
            Ok(PollOutput::HandshakeExpired) => {
                self.packet_queue.clear();
                TunnResult::Err(Error::NotEstablished)
            }
            Ok(PollOutput::SessionsExpired) => TunnResult::Err(Error::Expired),
            Ok(PollOutput::Idle) => TunnResult::Done,
            Err(e) => TunnResult::Err(e),
        }
    }

    /// The earliest `Instant` at which [`Tunn::update_timers`] may have
    /// work. `None` = no timers armed. (BoringTun has no equivalent;
    /// callers there poll once per second.)
    #[must_use]
    pub fn next_wake(&self) -> Option<Instant> {
        self.inner.next_wake().map(|t| {
            self.epoch
                .checked_add(std::time::Duration::from_nanos(t.nanos()))
                .unwrap_or(self.epoch)
        })
    }

    /// Explicitly start a handshake now.
    pub fn format_handshake_initiation<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let now = self.now();
        match self.inner.initiate_handshake(now, dst, &mut self.rng) {
            Ok(w) => TunnResult::WriteToNetwork(w),
            Err(Error::HandshakeRateLimited) => TunnResult::Done,
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Is there a confirmed session ready to encrypt outgoing data?
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.inner.is_established()
    }

    /// Cumulative counters from the core.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.inner.stats()
    }

    /// The shared rate limiter, for callers managing many tunnels on one
    /// interface.
    #[must_use]
    pub fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate_limiter
    }

    /// Borrow the underlying sans-I/O tunnel.
    #[must_use]
    pub fn core(&self) -> &Tunnel<Backend> {
        &self.inner
    }

    /// Mutably borrow the underlying sans-I/O tunnel. Use with care: the
    /// wrapper's queue and `queue_drainable` flag won't observe direct
    /// core calls.
    pub fn core_mut(&mut self) -> &mut Tunnel<Backend> {
        &mut self.inner
    }

    // ---- internals ------------------------------------------------------

    fn queue_packet(&mut self, packet: &[u8]) {
        if packet.is_empty() {
            return;
        }
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            self.packet_queue
                .push_back(PooledBuf::copy_from(&self.pool, packet));
        }
    }

    fn drain_queue_step<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if !self.queue_drainable {
            return TunnResult::Done;
        }
        let Some(packet) = self.packet_queue.pop_front() else {
            self.queue_drainable = false;
            return TunnResult::Done;
        };
        let now = self.now();
        match self.inner.encapsulate(now, &packet, dst, &mut self.rng) {
            Ok(Encapsulated::Transport(w)) => TunnResult::WriteToNetwork(w),
            Ok(Encapsulated::HandshakeInitiation(w)) => {
                // Session vanished mid-drain: requeue and stop.
                self.packet_queue.push_front(packet);
                self.queue_drainable = false;
                TunnResult::WriteToNetwork(w)
            }
            Err(e) => {
                self.packet_queue.push_front(packet);
                self.queue_drainable = false;
                TunnResult::Err(e)
            }
        }
    }
}

/// Encode a `SocketAddr` as the cookie's `remote` token: 16 bytes of IP
/// (v4 mapped into the first 4) + 2 bytes of port, big-endian. Stable
/// across calls so a cookie minted for an address validates a later
/// `mac2` from the same address.
#[must_use]
pub fn encode_addr(addr: SocketAddr) -> [u8; 18] {
    let mut b = [0u8; 18];
    match addr {
        SocketAddr::V4(a) => {
            if let Some(slot) = b.get_mut(..4) {
                slot.copy_from_slice(&a.ip().octets());
            }
        }
        SocketAddr::V6(a) => {
            if let Some(slot) = b.get_mut(..16) {
                slot.copy_from_slice(&a.ip().octets());
            }
        }
    }
    if let Some(slot) = b.get_mut(16..18) {
        slot.copy_from_slice(&addr.port().to_be_bytes());
    }
    b
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    fn pair() -> (Tunn, Tunn) {
        let mut rng = OsEntropy;
        use wireguard_sans_io::EntropySource;
        let a_key = StaticSecret::from_bytes(rng.gen32().unwrap());
        let b_key = StaticSecret::from_bytes(rng.gen32().unwrap());
        let a_pub = a_key.public_key();
        let b_pub = b_key.public_key();
        let rl = Arc::new(RateLimiter::new(100));
        (
            Tunn::new(a_key, b_pub, None, None, Some(rl.clone())).unwrap(),
            Tunn::new(b_key, a_pub, None, None, Some(rl)).unwrap(),
        )
    }

    #[test]
    fn handshake_and_transport_roundtrip() {
        let (mut a, mut b) = pair();
        let mut buf_a = vec![0u8; 2048];
        let mut buf_b = vec![0u8; 2048];

        // A → init
        let init = match a.format_handshake_initiation(&mut buf_a) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            other => panic!("{other:?}"),
        };
        // B ← init → resp
        let resp = match b.decapsulate(None, &init, &mut buf_b) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            other => panic!("{other:?}"),
        };
        // A ← resp → keepalive
        let ka = match a.decapsulate(None, &resp, &mut buf_a) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            other => panic!("{other:?}"),
        };
        assert!(a.is_established());
        // B ← keepalive
        match b.decapsulate(None, &ka, &mut buf_b) {
            TunnResult::Done => {}
            other => panic!("{other:?}"),
        }
        assert!(b.is_established());

        // Transport: a 60-byte fake IPv4 packet (so trim engages).
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&60u16.to_be_bytes());
        pkt[40..].fill(0xab);
        let wire = match a.encapsulate(&pkt, &mut buf_a) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            other => panic!("{other:?}"),
        };
        match b.decapsulate(None, &wire, &mut buf_b) {
            TunnResult::WriteToTunnel(d) => {
                assert_eq!(d.len(), 60, "padding must be trimmed");
                assert_eq!(d, &pkt[..]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn packet_queue_drains_after_handshake() {
        let (mut a, mut b) = pair();
        let mut buf_a = vec![0u8; 2048];
        let mut buf_b = vec![0u8; 2048];

        // A queues 3 packets while no session exists.
        let payloads: Vec<Vec<u8>> = (0..3u8)
            .map(|i| {
                let mut p = vec![0u8; 40];
                p[0] = 0x45;
                p[2..4].copy_from_slice(&40u16.to_be_bytes());
                p[39] = i;
                p
            })
            .collect();
        let mut to_send: Vec<Vec<u8>> = Vec::new();
        for p in &payloads {
            match a.encapsulate(p, &mut buf_a) {
                TunnResult::WriteToNetwork(w) => to_send.push(w.to_vec()),
                TunnResult::Done => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(to_send.len(), 1, "one initiation, two payloads queued");
        assert_eq!(a.packet_queue.len(), 3);

        // Handshake.
        let resp = match b.decapsulate(None, &to_send[0], &mut buf_b) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            other => panic!("{other:?}"),
        };
        // A processes response → keepalive comes back; then drain queue.
        let mut sent = Vec::new();
        let mut feed = resp.clone();
        loop {
            match a.decapsulate(None, &feed, &mut buf_a) {
                TunnResult::WriteToNetwork(w) => {
                    sent.push(w.to_vec());
                    feed = Vec::new(); // empty → drain step
                }
                TunnResult::Done => break,
                other => panic!("{other:?}"),
            }
        }
        // keepalive + 3 queued = 4 datagrams.
        assert_eq!(sent.len(), 4);
        assert!(a.packet_queue.is_empty());

        // B receives them all (skip the keepalive).
        let mut got = Vec::new();
        for w in &sent {
            match b.decapsulate(None, w, &mut buf_b) {
                TunnResult::WriteToTunnel(d) => got.push(d.to_vec()),
                TunnResult::Done => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(got, payloads);
    }

    #[test]
    fn rate_limiter_triggers_under_load() {
        let rl = Arc::new(RateLimiter::new(3));
        for i in 0..3 {
            assert!(!rl.note_handshake(), "first {i} are not under load");
        }
        for _ in 0..10 {
            assert!(rl.note_handshake(), "past the limit → under load");
        }
    }

    #[test]
    fn encode_addr_is_stable() {
        let a: SocketAddr = "192.0.2.7:51820".parse().unwrap();
        let b: SocketAddr = "192.0.2.7:51820".parse().unwrap();
        assert_eq!(encode_addr(a), encode_addr(b));
        let c: SocketAddr = "192.0.2.7:51821".parse().unwrap();
        assert_ne!(encode_addr(a), encode_addr(c));
        let d: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        assert_ne!(encode_addr(a), encode_addr(d));
    }
}
