//! `wireguard-embed`: a std + alloc driver around the
//! [`wireguard_sans_io`] no_std core, giving you BoringTun-style
//! ergonomics (built-in clock, OS RNG, rate limiter, packet queue) while
//! the protocol stays the core's: what goes on the wire, and when, is
//! decided by its panic-free, `forbid(unsafe_code)` state machine. (One
//! thing in the data path is not the core's own code: the ChaCha20
//! keystream of transport data, which comes from `wireguard-chacha-simd`
//! — the one crate here that contains `unsafe`. See *SIMD* below.)
//!
//! # One peer, one socket
//!
//! A [`Tunn`] is one peer **on a UDP socket of its own**. Each `Tunn`
//! owns a private [`wireguard_sans_io::Device`] — its own cookie secret
//! and its own key for session indices — so two of them cannot share a
//! socket: nothing can tell which of them a datagram is for, and offering
//! every datagram to every `Tunn` makes each of them answer the others'
//! peers (and strangers) with cookie replies and failed handshakes. For
//! several peers behind one socket use the core directly: one `Device`,
//! one [`wireguard_sans_io::Tunnel`] per peer, and `Device::receive` to
//! route (its documentation has the example).
//!
//! What several `Tunn`s *can* share is what belongs to the host rather
//! than to a socket: the buffer pool ([`Tunn::with_pool`]) and the
//! [`RateLimiter`] (one load signal, one allowance per source address).
//!
//! # What this crate adds on top of the core
//!
//! | Concern | `wireguard-sans-io` core | this crate |
//! |---|---|---|
//! | clock | caller passes `Ticks` | [`Tunn::now`]: a clock that keeps counting while the machine is suspended, where there is one (`CLOCK_BOOTTIME` on Linux and Android; `Instant` elsewhere), read by every call — or once per batch by the caller, who passes the reading to the `_at` form of each call. (`SystemTime` is read once, for the handshake-timestamp anchor.) |
//! | entropy | caller passes `&mut dyn EntropySource` | OS RNG via `getrandom` |
//! | keys in memory | caller builds `Device` and `Tunnel` where they are to stay | both behind a `Box` of their own, so a [`Tunn`] can be moved without its keys; the constructors leave nothing of the keys on the stack and wipe the copies they are given; [`Tunn::with_keys`] takes them by reference |
//! | rate limit / `under_load` | caller decides | built-in [`RateLimiter`]: under load once handshake messages have taken more time than a budget that fills at a tenth of a second per second and holds ten milliseconds (or, if you say so, once there have been so many), plus the kernel's per-source token bucket for sources a cookie has proven — and for the blocks of addresses they are in — and, if asked, a cap on cookie replies |
//! | padding vs. path MTU | caller passes the tunnel MTU | [`DEFAULT_MTU`] (1420) unless [`Tunn::set_mtu`] says otherwise |
//! | packet queue while no session | caller retries | internal `VecDeque` of at most [`MAX_QUEUE_DEPTH`] packets, none older than [`MAX_QUEUE_AGE`], drained in order once a session is usable |
//! | padding trim on receive | caller calls `ip_packet_len` | done for you |
//! | buffer management | caller-provided slices | [`SlabPool`] + RAII [`PooledBuf`]: bounded freelist of `Box<[u8]>` slabs (stable address ⇒ io_uring/RIO-ready); steady-state data path is allocation-free |
//! | async runtime | n/a | feature `async`: `tokio::AsyncTunn` — an event loop over a `UdpSocket`, the tunnel's timers and two `mpsc<PooledBuf>` channels for the TUN side, which never waits on the socket, reads its error queue, and does handshake arithmetic and cookie replies with the time traffic leaves it |
//!
//! What it deliberately does **not** add is protocol: which peer a
//! datagram is for, where the peer currently is, when a session is usable,
//! and every timer are decided by the core. In particular the destination
//! of every outgoing datagram comes from the core
//! ([`TunnResult::WriteToNetwork`] carries it) — this crate never infers
//! the peer's address from who it last heard from.
//!
//! # SIMD
//!
//! [`Tunn`] always uses [`Backend`] — the core's in-tree crypto provider
//! with the [`simd::Best`] ChaCha20 keystream for transport data: on
//! x86_64 the widest the CPU has, found when the program runs (AVX-512,
//! AVX2, or the scalar keystream — one build runs everywhere); NEON 4-way
//! on aarch64; the scalar path elsewhere. The core stays
//! `#![forbid(unsafe_code)]`; all `unsafe` is confined to the
//! `wireguard-chacha-simd` crate and validated against the scalar oracle.
//! To pin a specific provider, use the core API directly
//! ([`wireguard_sans_io::Device::with_provider`]).
//!
//! # API shape (BoringTun-compatible-ish)
//!
//! ```ignore
//! let mut tunn = Tunn::new(static_private, peer_public, None, None, Some(peer_addr), None)?;
//! match tunn.encapsulate(ip_packet, &mut dst) { ... }
//! match tunn.decapsulate(src_addr, datagram, &mut dst) { ... }
//! match tunn.update_timers(&mut dst) { ... }       // call once/sec, or:
//! let wake = tunn.next_wake();                     // sleep exactly
//!
//! // A batch on one reading of the clock:
//! let now = tunn.now();
//! for datagram in batch { match tunn.decapsulate_at(now, src_addr, datagram, &mut dst) { ... } }
//! ```
//!
//! Dropping back to the core API for anything this layer doesn't expose:
//! [`Tunn::core`] / [`Tunn::core_mut`] / [`Tunn::device`].
//!
//! # Which address replies leave from
//!
//! Neither this crate nor the core knows which *local* address a
//! datagram arrived at: a datagram to send carries where it goes
//! ([`TunnResult::WriteToNetwork`]), not where it leaves from. On a host
//! with one address that is all there is to know. On a host with several
//! — and a socket bound to all of them (`0.0.0.0`, `[::]`) — the system
//! picks the source address of every datagram from its routing table,
//! which need not be the address the peer contacted: the peer then
//! receives a handshake response from an address it did not write to,
//! and a NAT or firewall on the way may refuse it. (The Linux
//! implementation remembers, per peer, the local address the peer last
//! reached it at, and sends from there.) If your host has several
//! addresses, bind the socket to the one the peer is to use — one socket
//! per address if it is reachable at more than one.

#![forbid(unsafe_code)]

mod buffer;
mod clock;
mod rate_limiter;
mod rng;

#[cfg(feature = "async")]
pub mod tokio;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clock::Clock;
use wireguard_sans_io::crypto::ct;

#[cfg(feature = "async")]
use wireguard_sans_io::CookieChallenge;
use wireguard_sans_io::{
    Device, DeviceStats, DropReason, Encapsulated, Error, Handled, InTree, Incoming, PeerConfig,
    PeerId, PollOutput, PresharedKey, PublicKey, Received, StaticSecret, Ticks, Transmit, Tunnel,
    WallClock, ip_packet_len, peek,
};

pub use buffer::{BufferPool, MAX_DATAGRAM, NoPool, PooledBuf, SlabPool};
pub use rate_limiter::RateLimiter;
pub use rng::OsEntropy;
pub use wireguard_chacha_simd as simd;
pub use wireguard_sans_io as core;
pub use wireguard_sans_io::{ChaChaImpl, PacketKind, Stats};

/// The crypto provider [`Tunn`] uses: the core's in-tree primitives with
/// the best ChaCha20 keystream for this target (AVX2-8way on x86_64 where
/// the CPU has it, NEON-4way on aarch64, scalar elsewhere).
pub type Backend = InTree<wireguard_chacha_simd::Best>;

/// Max packets queued while no session is established (BoringTun: 256).
/// When a packet arrives at a full queue the *oldest* one makes way for
/// it (as in the Linux implementation) and is counted in
/// [`Tunn::queue_drops`].
pub const MAX_QUEUE_DEPTH: usize = 256;

/// How long a packet waits in the queue for a session before it is
/// dropped: Rekey-Attempt-Time, ninety seconds — the time after which the
/// protocol gives up on a handshake and on what was queued for it
/// (whitepaper §6.4).
///
/// The handshake's own deadline does not cover every packet. It starts
/// over with each packet that is queued, so a trickle of them keeps an
/// attempt — and the packets before them — alive indefinitely; and a
/// tunnel that does not know where its peer is has no attempt at all. So
/// each packet has its own: one that has waited this long is dropped
/// (and counted in [`Tunn::queue_drops`]) rather than sent, an hour
/// late, when the peer turns up.
pub const MAX_QUEUE_AGE: Duration = Duration::from_secs(90);

/// [`MAX_QUEUE_AGE`] in nanoseconds.
const MAX_QUEUE_AGE_NS: u64 = wireguard_sans_io::consts::REKEY_ATTEMPT_TIME;

/// The smallest buffer a [`Tunn`] call that may write a datagram accepts
/// as its `dst`: 148 bytes, a handshake initiation — the largest message
/// the tunnel sends of its own accord, and what such a call may have to
/// write instead of (or after) what it was asked for. BoringTun has the
/// same rule. A call given less does nothing and returns
/// `Err(TunnError::Core(Error::BufferTooSmall))`.
pub const MIN_BUFFER: usize = wireguard_sans_io::consts::HANDSHAKE_INITIATION_LEN;

/// The tunnel-interface MTU a [`Tunn`] assumes until told otherwise
/// ([`Tunn::set_mtu`]): 1420, the usual WireGuard MTU on a 1500-byte path.
///
/// WireGuard pads every packet to a multiple of 16 bytes, but never past
/// the tunnel MTU — otherwise a full-size packet on a tunnel whose MTU is
/// not a multiple of 16 (1420 is not) would grow by up to 15 bytes and no
/// longer fit the path.
pub const DEFAULT_MTU: u16 = 1420;

/// Offset of the decrypted packet inside a datagram that was processed
/// with [`Tunn::decapsulate_in_place`]: the transport header precedes it.
pub const PLAINTEXT_OFFSET: usize = wireguard_sans_io::consts::TRANSPORT_HEADER_LEN;

/// Why a [`Tunn`] call produced nothing to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TunnError {
    /// A local fault reported by the core: a buffer that is too small,
    /// an entropy failure, or an internal error. Nothing a remote party
    /// sends produces this.
    Core(Error),
    /// The received datagram was rejected. Drop it silently; nothing a
    /// remote party sends produces any error but this one,
    /// [`TunnError::TooLong`] and [`TunnError::RateLimited`].
    Dropped(DropReason),
    /// The received datagram is longer than the buffer
    /// [`Tunn::decapsulate`] was given to work in, and was not looked at.
    /// How long a datagram is, is its sender's choice, so this is not a
    /// fault of yours in the way [`TunnError::Core`] is — unless `dst` is
    /// smaller than the datagrams you mean to receive: give it the size
    /// of your receive buffer.
    TooLong,
    /// A handshake message that a limit kept from being answered (see
    /// [`RateLimiter`]): its source — proven by a cookie — has used up
    /// its allowance, or, under load, it had no cookie and the cap on
    /// cookie replies was reached. Dropped without doing any
    /// Diffie-Hellman work; the sender's own retransmission timer tries
    /// again.
    RateLimited,
    /// The handshake attempt was abandoned after `Rekey-Attempt-Time`;
    /// the packets queued for it were dropped.
    HandshakeExpired,
    /// All key material was wiped after nine minutes without a new
    /// session.
    SessionsExpired,
}

impl std::fmt::Display for TunnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(e) => write!(f, "{e}"),
            Self::Dropped(r) => write!(f, "datagram dropped: {r}"),
            Self::TooLong => f.write_str("datagram dropped: longer than the buffer for it"),
            Self::RateLimited => f.write_str("handshake message dropped: over a rate limit"),
            Self::HandshakeExpired => f.write_str("handshake attempt abandoned"),
            Self::SessionsExpired => f.write_str("sessions expired and were wiped"),
        }
    }
}

impl std::error::Error for TunnError {}

/// Result of [`Tunn::encapsulate`] / [`Tunn::decapsulate`] /
/// [`Tunn::update_timers`] — mirrors BoringTun's `TunnResult`.
///
/// Its `Debug` output gives the size of a packet or datagram, never its
/// bytes: a decrypted packet does not belong in a log.
pub enum TunnResult<'a> {
    /// Nothing to do.
    Done,
    /// Nothing to write; see [`TunnError`].
    Err(TunnError),
    /// Send this datagram to this address. The address is the core's
    /// decision — the peer's current endpoint, or, for a reply to an
    /// unauthenticated handshake message, wherever that message came
    /// from. Always send exactly there.
    ///
    /// After this result, **call [`Tunn::decapsulate`] again with an empty
    /// datagram** (or [`Tunn::drain_queue`]) until `Done`, to flush packets
    /// that were waiting for the session (BoringTun convention).
    WriteToNetwork(&'a [u8], SocketAddr),
    /// Deliver this decrypted IP packet to the local TUN interface.
    /// Padding has been trimmed via the inner IP length field. A payload
    /// that is not an IP packet (WireGuard carries nothing else, but the
    /// peer chooses what it sends) is passed on as it arrived, with the
    /// up to 15 bytes of padding the sender added.
    ///
    /// **The packet is authenticated; its addresses are not checked.**
    /// This layer does no cryptokey routing: before injecting the packet,
    /// check that its *source* address is one this peer may use
    /// (WireGuard's "allowed IPs";
    /// [`ip_packet_addresses`](wireguard_sans_io::ip_packet_addresses)
    /// reads it). Otherwise any peer can send packets in the name of any
    /// other.
    ///
    /// If this packet was the one that made a session usable, packets
    /// that were waiting for it are sent by the next
    /// [`Tunn::drain_queue`] / [`Tunn::update_timers`] calls
    /// ([`Tunn::next_wake`] reports that as due immediately).
    WriteToTunnel(&'a [u8]),
}

impl std::fmt::Debug for TunnResult<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Done => f.write_str("Done"),
            Self::Err(e) => f.debug_tuple("Err").field(e).finish(),
            Self::WriteToNetwork(datagram, to) => {
                write!(f, "WriteToNetwork({} bytes, {to})", datagram.len())
            }
            Self::WriteToTunnel(packet) => write!(f, "WriteToTunnel({} bytes)", packet.len()),
        }
    }
}

/// What [`Tunn::receive`] made of a datagram.
enum Inbound<'a> {
    /// The tunnel processed it.
    Handled(Handled<'a>),
    /// Under load, a handshake message without a valid cookie: send this
    /// cookie reply.
    Cookie(Transmit<'a>),
    /// It did not get as far as the tunnel.
    Refused(TunnError),
}

/// The pre-shared key as a constructor was given it: not at all, as the
/// 32 bytes [`Tunn::new`] takes, or as the key [`Tunn::with_keys`] takes.
/// Either way by reference — it is copied once, into the tunnel.
#[derive(Clone, Copy)]
enum Psk<'a> {
    None,
    Bytes(&'a [u8; 32]),
    Key(&'a PresharedKey),
}

impl<'a> Psk<'a> {
    fn bytes(given: Option<&'a [u8; 32]>) -> Self {
        given.map_or(Self::None, Self::Bytes)
    }
}

/// A WireGuard tunnel to a single peer, with std conveniences.
///
/// Thin owner around a [`wireguard_sans_io::Device`] and its one
/// [`wireguard_sans_io::Tunnel`]. All protocol work happens in the core;
/// this layer supplies time, entropy, the load signal and the
/// not-yet-established packet queue.
///
/// # Where the keys are
///
/// The device and the tunnel — everything that holds key material — live
/// on the heap, each in a box of its own. A `Tunn` can therefore be moved
/// (returned, handed to a task, put in a collection) without its keys
/// being copied: what moves is two pointers. They are wiped when the
/// `Tunn` is dropped.
///
/// The constructors leave nothing of the keys in their own stack frames,
/// and [`Tunn::new`] and [`Tunn::with_pool`], which are given the keys by
/// value, wipe what they were given. What they cannot reach is where the
/// caller had the keys before: giving a value away copies it, and the
/// bytes stay where they were. [`Tunn::with_keys`] takes references
/// instead — the caller keeps its one copy and says when it goes.
/// (`scripts/check_secret_residue.sh` looks at all of this on the stack
/// itself.)
pub struct Tunn {
    device: Box<Device<Backend>>,
    tunnel: Box<Tunnel<Backend>>,
    rate_limiter: Arc<RateLimiter>,
    pool: Arc<SlabPool>,
    /// Packets waiting for a session, each with the time it was queued.
    packet_queue: VecDeque<(Ticks, PooledBuf)>,
    /// Queued packets that were dropped: to make room in a full queue,
    /// because they waited too long, or because they could not be
    /// encrypted when their turn came.
    queue_drops: u64,
    /// A notification the timers produced during a call that had
    /// something else to report; [`Tunn::update_timers`] delivers it.
    pending_notice: Option<TunnError>,
    rng: rng::TunnEntropy,
    /// `Ticks` = this clock's reading: time since the tunnel was created.
    clock: Clock,
}

impl std::fmt::Debug for Tunn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunn")
            .field("tunnel", &self.tunnel)
            .field("queued", &self.packet_queue.len())
            .finish()
    }
}

impl Tunn {
    /// Create a tunnel.
    ///
    /// `endpoint` is where the peer can be reached, if known. Without it
    /// the tunnel cannot start a handshake; it learns the address from
    /// the peer's first authenticated message.
    ///
    /// `rate_limiter`: pass `None` to get a private limiter with the
    /// default load signal (cookies are demanded once handshake messages
    /// take more than a tenth of the time, ten milliseconds of it at
    /// once: [`RateLimiter::default`]), or one `Arc` to several `Tunn`s
    /// to give them a common load signal and a common allowance per
    /// source address. (Each `Tunn` still needs a socket of its own: see
    /// the crate documentation.)
    ///
    /// The tunnel assumes a tunnel-interface MTU of [`DEFAULT_MTU`]; if
    /// your TUN device has another, say so with [`Tunn::set_mtu`].
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] for a self-peering or low-order peer
    /// key; [`Error::EntropyFailure`] if the OS RNG fails.
    pub fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        mut preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        endpoint: Option<SocketAddr>,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Result<Self, Error> {
        // The two keys stay where they arrived — handing them on by value
        // would leave a copy here — and are wiped there: the pre-shared
        // key by hand, the static key as it is dropped.
        let made = Self::build(
            &static_private,
            peer_static_public,
            Psk::bytes(preshared_key.as_ref()),
            persistent_keepalive,
            endpoint,
            rate_limiter,
            SlabPool::for_wireguard(),
        );
        if let Some(psk) = &mut preshared_key {
            ct::wipe_array(psk);
        }
        made
    }

    /// As [`Tunn::new`], with an explicit buffer pool — share one
    /// `Arc<SlabPool>` across every `Tunn` (and its async driver, and
    /// your TUN reader) so the whole data path draws from one freelist.
    ///
    /// # Errors
    /// As [`Tunn::new`].
    pub fn with_pool(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        mut preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        endpoint: Option<SocketAddr>,
        rate_limiter: Option<Arc<RateLimiter>>,
        pool: Arc<SlabPool>,
    ) -> Result<Self, Error> {
        // As in `new`.
        let made = Self::build(
            &static_private,
            peer_static_public,
            Psk::bytes(preshared_key.as_ref()),
            persistent_keepalive,
            endpoint,
            rate_limiter,
            pool,
        );
        if let Some(psk) = &mut preshared_key {
            ct::wipe_array(psk);
        }
        made
    }

    /// As [`Tunn::new`], with the keys by reference: nothing of them is
    /// copied anywhere but into the tunnel. The caller's copies stay the
    /// caller's — one of each, wherever it keeps them, wiped when it
    /// drops them.
    ///
    /// `pool`: `None` for a private buffer pool, or the `Arc<SlabPool>`
    /// the tunnel is to share (see [`Tunn::with_pool`]).
    ///
    /// ```
    /// use wireguard_embed::core::{PresharedKey, StaticSecret};
    /// use wireguard_embed::{OsEntropy, Tunn};
    ///
    /// # fn main() -> Result<(), wireguard_embed::core::Error> {
    /// // The keys where they live (here: on the heap, generated in place).
    /// let key = Box::new(StaticSecret::generate(&mut OsEntropy)?);
    /// let psk = Box::new(PresharedKey::generate(&mut OsEntropy)?);
    /// # let peer = StaticSecret::generate(&mut OsEntropy)?.public_key();
    /// let tunn = Tunn::with_keys(&key, peer, Some(&psk), None, None, None, None)?;
    /// # drop(tunn);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// As [`Tunn::new`].
    pub fn with_keys(
        static_private: &StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<&PresharedKey>,
        persistent_keepalive: Option<u16>,
        endpoint: Option<SocketAddr>,
        rate_limiter: Option<Arc<RateLimiter>>,
        pool: Option<Arc<SlabPool>>,
    ) -> Result<Self, Error> {
        Self::build(
            static_private,
            peer_static_public,
            preshared_key.map_or(Psk::None, Psk::Key),
            persistent_keepalive,
            endpoint,
            rate_limiter,
            pool.unwrap_or_else(SlabPool::for_wireguard),
        )
    }

    /// Every constructor ends here: the keys by reference, and the stack
    /// that [`Tunn::assemble`] and the core's constructors beneath it
    /// used overwritten once the tunnel has been handed over.
    fn build(
        static_private: &StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Psk<'_>,
        persistent_keepalive: Option<u16>,
        endpoint: Option<SocketAddr>,
        rate_limiter: Option<Arc<RateLimiter>>,
        pool: Arc<SlabPool>,
    ) -> Result<Self, Error> {
        let mut scrub = ct::ScrubOnDrop::new();
        Self::assemble(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            endpoint,
            rate_limiter,
            pool,
            scrub.low(),
        )
    }

    /// The work of the constructors, in a frame of its own. The device
    /// and the tunnel are made here and moved into their boxes; what this
    /// frame, and those of the core's constructors beneath it, still hold
    /// of them afterwards is overwritten by the caller (`low` says how
    /// far down that goes).
    #[inline(never)]
    #[allow(clippy::too_many_arguments)] // the constructors' arguments, as they come
    fn assemble(
        static_private: &StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Psk<'_>,
        persistent_keepalive: Option<u16>,
        endpoint: Option<SocketAddr>,
        rate_limiter: Option<Arc<RateLimiter>>,
        pool: Arc<SlabPool>,
        low: &mut usize,
    ) -> Result<Self, Error> {
        *low = ct::stack_mark();
        let mut rng = rng::TunnEntropy::default();
        let clock = Clock::new();
        // The wall clock is read once, here, as the anchor for handshake
        // timestamps; everything afterwards runs off the tunnel's clock.
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let wall_clock = WallClock::new(Ticks::ZERO, wall.as_secs(), wall.subsec_nanos());
        let device = Box::new(Device::<Backend>::with_provider(
            static_private.clone(),
            wall_clock,
            &mut rng,
        )?);

        let mut config = PeerConfig::new(peer_static_public);
        match preshared_key {
            Psk::None => {}
            Psk::Bytes(psk) => config.psk = PresharedKey::from_bytes(*psk),
            Psk::Key(psk) => config.psk = psk.clone(),
        }
        config.persistent_keepalive = persistent_keepalive.and_then(std::num::NonZeroU16::new);
        config.endpoint = endpoint;
        config.mtu = std::num::NonZeroU16::new(DEFAULT_MTU);
        // One peer per `Tunn`: its id is always 0.
        let peer_id = PeerId::new(0).ok_or(Error::Internal)?;
        let tunnel = Box::new(device.tunnel(peer_id, config, &mut rng)?);
        Ok(Self {
            device,
            tunnel,
            rate_limiter: rate_limiter.unwrap_or_else(|| Arc::new(RateLimiter::default())),
            pool,
            packet_queue: VecDeque::new(),
            queue_drops: 0,
            pending_notice: None,
            rng,
            clock,
        })
    }

    /// The buffer pool this tunnel queues into. Hand this to your socket
    /// reader / TUN reader so everything shares one freelist.
    #[must_use]
    pub fn pool(&self) -> &Arc<SlabPool> {
        &self.pool
    }

    /// The tunnel's clock: nanoseconds since it was created. On Linux and
    /// Android that includes the time the machine has spent suspended
    /// (`CLOCK_BOOTTIME`) — a session is three minutes old after three
    /// minutes, whether or not anyone was awake; elsewhere it is
    /// `std::time::Instant`.
    ///
    /// Every call that takes no time of its own reads this clock. The
    /// `_at` variants ([`Tunn::encapsulate_at`] and the others) take a
    /// reading instead, for callers that handle packets in batches: read
    /// the clock once, pass it to every call of the batch. A reading may
    /// be a little old (the core never lets time go backwards); it must
    /// be *this* tunnel's — every `Tunn` counts from its own creation.
    #[must_use]
    pub fn now(&self) -> Ticks {
        self.clock.now()
    }

    /// Does [`Tunn::now`] count the time the machine spends suspended on
    /// this system? Where it does not, a tunnel that wakes up believes
    /// its sessions are as young as when it fell asleep; tell it
    /// otherwise (`core_mut().reset()` on resume) if you can.
    pub const CLOCK_COUNTS_SUSPEND: bool = Clock::COUNTS_SUSPEND;

    /// For the async loop, which keeps the tunnel's time on tokio's
    /// clock: see [`Clock::awake_and_suspended_ns`].
    #[cfg(feature = "async")]
    pub(crate) fn awake_and_suspended_ns(&self) -> (u64, u64) {
        self.clock.awake_and_suspended_ns()
    }

    /// For this crate's tests: while the switch is `true`, the tunnel's
    /// entropy source fails.
    #[cfg(all(test, feature = "async"))]
    pub(crate) fn entropy_switch(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.rng.switch()
    }

    /// Encrypt one IP packet from the TUN interface into `dst`.
    ///
    /// `dst` must hold the datagram — `src.len()` plus up to 47 bytes of
    /// padding and overhead — and never less than [`MIN_BUFFER`].
    ///
    /// The result says what became of `src`:
    ///
    /// * [`TunnResult::WriteToNetwork`] — send this datagram. `src` is in
    ///   it, or `src` is in the queue and this is what goes out first: an
    ///   older queued packet, or the handshake initiation that has to
    ///   come before any of them. Either way `src` has been taken.
    /// * [`TunnResult::Done`] — `src` was queued (no session yet, or no
    ///   endpoint to send to) and there is nothing to send right now.
    /// * [`TunnResult::Err`] — `src` was **not** taken: `dst` is too
    ///   small, or the core reported a fault while encrypting it. Nothing
    ///   was queued; the same call with the same arguments fails the same
    ///   way.
    ///
    /// The queue holds up to [`MAX_QUEUE_DEPTH`] packets; a packet that
    /// arrives when it is full pushes out the oldest
    /// ([`Tunn::queue_drops`]). Once a session is usable, queued packets
    /// go out first, in order: call [`Tunn::drain_queue`] until `Done`.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        self.encapsulate_at(self.now(), src, dst)
    }

    /// [`Tunn::encapsulate`] at a clock reading the caller took
    /// ([`Tunn::now`]).
    pub fn encapsulate_at<'a>(
        &mut self,
        now: Ticks,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if dst.len() < MIN_BUFFER {
            return TunnResult::Err(TunnError::Core(Error::BufferTooSmall));
        }
        // Plain values first, the borrow of `dst` at the very end: the
        // arms below need `self` and `dst` again in between.
        use EncapStep as Step;
        let step = if self.drainable(now) {
            // Keep the order: while older packets are still waiting and
            // can go out, this one goes behind them. The oldest goes out
            // now — which is also what makes room for this one. (If that
            // one cannot be encrypted it is dropped and counted; it is
            // not this call's packet, so it is not this call's error.)
            let sent = self.drain_one(now, dst);
            self.queue_packet(now, src);
            match sent {
                Drained::Sent(n, addr) => Step::Sent(n, addr),
                Drained::Dropped(_) | Drained::Nothing => Step::Queued,
            }
        } else {
            match self.tunnel.encapsulate(now, src, dst) {
                Ok(Encapsulated::Transport(tx)) => Step::Sent(tx.datagram.len(), tx.dst),
                Ok(Encapsulated::NoSession) => {
                    self.queue_packet(now, src);
                    // The core now wants a handshake: hand its initiation
                    // back right away if pacing allows one.
                    self.initiation_after_queuing(now, dst)
                }
                Ok(_) => {
                    // No endpoint: nowhere to send anything yet. Hold the
                    // packet until the peer contacts us — for a while
                    // ([`MAX_QUEUE_AGE`]).
                    self.queue_packet(now, src);
                    Step::Queued
                }
                Err(e) => Step::Err(TunnError::Core(e)),
            }
        };
        match step {
            Step::Sent(n, addr) => TunnResult::WriteToNetwork(dst.get(..n).unwrap_or(&[]), addr),
            Step::Queued => TunnResult::Done,
            Step::Err(e) => TunnResult::Err(e),
        }
    }

    /// Process a UDP datagram from the network, copying it into `dst`
    /// first (`dst` must be at least as long as the datagram, and never
    /// less than [`MIN_BUFFER`]: what is written there may be a datagram
    /// of the tunnel's own).
    ///
    /// `src_addr` is the address the datagram came from. The core binds
    /// cookies to it and — if the datagram authenticates — records it as
    /// the peer's endpoint.
    ///
    /// **BoringTun convention:** call this again with an *empty* datagram
    /// after a `WriteToNetwork` result to drain the packet queue, until
    /// `Done`.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: SocketAddr,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        self.decapsulate_at(self.now(), src_addr, datagram, dst)
    }

    /// [`Tunn::decapsulate`] at a clock reading the caller took
    /// ([`Tunn::now`]).
    pub fn decapsulate_at<'a>(
        &mut self,
        now: Ticks,
        src_addr: SocketAddr,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            return self.drain_queue_at(now, dst);
        }
        if dst.len() < MIN_BUFFER {
            return TunnResult::Err(TunnError::Core(Error::BufferTooSmall));
        }
        // How long the datagram is, is up to whoever sent it: one that
        // does not fit is the sender's doing, not a fault of ours.
        let Some(work) = dst.get_mut(..datagram.len()) else {
            return TunnResult::Err(TunnError::TooLong);
        };
        work.copy_from_slice(datagram);
        // A handshake response (92 bytes) or cookie reply (64) is built
        // here and copied to the front of `dst` afterwards.
        let mut reply = [0u8; wireguard_sans_io::consts::HANDSHAKE_RESPONSE_LEN];

        enum Step {
            Tunnel(usize),
            Reply(usize, SocketAddr),
            Quiet,
            Err(TunnError),
        }
        let (step, established) = match self.receive(now, src_addr, work, &mut reply) {
            Ok(Inbound::Handled(handled)) => {
                let step = match handled.received {
                    // Trim WireGuard's zero padding via the IP length
                    // header. Non-IP payloads are returned as-is.
                    Received::Data(d) => Step::Tunnel(ip_packet_len(d).unwrap_or(d.len())),
                    Received::HandshakeResponse(tx) | Received::CookieReply(tx) => {
                        Step::Reply(tx.datagram.len(), tx.dst)
                    }
                    Received::Dropped(reason) => Step::Err(TunnError::Dropped(reason)),
                    _ => Step::Quiet,
                };
                (step, handled.session_established)
            }
            Ok(Inbound::Cookie(tx)) => (Step::Reply(tx.datagram.len(), tx.dst), false),
            Ok(Inbound::Refused(why)) => (Step::Err(why), false),
            Err(e) => (Step::Err(TunnError::Core(e)), false),
        };
        match step {
            Step::Tunnel(n) => TunnResult::WriteToTunnel(
                dst.get(PLAINTEXT_OFFSET..PLAINTEXT_OFFSET.saturating_add(n))
                    .unwrap_or(&[]),
            ),
            Step::Reply(n, addr) => {
                let (Some(to), Some(from)) = (dst.get_mut(..n), reply.get(..n)) else {
                    return TunnResult::Err(TunnError::Core(Error::BufferTooSmall));
                };
                to.copy_from_slice(from);
                TunnResult::WriteToNetwork(dst.get(..n).unwrap_or(&[]), addr)
            }
            Step::Quiet if established => {
                // The session just became usable. Whatever was waiting
                // for it goes first (and doubles as the confirmation);
                // otherwise the core's confirming keepalive.
                if self.packet_queue.is_empty() {
                    self.poll_into(now, dst)
                } else {
                    self.drain_queue_at(now, dst)
                }
            }
            Step::Quiet => TunnResult::Done,
            Step::Err(e) => TunnResult::Err(e),
        }
    }

    /// Process a UDP datagram **in place**: transport data is decrypted
    /// inside `datagram` itself and [`TunnResult::WriteToTunnel`] borrows
    /// it (the packet starts at [`PLAINTEXT_OFFSET`]); a handshake
    /// response or cookie reply is written to `out` (which must hold 92
    /// bytes).
    ///
    /// Unlike [`Tunn::decapsulate`] this never sends anything of its own
    /// accord: after it, call [`Tunn::drain_queue`] and
    /// [`Tunn::update_timers`] until `Done` (the async driver does).
    pub fn decapsulate_in_place<'a>(
        &mut self,
        src_addr: SocketAddr,
        datagram: &'a mut [u8],
        out: &'a mut [u8],
    ) -> TunnResult<'a> {
        self.decapsulate_in_place_at(self.now(), src_addr, datagram, out)
    }

    /// [`Tunn::decapsulate_in_place`] at a clock reading the caller took
    /// ([`Tunn::now`]).
    pub fn decapsulate_in_place_at<'a>(
        &mut self,
        now: Ticks,
        src_addr: SocketAddr,
        datagram: &'a mut [u8],
        out: &'a mut [u8],
    ) -> TunnResult<'a> {
        match self.receive(now, src_addr, datagram, out) {
            Ok(Inbound::Handled(handled)) => match handled.received {
                Received::Data(d) => {
                    let n = ip_packet_len(d).unwrap_or(d.len());
                    TunnResult::WriteToTunnel(d.get(..n).unwrap_or(d))
                }
                Received::HandshakeResponse(tx) | Received::CookieReply(tx) => {
                    TunnResult::WriteToNetwork(tx.datagram, tx.dst)
                }
                Received::Dropped(reason) => TunnResult::Err(TunnError::Dropped(reason)),
                _ => TunnResult::Done,
            },
            Ok(Inbound::Cookie(tx)) => TunnResult::WriteToNetwork(tx.datagram, tx.dst),
            Ok(Inbound::Refused(why)) => TunnResult::Err(why),
            Err(e) => TunnResult::Err(TunnError::Core(e)),
        }
    }

    /// Send the oldest packet that was queued while no session existed,
    /// if a session is usable now. Call until `Done`.
    ///
    /// `dst` must hold [`MIN_BUFFER`] bytes (with less, nothing happens:
    /// `Err`). A queued packet that still does not fit `dst` is dropped,
    /// counted in [`Tunn::queue_drops`] and reported as `Err`; the ones
    /// behind it are not held up.
    pub fn drain_queue<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.drain_queue_at(self.now(), dst)
    }

    /// [`Tunn::drain_queue`] at a clock reading the caller took
    /// ([`Tunn::now`]).
    pub fn drain_queue_at<'a>(&mut self, now: Ticks, dst: &'a mut [u8]) -> TunnResult<'a> {
        if dst.len() < MIN_BUFFER {
            return TunnResult::Err(TunnError::Core(Error::BufferTooSmall));
        }
        match self.drain_one(now, dst) {
            Drained::Sent(n, addr) => TunnResult::WriteToNetwork(dst.get(..n).unwrap_or(&[]), addr),
            Drained::Dropped(e) => TunnResult::Err(TunnError::Core(e)),
            Drained::Nothing => TunnResult::Done,
        }
    }

    /// Packets dropped from the queue: the oldest one each time a packet
    /// arrived at a full queue ([`MAX_QUEUE_DEPTH`]), packets that waited
    /// longer than [`MAX_QUEUE_AGE`], and queued packets that could not
    /// be encrypted when their turn came (they did not fit the buffer
    /// they were to be written to). Packets dropped because a
    /// handshake attempt was given up are not counted here: that is
    /// reported as [`TunnError::HandshakeExpired`].
    #[must_use]
    pub fn queue_drops(&self) -> u64 {
        self.queue_drops
    }

    /// Timer tick (BoringTun's `update_timers`): call periodically (once
    /// per second is fine) **or** whenever [`Tunn::next_wake`] falls due.
    /// Returns at most one action; call again until it returns `Done` —
    /// or `Err(TunnError::Core(_))`, which is a local fault (a `dst`
    /// shorter than [`MIN_BUFFER`], the entropy source): what was to be
    /// done stays due, and asking again at once gets the same answer.
    /// The other errors are notifications, each delivered once.
    ///
    /// This is also the safety net for the packet queue: packets that are
    /// still waiting although a session has become usable are sent from
    /// here, oldest first, before any timer-driven datagram.
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.update_timers_at(self.now(), dst)
    }

    /// [`Tunn::update_timers`] at a clock reading the caller took
    /// ([`Tunn::now`]).
    pub fn update_timers_at<'a>(&mut self, now: Ticks, dst: &'a mut [u8]) -> TunnResult<'a> {
        if dst.len() < MIN_BUFFER {
            return TunnResult::Err(TunnError::Core(Error::BufferTooSmall));
        }
        if let Some(notice) = self.pending_notice.take() {
            return TunnResult::Err(notice);
        }
        self.expire_queue(now);
        if self.drainable(now) {
            return self.drain_queue_at(now, dst);
        }
        self.poll_into(now, dst)
    }

    /// The earliest `Instant` at which [`Tunn::update_timers`] has work:
    /// right now if queued packets can go out, otherwise the core's next
    /// timer or the moment the oldest queued packet has waited too long.
    /// `None` = nothing to do until something else happens. (BoringTun
    /// has no equivalent; callers there poll once per second.)
    ///
    /// The `Instant` is "this long from now". Where the tunnel's clock
    /// counts time spent suspended and `Instant` does not (Linux), a
    /// sleep that a suspend interrupts ends late by that clock; ask again
    /// after anything that may have been a suspend — or simply never
    /// sleep longer than a few seconds.
    #[must_use]
    pub fn next_wake(&self) -> Option<Instant> {
        let now = self.now();
        let due = self.next_wake_at(now)?;
        let wait = Duration::from_nanos(due.since(now));
        Some(
            Instant::now()
                .checked_add(wait)
                .unwrap_or_else(Instant::now),
        )
    }

    /// [`Tunn::next_wake`] on the tunnel's own clock: the reading at
    /// which [`Tunn::update_timers`] next has work, given that it is
    /// `now` — which is the answer itself if there is work already.
    #[must_use]
    pub fn next_wake_at(&self, now: Ticks) -> Option<Ticks> {
        if self.pending_notice.is_some() || self.drainable(now) {
            return Some(now);
        }
        let expiry = self
            .packet_queue
            .front()
            .map(|(queued_at, _)| queued_at.add_nanos(MAX_QUEUE_AGE_NS));
        match (self.tunnel.next_wake(), expiry) {
            (Some(timer), Some(expiry)) => Some(timer.min(expiry)),
            (timer, expiry) => timer.or(expiry),
        }
    }

    /// Ask for a handshake now and return the next datagram the tunnel
    /// wants to send — the initiation, unless pacing holds it back (then
    /// `Done`; [`Tunn::update_timers`] sends it when due).
    pub fn format_handshake_initiation<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let now = self.now();
        self.tunnel.request_handshake(now);
        self.poll_into(now, dst)
    }

    /// Is there a confirmed session ready to encrypt outgoing data?
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.is_established_at(self.now())
    }

    /// [`Tunn::is_established`] at a clock reading the caller took
    /// ([`Tunn::now`]).
    #[must_use]
    pub fn is_established_at(&self, now: Ticks) -> bool {
        self.tunnel.is_established(now)
    }

    /// Where the core currently sends this peer's datagrams.
    #[must_use]
    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.tunnel.endpoint()
    }

    /// Set the peer's endpoint (configuration or out-of-band discovery).
    pub fn set_endpoint(&mut self, endpoint: SocketAddr) {
        self.tunnel.set_endpoint(endpoint);
    }

    /// Tell the tunnel the MTU of your TUN interface (the inner MTU, not
    /// the path's). Padding never grows a packet past it; `None` removes
    /// the cap, which is only right if the MTU is a multiple of 16. The
    /// default is [`DEFAULT_MTU`].
    pub fn set_mtu(&mut self, mtu: Option<u16>) {
        self.tunnel.set_mtu(mtu.and_then(std::num::NonZeroU16::new));
    }

    /// The tunnel-interface MTU padding is capped at, if any.
    #[must_use]
    pub fn mtu(&self) -> Option<u16> {
        self.tunnel.mtu().map(std::num::NonZeroU16::get)
    }

    /// Packets currently waiting for a session.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.packet_queue.len()
    }

    /// Cumulative per-tunnel counters from the core.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.tunnel.stats()
    }

    /// Cumulative device-level counters from the core (malformed
    /// datagrams, `mac1` failures, cookies).
    #[must_use]
    pub fn device_stats(&self) -> DeviceStats {
        self.device.stats()
    }

    /// The rate limiter this tunnel consults — its own, or the one it
    /// was given to share with others.
    #[must_use]
    pub fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate_limiter
    }

    /// Borrow the underlying sans-I/O tunnel.
    #[must_use]
    pub fn core(&self) -> &Tunnel<Backend> {
        &self.tunnel
    }

    /// Mutably borrow the underlying sans-I/O tunnel.
    pub fn core_mut(&mut self) -> &mut Tunnel<Backend> {
        &mut self.tunnel
    }

    /// Borrow the underlying sans-I/O device.
    #[must_use]
    pub fn device(&self) -> &Device<Backend> {
        &self.device
    }

    // ---- internals ------------------------------------------------------

    /// Are there queued packets, and a session to send them on?
    fn drainable(&self, now: Ticks) -> bool {
        !self.packet_queue.is_empty() && self.tunnel.is_established(now)
    }

    /// The receive path: the core's device, the rate limiter, the tunnel.
    ///
    /// The order is the point (see [`RateLimiter`]):
    ///
    /// 1. The device checks `mac1` and, under load, the cookie. A datagram
    ///    that fails goes no further — and does not count toward the load
    ///    signal either, so someone who does not even know our public key
    ///    cannot push the interface "under load".
    /// 2. A handshake message that got through counts toward the load
    ///    signal: it is counted, and the time it takes from here to its
    ///    answer is measured. If a cookie proved its source address, that
    ///    source's allowance is consulted — the one place a per-source
    ///    limit can sit without being usable against the peer it is meant
    ///    to protect.
    /// 3. Only then the tunnel does the expensive part.
    ///
    /// None of this is on the data path. Transport data (and a cookie
    /// reply) has nothing to do with the limiter, and with one peer there
    /// is nothing to route either: it goes to the tunnel in one call,
    /// without the clock reads the load signal costs (two for a handshake
    /// message: when it arrives and when it is done with) and without
    /// decoding the receiver index into a peer id — together a quarter of
    /// the cost of receiving a small packet.
    fn receive<'a>(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        datagram: &'a mut [u8],
        out: &'a mut [u8],
    ) -> Result<Inbound<'a>, Error> {
        if !is_handshake(datagram) {
            return self
                .device
                .receive_for(
                    &mut self.tunnel,
                    now,
                    src,
                    false,
                    datagram,
                    out,
                    &mut self.rng,
                )
                .map(Inbound::Handled);
        }
        self.receive_handshake(now, src, datagram, out)
    }

    /// [`Tunn::receive`] for a handshake message: steps 1 to 3 there.
    /// Out of line, so that what the limiter needs — which is not little
    /// — is not laid out in the middle of the data path.
    #[inline(never)]
    fn receive_handshake<'a>(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        datagram: &'a mut [u8],
        out: &'a mut [u8],
    ) -> Result<Inbound<'a>, Error> {
        // The limiter's clock, once: for the window, the count and the
        // source's bucket, and as the start of what this message costs.
        let limiter = &self.rate_limiter;
        let started = limiter.now_ns();
        let under_load = limiter.is_under_load_at(started);
        let outcome = match self.device.receive(now, src, under_load, datagram) {
            Incoming::Initiation(initiation) => {
                let _ = limiter.note_handshake_at(started);
                if initiation.source_verified() && !limiter.allow_source_at(src.ip(), started) {
                    Ok(Inbound::Refused(TunnError::RateLimited))
                } else {
                    // One peer, so nobody to look up: the tunnel finds
                    // out itself whether the initiation is its peer's.
                    self.tunnel
                        .handle_initiation(now, &initiation, out, &mut self.rng)
                        .map(Inbound::Handled)
                }
            }
            Incoming::ForPeer(_, packet) => {
                let _ = limiter.note_handshake_at(started);
                if packet.source_verified() && !limiter.allow_source_at(src.ip(), started) {
                    Ok(Inbound::Refused(TunnError::RateLimited))
                } else {
                    self.tunnel.handle(now, src, packet).map(Inbound::Handled)
                }
            }
            Incoming::CookieRequired(challenge) => {
                let _ = limiter.note_handshake_at(started);
                if limiter.allow_cookie_reply_at(started) {
                    self.device
                        .cookie_reply(now, &challenge, out, &mut self.rng)
                        .map(Inbound::Cookie)
                } else {
                    Ok(Inbound::Refused(TunnError::RateLimited))
                }
            }
            // What did not pass the `mac1` check is not counted and not
            // timed: it says nothing about load that a stranger could not
            // say at will.
            Incoming::Dropped(reason) => {
                return Ok(Inbound::Refused(TunnError::Dropped(reason)));
            }
            _ => return Ok(Inbound::Refused(TunnError::Dropped(DropReason::Malformed))),
        };
        self.rate_limiter.note_handshake_time_since(started);
        outcome
    }

    /// The first half of [`Tunn::receive`], for a caller that does the
    /// second half later (the event loop): what kind of datagram is this,
    /// and is it worth any more work?
    ///
    /// For a handshake message this makes the cheap checks — `mac1`,
    /// under load the cookie, for a proven source its allowance — and
    /// stops there: nothing expensive has been done, and what is left to
    /// do is the caller's to schedule ([`Tunn::deferred_handshake_at`],
    /// [`Tunn::cookie_reply_at`]). Counting, and the time it took, go to
    /// the load signal as in `receive`.
    #[cfg(feature = "async")]
    pub(crate) fn triage(&mut self, now: Ticks, src: SocketAddr, datagram: &mut [u8]) -> Triage {
        if !is_handshake(datagram) {
            return Triage::Now;
        }
        let limiter = &self.rate_limiter;
        let started = limiter.now_ns();
        let under_load = limiter.is_under_load_at(started);
        let verdict = match self.device.receive(now, src, under_load, datagram) {
            Incoming::Initiation(initiation) => {
                let _ = limiter.note_handshake_at(started);
                if initiation.source_verified() && !limiter.allow_source_at(src.ip(), started) {
                    Triage::Refused
                } else {
                    Triage::Handshake
                }
            }
            Incoming::ForPeer(_, packet) => {
                let _ = limiter.note_handshake_at(started);
                if packet.source_verified() && !limiter.allow_source_at(src.ip(), started) {
                    Triage::Refused
                } else {
                    Triage::Handshake
                }
            }
            Incoming::CookieRequired(challenge) => {
                let _ = limiter.note_handshake_at(started);
                Triage::Challenge(challenge)
            }
            // As in `receive`: neither counted nor timed.
            _ => return Triage::Refused,
        };
        self.rate_limiter.note_handshake_time_since(started);
        verdict
    }

    /// The second half, for a handshake message that [`Tunn::triage`]
    /// called [`Triage::Handshake`]: the tunnel's part — the
    /// Diffie-Hellman operations — and the answer, if there is one, in
    /// `out` (92 bytes).
    ///
    /// The checks triage made were counted then. They are made once more
    /// here, a keyed hash, because that is the only way to the core's
    /// `Initiation`; the counters of that second look are not kept.
    #[cfg(feature = "async")]
    pub(crate) fn deferred_handshake_at<'a>(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        datagram: &'a mut [u8],
        out: &'a mut [u8],
    ) -> TunnResult<'a> {
        let started = self.rate_limiter.now_ns();
        let mut uncounted = DeviceStats::default();
        let handled = match self
            .device
            .receive_shared(None, now, src, datagram, &mut uncounted)
        {
            Incoming::Initiation(initiation) => self
                .tunnel
                .handle_initiation(now, &initiation, out, &mut self.rng)
                .map(Some),
            Incoming::ForPeer(_, packet) => self.tunnel.handle(now, src, packet).map(Some),
            _ => Ok(None),
        };
        self.rate_limiter.note_handshake_time_since(started);
        match handled {
            Ok(Some(handled)) => match handled.received {
                Received::HandshakeResponse(tx) | Received::CookieReply(tx) => {
                    TunnResult::WriteToNetwork(tx.datagram, tx.dst)
                }
                Received::Dropped(reason) => TunnResult::Err(TunnError::Dropped(reason)),
                _ => TunnResult::Done,
            },
            Ok(None) => TunnResult::Err(TunnError::Dropped(DropReason::Malformed)),
            Err(e) => TunnResult::Err(TunnError::Core(e)),
        }
    }

    /// The cookie reply for a handshake message that [`Tunn::triage`]
    /// called [`Triage::Challenge`], in `out` (64 bytes) — unless the
    /// limiter's cap on cookie replies says no
    /// ([`TunnError::RateLimited`]).
    #[cfg(feature = "async")]
    pub(crate) fn cookie_reply_at<'a>(
        &mut self,
        now: Ticks,
        challenge: &CookieChallenge,
        out: &'a mut [u8],
    ) -> TunnResult<'a> {
        let limiter = &self.rate_limiter;
        let started = limiter.now_ns();
        if !limiter.allow_cookie_reply_at(started) {
            return TunnResult::Err(TunnError::RateLimited);
        }
        let reply = self.device.cookie_reply(now, challenge, out, &mut self.rng);
        self.rate_limiter.note_handshake_time_since(started);
        match reply {
            Ok(tx) => TunnResult::WriteToNetwork(tx.datagram, tx.dst),
            Err(e) => TunnResult::Err(TunnError::Core(e)),
        }
    }

    /// One `poll` of the core, as a `TunnResult`.
    fn poll_into<'a>(&mut self, now: Ticks, dst: &'a mut [u8]) -> TunnResult<'a> {
        match self.tunnel.poll(now, dst, &mut self.rng) {
            Ok(PollOutput::Transmit(tx, _)) => TunnResult::WriteToNetwork(tx.datagram, tx.dst),
            Ok(PollOutput::HandshakeExpired) => {
                // §6.4: "…and clear all existing packets queued up to be
                // sent."
                self.packet_queue.clear();
                TunnResult::Err(TunnError::HandshakeExpired)
            }
            Ok(PollOutput::SessionsExpired) => TunnResult::Err(TunnError::SessionsExpired),
            Ok(_) => TunnResult::Done,
            Err(e) => TunnResult::Err(TunnError::Core(e)),
        }
    }

    /// Drop the queued packets that have waited [`MAX_QUEUE_AGE`] or
    /// longer (they are at the front: the queue is in order of arrival).
    fn expire_queue(&mut self, now: Ticks) {
        while self
            .packet_queue
            .front()
            .is_some_and(|(queued_at, _)| now.since(*queued_at) >= MAX_QUEUE_AGE_NS)
        {
            if self.packet_queue.pop_front().is_none() {
                break;
            }
            self.queue_drops = self.queue_drops.saturating_add(1);
        }
    }

    /// Put a packet at the back of the queue. A full queue gives up its
    /// oldest packet for it: the newest traffic is the traffic worth
    /// keeping, and the caller has been told this one was taken.
    fn queue_packet(&mut self, now: Ticks, packet: &[u8]) {
        if packet.is_empty() {
            return;
        }
        self.expire_queue(now);
        while self.packet_queue.len() >= MAX_QUEUE_DEPTH {
            if self.packet_queue.pop_front().is_none() {
                break;
            }
            self.queue_drops = self.queue_drops.saturating_add(1);
        }
        self.packet_queue
            .push_back((now, PooledBuf::copy_from(&self.pool, packet)));
    }

    /// Encrypt the oldest queued packet into `dst`, if a session is
    /// usable; `dst` holds at least [`MIN_BUFFER`] bytes.
    fn drain_one(&mut self, now: Ticks, dst: &mut [u8]) -> Drained {
        // Only when it can actually go out: asking the core to encrypt
        // without a session would count as a fresh send request.
        self.expire_queue(now);
        if !self.drainable(now) {
            return Drained::Nothing;
        }
        let Some((_, packet)) = self.packet_queue.pop_front() else {
            return Drained::Nothing;
        };
        match self.tunnel.encapsulate(now, &packet, dst) {
            Ok(Encapsulated::Transport(tx)) => Drained::Sent(tx.datagram.len(), tx.dst),
            // The core said a session was usable and then would not use
            // it. That cannot happen; if it ever did, putting the packet
            // back would make this call "due" forever. Report it instead.
            Ok(_) => {
                self.queue_drops = self.queue_drops.saturating_add(1);
                Drained::Dropped(Error::Internal)
            }
            // The same packet into the same buffer would fail the same
            // way: it is gone.
            Err(e) => {
                self.queue_drops = self.queue_drops.saturating_add(1);
                Drained::Dropped(e)
            }
        }
    }

    /// After `encapsulate` has queued its packet for want of a session:
    /// the handshake initiation, if one may go out now. Whatever else the
    /// timers have to say at this moment is not about that packet — it is
    /// in the queue — and is left for [`Tunn::update_timers`]: a local
    /// fault stays due in the core, a notification is kept for it.
    fn initiation_after_queuing(&mut self, now: Ticks, dst: &mut [u8]) -> EncapStep {
        // At most the key-wipe notification can come before the
        // initiation; the bound is for safety, not for need.
        for _ in 0..4 {
            match self.tunnel.poll(now, dst, &mut self.rng) {
                Ok(PollOutput::Transmit(tx, _)) => {
                    return EncapStep::Sent(tx.datagram.len(), tx.dst);
                }
                Ok(PollOutput::SessionsExpired) => {
                    self.pending_notice = Some(TunnError::SessionsExpired);
                }
                // §6.4: the attempt is abandoned and what was queued for
                // it is dropped — the packet of this call included, so
                // this one is the caller's to know. (It cannot follow a
                // send request, which restarts the attempt; handled all
                // the same.)
                Ok(PollOutput::HandshakeExpired) => {
                    self.packet_queue.clear();
                    return EncapStep::Err(TunnError::HandshakeExpired);
                }
                Ok(_) | Err(_) => return EncapStep::Queued,
            }
        }
        EncapStep::Queued
    }
}

/// What [`Tunn::triage`] made of a datagram that has just arrived.
#[cfg(feature = "async")]
pub(crate) enum Triage {
    /// Not a handshake message — transport data, a cookie reply, noise:
    /// to be processed at once ([`Tunn::decapsulate_in_place_at`]).
    Now,
    /// A handshake message that passed the cheap checks. What it costs
    /// comes next: [`Tunn::deferred_handshake_at`], when there is time.
    Handshake,
    /// Under load, a handshake message without a cookie: a cookie reply
    /// can be made for it ([`Tunn::cookie_reply_at`]) — when there is
    /// time, and if there is.
    Challenge(CookieChallenge),
    /// Dropped — a wrong `mac1`, or a proven source that is over its
    /// allowance: nothing more to do.
    Refused,
}

/// What became of the packet given to [`Tunn::encapsulate`].
enum EncapStep {
    /// A datagram is in `dst`: this many bytes, for this address.
    Sent(usize, SocketAddr),
    /// The packet is in the queue; nothing to send.
    Queued,
    /// The packet was not taken.
    Err(TunnError),
}

/// What [`Tunn::drain_one`] did.
enum Drained {
    /// A queued packet is in `dst`: this many bytes, for this address.
    Sent(usize, SocketAddr),
    /// The oldest queued packet could not be encrypted and is gone.
    Dropped(Error),
    /// Nothing to send: no usable session, or an empty queue.
    Nothing,
}

/// Is this datagram, by its type and length, a handshake initiation or
/// response? Borrow-only, and looks at nothing else.
fn is_handshake(datagram: &[u8]) -> bool {
    matches!(
        peek(datagram),
        Ok(PacketKind::HandshakeInitiation { .. } | PacketKind::HandshakeResponse { .. })
    )
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

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    fn a_addr() -> SocketAddr {
        addr("192.0.2.1:51820")
    }
    fn b_addr() -> SocketAddr {
        addr("192.0.2.2:51820")
    }

    fn keypair() -> (StaticSecret, PublicKey) {
        use wireguard_sans_io::EntropySource;
        let sk = StaticSecret::from_bytes(OsEntropy.gen32().unwrap());
        let pk = sk.public_key();
        (sk, pk)
    }

    /// A knows where B is; B learns A's address from the handshake.
    fn pair_with_limit(limit: u64) -> (Tunn, Tunn) {
        let (a_key, a_pub) = keypair();
        let (b_key, b_pub) = keypair();
        let rl = Arc::new(RateLimiter::new(limit));
        (
            Tunn::new(a_key, b_pub, None, None, Some(b_addr()), Some(rl.clone())).unwrap(),
            Tunn::new(b_key, a_pub, None, None, None, Some(rl)).unwrap(),
        )
    }

    fn pair() -> (Tunn, Tunn) {
        pair_with_limit(100)
    }

    fn ip_packet(len: usize, tag: u8) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[len - 1] = tag;
        p
    }

    fn net(r: TunnResult<'_>) -> (Vec<u8>, SocketAddr) {
        match r {
            TunnResult::WriteToNetwork(w, to) => (w.to_vec(), to),
            other => panic!("expected WriteToNetwork, got {other:?}"),
        }
    }

    /// A initiates, B responds, A confirms. Returns nothing; both are
    /// established afterwards.
    fn establish(a: &mut Tunn, b: &mut Tunn) {
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let (init, to) = net(a.format_handshake_initiation(&mut buf_a));
        assert_eq!(to, b_addr());
        let (resp, to) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        assert_eq!(
            to,
            a_addr(),
            "the response goes back to where the initiation came from"
        );
        let (ka, to) = net(a.decapsulate(b_addr(), &resp, &mut buf_a));
        assert_eq!(to, b_addr());
        assert!(a.is_established());
        assert!(matches!(
            b.decapsulate(a_addr(), &ka, &mut buf_b),
            TunnResult::Done
        ));
        assert!(b.is_established());
    }

    #[test]
    fn handshake_and_transport_roundtrip() {
        let (mut a, mut b) = pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        establish(&mut a, &mut b);
        assert_eq!(b.endpoint(), Some(a_addr()), "B learned A's address");

        // Transport: a 60-byte fake IPv4 packet (so trim engages).
        let pkt = ip_packet(60, 0xab);
        let (wire, to) = net(a.encapsulate(&pkt, &mut buf_a));
        assert_eq!(to, b_addr());
        match b.decapsulate(a_addr(), &wire, &mut buf_b) {
            TunnResult::WriteToTunnel(d) => {
                assert_eq!(d.len(), 60, "padding must be trimmed");
                assert_eq!(d, &pkt[..]);
            }
            other => panic!("{other:?}"),
        }
        // And back.
        let (wire, to) = net(b.encapsulate(&pkt, &mut buf_b));
        assert_eq!(to, a_addr());
        assert!(matches!(
            a.decapsulate(b_addr(), &wire, &mut buf_a),
            TunnResult::WriteToTunnel(d) if d == &pkt[..]
        ));
    }

    #[test]
    fn decapsulate_in_place_leaves_the_packet_behind_the_header() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        let (mut buf_a, mut out) = (vec![0u8; 2048], vec![0u8; 128]);
        let pkt = ip_packet(77, 0x5c);
        let (mut wire, _) = net(a.encapsulate(&pkt, &mut buf_a));
        match b.decapsulate_in_place(a_addr(), &mut wire, &mut out) {
            TunnResult::WriteToTunnel(d) => assert_eq!(d, &pkt[..]),
            other => panic!("{other:?}"),
        }
        assert_eq!(&wire[PLAINTEXT_OFFSET..PLAINTEXT_OFFSET + 77], &pkt[..]);
        // A forgery leaves the datagram exactly as it arrived.
        let (mut wire, _) = net(a.encapsulate(&pkt, &mut buf_a));
        wire[40] ^= 1;
        let before = wire.clone();
        assert!(matches!(
            b.decapsulate_in_place(a_addr(), &mut wire, &mut out),
            TunnResult::Err(TunnError::Dropped(DropReason::AuthFailure))
        ));
        assert_eq!(wire, before);
    }

    #[test]
    fn packet_queue_drains_in_order_after_handshake() {
        let (mut a, mut b) = pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);

        // A queues 3 packets while no session exists.
        let payloads: Vec<Vec<u8>> = (0..3u8).map(|i| ip_packet(40, i)).collect();
        let mut to_send: Vec<Vec<u8>> = Vec::new();
        for p in &payloads {
            match a.encapsulate(p, &mut buf_a) {
                TunnResult::WriteToNetwork(w, to) => {
                    assert_eq!(to, b_addr());
                    to_send.push(w.to_vec());
                }
                TunnResult::Done => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(to_send.len(), 1, "one initiation, three payloads queued");
        assert_eq!(a.queued(), 3);

        // Handshake.
        let (resp, _) = net(b.decapsulate(a_addr(), &to_send[0], &mut buf_b));
        // A processes the response: the first queued packet goes out at
        // once (it confirms the session; no keepalive is needed), then the
        // empty-datagram calls drain the rest.
        let mut sent = Vec::new();
        let mut feed = resp.clone();
        loop {
            match a.decapsulate(b_addr(), &feed, &mut buf_a) {
                TunnResult::WriteToNetwork(w, to) => {
                    assert_eq!(to, b_addr());
                    sent.push(w.to_vec());
                    feed = Vec::new(); // empty → drain step
                }
                TunnResult::Done => break,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(sent.len(), 3, "exactly the three queued packets");
        assert_eq!(a.queued(), 0);
        // No stray keepalive afterwards.
        assert!(matches!(a.update_timers(&mut buf_a), TunnResult::Done));

        // B receives them all, in the order they were queued.
        let mut got = Vec::new();
        for w in &sent {
            match b.decapsulate(a_addr(), w, &mut buf_b) {
                TunnResult::WriteToTunnel(d) => got.push(d.to_vec()),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(got, payloads);
    }

    /// A side that queued a packet and then became the RESPONDER of the
    /// handshake that completed must flush that packet too, and before
    /// anything newer. (It used to stay queued while later packets
    /// overtook it.)
    #[test]
    fn queued_packet_is_flushed_when_we_end_up_responder() {
        let (mut a, mut b) = pair();
        // B knows where A is, so it can try a handshake of its own.
        b.set_endpoint(a_addr());
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);

        // B has traffic and no session: packet #1 is queued, B's
        // initiation is emitted… and lost.
        let (_lost, _) = net(b.encapsulate(&ip_packet(60, 1), &mut buf_b));
        assert_eq!(b.queued(), 1);

        // Meanwhile A initiates; B answers as responder.
        let (init, _) = net(a.format_handshake_initiation(&mut buf_a));
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        let (confirm, _) = net(a.decapsulate(b_addr(), &resp, &mut buf_a));

        // A's confirming keepalive makes B's session usable: packet #1
        // goes out right then.
        let (wire1, to) = net(b.decapsulate(a_addr(), &confirm, &mut buf_b));
        assert_eq!(to, a_addr());
        assert!(b.is_established());
        assert_eq!(b.queued(), 0);
        match a.decapsulate(b_addr(), &wire1, &mut buf_a) {
            TunnResult::WriteToTunnel(d) => assert_eq!(d[59], 1, "the queued packet, first"),
            other => panic!("{other:?}"),
        }
        // A later packet follows normally.
        let (wire2, _) = net(b.encapsulate(&ip_packet(60, 2), &mut buf_b));
        match a.decapsulate(b_addr(), &wire2, &mut buf_a) {
            TunnResult::WriteToTunnel(d) => assert_eq!(d[59], 2),
            other => panic!("{other:?}"),
        }
    }

    /// A packet sent while older ones are still waiting goes behind them.
    #[test]
    fn sending_while_packets_are_queued_keeps_their_order() {
        let (mut a, mut b) = pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let (init, _) = net(a.encapsulate(&ip_packet(40, 1), &mut buf_a));
        assert!(matches!(
            a.encapsulate(&ip_packet(40, 2), &mut buf_a),
            TunnResult::Done
        ));
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        // The response is processed in place, which sends nothing itself…
        let mut resp = resp;
        let mut scratch = vec![0u8; 128];
        assert!(matches!(
            a.decapsulate_in_place(b_addr(), &mut resp, &mut scratch),
            TunnResult::Done
        ));
        assert_eq!(a.queued(), 2);
        // …so when the application sends #3 now, #1 goes out first.
        let mut order = Vec::new();
        let (w, _) = net(a.encapsulate(&ip_packet(40, 3), &mut buf_a));
        order.push(w);
        while let TunnResult::WriteToNetwork(w, _) = a.drain_queue(&mut buf_a) {
            order.push(w.to_vec());
        }
        let tags: Vec<u8> = order
            .iter()
            .map(|w| match b.decapsulate(a_addr(), w, &mut buf_b) {
                TunnResult::WriteToTunnel(d) => d[39],
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(tags, vec![1, 2, 3]);
    }

    /// The session can also be confirmed by a DATA packet, which has to be
    /// returned as `WriteToTunnel` — so the waiting packets cannot go out
    /// in the same call. They must not wait for the application to send
    /// again: the timer tick sends them, and `next_wake` says "now".
    #[test]
    fn queue_is_flushed_by_the_timer_tick_when_data_confirms_the_session() {
        let (mut a, mut b) = pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        // B has two packets and nowhere to send them. Nothing is due but
        // their own deadline, a minute and a half away.
        for tag in [1, 2] {
            assert!(matches!(
                b.encapsulate(&ip_packet(60, tag), &mut buf_b),
                TunnResult::Done
            ));
        }
        assert!(
            b.next_wake()
                .is_some_and(|at| at > Instant::now() + Duration::from_secs(80))
        );
        // A sends data: it is queued behind A's handshake and becomes the
        // first transport packet of the session.
        let (init, _) = net(a.encapsulate(&ip_packet(60, 9), &mut buf_a));
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        let (first, _) = net(a.decapsulate(b_addr(), &resp, &mut buf_a));
        match b.decapsulate(a_addr(), &first, &mut buf_b) {
            TunnResult::WriteToTunnel(d) => assert_eq!(d[59], 9),
            other => panic!("{other:?}"),
        }
        // B's two packets are still waiting, and B says so.
        assert_eq!(b.queued(), 2);
        assert!(
            b.next_wake().is_some_and(|at| at <= Instant::now()),
            "work is due immediately"
        );
        let mut tags = Vec::new();
        loop {
            match b.update_timers(&mut buf_b) {
                TunnResult::WriteToNetwork(w, to) => {
                    assert_eq!(to, a_addr());
                    match a.decapsulate(b_addr(), w, &mut buf_a) {
                        TunnResult::WriteToTunnel(d) => tags.push(d[59]),
                        other => panic!("{other:?}"),
                    }
                }
                TunnResult::Done => break,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(tags, vec![1, 2]);
        assert_eq!(b.queued(), 0);
        assert!(b.next_wake().is_none_or(|at| at > Instant::now()));
    }

    /// A queued packet that does not fit the output buffer is dropped and
    /// reported; it must not block the packets behind it forever.
    #[test]
    fn a_queued_packet_that_cannot_be_sent_does_not_block_the_queue() {
        let (mut a, mut b) = pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        // 2040 bytes pad to 2048 and need 2080 on the wire: too big for
        // the 2048-byte buffer used below.
        let (init, _) = net(a.encapsulate(&ip_packet(2040, 1), &mut buf_a));
        assert!(matches!(
            a.encapsulate(&ip_packet(60, 2), &mut buf_a),
            TunnResult::Done
        ));
        assert_eq!(a.queued(), 2);
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        assert!(matches!(
            a.decapsulate(b_addr(), &resp, &mut buf_a),
            TunnResult::Err(TunnError::Core(Error::BufferTooSmall))
        ));
        assert_eq!(a.queued(), 1, "the oversized packet is gone");
        let (wire, _) = net(a.drain_queue(&mut buf_a));
        match b.decapsulate(a_addr(), &wire, &mut buf_b) {
            TunnResult::WriteToTunnel(d) => assert_eq!(d[59], 2),
            other => panic!("{other:?}"),
        }
        assert_eq!(a.queued(), 0);
        assert!(matches!(a.drain_queue(&mut buf_a), TunnResult::Done));
    }

    /// A packet that is queued is queued whole, however big it is: it
    /// used to be cut down to the size of a pool buffer (2048 bytes) and
    /// sent like that, without a word.
    #[test]
    fn a_queued_packet_larger_than_a_pool_buffer_is_sent_whole() {
        let (mut a, mut b) = pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 8192], vec![0u8; 8192]);
        let mut big = ip_packet(3000, 9);
        for (i, byte) in big.iter_mut().enumerate().skip(20) {
            *byte = (i % 251) as u8;
        }
        let (init, _) = net(a.encapsulate(&big, &mut buf_a));
        assert_eq!(a.queued(), 1);
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        // The response completes the handshake, and the queued packet
        // goes out as its confirmation.
        let (wire, _) = net(a.decapsulate(b_addr(), &resp, &mut buf_a));
        // (Above the tunnel MTU the padding goes by the last `len % mtu`
        // bytes, as in the kernel: 3000 % 1420 = 160, already aligned.)
        assert_eq!(wire.len(), 3000 + 32);
        match b.decapsulate(a_addr(), &wire, &mut buf_b) {
            TunnResult::WriteToTunnel(d) => assert_eq!(d, &big[..]),
            other => panic!("{other:?}"),
        }
        assert_eq!(a.queue_drops(), 0);
    }

    /// A full queue makes room for a new packet by giving up its oldest —
    /// and counts it. The packet the caller has just been told was taken
    /// is never the one that silently disappears.
    #[test]
    fn a_full_queue_gives_up_its_oldest_packet_and_counts_it() {
        let (mut a, mut b) = pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let tag = |n: usize| ip_packet(60 + n % 2, (n % 251) as u8);
        let (init, _) = net(a.encapsulate(&tag(0), &mut buf_a));
        for n in 1..MAX_QUEUE_DEPTH + 3 {
            assert!(
                matches!(a.encapsulate(&tag(n), &mut buf_a), TunnResult::Done),
                "packet {n}: queued"
            );
        }
        assert_eq!(a.queued(), MAX_QUEUE_DEPTH);
        assert_eq!(a.queue_drops(), 3);

        // What comes out, in order, is packets 3 ..= 258: the newest 256.
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        let mut wires = vec![net(a.decapsulate(b_addr(), &resp, &mut buf_a)).0];
        loop {
            match a.drain_queue(&mut buf_a) {
                TunnResult::WriteToNetwork(w, _) => wires.push(w.to_vec()),
                TunnResult::Done => break,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(wires.len(), MAX_QUEUE_DEPTH);
        for (n, wire) in (3..).zip(&wires) {
            match b.decapsulate(a_addr(), wire, &mut buf_b) {
                TunnResult::WriteToTunnel(d) => assert_eq!(d, &tag(n)[..], "packet {n}"),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(a.queue_drops(), 3);
    }

    /// What `encapsulate` returns is about the packet it was given:
    /// success never for a packet that was dropped, an error never for
    /// one that was taken.
    #[test]
    fn the_result_of_encapsulate_is_about_the_packet_it_was_given() {
        // (a) A buffer that could not hold a handshake initiation: the
        // call does nothing at all. (It used to queue the packet and then
        // report the error of the initiation it could not write.)
        let (mut a, mut b) = pair();
        let mut small = [0u8; MIN_BUFFER - 1];
        assert!(matches!(
            a.encapsulate(&ip_packet(60, 1), &mut small),
            TunnResult::Err(TunnError::Core(Error::BufferTooSmall))
        ));
        assert_eq!(a.queued(), 0, "an error means the packet was not taken");
        assert_eq!(a.stats().handshakes_initiated, 0);
        // With exactly the minimum it works: queued, initiation out.
        let mut exact = [0u8; MIN_BUFFER];
        let (init, _) = net(a.encapsulate(&ip_packet(60, 1), &mut exact));
        assert_eq!(init.len(), 148);
        assert_eq!(a.queued(), 1);

        // (b) A full queue and a usable session: the oldest packet goes
        // out, the new one takes the place that frees — nothing is lost,
        // and "send this" is the truth. (The new packet used to be
        // dropped at the full queue while the call returned a datagram.)
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        for n in 2..=MAX_QUEUE_DEPTH {
            assert!(matches!(
                a.encapsulate(&ip_packet(60, (n % 251) as u8), &mut buf_a),
                TunnResult::Done
            ));
        }
        assert_eq!(a.queued(), MAX_QUEUE_DEPTH);
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        // (In place: completes the handshake without draining anything.)
        let mut resp_copy = resp.clone();
        let mut out = [0u8; 148];
        assert!(matches!(
            a.decapsulate_in_place(b_addr(), &mut resp_copy, &mut out),
            TunnResult::Done
        ));
        assert!(a.is_established());
        assert_eq!(a.queued(), MAX_QUEUE_DEPTH);
        let newest = ip_packet(77, 250);
        let (wire, _) = net(a.encapsulate(&newest, &mut buf_a));
        assert_eq!(a.queued(), MAX_QUEUE_DEPTH, "one out, one in");
        assert_eq!(a.queue_drops(), 0);
        match b.decapsulate(a_addr(), &wire, &mut buf_b) {
            TunnResult::WriteToTunnel(d) => assert_eq!(d[59], 1, "the oldest went out"),
            other => panic!("{other:?}"),
        }
        let mut last = None;
        while let TunnResult::WriteToNetwork(w, _) = a.drain_queue(&mut buf_a) {
            let w = w.to_vec();
            match b.decapsulate(a_addr(), &w, &mut buf_b) {
                TunnResult::WriteToTunnel(d) => last = Some(d.to_vec()),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            last.as_deref(),
            Some(&newest[..]),
            "the new packet was kept"
        );

        // (c) With a session, a packet that does not fit the buffer is an
        // error and is not queued either.
        let mut tight = [0u8; 200];
        assert!(matches!(
            a.encapsulate(&ip_packet(190, 3), &mut tight),
            TunnResult::Err(TunnError::Core(Error::BufferTooSmall))
        ));
        assert_eq!(a.queued(), 0);
    }

    /// Every call that may write a datagram wants a buffer that can hold
    /// the largest one the tunnel sends of its own accord, and says so at
    /// once — not only on the day a handshake happens to be due.
    #[test]
    fn a_buffer_below_the_minimum_is_refused_at_once() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        let mut small = [0u8; MIN_BUFFER - 1];
        let mut exact = [0u8; MIN_BUFFER];
        // Nothing is due — and still the small buffer is an error, the
        // same one on every call: an `Err(Core)` is where to stop asking.
        for _ in 0..3 {
            assert!(matches!(
                a.update_timers(&mut small),
                TunnResult::Err(TunnError::Core(Error::BufferTooSmall))
            ));
            assert!(matches!(
                a.drain_queue(&mut small),
                TunnResult::Err(TunnError::Core(Error::BufferTooSmall))
            ));
        }
        assert!(matches!(a.update_timers(&mut exact), TunnResult::Done));
        assert!(matches!(a.drain_queue(&mut exact), TunnResult::Done));
        // A datagram is not consumed into a buffer below the minimum.
        let (wire, _) = net(a.encapsulate(&ip_packet(60, 4), &mut vec![0u8; 2048]));
        assert!(matches!(
            b.decapsulate(a_addr(), &wire, &mut small),
            TunnResult::Err(TunnError::Core(Error::BufferTooSmall))
        ));
        assert!(matches!(
            b.decapsulate(a_addr(), &wire, &mut exact),
            TunnResult::WriteToTunnel(d) if d[59] == 4
        ));
    }

    /// Under load, a handshake message from anyone who knows our public
    /// key gets a cookie reply — addressed to them — and changes nothing
    /// about where the tunnel sends its peer's traffic.
    #[test]
    fn cookie_reply_goes_to_the_sender_and_never_moves_the_endpoint() {
        let (mut a, mut b) = pair_with_limit(2);
        establish(&mut a, &mut b);
        let outsider = addr("203.0.113.66:4444");
        let b_pub = b.device().public_key();
        let mut buf_b = vec![0u8; 2048];
        let mut cookies = 0;
        for _ in 0..30 {
            // A throwaway identity that knows nothing but B's public key.
            let (key, _) = keypair();
            let mut stranger = Tunn::new(key, b_pub, None, None, Some(b_addr()), None).unwrap();
            let mut buf = vec![0u8; 256];
            let (init, _) = net(stranger.format_handshake_initiation(&mut buf));
            match b.decapsulate(outsider, &init, &mut buf_b) {
                TunnResult::WriteToNetwork(w, to) => {
                    assert_eq!(w[0], 3, "a cookie reply");
                    assert_eq!(to, outsider, "addressed to whoever sent the message");
                    cookies += 1;
                }
                TunnResult::Err(TunnError::Dropped(DropReason::UnknownPeer)) => {}
                other => panic!("{other:?}"),
            }
            assert_eq!(
                b.endpoint(),
                Some(a_addr()),
                "the peer's endpoint must not move"
            );
        }
        assert!(
            cookies >= 25,
            "the limiter tripped: {cookies} cookie replies"
        );
        // B's traffic for A still goes to A.
        let (_, to) = net(b.encapsulate(&ip_packet(60, 9), &mut buf_b));
        assert_eq!(to, a_addr());
    }

    /// A peer that only sends keepalives still roams.
    #[test]
    fn keepalive_from_a_new_address_moves_the_endpoint() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let (ka, _) = net(a.encapsulate(&[], &mut buf_a));
        assert_eq!(ka.len(), 32);
        let roamed = addr("198.51.100.7:40000");
        assert!(matches!(
            b.decapsulate(roamed, &ka, &mut buf_b),
            TunnResult::Done
        ));
        assert_eq!(b.endpoint(), Some(roamed));
        let (_, to) = net(b.encapsulate(&ip_packet(60, 1), &mut buf_b));
        assert_eq!(to, roamed);
    }

    #[test]
    fn without_an_endpoint_packets_wait_for_the_peer() {
        let (mut a, mut b) = pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        // B does not know where A is: nothing can be sent, the packet
        // waits, and no timer spins — the only thing due is the packet's
        // own deadline.
        let t0 = b.now();
        assert!(matches!(
            b.encapsulate_at(t0, &ip_packet(60, 7), &mut buf_b),
            TunnResult::Done
        ));
        assert_eq!(b.queued(), 1);
        assert_eq!(b.next_wake_at(t0), Some(t0.add_nanos(MAX_QUEUE_AGE_NS)));
        // A calls; once the session is confirmed the packet goes out.
        let (init, _) = net(a.format_handshake_initiation(&mut buf_a));
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        let (confirm, _) = net(a.decapsulate(b_addr(), &resp, &mut buf_a));
        let (wire, to) = net(b.decapsulate(a_addr(), &confirm, &mut buf_b));
        assert_eq!(to, a_addr());
        assert!(matches!(
            a.decapsulate(b_addr(), &wire, &mut buf_a),
            TunnResult::WriteToTunnel(d) if d[59] == 7
        ));
    }

    /// Packets that have waited ninety seconds for a session are dropped,
    /// not sent — whether or not a handshake attempt was ever running for
    /// them. (They used to wait as long as it took: a tunnel that did not
    /// know where its peer was put hour-old packets on the wire when the
    /// peer turned up.)
    #[test]
    fn queued_packets_that_have_waited_too_long_are_dropped_not_sent() {
        let (mut a, mut b) = pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let t0 = b.now();
        let at = |secs: u64| t0.add_nanos(secs * 1_000_000_000);
        // B does not know where A is. Two packets now, one a minute on.
        for tag in [1, 2] {
            assert!(matches!(
                b.encapsulate_at(t0, &ip_packet(60, tag), &mut buf_b),
                TunnResult::Done
            ));
        }
        assert!(matches!(
            b.encapsulate_at(at(60), &ip_packet(60, 3), &mut buf_b),
            TunnResult::Done
        ));
        // The one thing due is the oldest packet's deadline.
        assert_eq!(b.next_wake_at(at(60)), Some(at(90)));
        assert!(matches!(
            b.update_timers_at(at(89), &mut buf_b),
            TunnResult::Done
        ));
        assert_eq!((b.queued(), b.queue_drops()), (3, 0));
        // Ninety seconds: the first two are gone, and counted. The third
        // has a minute left.
        assert!(matches!(
            b.update_timers_at(at(90), &mut buf_b),
            TunnResult::Done
        ));
        assert_eq!((b.queued(), b.queue_drops()), (1, 2));
        assert_eq!(b.next_wake_at(at(90)), Some(at(150)));

        // A calls at 149 s: the third packet goes out, and only that one.
        let (init, _) = net(a.format_handshake_initiation(&mut buf_a));
        let (resp, _) = net(b.decapsulate_at(at(149), a_addr(), &init, &mut buf_b));
        let (confirm, _) = net(a.decapsulate(b_addr(), &resp, &mut buf_a));
        let (wire, _) = net(b.decapsulate_at(at(149), a_addr(), &confirm, &mut buf_b));
        assert!(matches!(
            a.decapsulate(b_addr(), &wire, &mut buf_a),
            TunnResult::WriteToTunnel(d) if d[59] == 3
        ));
        assert!(matches!(
            b.drain_queue_at(at(149), &mut buf_b),
            TunnResult::Done
        ));
        assert_eq!((b.queued(), b.queue_drops()), (0, 2));
    }

    /// The same without anybody calling the timers: a packet that is too
    /// old when its turn comes is dropped then.
    #[test]
    fn a_packet_too_old_when_its_turn_comes_is_not_sent() {
        let (mut a, mut b) = pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let t0 = b.now();
        let hour = t0.add_nanos(3600 * 1_000_000_000);
        for tag in [1, 2, 3] {
            assert!(matches!(
                b.encapsulate_at(t0, &ip_packet(60, tag), &mut buf_b),
                TunnResult::Done
            ));
        }
        // An hour later A calls. Nothing B had waiting goes on the wire:
        // what B sends to confirm the session is an empty keepalive.
        let (init, _) = net(a.format_handshake_initiation(&mut buf_a));
        let (resp, _) = net(b.decapsulate_at(hour, a_addr(), &init, &mut buf_b));
        let (confirm, _) = net(a.decapsulate(b_addr(), &resp, &mut buf_a));
        let mut sent = Vec::new();
        let mut next = b.decapsulate_at(hour, a_addr(), &confirm, &mut buf_b);
        while let TunnResult::WriteToNetwork(w, _) = next {
            sent.push(w.to_vec());
            next = b.drain_queue_at(hour, &mut buf_b);
        }
        for wire in &sent {
            assert!(
                matches!(a.decapsulate(b_addr(), wire, &mut buf_a), TunnResult::Done),
                "a packet that had waited an hour was sent"
            );
        }
        assert_eq!((b.queued(), b.queue_drops()), (0, 3));
    }

    /// The handshake attempt's own deadline starts over with every packet
    /// that is queued, so a trickle of packets keeps the attempt alive for
    /// as long as it lasts. It does not keep the old packets: each has
    /// its own ninety seconds.
    #[test]
    fn a_trickle_of_packets_does_not_keep_the_old_ones_waiting() {
        // A knows where B is; B never answers.
        let (mut a, _b) = pair();
        let mut buf = vec![0u8; 2048];
        let t0 = a.now();
        for i in 0..10u64 {
            let now = t0.add_nanos(30 * i * 1_000_000_000);
            let _ = a.encapsulate_at(now, &ip_packet(60, i as u8), &mut buf);
            for _ in 0..100 {
                match a.update_timers_at(now, &mut buf) {
                    TunnResult::Done => break,
                    // Handshake initiations, over and over.
                    TunnResult::WriteToNetwork(w, _) => assert_eq!(w[0], 1),
                    other => panic!("{other:?}"),
                }
            }
            // What is waiting is what was queued in the last ninety
            // seconds: this packet and the two before it.
            assert_eq!(a.queued() as u64, (i + 1).min(3), "after packet {i}");
        }
        assert_eq!(a.queue_drops(), 7);
    }

    /// A datagram longer than the buffer it is to be worked on in is its
    /// sender's doing: `TooLong`, not the local fault it used to be
    /// reported as.
    #[test]
    fn a_datagram_longer_than_the_buffer_is_too_long_not_a_local_fault() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        let mut small = vec![0u8; MIN_BUFFER];
        let long = vec![4u8; MIN_BUFFER + 1];
        assert!(matches!(
            b.decapsulate(a_addr(), &long, &mut small),
            TunnResult::Err(TunnError::TooLong)
        ));
        // One that just fits is looked at, and dropped for what it is.
        assert!(matches!(
            b.decapsulate(a_addr(), &long[..MIN_BUFFER], &mut small),
            TunnResult::Err(TunnError::Dropped(DropReason::Malformed))
        ));
        // A buffer below the minimum is the caller's mistake, as before.
        let mut tiny = vec![0u8; MIN_BUFFER - 1];
        assert!(matches!(
            b.decapsulate(a_addr(), &long[..10], &mut tiny),
            TunnResult::Err(TunnError::Core(Error::BufferTooSmall))
        ));
        // None of it did anything to the tunnel.
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let (wire, _) = net(a.encapsulate(&ip_packet(60, 5), &mut buf_a));
        assert!(matches!(
            b.decapsulate(a_addr(), &wire, &mut buf_b),
            TunnResult::WriteToTunnel(d) if d[59] == 5
        ));
    }

    /// One reading of the clock serves a whole batch of calls, and the
    /// calls that take none read it themselves.
    #[test]
    fn a_reading_of_the_clock_serves_a_batch() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let (now_a, now_b) = (a.now(), b.now());
        assert!(a.is_established_at(now_a));
        for tag in 0..32u8 {
            let (wire, _) = net(a.encapsulate_at(now_a, &ip_packet(60, tag), &mut buf_a));
            assert!(matches!(
                b.decapsulate_at(now_b, a_addr(), &wire, &mut buf_b),
                TunnResult::WriteToTunnel(d) if d[59] == tag
            ));
            let (wire, _) = net(a.encapsulate_at(now_a, &ip_packet(60, tag), &mut buf_a));
            let mut wire = wire;
            let mut out = [0u8; 148];
            assert!(matches!(
                b.decapsulate_in_place_at(now_b, a_addr(), &mut wire, &mut out),
                TunnResult::WriteToTunnel(d) if d[59] == tag
            ));
        }
        // The clock is the tunnel's own: it starts when the tunnel is
        // made and does not go backwards.
        let later = a.now();
        assert!(later >= now_a);
        assert!(later.nanos() < 3600 * 1_000_000_000, "{later:?}");
        // `next_wake` is `next_wake_at`, as an `Instant`.
        let due = a.next_wake_at(later).unwrap();
        let wake = a.next_wake().unwrap();
        let expected = Instant::now() + Duration::from_nanos(due.since(later));
        let off = if wake > expected {
            wake - expected
        } else {
            expected - wake
        };
        assert!(off < Duration::from_secs(1), "{off:?}");
    }

    /// The `_at` calls work at the time they are given, not at the time
    /// it is: three minutes on, a session is too old to send or receive
    /// on, whatever the tunnel's own clock says.
    #[test]
    fn the_at_calls_take_the_time_they_are_given() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let (now_a, now_b) = (a.now(), b.now());
        let later = |t: Ticks| Ticks::from_nanos(t.nanos() + 200 * 1_000_000_000);

        // A packet that arrives now is taken; one that arrives, as B is
        // told, 200 seconds from now is not: the session it was made for
        // is past its time.
        let (wire, _) = net(a.encapsulate_at(now_a, &ip_packet(60, 1), &mut buf_a));
        assert_eq!(wire[0], 4, "transport data");
        assert!(matches!(
            b.decapsulate_at(now_b, a_addr(), &wire, &mut buf_b),
            TunnResult::WriteToTunnel(d) if d[59] == 1
        ));
        let (wire, _) = net(a.encapsulate_at(now_a, &ip_packet(60, 2), &mut buf_a));
        assert!(
            !matches!(
                b.decapsulate_at(later(now_b), a_addr(), &wire, &mut buf_b),
                TunnResult::WriteToTunnel(_)
            ),
            "a packet was taken on a session three minutes old"
        );

        // And a packet to send in 200 seconds does not go out on the old
        // session: it waits for a new one, and what goes out is the
        // handshake for it.
        assert!(a.is_established_at(now_a));
        assert!(!a.is_established_at(later(now_a)));
        let (wire, to) = net(a.encapsulate_at(later(now_a), &ip_packet(60, 3), &mut buf_a));
        assert_eq!(to, b_addr());
        assert_eq!(
            (wire[0], wire.len()),
            (1, 148),
            "a handshake initiation, not data"
        );
        assert_eq!(a.queued(), 1);
    }

    /// The keys by reference, by value, with a pool or without: the same
    /// tunnel comes out — the same pre-shared key in particular.
    #[test]
    fn every_constructor_makes_the_same_tunnel() {
        let (a_key, a_pub) = keypair();
        let (b_key, b_pub) = keypair();
        let psk = [0x6b; 32];
        let pool = SlabPool::for_wireguard();

        let key = Box::new(a_key);
        let shared = Box::new(PresharedKey::from_bytes(psk));
        let by_reference = |psk: Option<&PresharedKey>, pool| {
            Tunn::with_keys(&key, b_pub, psk, None, Some(b_addr()), None, pool).unwrap()
        };
        let mut a = by_reference(Some(&shared), Some(pool.clone()));
        assert!(Arc::ptr_eq(a.pool(), &pool), "the pool it was given");
        assert!(
            !Arc::ptr_eq(by_reference(None, None).pool(), &pool),
            "a pool of its own"
        );

        // By value, with the same pre-shared key: they agree.
        let mut b = Tunn::new(b_key.clone(), a_pub, Some(psk), None, None, None).unwrap();
        establish(&mut a, &mut b);

        // With another pre-shared key, or none, they do not: the key is
        // the one each constructor was given.
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        for other in [Some([0x6c; 32]), None] {
            let mut a = by_reference(Some(&shared), None);
            let mut b =
                Tunn::with_pool(b_key.clone(), a_pub, other, None, None, None, pool.clone())
                    .unwrap();
            assert!(Arc::ptr_eq(b.pool(), &pool));
            let (init, _) = net(a.format_handshake_initiation(&mut buf_a));
            let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
            assert!(
                !matches!(
                    a.decapsulate(b_addr(), &resp, &mut buf_a),
                    TunnResult::WriteToNetwork(..)
                ),
                "a response made with another pre-shared key was accepted"
            );
            assert!(!a.is_established());
        }
        // And without one on either side they agree again.
        let mut a = by_reference(None, None);
        let mut b = Tunn::with_pool(b_key, a_pub, None, None, None, None, pool).unwrap();
        establish(&mut a, &mut b);
    }

    /// A `Tunn` is two pointers and some bookkeeping: its keys are on the
    /// heap, and moving it — into a task, out of a function — copies none
    /// of them.
    #[test]
    fn a_tunn_can_be_moved_without_moving_its_keys() {
        assert!(std::mem::size_of::<Tunn>() <= 160);
        assert!(std::mem::size_of::<Tunnel<Backend>>() >= 4096);
        let (a, mut b) = pair();
        let core_before: *const Tunnel<Backend> = a.core();
        let device_before: *const Device<Backend> = a.device();
        let mut moved = Box::new(a);
        assert!(std::ptr::eq(core_before, moved.core()));
        assert!(std::ptr::eq(device_before, moved.device()));
        establish(&mut moved, &mut b);
    }

    #[test]
    fn hostile_input_is_a_drop_not_a_fault() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        let mut buf = vec![0u8; 2048];
        for junk in [
            &[][..],
            &[1u8][..],
            &[0u8; 4][..],
            &[0xffu8; 200][..],
            &[4u8; 31][..],
        ] {
            match b.decapsulate(a_addr(), junk, &mut buf) {
                TunnResult::Done => assert!(junk.is_empty(), "only the drain call is Done"),
                TunnResult::Err(TunnError::Dropped(_)) => {}
                other => panic!("{other:?}"),
            }
        }
        // A destination buffer smaller than the datagram is a local fault.
        let mut tiny = [0u8; 8];
        assert!(matches!(
            b.decapsulate(a_addr(), &[4u8; 64], &mut tiny),
            TunnResult::Err(TunnError::Core(Error::BufferTooSmall))
        ));
    }

    // ---- padding and the tunnel MTU -----------------------------------------

    /// A full-size packet must not grow past the tunnel MTU when it is
    /// padded: on the usual 1420-byte tunnel that would be a 1456-byte
    /// datagram, 1504 bytes on the wire over IPv6 — too big for a
    /// 1500-byte path.
    #[test]
    fn padding_never_grows_a_packet_past_the_tunnel_mtu() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        assert_eq!(a.mtu(), Some(DEFAULT_MTU));
        let mut buf = vec![0u8; 2048];
        let datagram_len = |a: &mut Tunn, buf: &mut [u8], len: usize| {
            let (wire, _) = net(a.encapsulate(&ip_packet(len, 1), buf));
            wire.len()
        };
        // Up to the MTU: the next multiple of 16, but never more than the
        // MTU itself, plus the 32 bytes of header and tag.
        assert_eq!(datagram_len(&mut a, &mut buf, 60), 64 + 32);
        assert_eq!(datagram_len(&mut a, &mut buf, 1408), 1408 + 32);
        assert_eq!(datagram_len(&mut a, &mut buf, 1409), 1420 + 32);
        assert_eq!(datagram_len(&mut a, &mut buf, 1420), 1420 + 32);
        // What arrives is still the packet, exactly.
        let pkt = ip_packet(1420, 0x7e);
        let (wire, _) = net(a.encapsulate(&pkt, &mut buf));
        let mut buf_b = vec![0u8; 2048];
        assert!(matches!(
            b.decapsulate(a_addr(), &wire, &mut buf_b),
            TunnResult::WriteToTunnel(d) if d == &pkt[..]
        ));

        // Another tunnel MTU.
        a.set_mtu(Some(1280));
        assert_eq!(a.mtu(), Some(1280));
        assert_eq!(datagram_len(&mut a, &mut buf, 1273), 1280 + 32);
        // No cap at all (only right for an MTU that is a multiple of 16).
        a.set_mtu(None);
        assert_eq!(a.mtu(), None);
        assert_eq!(datagram_len(&mut a, &mut buf, 1420), 1424 + 32);
    }

    // ---- the load signal and the per-source allowance -------------------------

    /// Give `init` (a handshake initiation with a valid `mac1`) the `mac2`
    /// for `src`, the way a sender that really is at `src` gets one: by
    /// opening the cookie reply the loaded responder sends there.
    fn add_cookie(init: &mut [u8], responder: &mut Tunn, src: SocketAddr) {
        use crate::core::consts::LABEL_COOKIE;
        use crate::core::crypto::{aead, blake2s};
        let mut buf = vec![0u8; 256];
        let reply = match responder.decapsulate(src, init, &mut buf) {
            TunnResult::WriteToNetwork(w, to) => {
                assert_eq!((w[0], to), (3, src), "a cookie reply, to the sender");
                w.to_vec()
            }
            other => panic!("expected a cookie reply, got {other:?}"),
        };
        let key = blake2s::hash(&[LABEL_COOKIE, responder.device().public_key().as_bytes()]);
        let nonce: [u8; 24] = reply[8..32].try_into().unwrap();
        let mut cookie = [0u8; 16];
        aead::xopen(&key, &nonce, &init[116..132], &reply[32..64], &mut cookie).unwrap();
        let mac2 = blake2s::mac(&cookie, &[&init[..132]]);
        init[132..148].copy_from_slice(&mac2);
    }

    /// A pair whose responder (B) is always under load; A is not.
    fn loaded_pair() -> (Tunn, Tunn) {
        let (a_key, a_pub) = keypair();
        let (b_key, b_pub) = keypair();
        let always = Arc::new(RateLimiter::new(0));
        (
            Tunn::new(a_key, b_pub, None, None, Some(b_addr()), None).unwrap(),
            Tunn::new(b_key, a_pub, None, None, None, Some(always)).unwrap(),
        )
    }

    /// One cookie must not buy unlimited X25519: a source that has proven
    /// its address gets a burst, and then the Linux rate.
    #[test]
    fn a_cookie_holder_gets_a_burst_and_is_then_limited() {
        let (mut a, mut b) = loaded_pair();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let (mut init, _) = net(a.format_handshake_initiation(&mut buf_a));
        add_cookie(&mut init, &mut b, a_addr());

        // The first copy is A's handshake: answered.
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        assert_eq!(resp[0], 2);
        // A hundred more copies of the same datagram, as fast as they
        // come: a few reach the tunnel (and are dropped there as
        // replays), the rest are refused before any Diffie-Hellman.
        let (mut reached_tunnel, mut limited) = (0, 0);
        for _ in 0..100 {
            match b.decapsulate(a_addr(), &init, &mut buf_b) {
                TunnResult::Err(TunnError::Dropped(DropReason::ReplayedTimestamp)) => {
                    reached_tunnel += 1;
                }
                TunnResult::Err(TunnError::RateLimited) => limited += 1,
                other => panic!("{other:?}"),
            }
        }
        // Burst of 5, one of which went to the genuine copy; a token comes
        // back every 50 ms, so allow for a slow machine.
        assert!((4..=8).contains(&reached_tunnel), "{reached_tunnel}");
        assert_eq!(reached_tunnel + limited, 100);
        // The limit is per source: the same flood from elsewhere does not
        // carry a cookie for *that* address, and gets cookie replies.
        let elsewhere = addr("203.0.113.9:9");
        assert!(matches!(
            b.decapsulate(elsewhere, &init, &mut buf_b),
            TunnResult::WriteToNetwork(w, to) if w[0] == 3 && to == elsewhere
        ));
        // And the handshake that was answered is unaffected by all this.
        let (confirm, _) = net(a.decapsulate(b_addr(), &resp, &mut buf_a));
        assert!(matches!(
            b.decapsulate(a_addr(), &confirm, &mut buf_b),
            TunnResult::Done
        ));
        assert!(a.is_established() && b.is_established());
    }

    /// Forging a peer's source address must not cost that peer its
    /// allowance: datagrams without a cookie for the address they claim
    /// never reach the limit.
    #[test]
    fn a_forged_source_address_cannot_lock_a_peer_out() {
        let (mut a, mut b) = loaded_pair();
        let b_pub = b.device().public_key();
        let mut buf_b = vec![0u8; 2048];
        // Two hundred initiations from strangers, all claiming A's address.
        for _ in 0..200 {
            let (key, _) = keypair();
            let mut stranger = Tunn::new(key, b_pub, None, None, Some(b_addr()), None).unwrap();
            let mut buf = vec![0u8; 256];
            let (forged, _) = net(stranger.format_handshake_initiation(&mut buf));
            assert!(matches!(
                b.decapsulate(a_addr(), &forged, &mut buf_b),
                TunnResult::WriteToNetwork(w, _) if w[0] == 3
            ));
        }
        // A itself, with the cookie for its address, is answered at once.
        let mut buf_a = vec![0u8; 2048];
        let (mut init, _) = net(a.format_handshake_initiation(&mut buf_a));
        add_cookie(&mut init, &mut b, a_addr());
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        assert_eq!(resp[0], 2, "a handshake response");
    }

    /// The same while the interface is *not* under load, where no cookie
    /// is asked for and so no source address is proven: then there is
    /// nothing a per-source limit could safely be keyed on, and none is
    /// applied. (Each forgery does cost an X25519 here — which is what
    /// the load signal is for: past its threshold, cookies are required.)
    #[test]
    fn an_unproven_source_address_is_never_limited() {
        let (mut a, mut b) = pair_with_limit(1000);
        let b_pub = b.device().public_key();
        let mut buf_b = vec![0u8; 2048];
        // Many more than a burst, all claiming to come from A's address.
        for _ in 0..40 {
            let (key, _) = keypair();
            let mut stranger = Tunn::new(key, b_pub, None, None, Some(b_addr()), None).unwrap();
            let mut buf = vec![0u8; 256];
            let (forged, _) = net(stranger.format_handshake_initiation(&mut buf));
            assert!(matches!(
                b.decapsulate(a_addr(), &forged, &mut buf_b),
                TunnResult::Err(TunnError::Dropped(DropReason::UnknownPeer))
            ));
        }
        // A's own handshake is not held against any of that.
        establish(&mut a, &mut b);
    }

    /// The rate limiter is for handshake messages, and routing is for
    /// devices with several peers. Transport data — and anything else
    /// that is not a handshake message — goes past both, through either
    /// receive call: it neither reads the limiter's clock nor has its
    /// receiver index decoded into a peer id. (Together those cost a
    /// quarter of what receiving a small packet costs.)
    #[test]
    fn the_data_path_pays_for_neither_the_rate_limiter_nor_routing() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let pkt = ip_packet(100, 7);
        let mut wire = |a: &mut Tunn| net(a.encapsulate(&pkt, &mut buf_a)).0;

        let before = b.rate_limiter().clock_reads();
        let routed_before = b.device_stats().routed;
        for _ in 0..50 {
            let datagram = wire(&mut a);
            assert!(matches!(
                b.decapsulate(a_addr(), &datagram, &mut buf_b),
                TunnResult::WriteToTunnel(d) if d == &pkt[..]
            ));
            let mut datagram = wire(&mut a);
            let mut out = [0u8; 148];
            assert!(matches!(
                b.decapsulate_in_place(a_addr(), &mut datagram, &mut out),
                TunnResult::WriteToTunnel(d) if d == &pkt[..]
            ));
        }
        // Neither does what is not a WireGuard message at all, nor a
        // replayed or forged transport datagram.
        let mut replay = wire(&mut a);
        let _ = b.decapsulate(a_addr(), &replay, &mut buf_b);
        for junk in [&[0u8; 7][..], &[4u8; 31][..], &[0xffu8; 200][..]] {
            assert!(matches!(
                b.decapsulate(a_addr(), junk, &mut buf_b),
                TunnResult::Err(TunnError::Dropped(_))
            ));
        }
        assert!(matches!(
            b.decapsulate(a_addr(), &replay, &mut buf_b),
            TunnResult::Err(TunnError::Dropped(DropReason::Replay))
        ));
        let last = replay.len() - 1;
        replay[last] ^= 1;
        let mut out = [0u8; 148];
        assert!(matches!(
            b.decapsulate_in_place(a_addr(), &mut replay, &mut out),
            TunnResult::Err(TunnError::Dropped(_))
        ));
        assert_eq!(
            b.rate_limiter().clock_reads(),
            before,
            "the rate limiter was consulted for something that is not a handshake message"
        );
        assert_eq!(
            b.device_stats().routed,
            routed_before,
            "a datagram for the only peer there is was routed by its index"
        );

        // What has the shape of a handshake message does consult it — the
        // counter can count.
        let mut looks_like_an_initiation = [0u8; 148];
        looks_like_an_initiation[0] = 1;
        let _ = b.decapsulate(a_addr(), &looks_like_an_initiation, &mut buf_b);
        assert!(b.rate_limiter().clock_reads() > before);
    }

    /// `{:?}` of a result ends up in logs: it gives sizes, not bytes — a
    /// decrypted packet least of all.
    #[test]
    fn debug_output_of_a_result_gives_sizes_not_bytes() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let mut pkt = ip_packet(100, 0);
        for (i, byte) in pkt.iter_mut().enumerate().skip(20) {
            *byte = 200 + (i % 50) as u8;
        }
        let leaks = |shown: &str| {
            pkt[20..]
                .windows(2)
                .any(|w| shown.contains(&format!("{}, {}", w[0], w[1])))
        };
        assert!(leaks(&format!("{pkt:?}")), "the check can see a leak");

        let sent = a.encapsulate(&pkt, &mut buf_a);
        let shown = format!("{sent:?}");
        assert_eq!(shown, format!("WriteToNetwork(144 bytes, {})", b_addr()));
        let (wire, _) = net(sent);
        let got = b.decapsulate(a_addr(), &wire, &mut buf_b);
        assert!(matches!(got, TunnResult::WriteToTunnel(d) if d == &pkt[..]));
        for shown in [format!("{got:?}"), format!("{got:#?}")] {
            assert_eq!(shown, "WriteToTunnel(100 bytes)");
            assert!(!leaks(&shown));
        }
    }

    /// Datagrams that merely *look* like handshake messages — from someone
    /// who does not know our public key — do not count toward the load
    /// signal: they cannot make every genuine handshake pay for a cookie
    /// round trip.
    #[test]
    fn junk_does_not_put_the_interface_under_load() {
        let (mut a, mut b) = pair_with_limit(3);
        let mut buf_b = vec![0u8; 2048];
        let mut junk = [0u8; 148];
        junk[0] = 1;
        for _ in 0..100 {
            assert!(matches!(
                b.decapsulate(addr("203.0.113.5:5"), &junk, &mut buf_b),
                TunnResult::Err(TunnError::Dropped(DropReason::InvalidMac1))
            ));
        }
        assert!(!b.rate_limiter().is_under_load());
        // A genuine handshake is answered directly, without a cookie.
        establish(&mut a, &mut b);
    }

    /// Triage — the event loop's first look at a datagram — is for
    /// handshake messages. Transport data and cookie replies are passed
    /// straight on: no limiter clock, no counter, nothing decoded.
    #[cfg(feature = "async")]
    #[test]
    fn triage_passes_everything_but_handshake_messages_straight_on() {
        let (mut a, mut b) = pair();
        establish(&mut a, &mut b);
        let mut dst = [0u8; 2048];
        let (mut wire, _) = net(a.encapsulate(&ip_packet(64, 0x11), &mut dst));
        let reads = b.rate_limiter().clock_reads();
        let spent = b.rate_limiter().spent_ns();
        let stats = b.device_stats();
        let now = b.now();
        assert!(matches!(b.triage(now, a_addr(), &mut wire), Triage::Now));
        let mut cookie_reply = [0u8; 64];
        cookie_reply[0] = 3;
        assert!(matches!(
            b.triage(now, a_addr(), &mut cookie_reply),
            Triage::Now
        ));
        assert!(matches!(b.triage(now, a_addr(), &mut []), Triage::Now));
        assert!(matches!(
            b.triage(now, a_addr(), &mut [0xff; 148]),
            Triage::Now
        ));
        assert_eq!(b.rate_limiter().clock_reads(), reads);
        assert!(b.device_stats() == stats);
        // A handshake message with a wrong `mac1` is refused there and
        // then — counted by the device, and not by the load signal.
        let mut junk = [0u8; 148];
        junk[0] = 1;
        assert!(matches!(
            b.triage(now, a_addr(), &mut junk),
            Triage::Refused
        ));
        assert_eq!(b.device_stats().mac1_failures, stats.mac1_failures + 1);
        assert_eq!(b.rate_limiter().spent_ns(), spent);
        // One that knows the public key is put off, and the work it asks
        // for is done when its turn comes.
        let mut init = strangers_initiation(b.device().public_key());
        assert!(matches!(
            b.triage(now, a_addr(), &mut init),
            Triage::Handshake
        ));
        assert_eq!(b.device_stats().initiations, stats.initiations + 1);
        let mut out = [0u8; 128];
        assert!(matches!(
            b.deferred_handshake_at(now, a_addr(), &mut init, &mut out),
            TunnResult::Err(_)
        ));
        assert_eq!(
            b.device_stats().initiations,
            stats.initiations + 1,
            "counted once, on arrival"
        );
        assert!(b.rate_limiter().spent_ns() > spent, "and timed");
    }

    /// A handshake initiation from someone who knows `public` and nothing
    /// else.
    fn strangers_initiation(public: PublicKey) -> Vec<u8> {
        let (key, _) = keypair();
        let mut stranger = Tunn::new(key, public, None, None, Some(b_addr()), None).unwrap();
        let mut buf = vec![0u8; 256];
        net(stranger.format_handshake_initiation(&mut buf)).0
    }

    /// The load signal is the time handshake messages take, and it is
    /// taken where it should be: for every handshake message that passed
    /// the `mac1` check — answered, refused or sent a cookie — and for
    /// nothing else.
    #[test]
    fn handshake_messages_are_timed_and_nothing_else_is() {
        let (a_key, a_pub) = keypair();
        let (b_key, b_pub) = keypair();
        let limiter = Arc::new(RateLimiter::default());
        let mut a = Tunn::new(a_key, b_pub, None, None, Some(b_addr()), None).unwrap();
        let mut b = Tunn::new(b_key, a_pub, None, None, None, Some(limiter.clone())).unwrap();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        let from = addr("203.0.113.5:5");

        // Junk that looks like a handshake message: not timed.
        let mut junk = [0u8; 148];
        junk[0] = 1;
        for _ in 0..10 {
            let _ = b.decapsulate(from, &junk, &mut buf_b);
        }
        assert_eq!(limiter.spent_ns(), 0);
        // A stranger's initiation is refused — after two X25519, and
        // that is on the books.
        let refused = b.decapsulate(from, &strangers_initiation(b_pub), &mut buf_b);
        assert!(
            matches!(refused, TunnResult::Err(TunnError::Dropped(_))),
            "{refused:?}"
        );
        let after_refusal = limiter.spent_ns();
        assert!(after_refusal > 0);
        // The peer's handshake: both of B's steps are timed. (A's are
        // not B's business: A has a limiter of its own.)
        let (init, _) = net(a.format_handshake_initiation(&mut buf_a));
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        let after_initiation = limiter.spent_ns();
        assert!(after_initiation > after_refusal);
        assert_eq!(a.rate_limiter().spent_ns(), 0);
        let (confirm, _) = net(a.decapsulate(b_addr(), &resp, &mut buf_a));
        // (So is A's one step, by A's limiter: the response it was sent.)
        assert!(a.rate_limiter().spent_ns() > 0);
        // Data, and keepalives: not timed, and the limiter's clock is not
        // even read (see `the_data_path_pays_for_neither…`).
        assert!(matches!(
            b.decapsulate(a_addr(), &confirm, &mut buf_b),
            TunnResult::Done
        ));
        let (wire, _) = net(a.encapsulate(&ip_packet(60, 1), &mut buf_a));
        assert!(matches!(
            b.decapsulate(a_addr(), &wire, &mut buf_b),
            TunnResult::WriteToTunnel(_)
        ));
        assert_eq!(limiter.spent_ns(), after_initiation);
        // None of this was load by the default budget. (Ten milliseconds
        // of handshake work at once would be — on a machine that takes
        // that long over three messages this test is right to fail.)
        assert!(!limiter.is_under_load());

        // A message that is answered with a cookie is timed as well.
        let (_, mut loaded) = loaded_pair();
        let reply = loaded.decapsulate(
            from,
            &strangers_initiation(loaded.device().public_key()),
            &mut buf_b,
        );
        assert!(matches!(reply, TunnResult::WriteToNetwork(w, _) if w[0] == 3));
        assert!(loaded.rate_limiter().spent_ns() > 0);
    }

    /// What it used to take to put a tunnel under load: thirty handshake
    /// messages a second from anyone who knew its public key. After that
    /// every handshake cost its peer a cookie round trip — five seconds —
    /// and could be kept from completing by whoever was able to race
    /// forged cookie replies.
    #[test]
    fn thirty_handshake_messages_are_not_load() {
        let (a_key, a_pub) = keypair();
        let (b_key, b_pub) = keypair();
        let mut b = Tunn::new(b_key, a_pub, None, None, None, None).unwrap();
        let mut buf_b = vec![0u8; 2048];
        let strangers: Vec<Vec<u8>> = (0..30).map(|_| strangers_initiation(b_pub)).collect();
        for init in &strangers {
            let r = b.decapsulate(addr("203.0.113.9:9"), init, &mut buf_b);
            assert!(
                matches!(r, TunnResult::Err(TunnError::Dropped(_))),
                "not under load, so no cookie reply: {r:?}"
            );
        }
        assert!(!b.rate_limiter().is_under_load());
        assert_eq!(b.device_stats().cookies_sent, 0);
        // The peer's handshake is answered directly.
        let mut a = Tunn::new(a_key, b_pub, None, None, Some(b_addr()), None).unwrap();
        establish(&mut a, &mut b);

        // With a limiter that counts ten a second — BoringTun's, and
        // what this crate's default used to be — the same thirty put the
        // tunnel under load, and the peer's handshake meets a cookie.
        let (a_key, a_pub) = keypair();
        let (b_key, b_pub) = keypair();
        let counting = Arc::new(RateLimiter::new(RateLimiter::DEFAULT_LIMIT));
        let mut b = Tunn::new(b_key, a_pub, None, None, None, Some(counting)).unwrap();
        for _ in 0..30 {
            let _ = b.decapsulate(
                addr("203.0.113.9:9"),
                &strangers_initiation(b_pub),
                &mut buf_b,
            );
        }
        assert!(b.rate_limiter().is_under_load());
        let mut a = Tunn::new(a_key, b_pub, None, None, Some(b_addr()), None).unwrap();
        let mut buf_a = vec![0u8; 2048];
        let (init, _) = net(a.format_handshake_initiation(&mut buf_a));
        let (reply, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        assert_eq!((reply[0], reply.len()), (3, 64), "a cookie reply");
    }

    /// A budget that is used up puts the tunnel under load, for the rest
    /// of the window.
    #[test]
    fn a_spent_budget_is_load() {
        let (a_key, a_pub) = keypair();
        let (b_key, b_pub) = keypair();
        // A budget nothing fits in.
        let tight = Arc::new(RateLimiter::with_budget(Duration::from_nanos(1)));
        let mut a = Tunn::new(a_key, b_pub, None, None, Some(b_addr()), None).unwrap();
        let mut b = Tunn::new(b_key, a_pub, None, None, None, Some(tight.clone())).unwrap();
        let (mut buf_a, mut buf_b) = (vec![0u8; 2048], vec![0u8; 2048]);
        // The first initiation arrives at a tunnel that is not under
        // load, and is answered.
        let (init, _) = net(a.format_handshake_initiation(&mut buf_a));
        let (resp, _) = net(b.decapsulate(a_addr(), &init, &mut buf_b));
        assert_eq!(resp[0], 2);
        // What it took is more than the budget: under load, for as long
        // as this window lasts. (Asked at the limiter's time zero, so
        // that the answer does not depend on how quick this test is.)
        assert!(tight.spent_ns() > 1);
        assert!(tight.is_under_load_at(0));
    }
}
