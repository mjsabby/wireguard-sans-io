//! The sans-I/O WireGuard state machine for one peer.
//!
//! A [`Tunnel`] owns every piece of per-peer protocol state — handshake,
//! sessions, the peer's endpoint, received cookies, timers — and never
//! performs I/O, reads a clock, or allocates. It is created by, and works
//! together with, a [`crate::Device`], which owns what all peers share.
//!
//! * [`Tunnel::encapsulate`] / [`Tunnel::encapsulate_in_place`]: plaintext
//!   in → transport datagram out.
//! * [`Tunnel::handle`] / [`Tunnel::handle_initiation`]: a datagram the
//!   device routed to this peer → plaintext, a handshake response to send,
//!   or a state change.
//! * [`Tunnel::poll`]: every datagram the tunnel sends on its own
//!   initiative — handshake initiations and retransmissions, keepalives —
//!   plus expiry notifications.
//! * [`Tunnel::next_wake`]: the earliest instant `poll` has something to
//!   do.
//!
//! Every datagram a tunnel hands out is a [`Transmit`]: the bytes *and*
//! where to send them. The tunnel tracks the peer's endpoint itself and
//! moves it only when a message authenticates (whitepaper §6.1, roaming).

use core::marker::PhantomData;
use core::net::SocketAddr;
use core::num::NonZeroU16;

use crate::consts::{
    DEAD_PEER_TIMEOUT, HANDSHAKE_INITIATION_LEN, HANDSHAKE_RESPONSE_LEN, INITIATION_MIN_INTERVAL,
    KEEPALIVE_TIMEOUT, PADDING_MULTIPLE, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME,
    REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME, REKEY_AFTER_TIME_RECV, REKEY_ATTEMPT_TIME,
    REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER_MAX, SESSION_DISCARD_TIME, TRANSPORT_HEADER_LEN,
    TRANSPORT_OVERHEAD, UNCONFIRMED_RESPONSE_HOLD,
};
use crate::cookie::{self, LastCookie, PeerMacKeys};
use crate::crypto::{CryptoProvider, InTree, ct};
use crate::debug::{Addr, debug_struct};
use crate::device::{Initiation, PeerPacket, PeerPacketKind};
use crate::entropy::EntropySource;
use crate::error::{DropReason, Error};
use crate::index::{IndexAllocator, IndexCodec, PeerId};
use crate::keys::{PresharedKey, PublicKey, StaticSecret};
use crate::message;
use crate::noise::{
    self, ConsumedInitiation, HandshakeConstants, Identity, InFlightInitiation, Reject,
};
use crate::session::{Session, Sessions, Slot};
use crate::time::{Tai64N, Ticks, WallClock};
use crate::timers::{Timer, TimerTable};

/// One second, in nanoseconds.
const SECOND: u64 = 1_000_000_000;

/// Configuration of one peer; see [`crate::Device::tunnel`].
#[non_exhaustive]
pub struct PeerConfig {
    /// The peer's static public key.
    pub peer_public: PublicKey,
    /// Optional pre-shared key (whitepaper §5.2); all-zero default means
    /// "no PSK".
    pub psk: PresharedKey,
    /// Optional persistent keepalive interval in seconds.
    pub persistent_keepalive: Option<NonZeroU16>,
    /// Tunnel-interface MTU in bytes (the inner/plaintext MTU, *not* the
    /// outer path MTU). Caps transport padding so the encrypted datagram
    /// fits the path (whitepaper §5.4.6: pad "to the closest multiple of
    /// 16 that does not exceed the MTU"); see [`padded_len`]. `None`
    /// disables the cap — equivalent to a 16-aligned MTU. May be adjusted
    /// at runtime via [`Tunnel::set_mtu`] (PMTU discovery).
    pub mtu: Option<NonZeroU16>,
    /// Where the peer can be reached, if known in advance. A tunnel
    /// without an endpoint cannot start a handshake; it takes the source
    /// of the first initiation it answers, and from then on follows the
    /// peer (see [`Tunnel::endpoint`]).
    pub endpoint: Option<SocketAddr>,
}

impl core::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("peer_public", &self.peer_public)
            .field("psk", &self.psk)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("mtu", &self.mtu)
            .field("endpoint", &self.endpoint.map(Addr))
            .finish()
    }
}

impl PeerConfig {
    /// Configuration with no PSK, no persistent keepalive, no MTU cap and
    /// no endpoint. Set the public fields for anything else.
    #[must_use]
    pub fn new(peer_public: PublicKey) -> Self {
        Self {
            peer_public,
            psk: PresharedKey::default(),
            persistent_keepalive: None,
            mtu: None,
            endpoint: None,
        }
    }
}

/// A datagram to put on the wire, and where to send it.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Transmit<'a> {
    /// Destination address.
    pub dst: SocketAddr,
    /// The bytes of the UDP payload.
    pub datagram: &'a [u8],
}

impl core::fmt::Debug for Transmit<'_> {
    /// The destination and the size: the bytes are ciphertext, of no use
    /// in a log.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Transmit {{ dst: {:?}, datagram: {} bytes }}",
            Addr(self.dst),
            self.datagram.len()
        )
    }
}

/// Result of [`Tunnel::encapsulate`] / [`Tunnel::encapsulate_in_place`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Encapsulated<'a> {
    /// The payload was encrypted; send this datagram.
    Transport(Transmit<'a>),
    /// There is no usable session, so **the payload was not consumed**. A
    /// handshake has been requested: [`Tunnel::poll`] will produce the
    /// initiation. Keep the payload and try again after
    /// [`Handled::session_established`].
    NoSession,
    /// There is no usable session **and no endpoint is known** for this
    /// peer, so nothing can be sent until the peer contacts us or
    /// [`Tunnel::set_endpoint`] is called. The payload was not consumed.
    NoEndpoint,
}

/// What an inbound datagram turned out to be; see [`Handled`].
///
/// Its `Debug` output (and so that of [`Handled`]) gives the *size* of a
/// decrypted payload, never its bytes.
#[non_exhaustive]
pub enum Received<'a> {
    /// Authenticated transport payload. WireGuard pads plaintext to 16
    /// bytes, so this may carry up to 15 trailing padding bytes (zero from
    /// a conformant peer; the padding is authenticated but its content is
    /// not verified here). [`crate::ip_packet_len`] recovers the inner
    /// length.
    Data(&'a [u8]),
    /// An authenticated keepalive. Nothing to deliver.
    Keepalive,
    /// The peer sent a valid handshake initiation; send this response.
    /// The new session cannot be used for sending until the peer confirms
    /// it with a first transport message (see
    /// [`Handled::session_established`]).
    HandshakeResponse(Transmit<'a>),
    /// A handshake we initiated completed. If no data is sent right away,
    /// [`Tunnel::poll`] emits a confirming keepalive.
    HandshakeComplete,
    /// A cookie reply was accepted; handshake retransmissions will carry
    /// `mac2` until the cookie expires. Nothing is sent now (whitepaper
    /// §6.6). The sender of a cookie reply is **not** authenticated as the
    /// peer.
    CookieStored,
    /// Under load, the device answered a handshake message with a cookie
    /// reply; send it. The sender of that handshake message is **not**
    /// authenticated. (Only [`crate::Device::receive_for`] returns this;
    /// with [`crate::Device::receive`] the same situation is
    /// [`crate::Incoming::CookieRequired`].)
    CookieReply(Transmit<'a>),
    /// The datagram was rejected: drop it silently.
    Dropped(DropReason),
}

impl Received<'_> {
    /// Did this datagram authenticate as coming from the configured peer?
    ///
    /// True for data, keepalives, a valid initiation (the response to it),
    /// and a valid response. False for cookie messages and drops. The
    /// tunnel has already updated its endpoint where the message calls for
    /// it ([`Tunnel::endpoint`]); this is for embedder-side bookkeeping.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        matches!(
            self,
            Self::Data(_) | Self::Keepalive | Self::HandshakeResponse(_) | Self::HandshakeComplete
        )
    }
}

impl core::fmt::Debug for Received<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // What the peer's user sent: a log line has no business with
            // more than how much of it there was.
            Self::Data(payload) => write!(f, "Data({} bytes)", payload.len()),
            Self::Keepalive => f.write_str("Keepalive"),
            Self::HandshakeResponse(tx) => f.debug_tuple("HandshakeResponse").field(tx).finish(),
            Self::HandshakeComplete => f.write_str("HandshakeComplete"),
            Self::CookieStored => f.write_str("CookieStored"),
            Self::CookieReply(tx) => f.debug_tuple("CookieReply").field(tx).finish(),
            Self::Dropped(reason) => f.debug_tuple("Dropped").field(reason).finish(),
        }
    }
}

/// Everything that happened when one inbound datagram was processed.
#[derive(Debug)]
#[non_exhaustive]
pub struct Handled<'a> {
    /// What the datagram was, with anything to deliver or send.
    pub received: Received<'a>,
    /// A session became usable for **sending** in this call — as initiator
    /// (the response arrived) or as responder (the peer's first transport
    /// message confirmed the session). Packets held back by
    /// [`Encapsulated::NoSession`] can go out now.
    pub session_established: bool,
    /// The peer's endpoint ([`Tunnel::endpoint`]) changed in this call:
    /// the peer proved to be at a new address.
    pub endpoint_changed: bool,
}

impl Handled<'_> {
    pub(crate) fn dropped(reason: DropReason) -> Self {
        Self {
            received: Received::Dropped(reason),
            session_established: false,
            endpoint_changed: false,
        }
    }
}

/// Result of [`Tunnel::poll`].
#[derive(Debug)]
#[non_exhaustive]
pub enum PollOutput<'a> {
    /// Send this datagram.
    Transmit(Transmit<'a>, SendReason),
    /// The current handshake attempt exceeded `Rekey-Attempt-Time` and was
    /// abandoned (whitepaper §6.4). Drop any packets you were holding for
    /// this peer; a later send starts a new attempt. So does, in a tunnel
    /// with a persistent keepalive, the next keepalive — at most one
    /// interval after this.
    HandshakeExpired,
    /// The keys of every session that was in use were wiped:
    /// `3 × Reject-After-Time` passed without a new session (whitepaper
    /// §6.3). Nothing can be sent or received until a handshake completes.
    /// A handshake that is under way at that moment — an initiation of
    /// ours in flight, or one of the peer's that we have just answered —
    /// is not affected and completes normally.
    SessionsExpired,
    /// Nothing to do until [`Tunnel::next_wake`].
    Idle,
}

/// Why [`Tunnel::poll`] produced a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendReason {
    /// A fresh handshake initiation (first contact, rekey, dead-peer
    /// recovery, or a keepalive that needs a session).
    HandshakeInitiation,
    /// Retransmission of the in-flight initiation (whitepaper §6.4).
    HandshakeRetransmit,
    /// Passive keepalive (whitepaper §6.5) or handshake-confirming
    /// keepalive.
    Keepalive,
    /// Configured persistent keepalive.
    PersistentKeepalive,
}

/// Per-tunnel observability counters. All values are cumulative since
/// construction.
///
/// # ⚠️ Sensitivity
///
/// The failure counters (`auth_failures`, `replays_dropped`) are
/// **attacker-influenceable** and, if exposed unaggregated to an untrusted
/// observer (e.g. an unauthenticated metrics endpoint), act as oracles.
/// Treat them as you would a debug log: aggregate before publishing, or
/// restrict who can read them.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
#[repr(C)] // in this order in memory: what a data packet counts comes first
pub struct Stats {
    /// Transport messages sent (including keepalives).
    pub tx_transport: u64,
    /// Transport messages received and authenticated (incl. keepalives).
    pub rx_transport: u64,
    /// Plaintext payload bytes sent (before padding).
    pub tx_bytes: u64,
    /// Plaintext payload bytes received (after padding, before trimming).
    pub rx_bytes: u64,
    /// Keepalives sent.
    pub tx_keepalives: u64,
    /// Keepalives received.
    pub rx_keepalives: u64,
    /// Handshake initiations sent (including retransmissions).
    pub handshakes_initiated: u64,
    /// Handshake responses sent (initiations we accepted).
    pub handshakes_responded: u64,
    /// Sessions established (as initiator or responder-confirmed).
    pub handshakes_completed: u64,
    /// Datagrams routed to this tunnel that failed authentication.
    pub auth_failures: u64,
    /// Transport messages dropped by the anti-replay window.
    pub replays_dropped: u64,
    /// Cookie replies accepted.
    pub cookies_received: u64,
    /// Monotonic instant of the last completed handshake.
    pub last_handshake_at: Option<Ticks>,
}

debug_struct!(Stats {
    tx_transport,
    rx_transport,
    tx_bytes,
    rx_bytes,
    tx_keepalives,
    rx_keepalives,
    handshakes_initiated,
    handshakes_responded,
    handshakes_completed,
    auth_failures,
    replays_dropped,
    cookies_received,
    last_handshake_at,
});

impl Stats {
    /// Nothing counted yet.
    const ZERO: Self = Self {
        tx_transport: 0,
        rx_transport: 0,
        tx_bytes: 0,
        rx_bytes: 0,
        tx_keepalives: 0,
        rx_keepalives: 0,
        handshakes_initiated: 0,
        handshakes_responded: 0,
        handshakes_completed: 0,
        auth_failures: 0,
        replays_dropped: 0,
        cookies_received: 0,
        last_handshake_at: None,
    };
}

/// `DH(S_priv_local, S_pub_peer)`: never changes for the life of a
/// `Tunnel`, computed once at construction. Wiped on drop.
struct StaticStaticSecret([u8; 32]);

impl Drop for StaticStaticSecret {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.0);
    }
}

/// The initiation we have in flight, if any — and the place the next one
/// is built in.
///
/// As with session keys ([`Sessions`]), the handshake state exists in two
/// places, both inside the tunnel and both wiped there: `staged`, where an
/// initiation is built, and `state`, where it is copied to (by reference,
/// wiping `staged`) once the datagram that carries it is ready to go.
struct InFlight {
    active: bool,
    state: InFlightInitiation,
    staged: InFlightInitiation,
}

impl InFlight {
    const fn new() -> Self {
        Self {
            active: false,
            state: InFlightInitiation::blank(),
            staged: InFlightInitiation::blank(),
        }
    }

    /// The initiation in flight.
    fn get(&self) -> Option<&InFlightInitiation> {
        if self.active { Some(&self.state) } else { None }
    }

    fn is_some(&self) -> bool {
        self.active
    }

    /// The session index of the initiation in flight.
    fn index(&self) -> Option<u32> {
        self.get().map(|i| i.local_index)
    }

    /// Forget the initiation in flight, wiping it where it lies.
    fn clear(&mut self) {
        self.active = false;
        self.state.wipe();
    }

    /// Where the next initiation is built. Blank when handed out.
    fn staging(&mut self) -> &mut InFlightInitiation {
        self.staged.wipe();
        &mut self.staged
    }

    /// Wipe an initiation that was built and is not going out.
    fn discard_staged(&mut self) {
        self.staged.wipe();
    }

    /// The staged initiation is in flight now; it replaces the one that
    /// was.
    fn commit(&mut self) {
        self.state.take_from(&mut self.staged);
        self.active = true;
    }
}

/// What [`Tunnel::poll`] decided to do, before any byte is written.
#[derive(Debug, Clone, Copy)]
enum Action {
    Idle,
    HandshakeExpired,
    SessionsExpired,
    /// Build and send an initiation; on failure re-arm the timer that
    /// asked for it.
    Initiation(SendReason, Timer, Ticks),
    /// Build and send a keepalive; on failure re-arm the timer that asked
    /// for it.
    Keepalive(SendReason, Timer, Ticks),
}

/// The WireGuard state machine for one peer.
///
/// Created with [`crate::Device::tunnel`]. Inbound datagrams reach it
/// through the device ([`crate::Device::receive`] →
/// [`Tunnel::handle`] / [`Tunnel::handle_initiation`], or
/// [`crate::Device::receive_for`] when there is only one peer).
///
/// # Driving it
///
/// After **every** call that takes `now`, and whenever [`Tunnel::next_wake`]
/// falls due, call [`Tunnel::poll`] until it returns [`PollOutput::Idle`].
/// That is the only place handshake initiations, retransmissions and
/// keepalives come from.
///
/// # Buffers
///
/// All buffers are caller-provided, and every size requirement is fixed —
/// none depends on what a remote party sends:
///
/// | call | output buffer |
/// |---|---|
/// | [`encapsulate`](Self::encapsulate) | [`transport_datagram_len`]`(payload.len())` |
/// | [`handle_initiation`](Self::handle_initiation) | 92 bytes |
/// | [`handle`](Self::handle) | none: transport data is decrypted in place |
/// | [`poll`](Self::poll) | 148 bytes |
///
/// # Errors and state
///
/// A method that returns `Err` has sent nothing and lost nothing: what it
/// was about to do is still to be done, and is done by the next call that
/// succeeds. Apart from two things it has also left the protocol state
/// exactly as it was:
///
/// * A session index reserved for a handshake message that then could not
///   be built (entropy failure) is not used again.
/// * [`poll`](Self::poll) goes through the timers that are due, in order,
///   until one of them has something to send — and it is the sending that
///   can fail (a buffer too small, no entropy). The timers before it have
///   fired and stay fired: a persistent keepalive that came due without a
///   session has become a request for a handshake, an unused session has
///   expired. The one that failed is still due.
///
/// # Crypto provider
///
/// The type parameter selects the [`CryptoProvider`]. The default,
/// [`InTree`], is this crate's own safe-Rust implementation. The wire
/// format is the same for every provider.
///
/// # Example
///
/// ```
/// use core::net::SocketAddr;
/// use wireguard_sans_io::testing::DeterministicRng;
/// use wireguard_sans_io::{
///     Device, Encapsulated, PeerConfig, PeerId, PollOutput, Received, StaticSecret, Ticks,
///     Transmit, WallClock,
/// };
///
/// // ⚠ use a real entropy source outside of tests/examples.
/// let mut rng = DeterministicRng::new(42);
/// let a_key = StaticSecret::generate(&mut rng)?;
/// let b_key = StaticSecret::generate(&mut rng)?;
/// let (a_pub, b_pub) = (a_key.public_key(), b_key.public_key());
/// let a_addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
/// let b_addr: SocketAddr = "192.0.2.2:51820".parse().unwrap();
///
/// // Caller-owned clock: one monotonic reading per call, and the wall
/// // clock once, as an anchor.
/// let now = Ticks::ZERO;
/// let wall = WallClock::new(now, 1_700_000_000, 0);
///
/// // One device per local key, one tunnel per peer. A knows where B is.
/// let id = PeerId::new(0).unwrap();
/// let mut a_dev = Device::new(a_key, wall, &mut rng)?;
/// let mut b_dev = Device::new(b_key, wall, &mut rng)?;
/// let mut a_cfg = PeerConfig::new(b_pub);
/// a_cfg.endpoint = Some(b_addr);
/// let mut a = a_dev.tunnel(id, a_cfg, &mut rng)?;
/// let mut b = b_dev.tunnel(id, PeerConfig::new(a_pub), &mut rng)?;
///
/// let (mut buf_a, mut buf_b) = ([0u8; 2048], [0u8; 2048]);
///
/// // A has data but no session: nothing is consumed, a handshake is
/// // requested, and poll() produces the initiation.
/// assert!(matches!(
///     a.encapsulate(now, b"ping", &mut buf_a)?,
///     Encapsulated::NoSession
/// ));
/// let mut wire = match a.poll(now, &mut buf_a, &mut rng)? {
///     PollOutput::Transmit(Transmit { dst, datagram, .. }, _) => {
///         assert_eq!(dst, b_addr);
///         datagram.to_vec()
///     }
///     other => panic!("{other:?}"),
/// };
///
/// // "Network": B's device routes it to B's tunnel, which answers.
/// let handled = b_dev.receive_for(&mut b, now, a_addr, false, &mut wire, &mut buf_b, &mut rng)?;
/// let mut wire = match handled.received {
///     Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
///     other => panic!("{other:?}"),
/// };
///
/// // A completes the handshake and can now send the payload.
/// let mut scratch = [0u8; 128];
/// let handled = a_dev.receive_for(&mut a, now, b_addr, false, &mut wire, &mut scratch, &mut rng)?;
/// assert!(matches!(handled.received, Received::HandshakeComplete));
/// assert!(handled.session_established);
/// let mut wire = match a.encapsulate(now, b"ping", &mut buf_a)? {
///     Encapsulated::Transport(tx) => tx.datagram.to_vec(),
///     other => panic!("{other:?}"),
/// };
///
/// // B decrypts in place (and trims the padding with `ip_packet_len` in
/// // real use). That first packet also confirms the session for B.
/// let handled = b_dev.receive_for(&mut b, now, a_addr, false, &mut wire, &mut buf_b, &mut rng)?;
/// assert!(handled.session_established);
/// match handled.received {
///     Received::Data(plain) => assert_eq!(&plain[..4], b"ping"),
///     other => panic!("{other:?}"),
/// }
/// // B learned where A is from the authenticated handshake.
/// assert_eq!(b.endpoint(), Some(a_addr));
/// # Ok::<(), wireguard_sans_io::Error>(())
/// ```
// The fields are laid out by hand (`repr(C)`: declaration order is memory
// order), in the order of how often they are used. An endpoint with many
// peers has more tunnels than cache: a data packet then finds its tunnel
// cold, and what it costs is mostly the number of cache lines it has to
// fetch. So everything a data packet reads or writes comes first and
// together, and everything only a handshake needs comes after it:
//
//   line 0      time, endpoint, settings, the per-packet flags
//   lines 1-2   the timer table
//   lines 3-4   the counters (those of a data packet in line 3)
//   lines 5-6   which session cell has which role; the staging area
//   lines 7..   the three session cells, 18 lines each: two lines of
//               keys and counters, then the replay bitmap, of which a
//               packet touches one word
//   after that  everything only a handshake touches
//
// `the_data_path_fields_are_together` (in the tests below) holds the
// layout to this.
#[repr(C, align(64))]
pub struct Tunnel<P: CryptoProvider = InTree> {
    // ---- line 0 ----------------------------------------------------------
    /// Monotonicity clamp for hostile/buggy caller clocks.
    last_now: Ticks,
    /// The jitter the dead-peer timer is armed with (§6.1: up to a third
    /// of a second), so that two ends that lose each other at the same
    /// instant do not start their handshakes at the same instant. The
    /// timer is armed in `encapsulate`, which has no entropy source; the
    /// jitter is therefore drawn whenever the tunnel makes a handshake
    /// message — where it has one — and used until the next.
    dead_peer_jitter: u64,
    /// Where the peer was last authenticated from (or was configured).
    endpoint: Option<SocketAddr>,
    persistent_keepalive: Option<NonZeroU16>,
    mtu: Option<NonZeroU16>,
    /// A handshake should be initiated as soon as pacing and a known
    /// endpoint allow.
    handshake_wanted: bool,
    /// A keepalive is owed and goes out as soon as a session is usable.
    keepalive_staged: bool,
    /// §6.2 receive-path rekey fired for the current session already.
    sent_lastminute_handshake: bool,
    /// There is a `candidate` address (below, with what only handshakes
    /// use): every authenticated packet has to ask, so the answer is kept
    /// here.
    has_candidate: bool,
    /// Sessions created so far; gives each its `serial`.
    sessions_created: u64,

    // ---- lines 1-2 -------------------------------------------------------
    timers: TimerTable,

    // ---- lines 3-4 -------------------------------------------------------
    stats: Stats,
    /// Start of the current handshake attempt (Rekey-Attempt-Time window).
    attempt_started: Option<Ticks>,

    // ---- lines 5.. -------------------------------------------------------
    /// The previous, current and next session (whitepaper §6.3).
    sessions: Sessions,

    // ---- handshakes only ---------------------------------------------------
    inflight: InFlight,
    /// When we last sent a handshake initiation (§6.1 pacing).
    last_initiation_sent: Option<Ticks>,
    /// When we last sent a handshake response, and when we sent the first
    /// of the responses that nothing has confirmed since (the peer has
    /// not used the session, and no handshake of ours has completed). An
    /// initiation of ours waits Rekey-Timeout after a response, for the
    /// peer's handshake to finish — but not for ever: see
    /// [`Self::pacing_deadline`].
    last_response_sent: Option<Ticks>,
    first_unconfirmed_response: Option<Ticks>,
    /// When we last accepted an initiation (flood guard).
    last_initiation_rx: Option<Ticks>,
    /// Where an initiation came from that we answered but could not take
    /// as proof of where the peer is (see [`Tunnel::endpoint`]): the place
    /// to try with an initiation of our own.
    candidate: Option<SocketAddr>,
    /// The next initiation of ours goes to the candidate address, if
    /// there is one (they then alternate with the endpoint).
    try_candidate: bool,
    /// The peer has shown, in this tunnel's lifetime, that an initiation
    /// of its own was live: it used a session that such an initiation
    /// created. From then on the timestamp of the last initiation we
    /// accepted is a point in real time, and an initiation with a later
    /// one was made after it.
    peer_initiation_proven: bool,
    cookie: LastCookie,
    /// `mac1` of the initiation in flight (what a cookie reply to it is
    /// sealed against), until a cookie reply has been accepted for it.
    last_init_mac1: Option<[u8; 16]>,
    /// The same for the response behind the session in `next`.
    last_resp_mac1: Option<[u8; 16]>,
    greatest_timestamp: Option<Tai64N>,
    /// TAI64N of the last initiation we sent: outbound timestamps are
    /// ratcheted strictly past this, so they increase even if the wall
    /// clock anchor is moved back.
    last_sent_tai64n: Option<Tai64N>,
    local_static: StaticSecret,
    local_public: PublicKey,
    peer_public: PublicKey,
    psk: PresharedKey,
    constants: HandshakeConstants,
    mac_keys: PeerMacKeys,
    /// Precomputed `DH(local_static, peer_public)`.
    precomputed_ss: StaticStaticSecret,
    wall_clock: WallClock,
    indices: IndexAllocator,
    _provider: PhantomData<fn() -> P>,
}

impl<P: CryptoProvider> core::fmt::Debug for Tunnel<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Tunnel<{}>(id={}, peer={:?}, endpoint={:?}, session={}, handshaking={})",
            P::name(),
            self.indices.peer().get(),
            self.peer_public,
            self.endpoint.map(Addr),
            self.sessions.current().is_some(),
            self.attempt_running()
        )
    }
}

/// A timer jitter (whitepaper §6.1): uniform in 0 ..= 333 ms.
///
/// A jitter is no secret, and a timer would work without one. But an
/// entropy source that reports failure is not believed a little: the
/// failure ends the operation, as it does for every other draw
/// (`EMBEDDER_OBLIGATIONS.md` §1.3) — the handshake message this jitter
/// belongs to is not sent, and the call can be repeated.
fn draw_jitter(rng: &mut dyn EntropySource) -> Result<u64, Error> {
    let mut bytes = [0u8; 8];
    match rng.fill(&mut bytes) {
        Ok(()) => Ok(u64::from_le_bytes(bytes)
            .checked_rem(REKEY_TIMEOUT_JITTER_MAX.saturating_add(1))
            .unwrap_or(0)),
        Err(_) => Err(Error::EntropyFailure),
    }
}

/// Padded plaintext length for a payload (whitepaper §5.4.6): the next
/// multiple of 16, **clamped to `mtu`** so padding never pushes the
/// encrypted datagram past the path MTU.
///
/// This is the kernel's `calculate_skb_padding` for every input (and
/// wireguard-go's `calculatePaddingSize`), including the case it handles
/// "just in case the networking layer gives us a packet that's bigger
/// than the MTU": such a payload is padded as if only its last
/// `payload_len % mtu` bytes counted.
///
/// `mtu` is the tunnel-interface (inner) MTU. `None` disables the clamp,
/// which is correct iff the configured MTU is itself 16-aligned. Never
/// returns less than `payload_len` (padding never truncates), and never
/// more than `payload_len + 15`.
#[must_use]
pub const fn padded_len(payload_len: usize, mtu: Option<NonZeroU16>) -> usize {
    let (last_unit, limit) = match mtu {
        None => (payload_len, usize::MAX),
        Some(mtu) => {
            let mtu = mtu.get() as usize;
            if payload_len > mtu {
                // (`mtu` is not zero; the fallback is never taken.)
                match payload_len.checked_rem(mtu) {
                    Some(last_unit) => (last_unit, mtu),
                    None => (payload_len, mtu),
                }
            } else {
                (payload_len, mtu)
            }
        }
    };
    // min(mtu, ALIGN(last_unit, 16)) − last_unit, in `usize` without
    // overflow: the alignment can only overflow when there is no MTU, and
    // then nothing is added. (`last_unit` is at most `limit` and at most
    // its own alignment, so the subtraction cannot underflow.)
    let padding = match last_unit.checked_add(PADDING_MULTIPLE - 1) {
        Some(v) => {
            let aligned = v & !(PADDING_MULTIPLE - 1);
            let padded = if aligned < limit { aligned } else { limit };
            padded.saturating_sub(last_unit)
        }
        None => 0,
    };
    payload_len.saturating_add(padding)
}

/// Datagram size for a payload: 16-byte header + zero-padded payload +
/// 16-byte tag (whitepaper §5.4.6). Equivalent to
/// `padded_len(payload_len, None) + 32`; for an MTU-aware size use
/// [`padded_len`] directly.
#[must_use]
pub const fn transport_datagram_len(payload_len: usize) -> usize {
    padded_len(payload_len, None).saturating_add(TRANSPORT_OVERHEAD)
}

impl<P: CryptoProvider> Tunnel<P> {
    /// A tunnel with nothing in it — no keys, no peer, no state. It is
    /// never handed out: [`Self::build_in`] puts it where the tunnel is
    /// going to live and then fills it in there, so that the keys are
    /// written to that one place and to no other on the way.
    const BLANK: Self = Self {
        local_static: StaticSecret::BLANK,
        local_public: PublicKey::from_bytes([0u8; 32]),
        peer_public: PublicKey::from_bytes([0u8; 32]),
        psk: PresharedKey::BLANK,
        persistent_keepalive: None,
        mtu: None,
        constants: HandshakeConstants::BLANK,
        mac_keys: PeerMacKeys::BLANK,
        precomputed_ss: StaticStaticSecret([0u8; 32]),
        wall_clock: WallClock::new(Ticks::ZERO, 0, 0),
        indices: IndexAllocator::BLANK,
        endpoint: None,
        candidate: None,
        try_candidate: true,
        peer_initiation_proven: false,
        inflight: InFlight::new(),
        last_init_mac1: None,
        last_resp_mac1: None,
        cookie: LastCookie::none(),
        greatest_timestamp: None,
        last_sent_tai64n: None,
        last_initiation_rx: None,
        sessions: Sessions::new(),
        sessions_created: 0,
        timers: TimerTable::new(),
        handshake_wanted: false,
        keepalive_staged: false,
        has_candidate: false,
        attempt_started: None,
        last_initiation_sent: None,
        last_response_sent: None,
        first_unconfirmed_response: None,
        sent_lastminute_handshake: false,
        last_now: Ticks::ZERO,
        dead_peer_jitter: 0,
        stats: Stats::ZERO,
        _provider: PhantomData,
    };

    /// Assemble a tunnel in `slot` from a device's shared state; see
    /// [`crate::Device::tunnel_in`]. Whatever was in the slot is dropped
    /// (and so wiped) first; after an error the slot is empty.
    #[allow(clippy::too_many_arguments)] // internal plumbing; every argument is distinct state
    pub(crate) fn build_in<'s>(
        slot: &'s mut Option<Self>,
        local_static: &StaticSecret,
        local_public: PublicKey,
        constants: &HandshakeConstants,
        wall_clock: WallClock,
        codec: &IndexCodec,
        id: PeerId,
        config: &PeerConfig,
        rng: &mut dyn EntropySource,
    ) -> Result<&'s mut Self, Error> {
        *slot = None;
        let filled = slot.insert(Self::BLANK).fill(
            local_static,
            local_public,
            constants,
            wall_clock,
            codec,
            id,
            config,
            rng,
        );
        if let Err(error) = filled {
            // Dropping the half-made tunnel wipes what was put into it.
            *slot = None;
            return Err(error);
        }
        slot.as_mut().ok_or(Error::Internal)
    }

    /// Assemble a tunnel in the value that is returned; see
    /// [`crate::Device::tunnel`]. The tunnel is not put together in a
    /// local and then copied out: the blank tunnel is the return value,
    /// and it is filled in where the caller receives it. (That is what
    /// an optimising compiler makes of a local that is returned as it
    /// stands. One that does not optimise copies it — and then the copy
    /// is in this function's frame, which is why this function says, in
    /// `low`, where its frame ends: the caller overwrites it.)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build(
        local_static: &StaticSecret,
        local_public: PublicKey,
        constants: &HandshakeConstants,
        wall_clock: WallClock,
        codec: &IndexCodec,
        id: PeerId,
        config: &PeerConfig,
        rng: &mut dyn EntropySource,
        low: &mut usize,
    ) -> Result<Self, Error> {
        *low = (*low).min(ct::stack_mark());
        let mut made = Ok(Self::BLANK);
        let filled = match &mut made {
            Ok(tunnel) => tunnel.fill(
                local_static,
                local_public,
                constants,
                wall_clock,
                codec,
                id,
                config,
                rng,
            ),
            Err(_) => Ok(()),
        };
        if let Err(error) = filled {
            // Dropping the half-made tunnel wipes what was put into it.
            made = Err(error);
        }
        made
    }

    /// Make a blank tunnel the tunnel for `config`'s peer. Every secret
    /// goes straight to its field: the static key and the pre-shared key
    /// byte by byte from where the device and the caller keep them, the
    /// static-static Diffie-Hellman result from the provider.
    #[allow(clippy::too_many_arguments)]
    fn fill(
        &mut self,
        local_static: &StaticSecret,
        local_public: PublicKey,
        constants: &HandshakeConstants,
        wall_clock: WallClock,
        codec: &IndexCodec,
        id: PeerId,
        config: &PeerConfig,
        rng: &mut dyn EntropySource,
    ) -> Result<(), Error> {
        if ct::ct_eq(local_public.as_bytes(), config.peer_public.as_bytes()) {
            return Err(Error::InvalidPublicKey);
        }
        self.indices.init(codec, id, rng)?;
        self.local_static.set(local_static);
        self.local_public = local_public;
        self.peer_public = config.peer_public;
        self.psk.set(&config.psk);
        self.persistent_keepalive = config.persistent_keepalive;
        self.mtu = config.mtu;
        self.constants = constants.clone();
        self.mac_keys = PeerMacKeys::new::<P>(&config.peer_public);
        self.wall_clock = wall_clock;
        self.endpoint = config.endpoint;
        // The static-static DH, once, straight into its place. This also
        // rejects a low-order `peer_public` up front: the provider reports
        // an all-zero result as a failure.
        if !P::x25519(
            self.local_static.as_bytes(),
            self.peer_public.as_bytes(),
            &mut self.precomputed_ss.0,
        ) {
            return Err(Error::InvalidPublicKey);
        }
        self.start_persistent_keepalive();
        Ok(())
    }

    // ----- sending ----------------------------------------------------------

    /// Encrypt `payload` into `out` as a transport datagram. An empty
    /// payload encodes a keepalive.
    ///
    /// When there is no usable session nothing is written and the payload
    /// is **not consumed** ([`Encapsulated::NoSession`] /
    /// [`Encapsulated::NoEndpoint`]); a handshake is requested instead and
    /// [`Tunnel::poll`] produces it.
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] if a session is usable and `out` is
    /// shorter than `padded_len(payload.len(), mtu) + 32`
    /// ([`transport_datagram_len`] is an upper bound);
    /// [`Error::MessageTooLong`] for a payload beyond the AEAD's limit of
    /// some 256 GiB.
    pub fn encapsulate<'a>(
        &mut self,
        now: Ticks,
        payload: &[u8],
        out: &'a mut [u8],
    ) -> Result<Encapsulated<'a>, Error> {
        let now = self.clamp_now(now);
        if let Some(not_sent) = self.cannot_send(now) {
            return Ok(not_sent);
        }
        // Padding is clamped to the configured MTU so the encrypted
        // datagram never exceeds the path MTU on a non-16-aligned tunnel
        // interface.
        let padded = padded_len(payload.len(), self.mtu);
        let total = padded
            .checked_add(TRANSPORT_OVERHEAD)
            .ok_or(Error::BufferTooSmall)?;
        let datagram = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;
        // Stage plaintext + zero padding directly in the outgoing buffer,
        // then seal in place.
        let staged = datagram
            .get_mut(TRANSPORT_HEADER_LEN..TRANSPORT_HEADER_LEN.saturating_add(padded))
            .ok_or(Error::Internal)?;
        let (data_part, pad_part) = staged
            .split_at_mut_checked(payload.len())
            .ok_or(Error::Internal)?;
        // (Exactly as long as each other: the split was at
        // `payload.len()`.)
        for (d, s) in data_part.iter_mut().zip(payload) {
            *d = *s;
        }
        pad_part.fill(0);
        let transmit = self.seal_staged(now, datagram, payload.len(), padded)?;
        Ok(Encapsulated::Transport(transmit))
    }

    /// As [`encapsulate`](Self::encapsulate), without copying the payload:
    /// the caller has already placed it at
    /// `buf[16..16 + payload_len]` (after
    /// [`crate::consts::TRANSPORT_HEADER_LEN`] bytes of headroom). The
    /// header is written in front of it, padding and the tag behind it,
    /// and the datagram is `buf[..padded_len(payload_len, mtu) + 32]`.
    ///
    /// When there is no usable session `buf` is left untouched.
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] if a session is usable and `buf` is
    /// shorter than `padded_len(payload_len, mtu) + 32`;
    /// [`Error::MessageTooLong`] for a payload beyond the AEAD's limit of
    /// some 256 GiB.
    pub fn encapsulate_in_place<'a>(
        &mut self,
        now: Ticks,
        buf: &'a mut [u8],
        payload_len: usize,
    ) -> Result<Encapsulated<'a>, Error> {
        let now = self.clamp_now(now);
        if let Some(not_sent) = self.cannot_send(now) {
            return Ok(not_sent);
        }
        let padded = padded_len(payload_len, self.mtu);
        let total = padded
            .checked_add(TRANSPORT_OVERHEAD)
            .ok_or(Error::BufferTooSmall)?;
        let datagram = buf.get_mut(..total).ok_or(Error::BufferTooSmall)?;
        // Zero the padding behind the payload (the caller's buffer may
        // hold anything there).
        let pad_start = TRANSPORT_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(Error::BufferTooSmall)?;
        datagram
            .get_mut(pad_start..TRANSPORT_HEADER_LEN.saturating_add(padded))
            .ok_or(Error::Internal)?
            .fill(0);
        let transmit = self.seal_staged(now, datagram, payload_len, padded)?;
        Ok(Encapsulated::Transport(transmit))
    }

    // ----- receiving --------------------------------------------------------

    /// Accept a handshake initiation ([`crate::Incoming::Initiation`]),
    /// writing the handshake response into `out`.
    ///
    /// Normally [`crate::Device::identify`] has already revealed whose
    /// initiation this is — that is how the caller found this tunnel. If
    /// nobody has (a single peer: nothing to look up), the tunnel does it
    /// here, at the same cost of one X25519.
    ///
    /// If the initiation authenticates, the response is addressed to the
    /// address it came from ([`Initiation::src`]). Whether that address
    /// also becomes the peer's endpoint depends on what the tunnel knows
    /// about the peer so far: see [`Tunnel::endpoint`].
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] (`out` must hold 92 bytes),
    /// [`Error::EntropyFailure`]. On error and on [`Received::Dropped`]
    /// there is nothing in `out` to send: it is as it was, or — where the
    /// fault came after the response had been written — zeroed.
    pub fn handle_initiation<'a>(
        &mut self,
        now: Ticks,
        initiation: &Initiation<'_>,
        out: &'a mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Handled<'a>, Error> {
        let now = self.clamp_now(now);
        if out.len() < HANDSHAKE_RESPONSE_LEN {
            return Err(Error::BufferTooSmall);
        }
        let src = initiation.src;
        // Who is calling? (`es`, unless the device has done it.)
        let mut own = Identity::blank();
        let identity = if initiation.identity.known {
            &initiation.identity
        } else {
            if let Err(reason) = noise::identify_initiation::<P>(
                &self.constants,
                &self.local_static,
                &self.local_public,
                &initiation.msg,
                &mut own,
            ) {
                self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
                return Ok(Handled::dropped(reason));
            }
            &own
        };
        // Identity check, then the `ss` step with the precomputed secret:
        // only now is the sender proven to hold the peer's private key.
        let mut consumed = ConsumedInitiation::blank();
        if let Err(reason) = noise::consume_initiation_finish::<P>(
            &initiation.msg,
            identity,
            &self.peer_public,
            &self.precomputed_ss.0,
            &mut consumed,
        ) {
            self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
            return Ok(Handled::dropped(reason));
        }
        // Replay (whitepaper §5.1), then flood (as the kernel: both only
        // for initiations that authenticated).
        if self
            .greatest_timestamp
            .is_some_and(|t| consumed.timestamp <= t)
        {
            return Ok(Handled::dropped(DropReason::ReplayedTimestamp));
        }
        if self
            .last_initiation_rx
            .is_some_and(|t| now.since(t) < INITIATION_MIN_INTERVAL)
        {
            return Ok(Handled::dropped(DropReason::InitiationFlood));
        }

        // The response, and the keys of the session it creates: derived
        // in the tunnel's staging area, where they stay until the session
        // is installed — or are wiped if anything below fails.
        let local_index = self.indices.allocate(&self.live_indices(), rng)?;
        match noise::create_response::<P>(
            &consumed,
            &self.psk,
            local_index,
            rng,
            out,
            self.sessions.staging(),
        ) {
            Ok(()) => {}
            Err(Reject::Drop(reason)) => {
                self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
                return Ok(Handled::dropped(reason));
            }
            Err(Reject::Fault(e)) => return Err(e),
        }
        let mac1 = match out
            .get_mut(..HANDSHAKE_RESPONSE_LEN)
            .ok_or(Error::Internal)
            .and_then(|msg| cookie::apply_macs::<P>(&self.mac_keys, &self.cookie, now, msg))
        {
            Ok(mac1) => mac1,
            Err(e) => {
                self.sessions.discard_staged();
                return Err(e);
            }
        };
        // The last thing that can fail: the jitter that goes with the
        // session this creates.
        let dead_peer_jitter = match draw_jitter(rng) {
            Ok(jitter) => jitter,
            Err(e) => {
                self.sessions.discard_staged();
                // The response is not going out, and is not left lying in
                // the caller's buffer either.
                if let Some(written) = out.get_mut(..HANDSHAKE_RESPONSE_LEN) {
                    written.fill(0);
                }
                return Err(e);
            }
        };

        // Commit.
        //
        // An initiation of our own that is in flight stays in flight: we
        // answer the peer's and still accept the answer to ours. This
        // matters when the two cross. The Linux implementation keeps one
        // handshake per peer and drops its own initiation when it answers
        // ours, so against it our handshake completes within one round
        // trip. (Dropping ours as well would leave neither side with a
        // session until a retransmission — and while both keep sending,
        // those cross again.) If the peer keeps its initiation too — this
        // implementation on both ends — both handshakes complete, and
        // `crossed_handshake_keeps_ours` picks the session both then use.
        //
        // The new session goes into `next` (see `Sessions::install_next`
        // for what happens to a session that is already there).
        let serial = self.next_serial();
        let crossed_with = self.inflight.index();
        self.sessions.install_next(now, serial, crossed_with)?;
        if let Some(expires) = self.sessions.next().map(Session::rejects_at) {
            self.timers.arm(Timer::ExpireNextSession, expires);
        }
        self.last_resp_mac1 = Some(mac1);
        self.dead_peer_jitter = dead_peer_jitter;
        self.greatest_timestamp = Some(consumed.timestamp);
        self.last_initiation_rx = Some(now);
        self.last_response_sent = Some(now);
        // The first of a run of responses that nothing confirms; a run
        // ends when something does, or with the session the first of them
        // created (Reject-After-Time). Not sooner: a run that could start
        // over as soon as its hold has run out would hold us back again
        // at once.
        if !self
            .first_unconfirmed_response
            .is_some_and(|first| now.since(first) < REJECT_AFTER_TIME)
        {
            self.first_unconfirmed_response = Some(now);
        }
        self.stats.handshakes_responded = self.stats.handshakes_responded.saturating_add(1);
        // An authenticated message arrived, and one goes out.
        self.on_authenticated_received(now);
        self.on_authenticated_sent(now);
        // The response goes to where the initiation came from. Whether
        // the *peer* is there is another matter: an initiation proves who
        // made it, not when. Only its timestamp speaks against a
        // recording — and that says something only once the timestamps we
        // hold have been tied to real time, by the peer using a session
        // that an initiation of its own created (`peer_initiation_proven`).
        // From then on this initiation was made after that moment, as it
        // is for the Linux implementation with every initiation, and the
        // endpoint follows it. Before that — a tunnel that has just been
        // created, or one whose peer has never been the initiator — any
        // recording ever made passes, and an endpoint we know is not given
        // up for one: the address is only remembered as the place to try
        // with our own next initiation. Without an endpoint there is
        // nothing to give up, and this address is the first guess.
        let endpoint_changed = if self.endpoint.is_none() || self.peer_initiation_proven {
            self.learn_endpoint(now, src)
        } else {
            if self.endpoint != Some(src) {
                self.candidate = Some(src);
                self.has_candidate = true;
            }
            false
        };

        let datagram = out.get(..HANDSHAKE_RESPONSE_LEN).ok_or(Error::Internal)?;
        Ok(Handled {
            received: Received::HandshakeResponse(Transmit { dst: src, datagram }),
            session_established: false,
            endpoint_changed,
        })
    }

    /// Process a datagram the [`crate::Device`] routed to this peer: a
    /// handshake response, a cookie reply, or transport data.
    ///
    /// `src` is the address the datagram came from; it becomes the peer's
    /// endpoint if (and only if) the datagram authenticates. Transport
    /// data is decrypted in place: [`Received::Data`] borrows the
    /// datagram's own buffer.
    ///
    /// # Errors
    /// Only [`Error::Internal`]. Everything a remote party can cause is
    /// [`Received::Dropped`].
    pub fn handle<'a>(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        packet: PeerPacket<'a>,
    ) -> Result<Handled<'a>, Error> {
        let now = self.clamp_now(now);
        match packet.kind {
            PeerPacketKind::Response(msg) => {
                let Some(inflight) = self
                    .inflight
                    .get()
                    .filter(|i| i.local_index == msg.receiver_index)
                else {
                    return Ok(Handled::dropped(DropReason::NoPendingHandshake));
                };
                // An initiation is in flight until its retransmission is
                // due; then it is replaced, and an answer to it is late.
                // That holds whether or not the caller has got round to
                // `poll` yet: a caller that was away for a minute and
                // processes its socket buffer first would otherwise start
                // a session the peer derived a minute ago, count its age
                // from now, and keep sending on it after the peer has let
                // it expire.
                if self
                    .timers
                    .get(Timer::RetransmitHandshake)
                    .is_some_and(|due| now >= due)
                {
                    return Ok(Handled::dropped(DropReason::NoPendingHandshake));
                }
                // The session keys are derived in the tunnel's staging
                // area (all-zero again if the response is rejected).
                if let Err(reason) = noise::consume_response::<P>(
                    inflight,
                    &self.local_static,
                    &self.psk,
                    &msg,
                    self.sessions.staging(),
                ) {
                    self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
                    return Ok(Handled::dropped(reason));
                }
                // Commit: the new session becomes current (whitepaper §6.3).
                // A session we answered in the meantime stays in `next`;
                // if the peer starts using it, `handle_transport` decides
                // whether it takes over.
                let serial = self.next_serial();
                self.sessions.install_current(now, serial)?;
                self.inflight.clear();
                self.first_unconfirmed_response = None;
                self.on_handshake_complete(now, now);
                self.on_authenticated_received(now);
                // §6.1/§6.5: confirm the session to the responder at once,
                // unless data goes out first.
                self.keepalive_staged = true;
                self.timers.arm(Timer::FlushKeepalive, now);
                let endpoint_changed = self.learn_endpoint(now, src);
                Ok(Handled {
                    received: Received::HandshakeComplete,
                    session_established: true,
                    endpoint_changed,
                })
            }
            PeerPacketKind::CookieReply(msg) => {
                // A cookie reply answers one handshake message of ours and
                // names it by the index that message carried: the
                // initiation in flight, or the response behind the session
                // waiting in `next`. Its seal is bound to that message's
                // `mac1` (the AAD). A reply for anything else — a handshake
                // that has since completed or been replaced, however live
                // the index written into it — is for nothing.
                let sent = if self.inflight.index() == Some(msg.receiver_index) {
                    &mut self.last_init_mac1
                } else if self
                    .sessions
                    .next()
                    .is_some_and(|s| s.keys.local_index == msg.receiver_index)
                {
                    &mut self.last_resp_mac1
                } else {
                    return Ok(Handled::dropped(DropReason::UnknownIndex));
                };
                // One reply per message, as in the kernel
                // (`have_sent_mac1`). The seal's key is derived from the
                // peer's *public* key, so anyone who has it and sees our
                // message can make a reply: the first to arrive is kept,
                // and nothing that comes later — the same reply again, or
                // a forgery sent at leisure — can replace the cookie it
                // brought.
                let Some(mac1) = *sent else {
                    return Ok(Handled::dropped(DropReason::NoPendingHandshake));
                };
                if !cookie::consume_cookie_reply::<P>(
                    &self.mac_keys,
                    &mac1,
                    &msg,
                    now,
                    &mut self.cookie,
                ) {
                    self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
                    return Ok(Handled::dropped(DropReason::InvalidCookie));
                }
                *sent = None;
                // Not an authenticated message from the peer: the endpoint
                // and the timers stay as they are.
                self.stats.cookies_received = self.stats.cookies_received.saturating_add(1);
                Ok(Handled {
                    received: Received::CookieStored,
                    session_established: false,
                    endpoint_changed: false,
                })
            }
            PeerPacketKind::Transport {
                receiver_index,
                counter,
                body,
            } => self.handle_transport(now, src, receiver_index, counter, body),
        }
    }

    // ----- timers -----------------------------------------------------------

    /// Everything the tunnel does on its own initiative: handshake
    /// initiations and retransmissions, keepalives, and expiry.
    ///
    /// Call it after every other call that takes `now` and whenever
    /// [`Tunnel::next_wake`] falls due; each call performs at most one
    /// action, so loop until [`PollOutput::Idle`]. Once it returns `Idle`,
    /// `next_wake()` is `None` or strictly later than `now`.
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] (`out` must hold 148 bytes),
    /// [`Error::EntropyFailure`]. The action stays due and is retried by
    /// the next call.
    pub fn poll<'a>(
        &mut self,
        now: Ticks,
        out: &'a mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<PollOutput<'a>, Error> {
        let now = self.clamp_now(now);
        match self.next_action(now)? {
            Action::Idle => Ok(PollOutput::Idle),
            Action::HandshakeExpired => Ok(PollOutput::HandshakeExpired),
            Action::SessionsExpired => Ok(PollOutput::SessionsExpired),
            Action::Initiation(reason, timer, deadline) => {
                match self.send_initiation(now, out, rng) {
                    Ok(transmit) => Ok(PollOutput::Transmit(transmit, reason)),
                    Err(e) => {
                        // Nothing was committed: leave the request due.
                        self.timers.arm(timer, deadline);
                        Err(e)
                    }
                }
            }
            Action::Keepalive(reason, timer, deadline) => match self.send_keepalive(now, out) {
                Ok(transmit) => Ok(PollOutput::Transmit(transmit, reason)),
                Err(e) => {
                    self.timers.arm(timer, deadline);
                    Err(e)
                }
            },
        }
    }

    /// The earliest instant at which [`Tunnel::poll`] has work. `None`
    /// means no timer is armed. A returned instant may be now or in the
    /// past — poll immediately then.
    #[must_use]
    pub fn next_wake(&self) -> Option<Ticks> {
        self.timers.next_wake()
    }

    /// The deadline of one timer, if it is armed. For diagnostics and
    /// tests; [`Tunnel::next_wake`] is the minimum over all of them.
    #[must_use]
    pub fn timer(&self, timer: Timer) -> Option<Ticks> {
        self.timers.get(timer)
    }

    // ----- control ----------------------------------------------------------

    /// Ask for a handshake now, whether or not a session exists — for
    /// example right after configuration, to bring the tunnel up before
    /// the first packet. [`Tunnel::poll`] sends the initiation as soon as
    /// the once-per-`Rekey-Timeout` pacing allows (whitepaper §6.1). A
    /// handshake already in flight absorbs the request.
    pub fn request_handshake(&mut self, now: Ticks) {
        let now = self.clamp_now(now);
        self.want_handshake(now);
    }

    /// Is there a confirmed session that can encrypt outgoing data at
    /// `now`? False once the current session is past `Reject-After-Time`
    /// or `Reject-After-Messages`.
    #[must_use]
    pub fn is_established(&self, now: Ticks) -> bool {
        self.current_usable(now.following(self.last_now))
    }

    /// Where datagrams for this peer are sent: the configured endpoint,
    /// until the peer proves to be somewhere else.
    ///
    /// The endpoint moves to the source address of a message that only
    /// the live peer can have sent from there:
    ///
    /// * a **response** to an initiation of ours (it answers a message we
    ///   have just made);
    /// * **transport data** or a keepalive on any session — which, for a
    ///   session we answered, is the first thing the peer sends on it.
    ///
    /// A **handshake initiation** is always answered where it came from.
    /// Whether it also moves the endpoint depends on what its timestamp
    /// is worth. An initiation proves who made it, not when; all that
    /// speaks against a recording is that timestamp, which has to be
    /// later than that of the last initiation accepted.
    ///
    /// * Once the peer has **used a session that an initiation of its own
    ///   created** — which no recording can do — the timestamps this
    ///   tunnel holds are tied to real time: a later one was made after
    ///   that moment. From then on an initiation moves the endpoint, as
    ///   every initiation does for the Linux implementation. (What is
    ///   left is what Linux has too: an initiation that was made later
    ///   but never reached us can be delivered by someone else, from
    ///   somewhere else.)
    /// * Before that — a tunnel that has just been created, after a
    ///   restart say, or one whose peer has only ever answered — there is
    ///   nothing to compare with, and any initiation ever recorded
    ///   passes. An endpoint that is known is **not** given up for one:
    ///   if it were, anyone holding a single recording could redirect a
    ///   new tunnel until the peer next speaks, which for a peer that
    ///   waits to be called is never. (This is where the Linux
    ///   implementation differs: it moves the endpoint.) The address is
    ///   remembered as a *candidate* instead: our own handshake
    ///   initiations go to it and to the endpoint in turn, the candidate
    ///   first, until one of them is answered — an answer is proof. A
    ///   peer that really has moved is found with the first of them; a
    ///   replayed recording costs one Rekey-Timeout.
    /// * A tunnel with no endpoint at all has nothing to lose and takes
    ///   the initiation's source as a first guess.
    ///
    /// A cookie reply proves nothing and moves nothing.
    #[must_use]
    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoint
    }

    /// Set the peer's endpoint (configuration, or out-of-band discovery).
    /// The peer still moves it by proving to be elsewhere
    /// ([`Tunnel::endpoint`]).
    pub fn set_endpoint(&mut self, endpoint: SocketAddr) {
        let now = self.last_now;
        self.learn_endpoint(now, endpoint);
    }

    /// The id this tunnel was created with.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.indices.peer()
    }

    /// The peer's static public key.
    #[must_use]
    pub fn peer_public(&self) -> PublicKey {
        self.peer_public
    }

    /// Cumulative counters.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Update the tunnel-interface MTU at runtime (e.g. after the
    /// embedder observes outer-path ICMP Fragmentation-Needed).
    ///
    /// Affects only the padding clamp on subsequent
    /// [`Tunnel::encapsulate`] calls. `None` disables the clamp (padding
    /// always to the next multiple of 16). See [`padded_len`].
    pub fn set_mtu(&mut self, mtu: Option<NonZeroU16>) {
        self.mtu = mtu;
    }

    /// The currently configured tunnel-interface MTU, if any.
    #[must_use]
    pub fn mtu(&self) -> Option<NonZeroU16> {
        self.mtu
    }

    /// Replace the wall-clock anchor used for handshake timestamps — for
    /// platforms that learn the time after start-up. Timestamps we send
    /// never decrease within a run, whatever the new anchor says. See
    /// also [`crate::Device::set_wall_clock`], which covers tunnels created
    /// afterwards.
    pub fn set_wall_clock(&mut self, wall_clock: WallClock) {
        self.wall_clock = wall_clock;
    }

    /// Drop and wipe all sessions, in-flight handshakes and cookies, and
    /// cancel every timer. With a persistent keepalive configured the
    /// tunnel then brings itself back up, as it does after construction.
    ///
    /// Kept across a reset: the endpoint, the handshake pacing, and the
    /// replay protections. In particular the greatest initiation
    /// timestamp seen from the peer is **retained**, so a captured
    /// initiation cannot be replayed across a reset. The consequence is
    /// that if the peer once sent an initiation with a far-future wall
    /// clock, `reset()` cannot un-poison the tunnel — every later
    /// initiation is [`DropReason::ReplayedTimestamp`] until real time
    /// catches up. To recover from that, drop this `Tunnel` and create a
    /// fresh one.
    pub fn reset(&mut self) {
        self.wipe_keys();
        self.attempt_started = None;
        self.handshake_wanted = false;
        self.keepalive_staged = false;
        self.timers.clear_all();
        self.start_persistent_keepalive();
    }

    // ----- internals: time ------------------------------------------------

    /// Defend timer arithmetic against a non-monotonic caller clock: time
    /// never goes backwards from the tunnel's perspective.
    fn clamp_now(&mut self, now: Ticks) -> Ticks {
        self.last_now = now.following(self.last_now);
        self.last_now
    }

    fn current_usable(&self, now: Ticks) -> bool {
        self.sessions
            .current()
            .is_some_and(|s| s.usable_for_send(now))
    }

    // ----- internals: timer events (whitepaper §6) --------------------------
    //
    // One function per protocol event, each arming or clearing the timers
    // the whitepaper ties to that event. Nothing else touches the five
    // protocol timers.

    /// A transport message carrying data was sent (§6.5): if nothing comes
    /// back for Keepalive-Timeout + Rekey-Timeout, start a new handshake.
    /// Measured from the first unanswered packet.
    fn on_data_sent(&mut self, now: Ticks) {
        self.timers.arm_if_idle(
            Timer::NewHandshake,
            now.add_nanos(DEAD_PEER_TIMEOUT)
                .add_nanos(self.dead_peer_jitter),
        );
    }

    /// A transport message carrying data was received (§6.5): if we send
    /// nothing for Keepalive-Timeout, send a keepalive. Measured from the
    /// first unanswered packet.
    fn on_data_received(&mut self, now: Ticks) {
        self.timers
            .arm_if_idle(Timer::SendKeepalive, now.add_nanos(KEEPALIVE_TIMEOUT));
    }

    /// Any authenticated message — data, keepalive, or handshake — was
    /// sent: the peer has heard from us, so no passive keepalive is owed.
    fn on_authenticated_sent(&mut self, now: Ticks) {
        self.timers.clear(Timer::SendKeepalive);
        self.on_authenticated_traversal(now);
    }

    /// Any authenticated message — data, keepalive, or handshake — was
    /// received: the peer is alive.
    fn on_authenticated_received(&mut self, now: Ticks) {
        self.timers.clear(Timer::NewHandshake);
        self.on_authenticated_traversal(now);
    }

    /// An authenticated message went either way: restart the persistent
    /// keepalive interval.
    fn on_authenticated_traversal(&mut self, now: Ticks) {
        if let Some(at) = self.persistent_keepalive_after(now) {
            self.timers.arm(Timer::PersistentKeepalive, at);
        }
    }

    /// One persistent-keepalive interval after `now`, if one is
    /// configured.
    fn persistent_keepalive_after(&self, now: Ticks) -> Option<Ticks> {
        let interval = self.persistent_keepalive?;
        Some(now.add_nanos(u64::from(interval.get()).saturating_mul(SECOND)))
    }

    /// A session became usable for sending, in either role. `created` is
    /// when its keys were derived.
    fn on_handshake_complete(&mut self, now: Ticks, created: Ticks) {
        self.timers.clear(Timer::RetransmitHandshake);
        self.timers.clear(Timer::SendInitiation);
        self.handshake_wanted = false;
        self.attempt_started = None;
        self.sent_lastminute_handshake = false;
        // §6.3: wipe everything 3 × Reject-After-Time after the newest
        // confirmed session was created. A session can be confirmed after
        // a newer one already was (crossed handshakes: we switch to the
        // session the peer initiated, which is a little older than ours),
        // so the deadline only ever moves later.
        let wipe_at = created.add_nanos(SESSION_DISCARD_TIME);
        let wipe_at = self
            .timers
            .get(Timer::ZeroKeyMaterial)
            .map_or(wipe_at, |armed| armed.max(wipe_at));
        self.timers.arm(Timer::ZeroKeyMaterial, wipe_at);
        if self.keepalive_staged {
            self.timers.arm(Timer::FlushKeepalive, now);
        }
        self.stats.handshakes_completed = self.stats.handshakes_completed.saturating_add(1);
        self.stats.last_handshake_at = Some(now);
    }

    /// A transport message went out on the current session.
    fn on_transport_sent(&mut self, now: Ticks, is_keepalive: bool) {
        // Whatever keepalive was staged is now redundant.
        self.keepalive_staged = false;
        self.timers.clear(Timer::FlushKeepalive);
        self.on_authenticated_sent(now);
        if !is_keepalive {
            self.on_data_sent(now);
        }
        // §6.2, send path: rekey on message count, and — initiator only —
        // on session age.
        let rekey = self.sessions.current().is_some_and(|s| {
            s.send_counter >= REKEY_AFTER_MESSAGES
                || (s.keys.is_initiator && s.age(now) >= REKEY_AFTER_TIME)
        });
        if rekey {
            self.want_handshake(now);
        }
    }

    // ----- internals: handshake requests ------------------------------------

    /// When the next handshake message may go out (§6.1: never more than
    /// one per Rekey-Timeout).
    fn pacing_deadline(&self) -> Ticks {
        // After an initiation of our own: Rekey-Timeout, always (§6.1).
        let after_initiation = self
            .last_initiation_sent
            .map_or(Ticks::ZERO, |t| t.add_nanos(REKEY_TIMEOUT));
        // After a response: the same, to let the handshake we have just
        // answered finish instead of crossing it with one of ours — but
        // counted from the first response that nothing has confirmed, not
        // more than `UNCONFIRMED_RESPONSE_HOLD`. Responses cost the sender
        // nothing but a recording each (a new tunnel accepts any that
        // were ever made, in the order of their timestamps), and without
        // this bound a stream of them would keep us from ever starting a
        // handshake of our own.
        let after_response = match (self.last_response_sent, self.first_unconfirmed_response) {
            (Some(last), Some(first)) => last
                .add_nanos(REKEY_TIMEOUT)
                .min(first.add_nanos(UNCONFIRMED_RESPONSE_HOLD)),
            // Nothing unconfirmed: the plain rule, as in the kernel.
            (Some(last), None) => last.add_nanos(REKEY_TIMEOUT),
            (None, _) => Ticks::ZERO,
        };
        after_initiation.max(after_response)
    }

    /// Is a handshake attempt of ours under way: an initiation in flight,
    /// with its retransmit timer running?
    fn attempt_running(&self) -> bool {
        self.inflight.is_some()
    }

    /// Record that a handshake is wanted (§6.2, §6.4, §6.5). Every such
    /// request restarts the Rekey-Attempt-Time window (§6.4: the retry
    /// limit "is reset" when a new packet is queued).
    fn want_handshake(&mut self, now: Ticks) {
        if self.attempt_running() {
            // Already running; its retransmit timer drives it.
            self.attempt_started = Some(now);
            return;
        }
        self.attempt_started = None;
        self.handshake_wanted = true;
        self.arm_initiation(now);
    }

    /// Schedule the wanted initiation for when pacing allows. Without an
    /// endpoint there is nowhere to send it: the request stays recorded
    /// and is scheduled when the endpoint becomes known.
    fn arm_initiation(&mut self, now: Ticks) {
        if self.endpoint.is_some() {
            self.timers
                .arm(Timer::SendInitiation, self.pacing_deadline().max(now));
        }
    }

    /// A keepalive is owed but no session is usable: keep it for later and
    /// get a session.
    fn stage_keepalive(&mut self, now: Ticks) {
        self.keepalive_staged = true;
        self.want_handshake(now);
    }

    /// With a persistent keepalive configured the tunnel keeps itself up:
    /// at start (and after `reset`) that means a handshake followed by a
    /// keepalive.
    fn start_persistent_keepalive(&mut self) {
        if self.persistent_keepalive.is_some() {
            self.keepalive_staged = true;
            self.handshake_wanted = true;
            self.arm_initiation(self.last_now);
        }
    }

    /// Record the peer's (authenticated or configured) address. Returns
    /// whether it changed.
    fn learn_endpoint(&mut self, now: Ticks, addr: SocketAddr) -> bool {
        // Whatever was only a guess is settled by this.
        self.forget_candidate();
        // The usual case first and on its own: the address the peer was at
        // already. (Every data packet comes through here; nothing below
        // is looked at for it — in particular not the handshake state,
        // which lies a long way from what a data packet uses.)
        if self.endpoint == Some(addr) {
            return false;
        }
        let was_unknown = self.endpoint.is_none();
        self.endpoint = Some(addr);
        if was_unknown && self.handshake_wanted && !self.attempt_running() {
            self.arm_initiation(now);
        }
        true
    }

    /// Drop the candidate address; the next one, should there be one,
    /// is tried first again.
    fn forget_candidate(&mut self) {
        if self.has_candidate {
            self.has_candidate = false;
            self.candidate = None;
            self.try_candidate = true;
        }
    }

    // ----- internals: poll --------------------------------------------------

    /// Run the handlers of every timer that is due, in service order,
    /// until one of them needs to emit something or nothing is due.
    fn next_action(&mut self, now: Ticks) -> Result<Action, Error> {
        // Each iteration consumes one due timer; a handler arms at most
        // one other timer for "now" (a wanted initiation), so this bound
        // is never reached.
        for _ in 0..Timer::ALL.len().saturating_mul(2) {
            let Some((timer, deadline)) = self.timers.take_due(now) else {
                return Ok(Action::Idle);
            };
            match timer {
                Timer::ZeroKeyMaterial => {
                    self.zero_key_material(now);
                    return Ok(Action::SessionsExpired);
                }
                Timer::ExpireNextSession => {
                    if self
                        .sessions
                        .next()
                        .is_some_and(|s| s.age(now) >= REJECT_AFTER_TIME)
                    {
                        self.sessions.discard(Slot::Next);
                    }
                }
                Timer::RetransmitHandshake => {
                    if !self.inflight.is_some() {
                        continue;
                    }
                    if self
                        .attempt_started
                        .is_some_and(|t0| now.since(t0) >= REKEY_ATTEMPT_TIME)
                    {
                        self.give_up_handshake(now);
                        return Ok(Action::HandshakeExpired);
                    }
                    return Ok(Action::Initiation(
                        SendReason::HandshakeRetransmit,
                        timer,
                        deadline,
                    ));
                }
                Timer::NewHandshake => self.want_handshake(now),
                Timer::SendInitiation => {
                    if self.attempt_running() {
                        // A handshake got under way in the meantime.
                        self.handshake_wanted = false;
                        continue;
                    }
                    if !self.handshake_wanted || self.endpoint.is_none() {
                        continue;
                    }
                    let pacing = self.pacing_deadline();
                    if now < pacing {
                        self.timers.arm(Timer::SendInitiation, pacing);
                        continue;
                    }
                    return Ok(Action::Initiation(
                        SendReason::HandshakeInitiation,
                        timer,
                        deadline,
                    ));
                }
                Timer::FlushKeepalive => {
                    if !self.keepalive_staged {
                        continue;
                    }
                    if self.current_usable(now) && self.endpoint.is_some() {
                        return Ok(Action::Keepalive(SendReason::Keepalive, timer, deadline));
                    }
                    // The session it was waiting for is gone again.
                    self.want_handshake(now);
                }
                Timer::SendKeepalive => {
                    if self.current_usable(now) && self.endpoint.is_some() {
                        return Ok(Action::Keepalive(SendReason::Keepalive, timer, deadline));
                    }
                    self.stage_keepalive(now);
                }
                Timer::PersistentKeepalive => {
                    if self.persistent_keepalive.is_none() {
                        continue;
                    }
                    if self.current_usable(now) && self.endpoint.is_some() {
                        return Ok(Action::Keepalive(
                            SendReason::PersistentKeepalive,
                            timer,
                            deadline,
                        ));
                    }
                    self.stage_keepalive(now);
                }
            }
        }
        Err(Error::Internal)
    }

    /// §6.4: the handshake attempt ran out of Rekey-Attempt-Time.
    fn give_up_handshake(&mut self, now: Ticks) {
        self.inflight.clear();
        self.attempt_started = None;
        self.handshake_wanted = false;
        // Neither address answered for a whole attempt: the candidate was
        // a guess, and it is dropped.
        self.forget_candidate();
        // "…and clear all existing packets queued up to be sent": the
        // keepalive we were holding, and the one we owed.
        self.keepalive_staged = false;
        self.timers.clear(Timer::SendInitiation);
        self.timers.clear(Timer::FlushKeepalive);
        self.timers.clear(Timer::SendKeepalive);
        // A tunnel with a persistent keepalive keeps itself up, so giving
        // up must not leave it with nothing scheduled. Its timer is
        // restarted by every message we send. If it has fired during this
        // attempt, the retransmission that would have restarted it is the
        // one we are not sending now (the caller was away for longer than
        // Rekey-Attempt-Time in between): start the interval again.
        if let Some(at) = self.persistent_keepalive_after(now) {
            self.timers.arm_if_idle(Timer::PersistentKeepalive, at);
        }
    }

    /// §6.3: no new session for 3 × Reject-After-Time — wipe the keys of
    /// every session that has been in use, and what belonged to them.
    ///
    /// This timer is about key material that has gone stale. A handshake
    /// that is under way at this moment is not stale; it is left alone and
    /// ends on its own, much shorter, deadline:
    ///
    /// * **an initiation of ours in flight** (replaced or abandoned within
    ///   Rekey-Timeout plus jitter). Wiping it would make us drop the
    ///   response that is on its way and start over five seconds later.
    /// * **a session we answered and have not switched to** (`next`; it
    ///   is wiped Reject-After-Time after we answered, on
    ///   `ExpireNextSession`). The peer may already hold our response;
    ///   wiping the session would leave the peer sending into the void
    ///   until its own dead-peer timer starts a new handshake.
    fn zero_key_material(&mut self, now: Ticks) {
        self.sessions.discard(Slot::Previous);
        self.sessions.discard(Slot::Current);
        self.sent_lastminute_handshake = false;
        // What a cookie reply is matched against goes with the handshake
        // message it belonged to.
        if self.sessions.next().is_none() {
            self.last_resp_mac1 = None;
        }
        if !self.inflight.is_some() {
            self.last_init_mac1 = None;
        }
        // A cookie that is still fresh is worth keeping for whichever
        // handshake message goes out next; a stale one is of no use.
        if self.cookie.fresh_value(now).is_none() {
            self.cookie.clear();
        }
        // Timers of the sessions that are gone: a keepalive owed on them,
        // a dead-peer check for them.
        for timer in [
            Timer::SendKeepalive,
            Timer::NewHandshake,
            Timer::ZeroKeyMaterial,
            Timer::FlushKeepalive,
        ] {
            self.timers.clear(timer);
        }
    }

    /// Wipe every session, the in-flight handshake and the cookie.
    fn wipe_keys(&mut self) {
        for slot in [Slot::Previous, Slot::Current, Slot::Next] {
            self.sessions.discard(slot);
        }
        self.sessions.discard_staged();
        self.inflight.clear();
        self.inflight.discard_staged();
        self.cookie.clear();
        self.forget_candidate();
        // Non-secret on-wire values, but meaningless once the handshake
        // state they belonged to is gone.
        self.last_init_mac1 = None;
        self.last_resp_mac1 = None;
        self.sent_lastminute_handshake = false;
    }

    // ----- internals: sessions ----------------------------------------------

    fn session_with_index(&self, index: u32) -> Option<Slot> {
        self.sessions.find(index)
    }

    /// The peer's first packet has arrived on a session we answered
    /// (`next`). Normally that session takes over (§6.3). It must not
    /// always, when `current` is a session we initiated ourselves and
    /// completed *after* answering this one:
    ///
    /// * **We initiated after answering.** The peer's handshake came
    ///   first and ours later, so the peer holds ours as *its* pending
    ///   session, newer than the one it is using, and will switch to ours
    ///   on our first packet. We keep ours. (Switching back to the older
    ///   session would leave each side responder of the session it sends
    ///   on, and nobody would rekey it: §6.2 leaves that to the
    ///   initiator.)
    /// * **The two handshakes crossed** — the initiation that became
    ///   `current` was in flight when we answered the peer's, and both
    ///   completed. The peer is in the same position, so both sides
    ///   settle on the same one of the two sessions: the one with the
    ///   smaller (initiator's index, responder's index) pair, two numbers
    ///   both sides know. Its initiator keeps it; the other side switches
    ///   to it as usual.
    ///
    /// Returns `true` to keep ours (do not promote `next`). `next` stays
    /// valid for receiving either way, so nothing in flight is lost.
    ///
    /// Everything here follows from the order of events — which session
    /// was created first, which initiation was in flight — and nothing
    /// from timestamps, so a coarse or stalled caller clock cannot change
    /// the outcome. In particular a session the peer starts after ours
    /// completed (a rekey, or a peer that restarted and knows no other)
    /// always takes over.
    ///
    /// A peer that runs one handshake at a time — the Linux implementation
    /// drops its own initiation when it answers ours — never sends on the
    /// session a crossing leaves in our `next`, so the comparison is never
    /// consulted against it.
    ///
    /// The comparison settles the matter only if the peer makes it too.
    /// When it does not — to the peer the handshakes did not cross — see
    /// `peer_uses_the_session_we_stepped_down_from`.
    fn crossed_handshake_keeps_ours(&self, now: Ticks) -> bool {
        match (self.sessions.current(), self.sessions.next()) {
            (Some(ours), Some(theirs)) => {
                ours.keys.is_initiator
                    && ours.serial > theirs.serial
                    && ours.usable_for_send(now)
                    && (theirs.crossed_with != Some(ours.keys.local_index)
                        || (ours.keys.local_index, ours.keys.peer_index)
                            < (theirs.keys.peer_index, theirs.keys.local_index))
            }
            _ => false,
        }
    }

    /// A packet has arrived on `previous`. Is the peer telling us, by
    /// sending there, that it uses the session we stepped down from?
    ///
    /// `previous` is normally the older session. It is the *newer* one in
    /// exactly one situation: we completed a handshake of our own, and
    /// then switched to an older session of the peer's because the two had
    /// crossed and the tie-break favoured the peer's
    /// (`crossed_handshake_keeps_ours`). The tie-break assumes the peer
    /// makes the same comparison. It does not if, from where it stands,
    /// the handshakes never crossed: the network held our initiation back
    /// until its own handshake was complete, so ours is simply the newer
    /// session to it, and it has switched to ours. Then each side would
    /// be the responder of the session it sends on — and since only a
    /// session's initiator rekeys it (§6.2), neither would, until both ran
    /// out of session.
    ///
    /// What the peer sends on is the better evidence of what the peer
    /// uses: a packet on the newer session, which we initiated, puts us
    /// back on it. (A peer that did make the comparison never sends
    /// there, so this cannot undo a tie-break both sides agree on; and a
    /// late packet on a session that really is the older one changes
    /// nothing.)
    fn peer_uses_the_session_we_stepped_down_from(&self, now: Ticks) -> bool {
        match (self.sessions.current(), self.sessions.get(Slot::Previous)) {
            (Some(current), Some(previous)) => {
                previous.serial > current.serial && previous.usable_for_send(now)
            }
            _ => false,
        }
    }

    /// The serial for a session being created.
    fn next_serial(&mut self) -> u64 {
        self.sessions_created = self.sessions_created.saturating_add(1);
        self.sessions_created
    }

    /// Every index this tunnel currently answers to.
    fn live_indices(&self) -> [Option<u32>; 4] {
        let [previous, current, next] = self.sessions.local_indices();
        [self.inflight.index(), previous, current, next]
    }

    // ----- internals: building datagrams ------------------------------------

    /// Why nothing can be encrypted right now, if so. Requests a handshake
    /// when the reason is a missing session (§6.4: an explicit attempt to
    /// send restarts the attempt window).
    fn cannot_send(&mut self, now: Ticks) -> Option<Encapsulated<'static>> {
        let usable = self.current_usable(now);
        if !usable {
            self.want_handshake(now);
        }
        match (usable, self.endpoint.is_some()) {
            (true, true) => None,
            (false, true) => Some(Encapsulated::NoSession),
            (_, false) => Some(Encapsulated::NoEndpoint),
        }
    }

    /// Seal a transport message whose (padded) plaintext is already in
    /// place at `datagram[16..16 + padded]`; `datagram` is exactly the
    /// final message length.
    fn seal_staged<'a>(
        &mut self,
        now: Ticks,
        datagram: &'a mut [u8],
        payload_len: usize,
        padded: usize,
    ) -> Result<Transmit<'a>, Error> {
        let dst = self.endpoint.ok_or(Error::Internal)?;
        let session = self
            .sessions
            .get_mut(Slot::Current)
            .ok_or(Error::Internal)?;
        let counter = session.next_counter().ok_or(Error::Internal)?;
        message::write_transport_header(datagram, session.keys.peer_index, counter)?;
        let body = datagram
            .get_mut(TRANSPORT_HEADER_LEN..)
            .ok_or(Error::Internal)?;
        let sealed = P::seal_in_place(&session.keys.send, counter, &[], padded, body)?;
        if sealed != body.len() {
            return Err(Error::Internal);
        }

        let is_keepalive = payload_len == 0;
        self.stats.tx_transport = self.stats.tx_transport.saturating_add(1);
        self.stats.tx_bytes = self.stats.tx_bytes.saturating_add(payload_len as u64);
        if is_keepalive {
            self.stats.tx_keepalives = self.stats.tx_keepalives.saturating_add(1);
        }
        self.on_transport_sent(now, is_keepalive);
        Ok(Transmit { dst, datagram })
    }

    /// Encrypt an empty payload on the current session.
    fn send_keepalive<'a>(&mut self, now: Ticks, out: &'a mut [u8]) -> Result<Transmit<'a>, Error> {
        let datagram = out
            .get_mut(..TRANSPORT_OVERHEAD)
            .ok_or(Error::BufferTooSmall)?;
        self.seal_staged(now, datagram, 0, 0)
    }

    /// Create, mac and account a handshake initiation in `out`.
    fn send_initiation<'a>(
        &mut self,
        now: Ticks,
        out: &'a mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Transmit<'a>, Error> {
        let endpoint = self.endpoint.ok_or(Error::Internal)?;
        // With a candidate address (see `Tunnel::endpoint`), initiations
        // go to it and to the endpoint in turn. The turn changes with
        // every initiation and with nothing else — in particular not when
        // a new candidate comes in — so however many recordings someone
        // replays, at least every other initiation goes to the endpoint.
        let dst = match self.candidate {
            Some(candidate) if self.try_candidate => candidate,
            _ => endpoint,
        };
        if out.len() < HANDSHAKE_INITIATION_LEN {
            return Err(Error::BufferTooSmall);
        }
        let local_index = self.indices.allocate(&self.live_indices(), rng)?;
        // Ratchet the outbound TAI64N strictly past the last one we sent,
        // so the peer never sees a timestamp repeat or go backwards (two
        // initiations inside one whitening quantum, or a wall-clock anchor
        // that was moved back). The ratchet adds 1 to the (already
        // whitened) low nanosecond bits and so leaks nothing the previous
        // timestamp did not.
        let wall = self.wall_clock.tai64n(now);
        let timestamp = match self.last_sent_tai64n {
            Some(last) if wall <= last => last.tick(),
            _ => wall,
        };
        // The handshake state — ephemeral private key included — is built
        // in the tunnel's staging area. Nothing is in flight until the
        // commit below; on any failure before it the staged state is
        // wiped and the initiation that was in flight stays as it was.
        noise::create_initiation::<P>(
            &self.constants,
            &self.local_public,
            &self.peer_public,
            &self.precomputed_ss.0,
            local_index,
            timestamp,
            rng,
            out,
            self.inflight.staging(),
        )?;
        // §6.1 jitter (≤ 333 ms), for the retransmission of this
        // initiation and for the dead-peer timer of the session it leads
        // to.
        let (jitter, dead_peer_jitter) = match (draw_jitter(rng), draw_jitter(rng)) {
            (Ok(jitter), Ok(dead_peer_jitter)) => (jitter, dead_peer_jitter),
            (Err(e), _) | (_, Err(e)) => {
                self.inflight.discard_staged();
                return Err(e);
            }
        };
        let mac1 = match out
            .get_mut(..HANDSHAKE_INITIATION_LEN)
            .ok_or(Error::Internal)
            .and_then(|msg| cookie::apply_macs::<P>(&self.mac_keys, &self.cookie, now, msg))
        {
            Ok(mac1) => mac1,
            Err(e) => {
                self.inflight.discard_staged();
                return Err(e);
            }
        };

        // Commit: nothing below can fail.
        self.inflight.commit();
        self.dead_peer_jitter = dead_peer_jitter;
        self.last_sent_tai64n = Some(timestamp);
        self.last_init_mac1 = Some(mac1);
        self.handshake_wanted = false;
        self.timers.clear(Timer::SendInitiation);
        if self.attempt_started.is_none() {
            self.attempt_started = Some(now);
        }
        self.last_initiation_sent = Some(now);
        self.try_candidate = self.candidate.is_none() || !self.try_candidate;
        self.timers.arm(
            Timer::RetransmitHandshake,
            now.add_nanos(REKEY_TIMEOUT).add_nanos(jitter),
        );
        self.on_authenticated_sent(now);
        self.stats.handshakes_initiated = self.stats.handshakes_initiated.saturating_add(1);

        let datagram = out.get(..HANDSHAKE_INITIATION_LEN).ok_or(Error::Internal)?;
        Ok(Transmit { dst, datagram })
    }

    fn handle_transport<'a>(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        receiver_index: u32,
        counter: u64,
        body: &'a mut [u8],
    ) -> Result<Handled<'a>, Error> {
        // Cheap pre-authentication rejects (DoS posture): unknown index,
        // out-of-range counter, expired session, replayed counter.
        let Some(slot) = self.session_with_index(receiver_index) else {
            return Ok(Handled::dropped(DropReason::UnknownIndex));
        };
        if counter >= REJECT_AFTER_MESSAGES {
            return Ok(Handled::dropped(DropReason::Expired));
        }
        let session = self.sessions.get_mut(slot).ok_or(Error::Internal)?;
        if session.age(now) >= REJECT_AFTER_TIME {
            return Ok(Handled::dropped(DropReason::Expired));
        }
        if !session.replay.check(counter) {
            self.stats.replays_dropped = self.stats.replays_dropped.saturating_add(1);
            return Ok(Handled::dropped(DropReason::Replay));
        }

        // Authenticate, then decrypt in place; `body` is untouched on
        // failure.
        let Some(len) = P::open_in_place(&session.keys.recv, counter, &[], body) else {
            self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
            return Ok(Handled::dropped(DropReason::AuthFailure));
        };

        // Only an authenticated counter may advance the replay window.
        if !session.replay.accept(counter) {
            // Unreachable (check() passed pre-AEAD and accept() is the
            // same predicate under &mut self), but if it WERE reached the
            // buffer already holds decrypted plaintext: wipe it rather
            // than leave it behind an error.
            if let Some(plaintext) = body.get_mut(..len) {
                ct::wipe(plaintext);
            }
            return Err(Error::Internal);
        }
        let confirms = !session.confirmed;
        session.confirmed = true;
        if confirms && !session.keys.is_initiator {
            // The peer holds the keys of a session that an initiation of
            // its own created: that initiation was live, not a recording,
            // and so its timestamp is a point in real time (see
            // `Tunnel::endpoint`). And the response we answered it with
            // has done its work.
            self.peer_initiation_proven = true;
            self.first_unconfirmed_response = None;
        }

        let mut session_established = false;
        if confirms && slot == Slot::Next && !self.crossed_handshake_keeps_ours(now) {
            // First authenticated transport on a responder session:
            // promote next → current (whitepaper §6.3).
            self.sessions.promote_next();
            self.timers.clear(Timer::ExpireNextSession);
            // A confirmed session in either role satisfies any in-flight
            // handshake of our own — drop it so a simultaneous open, or a
            // rekey raced by the peer's initiation, does not keep
            // retransmitting.
            self.inflight.clear();
            let created = self.sessions.current().map_or(now, |s| s.created);
            self.on_handshake_complete(now, created);
            session_established = true;
        }

        // The peer is sending on the newer session of ours that we had
        // stepped down from: go back to it.
        if slot == Slot::Previous && self.peer_uses_the_session_we_stepped_down_from(now) {
            self.sessions.swap_current_and_previous();
            self.sent_lastminute_handshake = false;
        }

        // §6.2 receive path: the initiator rekeys a session that is about
        // to become unusable, once.
        if !self.sent_lastminute_handshake
            && self
                .sessions
                .current()
                .is_some_and(|s| s.keys.is_initiator && s.age(now) >= REKEY_AFTER_TIME_RECV)
        {
            self.sent_lastminute_handshake = true;
            self.want_handshake(now);
        }

        let is_keepalive = len == 0;
        self.on_authenticated_received(now);
        if !is_keepalive {
            self.on_data_received(now);
        }
        let endpoint_changed = self.learn_endpoint(now, src);
        self.stats.rx_transport = self.stats.rx_transport.saturating_add(1);
        self.stats.rx_bytes = self.stats.rx_bytes.saturating_add(len as u64);
        let received = if is_keepalive {
            self.stats.rx_keepalives = self.stats.rx_keepalives.saturating_add(1);
            Received::Keepalive
        } else {
            Received::Data(body.get(..len).ok_or(Error::Internal)?)
        };
        Ok(Handled {
            received,
            session_established,
            endpoint_changed,
        })
    }
}

#[cfg(test)]
mod tests {
    //! What is left *inside* a tunnel: tests that need to look at the
    //! stored key material itself, which the public API (rightly) does not
    //! show. Protocol behaviour is tested from the outside, in `tests/`.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::consts::HANDSHAKE_INITIATION_LEN as INIT_LEN;
    use crate::testing::{DeterministicRng, FailingRng};
    use crate::{Device, Incoming};
    use std::vec::Vec;

    const S: u64 = SECOND;

    struct Side {
        device: Device,
        tunnel: Tunnel,
        addr: SocketAddr,
    }

    impl Side {
        /// One `poll`; the datagram it produced, if any.
        fn poll(
            &mut self,
            now: Ticks,
            rng: &mut DeterministicRng,
        ) -> (Option<Vec<u8>>, &'static str) {
            let mut buf = [0u8; 256];
            match self.tunnel.poll(now, &mut buf, rng).unwrap() {
                PollOutput::Transmit(tx, _) => (Some(tx.datagram.to_vec()), "transmit"),
                PollOutput::HandshakeExpired => (None, "handshake_expired"),
                PollOutput::SessionsExpired => (None, "sessions_expired"),
                PollOutput::Idle => (None, "idle"),
            }
        }

        /// Deliver a datagram; a reply to send back, if any, and whether
        /// it was dropped.
        fn recv(
            &mut self,
            now: Ticks,
            src: SocketAddr,
            datagram: &[u8],
            rng: &mut DeterministicRng,
        ) -> (Option<Vec<u8>>, Option<DropReason>) {
            let mut copy = datagram.to_vec();
            let mut out = [0u8; 256];
            let handled = self
                .device
                .receive_for(&mut self.tunnel, now, src, false, &mut copy, &mut out, rng)
                .unwrap();
            match handled.received {
                Received::HandshakeResponse(tx) => (Some(tx.datagram.to_vec()), None),
                Received::Dropped(reason) => (None, Some(reason)),
                _ => (None, None),
            }
        }

        fn send(&mut self, now: Ticks, payload: &[u8]) -> Option<Vec<u8>> {
            let mut buf = [0u8; 256];
            match self.tunnel.encapsulate(now, payload, &mut buf).unwrap() {
                Encapsulated::Transport(tx) => Some(tx.datagram.to_vec()),
                _ => None,
            }
        }

        /// No session key, no handshake secret, anywhere in the tunnel.
        fn holds_no_ephemeral_secrets(&self) -> bool {
            let t = &self.tunnel;
            t.sessions.is_wiped()
                && !t.inflight.active
                && t.inflight.state.is_blank()
                && t.inflight.staged.is_blank()
        }
    }

    fn pair_with_psk(
        seed: u64,
        psk_a: [u8; 32],
        psk_b: [u8; 32],
    ) -> (Side, Side, DeterministicRng) {
        let mut rng = DeterministicRng::new(seed);
        let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
        let a_key = StaticSecret::generate(&mut rng).unwrap();
        let b_key = StaticSecret::generate(&mut rng).unwrap();
        let (a_pub, b_pub) = (a_key.public_key(), b_key.public_key());
        let a_addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let b_addr: SocketAddr = "192.0.2.2:51820".parse().unwrap();
        let id = PeerId::new(0).unwrap();
        let a_device = Device::new(a_key, wall, &mut rng).unwrap();
        let b_device = Device::new(b_key, wall, &mut rng).unwrap();
        let mut a_cfg = PeerConfig::new(b_pub);
        a_cfg.endpoint = Some(b_addr);
        a_cfg.psk = PresharedKey::from_bytes(psk_a);
        let mut b_cfg = PeerConfig::new(a_pub);
        b_cfg.endpoint = Some(a_addr);
        b_cfg.psk = PresharedKey::from_bytes(psk_b);
        let a_tunnel = a_device.tunnel(id, a_cfg, &mut rng).unwrap();
        let b_tunnel = b_device.tunnel(id, b_cfg, &mut rng).unwrap();
        (
            Side {
                device: a_device,
                tunnel: a_tunnel,
                addr: a_addr,
            },
            Side {
                device: b_device,
                tunnel: b_tunnel,
                addr: b_addr,
            },
            rng,
        )
    }

    fn pair(seed: u64) -> (Side, Side, DeterministicRng) {
        pair_with_psk(seed, [0; 32], [0; 32])
    }

    /// `a` initiates at `now`; both sides end up with a usable session.
    fn establish(a: &mut Side, b: &mut Side, now: Ticks, rng: &mut DeterministicRng) {
        a.tunnel.request_handshake(now);
        let init = a.poll(now, rng).0.expect("an initiation");
        let resp = b.recv(now, a.addr, &init, rng).0.expect("a response");
        assert_eq!(a.recv(now, b.addr, &resp, rng), (None, None));
        let keepalive = a.poll(now, rng).0.expect("the confirming keepalive");
        assert_eq!(b.recv(now, a.addr, &keepalive, rng), (None, None));
        assert!(a.tunnel.is_established(now) && b.tunnel.is_established(now));
        assert_eq!(a.poll(now, rng).1, "idle");
        assert_eq!(b.poll(now, rng).1, "idle");
    }

    /// Poll at every wake-up until `until`, returning the events seen.
    fn run(side: &mut Side, until: Ticks, rng: &mut DeterministicRng) -> Vec<&'static str> {
        let mut events = Vec::new();
        while let Some(wake) = side.tunnel.next_wake().filter(|w| *w <= until) {
            loop {
                match side.poll(wake, rng) {
                    (_, "idle") => break,
                    (_, event) => events.push(event),
                }
            }
        }
        events
    }

    /// The session each side sends on, as `(local index, peer index)`.
    fn sends_on(side: &Side) -> (u32, u32) {
        let current = side.tunnel.sessions.current().expect("a current session");
        (current.keys.local_index, current.keys.peer_index)
    }

    /// Everything both sides have to send right now — handshake messages,
    /// keepalives — delivered at once, replies included, until neither has
    /// anything more. Returns how many handshake initiations went out.
    fn settle(a: &mut Side, b: &mut Side, now: Ticks, rng: &mut DeterministicRng) -> usize {
        let mut initiations = 0;
        for _ in 0..16 {
            let mut quiet = true;
            for a_sends in [true, false] {
                let (from, to) = if a_sends {
                    (&mut *a, &mut *b)
                } else {
                    (&mut *b, &mut *a)
                };
                while let (Some(datagram), _) = from.poll(now, rng) {
                    quiet = false;
                    initiations += usize::from(datagram.len() == INIT_LEN);
                    if let (Some(reply), _) = to.recv(now, from.addr, &datagram, rng) {
                        let _ = from.recv(now, to.addr, &reply, rng);
                    }
                }
            }
            if quiet {
                break;
            }
        }
        initiations
    }

    /// Crossed handshakes do not always end with both sides on one
    /// session — and nothing is lost when they do not.
    ///
    /// Both first initiations are lost. B retransmits; A answers it while
    /// its own first initiation is the one in flight, and that response
    /// is slow. Then A's retransmission comes due and replaces the
    /// initiation in flight; B answers it, and each side completes the
    /// handshake it began. To B the two crossed (it answered A's while its
    /// own was in flight). To A they did not: the session it answered B
    /// with is marked as crossed with an initiation that has since been
    /// replaced. So A keeps the session it initiated as simply the newer
    /// one, B's tie-break may keep B's — and each side sends on the
    /// session it initiated.
    ///
    /// That is two live key pairs instead of one, for as long as it takes
    /// one of them to be replaced: both sessions are valid on both sides,
    /// every packet is delivered, each side rekeys the session it
    /// initiated when that is due, and the first handshake after that
    /// puts both on the same session again. (Making the mark follow the
    /// retransmission settles this schedule at once and was tried; over
    /// thousands of random schedules it traded these stretches for
    /// shorter ones in which each side sends on the session it did *not*
    /// initiate — a few of them against the Linux implementation, where
    /// there are none now. So it stays as it is, and is documented.)
    #[test]
    fn crossed_handshakes_that_do_not_settle_lose_nothing_and_settle_at_the_next_rekey() {
        const MS: u64 = 1_000_000;
        let (mut split, mut settled_at_once) = (0, 0);
        for seed in 0..24u64 {
            let (mut a, mut b, mut rng) = pair(700 + seed);
            let t0 = Ticks::from_secs(1000);
            b.tunnel.request_handshake(t0);
            let _lost = b.poll(t0, &mut rng).0.expect("B's first initiation");
            let ta = t0.add_nanos(400 * MS);
            a.tunnel.request_handshake(ta);
            let _lost = a.poll(ta, &mut rng).0.expect("A's first initiation");
            let due_b = b.tunnel.timer(Timer::RetransmitHandshake).unwrap();
            let due_a = a.tunnel.timer(Timer::RetransmitHandshake).unwrap();
            if due_b >= due_a {
                continue; // the jitter put A's retransmission first
            }
            // B retransmits; A answers; the answer is slow.
            let init_b2 = b.poll(due_b, &mut rng).0.expect("B's retransmission");
            let resp_a = a
                .recv(due_b.add_nanos(MS), b.addr, &init_b2, &mut rng)
                .0
                .expect("A answers B");
            // A's retransmission replaces its initiation in flight.
            let init_a2 = a.poll(due_a, &mut rng).0.expect("A's retransmission");
            let t = due_a.add_nanos(20 * MS);
            let resp_b = b
                .recv(t, a.addr, &init_a2, &mut rng)
                .0
                .expect("B answers A");
            assert_eq!(
                a.recv(t.add_nanos(MS), b.addr, &resp_b, &mut rng),
                (None, None)
            );
            assert_eq!(
                b.recv(t.add_nanos(2 * MS), a.addr, &resp_a, &mut rng),
                (None, None)
            );
            let _ = settle(&mut a, &mut b, t.add_nanos(3 * MS), &mut rng);

            let one_session = |a: &Side, b: &Side| {
                let (on_a, on_b) = (sends_on(a), sends_on(b));
                (on_a.0, on_a.1) == (on_b.1, on_b.0)
            };
            if one_session(&a, &b) {
                settled_at_once += 1;
                continue;
            }
            split += 1;
            // Each is the initiator of the session it sends on.
            for side in [&a, &b] {
                assert!(side.tunnel.sessions.current().unwrap().keys.is_initiator);
            }
            // Traffic both ways, once a second: every packet is
            // delivered, and before long both sides are on one session.
            let mut settled = None;
            let mut initiations = 0;
            for second in 1..=200u64 {
                let now = t.add_nanos(second * S);
                let from_a = a.send(now, b"a to b").expect("A has a session");
                assert_eq!(
                    b.recv(now, a.addr, &from_a, &mut rng),
                    (None, None),
                    "seed {seed}, {second} s: a packet from A was not delivered"
                );
                let from_b = b.send(now, b"b to a").expect("B has a session");
                assert_eq!(
                    a.recv(now, b.addr, &from_b, &mut rng),
                    (None, None),
                    "seed {seed}, {second} s: a packet from B was not delivered"
                );
                initiations += settle(&mut a, &mut b, now, &mut rng);
                if settled.is_none() && one_session(&a, &b) {
                    settled = Some(second);
                }
            }
            // With the first rekey — Rekey-After-Time after the sessions
            // were made — and not later.
            let settled = settled.unwrap_or_else(|| panic!("seed {seed}: never settled"));
            assert!(
                (110..=130).contains(&settled),
                "seed {seed}: settled after {settled} s"
            );
            assert!(one_session(&a, &b), "seed {seed}: and it stays settled");
            // No handshake storm on the way: a rekey or two.
            assert!(
                (1..=4).contains(&initiations),
                "seed {seed}: {initiations} initiations"
            );
        }
        // Both outcomes came up.
        assert!(
            split > 0 && settled_at_once > 0,
            "{split} split, {settled_at_once} not"
        );
    }

    /// The layout the definition of `Tunnel` describes, held to it: the
    /// fields a data packet uses are in the first lines, the session
    /// cells start on a line and keep their hot part in two of them, and
    /// the replay bitmap starts on the third.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn the_data_path_fields_are_together() {
        use crate::session::Session;
        use core::mem::{align_of, offset_of, size_of};
        type T = Tunnel<InTree>;
        assert_eq!(align_of::<T>(), 64);
        // Line 0.
        assert_eq!(offset_of!(T, last_now), 0);
        for offset in [
            offset_of!(T, endpoint),
            offset_of!(T, mtu),
            offset_of!(T, handshake_wanted),
            offset_of!(T, keepalive_staged),
            offset_of!(T, has_candidate),
            offset_of!(T, sessions_created),
        ] {
            assert!(offset < 64, "{offset}");
        }
        // Lines 1-2, 3-4.
        assert_eq!(offset_of!(T, timers), 64);
        assert_eq!(size_of::<TimerTable>(), 128);
        assert_eq!(offset_of!(T, stats), 192);
        // What a data packet counts is in the first of the two.
        for offset in [
            offset_of!(Stats, tx_transport),
            offset_of!(Stats, rx_transport),
            offset_of!(Stats, tx_bytes),
            offset_of!(Stats, rx_bytes),
            offset_of!(Stats, tx_keepalives),
            offset_of!(Stats, rx_keepalives),
        ] {
            assert!(offset < 64, "{offset}");
        }
        // The sessions: roles first, cells on a line, eighteen lines each.
        let sessions = offset_of!(T, sessions);
        assert_eq!(sessions, 320);
        let first_cell = sessions + Sessions::CELLS_OFFSET;
        assert_eq!(first_cell % 64, 0);
        assert_eq!(size_of::<Session>(), 18 * 64);
        // A cell: keys and counters in two lines, then the bitmap.
        assert!(offset_of!(Session, send_counter) < 128);
        assert!(offset_of!(Session, confirmed) < 128);
        assert!(offset_of!(Session, created) < 128);
        assert_eq!(
            offset_of!(Session, replay) + crate::replay::ReplayWindow::BITMAP_OFFSET,
            128
        );
        // Everything else comes after the sessions.
        let after = sessions + size_of::<Sessions>();
        for offset in [
            offset_of!(T, inflight),
            offset_of!(T, candidate),
            offset_of!(T, local_static),
            offset_of!(T, psk),
            offset_of!(T, precomputed_ss),
            offset_of!(T, indices),
        ] {
            assert!(offset >= after, "{offset}");
        }
        // And the size the README states.
        assert_eq!(size_of::<T>(), 4736);
    }

    #[test]
    fn a_new_tunnel_holds_no_ephemeral_secrets() {
        let (a, b, _) = pair(1);
        assert!(a.holds_no_ephemeral_secrets() && b.holds_no_ephemeral_secrets());
    }

    /// §6.3: after 3 × Reject-After-Time without a new session the session
    /// keys are gone from the tunnel's memory — in either role. (As
    /// responder the session reached `current` by promotion from `next`.)
    #[test]
    fn the_key_wipe_leaves_no_session_key_in_either_role() {
        let (mut a, mut b, mut rng) = pair(2);
        let t0 = Ticks::from_secs(1);
        establish(&mut a, &mut b, t0, &mut rng);
        assert!(!a.tunnel.sessions.is_wiped() && !b.tunnel.sessions.is_wiped());
        assert!(!a.tunnel.sessions.has_stray_keys() && !b.tunnel.sessions.has_stray_keys());
        assert!(a.tunnel.sessions.current().unwrap().keys.is_initiator);
        assert!(!b.tunnel.sessions.current().unwrap().keys.is_initiator);

        let wipe_at = t0.add_nanos(SESSION_DISCARD_TIME);
        for side in [&mut a, &mut b] {
            // One nanosecond early: still there.
            let events = run(side, Ticks::from_nanos(wipe_at.nanos() - 1), &mut rng);
            assert!(!events.contains(&"sessions_expired"));
            assert!(!side.tunnel.sessions.is_wiped());
            assert_eq!(run(side, wipe_at, &mut rng), ["sessions_expired"]);
            assert!(side.holds_no_ephemeral_secrets());
        }
    }

    /// `reset` leaves nothing: sessions in all three roles, an initiation
    /// in flight and a cookie are all wiped where they lie.
    #[test]
    fn reset_leaves_no_ephemeral_secrets() {
        let (mut a, mut b, mut rng) = pair(3);
        establish(&mut a, &mut b, Ticks::from_secs(1), &mut rng);
        // A second session (previous + current), one answered (next), and
        // an initiation of A's own in flight.
        establish(&mut a, &mut b, Ticks::from_secs(10), &mut rng);
        let t = Ticks::from_secs(20);
        b.tunnel.request_handshake(t);
        let init = b.poll(t, &mut rng).0.unwrap();
        assert!(a.recv(t, b.addr, &init, &mut rng).0.is_some());
        let t = Ticks::from_secs(30);
        a.tunnel.request_handshake(t);
        assert!(a.poll(t, &mut rng).0.is_some());
        assert!(a.tunnel.sessions.get(Slot::Previous).is_some());
        assert!(a.tunnel.sessions.get(Slot::Current).is_some());
        assert!(a.tunnel.sessions.get(Slot::Next).is_some());
        assert!(a.tunnel.inflight.active && !a.tunnel.inflight.state.is_blank());
        assert!(!a.tunnel.sessions.has_stray_keys());

        a.tunnel.reset();
        assert!(a.holds_no_ephemeral_secrets());
        assert!(!a.tunnel.cookie.is_some());
        assert_eq!(a.tunnel.next_wake(), None);
    }

    /// A response that does not authenticate leaves no derived keys
    /// behind, and the handshake it claimed to answer is still in flight.
    #[test]
    fn a_rejected_response_leaves_no_keys_and_keeps_the_handshake() {
        // B has a different pre-shared key: its response is well-formed
        // and fails only at the very last step, after the session keys
        // could be derived.
        let (mut a, mut b, mut rng) = pair_with_psk(4, [1; 32], [2; 32]);
        let now = Ticks::from_secs(1);
        a.tunnel.request_handshake(now);
        let init = a.poll(now, &mut rng).0.unwrap();
        let resp = b.recv(now, a.addr, &init, &mut rng).0.unwrap();
        let index = a.tunnel.inflight.index();
        assert_eq!(
            a.recv(now, b.addr, &resp, &mut rng),
            (None, Some(DropReason::AuthFailure))
        );
        assert!(a.tunnel.sessions.is_wiped(), "no session, no staged keys");
        assert!(a.tunnel.inflight.active);
        assert_eq!(a.tunnel.inflight.index(), index);
        assert!(!a.tunnel.inflight.state.is_blank());
    }

    /// Every retransmission replaces the ephemeral key in place; giving
    /// up wipes it.
    #[test]
    fn retransmissions_replace_the_ephemeral_and_giving_up_wipes_it() {
        let (mut a, _b, mut rng) = pair(5);
        let now = Ticks::from_secs(1);
        a.tunnel.request_handshake(now);
        assert!(a.poll(now, &mut rng).0.is_some());
        let first = a.tunnel.inflight.index().unwrap();
        assert!(a.tunnel.inflight.staged.is_blank(), "nothing left staged");

        let retry_at = a.tunnel.timer(Timer::RetransmitHandshake).unwrap();
        assert!(a.poll(retry_at, &mut rng).0.is_some());
        let second = a.tunnel.inflight.index().unwrap();
        assert_ne!(first, second);
        assert!(a.tunnel.inflight.active && !a.tunnel.inflight.state.is_blank());
        assert!(a.tunnel.inflight.staged.is_blank());

        let events = run(&mut a, now.add_nanos(REKEY_ATTEMPT_TIME + 10 * S), &mut rng);
        assert_eq!(events.last(), Some(&"handshake_expired"));
        assert!(a.holds_no_ephemeral_secrets());
    }

    /// An initiation that cannot be built (no entropy) changes nothing:
    /// the one in flight stays, and nothing is left in the staging area.
    /// An entropy source that works for the first `good` requests and
    /// fails from then on.
    struct FailsAfter {
        inner: DeterministicRng,
        good: u32,
    }

    impl EntropySource for FailsAfter {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), crate::EntropyError> {
            match self.good.checked_sub(1) {
                Some(left) => {
                    self.good = left;
                    self.inner.fill(buf)
                }
                None => Err(crate::EntropyError),
            }
        }
    }

    /// A handshake message takes several draws: the ephemeral key, then
    /// the timer jitters. Whichever of them fails, the message is not
    /// made, nothing is committed, and the same call succeeds once the
    /// source works again.
    #[test]
    fn an_entropy_failure_at_any_draw_makes_no_handshake_message() {
        // The initiation: three draws.
        for good in 0..3 {
            let (mut a, _b, mut rng) = pair(50 + u64::from(good));
            let now = Ticks::from_secs(1);
            a.tunnel.request_handshake(now);
            let mut failing = FailsAfter {
                inner: DeterministicRng::new(1),
                good,
            };
            let mut out = [0u8; 256];
            assert_eq!(
                a.tunnel.poll(now, &mut out, &mut failing).map(|_| ()),
                Err(Error::EntropyFailure),
                "draw {good}"
            );
            assert!(a.holds_no_ephemeral_secrets(), "draw {good}");
            assert_eq!(a.tunnel.stats().handshakes_initiated, 0);
            // Still due, and made by the next call.
            assert_eq!(a.tunnel.next_wake(), Some(now));
            assert!(a.poll(now, &mut rng).0.is_some_and(|d| d.len() == INIT_LEN));
        }
        // With all three it is made.
        let (mut a, _b, _) = pair(53);
        let now = Ticks::from_secs(1);
        a.tunnel.request_handshake(now);
        let mut enough = FailsAfter {
            inner: DeterministicRng::new(1),
            good: 3,
        };
        let mut out = [0u8; 256];
        assert!(matches!(
            a.tunnel.poll(now, &mut out, &mut enough),
            Ok(PollOutput::Transmit(..))
        ));

        // The response: two draws.
        for good in 0..2 {
            let (mut a, mut b, mut rng) = pair(60 + u64::from(good));
            let now = Ticks::from_secs(1);
            a.tunnel.request_handshake(now);
            let init = a.poll(now, &mut rng).0.unwrap();
            let mut failing = FailsAfter {
                inner: DeterministicRng::new(2),
                good,
            };
            let mut copy = init.clone();
            let mut out = [0xeeu8; 256];
            let got = b
                .device
                .receive_for(
                    &mut b.tunnel,
                    now,
                    a.addr,
                    false,
                    &mut copy,
                    &mut out,
                    &mut failing,
                )
                .map(|_| ());
            assert_eq!(got, Err(Error::EntropyFailure), "draw {good}");
            // Nothing to send is left in the buffer: as it was, or zeroed.
            assert!(
                out[..HANDSHAKE_RESPONSE_LEN]
                    .iter()
                    .all(|b| *b == 0xee || *b == 0),
                "draw {good}"
            );
            assert!(out[HANDSHAKE_RESPONSE_LEN..].iter().all(|b| *b == 0xee));
            // No session, no timestamp on record: the same initiation is
            // answered when the source works again.
            assert!(b.holds_no_ephemeral_secrets(), "draw {good}");
            assert_eq!(b.tunnel.stats().handshakes_responded, 0);
            assert!(b.tunnel.greatest_timestamp.is_none());
            let (response, dropped) = b.recv(now, a.addr, &init, &mut rng);
            assert_eq!(dropped, None);
            assert!(response.is_some_and(|d| d.len() == HANDSHAKE_RESPONSE_LEN));
        }
    }

    #[test]
    fn a_failed_initiation_keeps_the_one_in_flight() {
        let (mut a, _b, mut rng) = pair(6);
        let now = Ticks::from_secs(1);
        a.tunnel.request_handshake(now);
        assert!(a.poll(now, &mut rng).0.is_some());
        let index = a.tunnel.inflight.index();
        let retry_at = a.tunnel.timer(Timer::RetransmitHandshake).unwrap();
        let mut buf = [0u8; INIT_LEN];
        assert_eq!(
            a.tunnel.poll(retry_at, &mut buf, &mut FailingRng).err(),
            Some(Error::EntropyFailure)
        );
        assert_eq!(buf, [0u8; INIT_LEN], "nothing was written");
        assert_eq!(a.tunnel.inflight.index(), index);
        assert!(a.tunnel.inflight.staged.is_blank());
        // The retransmission is still due, and works once entropy is back.
        assert!(a.poll(retry_at, &mut rng).0.is_some());
        assert_ne!(a.tunnel.inflight.index(), index);
    }

    /// A session we answered that the peer never uses is wiped after
    /// Reject-After-Time (a peer that sends initiations and nothing else
    /// must not be able to park key material here).
    #[test]
    fn a_pending_session_nobody_uses_is_wiped_when_it_expires() {
        let (mut a, mut b, mut rng) = pair(7);
        let now = Ticks::from_secs(1);
        a.tunnel.request_handshake(now);
        let init = a.poll(now, &mut rng).0.unwrap();
        assert!(b.recv(now, a.addr, &init, &mut rng).0.is_some());
        assert!(b.tunnel.sessions.get(Slot::Next).is_some());
        let expires = now.add_nanos(REJECT_AFTER_TIME);
        assert_eq!(b.tunnel.next_wake(), Some(expires));
        assert!(run(&mut b, Ticks::from_nanos(expires.nanos() - 1), &mut rng).is_empty());
        assert!(b.tunnel.sessions.get(Slot::Next).is_some());
        assert!(
            run(&mut b, expires, &mut rng).is_empty(),
            "nothing to report"
        );
        assert!(b.holds_no_ephemeral_secrets());
        assert_eq!(b.tunnel.next_wake(), None);
    }

    /// §6.2: a session is rekeyed after Rekey-After-Messages messages,
    /// whichever side sends them, and refuses to send at
    /// Reject-After-Messages. (2⁶⁰ messages cannot be sent in a test, so
    /// the counter is set.)
    #[test]
    fn rekey_and_reject_after_messages() {
        for sender_is_initiator in [true, false] {
            let (mut a, mut b, mut rng) = pair(8);
            let now = Ticks::from_secs(1);
            establish(&mut a, &mut b, now, &mut rng);
            let side = if sender_is_initiator { &mut a } else { &mut b };
            side.tunnel
                .sessions
                .get_mut(Slot::Current)
                .unwrap()
                .send_counter = REKEY_AFTER_MESSAGES - 2;
            // Message number Rekey-After-Messages − 1: nothing yet.
            assert!(side.send(now, b"x").is_some());
            assert_eq!(side.tunnel.timer(Timer::SendInitiation), None);
            assert_eq!(side.poll(now, &mut rng).1, "idle");
            // Message number Rekey-After-Messages: a handshake is wanted.
            // (It goes out when the pacing since the last handshake
            // message allows.)
            assert!(side.send(now, b"x").is_some());
            let at = side
                .tunnel
                .timer(Timer::SendInitiation)
                .expect("a rekey is scheduled");
            let (datagram, _) = side.poll(at, &mut rng);
            assert_eq!(datagram.map(|d| (d[0], d.len())), Some((1, INIT_LEN)));

            // The session keeps working up to Reject-After-Messages…
            side.tunnel
                .sessions
                .get_mut(Slot::Current)
                .unwrap()
                .send_counter = REJECT_AFTER_MESSAGES - 1;
            assert!(side.send(at, b"x").is_some());
            // …and then refuses.
            assert!(side.send(at, b"x").is_none());
            assert!(!side.tunnel.is_established(at));
        }
    }

    /// The device never hands out an identified initiation without the
    /// caller asking: `receive` itself costs no Diffie-Hellman, and what
    /// `identify` writes into the initiation is exactly what the tunnel
    /// would compute itself.
    #[test]
    fn identifying_in_the_device_or_in_the_tunnel_is_the_same() {
        let (mut a, mut b, mut rng) = pair(9);
        let now = Ticks::from_secs(1);
        a.tunnel.request_handshake(now);
        let init = a.poll(now, &mut rng).0.unwrap();

        // Identified by the device first.
        let mut copy = init.clone();
        let Incoming::Initiation(mut initiation) = b.device.receive(now, a.addr, false, &mut copy)
        else {
            panic!("expected an initiation")
        };
        assert!(!initiation.identity.known);
        assert_eq!(initiation.peer_public(), None);
        let claimed = b.device.identify(&mut initiation).unwrap();
        assert_eq!(claimed, a.device.public_key());
        assert_eq!(
            b.device.identify(&mut initiation),
            Ok(claimed),
            "idempotent"
        );
        let mut out = [0u8; 128];
        assert!(matches!(
            b.tunnel
                .handle_initiation(now, &initiation, &mut out, &mut rng)
                .unwrap()
                .received,
            Received::HandshakeResponse(_)
        ));

        // Left to the tunnel: the same initiation is now a replay, which
        // is only found out after the identity and the timestamp have
        // been decrypted — so the tunnel did identify it.
        let mut copy = init.clone();
        let Incoming::Initiation(initiation) = b.device.receive(now, a.addr, false, &mut copy)
        else {
            panic!("expected an initiation")
        };
        let handled = b
            .tunnel
            .handle_initiation(now, &initiation, &mut out, &mut rng)
            .unwrap();
        assert!(matches!(
            handled.received,
            Received::Dropped(DropReason::ReplayedTimestamp)
        ));
    }
}
