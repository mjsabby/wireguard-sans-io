//! The sans-I/O front end shared by every peer of one local identity.
//!
//! A [`Device`] owns what belongs to the *interface* rather than to any
//! one peer: the static private key, the `mac1` and cookie state that are
//! keyed by our own public key, the key that makes session indices
//! routable, and the wall-clock anchor. Per-peer state lives in a
//! [`Tunnel`], which the device creates.
//!
//! Every inbound datagram goes through [`Device::receive`] first. It does
//! the cheap work that must happen before the peer is known — and only
//! that:
//!
//! | message | `receive` does | then |
//! |---|---|---|
//! | handshake initiation | `mac1`, cookie gate | [`Incoming::Initiation`]: [`Device::identify`] (**one** X25519) tells whose it is; look that peer up by public key |
//! | handshake response | `mac1`, cookie gate, decodes the index | [`Incoming::ForPeer`] |
//! | cookie reply | decodes the index | [`Incoming::ForPeer`] |
//! | transport data | decodes the index | [`Incoming::ForPeer`] |
//!
//! So routing costs the same however many peers are configured, the
//! caller's peer table is the only table there is, and the device itself
//! allocates nothing.
//!
//! `receive` never does a Diffie-Hellman operation. The one that an
//! initiation needs before its sender is known happens in
//! [`Device::identify`], a separate call that takes `&self` — which leaves
//! the caller a place to decide, per source address, whether to spend it
//! (see [`Initiation::source_verified`]), and lets several of them run at
//! once.
//!
//! # One device, several threads
//!
//! Everything a device needs to *route* is fixed when it is made: its
//! keys. What changes while it receives is small — its counters, and the
//! cookie secret, which is only looked at while under load. So there are
//! two ways to call it:
//!
//! * [`Device::receive`] and [`Device::cookie_reply`] take `&mut self`
//!   and keep both inside the device. One thread, nothing to arrange.
//! * [`Device::receive_shared`] and [`Device::cookie_reply_shared`] take
//!   `&self`, and are handed what changes: counters of the caller's (one
//!   set per thread) and a [`CookieState`]. The device itself is then
//!   shared by plain reference — an `Arc<Device>`, no lock — and so is
//!   [`Device::identify`]: no datagram of any peer ever waits for another
//!   thread's handshake arithmetic. Only the `CookieState` needs a lock
//!   of its own, and only handshake messages that arrive under load ask
//!   for it.

use core::marker::PhantomData;
use core::net::SocketAddr;

use crate::consts::TRANSPORT_HEADER_LEN;
use crate::cookie::{self, CookieJar, DeviceMacKeys, RemoteBytes};
use crate::crypto::{CryptoProvider, InTree, ct};
use crate::debug::{Addr, debug_struct};
use crate::entropy::EntropySource;
use crate::error::{DropReason, Error};
use crate::index::{IndexCodec, PeerId};
use crate::keys::{PublicKey, StaticSecret};
use crate::message::{
    self, CookieReply, HandshakeInitiation, HandshakeResponse, Packet, PacketKind,
};
use crate::noise::{self, HandshakeConstants, Identity};
use crate::time::{Ticks, WallClock};
use crate::tunnel::{Handled, PeerConfig, Received, Transmit, Tunnel};

/// A datagram the [`Device`] has routed to one peer; pass it to that
/// peer's [`Tunnel::handle`].
///
/// It can only be obtained from [`Device::receive`], so a handshake
/// response that reaches a tunnel has always passed the `mac1` check (and,
/// under load, the cookie check).
#[derive(Debug)]
pub struct PeerPacket<'d> {
    pub(crate) kind: PeerPacketKind<'d>,
    /// A handshake response whose `mac2` was checked and valid.
    source_verified: bool,
}

impl PeerPacket<'_> {
    /// Is this a handshake response? It is the one kind of routed datagram
    /// that can cost Diffie-Hellman operations (two X25519, and only when
    /// its index matches an initiation the tunnel has in flight);
    /// everything else is rejected or processed with symmetric
    /// cryptography alone.
    #[must_use]
    pub fn is_handshake(&self) -> bool {
        matches!(self.kind, PeerPacketKind::Response(_))
    }

    /// For a handshake response: did a valid cookie (`mac2`) prove that
    /// its sender receives datagrams at the source address? See
    /// [`Initiation::source_verified`]; the same holds here.
    #[must_use]
    pub fn source_verified(&self) -> bool {
        self.source_verified
    }
}

pub(crate) enum PeerPacketKind<'d> {
    /// Handshake response; `mac1` verified.
    Response(HandshakeResponse<'d>),
    /// Cookie reply.
    CookieReply(CookieReply<'d>),
    /// Transport data; `body` is `ciphertext ∥ tag`, decrypted in place.
    Transport {
        receiver_index: u32,
        counter: u64,
        body: &'d mut [u8],
    },
}

impl core::fmt::Debug for PeerPacketKind<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Response(msg) => f.debug_tuple("Response").field(msg).finish(),
            Self::CookieReply(msg) => f.debug_tuple("CookieReply").field(msg).finish(),
            // The body is decrypted in place: by its size only.
            Self::Transport {
                receiver_index,
                counter,
                body,
            } => write!(
                f,
                "Transport {{ receiver_index: {receiver_index:#010x}, counter: {counter}, \
                 body: {} bytes }}",
                body.len()
            ),
        }
    }
}

/// A handshake initiation that passed the `mac1` check and, while under
/// load, the cookie check — and nothing else yet. No Diffie-Hellman
/// operation has been spent on it.
///
/// What to do with it:
///
/// 1. Decide whether to go on. This is the place for a **per-source rate
///    limit**, applied when (and only when)
///    [`source_verified`](Self::source_verified) is true.
/// 2. [`Device::identify`] — one X25519 — returns the static public key
///    the initiator claims. Look that peer up; if there is none, drop the
///    initiation: nothing has been sent and no state has changed.
/// 3. Pass it to that peer's [`Tunnel::handle_initiation`].
///
/// With a single peer, steps 2 and 3 are one: a tunnel that is handed an
/// initiation nobody has identified does it itself.
///
/// The sender is **not authenticated** until the tunnel accepts the
/// initiation. After `identify` it has shown that it knows *our* public
/// key and holds the private key of the ephemeral it sent; it has not been
/// shown to hold the private key of the static key it claims (the tunnel
/// verifies that), and the message may be a replay. Do not treat
/// [`src`](Self::src) as the peer's address before then.
///
/// After `identify` this value holds handshake state that is secret. It is
/// wiped when the value is dropped; pass it on by reference and let it go
/// out of scope rather than storing or moving it (a moved value leaves a
/// copy of its bytes behind).
pub struct Initiation<'d> {
    pub(crate) msg: HandshakeInitiation<'d>,
    pub(crate) src: SocketAddr,
    source_verified: bool,
    pub(crate) identity: Identity,
}

impl Initiation<'_> {
    /// The address the datagram came from. The handshake response goes
    /// back there.
    #[must_use]
    pub fn src(&self) -> SocketAddr {
        self.src
    }

    /// Did a valid cookie (`mac2`) prove that the sender receives
    /// datagrams at [`src`](Self::src)?
    ///
    /// Cookies are only checked while you assert `under_load`, so this is
    /// true exactly when the initiation arrived under load — every
    /// initiation that gets this far then carries a valid cookie — and
    /// false otherwise.
    ///
    /// Rate-limit per source address **only when this is true**. A source
    /// address that no cookie has proven costs nothing to forge: a limiter
    /// keyed on it lets anyone who knows your public key use up the
    /// allowance of an address of their choosing and so lock that peer
    /// out. (When not under load there is nothing to limit by; the remedy
    /// for too many handshakes is to assert `under_load`.)
    #[must_use]
    pub fn source_verified(&self) -> bool {
        self.source_verified
    }

    /// The initiator's session index (the `sender` field on the wire).
    #[must_use]
    pub fn sender_index(&self) -> u32 {
        self.msg.sender_index
    }

    /// The static public key the initiator claims, once
    /// [`Device::identify`] has revealed it.
    #[must_use]
    pub fn peer_public(&self) -> Option<PublicKey> {
        self.identity
            .known
            .then(|| PublicKey::from_bytes(self.identity.static_public))
    }
}

impl core::fmt::Debug for Initiation<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Initiation")
            .field("src", &Addr(self.src))
            .field("sender_index", &self.msg.sender_index)
            .field("source_verified", &self.source_verified)
            .field("peer_public", &self.peer_public())
            .finish()
    }
}

/// What a datagram is, before its receiver index (if it has one) is
/// turned into a peer id.
enum Classified<'d> {
    Initiation(Initiation<'d>),
    /// Addressed to the session or handshake with this receiver index.
    Indexed(u32, PeerPacket<'d>),
    CookieRequired(CookieChallenge),
    Dropped(DropReason),
}

/// A handshake message that passed `mac1` but, while under load, carried
/// no valid `mac2`. Answer it with [`Device::cookie_reply`] (whitepaper
/// §5.3) — or ignore it; either is allowed.
///
/// Whoever sent it is **not** authenticated: it only shows knowledge of
/// our public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CookieChallenge {
    src: SocketAddr,
    sender_index: u32,
    mac1: [u8; 16],
}

impl core::fmt::Debug for CookieChallenge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CookieChallenge")
            .field("src", &Addr(self.src))
            .field("sender_index", &self.sender_index)
            .field("mac1", &self.mac1)
            .finish()
    }
}

impl CookieChallenge {
    /// The address the handshake message came from; the cookie reply goes
    /// back there.
    #[must_use]
    pub fn src(&self) -> SocketAddr {
        self.src
    }
}

/// What [`Device::receive`] made of one datagram.
#[derive(Debug)]
#[non_exhaustive]
pub enum Incoming<'d> {
    /// A handshake initiation with a valid `mac1` (and, under load, a
    /// valid cookie). [`Device::identify`] tells which peer it claims to
    /// be from; that peer's [`Tunnel::handle_initiation`] processes it.
    /// See [`Initiation`].
    Initiation(Initiation<'d>),
    /// A datagram addressed to one of the sessions of the peer with this
    /// id. Find that peer's tunnel and call [`Tunnel::handle`]; if there
    /// is no such peer, drop it.
    ///
    /// The id is decoded from the receiver index and is always well
    /// formed, but nothing has been authenticated yet: an attacker can
    /// make any id come out. The tunnel checks.
    ForPeer(PeerId, PeerPacket<'d>),
    /// Under load, a handshake message without a valid cookie. Answer with
    /// [`Device::cookie_reply`]. The sender is not authenticated.
    CookieRequired(CookieChallenge),
    /// Rejected: drop it silently.
    Dropped(DropReason),
}

/// Per-device observability counters, cumulative since construction.
///
/// # ⚠️ Sensitivity
///
/// These are **attacker-influenceable**: an unauthenticated observer of
/// `mac1_failures` can confirm this endpoint's static public key, and one
/// of `cookies_sent` can probe its load state. Aggregate before
/// publishing, or restrict who can read them.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceStats {
    /// Datagrams dropped as structurally invalid.
    pub malformed: u64,
    /// Handshake messages dropped for a bad `mac1`.
    pub mac1_failures: u64,
    /// Handshake initiations that passed the MAC checks and were handed
    /// out as [`Incoming::Initiation`] (or, by [`Device::receive_for`], to
    /// the tunnel). What became of them is not counted here:
    /// [`Device::identify`] takes `&self` and reports its outcome to the
    /// caller.
    pub initiations: u64,
    /// Handshake messages that needed a cookie while under load
    /// ([`Incoming::CookieRequired`]).
    pub cookies_required: u64,
    /// Cookie replies built by [`Device::cookie_reply`].
    pub cookies_sent: u64,
    /// Datagrams [`Device::receive`] routed to a peer by their receiver
    /// index ([`Incoming::ForPeer`]). [`Device::receive_for`] has nothing
    /// to route and does not count here — which is how a single-peer
    /// embedder can check that its data path does not pay for routing.
    pub routed: u64,
}

debug_struct!(DeviceStats {
    malformed,
    mac1_failures,
    initiations,
    cookies_required,
    cookies_sent,
    routed,
});

impl DeviceStats {
    /// Nothing counted yet.
    const ZERO: Self = Self {
        malformed: 0,
        mac1_failures: 0,
        initiations: 0,
        cookies_required: 0,
        cookies_sent: 0,
        routed: 0,
    };

    /// Add `other`'s counts to these. For a device that several threads
    /// share ([`Device::receive_shared`]): each thread counts for itself,
    /// and whoever wants the totals adds them up.
    pub fn merge(&mut self, other: &Self) {
        self.malformed = self.malformed.saturating_add(other.malformed);
        self.mac1_failures = self.mac1_failures.saturating_add(other.mac1_failures);
        self.initiations = self.initiations.saturating_add(other.initiations);
        self.cookies_required = self.cookies_required.saturating_add(other.cookies_required);
        self.cookies_sent = self.cookies_sent.saturating_add(other.cookies_sent);
        self.routed = self.routed.saturating_add(other.routed);
    }
}

/// The cookie secret of one [`Device`] and the clock it ages by: the one
/// part of receiving that changes from datagram to datagram.
///
/// A device has one of its own, which [`Device::receive`] and
/// [`Device::cookie_reply`] use — that is why those two take `&mut self`.
/// A device that several threads share is called through
/// [`Device::receive_shared`] and [`Device::cookie_reply_shared`]
/// instead: they take `&self` and are handed the cookie state. Keep one
/// `CookieState` next to such a device, behind a lock of its own. It is
/// asked for only while under load — shared, to check a cookie;
/// exclusively, to make a cookie reply — so transport data never waits
/// for it, and nothing at all waits for [`Device::identify`].
///
/// A cookie is good only for the state that made it. Use one state with a
/// device: not this one and the device's own in turn, and not one per
/// thread (a cookie handed out by one thread would be refused by the
/// next).
///
/// Holds the cookie secrets; they are wiped when it is dropped.
pub struct CookieState {
    jar: CookieJar,
    /// The latest instant seen (cookies age by this clock): time never
    /// goes backwards here either, nor out of range.
    last_now: Ticks,
}

impl CookieState {
    /// A state without a secret: one is drawn when the first cookie reply
    /// is made.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            jar: CookieJar::new(),
            last_now: Ticks::ZERO,
        }
    }

    /// Time as this state counts it — see [`Ticks::MAX`] — moving its
    /// clock on.
    fn clamp_now(&mut self, now: Ticks) -> Ticks {
        self.last_now = now.following(self.last_now);
        self.last_now
    }

    /// The same for a state that is shared, whose clock is read and not
    /// moved: an instant before the last one the state was moved to — or
    /// out of range — counts as that one. (The clock is moved whenever a
    /// cookie reply is made, which is also the only time a secret is
    /// drawn: no instant read here is ever before the secret it is
    /// compared with.)
    fn seen(&self, now: Ticks) -> Ticks {
        now.following(self.last_now)
    }

    /// Does `mac2` show a cookie of ours for `src`, at `now` as this
    /// state counts it?
    fn accepts<P: CryptoProvider>(
        &self,
        now: Ticks,
        src: SocketAddr,
        beta: &[u8],
        mac2: &[u8; 16],
    ) -> bool {
        self.jar
            .verify_mac2::<P>(now, RemoteBytes::new(src).as_slice(), beta, mac2)
    }
}

impl Default for CookieState {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for CookieState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CookieState")
    }
}

/// Whether handshake messages have to carry a cookie, and the state to
/// check it against.
enum Load<'c> {
    /// Not under load: `mac1` is all a handshake message needs.
    Light,
    /// Under load, with a cookie state that is shared: its clock is read.
    Shared(&'c CookieState),
    /// Under load, with a cookie state that is the caller's alone: its
    /// clock moves on.
    Exclusive(&'c mut CookieState),
}

impl Load<'_> {
    fn under_load(&self) -> bool {
        !matches!(self, Self::Light)
    }
}

/// The local identity and everything its peers share.
///
/// # Example: several peers
///
/// ```
/// use core::net::SocketAddr;
/// use wireguard_sans_io::testing::DeterministicRng;
/// use wireguard_sans_io::{
///     Device, Incoming, PeerConfig, PeerId, PollOutput, Received, StaticSecret, Ticks, Tunnel,
///     WallClock,
/// };
///
/// let mut rng = DeterministicRng::new(7); // ⚠ tests only
/// let now = Ticks::ZERO;
/// let wall = WallClock::new(now, 1_700_000_000, 0);
/// let server_addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
///
/// // A server with three peers. The peer table is yours: here a Vec
/// // indexed by PeerId.
/// let server_key = StaticSecret::generate(&mut rng)?;
/// let server_pub = server_key.public_key();
/// let mut server = Device::new(server_key, wall, &mut rng)?;
/// let client_keys: Vec<StaticSecret> = (0..3)
///     .map(|_| StaticSecret::generate(&mut rng))
///     .collect::<Result<_, _>>()?;
/// let mut peers: Vec<Tunnel> = Vec::new();
/// for (i, key) in client_keys.iter().enumerate() {
///     let id = PeerId::new(i as u32).unwrap();
///     peers.push(server.tunnel(id, PeerConfig::new(key.public_key()), &mut rng)?);
/// }
///
/// // Client 2 starts a handshake.
/// let client_addr: SocketAddr = "198.51.100.2:40000".parse().unwrap();
/// let mut client_dev = Device::new(client_keys[2].clone(), wall, &mut rng)?;
/// let mut cfg = PeerConfig::new(server_pub);
/// cfg.endpoint = Some(server_addr);
/// let mut client = client_dev.tunnel(PeerId::new(0).unwrap(), cfg, &mut rng)?;
/// client.request_handshake(now);
/// let mut buf = [0u8; 256];
/// let mut datagram = match client.poll(now, &mut buf, &mut rng)? {
///     PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
///     other => panic!("{other:?}"),
/// };
///
/// // The server's receive path: one device call, one table lookup.
/// // Everything in the datagram is the sender's choice, so nothing here
/// // may panic on it: an unknown key or id is simply dropped.
/// let under_load = false; // your load signal
/// let mut out = [0u8; 256];
/// let handled = match server.receive(now, client_addr, under_load, &mut datagram) {
///     Incoming::Initiation(mut init) => {
///         // A per-source rate limit goes here — and only applies when a
///         // cookie has proven the source address:
///         // if init.source_verified() && !limiter.allow(init.src().ip()) { return Ok(()); }
///
///         // One X25519 reveals who claims to be calling…
///         let Ok(public_key) = server.identify(&mut init) else {
///             return Ok(());
///         };
///         // …and that is the key to look the peer up by.
///         let Some(peer) = peers.iter_mut().find(|t| t.peer_public() == public_key) else {
///             return Ok(());
///         };
///         peer.handle_initiation(now, &init, &mut out, &mut rng)?
///     }
///     Incoming::ForPeer(id, packet) => {
///         let Some(peer) = peers.get_mut(id.get() as usize) else {
///             return Ok(());
///         };
///         peer.handle(now, client_addr, packet)?
///     }
///     Incoming::CookieRequired(challenge) => {
///         let _reply = server.cookie_reply(now, &challenge, &mut out, &mut rng)?;
///         return Ok(());
///     }
///     Incoming::Dropped(_) => return Ok(()),
///     _ => return Ok(()),
/// };
/// assert!(matches!(handled.received, Received::HandshakeResponse(_)));
/// assert_eq!(peers[2].endpoint(), Some(client_addr));
/// # Ok::<(), wireguard_sans_io::Error>(())
/// ```
pub struct Device<P: CryptoProvider = InTree> {
    local_static: StaticSecret,
    local_public: PublicKey,
    constants: HandshakeConstants,
    mac_keys: DeviceMacKeys,
    codec: IndexCodec,
    wall_clock: WallClock,
    /// What [`Device::receive`] and [`Device::cookie_reply`] change: the
    /// cookie secret and the counters. (The calls for a shared device are
    /// handed theirs.) Nothing else in a device changes once it is made,
    /// short of [`Device::set_wall_clock`].
    cookies: CookieState,
    stats: DeviceStats,
    /// (`fn() -> P`: a provider is a type that is never made, and says
    /// nothing about whether a device may be shared between threads.)
    _provider: PhantomData<fn() -> P>,
}

impl<P: CryptoProvider> core::fmt::Debug for Device<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Device<{}>(public={:?})", P::name(), self.local_public)
    }
}

impl Device<InTree> {
    /// A device using the in-tree, safe-Rust crypto provider.
    ///
    /// `wall_clock` anchors handshake timestamps (see [`WallClock`]);
    /// `rng` supplies the key that makes session indices routable.
    ///
    /// The device is returned by value, and the caller then moves it to
    /// where it is kept — which leaves copies of the static key behind,
    /// in the caller's frames (see [`Device::new_in`], which has none of
    /// that, and `EMBEDDER_OBLIGATIONS.md` §10.4).
    ///
    /// # Errors
    /// [`Error::EntropyFailure`].
    pub fn new(
        local_static: StaticSecret,
        wall_clock: WallClock,
        rng: &mut dyn EntropySource,
    ) -> Result<Self, Error> {
        Self::with_provider(local_static, wall_clock, rng)
    }

    /// [`Device::new`], in place: the device is made in `slot`, where it
    /// is going to live. See [`Device::with_provider_in`].
    ///
    /// # Errors
    /// [`Error::EntropyFailure`]; `slot` is then empty.
    pub fn new_in<'s>(
        slot: &'s mut Option<Self>,
        local_static: &StaticSecret,
        wall_clock: WallClock,
        rng: &mut dyn EntropySource,
    ) -> Result<&'s mut Self, Error> {
        Self::with_provider_in(slot, local_static, wall_clock, rng)
    }
}

impl<P: CryptoProvider> Device<P> {
    /// A device with nothing in it. Never handed out: see
    /// [`Tunnel`]'s equivalent.
    const BLANK: Self = Self {
        local_static: StaticSecret::BLANK,
        local_public: PublicKey::from_bytes([0u8; 32]),
        constants: HandshakeConstants::BLANK,
        mac_keys: DeviceMacKeys::BLANK,
        codec: IndexCodec::BLANK,
        wall_clock: WallClock::new(Ticks::ZERO, 0, 0),
        cookies: CookieState::new(),
        stats: DeviceStats::ZERO,
        _provider: PhantomData,
    };

    /// A device with an explicit [`CryptoProvider`]. The wire format is
    /// the same for every provider.
    ///
    /// Returned by value; see [`Device::new`] on what that means for the
    /// static key, and [`Device::with_provider_in`] for the alternative.
    ///
    /// # Errors
    /// [`Error::EntropyFailure`].
    pub fn with_provider(
        local_static: StaticSecret,
        wall_clock: WallClock,
        rng: &mut dyn EntropySource,
    ) -> Result<Self, Error> {
        // The device is made in a frame of its own and moved out of it
        // to where the caller receives it; what that frame still holds of
        // it is overwritten once that has happened. (What becomes of the
        // value from there on is the caller's.)
        let mut scrub = ct::ScrubOnDrop::new();
        Self::by_value(&local_static, wall_clock, rng, scrub.low())
    }

    /// [`Self::with_provider`]'s work, in a frame that can be overwritten
    /// once this has returned; `low` is set to where that frame ends.
    #[inline(never)]
    fn by_value(
        local_static: &StaticSecret,
        wall_clock: WallClock,
        rng: &mut dyn EntropySource,
        low: &mut usize,
    ) -> Result<Self, Error> {
        *low = ct::stack_mark();
        // Made in the value that is returned, not in a local that is then
        // copied into it; see `Tunnel::build`.
        let mut made = Ok(Self::BLANK);
        let filled = match &mut made {
            Ok(device) => device.fill(local_static, wall_clock, rng),
            Err(_) => Ok(()),
        };
        if let Err(error) = filled {
            made = Err(error);
        }
        made
    }

    /// A device with an explicit [`CryptoProvider`], made in place.
    ///
    /// `slot` is where the device is going to live: a `static`, a field
    /// of a larger structure, the inside of a `Box`. The device is put
    /// together there — the static key is copied byte by byte from
    /// `local_static` to its field and exists nowhere else on the way —
    /// so nothing of it is left on the stack, and the stack is not asked
    /// to hold a device either. Whatever was in `slot` before is dropped
    /// first. `local_static` stays the caller's: drop it once the device
    /// exists (dropping wipes it).
    ///
    /// # Errors
    /// [`Error::EntropyFailure`]; `slot` is then empty.
    pub fn with_provider_in<'s>(
        slot: &'s mut Option<Self>,
        local_static: &StaticSecret,
        wall_clock: WallClock,
        rng: &mut dyn EntropySource,
    ) -> Result<&'s mut Self, Error> {
        *slot = None;
        let filled = slot.insert(Self::BLANK).fill(local_static, wall_clock, rng);
        if let Err(error) = filled {
            *slot = None;
            return Err(error);
        }
        slot.as_mut().ok_or(Error::Internal)
    }

    /// Make a blank device the device for `local_static`.
    fn fill(
        &mut self,
        local_static: &StaticSecret,
        wall_clock: WallClock,
        rng: &mut dyn EntropySource,
    ) -> Result<(), Error> {
        self.codec.regenerate(rng)?;
        self.local_static.set(local_static);
        self.local_public = PublicKey::from_bytes(P::x25519_public(self.local_static.as_bytes()));
        self.mac_keys = DeviceMacKeys::new::<P>(&self.local_public);
        self.constants = HandshakeConstants::new::<P>();
        self.wall_clock = wall_clock;
        Ok(())
    }

    /// Our static public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.local_public
    }

    /// Create the tunnel for one peer.
    ///
    /// `id` is your name for the peer: [`Device::receive`] returns it for
    /// every datagram addressed to this tunnel. Tunnels of one device
    /// that are alive at the same time must have different ids.
    ///
    /// The tunnel is self-contained: it does not borrow the device and
    /// may live on another thread.
    ///
    /// It is returned by value. A tunnel is several kilobytes: this call
    /// puts one together on the stack, the place the caller receives it
    /// in is usually on the stack as well, and wherever the value travels
    /// from there, the keys in it stay behind (the static key, the
    /// pre-shared key, the static-static Diffie-Hellman result).
    /// [`Device::tunnel_in`] makes the tunnel where it is going to live
    /// and has neither cost; it is the one to use on a small stack.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if the peer's public key equals our
    /// own or is a low-order point; [`Error::EntropyFailure`].
    pub fn tunnel(
        &self,
        id: PeerId,
        config: PeerConfig,
        rng: &mut dyn EntropySource,
    ) -> Result<Tunnel<P>, Error> {
        // As in `with_provider`: the frame the tunnel is made in.
        let mut scrub = ct::ScrubOnDrop::new();
        self.tunnel_by_value(id, &config, rng, scrub.low())
    }

    /// [`Self::tunnel`]'s work, in a frame that can be overwritten once
    /// this has returned; `low` is set to where the frames it is done in
    /// end.
    #[inline(never)]
    fn tunnel_by_value(
        &self,
        id: PeerId,
        config: &PeerConfig,
        rng: &mut dyn EntropySource,
        low: &mut usize,
    ) -> Result<Tunnel<P>, Error> {
        *low = ct::stack_mark();
        Tunnel::build(
            &self.local_static,
            self.local_public,
            &self.constants,
            self.wall_clock,
            &self.codec,
            id,
            config,
            rng,
            low,
        )
    }

    /// Create the tunnel for one peer, in place.
    ///
    /// As [`Device::tunnel`], except for where the tunnel comes into
    /// being: in `slot`, which is where it is going to live — an entry of
    /// your peer table, a `static`, the inside of a `Box`. The keys are
    /// written to their fields there and nowhere else: the static key
    /// from the device's, the pre-shared key from `config`'s (which stays
    /// yours to drop, and dropping wipes it), the static-static
    /// Diffie-Hellman result as it is computed. Nothing of the tunnel is
    /// ever on the stack, so this needs less of it than a handshake does
    /// (see the stack figures in the README), where [`Device::tunnel`]
    /// needs room for the tunnel it returns on top.
    ///
    /// Whatever was in `slot` before is dropped first.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if the peer's public key equals our
    /// own or is a low-order point; [`Error::EntropyFailure`]. `slot` is
    /// then empty.
    pub fn tunnel_in<'s>(
        &self,
        slot: &'s mut Option<Tunnel<P>>,
        id: PeerId,
        config: &PeerConfig,
        rng: &mut dyn EntropySource,
    ) -> Result<&'s mut Tunnel<P>, Error> {
        Tunnel::build_in(
            slot,
            &self.local_static,
            self.local_public,
            &self.constants,
            self.wall_clock,
            &self.codec,
            id,
            config,
            rng,
        )
    }

    /// Classify and route one received datagram.
    ///
    /// `now` is the current monotonic time (it bounds how long a cookie
    /// stays acceptable). `src` is the address the datagram came from.
    /// `under_load` is your own load
    /// signal (for example the receive queue depth, or the handshake
    /// rate); while it is `true`, handshake messages without a valid
    /// `mac2` are not processed and come back as
    /// [`Incoming::CookieRequired`] (whitepaper §5.3).
    ///
    /// This never fails and never writes anything but its own counters:
    /// whatever a remote party sends ends up as one of the [`Incoming`]
    /// variants. `datagram` is borrowed mutably because transport data is
    /// later decrypted in place by the tunnel; `receive` itself does not
    /// modify it.
    ///
    /// # Cost
    ///
    /// Cheap for every input: keyed hashes and the index decoding, and no
    /// Diffie-Hellman operation. A handshake message costs one keyed hash
    /// (`mac1`); under load, two more for the cookie check (the cookie for
    /// its source address, and the `mac2` that cookie gives the message)
    /// — and in the ten seconds after the cookie secret has changed, two
    /// more again, for the secret before. Anything else costs the index
    /// decoding alone. The expensive steps come after this call, and are
    /// yours to grant or refuse: [`Device::identify`] for an initiation,
    /// [`Tunnel::handle`] for a handshake response.
    ///
    /// Do **not** put a per-source rate limiter in front of this call.
    /// Before the MAC checks a source address is whatever the sender wrote
    /// into the packet. See [`Initiation::source_verified`] for where a
    /// limiter belongs.
    pub fn receive<'d>(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        under_load: bool,
        datagram: &'d mut [u8],
    ) -> Incoming<'d> {
        let load = if under_load {
            Load::Exclusive(&mut self.cookies)
        } else {
            Load::Light
        };
        let classified = Self::classify(&self.mac_keys, load, &mut self.stats, now, src, datagram);
        Self::route(&self.codec, &mut self.stats, classified)
    }

    /// [`Device::receive`] for a device that is shared: `&self`, with what
    /// changes handed in.
    ///
    /// * `cookies` is the load signal and the cookie state in one: `None`
    ///   while not under load; under load, the [`CookieState`] handshake
    ///   messages are checked against (the one
    ///   [`Device::cookie_reply_shared`] makes its replies with).
    /// * `stats` is where this call counts: a [`DeviceStats`] of the
    ///   caller's — one per thread, added up with [`DeviceStats::merge`]
    ///   when someone asks. [`Device::stats`] does not see it.
    ///
    /// Everything else is as in [`Device::receive`]: the same checks at
    /// the same cost, the same [`Incoming`]. What differs is who may call
    /// it when. Nothing in the device is written, so any number of
    /// threads receive at once — and next to [`Device::identify`], which
    /// takes `&self` as well: the one X25519 an initiation costs before
    /// its peer is known never stands between another datagram and its
    /// tunnel. (With `&mut self` it does, whatever the lock: a
    /// reader-writer lock held *shared* across `identify` keeps every
    /// writer out for as long, and `Device::receive` is a writer.)
    ///
    /// ```
    /// use std::sync::RwLock;
    /// use wireguard_sans_io::testing::DeterministicRng;
    /// use wireguard_sans_io::{CookieState, Device, DeviceStats, Incoming, StaticSecret, Ticks, WallClock};
    ///
    /// let mut rng = DeterministicRng::new(1); // ⚠ tests only
    /// let key = StaticSecret::generate(&mut rng)?;
    /// let device = Device::new(key, WallClock::new(Ticks::ZERO, 1_700_000_000, 0), &mut rng)?;
    /// // Shared by reference; the cookie state alone is behind a lock.
    /// let cookies = RwLock::new(CookieState::new());
    /// let under_load = || false; // your load signal
    ///
    /// std::thread::scope(|threads| {
    ///     for _ in 0..2 {
    ///         threads.spawn(|| {
    ///             let mut stats = DeviceStats::default(); // this thread's
    ///             let mut datagram = [0u8; 64]; // …from this thread's socket
    ///             let src = "192.0.2.7:51820".parse().unwrap();
    ///             // The lock is taken only while under load, and shared.
    ///             let guard = under_load().then(|| cookies.read().unwrap());
    ///             match device.receive_shared(guard.as_deref(), Ticks::ZERO, src, &mut datagram, &mut stats) {
    ///                 Incoming::ForPeer(_id, _packet) => { /* the peer's tunnel, under its own lock */ }
    ///                 Incoming::Initiation(mut init) => { let _ = device.identify(&mut init); }
    ///                 Incoming::CookieRequired(_challenge) => {
    ///                     // drop(guard); cookies.write() … device.cookie_reply_shared(…)
    ///                 }
    ///                 _ => {}
    ///             }
    ///             assert_eq!(stats.malformed, 1);
    ///         });
    ///     }
    /// });
    /// # Ok::<(), wireguard_sans_io::Error>(())
    /// ```
    pub fn receive_shared<'d>(
        &self,
        cookies: Option<&CookieState>,
        now: Ticks,
        src: SocketAddr,
        datagram: &'d mut [u8],
        stats: &mut DeviceStats,
    ) -> Incoming<'d> {
        let load = match cookies {
            Some(cookies) => Load::Shared(cookies),
            None => Load::Light,
        };
        let classified = Self::classify(&self.mac_keys, load, stats, now, src, datagram);
        Self::route(&self.codec, stats, classified)
    }

    /// The last step of receiving: the receiver index, if there is one,
    /// decoded into a peer id.
    fn route<'d>(
        codec: &IndexCodec,
        stats: &mut DeviceStats,
        classified: Classified<'d>,
    ) -> Incoming<'d> {
        match classified {
            Classified::Initiation(initiation) => Incoming::Initiation(initiation),
            Classified::Indexed(receiver_index, packet) => {
                stats.routed = stats.routed.saturating_add(1);
                Incoming::ForPeer(codec.decode(receiver_index), packet)
            }
            Classified::CookieRequired(challenge) => Incoming::CookieRequired(challenge),
            Classified::Dropped(reason) => Incoming::Dropped(reason),
        }
    }

    /// Everything [`receive`](Self::receive) does except decoding the
    /// receiver index into a peer id. It reads the `mac1` key, counts in
    /// `stats`, and — under load — looks at the cookie state `load` came
    /// with: nothing else of a device, which is what lets a shared one
    /// be received on.
    fn classify<'d>(
        mac_keys: &DeviceMacKeys,
        load: Load<'_>,
        stats: &mut DeviceStats,
        now: Ticks,
        src: SocketAddr,
        datagram: &'d mut [u8],
    ) -> Classified<'d> {
        let kind = match message::peek(datagram) {
            Ok(kind) => kind,
            Err(reason) => {
                stats.malformed = stats.malformed.saturating_add(1);
                return Classified::Dropped(reason);
            }
        };
        match kind {
            PacketKind::TransportData {
                receiver_index,
                counter,
            } => {
                let Some((_header, body)) = datagram.split_at_mut_checked(TRANSPORT_HEADER_LEN)
                else {
                    return Classified::Dropped(DropReason::Malformed);
                };
                Classified::Indexed(
                    receiver_index,
                    PeerPacket {
                        kind: PeerPacketKind::Transport {
                            receiver_index,
                            counter,
                            body,
                        },
                        source_verified: false,
                    },
                )
            }
            PacketKind::CookieReply { receiver_index } => {
                let datagram: &'d [u8] = datagram;
                let Ok(Packet::CookieReply(msg)) = message::parse(datagram) else {
                    return Classified::Dropped(DropReason::Malformed);
                };
                Classified::Indexed(
                    receiver_index,
                    PeerPacket {
                        kind: PeerPacketKind::CookieReply(msg),
                        source_verified: false,
                    },
                )
            }
            PacketKind::HandshakeResponse { receiver_index, .. } => {
                let datagram: &'d [u8] = datagram;
                let Ok(Packet::HandshakeResponse(msg)) = message::parse(datagram) else {
                    return Classified::Dropped(DropReason::Malformed);
                };
                // The gate checks `mac2` exactly while under load.
                let source_verified = load.under_load();
                if let Some(rejected) = Self::gate(
                    mac_keys,
                    load,
                    stats,
                    now,
                    src,
                    msg.alpha,
                    msg.beta,
                    msg.mac1,
                    msg.mac2,
                    msg.sender_index,
                ) {
                    return rejected;
                }
                Classified::Indexed(
                    receiver_index,
                    PeerPacket {
                        kind: PeerPacketKind::Response(msg),
                        source_verified,
                    },
                )
            }
            PacketKind::HandshakeInitiation { .. } => {
                let datagram: &'d [u8] = datagram;
                let Ok(Packet::HandshakeInitiation(msg)) = message::parse(datagram) else {
                    return Classified::Dropped(DropReason::Malformed);
                };
                // The gate checks `mac2` exactly while under load.
                let source_verified = load.under_load();
                if let Some(rejected) = Self::gate(
                    mac_keys,
                    load,
                    stats,
                    now,
                    src,
                    msg.alpha,
                    msg.beta,
                    msg.mac1,
                    msg.mac2,
                    msg.sender_index,
                ) {
                    return rejected;
                }
                // The cheap MACs passed. Everything expensive comes
                // later, in `identify` and in the tunnel.
                stats.initiations = stats.initiations.saturating_add(1);
                Classified::Initiation(Initiation {
                    msg,
                    src,
                    source_verified,
                    identity: Identity::blank(),
                })
            }
        }
    }

    /// The checks every handshake message passes before anything
    /// expensive: `mac1` always, `mac2` while under load (whitepaper
    /// §5.3). `None` means "go on".
    #[allow(clippy::too_many_arguments)] // the fields of one handshake message
    fn gate(
        mac_keys: &DeviceMacKeys,
        load: Load<'_>,
        stats: &mut DeviceStats,
        now: Ticks,
        src: SocketAddr,
        alpha: &[u8],
        beta: &[u8],
        mac1: &[u8; 16],
        mac2: &[u8; 16],
        sender_index: u32,
    ) -> Option<Classified<'static>> {
        if !cookie::verify_mac1::<P>(mac_keys, alpha, mac1) {
            stats.mac1_failures = stats.mac1_failures.saturating_add(1);
            return Some(Classified::Dropped(DropReason::InvalidMac1));
        }
        let proven = match load {
            Load::Light => true,
            Load::Shared(cookies) => cookies.accepts::<P>(cookies.seen(now), src, beta, mac2),
            Load::Exclusive(cookies) => {
                let now = cookies.clamp_now(now);
                cookies.accepts::<P>(now, src, beta, mac2)
            }
        };
        if !proven {
            stats.cookies_required = stats.cookies_required.saturating_add(1);
            return Some(Classified::CookieRequired(CookieChallenge {
                src,
                sender_index,
                mac1: *mac1,
            }));
        }
        None
    }

    /// Find out who an initiation claims to be from: the `es`
    /// Diffie-Hellman and the AEAD that hides the initiator's static
    /// public key (whitepaper §5.4.2). Returns that key; use it to look
    /// the peer up, then pass the initiation to its
    /// [`Tunnel::handle_initiation`].
    ///
    /// This is the expensive step of receiving an initiation — **one
    /// X25519** — and the only one that happens before the peer is known.
    /// It takes `&self`: it changes nothing in the device, so several can
    /// run at once — and, on a device that is shared
    /// ([`Device::receive_shared`]), at the same time as anything else.
    /// Anyone who knows our public key (and, under load, has a cookie)
    /// can make us spend it; whether to is the caller's decision — see
    /// [`Initiation::source_verified`].
    ///
    /// Calling it again on the same initiation returns the same key
    /// without repeating the work.
    ///
    /// # Errors
    /// The initiation is to be dropped: [`DropReason::InvalidPublicKey`]
    /// (low-order ephemeral) or [`DropReason::AuthFailure`] (the identity
    /// does not decrypt: a forgery, or a message for another responder).
    pub fn identify(&self, initiation: &mut Initiation<'_>) -> Result<PublicKey, DropReason> {
        if !initiation.identity.known {
            noise::identify_initiation::<P>(
                &self.constants,
                &self.local_static,
                &self.local_public,
                &initiation.msg,
                &mut initiation.identity,
            )?;
        }
        Ok(PublicKey::from_bytes(initiation.identity.static_public))
    }

    /// Build the cookie reply for an [`Incoming::CookieRequired`]
    /// (whitepaper §5.4.7). The reply goes to the address the challenged
    /// message came from.
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] (`out` must hold 64 bytes),
    /// [`Error::EntropyFailure`] (the cookie secret is drawn here, on
    /// first use and every two minutes).
    pub fn cookie_reply<'o>(
        &mut self,
        now: Ticks,
        challenge: &CookieChallenge,
        out: &'o mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Transmit<'o>, Error> {
        Self::reply(
            &self.mac_keys,
            &mut self.cookies,
            &mut self.stats,
            now,
            challenge,
            out,
            rng,
        )
    }

    /// [`Device::cookie_reply`] for a device that is shared: `&self`,
    /// with the [`CookieState`] to mint from — the one
    /// [`Device::receive_shared`] checks cookies against — and the
    /// [`DeviceStats`] to count in handed to it.
    ///
    /// This is the one call that needs the cookie state exclusively (the
    /// secret is drawn here, and every reply takes a nonce), for the time
    /// one reply takes to build. Whoever waits for it is a handshake
    /// message that arrived under load; transport data is not among them.
    ///
    /// # Errors
    /// As [`Device::cookie_reply`].
    pub fn cookie_reply_shared<'o>(
        &self,
        cookies: &mut CookieState,
        now: Ticks,
        challenge: &CookieChallenge,
        out: &'o mut [u8],
        rng: &mut dyn EntropySource,
        stats: &mut DeviceStats,
    ) -> Result<Transmit<'o>, Error> {
        Self::reply(&self.mac_keys, cookies, stats, now, challenge, out, rng)
    }

    /// A cookie reply from `cookies`, counted in `stats`.
    fn reply<'o>(
        mac_keys: &DeviceMacKeys,
        cookies: &mut CookieState,
        stats: &mut DeviceStats,
        now: Ticks,
        challenge: &CookieChallenge,
        out: &'o mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Transmit<'o>, Error> {
        let now = cookies.clamp_now(now);
        let len = cookie::build_cookie_reply::<P>(
            mac_keys,
            &mut cookies.jar,
            now,
            rng,
            challenge.sender_index,
            &challenge.mac1,
            RemoteBytes::new(challenge.src).as_slice(),
            out,
        )?;
        stats.cookies_sent = stats.cookies_sent.saturating_add(1);
        let datagram = out.get(..len).ok_or(Error::Internal)?;
        Ok(Transmit {
            dst: challenge.src,
            datagram,
        })
    }

    /// The whole receive path for the common case of exactly one peer:
    /// the datagram is processed if it belongs to `tunnel` and dropped
    /// otherwise.
    ///
    /// With a single tunnel there is nothing to route, so this skips
    /// decoding the receiver index into a peer id (the one per-datagram
    /// cost [`Device::receive`] adds) and hands the datagram straight to
    /// the tunnel, which checks the index against its own sessions anyway.
    ///
    /// Being one call, it leaves no place for a per-source rate limit:
    /// every initiation that passes the MAC checks costs one X25519. Where
    /// that matters, use [`Device::receive`] and the calls it leads to.
    ///
    /// `out` receives a handshake response or a cookie reply (it must
    /// hold 92 bytes); transport data is decrypted in place in `datagram`.
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`], [`Error::EntropyFailure`].
    #[allow(clippy::too_many_arguments)] // the union of the calls it wraps
    pub fn receive_for<'a>(
        &mut self,
        tunnel: &mut Tunnel<P>,
        now: Ticks,
        src: SocketAddr,
        under_load: bool,
        datagram: &'a mut [u8],
        out: &'a mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Handled<'a>, Error> {
        let load = if under_load {
            Load::Exclusive(&mut self.cookies)
        } else {
            Load::Light
        };
        match Self::classify(&self.mac_keys, load, &mut self.stats, now, src, datagram) {
            // The tunnel identifies the initiation itself: with one peer
            // there is nobody to look up.
            Classified::Initiation(initiation) => {
                tunnel.handle_initiation(now, &initiation, out, rng)
            }
            Classified::Indexed(_, packet) => tunnel.handle(now, src, packet),
            Classified::CookieRequired(challenge) => {
                let transmit = self.cookie_reply(now, &challenge, out, rng)?;
                Ok(Handled {
                    received: Received::CookieReply(transmit),
                    session_established: false,
                    endpoint_changed: false,
                })
            }
            Classified::Dropped(reason) => Ok(Handled::dropped(reason)),
        }
    }

    /// Replace the wall-clock anchor handed to tunnels created from now
    /// on. Existing tunnels keep theirs; see [`Tunnel::set_wall_clock`].
    pub fn set_wall_clock(&mut self, wall_clock: WallClock) {
        self.wall_clock = wall_clock;
    }

    /// Cumulative counters.
    #[must_use]
    pub fn stats(&self) -> DeviceStats {
        self.stats
    }
}
