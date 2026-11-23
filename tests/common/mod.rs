//! Shared harness for the integration test battery: a deterministic
//! clock, device + tunnel pairs, and handshake/transport pumps — all
//! through the public API only.
//!
//! The helpers return *owned* summaries ([`Rx`], [`Tx`], [`Polled`]) so a
//! test can keep a datagram around, corrupt it, replay it, or deliver it
//! twice without fighting the borrow checker.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

pub mod counting;
pub mod timer_model;

use std::net::SocketAddr;

use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    CryptoProvider, Device, DropReason, Encapsulated, EntropySource, Error, Handled, InTree,
    Incoming, PeerConfig, PeerId, PollOutput, PresharedKey, PublicKey, Received, SendReason,
    StaticSecret, Ticks, Tunnel, WallClock,
};

pub const S: u64 = 1_000_000_000;
pub const MS: u64 = 1_000_000;

/// Unix time the simulated wall clock reads at `Ticks::ZERO`.
pub const BASE_UNIX: u64 = 1_700_000_000;

pub fn a_addr() -> SocketAddr {
    "192.0.2.1:51820".parse().unwrap()
}
pub fn b_addr() -> SocketAddr {
    "192.0.2.2:51820".parse().unwrap()
}
/// An address that belongs to neither side (an off-path sender).
pub fn x_addr() -> SocketAddr {
    "203.0.113.66:4444".parse().unwrap()
}

pub fn wall() -> WallClock {
    WallClock::new(Ticks::ZERO, BASE_UNIX, 0)
}

pub fn id(n: u32) -> PeerId {
    PeerId::new(n).unwrap()
}

/// A deterministic, manually-advanced clock. Sans-I/O makes every timer
/// reachable instantly: tests jump straight to the interesting instants.
pub struct Clock {
    pub mono_ns: u64,
}

impl Clock {
    pub fn new() -> Self {
        Self { mono_ns: 0 }
    }

    pub fn now(&self) -> Ticks {
        Ticks::from_nanos(self.mono_ns)
    }

    pub fn advance(&mut self, ns: u64) -> Ticks {
        self.mono_ns += ns;
        self.now()
    }

    pub fn set(&mut self, at: Ticks) -> Ticks {
        self.mono_ns = self.mono_ns.max(at.nanos());
        self.now()
    }
}

/// What one inbound datagram turned out to be (owned copy of
/// [`Received`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rx {
    Data(Vec<u8>),
    Keepalive,
    /// Handshake response to send back.
    Response(Vec<u8>),
    HandshakeComplete,
    CookieStored,
    /// Cookie reply to send back (sender not authenticated).
    CookieReply(Vec<u8>),
    Dropped(DropReason),
}

/// Owned copy of [`Handled`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxInfo {
    pub rx: Rx,
    pub session_established: bool,
    pub endpoint_changed: bool,
    /// Where the reply in `rx` (a response or a cookie reply) is to be
    /// sent.
    pub reply_dst: Option<SocketAddr>,
}

impl RxInfo {
    pub fn from_handled(h: &Handled<'_>) -> Self {
        let mut reply_dst = None;
        let rx = match &h.received {
            Received::Data(d) => Rx::Data(d.to_vec()),
            Received::Keepalive => Rx::Keepalive,
            Received::HandshakeResponse(tx) => {
                reply_dst = Some(tx.dst);
                Rx::Response(tx.datagram.to_vec())
            }
            Received::HandshakeComplete => Rx::HandshakeComplete,
            Received::CookieStored => Rx::CookieStored,
            Received::CookieReply(tx) => {
                reply_dst = Some(tx.dst);
                Rx::CookieReply(tx.datagram.to_vec())
            }
            Received::Dropped(r) => Rx::Dropped(*r),
            other => panic!("unhandled Received variant {other:?}"),
        };
        Self {
            rx,
            session_established: h.session_established,
            endpoint_changed: h.endpoint_changed,
            reply_dst,
        }
    }

    /// A datagram that was dropped before it reached a tunnel.
    pub fn dropped(reason: DropReason) -> Self {
        Self {
            rx: Rx::Dropped(reason),
            session_established: false,
            endpoint_changed: false,
            reply_dst: None,
        }
    }

    /// A cookie reply the device built.
    pub fn cookie_reply(reply: &wireguard_sans_io::Transmit<'_>) -> Self {
        Self {
            rx: Rx::CookieReply(reply.datagram.to_vec()),
            session_established: false,
            endpoint_changed: false,
            reply_dst: Some(reply.dst),
        }
    }
}

/// Owned copy of [`Encapsulated`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tx {
    Transport(Vec<u8>),
    NoSession,
    NoEndpoint,
}

/// Owned copy of [`PollOutput`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Polled {
    Transmit(Vec<u8>, SendReason, SocketAddr),
    HandshakeExpired,
    SessionsExpired,
    Idle,
}

/// One endpoint: a device with a single tunnel, and the address the other
/// side knows it by. The crypto provider is the default one unless a test
/// asks for another (see [`counting`]).
pub struct Side<P: CryptoProvider = InTree> {
    pub device: Device<P>,
    pub tunnel: Tunnel<P>,
    pub addr: SocketAddr,
}

impl<P: CryptoProvider> Side<P> {
    /// Deliver `datagram`, as if it arrived from `src`. The bytes are
    /// copied first, so the caller's datagram stays pristine.
    pub fn recv_from(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        under_load: bool,
        datagram: &[u8],
        rng: &mut dyn EntropySource,
    ) -> RxInfo {
        self.try_recv_from(now, src, under_load, datagram, rng)
            .expect("receive path reported a local fault")
    }

    pub fn try_recv_from(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        under_load: bool,
        datagram: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<RxInfo, Error> {
        self.try_recv(now, src, under_load, datagram, rng, false)
    }

    /// Deliver `datagram` the way an embedder with a table of peers does:
    /// [`Device::receive`], then — for an initiation —
    /// [`Device::identify`] and a look-up by public key, or — for
    /// everything else — a look-up by the peer id the device decoded. The
    /// table here has one entry, this side's tunnel.
    pub fn recv_routed(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        under_load: bool,
        datagram: &[u8],
        rng: &mut dyn EntropySource,
    ) -> RxInfo {
        self.try_recv(now, src, under_load, datagram, rng, true)
            .expect("receive path reported a local fault")
    }

    /// One datagram through either receive path, with the buffer
    /// discipline checked.
    pub fn try_recv(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        under_load: bool,
        datagram: &[u8],
        rng: &mut dyn EntropySource,
        routed: bool,
    ) -> Result<RxInfo, Error> {
        let mut copy = datagram.to_vec();
        let mut out = [0xEEu8; 256];
        let result = if routed {
            self.route(now, src, under_load, &mut copy, &mut out, rng)
        } else {
            self.device
                .receive_for(
                    &mut self.tunnel,
                    now,
                    src,
                    under_load,
                    &mut copy,
                    &mut out,
                    rng,
                )
                .map(|handled| RxInfo::from_handled(&handled))
        };
        // Buffer discipline, checked on every datagram any test delivers:
        // the datagram is modified only to decrypt authenticated data in
        // place, and `out` is written only when a reply is produced.
        let wrote_reply = matches!(
            result.as_ref().map(|i| &i.rx),
            Ok(Rx::Response(_) | Rx::CookieReply(_))
        );
        let decrypted = matches!(result.as_ref().map(|i| &i.rx), Ok(Rx::Data(_)));
        if !wrote_reply {
            assert!(
                out.iter().all(|&b| b == 0xEE),
                "output buffer written without a reply: {result:?}"
            );
        }
        if decrypted {
            assert_eq!(&copy[..16], &datagram[..16], "transport header modified");
        } else {
            assert_eq!(
                copy, datagram,
                "datagram modified without decrypting: {result:?}"
            );
        }
        result
    }

    /// The two-step receive path; see [`Side::recv_routed`].
    fn route(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        under_load: bool,
        datagram: &mut [u8],
        out: &mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<RxInfo, Error> {
        let dropped = RxInfo::dropped;
        Ok(match self.device.receive(now, src, under_load, datagram) {
            Incoming::Initiation(mut initiation) => {
                assert_eq!(initiation.src(), src);
                assert_eq!(initiation.source_verified(), under_load);
                match self.device.identify(&mut initiation) {
                    Err(reason) => dropped(reason),
                    // Nobody in the table has that key.
                    Ok(key) if key != self.tunnel.peer_public() => dropped(DropReason::UnknownPeer),
                    Ok(_) => RxInfo::from_handled(&self.tunnel.handle_initiation(
                        now,
                        &initiation,
                        out,
                        rng,
                    )?),
                }
            }
            Incoming::ForPeer(peer, packet) => {
                if peer == self.tunnel.peer_id() {
                    RxInfo::from_handled(&self.tunnel.handle(now, src, packet)?)
                } else {
                    // Nobody in the table has that id.
                    dropped(DropReason::UnknownIndex)
                }
            }
            Incoming::CookieRequired(challenge) => {
                assert_eq!(challenge.src(), src);
                let reply = self.device.cookie_reply(now, &challenge, out, rng)?;
                assert_eq!(reply.dst, src);
                RxInfo::cookie_reply(&reply)
            }
            Incoming::Dropped(reason) => dropped(reason),
            other => panic!("unhandled Incoming variant {other:?}"),
        })
    }

    /// Deliver `datagram` in place and report what is left in the buffer:
    /// `(result, buffer afterwards)`.
    pub fn recv_in_place(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        datagram: &[u8],
        rng: &mut dyn EntropySource,
    ) -> (RxInfo, Vec<u8>) {
        let mut copy = datagram.to_vec();
        let mut out = [0u8; 256];
        let info = {
            let handled = self
                .device
                .receive_for(&mut self.tunnel, now, src, false, &mut copy, &mut out, rng)
                .expect("receive path reported a local fault");
            RxInfo::from_handled(&handled)
        };
        (info, copy)
    }

    /// Encrypt `payload`.
    pub fn send(&mut self, now: Ticks, payload: &[u8]) -> Tx {
        let mut buf = vec![0u8; payload.len() + 64];
        match self.tunnel.encapsulate(now, payload, &mut buf).unwrap() {
            Encapsulated::Transport(tx) => Tx::Transport(tx.datagram.to_vec()),
            Encapsulated::NoSession => Tx::NoSession,
            Encapsulated::NoEndpoint => Tx::NoEndpoint,
            other => panic!("unhandled Encapsulated variant {other:?}"),
        }
    }

    /// One `poll` call, owned.
    pub fn poll(&mut self, now: Ticks, rng: &mut dyn EntropySource) -> Polled {
        self.try_poll(now, rng)
            .expect("poll reported a local fault")
    }

    pub fn try_poll(&mut self, now: Ticks, rng: &mut dyn EntropySource) -> Result<Polled, Error> {
        let mut buf = [0u8; 256];
        Ok(match self.tunnel.poll(now, &mut buf, rng)? {
            PollOutput::Transmit(tx, why) => Polled::Transmit(tx.datagram.to_vec(), why, tx.dst),
            PollOutput::HandshakeExpired => Polled::HandshakeExpired,
            PollOutput::SessionsExpired => Polled::SessionsExpired,
            PollOutput::Idle => Polled::Idle,
            other => panic!("unhandled PollOutput variant {other:?}"),
        })
    }

    /// Poll until `Idle`, returning `(datagrams, events)`.
    pub fn drain(
        &mut self,
        now: Ticks,
        rng: &mut dyn EntropySource,
    ) -> (Vec<(Vec<u8>, SendReason)>, Vec<&'static str>) {
        let mut wires = Vec::new();
        let mut events = Vec::new();
        loop {
            match self.poll(now, rng) {
                Polled::Transmit(w, why, _) => wires.push((w, why)),
                Polled::HandshakeExpired => events.push("handshake_expired"),
                Polled::SessionsExpired => events.push("sessions_expired"),
                Polled::Idle => break,
            }
            assert!(wires.len() + events.len() < 16, "poll never stabilizes");
        }
        assert!(
            self.tunnel.next_wake().is_none_or(|w| w > now),
            "poll returned Idle with a wake-up that is not in the future"
        );
        (wires, events)
    }

    /// Request a handshake and return the initiation `poll` produces: a
    /// fresh one, or — if a handshake is already in flight and its
    /// retransmission is due — that retransmission.
    pub fn initiate(&mut self, now: Ticks, rng: &mut dyn EntropySource) -> Vec<u8> {
        self.tunnel.request_handshake(now);
        match self.poll(now, rng) {
            Polled::Transmit(
                w,
                SendReason::HandshakeInitiation | SendReason::HandshakeRetransmit,
                _,
            ) => {
                assert_eq!(w.len(), 148);
                assert_eq!(w[0], 1);
                w
            }
            other => panic!("expected a handshake initiation, got {other:?}"),
        }
    }

    pub fn is_established(&self, now: Ticks) -> bool {
        self.tunnel.is_established(now)
    }
}

pub struct Pair<P: CryptoProvider = InTree> {
    pub a: Side<P>,
    pub b: Side<P>,
    pub rng: DeterministicRng,
    pub clock: Clock,
}

/// Options for [`new_pair_opts`]. Everything defaults to "plain".
#[derive(Default)]
pub struct Opts {
    pub psk: Option<[u8; 32]>,
    /// Persistent keepalive (seconds) for side A.
    pub keepalive_a: Option<u16>,
    /// Persistent keepalive (seconds) for side B.
    pub keepalive_b: Option<u16>,
    /// B is configured without A's endpoint (a pure responder, as a
    /// server with roaming clients is).
    pub b_without_endpoint: bool,
}

pub fn keypair(rng: &mut DeterministicRng) -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::generate(rng).unwrap();
    let public = secret.public_key();
    (secret, public)
}

/// A side with one tunnel (peer id 0) toward `peer_public`.
pub fn side(
    secret: StaticSecret,
    peer_public: PublicKey,
    addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    psk: Option<[u8; 32]>,
    keepalive: Option<u16>,
    rng: &mut DeterministicRng,
) -> Side {
    side_with(secret, peer_public, addr, peer_addr, psk, keepalive, rng)
}

/// As [`side`], for any crypto provider.
pub fn side_with<P: CryptoProvider>(
    secret: StaticSecret,
    peer_public: PublicKey,
    addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    psk: Option<[u8; 32]>,
    keepalive: Option<u16>,
    rng: &mut DeterministicRng,
) -> Side<P> {
    let device = Device::with_provider(secret, wall(), rng).unwrap();
    let mut cfg = PeerConfig::new(peer_public);
    cfg.endpoint = peer_addr;
    if let Some(psk) = psk {
        cfg.psk = PresharedKey::from_bytes(psk);
    }
    cfg.persistent_keepalive = keepalive.and_then(core::num::NonZeroU16::new);
    let tunnel = device.tunnel(id(0), cfg, rng).unwrap();
    Side {
        device,
        tunnel,
        addr,
    }
}

pub fn new_pair_opts(seed: u64, opts: Opts) -> Pair {
    new_pair_opts_with(seed, opts)
}

/// As [`new_pair_opts`], for any crypto provider.
pub fn new_pair_opts_with<P: CryptoProvider>(seed: u64, opts: Opts) -> Pair<P> {
    let mut rng = DeterministicRng::new(seed);
    let (a_key, a_pub) = keypair(&mut rng);
    let (b_key, b_pub) = keypair(&mut rng);
    let a = side_with(
        a_key,
        b_pub,
        a_addr(),
        Some(b_addr()),
        opts.psk,
        opts.keepalive_a,
        &mut rng,
    );
    let b = side_with(
        b_key,
        a_pub,
        b_addr(),
        (!opts.b_without_endpoint).then(a_addr),
        opts.psk,
        opts.keepalive_b,
        &mut rng,
    );
    Pair {
        a,
        b,
        rng,
        clock: Clock::new(),
    }
}

/// `keepalive_secs` applies to side A only (as most tests want).
pub fn new_pair_with(seed: u64, psk: Option<[u8; 32]>, keepalive_secs: Option<u16>) -> Pair {
    new_pair_opts(
        seed,
        Opts {
            psk,
            keepalive_a: keepalive_secs,
            ..Opts::default()
        },
    )
}

pub fn new_pair(seed: u64) -> Pair {
    new_pair_with(seed, None, None)
}

/// A plain pair whose crypto operations are counted (see [`counting`]).
pub fn new_counting_pair(seed: u64) -> Pair<counting::Counting> {
    new_pair_opts_with(seed, Opts::default())
}

impl<P: CryptoProvider> Pair<P> {
    /// Deliver a datagram from A to B (source address: A's).
    pub fn deliver_to_b(&mut self, datagram: &[u8]) -> RxInfo {
        let now = self.clock.now();
        self.b
            .recv_from(now, self.a.addr, false, datagram, &mut self.rng)
    }

    /// Deliver a datagram from B to A (source address: B's).
    pub fn deliver_to_a(&mut self, datagram: &[u8]) -> RxInfo {
        let now = self.clock.now();
        self.a
            .recv_from(now, self.b.addr, false, datagram, &mut self.rng)
    }

    /// A requests a handshake; returns the initiation.
    pub fn a_initiates(&mut self) -> Vec<u8> {
        let now = self.clock.now();
        self.a.initiate(now, &mut self.rng)
    }

    /// B requests a handshake; returns the initiation.
    pub fn b_initiates(&mut self) -> Vec<u8> {
        let now = self.clock.now();
        self.b.initiate(now, &mut self.rng)
    }

    /// Run a full handshake (A initiates) and confirm it with A's
    /// keepalive so both directions are usable. Returns the number of
    /// wire datagrams exchanged.
    pub fn establish(&mut self) -> usize {
        let now = self.clock.now();
        let init = self.a_initiates();
        let resp = match self.deliver_to_b(&init).rx {
            Rx::Response(w) => w,
            other => panic!("expected response, got {other:?}"),
        };
        let info = self.deliver_to_a(&resp);
        assert_eq!(info.rx, Rx::HandshakeComplete);
        assert!(
            info.session_established,
            "initiator must report the session"
        );
        // A's confirmation keepalive lets B promote + use the session.
        let ka = match self.a.poll(now, &mut self.rng) {
            Polled::Transmit(w, SendReason::Keepalive, _) => w,
            other => panic!("expected confirm keepalive, got {other:?}"),
        };
        let info = self.deliver_to_b(&ka);
        assert_eq!(info.rx, Rx::Keepalive);
        assert!(
            info.session_established,
            "responder must report the session"
        );
        assert!(self.a.is_established(now) && self.b.is_established(now));
        assert_eq!(self.a.poll(now, &mut self.rng), Polled::Idle);
        assert_eq!(self.b.poll(now, &mut self.rng), Polled::Idle);
        4
    }

    /// Encrypt `payload` from A, returning the wire datagram.
    pub fn seal_from_a(&mut self, payload: &[u8]) -> Vec<u8> {
        let now = self.clock.now();
        match self.a.send(now, payload) {
            Tx::Transport(w) => w,
            other => panic!("expected transport, got {other:?}"),
        }
    }

    pub fn seal_from_b(&mut self, payload: &[u8]) -> Vec<u8> {
        let now = self.clock.now();
        match self.b.send(now, payload) {
            Tx::Transport(w) => w,
            other => panic!("expected transport, got {other:?}"),
        }
    }

    /// Deliver a wire datagram to B, expecting decrypted data back.
    pub fn open_at_b(&mut self, wire: &[u8]) -> Vec<u8> {
        match self.deliver_to_b(wire).rx {
            Rx::Data(d) => d,
            other => panic!("expected data, got {other:?}"),
        }
    }

    pub fn open_at_a(&mut self, wire: &[u8]) -> Vec<u8> {
        match self.deliver_to_a(wire).rx {
            Rx::Data(d) => d,
            other => panic!("expected data, got {other:?}"),
        }
    }

    /// Round-trip a payload A→B and assert it arrives intact (modulo the
    /// protocol's zero padding, which is asserted too).
    pub fn assert_roundtrip_a_to_b(&mut self, payload: &[u8]) {
        let wire = self.seal_from_a(payload);
        let got = self.open_at_b(&wire);
        assert!(got.len() >= payload.len());
        assert_eq!(&got[..payload.len()], payload);
        assert!(
            got[payload.len()..].iter().all(|&b| b == 0),
            "padding must be zeros"
        );
        assert_eq!(got.len() % 16, 0, "padded length must be 16-aligned");
    }
}

/// Which side of a [`Pair`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    A,
    B,
}

impl Who {
    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// Feed the reference timer model what a tunnel was just observed to do,
/// so the two can be compared. These three functions are the whole
/// mapping from "what the public API reported" to "protocol events".
pub mod shadow {
    use super::timer_model::TimerModel;
    use super::{Polled, Rx, RxInfo};
    use wireguard_sans_io::{SendReason, Tunnel};

    /// The tunnel encrypted a payload of `payload_len` bytes.
    pub fn sent(model: &mut TimerModel, t: u64, payload_len: usize) {
        model.sent_transport(t, payload_len);
    }

    /// The tunnel processed an inbound datagram with this outcome.
    pub fn received(model: &mut TimerModel, t: u64, info: &RxInfo) {
        match &info.rx {
            Rx::Data(d) => model.accepted_transport(t, d.len(), info.session_established),
            Rx::Keepalive => model.accepted_transport(t, 0, info.session_established),
            Rx::Response(_) => model.accepted_initiation(t),
            Rx::HandshakeComplete => model.accepted_response(t),
            Rx::CookieStored | Rx::CookieReply(_) | Rx::Dropped(_) => {}
        }
    }

    /// One `poll()` call of `tunnel` returned this.
    pub fn polled(model: &mut TimerModel, t: u64, polled: &Polled, tunnel: &Tunnel) {
        match polled {
            Polled::Transmit(_, SendReason::HandshakeInitiation, _) => {
                model.sent_initiation(t, true);
            }
            Polled::Transmit(_, SendReason::HandshakeRetransmit, _) => {
                model.sent_initiation(t, false);
            }
            Polled::Transmit(..) => model.sent_transport(t, 0),
            Polled::HandshakeExpired => model.gave_up(t),
            Polled::SessionsExpired => model.keys_zeroed(),
            Polled::Idle => model.polled_to_idle(t, tunnel),
        }
    }
}

/// Two sides driven the way a real embedder drives them — sleep until
/// `next_wake()`, then `poll()` to `Idle` — over a network that delivers
/// instantly unless told to lose things.
///
/// Every step is shadowed by the reference timer model
/// ([`timer_model::TimerModel`]): after each operation the five protocol
/// timers of the affected tunnel must equal the model's.
pub struct Sim {
    pub p: Pair,
    /// Every datagram a side emitted from `poll()`: `(time, side, why)`.
    pub log: Vec<(u64, Who, SendReason)>,
    /// `HandshakeExpired` / `SessionsExpired` notifications.
    pub events: Vec<(u64, Who, &'static str)>,
    /// Lose every datagram travelling A → B / B → A.
    pub lose_a_to_b: bool,
    pub lose_b_to_a: bool,
    /// B is switched off: it neither receives nor is polled.
    pub b_off: bool,
    /// The wire takes time: a datagram arrives only after both sides have
    /// had their turn at the instant it was sent, so that what the two
    /// send at the same instant crosses. (Off: a datagram arrives the
    /// moment it is sent, before the other side is polled.)
    pub crossing_wire: bool,
    /// Datagrams on such a wire: `(sender, datagram)`.
    in_flight: Vec<(Who, Vec<u8>)>,
    /// Payloads delivered to each side's application.
    pub data_at_a: Vec<Vec<u8>>,
    pub data_at_b: Vec<Vec<u8>>,
    /// `session_established` reports per side.
    pub established: Vec<(u64, Who)>,
    pub model_a: timer_model::TimerModel,
    pub model_b: timer_model::TimerModel,
}

impl Sim {
    pub fn new(seed: u64) -> Self {
        Self::with_opts(seed, Opts::default())
    }

    pub fn with_opts(seed: u64, opts: Opts) -> Self {
        let model_a = timer_model::TimerModel::new(opts.keepalive_a);
        let model_b = timer_model::TimerModel::new(opts.keepalive_b);
        Self {
            p: new_pair_opts(seed, opts),
            log: Vec::new(),
            events: Vec::new(),
            lose_a_to_b: false,
            lose_b_to_a: false,
            b_off: false,
            crossing_wire: false,
            in_flight: Vec::new(),
            data_at_a: Vec::new(),
            data_at_b: Vec::new(),
            established: Vec::new(),
            model_a,
            model_b,
        }
    }

    pub fn t(&self) -> u64 {
        self.p.clock.mono_ns
    }

    fn side(
        &mut self,
        who: Who,
    ) -> (
        &mut Side,
        &mut timer_model::TimerModel,
        &mut DeterministicRng,
    ) {
        match who {
            Who::A => (&mut self.p.a, &mut self.model_a, &mut self.p.rng),
            Who::B => (&mut self.p.b, &mut self.model_b, &mut self.p.rng),
        }
    }

    fn check(&mut self, who: Who, what: &str) {
        let t = self.t();
        let (side, model, _) = self.side(who);
        model.assert_matches(
            &side.tunnel,
            t,
            &format!("t={t}ns side {who:?} after {what}"),
        );
    }

    /// Put a datagram `from` emitted on the wire: it reaches the other
    /// side (and whatever that side answers travels back) unless lost —
    /// at once, or, on a [crossing wire](Self::crossing_wire), in the next
    /// round of [`pump`](Self::pump).
    pub fn transmit(&mut self, from: Who, datagram: Vec<u8>) {
        if self.crossing_wire {
            self.in_flight.push((from, datagram));
            return;
        }
        self.deliver(from, datagram);
    }

    /// The datagram `from` sent arrives.
    fn deliver(&mut self, from: Who, datagram: Vec<u8>) {
        let mut pending = vec![(from, datagram)];
        while let Some((from, datagram)) = pending.pop() {
            let lost = match from {
                Who::A => self.lose_a_to_b || self.b_off,
                Who::B => self.lose_b_to_a,
            };
            if lost {
                continue;
            }
            let to = from.other();
            let now = self.p.clock.now();
            let t = self.t();
            let src = match from {
                Who::A => self.p.a.addr,
                Who::B => self.p.b.addr,
            };
            let (side, model, rng) = self.side(to);
            let info = side.recv_from(now, src, false, &datagram, rng);
            shadow::received(model, t, &info);
            if info.session_established {
                self.established.push((t, to));
            }
            match info.rx {
                Rx::Data(d) => match to {
                    Who::A => self.data_at_a.push(d),
                    Who::B => self.data_at_b.push(d),
                },
                Rx::Response(w) | Rx::CookieReply(w) => {
                    if self.crossing_wire {
                        self.in_flight.push((to, w));
                    } else {
                        pending.push((to, w));
                    }
                }
                _ => {}
            }
            self.check(to, "receive");
        }
    }

    /// `who`'s application sends `payload`. Returns whether a transport
    /// datagram went out (as opposed to `NoSession`).
    pub fn send(&mut self, who: Who, payload: &[u8]) -> bool {
        let now = self.p.clock.now();
        let t = self.t();
        let (side, model, _) = self.side(who);
        let sent = match side.send(now, payload) {
            Tx::Transport(w) => {
                shadow::sent(model, t, payload.len());
                Some(w)
            }
            Tx::NoSession | Tx::NoEndpoint => None,
        };
        self.check(who, "send");
        match sent {
            Some(w) => {
                self.transmit(who, w);
                true
            }
            None => false,
        }
    }

    pub fn request_handshake(&mut self, who: Who) {
        let now = self.p.clock.now();
        self.side(who).0.tunnel.request_handshake(now);
    }

    /// Poll both sides to `Idle`, delivering whatever they emit, until
    /// neither has anything left to do at the current instant.
    pub fn pump(&mut self) {
        for round in 0.. {
            assert!(round < 64, "the two sides never settle");
            let mut progressed = false;
            for who in [Who::A, Who::B] {
                if who == Who::B && self.b_off {
                    continue;
                }
                loop {
                    let now = self.p.clock.now();
                    let t = self.t();
                    let (side, model, rng) = self.side(who);
                    let polled = side.poll(now, rng);
                    shadow::polled(model, t, &polled, &side.tunnel);
                    match polled {
                        Polled::Transmit(w, why, _dst) => {
                            self.log.push((t, who, why));
                            self.check(who, "poll output");
                            self.transmit(who, w);
                            progressed = true;
                        }
                        Polled::HandshakeExpired => {
                            self.events.push((t, who, "handshake_expired"));
                            progressed = true;
                        }
                        Polled::SessionsExpired => {
                            self.events.push((t, who, "sessions_expired"));
                            progressed = true;
                        }
                        Polled::Idle => {
                            assert!(
                                side.tunnel.next_wake().is_none_or(|w| w > now),
                                "t={t}: side {who:?} is Idle with a wake-up that is not in the \
                                 future (the caller would spin)"
                            );
                            self.check(who, "poll to idle");
                            break;
                        }
                    }
                }
            }
            // What was sent in this round arrives, now that both sides
            // have had their turn.
            for (from, datagram) in std::mem::take(&mut self.in_flight) {
                self.deliver(from, datagram);
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
    }

    /// The earliest wake-up either live side has asked for.
    pub fn next_wake(&self) -> Option<u64> {
        let a = self.p.a.tunnel.next_wake().map(Ticks::nanos);
        let b = if self.b_off {
            None
        } else {
            self.p.b.tunnel.next_wake().map(Ticks::nanos)
        };
        [a, b].into_iter().flatten().min()
    }

    /// Let time pass until `end_ns`, waking exactly when a side asks to.
    pub fn run_until(&mut self, end_ns: u64) {
        loop {
            self.pump();
            match self.next_wake() {
                Some(w) if w <= end_ns => {
                    assert!(w > self.t(), "wake-up in the past after Idle");
                    self.p.clock.mono_ns = w;
                }
                _ => {
                    self.p.clock.mono_ns = self.p.clock.mono_ns.max(end_ns);
                    self.pump();
                    return;
                }
            }
        }
    }

    /// A initiates, B responds, A confirms: both sides established.
    pub fn establish(&mut self, initiator: Who) {
        self.request_handshake(initiator);
        self.pump();
        let now = self.p.clock.now();
        assert!(
            self.p.a.is_established(now) && self.p.b.is_established(now),
            "handshake did not complete"
        );
    }

    /// Datagrams `who` emitted from `poll()` for `why` in `[from, to]`.
    pub fn count(&self, who: Who, why: SendReason, from: u64, to: u64) -> usize {
        self.times(who, why)
            .into_iter()
            .filter(|t| (from..=to).contains(t))
            .count()
    }

    /// Times at which `who` emitted a datagram for `why` from `poll()`.
    pub fn times(&self, who: Who, why: SendReason) -> Vec<u64> {
        self.log
            .iter()
            .filter(|(_, w, r)| *w == who && *r == why)
            .map(|(t, _, _)| *t)
            .collect()
    }
}

/// Fingerprint of a payload, for exact-delivery accounting.
pub fn fingerprint(data: &[u8]) -> u64 {
    // FNV-1a, good enough for accounting.
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in data {
        h = (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
    }
    h ^ (data.len() as u64)
}

/// One side of a randomized test: a [`Side`], its own entropy stream, the
/// reference timer model shadowing it, and a record of what it sent and
/// accepted.
pub struct Endpoint {
    pub name: &'static str,
    pub side: Side,
    pub model: timer_model::TimerModel,
    pub rng: DeterministicRng,
    /// Fingerprints of every payload this endpoint has ever encapsulated
    /// (padded form, since the receiver sees padding).
    pub sent: std::collections::HashSet<u64>,
    /// Fingerprints of every transport datagram this endpoint has
    /// accepted. Each datagram carries its own counter, so accepting the
    /// same bytes a second time is a replay getting through.
    pub accepted: std::collections::HashSet<u64>,
    pub delivered: u64,
}

impl Endpoint {
    pub fn new(name: &'static str, side: Side, keepalive: Option<u16>, rng_seed: u64) -> Self {
        Self {
            name,
            side,
            model: timer_model::TimerModel::new(keepalive),
            rng: DeterministicRng::new(rng_seed),
            sent: std::collections::HashSet::new(),
            accepted: std::collections::HashSet::new(),
            delivered: 0,
        }
    }

    pub fn check(&self, t: u64, what: &str) {
        self.model.assert_matches(
            &self.side.tunnel,
            t,
            &format!("t={t} endpoint {} after {what}", self.name),
        );
    }

    /// Encrypt a payload; returns the datagram if one was produced.
    pub fn send(&mut self, t: u64, payload: &[u8]) -> Option<Vec<u8>> {
        let out = match self.side.send(Ticks::from_nanos(t), payload) {
            Tx::Transport(w) => {
                shadow::sent(&mut self.model, t, payload.len());
                let mut padded = payload.to_vec();
                padded.resize(payload.len().div_ceil(16) * 16, 0);
                self.sent.insert(fingerprint(&padded));
                Some(w)
            }
            Tx::NoSession | Tx::NoEndpoint => None,
        };
        self.check(t, "send");
        out
    }

    /// Process one datagram — through the single-call receive path, or
    /// (`routed`) the two-step one a multi-peer embedder uses. Returns a
    /// reply to route back, if any, and the delivered payload, if any.
    pub fn deliver(
        &mut self,
        t: u64,
        src: SocketAddr,
        under_load: bool,
        datagram: &[u8],
        routed: bool,
    ) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let info = self
            .side
            .try_recv(
                Ticks::from_nanos(t),
                src,
                under_load,
                datagram,
                &mut self.rng,
                routed,
            )
            .expect("receive path reported a local fault");
        shadow::received(&mut self.model, t, &info);
        self.check(t, "receive");
        // INVARIANT: a transport datagram is accepted at most once.
        if matches!(info.rx, Rx::Data(_) | Rx::Keepalive) {
            assert!(
                self.accepted.insert(fingerprint(datagram)),
                "t={t}: endpoint {} accepted the same datagram twice (a replay got through)",
                self.name
            );
        }
        match info.rx {
            Rx::Data(d) => {
                self.delivered += 1;
                (None, Some(d))
            }
            Rx::Response(w) | Rx::CookieReply(w) => (Some(w), None),
            _ => (None, None),
        }
    }

    /// Poll to `Idle`, returning everything emitted.
    pub fn poll_to_idle(&mut self, t: u64) -> Vec<Vec<u8>> {
        let now = Ticks::from_nanos(t);
        let mut wires = Vec::new();
        for _ in 0..32 {
            let polled = self.side.poll(now, &mut self.rng);
            shadow::polled(&mut self.model, t, &polled, &self.side.tunnel);
            match polled {
                Polled::Transmit(w, _, _) => wires.push(w),
                Polled::HandshakeExpired | Polled::SessionsExpired => {}
                Polled::Idle => {
                    assert!(
                        self.side.tunnel.next_wake().is_none_or(|w| w > now),
                        "t={t}: endpoint {} Idle with a due wake-up",
                        self.name
                    );
                    self.check(t, "poll to idle");
                    return wires;
                }
            }
        }
        panic!("t={t}: endpoint {} never reaches Idle", self.name);
    }
}
