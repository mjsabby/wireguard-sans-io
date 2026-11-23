//! Which secrets are inside a `Tunnel` or a `Device` — in its own bytes —
//! at each stage of its life, and after it has been dropped?
//!
//! Method. The inspected tunnel uses a recording crypto provider: every
//! 32-byte secret that passes through a primitive (Diffie-Hellman inputs
//! and results, KDF keys and outputs, AEAD keys) is noted, with what it
//! was used for. The tunnel lives in a heap slot whose bytes can be read
//! at any time — including after the value in it has been dropped, which
//! is the one moment no safe test can look at.
//!
//! What must hold:
//!
//! | stage | may be in the tunnel |
//! |---|---|
//! | configured | long-term keys only: static private key, pre-shared key, `DH(static, static)` |
//! | initiation in flight | + the ephemeral private key and the chaining key |
//! | response sent, session not confirmed | + the two transport keys of that session |
//! | session live | + the two transport keys per session — and no handshake secret |
//! | after `SessionsExpired` | long-term keys only |
//! | after `reset()` | long-term keys only |
//! | after it is dropped | nothing at all |
//!
//! "Nothing at all" is checked for more than the secrets a provider sees.
//! The entropy source keeps a record of everything it handed out —
//! ephemeral private keys, cookie secrets, the keys behind session
//! indices and cookie-reply nonces — and none of it may be in a tunnel or
//! a device that has been dropped. And the endings are tried from the
//! states in which there is most to forget: a tunnel dropped with an
//! initiation in flight; a tunnel that is reset, and one that is dropped,
//! while it holds a cookie; a device dropped after it has minted cookies
//! under two secrets.
//!
//! Exit status: 0 if all of that holds, 1 if not, 2 if the probe itself
//! does not work (it must see the transport keys while a session is live,
//! the cookie while it is stored, and the device's secrets while the
//! device is).

use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Mutex;

use wireguard_probes::{Found, Needle, Needles, Recorded, bytes_of};
use wireguard_sans_io::crypto::{aead, blake2s, x25519};
use wireguard_sans_io::{
    CryptoProvider, Device, Encapsulated, Error, InTree, Incoming, PeerConfig, PeerId, PollOutput,
    PresharedKey, Received, StaticSecret, Ticks, Tunnel, WallClock,
};

/// What a recorded secret was seen as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// The scalar of a Diffie-Hellman operation.
    DhSecret,
    /// The result of one.
    DhResult,
    /// The key of an HMAC: a chaining key, or a KDF's intermediate key.
    KdfKey,
    /// The output of an HMAC: chaining keys, AEAD keys, transport keys.
    KdfOutput,
    /// An AEAD key used with additional data: one of the handshake's.
    HandshakeAeadKey,
    /// An AEAD key used without: a transport key.
    TransportKey,
}

static SEEN: Mutex<Vec<(Kind, [u8; 32])>> = Mutex::new(Vec::new());

fn note(kind: Kind, value: &[u8]) {
    if let Ok(value) = <[u8; 32]>::try_from(value) {
        // The chain starts from a public constant, `Hash(Construction)`,
        // which every device and tunnel keeps: not a secret.
        if value == blake2s::hash(&[b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"]) {
            return;
        }
        let mut seen = SEEN.lock().unwrap();
        if !seen.contains(&(kind, value)) {
            seen.push((kind, value));
        }
    }
}

/// The default provider, with every secret noted on the way through.
struct Recording;
type Inner = InTree;

impl CryptoProvider for Recording {
    fn name() -> &'static str {
        "recording"
    }
    fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
        note(Kind::DhSecret, secret);
        Inner::x25519_public(secret)
    }
    fn x25519(secret: &[u8; 32], public: &[u8; 32], out: &mut [u8; 32]) -> bool {
        note(Kind::DhSecret, secret);
        let ok = Inner::x25519(secret, public, out);
        note(Kind::DhResult, out);
        ok
    }
    fn hash(parts: &[&[u8]], out: &mut [u8; 32]) {
        Inner::hash(parts, out);
    }
    fn mac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 16]) {
        Inner::mac(key, parts, out);
    }
    fn hmac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 32]) {
        note(Kind::KdfKey, key);
        Inner::hmac(key, parts, out);
        note(Kind::KdfOutput, out);
    }
    fn seal_in_place(
        key: &[u8; 32],
        counter: u64,
        aad: &[u8],
        pt_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        note(aead_kind(aad), key);
        Inner::seal_in_place(key, counter, aad, pt_len, buf)
    }
    fn open_in_place(key: &[u8; 32], counter: u64, aad: &[u8], buf: &mut [u8]) -> Option<usize> {
        note(aead_kind(aad), key);
        Inner::open_in_place(key, counter, aad, buf)
    }
    fn xseal_in_place(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        pt_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        Inner::xseal_in_place(key, nonce, aad, pt_len, buf)
    }
    fn xopen_in_place(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Option<usize> {
        Inner::xopen_in_place(key, nonce, aad, buf)
    }
}

fn aead_kind(aad: &[u8]) -> Kind {
    if aad.is_empty() {
        Kind::TransportKey
    } else {
        Kind::HandshakeAeadKey
    }
}

/// A value in a heap slot whose bytes stay readable after the value has
/// been dropped.
struct Slot<T> {
    storage: Box<MaybeUninit<T>>,
    live: bool,
}

impl<T> Slot<T> {
    fn new(value: T) -> Self {
        let mut storage = Box::new(MaybeUninit::zeroed());
        storage.write(value);
        Self {
            storage,
            live: true,
        }
    }

    fn get(&mut self) -> &mut T {
        assert!(self.live);
        // SAFETY: written in `new`, not dropped yet.
        unsafe { self.storage.assume_init_mut() }
    }

    /// The bytes of the slot: of the live value, or of what its `Drop`
    /// left behind.
    fn bytes(&self) -> Vec<u8> {
        bytes_of(&*self.storage)
    }

    /// Drop the value where it lies; the storage stays allocated.
    fn drop_in_place(&mut self) {
        assert!(self.live);
        // SAFETY: the value is initialised and is not used again.
        unsafe { self.storage.assume_init_drop() };
        self.live = false;
    }
}

struct Party<P: CryptoProvider> {
    device: Slot<Device<P>>,
    tunnel: Slot<Tunnel<P>>,
}

fn poll_all<P: CryptoProvider>(
    p: &mut Party<P>,
    now: Ticks,
    rng: &mut Recorded,
) -> (Vec<Vec<u8>>, Vec<&'static str>) {
    let mut sent = Vec::new();
    let mut events = Vec::new();
    loop {
        let mut buf = [0u8; 256];
        match p.tunnel.get().poll(now, &mut buf, rng).unwrap() {
            PollOutput::Transmit(tx, _) => sent.push(tx.datagram.to_vec()),
            PollOutput::SessionsExpired => events.push("sessions_expired"),
            PollOutput::HandshakeExpired => events.push("handshake_expired"),
            PollOutput::Idle => break,
            _ => events.push("other"),
        }
    }
    (sent, events)
}

/// Deliver `wire` to `to`. Returns a reply to carry back, if any, and what
/// the datagram was.
fn deliver<P: CryptoProvider>(
    to: &mut Party<P>,
    from: SocketAddr,
    now: Ticks,
    wire: &[u8],
    rng: &mut Recorded,
) -> (Option<Vec<u8>>, &'static str) {
    let mut datagram = wire.to_vec();
    let mut out = [0u8; 256];
    let Party { device, tunnel, .. } = to;
    let handled = device
        .get()
        .receive_for(tunnel.get(), now, from, false, &mut datagram, &mut out, rng)
        .unwrap();
    match handled.received {
        Received::HandshakeResponse(tx) => (Some(tx.datagram.to_vec()), "response"),
        Received::HandshakeComplete => (None, "complete"),
        Received::CookieStored => (None, "cookie"),
        Received::Keepalive => (None, "keepalive"),
        Received::Data(_) => (None, "data"),
        _ => (None, "other"),
    }
}

fn send<P: CryptoProvider>(p: &mut Party<P>, now: Ticks, payload: &[u8]) -> Option<Vec<u8>> {
    let mut buf = [0u8; 256];
    match p.tunnel.get().encapsulate(now, payload, &mut buf).unwrap() {
        Encapsulated::Transport(tx) => Some(tx.datagram.to_vec()),
        _ => None,
    }
}

/// What is expected to be inside the inspected tunnel at one stage.
struct Expect {
    /// An initiation is in flight: its ephemeral private key and chaining
    /// key are in the tunnel.
    in_flight: bool,
    /// How many transport keys (two per session).
    transport_keys: usize,
    /// Long-term keys (false only after the tunnel was dropped).
    long_term: bool,
}

struct Probe {
    long_term: Needles,
    failures: usize,
    /// The transport keys were seen in a live tunnel at least once: the
    /// probe can see what it is looking for.
    saw_transport_keys: bool,
    /// The same for a stored cookie, and for what a device draws from
    /// the entropy source.
    saw_cookie: bool,
    saw_device_secrets: bool,
}

/// Which of the values the entropy source handed out are in `bytes`:
/// requests of sixteen bytes and more (keys; shorter ones are timer
/// jitter). A 32-byte value is also looked for without its first and
/// last byte, which is all that clamping a private key changes.
fn entropy_in(bytes: &[u8], log: &[Vec<u8>]) -> Vec<usize> {
    log.iter()
        .enumerate()
        .filter(|(_, drawn)| drawn.len() >= 16)
        .filter(|(_, drawn)| {
            let inner = if drawn.len() == 32 {
                drawn.get(1..31).unwrap_or(drawn)
            } else {
                drawn
            };
            bytes.windows(inner.len()).any(|w| w == inner)
        })
        .map(|(i, _)| i)
        .collect()
}

/// Is `needle` among `found`, and all of it? (What must be gone is gone
/// only if no part of it is left; what must be there is there whole.)
fn whole(found: &[(&Needle, Found)], needle: &Needle) -> bool {
    found
        .iter()
        .any(|(n, how)| n.name == needle.name && matches!(how, Found::Whole(_)))
}

impl Probe {
    fn result(&mut self, stage: &str, problems: &[String]) {
        if problems.is_empty() {
            println!("  ok    {stage}");
        } else {
            println!("  FAIL  {stage}");
            for problem in problems {
                println!("          {problem}");
            }
            self.failures += 1;
        }
    }

    /// After a drop: nothing the entropy source handed out, and none of
    /// `others` (named byte strings: a cookie).
    fn check_gone(&mut self, stage: &str, bytes: &[u8], log: &[Vec<u8>], others: &Needles) {
        let mut problems = Vec::new();
        for index in entropy_in(bytes, log) {
            problems.push(format!(
                "a {}-byte value from the entropy source (its request no. {index}) is still there",
                log[index].len()
            ));
        }
        for (needle, _) in others.found_in(bytes) {
            problems.push(format!("{} is still there", needle.name));
        }
        self.result(stage, &problems);
    }

    /// While alive: all of `must` are there, whole (or the probe is not
    /// looking at what it thinks it is).
    fn check_present(&mut self, stage: &str, bytes: &[u8], must: &Needles) -> bool {
        let found = must.found_in(bytes);
        let problems: Vec<String> = must
            .0
            .iter()
            .filter(|needle| !whole(&found, needle))
            .map(|needle| format!("{} is NOT there (probe broken?)", needle.name))
            .collect();
        self.result(stage, &problems);
        problems.is_empty()
    }

    fn check(&mut self, stage: &str, bytes: &[u8], expect: &Expect) {
        let seen = SEEN.lock().unwrap().clone();
        let present = |value: &[u8; 32]| bytes.windows(32).any(|w| w == value);
        let long_term_found = self.long_term.found_in(bytes);
        let is_long_term = |value: &[u8; 32]| self.long_term.0.iter().any(|n| n.bytes == value);

        let mut transport = Vec::new();
        let mut handshake = Vec::new();
        for (kind, value) in &seen {
            if is_long_term(value) || !present(value) {
                continue;
            }
            // One value can be seen in several roles (a transport key is
            // first a KDF output); what it is *used* as decides.
            let used_as_transport = seen
                .iter()
                .any(|(k, v)| *k == Kind::TransportKey && v == value);
            if used_as_transport {
                if !transport.contains(value) {
                    transport.push(*value);
                }
            } else if !handshake.iter().any(|(_, v)| v == value) {
                handshake.push((*kind, *value));
            }
        }

        let mut problems = Vec::new();
        if expect.long_term {
            for needle in &self.long_term.0 {
                if !whole(&long_term_found, needle) {
                    // Not a leak, but then the probe is not looking at
                    // what it thinks it is looking at.
                    problems.push(format!("{} is NOT there (probe broken?)", needle.name));
                }
            }
        } else {
            for (needle, _) in &long_term_found {
                problems.push(format!("{} is still there", needle.name));
            }
        }
        if transport.len() != expect.transport_keys {
            problems.push(format!(
                "{} transport keys, expected {}",
                transport.len(),
                expect.transport_keys
            ));
        }
        // In flight: exactly the ephemeral private key (a DH scalar) and
        // the chaining key (a KDF output that is also the next KDF key).
        let expected_handshake = if expect.in_flight { 2 } else { 0 };
        let in_flight_shape = handshake
            .iter()
            .filter(|(k, _)| *k == Kind::DhSecret)
            .count()
            == 1
            && !handshake
                .iter()
                .any(|(k, _)| matches!(k, Kind::DhResult | Kind::HandshakeAeadKey));
        if handshake.len() != expected_handshake || (expect.in_flight && !in_flight_shape) {
            problems.push(format!(
                "handshake secrets present: {:?}, expected {}",
                handshake.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
                if expect.in_flight {
                    "the ephemeral private key and the chaining key"
                } else {
                    "none"
                }
            ));
        }
        if expect.transport_keys > 0 && transport.len() == expect.transport_keys {
            self.saw_transport_keys = true;
        }
        self.result(stage, &problems);
    }
}

/// One life of a tunnel, inspected at every stage. `as_initiator` says
/// which role the inspected tunnel has in its first handshake.
#[allow(clippy::too_many_lines)]
fn run(as_initiator: bool, probe: &mut Probe) {
    SEEN.lock().unwrap().clear();
    let mut rng = Recorded::new(if as_initiator { 0x1111 } else { 0x2222 });
    let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
    let x_static: [u8; 32] = core::array::from_fn(|i| 0x40 ^ (i as u8).wrapping_mul(11));
    let psk: [u8; 32] = core::array::from_fn(|i| 0x77 ^ (i as u8).wrapping_mul(5));
    let y_key = StaticSecret::generate(&mut rng).unwrap();
    let x_pub = StaticSecret::from_bytes(x_static).public_key();
    let y_pub = y_key.public_key();
    let x_addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
    let y_addr: SocketAddr = "192.0.2.2:51820".parse().unwrap();
    let id = PeerId::new(0).unwrap();
    let at = Ticks::from_secs;

    // The inspected side (x) records; its peer (y) is ordinary.
    let x_device: Device<Recording> =
        Device::with_provider(StaticSecret::from_bytes(x_static), wall, &mut rng).unwrap();
    let mut cfg = PeerConfig::new(y_pub);
    cfg.endpoint = Some(y_addr);
    cfg.psk = PresharedKey::from_bytes(psk);
    let x_tunnel = x_device.tunnel(id, cfg, &mut rng).unwrap();
    let mut x = Party {
        device: Slot::new(x_device),
        tunnel: Slot::new(x_tunnel),
    };
    let y_device = Device::new(y_key, wall, &mut rng).unwrap();
    let mut cfg = PeerConfig::new(x_pub);
    cfg.endpoint = Some(x_addr);
    cfg.psk = PresharedKey::from_bytes(psk);
    let y_tunnel = y_device.tunnel(id, cfg, &mut rng).unwrap();
    let mut y = Party {
        device: Slot::new(y_device),
        tunnel: Slot::new(y_tunnel),
    };

    probe.long_term = Needles::default();
    probe.long_term.add("the static private key", &x_static);
    probe.long_term.add("the pre-shared key", &psk);
    probe.long_term.add(
        "DH(static, static)",
        &x25519::x25519(&x_static, y_pub.as_bytes()),
    );
    let long_term_only = Expect {
        in_flight: false,
        transport_keys: 0,
        long_term: true,
    };
    let sessions = |n: usize| Expect {
        in_flight: false,
        transport_keys: 2 * n,
        long_term: true,
    };

    probe.check("configured", &x.tunnel.bytes(), &long_term_only);

    // ---- first handshake, in the chosen role --------------------------------
    let now = at(1);
    if as_initiator {
        assert!(send(&mut x, now, b"hello").is_none());
        let (sent, _) = poll_all(&mut x, now, &mut rng);
        probe.check(
            "initiation in flight",
            &x.tunnel.bytes(),
            &Expect {
                in_flight: true,
                transport_keys: 0,
                long_term: true,
            },
        );
        let (resp, _) = deliver(&mut y, x_addr, now, &sent[0], &mut rng);
        let (_, what) = deliver(&mut x, y_addr, now, &resp.unwrap(), &mut rng);
        assert_eq!(what, "complete");
        // The transport keys of a session nobody has used yet have not
        // passed through an AEAD; they are recognised once they have.
        let completed = x.tunnel.bytes();
        let data = send(&mut x, now, b"hello").unwrap();
        assert_eq!(deliver(&mut y, x_addr, now, &data, &mut rng).1, "data");
        let reply = send(&mut y, now, b"world").unwrap();
        assert_eq!(deliver(&mut x, y_addr, now, &reply, &mut rng).1, "data");
        probe.check(
            "handshake complete, nothing sent yet",
            &completed,
            &sessions(1),
        );
    } else {
        assert!(send(&mut y, now, b"hello").is_none());
        let (sent, _) = poll_all(&mut y, now, &mut rng);
        let (resp, _) = deliver(&mut x, y_addr, now, &sent[0], &mut rng);
        let unconfirmed = x.tunnel.bytes();
        let (_, what) = deliver(&mut y, x_addr, now, &resp.unwrap(), &mut rng);
        assert_eq!(what, "complete");
        let data = send(&mut y, now, b"hello").unwrap();
        assert_eq!(deliver(&mut x, y_addr, now, &data, &mut rng).1, "data");
        let reply = send(&mut x, now, b"world").unwrap();
        assert_eq!(deliver(&mut y, x_addr, now, &reply, &mut rng).1, "data");
        probe.check(
            "response sent, session not confirmed",
            &unconfirmed,
            &sessions(1),
        );
    }
    poll_all(&mut x, now, &mut rng);
    poll_all(&mut y, now, &mut rng);
    probe.check(
        "session live, data both ways",
        &x.tunnel.bytes(),
        &sessions(1),
    );

    // ---- a second session: the first becomes `previous` -----------------------
    let now = at(30);
    x.tunnel.get().request_handshake(now);
    let (sent, _) = poll_all(&mut x, now, &mut rng);
    let (resp, _) = deliver(&mut y, x_addr, now, &sent[0], &mut rng);
    assert_eq!(
        deliver(&mut x, y_addr, now, &resp.unwrap(), &mut rng).1,
        "complete"
    );
    let data = send(&mut x, now, b"again").unwrap();
    assert_eq!(deliver(&mut y, x_addr, now, &data, &mut rng).1, "data");
    let reply = send(&mut y, now, b"again").unwrap();
    assert_eq!(deliver(&mut x, y_addr, now, &reply, &mut rng).1, "data");
    poll_all(&mut x, now, &mut rng);
    poll_all(&mut y, now, &mut rng);
    probe.check(
        "two sessions (previous and current)",
        &x.tunnel.bytes(),
        &sessions(2),
    );

    // ---- a third: the first is rotated out, and must be gone ------------------
    let now = at(60);
    y.tunnel.get().request_handshake(now);
    let (sent, _) = poll_all(&mut y, now, &mut rng);
    let (resp, _) = deliver(&mut x, y_addr, now, &sent[0], &mut rng);
    assert_eq!(
        deliver(&mut y, x_addr, now, &resp.unwrap(), &mut rng).1,
        "complete"
    );
    let data = send(&mut y, now, b"third").unwrap();
    assert_eq!(deliver(&mut x, y_addr, now, &data, &mut rng).1, "data");
    let reply = send(&mut x, now, b"third").unwrap();
    assert_eq!(deliver(&mut y, x_addr, now, &reply, &mut rng).1, "data");
    poll_all(&mut x, now, &mut rng);
    poll_all(&mut y, now, &mut rng);
    probe.check(
        "three sessions made, the oldest rotated out",
        &x.tunnel.bytes(),
        &sessions(2),
    );

    // ---- silence: the key-wipe timer -------------------------------------------
    let mut wiped = false;
    while let Some(wake) = x.tunnel.get().next_wake() {
        let (_, events) = poll_all(&mut x, wake, &mut rng);
        wiped |= events.contains(&"sessions_expired");
    }
    assert!(wiped, "the key-wipe timer did not fire");
    probe.check("after SessionsExpired", &x.tunnel.bytes(), &long_term_only);

    // ---- a new session and an initiation in flight, then reset() ---------------
    let now = at(3600);
    while y.tunnel.get().next_wake().is_some_and(|w| w <= now) {
        let wake = y.tunnel.get().next_wake().unwrap();
        poll_all(&mut y, wake, &mut rng);
    }
    assert!(send(&mut x, now, b"later").is_none());
    let (sent, _) = poll_all(&mut x, now, &mut rng);
    let (resp, _) = deliver(&mut y, x_addr, now, &sent[0], &mut rng);
    assert_eq!(
        deliver(&mut x, y_addr, now, &resp.unwrap(), &mut rng).1,
        "complete"
    );
    let data = send(&mut x, now, b"later").unwrap();
    assert_eq!(deliver(&mut y, x_addr, now, &data, &mut rng).1, "data");
    let reply = send(&mut y, now, b"later").unwrap();
    assert_eq!(deliver(&mut x, y_addr, now, &reply, &mut rng).1, "data");
    poll_all(&mut x, now, &mut rng);
    let now = at(3610);
    x.tunnel.get().request_handshake(now);
    let (sent, _) = poll_all(&mut x, now, &mut rng);
    assert_eq!(sent.len(), 1, "an initiation is in flight");
    probe.check(
        "a session, and an initiation in flight",
        &x.tunnel.bytes(),
        &Expect {
            in_flight: true,
            transport_keys: 2,
            long_term: true,
        },
    );
    x.tunnel.get().reset();
    probe.check("after reset()", &x.tunnel.bytes(), &long_term_only);

    // ---- a last session, and then the tunnel and the device are dropped --------
    let now = at(3700);
    assert!(send(&mut x, now, b"last").is_none());
    let (sent, _) = poll_all(&mut x, now, &mut rng);
    let (resp, _) = deliver(&mut y, x_addr, now, &sent[0], &mut rng);
    assert_eq!(
        deliver(&mut x, y_addr, now, &resp.unwrap(), &mut rng).1,
        "complete"
    );
    let data = send(&mut x, now, b"last").unwrap();
    assert_eq!(deliver(&mut y, x_addr, now, &data, &mut rng).1, "data");
    let reply = send(&mut y, now, b"last").unwrap();
    assert_eq!(deliver(&mut x, y_addr, now, &reply, &mut rng).1, "data");
    probe.check(
        "a live session, about to be dropped",
        &x.tunnel.bytes(),
        &sessions(1),
    );
    x.tunnel.drop_in_place();
    let nothing = Expect {
        in_flight: false,
        transport_keys: 0,
        long_term: false,
    };
    probe.check("after the tunnel was dropped", &x.tunnel.bytes(), &nothing);
    probe.check_gone(
        "after the tunnel was dropped: nothing from the entropy source",
        &x.tunnel.bytes(),
        &rng.log,
        &Needles::default(),
    );
    x.device.drop_in_place();
    probe.check("after the device was dropped", &x.device.bytes(), &nothing);
    probe.check_gone(
        "after the device was dropped: nothing from the entropy source",
        &x.device.bytes(),
        &rng.log,
        &Needles::default(),
    );
}

/// The endings, from the states in which there is most to forget.
#[allow(clippy::too_many_lines)]
fn endings(probe: &mut Probe) {
    SEEN.lock().unwrap().clear();
    let mut rng = Recorded::new(0x3333);
    let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
    let x_static: [u8; 32] = core::array::from_fn(|i| 0x21 ^ (i as u8).wrapping_mul(23));
    let psk: [u8; 32] = core::array::from_fn(|i| 0x66 ^ (i as u8).wrapping_mul(9));
    let y_key = StaticSecret::generate(&mut rng).unwrap();
    let x_pub = StaticSecret::from_bytes(x_static).public_key();
    let y_pub = y_key.public_key();
    let x_addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
    let y_addr: SocketAddr = "192.0.2.2:51820".parse().unwrap();
    let id = PeerId::new(0).unwrap();
    let at = Ticks::from_secs;
    let nothing = Expect {
        in_flight: false,
        transport_keys: 0,
        long_term: false,
    };

    let x_device: Device<Recording> =
        Device::with_provider(StaticSecret::from_bytes(x_static), wall, &mut rng).unwrap();
    let x_tunnel = |device: &Device<Recording>, rng: &mut Recorded| {
        let mut cfg = PeerConfig::new(y_pub);
        cfg.endpoint = Some(y_addr);
        cfg.psk = PresharedKey::from_bytes(psk);
        device.tunnel(id, cfg, rng).unwrap()
    };
    let first = x_tunnel(&x_device, &mut rng);
    let mut x = Party {
        device: Slot::new(x_device),
        tunnel: Slot::new(first),
    };
    let y_device = Device::new(y_key, wall, &mut rng).unwrap();
    let mut cfg = PeerConfig::new(x_pub);
    cfg.endpoint = Some(x_addr);
    cfg.psk = PresharedKey::from_bytes(psk);
    let y_tunnel = y_device.tunnel(id, cfg, &mut rng).unwrap();
    let mut y = Party {
        device: Slot::new(y_device),
        tunnel: Slot::new(y_tunnel),
    };
    probe.long_term = Needles::default();
    probe.long_term.add("the static private key", &x_static);
    probe.long_term.add("the pre-shared key", &psk);
    probe.long_term.add(
        "DH(static, static)",
        &x25519::x25519(&x_static, y_pub.as_bytes()),
    );

    // ---- dropped with an initiation in flight -----------------------------------
    let now = at(1);
    assert!(send(&mut x, now, b"hello").is_none());
    let (sent, _) = poll_all(&mut x, now, &mut rng);
    assert_eq!(sent.len(), 1, "an initiation is in flight");
    probe.check(
        "an initiation in flight, about to be dropped",
        &x.tunnel.bytes(),
        &Expect {
            in_flight: true,
            transport_keys: 0,
            long_term: true,
        },
    );
    x.tunnel.drop_in_place();
    probe.check(
        "dropped with an initiation in flight",
        &x.tunnel.bytes(),
        &nothing,
    );
    probe.check_gone(
        "dropped with an initiation in flight: nothing from the entropy source",
        &x.tunnel.bytes(),
        &rng.log,
        &Needles::default(),
    );

    // ---- a cookie: stored, then reset(); stored again, then dropped ----------------
    // y is under load and answers x's initiation with a cookie reply.
    // What the cookie is, the probe finds out the way x does: by opening
    // the reply (whitepaper §5.4.7).
    let cookie_key = blake2s::hash(&[b"cookie--", y_pub.as_bytes()]);
    let cookie_round =
        |x: &mut Party<Recording>, y: &mut Party<InTree>, now: Ticks, rng: &mut Recorded| {
            x.tunnel.get().request_handshake(now);
            let (sent, _) = poll_all(x, now, rng);
            let init = sent.first().expect("an initiation").clone();
            let mut datagram = init.clone();
            let mut out = [0u8; 64];
            let reply = match y.device.get().receive(now, x_addr, true, &mut datagram) {
                Incoming::CookieRequired(challenge) => y
                    .device
                    .get()
                    .cookie_reply(now, &challenge, &mut out, rng)
                    .unwrap()
                    .datagram
                    .to_vec(),
                other => panic!("expected a cookie to be required, got {other:?}"),
            };
            let nonce: [u8; 24] = reply[8..32].try_into().unwrap();
            let mut cookie = [0u8; 16];
            aead::xopen(
                &cookie_key,
                &nonce,
                &init[116..132],
                &reply[32..64],
                &mut cookie,
            )
            .unwrap();
            assert_eq!(deliver(x, y_addr, now, &reply, rng).1, "cookie");
            cookie
        };

    x.tunnel = Slot::new(x_tunnel(x.device.get(), &mut rng));
    let cookie = cookie_round(&mut x, &mut y, at(10), &mut rng);
    let mut cookies = Needles::default();
    cookies.add("the cookie", &cookie);
    probe.saw_cookie = probe.check_present(
        "a cookie reply received: the cookie is in the tunnel",
        &x.tunnel.bytes(),
        &cookies,
    );
    x.tunnel.get().reset();
    probe.check_gone(
        "after reset(): no cookie, and nothing from the entropy source but the index order",
        &x.tunnel.bytes(),
        // The key that orders this tunnel's session indices stays (it is
        // not a secret of any session): it was the tunnel's first draw.
        &[],
        &cookies,
    );
    let second = cookie_round(&mut x, &mut y, at(20), &mut rng);
    cookies.add("the second cookie", &second);
    probe.saw_cookie &=
        probe.check_present("a second cookie reply received", &x.tunnel.bytes(), &{
            let mut only = Needles::default();
            only.add("the second cookie", &second);
            only
        });
    x.tunnel.drop_in_place();
    probe.check(
        "dropped while holding a cookie",
        &x.tunnel.bytes(),
        &nothing,
    );
    probe.check_gone(
        "dropped while holding a cookie: no cookie, nothing from the entropy source",
        &x.tunnel.bytes(),
        &rng.log,
        &cookies,
    );

    // ---- the device: cookie secrets, and the keys behind indices and nonces --------
    // x, under load, answers y's initiations with cookie replies: once
    // now, and once more than two minutes on, under a new secret.
    let mut minted = Needles::default();
    for (round, now) in [at(100), at(300)].into_iter().enumerate() {
        y.tunnel.get().request_handshake(now);
        let (sent, _) = poll_all(&mut y, now, &mut rng);
        let mut datagram = sent.first().expect("an initiation").clone();
        let mut out = [0u8; 64];
        let before = rng.log.len();
        match x.device.get().receive(now, y_addr, true, &mut datagram) {
            Incoming::CookieRequired(challenge) => {
                x.device
                    .get()
                    .cookie_reply(now, &challenge, &mut out, &mut rng)
                    .unwrap();
            }
            other => panic!("expected a cookie to be required, got {other:?}"),
        }
        // What the device drew to do that: its cookie secret.
        for drawn in rng.log[before..].iter().filter(|d| d.len() == 32) {
            minted.add(&format!("cookie secret no. {}", round + 1), drawn);
        }
        // y gives up on this attempt before the next.
        y.tunnel.get().reset();
    }
    assert_eq!(minted.0.len(), 2, "two cookie secrets were drawn");
    let alive = x.device.bytes();
    let holds = entropy_in(&alive, &rng.log);
    println!(
        "  (the live device holds {} values from the entropy source)",
        holds.len()
    );
    probe.saw_device_secrets = probe.check_present(
        "a device that has minted cookies holds its current secret",
        &alive,
        &{
            let mut current = Needles::default();
            current.add("cookie secret no. 2", &minted.0[1].bytes);
            current
        },
    ) && holds.len() >= 3;
    x.device.drop_in_place();
    probe.check("after that device was dropped", &x.device.bytes(), &nothing);
    probe.check_gone(
        "after that device was dropped: nothing from the entropy source",
        &x.device.bytes(),
        &rng.log,
        &minted,
    );
}

fn main() -> ExitCode {
    let mut probe = Probe {
        long_term: Needles::default(),
        failures: 0,
        saw_transport_keys: false,
        saw_cookie: false,
        saw_device_secrets: false,
    };
    println!(
        "size of a Tunnel: {} bytes; of a Device: {} bytes",
        size_of::<Tunnel>(),
        size_of::<Device>()
    );
    println!("the inspected tunnel initiates its first session:");
    run(true, &mut probe);
    println!("the inspected tunnel answers its first session:");
    run(false, &mut probe);
    println!("the endings:");
    endings(&mut probe);

    if !(probe.saw_transport_keys && probe.saw_cookie && probe.saw_device_secrets) {
        println!(
            "RESULT: the probe never saw {}; nothing can be concluded",
            if !probe.saw_transport_keys {
                "a live session's keys"
            } else if !probe.saw_cookie {
                "a stored cookie"
            } else {
                "a live device's secrets"
            }
        );
        return ExitCode::from(2);
    }
    if probe.failures == 0 {
        println!(
            "RESULT: a tunnel holds exactly the secrets it needs at every stage, and none once dropped"
        );
        ExitCode::SUCCESS
    } else {
        println!("RESULT: {} stage(s) failed", probe.failures);
        ExitCode::FAILURE
    }
}
