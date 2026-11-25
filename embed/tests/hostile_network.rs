//! Two `Tunn`s and a network that is out to get them, on virtual time.
//!
//! Each run is a random walk of some thousands of steps, chosen by a
//! seed: time passes (a little, or twelve minutes at once), either end
//! sends a packet, and the network delivers what is in flight — in
//! order, out of order, twice, with a bit flipped or cut short, or not at
//! all. An attacker on it replays what it has recorded (from where it was
//! sent, or from its own address; to whom it was sent, or to the other
//! end), forges handshake messages with a valid `mac1` (it knows both
//! public keys), and sends noise shaped like each message type.
//!
//! After every step:
//!
//! * nothing anyone sent has produced `TunnError::Core(Internal)`;
//! * `update_timers` has reached `Done` in a bounded number of calls, and
//!   the next wake-up is then in the future (no spinning);
//! * every packet handed to "the TUN side" is one the other end sent,
//!   byte for byte, and no packet is handed over twice;
//! * the packet queue is within its documented bound.
//!
//! The default run is a few seconds. `HOSTILE_SEEDS`, `HOSTILE_STEPS` and
//! `HOSTILE_FIRST_SEED` choose another; the ignored test is the long one
//! (all cores, for some minutes):
//!
//! ```sh
//! cargo test --release -p wireguard-embed --test hostile_network -- --ignored --nocapture
//! ```
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use wireguard_embed::core::crypto::blake2s;
use wireguard_embed::core::testing::DeterministicRng;
use wireguard_embed::core::{EntropySource, Error, PublicKey, StaticSecret, Ticks};
use wireguard_embed::{MAX_QUEUE_DEPTH, RateLimiter, Tunn, TunnError, TunnResult};

/// A handshake message of `len` bytes and type `kind` whose `mac1` is
/// right for `receiver` and whose contents are random: what anyone who
/// knows the public key can send. (`mac1` covers everything before it,
/// and is followed by sixteen bytes of `mac2`.)
fn forged_handshake(
    kind: u8,
    len: usize,
    receiver: &PublicKey,
    receiver_index: Option<u32>,
    rng: &mut DeterministicRng,
) -> Vec<u8> {
    let mut m = vec![0u8; len];
    let body = len - 32;
    rng.fill(&mut m[4..body]).unwrap();
    m[0] = kind;
    if let Some(index) = receiver_index {
        m[8..12].copy_from_slice(&index.to_le_bytes());
    }
    let key = blake2s::hash(&[b"mac1----", receiver.as_bytes()]);
    let mac = blake2s::mac(&key, &[&m[..body]]);
    m[body..body + 16].copy_from_slice(&mac);
    m
}

struct End {
    tunn: Tunn,
    addr: SocketAddr,
    base: Ticks,
    public: PublicKey,
    /// What this end has sent into the tunnel, by the id inside it.
    sent: HashMap<u64, Vec<u8>>,
    /// The ids of what has been delivered here.
    got: HashSet<u64>,
}

impl End {
    fn new(tunn: Tunn, addr: SocketAddr, public: PublicKey) -> Self {
        Self {
            base: tunn.now(),
            tunn,
            addr,
            public,
            sent: HashMap::new(),
            got: HashSet::new(),
        }
    }
}

/// A datagram in flight: for A?, from where, the bytes.
type InFlight = (bool, SocketAddr, Vec<u8>);

/// An IPv4 packet (as far as its length field goes) with `id` inside.
fn packet(id: u64, len: usize) -> Vec<u8> {
    let len = len.max(28);
    let mut p = vec![0u8; len];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[20..28].copy_from_slice(&id.to_le_bytes());
    for (i, b) in p.iter_mut().enumerate().skip(28) {
        *b = (id as u8).wrapping_add(i as u8);
    }
    p
}

/// What a call on a `Tunn` came back with.
enum Kind {
    Net(Vec<u8>, SocketAddr),
    Tun(Vec<u8>),
    Internal,
    Nothing,
}

fn kind(r: TunnResult<'_>) -> Kind {
    match r {
        TunnResult::WriteToNetwork(d, to) => Kind::Net(d.to_vec(), to),
        TunnResult::WriteToTunnel(p) => Kind::Tun(p.to_vec()),
        TunnResult::Err(TunnError::Core(Error::Internal)) => Kind::Internal,
        _ => Kind::Nothing,
    }
}

struct Sim {
    a: End,
    b: End,
    wire: VecDeque<InFlight>,
    recorded: Vec<InFlight>,
    rng: DeterministicRng,
    elapsed: u64,
    next_id: u64,
    seed: u64,
    step: u64,
    delivered: u64,
}

impl Sim {
    fn new(seed: u64) -> Self {
        let mut rng = DeterministicRng::new(seed);
        let (mut ka, mut kb) = ([0u8; 32], [0u8; 32]);
        rng.fill(&mut ka).unwrap();
        rng.fill(&mut kb).unwrap();
        let (ka, kb) = (StaticSecret::from_bytes(ka), StaticSecret::from_bytes(kb));
        let (pa, pb) = (ka.public_key(), kb.public_key());
        let addr_a: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let addr_b: SocketAddr = "192.0.2.2:51820".parse().unwrap();
        // The seed also chooses the configuration: persistent keepalives
        // (none, the usual 25 s, every second), a pre-shared key or not,
        // and whether B knows where A is before A says so.
        let keepalive = |n: u64| match n % 3 {
            0 => None,
            1 => Some(25u16),
            _ => Some(1u16),
        };
        let psk = (seed % 2 == 0).then_some([7u8; 32]);
        // And the load signal of each end. That one runs on real time,
        // which a walk is not on: it goes through hours in a fraction of
        // a second, and a peer's handshakes — one every few steps — are
        // thousands a second to a limiter. So most walks have none, and
        // are about the protocol from their first step to their last. The
        // others are about what it refuses: with the default, an end is
        // under load once it has done ten milliseconds of handshake work
        // (some thousand steps in), with no budget at all from its first
        // message — it then asks for cookies, and allows the peer's
        // address the five handshake messages at once that any address
        // gets, after which that end answers no more handshakes. (The
        // walk goes on with the handshakes the other end answers.)
        let limiter = |n: u64| match n % 8 {
            0..=4 => Some(Arc::new(RateLimiter::new(u64::MAX))),
            5 | 6 => None,
            _ => Some(Arc::new(RateLimiter::with_budget(Duration::ZERO))),
        };
        let ta = Tunn::new(ka, pb, psk, keepalive(seed), Some(addr_b), limiter(seed)).unwrap();
        let tb = Tunn::new(
            kb,
            pa,
            psk,
            keepalive(seed / 3),
            (seed % 5 != 0).then_some(addr_a),
            limiter(seed / 8),
        )
        .unwrap();
        Self {
            a: End::new(ta, addr_a, pa),
            b: End::new(tb, addr_b, pb),
            wire: VecDeque::new(),
            recorded: Vec::new(),
            rng,
            elapsed: 0,
            next_id: 1,
            seed,
            step: 0,
            delivered: 0,
        }
    }

    fn fail(&self, what: &str) -> ! {
        panic!("seed {} step {}: {what}", self.seed, self.step);
    }

    fn r(&mut self, n: u64) -> u64 {
        self.rng.next_u64() % n.max(1)
    }

    fn end(&mut self, is_a: bool) -> &mut End {
        if is_a { &mut self.a } else { &mut self.b }
    }

    fn now(&self, is_a: bool) -> Ticks {
        let e = if is_a { &self.a } else { &self.b };
        e.base.add_nanos(self.elapsed)
    }

    /// Deal with what a call on end `is_a` came back with.
    fn outcome(&mut self, is_a: bool, result: Kind) {
        match result {
            Kind::Net(bytes, to) => {
                let (from, peer) = if is_a {
                    (self.a.addr, self.b.addr)
                } else {
                    (self.b.addr, self.a.addr)
                };
                // Only what is addressed to the peer reaches it; answers
                // to forged sources go nowhere.
                if to == peer {
                    self.wire.push_back((!is_a, from, bytes));
                }
            }
            Kind::Tun(bytes) => {
                if bytes.len() < 28 {
                    self.fail("delivered a packet shorter than anything sent");
                }
                let id = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
                let sender = if is_a { &self.b } else { &self.a };
                match sender.sent.get(&id) {
                    Some(original) if *original == bytes => {}
                    Some(_) => self.fail("delivered packet differs from what was sent"),
                    None => self.fail("delivered a packet nobody sent"),
                }
                if !self.end(is_a).got.insert(id) {
                    self.fail("the same packet delivered twice");
                }
                self.delivered += 1;
            }
            Kind::Internal => self.fail("TunnError::Core(Internal) surfaced"),
            Kind::Nothing => {}
        }
    }

    fn timers(&mut self, is_a: bool) {
        let now = self.now(is_a);
        let mut buf = vec![0u8; 2048];
        for round in 0.. {
            if round > 600 {
                self.fail("update_timers never reached Done at one instant");
            }
            let k = kind(self.end(is_a).tunn.update_timers_at(now, &mut buf));
            // `Nothing` is also what a notification maps to: ask again
            // until the tunnel itself has nothing due.
            let done = matches!(k, Kind::Nothing)
                && self
                    .end(is_a)
                    .tunn
                    .next_wake_at(now)
                    .is_none_or(|wake| wake > now);
            self.outcome(is_a, k);
            if done {
                break;
            }
        }
        if self.end(is_a).tunn.queued() > MAX_QUEUE_DEPTH {
            self.fail("queue beyond its bound");
        }
    }

    fn deliver(&mut self, to_a: bool, src: SocketAddr, mut bytes: Vec<u8>) {
        let now = self.now(to_a);
        let mut out = vec![0u8; 2048];
        // Half through the copying call, half through the in-place one.
        if self.r(2) == 0 {
            let k = kind(
                self.end(to_a)
                    .tunn
                    .decapsulate_at(now, src, &bytes, &mut out),
            );
            self.outcome(to_a, k);
            // BoringTun's convention: drain with empty datagrams.
            for _ in 0..(MAX_QUEUE_DEPTH + 8) {
                let k = kind(self.end(to_a).tunn.decapsulate_at(now, src, &[], &mut out));
                let stop = matches!(k, Kind::Nothing);
                self.outcome(to_a, k);
                if stop {
                    break;
                }
            }
        } else {
            let k = kind(
                self.end(to_a)
                    .tunn
                    .decapsulate_in_place_at(now, src, &mut bytes, &mut out),
            );
            self.outcome(to_a, k);
        }
        self.timers(to_a);
    }

    fn run(&mut self, steps: u64) {
        let evil: SocketAddr = "203.0.113.66:666".parse().unwrap();
        for step in 0..steps {
            self.step = step;
            match self.r(100) {
                // Time passes: mostly a little, sometimes a lot.
                0..=17 => {
                    self.elapsed += match self.r(12) {
                        0 => self.r(700) * 1_000_000_000,
                        1..=3 => self.r(30_000) * 1_000_000,
                        _ => self.r(2_000) * 1_000_000,
                    };
                    self.timers(true);
                    self.timers(false);
                }
                // Either end sends.
                18..=45 => {
                    let is_a = self.r(2) == 0;
                    let id = self.next_id;
                    self.next_id += 1;
                    let len = match self.r(6) {
                        0 => 28,
                        1 => 1420,
                        2 => 1500 + self.r(400) as usize,
                        _ => 28 + self.r(1392) as usize,
                    };
                    let p = packet(id, len);
                    let now = self.now(is_a);
                    let mut buf = vec![0u8; 2048];
                    let (k, taken) = {
                        let r = self.end(is_a).tunn.encapsulate_at(now, &p, &mut buf);
                        let taken = !matches!(r, TunnResult::Err(_));
                        (kind(r), taken)
                    };
                    if taken {
                        self.end(is_a).sent.insert(id, p);
                    }
                    self.outcome(is_a, k);
                    self.timers(is_a);
                }
                // The network delivers the next datagram, as sent …
                46..=70 => {
                    if let Some((to_a, src, bytes)) = self.wire.pop_front() {
                        self.recorded.push((to_a, src, bytes.clone()));
                        self.deliver(to_a, src, bytes);
                    }
                }
                // … or one from further back …
                71..=75 => {
                    let n = self.wire.len();
                    if n > 1 {
                        let i = self.r(n as u64) as usize;
                        let (to_a, src, bytes) = self.wire.remove(i).unwrap();
                        self.recorded.push((to_a, src, bytes.clone()));
                        self.deliver(to_a, src, bytes);
                    }
                }
                // … or loses it …
                76..=79 => {
                    let _ = self.wire.pop_front();
                }
                // … or delivers it twice.
                80..=82 => {
                    if let Some((to_a, src, bytes)) = self.wire.front().cloned() {
                        self.deliver(to_a, src, bytes);
                    }
                }
                // The attacker replays something recorded, perhaps from
                // elsewhere, perhaps to the other end …
                83..=88 => {
                    let n = self.recorded.len();
                    if n > 0 {
                        let i = self.r(n as u64) as usize;
                        let (to_a, src, bytes) = self.recorded[i].clone();
                        let src = if self.r(2) == 0 { src } else { evil };
                        let to_a = if self.r(8) == 0 { !to_a } else { to_a };
                        self.deliver(to_a, src, bytes);
                    }
                }
                // … or flips a bit in something in flight, and may cut
                // it short …
                89..=92 => {
                    if let Some((to_a, src, mut bytes)) = self.wire.front().cloned() {
                        let i = self.r(bytes.len() as u64) as usize;
                        bytes[i] ^= 1 << self.r(8);
                        if self.r(4) == 0 {
                            let cut = self.r(bytes.len() as u64) as usize;
                            bytes.truncate(cut);
                        }
                        self.deliver(to_a, src, bytes);
                    }
                }
                // … or forges a handshake message with a valid mac1 …
                93..=96 => {
                    let to_a = self.r(2) == 0;
                    let target = if to_a { self.a.public } else { self.b.public };
                    let bytes = if self.r(2) == 0 {
                        forged_handshake(1, 148, &target, None, &mut self.rng)
                    } else {
                        let index = self.rng.next_u64() as u32;
                        forged_handshake(2, 92, &target, Some(index), &mut self.rng)
                    };
                    self.deliver(to_a, evil, bytes);
                }
                // … or sends noise, half of it shaped like a message.
                _ => {
                    let to_a = self.r(2) == 0;
                    let len = self.r(200) as usize;
                    let mut bytes = vec![0u8; len];
                    self.rng.fill(&mut bytes).unwrap();
                    if len > 4 && self.r(2) == 0 {
                        bytes[0] = 1 + self.r(4) as u8;
                        bytes[1..4].fill(0);
                    }
                    self.deliver(to_a, evil, bytes);
                }
            }
            if self.wire.len() > 4096 {
                self.wire.drain(..2048);
            }
            if self.recorded.len() > 512 {
                self.recorded.drain(..256);
            }
        }
    }
}

fn setting(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Run `seeds` walks of `steps` steps from `first` on, on `threads`
/// threads; returns how many packets arrived end to end.
fn walks(first: u64, seeds: u64, steps: u64, threads: u64) -> u64 {
    let threads = threads.clamp(1, seeds.max(1));
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|worker| {
                scope.spawn(move || {
                    let mut delivered = 0;
                    for seed in (first..first + seeds).filter(|seed| seed % threads == worker) {
                        let mut sim = Sim::new(seed);
                        sim.run(steps);
                        delivered += sim.delivered;
                    }
                    delivered
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| match worker.join() {
                Ok(delivered) => delivered,
                // The walk's own message says which seed and step.
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .sum()
    })
}

#[test]
fn two_tunnels_keep_their_promises_on_a_hostile_network() {
    let first = setting("HOSTILE_FIRST_SEED", 1);
    let seeds = setting("HOSTILE_SEEDS", 48);
    let steps = setting("HOSTILE_STEPS", 4_000);
    let delivered = walks(first, seeds, steps, 4);
    println!(
        "seeds {first}..{}: {delivered} packets end to end",
        first + seeds
    );
    // The network is hostile, not dead: about one step in twenty ends
    // with a packet delivered. Far fewer, and the walks no longer test
    // what they are for.
    assert!(
        delivered > seeds * steps / 60,
        "only {delivered} packets arrived in {seeds} walks of {steps} steps"
    );
}

#[test]
#[ignore = "minutes on all cores: the long version of the test above"]
fn two_tunnels_keep_their_promises_on_a_hostile_network_for_longer() {
    let first = setting("HOSTILE_FIRST_SEED", 1_000);
    let seeds = setting("HOSTILE_SEEDS", 4_000);
    let steps = setting("HOSTILE_STEPS", 20_000);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get() as u64);
    let delivered = walks(first, seeds, steps, threads);
    println!(
        "seeds {first}..{}: {delivered} packets end to end",
        first + seeds
    );
    assert!(delivered > seeds * steps / 60);
}
