//! Async driver: a [`tokio`] event loop that owns one [`Tunn`] and one
//! `UdpSocket` and shuttles [`PooledBuf`]s between the network and a
//! pair of mpsc channels (your TUN device).
//!
//! ```text
//!             ┌──────────────┐ PooledBuf  ┌──────────────────────────┐
//!  TUN read ─►│ to_net  (tx) │───────────►│                          │
//!             └──────────────┘            │   AsyncTunn::run()       │  UDP
//!             ┌──────────────┐ PooledBuf  │  select! { socket,       │◄─────►
//!  TUN write◄─│ from_net (rx)│◄───────────│   to_net, next_wake }    │ socket
//!             └──────────────┘            └──────────────────────────┘
//! ```
//!
//! # What the loop does, and does not, decide
//!
//! Every iteration first sends whatever the tunnel has ready — packets
//! that were waiting for a session, then timer-driven datagrams — and then
//! waits for the socket, for a packet from the TUN side, or for the
//! tunnel's next timer ([`Tunn::next_wake_at`]). What it wakes up to it
//! takes in batches: up to 32 datagrams, or 32 packets, on one reading of
//! the clock.
//!
//! The loop decides **nothing** about the protocol. In particular it does
//! not track the peer's address: every datagram is sent to the destination
//! the core attached to it. The core moves a peer's endpoint only when the
//! peer has proved where it is, so a datagram that merely *provokes a
//! reply* — a handshake message from anyone who knows our public key,
//! answered with a cookie under load; a replayed initiation, answered with
//! a response — cannot redirect the tunnel. Nor does the loop look inside
//! the packets it delivers: checking a packet's inner source address
//! against the peer's allowed IPs is the TUN side's job.
//!
//! # Traffic first
//!
//! What arrives is not all worth the same. A transport datagram is dealt
//! with at once: decrypted (or rejected, which is cheaper) and passed on.
//! A handshake message is only *looked at* when it arrives — the keyed
//! hashes that say whether it knows our public key and, under load,
//! whether it holds a cookie — and then waits:
//!
//! * one that passed is queued, at most thirty-two of them, and its
//!   Diffie-Hellman operations are done when the socket has been read;
//! * one that needs a cookie first is remembered as the forty bytes the
//!   reply is made from, at most 256 of them, and the reply is made
//!   after everything else;
//! * one that passed neither check is dropped on the spot.
//!
//! While the socket has no more than the loop can take at a time, what
//! waits is done within the same turn: for a quarter of a millisecond at
//! a stretch when the socket had nothing, and for less the more it had,
//! so that what arrives meanwhile stays a fraction of what the loop takes
//! at a time. While the socket has more than that — a flood — handshake
//! work gets a third of the loop's time and traffic the rest; what does
//! not fit the two queues is dropped and counted
//! ([`LoopStats::handshake_drops`], [`LoopStats::cookie_reply_drops`]),
//! and a cookie reply the socket has no room for is dropped rather than
//! put in the way of the tunnel's own datagrams. So a flood of handshake
//! messages — which anyone who knows our public key can send — costs
//! handshakes, as it must (theirs wait for a cookie; that is the
//! protocol's defence), and does not cost the session that is up: its
//! packets are neither kept waiting behind someone else's X25519 nor
//! behind replies to strangers.
//!
//! (It used to: every datagram was dealt with in full, in the order it
//! came. With the load signal of the time — a tenth of each second, all
//! of it up front — 150,000 forged initiations a second cost a tunnel a
//! tenth of a second of deafness every second, and 400,000 all of it.
//! `embed/tests/flood.rs` measures what they cost now: nothing, up to
//! what the loop can look at — half a million a second on the machine
//! this was written on — and beyond that what the socket's buffer has no
//! room for, the session's datagrams at the same odds as the flood's.)
//!
//! # When things go wrong
//!
//! Nothing that arrives from the network, and nothing the rest of the
//! program does short of closing a channel, ends the loop. And the loop
//! waits for nothing but its next event: no call it makes on the socket
//! blocks, and none is awaited. Whatever the socket's state, it goes on
//! reading it — handshake messages, keepalives and cookie replies arrive
//! there too, and a tunnel that stops reading them declares its peer dead
//! fifteen seconds later and loses its session after three minutes.
//!
//! * **The TUN side is slow.** When `from_net` is full, a decrypted packet
//!   that has nowhere to go is dropped and counted
//!   ([`LoopStats::tun_drops`]) — what a full socket buffer does. Size the
//!   channel for the bursts you want to absorb.
//! * **The socket has no room** — the way out is slower than the traffic.
//!   The datagram that did not fit is set aside and the loop stops taking
//!   packets from `to_net`, which fills up: that is how the TUN side
//!   learns to slow down (or to drop, as it chooses). When the socket has
//!   room again, what was set aside goes out first. Answers to what
//!   arrives in the meantime — a handshake response, a cookie reply — are
//!   set aside behind it, up to sixteen datagrams in all; any beyond
//!   that are dropped and counted ([`LoopStats::egress_drops`]). The
//!   tunnel's timers wait too: what they want to send would only queue
//!   behind the rest.
//! * **A datagram cannot be sent** (no route for a moment, a firewall).
//!   The send is tried again, twice — an error a socket reports on a send
//!   is as often as not about an *earlier* datagram (see below), and then
//!   the one at hand has not been sent at all
//!   ([`LoopStats::send_retries`]). If it still fails it is counted in
//!   [`LoopStats::send_errors`] and otherwise treated as lost on the
//!   network: the protocol's timers recover from loss whatever its cause.
//! * **A packet from the TUN side is too large** to fit a pool buffer
//!   once it is encrypted. It is dropped and counted in
//!   [`LoopStats::oversize_drops`]; with the default buffers and a TUN
//!   device at the usual MTU this does not happen.
//! * **The socket reports an error.** On a connected socket, or one with
//!   `IP_RECVERR` / `IPV6_RECVERR`, the kernel reports ICMP errors about
//!   datagrams sent earlier: a path-MTU change (`EMSGSIZE`), a firewall's
//!   reject (`EACCES`), a port, host, network or protocol that is
//!   unreachable, and more. Any host that can reach ours can forge every
//!   one of them, knowing no more than our address, so none of them may
//!   end the tunnel, stop it listening, or cost it a datagram:
//!
//!   * The error is taken from the socket as soon as the socket signals
//!     it, and counted ([`LoopStats::recv_errors`]). Left there, the
//!     kernel would hand it to whichever call came next — and if that is
//!     a send, the datagram is not sent.
//!   * With `IP_RECVERR`, Linux also *keeps* every such error, in the
//!     socket's error queue, and what is in that queue counts against the
//!     socket's receive buffer: a couple of hundred unread errors, and the
//!     socket drops every datagram it is sent, for good. The loop reads
//!     the queue empty whenever the socket reports an error
//!     ([`LoopStats::error_queue_messages`]) and discards what it reads —
//!     the kernel has acted on a path-MTU change by then. The queue is
//!     therefore the loop's: do not expect to find anything in it
//!     yourself (transmit timestamps and zero-copy notifications, which
//!     arrive there, included).
//!
//!   If receiving fails sixteen times running, with not one datagram and
//!   not one "nothing there" in between — a socket that is broken, not one
//!   that is being told things — it is left alone for a tenth of a second
//!   at a time, so that it cannot spin the loop. Timers and outbound
//!   traffic are not affected.
//!
//! # Time
//!
//! The loop keeps the tunnel's time itself: tokio's clock, plus the time
//! the machine has spent suspended since the loop started.
//!
//! * tokio's clock, so that a test can pause it and move it
//!   (`tokio::time::pause`, `start_paused`): the tunnel's timers then run
//!   on that time, as every other timer in the test does.
//! * The time spent suspended, because tokio's clock does not count it and
//!   WireGuard's lifetimes are in real time: see [`Tunn::now`]. A sleep
//!   that a suspend interrupts cannot know; so, where the system has a
//!   clock that counts suspend ([`Tunn::CLOCK_COUNTS_SUSPEND`]), the loop
//!   does not sleep longer than ten seconds at a stretch, and looks at
//!   that clock when it wakes.
//!
//! # What the loop knows
//!
//! `run` takes the [`Tunn`] with it. What an embedder could ask it
//! before — its counters, how many packets are waiting, where the peer is
//! — the running loop publishes in [`LoopStats`], together with what the
//! loop itself had to drop: take the handle from
//! [`AsyncTunn::loop_stats`] before calling [`AsyncTunn::run`].
//!
//! # Buffers
//!
//! All buffers are [`PooledBuf`] from one shared [`SlabPool`], so the
//! steady-state loop does no heap allocation, and the receive path does no
//! copy either: a slab comes off the freelist for the receive, the packet
//! is decrypted in place, the same slab travels through the channel with
//! its valid range set to the plaintext, and it returns to the freelist
//! when the TUN writer drops it.
//!
//! tokio's `UdpSocket` is **readiness-based** (epoll/kqueue/IOCP poll
//! mode): the kernel tells us "readable", then we copy into our buffer.
//! That doesn't need a stable address. But [`PooledBuf`]'s backing
//! `Box<[u8]>` *has* one anyway, which is exactly what
//! **completion-based** I/O (Linux `tokio-uring`'s
//! `UdpSocket::recv_from(BoundedBuf)`, Windows RIO) requires. Swapping
//! the socket type below is the only change needed for that upgrade.
//!
//! # Threading
//!
//! `run()` is the single owner of the `Tunn`; the rest of your program
//! talks to it through the two channels. Spawn `run()` on its own task.
//!
//! The task does not keep its thread to itself, however much there is to
//! do: after every full batch, and every thirty-two turns of the loop
//! whatever they were, it hands control back to the runtime. (A loop
//! that always finds a datagram waiting would otherwise never pass
//! through the scheduler — waiting for a socket is not something tokio
//! meters — and on a single-threaded runtime nothing else would run,
//! the task that reads `from_net` included.)

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{Interest, Ready};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::{Instant as TokioInstant, sleep_until};

use wireguard_sans_io::{CookieChallenge, DeviceStats, Error, Stats, Ticks};

use crate::{PLAINTEXT_OFFSET, PooledBuf, SlabPool, Triage, Tunn, TunnError, TunnResult};

/// How long to wait before retrying after the core reports a local fault
/// (for example an entropy failure), so a persistent fault cannot spin
/// the loop — and how long a socket that does nothing but fail is left
/// alone.
const FAULT_BACKOFF: Duration = Duration::from_millis(100);

/// Upper bound on datagrams sent per loop iteration before the loop goes
/// back to `select!`, so a long queue cannot starve the receive path.
const FLUSH_BUDGET: usize = 64;

/// Datagrams received, or packets taken from the TUN side, per wake-up
/// before the loop looks at its other sources again.
const BATCH: usize = 32;

/// How many receive errors in a row — with no datagram received and no
/// "nothing to receive" in between — the loop takes before it leaves the
/// socket alone for [`FAULT_BACKOFF`]. An ICMP error is one failed receive
/// and then the socket works again; an unbroken run means it does not.
const RECV_ERROR_BURST: u32 = 16;

/// How often a send is tried before the datagram is given up as lost. A
/// failure may be an earlier datagram's ICMP error, reported on this send;
/// three in a row are this datagram's own.
const SEND_ATTEMPTS: u32 = 3;

/// How many datagrams are kept for a socket that has no room. One is the
/// datagram that found it full; the rest are answers to what arrived
/// while it was.
const OUTBOX_DEPTH: usize = 16;

/// How many messages are read from the socket's error queue at a time
/// before the loop looks at its other sources again.
const ERROR_QUEUE_BATCH: usize = 64;

/// Where the tunnel's clock counts time spent suspended, the longest the
/// loop sleeps before it looks at that clock again.
const SUSPEND_LOOK: Duration = Duration::from_secs(10);

/// How often a socket that has no room is tried again where tokio cannot
/// say when it has (see `write_stuck` in [`AsyncTunn::run`]).
const WRITE_RETRY: Duration = Duration::from_millis(1);

/// How many turns of the loop may follow one another without the task
/// having handed control back to the runtime.
const YIELD_EVERY: u32 = 32;

/// How many handshake messages that passed the cheap checks wait for
/// their Diffie-Hellman operations, at the most. One peer sends one every
/// five seconds; the rest of a full queue is somebody's flood, and what
/// arrives at it is dropped.
const HANDSHAKE_QUEUE: usize = 32;

/// How many cookie replies are owed at the most (forty bytes each, the
/// part of a handshake message the reply is made from).
const COOKIE_QUEUE: usize = 256;

/// The longest stretch of handshake work — queued handshake messages,
/// then cookie replies — between two looks at the socket: what a packet
/// may be kept waiting by it, and what the loop allows itself when the
/// socket had nothing. When it had something, the stretch is shorter in
/// proportion (see [`Allowance::refill`]). (At least one item is done
/// whatever it takes: a handshake answered is about half of this.)
const DEFERRED_SLICE: Duration = Duration::from_micros(250);

/// While the socket has more waiting than the loop takes at a time,
/// handshake work is given one part of time for every this many parts
/// spent receiving: a third of the loop, with two.
const DEFERRED_SHARE: u64 = 2;

/// How often, at most, the loop looks at the machine's clocks (for a
/// suspend, and for whether tokio's clock is in step with them). In
/// between, one reading of tokio's clock per wake-up is all it takes.
const CLOCK_LOOK: Duration = Duration::from_millis(1);

/// How far tokio's clock and the machine's may have drifted apart since
/// the loop started and still count as the same clock. (Unpaused they
/// *are* the same clock, read a few nanoseconds apart.)
const STEADY_SLACK_NS: u64 = 100_000_000;

/// How much time handshake work may still take before the loop looks at
/// the socket again, in nanoseconds (see the module docs, "Traffic
/// first"). Negative: it has taken more than its share, and waits until
/// receiving has made up for that.
#[derive(Debug, Default)]
struct Allowance(i64);

impl Allowance {
    /// The socket was read empty, `room` datagrams short of the
    /// [`BATCH`] the loop takes at a time: whatever was owed, that part
    /// of a [`DEFERRED_SLICE`] — all of it after a look that found
    /// nothing, a thirty-second of it after one that found a datagram
    /// less than a batch.
    ///
    /// What the socket held is what arrived during the last stretch, so
    /// this is a stretch that shrinks as traffic grows: the datagrams
    /// that wait for it to end stay a fraction of a batch, where a fixed
    /// quarter of a millisecond is a hundred datagrams of a flood the
    /// loop could otherwise just keep up with — half a socket buffer of
    /// the default size, and with a little bad luck all of it.
    fn refill(&mut self, room: usize) {
        let room = i64::try_from(room.clamp(1, BATCH)).unwrap_or(1);
        let batch = i64::try_from(BATCH).unwrap_or(i64::MAX);
        let part = slice_ns()
            .saturating_mul(room)
            .checked_div(batch)
            .unwrap_or(0);
        self.0 = self.0.max(part.max(1));
    }

    /// Receiving took `receiving` while the socket was backed up:
    /// handshake work has earned its share of that — one part in
    /// [`DEFERRED_SHARE`], never more than a slice in all.
    fn earn(&mut self, receiving: Duration) {
        let share = nanos(receiving).checked_div(DEFERRED_SHARE).unwrap_or(0);
        self.0 = self
            .0
            .saturating_add(i64::try_from(share).unwrap_or(i64::MAX))
            .min(slice_ns());
    }

    /// Handshake work took `took`.
    fn spend(&mut self, took: Duration) {
        self.0 = self
            .0
            .saturating_sub(i64::try_from(nanos(took)).unwrap_or(i64::MAX));
    }

    /// May another item be done?
    fn open(&self) -> bool {
        self.0 > 0
    }
}

/// What the running loop knows: what it could not deliver, and what the
/// tunnel it owns has counted. Shared with the loop: take the handle from
/// [`AsyncTunn::loop_stats`] before calling [`AsyncTunn::run`].
#[derive(Debug, Default)]
pub struct LoopStats {
    send_errors: AtomicU64,
    send_retries: AtomicU64,
    egress_drops: AtomicU64,
    recv_errors: AtomicU64,
    recv_pauses: AtomicU64,
    error_queue_messages: AtomicU64,
    tun_drops: AtomicU64,
    oversize_drops: AtomicU64,
    handshake_drops: AtomicU64,
    cookie_reply_drops: AtomicU64,
    wakeups: AtomicU64,
    /// The tunnel's own figures, as of the loop's last iteration.
    published: Mutex<Published>,
}

/// What the loop publishes of its [`Tunn`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Published {
    tunnel: Stats,
    device: DeviceStats,
    endpoint: Option<SocketAddr>,
    queued: usize,
    queue_drops: u64,
}

impl LoopStats {
    /// Datagrams the socket refused to send, three times over. Each was
    /// treated as lost.
    #[must_use]
    pub fn send_errors(&self) -> u64 {
        self.send_errors.load(Ordering::Relaxed)
    }

    /// Sends that were repeated because the socket reported an error:
    /// usually an ICMP error about an earlier datagram, which the kernel
    /// reports on whichever call comes next.
    #[must_use]
    pub fn send_retries(&self) -> u64 {
        self.send_retries.load(Ordering::Relaxed)
    }

    /// Datagrams dropped because the socket had no room for them and too
    /// many were already waiting for it: answers to handshake messages
    /// that arrived while the way out was full.
    #[must_use]
    pub fn egress_drops(&self) -> u64 {
        self.egress_drops.load(Ordering::Relaxed)
    }

    /// Errors the socket reported that were not about a send of ours: on
    /// a receive, or taken from the socket when it signalled one.
    /// Typically ICMP errors about datagrams sent earlier — genuine or
    /// forged. None of them ends the loop.
    #[must_use]
    pub fn recv_errors(&self) -> u64 {
        self.recv_errors.load(Ordering::Relaxed)
    }

    /// How often the socket was left alone for a tenth of a second
    /// because receiving did nothing but fail (sixteen errors running:
    /// see the module docs). ICMP errors do not do this, however many;
    /// a number here says the socket itself is in trouble.
    #[must_use]
    pub fn recv_pauses(&self) -> u64 {
        self.recv_pauses.load(Ordering::Relaxed)
    }

    /// Messages read from the socket's error queue and discarded (Linux,
    /// a socket with `IP_RECVERR` or `IPV6_RECVERR`): one per ICMP error
    /// the kernel accepted for the socket. (The same error may also have
    /// been reported on a call first, and be counted there as well.)
    #[must_use]
    pub fn error_queue_messages(&self) -> u64 {
        self.error_queue_messages.load(Ordering::Relaxed)
    }

    /// Decrypted packets dropped because `from_net` was full: the TUN
    /// side was not reading fast enough.
    #[must_use]
    pub fn tun_drops(&self) -> u64 {
        self.tun_drops.load(Ordering::Relaxed)
    }

    /// Packets from the TUN side that were too large to send: encrypted,
    /// a packet grows by 32 bytes (and up to 15 of padding), and the
    /// datagram has to fit one pool buffer. With the default 2048-byte
    /// buffers that means packets of some 2000 bytes and more — far beyond
    /// what a correctly configured TUN device (MTU 1420) hands over.
    #[must_use]
    pub fn oversize_drops(&self) -> u64 {
        self.oversize_drops.load(Ordering::Relaxed)
    }

    /// Handshake messages that passed the cheap checks and were dropped
    /// all the same, because thirty-two such were already waiting for
    /// their turn: more of them than the loop had time for. Their senders
    /// retransmit.
    #[must_use]
    pub fn handshake_drops(&self) -> u64 {
        self.handshake_drops.load(Ordering::Relaxed)
    }

    /// Cookie replies that were owed and not made: too many were waiting
    /// already, the socket had no room, or the limiter's cap on them was
    /// reached ([`crate::RateLimiter::with_cookie_reply_limit`]). Under
    /// a flood this is where most of it ends.
    #[must_use]
    pub fn cookie_reply_drops(&self) -> u64 {
        self.cookie_reply_drops.load(Ordering::Relaxed)
    }

    /// How often the loop has woken up: once for every batch of
    /// datagrams or packets, and for every timer. (A loop that is idle
    /// wakes up for the tunnel's timers and, where the clock counts time
    /// spent suspended, every ten seconds.)
    #[must_use]
    pub fn wakeups(&self) -> u64 {
        self.wakeups.load(Ordering::Relaxed)
    }

    /// [`Tunn::queue_drops`] of the tunnel the loop owns: packets that
    /// were waiting for a session and were given up — pushed out of a
    /// full queue, too old, or impossible to encrypt.
    #[must_use]
    pub fn queue_drops(&self) -> u64 {
        self.published().queue_drops
    }

    /// [`Tunn::queued`]: packets waiting for a session right now.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.published().queued
    }

    /// [`Tunn::stats`]: the tunnel's cumulative counters.
    #[must_use]
    pub fn tunnel_stats(&self) -> Stats {
        self.published().tunnel
    }

    /// [`Tunn::device_stats`]: what was dropped before it reached the
    /// tunnel, and the cookies.
    #[must_use]
    pub fn device_stats(&self) -> DeviceStats {
        self.published().device
    }

    /// [`Tunn::endpoint`]: where the core currently sends this peer's
    /// datagrams.
    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.published().endpoint
    }

    fn published(&self) -> Published {
        // Nothing done under this lock can leave it half-written.
        *self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn count(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// One peer's async driver.
pub struct AsyncTunn {
    tunn: Tunn,
    socket: Arc<UdpSocket>,
    pool: Arc<SlabPool>,
    stats: Arc<LoopStats>,
    /// Datagrams the socket had no room for, in the order they are to go
    /// out, each with where it goes. While there are any, nothing new is
    /// made: see the module docs.
    outbox: VecDeque<(PooledBuf, SocketAddr)>,
    /// Handshake messages that passed the cheap checks, each with where
    /// it came from, waiting for the expensive part (see the module docs,
    /// "Traffic first").
    handshakes: VecDeque<(PooledBuf, SocketAddr)>,
    /// Cookie replies that are owed.
    challenges: VecDeque<CookieChallenge>,
    /// The time handshake work may still take before the loop looks at
    /// the socket again.
    deferred: Allowance,
    /// What the socket is to answer instead of being asked.
    #[cfg(test)]
    script: Arc<Script>,
}

impl std::fmt::Debug for AsyncTunn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncTunn")
            .field("tunn", &self.tunn)
            .field("socket", &self.socket)
            .field("held", &self.outbox.len())
            .finish_non_exhaustive()
    }
}

/// The two channel halves the rest of your program holds.
#[derive(Debug)]
pub struct TunnChannels {
    /// Send IP packets here to have them encrypted and put on the wire.
    /// Buffer comes from the shared pool: `pool.get()`, fill, `set_len`,
    /// send.
    pub to_net: mpsc::Sender<PooledBuf>,
    /// Decrypted IP packets arrive here, padding already trimmed.
    /// Dropping the `PooledBuf` returns it to the pool.
    pub from_net: mpsc::Receiver<PooledBuf>,
}

/// The loop's two working buffers: one for everything it transmits, one
/// it receives into. Both live for the whole loop; either is swapped for
/// a fresh one when it leaves with its contents.
struct Slabs {
    net_out: PooledBuf,
    rx: PooledBuf,
}

/// What woke the loop up.
enum Event {
    /// The TUN side went away.
    Closed,
    /// The socket has something to receive, or an error to report.
    Socket(io::Result<Ready>),
    /// The socket (says it) has room again.
    Room(io::Result<Ready>),
    /// A packet from the TUN side — or the end of them.
    Packet(Option<PooledBuf>),
    /// The timer.
    Timer,
}

/// What became of an attempt to put a datagram on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    /// The socket took it.
    Sent,
    /// The socket has no room.
    Full,
    /// The socket refused it, every time it was tried.
    Failed,
}

/// Receive errors in a row.
#[derive(Debug, Default)]
struct ErrorStreak(u32);

impl ErrorStreak {
    /// A receive failed. `true` if that makes [`RECV_ERROR_BURST`] in a
    /// row: time to leave the socket alone for a moment.
    fn error(&mut self) -> bool {
        self.0 = self.0.saturating_add(1);
        if self.0 >= RECV_ERROR_BURST {
            self.0 = 0;
            return true;
        }
        false
    }

    /// A receive produced a datagram, or found that there is none: the
    /// socket works.
    fn progress(&mut self) {
        self.0 = 0;
    }
}

/// The tunnel's clock as the loop keeps it: tokio's clock, plus the time
/// the machine has spent suspended since the loop started (see the module
/// docs, "Time").
#[derive(Debug)]
struct LoopClock {
    /// The tunnel's clock when the loop started…
    base: Ticks,
    /// …tokio's…
    started: TokioInstant,
    /// …the machine's own, which like tokio's stands still while the
    /// machine is suspended…
    awake_at_start: u64,
    /// …and how much time it had spent suspended by then.
    suspended_at_start: u64,
    /// What the last look at the machine's clocks found: the time spent
    /// suspended since the loop started, and whether tokio's clock is in
    /// step with the machine's (it is not when a test has paused it).
    suspended: u64,
    steady: bool,
    /// When that look was, by tokio's clock.
    looked: TokioInstant,
}

/// One reading of the [`LoopClock`].
#[derive(Debug, Clone, Copy)]
struct Reading {
    /// The tunnel's time.
    now: Ticks,
    /// tokio's.
    instant: TokioInstant,
    /// Is tokio's clock in step with the machine's?
    steady: bool,
}

impl LoopClock {
    fn start(tunn: &Tunn) -> Self {
        let (awake_at_start, suspended_at_start) = tunn.awake_and_suspended_ns();
        let started = TokioInstant::now();
        Self {
            base: tunn.now(),
            started,
            awake_at_start,
            suspended_at_start,
            suspended: 0,
            steady: true,
            looked: started,
        }
    }

    fn read(&mut self, tunn: &Tunn) -> Reading {
        let instant = TokioInstant::now();
        let elapsed = nanos(instant.saturating_duration_since(self.started));
        if instant.saturating_duration_since(self.looked) >= CLOCK_LOOK {
            self.looked = instant;
            let (awake, suspended) = tunn.awake_and_suspended_ns();
            self.look(
                elapsed,
                awake.saturating_sub(self.awake_at_start),
                suspended.saturating_sub(self.suspended_at_start),
            );
        }
        Reading {
            now: self.ticks(elapsed),
            instant,
            steady: self.steady,
        }
    }

    /// Take note of what the machine's clocks say: `awake` and
    /// `suspended` nanoseconds since the loop started, when tokio's clock
    /// says `elapsed`.
    fn look(&mut self, elapsed: u64, awake: u64, suspended: u64) {
        // Time spent suspended does not come back.
        self.suspended = self.suspended.max(suspended);
        self.steady = elapsed.abs_diff(awake) < STEADY_SLACK_NS;
    }

    /// The tunnel's time when tokio's clock says `elapsed` nanoseconds
    /// have passed since the loop started.
    fn ticks(&self, elapsed: u64) -> Ticks {
        self.base.add_nanos(elapsed).add_nanos(self.suspended)
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// [`DEFERRED_SLICE`] in nanoseconds, as an allowance.
fn slice_ns() -> i64 {
    i64::try_from(nanos(DEFERRED_SLICE)).unwrap_or(i64::MAX)
}

/// `instant + wait`, or as near as an `Instant` gets.
fn after(instant: TokioInstant, wait: Duration) -> TokioInstant {
    instant
        .checked_add(wait)
        .unwrap_or_else(|| far_future(instant))
}

fn far_future(instant: TokioInstant) -> TokioInstant {
    instant
        .checked_add(Duration::from_secs(86_400))
        .unwrap_or(instant)
}

impl AsyncTunn {
    /// Wrap a `Tunn` and a bound `UdpSocket`. Where to reach the peer is
    /// the `Tunn`'s business: give it an endpoint when you create it, or
    /// let it learn one from the peer's first authenticated message.
    #[must_use]
    pub fn new(tunn: Tunn, socket: Arc<UdpSocket>) -> Self {
        let pool = Arc::clone(tunn.pool());
        let driver = Self {
            tunn,
            socket,
            pool,
            stats: Arc::default(),
            outbox: VecDeque::with_capacity(OUTBOX_DEPTH),
            handshakes: VecDeque::with_capacity(HANDSHAKE_QUEUE),
            challenges: VecDeque::with_capacity(COOKIE_QUEUE),
            deferred: Allowance::default(),
            #[cfg(test)]
            script: Arc::default(),
        };
        driver.publish(&mut Published::default());
        driver
    }

    /// Build the channel pair and the driver in one call. `depth` is the
    /// mpsc bound in each direction (number of in-flight `PooledBuf`s);
    /// 256 matches [`crate::MAX_QUEUE_DEPTH`]. A depth of 0 is treated as
    /// 1 (a channel needs room for one item), and one beyond what a tokio
    /// channel can be given as the largest it can.
    #[must_use]
    pub fn channels(
        tunn: Tunn,
        socket: Arc<UdpSocket>,
        depth: usize,
    ) -> (
        Self,
        TunnChannels,
        mpsc::Receiver<PooledBuf>,
        mpsc::Sender<PooledBuf>,
    ) {
        let depth = depth.clamp(1, tokio::sync::Semaphore::MAX_PERMITS);
        let (to_net_tx, to_net_rx) = mpsc::channel(depth);
        let (from_net_tx, from_net_rx) = mpsc::channel(depth);
        let driver = Self::new(tunn, socket);
        (
            driver,
            TunnChannels {
                to_net: to_net_tx,
                from_net: from_net_rx,
            },
            to_net_rx,
            from_net_tx,
        )
    }

    /// The shared pool — hand to your TUN reader so it allocates from
    /// the same freelist.
    #[must_use]
    pub fn pool(&self) -> &Arc<SlabPool> {
        &self.pool
    }

    /// Where the core currently sends this peer's datagrams. (Once the
    /// loop runs: [`LoopStats::peer_addr`].)
    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.tunn.endpoint()
    }

    /// Borrow the inner sync `Tunn` (e.g. for `stats()`). Once the loop
    /// runs, [`LoopStats`] has what it counts.
    #[must_use]
    pub fn tunn(&self) -> &Tunn {
        &self.tunn
    }

    /// What the running loop knows; see [`LoopStats`].
    #[must_use]
    pub fn loop_stats(&self) -> Arc<LoopStats> {
        Arc::clone(&self.stats)
    }

    /// Run the event loop until either channel closes. Spawn this on its
    /// own task:
    ///
    /// ```ignore
    /// let (driver, chans, to_net_rx, from_net_tx) = AsyncTunn::channels(tunn, socket, 256);
    /// let stats = driver.loop_stats();
    /// tokio::spawn(driver.run(to_net_rx, from_net_tx));
    /// // your code talks to `chans.to_net` / `chans.from_net`, and reads `stats`
    /// ```
    ///
    /// # Errors
    /// [`std::io::ErrorKind::Unsupported`] if the runtime it runs on has
    /// no timer (`Builder::enable_time` or `enable_all`; `#[tokio::main]`
    /// has it): the tunnel cannot work without timers, and the loop does
    /// not start. (A program built with `panic = "abort"` aborts there
    /// instead, as tokio itself does.) Otherwise only what tokio reports
    /// when the runtime's I/O driver is gone — the runtime is shutting
    /// down. Socket errors are counted in [`LoopStats`] and the loop goes
    /// on: see the module docs for why.
    pub async fn run(
        mut self,
        mut to_net: mpsc::Receiver<PooledBuf>,
        from_net: mpsc::Sender<PooledBuf>,
    ) -> io::Result<()> {
        // tokio panics when a sleep is created on a runtime without the
        // time driver, and has no way of asking. Find out here, once, and
        // say so, rather than panicking somewhere inside the loop.
        if std::panic::catch_unwind(|| drop(tokio::time::sleep(Duration::ZERO))).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "AsyncTunn::run needs a tokio runtime with timers enabled \
                 (Builder::enable_time or enable_all)",
            ));
        }
        let mut slabs = Slabs {
            net_out: self.pool.get(),
            rx: self.pool.get(),
        };
        let mut clock = LoopClock::start(&self.tunn);
        let mut reading = clock.read(&self.tunn);
        // One timer for the life of the loop. `armed` is the deadline it
        // is set to; it is set again only when the deadline has passed or
        // an earlier one is wanted. (The deadline usually moves *later* —
        // every packet restarts a keepalive interval — and then the timer
        // is left where it is: it fires early, finds nothing due, and is
        // set again.)
        let sleep = sleep_until(far_future(reading.instant));
        tokio::pin!(sleep);
        let mut armed: Option<TokioInstant> = None;
        let closed = from_net.closed();
        tokio::pin!(closed);
        let mut streak = ErrorStreak::default();
        let mut recv_paused_until: Option<TokioInstant> = None;
        // tokio cannot say when this socket has room again: see
        // `Event::Room` below.
        let mut write_stuck = false;
        let mut published = Published::default();
        // Turns of the loop since the task last stepped aside.
        let mut turns = 0u32;
        // How many datagrams short of a full batch the last look at the
        // socket was. Zero: it found more than the loop takes at a time,
        // the socket is backed up. (After such a look tokio still holds
        // the socket to be readable, so the next one is not far off:
        // a zero cannot go stale while the socket is idle.)
        let mut room = BATCH;

        loop {
            let Reading {
                now,
                instant,
                steady,
            } = reading;
            LoopStats::count(&self.stats.wakeups);

            // Whatever is ready to go out goes out first: packets that
            // were waiting for a session, then timer-driven datagrams —
            // if the socket is taking any. (Asking costs less than
            // trying: nearly every time, nothing is due.)
            let mut fault = false;
            if self.outbox.is_empty() && self.tunn.next_wake_at(now).is_some_and(|due| due <= now) {
                fault = self.flush(now, &mut slabs.net_out);
            }
            self.publish(&mut published);

            // When to wake up if nothing else happens.
            let blocked = !self.outbox.is_empty();
            let mut wake = far_future(instant);
            if blocked {
                // The timers wait for the socket. So does this loop —
                // on tokio's word where that can be had.
                if write_stuck {
                    wake = after(instant, WRITE_RETRY);
                }
            } else {
                if let Some(due) = self.tunn.next_wake_at(now) {
                    wake = after(instant, Duration::from_nanos(due.since(now)));
                }
                if fault {
                    // The core reported a local fault and the work is
                    // still due: wait a little instead of spinning on it.
                    wake = wake.max(after(instant, FAULT_BACKOFF));
                }
                // Handshake work that did not fit the last stretch: back
                // for it at once. (Not while the socket is backed up:
                // its own events bring the loop round, and the share of
                // handshake work is counted against them.)
                if self.has_deferred() && room > 0 {
                    wake = instant;
                }
            }
            // While receiving is paused, wake up when the pause ends.
            recv_paused_until = recv_paused_until.filter(|until| instant < *until);
            if let Some(until) = recv_paused_until {
                wake = wake.min(until);
            }
            // A sleep cannot tell that the machine was suspended in the
            // middle of it. (Not on a clock a test is moving by hand:
            // there the loop's time *is* tokio's.)
            if steady && Tunn::CLOCK_COUNTS_SUSPEND {
                wake = wake.min(after(instant, SUSPEND_LOOK));
            }
            if armed.is_none_or(|at| wake < at) {
                sleep.as_mut().reset(wake);
                armed = Some(wake);
            }

            let event = tokio::select! {
                () = &mut closed => Event::Closed,
                ready = self.socket.ready(Interest::READABLE | Interest::ERROR),
                    if recv_paused_until.is_none() => Event::Socket(ready),
                ready = self.socket.ready(Interest::WRITABLE),
                    if blocked && !write_stuck => Event::Room(ready),
                packet = to_net.recv(), if !blocked => Event::Packet(packet),
                () = &mut sleep => Event::Timer,
            };
            // The one clock reading of this wake-up: for what there is to
            // do now, and for the flush and the timer at the top of the
            // loop when it is done.
            reading = clock.read(&self.tunn);
            let now = reading.now;
            // Did this turn take all it may take at a time — so that
            // there is, in all likelihood, more where that came from?
            let mut full = false;

            match event {
                Event::Closed | Event::Packet(None) => return Ok(()),

                // ---- inbound from the network ----------------------------
                Event::Socket(ready) => {
                    if ready?.is_error() {
                        self.error_signalled();
                    }
                    full = true;
                    let batch_started = std::time::Instant::now();
                    let mut taken = 0usize;
                    for _ in 0..BATCH {
                        match self.wire_recv(slabs.rx.spare_mut()) {
                            Ok((len, src)) => {
                                streak.progress();
                                taken = taken.saturating_add(1);
                                if !self.on_datagram(now, len, src, &mut slabs, &from_net) {
                                    return Ok(()); // consumer gone
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                streak.progress();
                                full = false;
                                break;
                            }
                            // No receive error ends the loop: every one of
                            // them can be provoked from outside (see the
                            // module docs). Count it, take whatever else
                            // the socket holds against us, and carry on —
                            // with a pause if it does nothing but fail.
                            Err(_) => {
                                LoopStats::count(&self.stats.recv_errors);
                                let _ = self.take_socket_errors();
                                if streak.error() {
                                    LoopStats::count(&self.stats.recv_pauses);
                                    recv_paused_until = Some(after(reading.instant, FAULT_BACKOFF));
                                    full = false;
                                    break;
                                }
                            }
                        }
                    }
                    if full {
                        room = 0;
                        self.deferred.earn(batch_started.elapsed());
                    } else {
                        room = BATCH.saturating_sub(taken).max(1);
                    }
                }

                // ---- the socket has room again ---------------------------
                Event::Room(ready) => {
                    let ready = ready?;
                    self.drain_outbox();
                    // tokio says "writable", and the socket says it is
                    // full. After an ICMP error that is all tokio will
                    // ever say about this socket: the event that reports
                    // one looks to it like the far end of a pipe going
                    // away, which it remembers as final, and "closed for
                    // writing" counts as "ready for writing". Waiting on
                    // that would spin; such a socket is tried on a timer
                    // instead.
                    if !self.outbox.is_empty() && (ready & Ready::WRITABLE).is_empty() {
                        write_stuck = true;
                    }
                }

                // ---- outbound from the TUN -------------------------------
                Event::Packet(Some(mut packet)) => {
                    let mut budget = BATCH;
                    loop {
                        // `false`: the socket is full. The packets behind
                        // this one stay in the channel.
                        if !self.on_packet(now, &packet, &mut slabs.net_out) {
                            break;
                        }
                        budget = budget.saturating_sub(1);
                        if budget == 0 {
                            full = true;
                            break;
                        }
                        // (The packet before goes back to the pool here.)
                        match to_net.try_recv() {
                            Ok(next) => packet = next,
                            Err(_) => break,
                        }
                    }
                }

                // ---- timers ----------------------------------------------
                Event::Timer => {
                    armed = None;
                    // The flush at the top of the loop runs whatever has
                    // fallen due. What is left to do here is the socket
                    // that tokio cannot watch for us.
                    if !self.outbox.is_empty() {
                        self.drain_outbox();
                    }
                }
            }

            // What was put off: handshake messages that passed the cheap
            // checks, then cookie replies — as much as traffic leaves
            // time for (see the module docs, "Traffic first").
            self.serve_deferred(now, &mut slabs, room);

            // A turn of this loop does not necessarily pass through the
            // runtime: `select!` returns at once when one of its branches
            // is ready, and tokio does not meter waiting for a socket the
            // way it meters receiving from one. A loop that always finds
            // work — datagrams arriving faster than they can be dealt
            // with — would keep its thread to itself. So it steps aside.
            turns = turns.saturating_add(1);
            if full || turns >= YIELD_EVERY {
                turns = 0;
                tokio::task::yield_now().await;
                reading = clock.read(&self.tunn);
            }
        }
    }

    /// Tell [`LoopStats`] what the tunnel counts, if that has changed.
    fn publish(&self, last: &mut Published) {
        let seen = Published {
            tunnel: self.tunn.stats(),
            device: self.tunn.device_stats(),
            endpoint: self.tunn.endpoint(),
            queued: self.tunn.queued(),
            queue_drops: self.tunn.queue_drops(),
        };
        if seen != *last {
            *self
                .stats
                .published
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = seen;
            *last = seen;
        }
    }

    /// One received datagram, `len` bytes of `slabs.rx`. Returns `false`
    /// when the consumer of `from_net` is gone.
    fn on_datagram(
        &mut self,
        now: Ticks,
        len: usize,
        src: SocketAddr,
        slabs: &mut Slabs,
        from_net: &mpsc::Sender<PooledBuf>,
    ) -> bool {
        // Reduce the borrow-carrying result to plain values before
        // touching the slabs again.
        enum Got {
            Deliver(usize),
            Reply(usize, SocketAddr),
            Nothing,
        }
        // A handshake message is only looked at now; what it costs is
        // done when traffic has been seen to (`serve_deferred`).
        match self.tunn.triage(
            now,
            src,
            slabs.rx.spare_mut().get_mut(..len).unwrap_or(&mut []),
        ) {
            Triage::Now => {}
            Triage::Handshake => {
                // A full queue gives up its oldest: a handshake message
                // is worth less the longer it has waited (its sender
                // starts over after five seconds), and whatever kept the
                // queue from being served has kept that one longest.
                if self.handshakes.len() >= HANDSHAKE_QUEUE && self.handshakes.pop_front().is_some()
                {
                    LoopStats::count(&self.stats.handshake_drops);
                }
                // The slab goes with the message; a fresh one takes its
                // place.
                slabs.rx.set_len(len);
                let held = std::mem::replace(&mut slabs.rx, self.pool.get());
                self.handshakes.push_back((held, src));
                return true;
            }
            Triage::Challenge(challenge) => {
                // The same: the oldest makes way.
                if self.challenges.len() >= COOKIE_QUEUE && self.challenges.pop_front().is_some() {
                    LoopStats::count(&self.stats.cookie_reply_drops);
                }
                self.challenges.push_back(challenge);
                return true;
            }
            Triage::Refused => return true,
        }
        let got = match self.tunn.decapsulate_in_place_at(
            now,
            src,
            slabs.rx.spare_mut().get_mut(..len).unwrap_or(&mut []),
            slabs.net_out.spare_mut(),
        ) {
            TunnResult::WriteToTunnel(packet) => Got::Deliver(packet.len()),
            TunnResult::WriteToNetwork(datagram, to) => Got::Reply(datagram.len(), to),
            // Dropped datagrams are dropped silently (counted in the
            // core's stats); local faults too — the next iteration's
            // flush reports and backs off.
            TunnResult::Done | TunnResult::Err(_) => Got::Nothing,
        };
        match got {
            Got::Deliver(len) => {
                // The packet was decrypted in place, right behind the
                // transport header: ship this very slab to the TUN side
                // and pull a fresh one.
                slabs.rx.set_range(PLAINTEXT_OFFSET, len);
                let delivered = std::mem::replace(&mut slabs.rx, self.pool.get());
                match from_net.try_send(delivered) {
                    Ok(()) => {}
                    // No room: the packet is dropped, as it would be at a
                    // full socket buffer. The loop must not wait for room
                    // — the socket also carries the handshake messages
                    // and keepalives that keep the tunnel alive.
                    Err(TrySendError::Full(_)) => LoopStats::count(&self.stats.tun_drops),
                    Err(TrySendError::Closed(_)) => return false,
                }
            }
            Got::Reply(len, to) => {
                let _ = self.transmit(&mut slabs.net_out, len, to);
            }
            Got::Nothing => {}
        }
        true
    }

    /// Is there handshake work waiting?
    fn has_deferred(&self) -> bool {
        !self.handshakes.is_empty() || !self.challenges.is_empty()
    }

    /// Do what was put off, for as long as its allowance lasts: queued
    /// handshake messages first — they have passed every check there is
    /// short of the handshake itself — then the cookie replies that are
    /// owed.
    ///
    /// `room` is how far short of a full batch the last look at the
    /// socket was. The allowance is that part of a [`DEFERRED_SLICE`]
    /// ([`Allowance::refill`]) whenever the socket was read empty. With no
    /// room — the socket is backed up — the allowance is what receiving
    /// has earned ([`Allowance::earn`]), and an item that took more than
    /// there was leaves a debt that receiving has to make up before the
    /// next one: a flood gets its replies, and traffic keeps two thirds
    /// of the loop.
    ///
    /// Nothing is done while datagrams are waiting for the socket to
    /// have room: an answer made now would only wait behind them.
    fn serve_deferred(&mut self, now: Ticks, slabs: &mut Slabs, room: usize) {
        if room > 0 {
            self.deferred.refill(room);
        }
        while self.deferred.open() && self.outbox.is_empty() {
            let started = std::time::Instant::now();
            if let Some((mut datagram, src)) = self.handshakes.pop_front() {
                let answer = match self.tunn.deferred_handshake_at(
                    now,
                    src,
                    &mut datagram,
                    slabs.net_out.spare_mut(),
                ) {
                    TunnResult::WriteToNetwork(datagram, to) => Some((datagram.len(), to)),
                    // Rejected by the tunnel, or a response of the peer's
                    // that completed a handshake of ours: nothing to send
                    // (the flush at the top of the loop sends what a new
                    // session calls for).
                    _ => None,
                };
                if let Some((len, to)) = answer {
                    let _ = self.transmit(&mut slabs.net_out, len, to);
                }
            } else if let Some(challenge) = self.challenges.pop_front() {
                let reply =
                    match self
                        .tunn
                        .cookie_reply_at(now, &challenge, slabs.net_out.spare_mut())
                    {
                        TunnResult::WriteToNetwork(datagram, to) => Some((datagram.len(), to)),
                        // The cap on cookie replies, or a local fault (the
                        // entropy source): this one is not made.
                        _ => None,
                    };
                match reply {
                    Some((len, to)) => {
                        if !self.transmit_or_drop(&mut slabs.net_out, len, to) {
                            // The socket has no room. It is not to be
                            // kept for answers to strangers: what else is
                            // owed them is let go as well. (Their senders
                            // ask again in five seconds.)
                            for _ in self.challenges.drain(..) {
                                LoopStats::count(&self.stats.cookie_reply_drops);
                            }
                        }
                    }
                    None => LoopStats::count(&self.stats.cookie_reply_drops),
                }
            } else {
                break;
            }
            self.deferred.spend(started.elapsed());
        }
    }

    /// Put a cookie reply on the wire if the socket takes it now, and
    /// drop it (and count it) if not: it is an answer to someone who has
    /// proven nothing, and is not set aside ahead of the tunnel's own
    /// datagrams. Returns whether the socket had room.
    fn transmit_or_drop(&mut self, slab: &mut PooledBuf, len: usize, to: SocketAddr) -> bool {
        slab.set_len(len);
        let wire = if self.outbox.is_empty() {
            self.send(slab, to)
        } else {
            Wire::Full
        };
        if wire != Wire::Sent {
            LoopStats::count(&self.stats.cookie_reply_drops);
        }
        wire != Wire::Full
    }

    /// One packet from the TUN side. Returns `false` when the socket had
    /// no room for it: no more for now.
    fn on_packet(&mut self, now: Ticks, packet: &[u8], net_out: &mut PooledBuf) -> bool {
        let sent = match self.tunn.encapsulate_at(now, packet, net_out.spare_mut()) {
            TunnResult::WriteToNetwork(datagram, to) => Some((datagram.len(), to)),
            // It does not fit a buffer once encrypted: it cannot go out,
            // and that is not kept quiet.
            TunnResult::Err(TunnError::Core(Error::BufferTooSmall)) => {
                LoopStats::count(&self.stats.oversize_drops);
                None
            }
            // Queued (no session or no endpoint yet), or a local fault:
            // nothing to put on the wire.
            _ => None,
        };
        match sent {
            Some((len, to)) => self.transmit(net_out, len, to),
            None => true,
        }
    }

    /// Send every datagram the tunnel has ready, as long as the socket
    /// takes them. Returns whether the core reported a local fault for
    /// work that is still due (the caller backs off before retrying).
    fn flush(&mut self, now: Ticks, net_out: &mut PooledBuf) -> bool {
        enum Step {
            Send(usize, SocketAddr),
            /// Something was consumed without producing a datagram: look
            /// for more work.
            Again,
            Fault,
            Idle,
        }
        for _ in 0..FLUSH_BUDGET {
            // Queued packets first: they are older than anything a timer
            // wants to send, and the first of them confirms a new session.
            let step = match self.tunn.drain_queue_at(now, net_out.spare_mut()) {
                TunnResult::WriteToNetwork(datagram, to) => Step::Send(datagram.len(), to),
                // A queued packet that could not be encrypted was dropped
                // (it was too large for a buffer: see `oversize_drops`);
                // the rest of the queue is still there.
                TunnResult::Err(e) => {
                    if e == TunnError::Core(Error::BufferTooSmall) {
                        LoopStats::count(&self.stats.oversize_drops);
                    }
                    Step::Again
                }
                _ => match self.tunn.update_timers_at(now, net_out.spare_mut()) {
                    TunnResult::WriteToNetwork(datagram, to) => Step::Send(datagram.len(), to),
                    // The timer that wanted to send is still due.
                    TunnResult::Err(TunnError::Core(_)) => Step::Fault,
                    // An expiry notification: the queue was already
                    // cleared by the `Tunn`.
                    TunnResult::Err(_) => Step::Again,
                    _ => Step::Idle,
                },
            };
            match step {
                Step::Send(len, to) => {
                    if !self.transmit(net_out, len, to) {
                        return false;
                    }
                }
                Step::Again => {}
                Step::Fault => return true,
                Step::Idle => return false,
            }
        }
        false
    }

    /// Put the first `len` bytes of `slab` on the wire, for `to` — or, if
    /// the socket has no room, set them aside until it has. Returns
    /// `false` in that case: the caller makes no more for now.
    ///
    /// Nothing here waits. A datagram the socket refuses outright is a
    /// lost datagram, whatever the reason: it is counted, and the
    /// protocol's timers take it from there as they do for any loss.
    fn transmit(&mut self, slab: &mut PooledBuf, len: usize, to: SocketAddr) -> bool {
        slab.set_len(len);
        // Not ahead of what is already waiting.
        if self.outbox.is_empty() && self.send(slab, to) != Wire::Full {
            return true;
        }
        if self.outbox.len() >= OUTBOX_DEPTH {
            LoopStats::count(&self.stats.egress_drops);
        } else {
            // The slab goes with its datagram; a fresh one takes its
            // place.
            let held = std::mem::replace(slab, self.pool.get());
            self.outbox.push_back((held, to));
        }
        false
    }

    /// Send what was set aside, oldest first, as far as the socket takes
    /// it.
    fn drain_outbox(&mut self) {
        while let Some((datagram, to)) = self.outbox.front() {
            if self.send(datagram, *to) == Wire::Full {
                return;
            }
            let _ = self.outbox.pop_front();
        }
    }

    /// One datagram to the socket, without waiting.
    fn send(&self, datagram: &[u8], to: SocketAddr) -> Wire {
        for attempt in 1..=SEND_ATTEMPTS {
            match self.wire_send(datagram, to) {
                Ok(_) => return Wire::Sent,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Wire::Full,
                // An error — of this datagram's, or one the socket had
                // pending from an earlier one (an ICMP error is reported
                // on whichever call comes next; this datagram has then
                // not been sent). Take whatever else the socket holds
                // against us, and try again.
                Err(_) => {
                    let _ = self.take_socket_errors();
                    if attempt < SEND_ATTEMPTS {
                        LoopStats::count(&self.stats.send_retries);
                    }
                }
            }
        }
        LoopStats::count(&self.stats.send_errors);
        Wire::Failed
    }

    /// The socket has signalled an error. Take it — and what is in the
    /// error queue — off the socket, and tell tokio that this has been
    /// seen to (unless there is more: then it stays signalled, and the
    /// loop comes back).
    fn error_signalled(&self) {
        let _ = self.socket.try_io(Interest::ERROR, || {
            if self.take_socket_errors() {
                Err::<(), _>(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(())
            }
        });
    }

    /// Take from the socket what the kernel holds against it: the
    /// messages in its error queue (which are discarded — see the module
    /// docs) and the pending error itself. Returns `false` if there is
    /// more in the queue than is read at one time.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn take_socket_errors(&self) -> bool {
        use rustix::net::{RecvFlags, recv, sockopt};
        // The queue first: taking a message off it changes the pending
        // error to that of the next message, or clears it.
        let mut emptied = false;
        // One byte is room enough: what is queued is the datagram the
        // error is about, and nothing here wants to see it.
        let mut scratch = [0u8; 1];
        for _ in 0..ERROR_QUEUE_BATCH {
            match recv(
                &*self.socket,
                scratch.as_mut_slice(),
                RecvFlags::ERRQUEUE | RecvFlags::DONTWAIT,
            ) {
                Ok(_) => LoopStats::count(&self.stats.error_queue_messages),
                // Nothing (more) there.
                Err(_) => {
                    emptied = true;
                    break;
                }
            }
        }
        // The pending error, if one is left: reading it clears it.
        if let Ok(Err(_)) = sockopt::socket_error(&*self.socket) {
            LoopStats::count(&self.stats.recv_errors);
        }
        emptied
    }

    /// Elsewhere there is no error queue, and an error the socket has
    /// pending is reported on the next receive or send (which is
    /// repeated).
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[allow(clippy::unused_self)]
    fn take_socket_errors(&self) -> bool {
        true
    }

    /// `send_to`, if the socket can take it now.
    fn wire_send(&self, datagram: &[u8], to: SocketAddr) -> io::Result<usize> {
        #[cfg(test)]
        if let Some(scripted) = self.script.next_send(&self.socket) {
            return Err(scripted);
        }
        self.socket.try_send_to(datagram, to)
    }

    /// `recv_from`, if there is something to receive now.
    fn wire_recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        #[cfg(test)]
        if let Some(scripted) = self.script.next_recv() {
            return Err(scripted);
        }
        self.socket.try_recv_from(buf)
    }
}

/// For this module's tests: errors for the socket to report instead of
/// doing what it is asked.
#[cfg(test)]
#[derive(Debug, Default)]
struct Script {
    sends: Mutex<VecDeque<io::ErrorKind>>,
    /// `None`: this receive is the socket's own.
    recvs: Mutex<VecDeque<Option<io::ErrorKind>>>,
}

#[cfg(test)]
impl Script {
    /// The next `count` sends fail with `kind`.
    fn fail_sends(&self, kind: io::ErrorKind, count: usize) {
        let mut sends = self.sends.lock().unwrap_or_else(PoisonError::into_inner);
        sends.extend(std::iter::repeat_n(kind, count));
    }

    /// The next `count` receives fail with `kind`.
    fn fail_recvs(&self, kind: io::ErrorKind, count: usize) {
        let mut recvs = self.recvs.lock().unwrap_or_else(PoisonError::into_inner);
        recvs.extend(std::iter::repeat_n(Some(kind), count));
    }

    /// …and then one is what the socket really has.
    fn real_recv(&self) {
        let mut recvs = self.recvs.lock().unwrap_or_else(PoisonError::into_inner);
        recvs.push_back(None);
    }

    fn sends_left(&self) -> usize {
        self.sends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// From now on the socket is asked again.
    fn clear(&self) {
        self.sends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.recvs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    fn next_send(&self, socket: &UdpSocket) -> Option<io::Error> {
        let kind = self
            .sends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()?;
        if kind == io::ErrorKind::WouldBlock {
            // What a send that finds the socket full does to tokio's idea
            // of it.
            let _ = socket.try_io(Interest::WRITABLE, || {
                Err::<(), _>(io::ErrorKind::WouldBlock.into())
            });
        }
        Some(kind.into())
    }

    fn next_recv(&self) -> Option<io::Error> {
        let kind = self
            .recvs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()??;
        Some(kind.into())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use wireguard_sans_io::{PublicKey, StaticSecret};

    async fn bound_socket() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    fn keypair() -> (StaticSecret, PublicKey) {
        use wireguard_sans_io::EntropySource;
        let sk = StaticSecret::from_bytes(crate::OsEntropy.gen32().unwrap());
        let pk = sk.public_key();
        (sk, pk)
    }

    fn ip_packet(tag: u8) -> [u8; 60] {
        let mut p = [0u8; 60];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&60u16.to_be_bytes());
        p[40..].fill(0xab);
        p[59] = tag;
        p
    }

    const WAIT: Duration = Duration::from_secs(5);

    /// A running pair: A knows B's address, B learns A's.
    struct Running {
        pool: Arc<SlabPool>,
        a: TunnChannels,
        b: TunnChannels,
        addr_a: SocketAddr,
        addr_b: SocketAddr,
        b_pub: PublicKey,
    }

    async fn start(b_limit: Option<u64>) -> Running {
        start_with_depth(b_limit, 64).await
    }

    async fn start_with_depth(b_limit: Option<u64>, depth: usize) -> Running {
        let pool = SlabPool::for_wireguard();
        pool.prefill(32);
        let (a_sk, a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let sock_a = bound_socket().await;
        let sock_b = bound_socket().await;
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let limiter = b_limit.map(|l| Arc::new(crate::RateLimiter::new(l)));
        let tunn_a =
            Tunn::with_pool(a_sk, b_pk, None, None, Some(addr_b), None, pool.clone()).unwrap();
        let tunn_b = Tunn::with_pool(b_sk, a_pk, None, None, None, limiter, pool.clone()).unwrap();
        let (drv_a, a, rx_a, tx_a) = AsyncTunn::channels(tunn_a, sock_a, depth);
        let (drv_b, b, rx_b, tx_b) = AsyncTunn::channels(tunn_b, sock_b, depth);
        tokio::spawn(drv_a.run(rx_a, tx_a));
        tokio::spawn(drv_b.run(rx_b, tx_b));
        Running {
            pool,
            a,
            b,
            addr_a,
            addr_b,
            b_pub: b_pk,
        }
    }

    async fn recv(from: &mut mpsc::Receiver<PooledBuf>) -> PooledBuf {
        tokio::time::timeout(WAIT, from.recv())
            .await
            .expect("timeout waiting for a packet")
            .expect("channel closed")
    }

    /// Two AsyncTunn drivers on loopback; push IP packets through the
    /// channels and verify they emerge decrypted on the far side, with
    /// the pool in steady state afterwards.
    #[tokio::test]
    async fn async_roundtrip_via_channels() {
        let mut r = start(None).await;
        let baseline_idle = r.pool.idle();

        // Kick off the handshake by sending one packet from A. It is
        // queued, the handshake runs, and the queued packet follows.
        r.a.to_net
            .send(PooledBuf::copy_from(&r.pool, &ip_packet(1)))
            .await
            .unwrap();
        let got = recv(&mut r.b.from_net).await;
        assert_eq!(&*got, &ip_packet(1)[..]);
        drop(got);

        // Pump 100 more both ways.
        for i in 0..100u8 {
            r.a.to_net
                .send(PooledBuf::copy_from(&r.pool, &ip_packet(i)))
                .await
                .unwrap();
            assert_eq!(recv(&mut r.b.from_net).await[59], i);
            r.b.to_net
                .send(PooledBuf::copy_from(&r.pool, &ip_packet(i)))
                .await
                .unwrap();
            assert_eq!(recv(&mut r.a.from_net).await[59], i);
        }
        // After everything settles nothing leaked: the slabs in flight
        // are the four the two loops hold.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            r.pool.outstanding() <= 8,
            "outstanding={}",
            r.pool.outstanding()
        );
        assert!(r.pool.idle() >= baseline_idle.saturating_sub(8));
    }

    /// A packet from the TUN side that cannot be sent — encrypted, it
    /// would not fit a buffer — is counted, whether it meets a session or
    /// has to wait for one, and the loop carries on. (Such packets used to
    /// vanish without a trace.)
    #[tokio::test]
    async fn a_tun_packet_too_large_to_send_is_counted() {
        let pool = SlabPool::for_wireguard();
        let (a_sk, a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let sock_a = bound_socket().await;
        let sock_b = bound_socket().await;
        let addr_b = sock_b.local_addr().unwrap();
        let tunn_a =
            Tunn::with_pool(a_sk, b_pk, None, None, Some(addr_b), None, pool.clone()).unwrap();
        let tunn_b = Tunn::with_pool(b_sk, a_pk, None, None, None, None, pool.clone()).unwrap();
        let (drv_a, a, rx_a, tx_a) = AsyncTunn::channels(tunn_a, sock_a, 64);
        let (drv_b, mut b, rx_b, tx_b) = AsyncTunn::channels(tunn_b, sock_b, 64);
        let stats_a = drv_a.loop_stats();
        tokio::spawn(drv_a.run(rx_a, tx_a));
        tokio::spawn(drv_b.run(rx_b, tx_b));
        let oversized = |tag: u8| {
            let mut p = vec![0u8; 2040];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&2040u16.to_be_bytes());
            p[2039] = tag;
            p
        };
        let counted = |n: u64| {
            let stats = stats_a.clone();
            async move {
                tokio::time::timeout(WAIT, async {
                    while stats.oversize_drops() < n {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("the oversized packet was never counted");
            }
        };

        // Before there is a session: queued, then found unsendable when
        // its turn comes — and the packet behind it gets through.
        a.to_net
            .send(PooledBuf::copy_from(&pool, &oversized(1)))
            .await
            .unwrap();
        a.to_net
            .send(PooledBuf::copy_from(&pool, &ip_packet(2)))
            .await
            .unwrap();
        assert_eq!(recv(&mut b.from_net).await[59], 2);
        counted(1).await;
        // With a session: refused at once.
        a.to_net
            .send(PooledBuf::copy_from(&pool, &oversized(3)))
            .await
            .unwrap();
        counted(2).await;
        // A packet that does fit (2000 bytes: 2012 padded, 2044 on the
        // wire) is sent, and nothing else was counted.
        let mut fits = vec![0u8; 2000];
        fits[0] = 0x45;
        fits[2..4].copy_from_slice(&2000u16.to_be_bytes());
        fits[1999] = 4;
        a.to_net
            .send(PooledBuf::copy_from(&pool, &fits))
            .await
            .unwrap();
        let got = recv(&mut b.from_net).await;
        assert_eq!((got.len(), got[1999]), (2000, 4));
        assert_eq!(stats_a.oversize_drops(), 2);
    }

    /// The loop needs timers. On a runtime that has none, tokio panics
    /// when the first sleep is made; `run` finds that out before it
    /// starts and returns an error instead.
    #[test]
    fn a_runtime_without_timers_is_an_error_not_a_panic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let (a_sk, _) = keypair();
            let (_, b_pk) = keypair();
            let tunn = Tunn::new(a_sk, b_pk, None, Some(25), None, None).unwrap();
            let (driver, _channels, rx, tx) = AsyncTunn::channels(tunn, bound_socket().await, 4);
            driver.run(rx, tx).await
        });
        let error = result.expect_err("the loop ran without timers");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("timers"), "{error}");
    }

    /// B has a packet to send but does not know where A is. When A calls,
    /// B ends up as the handshake's responder — and its waiting packet
    /// must go out as soon as A's first message confirms the session.
    #[tokio::test]
    async fn packet_queued_by_the_eventual_responder_is_delivered() {
        let mut r = start(None).await;
        r.b.to_net
            .send(PooledBuf::copy_from(&r.pool, &ip_packet(7)))
            .await
            .unwrap();
        // Nothing can happen yet.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), r.a.from_net.recv())
                .await
                .is_err()
        );
        // A sends; the handshake completes with B as responder.
        r.a.to_net
            .send(PooledBuf::copy_from(&r.pool, &ip_packet(1)))
            .await
            .unwrap();
        assert_eq!(recv(&mut r.b.from_net).await[59], 1);
        // B's waiting packet arrives at A without anyone sending again.
        assert_eq!(recv(&mut r.a.from_net).await[59], 7);
    }

    /// One side driven by hand over plain sockets, the other by the event
    /// loop under test — so the test controls exactly what arrives at the
    /// loop, from where, and when.
    struct ByHand {
        tunn: Tunn,
        socket: UdpSocket,
        out: Vec<u8>,
    }

    impl ByHand {
        /// Encrypt one packet and send it from `self.socket`.
        async fn send(&mut self, tag: u8) {
            match self.tunn.encapsulate(&ip_packet(tag), &mut self.out) {
                TunnResult::WriteToNetwork(datagram, to) => {
                    self.socket.send_to(datagram, to).await.unwrap();
                }
                other => panic!("no session: {other:?}"),
            }
        }

        /// Receive one datagram on `socket` and return the packet in it.
        async fn recv_packet(&mut self, socket: &UdpSocket) -> Vec<u8> {
            let mut wire = vec![0u8; 2048];
            let (n, from) = tokio::time::timeout(WAIT, socket.recv_from(&mut wire))
                .await
                .expect("timeout waiting for a datagram")
                .unwrap();
            let mut buf = vec![0u8; 2048];
            match self.tunn.decapsulate(from, &wire[..n], &mut buf) {
                TunnResult::WriteToTunnel(packet) => packet.to_vec(),
                other => panic!("expected a packet, got {other:?}"),
            }
        }
    }

    /// What [`by_hand_and_loop`] sets up.
    struct Rig {
        a: ByHand,
        b: TunnChannels,
        stats: Arc<LoopStats>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
        pool: Arc<SlabPool>,
        /// What B's socket is to answer instead of being asked.
        script: Arc<Script>,
    }

    impl Rig {
        /// B's TUN side sends a packet.
        async fn b_sends(&self, tag: u8) {
            self.b
                .to_net
                .send(PooledBuf::copy_from(&self.pool, &ip_packet(tag)))
                .await
                .unwrap();
        }

        /// A receives one datagram on its socket and returns the packet
        /// in it.
        async fn a_receives(&mut self) -> Vec<u8> {
            let mut wire = vec![0u8; 2048];
            let (n, from) = tokio::time::timeout(WAIT, self.a.socket.recv_from(&mut wire))
                .await
                .expect("timeout waiting for a datagram")
                .unwrap();
            let mut buf = vec![0u8; 2048];
            match self.a.tunn.decapsulate(from, &wire[..n], &mut buf) {
                TunnResult::WriteToTunnel(packet) => packet.to_vec(),
                other => panic!("expected a packet, got {other:?}"),
            }
        }

        /// Make an ICMP error arrive at B's socket (which must be
        /// connected to A's address): A's port closes, B sends into it,
        /// and A comes back on the same port.
        async fn icmp_error_at_b(&mut self) {
            let addr_a = self.a.socket.local_addr().unwrap();
            let closed = std::mem::replace(
                &mut self.a.socket,
                UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            );
            drop(closed);
            let before = self.stats.recv_errors();
            self.b_sends(50).await;
            let stats = self.stats.clone();
            wait_until("the ICMP error was reported", || {
                stats.recv_errors() > before
            })
            .await;
            self.a.socket = UdpSocket::bind(addr_a).await.unwrap();
        }
    }

    /// A socket for B that is connected to `peer`: the kernel then
    /// reports ICMP errors on it.
    fn connected_to(peer: SocketAddr) -> Arc<UdpSocket> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(peer).unwrap();
        socket.set_nonblocking(true).unwrap();
        Arc::new(UdpSocket::from_std(socket).unwrap())
    }

    /// A (by hand) and B (the loop, on `socket_b`, channel depth `depth`),
    /// with a session established and one packet through.
    async fn by_hand_and_loop(socket_b: Arc<UdpSocket>, socket_a: UdpSocket, depth: usize) -> Rig {
        by_hand_and_loop_with(socket_b, socket_a, depth, None).await
    }

    /// The same, with a rate limiter for B.
    async fn by_hand_and_loop_with(
        socket_b: Arc<UdpSocket>,
        socket_a: UdpSocket,
        depth: usize,
        limiter: Option<Arc<crate::RateLimiter>>,
    ) -> Rig {
        let pool = SlabPool::for_wireguard();
        let (a_sk, a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let addr_b = socket_b.local_addr().unwrap();
        let tunn_a = Tunn::new(a_sk, b_pk, None, None, Some(addr_b), None).unwrap();
        let tunn_b = Tunn::with_pool(b_sk, a_pk, None, None, None, limiter, pool.clone()).unwrap();
        let (driver, mut b, rx, tx) = AsyncTunn::channels(tunn_b, socket_b, depth);
        let stats = driver.loop_stats();
        let script = driver.script.clone();
        let task = tokio::spawn(driver.run(rx, tx));
        let mut a = ByHand {
            tunn: tunn_a,
            socket: socket_a,
            out: vec![0u8; 2048],
        };

        // Handshake by hand.
        let mut wire = vec![0u8; 2048];
        let mut buf = vec![0u8; 2048];
        if let TunnResult::WriteToNetwork(d, to) = a.tunn.format_handshake_initiation(&mut a.out) {
            a.socket.send_to(d, to).await.unwrap();
        }
        let (n, from) = tokio::time::timeout(WAIT, a.socket.recv_from(&mut wire))
            .await
            .expect("timeout waiting for the handshake response")
            .unwrap();
        if let TunnResult::WriteToNetwork(d, to) = a.tunn.decapsulate(from, &wire[..n], &mut buf) {
            a.socket.send_to(d, to).await.unwrap();
        }
        assert!(a.tunn.is_established());
        a.send(0).await;
        assert_eq!(recv(&mut b.from_net).await[59], 0);
        Rig {
            a,
            b,
            stats,
            task,
            pool,
            script,
        }
    }

    async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(WAIT, async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timeout waiting until {what}"));
    }

    /// B's TUN reader stops reading while A keeps sending. The packets B
    /// has no room for are dropped and counted — and that is all: B goes
    /// on reading its socket. Here it notices, from a packet it has to
    /// drop, that A has moved to another address, and B's own traffic
    /// follows A there. (The loop used to stop reading the socket while
    /// the reader was away, which also cut it off from handshake messages
    /// and keepalives: fifteen seconds later it presumed the peer dead,
    /// and after three minutes it had no session.)
    #[tokio::test]
    async fn a_stalled_tun_reader_costs_packets_not_the_tunnel() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let Rig {
            mut a,
            mut b,
            stats,
            task,
            pool,
            ..
        } = by_hand_and_loop(bound_socket().await, socket_a, 2).await;

        // B's reader goes away; A sends ten packets. Two fit the channel.
        for tag in 1..=10u8 {
            a.send(tag).await;
        }
        wait_until("eight packets were dropped", || stats.tun_drops() == 8).await;

        // A roams: its next packet comes from another address. B has no
        // room for it either — but it has read it.
        let roamed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old = std::mem::replace(&mut a.socket, roamed);
        a.send(11).await;
        wait_until("the packet from the new address was read", || {
            stats.tun_drops() == 9
        })
        .await;

        // B's own traffic now goes to where A is.
        b.to_net
            .send(PooledBuf::copy_from(&pool, &ip_packet(99)))
            .await
            .unwrap();
        let socket = std::mem::replace(&mut a.socket, old);
        assert_eq!(a.recv_packet(&socket).await[59], 99);
        a.socket = socket;

        // The reader comes back: the two packets that fitted are there,
        // and what arrives from now on is delivered.
        assert_eq!(recv(&mut b.from_net).await[59], 1);
        assert_eq!(recv(&mut b.from_net).await[59], 2);
        a.send(12).await;
        assert_eq!(recv(&mut b.from_net).await[59], 12);
        assert_eq!(stats.tun_drops(), 9);
        assert!(!task.is_finished());
    }

    /// Dropping the receiving end of `from_net` ends the loop promptly,
    /// not at the next packet that would have been delivered.
    #[tokio::test]
    async fn the_loop_ends_when_the_tun_side_goes_away() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let Rig { a: _a, b, task, .. } = by_hand_and_loop(bound_socket().await, socket_a, 2).await;
        drop(b.from_net);
        let result = tokio::time::timeout(WAIT, task)
            .await
            .expect("the loop did not notice")
            .unwrap();
        assert!(result.is_ok());
    }

    /// A real ICMP error must not end the loop. B's socket is connected
    /// to A's address, which makes the kernel report ICMP errors on it.
    /// A's socket goes away and B sends: the kernel's "port unreachable"
    /// comes back and B's next receive fails. Then A returns on the same
    /// port, and the tunnel is still there.
    ///
    /// (The other errors a host on the network can provoke — path MTU,
    /// administratively prohibited, protocol unreachable, parameter
    /// problem — need forged ICMP and so raw sockets; see
    /// `tests/icmp_errors.rs`.)
    #[tokio::test]
    async fn an_icmp_error_on_receive_is_counted_and_the_loop_goes_on() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let socket_b = connected_to(addr_a);
        let Rig {
            mut a,
            mut b,
            stats,
            task,
            pool,
            ..
        } = by_hand_and_loop(socket_b, socket_a, 8).await;

        // A's port closes; B sends into it.
        let closed =
            std::mem::replace(&mut a.socket, UdpSocket::bind("127.0.0.1:0").await.unwrap());
        drop(closed);
        b.to_net
            .send(PooledBuf::copy_from(&pool, &ip_packet(50)))
            .await
            .unwrap();
        if cfg!(target_os = "linux") {
            wait_until("the ICMP error was reported", || stats.recv_errors() >= 1).await;
        } else {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!task.is_finished(), "the loop ended on a receive error");
        // And the error is dealt with: the socket does not go on
        // signalling it, with the loop going round and round.
        let wakeups = stats.wakeups();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let more = stats.wakeups() - wakeups;
        assert!(more < 50, "{more} wake-ups in 200 ms after one ICMP error");
        assert_eq!(stats.recv_pauses(), 0);

        // A is back on its port: packets flow again.
        a.socket = UdpSocket::bind(addr_a).await.unwrap();
        a.send(51).await;
        assert_eq!(recv(&mut b.from_net).await[59], 51);
        assert!(!task.is_finished());
    }

    /// A datagram the socket refuses to send is a lost datagram, not the
    /// end of the tunnel.
    #[tokio::test]
    async fn a_datagram_that_cannot_be_sent_is_counted_and_the_loop_goes_on() {
        let pool = SlabPool::for_wireguard();
        let (key, _) = keypair();
        let (_, peer) = keypair();
        // An IPv6 endpoint on an IPv4 socket: every send fails.
        let unreachable: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        let tunn =
            Tunn::with_pool(key, peer, None, None, Some(unreachable), None, pool.clone()).unwrap();
        let (driver, channels, rx, tx) = AsyncTunn::channels(tunn, bound_socket().await, 8);
        let stats = driver.loop_stats();
        let task = tokio::spawn(driver.run(rx, tx));

        channels
            .to_net
            .send(PooledBuf::copy_from(&pool, &ip_packet(1)))
            .await
            .unwrap();
        // The handshake initiation could not be sent…
        tokio::time::timeout(WAIT, async {
            while stats.send_errors() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the failed send was not counted");
        // …and the loop is still there, taking packets.
        channels
            .to_net
            .send(PooledBuf::copy_from(&pool, &ip_packet(2)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "the loop ended on a send error");
    }

    /// An outsider who knows only B's PUBLIC key floods B with
    /// handshake initiations until B is under load and answers with cookie
    /// replies. B's traffic for A must keep going to A.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outsider_with_only_the_public_key_cannot_redirect_traffic() {
        // B trips into "under load" after two handshake messages.
        let mut r = start(Some(2)).await;
        r.a.to_net
            .send(PooledBuf::copy_from(&r.pool, &ip_packet(1)))
            .await
            .unwrap();
        assert_eq!(recv(&mut r.b.from_net).await[59], 1);
        r.b.to_net
            .send(PooledBuf::copy_from(&r.pool, &ip_packet(2)))
            .await
            .unwrap();
        assert_eq!(recv(&mut r.a.from_net).await[59], 2);

        // The outsider: its own socket, throwaway identities, and
        // nothing but B's public key.
        let outsider = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..30 {
            let (key, _) = keypair();
            let mut stranger = Tunn::new(key, r.b_pub, None, None, Some(r.addr_b), None).unwrap();
            let mut buf = [0u8; 256];
            match stranger.format_handshake_initiation(&mut buf) {
                TunnResult::WriteToNetwork(init, _) => {
                    outsider.send_to(init, r.addr_b).await.unwrap();
                }
                other => panic!("{other:?}"),
            }
        }
        // It does get cookie replies — B really was under load…
        let mut buf = [0u8; 2048];
        let mut cookies = 0;
        while let Ok(Ok((n, from))) =
            tokio::time::timeout(Duration::from_millis(300), outsider.recv_from(&mut buf)).await
        {
            assert_eq!(from, r.addr_b);
            assert_eq!(
                (buf[0], n),
                (3, 64),
                "only cookie replies reach the outsider"
            );
            cookies += 1;
        }
        assert!(cookies >= 20, "B was under load: {cookies} cookie replies");

        // …and B's next packet still reaches A, and only A.
        r.b.to_net
            .send(PooledBuf::copy_from(&r.pool, &ip_packet(3)))
            .await
            .unwrap();
        assert_eq!(recv(&mut r.a.from_net).await[59], 3);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), outsider.recv_from(&mut buf))
                .await
                .is_err(),
            "the outsider received tunnel traffic"
        );
        let _ = r.addr_a;
    }

    // ---- what the running loop tells the embedder ---------------------------

    /// `run` takes the `Tunn` with it; what the tunnel counts must still
    /// be within reach. A thousand packets for a peer that never answers:
    /// the queue keeps 256 and the rest are gone — and counted, where the
    /// embedder can see it. (They used to appear in no counter of the
    /// running loop.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_running_loop_publishes_what_its_tunnel_counts() {
        let pool = SlabPool::for_wireguard();
        let (key, _) = keypair();
        let (_, peer) = keypair();
        // A peer that does not answer: a bound socket nobody reads.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let tunn =
            Tunn::with_pool(key, peer, None, None, Some(silent_addr), None, pool.clone()).unwrap();
        let (driver, channels, rx, tx) = AsyncTunn::channels(tunn, bound_socket().await, 64);
        let stats = driver.loop_stats();
        // Before the loop runs: where the peer is, and nothing counted.
        assert_eq!(stats.peer_addr(), Some(silent_addr));
        assert_eq!(
            (stats.queued(), stats.queue_drops(), stats.wakeups()),
            (0, 0, 0)
        );
        let task = tokio::spawn(driver.run(rx, tx));

        let sent = 1000u64;
        for i in 0..sent {
            channels
                .to_net
                .send(PooledBuf::copy_from(&pool, &ip_packet(i as u8)))
                .await
                .unwrap();
        }
        let gone = sent - crate::MAX_QUEUE_DEPTH as u64;
        wait_until("the packets the queue gave up were counted", || {
            stats.queue_drops() == gone
        })
        .await;
        assert_eq!(stats.queued(), crate::MAX_QUEUE_DEPTH);
        // The tunnel's own counters: it has asked for a handshake, and
        // nobody has answered.
        let tunnel = stats.tunnel_stats();
        assert!(tunnel.handshakes_initiated >= 1);
        assert_eq!((tunnel.handshakes_completed, tunnel.tx_transport), (0, 0));
        assert_eq!(stats.device_stats(), DeviceStats::default());
        // Nothing else was lost, and the loop is still there.
        assert_eq!(
            stats.send_errors() + stats.egress_drops() + stats.tun_drops() + stats.oversize_drops(),
            0
        );
        assert!(stats.wakeups() > 0);
        assert!(!task.is_finished());
    }

    /// The other half: a tunnel that works. What was `Tunn::stats()` and
    /// `Tunn::endpoint()` before `run` is in `LoopStats` after.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_running_loop_publishes_where_its_peer_is() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let mut rig = by_hand_and_loop(bound_socket().await, socket_a, 8).await;
        let stats = rig.stats.clone();
        // B did not know where A was: it has learned it.
        wait_until("the endpoint was published", || {
            stats.peer_addr() == Some(addr_a)
        })
        .await;
        rig.b_sends(1).await;
        assert_eq!(rig.a_receives().await[59], 1);
        wait_until("the packet B sent was counted", || {
            stats.tunnel_stats().tx_transport >= 1
        })
        .await;
        let tunnel = stats.tunnel_stats();
        assert_eq!(
            (tunnel.handshakes_responded, tunnel.handshakes_completed),
            (1, 1)
        );
        assert!(tunnel.rx_transport >= 1 && tunnel.last_handshake_at.is_some());
        assert_eq!(stats.device_stats().initiations, 1);
        assert_eq!((stats.queued(), stats.queue_drops()), (0, 0));
    }

    // ---- a socket that reports errors, or has no room -----------------------

    /// An error on a send is, as often as not, about an earlier datagram
    /// (a pending ICMP error is reported on whichever call comes next),
    /// and then this one has not been sent. The send is repeated — and
    /// only a datagram that is refused every time is given up as lost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_send_that_meets_an_error_is_repeated() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut rig = by_hand_and_loop(bound_socket().await, socket_a, 8).await;
        // Two errors, then the socket takes it: delivered.
        rig.script.fail_sends(io::ErrorKind::ConnectionRefused, 2);
        rig.b_sends(1).await;
        assert_eq!(rig.a_receives().await[59], 1);
        assert_eq!((rig.stats.send_retries(), rig.stats.send_errors()), (2, 0));
        // Three: lost, and counted as lost. The one behind it is sent.
        rig.script.fail_sends(io::ErrorKind::ConnectionRefused, 3);
        rig.b_sends(2).await;
        rig.b_sends(3).await;
        assert_eq!(rig.a_receives().await[59], 3);
        assert_eq!((rig.stats.send_retries(), rig.stats.send_errors()), (4, 1));
        assert_eq!(rig.stats.egress_drops(), 0);
        assert!(!rig.task.is_finished());
    }

    /// The way out is full. Nothing is lost, and nothing waits for it but
    /// what has to: the datagram that did not fit is kept, the packets
    /// behind it stay in the channel, and the loop goes on receiving.
    ///
    /// (The socket here has had an ICMP error. After one, tokio can no
    /// longer say when a socket has room — see `Event::Room` — and the
    /// socket is tried on a timer instead. A loop that waited on tokio's
    /// word would go round as fast as it can.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_socket_delays_datagrams_and_loses_none() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_b = connected_to(socket_a.local_addr().unwrap());
        let mut rig = by_hand_and_loop(socket_b, socket_a, 64).await;
        rig.icmp_error_at_b().await;

        // The socket has no room, five hundred times over. Forty packets
        // meanwhile: more than the loop would keep for it — it keeps
        // one, and leaves the others where they are.
        rig.script.fail_sends(io::ErrorKind::WouldBlock, 500);
        let wakeups_before = rig.stats.wakeups();
        let started = std::time::Instant::now();
        for tag in 1..=40 {
            rig.b_sends(tag).await;
        }
        // Meanwhile the loop receives as ever.
        rig.a.send(77).await;
        assert_eq!(recv(&mut rig.b.from_net).await[59], 77);
        assert!(
            rig.script.sends_left() > 0,
            "that was while the socket was still full"
        );
        // When there is room, everything goes out, in order.
        for tag in 1..=40 {
            assert_eq!(rig.a_receives().await[59], tag);
        }
        assert_eq!(rig.script.sends_left(), 0);
        // It was tried once a millisecond — not as often as the loop can
        // go round.
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "{:?}",
            started.elapsed()
        );
        let wakeups = rig.stats.wakeups() - wakeups_before;
        assert!(wakeups < 800, "{wakeups} wake-ups for 500 tries");
        assert_eq!((rig.stats.egress_drops(), rig.stats.send_errors()), (0, 0));
        assert!(!rig.task.is_finished());
    }

    /// While the socket is backed up, handshake work gets a third of the
    /// loop and no more — however long its items take; while it is being
    /// read empty, a quarter of a millisecond at a stretch, or the part
    /// of that the last batch left room for.
    #[test]
    fn handshake_work_gets_a_third_of_a_backed_up_loop() {
        let us = Duration::from_micros;
        // Every turn receives for 40 µs and finds more waiting; every
        // item of handshake work takes `item`. The share that goes to the
        // items, over ten thousand turns:
        for item in [us(3), us(34), us(125), us(900)] {
            let mut allowance = Allowance::default();
            let (mut receiving, mut handshakes) = (Duration::ZERO, Duration::ZERO);
            for _ in 0..10_000 {
                allowance.earn(us(40));
                receiving += us(40);
                while allowance.open() {
                    allowance.spend(item);
                    handshakes += item;
                }
            }
            let share = handshakes.as_secs_f64() / (handshakes + receiving).as_secs_f64();
            assert!((0.32..=0.35).contains(&share), "{item:?}: {share:.3}");
        }
        // What is earned does not pile up beyond a slice: after a long
        // stretch of receiving with nothing owed, a stretch of handshake
        // work is as long as after a short one.
        let mut allowance = Allowance::default();
        for _ in 0..1_000_000 {
            allowance.earn(us(40));
        }
        let mut stretch = Duration::ZERO;
        while allowance.open() {
            allowance.spend(us(10));
            stretch += us(10);
        }
        assert_eq!(stretch, DEFERRED_SLICE);
        // An item that overdraws leaves a debt, and receiving pays it off
        // before the next: 900 µs against an allowance of one takes
        // forty-five turns of 40 µs to make up for.
        let mut allowance = Allowance::default();
        allowance.earn(us(2));
        assert!(allowance.open());
        allowance.spend(us(900));
        let mut turns = 0;
        while !allowance.open() {
            allowance.earn(us(40));
            turns += 1;
        }
        assert_eq!(turns, 45);
        // A socket read empty: a slice, whatever was owed.
        allowance.spend(Duration::from_secs(3600));
        assert!(!allowance.open());
        allowance.refill(BATCH);
        let mut stretch = Duration::ZERO;
        while allowance.open() {
            allowance.spend(us(125));
            stretch += us(125);
        }
        assert_eq!(stretch, us(250));
        // One that held something when it was read empty: the less room
        // there was in the batch, the shorter the stretch — and never
        // none at all.
        for (room, expected) in [
            (BATCH, 250_000),
            (BATCH / 2, 125_000),
            (4, 31_250),
            (1, 7_812),
        ] {
            let mut allowance = Allowance::default();
            allowance.spend(us(900));
            allowance.refill(room);
            assert_eq!(allowance.0, expected, "room {room}");
        }
        let mut allowance = Allowance::default();
        allowance.refill(0);
        assert!(allowance.open());
        // What was earned while the socket was backed up is not taken
        // away by a look that found it nearly full.
        let mut allowance = Allowance::default();
        allowance.earn(us(400));
        allowance.refill(1);
        assert_eq!(allowance.0, 200_000);
    }

    /// What is put off is bounded, and what is kept is the newest: of
    /// forty handshake messages that pass the cheap checks thirty-two
    /// wait, of three hundred that are owed a cookie reply 256 — and the
    /// replies go out in the order they were asked for.
    #[tokio::test]
    async fn what_is_put_off_is_bounded_and_the_oldest_makes_way() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let socket_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_b = socket_b.local_addr().unwrap();
        let (b_sk, b_pk) = keypair();
        let (_, a_pk) = keypair();
        // Not under load until this test says so: a second of handshake
        // work at once is more than it does.
        let limiter = Arc::new(
            crate::RateLimiter::with_budget(Duration::from_secs(1))
                .with_burst(Duration::from_secs(1)),
        );
        let tunn_b = Tunn::new(b_sk, a_pk, None, None, None, Some(limiter.clone())).unwrap();
        let (mut driver, _channels, _rx, from_net) = AsyncTunn::channels(tunn_b, socket_b, 8);
        let stats = driver.loop_stats();
        let mut slabs = Slabs {
            net_out: driver.pool.get(),
            rx: driver.pool.get(),
        };
        // No loop is running here to learn it from the reactor: the
        // socket has room.
        driver.socket.writable().await.unwrap();
        // Handshake initiations from people who know B's public key, each
        // with the index its answer would carry.
        let strangers: Vec<(Vec<u8>, Vec<u8>)> = (0..340)
            .map(|_| {
                let (key, _) = keypair();
                let mut stranger = Tunn::new(key, b_pk, None, None, Some(addr_b), None).unwrap();
                let mut buf = [0u8; 256];
                match stranger.format_handshake_initiation(&mut buf) {
                    TunnResult::WriteToNetwork(init, _) => (init.to_vec(), init[4..8].to_vec()),
                    other => panic!("{other:?}"),
                }
            })
            .collect();
        let arrive = |driver: &mut AsyncTunn, slabs: &mut Slabs, datagram: &[u8]| {
            slabs.rx.spare_mut()[..datagram.len()].copy_from_slice(datagram);
            let now = driver.tunn.now();
            assert!(driver.on_datagram(now, datagram.len(), addr_a, slabs, &from_net));
        };
        // One piece of what was put off, so that what it sends can be
        // read back before the next.
        let one = |driver: &mut AsyncTunn, slabs: &mut Slabs| {
            driver.deferred = Allowance(1);
            let now = driver.tunn.now();
            driver.serve_deferred(now, slabs, 0);
        };

        // Not under load: forty arrive before any is dealt with.
        for (init, _) in &strangers[..40] {
            arrive(&mut driver, &mut slabs, init);
        }
        assert_eq!(driver.tunn.device_stats().initiations, 40);
        assert_eq!(driver.handshakes.len(), HANDSHAKE_QUEUE);
        assert_eq!(stats.handshake_drops(), 8);
        let waiting: Vec<Vec<u8>> = driver
            .handshakes
            .iter()
            .map(|(datagram, _)| datagram[4..8].to_vec())
            .collect();
        let newest: Vec<Vec<u8>> = strangers[8..40].iter().map(|(_, i)| i.clone()).collect();
        assert_eq!(waiting, newest, "the eight oldest made way");
        assert!(driver.challenges.is_empty() && driver.outbox.is_empty());
        // Their turn, one at a time. None is B's peer, so none is
        // answered.
        for left in (0..HANDSHAKE_QUEUE).rev() {
            assert!(driver.has_deferred());
            one(&mut driver, &mut slabs);
            assert_eq!(driver.handshakes.len(), left);
        }
        assert!(!driver.has_deferred() && driver.outbox.is_empty());
        assert_eq!(stats.handshake_drops(), 8, "no more were lost");
        assert!(!limiter.is_under_load());

        // Under load: three hundred more. Each is owed a cookie reply, and
        // 256 of those can wait.
        limiter.note_handshake_time(Duration::from_secs(5));
        assert!(limiter.is_under_load());
        for (init, _) in &strangers[40..] {
            arrive(&mut driver, &mut slabs, init);
        }
        assert!(driver.handshakes.is_empty());
        assert_eq!(driver.challenges.len(), COOKIE_QUEUE);
        assert_eq!(stats.cookie_reply_drops(), 300 - 256);
        assert_eq!(driver.tunn.device_stats().cookies_required, 300);
        assert_eq!(driver.tunn.device_stats().cookies_sent, 0, "none made yet");
        // The replies: to the newest 256, oldest first.
        let mut wire = [0u8; 128];
        for (_, index) in &strangers[340 - 256..] {
            one(&mut driver, &mut slabs);
            let (n, from) = tokio::time::timeout(WAIT, socket_a.recv_from(&mut wire))
                .await
                .expect("a cookie reply")
                .unwrap();
            assert_eq!((wire[0], n, from), (3, 64, addr_b));
            assert_eq!(wire[4..8], index[..]);
        }
        assert!(!driver.has_deferred());
        assert_eq!(driver.tunn.device_stats().cookies_sent, 256);
        assert_eq!(stats.cookie_reply_drops(), 300 - 256, "no more were lost");
        assert_eq!(stats.egress_drops(), 0);
    }

    /// Cookie replies are owed to people who have proven nothing. While
    /// the socket has no room they are not kept for it — nothing of
    /// theirs is set aside ahead of the tunnel's own datagrams — but
    /// dropped, and counted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn answers_a_full_socket_cannot_be_given_are_counted() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_b = connected_to(socket_a.local_addr().unwrap());
        let addr_b = socket_b.local_addr().unwrap();
        // B is under load from its first handshake message on: what
        // follows is owed a cookie reply.
        let loaded = Arc::new(crate::RateLimiter::with_budget(Duration::from_nanos(1)));
        let mut rig = by_hand_and_loop_with(socket_b, socket_a, 8, Some(loaded)).await;
        let b_pub = rig.a.tunn.core().peer_public();
        rig.icmp_error_at_b().await;
        let stats = rig.stats.clone();

        // The socket has no room, for as long as this takes.
        rig.script.fail_sends(io::ErrorKind::WouldBlock, 1_000_000);
        // Forty handshake initiations from people who know B's public
        // key (sent from A's address: B's socket is connected to it).
        let stranger_asks = |rig: &Rig| {
            let (key, _) = keypair();
            let mut stranger = Tunn::new(key, b_pub, None, None, Some(addr_b), None).unwrap();
            let mut buf = [0u8; 256];
            match stranger.format_handshake_initiation(&mut buf) {
                TunnResult::WriteToNetwork(init, _) => {
                    let index = init[4..8].to_vec();
                    rig.a.socket.try_send_to(init, addr_b).unwrap();
                    index
                }
                other => panic!("{other:?}"),
            }
        };
        for _ in 0..40 {
            let _ = stranger_asks(&rig);
        }
        // (All of them — or all but the first, if the handshake that set
        // this up is more than the limiter's hold ago and that one found
        // B not under load.)
        wait_until("B has seen them", || {
            stats.device_stats().cookies_required >= 39
        })
        .await;
        wait_until("…and has let every reply go", || {
            stats.cookie_reply_drops() >= stats.device_stats().cookies_required
        })
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let owed = stats.device_stats().cookies_required;
        assert!((39..=40).contains(&owed), "{owed}");
        assert_eq!(stats.cookie_reply_drops(), owed);
        // Not one of them was set aside, and none was made twice: a reply
        // is built only to find out that the socket has no room, and then
        // the rest of what is owed is let go unbuilt.
        assert_eq!(stats.egress_drops(), 0);
        let built = stats.device_stats().cookies_sent;
        assert!((1..=owed).contains(&built), "{built}");

        // Room again: nothing that was owed goes out late…
        rig.script.clear();
        let mut wire = [0u8; 256];
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                rig.a.socket.recv_from(&mut wire)
            )
            .await
            .is_err()
        );
        // …and the next one to ask is answered.
        let index = stranger_asks(&rig);
        let (n, from) = tokio::time::timeout(WAIT, rig.a.socket.recv_from(&mut wire))
            .await
            .expect("a cookie reply, now that there is room")
            .unwrap();
        assert_eq!((wire[0], n, from), (3, 64, addr_b));
        assert_eq!(wire[4..8], index[..]);
        assert_eq!(stats.cookie_reply_drops(), owed);
        // And the tunnel is as it was.
        rig.a.send(9).await;
        assert_eq!(recv(&mut rig.b.from_net).await[59], 9);
    }

    /// While the socket has no room the loop makes nothing new: what the
    /// tunnel has to send stays in the tunnel — here, nineteen of twenty
    /// packets that were waiting for a session — instead of being taken
    /// out, found unsendable, and dropped. (This socket has had no ICMP
    /// error: tokio says when it has room.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_socket_stops_the_tunnel_making_more() {
        let pool = SlabPool::for_wireguard();
        let (a_sk, a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        // B's socket, and a second handle on it for the test.
        let std_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        std_b.set_nonblocking(true).unwrap();
        let handle_b = std_b.try_clone().unwrap();
        let addr_b = std_b.local_addr().unwrap();
        let socket_b = Arc::new(UdpSocket::from_std(std_b).unwrap());
        let mut a = ByHand {
            tunn: Tunn::new(a_sk, b_pk, None, None, Some(addr_b), None).unwrap(),
            socket: socket_a,
            out: vec![0u8; 2048],
        };
        // B, the loop, calls A.
        let tunn_b =
            Tunn::with_pool(b_sk, a_pk, None, None, Some(addr_a), None, pool.clone()).unwrap();
        let (driver, b, rx, tx) = AsyncTunn::channels(tunn_b, socket_b, 64);
        let stats = driver.loop_stats();
        let script = driver.script.clone();
        let task = tokio::spawn(driver.run(rx, tx));

        // Twenty packets wait for the handshake B starts.
        for tag in 1..=20 {
            b.to_net
                .send(PooledBuf::copy_from(&pool, &ip_packet(tag)))
                .await
                .unwrap();
        }
        let mut wire = vec![0u8; 2048];
        let (n, from) = tokio::time::timeout(WAIT, a.socket.recv_from(&mut wire))
            .await
            .expect("B's initiation")
            .unwrap();
        assert_eq!((wire[0], n), (1, 148));
        wait_until("the packets are waiting", || stats.queued() == 20).await;

        // From here on the socket has no room. A answers: B has a
        // session, and twenty packets to send on it.
        script.fail_sends(io::ErrorKind::WouldBlock, 1_000_000);
        let mut buf = vec![0u8; 2048];
        match a.tunn.decapsulate(from, &wire[..n], &mut buf) {
            TunnResult::WriteToNetwork(response, to) => {
                a.socket.send_to(response, to).await.unwrap();
            }
            other => panic!("{other:?}"),
        }
        // B takes the first of them, finds no room for it, keeps it —
        // and leaves the other nineteen where they are. Also when the
        // loop comes round again for something else (a datagram that
        // means nothing).
        wait_until("B has tried to send", || stats.queued() == 19).await;
        a.socket.send_to(&[0u8; 8], addr_b).await.unwrap();
        wait_until("B has read the datagram", || {
            stats.device_stats().malformed == 1
        })
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!((stats.queued(), stats.egress_drops()), (19, 0));
        assert_eq!(stats.tunnel_stats().tx_transport, 1);

        // Room again. (tokio hears of that from the kernel, when a
        // datagram has left the socket: one does, through the test's own
        // handle on it.)
        script.clear();
        handle_b.send_to(b"room", addr_a).unwrap();
        // All twenty arrive, in order.
        let mut tags = Vec::new();
        while tags.len() < 20 {
            let (n, from) = tokio::time::timeout(WAIT, a.socket.recv_from(&mut wire))
                .await
                .expect("the packets B had were not all sent")
                .unwrap();
            if let TunnResult::WriteToTunnel(packet) =
                a.tunn.decapsulate(from, &wire[..n], &mut buf)
            {
                tags.push(packet[59]);
            }
        }
        assert_eq!(tags, (1..=20).collect::<Vec<u8>>());
        assert_eq!((stats.queued(), stats.egress_drops()), (0, 0));
        assert!(!task.is_finished());
    }

    /// However much there is to do, the loop does not keep its thread to
    /// itself: it hands control back to the runtime after every batch.
    /// On a single-threaded runtime, with some three hundred datagrams
    /// waiting at its socket, another task gets a turn between the
    /// batches — and sees the count go up in steps — where it would
    /// otherwise see nothing until the loop had gone through them all.
    #[tokio::test]
    async fn a_busy_loop_lets_other_tasks_run() {
        let (key, _) = keypair();
        let (_, peer) = keypair();
        let tunn = Tunn::new(key, peer, None, None, None, None).unwrap();
        let socket_b = bound_socket().await;
        let addr_b = socket_b.local_addr().unwrap();
        let (driver, _channels, rx, tx) = AsyncTunn::channels(tunn, socket_b, 8);
        let stats = driver.loop_stats();
        let _task = tokio::spawn(driver.run(rx, tx));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(stats.wakeups(), 1, "the loop is waiting");

        // As many datagrams as the socket's buffer takes (they mean
        // nothing, and are counted as that), sent without the loop
        // getting a look in.
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..1000 {
            sender.send_to(&[0u8; 8], addr_b).unwrap();
        }
        let mut seen = vec![stats.device_stats().malformed];
        for _ in 0..10_000 {
            tokio::task::yield_now().await;
            let count = stats.device_stats().malformed;
            if seen.last() != Some(&count) {
                seen.push(count);
            }
        }
        let total = *seen.last().unwrap();
        assert!(
            total >= 128,
            "only {total} datagrams fitted the socket's buffer"
        );
        // A step per batch of thirty-two. (The last one may be two
        // batches: after one that is not full the loop goes on to wait
        // without stepping aside first.)
        assert!(
            seen.len() as u64 > total / 64,
            "{total} datagrams, seen going by as {seen:?}"
        );
        assert!(
            seen.windows(2).all(|w| w[1] - w[0] < 2 * BATCH as u64),
            "{seen:?}"
        );
    }

    /// The same for a loop that keeps coming round without ever having a
    /// batch to show for it — whatever the reason: every thirty-two
    /// turns it steps aside. (Here the socket claims, ten thousand times
    /// in a row, to have something, and then has nothing.)
    #[tokio::test]
    async fn a_loop_that_keeps_coming_round_lets_other_tasks_run() {
        let (key, _) = keypair();
        let (_, peer) = keypair();
        let tunn = Tunn::new(key, peer, None, None, None, None).unwrap();
        let socket_b = bound_socket().await;
        let addr_b = socket_b.local_addr().unwrap();
        let (driver, _channels, rx, tx) = AsyncTunn::channels(tunn, socket_b, 8);
        let stats = driver.loop_stats();
        let script = driver.script.clone();
        let _task = tokio::spawn(driver.run(rx, tx));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(stats.wakeups(), 1, "the loop is waiting");

        script.fail_recvs(io::ErrorKind::WouldBlock, 10_000);
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(&[0u8; 8], addr_b).unwrap();
        // How often does this task get to look before the loop is done?
        let mut looks = 0u32;
        while stats.device_stats().malformed == 0 {
            looks += 1;
            assert!(looks < 100_000, "the datagram was never read");
            tokio::task::yield_now().await;
        }
        let turns = stats.wakeups();
        assert!(turns > 10_000, "{turns} turns of the loop");
        // One look in for every thirty-two turns: some 312 of them. Not
        // fewer (the loop keeping at it for longer), and not many more
        // (the loop stepping aside at every turn once it has started).
        assert!(
            (250..500).contains(&looks),
            "{looks} looks in while the loop went round {turns} times"
        );
    }

    /// And for packets from the TUN side: thirty-two at a time, with a
    /// turn for everybody else in between.
    #[tokio::test]
    async fn a_busy_tun_side_lets_other_tasks_run() {
        let pool = SlabPool::for_wireguard();
        let (key, _) = keypair();
        let (_, peer) = keypair();
        // No endpoint: every packet is queued (and, once 256 are, the
        // oldest dropped), which is quick and can be counted.
        let tunn = Tunn::with_pool(key, peer, None, None, None, None, pool.clone()).unwrap();
        let (driver, channels, rx, tx) = AsyncTunn::channels(tunn, bound_socket().await, 512);
        let stats = driver.loop_stats();
        let _task = tokio::spawn(driver.run(rx, tx));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(stats.wakeups(), 1, "the loop is waiting");

        for tag in 0..=255u8 {
            channels
                .to_net
                .try_send(PooledBuf::copy_from(&pool, &ip_packet(tag)))
                .unwrap();
            channels
                .to_net
                .try_send(PooledBuf::copy_from(&pool, &ip_packet(tag)))
                .unwrap();
        }
        let taken = |stats: &LoopStats| stats.queued() as u64 + stats.queue_drops();
        let mut seen = vec![taken(&stats)];
        while taken(&stats) < 512 {
            assert!(seen.len() < 1000, "{seen:?}");
            tokio::task::yield_now().await;
            let count = taken(&stats);
            if seen.last() != Some(&count) {
                seen.push(count);
            }
        }
        // Sixteen batches; this task saw most of them go by.
        assert!(seen.len() >= 12, "{seen:?}");
        assert!(
            seen.windows(2).all(|w| w[1] - w[0] < 2 * BATCH as u64),
            "{seen:?}"
        );
    }

    #[test]
    fn sixteen_receive_errors_in_a_row_are_a_streak() {
        assert_eq!(RECV_ERROR_BURST, 16);
        let mut streak = ErrorStreak::default();
        for round in 0..3 {
            for n in 1..RECV_ERROR_BURST {
                assert!(!streak.error(), "round {round}, error {n}");
            }
            assert!(streak.error(), "round {round}");
        }
        // Anything else in between, and it starts over.
        for _ in 0..100 {
            for _ in 1..RECV_ERROR_BURST {
                assert!(!streak.error());
            }
            streak.progress();
        }
    }

    /// A socket that does nothing but fail is left alone for a tenth of a
    /// second at a time, so that it cannot spin the loop — and is read
    /// again after that. Sending goes on meanwhile.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_socket_that_only_fails_is_left_alone_for_a_moment() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut rig = by_hand_and_loop(bound_socket().await, socket_a, 8).await;
        let errors_before = rig.stats.recv_errors();
        rig.script
            .fail_recvs(io::ErrorKind::ConnectionReset, RECV_ERROR_BURST as usize);
        let started = std::time::Instant::now();
        rig.a.send(1).await;
        // B's own traffic is not held up by it.
        rig.b_sends(2).await;
        assert_eq!(rig.a_receives().await[59], 2);
        // The datagram that was waiting is read when the pause is over.
        assert_eq!(recv(&mut rig.b.from_net).await[59], 1);
        assert!(
            started.elapsed() >= Duration::from_millis(90),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            rig.stats.recv_errors() - errors_before,
            u64::from(RECV_ERROR_BURST)
        );
        assert_eq!(rig.stats.recv_pauses(), 1);
        assert!(!rig.task.is_finished());
    }

    /// Errors with something else in between — a datagram, or the
    /// socket saying that it has none — are not that: this is what ICMP
    /// errors look like, however many there are, and nobody who sends
    /// them gets the socket left alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn errors_with_anything_in_between_do_not_pause_the_socket() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut rig = by_hand_and_loop(bound_socket().await, socket_a, 8).await;
        let errors_before = rig.stats.recv_errors();
        for _ in 0..100 {
            rig.script.fail_recvs(io::ErrorKind::ConnectionRefused, 1);
            rig.script.fail_recvs(io::ErrorKind::WouldBlock, 1);
        }
        rig.a.send(1).await;
        assert_eq!(recv(&mut rig.b.from_net).await[59], 1);
        assert_eq!(rig.stats.recv_errors() - errors_before, 100);
        assert_eq!(rig.stats.recv_pauses(), 0);

        // Fifteen errors, a datagram, fifteen errors, a datagram: thirty
        // errors, and no sixteen of them in a row.
        for _ in 0..2 {
            rig.script.fail_recvs(
                io::ErrorKind::ConnectionRefused,
                RECV_ERROR_BURST as usize - 1,
            );
            rig.script.real_recv();
        }
        rig.a.send(2).await;
        rig.a.send(3).await;
        assert_eq!(recv(&mut rig.b.from_net).await[59], 2);
        assert_eq!(recv(&mut rig.b.from_net).await[59], 3);
        assert_eq!(rig.stats.recv_errors() - errors_before, 130);
        assert_eq!(rig.stats.recv_pauses(), 0);
    }

    /// A fault in the core that does not go away — here: no entropy for a
    /// handshake — must neither end the loop nor spin it. What is due is
    /// tried again ten times a second, and done when it can be.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fault_that_stays_does_not_spin_the_loop() {
        let pool = SlabPool::for_wireguard();
        let (key, _) = keypair();
        let (_, peer) = keypair();
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tunn = Tunn::with_pool(
            key,
            peer,
            None,
            None,
            Some(listener.local_addr().unwrap()),
            None,
            pool.clone(),
        )
        .unwrap();
        let entropy = tunn.entropy_switch();
        let (driver, channels, rx, tx) = AsyncTunn::channels(tunn, bound_socket().await, 8);
        let stats = driver.loop_stats();
        let task = tokio::spawn(driver.run(rx, tx));

        entropy.store(true, Ordering::Relaxed);
        channels
            .to_net
            .send(PooledBuf::copy_from(&pool, &ip_packet(1)))
            .await
            .unwrap();
        // Half a second without entropy: no initiation can be made.
        let mut wire = [0u8; 256];
        assert!(
            tokio::time::timeout(Duration::from_millis(500), listener.recv_from(&mut wire))
                .await
                .is_err()
        );
        let wakeups = stats.wakeups();
        assert!(
            (2..=20).contains(&wakeups),
            "{wakeups} wake-ups in half a second without entropy"
        );
        assert!(!task.is_finished());
        assert_eq!(stats.queued(), 1, "the packet is waiting");
        // The source is back: the initiation goes out.
        entropy.store(false, Ordering::Relaxed);
        let (n, _) = tokio::time::timeout(WAIT, listener.recv_from(&mut wire))
            .await
            .expect("no initiation after the entropy source came back")
            .unwrap();
        assert_eq!((wire[0], n), (1, 148));
    }

    // ---- the loop's clock -----------------------------------------------------

    #[test]
    fn the_loops_clock_is_tokios_plus_the_time_spent_suspended() {
        let (key, _) = keypair();
        let (_, peer) = keypair();
        let tunn = Tunn::new(key, peer, None, None, None, None).unwrap();
        let mut clock = LoopClock::start(&tunn);
        let base = clock.base;
        assert!(base <= tunn.now());
        assert_eq!(clock.ticks(0), base);
        assert_eq!(clock.ticks(5_000), base.add_nanos(5_000));

        // The machine's clocks agree with tokio's, and say that an hour
        // was spent suspended: the tunnel's time is an hour further on,
        // and stays there.
        const MS: u64 = 1_000_000;
        const HOUR: u64 = 3600 * 1000 * MS;
        clock.look(10 * MS, 10 * MS, HOUR);
        assert!(clock.steady);
        assert_eq!(clock.ticks(10 * MS), base.add_nanos(10 * MS + HOUR));
        // Time spent suspended does not come back.
        clock.look(20 * MS, 20 * MS, 0);
        assert_eq!(clock.ticks(20 * MS), base.add_nanos(20 * MS + HOUR));
        clock.look(30 * MS, 30 * MS, 2 * HOUR);
        assert_eq!(clock.ticks(30 * MS), base.add_nanos(30 * MS + 2 * HOUR));

        // tokio's clock out of step with the machine's — paused, or moved
        // by hand: not the clock to measure a suspend against.
        clock.look(10_000 * MS, 31 * MS, 2 * HOUR);
        assert!(!clock.steady);
        clock.look(31 * MS, 10_000 * MS, 2 * HOUR);
        assert!(!clock.steady);
        clock.look(10_000 * MS, 10_000 * MS + STEADY_SLACK_NS - 1, 2 * HOUR);
        assert!(clock.steady);
        clock.look(10_000 * MS, 10_000 * MS + STEADY_SLACK_NS, 2 * HOUR);
        assert!(!clock.steady);

        // And for real: the readings go forward, in step.
        let mut clock = LoopClock::start(&tunn);
        let first = clock.read(&tunn);
        std::thread::sleep(Duration::from_millis(20));
        let second = clock.read(&tunn);
        let passed = second.now.since(first.now);
        assert!((20 * MS..2_000 * MS).contains(&passed), "{passed}");
        assert!(second.steady);
        // The tunnel's own clock says the same.
        assert!(tunn.now().since(second.now) < 1_000 * MS);
    }

    /// A loop with nothing to do does nothing: where the clock counts
    /// time spent suspended it wakes up every ten seconds to look at it,
    /// and that is all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_idle_loop_does_not_wake_up() {
        let (key, _) = keypair();
        let (_, peer) = keypair();
        let tunn = Tunn::new(key, peer, None, None, None, None).unwrap();
        let (driver, channels, rx, tx) = AsyncTunn::channels(tunn, bound_socket().await, 8);
        let stats = driver.loop_stats();
        let task = tokio::spawn(driver.run(rx, tx));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let wakeups = stats.wakeups();
        assert!((1..=2).contains(&wakeups), "{wakeups}");
        // …and ends when it is told to.
        drop(channels);
        assert!(
            tokio::time::timeout(WAIT, task)
                .await
                .expect("the loop did not end")
                .unwrap()
                .is_ok()
        );
    }

    /// On a clock that a test has paused, the loop's time is tokio's. An
    /// idle loop sleeps through an hour of it. (The loop used to keep
    /// real time while it slept on tokio's: every sleep ended at once,
    /// nothing was due, and it went round as fast as it could.)
    #[tokio::test(start_paused = true)]
    async fn on_a_paused_clock_an_idle_loop_sleeps() {
        let (key, _) = keypair();
        let (_, peer) = keypair();
        let tunn = Tunn::new(key, peer, None, None, None, None).unwrap();
        let (driver, _channels, rx, tx) = AsyncTunn::channels(tunn, bound_socket().await, 8);
        let stats = driver.loop_stats();
        let task = tokio::spawn(driver.run(rx, tx));
        // An hour, a minute at a time. (Moved by hand, and with the loop
        // given its turn after every step: a loop that went round and
        // round would show here as a number, not as a test that never
        // ends.)
        let before = TokioInstant::now();
        for _ in 0..60 {
            tokio::time::advance(Duration::from_secs(60)).await;
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
        }
        assert_eq!(before.elapsed(), Duration::from_secs(3600));
        // Once when it started, and once (where the clock counts time
        // spent suspended) before it had seen that tokio's clock is not
        // the machine's.
        let wakeups = stats.wakeups();
        assert!((1..=3).contains(&wakeups), "{wakeups} wake-ups in an hour");
        assert!(!task.is_finished());
    }

    /// Where the tunnel's clock counts time spent suspended, the loop
    /// does not sleep longer than ten seconds: a sleep cannot tell that
    /// the machine was suspended in the middle of it. (Seen here on a
    /// paused clock, which the loop takes for the machine's until it has
    /// had a look: one wake-up at ten seconds, and — the clocks being
    /// out of step — no more.)
    #[tokio::test(start_paused = true)]
    async fn the_loop_looks_at_the_clock_every_ten_seconds() {
        let (key, _) = keypair();
        let (_, peer) = keypair();
        let tunn = Tunn::new(key, peer, None, None, None, None).unwrap();
        let (driver, _channels, rx, tx) = AsyncTunn::channels(tunn, bound_socket().await, 8);
        let stats = driver.loop_stats();
        let _task = tokio::spawn(driver.run(rx, tx));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(stats.wakeups(), 1);
        tokio::time::advance(Duration::from_millis(9_990)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(stats.wakeups(), 1);
        tokio::time::advance(Duration::from_millis(20)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        let expected = if Tunn::CLOCK_COUNTS_SUSPEND { 2 } else { 1 };
        assert_eq!(stats.wakeups(), expected);
        tokio::time::advance(Duration::from_secs(3600)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(stats.wakeups(), expected);
    }

    /// And the tunnel's timers run on that clock: a persistent keepalive
    /// goes out when tokio's clock says twenty-five seconds have passed —
    /// no sooner, and without anybody waiting twenty-five seconds.
    ///
    /// (tokio moves a paused clock on by itself whenever the runtime has
    /// nothing to run, whether or not a datagram is on its way; so this
    /// test never waits for anything. It lets the loop run with
    /// `yield_now`, and moves the clock by hand.)
    #[tokio::test(start_paused = true)]
    async fn on_a_paused_clock_the_tunnels_timers_keep_tokios_time() {
        /// Let the loop do what it has to do.
        async fn settle() {
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
        }
        /// The datagrams waiting at `socket`.
        fn waiting(socket: &std::net::UdpSocket) -> Vec<(Vec<u8>, SocketAddr)> {
            let mut wire = [0u8; 2048];
            let mut got = Vec::new();
            while let Ok((n, from)) = socket.recv_from(&mut wire) {
                got.push((wire[..n].to_vec(), from));
            }
            got
        }

        let pool = SlabPool::for_wireguard();
        let (a_sk, a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        // A, by hand, on a socket of the standard library's.
        let socket_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket_a.set_nonblocking(true).unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let socket_b = bound_socket().await;
        let addr_b = socket_b.local_addr().unwrap();
        let mut a = Tunn::new(a_sk, b_pk, None, None, Some(addr_b), None).unwrap();
        // B, the loop: knows where A is, and keeps the path alive.
        let tunn_b =
            Tunn::with_pool(b_sk, a_pk, None, Some(25), Some(addr_a), None, pool.clone()).unwrap();
        let (driver, b, rx, tx) = AsyncTunn::channels(tunn_b, socket_b, 8);
        let stats = driver.loop_stats();
        let _task = tokio::spawn(driver.run(rx, tx));
        let (mut out, mut buf) = (vec![0u8; 2048], vec![0u8; 2048]);

        // B has a packet: handshake, then the packet. No time passes.
        let started = TokioInstant::now();
        b.to_net
            .try_send(PooledBuf::copy_from(&pool, &ip_packet(1)))
            .unwrap();
        settle().await;
        let got = waiting(&socket_a);
        assert_eq!(got.len(), 1, "the initiation");
        let (init, from) = &got[0];
        assert_eq!((init[0], init.len(), *from), (1, 148, addr_b));
        match a.decapsulate(*from, init, &mut buf) {
            TunnResult::WriteToNetwork(response, to) => {
                socket_a.send_to(response, to).unwrap();
            }
            other => panic!("{other:?}"),
        }
        settle().await;
        let got = waiting(&socket_a);
        assert_eq!(got.len(), 1, "the packet that was waiting");
        assert!(matches!(
            a.decapsulate(got[0].1, &got[0].0, &mut buf),
            TunnResult::WriteToTunnel(packet) if packet[59] == 1
        ));
        // A lets B know it is there (B would otherwise presume it dead,
        // fifteen seconds on, and start over) — with a keepalive, which
        // asks for nothing in return.
        match a.encapsulate(&[], &mut out) {
            TunnResult::WriteToNetwork(keepalive, to) => {
                socket_a.send_to(keepalive, to).unwrap();
            }
            other => panic!("{other:?}"),
        }
        settle().await;
        assert!(waiting(&socket_a).is_empty());
        assert_eq!(started.elapsed(), Duration::ZERO);

        // Twenty-four seconds on: nothing. (A, on the machine's clock,
        // has nothing to say either.)
        tokio::time::advance(Duration::from_secs(24)).await;
        settle().await;
        assert!(waiting(&socket_a).is_empty());
        // Two more, and the keepalive has gone out — once.
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        let got = waiting(&socket_a);
        assert_eq!(got.len(), 1, "the keepalive");
        assert_eq!((got[0].0[0], got[0].0.len()), (4, 32));
        assert!(matches!(
            a.decapsulate(got[0].1, &got[0].0, &mut buf),
            TunnResult::Done
        ));
        assert_eq!(stats.tunnel_stats().tx_keepalives, 1);
        // And so on, every twenty-five seconds of tokio's time.
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(25)).await;
            settle().await;
            assert_eq!(waiting(&socket_a).len(), 1);
        }
        assert_eq!(stats.tunnel_stats().tx_keepalives, 4);
        // A is still there for B: a packet goes through.
        match a.encapsulate(&ip_packet(2), &mut out) {
            TunnResult::WriteToNetwork(wire, to) => {
                socket_a.send_to(wire, to).unwrap();
            }
            other => panic!("{other:?}"),
        }
        settle().await;
        let mut b = b;
        assert_eq!(b.from_net.try_recv().unwrap()[59], 2);
        // All of that in a hundred seconds of tokio's time and a few
        // dozen turns of the loop.
        assert_eq!(started.elapsed(), Duration::from_secs(101));
        let wakeups = stats.wakeups();
        assert!(wakeups < 100, "{wakeups} wake-ups");
    }

    /// `channels` takes any depth: tokio's channels do not (zero, and
    /// anything beyond their limit, make them panic).
    #[tokio::test]
    async fn any_channel_depth_is_taken() {
        for depth in [0, 1, usize::MAX] {
            let (key, _) = keypair();
            let (_, peer) = keypair();
            let tunn = Tunn::new(key, peer, None, None, None, None).unwrap();
            let (_driver, channels, _rx, _tx) =
                AsyncTunn::channels(tunn, bound_socket().await, depth);
            assert!(channels.to_net.max_capacity() >= 1);
        }
    }
}
