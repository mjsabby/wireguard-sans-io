//! Handshake rate limiting: when to demand cookies, and how much a source
//! that holds one may ask for.
//!
//! WireGuard defends its handshake against CPU exhaustion in two steps
//! (whitepaper §5.3), and [`RateLimiter`] is both of them:
//!
//! 1. **The load signal.** While the interface is *under load*, the core
//!    answers handshake messages that carry no valid cookie with a cookie
//!    reply instead of doing any Diffie-Hellman work. A cookie proves
//!    that its holder receives datagrams at the address it sends from.
//!
//!    Under load is a statement about this machine, so it is measured on
//!    this machine: the time spent on handshake messages that passed the
//!    `mac1` check is added up over a window of about a second, and once
//!    it exceeds a budget — by default a tenth of the window, a tenth of
//!    one core — the interface is under load for the rest of the window.
//!    (The Linux implementation's signal is of the same kind: a backlog
//!    of handshake work. BoringTun counts messages instead, ten a second
//!    per peer; a count can be set here too, [`RateLimiter::new`], and
//!    the two then both apply.)
//!
//!    The budget matters because being under load is not free. A
//!    handshake that meets a cookie reply starts over one Rekey-Timeout
//!    later — five seconds, in either role — and while cookies are being
//!    demanded, someone who can see our handshake messages and inject
//!    datagrams (but not drop any) can keep handshakes from completing by
//!    racing forged cookie replies: the key they are sealed with is
//!    derived from a public key. A limiter that trips at ten messages a
//!    second hands that position to anyone who knows the interface's
//!    public key and can send thirty datagrams a second. One that trips
//!    when handshakes cost real time does not trip before they do.
//! 2. **The per-source allowance.** A proven address is something a limit
//!    can safely be keyed on, so each one gets a token bucket: the Linux
//!    implementation's 20 handshake messages per second with a burst of 5.
//!    Without this a single cookie would buy unlimited X25519.
//!
//! The order matters, and the driver keeps to it: the allowance is only
//! consulted for a message whose cookie has been verified. Keyed on an
//! *unproven* source address — which costs nothing to forge — the same
//! limit would let anyone who knows the interface's public key use up the
//! allowance of an address of their choosing, and so lock that peer out.
//!
//! The window is advanced by the limiter itself, from its own monotonic
//! clock, every time it is consulted. It does not depend on anything else
//! being called: an idle tunnel that suddenly receives a burst of
//! handshake messages sees a fresh window, and a limiter that tripped
//! un-trips one window later without any timer having to fire.
//!
//! A limiter is consulted by the [`crate::Tunn`] it was given to. One
//! `Arc` may be given to several of them (each on its own socket) to
//! make the load signal and the per-source allowances those of the host
//! as a whole.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// One second, in nanoseconds.
const SECOND_NS: u64 = 1_000_000_000;

/// What a source's bucket is keyed on: the IPv4 address, or the /64 an
/// IPv6 address is in (one subscriber typically controls a whole /64, so
/// its addresses share an allowance — as in the Linux implementation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SourceKey {
    V4([u8; 4]),
    V6Prefix([u8; 8]),
}

impl SourceKey {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self::V4(v4.octets()),
                None => {
                    let [a, b, c, d, e, f, g, h, ..] = v6.octets();
                    Self::V6Prefix([a, b, c, d, e, f, g, h])
                }
            },
        }
    }
}

/// A token bucket, in nanoseconds of credit: a message costs
/// [`RateLimiter::SOURCE_COST_NS`], and credit accrues with time up to
/// [`RateLimiter::SOURCE_CREDIT_MAX_NS`].
#[derive(Debug, Clone, Copy)]
struct Bucket {
    credit_ns: u64,
    last_ns: u64,
}

impl Bucket {
    /// A bucket that has never been drawn on: full.
    const fn full(now_ns: u64) -> Self {
        Self {
            credit_ns: RateLimiter::SOURCE_CREDIT_MAX_NS,
            last_ns: now_ns,
        }
    }

    /// Take one token, if there is one.
    fn take(&mut self, now_ns: u64) -> bool {
        let earned = now_ns.saturating_sub(self.last_ns);
        self.credit_ns = self
            .credit_ns
            .saturating_add(earned)
            .min(RateLimiter::SOURCE_CREDIT_MAX_NS);
        self.last_ns = now_ns;
        match self.credit_ns.checked_sub(RateLimiter::SOURCE_COST_NS) {
            Some(rest) => {
                self.credit_ns = rest;
                true
            }
            None => false,
        }
    }
}

/// The per-source table, and when it was last swept.
#[derive(Debug)]
struct Sources {
    buckets: HashMap<SourceKey, Bucket>,
    swept_ns: u64,
    /// The one bucket that sources share which there is no room for in
    /// the table.
    overflow: Bucket,
}

impl Default for Sources {
    fn default() -> Self {
        Self {
            buckets: HashMap::new(),
            swept_ns: 0,
            overflow: Bucket::full(0),
        }
    }
}

/// Handshake limiter (load signal and per-source allowance); see the
/// module docs.
#[derive(Debug)]
pub struct RateLimiter {
    /// Handshake messages allowed per [`Self::RESET_PERIOD`] before
    /// `under_load` engages (`u64::MAX`: any number).
    limit: u64,
    /// Time handshake messages may take per [`Self::RESET_PERIOD`] before
    /// `under_load` engages, in nanoseconds (`u64::MAX`: any amount).
    budget_ns: u64,
    /// Handshake messages seen in the current window.
    count: AtomicU64,
    /// Time spent on handshake messages in the current window.
    spent_ns: AtomicU64,
    /// Nanos-since-construction at which the current window began;
    /// advanced lock-free via CAS.
    window_start_ns: AtomicU64,
    /// Token buckets of sources whose address a cookie has proven. Only
    /// touched for such messages — never on the data path.
    sources: Mutex<Sources>,
    epoch: Instant,
    /// How often the clock has been read. The limiter is for handshake
    /// messages; the tests of the data path check that it stays out of it.
    #[cfg(test)]
    clock_reads: AtomicU64,
}

impl RateLimiter {
    /// BoringTun's number for a limiter that counts messages
    /// (`PEER_HANDSHAKE_RATE_LIMIT = 10` a second). It is not what
    /// [`RateLimiter::default`] does — see the module documentation for
    /// what a threshold this low gives away — and is here for callers
    /// that want BoringTun's behaviour: `RateLimiter::new(DEFAULT_LIMIT)`.
    pub const DEFAULT_LIMIT: u64 = 10;
    /// The default load signal: handshake messages may take this much
    /// time in every [`Self::RESET_PERIOD`] — a tenth of it, a tenth of
    /// one core — before cookies are demanded.
    pub const DEFAULT_BUDGET: Duration = Duration::from_millis(100);
    /// Length of one counting window.
    pub const RESET_PERIOD: Duration = Duration::from_secs(1);

    /// Sustained handshake messages per second one proven source may send
    /// (Linux: `PACKETS_PER_SECOND`).
    pub const SOURCE_RATE: u64 = 20;
    /// …and how many it may send at once (Linux: `PACKETS_BURSTABLE`).
    pub const SOURCE_BURST: u64 = 5;
    /// How many sources are tracked at a time (as many as the Linux
    /// implementation tracks). A source is forgotten one second after its
    /// last message. While the table is full, the sources that are not in
    /// it are not refused: they share one allowance between them, so that
    /// a peer nobody has seen yet still has a chance — which, when
    /// somebody holds 65,536 proven addresses against us, is what there is
    /// to give.
    pub const MAX_SOURCES: usize = 65_536;

    const SOURCE_COST_NS: u64 = SECOND_NS / Self::SOURCE_RATE;
    const SOURCE_CREDIT_MAX_NS: u64 = Self::SOURCE_COST_NS * Self::SOURCE_BURST;
    /// While the table is full it is swept for sources to forget at most
    /// this often (and once a second otherwise): a sweep looks at every
    /// entry, and a full table is exactly when there are many calls.
    const SWEEP_WHEN_FULL_NS: u64 = SECOND_NS / 10;

    /// A limiter that counts: under load once more than `limit` handshake
    /// messages have passed the `mac1` check within one
    /// [`Self::RESET_PERIOD`] (BoringTun's heuristic; `0` means always).
    /// The time they take is not limited; see [`RateLimiter::with_budget`]
    /// and [`RateLimiter::with_limits`].
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self::with_limits(limit, Duration::MAX)
    }

    /// A limiter that measures: under load once handshake messages have
    /// taken more than `budget` of the current [`Self::RESET_PERIOD`].
    /// Their number is not limited. This is what [`RateLimiter::default`]
    /// is, with [`Self::DEFAULT_BUDGET`].
    #[must_use]
    pub fn with_budget(budget: Duration) -> Self {
        Self::with_limits(u64::MAX, budget)
    }

    /// A limiter with both thresholds: under load once either the number
    /// of handshake messages in the current window exceeds `limit`, or
    /// the time they have taken exceeds `budget`.
    #[must_use]
    pub fn with_limits(limit: u64, budget: Duration) -> Self {
        Self {
            limit,
            budget_ns: u64::try_from(budget.as_nanos()).unwrap_or(u64::MAX),
            count: AtomicU64::new(0),
            spent_ns: AtomicU64::new(0),
            window_start_ns: AtomicU64::new(0),
            sources: Mutex::default(),
            epoch: Instant::now(),
            #[cfg(test)]
            clock_reads: AtomicU64::new(0),
        }
    }

    /// How often this limiter has read the clock.
    #[cfg(test)]
    pub(crate) fn clock_reads(&self) -> u64 {
        self.clock_reads.load(Ordering::Relaxed)
    }

    /// What handshake messages have taken in the current window.
    #[cfg(test)]
    pub(crate) fn spent_ns(&self) -> u64 {
        self.spent_ns.load(Ordering::Relaxed)
    }

    /// Record one handshake message and return `true` if this window's
    /// count was already at `limit` (= treat this message as arriving
    /// under load).
    #[must_use]
    pub fn note_handshake(&self) -> bool {
        self.note_handshake_at(self.now_ns())
    }

    /// Record how long one handshake message took to deal with, from the
    /// moment it was looked at to the moment its answer (or the decision
    /// to give none) was ready. This is what the time budget is drawn
    /// down by; a limiter that only counts ignores it.
    pub fn note_handshake_time(&self, took: Duration) {
        let took_ns = u64::try_from(took.as_nanos()).unwrap_or(u64::MAX);
        // Saturating: a sum that wrapped would read as "no load".
        let mut spent = self.spent_ns.load(Ordering::Relaxed);
        loop {
            let sum = spent.saturating_add(took_ns);
            match self.spent_ns.compare_exchange_weak(
                spent,
                sum,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(seen) => spent = seen,
            }
        }
    }

    /// Current under-load state without bumping the counter.
    #[must_use]
    pub fn is_under_load(&self) -> bool {
        self.is_under_load_at(self.now_ns())
    }

    /// May a handshake message from `source` — an address **a cookie has
    /// proven** — be processed now? Takes one token from that source's
    /// bucket if there is one.
    ///
    /// Only ever call this for a message whose `mac2` was verified
    /// ([`wireguard_sans_io::Initiation::source_verified`]); see the
    /// module docs for what goes wrong otherwise.
    #[must_use]
    pub fn allow_source(&self, source: IpAddr) -> bool {
        self.allow_source_at(source, self.now_ns())
    }

    /// Unconditionally start a new window now, and forget every source.
    pub fn reset(&self) {
        let now_ns = self.now_ns();
        self.window_start_ns.store(now_ns, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
        self.spent_ns.store(0, Ordering::Relaxed);
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        sources.buckets.clear();
        sources.overflow = Bucket::full(now_ns);
    }

    /// One reading of this limiter's clock (nanoseconds since it was
    /// made), for the `_at` calls: [`crate::Tunn`] reads it once when a
    /// handshake message arrives and once when it has been dealt with.
    pub(crate) fn now_ns(&self) -> u64 {
        #[cfg(test)]
        self.clock_reads.fetch_add(1, Ordering::Relaxed);
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// [`note_handshake_time`](Self::note_handshake_time) for a message
    /// that was first looked at when the clock read `started_ns`.
    pub(crate) fn note_handshake_time_since(&self, started_ns: u64) {
        let took_ns = self.now_ns().saturating_sub(started_ns);
        self.note_handshake_time(Duration::from_nanos(took_ns));
    }

    /// [`note_handshake`](Self::note_handshake) at an explicit instant
    /// (nanoseconds since construction).
    pub(crate) fn note_handshake_at(&self, now_ns: u64) -> bool {
        self.roll_window(now_ns);
        let over_count = self.count.fetch_add(1, Ordering::Relaxed) >= self.limit;
        over_count || self.over_budget()
    }

    /// [`is_under_load`](Self::is_under_load) at an explicit instant.
    pub(crate) fn is_under_load_at(&self, now_ns: u64) -> bool {
        self.roll_window(now_ns);
        self.count.load(Ordering::Relaxed) >= self.limit || self.over_budget()
    }

    /// Has the time spent in this window used up the budget? (Never, for
    /// a limiter without one — whatever it has been told.)
    fn over_budget(&self) -> bool {
        self.budget_ns != u64::MAX && self.spent_ns.load(Ordering::Relaxed) >= self.budget_ns
    }

    /// [`allow_source`](Self::allow_source) at an explicit instant.
    pub(crate) fn allow_source_at(&self, source: IpAddr, now_ns: u64) -> bool {
        let key = SourceKey::of(source);
        // A panic while the lock was held cannot leave the table in a
        // state worth refusing service over.
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);

        // Forget sources that have been quiet for a second (their bucket
        // would be full again anyway): once a second, and — when room is
        // needed — a little more often than that, but not on every call:
        // a sweep looks at every entry.
        let full = sources.buckets.len() >= Self::MAX_SOURCES;
        let since_sweep = now_ns.saturating_sub(sources.swept_ns);
        if since_sweep >= SECOND_NS || (full && since_sweep >= Self::SWEEP_WHEN_FULL_NS) {
            sources
                .buckets
                .retain(|_, bucket| now_ns.saturating_sub(bucket.last_ns) < SECOND_NS);
            sources.swept_ns = now_ns;
        }

        if let Some(bucket) = sources.buckets.get_mut(&key) {
            return bucket.take(now_ns);
        }
        if sources.buckets.len() >= Self::MAX_SOURCES {
            // Still full of sources seen within the last second. The
            // table does not grow without bound, and the newcomer is not
            // refused outright either — it would be the genuine peer as
            // likely as not: those without a place share one bucket.
            return sources.overflow.take(now_ns);
        }
        let mut bucket = Bucket::full(now_ns);
        let allowed = bucket.take(now_ns);
        sources.buckets.insert(key, bucket);
        allowed
    }

    /// Start a new window if the current one is over. Lock-free: only one
    /// caller wins the CAS and zeroes the count.
    fn roll_window(&self, now_ns: u64) {
        let period = u64::try_from(Self::RESET_PERIOD.as_nanos()).unwrap_or(u64::MAX);
        let start = self.window_start_ns.load(Ordering::Relaxed);
        if now_ns.saturating_sub(start) >= period
            && self
                .window_start_ns
                .compare_exchange(start, now_ns, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.count.store(0, Ordering::Relaxed);
            self.spent_ns.store(0, Ordering::Relaxed);
        }
    }
}

impl Default for RateLimiter {
    /// [`RateLimiter::with_budget`] at [`RateLimiter::DEFAULT_BUDGET`].
    fn default() -> Self {
        Self::with_budget(Self::DEFAULT_BUDGET)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn trips_past_the_limit_within_one_window() {
        let rl = RateLimiter::new(3);
        for i in 0..3 {
            assert!(
                !rl.note_handshake_at(i * MS),
                "message {i} is within the limit"
            );
        }
        for i in 3..13 {
            assert!(rl.note_handshake_at(i * MS), "past the limit → under load");
        }
    }

    /// The window advances by itself: nothing else has to be called for a
    /// tripped limiter to recover.
    #[test]
    fn recovers_one_window_later_without_any_external_tick() {
        let rl = RateLimiter::new(2);
        assert!(!rl.note_handshake_at(0));
        assert!(!rl.note_handshake_at(10 * MS));
        assert!(rl.note_handshake_at(20 * MS));
        assert!(rl.note_handshake_at(999 * MS));
        // One second after the window began: a fresh window.
        assert!(!rl.note_handshake_at(1000 * MS));
        assert!(!rl.note_handshake_at(1500 * MS));
        assert!(rl.note_handshake_at(1900 * MS));
        // …and after a long idle period too.
        assert!(!rl.note_handshake_at(3_600_000 * MS));
    }

    #[test]
    fn idle_limiter_does_not_accumulate_across_windows() {
        // One handshake every ten seconds for a day must never trip a
        // limit of 10 per second — nor a budget, whatever each took.
        for rl in [
            RateLimiter::new(RateLimiter::DEFAULT_LIMIT),
            RateLimiter::default(),
        ] {
            for i in 0..8640u64 {
                assert!(!rl.note_handshake_at(i * 10_000 * MS), "handshake {i}");
                rl.note_handshake_time(Duration::from_millis(90));
            }
        }
    }

    /// The default signal: time, not number. Any number of messages that
    /// cost nothing do not trip it; a tenth of a second of work does, for
    /// the rest of the window, and the next window starts clean.
    #[test]
    fn the_default_limiter_trips_on_time_spent_not_on_a_count() {
        let rl = RateLimiter::default();
        for i in 0..100_000u64 {
            assert!(!rl.note_handshake_at(i * 1000), "message {i}");
        }
        assert!(!rl.is_under_load_at(200 * MS));
        // 99 ms of handshake work in this window: within the budget.
        rl.note_handshake_time(Duration::from_millis(99));
        assert!(!rl.is_under_load_at(300 * MS));
        // One more millisecond: the budget is spent.
        rl.note_handshake_time(Duration::from_millis(1));
        assert!(rl.is_under_load_at(300 * MS));
        assert!(rl.note_handshake_at(400 * MS));
        assert!(rl.is_under_load_at(999 * MS));
        // A new window, a new budget.
        assert!(!rl.is_under_load_at(1000 * MS));
        assert!(!rl.note_handshake_at(1001 * MS));
        // The sum cannot wrap into "no load".
        rl.note_handshake_time(Duration::from_nanos(u64::MAX - 5));
        rl.note_handshake_time(Duration::from_nanos(10));
        assert!(rl.is_under_load_at(1002 * MS));
        rl.note_handshake_time(Duration::MAX);
        assert!(rl.is_under_load_at(1002 * MS));
        // `reset` clears it.
        rl.reset();
        assert!(!rl.is_under_load());
    }

    /// Both thresholds at once: whichever is reached first.
    #[test]
    fn a_limiter_with_both_thresholds_trips_on_either() {
        let rl = RateLimiter::with_limits(3, Duration::from_millis(10));
        assert!(!rl.note_handshake_at(0));
        rl.note_handshake_time(Duration::from_millis(10));
        assert!(rl.is_under_load_at(MS), "by time");
        let rl = RateLimiter::with_limits(3, Duration::from_millis(10));
        for i in 0..3 {
            assert!(!rl.note_handshake_at(i));
        }
        assert!(rl.is_under_load_at(MS), "by count");
        // A counting limiter does not care how long anything took.
        let rl = RateLimiter::new(3);
        rl.note_handshake_time(Duration::from_secs(3600));
        assert!(!rl.is_under_load_at(MS));
        rl.note_handshake_time(Duration::MAX);
        assert!(!rl.is_under_load_at(MS));
        // What `Tunn` does: one reading when the message arrives, one
        // when it is done with, and the difference is what it took.
        let rl = RateLimiter::with_budget(Duration::from_millis(5));
        let started = rl.now_ns();
        assert!(!rl.is_under_load_at(started));
        std::thread::sleep(Duration::from_millis(6));
        rl.note_handshake_time_since(started);
        assert!(rl.is_under_load_at(started));
    }

    #[test]
    fn reset_and_query() {
        let rl = RateLimiter::new(1);
        assert!(!rl.is_under_load());
        assert!(!rl.note_handshake());
        assert!(rl.is_under_load());
        rl.reset();
        assert!(!rl.is_under_load());
    }

    // ---- the per-source allowance -----------------------------------------

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// How many of `n` messages arriving at `at_ns` are allowed.
    fn allowed(rl: &RateLimiter, source: &str, n: u32, at_ns: u64) -> u32 {
        (0..n)
            .filter(|_| rl.allow_source_at(ip(source), at_ns))
            .count() as u32
    }

    /// The Linux numbers: a burst of 5, then 20 per second.
    #[test]
    fn a_source_gets_a_burst_and_then_a_steady_rate() {
        let rl = RateLimiter::default();
        assert_eq!(allowed(&rl, "198.51.100.7", 100, 0), 5, "the burst");
        // One token every 50 ms.
        assert_eq!(allowed(&rl, "198.51.100.7", 10, 49 * MS), 0);
        assert_eq!(allowed(&rl, "198.51.100.7", 10, 50 * MS), 1);
        assert_eq!(allowed(&rl, "198.51.100.7", 10, 150 * MS), 2);
        // A flood of 1000 messages spread over one second from then on:
        // twenty get through.
        let mut through = 0;
        for i in 1..=1000u64 {
            through += allowed(&rl, "198.51.100.7", 1, 150 * MS + i * MS);
        }
        assert_eq!(through, 20);
        // Credit does not pile up beyond the burst, however long the
        // source stays quiet.
        assert_eq!(allowed(&rl, "198.51.100.7", 100, 3_600_000 * MS), 5);
    }

    #[test]
    fn sources_do_not_share_an_allowance() {
        let rl = RateLimiter::default();
        assert_eq!(allowed(&rl, "198.51.100.7", 100, 0), 5);
        // Another address is not affected by the first one's flood…
        assert_eq!(allowed(&rl, "198.51.100.8", 100, 0), 5);
        // …the same address in its IPv4-mapped form is the same source…
        assert_eq!(allowed(&rl, "::ffff:198.51.100.7", 100, 0), 0);
        // …and so is every address of one IPv6 /64, but not the next /64.
        assert_eq!(allowed(&rl, "2001:db8:1:2::1", 100, 0), 5);
        assert_eq!(allowed(&rl, "2001:db8:1:2:ffff::9", 100, 0), 0);
        assert_eq!(allowed(&rl, "2001:db8:1:3::1", 100, 0), 5);
    }

    #[test]
    fn quiet_sources_are_forgotten_and_the_table_is_bounded() {
        assert_eq!(RateLimiter::MAX_SOURCES, 65_536);
        assert_eq!(RateLimiter::DEFAULT_BUDGET, Duration::from_millis(100));
        let rl = RateLimiter::default();
        // Fill the table with distinct sources, all within one second.
        for i in 0..RateLimiter::MAX_SOURCES as u32 {
            let source = IpAddr::from(i.to_be_bytes());
            assert!(rl.allow_source_at(source, u64::from(i)), "source {i}");
        }
        let table_len = |rl: &RateLimiter| rl.sources.lock().unwrap().buckets.len();
        assert_eq!(table_len(&rl), RateLimiter::MAX_SOURCES);
        // While it is full of recent sources, a source that is in it
        // keeps its bucket, and those that are not in it share one: a
        // burst between all of them, then twenty a second.
        assert!(rl.allow_source_at(ip("0.0.0.5"), 500 * MS));
        let newcomers = |rl: &RateLimiter, n: u32, at_ns: u64| -> u32 {
            (0..n)
                .filter(|i| {
                    let source = IpAddr::from((0xcb00_0000u32 + i).to_be_bytes());
                    rl.allow_source_at(source, at_ns)
                })
                .count() as u32
        };
        assert_eq!(newcomers(&rl, 100, 500 * MS), 5, "the shared burst");
        assert_eq!(newcomers(&rl, 100, 549 * MS), 0);
        assert_eq!(newcomers(&rl, 100, 550 * MS), 1, "and the shared rate");
        assert_eq!(table_len(&rl), RateLimiter::MAX_SOURCES, "it did not grow");
        // A second after they were last seen the old entries are gone
        // (all but the one that was seen at 500 ms), and there is room
        // again: a newcomer gets a bucket of its own.
        assert_eq!(allowed(&rl, "203.0.113.1", 100, 1100 * MS), 5);
        assert_eq!(table_len(&rl), 2);
        // `reset` forgets everything.
        rl.reset();
        assert_eq!(table_len(&rl), 0);
    }

    /// A full table is not swept on every call (each sweep looks at all
    /// of it): ten times a second at the most.
    #[test]
    fn a_full_table_is_swept_ten_times_a_second_at_most() {
        let rl = RateLimiter::default();
        for i in 0..RateLimiter::MAX_SOURCES as u32 {
            let source = IpAddr::from(i.to_be_bytes());
            assert!(rl.allow_source_at(source, 900 * MS + u64::from(i)));
        }
        let swept = |rl: &RateLimiter| rl.sources.lock().unwrap().swept_ns;
        // (The table was last swept when it was created, at 0; it is due
        // at one second whatever happens.)
        assert_eq!(swept(&rl), 0);
        let mut sweeps = 0;
        let mut last = swept(&rl);
        // Ten thousand calls from newcomers within the next half second.
        for i in 0..10_000u64 {
            let at = 1000 * MS + i * 50_000;
            let source = IpAddr::from((0xcb00_0000u32 + i as u32).to_be_bytes());
            let _ = rl.allow_source_at(source, at);
            if swept(&rl) != last {
                sweeps += 1;
                last = swept(&rl);
            }
        }
        assert!(
            (4..=6).contains(&sweeps),
            "{sweeps} sweeps in half a second"
        );
    }
}
