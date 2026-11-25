//! Handshake rate limiting: when to demand cookies, how much a source
//! that holds one may ask for, and how many cookie replies to make.
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
//!    `mac1` check is drawn from a budget that fills up again
//!    continuously — by default a tenth of a second every second, a tenth
//!    of one core — and holds at most a *burst* of it (ten milliseconds).
//!    Once more has been spent than the budget had, the interface is
//!    under load, and stays so for a second after the last time that was
//!    the case. (The Linux implementation's signal is of the same kind —
//!    a backlog of handshake work — and it holds for a second as well.
//!    BoringTun counts messages instead, ten a second per peer; a count
//!    can be set here too, [`RateLimiter::new`], and the two then both
//!    apply.)
//!
//!    Two things about that shape are deliberate.
//!
//!    *The budget fills continuously and is small.* It used to be a tenth
//!    of each one-second window, all of it available the moment the
//!    window began: a hundred milliseconds of handshake arithmetic in one
//!    piece, once a second, for as long as anyone who knows the public
//!    key kept sending — and a caller that does that work where it reads
//!    its socket read nothing else meanwhile. Now the most that is ever
//!    done in one piece is the burst, and a flood that goes on is held to
//!    cookie replies: the hold means it does not get its tenth of a core
//!    back every time the budget recovers.
//!
//!    *The budget is in time, not in messages.* Being under load is not
//!    free. A handshake that meets a cookie reply starts over one
//!    Rekey-Timeout later — five seconds, in either role — and while
//!    cookies are being demanded, someone who can see our handshake
//!    messages and inject datagrams (but not drop any) can keep
//!    handshakes from completing by racing forged cookie replies: the key
//!    they are sealed with is derived from a public key. A limiter that
//!    trips at ten messages a second hands that position to anyone who
//!    knows the interface's public key and can send thirty datagrams a
//!    second. One that trips when handshakes cost real time does not trip
//!    before they do.
//! 2. **The per-source allowance.** A proven address is something a limit
//!    can safely be keyed on, so each one gets a token bucket: the Linux
//!    implementation's 20 handshake messages per second with a burst of 5,
//!    per IPv4 address or IPv6 /64. Without this a single cookie would buy
//!    unlimited X25519. And because addresses come in blocks — whoever
//!    holds a /48 has 65,536 /64s to send from — the blocks have
//!    allowances as well: an IPv4 /24 or IPv6 /48 may send what sixteen
//!    of its sources may, an IPv4 /16 or IPv6 /32 what 256 may.
//!
//! The order matters, and the driver keeps to it: the allowance is only
//! consulted for a message whose cookie has been verified. Keyed on an
//! *unproven* source address — which costs nothing to forge — the same
//! limit would let anyone who knows the interface's public key use up the
//! allowance of an address of their choosing, and so lock that peer out.
//!
//! **Cookie replies** are the third thing a limiter can bound
//! ([`RateLimiter::with_cookie_reply_limit`]). Under load every handshake
//! message without a cookie asks for one: sixty-four bytes to an address
//! its sender chose. By default nothing caps them but the caller's spare
//! time (the event loop of this crate makes them last, after traffic and
//! after proven handshakes, and drops what it has no time or room for);
//! on an uplink much narrower than the downlink, give them a number. The
//! cap is for all of them together — never per source, for the reason
//! above: the address is unproven.
//!
//! Everything here advances by the limiter's own monotonic clock,
//! whenever it is consulted. It does not depend on anything else being
//! called: an idle tunnel that suddenly receives a burst of handshake
//! messages finds a full budget, and a limiter that tripped recovers
//! without any timer having to fire.
//!
//! A limiter is consulted by the [`crate::Tunn`] it was given to. One
//! `Arc` may be given to several of them (each on its own socket) to
//! make the load signal and the per-source allowances those of the host
//! as a whole.
//!
//! # Choosing the budget
//!
//! The default — a tenth of a core — is for what a [`crate::Tunn`] is:
//! one peer. That peer's own handshakes are one every two minutes, so
//! whatever takes a tenth of a core is somebody else's, and it takes a
//! few thousand forged initiations a second to get there (the X25519
//! each one costs is a few dozen microseconds). Raising the budget does
//! not keep anyone from getting there — five times the budget is five
//! times the datagrams, still a few megabits — it only lets them have
//! that much more of the core first; and what being under load costs
//! the peer is five seconds on a *new* handshake, nothing on a session
//! that is up. So the default errs towards cookies. Lower is not better
//! either: under load is also when a forged cookie reply can do harm
//! (above), and a threshold that the peer's own retransmissions can
//! reach would be BoringTun's problem again.
//!
//! A limiter shared by many tunnels sees the handshakes of all of them,
//! and should be given a budget for that: a thousand peers rekeying are
//! eight handshakes a second, a millisecond or two of every second and
//! nowhere near the default; all of them reconnecting at once — after a
//! restart — is an eighth of a second of work arriving within a round
//! trip, which the default answers with cookies after the first eighty
//! (they then all complete five seconds later). If that is not wanted,
//! [`RateLimiter::with_budget`] and [`RateLimiter::with_burst`] say what
//! is: a burst as long as the storm, a budget for the cores handshakes
//! are done on.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// One second, in nanoseconds.
const SECOND_NS: u64 = 1_000_000_000;

/// What a bucket is keyed on: a source, or a block of them. A source is
/// an IPv4 address or the /64 an IPv6 address is in (one subscriber
/// typically controls a whole /64, so its addresses share an allowance —
/// as in the Linux implementation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SourceKey {
    V4([u8; 4]),
    V4Net24([u8; 3]),
    V4Net16([u8; 2]),
    V6Net64([u8; 8]),
    V6Net48([u8; 6]),
    V6Net32([u8; 4]),
}

impl SourceKey {
    /// The buckets a message from `ip` draws on, widest block first, each
    /// with what one message costs it.
    fn levels(ip: IpAddr) -> [(Self, u64); 3] {
        let v4 = |[a, b, c, d]: [u8; 4]| {
            [
                (Self::V4Net16([a, b]), RateLimiter::REGION_COST_NS),
                (Self::V4Net24([a, b, c]), RateLimiter::GROUP_COST_NS),
                (Self::V4([a, b, c, d]), RateLimiter::SOURCE_COST_NS),
            ]
        };
        match ip {
            IpAddr::V4(v4_addr) => v4(v4_addr.octets()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(mapped) => v4(mapped.octets()),
                None => {
                    let [a, b, c, d, e, f, g, h, ..] = v6.octets();
                    [
                        (Self::V6Net32([a, b, c, d]), RateLimiter::REGION_COST_NS),
                        (
                            Self::V6Net48([a, b, c, d, e, f]),
                            RateLimiter::GROUP_COST_NS,
                        ),
                        (
                            Self::V6Net64([a, b, c, d, e, f, g, h]),
                            RateLimiter::SOURCE_COST_NS,
                        ),
                    ]
                }
            },
        }
    }
}

/// A token bucket, in nanoseconds of credit: credit accrues with time up
/// to [`RateLimiter::SOURCE_CREDIT_MAX_NS`], and a message costs what its
/// level says ([`SourceKey::levels`]).
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

    /// Bring the credit up to date; is there enough of it for `cost_ns`?
    fn has(&mut self, now_ns: u64, cost_ns: u64) -> bool {
        let earned = now_ns.saturating_sub(self.last_ns);
        self.credit_ns = self
            .credit_ns
            .saturating_add(earned)
            .min(RateLimiter::SOURCE_CREDIT_MAX_NS);
        self.last_ns = now_ns;
        self.credit_ns >= cost_ns
    }

    /// Take `cost_ns` (after [`Self::has`] said there is that much).
    fn take(&mut self, cost_ns: u64) {
        self.credit_ns = self.credit_ns.saturating_sub(cost_ns);
    }
}

/// The per-source table, and when it was last swept.
#[derive(Debug)]
struct Sources {
    buckets: HashMap<SourceKey, Bucket>,
    swept_ns: u64,
    /// The one bucket shared by the sources (and blocks) there is no room
    /// for in the table.
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

/// Handshake limiter (load signal, per-source allowance, cookie replies);
/// see the module docs.
#[derive(Debug)]
pub struct RateLimiter {
    /// Handshake messages allowed per [`Self::RESET_PERIOD`] before
    /// `under_load` engages (`u64::MAX`: any number).
    limit: u64,
    /// Time handshake messages may take per [`Self::RESET_PERIOD`] on
    /// average before `under_load` engages, in nanoseconds (`u64::MAX`:
    /// any amount).
    budget_ns: u64,
    /// How much of that time may be spent at once.
    burst_ns: u64,
    /// Handshake messages seen in the current window (for `limit`).
    count: AtomicU64,
    /// Nanos-since-construction at which the current window began;
    /// advanced lock-free via CAS.
    window_start_ns: AtomicU64,
    /// The time budget, kept as one instant: the moment by which the
    /// handshake time spent so far will have been earned back at the
    /// budget's rate. It lies in the past while the budget is full, and
    /// further ahead of now than the burst allows once it is overdrawn.
    earned_back_ns: AtomicU64,
    /// Under load until this instant at the least: [`Self::LOAD_HOLD`]
    /// after the budget was last found overdrawn.
    held_until_ns: AtomicU64,
    /// Cookie replies allowed per second (`u64::MAX`: any number).
    reply_limit: u64,
    /// The same kind of instant as `earned_back_ns`, for cookie replies.
    replies_earned_back_ns: AtomicU64,
    /// Token buckets of sources whose address a cookie has proven. Only
    /// touched for such messages — never on the data path.
    sources: Mutex<Sources>,
    epoch: Instant,
    /// How often the clock has been read. The limiter is for handshake
    /// messages; the tests of the data path check that it stays out of it.
    #[cfg(test)]
    clock_reads: AtomicU64,
    /// All the handshake time this limiter was ever told of.
    #[cfg(test)]
    spent_ns: AtomicU64,
}

impl RateLimiter {
    /// BoringTun's number for a limiter that counts messages
    /// (`PEER_HANDSHAKE_RATE_LIMIT = 10` a second). It is not what
    /// [`RateLimiter::default`] does — see the module documentation for
    /// what a threshold this low gives away — and is here for callers
    /// that want BoringTun's behaviour: `RateLimiter::new(DEFAULT_LIMIT)`.
    pub const DEFAULT_LIMIT: u64 = 10;
    /// The default load signal: handshake messages may take this much
    /// time for every [`Self::RESET_PERIOD`] that passes — a tenth of it,
    /// a tenth of one core — before cookies are demanded.
    pub const DEFAULT_BUDGET: Duration = Duration::from_millis(100);
    /// The time the budget is counted against (and the length of one
    /// counting window, for a limiter that counts).
    pub const RESET_PERIOD: Duration = Duration::from_secs(1);
    /// How much of the budget may be spent in one piece: what the budget
    /// holds when nothing has drawn on it for a while. Eighty handshakes
    /// answered back to back, on the machine this was written on — and
    /// the longest a caller that does handshakes where it reads its
    /// socket is kept from reading it. (A budget smaller than this is its
    /// own burst.) [`RateLimiter::with_burst`] changes it.
    pub const DEFAULT_BURST: Duration = Duration::from_millis(10);
    /// How long the interface stays under load after its budget was last
    /// found overdrawn (the Linux implementation's second).
    pub const LOAD_HOLD: Duration = Duration::from_secs(1);

    /// Sustained handshake messages per second one proven source may send
    /// (Linux: `PACKETS_PER_SECOND`).
    pub const SOURCE_RATE: u64 = 20;
    /// …and how many it may send at once (Linux: `PACKETS_BURSTABLE`).
    pub const SOURCE_BURST: u64 = 5;
    /// What a block of sources — an IPv4 /24, an IPv6 /48 — may send, in
    /// sources' allowances: sixteen times [`Self::SOURCE_RATE`] with
    /// sixteen times the burst, however many of its addresses take part.
    pub const SOURCE_GROUP: u64 = 16;
    /// The same for the block above that: an IPv4 /16, an IPv6 /32.
    pub const SOURCE_REGION: u64 = 256;
    /// How many buckets are kept at a time (as many as the Linux
    /// implementation keeps). A source takes one, and so does each of
    /// the two blocks it is in, if they have none yet. A bucket is
    /// forgotten one second after it was last asked. While the table is
    /// full, what has no bucket in it is not refused: it draws on one
    /// allowance shared by everything in that position, so that a peer
    /// nobody has seen yet still has a chance.
    pub const MAX_SOURCES: usize = 65_536;

    const SOURCE_COST_NS: u64 = SECOND_NS / Self::SOURCE_RATE;
    const GROUP_COST_NS: u64 = Self::SOURCE_COST_NS / Self::SOURCE_GROUP;
    const REGION_COST_NS: u64 = Self::SOURCE_COST_NS / Self::SOURCE_REGION;
    /// The same for every level: a level's burst is its cost into this.
    const SOURCE_CREDIT_MAX_NS: u64 = Self::SOURCE_COST_NS * Self::SOURCE_BURST;
    /// While the table is full it is swept for buckets to forget at most
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

    /// A limiter that measures: handshake messages may take `budget` for
    /// every [`Self::RESET_PERIOD`] that passes, and
    /// [`Self::DEFAULT_BURST`] of it at once (all of it, if it is less
    /// than that); when more has been spent, the interface is under load.
    /// Their number is not limited. This is what [`RateLimiter::default`]
    /// is, with [`Self::DEFAULT_BUDGET`].
    #[must_use]
    pub fn with_budget(budget: Duration) -> Self {
        Self::with_limits(u64::MAX, budget)
    }

    /// A limiter with both thresholds: under load once either the number
    /// of handshake messages in the current window exceeds `limit`, or
    /// the time they have taken exceeds what `budget` allows.
    #[must_use]
    pub fn with_limits(limit: u64, budget: Duration) -> Self {
        let budget_ns = u64::try_from(budget.as_nanos()).unwrap_or(u64::MAX);
        Self {
            limit,
            budget_ns,
            burst_ns: budget_ns.min(nanos(Self::DEFAULT_BURST)),
            count: AtomicU64::new(0),
            window_start_ns: AtomicU64::new(0),
            earned_back_ns: AtomicU64::new(0),
            held_until_ns: AtomicU64::new(0),
            reply_limit: u64::MAX,
            replies_earned_back_ns: AtomicU64::new(0),
            sources: Mutex::default(),
            epoch: Instant::now(),
            #[cfg(test)]
            clock_reads: AtomicU64::new(0),
            #[cfg(test)]
            spent_ns: AtomicU64::new(0),
        }
    }

    /// The same limiter with another burst: how much of the time budget
    /// may be spent in one piece (see [`Self::DEFAULT_BURST`]). A host
    /// whose peers all come back at once after a restart wants more; a
    /// caller that cannot be kept from its socket for ten milliseconds
    /// wants less.
    #[must_use]
    pub fn with_burst(mut self, burst: Duration) -> Self {
        self.burst_ns = nanos(burst);
        self
    }

    /// The same limiter with a cap on cookie replies: at most
    /// `per_second` of them, with a tenth of that at once (`0`: none at
    /// all). Without a cap — the default — as many are made as the caller
    /// has time for. See the module documentation for when to set one,
    /// and for why it is not per source.
    #[must_use]
    pub fn with_cookie_reply_limit(mut self, per_second: u64) -> Self {
        self.reply_limit = per_second;
        self
    }

    /// How often this limiter has read the clock.
    #[cfg(test)]
    pub(crate) fn clock_reads(&self) -> u64 {
        self.clock_reads.load(Ordering::Relaxed)
    }

    /// All the handshake time this limiter has been told of.
    #[cfg(test)]
    pub(crate) fn spent_ns(&self) -> u64 {
        self.spent_ns.load(Ordering::Relaxed)
    }

    /// Record one handshake message and return `true` if it is to be
    /// treated as arriving under load.
    #[must_use]
    pub fn note_handshake(&self) -> bool {
        self.note_handshake_at(self.now_ns())
    }

    /// Record how long one handshake message took to deal with, from the
    /// moment it was looked at to the moment its answer (or the decision
    /// to give none) was ready. This is what the time budget is drawn
    /// down by; a limiter that only counts ignores it.
    pub fn note_handshake_time(&self, took: Duration) {
        self.note_handshake_time_at(self.now_ns(), nanos(took));
    }

    /// Current under-load state without bumping the counter.
    #[must_use]
    pub fn is_under_load(&self) -> bool {
        self.is_under_load_at(self.now_ns())
    }

    /// May a handshake message from `source` — an address **a cookie has
    /// proven** — be processed now? Takes one token from that source's
    /// bucket, and from those of the blocks it is in, if each has one.
    ///
    /// Only ever call this for a message whose `mac2` was verified
    /// ([`wireguard_sans_io::Initiation::source_verified`]); see the
    /// module docs for what goes wrong otherwise.
    #[must_use]
    pub fn allow_source(&self, source: IpAddr) -> bool {
        self.allow_source_at(source, self.now_ns())
    }

    /// May one more cookie reply be made now? Always, unless the limiter
    /// was given a cap ([`RateLimiter::with_cookie_reply_limit`]); with
    /// one, this takes a reply from it.
    #[must_use]
    pub fn allow_cookie_reply(&self) -> bool {
        self.allow_cookie_reply_at(self.now_ns())
    }

    /// Unconditionally start afresh: a full budget, a new window, no
    /// hold, and every source forgotten.
    pub fn reset(&self) {
        let now_ns = self.now_ns();
        self.window_start_ns.store(now_ns, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
        self.earned_back_ns.store(0, Ordering::Relaxed);
        self.held_until_ns.store(0, Ordering::Relaxed);
        self.replies_earned_back_ns.store(0, Ordering::Relaxed);
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
        let now_ns = self.now_ns();
        self.note_handshake_time_at(now_ns, now_ns.saturating_sub(started_ns));
    }

    /// [`note_handshake_time`](Self::note_handshake_time) at an explicit
    /// instant: `took_ns` of handshake time, ending at `now_ns`.
    pub(crate) fn note_handshake_time_at(&self, now_ns: u64, took_ns: u64) {
        #[cfg(test)]
        {
            // Saturating (and not atomic as a whole): this is for tests
            // that ask whether any time was counted at all.
            let spent = self.spent_ns.load(Ordering::Relaxed);
            self.spent_ns
                .store(spent.saturating_add(took_ns), Ordering::Relaxed);
        }
        if self.budget_ns == u64::MAX {
            return;
        }
        // `took_ns` of work takes `ahead` to earn back; the budget is
        // overdrawn when more is owed than the burst covers.
        let slack = self.slack_ns();
        let ahead = self.earning_time_ns(took_ns);
        // What is owed is bounded — at twice the burst — so that an
        // interface which was flooded for an hour does not stay under
        // load for the next one: it recovers within the burst's worth of
        // time, and the hold.
        let ceiling = now_ns.saturating_add(slack.saturating_mul(2));
        let mut seen = self.earned_back_ns.load(Ordering::Relaxed);
        let owed = loop {
            let owed = seen.max(now_ns).saturating_add(ahead);
            // (Never earlier than it was: another thread may have read a
            // later clock.)
            let stored = owed.min(ceiling).max(seen);
            match self.earned_back_ns.compare_exchange_weak(
                seen,
                stored,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break owed,
                Err(now_seen) => seen = now_seen,
            }
        };
        if owed.saturating_sub(now_ns) > slack {
            let until = now_ns.saturating_add(nanos(Self::LOAD_HOLD));
            self.held_until_ns.fetch_max(until, Ordering::Relaxed);
        }
    }

    /// [`note_handshake`](Self::note_handshake) at an explicit instant
    /// (nanoseconds since construction).
    pub(crate) fn note_handshake_at(&self, now_ns: u64) -> bool {
        self.roll_window(now_ns);
        let over_count = self.count.fetch_add(1, Ordering::Relaxed) >= self.limit;
        over_count || self.over_budget(now_ns)
    }

    /// [`is_under_load`](Self::is_under_load) at an explicit instant.
    pub(crate) fn is_under_load_at(&self, now_ns: u64) -> bool {
        self.roll_window(now_ns);
        self.count.load(Ordering::Relaxed) >= self.limit || self.over_budget(now_ns)
    }

    /// How long it takes to earn back `took_ns` of handshake time at the
    /// budget's rate.
    fn earning_time_ns(&self, took_ns: u64) -> u64 {
        let period = u128::from(nanos(Self::RESET_PERIOD));
        match u128::from(took_ns)
            .saturating_mul(period)
            .checked_div(u128::from(self.budget_ns))
        {
            Some(ahead) => u64::try_from(ahead).unwrap_or(u64::MAX),
            // No budget at all: nothing is ever earned back.
            None => u64::MAX,
        }
    }

    /// How far ahead of now `earned_back_ns` may lie: the burst, in the
    /// time it takes to earn it back.
    fn slack_ns(&self) -> u64 {
        self.earning_time_ns(self.burst_ns)
    }

    /// Is the time budget overdrawn, or was it within the last
    /// [`Self::LOAD_HOLD`]? (Never, for a limiter without one — whatever
    /// it has been told.)
    fn over_budget(&self, now_ns: u64) -> bool {
        if self.budget_ns == u64::MAX {
            return false;
        }
        if self.budget_ns == 0 {
            return true; // no time at all: under load from the start
        }
        now_ns < self.held_until_ns.load(Ordering::Relaxed)
            || self
                .earned_back_ns
                .load(Ordering::Relaxed)
                .saturating_sub(now_ns)
                > self.slack_ns()
    }

    /// [`allow_cookie_reply`](Self::allow_cookie_reply) at an explicit
    /// instant.
    pub(crate) fn allow_cookie_reply_at(&self, now_ns: u64) -> bool {
        if self.reply_limit == u64::MAX {
            return true;
        }
        // One reply every `interval`, and a tenth of a second's worth at
        // once.
        let Some(interval) = SECOND_NS.checked_div(self.reply_limit) else {
            return false; // a cap of none
        };
        let burst = (self.reply_limit / 10).max(1);
        let tolerance = interval.saturating_mul(burst.saturating_sub(1));
        let mut seen = self.replies_earned_back_ns.load(Ordering::Relaxed);
        loop {
            if seen.saturating_sub(now_ns) > tolerance {
                return false;
            }
            let next = seen.max(now_ns).saturating_add(interval);
            match self.replies_earned_back_ns.compare_exchange_weak(
                seen,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(now_seen) => seen = now_seen,
            }
        }
    }

    /// [`allow_source`](Self::allow_source) at an explicit instant.
    pub(crate) fn allow_source_at(&self, source: IpAddr, now_ns: u64) -> bool {
        let levels = SourceKey::levels(source);
        // A panic while the lock was held cannot leave the table in a
        // state worth refusing service over.
        let mut guard = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        let sources = &mut *guard;

        // Forget buckets that have not been asked for a second (they
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

        // First: is there a token at every level? Widest block first, and
        // no further once one says no — so that a block which is over its
        // allowance cannot fill the table with buckets for its addresses.
        let mut unplaced = false;
        for (key, cost) in levels {
            let room = sources.buckets.len() < Self::MAX_SOURCES;
            match sources.buckets.get_mut(&key) {
                Some(bucket) => {
                    if !bucket.has(now_ns, cost) {
                        return false;
                    }
                }
                None if room => {
                    sources.buckets.insert(key, Bucket::full(now_ns));
                }
                // Still full of buckets asked within the last second. The
                // table does not grow without bound, and the newcomer is
                // not refused outright either — it would be the genuine
                // peer as likely as not: what has no place shares one
                // bucket.
                None => unplaced = true,
            }
        }
        if unplaced && !sources.overflow.has(now_ns, Self::SOURCE_COST_NS) {
            return false;
        }
        // Then: take one from each. (Not before every level has agreed: a
        // source that is over its own allowance does not use up its
        // neighbours'.)
        for (key, cost) in levels {
            if let Some(bucket) = sources.buckets.get_mut(&key) {
                bucket.take(cost);
            }
        }
        if unplaced {
            sources.overflow.take(Self::SOURCE_COST_NS);
        }
        true
    }

    /// Start a new counting window if the current one is over. Lock-free:
    /// only one caller wins the CAS and zeroes the count.
    fn roll_window(&self, now_ns: u64) {
        let period = nanos(Self::RESET_PERIOD);
        let start = self.window_start_ns.load(Ordering::Relaxed);
        if now_ns.saturating_sub(start) >= period
            && self
                .window_start_ns
                .compare_exchange(start, now_ns, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.count.store(0, Ordering::Relaxed);
        }
    }
}

/// A duration in nanoseconds, or as near as a `u64` gets.
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
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
    const US: u64 = 1_000;

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
    fn idle_limiter_does_not_accumulate() {
        // One handshake every ten seconds for a day must never trip a
        // limit of 10 per second — nor a budget, though each takes nearly
        // all the budget holds at once.
        for rl in [
            RateLimiter::new(RateLimiter::DEFAULT_LIMIT),
            RateLimiter::default(),
        ] {
            for i in 0..8640u64 {
                let at = i * 10_000 * MS;
                assert!(!rl.note_handshake_at(at), "handshake {i}");
                rl.note_handshake_time_at(at + 9 * MS, 9 * MS);
            }
        }
    }

    /// The default signal: time, not number. Any number of messages that
    /// cost nothing do not trip it; nor does work up to the burst, done in
    /// one piece; a little more does, and the interface is then under
    /// load for a second after the last time that was so.
    #[test]
    fn the_default_limiter_trips_on_time_spent_not_on_a_count() {
        assert_eq!(RateLimiter::DEFAULT_BUDGET, Duration::from_millis(100));
        assert_eq!(RateLimiter::DEFAULT_BURST, Duration::from_millis(10));
        assert_eq!(RateLimiter::LOAD_HOLD, Duration::from_secs(1));
        let rl = RateLimiter::default();
        for i in 0..100_000u64 {
            assert!(!rl.note_handshake_at(i * 1000), "message {i}");
        }
        assert!(!rl.is_under_load_at(200 * MS));
        // The whole burst in one piece: within the budget.
        rl.note_handshake_time_at(300 * MS, 10 * MS);
        assert!(!rl.is_under_load_at(300 * MS));
        // A microsecond more: overdrawn.
        rl.note_handshake_time_at(300 * MS, US);
        assert!(rl.is_under_load_at(300 * MS));
        assert!(rl.note_handshake_at(301 * MS));
        // What was owed is earned back in no time (a microsecond of work
        // is ten of budget) — but the interface stays under load for a
        // second after it was last overdrawn…
        assert!(rl.is_under_load_at(1299 * MS));
        // …and then it is not, with nothing having been called between.
        assert!(!rl.is_under_load_at(1300 * MS));
        assert!(!rl.note_handshake_at(1301 * MS));
        // The sum cannot wrap into "no load", and what is owed is
        // bounded: after any amount of work the budget is back within
        // the time it takes to earn the burst (and the hold).
        rl.note_handshake_time_at(2000 * MS, u64::MAX - 5);
        rl.note_handshake_time_at(2000 * MS, 10);
        assert!(rl.is_under_load_at(2000 * MS));
        rl.note_handshake_time(Duration::MAX);
        assert!(rl.is_under_load());
        // `reset` clears it.
        rl.reset();
        assert!(!rl.is_under_load());
    }

    /// The budget fills continuously: work that stays under a tenth of
    /// the time never trips it, however long it goes on, and work above
    /// that does once the burst is gone — for good, while it lasts.
    #[test]
    fn the_budget_is_a_rate_with_a_burst_not_a_window() {
        // 90 µs of work every millisecond: 9 % of the time.
        let rl = RateLimiter::default();
        for i in 0..3_600_000u64 {
            let at = i * MS;
            assert!(!rl.note_handshake_at(at), "at {i} ms");
            rl.note_handshake_time_at(at + 90 * US, 90 * US);
        }
        // 110 µs every millisecond: 11 %. The burst lasts a while (ten
        // microseconds are lost to it each time: a thousand rounds), and
        // then it is over.
        let rl = RateLimiter::default();
        let mut tripped_at = None;
        for i in 0..5_000u64 {
            let at = i * MS;
            let loaded = rl.note_handshake_at(at);
            if loaded && tripped_at.is_none() {
                tripped_at = Some(i);
            }
            if tripped_at.is_some() {
                assert!(loaded, "at {i} ms: under load stays under load");
            }
            rl.note_handshake_time_at(at + 110 * US, 110 * US);
        }
        let tripped_at = tripped_at.unwrap(); // 11 % is over the budget
        assert!(
            (900..=1100).contains(&tripped_at),
            "tripped at {tripped_at} ms"
        );
    }

    /// What this limiter is for. Messages arrive as fast as they can be
    /// dealt with, each costing an X25519 while the interface is not
    /// under load and a cookie reply while it is — a flood by someone who
    /// knows the public key. The handshake arithmetic that gets done is
    /// the burst once, and then next to nothing: never a tenth of a
    /// second in one piece every second, which is what a budget that
    /// started over with every window allowed.
    #[test]
    fn a_flood_gets_the_burst_once_and_no_long_stretch_of_work_again() {
        const X25519: u64 = 34 * US;
        const COOKIE: u64 = 1400;
        for (gap, what) in [(0u64, "back to back"), (20 * US, "50,000 a second")] {
            let rl = RateLimiter::default();
            let mut now = 0u64;
            let (mut stretch, mut longest, mut worked) = (0u64, 0u64, 0u64);
            let mut first_stretch = None;
            while now < 10_000 * MS {
                let cost = if rl.note_handshake_at(now) {
                    if first_stretch.is_none() {
                        first_stretch = Some(stretch);
                    }
                    stretch = 0;
                    COOKIE
                } else {
                    stretch += X25519;
                    worked += X25519;
                    longest = longest.max(stretch);
                    X25519
                };
                now += cost;
                rl.note_handshake_time_at(now, cost);
                now += gap;
            }
            // The first stretch is the burst (and what was earned while
            // it lasted); none is longer.
            let first = first_stretch.unwrap(); // the flood trips the limiter
            assert_eq!(first, longest, "{what}");
            assert!(
                (10 * MS..=12 * MS).contains(&longest),
                "{what}: {longest} ns"
            );
            // Ten seconds of flood: under the old window that was a full
            // second of arithmetic. Now it is the burst, and whatever the
            // hold lets through when it runs out.
            assert!(
                worked <= 120 * MS,
                "{what}: {worked} ns of X25519 in ten seconds"
            );
        }
    }

    /// A burst of another size, and what no budget and no burst mean.
    #[test]
    fn the_burst_can_be_chosen() {
        let rl = RateLimiter::default().with_burst(Duration::from_millis(50));
        rl.note_handshake_time_at(0, 50 * MS);
        assert!(!rl.is_under_load_at(0));
        rl.note_handshake_time_at(0, US);
        assert!(rl.is_under_load_at(0));
        // No burst: any work at all puts the interface under load for the
        // hold.
        let rl = RateLimiter::default().with_burst(Duration::ZERO);
        assert!(!rl.is_under_load_at(0));
        rl.note_handshake_time_at(5 * MS, 1);
        assert!(rl.is_under_load_at(5 * MS));
        assert!(rl.is_under_load_at(1004 * MS));
        assert!(!rl.is_under_load_at(1005 * MS));
        // A budget smaller than the default burst is its own burst.
        let rl = RateLimiter::with_budget(Duration::from_millis(2));
        rl.note_handshake_time_at(0, 2 * MS);
        assert!(!rl.is_under_load_at(0));
        rl.note_handshake_time_at(0, US);
        assert!(rl.is_under_load_at(0));
        // No budget: under load from the start.
        let rl = RateLimiter::with_budget(Duration::ZERO);
        assert!(rl.is_under_load_at(0));
        assert!(rl.note_handshake_at(0));
    }

    /// Both thresholds at once: whichever is reached first.
    #[test]
    fn a_limiter_with_both_thresholds_trips_on_either() {
        let rl = RateLimiter::with_limits(3, Duration::from_millis(10));
        assert!(!rl.note_handshake_at(0));
        rl.note_handshake_time_at(0, 10 * MS + 1);
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
        assert!(rl.spent_ns() > 0, "…though it was told");
        // What `Tunn` does: one reading when the message arrives, one
        // when it is done with, and the difference is what it took.
        let rl = RateLimiter::with_budget(Duration::from_millis(5));
        let started = rl.now_ns();
        assert!(!rl.is_under_load_at(started));
        std::thread::sleep(Duration::from_millis(6));
        rl.note_handshake_time_since(started);
        assert!(rl.is_under_load());
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

    // ---- cookie replies ----------------------------------------------------

    #[test]
    fn cookie_replies_are_uncapped_unless_asked() {
        let rl = RateLimiter::default();
        for i in 0..100_000u64 {
            assert!(rl.allow_cookie_reply_at(i));
        }
        assert!(rl.allow_cookie_reply());
    }

    /// A cap of a thousand a second: a tenth of that at once, and then
    /// one a millisecond — in all, not per source.
    #[test]
    fn a_cap_on_cookie_replies_is_a_rate_with_a_burst() {
        let rl = RateLimiter::default().with_cookie_reply_limit(1000);
        let at = |ns: u64, n: u32| (0..n).filter(|_| rl.allow_cookie_reply_at(ns)).count();
        assert_eq!(at(0, 500), 100, "the burst");
        assert_eq!(at(999 * US, 10), 0);
        assert_eq!(at(MS, 10), 1);
        // A flood for a second: a thousand replies.
        let mut made = 0;
        for i in 1..=100_000u64 {
            made += at(MS + i * 10 * US, 1);
        }
        assert_eq!(made, 1000);
        // Quiet for a minute: the burst again, and no more than that.
        assert_eq!(at(60_000 * MS, 500), 100);
        // One a second is one a second; none is none.
        let rl = RateLimiter::default().with_cookie_reply_limit(1);
        assert!(rl.allow_cookie_reply_at(0));
        assert!(!rl.allow_cookie_reply_at(999 * MS));
        assert!(rl.allow_cookie_reply_at(1000 * MS));
        let rl = RateLimiter::default().with_cookie_reply_limit(0);
        assert!(!rl.allow_cookie_reply_at(0));
        assert!(!rl.allow_cookie_reply_at(3_600_000 * MS));
        // `reset` gives the burst back.
        let rl = RateLimiter::default().with_cookie_reply_limit(10);
        assert!(rl.allow_cookie_reply_at(0));
        assert!(!rl.allow_cookie_reply_at(0));
        rl.reset();
        assert!(rl.allow_cookie_reply_at(0));
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

    /// A block of addresses has an allowance too: whoever holds a /48 has
    /// 65,536 /64s to send from, and gets what sixteen sources get — not
    /// 65,536 times what one does. The same one level up, and for IPv4.
    #[test]
    fn a_block_of_sources_gets_sixteen_sources_worth_and_a_bigger_one_256() {
        assert_eq!(
            (RateLimiter::SOURCE_GROUP, RateLimiter::SOURCE_REGION),
            (16, 256)
        );
        let through = |rl: &RateLimiter, sources: &mut dyn Iterator<Item = IpAddr>, at: u64| {
            sources.filter(|s| rl.allow_source_at(*s, at)).count()
        };
        // Every /64 of one /48, once each, at one instant: 80 get
        // through (sixteen bursts of five) — not 65,536.
        let rl = RateLimiter::default();
        let mut all = (0..=u16::MAX).map(|n| IpAddr::from([0x2001, 0xdb8, 7, n, 0, 0, 0, 1]));
        assert_eq!(through(&rl, &mut all, 0), 80);
        // Over the next second: 320 (sixteen times twenty).
        let mut passed = 0;
        for ms in 1..=1000u64 {
            let mut some = (0..200u16).map(|n| {
                IpAddr::from([
                    0x2001,
                    0xdb8,
                    7,
                    (ms as u16).wrapping_mul(200).wrapping_add(n),
                    0,
                    0,
                    0,
                    1,
                ])
            });
            passed += through(&rl, &mut some, ms * MS);
        }
        assert_eq!(passed, 320);
        // Another /48 of the same /32 has its own allowance…
        let mut next = (0..=u16::MAX).map(|n| IpAddr::from([0x2001, 0xdb8, 8, n, 0, 0, 0, 1]));
        assert_eq!(through(&rl, &mut next, 1000 * MS), 80);
        // …but all of a /32 together get 256 sources' worth: 1,280 at
        // once, from however many /48s.
        let rl = RateLimiter::default();
        let mut wide = (0..40_000u32)
            .map(|n| IpAddr::from([0x2001, 0xdb8, (n / 4) as u16, (n % 4) as u16, 0, 0, 0, 1]));
        assert_eq!(through(&rl, &mut wide, 0), 1280);

        // IPv4: a /24 is the block, a /16 the bigger one.
        let rl = RateLimiter::default();
        let mut hosts = (0..=255u8).map(|n| IpAddr::from([203, 0, 113, n]));
        assert_eq!(through(&rl, &mut hosts, 0), 80);
        let rl = RateLimiter::default();
        let mut nets =
            (0..20_000u32).map(|n| IpAddr::from([198, 18, (n / 80) as u8, (n % 80) as u8]));
        assert_eq!(through(&rl, &mut nets, 0), 1280);
    }

    /// A source that is over its own allowance does not use up its
    /// neighbours': the block's tokens go only to messages that are let
    /// through.
    #[test]
    fn a_greedy_source_does_not_spend_its_blocks_allowance() {
        let rl = RateLimiter::default();
        // One address asks a hundred thousand times at once: its burst…
        assert_eq!(allowed(&rl, "203.0.113.9", 100_000, 0), 5);
        // …and its neighbours in the /24 have what the block has left at
        // that instant: eighty, less those five — not less a hundred
        // thousand.
        let mut hosts = (10..=255u8).map(|n| IpAddr::from([203, 0, 113, n]));
        assert_eq!(
            hosts.by_ref().filter(|s| rl.allow_source_at(*s, 0)).count(),
            75
        );
        // Over a second of the same, the greedy one gets its twenty and
        // the block is none the poorer for the rest.
        let rl = RateLimiter::default();
        let mut through = 0;
        for i in 0..100_000u64 {
            through += allowed(&rl, "203.0.113.9", 1, i * 10 * US);
        }
        assert_eq!(
            through,
            5 + 19,
            "the burst, and a second's worth less the first instant"
        );
        let mut hosts = (10..=255u8).map(|n| IpAddr::from([203, 0, 113, n]));
        let at = 1000 * MS;
        assert_eq!(
            hosts
                .by_ref()
                .filter(|s| rl.allow_source_at(*s, at))
                .count(),
            80
        );
    }

    #[test]
    fn quiet_sources_are_forgotten_and_the_table_is_bounded() {
        assert_eq!(RateLimiter::MAX_SOURCES, 65_536);
        let rl = RateLimiter::default();
        // Fill the table with sources that have nothing in common — each
        // in a /16 of its own, so each brings three buckets (itself and
        // its two blocks) — all within one second.
        let source = |i: u32| IpAddr::from([(i >> 8) as u8, i as u8, 0, 1]);
        let sources = RateLimiter::MAX_SOURCES as u32 / 3;
        for i in 0..sources {
            assert!(rl.allow_source_at(source(i), u64::from(i)), "source {i}");
        }
        let table_len = |rl: &RateLimiter| rl.sources.lock().unwrap().buckets.len();
        assert_eq!(table_len(&rl), 3 * sources as usize);
        // One bucket's room is left: the next newcomer gets the bucket of
        // its widest block, and nothing after that fits.
        assert!(rl.allow_source_at(source(sources), 400 * MS));
        assert_eq!(table_len(&rl), RateLimiter::MAX_SOURCES);
        // While it is full of recent buckets, a source that is in it
        // keeps its own, and those that are not in it share one: a burst
        // between all of them, then twenty a second.
        assert!(rl.allow_source_at(source(5), 500 * MS));
        let newcomers = |rl: &RateLimiter, n: u32, at_ns: u64| -> u32 {
            (0..n)
                .filter(|i| rl.allow_source_at(source(40_000 + i), at_ns))
                .count() as u32
        };
        // (One of the shared burst went to the newcomer above, a tenth
        // of a second ago: earned back since.)
        assert_eq!(newcomers(&rl, 100, 500 * MS), 5, "the shared burst");
        assert_eq!(newcomers(&rl, 100, 549 * MS), 0);
        assert_eq!(newcomers(&rl, 100, 550 * MS), 1, "and the shared rate");
        assert_eq!(table_len(&rl), RateLimiter::MAX_SOURCES, "it did not grow");
        // A second after they were last asked the old buckets are gone
        // (all but those of the source that was seen at 500 ms), and
        // there is room again: a newcomer gets buckets of its own.
        assert_eq!(allowed(&rl, "203.0.113.1", 100, 1401 * MS), 5);
        assert_eq!(table_len(&rl), 3 + 3);
        // `reset` forgets everything.
        rl.reset();
        assert_eq!(table_len(&rl), 0);
    }

    /// A full table is not swept on every call (each sweep looks at all
    /// of it): ten times a second at the most.
    #[test]
    fn a_full_table_is_swept_ten_times_a_second_at_most() {
        let rl = RateLimiter::default();
        let source = |i: u32| IpAddr::from([(i >> 8) as u8, i as u8, 0, 1]);
        for i in 0..=RateLimiter::MAX_SOURCES as u32 / 3 {
            assert!(rl.allow_source_at(source(i), 900 * MS + u64::from(i)));
        }
        assert_eq!(
            rl.sources.lock().unwrap().buckets.len(),
            RateLimiter::MAX_SOURCES
        );
        let swept = |rl: &RateLimiter| rl.sources.lock().unwrap().swept_ns;
        // (The table was last swept when it was created, at 0; it is due
        // at one second whatever happens.)
        assert_eq!(swept(&rl), 0);
        let mut sweeps = 0;
        let mut last = swept(&rl);
        // Ten thousand calls from newcomers within the next half second.
        for i in 0..10_000u32 {
            let at = 1000 * MS + u64::from(i) * 50_000;
            let _ = rl.allow_source_at(source(30_000 + i), at);
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
