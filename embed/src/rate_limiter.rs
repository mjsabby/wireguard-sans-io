//! Handshake rate limiter — decides `under_load` for the core.
//!
//! BoringTun's heuristic, lock-free: count handshake-type datagrams
//! (types 1 and 2) in a sliding ~1-second window; once the count exceeds
//! `limit`, every subsequent handshake message is treated as
//! `under_load = true` until the window resets, which makes the core
//! reply with a cheap cookie instead of doing X25519.
//!
//! This is a *global* limiter (one per interface, shared `Arc` across
//! all `Tunn`s). For per-source-IP token buckets — the second half of
//! the kernel's defence — see the README's *Embedding guide*; that needs
//! a `HashMap<IpAddr, Bucket>` and so lives in the multi-peer router
//! layer, not here.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Shared per-interface handshake counter.
#[derive(Debug)]
pub struct RateLimiter {
    /// Handshake messages allowed per [`Self::RESET_PERIOD`] before
    /// `under_load` engages.
    limit: u64,
    /// Handshake messages seen since the last reset.
    count: AtomicU64,
    /// Nanos-since-process-start of the last reset; updated lock-free
    /// via CAS in [`Self::maybe_reset`].
    last_reset_ns: AtomicU64,
    epoch: Instant,
}

impl RateLimiter {
    /// BoringTun's default (`PEER_HANDSHAKE_RATE_LIMIT = 10`).
    pub const DEFAULT_LIMIT: u64 = 10;
    /// How often the counter resets.
    pub const RESET_PERIOD: Duration = Duration::from_secs(1);

    /// New limiter with the given handshakes-per-second threshold.
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            count: AtomicU64::new(0),
            last_reset_ns: AtomicU64::new(0),
            epoch: Instant::now(),
        }
    }

    /// Record one handshake-type datagram and return `true` if the
    /// per-window count is now past `limit` (= caller should pass
    /// `under_load = true`).
    #[must_use]
    pub fn note_handshake(&self) -> bool {
        self.count.fetch_add(1, Ordering::Relaxed) >= self.limit
    }

    /// Current under-load state without bumping the counter.
    #[must_use]
    pub fn is_under_load(&self) -> bool {
        self.count.load(Ordering::Relaxed) >= self.limit
    }

    /// Reset the window if [`Self::RESET_PERIOD`] has elapsed. Called
    /// from `Tunn::update_timers`; cheap enough to call on every tick.
    /// Lock-free: only one caller wins the CAS and performs the reset.
    pub fn maybe_reset(&self) {
        let now_ns = u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let last = self.last_reset_ns.load(Ordering::Relaxed);
        let period = u64::try_from(Self::RESET_PERIOD.as_nanos()).unwrap_or(u64::MAX);
        if now_ns.saturating_sub(last) >= period
            && self
                .last_reset_ns
                .compare_exchange(last, now_ns, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.count.store(0, Ordering::Relaxed);
        }
    }

    /// Unconditionally reset the window (e.g. from a dedicated 1 Hz
    /// ticker thread, BoringTun-style).
    pub fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        let now_ns = u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last_reset_ns.store(now_ns, Ordering::Relaxed);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(Self::DEFAULT_LIMIT)
    }
}
