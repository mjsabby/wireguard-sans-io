//! The driver's clock: how long ago a [`crate::Tunn`] was created, as the
//! core's [`Ticks`].
//!
//! # A clock that counts while the machine sleeps
//!
//! WireGuard's keys have lifetimes in real time. A session is good for
//! three minutes; the peer deletes its half after that whether or not we
//! were awake to see it. A clock that stands still while the machine is
//! suspended — which is what `std::time::Instant` is on Linux
//! (`CLOCK_MONOTONIC`) — makes a tunnel that wakes up after an hour
//! believe its session is as young as when the lid was closed: it sends
//! on keys the peer has long expired, everything it sends is lost, and it
//! takes the dead-peer timer fifteen seconds to start a handshake. Keys
//! that should have been wiped nine minutes into the hour are still there.
//!
//! So on Linux and Android the driver's clock is `CLOCK_BOOTTIME`, which
//! counts the time spent suspended (as the kernel's WireGuard does). On
//! other systems it is `Instant`, whatever that is there.
//!
//! What a clock cannot do is run code while the machine is off: timers
//! that came due during a suspend are served on the first call after it.

use wireguard_sans_io::Ticks;

/// Nanoseconds since some fixed point, by the clock that keeps counting
/// during a suspend.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn boot_time_ns() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let secs = u64::try_from(now.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(now.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

/// A point in time to count from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Clock {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    boot_epoch_ns: u64,
    instant_epoch: std::time::Instant,
}

impl Clock {
    /// A clock that reads zero now.
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            boot_epoch_ns: boot_time_ns(),
            instant_epoch: std::time::Instant::now(),
        }
    }

    /// Nanoseconds since this clock was made — including, where the
    /// system can say, the time the machine spent suspended.
    pub(crate) fn now(&self) -> Ticks {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            self.at_boot_time(boot_time_ns())
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            Ticks::from_nanos(self.awake_ns())
        }
    }

    /// This clock's reading when the boot-time clock says `boot_ns`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn at_boot_time(&self, boot_ns: u64) -> Ticks {
        Ticks::from_nanos(boot_ns.saturating_sub(self.boot_epoch_ns))
    }

    /// Nanoseconds since this clock was made by the clock that stops
    /// while the machine is suspended.
    fn awake_ns(&self) -> u64 {
        u64::try_from(self.instant_epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// Two figures, in nanoseconds: how long ago this clock was made by
    /// the clock that stops while the machine is suspended, and how much
    /// of the time since the machine spent suspended — what [`Self::now`]
    /// has counted and `Instant` has not (zero where the system cannot
    /// say).
    ///
    /// (For the async driver, which keeps tokio's time — so that it can
    /// be paused in tests — and adds the second figure to it.)
    #[cfg_attr(not(feature = "async"), allow(dead_code))]
    pub(crate) fn awake_and_suspended_ns(&self) -> (u64, u64) {
        let awake = self.awake_ns();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            (awake, Self::suspended(self.now().nanos(), awake))
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            (awake, 0)
        }
    }

    /// The time spent suspended, given how long ago this clock was made
    /// by the clock that counts it (`elapsed`) and by the one that does
    /// not (`awake`).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn suspended(elapsed: u64, awake: u64) -> u64 {
        // The two clocks are read one after the other, so the difference
        // is a few dozen nanoseconds out; a suspend is seconds at the
        // least. Anything under a millisecond is the reading, not a
        // suspend.
        let suspended = elapsed.saturating_sub(awake);
        if suspended < 1_000_000 { 0 } else { suspended }
    }

    /// Does [`Self::now`] count the time spent suspended on this system?
    pub(crate) const COUNTS_SUSPEND: bool = cfg!(any(target_os = "linux", target_os = "android"));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_clock_starts_at_zero_and_only_goes_forward() {
        let clock = Clock::new();
        let first = clock.now();
        assert!(first.nanos() < 1_000_000_000, "{first:?}");
        std::thread::sleep(Duration::from_millis(20));
        let second = clock.now();
        let passed = second.since(first);
        assert!((20_000_000..2_000_000_000).contains(&passed), "{passed}");
        // Awake all the while: nothing was spent suspended. (Three
        // looks: the two clocks are read one after the other, and a test
        // thread can be taken off the processor in between.)
        let suspended = (0..3).map(|_| clock.awake_and_suspended_ns().1).min();
        assert_eq!(suspended, Some(0));
        let (awake, _) = clock.awake_and_suspended_ns();
        assert!((20_000_000..2_000_000_000).contains(&awake), "{awake}");
    }

    /// What the clock makes of its two sources, on figures no test could
    /// wait for: an hour with five seconds of it awake.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_clock_counts_what_the_boot_time_clock_counts() {
        const S: u64 = 1_000_000_000;
        let clock = Clock::new();
        let made = clock.boot_epoch_ns;
        assert_eq!(clock.at_boot_time(made), Ticks::ZERO);
        assert_eq!(clock.at_boot_time(made + 3600 * S).nanos(), 3600 * S);
        // (A boot-time clock does not go back; if a reading ever did,
        // the tunnel's clock would stand still rather than wrap.)
        assert_eq!(clock.at_boot_time(made - 1), Ticks::ZERO);
        // Of that hour, 3595 seconds were spent suspended…
        assert_eq!(Clock::suspended(3600 * S, 5 * S), 3595 * S);
        // …and of an hour awake, none: not even the few nanoseconds
        // between reading one clock and the other, either way round.
        assert_eq!(Clock::suspended(3600 * S, 3600 * S), 0);
        assert_eq!(Clock::suspended(3600 * S + 999_999, 3600 * S), 0);
        assert_eq!(Clock::suspended(3600 * S, 3600 * S + 500), 0);
        assert_eq!(Clock::suspended(3600 * S + 1_000_000, 3600 * S), 1_000_000);
    }

    /// The clock the tunnel's time is taken from is the one that counts
    /// time spent suspended, and not the one `Instant` reads.
    ///
    /// On a machine that has never been suspended the two read the same,
    /// so this needs a place where they do not: a time namespace in which
    /// the boot-time clock is a day ahead — as it is on a machine that
    /// has slept for a day. `scripts/driver_netns_tests.sh` runs this
    /// test in one and says so in `WG_BOOT_TIME_AHEAD_SECS`; anywhere
    /// else all it can check is that the clock is not behind.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_clock_is_the_one_that_counts_suspend() {
        let monotonic = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        let monotonic_ns = monotonic.tv_sec as u64 * 1_000_000_000 + monotonic.tv_nsec as u64;
        let ahead_ns = boot_time_ns().saturating_sub(monotonic_ns);
        assert!(boot_time_ns() + 1_000_000 >= monotonic_ns);
        if let Ok(expected) = std::env::var("WG_BOOT_TIME_AHEAD_SECS") {
            let expected: u64 = expected.parse().unwrap();
            let ahead = ahead_ns / 1_000_000_000;
            assert!(
                ahead.abs_diff(expected) <= 1,
                "the clock read is {ahead} s ahead of CLOCK_MONOTONIC here, not {expected} s"
            );
            println!("boot-time clock {ahead} s ahead of CLOCK_MONOTONIC, as arranged");
        }
    }

    /// The boot-time clock and `Instant` agree while the machine is
    /// awake — which is all a test can arrange — and the driver's clock
    /// is the former where there is one.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn on_linux_the_clock_is_boot_time() {
        const { assert!(Clock::COUNTS_SUSPEND) };
        let clock = Clock::new();
        std::thread::sleep(Duration::from_millis(10));
        let by_boot_time = boot_time_ns().saturating_sub(clock.boot_epoch_ns);
        let by_clock = clock.now().nanos();
        assert!(by_clock.abs_diff(by_boot_time) < 5_000_000);
        // /proc/uptime is the same clock, to a hundredth of a second: the
        // epoch really is boot time and not something else that happens
        // to tick.
        let uptime: f64 = std::fs::read_to_string("/proc/uptime")
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let boot = boot_time_ns() as f64 / 1e9;
        assert!(
            (boot - uptime).abs() < 1.0,
            "boot time {boot} vs uptime {uptime}"
        );
    }
}
