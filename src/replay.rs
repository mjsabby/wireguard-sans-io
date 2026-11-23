//! Anti-replay sliding window for transport counters (whitepaper §5.4.6,
//! RFC 6479 style bitmap).
//!
//! Checked only *after* AEAD authentication succeeds, so only the
//! legitimate peer can advance it; a cheap read-only pre-check
//! ([`ReplayWindow::check`]) lets the caller drop obvious replays before
//! paying for AEAD verification.

use crate::consts::REJECT_AFTER_MESSAGES;

/// How far behind the greatest counter received a counter may be and
/// still be accepted: a counter `c` is in the window while
/// `greatest − c ≤ WINDOW_BITS`. This is the Linux kernel's rule and its
/// number (`COUNTER_WINDOW_SIZE = COUNTER_BITS_TOTAL − BITS_PER_LONG =
/// 8192 − 64`; `counter_validate` rejects when `COUNTER_WINDOW_SIZE +
/// their_counter < counter`, with both counters stored plus one), so the
/// two accept exactly the same sequences of counters below the message
/// limit — the unit tests compare this window with a transliteration of
/// the kernel's function. (The limit itself differs by 63: the kernel's
/// `REJECT_AFTER_MESSAGES` is `2^64 − 8130`, ours the whitepaper's
/// `2^64 − 2^13 − 1`. No session gets there.) wireguard-go's window is
/// the same width.
///
/// The width matters on links with a large bandwidth-delay product: a
/// 500 ms RTT satellite link at 100 Mbit/s has some 4400 packets in
/// flight. It is purely local (never on the wire), so it has no interop
/// consequence.
///
/// With the redundant word below, the bitmap is 128 × u64 = 8192 bits =
/// 1024 bytes per session, as the kernel's
/// `unsigned long backtrack[COUNTER_BITS_TOTAL / BITS_PER_LONG]`.
pub const WINDOW_BITS: u64 = 8128;
/// One redundant word beyond the window: when the top slides into a new
/// word, that word is cleared, and without the spare word the clear would
/// erase bits of counters still inside the window (RFC 6479's
/// "bitmap minus one word" rule). The ring of `WORDS` words always holds
/// the word of the greatest counter and the 127 before it, which is every
/// counter down to `greatest − WINDOW_BITS − (greatest mod 64)`: the
/// whole window, whatever the alignment.
const WORDS: usize = (WINDOW_BITS / 64) as usize + 1;
/// `WORDS` as `u64`, so word-index modulo is computed before any
/// `usize` cast (correct on 32-bit targets even at counter ≥ 2³⁸).
const WORDS_U64: u64 = WORDS as u64;

/// Sliding bitmap of received counters.
///
/// In memory in the order written (`repr(C)`): the two small fields, which
/// every packet reads, in front of the bitmap rather than wherever a
/// compiler puts them — which was behind it, a kilobyte away from the
/// rest of what a packet needs.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ReplayWindow {
    /// Highest accepted counter (the window covers
    /// `greatest − WINDOW_BITS ..= greatest`).
    greatest: u64,
    /// `true` once any counter has been accepted (so counter 0 works).
    primed: bool,
    bitmap: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Where the bitmap begins (for the test of the tunnel's layout).
    #[cfg(test)]
    pub(crate) const BITMAP_OFFSET: usize = core::mem::offset_of!(Self, bitmap);

    /// An empty window: everything below `REJECT_AFTER_MESSAGES` is new.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            greatest: 0,
            primed: false,
            bitmap: [0u64; WORDS],
        }
    }

    /// Would `counter` be accepted right now? Read-only; counters at or
    /// above `REJECT_AFTER_MESSAGES`, already-seen counters, and counters
    /// older than the window are rejected.
    #[must_use]
    pub fn check(&self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if !self.primed || counter > self.greatest {
            return true;
        }
        if self.greatest.wrapping_sub(counter) > WINDOW_BITS {
            return false; // too old
        }
        !self.bit(counter)
    }

    /// Record `counter` as received. Must be called only after [`Self::check`]
    /// returned `true` *and* the packet authenticated; returns `false`
    /// (and changes nothing) if the counter would not be accepted, as a
    /// defensive double-check.
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.check(counter) {
            return false;
        }
        if !self.primed {
            self.primed = true;
            self.greatest = counter;
            self.bitmap = [0u64; WORDS];
            self.set_bit(counter);
            return true;
        }
        if counter > self.greatest {
            // Slide forward: clear every word the top moves into. Words
            // are used modulo WORDS, so a jump of WORDS words or more
            // clears them all — and a shorter one must not: the word the
            // old top was in may still hold counters inside the new
            // window (the old top itself, when the jump is exactly
            // WINDOW_BITS).
            let old_word = self.greatest >> 6;
            let new_word = counter >> 6;
            if new_word.wrapping_sub(old_word) >= WORDS_U64 {
                self.bitmap = [0u64; WORDS];
            } else {
                // Exclusive-old / inclusive-new. The modulo is taken in
                // u64 BEFORE the usize cast so 32-bit targets index
                // correctly even at counter ≥ 2^38 (unreachable in
                // practice but cheap to do right).
                let mut w = old_word.wrapping_add(1);
                while w <= new_word {
                    if let Some(slot) = self.bitmap.get_mut((w % WORDS_U64) as usize) {
                        *slot = 0;
                    }
                    w = w.wrapping_add(1);
                }
            }
            self.greatest = counter;
        }
        self.set_bit(counter);
        true
    }

    /// Highest counter accepted so far (0 if none).
    #[must_use]
    pub fn greatest(&self) -> u64 {
        if self.primed { self.greatest } else { 0 }
    }

    fn bit(&self, counter: u64) -> bool {
        let word = ((counter >> 6) % WORDS_U64) as usize;
        let mask = 1u64 << (counter & 63);
        self.bitmap.get(word).is_some_and(|w| w & mask != 0)
    }

    fn set_bit(&mut self, counter: u64) {
        let word = ((counter >> 6) % WORDS_U64) as usize;
        let mask = 1u64 << (counter & 63);
        if let Some(w) = self.bitmap.get_mut(word) {
            *w |= mask;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::int_plus_one // the kernel's own comparison, kept verbatim
    )]
    use super::*;
    use std::collections::HashSet;
    use std::vec::Vec;

    #[test]
    fn fresh_window_accepts_zero_once() {
        let mut w = ReplayWindow::new();
        assert!(w.check(0));
        assert!(w.accept(0));
        assert!(!w.check(0), "duplicate of counter 0 must be rejected");
        assert!(!w.accept(0));
        assert!(w.accept(1));
    }

    #[test]
    fn in_order_and_duplicates() {
        let mut w = ReplayWindow::new();
        for c in 0..1000u64 {
            assert!(w.accept(c), "fresh {c}");
            assert!(!w.accept(c), "dup {c}");
        }
        assert_eq!(w.greatest(), 999);
    }

    #[test]
    fn reordering_within_window() {
        let mut w = ReplayWindow::new();
        let top = WINDOW_BITS * 2; // any value > WINDOW_BITS
        assert!(w.accept(top));
        // Everything within the window, in reverse, never seen: accepted.
        for c in (top - WINDOW_BITS..top).rev() {
            assert!(w.accept(c), "{c}");
        }
        // All now duplicates.
        for c in top - WINDOW_BITS..=top {
            assert!(!w.accept(c), "{c}");
        }
        // One past the window's left edge: too old.
        assert!(!w.accept(top - WINDOW_BITS - 1));
    }

    /// The window's left edge, at every alignment of the greatest counter
    /// within a bitmap word: a counter exactly `WINDOW_BITS` behind is
    /// accepted (once), the one before it is not.
    #[test]
    fn window_edges_exactly() {
        for top in (100_000u64..100_000 + 130).chain([WINDOW_BITS, WINDOW_BITS + 1]) {
            let mut w = ReplayWindow::new();
            assert!(w.accept(top));
            assert!(w.check(top - WINDOW_BITS), "{top}: oldest in-window");
            assert!(w.accept(top - WINDOW_BITS), "{top}");
            assert!(!w.check(top - WINDOW_BITS), "{top}: now a duplicate");
            if let Some(out) = top.checked_sub(WINDOW_BITS + 1) {
                assert!(!w.check(out), "{top}: first out-of-window");
                assert!(!w.accept(out), "{top}");
            }
        }
    }

    /// A jump of exactly the window width keeps the old top in the window
    /// — and it has been seen: it must not come back as new. (The bitmap
    /// may only be cleared wholesale for jumps that leave nothing of the
    /// old window in the new one.)
    #[test]
    fn a_jump_of_exactly_the_window_keeps_the_old_top() {
        for start in [0u64, 1, 63, 64, 65, 5000, 8127, 8128, 8129] {
            for jump in WINDOW_BITS - 70..=WINDOW_BITS + 70 {
                let mut w = ReplayWindow::new();
                assert!(w.accept(start));
                assert!(w.accept(start + jump), "{start}+{jump}");
                assert!(
                    !w.check(start),
                    "start {start}, jump {jump}: the old top was accepted again"
                );
                // A counter next to the old top that was never seen is
                // new if and only if it is in the window.
                let neighbour = start + 1;
                assert_eq!(
                    w.check(neighbour),
                    jump - 1 <= WINDOW_BITS && jump > 1,
                    "start {start}, jump {jump}"
                );
            }
        }
    }

    #[test]
    fn giant_jumps_clear_the_bitmap() {
        let mut w = ReplayWindow::new();
        for c in 0..100u64 {
            assert!(w.accept(c));
        }
        assert!(w.accept(1_000_000));
        // Everything in the new window that wasn't seen is fresh, even
        // where stale bits would have lived without clearing.
        for c in 1_000_000 - 200..1_000_000 {
            assert!(w.accept(c), "{c}");
        }
        // Old counters far below: rejected as too old.
        assert!(!w.accept(50));
    }

    #[test]
    fn reject_after_messages_limit() {
        let mut w = ReplayWindow::new();
        assert!(!w.accept(REJECT_AFTER_MESSAGES));
        assert!(!w.accept(REJECT_AFTER_MESSAGES + 1));
        assert!(!w.accept(u64::MAX));
        assert!(w.accept(REJECT_AFTER_MESSAGES - 1));
        // Greatest is at the cliff edge; older traffic in-window still ok.
        assert!(w.accept(REJECT_AFTER_MESSAGES - 2));
    }

    /// splitmix64.
    fn mix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    #[test]
    fn model_based_random_sequences() {
        // Compare against a trivially-correct model: a set of seen
        // counters plus the window rule.
        let mut state = 0x1234_5678u64;
        for _case in 0..50 {
            let mut w = ReplayWindow::new();
            let mut seen: HashSet<u64> = HashSet::new();
            let mut greatest: Option<u64> = None;
            // Mix of local jitter around a rising base and occasional
            // big jumps.
            let mut base = 0u64;
            let counters: Vec<u64> = (0..600)
                .map(|_| {
                    let r = mix(&mut state);
                    if r % 19 == 0 {
                        base = base.wrapping_add(r % 100_000);
                    } else {
                        base = base.wrapping_add(r % 7);
                    }
                    let jitter = mix(&mut state) % (WINDOW_BITS * 2);
                    base.saturating_sub(jitter)
                })
                .collect();
            for c in counters {
                let model_ok = c < REJECT_AFTER_MESSAGES
                    && !seen.contains(&c)
                    && greatest.is_none_or(|g| c > g || g - c <= WINDOW_BITS);
                assert_eq!(w.check(c), model_ok, "check({c}) greatest={greatest:?}");
                assert_eq!(w.accept(c), model_ok, "accept({c})");
                if model_ok {
                    seen.insert(c);
                    greatest = Some(greatest.map_or(c, |g| g.max(c)));
                }
            }
        }
    }

    /// `counter_validate` from the Linux kernel
    /// (`drivers/net/wireguard/receive.c`), transliterated line by line —
    /// same variables, same arithmetic, `unsigned long` as `u64`. Returns
    /// what the kernel returns: whether the counter is accepted.
    struct KernelCounter {
        counter: u64,
        backtrack: [u64; KERNEL_BITS_TOTAL / 64],
    }
    const KERNEL_BITS_TOTAL: usize = 8192;
    const KERNEL_REDUNDANT_BITS: u64 = 64;
    const KERNEL_WINDOW_SIZE: u64 = KERNEL_BITS_TOTAL as u64 - KERNEL_REDUNDANT_BITS;

    impl KernelCounter {
        fn new() -> Self {
            Self {
                counter: 0,
                backtrack: [0; KERNEL_BITS_TOTAL / 64],
            }
        }

        fn validate(&mut self, mut their_counter: u64) -> bool {
            if self.counter >= REJECT_AFTER_MESSAGES + 1 || their_counter >= REJECT_AFTER_MESSAGES {
                return false;
            }
            their_counter += 1;
            if KERNEL_WINDOW_SIZE + their_counter < self.counter {
                return false;
            }
            let mut index = (their_counter >> 6) as usize;
            if their_counter > self.counter {
                let index_current = (self.counter >> 6) as usize;
                let top = (index - index_current).min(KERNEL_BITS_TOTAL / 64);
                for i in 1..=top {
                    self.backtrack[(i + index_current) & (KERNEL_BITS_TOTAL / 64 - 1)] = 0;
                }
                self.counter = their_counter;
            }
            index &= KERNEL_BITS_TOTAL / 64 - 1;
            let bit = 1u64 << (their_counter & 63);
            let was_set = self.backtrack[index] & bit != 0;
            self.backtrack[index] |= bit;
            !was_set
        }
    }

    /// This window and the kernel's accept exactly the same counters, in
    /// every order: random walks with reordering deeper than the window,
    /// jumps of every size around the window width and around the size of
    /// the whole bitmap, and long runs of duplicates.
    #[test]
    fn accepts_exactly_what_the_kernel_accepts() {
        let mut state = 0x6b65_726e_656c_u64;
        let mut compared = 0u64;
        let mut accepted = 0u64;
        for case in 0..400 {
            let mut ours = ReplayWindow::new();
            let mut kernel = KernelCounter::new();
            // Start anywhere, including right at the top of the range.
            let mut base = match case % 4 {
                0 => 0,
                1 => mix(&mut state) % 20_000,
                2 => mix(&mut state) % (1 << 40),
                _ => REJECT_AFTER_MESSAGES - 1 - mix(&mut state) % 30_000,
            };
            for _ in 0..1500 {
                let r = mix(&mut state);
                base = base.saturating_add(match r % 23 {
                    0 => WINDOW_BITS - 66 + mix(&mut state) % 133, // around the window width
                    1 => 8192 - 66 + mix(&mut state) % 133,        // around the bitmap size
                    2 => mix(&mut state) % 100_000,
                    3..=5 => 0,
                    _ => r % 5,
                });
                let behind = match mix(&mut state) % 7 {
                    0 => WINDOW_BITS - 3 + mix(&mut state) % 7, // the left edge
                    1 => mix(&mut state) % (WINDOW_BITS * 2),
                    2 => 0,
                    _ => mix(&mut state) % 70,
                };
                let c = base.saturating_sub(behind);
                let expected = kernel.validate(c);
                assert_eq!(
                    ours.check(c),
                    expected,
                    "case {case}: check({c}) with greatest {}",
                    ours.greatest()
                );
                assert_eq!(ours.accept(c), expected, "case {case}: accept({c})");
                compared += 1;
                accepted += u64::from(expected);
            }
        }
        // The walk must have exercised both outcomes thoroughly.
        assert!(
            accepted > compared / 4 && accepted < compared * 3 / 4,
            "{accepted} of {compared} accepted"
        );
    }
}
