//! Constant-time comparison and best-effort wiping of secrets.

/// Constant-time equality of two byte strings whose *lengths are public*.
///
/// Returns `false` immediately on length mismatch (the length of every
/// comparison in this crate is fixed by the protocol, so this branch never
/// depends on a secret). Otherwise the comparison touches every byte
/// exactly once with no data-dependent branches.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Optimization barrier: deny the compiler the knowledge it would need
    // to turn the fold into an early-exit comparison.
    core::hint::black_box(diff) == 0
}

/// Constant-time check that a byte string is all zero.
///
/// Used to reject low-order Diffie-Hellman results without leaking, via
/// timing, which prefix of the result was non-zero.
#[must_use]
pub fn ct_is_zero(a: &[u8]) -> bool {
    let mut acc = 0u8;
    for x in a {
        acc |= x;
    }
    core::hint::black_box(acc) == 0
}

/// Best-effort wipe of secret material.
///
/// Safe Rust offers no guaranteed-volatile write, so this zeroes the bytes
/// and then routes the reference through [`core::hint::black_box`], forcing
/// the compiler to assume the zeroed memory is observed (and therefore not
/// elide the stores). This is a hardening measure, not a guarantee: copies
/// the compiler already spilled elsewhere (moved values, registers) are out
/// of reach — as they are for every zeroization strategy.
pub fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(bytes);
}

/// [`wipe`] for fixed-size arrays.
pub fn wipe_array<const N: usize>(bytes: &mut [u8; N]) {
    wipe(bytes.as_mut_slice());
}

/// Copy a secret from one place straight to another, byte by byte.
///
/// An array assignment (`*dst = *src`) says the same thing, but leaves it
/// to the compiler how: an unoptimised build goes through a temporary on
/// the stack — one more copy of the secret, which nothing wipes. This
/// never has one, at any optimisation level.
pub fn copy_secret<const N: usize>(dst: &mut [u8; N], src: &[u8; N]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
}

/// Exchange two secrets where they lie, byte by byte: like
/// [`copy_secret`], without a temporary that would hold either of them.
pub fn swap_secret<const N: usize>(a: &mut [u8; N], b: &mut [u8; N]) {
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        core::mem::swap(x, y);
    }
}

/// [`wipe`] for arrays of words: cipher and hash state, field elements.
pub fn wipe_words<T: Copy + Default, const N: usize>(words: &mut [T; N]) {
    for w in words.iter_mut() {
        *w = T::default();
    }
    core::hint::black_box(words);
}

/// Where the stack ends right now: an address just below the frame of
/// the function that calls this.
///
/// The address of a local variable of this function, which is never
/// inlined: its frame lies directly beneath its caller's. Nothing is read
/// or written through the address; it is only a number, to be handed to
/// [`scrub_stack_to`] later.
#[inline(never)]
#[must_use]
pub fn stack_mark() -> usize {
    let here = 0u8;
    core::hint::black_box(&raw const here) as usize
}

/// The size of one step of [`scrub_stack_to`] — and so the most it
/// overwrites beyond what it was asked to.
const SCRUB_STEP: usize = 128;

/// The most [`scrub_stack_to`] will ever overwrite: a bound for the cases
/// in which addresses do not mean what it takes them to mean (an
/// interpreter such as Miri, where locals are not on one stack). Several
/// times what the deepest computation in this crate uses in an optimised
/// build, and more than it uses in an unoptimised one.
const SCRUB_LIMIT: usize = 32 * 1024;

/// Zero the stack below the caller's frame, down to the address `low`
/// (a [`stack_mark`] taken deeper down, or such an address less a margin).
///
/// Wiping a secret where it is declared reaches the declared variable. It
/// does not reach what a compiler makes of it on the way: values passed
/// and returned by value, the temporaries of an arithmetic expression,
/// registers spilled around a call. Those lie in the frames of the
/// functions that computed with the secret, and are still there, dead,
/// after they return — in whatever form the computation had them. This
/// overwrites those frames. It needs to know how far down they went, and
/// that is what `low` says: the computation takes a [`stack_mark`] in its
/// deepest function that is not inlined into another, and returns it.
///
/// What this is and is not. It is best effort, like [`wipe`] and for the
/// same reason. It reaches the stack, not registers. It assumes a stack
/// that grows towards lower addresses, as on every target Rust has; on
/// one that did not it would do nothing (and nothing wrong). It uses as
/// much stack as it overwrites — which the computation it cleans up after
/// used a moment ago — plus a step and a half.
///
/// How. A chain of calls, each with a frame of 128 bytes of zeros,
/// until one lies beneath `low` — twice. A frame is its zeros and what
/// the compiler puts around them: a return address and saved registers,
/// which overwrite what was there, and padding that keeps the stack
/// aligned, which does not. One chain therefore leaves a few bytes in
/// every step as they were (eight in a hundred and sixty, on x86-64). The
/// second chain starts half a step further down, so that its zeros lie
/// where the first left its gaps, and its gaps where the first has
/// already been. (`probes/` checks that no byte in between survives.)
///
/// Always inlined, so that both chains start directly beneath the
/// function that asks: a frame of this function's own in between would
/// be one more that nothing overwrites.
#[inline(always)]
pub fn scrub_stack_to(low: usize) {
    scrub_step(low, SCRUB_LIMIT / SCRUB_STEP);
    scrub_half_a_step_down(low);
}

/// [`scrub_stack_to`] for one small function that has just returned, at
/// a fraction of the cost: a single frame of `WORDS` 64-bit words of
/// zeros, which lies where that function's frame lay — both are called
/// from the same place. `low` is the [`stack_mark`] the function took:
/// if its frame went deeper than `WORDS` words reach after all (another
/// compiler, a build without optimisation), [`scrub_stack_to`] does the
/// rest.
///
/// This is for the per-packet paths, where a chain of steps would be
/// felt: the cipher's block function keeps sixteen words in play, and a
/// machine with fewer registers than that parks some in its frame.
#[inline(never)]
pub(crate) fn scrub_frame<const WORDS: usize>(low: usize) {
    let frame = [0u64; WORDS];
    let lowest = core::ptr::from_ref(core::hint::black_box(&frame)) as usize;
    if low < lowest {
        #[cfg(test)]
        tests::DEEP_FRAMES.with(|n| n.set(n.get().wrapping_add(1)));
        scrub_stack_to(low);
    }
}

/// The second chain of [`scrub_stack_to`]: the same steps, beneath a
/// frame of half a step.
#[inline(never)]
fn scrub_half_a_step_down(low: usize) {
    let mut pad = [0u8; SCRUB_STEP / 2];
    core::hint::black_box(&mut pad);
    scrub_step(low, SCRUB_LIMIT / SCRUB_STEP);
    // After the call, as in `scrub_step`.
    core::hint::black_box(&mut pad);
}

/// Calls [`scrub_stack_to`] when it goes out of scope.
///
/// For a function that hands a secret-bearing value back *by value*. Such
/// a function cannot clean up after itself in the ordinary way — "call
/// the function that makes the value, overwrite its frame, return the
/// value" keeps the value in a local of its own in between, which is one
/// more copy and in a frame nobody overwrites. With this as a local, the
/// call that makes the value can be the function's last expression: its
/// result then goes straight to where the caller receives it, and the
/// overwriting happens after that, as the locals are dropped.
///
/// ```
/// # use wireguard_sans_io::crypto::ct::{ScrubOnDrop, stack_mark};
/// fn secret() -> [u8; 32] {
///     let mut scrub = ScrubOnDrop::new();
///     make(scrub.low())
/// }
///
/// #[inline(never)]
/// fn make(low: &mut usize) -> [u8; 32] {
///     *low = stack_mark(); // this frame, and whatever is called from it
///     [7; 32]
/// }
/// # assert_eq!(secret(), [7; 32]);
/// ```
#[derive(Debug)]
pub struct ScrubOnDrop {
    low: usize,
}

impl ScrubOnDrop {
    /// A guard that overwrites nothing until [`low`](Self::low) has been
    /// given a mark.
    #[must_use]
    pub const fn new() -> Self {
        Self { low: usize::MAX }
    }

    /// Where to put the [`stack_mark`] of the deepest frame to overwrite.
    pub fn low(&mut self) -> &mut usize {
        &mut self.low
    }
}

impl Default for ScrubOnDrop {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ScrubOnDrop {
    // Always inlined, like `scrub_stack_to`: no frame in between.
    #[inline(always)]
    fn drop(&mut self) {
        scrub_stack_to(self.low);
    }
}

/// One step: a frame of zeros where a frame of the computation was, and
/// another one beneath it until `low` is reached.
#[inline(never)]
fn scrub_step(low: usize, steps_left: usize) {
    let mut pad = [0u8; SCRUB_STEP];
    let here = core::hint::black_box(pad.as_mut_ptr()) as usize;
    if here > low {
        if let Some(steps_left) = steps_left.checked_sub(1) {
            scrub_step(low, steps_left);
        }
    }
    // After the call, so that the call is not the last thing this function
    // does (which would let every step reuse the same frame).
    core::hint::black_box(&mut pad);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    std::thread_local! {
        /// How often [`scrub_frame`] met a frame deeper than the one it
        /// overwrites at once, and had [`scrub_stack_to`] do the rest —
        /// on this thread, so that each test counts its own.
        pub(crate) static DEEP_FRAMES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    /// A frame that the fast scrub does not reach is scrubbed the slow
    /// way, and one that it does reach is not.
    #[test]
    fn a_frame_deeper_than_the_fast_scrub_gets_the_slow_one() {
        let before = DEEP_FRAMES.with(core::cell::Cell::get);
        let deep = descend(8);
        scrub_frame::<1>(deep);
        assert_eq!(DEEP_FRAMES.with(core::cell::Cell::get), before + 1);
        // Nothing went deeper than this function's own callees: the
        // frame of zeros is all there is to do.
        scrub_frame::<64>(usize::MAX);
        assert_eq!(DEEP_FRAMES.with(core::cell::Cell::get), before + 1);
    }

    /// A function with a frame of its own, `depth` levels deep, that
    /// reports where its deepest frame was.
    #[inline(never)]
    fn descend(depth: u32) -> usize {
        let mut frame = [0x5au8; 200];
        core::hint::black_box(&mut frame);
        let low = match depth.checked_sub(1) {
            None => stack_mark(),
            Some(less) => descend(less),
        };
        core::hint::black_box(&mut frame);
        low
    }

    #[test]
    fn a_mark_lies_below_its_caller_and_scrubbing_to_it_returns() {
        let here = stack_mark();
        let deep = descend(20);
        // Twenty frames of at least 200 bytes further down.
        assert!(deep < here, "the stack grows downwards on this target");
        assert!(here - deep >= 20 * 200, "{}", here - deep);
        // Scrubbing is invisible from inside the language; what can be
        // checked here is that it ends: for a mark below, for one that is
        // not below at all, and for one that is out of all proportion.
        scrub_stack_to(deep);
        scrub_stack_to(usize::MAX);
        scrub_stack_to(here.saturating_sub(4 * SCRUB_LIMIT));
        scrub_stack_to(0);
    }

    #[test]
    fn swap_exchanges() {
        let mut a = [1u8, 2, 3, 4];
        let mut b = [9u8, 8, 7, 6];
        swap_secret(&mut a, &mut b);
        assert_eq!((a, b), ([9, 8, 7, 6], [1, 2, 3, 4]));
    }

    #[test]
    fn eq_basic() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"x"));
    }

    #[test]
    fn eq_detects_single_bit_differences_at_every_position() {
        let a = [0x5au8; 64];
        for byte in 0..64 {
            for bit in 0..8 {
                let mut b = a;
                if let Some(v) = b.get_mut(byte) {
                    *v ^= 1u8 << bit;
                }
                assert!(!ct_eq(&a, &b), "flip at byte {byte} bit {bit} missed");
            }
        }
    }

    #[test]
    fn is_zero() {
        assert!(ct_is_zero(b""));
        assert!(ct_is_zero(&[0u8; 32]));
        let mut x = [0u8; 32];
        for i in 0..32 {
            x.fill(0);
            if let Some(v) = x.get_mut(i) {
                *v = 1;
            }
            assert!(!ct_is_zero(&x), "non-zero byte at {i} missed");
        }
    }

    #[test]
    fn wipe_zeroes() {
        let mut secret = [0xffu8; 48];
        wipe(&mut secret);
        assert_eq!(secret, [0u8; 48]);
        let mut arr = *b"0123456789abcdef0123456789abcdef";
        wipe_array(&mut arr);
        assert!(ct_is_zero(&arr));
        let mut copy = [0u8; 32];
        copy_secret(&mut copy, b"0123456789abcdef0123456789abcdef");
        assert_eq!(&copy, b"0123456789abcdef0123456789abcdef");
        let mut words = [0xdead_beefu32; 16];
        wipe_words(&mut words);
        assert_eq!(words, [0u32; 16]);
        let mut limbs = [u64::MAX; 5];
        wipe_words(&mut limbs);
        assert_eq!(limbs, [0u64; 5]);
    }
}
