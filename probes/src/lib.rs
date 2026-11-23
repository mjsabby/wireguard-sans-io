//! Shared pieces of the probes: looking at dead stack memory, looking at
//! the raw bytes of a value, and searching either for known secrets — in
//! the form they are handed over in, and in the forms the arithmetic has
//! them in on the way.
//!
//! Everything here is diagnostic code. It deliberately does what a program
//! must not do — read memory that no live value owns — because that is
//! exactly what an attacker with a memory-disclosure bug does, and the
//! point is to see what such an attacker would find.

use std::collections::HashMap;
use std::hint::black_box;

/// How much stack below the caller is painted before a call…
const PAINT: usize = 384 * 1024;
/// …and how much of it is inspected afterwards.
pub const SNAPSHOT: usize = 256 * 1024;
/// The byte the stack is painted with.
pub const PAINT_BYTE: u8 = 0xA5;

/// Overwrite the stack below the caller with [`PAINT_BYTE`].
#[inline(never)]
pub fn paint() {
    paint_with(PAINT_BYTE);
}

/// Overwrite the stack below the caller with `colour`.
#[inline(always)]
pub fn paint_with(colour: u8) {
    let mut area = [0u8; PAINT];
    for byte in &mut area {
        // SAFETY: a volatile store into a live local.
        unsafe { core::ptr::write_volatile(byte, colour) };
    }
    black_box(&area);
}

/// Copy the [`SNAPSHOT`] bytes of dead stack below the caller into `dst`
/// (which must be `SNAPSHOT` bytes long). `dst[SNAPSHOT - 1]` is the byte
/// just below this function's own frame. Returns the address `dst[0]` was
/// read from.
#[inline(never)]
pub fn snapshot(dst: &mut [u8]) -> usize {
    assert_eq!(dst.len(), SNAPSHOT);
    let marker = 0u8;
    let top = black_box(&raw const marker) as usize;
    let start = top - dst.len();
    for (i, d) in dst.iter_mut().enumerate() {
        // SAFETY (diagnostic only): the pages were touched by `paint`, so
        // they are mapped; nothing owns the bytes, which is the point.
        *d = unsafe { core::ptr::read_volatile((start + i) as *const u8) };
    }
    start
}

/// Run `f` a little way down the stack, so that the frames of whatever it
/// calls lie clear of the few bytes [`snapshot`]'s own frame overwrites.
#[inline(never)]
pub fn call_deep<R>(f: impl FnOnce() -> R) -> R {
    let spacer = [0u8; 512];
    black_box(&spacer);
    let result = f();
    black_box(&spacer);
    result
}

/// Where the frame of the function this is written in ends: its stack
/// pointer. What that function calls has its frames below this address;
/// what is at it or above is the function's own (and its callers').
///
/// Exact where the stack pointer can be read (x86-64, aarch64).
/// Elsewhere: the address of a local in a function called from here,
/// and a little more — which counts the last few bytes of the caller's
/// frame as the callee's.
#[inline(always)]
#[must_use]
pub fn frame_end() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let sp: usize;
        // SAFETY: reads a register; touches neither memory nor the stack.
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        sp
    }
    #[cfg(target_arch = "aarch64")]
    {
        let sp: usize;
        // SAFETY: reads a register; touches neither memory nor the stack.
        unsafe {
            core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        sp
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        wireguard_sans_io::crypto::ct::stack_mark().saturating_add(32)
    }
}

/// How many bytes of a snapshot the call in between overwrote.
#[must_use]
pub fn bytes_touched(snapshot: &[u8]) -> usize {
    snapshot.iter().filter(|b| **b != PAINT_BYTE).count()
}

/// How far below the caller the deepest byte lies that the call wrote.
#[must_use]
pub fn depth(snapshot: &[u8]) -> usize {
    snapshot
        .iter()
        .position(|b| *b != PAINT_BYTE)
        .map_or(0, |i| SNAPSHOT - i)
}

/// Of the stack a call used, how many bytes are neither paint nor zero:
/// what is left of its frames. After a call that overwrites its frames
/// that is the little the overwriting itself leaves (return addresses,
/// saved registers); after one that does not, it is most of what the
/// call computed with.
#[must_use]
pub fn bytes_left(snapshot: &[u8]) -> usize {
    snapshot
        .iter()
        .filter(|b| **b != PAINT_BYTE && **b != 0)
        .count()
}

/// The raw bytes of a value, padding included.
#[must_use]
pub fn bytes_of<T>(value: &T) -> Vec<u8> {
    let ptr = (value as *const T).cast::<u8>();
    (0..size_of::<T>())
        // SAFETY (diagnostic only): reads the object representation of a
        // live value through a byte pointer.
        .map(|i| unsafe { core::ptr::read_volatile(ptr.add(i)) })
        .collect()
}

/// An entropy source for the probes: deterministic, and one that keeps
/// a record of everything it hands out — which is how a probe knows the
/// ephemeral keys and cookie secrets it is to look for.
///
/// It writes each byte straight into the caller's buffer and nowhere
/// else (the record is on the heap), the way an operating system's
/// source does: a generator that left its output in a stack frame of its
/// own would be found by the probes, and blamed on the library.
pub struct Recorded {
    state: u64,
    /// Every request, in order.
    pub log: Vec<Vec<u8>>,
}

impl Recorded {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9e37_79b9_7f4a_7c15,
            log: Vec::new(),
        }
    }
}

impl wireguard_sans_io::EntropySource for Recorded {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), wireguard_sans_io::EntropyError> {
        for byte in buf.iter_mut() {
            // SplitMix64, one output byte per step.
            self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *byte = ((z ^ (z >> 31)) >> 24) as u8;
        }
        self.log.push(buf.to_vec());
        Ok(())
    }
}

/// What a needle is, which decides how it is looked for and what finding
/// it means.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    /// The secret as it is handed over: a byte string. Looked for whole,
    /// and in part — [`PIECE`] bytes of it in a row, wherever in it they
    /// are: what is left of a copy that something else has since written
    /// over the rest of.
    Bytes,
    /// A form the arithmetic has it in: machine words (the limbs of a
    /// field element, the halves of a key). Looked for whole, and word by
    /// word — a compiler keeps the words of such a value wherever it
    /// likes, not necessarily side by side.
    Words,
}

/// A named byte string to look for.
#[derive(Clone)]
pub struct Needle {
    pub name: String,
    pub bytes: Vec<u8>,
    pub form: Form,
    /// For [`Form::Words`]: how many bytes a word has (8 or 4).
    pub word: usize,
}

/// Where a needle was found: at these offsets (whole); this many of
/// its words (scattered) — of so many that say something — the first of
/// each at these offsets; or this many of its bytes (part), of so many,
/// in their places relative to one another, the first piece of them at
/// this offset.
pub enum Found {
    Whole(Vec<usize>),
    Scattered(usize, usize, Vec<usize>),
    Part(usize, usize, usize),
}

/// The least of a byte string that is some of it: this many bytes in a
/// row. (Eight bytes of a key in the right order are not there by
/// chance, and they are an eighth of the work of guessing it gone — or,
/// of a key with structure, more.)
pub const PIECE: usize = 8;

/// Does a piece say something: not mostly zeros, not one byte repeated
/// (which is what padding, paint and counters look like).
fn telling(piece: &[u8]) -> bool {
    piece.iter().filter(|b| **b != 0).count() >= 5 && piece.iter().any(|b| *b != piece[0])
}

/// A list of secrets to look for.
#[derive(Default, Clone)]
pub struct Needles(pub Vec<Needle>);

impl Needles {
    pub fn add(&mut self, name: &str, bytes: &[u8]) {
        self.push(name, bytes, Form::Bytes, 8);
    }

    /// A value as 64-bit words, little-endian, in the order given.
    pub fn add_words(&mut self, name: &str, words: &[u64]) {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.push(name, &bytes, Form::Words, 8);
    }

    /// A value as 32-bit words (the state of a cipher or a hash that
    /// computes with such), given as the bytes they are in memory.
    pub fn add_words32(&mut self, name: &str, bytes: &[u8]) {
        assert_eq!(bytes.len() % 4, 0);
        self.push(name, bytes, Form::Words, 4);
    }

    fn push(&mut self, name: &str, bytes: &[u8], form: Form, word: usize) {
        if !self
            .0
            .iter()
            .any(|n| n.bytes == bytes && n.form == form && n.word == word)
        {
            self.0.push(Needle {
                name: name.to_string(),
                bytes: bytes.to_vec(),
                form,
                word,
            });
        }
    }

    /// For each byte-string needle some of which is in `hay`: how many of
    /// its bytes are there, in their places relative to one another, at
    /// the best of the places a piece of it was found, and where that
    /// piece is.
    ///
    /// One pass over `hay` for all needles together: every [`PIECE`]
    /// bytes in a row of every needle are looked up in a table.
    fn parts_in(&self, hay: &[u8]) -> HashMap<usize, (usize, usize)> {
        let mut pieces: HashMap<u64, Vec<(usize, usize)>> = HashMap::new();
        for (n, needle) in self.0.iter().enumerate() {
            if needle.form != Form::Bytes {
                continue;
            }
            for (offset, piece) in needle.bytes.windows(PIECE).enumerate() {
                if telling(piece) {
                    pieces
                        .entry(u64::from_le_bytes(piece.try_into().unwrap()))
                        .or_default()
                        .push((n, offset));
                }
            }
        }
        let mut best: HashMap<usize, (usize, usize)> = HashMap::new();
        if pieces.is_empty() {
            return best;
        }
        for (i, window) in hay.windows(PIECE).enumerate() {
            let word = u64::from_le_bytes(window.try_into().unwrap());
            // Most of a snapshot is paint or zeros: one byte repeated.
            if word == u64::from(window[0]).wrapping_mul(0x0101_0101_0101_0101) {
                continue;
            }
            let Some(hits) = pieces.get(&word) else {
                continue;
            };
            for &(n, offset) in hits {
                // With this piece where it is, the needle's byte `k`
                // would be at `i + k - offset`: how many are?
                let present = self.0[n]
                    .bytes
                    .iter()
                    .enumerate()
                    .filter(|(k, byte)| {
                        (i + k).checked_sub(offset).and_then(|at| hay.get(at)) == Some(*byte)
                    })
                    .count();
                let entry = best.entry(n).or_insert((0, i));
                if present > entry.0 {
                    *entry = (present, i);
                }
            }
        }
        best
    }

    /// Every needle that occurs in `hay`, and how.
    #[must_use]
    pub fn found_in(&self, hay: &[u8]) -> Vec<(&Needle, Found)> {
        let parts = self.parts_in(hay);
        self.0
            .iter()
            .enumerate()
            .filter_map(|(n, needle)| {
                let at: Vec<usize> = hay
                    .windows(needle.bytes.len())
                    .enumerate()
                    .filter(|(_, w)| *w == needle.bytes.as_slice())
                    .map(|(i, _)| i)
                    .collect();
                if !at.is_empty() {
                    return Some((needle, Found::Whole(at)));
                }
                if needle.form == Form::Words {
                    // Words that say something: not zero, not a small
                    // number (which could be anything).
                    let telling = if needle.word == 8 { 5 } else { 4 };
                    let words: Vec<&[u8]> = needle
                        .bytes
                        .chunks(needle.word)
                        .filter(|w| w.iter().filter(|b| **b != 0).count() >= telling)
                        .collect();
                    let at: Vec<usize> = words
                        .iter()
                        .filter_map(|word| hay.windows(needle.word).position(|w| w == *word))
                        .collect();
                    // One 64-bit word that says something is not there
                    // by chance; of 32-bit words it takes two.
                    let enough = if needle.word == 8 { 1 } else { 2 };
                    if at.len() >= enough {
                        return Some((needle, Found::Scattered(at.len(), words.len(), at)));
                    }
                }
                if let Some(&(present, at)) = parts.get(&n) {
                    return Some((needle, Found::Part(present, needle.bytes.len(), at)));
                }
                None
            })
            .collect()
    }
}

/// The snapshot, what to look for in it, and the count.
pub struct Scan {
    pub snap: Vec<u8>,
    /// The address the first byte of the snapshot was read from.
    pub start: usize,
    pub needles: Needles,
    pub findings: usize,
    /// Word forms, and parts of byte strings, found in an unoptimised
    /// build: reported, not counted.
    pub not_counted: usize,
    pub unoptimised: bool,
}

impl Scan {
    /// A scan with nothing to look for yet. In an unoptimised build —
    /// `WG_PROBE_UNOPTIMISED` is set — word forms, and parts of byte
    /// strings, are reported and not counted.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snap: vec![0u8; SNAPSHOT],
            start: 0,
            needles: Needles::default(),
            findings: 0,
            not_counted: 0,
            unoptimised: std::env::var_os("WG_PROBE_UNOPTIMISED").is_some(),
        }
    }

    /// Take the snapshot. Call right after the call under test returned,
    /// before anything else touches the stack.
    pub fn take(&mut self) {
        self.start = snapshot(&mut self.snap);
    }

    /// Search the whole snapshot for every secret known so far.
    pub fn report(&mut self, after: &str) {
        self.report_below(after, usize::MAX);
    }

    /// Search the snapshot; what lies at `caller` ([`frame_end`], taken
    /// in the function that makes the call) or above belongs to the frame
    /// the call was made from, and is the caller's.
    pub fn report_below(&mut self, after: &str, caller: usize) {
        let touched = bytes_touched(&self.snap);
        assert!(touched > 0, "the call did not use the painted region");
        let boundary = caller.saturating_sub(self.start).min(self.snap.len());
        let (library, callers) = self.snap.split_at(boundary);
        let found = self.needles.found_in(library);
        let in_caller = self.needles.found_in(callers);
        // In an unoptimised build a word form is reported and not
        // counted, and so is a part of a byte string — there a word
        // loaded from one is eight bytes of it in a stack slot.
        let counts = |needle: &Needle, how: &Found| {
            !(self.unoptimised && (needle.form == Form::Words || matches!(how, Found::Part(..))))
        };
        let counted: Vec<_> = found
            .iter()
            .filter(|(needle, how)| counts(needle, how))
            .collect();
        println!(
            "after {after}: {} bytes of stack used ({} not zero), {} of {} tracked secrets found",
            depth(&self.snap),
            bytes_left(&self.snap),
            counted.len(),
            self.needles.0.len()
        );
        for (needle, how) in &found {
            let counts = counts(needle, how);
            let label = if counts {
                "LEFT ON THE STACK"
            } else if needle.form == Form::Words {
                "left on the stack (word form, unoptimised build: not counted)"
            } else {
                "left on the stack (a part, unoptimised build: not counted)"
            };
            match how {
                Found::Whole(at) => {
                    let depths: Vec<usize> = at.iter().map(|i| SNAPSHOT - i).collect();
                    println!(
                        "    {label}: {} ({} cop{}, {:?} bytes below the caller)",
                        needle.name,
                        at.len(),
                        if at.len() == 1 { "y" } else { "ies" },
                        &depths[..depths.len().min(4)]
                    );
                }
                Found::Scattered(present, of, at) => {
                    let depths: Vec<usize> = at.iter().map(|i| SNAPSHOT - i).collect();
                    println!(
                        "    {label}: {} ({present} of its {of} words, apart, {:?} bytes below the caller)",
                        needle.name,
                        &depths[..depths.len().min(8)]
                    );
                }
                Found::Part(present, of, at) => {
                    println!(
                        "    {label}: {} ({present} of its {of} bytes, {} bytes below the caller)",
                        needle.name,
                        SNAPSHOT - at
                    );
                }
            }
            if !counts {
                self.not_counted += 1;
            }
        }
        if !in_caller.is_empty() {
            let names: Vec<&str> = in_caller.iter().map(|(n, _)| n.name.as_str()).collect();
            println!(
                "    in the caller's own frame (what it passed or was returned by value; the caller's, not counted): {}",
                names.join("; ")
            );
        }
        self.findings += counted.len();
    }
}

impl Scan {
    /// After a call that overwrites its frames when it is done — the
    /// curve arithmetic — and whatever the search for particular values
    /// said: of the stack the call used, no more than a quarter may be
    /// anything but zero. (With the frames overwritten it is about a
    /// tenth, the overwriting's own return addresses and saved registers;
    /// without, most of it. This needs no knowledge of what the call
    /// computes on the way, which the search does.) Not in an unoptimised
    /// build, whose frames go deeper than the overwriting reaches.
    pub fn expect_overwritten(&mut self, after: &str) {
        if self.unoptimised {
            return;
        }
        let (left, used) = (bytes_left(&self.snap), depth(&self.snap));
        if left.saturating_mul(4) > used {
            println!(
                "    LEFT ON THE STACK: what {after} computed with ({left} of the {used} bytes it used are not zero: its frames were not overwritten)"
            );
            self.findings += 1;
        }
    }

    /// Is any of `words` in the snapshot — 32-bit words, each a value
    /// that exists nowhere but inside the rounds of a hash (`what`)?
    /// They are only ever in registers and in what a compiler parks of
    /// them on the stack, so one word found is a find: counted, except in
    /// an unoptimised build, where the rounds are functions of their own
    /// with frames deeper than the library overwrites.
    pub fn expect_none_of(&mut self, what: &str, words: &[u32]) {
        let found = self.words_found(words);
        if found == 0 {
            return;
        }
        if self.unoptimised {
            println!(
                "    left on the stack (word form, unoptimised build: not counted): {found} of the {} words {what} passes through inside its rounds",
                words.len()
            );
            self.not_counted += 1;
        } else {
            println!(
                "    LEFT ON THE STACK: {found} of the {} words {what} passes through inside its rounds",
                words.len()
            );
            self.findings += 1;
        }
    }

    /// How many of `words` are in the snapshot. (A word that says
    /// little, with a zero byte in it, is left out.)
    #[must_use]
    pub fn words_found(&self, words: &[u32]) -> usize {
        let mut telling: Vec<[u8; 4]> = words
            .iter()
            .map(|w| w.to_le_bytes())
            .filter(|w| w.iter().all(|b| *b != 0))
            .collect();
        telling.sort_unstable();
        telling.dedup();
        telling
            .iter()
            .filter(|word| self.snap.windows(4).any(|w| w == word.as_slice()))
            .count()
    }

    /// Search the memory of a value that is still alive — `bytes`, as
    /// [`bytes_of`] reads them — for every secret known so far: what a
    /// hasher or an authenticator that has finished still holds.
    pub fn report_value(&mut self, what: &str, bytes: &[u8]) {
        let found = self.needles.found_in(bytes);
        println!(
            "in {what}: {} of {} tracked secrets found",
            found.len(),
            self.needles.0.len()
        );
        for (needle, _) in &found {
            println!("    LEFT IN IT: {}", needle.name);
        }
        self.findings += found.len();
    }

    /// [`Scan::report_below`] for a convenience function that returns a
    /// possibly secret result by value and makes no claim about its own
    /// frame short of full optimisation: there the result is written
    /// straight to where the caller receives it; in a build with less
    /// optimisation it is first a local of the function, and stays in its
    /// dead frame. (Each has a form that writes the result in place, and
    /// that one is checked in every build.) In such a build — the probes'
    /// dev profile — what is found is shown and not counted.
    pub fn report_convenience(&mut self, after: &str, caller: usize) {
        if cfg!(debug_assertions) {
            let before = self.findings;
            self.report_below(after, caller);
            let shown = self.findings - before;
            self.findings = before;
            if shown > 0 {
                println!(
                    "    ({shown} of these in the function's own frame: a by-value convenience in a build without full optimisation — not counted)"
                );
            }
        } else {
            self.report_below(after, caller);
        }
    }
}

impl Default for Scan {
    fn default() -> Self {
        Self::new()
    }
}

/// Curve25519 arithmetic and the BLAKE2s compression function written
/// for this probe alone: plain, variable time, nothing shared with the
/// library. They exist to say what the library has in its hands on the
/// way — the ladder's projective result, its inverse, the products of the
/// last steps; a hash's state between two blocks — so that the stack can
/// be searched for *those*, not only for the bytes that come out.
pub mod reference {
    /// A field element as the library keeps one: five 51-bit limbs.
    pub type Fe = [u64; 5];
    const MASK: u64 = (1 << 51) - 1;

    fn canonical(mut l: [u128; 5]) -> Fe {
        for _ in 0..3 {
            let mut carry: u128 = 0;
            for limb in &mut l {
                *limb += carry;
                carry = *limb >> 51;
                *limb &= u128::from(MASK);
            }
            l[0] += carry * 19;
        }
        let r: Fe = l.map(|limb| limb as u64);
        let [r0, r1, r2, r3, r4] = r;
        if r4 == MASK && r3 == MASK && r2 == MASK && r1 == MASK && r0 >= MASK - 18 {
            return [r0 - (MASK - 18), 0, 0, 0, 0];
        }
        r
    }

    /// The field element a 32-byte string encodes (top bit ignored).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let w: Vec<u64> = bytes
            .chunks(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        canonical([
            u128::from(w[0] & MASK),
            u128::from(((w[0] >> 51) | (w[1] << 13)) & MASK),
            u128::from(((w[1] >> 38) | (w[2] << 26)) & MASK),
            u128::from(((w[2] >> 25) | (w[3] << 39)) & MASK),
            u128::from((w[3] >> 12) & MASK),
        ])
    }

    #[must_use]
    pub fn mul(a: Fe, b: Fe) -> Fe {
        let mut t = [0u128; 5];
        for i in 0..5 {
            for j in 0..5 {
                let p = u128::from(a[i]) * u128::from(b[j]);
                if i + j < 5 {
                    t[i + j] += p;
                } else {
                    t[i + j - 5] += p * 19;
                }
            }
        }
        canonical(t)
    }

    fn add(a: Fe, b: Fe) -> Fe {
        canonical(core::array::from_fn(|i| {
            u128::from(a[i]) + u128::from(b[i])
        }))
    }

    fn sub(a: Fe, b: Fe) -> Fe {
        let two_p = [2 * (MASK - 18), 2 * MASK, 2 * MASK, 2 * MASK, 2 * MASK];
        canonical(core::array::from_fn(|i| {
            u128::from(a[i]) + u128::from(two_p[i]) - u128::from(b[i])
        }))
    }

    /// `a⁻¹` (`a^(p−2)`).
    #[must_use]
    pub fn invert(a: Fe) -> Fe {
        let mut exponent = [0xffu8; 32];
        exponent[0] = 0xeb;
        exponent[31] = 0x7f;
        let mut r: Fe = [1, 0, 0, 0, 0];
        for bit in (0..255).rev() {
            r = mul(r, r);
            if (exponent[bit / 8] >> (bit % 8)) & 1 == 1 {
                r = mul(r, a);
            }
        }
        r
    }

    /// The Montgomery ladder for scalar `k` (clamped here) and point `u`:
    /// the projective result `(X2, Z2)`, and the named products of the
    /// last `keep` steps.
    #[must_use]
    pub fn ladder(k: &[u8; 32], u: &[u8; 32], keep: usize) -> (Fe, Fe, Vec<(String, Fe)>) {
        let mut k = *k;
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        let mut u = *u;
        u[31] &= 0x7f;
        let x1 = from_bytes(&u);
        let one: Fe = [1, 0, 0, 0, 0];
        let (mut x2, mut z2, mut x3, mut z3) = (one, [0; 5], x1, one);
        let mut swap = 0u8;
        let mut products = Vec::new();
        for t in (0..255).rev() {
            let bit = (k[t >> 3] >> (t & 7)) & 1;
            swap ^= bit;
            if swap == 1 {
                core::mem::swap(&mut x2, &mut x3);
                core::mem::swap(&mut z2, &mut z3);
            }
            swap = bit;
            let a = add(x2, z2);
            let aa = mul(a, a);
            let b = sub(x2, z2);
            let bb = mul(b, b);
            let e = sub(aa, bb);
            let c = add(x3, z3);
            let d = sub(x3, z3);
            let da = mul(d, a);
            let cb = mul(c, b);
            let sum = add(da, cb);
            x3 = mul(sum, sum);
            let difference = sub(da, cb);
            let squared = mul(difference, difference);
            z3 = mul(x1, squared);
            x2 = mul(aa, bb);
            let e121665 = mul(e, [121_665, 0, 0, 0, 0]);
            z2 = mul(e, add(aa, e121665));
            if t < keep {
                // Products: what comes out of a multiplication is (nearly)
                // canonical in the library too, sums and differences are
                // not.
                for (name, value) in [
                    ("AA", aa),
                    ("BB", bb),
                    ("DA", da),
                    ("CB", cb),
                    ("X3", x3),
                    ("Z3", z3),
                    ("X2", x2),
                    ("Z2", z2),
                    ("(DA−CB)²", squared),
                ] {
                    products.push((format!("{name} of ladder step {t}"), value));
                }
            }
        }
        if swap == 1 {
            core::mem::swap(&mut x2, &mut x3);
            core::mem::swap(&mut z2, &mut z3);
        }
        (x2, z2, products)
    }

    /// The scalar as the ladder uses it.
    #[must_use]
    pub fn clamp(k: &[u8; 32]) -> [u8; 32] {
        let mut k = *k;
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        k
    }

    const BLAKE2S_IV: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const BLAKE2S_SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    /// The state a BLAKE2s computation starts from (RFC 7693 §3.3):
    /// `out_len` bytes of output, a key of `key_len` bytes.
    #[must_use]
    pub fn blake2s_start(out_len: u32, key_len: u32) -> [u32; 8] {
        let mut h = BLAKE2S_IV;
        h[0] ^= 0x0101_0000 ^ (key_len << 8) ^ out_len;
        h
    }

    /// One step of BLAKE2s (RFC 7693 §3.2), written for this probe alone:
    /// `block` is compressed into `h`, `t` bytes in so far. Returns the
    /// working vector as it stood when the step was done — what a hash
    /// has in its hands between two blocks is what the stack is searched
    /// for, not only what comes out.
    pub fn blake2s_compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool) -> [u32; 16] {
        blake2s_trace(h, block, t, last, &mut Vec::new())
    }

    /// [`blake2s_compress`], which also appends to `inside` every word
    /// the working vector takes on the way: the four words each of the
    /// eighty mixing steps leaves. A compiler that runs out of registers
    /// parks some of these, at some point of the rounds, on the stack.
    pub fn blake2s_trace(
        h: &mut [u32; 8],
        block: &[u8; 64],
        t: u64,
        last: bool,
        inside: &mut Vec<u32>,
    ) -> [u32; 16] {
        let m: Vec<u32> = block
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(h);
        v[8..].copy_from_slice(&BLAKE2S_IV);
        v[12] ^= t as u32;
        v[13] ^= (t >> 32) as u32;
        if last {
            v[14] = !v[14];
        }
        for s in &BLAKE2S_SIGMA {
            let mut g = |a: usize, b: usize, c: usize, d: usize, x: u32, y: u32| {
                v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
                v[d] = (v[d] ^ v[a]).rotate_right(16);
                v[c] = v[c].wrapping_add(v[d]);
                v[b] = (v[b] ^ v[c]).rotate_right(12);
                inside.extend([v[a], v[b], v[c], v[d]]);
                v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
                v[d] = (v[d] ^ v[a]).rotate_right(8);
                v[c] = v[c].wrapping_add(v[d]);
                v[b] = (v[b] ^ v[c]).rotate_right(7);
                inside.extend([v[a], v[b], v[c], v[d]]);
            };
            g(0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            h[i] ^= v[i] ^ v[i + 8];
        }
        v
    }

    /// 32-bit words as the bytes they are in memory.
    #[must_use]
    pub fn words_le(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
}
