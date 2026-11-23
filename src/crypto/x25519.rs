//! X25519 Diffie-Hellman (RFC 7748) — whitepaper `DH()`.
//!
//! Field arithmetic over GF(2^255 − 19) in radix 2^51: five `u64` limbs,
//! products accumulated in `u128`. Two ladders, each of a fixed number of
//! steps with arithmetic conditional swaps: the Montgomery ladder of
//! RFC 7748 for any point, and a fixed-base ladder for the base point —
//! key generation — which reads a table of constants in the order of its
//! loop counter (cargo feature `x25519-table`, on by default; without it
//! the base point takes the first ladder). There are no secret-dependent
//! branches or memory indices anywhere.
//!
//! # Limb bound discipline
//!
//! Every operation documents its input/output bounds; the invariants are:
//!
//! * `mul`, `square` and `mul_small` accept limbs `< 2^54` and produce
//!   *weakly reduced* elements: limbs `< 2^51 + 2^18`. (`from_bytes` and
//!   the table's constants are fully reduced: limbs `< 2^51`.)
//! * `add` and `sub` do not reduce. Of weakly reduced inputs they give
//!   limbs `< 2^52.6`; the fixed-base ladder applies them once more to
//!   such a value and a weakly reduced one, for limbs `< 2^53.1`. That is
//!   the most a multiplication is ever given.
//! * `sub` needs a weakly reduced right-hand side (limbs `<= 2^52 − 38`).
//! * `encode` accepts weakly reduced elements and emits the unique
//!   canonical encoding, in constant time.
//!
//! # What is left behind
//!
//! The scalar's working copy and the ladder's state are wiped where they
//! are declared. That does not reach the temporaries of the arithmetic —
//! the sums and products of a ladder step are as good as its state — which
//! the compiler keeps wherever it sees fit in the ladder's frame. So each
//! ladder runs in a function of its own, notes how far down the stack it
//! and what it calls reached ([`ct::stack_mark`]), and that much stack is
//! overwritten once it has returned ([`ct::scrub_stack_to`]).
//!
//! # Inlining, speed and stack
//!
//! On a 64-bit target, in a build without debug assertions, the field
//! operations are forced into the ladders (`inline(always)`). That is
//! worth a tenth to a fifth of the time of a scalar multiplication there
//! (measured on x86-64: the compiler's own choice leaves the
//! multiplication a call), costs half a kilobyte of stack, and makes the
//! marks above exact, since nothing is left beneath the functions that
//! take them.
//!
//! Everywhere else it is left to the compiler:
//!
//! * on 32-bit targets, where the same inlining was measured to take two
//!   kilobytes more stack (Cortex-M4, RV32) for a gain nobody has
//!   measured — a limb multiplication there is a hundred instructions,
//!   and a call is not what it waits for;
//! * in builds with debug assertions, which is how this module tells an
//!   unoptimised build from an optimised one: forced inlining at
//!   `opt-level = 0` gives the ladder a frame of 75 KiB.
//!
//! There the field operations may be calls, with frames of their own
//! beneath the marks, and a fixed allowance is made for them
//! (`BELOW_MARK`): enough in an optimised build, not claimed to be
//! enough at `opt-level = 0`.

use crate::Error;
use crate::crypto::bytes;
use crate::crypto::ct;

#[cfg(feature = "x25519-table")]
mod base_table;

/// 51-bit limb mask.
const MASK: u64 = (1 << 51) - 1;

/// `(p - 2) mod 2^51` style constants for limbwise subtraction: adding
/// `2·p` (limbwise `2^52 − 38, 2^52 − 2, …`) before subtracting keeps every
/// limb positive for any weakly reduced operand.
const TWO_P0: u64 = 0x000f_ffff_ffff_ffda;
const TWO_P1234: u64 = 0x000f_ffff_ffff_fffe;

/// How far below the deepest [`ct::stack_mark`] of a ladder the stack is
/// overwritten afterwards: room for what lies beneath the functions that
/// take the marks.
///
/// Where the field operations are forced into those functions (see the
/// module documentation) that is next to nothing: the few bytes of a
/// mark's own frame and of a byte-copying helper. Elsewhere the field
/// operations may be calls: a multiplication and the carry it ends with,
/// which in an optimised build take under 200 bytes between them on the
/// targets measured (x86-64, aarch64, 32-bit x86 and ARM). At
/// `opt-level = 0` they take a few kilobytes, and this does not cover
/// them. (`probes/` looks for what is left.)
#[cfg(all(not(debug_assertions), target_pointer_width = "64"))]
const BELOW_MARK: usize = 256;
#[cfg(not(all(not(debug_assertions), target_pointer_width = "64")))]
const BELOW_MARK: usize = 512;

/// Widening u64 multiply. u64×u64 cannot overflow u128, so this is total.
#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    u128::from(x).wrapping_mul(u128::from(y))
}

/// A field element.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl core::fmt::Debug for Fe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Limbs may carry secret-derived state during the ladder.
        f.write_str("Fe(REDACTED)")
    }
}

impl Fe {
    const ZERO: Self = Self([0; 5]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// Decode 32 little-endian bytes, masking bit 255 (RFC 7748 §5).
    /// Output limbs `<= MASK`.
    #[cfg_attr(
        all(not(debug_assertions), target_pointer_width = "64"),
        inline(always)
    )]
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut q = [0u64; 4];
        bytes::load_le64(q.iter_mut(), bytes);
        let [t0, t1, t2, t3] = q;
        Self([
            t0 & MASK,
            ((t0 >> 51) | (t1 << 13)) & MASK,
            ((t1 >> 38) | (t2 << 26)) & MASK,
            ((t2 >> 25) | (t3 << 39)) & MASK,
            (t3 >> 12) & MASK,
        ])
    }

    /// Canonical constant-time encoding, written to `out`. Accepts weakly
    /// reduced input (limbs `< 2^52`).
    #[cfg_attr(
        all(not(debug_assertions), target_pointer_width = "64"),
        inline(always)
    )]
    fn encode(&self, out: &mut [u8; 32]) {
        let [mut l0, mut l1, mut l2, mut l3, mut l4] = self.0;

        // One carry pass (with the 19-fold) to tighten limbs below
        // 2^51 + 2^13.
        let mut c;
        c = l0 >> 51;
        l0 &= MASK;
        l1 = l1.wrapping_add(c);
        c = l1 >> 51;
        l1 &= MASK;
        l2 = l2.wrapping_add(c);
        c = l2 >> 51;
        l2 &= MASK;
        l3 = l3.wrapping_add(c);
        c = l3 >> 51;
        l3 &= MASK;
        l4 = l4.wrapping_add(c);
        c = l4 >> 51;
        l4 &= MASK;
        l0 = l0.wrapping_add(c.wrapping_mul(19));
        c = l0 >> 51;
        l0 &= MASK;
        l1 = l1.wrapping_add(c);

        // q = 1 iff the value is >= p (computed as the bit-255 carry of
        // value + 19); adding 19·q and dropping bit 255 then subtracts p
        // exactly when needed. Constant time.
        let mut q = l0.wrapping_add(19) >> 51;
        q = l1.wrapping_add(q) >> 51;
        q = l2.wrapping_add(q) >> 51;
        q = l3.wrapping_add(q) >> 51;
        q = l4.wrapping_add(q) >> 51;

        l0 = l0.wrapping_add(q.wrapping_mul(19));
        c = l0 >> 51;
        l0 &= MASK;
        l1 = l1.wrapping_add(c);
        c = l1 >> 51;
        l1 &= MASK;
        l2 = l2.wrapping_add(c);
        c = l2 >> 51;
        l2 &= MASK;
        l3 = l3.wrapping_add(c);
        c = l3 >> 51;
        l3 &= MASK;
        l4 = l4.wrapping_add(c);
        l4 &= MASK;

        let mut words = [
            l0 | (l1 << 51),
            (l1 >> 13) | (l2 << 38),
            (l2 >> 26) | (l3 << 25),
            (l3 >> 39) | (l4 << 12),
        ];
        bytes::store_le64(out, words);
        // The four words are the encoding itself.
        ct::wipe_words(&mut words);
    }

    /// Zero the limbs where they lie.
    fn wipe(&mut self) {
        ct::wipe_words(&mut self.0);
    }

    #[cfg(test)]
    fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.encode(&mut out);
        out
    }

    /// Limbwise sum; no reduction.
    #[cfg_attr(
        all(not(debug_assertions), target_pointer_width = "64"),
        inline(always)
    )]
    fn add(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;
        Self([
            a0.wrapping_add(b0),
            a1.wrapping_add(b1),
            a2.wrapping_add(b2),
            a3.wrapping_add(b3),
            a4.wrapping_add(b4),
        ])
    }

    /// `self − rhs`, computed as `self + 2p − rhs` limbwise so nothing
    /// underflows for weakly reduced `rhs` (limbs `<= 2^52 − 38`). No
    /// reduction: the result's limbs are below `self`'s plus `2^52`.
    #[cfg_attr(
        all(not(debug_assertions), target_pointer_width = "64"),
        inline(always)
    )]
    fn sub(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;
        Self([
            a0.wrapping_add(TWO_P0).wrapping_sub(b0),
            a1.wrapping_add(TWO_P1234).wrapping_sub(b1),
            a2.wrapping_add(TWO_P1234).wrapping_sub(b2),
            a3.wrapping_add(TWO_P1234).wrapping_sub(b3),
            a4.wrapping_add(TWO_P1234).wrapping_sub(b4),
        ])
    }

    /// Schoolbook multiplication mod p with the 19-fold on high cross
    /// terms. Limbs `< 2^54` on both sides: the 19-fold limbs stay below
    /// `2^58.3`, the accumulators below `77·2^108 < 2^114.3` (one product
    /// of two limbs and four of a limb with a 19-fold limb) and the last
    /// one, which has no folded terms, below `5·2^108 < 2^110.4` — the
    /// bounds [`Self::carry`] is written for. Output is weakly reduced.
    #[cfg_attr(
        all(not(debug_assertions), target_pointer_width = "64"),
        inline(always)
    )]
    fn mul(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;
        let b1_19 = b1.wrapping_mul(19);
        let b2_19 = b2.wrapping_mul(19);
        let b3_19 = b3.wrapping_mul(19);
        let b4_19 = b4.wrapping_mul(19);

        // u64×u64 in u128 can never overflow, and the five-term sums stay
        // below 2^114.3 (above), so the wrapping operations never wrap.
        let t0 = m(a0, b0)
            .wrapping_add(m(a1, b4_19))
            .wrapping_add(m(a2, b3_19))
            .wrapping_add(m(a3, b2_19))
            .wrapping_add(m(a4, b1_19));
        let t1 = m(a0, b1)
            .wrapping_add(m(a1, b0))
            .wrapping_add(m(a2, b4_19))
            .wrapping_add(m(a3, b3_19))
            .wrapping_add(m(a4, b2_19));
        let t2 = m(a0, b2)
            .wrapping_add(m(a1, b1))
            .wrapping_add(m(a2, b0))
            .wrapping_add(m(a3, b4_19))
            .wrapping_add(m(a4, b3_19));
        let t3 = m(a0, b3)
            .wrapping_add(m(a1, b2))
            .wrapping_add(m(a2, b1))
            .wrapping_add(m(a3, b0))
            .wrapping_add(m(a4, b4_19));
        let t4 = m(a0, b4)
            .wrapping_add(m(a1, b3))
            .wrapping_add(m(a2, b2))
            .wrapping_add(m(a3, b1))
            .wrapping_add(m(a4, b0));

        Self::carry(t0, t1, t2, t3, t4)
    }

    /// Squaring with the symmetric-term shortcuts; same bounds as `mul`.
    ///
    /// With `a = Σ aᵢ·2^(51·i)`, the product coefficients fold (×19) from
    /// positions 5..9 back onto 0..4:
    ///
    /// ```text
    /// t0 = a0²        + 19·(2·a1·a4 + 2·a2·a3)
    /// t1 = 2·a0·a1    + 19·(2·a2·a4 +   a3²)
    /// t2 = 2·a0·a2 + a1² + 19·(2·a3·a4)
    /// t3 = 2·a0·a3 + 2·a1·a2 + 19·a4²
    /// t4 = 2·a0·a4 + 2·a1·a3 + a2²
    /// ```
    #[cfg_attr(
        all(not(debug_assertions), target_pointer_width = "64"),
        inline(always)
    )]
    fn square(self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let d0 = a0.wrapping_mul(2);
        let d1 = a1.wrapping_mul(2);
        let d2 = a2.wrapping_mul(2);
        let d3 = a3.wrapping_mul(2);
        let a3_19 = a3.wrapping_mul(19);
        let a4_19 = a4.wrapping_mul(19);

        let t0 = m(a0, a0)
            .wrapping_add(m(d1, a4_19))
            .wrapping_add(m(d2, a3_19));
        let t1 = m(d0, a1)
            .wrapping_add(m(d2, a4_19))
            .wrapping_add(m(a3, a3_19));
        let t2 = m(d0, a2).wrapping_add(m(a1, a1)).wrapping_add(m(d3, a4_19));
        let t3 = m(d0, a3).wrapping_add(m(d1, a2)).wrapping_add(m(a4, a4_19));
        let t4 = m(d0, a4).wrapping_add(m(d1, a3)).wrapping_add(m(a2, a2));

        Self::carry(t0, t1, t2, t3, t4)
    }

    /// From five `u128` accumulators back to weakly reduced limbs, in two
    /// rounds of carries that do not wait for each other.
    ///
    /// Round 1 splits every accumulator at bit 51 and adds each high part
    /// to the limb above (the top one, times 19, to limb 0). Round 2 does
    /// the same once more with what are by then small carries. A single
    /// chain through all five accumulators and around again gives tighter
    /// limbs, but every step of it waits for the one before.
    ///
    /// The high part `t >> 51` is `(lo >> 51) + (hi << 13)`, the two terms
    /// having no bit in common; they are added to the limb above one after
    /// the other. (Written as the one 128-bit shift it becomes a
    /// double-precision shift instruction, which on current AMD cores is
    /// microcoded and limited to one a cycle — a tenth of the micro-ops of
    /// a scalar multiplication. Three plain instructions are the same or
    /// better everywhere.)
    ///
    /// Bounds: accumulators `< 2^114.3`, the last one `< 2^110.4` (see
    /// [`Self::mul`]). So `hi < 2^50.3`, which the shift by 13 does not
    /// push out of the word; a round-1 sum is below
    /// `2^51 + 2^13 + 2^63.3 < 2^64`, and that of limb 0 below
    /// `2^51 + 19·(2^13 + 2^59.4) < 2^63.7`. Their high parts are `< 2^13`:
    /// the result has limbs `< 2^51 + 2^13`, limb 0 `< 2^51 + 19·2^13`.
    #[cfg_attr(
        all(not(debug_assertions), target_pointer_width = "64"),
        inline(always)
    )]
    fn carry(t0: u128, t1: u128, t2: u128, t3: u128, t4: u128) -> Self {
        /// `(lo >> 51, hi << 13)`: the two terms of `t >> 51`.
        #[inline(always)]
        fn high(t: u128) -> (u64, u64) {
            ((t as u64) >> 51, ((t >> 64) as u64) << 13)
        }
        let (a0, b0) = high(t0);
        let (a1, b1) = high(t1);
        let (a2, b2) = high(t2);
        let (a3, b3) = high(t3);
        let (a4, b4) = high(t4);
        let s0 = ((t0 as u64) & MASK)
            .wrapping_add(a4.wrapping_mul(19))
            .wrapping_add(b4.wrapping_mul(19));
        let s1 = ((t1 as u64) & MASK).wrapping_add(a0).wrapping_add(b0);
        let s2 = ((t2 as u64) & MASK).wrapping_add(a1).wrapping_add(b1);
        let s3 = ((t3 as u64) & MASK).wrapping_add(a2).wrapping_add(b2);
        let s4 = ((t4 as u64) & MASK).wrapping_add(a3).wrapping_add(b3);
        Self([
            (s0 & MASK).wrapping_add((s4 >> 51).wrapping_mul(19)),
            (s1 & MASK).wrapping_add(s0 >> 51),
            (s2 & MASK).wrapping_add(s1 >> 51),
            (s3 & MASK).wrapping_add(s2 >> 51),
            (s4 & MASK).wrapping_add(s3 >> 51),
        ])
    }

    /// Multiply by a small constant (121665 = (A−2)/4). Limbs `< 2^54`;
    /// output weakly reduced.
    #[cfg_attr(
        all(not(debug_assertions), target_pointer_width = "64"),
        inline(always)
    )]
    fn mul_small(self, k: u32) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let k = u64::from(k);
        Self::carry(m(a0, k), m(a1, k), m(a2, k), m(a3, k), m(a4, k))
    }

    /// `self^(p−2) = self^−1` (and `0 ↦ 0`), classic addition chain.
    ///
    /// `low` is lowered to the deepest [`ct::stack_mark`] taken here and
    /// in the squaring loops (see the module documentation). Neither is
    /// ever inlined, so that where those marks are taken does not depend
    /// on what a compiler decides to inline: this function's frame lies
    /// beneath the ladder's, a squaring loop's beneath this one's.
    #[inline(never)]
    fn invert(self, low: &mut usize) -> Self {
        #[inline(never)]
        fn nsquare(mut x: Fe, n: u32, low: &mut usize) -> Fe {
            *low = (*low).min(ct::stack_mark());
            for _ in 0..n {
                x = x.square();
            }
            x
        }
        *low = (*low).min(ct::stack_mark());
        let z = self;
        let z2 = z.square(); // 2
        let z9 = nsquare(z2, 2, low).mul(z); // 9
        let z11 = z9.mul(z2); // 11
        let z_5_0 = z11.square().mul(z9); // 31 = 2^5 − 1
        let z_10_0 = nsquare(z_5_0, 5, low).mul(z_5_0); // 2^10 − 1
        let z_20_0 = nsquare(z_10_0, 10, low).mul(z_10_0); // 2^20 − 1
        let z_40_0 = nsquare(z_20_0, 20, low).mul(z_20_0); // 2^40 − 1
        let z_50_0 = nsquare(z_40_0, 10, low).mul(z_10_0); // 2^50 − 1
        let z_100_0 = nsquare(z_50_0, 50, low).mul(z_50_0); // 2^100 − 1
        let z_200_0 = nsquare(z_100_0, 100, low).mul(z_100_0); // 2^200 − 1
        let z_250_0 = nsquare(z_200_0, 50, low).mul(z_50_0); // 2^250 − 1
        nsquare(z_250_0, 5, low).mul(z11) // 2^255 − 21
    }

    /// Constant-time conditional swap of two pairs: exchanges `a` with
    /// `b` and `c` with `d` iff `swap == 1`. `swap` must be 0 or 1.
    ///
    /// Both swaps of a ladder step are behind one optimisation barrier.
    /// The barrier keeps the compiler from learning that the mask is one
    /// of two values and branching on it; it is also a point at which
    /// everything whose address is taken anywhere — the ladder's state
    /// is, by the wipe at the end — has to be in memory, so each one is a
    /// round trip of that state through the stack.
    #[cfg_attr(
        all(not(debug_assertions), target_pointer_width = "64"),
        inline(always)
    )]
    fn cswap2(swap: u64, a: &mut Self, b: &mut Self, c: &mut Self, d: &mut Self) {
        let mask = 0u64.wrapping_sub(core::hint::black_box(swap));
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let t = mask & (*x ^ *y);
            *x ^= t;
            *y ^= t;
        }
        for (x, y) in c.0.iter_mut().zip(d.0.iter_mut()) {
            let t = mask & (*x ^ *y);
            *x ^= t;
            *y ^= t;
        }
    }

    /// One doubling in the ladder's coordinates: `(x : z) := 2·(x : z)`.
    #[cfg(any(test, feature = "x25519-table"))]
    #[cfg_attr(
        all(not(debug_assertions), target_pointer_width = "64"),
        inline(always)
    )]
    fn double(x: &mut Self, z: &mut Self) {
        let aa = x.add(*z).square();
        let bb = x.sub(*z).square();
        let e = aa.sub(bb);
        *x = aa.mul(bb);
        *z = e.mul(aa.add(e.mul_small(121_665)));
    }
}

/// Bit `t` of a scalar, as 0 or 1.
#[inline(always)]
fn scalar_bit(k: &[u8; 32], t: usize) -> u64 {
    let byte = k.get(t >> 3).copied().unwrap_or(0);
    u64::from((byte >> (t & 7)) & 1)
}

/// RFC 7748 §5 scalar clamping.
#[must_use]
pub fn clamp_scalar(mut scalar: [u8; 32]) -> [u8; 32] {
    clamp_in_place(&mut scalar);
    scalar
}

/// RFC 7748 §5 scalar clamping, in place: the form for a scalar that is a
/// secret, of which [`clamp_scalar`] would make a second copy.
pub fn clamp_in_place(scalar: &mut [u8; 32]) {
    if let Some(first) = scalar.first_mut() {
        *first &= 248;
    }
    if let Some(last) = scalar.last_mut() {
        *last &= 127;
        *last |= 64;
    }
}

/// The X25519 function: scalar multiplication on the Montgomery curve.
/// `scalar` is clamped internally; bit 255 of `u` is ignored (RFC 7748).
///
/// The result comes back by value: into a place of the caller's, and
/// nowhere else — the frame it is computed in is overwritten afterwards
/// ([`ct::ScrubOnDrop`]). What becomes of the caller's copy is the
/// caller's business; [`x25519_into`] writes it where it is to stay.
#[must_use]
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut scrub = ct::ScrubOnDrop::new();
    x25519_by_value(scalar, u, scrub.low())
}

/// [`x25519`]'s work, in a frame of its own; `low` says where it ends.
#[inline(never)]
fn x25519_by_value(scalar: &[u8; 32], u: &[u8; 32], low: &mut usize) -> [u8; 32] {
    *low = ct::stack_mark();
    let mut out = [0u8; 32];
    x25519_into(scalar, u, &mut out);
    out
}

/// As [`x25519`], writing the result to `out`. This is the form to use
/// when the result is a secret: nothing is returned by value, and the
/// clamped scalar and everything the ladder worked with are wiped before
/// returning.
pub fn x25519_into(scalar: &[u8; 32], u: &[u8; 32], out: &mut [u8; 32]) {
    let low = ladder(scalar, u, out);
    ct::scrub_stack_to(low.saturating_sub(BELOW_MARK));
}

/// The Montgomery ladder of RFC 7748 §5. Not inlined: its frame, and what
/// lies beneath it, is what [`x25519_into`] overwrites afterwards. Returns
/// how far down that goes.
#[inline(never)]
fn ladder(scalar: &[u8; 32], u: &[u8; 32], out: &mut [u8; 32]) -> usize {
    let mut low = ct::stack_mark();
    let mut k = [0u8; 32];
    ct::copy_secret(&mut k, scalar);
    clamp_in_place(&mut k);
    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;

    let mut t = 255usize;
    while t > 0 {
        t = t.wrapping_sub(1);
        let bit = scalar_bit(&k, t);
        swap ^= bit;
        Fe::cswap2(swap, &mut x2, &mut x3, &mut z2, &mut z3);
        swap = bit;

        // RFC 7748 §5 ladder step.
        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.mul_small(121_665)));
    }
    Fe::cswap2(swap, &mut x2, &mut x3, &mut z2, &mut z3);

    // z2 == 0 (low-order input) inverts to 0 and yields an all-zero
    // output, which `shared_secret` rejects.
    let mut affine = x2.mul(z2.invert(&mut low));
    affine.encode(out);

    ct::wipe_array(&mut k);
    for fe in [&mut affine, &mut x2, &mut z2, &mut x3, &mut z3] {
        fe.wipe();
    }
    low
}

/// The X25519 base point (u = 9).
pub const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Derive the public key for a private key: `x25519(scalar, BASEPOINT)`.
///
/// With the cargo feature `x25519-table` (on by default) this is a ladder
/// made for the base point: constant time like the other, a little over
/// half its cost, and 10 KiB of constants. Without the feature it is the
/// other ladder.
#[must_use]
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    #[cfg(feature = "x25519-table")]
    {
        let low = base_ladder(scalar, &mut out);
        ct::scrub_stack_to(low.saturating_sub(BELOW_MARK));
    }
    #[cfg(not(feature = "x25519-table"))]
    x25519_into(scalar, &BASEPOINT, &mut out);
    out
}

/// The fixed-base ladder of Oliveira, López, Hışıl, Faz-Hernández and
/// Rodríguez-Henríquez ("How to (pre-)compute a ladder", SAC 2017).
///
/// A clamped scalar is a multiple of 8; let `k' = k/8`, `G` the base
/// point and `S` a point of order 4 (`x = 1`). The loop keeps
///
/// ```text
/// R1 = (k' mod 2^m)·G + S        R2 = R1 − 2^m·G
/// ```
///
/// Step `m` is one differential addition with `2^m·G`. For a 1 bit it is
/// `R1 := R1 + 2^m·G`, whose difference is `R2`; for a 0 bit
/// `R2 := R2 − 2^m·G`, whose difference is `R1`. Either way the pair's
/// difference is `2^(m+1)·G` afterwards. The point `2^m·G` enters only
/// through `μ_m = (x + 1)/(x − 1)` of its x-coordinate, which is the
/// table: with `(X : Z)` the point to update and `(X' : Z')` the other,
///
/// ```text
/// X := Z'·((X + Z) + μ_m·(X − Z))²        Z := X'·((X + Z) − μ_m·(X − Z))²
/// ```
///
/// which is the ordinary differential addition with both coordinates
/// divided by `(x − 1)²`: three multiplications and two squarings a bit,
/// against five, four and a small one. Three doublings at the end give
/// `8·(k'·G + S) = k·G`.
///
/// `S` is what makes this sound. A differential addition fails only when
/// the difference is the point at infinity or the point of order 2. Every
/// point above is `j·G + S` for some `j`; `j·G` has odd order or is the
/// identity, so the sum has order divisible by 4 and is neither. For the
/// same reason no `Z` here is ever zero, and `x(2^m·G)` is never 1.
///
/// Constant time for the same reasons as [`ladder`]: the table is read in
/// the order of the loop counter, never at a secret index; the scalar's
/// bits steer the same arithmetic conditional swaps.
#[cfg(feature = "x25519-table")]
#[inline(never)]
fn base_ladder(scalar: &[u8; 32], out: &mut [u8; 32]) -> usize {
    let mut low = ct::stack_mark();
    let mut k = [0u8; 32];
    ct::copy_secret(&mut k, scalar);
    clamp_in_place(&mut k);
    // (u1 : z1) is the point to update, (u2 : z2) the other: R1 and R2 to
    // begin with.
    let mut u1 = Fe::ONE;
    let mut z1 = Fe::ONE;
    let mut u2 = Fe(base_table::S_MINUS_G);
    let mut z2 = Fe::ONE;
    // Whether R1 is in the first place. A step needs it there for a 1 bit
    // and R2 for a 0 bit, so it swaps when its bit differs from this.
    let mut r1_first = 1u64;
    // Scalar bit `m + 3` goes with entry `m`.
    for (mu, t) in base_table::MU.iter().zip(3usize..) {
        let bit = scalar_bit(&k, t);
        Fe::cswap2(r1_first ^ bit, &mut u1, &mut u2, &mut z1, &mut z2);
        r1_first = bit;

        let b = u1.sub(z1);
        let a = u1.add(z1);
        let c = Fe(*mu).mul(b);
        u1 = z2.mul(a.add(c).square());
        z1 = u2.mul(a.sub(c).square());
    }
    // Bit 254 of a clamped scalar is set, so the last step left R1 in the
    // first place: (u1 : z1) is k'·G + S. Times 8:
    for _ in 0..3 {
        Fe::double(&mut u1, &mut z1);
    }
    let mut affine = u1.mul(z1.invert(&mut low));
    affine.encode(out);

    ct::wipe_array(&mut k);
    for fe in [&mut affine, &mut u1, &mut z1, &mut u2, &mut z2] {
        fe.wipe();
    }
    low
}

/// Diffie-Hellman with mandatory contributory-behaviour check: an all-zero
/// shared secret (low-order or zero `peer_public`) is rejected, in
/// constant time, exactly like the kernel implementation.
///
/// # Errors
/// [`Error::InvalidPublicKey`] if the shared secret is all-zero.
pub fn shared_secret(private: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32], Error> {
    // By value, as in `x25519`.
    let mut scrub = ct::ScrubOnDrop::new();
    shared_secret_by_value(private, peer_public, scrub.low())
}

/// [`shared_secret`]'s work, in a frame of its own; `low` says where it
/// ends.
#[inline(never)]
fn shared_secret_by_value(
    private: &[u8; 32],
    peer_public: &[u8; 32],
    low: &mut usize,
) -> Result<[u8; 32], Error> {
    *low = ct::stack_mark();
    let mut out = [0u8; 32];
    if shared_secret_into(private, peer_public, &mut out) {
        Ok(out)
    } else {
        Err(Error::InvalidPublicKey)
    }
}

/// As [`shared_secret`], writing the secret to `out` instead of returning
/// it. Returns `false` — with `out` all-zero — when the shared secret is
/// the all-zero value.
#[must_use]
pub fn shared_secret_into(private: &[u8; 32], peer_public: &[u8; 32], out: &mut [u8; 32]) -> bool {
    x25519_into(private, peer_public, out);
    // `out` is all-zero exactly when this is false, so there is nothing
    // left to wipe in that case.
    !ct::ct_is_zero(out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::string_slice,
        clippy::panic
    )]
    use super::*;
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    /// splitmix64 for deterministic property tests.
    struct Rng(u64);
    impl Rng {
        fn next32(&mut self) -> [u8; 32] {
            let mut out = [0u8; 32];
            for chunk in out.chunks_mut(8) {
                self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
            }
            out
        }
    }

    #[test]
    fn rfc7748_vector_1() {
        let scalar = arr("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = arr("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = arr("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(&scalar, &u), expected);
    }

    #[test]
    fn rfc7748_vector_2() {
        // u has its high bit set: must be masked, not rejected.
        let scalar = arr("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = arr("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected = arr("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(x25519(&scalar, &u), expected);
    }

    #[test]
    fn rfc7748_iterated() {
        // RFC 7748 §5.2: k = u = base point, iterate k := X25519(k, u).
        let mut k = BASEPOINT;
        let mut u = BASEPOINT;
        for i in 1..=1000u32 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(
                    k,
                    arr("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        assert_eq!(
            k,
            arr("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        // RFC 7748 §6.1.
        let alice_priv = arr("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub = arr("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_priv = arr("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pub = arr("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = arr("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519_base(&alice_priv), alice_pub);
        assert_eq!(x25519_base(&bob_priv), bob_pub);
        assert_eq!(x25519(&alice_priv, &bob_pub), shared);
        assert_eq!(x25519(&bob_priv, &alice_pub), shared);
        assert_eq!(shared_secret(&alice_priv, &bob_pub).unwrap(), shared);
    }

    #[test]
    fn dh_commutes_on_random_keys() {
        let mut rng = Rng(0x5eed);
        for _ in 0..24 {
            let a = rng.next32();
            let b = rng.next32();
            let ga = x25519_base(&a);
            let gb = x25519_base(&b);
            assert_eq!(x25519(&a, &gb), x25519(&b, &ga));
        }
    }

    #[test]
    fn square_equals_mul_self_and_inverse_works() {
        let mut rng = Rng(0xfeed);
        for _ in 0..64 {
            let bytes = rng.next32();
            let z = Fe::from_bytes(&bytes);
            assert_eq!(z.square().to_bytes(), z.mul(z).to_bytes());
            // x · x^(p−2) ≡ 1 for x ≠ 0.
            let inv = z.inverse();
            assert_eq!(z.mul(inv).to_bytes(), Fe::ONE.to_bytes());
        }
        // Sub/add/mul_small consistency: (a + b) − b ≡ a.
        for _ in 0..64 {
            let a = Fe::from_bytes(&rng.next32());
            let b = Fe::from_bytes(&rng.next32());
            // Normalize through mul by one to exercise carry paths.
            let lhs = a.add(b).sub(b).mul(Fe::ONE).to_bytes();
            assert_eq!(lhs, a.mul(Fe::ONE).to_bytes());
            // 121665·a == a · fe(121665)
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&121_665u32.to_le_bytes());
            assert_eq!(
                a.mul_small(121_665).to_bytes(),
                a.mul(Fe::from_bytes(&k)).to_bytes()
            );
        }
    }

    #[test]
    fn canonical_encoding_of_noncanonical_inputs() {
        // p ≡ 0, p+1 ≡ 1, 2^255−1 ≡ 18 (mod p): from_bytes+to_bytes must
        // produce the canonical representative.
        let p = arr("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let p1 = arr("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let all = arr("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert_eq!(Fe::from_bytes(&p).to_bytes(), [0u8; 32]);
        assert_eq!(Fe::from_bytes(&p1).to_bytes(), Fe::ONE.to_bytes());
        let mut eighteen = [0u8; 32];
        eighteen[0] = 18;
        assert_eq!(Fe::from_bytes(&all).to_bytes(), eighteen);
    }

    #[test]
    fn low_order_points_rejected_by_shared_secret() {
        let priv_key = Rng(7).next32();
        // u = 0 and u = 1 are low order; u = p−1 has order 4.
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1;
        let pm1 = arr("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        for u in [&zero, &one, &pm1] {
            assert_eq!(x25519(&priv_key, u), [0u8; 32], "u={u:02x?}");
            assert_eq!(
                shared_secret(&priv_key, u),
                Err(Error::InvalidPublicKey),
                "u={u:02x?}"
            );
        }
        // A valid point is accepted.
        assert!(shared_secret(&priv_key, &BASEPOINT).is_ok());
    }

    impl Fe {
        /// The inverse, for tests that have no use for the stack mark.
        fn inverse(self) -> Fe {
            let mut low = usize::MAX;
            self.invert(&mut low)
        }
    }

    /// The value of an element whatever its limbs look like: through the
    /// canonical encoding and back.
    fn canonical(x: Fe) -> Fe {
        Fe::from_bytes(&x.to_bytes())
    }

    #[test]
    fn multiplication_at_the_documented_limb_bounds() {
        // `mul`, `square` and `mul_small` are documented for limbs below
        // 2^54. Nothing may wrap there: the product of two such elements
        // must be the product of their reduced forms. (`encode` is given
        // more than it documents here; one carry pass is all it needs
        // below 2^63.)
        const TOP: u64 = (1 << 54) - 1;
        let mut rng = Rng(0xb0bd);
        let mut cases: Vec<Fe> = std::vec![
            Fe([TOP; 5]),
            Fe([TOP, 0, TOP, 0, TOP]),
            Fe([0, TOP, 0, TOP, 0]),
            Fe([MASK; 5]),
            Fe([TOP, MASK, 1, 0, TOP]),
        ];
        for one in 0..5 {
            let mut limbs = [0u64; 5];
            limbs[one] = TOP;
            cases.push(Fe(limbs));
            let mut limbs = [TOP; 5];
            limbs[one] = 0;
            cases.push(Fe(limbs));
        }
        for _ in 0..48 {
            let r = rng.next32();
            let mut limbs = [0u64; 5];
            for (limb, chunk) in limbs.iter_mut().zip(r.chunks(6)) {
                let mut word = [0u8; 8];
                word[..6].copy_from_slice(&chunk[..6]);
                // The top six bits set: between 2^53.9 and 2^54.
                *limb = (u64::from_le_bytes(word) & TOP) | (0x3f << 48);
            }
            cases.push(Fe(limbs));
        }
        for a in &cases {
            let ca = canonical(*a);
            assert_eq!(a.square().to_bytes(), ca.square().to_bytes());
            assert_eq!(a.square().to_bytes(), ca.mul(ca).to_bytes());
            assert_eq!(
                a.mul_small(u32::MAX).to_bytes(),
                ca.mul_small(u32::MAX).to_bytes()
            );
            assert_eq!(
                a.mul_small(121_665).to_bytes(),
                ca.mul_small(121_665).to_bytes()
            );
            for b in &cases {
                let cb = canonical(*b);
                assert_eq!(a.mul(*b).to_bytes(), ca.mul(cb).to_bytes());
            }
            // What comes out is weakly reduced, as documented.
            for out in [a.square(), a.mul(*a), a.mul_small(u32::MAX)] {
                assert!(out.0[0] < (1 << 51) + 19 * (1 << 13));
                assert!(out.0[1..].iter().all(|l| *l < (1 << 51) + (1 << 13)));
            }
        }
    }

    #[test]
    fn field_identities_on_random_elements() {
        // Independent of how a product is carried: the ring laws.
        let mut rng = Rng(0x1de4);
        for _ in 0..200 {
            let a = Fe::from_bytes(&rng.next32());
            let b = Fe::from_bytes(&rng.next32());
            let c = Fe::from_bytes(&rng.next32());
            assert_eq!(a.mul(b).to_bytes(), b.mul(a).to_bytes());
            assert_eq!(a.mul(b).mul(c).to_bytes(), a.mul(b.mul(c)).to_bytes());
            assert_eq!(
                a.mul(b.add(c)).to_bytes(),
                a.mul(b).add(a.mul(c)).mul(Fe::ONE).to_bytes()
            );
            assert_eq!(
                a.add(b).square().to_bytes(),
                a.square()
                    .add(b.square())
                    .add(a.mul(b).mul_small(2))
                    .mul(Fe::ONE)
                    .to_bytes()
            );
            assert_eq!(a.sub(a).mul(Fe::ONE).to_bytes(), [0u8; 32]);
        }
        // Small numbers, by hand: 2^255 ≡ 19, so 2^128·2^127 = 19.
        let mut two_128 = [0u8; 32];
        two_128[16] = 1;
        let mut two_127 = [0u8; 32];
        two_127[15] = 0x80;
        let mut nineteen = [0u8; 32];
        nineteen[0] = 19;
        assert_eq!(
            Fe::from_bytes(&two_128)
                .mul(Fe::from_bytes(&two_127))
                .to_bytes(),
            nineteen
        );
        // (p − 1)² = 1 and (p − 1)·2 = p − 2.
        let pm1 = Fe::from_bytes(&arr(
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ));
        assert_eq!(pm1.square().to_bytes(), Fe::ONE.to_bytes());
        assert_eq!(
            pm1.mul_small(2).to_bytes(),
            arr("ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        );
    }

    #[test]
    fn the_swap_exchanges_both_pairs_or_neither() {
        let mut rng = Rng(0x5a9);
        let fresh = |rng: &mut Rng| Fe::from_bytes(&rng.next32());
        let (a, b, c, d) = (
            fresh(&mut rng),
            fresh(&mut rng),
            fresh(&mut rng),
            fresh(&mut rng),
        );
        let (mut w, mut x, mut y, mut z) = (a, b, c, d);
        Fe::cswap2(0, &mut w, &mut x, &mut y, &mut z);
        assert_eq!((w.0, x.0, y.0, z.0), (a.0, b.0, c.0, d.0));
        Fe::cswap2(1, &mut w, &mut x, &mut y, &mut z);
        assert_eq!((w.0, x.0, y.0, z.0), (b.0, a.0, d.0, c.0));
    }

    /// The fixed-base ladder is the ordinary one at the base point. (When
    /// the table is not built in, this compares the ladder with itself.)
    #[test]
    fn base_point_multiplication_agrees_with_the_ladder() {
        let mut rng = Rng(0xba5e);
        for _ in 0..300 {
            let s = rng.next32();
            assert_eq!(x25519_base(&s), x25519(&s, &BASEPOINT));
        }
        // The extremes of a clamped scalar, and every bit by itself: a
        // step that takes the other branch of its swap exactly once.
        for s in [[0u8; 32], [0xffu8; 32], [1u8; 32], [0x80u8; 32]] {
            assert_eq!(x25519_base(&s), x25519(&s, &BASEPOINT));
        }
        for t in 0..256 {
            let mut one = [0u8; 32];
            one[t >> 3] |= 1 << (t & 7);
            assert_eq!(x25519_base(&one), x25519(&one, &BASEPOINT), "bit {t}");
            let mut all_but = [0xffu8; 32];
            all_but[t >> 3] &= !(1 << (t & 7));
            assert_eq!(
                x25519_base(&all_but),
                x25519(&all_but, &BASEPOINT),
                "all but bit {t}"
            );
        }
    }

    /// Every constant of the fixed-base ladder, from first principles.
    #[cfg(feature = "x25519-table")]
    #[test]
    fn the_table_is_what_it_says() {
        // One entry for every bit of a clamped scalar above its three
        // zero bits and up to bit 254.
        assert_eq!(base_table::MU.len(), 252);
        // μ_m·(x − z) = x + z for (x : z) = 2^m·G, by repeated doubling
        // from the base point.
        let mut x = Fe::from_bytes(&BASEPOINT);
        let mut z = Fe::ONE;
        for (m, mu) in base_table::MU.iter().enumerate() {
            assert!(mu.iter().all(|limb| *limb <= MASK), "entry {m}");
            assert_eq!(canonical(Fe(*mu)).0, *mu, "entry {m} is not reduced");
            assert_eq!(
                Fe(*mu).mul(x.sub(z)).to_bytes(),
                x.add(z).mul(Fe::ONE).to_bytes(),
                "entry {m}"
            );
            Fe::double(&mut x, &mut z);
        }

        // x(S − G): a root of 64·(t² + 1) = 17520032·t, which is
        // t + 1/t = x(S − G) + x(S + G) for x(S) = 1 and x(G) = 9 on
        // y² = x³ + 486662·x² + x.
        let t = Fe(base_table::S_MINUS_G);
        assert!(base_table::S_MINUS_G.iter().all(|limb| *limb <= MASK));
        assert_eq!(canonical(t).0, base_table::S_MINUS_G);
        assert_eq!(
            t.square().add(Fe::ONE).mul_small(64).to_bytes(),
            t.mul_small(17_520_032).to_bytes()
        );
        // The sum of the two roots, from the curve equation: with
        // f(x) = x³ + A·x² + x,
        // x(P+Q) + x(P−Q) = 2·(f(x1) + f(x2))/(x1 − x2)² − 2·(A + x1 + x2).
        let small = |n: u32| Fe::ONE.mul_small(n);
        let f = |x: Fe| {
            x.square()
                .mul(x)
                .add(x.square().mul_small(486_662))
                .add(x)
                .mul(Fe::ONE)
        };
        let (x1, x2) = (small(1), small(9));
        let sum = f(x1)
            .add(f(x2))
            .mul_small(2)
            .mul(x1.sub(x2).square().inverse())
            .sub(small(2 * (486_662 + 1 + 9)));
        // t² + 1 = sum·t
        assert_eq!(
            t.square().add(Fe::ONE).mul(Fe::ONE).to_bytes(),
            sum.mul(t).to_bytes()
        );
    }

    /// The doubling used at the end of the fixed-base ladder (and by the
    /// table's test) against the ladder: 2^n·G for a clamped-looking n.
    #[test]
    fn doubling_agrees_with_the_ladder() {
        let mut x = Fe::from_bytes(&BASEPOINT);
        let mut z = Fe::ONE;
        for _ in 0..254 {
            Fe::double(&mut x, &mut z);
        }
        // The all-zero scalar clamps to 2^254.
        assert_eq!(
            x.mul(z.inverse()).to_bytes(),
            x25519(&[0u8; 32], &BASEPOINT)
        );
    }

    #[test]
    fn clamping() {
        let c = clamp_scalar([0xffu8; 32]);
        assert_eq!(c[0] & 7, 0);
        assert_eq!(c[31] & 128, 0);
        assert_eq!(c[31] & 64, 64);
        // Clamping is idempotent.
        assert_eq!(clamp_scalar(c), c);
        // The ladder clamps internally: passing clamped or unclamped gives
        // the same result.
        let mut rng = Rng(0xc1a3);
        for _ in 0..8 {
            let s = rng.next32();
            assert_eq!(x25519_base(&s), x25519_base(&clamp_scalar(s)));
        }
    }
}
