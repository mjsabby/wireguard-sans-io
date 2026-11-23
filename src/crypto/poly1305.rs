//! Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! Two limb representations compute the same function, and the target
//! decides which one is built:
//!
//! * **radix 2^64** where a machine word has 64 bits: the accumulator is
//!   two 64-bit limbs and a small third one, `r` is two 64-bit limbs and
//!   products are `u128`s (as in the X25519 field arithmetic). One block
//!   costs four 64×64→128 multiplications and two small ones, and the
//!   reduction is two additions with carry.
//! * **radix 2^26** ("donna") everywhere else: five 26-bit limbs in `u32`s
//!   with `u64` products — twenty-five 32×32→64 multiplications a block,
//!   which is what a 32-bit core does well; there, each 64×64→128 product
//!   would be a library call.
//!
//! Whole blocks are absorbed in one loop that holds the accumulator in
//! locals and writes it back once: a caller that hands over a packet pays
//! for one load and one store of the state, not one per sixteen bytes.
//! The shapes of all operations are fixed; there are no secret-dependent
//! branches or indices. The unit tests run both representations against
//! each other and against a big-integer model on every host.

use crate::crypto::bytes;
use crate::crypto::ct;

/// Read up to 8 little-endian bytes at `offset`, zero-padding past the end.
/// Total for every input; all call sites stay in bounds anyway.
#[inline(always)]
fn le64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut tmp = [0u8; 8];
    let src = bytes.get(offset..).unwrap_or(&[]);
    for (d, s) in tmp.iter_mut().zip(src.iter()) {
        *d = *s;
    }
    u64::from_le_bytes(tmp)
}

/// What a limb representation provides. The key-derived state lives in
/// the implementor and is only ever written in place.
trait Limbs: Clone {
    /// The state before a key has been set: all zero.
    const BLANK: Self;
    /// Set the key (`r ∥ s`, RFC 8439 §2.5) and clear the accumulator.
    fn set_key(&mut self, key: &[u8; 32]);
    /// Absorb whole 16-byte blocks (a trailing fragment of `data` would
    /// be ignored; no caller passes one). `FULL` says whether these are
    /// message blocks proper, which carry the 2^128 bit, or the final
    /// partial block, which carries its own 0x01 terminator instead. (A
    /// constant, so that the bit is one in the instruction stream and not
    /// one more operand on the path from block to block.)
    fn blocks<const FULL: bool>(&mut self, data: &[u8]);
    /// Reduce the accumulator, add `s` and write the tag. With `MARK`,
    /// returns where the stack ends beneath the frame this was done in
    /// ([`ct::stack_mark`]) — for the one caller that overwrites it, the
    /// AEAD after a tag that did not match; without, `usize::MAX`.
    fn tag_into<const MARK: bool>(&self, out: &mut [u8; 16]) -> usize;
    /// Zero everything.
    fn wipe(&mut self);
    /// Is everything zero?
    #[cfg(test)]
    fn is_blank(&self) -> bool;
}

#[cfg(any(test, target_pointer_width = "64"))]
mod wide {
    //! Radix 2^64.
    use super::{Limbs, bytes, ct, le64_at};

    /// Widening multiply: cannot overflow.
    #[inline(always)]
    fn m(x: u64, y: u64) -> u128 {
        u128::from(x).wrapping_mul(u128::from(y))
    }

    #[derive(Clone)]
    pub(super) struct Limbs64 {
        /// Clamped `r`: `r[0] + 2^64·r[1]`; both below 2^60, `r[1]` a
        /// multiple of four.
        r: [u64; 2],
        /// Accumulator: `h[0] + 2^64·h[1] + 2^128·h[2]`, with `h[2]` at
        /// most 4 between blocks.
        h: [u64; 3],
        /// The `s` half of the key.
        pad: [u64; 2],
    }

    impl Limbs for Limbs64 {
        const BLANK: Self = Self {
            r: [0; 2],
            h: [0; 3],
            pad: [0; 2],
        };

        fn set_key(&mut self, key: &[u8; 32]) {
            // Clamp r: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff.
            self.r = [
                le64_at(key, 0) & 0x0fff_fffc_0fff_ffff,
                le64_at(key, 8) & 0x0fff_fffc_0fff_fffc,
            ];
            self.h = [0; 3];
            self.pad = [le64_at(key, 16), le64_at(key, 24)];
        }

        #[inline]
        fn blocks<const FULL: bool>(&mut self, data: &[u8]) {
            let hibit = u64::from(FULL);
            let [r0, r1] = self.r;
            // 2^130 ≡ 5 and r1 is a multiple of 4, so
            // h1·r1·2^128 = h1·(r1/4)·2^130 ≡ h1·(5·r1/4).
            let s1 = r1.wrapping_add(r1 >> 2);
            let [mut h0, mut h1, mut h2] = self.h;

            let mut rest = data;
            while let Some((block, tail)) = rest.split_first_chunk::<16>() {
                rest = tail;
                // h += block (and the 2^128 bit): h2 ≤ 4 + 1 + 1.
                let t = u128::from(h0).wrapping_add(u128::from(le64_at(block, 0)));
                h0 = t as u64;
                let t = u128::from(h1)
                    .wrapping_add(u128::from(le64_at(block, 8)))
                    .wrapping_add(t >> 64);
                h1 = t as u64;
                h2 = h2.wrapping_add((t >> 64) as u64).wrapping_add(hibit);

                // h *= r. With h0, h1 < 2^64, h2 ≤ 6, r0, r1 < 2^60 and
                // s1 < 2^60.33: d0 < 2^125.3, d1 < 2^125.1, and the two
                // small products stay below 2^63.
                let d0 = m(h0, r0).wrapping_add(m(h1, s1));
                let d1 = m(h0, r1)
                    .wrapping_add(m(h1, r0))
                    .wrapping_add(u128::from(h2.wrapping_mul(s1)));
                let d2 = h2.wrapping_mul(r0);

                // Carry: the limbs are 64 bits apart already. d2 stays
                // below 2^63.1.
                h0 = d0 as u64;
                let d1 = d1.wrapping_add(d0 >> 64);
                h1 = d1 as u64;
                let d2 = d2.wrapping_add((d1 >> 64) as u64);
                // Fold everything from 2^130 up back in, times five:
                // c = 5·(d2 >> 2) < 2^63.4.
                let c = (d2 >> 2).wrapping_add(d2 & !3);
                h2 = d2 & 3;
                let t = u128::from(h0).wrapping_add(u128::from(c));
                h0 = t as u64;
                let t = u128::from(h1).wrapping_add(t >> 64);
                h1 = t as u64;
                // h2 ≤ 3 + 1.
                h2 = h2.wrapping_add((t >> 64) as u64);
            }
            self.h = [h0, h1, h2];
        }

        fn tag_into<const MARK: bool>(&self, out: &mut [u8; 16]) -> usize {
            // h < 5·2^128 < 2p, so h mod p is h or h − p. g = h + 5 − 2^130
            // is h − p; it is the answer exactly when h + 5 reaches 2^130.
            let [h0, h1, h2] = self.h;
            let t = u128::from(h0).wrapping_add(5);
            let g0 = t as u64;
            let t = u128::from(h1).wrapping_add(t >> 64);
            let g1 = t as u64;
            let g2 = h2.wrapping_add((t >> 64) as u64);
            // g2 ≤ 5, so the shifted value is 0 or 1: the mask is all-ones
            // iff h + 5 ≥ 2^130. Only the low 128 bits of the result are
            // used below, which is what "mod 2^128" asks for.
            let mask = 0u64.wrapping_sub(g2 >> 2);
            let h0 = (h0 & !mask) | (g0 & mask);
            let h1 = (h1 & !mask) | (g1 & mask);

            // tag = (h + s) mod 2^128.
            let [p0, p1] = self.pad;
            let t = u128::from(h0).wrapping_add(u128::from(p0));
            let lo = t as u64;
            let hi = h1.wrapping_add(p1).wrapping_add((t >> 64) as u64);
            bytes::store_le64(out, [lo, hi]);
            if MARK { ct::stack_mark() } else { usize::MAX }
        }

        fn wipe(&mut self) {
            ct::wipe_words(&mut self.r);
            ct::wipe_words(&mut self.h);
            ct::wipe_words(&mut self.pad);
        }

        #[cfg(test)]
        fn is_blank(&self) -> bool {
            self.r == [0; 2] && self.h == [0; 3] && self.pad == [0; 2]
        }
    }
}

#[cfg(any(test, not(target_pointer_width = "64")))]
mod narrow {
    //! Radix 2^26.
    use super::{Limbs, bytes, ct, le64_at};

    /// 26-bit limb mask.
    const M26: u64 = 0x03ff_ffff;

    /// Read up to 4 little-endian bytes at `offset`, zero-padding past
    /// the end.
    #[inline]
    fn le32_at(bytes: &[u8], offset: usize) -> u32 {
        let mut tmp = [0u8; 4];
        let src = bytes.get(offset..).unwrap_or(&[]);
        for (d, s) in tmp.iter_mut().zip(src.iter()) {
            *d = *s;
        }
        u32::from_le_bytes(tmp)
    }

    #[derive(Clone)]
    pub(super) struct Limbs26 {
        /// Clamped `r`, radix 2^26.
        r: [u32; 5],
        /// Accumulator, radix 2^26.
        h: [u32; 5],
        /// The `s` half of the key.
        pad: [u32; 4],
    }

    impl Limbs for Limbs26 {
        const BLANK: Self = Self {
            r: [0; 5],
            h: [0; 5],
            pad: [0; 4],
        };

        fn set_key(&mut self, key: &[u8; 32]) {
            // Clamp r: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff.
            let t0 = le64_at(key, 0) & 0x0fff_fffc_0fff_ffff;
            let t1 = le64_at(key, 8) & 0x0fff_fffc_0fff_fffc;
            self.r = [
                (t0 & M26) as u32,
                ((t0 >> 26) & M26) as u32,
                (((t0 >> 52) | (t1 << 12)) & M26) as u32,
                ((t1 >> 14) & M26) as u32,
                ((t1 >> 40) & M26) as u32,
            ];
            self.h = [0; 5];
            self.pad = [
                le32_at(key, 16),
                le32_at(key, 20),
                le32_at(key, 24),
                le32_at(key, 28),
            ];
        }

        #[inline]
        fn blocks<const FULL: bool>(&mut self, data: &[u8]) {
            let hibit = u64::from(FULL) << 24;
            let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
            let s1 = r1.wrapping_mul(5);
            let s2 = r2.wrapping_mul(5);
            let s3 = r3.wrapping_mul(5);
            let s4 = r4.wrapping_mul(5);
            let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h.map(u64::from);
            let m = u64::wrapping_mul;

            let mut rest = data;
            while let Some((block, tail)) = rest.split_first_chunk::<16>() {
                rest = tail;
                let t0 = le64_at(block, 0);
                let t1 = le64_at(block, 8);
                // h += block (with the high bit appended). Limbs stay
                // below 2^27.
                h0 = h0.wrapping_add(t0 & M26);
                h1 = h1.wrapping_add((t0 >> 26) & M26);
                h2 = h2.wrapping_add(((t0 >> 52) | (t1 << 12)) & M26);
                h3 = h3.wrapping_add((t1 >> 14) & M26);
                h4 = h4.wrapping_add((t1 >> 40) | hibit);

                // h *= r (mod 2^130 − 5). Bounds: h0..h4 < 2^27 (h1 may
                // carry an extra 2^10 from the previous block's
                // wrap-around fold, still < 2^27), r < 2^26, s < 2^29:
                // each product < 2^56 and each five-term sum < 2^58.4.
                let d0 = m(h0, r0)
                    .wrapping_add(m(h1, s4))
                    .wrapping_add(m(h2, s3))
                    .wrapping_add(m(h3, s2))
                    .wrapping_add(m(h4, s1));
                let d1 = m(h0, r1)
                    .wrapping_add(m(h1, r0))
                    .wrapping_add(m(h2, s4))
                    .wrapping_add(m(h3, s3))
                    .wrapping_add(m(h4, s2));
                let d2 = m(h0, r2)
                    .wrapping_add(m(h1, r1))
                    .wrapping_add(m(h2, r0))
                    .wrapping_add(m(h3, s4))
                    .wrapping_add(m(h4, s3));
                let d3 = m(h0, r3)
                    .wrapping_add(m(h1, r2))
                    .wrapping_add(m(h2, r1))
                    .wrapping_add(m(h3, r0))
                    .wrapping_add(m(h4, s4));
                let d4 = m(h0, r4)
                    .wrapping_add(m(h1, r3))
                    .wrapping_add(m(h2, r2))
                    .wrapping_add(m(h3, r1))
                    .wrapping_add(m(h4, r0));

                // Carry chain back to < 2^26 (+ epsilon) limbs.
                let mut c = d0 >> 26;
                h0 = d0 & M26;
                let d1 = d1.wrapping_add(c);
                c = d1 >> 26;
                h1 = d1 & M26;
                let d2 = d2.wrapping_add(c);
                c = d2 >> 26;
                h2 = d2 & M26;
                let d3 = d3.wrapping_add(c);
                c = d3 >> 26;
                h3 = d3 & M26;
                let d4 = d4.wrapping_add(c);
                c = d4 >> 26;
                h4 = d4 & M26;
                h0 = h0.wrapping_add(c.wrapping_mul(5));
                c = h0 >> 26;
                h0 &= M26;
                h1 = h1.wrapping_add(c);
            }
            self.h = [h0 as u32, h1 as u32, h2 as u32, h3 as u32, h4 as u32];
        }

        fn tag_into<const MARK: bool>(&self, out: &mut [u8; 16]) -> usize {
            // Fully reduce h mod 2^130 − 5, constant time.
            let [h0, h1, h2, h3, h4] = self.h.map(u64::from);
            let mut c = h1 >> 26;
            let h1 = h1 & M26;
            let h2 = h2.wrapping_add(c);
            c = h2 >> 26;
            let h2 = h2 & M26;
            let h3 = h3.wrapping_add(c);
            c = h3 >> 26;
            let h3 = h3 & M26;
            let h4 = h4.wrapping_add(c);
            c = h4 >> 26;
            let h4 = h4 & M26;
            let h0 = h0.wrapping_add(c.wrapping_mul(5));
            c = h0 >> 26;
            let h0 = h0 & M26;
            let h1 = h1.wrapping_add(c);

            // g = h + 5 − 2^130; select g when h ≥ p (i.e. no borrow).
            let g0 = h0.wrapping_add(5);
            c = g0 >> 26;
            let g0 = g0 & M26;
            let g1 = h1.wrapping_add(c);
            c = g1 >> 26;
            let g1 = g1 & M26;
            let g2 = h2.wrapping_add(c);
            c = g2 >> 26;
            let g2 = g2 & M26;
            let g3 = h3.wrapping_add(c);
            c = g3 >> 26;
            let g3 = g3 & M26;
            let g4 = h4.wrapping_add(c).wrapping_sub(1u64 << 26);

            // mask = all-ones iff g4's sign bit (bit 63 after the wrapping
            // subtraction) is clear, i.e. h ≥ p.
            let mask = (g4 >> 63).wrapping_sub(1);
            let h0 = (h0 & !mask) | (g0 & mask);
            let h1 = (h1 & !mask) | (g1 & mask);
            let h2 = (h2 & !mask) | (g2 & mask);
            let h3 = (h3 & !mask) | (g3 & mask);
            let h4 = (h4 & !mask) | (g4 & mask & M26);

            // Repack to four 32-bit words (h mod 2^128).
            let w0 = (h0 | (h1 << 26)) as u32;
            let w1 = ((h1 >> 6) | (h2 << 20)) as u32;
            let w2 = ((h2 >> 12) | (h3 << 14)) as u32;
            let w3 = ((h3 >> 18) | (h4 << 8)) as u32;

            // tag = (h + s) mod 2^128.
            let [p0, p1, p2, p3] = self.pad;
            let mut f = u64::from(w0).wrapping_add(u64::from(p0));
            let o0 = f as u32;
            f = u64::from(w1)
                .wrapping_add(u64::from(p1))
                .wrapping_add(f >> 32);
            let o1 = f as u32;
            f = u64::from(w2)
                .wrapping_add(u64::from(p2))
                .wrapping_add(f >> 32);
            let o2 = f as u32;
            f = u64::from(w3)
                .wrapping_add(u64::from(p3))
                .wrapping_add(f >> 32);
            let o3 = f as u32;

            bytes::store_le32(out, [o0, o1, o2, o3]);
            if MARK { ct::stack_mark() } else { usize::MAX }
        }

        fn wipe(&mut self) {
            ct::wipe_words(&mut self.r);
            ct::wipe_words(&mut self.h);
            ct::wipe_words(&mut self.pad);
        }

        #[cfg(test)]
        fn is_blank(&self) -> bool {
            self.r == [0; 5] && self.h == [0; 5] && self.pad == [0; 4]
        }
    }
}

/// The limb representation this target uses.
#[cfg(target_pointer_width = "64")]
type Native = wide::Limbs64;
/// The limb representation this target uses.
#[cfg(not(target_pointer_width = "64"))]
type Native = narrow::Limbs26;

/// The streaming logic, over either representation.
#[derive(Clone)]
struct Stream<L: Limbs> {
    limbs: L,
    buf: [u8; 16],
    buf_len: usize,
    /// Is there anything to wipe? Set by `rekey`, cleared by `wipe`, so
    /// that a state which was finished is not wiped a second time when it
    /// is dropped.
    keyed: bool,
}

impl<L: Limbs> Stream<L> {
    const BLANK: Self = Self {
        limbs: L::BLANK,
        buf: [0u8; 16],
        buf_len: 0,
        keyed: false,
    };

    fn rekey(&mut self, key: &[u8; 32]) {
        self.limbs.set_key(key);
        self.buf_len = 0;
        self.keyed = true;
    }

    fn update(&mut self, mut data: &[u8]) {
        // Top up a partial block first.
        if self.buf_len > 0 {
            let space = self.buf.get_mut(self.buf_len..).unwrap_or(&mut []);
            let take = space.len().min(data.len());
            for (d, s) in space.iter_mut().zip(data.iter()) {
                *d = *s;
            }
            self.buf_len = self.buf_len.saturating_add(take);
            data = data.get(take..).unwrap_or(&[]);
            if self.buf_len < 16 {
                // `data` is exhausted; the partial block stays buffered.
                return;
            }
            self.limbs.blocks::<true>(&self.buf);
            self.buf_len = 0;
        }
        // Whole blocks straight from the input, in one call.
        let whole = data.len() & !15;
        let (head, rem) = data.split_at_checked(whole).unwrap_or((&[], data));
        if !head.is_empty() {
            self.limbs.blocks::<true>(head);
        }
        // Stash the tail.
        for (d, s) in self.buf.iter_mut().zip(rem.iter()) {
            *d = *s;
        }
        self.buf_len = rem.len();
    }

    fn update_padded(&mut self, data: &[u8]) {
        self.update(data);
        if self.buf_len != 0 {
            // Zero-fill the buffered tail and absorb it as a full block.
            for b in self.buf.iter_mut().skip(self.buf_len) {
                *b = 0;
            }
            self.limbs.blocks::<true>(&self.buf);
            self.buf_len = 0;
        }
    }

    fn finalize_into<const MARK: bool>(&mut self, out: &mut [u8; 16]) -> usize {
        if self.buf_len > 0 {
            // Final partial block: append 0x01, zero-fill, no high bit.
            for b in self.buf.iter_mut().skip(self.buf_len) {
                *b = 0;
            }
            if let Some(slot) = self.buf.get_mut(self.buf_len) {
                *slot = 1;
            }
            self.limbs.blocks::<false>(&self.buf);
            self.buf_len = 0;
        }
        let low = self.limbs.tag_into::<MARK>(out);
        self.wipe();
        low
    }

    fn wipe(&mut self) {
        if self.keyed {
            self.limbs.wipe();
            ct::wipe(&mut self.buf);
            self.buf_len = 0;
            self.keyed = false;
        }
    }
}

/// Streaming Poly1305.
#[derive(Clone)]
pub struct Poly1305(Stream<Native>);

impl Poly1305 {
    /// Key in the standard `r ∥ s` layout. The caller must never reuse a
    /// key across messages (the AEAD derives a fresh one per nonce).
    ///
    /// The value is returned by move; where the key must not be copied
    /// around, this crate builds the state in place instead
    /// (`Poly1305::blank` and `rekey`, crate-internal).
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let mut p = Self::blank();
        p.rekey(key);
        p
    }

    /// A state without a key: holds nothing secret, and must be given a
    /// key with [`Poly1305::rekey`] before it is used.
    pub(crate) const fn blank() -> Self {
        Self(Stream::BLANK)
    }

    /// Set the key, in place, and start a new message.
    pub(crate) fn rekey(&mut self, key: &[u8; 32]) {
        self.0.rekey(key);
    }

    /// Absorb message bytes.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    /// Absorb `data` and then zero bytes up to the next 16-byte boundary
    /// of the stream (the AEAD's `pad16`, where every padded part starts
    /// on such a boundary).
    pub fn update_padded(&mut self, data: &[u8]) -> &mut Self {
        self.0.update_padded(data);
        self
    }

    /// Finish: write the tag to `out` and wipe the key-derived state.
    /// Nothing is returned by value, so no copy of the tag exists but the
    /// one in `out`. The state needs a new key before it can be used
    /// again.
    pub fn finalize_into(&mut self, out: &mut [u8; 16]) {
        let _ = self.0.finalize_into::<false>(out);
    }

    /// [`Self::finalize_into`], which also says where the stack ends
    /// beneath the frame the tag was put together in. For the AEAD: a
    /// tag that does not match what a datagram carries is the one thing
    /// its forger lacked, and what the arithmetic left of it on the way
    /// to `out` is overwritten ([`ct::scrub_stack_to`]).
    pub(crate) fn finalize_into_marked(&mut self, out: &mut [u8; 16]) -> usize {
        self.0.finalize_into::<true>(out)
    }

    /// Finish and produce the tag. This takes the state by value, which
    /// may copy it once more on the way in (the copy is wiped, what it
    /// was copied from is not): prefer [`Poly1305::finalize_into`] where
    /// that matters.
    #[must_use]
    #[inline]
    pub fn finalize(mut self) -> [u8; 16] {
        let mut tag = [0u8; 16];
        self.finalize_into(&mut tag);
        tag
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        // Wipe everything key-derived whether or not a `finalize` ran, so
        // a `Poly1305` abandoned mid-stream leaves nothing behind.
        self.0.wipe();
    }
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Poly1305 { .. }")
    }
}

/// One-shot tag over a single byte string.
#[must_use]
pub fn poly1305(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    // Keyed, used and wiped where it stands: `new` and `finalize` would
    // move the state, and a move leaves the bytes it copied from behind.
    let mut p = Poly1305::blank();
    p.rekey(key);
    p.update(data);
    let mut tag = [0u8; 16];
    p.finalize_into(&mut tag);
    tag
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
    use std::vec;
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8439_basic_vector() {
        // RFC 8439 §2.5.2.
        let key: [u8; 32] =
            unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .try_into()
                .unwrap();
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(tag.as_slice(), unhex("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    // ----- slow reference implementation ---------------------------------
    // Schoolbook arithmetic in base 2^32 with explicit reduction mod
    // 2^130-5: deliberately naive so it is easy to check by inspection, used to verify
    // the limb implementation on attacker-crafted inputs.

    /// Little-endian base-2^32 digits.
    type Big = Vec<u64>;

    fn big_from_le_bytes(bytes: &[u8]) -> Big {
        let mut digits = vec![0u64; bytes.len().div_ceil(4)];
        for (i, b) in bytes.iter().enumerate() {
            digits[i / 4] |= u64::from(*b) << (8 * (i % 4));
        }
        digits
    }

    fn big_normalize(a: &mut Big) {
        let mut carry = 0u64;
        for d in a.iter_mut() {
            let v = *d + carry;
            *d = v & 0xffff_ffff;
            carry = v >> 32;
        }
        while carry > 0 {
            a.push(carry & 0xffff_ffff);
            carry >>= 32;
        }
        while a.last() == Some(&0) {
            a.pop();
        }
    }

    fn big_add(a: &Big, b: &Big) -> Big {
        let mut out = vec![0u64; a.len().max(b.len())];
        for (i, o) in out.iter_mut().enumerate() {
            *o = a.get(i).copied().unwrap_or(0) + b.get(i).copied().unwrap_or(0);
        }
        big_normalize(&mut out);
        out
    }

    fn big_mul(a: &Big, b: &Big) -> Big {
        if a.is_empty() || b.is_empty() {
            return Vec::new();
        }
        let mut acc = vec![0u128; a.len() + b.len()];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                acc[i + j] += u128::from(*x) * u128::from(*y);
            }
        }
        // Propagate 128-bit columns into 32-bit digits.
        let mut out = vec![0u64; acc.len() + 2];
        let mut carry = 0u128;
        for (i, col) in acc.iter().enumerate() {
            let v = col + carry;
            out[i] = (v & 0xffff_ffff) as u64;
            carry = v >> 32;
        }
        let mut i = acc.len();
        while carry > 0 {
            out[i] = (carry & 0xffff_ffff) as u64;
            carry >>= 32;
            i += 1;
        }
        big_normalize(&mut out);
        out
    }

    fn big_bit_len(a: &Big) -> usize {
        match a.last() {
            None => 0,
            Some(top) => (a.len() - 1) * 32 + (64 - top.leading_zeros() as usize),
        }
    }

    fn big_shift_right_130(a: &Big) -> Big {
        // floor(a / 2^130): drop 4 whole digits (128 bits) then 2 more bits.
        let mut out: Big = a.iter().skip(4).copied().collect();
        let mut prev = 0u64;
        for d in out.iter_mut().rev() {
            let v = *d;
            *d = (v >> 2) | ((prev & 0b11) << 30);
            prev = v;
        }
        while out.last() == Some(&0) {
            out.pop();
        }
        out
    }

    fn big_low_130(a: &Big) -> Big {
        let mut out: Big = a.iter().take(5).copied().collect();
        if let Some(top) = out.get_mut(4) {
            *top &= 0b11; // keep bits 128..130
        }
        while out.last() == Some(&0) {
            out.pop();
        }
        out
    }

    fn big_ge(a: &Big, b: &Big) -> bool {
        if a.len() != b.len() {
            return a.len() > b.len();
        }
        for (x, y) in a.iter().rev().zip(b.iter().rev()) {
            if x != y {
                return x > y;
            }
        }
        true
    }

    fn big_sub(a: &Big, b: &Big) -> Big {
        // requires a >= b
        let mut out = vec![0u64; a.len()];
        let mut borrow = 0i64;
        for (i, o) in out.iter_mut().enumerate() {
            let mut v = a[i] as i64 - b.get(i).copied().unwrap_or(0) as i64 - borrow;
            if v < 0 {
                v += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            *o = v as u64;
        }
        assert_eq!(borrow, 0);
        while out.last() == Some(&0) {
            out.pop();
        }
        out
    }

    fn p130() -> Big {
        // 2^130 - 5
        let mut p = vec![0u64; 5];
        p[4] = 0b100;
        let five = vec![5u64];
        big_sub(&p, &five)
    }

    fn big_mod_p(mut a: Big) -> Big {
        let p = p130();
        let five = vec![5u64];
        while big_bit_len(&a) > 130 {
            let hi = big_shift_right_130(&a);
            let lo = big_low_130(&a);
            a = big_add(&lo, &big_mul(&hi, &five));
        }
        while !a.is_empty() && big_ge(&a, &p) {
            a = big_sub(&a, &p);
        }
        a
    }

    fn poly1305_slow(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        let mut r_bytes: [u8; 16] = key[..16].try_into().unwrap();
        // clamp
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;
        let r = big_from_le_bytes(&r_bytes);
        let s = big_from_le_bytes(&key[16..]);

        let mut acc: Big = Vec::new();
        for chunk in msg.chunks(16) {
            let mut n = chunk.to_vec();
            n.push(0x01);
            let n = big_from_le_bytes(&n);
            acc = big_mod_p(big_mul(&big_add(&acc, &n), &r));
        }
        let mut acc = big_add(&acc, &s);
        acc.resize(4, 0); // truncate mod 2^128 / pad
        let mut tag = [0u8; 16];
        for (i, d) in acc.iter().take(4).enumerate() {
            tag[i * 4..i * 4 + 4].copy_from_slice(&(*d as u32).to_le_bytes());
        }
        tag
    }

    #[test]
    fn slow_model_reproduces_rfc_vector() {
        let key: [u8; 32] =
            unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .try_into()
                .unwrap();
        let tag = poly1305_slow(&key, b"Cryptographic Forum Research Group");
        assert_eq!(tag.as_slice(), unhex("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    /// Deterministic test PRNG (splitmix64).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let v = self.next().to_le_bytes();
                for (d, s) in chunk.iter_mut().zip(v.iter()) {
                    *d = *s;
                }
            }
        }
    }

    #[test]
    fn fast_matches_slow_model_on_random_and_crafted_inputs() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        // Random keys/messages at every length 0..=64 plus longer ones.
        for len in (0..=400).chain([511, 512, 513, 1024, 1280, 1420, 1424, 4096]) {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            let mut msg = vec![0u8; len];
            rng.fill(&mut msg);
            assert_eq!(poly1305(&key, &msg), poly1305_slow(&key, &msg), "len={len}");
        }
        // Crafted corners: maximal r/s/message bytes, zero key, sparse
        // patterns that maximize carries.
        let specials: [[u8; 32]; 4] = [
            [0xff; 32],
            [0x00; 32],
            {
                let mut k = [0u8; 32];
                k[0] = 0xff;
                k[15] = 0xff;
                k[16] = 0xff;
                k[31] = 0xff;
                k
            },
            {
                let mut k = [0xffu8; 32];
                k[..16].copy_from_slice(&[0x02; 16]);
                k
            },
        ];
        for key in &specials {
            for msg_byte in [0x00u8, 0x01, 0xfe, 0xff] {
                for len in [
                    0usize, 1, 15, 16, 17, 32, 48, 64, 96, 128, 129, 191, 192, 255, 256, 257, 1024,
                    1425,
                ] {
                    let msg = vec![msg_byte; len];
                    assert_eq!(
                        poly1305(key, &msg),
                        poly1305_slow(key, &msg),
                        "key={key:02x?} byte={msg_byte:02x} len={len}"
                    );
                }
            }
        }
    }

    #[test]
    fn streaming_equals_oneshot() {
        let mut rng = Rng(42);
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let mut msg = [0u8; 100];
        rng.fill(&mut msg);
        let oneshot = poly1305(&key, &msg);
        for split in 0..=100 {
            let mut p = Poly1305::new(&key);
            p.update(&msg[..split]).update(&msg[split..]);
            assert_eq!(p.finalize(), oneshot, "split={split}");
        }
        // Byte at a time.
        let mut p = Poly1305::new(&key);
        for b in &msg {
            p.update(core::slice::from_ref(b));
        }
        assert_eq!(p.finalize(), oneshot);
    }

    #[test]
    fn update_padded_pads_to_block_boundary() {
        let key = [9u8; 32];
        let data = [0xabu8; 21];
        let mut a = Poly1305::new(&key);
        a.update_padded(&data);
        let mut b = Poly1305::new(&key);
        b.update(&data).update(&[0u8; 11]);
        assert_eq!(a.finalize(), b.finalize());
        // Already aligned: no padding added.
        let data = [0xabu8; 32];
        let mut a = Poly1305::new(&key);
        a.update_padded(&data);
        let mut b = Poly1305::new(&key);
        b.update(&data);
        assert_eq!(a.finalize(), b.finalize());
        // Entered off a block boundary (the AEAD never does): it still
        // pads to the next boundary of the stream, in every build.
        let data = [0xabu8; 21];
        let mut a = Poly1305::new(&key);
        a.update(&[1, 2, 3]).update_padded(&data);
        let mut b = Poly1305::new(&key);
        b.update(&[1, 2, 3]).update(&data).update(&[0u8; 8]);
        assert_eq!(a.finalize(), b.finalize());
    }

    /// A tag computed by one limb representation, with the message fed in
    /// pieces cut at `cuts`.
    fn tag_with<L: Limbs>(key: &[u8; 32], msg: &[u8], cuts: &[usize]) -> [u8; 16] {
        let mut stream = Stream::<L>::BLANK;
        stream.rekey(key);
        let mut at = 0;
        for &cut in cuts {
            let cut = cut.clamp(at, msg.len());
            stream.update(&msg[at..cut]);
            at = cut;
        }
        stream.update(&msg[at..]);
        let mut tag = [0u8; 16];
        stream.finalize_into::<false>(&mut tag);
        assert!(
            stream.limbs.is_blank() && stream.buf == [0u8; 16],
            "state not wiped"
        );
        tag
    }

    /// Both representations are built in a test build whatever the
    /// target, and must agree with each other and with the model: on
    /// random inputs of every length around the block and packet sizes,
    /// fed whole and in pieces.
    #[test]
    fn both_limb_representations_agree_with_each_other_and_the_model() {
        let mut rng = Rng(0x5eed_0f2a_1100);
        for len in (0..=400).chain([511, 512, 513, 1024, 1280, 1420, 1424, 1425, 4096, 9000]) {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            let mut msg = vec![0u8; len];
            rng.fill(&mut msg);
            if len % 7 == 3 {
                msg.fill(0xff);
            }
            let cuts = [
                (rng.next() % 40) as usize,
                (rng.next() % 400) as usize,
                (rng.next() % 2000) as usize,
            ];
            let wide_whole = tag_with::<wide::Limbs64>(&key, &msg, &[]);
            let narrow_whole = tag_with::<narrow::Limbs26>(&key, &msg, &[]);
            assert_eq!(wide_whole, narrow_whole, "len={len}");
            assert_eq!(
                tag_with::<wide::Limbs64>(&key, &msg, &cuts),
                wide_whole,
                "len={len} {cuts:?}"
            );
            assert_eq!(
                tag_with::<narrow::Limbs26>(&key, &msg, &cuts),
                wide_whole,
                "len={len} {cuts:?}"
            );
            assert_eq!(poly1305(&key, &msg), wide_whole, "len={len}");
            if len <= 1425 {
                assert_eq!(wide_whole, poly1305_slow(&key, &msg), "len={len}");
            }
        }
    }

    /// The final reduction at its edges. With `r = 1` the accumulator is
    /// the plain sum of the blocks (each with its 2^128 bit), so three
    /// blocks can be chosen to land it on any value around `p = 2^130 − 5`
    /// and around 2^130; `r = 2` and `r = 4` put the same sums through the
    /// carries of the multiplication.
    #[test]
    fn final_reduction_at_the_edges_of_the_field() {
        // Three blocks sum to 3·2^128 + (b0 + b1 + b2); b0 = 2^128 − 1 − d,
        // b1 = e, b2 = 0 gives 2^130 − 1 − d + e.
        for r in [1u8, 2, 4] {
            for d in 0u8..=12 {
                for e in 0u8..=12 {
                    for s_byte in [0x00u8, 0xff] {
                        let mut key = [s_byte; 32];
                        key[..16].fill(0);
                        key[0] = r;
                        let mut msg = [0u8; 48];
                        msg[..16].fill(0xff);
                        msg[0] = 0xff - d;
                        msg[16] = e;
                        let want = poly1305_slow(&key, &msg);
                        assert_eq!(
                            tag_with::<wide::Limbs64>(&key, &msg, &[]),
                            want,
                            "r={r} d={d} e={e}"
                        );
                        assert_eq!(
                            tag_with::<narrow::Limbs26>(&key, &msg, &[]),
                            want,
                            "r={r} d={d} e={e}"
                        );
                        // The same sum with a short final block in play.
                        let mut tail = msg.to_vec();
                        tail.extend_from_slice(&[e, d, 0xff]);
                        let want = poly1305_slow(&key, &tail);
                        assert_eq!(tag_with::<wide::Limbs64>(&key, &tail, &[17]), want);
                        assert_eq!(tag_with::<narrow::Limbs26>(&key, &tail, &[17]), want);
                    }
                }
            }
        }
        // All-ones everything: the largest accumulators either
        // representation sees between blocks.
        for len in [16usize, 32, 64, 256, 1024] {
            let msg = vec![0xffu8; len];
            let want = poly1305_slow(&[0xff; 32], &msg);
            assert_eq!(
                tag_with::<wide::Limbs64>(&[0xff; 32], &msg, &[]),
                want,
                "len={len}"
            );
            assert_eq!(
                tag_with::<narrow::Limbs26>(&[0xff; 32], &msg, &[]),
                want,
                "len={len}"
            );
        }
    }

    /// `finalize_into` leaves no key-derived state behind, and a state
    /// can be keyed again in place.
    #[test]
    fn finalize_into_wipes_and_the_state_can_be_rekeyed() {
        let key = [7u8; 32];
        let mut p = Poly1305::blank();
        p.rekey(&key);
        p.update(b"some message, longer than one block");
        let mut tag = [0u8; 16];
        p.finalize_into(&mut tag);
        assert_eq!(tag, poly1305(&key, b"some message, longer than one block"));
        assert!(p.0.limbs.is_blank() && p.0.buf == [0u8; 16] && p.0.buf_len == 0);
        let other = [9u8; 32];
        p.rekey(&other);
        p.update(b"x");
        p.finalize_into(&mut tag);
        assert_eq!(tag, poly1305(&other, b"x"));
    }
}
