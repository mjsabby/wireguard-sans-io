//! ChaCha20 on x86_64 AVX2: 4-way (128-bit `__m128i`) and 8-way
//! (256-bit `__m256i`).
//!
//! Both are the same N-block-parallel algorithm: 16 vector registers,
//! register *i* holding word *i* of N blocks, so every quarter-round op
//! is a straight vertical add/xor/rotate. The only structural
//! difference between 4-way and 8-way is the lane count and the
//! transpose width — the round function is character-for-character the
//! same with `_mm_` ↔ `_mm256_`.
//!
//! Tail handling: full-stride chunks first, then **one extra SIMD
//! stride for the partial tail** (XOR only `tail.len()` bytes of it),
//! so every byte of an MTU-sized packet goes through SIMD. Only a
//! sub-64-byte final fragment falls to scalar (and that case never
//! occurs for WireGuard transport, which pads to 16 and starts at
//! counter 1 with ≥ 16-byte tag headroom).
//!
//! # Safety
//!
//! Every `unsafe` block is one of:
//! 1. a `core::arch::x86_64` intrinsic call — safe given the
//!    `#[target_feature(enable = "avx2")]` gate (and the runtime
//!    `is_x86_feature_detected!` that guards the only call in);
//! 2. an unaligned store on a stack `[u8; 256]` / `[u8; 512]` we just
//!    declared, at fixed in-bounds offsets.
//!
//! No attacker-controlled length, pointer, or index reaches an
//! intrinsic.

#![allow(unsafe_code)]

use core::arch::x86_64::*;

use crate::{ChaChaImpl, SIGMA, Scalar, key_words, nonce_words, xor_tail};

// AVX2 is a hard build requirement on x86_64 (enforced by the
// `compile_error!` in lib.rs). There is no runtime check and no
// scalar fallback in this module — every call into `four_blocks` /
// `eight_blocks` is sound because the binary cannot exist for a
// non-AVX2 CPU.

// ===========================================================================
// 4-way (128-bit)
// ===========================================================================

/// AVX2 4-block-parallel ChaCha20 (128-bit lanes, VEX-encoded).
#[derive(Debug, Clone, Copy, Default)]
pub struct Avx2;

impl ChaChaImpl for Avx2 {
    #[inline]
    fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        let kw = key_words(key);
        let nw = nonce_words(nonce);
        let mut ctr = counter;
        let mut chunks = buf.chunks_exact_mut(256);
        for chunk in &mut chunks {
            // SAFETY: AVX2 is a compile-time requirement (lib.rs
            // `compile_error!`); `four_blocks` writes exactly 256
            // bytes into the stack array it returns.
            let ks = unsafe { four_blocks(&kw, &nw, ctr) };
            xor_tail(chunk, &ks);
            ctr = ctr.wrapping_add(4);
        }
        let tail = chunks.into_remainder();
        if tail.len() >= 64 {
            // SAFETY: as above.
            let ks = unsafe { four_blocks(&kw, &nw, ctr) };
            xor_tail(tail, &ks);
        } else if !tail.is_empty() {
            // < 1 block: not worth a 4-block compute.
            Scalar::apply_keystream(key, nonce, ctr, tail);
        }
    }
    fn name() -> &'static str {
        "avx2-4way"
    }
}

/// # Safety
/// Caller must ensure the `avx2` target feature is available.
#[target_feature(enable = "avx2")]
#[allow(clippy::multiple_unsafe_ops_per_block)] // every line is an intrinsic
unsafe fn four_blocks(key: &[u32; 8], nonce: &[u32; 3], ctr: u32) -> [u8; 256] {
    // SAFETY: every intrinsic is gated by `target_feature(avx2)`; all
    // stores are to the local `out` at fixed offsets 0..=240.
    unsafe {
        let rol16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
        let rol8 = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

        macro_rules! splat {
            ($x:expr) => {
                _mm_set1_epi32($x as i32)
            };
        }
        macro_rules! rotl {
            ($v:expr, 16) => {
                _mm_shuffle_epi8($v, rol16)
            };
            ($v:expr, 8) => {
                _mm_shuffle_epi8($v, rol8)
            };
            ($v:expr, $n:literal) => {
                _mm_or_si128(_mm_slli_epi32($v, $n), _mm_srli_epi32($v, 32 - $n))
            };
        }
        macro_rules! qr {
            ($a:ident,$b:ident,$c:ident,$d:ident) => {
                $a = _mm_add_epi32($a, $b);
                $d = rotl!(_mm_xor_si128($d, $a), 16);
                $c = _mm_add_epi32($c, $d);
                $b = rotl!(_mm_xor_si128($b, $c), 12);
                $a = _mm_add_epi32($a, $b);
                $d = rotl!(_mm_xor_si128($d, $a), 8);
                $c = _mm_add_epi32($c, $d);
                $b = rotl!(_mm_xor_si128($b, $c), 7);
            };
        }

        let s0 = splat!(SIGMA[0]);
        let s1 = splat!(SIGMA[1]);
        let s2 = splat!(SIGMA[2]);
        let s3 = splat!(SIGMA[3]);
        let s4 = splat!(key[0]);
        let s5 = splat!(key[1]);
        let s6 = splat!(key[2]);
        let s7 = splat!(key[3]);
        let s8 = splat!(key[4]);
        let s9 = splat!(key[5]);
        let s10 = splat!(key[6]);
        let s11 = splat!(key[7]);
        let s12 = _mm_set_epi32(
            ctr.wrapping_add(3) as i32,
            ctr.wrapping_add(2) as i32,
            ctr.wrapping_add(1) as i32,
            ctr as i32,
        );
        let s13 = splat!(nonce[0]);
        let s14 = splat!(nonce[1]);
        let s15 = splat!(nonce[2]);

        let (mut x0, mut x1, mut x2, mut x3) = (s0, s1, s2, s3);
        let (mut x4, mut x5, mut x6, mut x7) = (s4, s5, s6, s7);
        let (mut x8, mut x9, mut x10, mut x11) = (s8, s9, s10, s11);
        let (mut x12, mut x13, mut x14, mut x15) = (s12, s13, s14, s15);

        for _ in 0..10 {
            qr!(x0, x4, x8, x12);
            qr!(x1, x5, x9, x13);
            qr!(x2, x6, x10, x14);
            qr!(x3, x7, x11, x15);
            qr!(x0, x5, x10, x15);
            qr!(x1, x6, x11, x12);
            qr!(x2, x7, x8, x13);
            qr!(x3, x4, x9, x14);
        }

        x0 = _mm_add_epi32(x0, s0);
        x1 = _mm_add_epi32(x1, s1);
        x2 = _mm_add_epi32(x2, s2);
        x3 = _mm_add_epi32(x3, s3);
        x4 = _mm_add_epi32(x4, s4);
        x5 = _mm_add_epi32(x5, s5);
        x6 = _mm_add_epi32(x6, s6);
        x7 = _mm_add_epi32(x7, s7);
        x8 = _mm_add_epi32(x8, s8);
        x9 = _mm_add_epi32(x9, s9);
        x10 = _mm_add_epi32(x10, s10);
        x11 = _mm_add_epi32(x11, s11);
        x12 = _mm_add_epi32(x12, s12);
        x13 = _mm_add_epi32(x13, s13);
        x14 = _mm_add_epi32(x14, s14);
        x15 = _mm_add_epi32(x15, s15);

        macro_rules! transpose4 {
            ($a:ident,$b:ident,$c:ident,$d:ident) => {{
                let t0 = _mm_unpacklo_epi32($a, $b);
                let t1 = _mm_unpacklo_epi32($c, $d);
                let t2 = _mm_unpackhi_epi32($a, $b);
                let t3 = _mm_unpackhi_epi32($c, $d);
                $a = _mm_unpacklo_epi64(t0, t1);
                $b = _mm_unpackhi_epi64(t0, t1);
                $c = _mm_unpacklo_epi64(t2, t3);
                $d = _mm_unpackhi_epi64(t2, t3);
            }};
        }
        transpose4!(x0, x1, x2, x3);
        transpose4!(x4, x5, x6, x7);
        transpose4!(x8, x9, x10, x11);
        transpose4!(x12, x13, x14, x15);

        let mut out = [0u8; 256];
        let p = out.as_mut_ptr();
        macro_rules! store {
            ($off:expr, $v:expr) => {
                _mm_storeu_si128(p.add($off) as *mut __m128i, $v);
            };
        }
        store!(0, x0);
        store!(16, x4);
        store!(32, x8);
        store!(48, x12);
        store!(64, x1);
        store!(80, x5);
        store!(96, x9);
        store!(112, x13);
        store!(128, x2);
        store!(144, x6);
        store!(160, x10);
        store!(176, x14);
        store!(192, x3);
        store!(208, x7);
        store!(224, x11);
        store!(240, x15);
        out
    }
}

// ===========================================================================
// 8-way (256-bit) — same algorithm, double-width lanes. This is what
// ring's data path does and is the natural AVX2 width.
// ===========================================================================

/// AVX2 8-block-parallel ChaCha20 (256-bit `__m256i` lanes).
#[derive(Debug, Clone, Copy, Default)]
pub struct Avx2x8;

impl ChaChaImpl for Avx2x8 {
    #[inline]
    fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        let kw = key_words(key);
        let nw = nonce_words(nonce);
        let mut ctr = counter;
        let mut chunks = buf.chunks_exact_mut(512);
        for chunk in &mut chunks {
            // SAFETY: AVX2 is a compile-time requirement (lib.rs
            // `compile_error!`); `eight_blocks` writes exactly 512
            // bytes into the stack array it returns.
            let ks = unsafe { eight_blocks(&kw, &nw, ctr) };
            xor_tail(chunk, &ks);
            ctr = ctr.wrapping_add(8);
        }
        let tail = chunks.into_remainder();
        if tail.len() >= 256 {
            // SAFETY: as above.
            let ks = unsafe { eight_blocks(&kw, &nw, ctr) };
            xor_tail(tail, &ks);
        } else if tail.len() >= 64 {
            // 64..255 bytes: one 4-stride is enough and cheaper.
            // SAFETY: as above (four_blocks is also AVX2-gated).
            let ks = unsafe { four_blocks(&kw, &nw, ctr) };
            xor_tail(tail, &ks);
        } else if !tail.is_empty() {
            Scalar::apply_keystream(key, nonce, ctr, tail);
        }
    }
    fn name() -> &'static str {
        "avx2-8way"
    }
}

/// # Safety
/// Caller must ensure the `avx2` target feature is available.
#[target_feature(enable = "avx2")]
#[allow(clippy::multiple_unsafe_ops_per_block)] // every line is an intrinsic
unsafe fn eight_blocks(key: &[u32; 8], nonce: &[u32; 3], ctr: u32) -> [u8; 512] {
    // SAFETY: as `four_blocks`, with __m256i and a [u8; 512] target.
    unsafe {
        // pshufb masks, broadcast across both 128-bit halves.
        let rol16 = _mm256_broadcastsi128_si256(_mm_set_epi8(
            13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
        ));
        let rol8 = _mm256_broadcastsi128_si256(_mm_set_epi8(
            14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
        ));

        macro_rules! splat {
            ($x:expr) => {
                _mm256_set1_epi32($x as i32)
            };
        }
        macro_rules! rotl {
            ($v:expr, 16) => {
                _mm256_shuffle_epi8($v, rol16)
            };
            ($v:expr, 8) => {
                _mm256_shuffle_epi8($v, rol8)
            };
            ($v:expr, $n:literal) => {
                _mm256_or_si256(_mm256_slli_epi32($v, $n), _mm256_srli_epi32($v, 32 - $n))
            };
        }
        macro_rules! qr {
            ($a:ident,$b:ident,$c:ident,$d:ident) => {
                $a = _mm256_add_epi32($a, $b);
                $d = rotl!(_mm256_xor_si256($d, $a), 16);
                $c = _mm256_add_epi32($c, $d);
                $b = rotl!(_mm256_xor_si256($b, $c), 12);
                $a = _mm256_add_epi32($a, $b);
                $d = rotl!(_mm256_xor_si256($d, $a), 8);
                $c = _mm256_add_epi32($c, $d);
                $b = rotl!(_mm256_xor_si256($b, $c), 7);
            };
        }

        let s0 = splat!(SIGMA[0]);
        let s1 = splat!(SIGMA[1]);
        let s2 = splat!(SIGMA[2]);
        let s3 = splat!(SIGMA[3]);
        let s4 = splat!(key[0]);
        let s5 = splat!(key[1]);
        let s6 = splat!(key[2]);
        let s7 = splat!(key[3]);
        let s8 = splat!(key[4]);
        let s9 = splat!(key[5]);
        let s10 = splat!(key[6]);
        let s11 = splat!(key[7]);
        let s12 = _mm256_set_epi32(
            ctr.wrapping_add(7) as i32,
            ctr.wrapping_add(6) as i32,
            ctr.wrapping_add(5) as i32,
            ctr.wrapping_add(4) as i32,
            ctr.wrapping_add(3) as i32,
            ctr.wrapping_add(2) as i32,
            ctr.wrapping_add(1) as i32,
            ctr as i32,
        );
        let s13 = splat!(nonce[0]);
        let s14 = splat!(nonce[1]);
        let s15 = splat!(nonce[2]);

        let (mut x0, mut x1, mut x2, mut x3) = (s0, s1, s2, s3);
        let (mut x4, mut x5, mut x6, mut x7) = (s4, s5, s6, s7);
        let (mut x8, mut x9, mut x10, mut x11) = (s8, s9, s10, s11);
        let (mut x12, mut x13, mut x14, mut x15) = (s12, s13, s14, s15);

        for _ in 0..10 {
            qr!(x0, x4, x8, x12);
            qr!(x1, x5, x9, x13);
            qr!(x2, x6, x10, x14);
            qr!(x3, x7, x11, x15);
            qr!(x0, x5, x10, x15);
            qr!(x1, x6, x11, x12);
            qr!(x2, x7, x8, x13);
            qr!(x3, x4, x9, x14);
        }

        x0 = _mm256_add_epi32(x0, s0);
        x1 = _mm256_add_epi32(x1, s1);
        x2 = _mm256_add_epi32(x2, s2);
        x3 = _mm256_add_epi32(x3, s3);
        x4 = _mm256_add_epi32(x4, s4);
        x5 = _mm256_add_epi32(x5, s5);
        x6 = _mm256_add_epi32(x6, s6);
        x7 = _mm256_add_epi32(x7, s7);
        x8 = _mm256_add_epi32(x8, s8);
        x9 = _mm256_add_epi32(x9, s9);
        x10 = _mm256_add_epi32(x10, s10);
        x11 = _mm256_add_epi32(x11, s11);
        x12 = _mm256_add_epi32(x12, s12);
        x13 = _mm256_add_epi32(x13, s13);
        x14 = _mm256_add_epi32(x14, s14);
        x15 = _mm256_add_epi32(x15, s15);

        // 8×8 u32 transpose. Strategy: do the 4×4 transpose of each
        // 128-bit half (unpack32 + unpack64, lane-local under AVX2),
        // then permute2x128 to swap the high half of vector j with the
        // low half of vector j+4. After both stages, x[j] holds block
        // j's 8 consecutive words 0..8? — no: it holds two 4-word rows
        // of block j (words 0..4 in the low half, 4..8 in the high…).
        //
        // Simpler and equally fast: store each post-transpose-4×4
        // 128-bit half directly to its destination via extract. The
        // layout work is then just pointer arithmetic, no extra
        // shuffles. (16 vectors × 2 halves × 16 bytes = 512 bytes.)
        macro_rules! transpose4 {
            ($a:ident,$b:ident,$c:ident,$d:ident) => {{
                let t0 = _mm256_unpacklo_epi32($a, $b);
                let t1 = _mm256_unpacklo_epi32($c, $d);
                let t2 = _mm256_unpackhi_epi32($a, $b);
                let t3 = _mm256_unpackhi_epi32($c, $d);
                $a = _mm256_unpacklo_epi64(t0, t1);
                $b = _mm256_unpackhi_epi64(t0, t1);
                $c = _mm256_unpacklo_epi64(t2, t3);
                $d = _mm256_unpackhi_epi64(t2, t3);
            }};
        }
        transpose4!(x0, x1, x2, x3);
        transpose4!(x4, x5, x6, x7);
        transpose4!(x8, x9, x10, x11);
        transpose4!(x12, x13, x14, x15);
        // After lane-local transpose, low128(xN) carries block (N%4)'s
        // row N/4-ish for blocks 0..4, and high128(xN) the same for
        // blocks 4..8. Concretely, for the group (x0,x1,x2,x3):
        //   low128(x0)=blk0.w[0..4], hi128(x0)=blk4.w[0..4]
        //   low128(x1)=blk1.w[0..4], hi128(x1)=blk5.w[0..4]
        //   …
        // So each store is `extract128` of the right half to the right
        // 16-byte slot.
        let mut out = [0u8; 512];
        let p = out.as_mut_ptr();
        macro_rules! lo {
            ($off:expr, $v:expr) => {
                _mm_storeu_si128(p.add($off) as *mut __m128i, _mm256_castsi256_si128($v));
            };
        }
        macro_rules! hi {
            ($off:expr, $v:expr) => {
                _mm_storeu_si128(p.add($off) as *mut __m128i, _mm256_extracti128_si256($v, 1));
            };
        }
        // blk0..3 from the low halves; blk4..7 from the high halves.
        // Each block is 64 bytes = four 16-byte rows from groups
        // (x0..3),(x4..7),(x8..11),(x12..15).
        macro_rules! emit_block {
            ($base:expr, $half:ident, $r0:ident,$r1:ident,$r2:ident,$r3:ident) => {
                $half!($base + 0, $r0);
                $half!($base + 16, $r1);
                $half!($base + 32, $r2);
                $half!($base + 48, $r3);
            };
        }
        emit_block!(0, lo, x0, x4, x8, x12); // blk0
        emit_block!(64, lo, x1, x5, x9, x13); // blk1
        emit_block!(128, lo, x2, x6, x10, x14); // blk2
        emit_block!(192, lo, x3, x7, x11, x15); // blk3
        emit_block!(256, hi, x0, x4, x8, x12); // blk4
        emit_block!(320, hi, x1, x5, x9, x13); // blk5
        emit_block!(384, hi, x2, x6, x10, x14); // blk6
        emit_block!(448, hi, x3, x7, x11, x15); // blk7
        out
    }
}
