//! ChaCha20 4-way on AArch64 NEON.
//!
//! Identical algorithm to `avx2.rs`: 16 × `uint32x4_t`, register *i*
//! holds word *i* of four blocks. NEON is mandatory on AArch64, so
//! there's no runtime feature check — `apply_keystream` calls straight
//! into `four_blocks`.
//!
//! Rotations: 16-bit via `vrev32q_u16` (free byte-swap), 8-bit via
//! `vqtbl1q_u8`, 12/7-bit via `vsli`+`vshr` (shift-left-and-insert).
//!
//! # What is left behind
//!
//! Nothing that is the key or the keystream: the key words unpacked
//! here and the stack buffer the keystream goes through are zeroed
//! before a call returns, and so is the kernel's whole stack frame,
//! where the compiler parks registers it has no room for — its caller
//! overwrites it after the last stride (`clear_frames`, see the crate
//! documentation).
//!
//! # Safety
//!
//! Every `unsafe` block is a `core::arch::aarch64` intrinsic call. NEON
//! is architecturally guaranteed on AArch64, so the only obligation is
//! "don't read/write out of bounds" — and the only memory ops are
//! `vst1q_u8` into the `[u8; 256]` the kernel is handed by reference, at
//! fixed offsets 0, 16, …, 240.

#![allow(unsafe_code)]

use core::arch::aarch64::*;

use wireguard_sans_io::crypto::ct;

use crate::{ChaChaImpl, SIGMA, Scalar, clear_frames, load_key_words, nonce_words, xor_tail};

/// What [`clear_frames`] overwrites at once after the kernel, in 64-bit
/// words.
const KERNEL_FRAME: usize = 112;

/// NEON 4-block-parallel ChaCha20.
///
/// 128-bit lanes are the architectural width on AArch64 — there is no
/// "8-way NEON" in the AVX2 sense. ARMv9 SVE2 (e.g. Pixel 9 / Tensor G4)
/// is also 128-bit on current Android silicon, so this *is* the
/// wide-as-it-gets path for that target. The "in-spirit-same" change
/// vs the AVX2 8-way upgrade is the **partial-tail** fix below: one
/// extra 4-block stride covers any 64..255-byte remainder, so an
/// MTU-sized packet is 100% NEON.
#[derive(Debug, Clone, Copy, Default)]
pub struct Neon;

impl ChaChaImpl for Neon {
    #[inline]
    fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        let mut kw = [0u32; 8];
        load_key_words(key, &mut kw);
        let nw = nonce_words(nonce);
        let mut ctr = counter;
        // How far down the kernel's frame went (see `clear_frames`).
        let mut low = usize::MAX;
        // One buffer for every stride: it holds keystream, and is wiped
        // once at the end.
        let mut ks = [0u8; 256];
        let mut chunks = buf.chunks_exact_mut(256);
        for chunk in &mut chunks {
            // SAFETY: NEON is mandatory on AArch64.
            low = low.min(unsafe { four_blocks(&kw, &nw, ctr, &mut ks) });
            xor_tail(chunk, &ks);
            ctr = ctr.wrapping_add(4);
        }
        let tail = chunks.into_remainder();
        if tail.len() >= 64 {
            // SAFETY: NEON is mandatory on AArch64.
            low = low.min(unsafe { four_blocks(&kw, &nw, ctr, &mut ks) });
            xor_tail(tail, &ks);
        } else if !tail.is_empty() {
            Scalar::apply_keystream(key, nonce, ctr, tail);
        }
        ct::wipe_array(&mut ks);
        ct::wipe_words(&mut kw);
        clear_frames::<KERNEL_FRAME>(low);
    }
    fn name() -> &'static str {
        "neon-4way"
    }
}

/// Four keystream blocks, starting at block `ctr`, written to `out`.
///
/// Returns where the stack ends beneath this function's frame
/// ([`ct::stack_mark`]). The frame holds whatever registers the compiler
/// parked during the rounds; the caller overwrites it when it is done
/// with the kernel ([`clear_frames`]), which is why this is never
/// inlined: the frame has to be one of its own.
///
/// # Safety
/// NEON is mandatory on AArch64; the caller need only be on aarch64
/// (enforced by `cfg`). All stores are to `out`.
#[target_feature(enable = "neon")]
#[inline(never)]
#[allow(clippy::multiple_unsafe_ops_per_block)] // every line is an intrinsic
unsafe fn four_blocks(key: &[u32; 8], nonce: &[u32; 3], ctr: u32, out: &mut [u8; 256]) -> usize {
    // Taken before anything is in a vector register: a call in the
    // middle would have all of them saved around it.
    let low = ct::stack_mark();
    // SAFETY: every intrinsic below is NEON (mandatory on AArch64);
    // every `vst1q_u8` targets `out` at a fixed in-bounds offset.
    unsafe {
        // 8-bit left-rotate within each u32 lane, as a tbl mask.
        let rol8_idx: uint8x16_t =
            core::mem::transmute([3u8, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]);

        macro_rules! splat {
            ($x:expr) => {
                vdupq_n_u32($x)
            };
        }
        macro_rules! rotl16 {
            ($v:expr) => {
                vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32($v)))
            };
        }
        macro_rules! rotl8 {
            ($v:expr) => {
                vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32($v), rol8_idx))
            };
        }
        macro_rules! rotl {
            ($v:expr, $n:literal) => {
                vsliq_n_u32(vshrq_n_u32($v, 32 - $n), $v, $n)
            };
        }
        macro_rules! qr {
            ($a:ident,$b:ident,$c:ident,$d:ident) => {
                $a = vaddq_u32($a, $b);
                $d = rotl16!(veorq_u32($d, $a));
                $c = vaddq_u32($c, $d);
                $b = rotl!(veorq_u32($b, $c), 12);
                $a = vaddq_u32($a, $b);
                $d = rotl8!(veorq_u32($d, $a));
                $c = vaddq_u32($c, $d);
                $b = rotl!(veorq_u32($b, $c), 7);
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
        let ctrs = [
            ctr,
            ctr.wrapping_add(1),
            ctr.wrapping_add(2),
            ctr.wrapping_add(3),
        ];
        let s12 = vld1q_u32(ctrs.as_ptr());
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

        x0 = vaddq_u32(x0, s0);
        x1 = vaddq_u32(x1, s1);
        x2 = vaddq_u32(x2, s2);
        x3 = vaddq_u32(x3, s3);
        x4 = vaddq_u32(x4, s4);
        x5 = vaddq_u32(x5, s5);
        x6 = vaddq_u32(x6, s6);
        x7 = vaddq_u32(x7, s7);
        x8 = vaddq_u32(x8, s8);
        x9 = vaddq_u32(x9, s9);
        x10 = vaddq_u32(x10, s10);
        x11 = vaddq_u32(x11, s11);
        x12 = vaddq_u32(x12, s12);
        x13 = vaddq_u32(x13, s13);
        x14 = vaddq_u32(x14, s14);
        x15 = vaddq_u32(x15, s15);

        // 4×4 u32 transpose so each output vector is one block's row.
        // vtrnq gives (a0 b0 a2 b2, a1 b1 a3 b3); then 64-bit trn on
        // those pairs yields the four per-block rows.
        macro_rules! transpose4 {
            ($a:ident,$b:ident,$c:ident,$d:ident) => {{
                let ab = vtrnq_u32($a, $b); // (a0 b0 a2 b2), (a1 b1 a3 b3)
                let cd = vtrnq_u32($c, $d); // (c0 d0 c2 d2), (c1 d1 c3 d3)
                let ac0 = vtrn1q_u64(vreinterpretq_u64_u32(ab.0), vreinterpretq_u64_u32(cd.0));
                let ac1 = vtrn2q_u64(vreinterpretq_u64_u32(ab.0), vreinterpretq_u64_u32(cd.0));
                let bd0 = vtrn1q_u64(vreinterpretq_u64_u32(ab.1), vreinterpretq_u64_u32(cd.1));
                let bd1 = vtrn2q_u64(vreinterpretq_u64_u32(ab.1), vreinterpretq_u64_u32(cd.1));
                $a = vreinterpretq_u32_u64(ac0); // a0 b0 c0 d0
                $b = vreinterpretq_u32_u64(bd0); // a1 b1 c1 d1
                $c = vreinterpretq_u32_u64(ac1); // a2 b2 c2 d2
                $d = vreinterpretq_u32_u64(bd1); // a3 b3 c3 d3
            }};
        }
        transpose4!(x0, x1, x2, x3);
        transpose4!(x4, x5, x6, x7);
        transpose4!(x8, x9, x10, x11);
        transpose4!(x12, x13, x14, x15);

        let p = out.as_mut_ptr();
        macro_rules! store {
            ($off:expr, $v:expr) => {
                vst1q_u8(p.add($off), vreinterpretq_u8_u32($v));
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
    }
    low
}
