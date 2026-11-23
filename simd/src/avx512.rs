//! ChaCha20 on AVX-512F: sixteen blocks per set of 512-bit registers, and
//! two such sets interleaved — thirty-two blocks a stride — so that a
//! whole MTU-sized packet, the AEAD's block 0 included, is one pass.
//!
//! Why interleave: a quarter-round is one dependency chain of twelve
//! operations, and one sixteen-block state is four such chains. A core
//! that runs four vector operations a cycle but needs more than a cycle
//! for each link of a chain (two, on the AMD cores this was measured on)
//! is half idle with one state; a second, independent state fills the
//! other half. AVX-512 has exactly the thirty-two registers that takes,
//! and a rotate instruction, so nothing lives in memory.
//!
//! This module exists when the crate is built by Rust 1.89 or later (the
//! release that made the intrinsics available); the build script checks.
//! It is used when the CPU has AVX-512F *and* AVX-512 VBMI2. The second
//! feature is not needed by the code: it marks the generations (Intel
//! from Ice Lake, AMD from Zen 4) that do not lower their clock for
//! 512-bit integer code, which the first AVX-512 parts did, to the cost
//! of everything else on the core.
//!
//! # Strides and tails
//!
//! Whole strides of thirty-two blocks are XORed into the buffer straight
//! from the registers. What is left takes one more stride — of thirty-two
//! blocks if more than sixteen are needed, of sixteen otherwise — by way
//! of a stack buffer that is wiped; one or two blocks go to the scalar
//! code. An AEAD's first stride starts at block 0 and always goes through
//! the stack buffer: its first half-block is the one-time authenticator
//! key.
//!
//! # Safety
//!
//! Every `unsafe` block is an intrinsic call under
//! `#[target_feature(enable = "avx512f")]` — reached only after
//! [`available`] — or an unaligned 64-byte load or store through a
//! pointer into a `[u8; 1024]` that the function was handed by reference,
//! at the fixed offsets 0, 64, …, 960. No length or index that depends on
//! the caller's data reaches an intrinsic: buffers are cut into
//! fixed-size arrays by safe code first.

#![allow(unsafe_code)]
// This module is only compiled when the build script found a compiler that
// has these intrinsics (`cfg(wg_avx512)`); the crate's minimum supported
// version builds without it.
#![allow(clippy::incompatible_msrv)]

use core::arch::x86_64::*;

use wireguard_sans_io::crypto::ct;

use crate::avx2::{SCALAR_TAIL_MAX, xor_after_block_0};
use crate::{ChaChaImpl, SIGMA, Scalar, load_key_words, nonce_words, xor_tail};

/// Sixteen blocks.
const HALF: usize = 1024;
/// Thirty-two blocks.
const FULL: usize = 2048;

/// What [`clear_kernel_frames`] overwrites at once after [`blocks16`],
/// in 64-byte vectors. Sixteen state vectors and the few the output
/// stage needs fit the thirty-two registers: in an optimised build the
/// kernel parks none, and its frame is a few saved registers.
#[cfg_attr(wg_low_opt, allow(dead_code))] // such a build does not size its clean-up
const FRAME_16: usize = 2;
/// The same after [`blocks32`]: two states are all the registers there
/// are, so one of them waits in the frame — sixteen vectors of sixty-four
/// bytes — while the other is written out.
#[cfg_attr(wg_low_opt, allow(dead_code))]
const FRAME_32: usize = 20;

/// [`clear_frames`](crate::clear_frames) for this module's kernels: the
/// frame of zeros is `VECTORS` 512-bit vectors, written with as many
/// stores.
///
/// # Safety
/// Caller must ensure the `avx512f` target feature is available.
#[cfg(not(wg_low_opt))]
#[target_feature(enable = "avx512f")]
#[inline(never)]
unsafe fn clear_kernel_frames<const VECTORS: usize>(low: usize) {
    let mut frame = [core::mem::MaybeUninit::<__m512i>::uninit(); VECTORS];
    let zero = _mm512_setzero_si512();
    for slot in &mut frame {
        // SAFETY: a volatile store to an element of a local array.
        // (Volatile: the stores are the point, and they are to stay
        // `VECTORS` stores of a register, not a call to `memset`.)
        unsafe { core::ptr::write_volatile(slot.as_mut_ptr(), zero) };
    }
    let lowest = core::ptr::from_ref(core::hint::black_box(&frame)) as usize;
    crate::clear_below(low, lowest);
}

/// Overwrite the frames of the kernels that ran (`$low`: how far down
/// they went), from the function that called them: with
/// [`clear_kernel_frames`], or the way every build with `opt-level` 0 or
/// 1 does it ([`crate::scrub_deep`]).
macro_rules! clear_after_kernels {
    ($vectors:ident, $low:expr) => {{
        #[cfg(not(wg_low_opt))]
        // SAFETY: AVX-512F is available — the contract of the function
        // this is written in.
        unsafe {
            clear_kernel_frames::<$vectors>($low)
        };
        #[cfg(wg_low_opt)]
        crate::scrub_deep($low);
    }};
}

/// Should the AVX-512 kernels be used on this CPU? (See the module
/// documentation for why this asks for more than AVX-512F.)
#[inline]
pub(crate) fn available() -> bool {
    std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512vbmi2")
}

/// XOR the keystream that starts at block `counter` into `buf`.
///
/// # Safety
/// Caller must ensure the `avx512f` target feature is available.
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn apply(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
    let mut kw = [0u32; 8];
    load_key_words(key, &mut kw);
    let nw = nonce_words(nonce);
    let mut ctr = counter;
    // How far down the kernels' frames went, and whether the kernel with
    // the larger frame was among them (see `clear_frames`).
    let mut low = usize::MAX;
    let mut wide = false;
    let mut chunks = buf.chunks_exact_mut(FULL);
    for chunk in &mut chunks {
        // Always two halves: that is what `chunks_exact_mut` yields.
        if let Some((lo, hi)) = chunk.split_first_chunk_mut::<HALF>() {
            if let Ok(hi) = <&mut [u8; HALF]>::try_from(hi) {
                // SAFETY: AVX-512F is available (this function's contract).
                low = low.min(unsafe { blocks32::<true>(&kw, &nw, ctr, lo, hi) });
                wide = true;
            }
        }
        ctr = ctr.wrapping_add(32);
    }
    let tail = chunks.into_remainder();
    if tail.len() > SCALAR_TAIL_MAX {
        let mut ks = [[0u8; HALF]; 2];
        let [lo, hi] = &mut ks;
        if tail.len() > HALF {
            // SAFETY: as above.
            low = low.min(unsafe { blocks32::<false>(&kw, &nw, ctr, lo, hi) });
            wide = true;
            if let Some((first, second)) = tail.split_at_mut_checked(HALF) {
                xor_tail(first, lo);
                xor_tail(second, hi);
            }
        } else {
            // SAFETY: as above.
            low = low.min(unsafe { blocks16::<false>(&kw, &nw, ctr, lo) });
            xor_tail(tail, lo);
        }
        ct::wipe_array(lo);
        ct::wipe_array(hi);
    } else if !tail.is_empty() {
        Scalar::apply_keystream(key, nonce, ctr, tail);
    }
    ct::wipe_words(&mut kw);
    if wide {
        clear_after_kernels!(FRAME_32, low);
    } else if low != usize::MAX {
        clear_after_kernels!(FRAME_16, low);
    }
}

/// The first stride of an AEAD: blocks 0 onwards, as many as `len` bytes
/// of data after block 0 call for (sixteen or thirty-two), written to
/// `ks`. Returns how many bytes of `ks` were written.
///
/// # Safety
/// Caller must ensure the `avx512f` target feature is available.
#[target_feature(enable = "avx512f")]
unsafe fn first_stride(
    key: &[u8; 32],
    nonce: &[u8; 12],
    len: usize,
    ks: &mut [[u8; HALF]; 2],
) -> usize {
    let mut kw = [0u32; 8];
    load_key_words(key, &mut kw);
    let nw = nonce_words(nonce);
    let [lo, hi] = ks;
    // Block 0 and `len` bytes: more than sixteen blocks?
    if len > HALF.saturating_sub(64) {
        // SAFETY: AVX-512F is available (this function's contract).
        let low = unsafe { blocks32::<false>(&kw, &nw, 0, lo, hi) };
        ct::wipe_words(&mut kw);
        clear_after_kernels!(FRAME_32, low);
        FULL
    } else {
        // SAFETY: as above.
        let low = unsafe { blocks16::<false>(&kw, &nw, 0, lo) };
        ct::wipe_words(&mut kw);
        clear_after_kernels!(FRAME_16, low);
        HALF
    }
}

/// XOR the keystream after block 0 of a first stride into `buf`; returns
/// what the stride did not reach (which then starts at block
/// `written / 64`).
fn xor_first_stride<'a>(buf: &'a mut [u8], ks: &[[u8; HALF]; 2], written: usize) -> &'a mut [u8] {
    let [lo, hi] = ks;
    let rest = xor_after_block_0(buf, lo);
    if written == FULL {
        let n = rest.len().min(HALF);
        match rest.split_at_mut_checked(n) {
            Some((now, later)) => {
                xor_tail(now, hi);
                later
            }
            // Unreachable: `n` is at most `rest.len()`.
            None => &mut [],
        }
    } else {
        rest
    }
}

/// For an AEAD seal: the first half of block 0 to `otk`, blocks 1
/// onwards into `buf`.
///
/// # Safety
/// Caller must ensure the `avx512f` target feature is available.
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn seal(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8], otk: &mut [u8; 32]) {
    if buf.len() <= 64 {
        // Two blocks in all: the scalar code is faster.
        Scalar::seal_keystream(key, nonce, buf, otk);
        return;
    }
    let mut ks = [[0u8; HALF]; 2];
    // SAFETY: AVX-512F is available (this function's contract).
    let written = unsafe { first_stride(key, nonce, buf.len(), &mut ks) };
    for (d, s) in otk.iter_mut().zip(ks[0].iter()) {
        *d = *s;
    }
    let later = xor_first_stride(buf, &ks, written);
    let [lo, hi] = &mut ks;
    ct::wipe_array(lo);
    ct::wipe_array(hi);
    if !later.is_empty() {
        // SAFETY: as above.
        unsafe { apply(key, nonce, (written / 64) as u32, later) };
    }
}

/// For an AEAD open: the first stride, the caller's verdict on the
/// ciphertext under the one-time key, and only then the keystream into
/// `buf`. The stride is held on the stack while the caller decides, and
/// wiped whatever the verdict.
///
/// # Safety
/// Caller must ensure the `avx512f` target feature is available.
#[target_feature(enable = "avx512f")]
#[inline]
pub(crate) unsafe fn open<F: FnOnce(&[u8; 32], &[u8]) -> bool>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    buf: &mut [u8],
    verify: F,
) -> bool {
    if buf.len() <= 64 {
        return Scalar::open_keystream(key, nonce, buf, verify);
    }
    let mut ks = [[0u8; HALF]; 2];
    // SAFETY: AVX-512F is available (this function's contract).
    let written = unsafe { first_stride(key, nonce, buf.len(), &mut ks) };
    let ok = match ks[0].first_chunk::<32>() {
        Some(otk) => verify(otk, buf),
        None => false,
    };
    let later = if ok {
        xor_first_stride(buf, &ks, written)
    } else {
        &mut []
    };
    let [lo, hi] = &mut ks;
    ct::wipe_array(lo);
    ct::wipe_array(hi);
    if !later.is_empty() {
        // SAFETY: as above.
        unsafe { apply(key, nonce, (written / 64) as u32, later) };
    }
    ok
}

// ===========================================================================
// The kernels
// ===========================================================================

macro_rules! qr512 {
    ($x:ident, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $x[$a] = _mm512_add_epi32($x[$a], $x[$b]);
        $x[$d] = _mm512_rol_epi32::<16>(_mm512_xor_si512($x[$d], $x[$a]));
        $x[$c] = _mm512_add_epi32($x[$c], $x[$d]);
        $x[$b] = _mm512_rol_epi32::<12>(_mm512_xor_si512($x[$b], $x[$c]));
        $x[$a] = _mm512_add_epi32($x[$a], $x[$b]);
        $x[$d] = _mm512_rol_epi32::<8>(_mm512_xor_si512($x[$d], $x[$a]));
        $x[$c] = _mm512_add_epi32($x[$c], $x[$d]);
        $x[$b] = _mm512_rol_epi32::<7>(_mm512_xor_si512($x[$b], $x[$c]));
    };
}

/// The sixteen input vectors: word `i` of blocks `ctr .. ctr + 16`
/// (counters wrap per lane, per RFC 8439).
///
/// A macro, like `emit!` below, and not a function: what they compute
/// with has to lie in the frame of the kernel that uses them at every
/// optimisation level — that is the frame that is overwritten afterwards
/// (`clear_frames`) — and a function is only part of its caller's frame
/// when the compiler chooses to inline it.
macro_rules! input {
    ($key:expr, $nonce:expr, $ctr:expr) => {{
        // Each key word is read where it is used: taking the eight of
        // them out of `$key` first would be a copy of the key, in this
        // frame, in a build that keeps such things in memory.
        let key: &[u32; 8] = $key;
        let [n0, n1, n2] = *$nonce;
        let [c0, c1, c2, c3] = SIGMA;
        let lanes = _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        [
            _mm512_set1_epi32(c0 as i32),
            _mm512_set1_epi32(c1 as i32),
            _mm512_set1_epi32(c2 as i32),
            _mm512_set1_epi32(c3 as i32),
            _mm512_set1_epi32(key[0] as i32),
            _mm512_set1_epi32(key[1] as i32),
            _mm512_set1_epi32(key[2] as i32),
            _mm512_set1_epi32(key[3] as i32),
            _mm512_set1_epi32(key[4] as i32),
            _mm512_set1_epi32(key[5] as i32),
            _mm512_set1_epi32(key[6] as i32),
            _mm512_set1_epi32(key[7] as i32),
            _mm512_add_epi32(_mm512_set1_epi32($ctr as i32), lanes),
            _mm512_set1_epi32(n0 as i32),
            _mm512_set1_epi32(n1 as i32),
            _mm512_set1_epi32(n2 as i32),
        ]
    }};
}

/// Transpose the sixteen vectors of the array `$x` (word `i` of sixteen
/// blocks each) into sixteen 64-byte blocks in stream order, and write
/// them to the `[u8; HALF]` `$out` — or, with `$xor`, XOR them into it.
/// The array is used up: the first stage is done in place, so that the
/// whole of it needs four registers more than the sixteen it starts
/// with.
///
/// The loads and stores through `p` are 64 bytes at offsets 0, 64, …,
/// 960 of the 1024-byte array `$out`.
macro_rules! emit {
    ($xor:expr, $x:ident, $out:expr) => {{
        let out: &mut [u8; HALF] = $out;
        // Stage 1, inside each 128-bit lane (blocks 4L..4L+3): afterwards
        // `$x[4g + k]` holds words 4g..4g+3 of block 4L + k in lane L.
        let mut g = 0;
        while g < 16 {
            let t0 = _mm512_unpacklo_epi32($x[g], $x[g + 1]);
            let t1 = _mm512_unpackhi_epi32($x[g], $x[g + 1]);
            let t2 = _mm512_unpacklo_epi32($x[g + 2], $x[g + 3]);
            let t3 = _mm512_unpackhi_epi32($x[g + 2], $x[g + 3]);
            $x[g] = _mm512_unpacklo_epi64(t0, t2);
            $x[g + 1] = _mm512_unpackhi_epi64(t0, t2);
            $x[g + 2] = _mm512_unpacklo_epi64(t1, t3);
            $x[g + 3] = _mm512_unpackhi_epi64(t1, t3);
            g += 4;
        }
        // Stage 2, across lanes: block 4L + k is lane L of `$x[k]`,
        // `$x[4 + k]`, `$x[8 + k]`, `$x[12 + k]`.
        let p = out.as_mut_ptr();
        let mut k = 0;
        while k < 4 {
            let t0 = _mm512_shuffle_i32x4::<0x44>($x[k], $x[4 + k]);
            let t1 = _mm512_shuffle_i32x4::<0xee>($x[k], $x[4 + k]);
            let t2 = _mm512_shuffle_i32x4::<0x44>($x[8 + k], $x[12 + k]);
            let t3 = _mm512_shuffle_i32x4::<0xee>($x[8 + k], $x[12 + k]);
            let blocks = [
                (k, _mm512_shuffle_i32x4::<0x88>(t0, t2)),
                (4 + k, _mm512_shuffle_i32x4::<0xdd>(t0, t2)),
                (8 + k, _mm512_shuffle_i32x4::<0x88>(t1, t3)),
                (12 + k, _mm512_shuffle_i32x4::<0xdd>(t1, t3)),
            ];
            for (block, v) in blocks {
                // `block` is below 16: the 64 bytes at `64 * block` are
                // inside `out`.
                let at = p.add(64 * block);
                if $xor {
                    let have = _mm512_loadu_si512(at.cast());
                    _mm512_storeu_si512(at.cast(), _mm512_xor_si512(have, v));
                } else {
                    _mm512_storeu_si512(at.cast(), v);
                }
            }
            k += 1;
        }
    }};
}

/// Blocks `ctr .. ctr + 16`, written to `out` or XORed into it.
///
/// Returns where the stack ends beneath this function's frame
/// ([`ct::stack_mark`]). The frame holds whatever registers the compiler
/// parked during the rounds; the caller overwrites it when it is done
/// with the kernels ([`clear_kernel_frames`]), which is why this is never
/// inlined: the frame has to be one of its own.
///
/// # Safety
/// Caller must ensure the `avx512f` target feature is available.
#[target_feature(enable = "avx512f")]
#[inline(never)]
#[allow(clippy::multiple_unsafe_ops_per_block, clippy::indexing_slicing)] // intrinsics; constant indices below 16
unsafe fn blocks16<const XOR: bool>(
    key: &[u32; 8],
    nonce: &[u32; 3],
    ctr: u32,
    out: &mut [u8; HALF],
) -> usize {
    // Taken before anything is in a vector register: a call in the
    // middle would have all of them saved around it.
    let low = ct::stack_mark();
    // SAFETY: intrinsics under avx512f; `emit!`'s loads and stores are 64
    // bytes at offsets 0, 64, …, 960 of a 1024-byte array.
    unsafe {
        let mut x = input!(key, nonce, ctr);
        for _ in 0..10 {
            qr512!(x, 0, 4, 8, 12);
            qr512!(x, 1, 5, 9, 13);
            qr512!(x, 2, 6, 10, 14);
            qr512!(x, 3, 7, 11, 15);
            qr512!(x, 0, 5, 10, 15);
            qr512!(x, 1, 6, 11, 12);
            qr512!(x, 2, 7, 8, 13);
            qr512!(x, 3, 4, 9, 14);
        }
        // Feed-forward: the inputs once more, read back through
        // references the optimiser knows nothing about. It would
        // otherwise keep all sixteen input vectors at hand across the
        // rounds — the key among them — and having no registers for
        // them, keep them in this frame.
        let (key, nonce) = core::hint::black_box((key, nonce));
        let s = input!(key, nonce, ctr);
        let mut i = 0;
        while i < 16 {
            x[i] = _mm512_add_epi32(x[i], s[i]);
            i += 1;
        }
        emit!(XOR, x, out);
    }
    low
}

/// Blocks `ctr .. ctr + 32`: two independent sixteen-block states with
/// their quarter-rounds interleaved; the first sixteen blocks go to `lo`,
/// the rest to `hi`. Returns, and is never inlined, as [`blocks16`].
///
/// # Safety
/// Caller must ensure the `avx512f` target feature is available.
#[target_feature(enable = "avx512f")]
#[inline(never)]
#[allow(clippy::multiple_unsafe_ops_per_block, clippy::indexing_slicing)] // intrinsics; constant indices below 16
unsafe fn blocks32<const XOR: bool>(
    key: &[u32; 8],
    nonce: &[u32; 3],
    ctr: u32,
    lo: &mut [u8; HALF],
    hi: &mut [u8; HALF],
) -> usize {
    // As in `blocks16`.
    let low = ct::stack_mark();
    // SAFETY: as in `blocks16`.
    unsafe {
        let mut x = input!(key, nonce, ctr);
        let mut y = x;
        // The second state's counters start sixteen further on.
        y[12] = _mm512_add_epi32(x[12], _mm512_set1_epi32(16));
        for _ in 0..10 {
            qr512!(x, 0, 4, 8, 12);
            qr512!(y, 0, 4, 8, 12);
            qr512!(x, 1, 5, 9, 13);
            qr512!(y, 1, 5, 9, 13);
            qr512!(x, 2, 6, 10, 14);
            qr512!(y, 2, 6, 10, 14);
            qr512!(x, 3, 7, 11, 15);
            qr512!(y, 3, 7, 11, 15);
            qr512!(x, 0, 5, 10, 15);
            qr512!(y, 0, 5, 10, 15);
            qr512!(x, 1, 6, 11, 12);
            qr512!(y, 1, 6, 11, 12);
            qr512!(x, 2, 7, 8, 13);
            qr512!(y, 2, 7, 8, 13);
            qr512!(x, 3, 4, 9, 14);
            qr512!(y, 3, 4, 9, 14);
        }
        // Feed-forward and output, one state after the other, each from
        // inputs read once more as in `blocks16` — and each from a
        // reading of its own: two states are all thirty-two registers
        // there are, and one reading for both would be sixteen vectors
        // with nowhere to be but this frame.
        {
            let (key, nonce) = core::hint::black_box((key, nonce));
            let s = input!(key, nonce, ctr);
            let mut i = 0;
            while i < 16 {
                x[i] = _mm512_add_epi32(x[i], s[i]);
                i += 1;
            }
            emit!(XOR, x, lo);
        }
        {
            let (key, nonce) = core::hint::black_box((key, nonce));
            let s = input!(key, nonce, ctr);
            let mut i = 0;
            while i < 16 {
                y[i] = _mm512_add_epi32(y[i], s[i]);
                i += 1;
            }
            // The second state's counters started sixteen further on.
            y[12] = _mm512_add_epi32(y[12], _mm512_set1_epi32(16));
            emit!(XOR, y, hi);
        }
    }
    low
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AVX-512 tier itself, on any CPU that has AVX-512F — also one
    /// that `Detect` would not use it on.
    struct Avx512Tier;
    fn has_avx512f() -> bool {
        std::is_x86_feature_detected!("avx512f")
    }
    impl ChaChaImpl for Avx512Tier {
        fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
            assert!(has_avx512f());
            // SAFETY: the CPU has AVX-512F — asserted on the line above.
            unsafe { apply(key, nonce, counter, buf) }
        }
        fn seal_keystream(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8], otk: &mut [u8; 32]) {
            assert!(has_avx512f());
            // SAFETY: as above.
            unsafe { seal(key, nonce, buf, otk) }
        }
        fn open_keystream<F: FnOnce(&[u8; 32], &[u8]) -> bool>(
            key: &[u8; 32],
            nonce: &[u8; 12],
            buf: &mut [u8],
            verify: F,
        ) -> bool {
            assert!(has_avx512f());
            // SAFETY: as above.
            unsafe { open(key, nonce, buf, verify) }
        }
        fn name() -> &'static str {
            "avx512 tier"
        }
    }

    #[test]
    fn the_avx512_tier_matches_scalar() {
        if !has_avx512f() {
            eprintln!("skipped: this CPU has no AVX-512F");
            return;
        }
        crate::check::all::<Avx512Tier>();
    }
}
