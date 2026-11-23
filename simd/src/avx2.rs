//! ChaCha20 on x86_64 AVX2: eight blocks at a time in 256-bit registers,
//! and the dispatch between this, AVX-512 and the scalar code.
//!
//! Register *i* holds word *i* of eight blocks, so every quarter-round
//! operation is a straight vertical add, xor or rotate. Sixteen state
//! vectors, a temporary for the two rotations that have no byte shuffle,
//! and two shuffle masks do not fit sixteen registers, so something has
//! to live in memory — and which words do decides how fast the kernel is.
//! Here it is the four `c` words (state words 8 to 11), on purpose: a `c`
//! word is only ever read as `c += d`, and its new value is not needed
//! again for half a round, which is longer than a store takes to forward.
//! Left to itself the compiler spills `b` and `d` words, whose reload
//! sits on the longest dependency chain of the round.
//!
//! # Strides and tails
//!
//! Whole 512-byte strides are XORed into the buffer straight from the
//! registers. What is left goes through one more stride, by way of a
//! stack buffer that is wiped — unless it is at most two blocks (128
//! bytes): for so little the scalar code is faster, and such tails are
//! common (transport payloads are padded to 16 bytes, not to a stride; a
//! small packet is nothing but tail).
//!
//! For an AEAD, block 0 — the one-time authenticator key — is a block of
//! the first stride ([`ChaChaImpl::seal_keystream`],
//! [`ChaChaImpl::open_keystream`]) instead of a scalar block of its own.
//!
//! # Which CPU
//!
//! The kernels are compiled with `#[target_feature(enable = "avx2")]`
//! whatever the build's own target features are, so they exist in every
//! x86_64 build; what differs is who may call them.
//!
//! * A build that has AVX2 enabled for the whole program
//!   (`-C target-cpu=x86-64-v3`, `-C target-feature=+avx2`, …) can only
//!   run on a CPU that has it: [`Avx2x8`] calls the kernel
//!   unconditionally, and exists only in such a build.
//! * [`Detect`] exists in every build and asks the CPU on every call
//!   (`is_x86_feature_detected!`, a cached flag; no check at all for a
//!   feature the build already requires): the AVX-512 kernels if it has
//!   them (see `avx512.rs`), this one if it has AVX2, the scalar
//!   keystream otherwise.
//!
//! # What is left behind
//!
//! Nothing that is the key or the keystream: the key words this module
//! unpacks, the `c` words in memory and every stack buffer that held
//! keystream are zeroed before a function returns — and so is the
//! kernel's whole stack frame, where the compiler parks registers it has
//! no room for (words of the key and of the keystream among them): its
//! caller overwrites it after the last stride (`clear_frames`, see the
//! crate documentation).
//!
//! # Safety
//!
//! Every `unsafe` block is one of:
//! 1. a call to a kernel or a `core::arch::x86_64` intrinsic, for which
//!    AVX2 has been established as above — by `cfg` for the build, or by
//!    the run-time check on the line before;
//! 2. an unaligned load or store through a pointer into a `[u8; 512]`
//!    that the function was handed by reference, at fixed offsets below
//!    512;
//! 3. a volatile read or write of one of the four slots of a local
//!    array.
//!
//! No attacker-controlled length, pointer, or index reaches an
//! intrinsic.

#![allow(unsafe_code)]

use core::arch::x86_64::*;

use wireguard_sans_io::crypto::ct;

use crate::{ChaChaImpl, SIGMA, Scalar, clear_frames, load_key_words, nonce_words, xor_tail};

/// The longest tail that goes to the scalar code: two blocks. A stride
/// costs about as much as two and a quarter scalar blocks whatever its
/// width, so for one or two blocks — every small packet: a keepalive, an
/// ACK, a DNS query — the scalar keystream is the faster one.
pub(crate) const SCALAR_TAIL_MAX: usize = 128;

/// What one stride yields.
const STRIDE: usize = 512;

/// What [`clear_frames`] overwrites at once after the kernel, in 64-bit
/// words: its frame is about half a kilobyte in an optimised build (the
/// four `c` rows and a dozen parked registers of thirty-two bytes).
const KERNEL_FRAME: usize = 112;

// ===========================================================================
// The public types
// ===========================================================================

/// AVX2 8-block-parallel ChaCha20 (256-bit `__m256i` lanes). Only in
/// builds that have AVX2 enabled for the whole program; [`Detect`] is the
/// same kernel behind a run-time check.
#[cfg(target_feature = "avx2")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Avx2x8;

#[cfg(target_feature = "avx2")]
impl ChaChaImpl for Avx2x8 {
    #[inline]
    fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        // SAFETY: this impl exists only where AVX2 is enabled for the
        // build (`cfg` above): every CPU the program can run on has it.
        unsafe { apply_8way(key, nonce, counter, buf) }
    }
    #[inline]
    fn seal_keystream(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8], otk: &mut [u8; 32]) {
        // SAFETY: as `apply_keystream`.
        unsafe { seal_8way(key, nonce, buf, otk) }
    }
    #[inline]
    fn open_keystream<F: FnOnce(&[u8; 32], &[u8]) -> bool>(
        key: &[u8; 32],
        nonce: &[u8; 12],
        buf: &mut [u8],
        verify: F,
    ) -> bool {
        // SAFETY: as `apply_keystream`.
        unsafe { open_8way(key, nonce, buf, verify) }
    }
    fn name() -> &'static str {
        "avx2-8way"
    }
}

/// The widest keystream this CPU has, found out when the program runs:
/// the AVX-512 kernels, the 8-way AVX2 kernel, or the scalar code. This
/// is what [`crate::Best`] is on x86_64, so that one build runs
/// everywhere and is fast where it can be.
///
/// A check is one cached flag per call, and there is none for a feature
/// the build already requires. A kernel cannot be inlined into code that
/// was compiled without its target feature, which costs a call per
/// stride.
#[derive(Debug, Clone, Copy, Default)]
pub struct Detect;

impl Detect {
    /// Does this CPU (and the operating system, which has to save the
    /// registers) support AVX2?
    #[must_use]
    pub fn avx2_available() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    /// Will the AVX-512 kernels be used? (They are when the CPU has
    /// AVX-512F and is of a generation that does not lower its clock for
    /// 512-bit code, and the crate was built by a compiler that has the
    /// intrinsics: Rust 1.89 or later.)
    #[must_use]
    pub fn avx512_in_use() -> bool {
        #[cfg(wg_avx512)]
        {
            crate::avx512::available()
        }
        #[cfg(not(wg_avx512))]
        {
            false
        }
    }
}

impl ChaChaImpl for Detect {
    #[inline]
    fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        #[cfg(wg_avx512)]
        if crate::avx512::available() {
            // SAFETY: the CPU has AVX-512F — checked on the line above.
            unsafe { crate::avx512::apply(key, nonce, counter, buf) };
            return;
        }
        if Self::avx2_available() {
            // SAFETY: the CPU has AVX2 — checked on the line above.
            unsafe { apply_8way(key, nonce, counter, buf) }
        } else {
            Scalar::apply_keystream(key, nonce, counter, buf);
        }
    }

    #[inline]
    fn seal_keystream(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8], otk: &mut [u8; 32]) {
        #[cfg(wg_avx512)]
        if crate::avx512::available() {
            // SAFETY: the CPU has AVX-512F — checked on the line above.
            unsafe { crate::avx512::seal(key, nonce, buf, otk) };
            return;
        }
        if Self::avx2_available() {
            // SAFETY: the CPU has AVX2 — checked on the line above.
            unsafe { seal_8way(key, nonce, buf, otk) }
        } else {
            Scalar::seal_keystream(key, nonce, buf, otk);
        }
    }

    #[inline]
    fn open_keystream<F: FnOnce(&[u8; 32], &[u8]) -> bool>(
        key: &[u8; 32],
        nonce: &[u8; 12],
        buf: &mut [u8],
        verify: F,
    ) -> bool {
        #[cfg(wg_avx512)]
        if crate::avx512::available() {
            // SAFETY: the CPU has AVX-512F — checked on the line above.
            return unsafe { crate::avx512::open(key, nonce, buf, verify) };
        }
        if Self::avx2_available() {
            // SAFETY: the CPU has AVX2 — checked on the line above.
            unsafe { open_8way(key, nonce, buf, verify) }
        } else {
            Scalar::open_keystream(key, nonce, buf, verify)
        }
    }

    /// The keystream in use on this CPU.
    fn name() -> &'static str {
        if Self::avx512_in_use() {
            "avx512-16/32way (detected)"
        } else if Self::avx2_available() {
            "avx2-8way (detected)"
        } else {
            "scalar (no avx2)"
        }
    }
}

// ===========================================================================
// Strides over a buffer
// ===========================================================================

/// The 8-way keystream loop.
///
/// # Safety
/// Caller must ensure the `avx2` target feature is available.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn apply_8way(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
    let mut kw = [0u32; 8];
    load_key_words(key, &mut kw);
    let nw = nonce_words(nonce);
    let mut ctr = counter;
    // How far down the kernel's frame went (see `clear_frames`).
    let mut low = usize::MAX;
    let mut chunks = buf.chunks_exact_mut(STRIDE);
    for chunk in &mut chunks {
        // Always the case: that is what `chunks_exact_mut` yields.
        if let Ok(chunk) = <&mut [u8; STRIDE]>::try_from(chunk) {
            // SAFETY: AVX2 is available (this function's contract).
            low = low.min(unsafe { eight_blocks::<true>(&kw, &nw, ctr, chunk) });
        }
        ctr = ctr.wrapping_add(8);
    }
    let tail = chunks.into_remainder();
    if tail.len() > SCALAR_TAIL_MAX {
        let mut ks = [0u8; STRIDE];
        // SAFETY: as above.
        low = low.min(unsafe { eight_blocks::<false>(&kw, &nw, ctr, &mut ks) });
        xor_tail(tail, &ks);
        ct::wipe_array(&mut ks);
    } else if !tail.is_empty() {
        Scalar::apply_keystream(key, nonce, ctr, tail);
    }
    ct::wipe_words(&mut kw);
    clear_frames::<KERNEL_FRAME>(low);
}

/// For an AEAD seal: the first half of block 0 to `otk`, blocks 1
/// onwards into `buf` — block 0 being the first block of the first
/// stride.
///
/// # Safety
/// Caller must ensure the `avx2` target feature is available.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn seal_8way(
    key: &[u8; 32],
    nonce: &[u8; 12],
    buf: &mut [u8],
    otk: &mut [u8; 32],
) {
    if buf.len() <= 64 {
        // Two blocks in all: the scalar code is faster.
        Scalar::seal_keystream(key, nonce, buf, otk);
        return;
    }
    let mut kw = [0u32; 8];
    load_key_words(key, &mut kw);
    let nw = nonce_words(nonce);
    let mut ks = [0u8; STRIDE];
    // SAFETY: AVX2 is available (this function's contract).
    let low = unsafe { eight_blocks::<false>(&kw, &nw, 0, &mut ks) };
    ct::wipe_words(&mut kw);
    clear_frames::<KERNEL_FRAME>(low);
    for (d, s) in otk.iter_mut().zip(ks.iter()) {
        *d = *s;
    }
    let later = xor_after_block_0(buf, &ks);
    ct::wipe_array(&mut ks);
    if !later.is_empty() {
        // SAFETY: as above.
        unsafe { apply_8way(key, nonce, 8, later) };
    }
}

/// For an AEAD open: block 0 and the first seven blocks of keystream in
/// one stride, the caller's verdict on the ciphertext under the one-time
/// key, and only then the keystream into `buf`. The stride is held on
/// the stack while the caller decides, and wiped whatever the verdict.
///
/// # Safety
/// Caller must ensure the `avx2` target feature is available.
#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn open_8way<F: FnOnce(&[u8; 32], &[u8]) -> bool>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    buf: &mut [u8],
    verify: F,
) -> bool {
    if buf.len() <= 64 {
        return Scalar::open_keystream(key, nonce, buf, verify);
    }
    let mut kw = [0u32; 8];
    load_key_words(key, &mut kw);
    let nw = nonce_words(nonce);
    let mut ks = [0u8; STRIDE];
    // SAFETY: AVX2 is available (this function's contract).
    let low = unsafe { eight_blocks::<false>(&kw, &nw, 0, &mut ks) };
    ct::wipe_words(&mut kw);
    clear_frames::<KERNEL_FRAME>(low);
    let ok = match ks.first_chunk::<32>() {
        Some(otk) => verify(otk, buf),
        None => false,
    };
    if ok {
        let later = xor_after_block_0(buf, &ks);
        ct::wipe_array(&mut ks);
        if !later.is_empty() {
            // SAFETY: as above.
            unsafe { apply_8way(key, nonce, 8, later) };
        }
    } else {
        ct::wipe_array(&mut ks);
    }
    ok
}

/// XOR a first stride's keystream after block 0 into the start of `buf`
/// and return what the stride did not reach.
#[inline]
pub(crate) fn xor_after_block_0<'a>(buf: &'a mut [u8], stride: &[u8]) -> &'a mut [u8] {
    let ks = stride.get(64..).unwrap_or(&[]);
    let n = buf.len().min(ks.len());
    match buf.split_at_mut_checked(n) {
        Some((now, later)) => {
            xor_tail(now, ks);
            later
        }
        // Unreachable: `n` is at most `buf.len()`.
        None => &mut [],
    }
}

// ===========================================================================
// The kernel
// ===========================================================================

/// The four `c` rows, in memory.
#[repr(C, align(32))]
struct CRows([__m256i; 4]);

/// Eight keystream blocks, starting at block `ctr`: written to `buf` if
/// `XOR` is false, XORed into it if true.
///
/// Returns where the stack ends beneath this function's frame
/// ([`ct::stack_mark`]). The frame holds whatever registers the compiler
/// parked during the rounds, besides the `c` rows; the caller overwrites
/// it when it is done with the kernel ([`clear_frames`]), which is why
/// this is never inlined: the frame has to be one of its own.
///
/// # Safety
/// Caller must ensure the `avx2` target feature is available.
#[target_feature(enable = "avx2")]
#[inline(never)]
#[allow(clippy::multiple_unsafe_ops_per_block, clippy::indexing_slicing)] // every line is an intrinsic; constant indices below 8
unsafe fn eight_blocks<const XOR: bool>(
    key: &[u32; 8],
    nonce: &[u32; 3],
    ctr: u32,
    buf: &mut [u8; STRIDE],
) -> usize {
    // Taken before anything is in a vector register: a call in the
    // middle would have all of them saved around it.
    let low = ct::stack_mark();
    // SAFETY: every intrinsic is gated by `target_feature(avx2)`; the
    // volatile reads and writes are of the four slots of the local `c`
    // (`cp.add(0..=3)`); the loads and stores through `p` are 32 bytes at
    // offsets 0, 32, …, 480 of the 512-byte array `buf`.
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
        // Each key word is read where it is used: taking the eight of
        // them out of `key` first would be a copy of the key, in this
        // frame, in a build that keeps such things in memory.
        let [n0, n1, n2] = *nonce;
        let [c0, c1, c2, c3] = SIGMA;

        let mut c = CRows([
            splat!(key[4]),
            splat!(key[5]),
            splat!(key[6]),
            splat!(key[7]),
        ]);
        let cp = c.0.as_mut_ptr();
        macro_rules! qr {
            ($a:ident, $b:ident, $ci:expr, $d:ident) => {
                $a = _mm256_add_epi32($a, $b);
                $d = _mm256_shuffle_epi8(_mm256_xor_si256($d, $a), rol16);
                let cv = _mm256_add_epi32(core::ptr::read_volatile(cp.add($ci)), $d);
                core::ptr::write_volatile(cp.add($ci), cv);
                let t = _mm256_xor_si256($b, cv);
                $b = _mm256_or_si256(_mm256_slli_epi32(t, 12), _mm256_srli_epi32(t, 20));
                $a = _mm256_add_epi32($a, $b);
                $d = _mm256_shuffle_epi8(_mm256_xor_si256($d, $a), rol8);
                let cv = _mm256_add_epi32(core::ptr::read_volatile(cp.add($ci)), $d);
                core::ptr::write_volatile(cp.add($ci), cv);
                let t = _mm256_xor_si256($b, cv);
                $b = _mm256_or_si256(_mm256_slli_epi32(t, 7), _mm256_srli_epi32(t, 25));
            };
        }
        // Per-lane counters: ctr + 0..7 (wrapping, per RFC 8439).
        let s12 = _mm256_add_epi32(splat!(ctr), _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
        let (mut x0, mut x1, mut x2, mut x3) = (splat!(c0), splat!(c1), splat!(c2), splat!(c3));
        let (mut x4, mut x5, mut x6, mut x7) = (
            splat!(key[0]),
            splat!(key[1]),
            splat!(key[2]),
            splat!(key[3]),
        );
        let (mut x12, mut x13, mut x14, mut x15) = (s12, splat!(n0), splat!(n1), splat!(n2));

        for _ in 0..10 {
            // Columns.
            qr!(x0, x4, 0, x12);
            qr!(x1, x5, 1, x13);
            qr!(x2, x6, 2, x14);
            qr!(x3, x7, 3, x15);
            // Diagonals.
            qr!(x0, x5, 2, x15);
            qr!(x1, x6, 3, x12);
            qr!(x2, x7, 0, x13);
            qr!(x3, x4, 1, x14);
        }

        // Feed-forward from the inputs, broadcast again (they were not
        // kept in registers across the rounds).
        x0 = _mm256_add_epi32(x0, splat!(c0));
        x1 = _mm256_add_epi32(x1, splat!(c1));
        x2 = _mm256_add_epi32(x2, splat!(c2));
        x3 = _mm256_add_epi32(x3, splat!(c3));
        x4 = _mm256_add_epi32(x4, splat!(key[0]));
        x5 = _mm256_add_epi32(x5, splat!(key[1]));
        x6 = _mm256_add_epi32(x6, splat!(key[2]));
        x7 = _mm256_add_epi32(x7, splat!(key[3]));
        let mut x8 = _mm256_add_epi32(core::ptr::read_volatile(cp), splat!(key[4]));
        let mut x9 = _mm256_add_epi32(core::ptr::read_volatile(cp.add(1)), splat!(key[5]));
        let mut x10 = _mm256_add_epi32(core::ptr::read_volatile(cp.add(2)), splat!(key[6]));
        let mut x11 = _mm256_add_epi32(core::ptr::read_volatile(cp.add(3)), splat!(key[7]));
        x12 = _mm256_add_epi32(x12, s12);
        x13 = _mm256_add_epi32(x13, splat!(n0));
        x14 = _mm256_add_epi32(x14, splat!(n1));
        x15 = _mm256_add_epi32(x15, splat!(n2));
        // The `c` rows held key words and then working state.
        let zero = _mm256_setzero_si256();
        core::ptr::write_volatile(cp, zero);
        core::ptr::write_volatile(cp.add(1), zero);
        core::ptr::write_volatile(cp.add(2), zero);
        core::ptr::write_volatile(cp.add(3), zero);

        // Transpose within each 128-bit half: afterwards register 4g + k
        // holds words 4g..4g+3 of block k (low half) and block k + 4
        // (high half).
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

        let p = buf.as_mut_ptr();
        macro_rules! put {
            ($off:expr, $v:expr) => {{
                let at = p.add($off).cast::<__m256i>();
                if XOR {
                    _mm256_storeu_si256(at, _mm256_xor_si256(_mm256_loadu_si256(at), $v));
                } else {
                    _mm256_storeu_si256(at, $v);
                }
            }};
        }
        macro_rules! emit {
            ($blk:expr, $r0:ident, $r1:ident, $r2:ident, $r3:ident) => {
                // Block `$blk` from the low halves, block `$blk + 4` from
                // the high halves.
                put!(64 * $blk, _mm256_permute2x128_si256($r0, $r1, 0x20));
                put!(64 * $blk + 32, _mm256_permute2x128_si256($r2, $r3, 0x20));
                put!(64 * ($blk + 4), _mm256_permute2x128_si256($r0, $r1, 0x31));
                put!(
                    64 * ($blk + 4) + 32,
                    _mm256_permute2x128_si256($r2, $r3, 0x31)
                );
            };
        }
        emit!(0, x0, x4, x8, x12);
        emit!(1, x1, x5, x9, x13);
        emit!(2, x2, x6, x10, x14);
        emit!(3, x3, x7, x11, x15);
    }
    low
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AVX2 tier itself, whatever `Detect` would choose on this CPU.
    struct Avx2Tier;
    impl ChaChaImpl for Avx2Tier {
        fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
            assert!(Detect::avx2_available());
            // SAFETY: the CPU has AVX2 — asserted on the line above.
            unsafe { apply_8way(key, nonce, counter, buf) }
        }
        fn seal_keystream(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8], otk: &mut [u8; 32]) {
            assert!(Detect::avx2_available());
            // SAFETY: as above.
            unsafe { seal_8way(key, nonce, buf, otk) }
        }
        fn open_keystream<F: FnOnce(&[u8; 32], &[u8]) -> bool>(
            key: &[u8; 32],
            nonce: &[u8; 12],
            buf: &mut [u8],
            verify: F,
        ) -> bool {
            assert!(Detect::avx2_available());
            // SAFETY: as above.
            unsafe { open_8way(key, nonce, buf, verify) }
        }
        fn name() -> &'static str {
            "avx2 tier"
        }
    }

    #[test]
    fn the_avx2_tier_matches_scalar() {
        if !Detect::avx2_available() {
            eprintln!("skipped: this CPU has no AVX2");
            return;
        }
        crate::check::all::<Avx2Tier>();
    }
}
