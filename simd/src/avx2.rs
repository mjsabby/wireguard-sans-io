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
//! stack buffer that is wiped — unless it is at most six blocks (384
//! bytes). Such tails are common (transport payloads are padded to 16
//! bytes, not to a stride; a small packet is nothing but tail), and a
//! stride is a poor way to make them: it costs what eight blocks cost.
//!
//! # Two blocks, four, six
//!
//! They have a kernel of their own ([`pairs`]), which is the other way
//! of putting ChaCha20 into 256-bit registers: a register holds a *row*
//! of the state — four words — of two blocks, one in each 128-bit half.
//! The whole state of a pair of blocks is four registers, a quarter-round
//! on registers is the four quarter-rounds of a round at once, and
//! between the column round and the diagonal round the rows are rotated
//! against each other. A round is then one chain of twelve operations
//! where the scalar code has four of them to get through, and two blocks
//! cost less than one does there: about 300 cycles against 400 apiece on
//! the machine this was written on. That is the keystream of every packet
//! of up to 64 bytes — an ACK, a keepalive, a DNS query — which is block
//! 0 for the authenticator key and one block of stream; such a packet
//! used to be two scalar blocks, three quarters of what sealing it cost.
//!
//! One chain leaves most of the core idle, so a second pair of blocks
//! next to the first costs little, and a third little more: about 380
//! cycles for four blocks and 440 for six, where a stride — eight — is
//! 550. Up to six blocks are therefore pairs, and only more than that a
//! stride. (Four pairs at once are no better than the stride: the state
//! is then all sixteen registers.)
//!
//! For an AEAD, block 0 — the one-time authenticator key — is a block of
//! the first stride, or of the first pair ([`ChaChaImpl::seal_keystream`],
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
//! keystream are zeroed before a function returns — and so is a
//! kernel's whole stack frame, where the compiler parks registers it has
//! no room for (words of the key and of the keystream among them): its
//! caller overwrites it after the last stride (`clear_frames`, see the
//! crate documentation). The kernel for pairs reads the key from where
//! the caller has it, straight into registers: there is no copy of it to
//! zero.
//!
//! # Safety
//!
//! Every `unsafe` block is one of:
//! 1. a call to a kernel or a `core::arch::x86_64` intrinsic, for which
//!    AVX2 has been established as above — by `cfg` for the build, or by
//!    the run-time check on the line before;
//! 2. an unaligned load or store through a pointer into a `[u8; 512]`
//!    (the kernel for pairs: an array of `[u8; 128]`s, and the
//!    `[u8; 32]` of the key) that the function was handed by reference,
//!    at fixed offsets inside it;
//! 3. a volatile read or write of one of the four slots of a local
//!    array.
//!
//! No attacker-controlled length, pointer, or index reaches an
//! intrinsic.

#![allow(unsafe_code)]

use core::arch::x86_64::*;

use wireguard_sans_io::crypto::ct;

use crate::{ChaChaImpl, SIGMA, Scalar, clear_frames, load_key_words, nonce_words, xor_tail};

/// The longest tail the AVX-512 module hands to the scalar code: two
/// blocks. A stride costs about as much as two and a quarter scalar
/// blocks whatever its width, so for one or two blocks — every small
/// packet: a keepalive, an ACK, a DNS query — it is the wrong tool.
/// (This module has [`pairs`] for them, and [`Detect`] sends what is
/// small as a whole there on every CPU.)
#[cfg(wg_avx512)]
pub(crate) const SCALAR_TAIL_MAX: usize = 128;

/// What one stride yields.
const STRIDE: usize = 512;

/// What a pair of blocks yields.
const PAIR: usize = 128;

/// The most that goes through [`pairs`] and not through a stride: three
/// pairs, six blocks.
const PAIRS_MAX: usize = 3 * PAIR;

/// What one pair leaves for an AEAD's stream once block 0 has gone to
/// the authenticator key: one block. A packet of up to this is the
/// smallest there is to do, and what [`Detect`] always has done here.
const PAIR_STREAM: usize = PAIR - 64;

/// The same of three pairs: five blocks.
const PAIRS_STREAM_MAX: usize = PAIRS_MAX - 64;

/// What [`clear_frames`] overwrites at once after the kernel, in 64-bit
/// words: its frame is about half a kilobyte in an optimised build (the
/// four `c` rows and a dozen parked registers of thirty-two bytes).
const KERNEL_FRAME: usize = 112;

/// The same after [`pairs`] of one pair: four rows, their inputs and two
/// masks are a dozen registers of sixteen, so in an optimised build
/// nothing is parked and the frame is a few saved registers.
#[cfg_attr(wg_low_opt, allow(dead_code))] // such a build does not size its clean-up
const PAIR_FRAME: usize = 16;

/// …and of two or three pairs: twelve rows are all the registers there
/// are but four, and the counters and the masks want those.
#[cfg_attr(wg_low_opt, allow(dead_code))]
const PAIRS_FRAME: usize = 64;

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
    /// One or two blocks are [`two_blocks`].
    const SMALL_PACKETS: bool = true;

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
    /// One or two blocks are the AVX2 kernel for that on every CPU that
    /// has AVX2 (and the scalar code's, as before, on one that has not).
    const SMALL_PACKETS: bool = true;

    #[inline]
    fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        // (One or two blocks are the AVX2 pair kernel's on every CPU
        // that has it, which is every CPU with AVX-512.)
        #[cfg(wg_avx512)]
        if buf.len() > PAIR && crate::avx512::available() {
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
        // (As above: a small packet is block 0 and one block of stream.)
        #[cfg(wg_avx512)]
        if buf.len() > PAIR_STREAM && crate::avx512::available() {
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
        if buf.len() > PAIR_STREAM && crate::avx512::available() {
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
    let nw = nonce_words(nonce);
    if buf.len() <= PAIR {
        // One or two blocks: the kernel for that, which reads the key
        // where it is.
        if !buf.is_empty() {
            let mut ks = [[0u8; PAIR]; 1];
            // SAFETY: AVX2 is available (this function's contract).
            let low = unsafe { pairs(key, &nw, counter, &mut ks) };
            clear_frames::<PAIR_FRAME>(low);
            xor_tail(buf, ks.as_flattened());
            ct::wipe(ks.as_flattened_mut());
        }
        return;
    }
    if buf.len() <= PAIRS_MAX {
        // Up to six: the same, two or three pairs at a time.
        let mut ks = [[0u8; PAIR]; 3];
        // SAFETY: as above.
        let low = unsafe { few_blocks(key, &nw, counter, buf.len(), &mut ks) };
        clear_frames::<PAIRS_FRAME>(low);
        xor_tail(buf, ks.as_flattened());
        ct::wipe(ks.as_flattened_mut());
        return;
    }
    let mut kw = [0u32; 8];
    load_key_words(key, &mut kw);
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
    if tail.len() > PAIRS_MAX {
        let mut ks = [0u8; STRIDE];
        // SAFETY: as above.
        low = low.min(unsafe { eight_blocks::<false>(&kw, &nw, ctr, &mut ks) });
        xor_tail(tail, &ks);
        ct::wipe_array(&mut ks);
    } else if tail.len() > PAIR {
        let mut ks = [[0u8; PAIR]; 3];
        // SAFETY: as above.
        low = low.min(unsafe { few_blocks(key, &nw, ctr, tail.len(), &mut ks) });
        xor_tail(tail, ks.as_flattened());
        ct::wipe(ks.as_flattened_mut());
    } else if !tail.is_empty() {
        let mut ks = [[0u8; PAIR]; 1];
        // SAFETY: as above.
        low = low.min(unsafe { pairs(key, &nw, ctr, &mut ks) });
        xor_tail(tail, ks.as_flattened());
        ct::wipe(ks.as_flattened_mut());
    }
    ct::wipe_words(&mut kw);
    clear_frames::<KERNEL_FRAME>(low);
}

/// The keystream for `len` bytes — at most [`PAIRS_MAX`] — from block
/// `ctr` on, at the start of `ks`: one, two or three pairs of blocks, as
/// many as it takes. Returns what [`pairs`] returns.
///
/// # Safety
/// Caller must ensure the `avx2` target feature is available.
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn few_blocks(
    key: &[u8; 32],
    nonce: &[u32; 3],
    ctr: u32,
    len: usize,
    ks: &mut [[u8; PAIR]; 3],
) -> usize {
    if len <= PAIR {
        if let Some(one) = ks.first_chunk_mut::<1>() {
            // SAFETY: AVX2 is available (this function's contract).
            return unsafe { pairs(key, nonce, ctr, one) };
        }
    } else if len <= 2 * PAIR {
        if let Some(two) = ks.first_chunk_mut::<2>() {
            // SAFETY: as above.
            return unsafe { pairs(key, nonce, ctr, two) };
        }
    }
    // SAFETY: as above.
    unsafe { pairs(key, nonce, ctr, ks) }
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
    let nw = nonce_words(nonce);
    if buf.len() <= PAIR_STREAM {
        // Two blocks in all: block 0 and the stream's one, as a pair.
        let mut ks = [[0u8; PAIR]; 1];
        // SAFETY: AVX2 is available (this function's contract).
        let low = unsafe { pairs(key, &nw, 0, &mut ks) };
        clear_frames::<PAIR_FRAME>(low);
        for (d, s) in otk.iter_mut().zip(ks.as_flattened()) {
            *d = *s;
        }
        xor_tail(buf, ks.as_flattened().get(64..).unwrap_or(&[]));
        ct::wipe(ks.as_flattened_mut());
        return;
    }
    if buf.len() <= PAIRS_STREAM_MAX {
        // Up to six blocks in all: two or three pairs.
        let mut ks = [[0u8; PAIR]; 3];
        // SAFETY: as above.
        let low = unsafe { few_blocks(key, &nw, 0, buf.len().saturating_add(64), &mut ks) };
        clear_frames::<PAIRS_FRAME>(low);
        for (d, s) in otk.iter_mut().zip(ks.as_flattened()) {
            *d = *s;
        }
        xor_tail(buf, ks.as_flattened().get(64..).unwrap_or(&[]));
        ct::wipe(ks.as_flattened_mut());
        return;
    }
    let mut kw = [0u32; 8];
    load_key_words(key, &mut kw);
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
    let nw = nonce_words(nonce);
    if buf.len() <= PAIR_STREAM {
        // As in `seal_8way`: one pair. Both blocks are made before the
        // verdict — which is still less than the scalar code's one.
        let mut ks = [[0u8; PAIR]; 1];
        // SAFETY: AVX2 is available (this function's contract).
        let low = unsafe { pairs(key, &nw, 0, &mut ks) };
        clear_frames::<PAIR_FRAME>(low);
        let ok = match ks.as_flattened().first_chunk::<32>() {
            Some(otk) => verify(otk, buf),
            None => false,
        };
        if ok {
            xor_tail(buf, ks.as_flattened().get(64..).unwrap_or(&[]));
        }
        ct::wipe(ks.as_flattened_mut());
        return ok;
    }
    if buf.len() <= PAIRS_STREAM_MAX {
        // …or two or three.
        let mut ks = [[0u8; PAIR]; 3];
        // SAFETY: as above.
        let low = unsafe { few_blocks(key, &nw, 0, buf.len().saturating_add(64), &mut ks) };
        clear_frames::<PAIRS_FRAME>(low);
        let ok = match ks.as_flattened().first_chunk::<32>() {
            Some(otk) => verify(otk, buf),
            None => false,
        };
        if ok {
            xor_tail(buf, ks.as_flattened().get(64..).unwrap_or(&[]));
        }
        ct::wipe(ks.as_flattened_mut());
        return ok;
    }
    let mut kw = [0u32; 8];
    load_key_words(key, &mut kw);
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

/// `N` pairs of keystream blocks, from block `ctr` on, written to `out`:
/// the other layout (see the module documentation). Each register is a
/// row of the state of one pair, the even block in its low half and the
/// odd one in its high half; the diagonal round is the column round on
/// rows that have been rotated against each other. The pairs are
/// independent of each other and go through the rounds side by side.
///
/// The key is read from `key` into registers — once for the state and
/// once for the feed-forward — and is nowhere else. Returns where the
/// stack ends beneath this function's frame, as [`eight_blocks`] does
/// and for the same reason; never inlined, for the same reason too.
///
/// # Safety
/// Caller must ensure the `avx2` target feature is available.
#[target_feature(enable = "avx2")]
#[inline(never)]
#[allow(clippy::multiple_unsafe_ops_per_block, clippy::indexing_slicing)] // every line is an intrinsic; indices below N, from loops over 0..N
unsafe fn pairs<const N: usize>(
    key: &[u8; 32],
    nonce: &[u32; 3],
    ctr: u32,
    out: &mut [[u8; PAIR]; N],
) -> usize {
    // Taken before anything is in a vector register: a call in the
    // middle would have all of them saved around it.
    let low = ct::stack_mark();
    // SAFETY: every intrinsic is gated by `target_feature(avx2)`; the
    // loads through `kp` are 16 bytes at offsets 0 and 16 of the 32-byte
    // array `key`; the stores through a `block` pointer are 32 bytes at
    // offsets 0, 32, 64 and 96 of one of the 128-byte arrays of `out`.
    unsafe {
        // pshufb masks, broadcast across both 128-bit halves.
        let rol16 = _mm256_broadcastsi128_si256(_mm_set_epi8(
            13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
        ));
        let rol8 = _mm256_broadcastsi128_si256(_mm_set_epi8(
            14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
        ));
        let [s0, s1, s2, s3] = SIGMA.map(|word| word as i32);
        let [n0, n1, n2] = nonce.map(|word| word as i32);
        let kp = key.as_ptr();
        let sigma = _mm256_setr_epi32(s0, s1, s2, s3, s0, s1, s2, s3);
        // Pair i is blocks `ctr + 2 i` (low half) and `ctr + 2 i + 1`
        // (high half), wrapping, per RFC 8439.
        let mut d0 = [sigma; N];
        let mut first = ctr;
        for row in &mut d0 {
            *row = _mm256_setr_epi32(
                first as i32,
                n0,
                n1,
                n2,
                first.wrapping_add(1) as i32,
                n0,
                n1,
                n2,
            );
            first = first.wrapping_add(2);
        }
        let mut a = [sigma; N];
        let mut b = [_mm256_broadcastsi128_si256(_mm_loadu_si128(kp.cast())); N];
        let mut c = [_mm256_broadcastsi128_si256(_mm_loadu_si128(kp.add(16).cast())); N];
        let mut d = d0;
        // One step for every pair before the next step for any: the
        // pairs' chains then run next to each other.
        macro_rules! each {
            ($row:ident = $op:ident($($arg:tt)*)) => {
                for i in 0..N {
                    $row[i] = $op!(i, $($arg)*);
                }
            };
        }
        macro_rules! add {
            ($i:ident, $x:ident, $y:ident) => {
                _mm256_add_epi32($x[$i], $y[$i])
            };
        }
        macro_rules! xor {
            ($i:ident, $x:ident, $y:ident) => {
                _mm256_xor_si256($x[$i], $y[$i])
            };
        }
        macro_rules! xor_rol {
            ($i:ident, $x:ident, $y:ident, $mask:ident) => {
                _mm256_shuffle_epi8(_mm256_xor_si256($x[$i], $y[$i]), $mask)
            };
        }
        macro_rules! rol {
            ($i:ident, $x:ident, $left:literal, $right:literal) => {
                _mm256_or_si256(
                    _mm256_slli_epi32($x[$i], $left),
                    _mm256_srli_epi32($x[$i], $right),
                )
            };
        }
        // The four quarter-rounds of a round, on whole rows.
        macro_rules! round {
            () => {
                each!(a = add(a, b));
                each!(d = xor_rol(d, a, rol16));
                each!(c = add(c, d));
                each!(b = xor(b, c));
                each!(b = rol(b, 12, 20));
                each!(a = add(a, b));
                each!(d = xor_rol(d, a, rol8));
                each!(c = add(c, d));
                each!(b = xor(b, c));
                each!(b = rol(b, 7, 25));
            };
        }
        for _ in 0..10 {
            // Columns.
            round!();
            // Diagonals: the rows are rotated against each other — and
            // back afterwards. Against row b, which stays where it is:
            // b is the last a round computes and the first thing the next
            // one needs, so a shuffle of b would be one more link in the
            // chain, while the others have time to spare. (Word i of b
            // meets word i - 1 of a, i + 1 of c and i + 2 of d.)
            for ((a, c), d) in a.iter_mut().zip(c.iter_mut()).zip(d.iter_mut()) {
                *a = _mm256_shuffle_epi32(*a, 0b10_01_00_11);
                *c = _mm256_shuffle_epi32(*c, 0b00_11_10_01);
                *d = _mm256_shuffle_epi32(*d, 0b01_00_11_10);
            }
            round!();
            for ((a, c), d) in a.iter_mut().zip(c.iter_mut()).zip(d.iter_mut()) {
                *a = _mm256_shuffle_epi32(*a, 0b00_11_10_01);
                *c = _mm256_shuffle_epi32(*c, 0b10_01_00_11);
                *d = _mm256_shuffle_epi32(*d, 0b01_00_11_10);
            }
        }
        // Feed-forward, the key from where it was read before (it was
        // not kept in registers across the rounds), and out: a block is
        // the low halves of the four rows, in order; the next one the
        // high halves.
        let kb = _mm256_broadcastsi128_si256(_mm_loadu_si128(kp.cast()));
        let kc = _mm256_broadcastsi128_si256(_mm_loadu_si128(kp.add(16).cast()));
        for (block, (a, (b, (c, (d, d0))))) in out.iter_mut().zip(
            a.iter()
                .zip(b.iter().zip(c.iter().zip(d.iter().zip(d0.iter())))),
        ) {
            let a = _mm256_add_epi32(*a, sigma);
            let b = _mm256_add_epi32(*b, kb);
            let c = _mm256_add_epi32(*c, kc);
            let d = _mm256_add_epi32(*d, *d0);
            let p = block.as_mut_ptr();
            _mm256_storeu_si256(p.cast(), _mm256_permute2x128_si256(a, b, 0x20));
            _mm256_storeu_si256(p.add(32).cast(), _mm256_permute2x128_si256(c, d, 0x20));
            _mm256_storeu_si256(p.add(64).cast(), _mm256_permute2x128_si256(a, b, 0x31));
            _mm256_storeu_si256(p.add(96).cast(), _mm256_permute2x128_si256(c, d, 0x31));
        }
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

    /// The kernel for pairs by itself: its blocks are the scalar code's
    /// blocks `ctr`, `ctr + 1`, … — for one, two and three pairs, for the
    /// counters that matter (the first, the last, where a block's number
    /// wraps inside a pair and between two) and for keys and nonces with
    /// every bit of every word in play.
    #[test]
    fn the_pair_kernel_makes_scalar_blocks() {
        use wireguard_sans_io::crypto::chacha20::block;
        if !Detect::avx2_available() {
            eprintln!("skipped: this CPU has no AVX2");
            return;
        }
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 56) as u8
        };
        let mut keys: Vec<([u8; 32], [u8; 12])> = vec![
            ([0u8; 32], [0u8; 12]),
            ([0xff; 32], [0xff; 12]),
            (
                crate::check::rfc_key(),
                [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0],
            ),
        ];
        for _ in 0..200 {
            let mut key = [0u8; 32];
            key.iter_mut().for_each(|b| *b = next());
            let mut nonce = [0u8; 12];
            nonce.iter_mut().for_each(|b| *b = next());
            keys.push((key, nonce));
        }
        fn check<const N: usize>(key: &[u8; 32], nonce: &[u8; 12], ctr: u32) {
            let mut out = [[0xa5u8; PAIR]; N];
            // SAFETY: the CPU has AVX2 — the caller has checked.
            let low = unsafe { pairs(key, &nonce_words(nonce), ctr, &mut out) };
            clear_frames::<PAIRS_FRAME>(low);
            for (i, made) in out.as_flattened().chunks_exact(64).enumerate() {
                assert!(
                    made == &block(key, ctr.wrapping_add(i as u32), nonce)[..],
                    "{N} pairs from block {ctr}: block {i}"
                );
            }
        }
        for (key, nonce) in &keys {
            for ctr in [
                0,
                1,
                2,
                0x7fff_ffff,
                0x8000_0000,
                u32::MAX - 5,
                u32::MAX - 4,
                u32::MAX - 3,
                u32::MAX - 2,
                u32::MAX - 1,
                u32::MAX,
            ] {
                check::<1>(key, nonce, ctr);
                check::<2>(key, nonce, ctr);
                check::<3>(key, nonce, ctr);
            }
        }
    }
}
