//! Buffer pool: bounded freelist of MTU-sized scratch buffers with RAII
//! return-on-drop, so the steady-state data path does **zero heap
//! allocation**.
//!
//! # Why these buffers are "pinned enough"
//!
//! Each buffer is a `Box<[u8]>`: one heap allocation whose address never
//! moves for the life of the box (Rust guarantees `Box` contents have a
//! stable address). That is exactly the property completion-based I/O
//! (io_uring `IORING_OP_RECV` with registered buffers, Windows RIO)
//! needs — the kernel can DMA straight into the slab while userspace
//! holds only the handle.
//!
//! tokio's default `UdpSocket` is *readiness*-based (epoll/IOCP poll
//! mode), so it doesn't strictly need stable addresses; but using the
//! same pool means switching to `tokio-uring` later is a socket swap,
//! not a buffer-management rewrite.
//!
//! # Sizing
//!
//! `SlabPool::for_wireguard()` picks a slab of `MAX_DATAGRAM` bytes —
//! large enough for a 1500-byte-MTU IP packet plus the 32-byte transport
//! overhead plus 16 bytes of padding headroom. Change it if you run
//! jumbo frames.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

/// Largest datagram a WireGuard transport message can be for a
/// 1500-byte-MTU inner packet, rounded up: 1500 padded to 1504 + 32
/// overhead = 1536, plus slack.
pub const MAX_DATAGRAM: usize = 2048;

/// A source of reusable byte buffers.
pub trait BufferPool: Send + Sync + fmt::Debug {
    /// Buffer capacity this pool hands out.
    fn slab_len(&self) -> usize;
    /// Take a buffer of `slab_len()` bytes. The contents are
    /// **unspecified** (likely the previous user's leftovers) — callers
    /// either overwrite the prefix they use and slice to that length, or
    /// zero what they need. May allocate when the freelist is empty.
    fn take(&self) -> Box<[u8]>;
    /// Return a buffer for reuse. Buffers of the wrong size are dropped.
    fn give(&self, buf: Box<[u8]>);
}

/// The trivial pool: every `take` allocates, every `give` drops. Kept
/// for tests and as the documented "no pooling" baseline.
#[derive(Debug, Clone, Copy)]
pub struct NoPool {
    slab_len: usize,
}

impl NoPool {
    /// A non-pooling pool with the given slab size.
    #[must_use]
    pub const fn new(slab_len: usize) -> Self {
        Self { slab_len }
    }
}

impl Default for NoPool {
    fn default() -> Self {
        Self::new(MAX_DATAGRAM)
    }
}

impl BufferPool for NoPool {
    fn slab_len(&self) -> usize {
        self.slab_len
    }
    fn take(&self) -> Box<[u8]> {
        vec![0u8; self.slab_len].into_boxed_slice()
    }
    fn give(&self, _buf: Box<[u8]>) {}
}

/// A bounded freelist of fixed-size boxed slabs.
///
/// `take()` pops the freelist (O(1), one mutex acquire) or allocates a
/// fresh slab when empty; `give()` pushes back up to `max_idle`, drops
/// beyond that. Under steady-state traffic the freelist saturates and
/// the data path never allocates.
///
/// The mutex is held only for the `Vec::pop`/`push` — nanoseconds. If a
/// lock-free MPMC queue is wanted later, this is the one type to swap.
pub struct SlabPool {
    slab_len: usize,
    max_idle: usize,
    free: Mutex<Vec<Box<[u8]>>>,
    /// Buffers handed out and not yet returned. Diagnostic only.
    outstanding: std::sync::atomic::AtomicUsize,
}

impl SlabPool {
    /// New pool of `slab_len`-byte buffers, retaining at most `max_idle`
    /// on the freelist.
    #[must_use]
    pub fn new(slab_len: usize, max_idle: usize) -> Arc<Self> {
        Arc::new(Self {
            slab_len,
            max_idle,
            free: Mutex::new(Vec::with_capacity(max_idle)),
            outstanding: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Pool sized for WireGuard at a 1500-byte MTU: 2 KiB slabs, up to
    /// 256 idle (≈ one replay-window's worth of in-flight packets).
    #[must_use]
    pub fn for_wireguard() -> Arc<Self> {
        Self::new(MAX_DATAGRAM, 256)
    }

    /// Pre-fill the freelist so the first `n` takes never allocate
    /// (e.g. before going realtime).
    pub fn prefill(&self, n: usize) {
        let n = n.min(self.max_idle);
        if let Ok(mut free) = self.free.lock() {
            while free.len() < n {
                free.push(vec![0u8; self.slab_len].into_boxed_slice());
            }
        }
    }

    /// RAII handle: returns to the pool on drop. Prefer this over
    /// [`BufferPool::take`] — it's what [`crate::Tunn`] and the async
    /// driver use.
    #[must_use]
    pub fn get(self: &Arc<Self>) -> PooledBuf {
        let storage = BufferPool::take(self.as_ref());
        PooledBuf {
            storage: Some(storage),
            len: 0,
            pool: Arc::clone(self),
        }
    }

    /// Buffers currently checked out (diagnostic).
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.outstanding.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Buffers currently idle on the freelist (diagnostic).
    #[must_use]
    pub fn idle(&self) -> usize {
        self.free.lock().map(|f| f.len()).unwrap_or(0)
    }
}

impl BufferPool for SlabPool {
    fn slab_len(&self) -> usize {
        self.slab_len
    }
    fn take(&self) -> Box<[u8]> {
        self.outstanding
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut free) = self.free.lock() {
            if let Some(buf) = free.pop() {
                return buf;
            }
        }
        vec![0u8; self.slab_len].into_boxed_slice()
    }
    fn give(&self, buf: Box<[u8]>) {
        self.outstanding
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if buf.len() != self.slab_len {
            return; // foreign buffer — drop it.
        }
        if let Ok(mut free) = self.free.lock() {
            if free.len() < self.max_idle {
                free.push(buf);
            }
        }
    }
}

impl fmt::Debug for SlabPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlabPool")
            .field("slab_len", &self.slab_len)
            .field("max_idle", &self.max_idle)
            .field("idle", &self.idle())
            .field("outstanding", &self.outstanding())
            .finish()
    }
}

/// An RAII buffer checked out of a [`SlabPool`].
///
/// * `Deref`/`DerefMut` to `[u8]` give the **filled prefix** (`len`
///   bytes); use [`PooledBuf::spare_mut`] for the full backing slab when
///   you need to write into it (e.g. as a `recv()` destination), then
///   [`PooledBuf::set_len`] to record how much was written.
/// * Dropping returns the slab to the pool. The contents are **not**
///   wiped — the protocol layer never puts long-lived secrets in these
///   (transport plaintext lives here transiently, same as in any
///   socket buffer).
/// * The backing `Box<[u8]>` has a stable heap address for its whole
///   life, so handing `spare_mut().as_mut_ptr()` to a completion-based
///   kernel API (io_uring registered buffer, RIO) is sound as long as
///   the `PooledBuf` outlives the operation.
pub struct PooledBuf {
    storage: Option<Box<[u8]>>,
    /// Filled-prefix length (`0..=slab_len`).
    len: usize,
    pool: Arc<SlabPool>,
}

impl PooledBuf {
    /// The full backing slab, mutably — pass this to `recv()` etc.
    #[must_use]
    pub fn spare_mut(&mut self) -> &mut [u8] {
        self.storage.as_deref_mut().unwrap_or(&mut [])
    }

    /// Record how many bytes of the slab are now valid (e.g. the return
    /// value of `recv()`). Clamped to the slab size.
    pub fn set_len(&mut self, len: usize) {
        let cap = self.storage.as_deref().map_or(0, <[u8]>::len);
        self.len = len.min(cap);
    }

    /// The filled-prefix length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// `len() == 0`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Backing slab capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.storage.as_deref().map_or(0, <[u8]>::len)
    }

    /// Copy `data` into a fresh pooled buffer (queue-a-packet helper).
    #[must_use]
    pub fn copy_from(pool: &Arc<SlabPool>, data: &[u8]) -> Self {
        let mut b = pool.get();
        let n = data.len().min(b.capacity());
        if let Some(dst) = b.spare_mut().get_mut(..n) {
            dst.copy_from_slice(data.get(..n).unwrap_or(&[]));
        }
        b.set_len(n);
        b
    }
}

impl Deref for PooledBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.storage
            .as_deref()
            .and_then(|s| s.get(..self.len))
            .unwrap_or(&[])
    }
}

impl DerefMut for PooledBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.storage
            .as_deref_mut()
            .and_then(|s| s.get_mut(..self.len))
            .unwrap_or(&mut [])
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(storage) = self.storage.take() {
            self.pool.give(storage);
        }
    }
}

impl fmt::Debug for PooledBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PooledBuf")
            .field("len", &self.len)
            .field("capacity", &self.capacity())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn slab_pool_recycles() {
        let pool = SlabPool::new(128, 4);
        assert_eq!(pool.idle(), 0);
        // Hold four out simultaneously so four distinct slabs allocate.
        let bufs: Vec<PooledBuf> = (0..4).map(|_| pool.get()).collect();
        let addrs: Vec<usize> = bufs
            .iter()
            .map(|b| b.storage.as_ref().unwrap().as_ptr() as usize)
            .collect();
        assert_eq!(pool.outstanding(), 4);
        drop(bufs);
        assert_eq!(pool.idle(), 4);
        assert_eq!(pool.outstanding(), 0);
        // Next four gets reuse exactly those slabs (LIFO).
        let mut held = Vec::new();
        for expected in addrs.iter().rev() {
            let b = pool.get();
            assert_eq!(b.storage.as_ref().unwrap().as_ptr() as usize, *expected);
            held.push(b);
        }
        assert_eq!(pool.idle(), 0);
    }

    #[test]
    fn pool_is_bounded() {
        let pool = SlabPool::new(64, 2);
        let bufs: Vec<_> = (0..10).map(|_| pool.get()).collect();
        assert_eq!(pool.outstanding(), 10);
        drop(bufs);
        assert_eq!(pool.idle(), 2, "freelist must not exceed max_idle");
        assert_eq!(pool.outstanding(), 0);
    }

    #[test]
    fn pooled_buf_len_and_deref() {
        let pool = SlabPool::new(32, 4);
        let mut b = pool.get();
        assert_eq!(b.len(), 0);
        assert_eq!(b.capacity(), 32);
        b.spare_mut()[..5].copy_from_slice(b"hello");
        b.set_len(5);
        assert_eq!(&*b, b"hello");
        b.set_len(1000);
        assert_eq!(b.len(), 32, "clamped to capacity");
    }

    #[test]
    fn copy_from_helper() {
        let pool = SlabPool::new(32, 4);
        let b = PooledBuf::copy_from(&pool, b"wireguard");
        assert_eq!(&*b, b"wireguard");
    }

    #[test]
    fn stable_address_across_moves() {
        // The whole point for io_uring/RIO: moving the PooledBuf does
        // NOT move the backing bytes.
        let pool = SlabPool::new(64, 1);
        let b = pool.get();
        let addr = b.storage.as_ref().unwrap().as_ptr() as usize;
        let b2 = b; // move
        assert_eq!(b2.storage.as_ref().unwrap().as_ptr() as usize, addr);
        let boxed = Box::new(b2); // move into a Box
        assert_eq!(boxed.storage.as_ref().unwrap().as_ptr() as usize, addr);
    }
}
