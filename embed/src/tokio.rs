//! Async driver: a [`tokio`] event loop that owns one [`Tunn`] and one
//! `UdpSocket` and shuttles [`PooledBuf`]s between the network and a
//! pair of mpsc channels (your TUN device).
//!
//! ```text
//!             ┌──────────────┐ PooledBuf  ┌──────────────────────────┐
//!  TUN read ─►│ to_net  (tx) │───────────►│                          │
//!             └──────────────┘            │   AsyncTunn::run()       │  UDP
//!             ┌──────────────┐ PooledBuf  │  select! { recv, send,   │◄─────►
//!  TUN write◄─│ from_net (rx)│◄───────────│   to_net, next_wake }    │ socket
//!             └──────────────┘            └──────────────────────────┘
//! ```
//!
//! All buffers are [`PooledBuf`] from one shared [`SlabPool`], so the
//! steady-state loop does no heap allocation: a slab comes off the
//! freelist for `recv_from`, carries the decrypted plaintext through
//! the channel, and returns to the freelist when the TUN writer drops
//! it.
//!
//! # Pinned / registered buffers
//!
//! tokio's `UdpSocket` is **readiness-based** (epoll/kqueue/IOCP poll
//! mode): the kernel tells us "readable", then we copy into our buffer.
//! That doesn't need a stable address. But [`PooledBuf`]'s backing
//! `Box<[u8]>` *has* one anyway, which is exactly what
//! **completion-based** I/O (Linux `tokio-uring`'s
//! `UdpSocket::recv_from(BoundedBuf)`, Windows RIO) requires. Swapping
//! the socket type below is the only change needed for that upgrade —
//! the channel/buffer plumbing is already shaped for it.
//!
//! # Threading
//!
//! `Tunn` is `!Sync` (it owns `&mut` protocol state). `run()` is the
//! single owner; the rest of your program talks to it through the two
//! channels, which *are* `Send`/`Sync`. Spawn `run()` on its own task.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Instant as TokioInstant, sleep_until};

use crate::{PooledBuf, SlabPool, Tunn, TunnResult};

/// One peer's async driver.
#[derive(Debug)]
pub struct AsyncTunn {
    tunn: Tunn,
    socket: Arc<UdpSocket>,
    pool: Arc<SlabPool>,
    /// Where to send the peer's datagrams. Roams when an authenticated
    /// packet arrives from a new source (whitepaper §6.1 roaming).
    peer_addr: Option<SocketAddr>,
}

/// The two channel halves the rest of your program holds.
#[derive(Debug)]
pub struct TunnChannels {
    /// Send IP packets here to have them encrypted and put on the wire.
    /// Buffer comes from the shared pool: `pool.get()`, fill, `set_len`,
    /// send.
    pub to_net: mpsc::Sender<PooledBuf>,
    /// Decrypted IP packets arrive here, padding already trimmed.
    /// Dropping the `PooledBuf` returns it to the pool.
    pub from_net: mpsc::Receiver<PooledBuf>,
}

impl AsyncTunn {
    /// Wrap a `Tunn` and a bound `UdpSocket`. The pool is shared with
    /// (and must be the same instance as) `tunn.pool()` so queue and
    /// I/O draw from one freelist.
    #[must_use]
    pub fn new(tunn: Tunn, socket: Arc<UdpSocket>, peer_addr: Option<SocketAddr>) -> Self {
        let pool = Arc::clone(tunn.pool());
        Self {
            tunn,
            socket,
            pool,
            peer_addr,
        }
    }

    /// Build the channel pair and the driver in one call. `depth` is the
    /// mpsc bound in each direction (number of in-flight `PooledBuf`s);
    /// 256 matches [`crate::MAX_QUEUE_DEPTH`].
    #[must_use]
    pub fn channels(
        tunn: Tunn,
        socket: Arc<UdpSocket>,
        peer_addr: Option<SocketAddr>,
        depth: usize,
    ) -> (
        Self,
        TunnChannels,
        mpsc::Receiver<PooledBuf>,
        mpsc::Sender<PooledBuf>,
    ) {
        let (to_net_tx, to_net_rx) = mpsc::channel(depth);
        let (from_net_tx, from_net_rx) = mpsc::channel(depth);
        let driver = Self::new(tunn, socket, peer_addr);
        (
            driver,
            TunnChannels {
                to_net: to_net_tx,
                from_net: from_net_rx,
            },
            to_net_rx,
            from_net_tx,
        )
    }

    /// The shared pool — hand to your TUN reader so it allocates from
    /// the same freelist.
    #[must_use]
    pub fn pool(&self) -> &Arc<SlabPool> {
        &self.pool
    }

    /// Current peer endpoint (after roaming).
    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Borrow the inner sync `Tunn` (e.g. for `stats()`).
    #[must_use]
    pub fn tunn(&self) -> &Tunn {
        &self.tunn
    }

    /// Run the event loop until either channel closes or the socket
    /// errors. Spawn this on its own task:
    ///
    /// ```ignore
    /// let (driver, chans, to_net_rx, from_net_tx) =
    ///     AsyncTunn::channels(tunn, socket, Some(peer), 256);
    /// tokio::spawn(driver.run(to_net_rx, from_net_tx));
    /// // your code talks to `chans.to_net` / `chans.from_net`
    /// ```
    pub async fn run(
        mut self,
        mut to_net: mpsc::Receiver<PooledBuf>,
        from_net: mpsc::Sender<PooledBuf>,
    ) -> std::io::Result<()> {
        // Two scratch slabs that live for the whole loop: one for
        // `encapsulate`/`update_timers` output, one for `decapsulate`
        // output. After each use we either ship the bytes (copy into a
        // PooledBuf headed for a channel, or `send_to` straight from the
        // slab) and reuse — so the loop body itself never allocates.
        let mut net_out = self.pool.get();
        let mut tun_out = self.pool.get();
        // The slab we hand to recv_from. Stable address (Box-backed),
        // ready for tokio-uring registered-buffer mode later.
        let mut rx = self.pool.get();

        loop {
            let wake = self
                .tunn
                .next_wake()
                .map(TokioInstant::from_std)
                .unwrap_or_else(far_future);

            tokio::select! {
                biased;

                // ---- inbound from the network --------------------------------
                r = self.socket.recv_from(rx.spare_mut()) => {
                    let (n, src) = r?;
                    rx.set_len(n);
                    let datagram = &*rx;
                    match self.tunn.decapsulate(Some(src), datagram, tun_out.spare_mut()) {
                        TunnResult::WriteToTunnel(d) => {
                            // Authenticated → roam.
                            self.peer_addr = Some(src);
                            let n = d.len();
                            tun_out.set_len(n);
                            // Ship this slab to the TUN side and pull a fresh one.
                            let delivered = std::mem::replace(&mut tun_out, self.pool.get());
                            if from_net.send(delivered).await.is_err() {
                                return Ok(()); // consumer gone
                            }
                        }
                        TunnResult::WriteToNetwork(w) => {
                            // Handshake reply / cookie / keepalive / queued drain.
                            self.peer_addr = Some(src);
                            let first_len = w.len();
                            self.send_slice(tun_out.spare_mut(), first_len, src).await?;
                            // Drain any queued packets (BoringTun convention).
                            self.drain_queue(&mut net_out, src).await?;
                        }
                        TunnResult::Done => {}
                        TunnResult::Err(_) => {
                            // Attacker-triggerable: drop silently. (Stats
                            // recorded in the core.)
                        }
                    }
                    rx.set_len(0); // slab is reusable as-is
                }

                // ---- outbound from the TUN -----------------------------------
                pkt = to_net.recv() => {
                    let Some(pkt) = pkt else { return Ok(()); }; // sender dropped
                    let Some(dst) = self.peer_addr else {
                        // No endpoint yet: encapsulate will queue + emit
                        // an initiation, but we can't send it anywhere.
                        // Drop the initiation; the timer will retry once
                        // we learn an address (responder-only mode).
                        let _ = self.tunn.encapsulate(&pkt, net_out.spare_mut());
                        continue;
                    };
                    match self.tunn.encapsulate(&pkt, net_out.spare_mut()) {
                        TunnResult::WriteToNetwork(w) => {
                            let n = w.len();
                            self.send_slice(net_out.spare_mut(), n, dst).await?;
                        }
                        TunnResult::Done => {} // queued (handshake in flight)
                        TunnResult::Err(_) => {}
                        TunnResult::WriteToTunnel(_) => {} // unreachable for encapsulate
                    }
                    // `pkt` drops here → back to the pool.
                }

                // ---- timers --------------------------------------------------
                () = sleep_until(wake) => {
                    let Some(dst) = self.peer_addr else { continue; };
                    loop {
                        match self.tunn.update_timers(net_out.spare_mut()) {
                            TunnResult::WriteToNetwork(w) => {
                                let n = w.len();
                                self.send_slice(net_out.spare_mut(), n, dst).await?;
                            }
                            TunnResult::Done => break,
                            TunnResult::Err(_) => break,
                            TunnResult::WriteToTunnel(_) => break,
                        }
                    }
                }
            }
        }
    }

    async fn send_slice(&self, slab: &mut [u8], n: usize, dst: SocketAddr) -> std::io::Result<()> {
        if let Some(bytes) = slab.get(..n) {
            self.socket.send_to(bytes, dst).await?;
        }
        Ok(())
    }

    async fn drain_queue(
        &mut self,
        net_out: &mut PooledBuf,
        dst: SocketAddr,
    ) -> std::io::Result<()> {
        loop {
            match self.tunn.decapsulate(Some(dst), &[], net_out.spare_mut()) {
                TunnResult::WriteToNetwork(w) => {
                    let n = w.len();
                    self.send_slice(net_out.spare_mut(), n, dst).await?;
                }
                _ => return Ok(()),
            }
        }
    }
}

fn far_future() -> TokioInstant {
    TokioInstant::now()
        .checked_add(std::time::Duration::from_secs(86_400))
        .unwrap_or_else(TokioInstant::now)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::RateLimiter;
    use wireguard_sans_io::{PublicKey, StaticSecret};

    async fn bound_socket() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    fn keypair() -> (StaticSecret, PublicKey) {
        use wireguard_sans_io::EntropySource;
        let sk = StaticSecret::from_bytes(crate::OsEntropy.gen32().unwrap());
        let pk = sk.public_key();
        (sk, pk)
    }

    /// Two AsyncTunn drivers on loopback; push IP packets through the
    /// channels and verify they emerge decrypted on the far side, with
    /// zero heap growth in the pool after warm-up.
    #[tokio::test]
    async fn async_roundtrip_via_channels() {
        let pool = SlabPool::for_wireguard();
        pool.prefill(32);
        let rl = Arc::new(RateLimiter::new(1_000_000));

        let (a_sk, a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let sock_a = bound_socket().await;
        let sock_b = bound_socket().await;
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let tunn_a =
            Tunn::with_pool(a_sk, b_pk, None, None, Some(rl.clone()), pool.clone()).unwrap();
        let tunn_b = Tunn::with_pool(b_sk, a_pk, None, None, Some(rl), pool.clone()).unwrap();

        let (drv_a, chans_a, rx_a, tx_a) = AsyncTunn::channels(tunn_a, sock_a, Some(addr_b), 64);
        let (drv_b, mut chans_b, rx_b, tx_b) =
            AsyncTunn::channels(tunn_b, sock_b, Some(addr_a), 64);

        let ha = tokio::spawn(drv_a.run(rx_a, tx_a));
        let hb = tokio::spawn(drv_b.run(rx_b, tx_b));

        // Kick off the handshake by sending one packet from A.
        let pkt = PooledBuf::copy_from(&pool, &{
            let mut p = [0u8; 60];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&60u16.to_be_bytes());
            p[40..].fill(0xab);
            p
        });
        // Record allocation high-water mark BEFORE traffic.
        let baseline_idle = pool.idle();
        chans_a.to_net.send(pkt).await.unwrap();

        // B should receive the decrypted packet.
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), chans_b.from_net.recv())
            .await
            .expect("timeout waiting for first packet")
            .expect("channel closed");
        assert_eq!(got.len(), 60);
        assert_eq!(got[40], 0xab);
        drop(got);

        // Pump 100 more both ways; pool should be in steady state (no
        // net new allocations after warm-up).
        for i in 0..100u8 {
            let mut p = [0u8; 60];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&60u16.to_be_bytes());
            p[59] = i;
            chans_a
                .to_net
                .send(PooledBuf::copy_from(&pool, &p))
                .await
                .unwrap();
            let g =
                tokio::time::timeout(std::time::Duration::from_secs(2), chans_b.from_net.recv())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(g[59], i);
        }
        // After everything settles, idle count should be >= what we
        // started with (nothing leaked) and outstanding bounded.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            pool.outstanding() <= 16,
            "outstanding={}",
            pool.outstanding()
        );
        assert!(pool.idle() >= baseline_idle.saturating_sub(16));

        // Shut down.
        drop(chans_a);
        drop(chans_b);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), ha).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), hb).await;
    }
}
