//! One `Device` on several threads: what the threads that receive for
//! their peers get done while other threads feed the same device what an
//! attacker would send.
//!
//!   lock_scaling <workers> <junk-threads> <kind> <packets-per-worker> <sharing>
//!                [io-ns] [max-seconds] [junk-io-ns]
//!
//! `sharing` is how the device is shared:
//!
//!   shared   by reference — `Device::receive_shared`, with the counters
//!            per thread and the cookie state behind a lock of its own
//!            (what the README and EMBEDDER_OBLIGATIONS §3.4 say to do)
//!   rwlock   behind an `RwLock`, held exclusively for `Device::receive`
//!            and shared for `identify`: what they used to say, and what
//!            a `&mut self` receive leaves one to do
//!   mutex    behind a `Mutex`
//!
//! `kind` is what the junk threads send: `none`, `garbage` (no message
//! at all), `badmac1` (handshake-shaped, wrong `mac1`), `identify`
//! (initiations with a valid `mac1`, not under load: an X25519 each),
//! `cookie` (the same under load: a cookie check and a reply each).
//!
//! Workers receive genuine 64-byte transport packets, each for its own
//! peer. `io-ns` is time each spends between two datagrams without the
//! device (the receive call a real I/O thread makes); with locks, how
//! long that is decides how often a worker finds the lock taken.

use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::time::Instant;

use wireguard_audit::{addr, forged_initiation};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    CookieState, Device, DeviceStats, Encapsulated, InTree, Incoming, PeerConfig, PeerId,
    PollOutput, Received, StaticSecret, Ticks, Tunnel, WallClock,
};

type P = InTree<wireguard_chacha_simd::Best>;

enum Shared {
    Mutex(Mutex<Device<P>>),
    RwLock(RwLock<Device<P>>),
    /// No lock around the device; one around what cookies are made of.
    Plain(Device<P>, RwLock<CookieState>),
}

impl Shared {
    /// Run `f` with the device shared (`identify` takes `&self`).
    fn shared<R>(&self, f: impl FnOnce(&Device<P>) -> R) -> R {
        match self {
            Self::Mutex(m) => f(&m.lock().unwrap()),
            Self::RwLock(l) => f(&l.read().unwrap()),
            Self::Plain(d, _) => f(d),
        }
    }

    /// `Device::receive`, the way this kind of sharing does it.
    fn receive<'d>(
        &self,
        t: Ticks,
        src: SocketAddr,
        under_load: bool,
        datagram: &'d mut [u8],
        stats: &mut DeviceStats,
    ) -> Incoming<'d> {
        match self {
            Self::Mutex(m) => m.lock().unwrap().receive(t, src, under_load, datagram),
            Self::RwLock(l) => l.write().unwrap().receive(t, src, under_load, datagram),
            Self::Plain(d, cookies) => {
                if under_load {
                    d.receive_shared(Some(&cookies.read().unwrap()), t, src, datagram, stats)
                } else {
                    d.receive_shared(None, t, src, datagram, stats)
                }
            }
        }
    }

    /// Under load: the cookie check and, for a message without a valid
    /// cookie, the reply.
    fn challenge(
        &self,
        t: Ticks,
        src: SocketAddr,
        datagram: &mut [u8],
        out: &mut [u8],
        rng: &mut DeterministicRng,
        stats: &mut DeviceStats,
    ) {
        match self {
            // Both need the device exclusively.
            Self::Mutex(_) | Self::RwLock(_) => {
                let mut reply = |d: &mut Device<P>| {
                    if let Incoming::CookieRequired(ch) = d.receive(t, src, true, datagram) {
                        let tx = d.cookie_reply(t, &ch, out, rng).unwrap();
                        black_box(tx.datagram);
                    }
                };
                match self {
                    Self::Mutex(m) => reply(&mut m.lock().unwrap()),
                    Self::RwLock(l) => reply(&mut l.write().unwrap()),
                    Self::Plain(..) => unreachable!(),
                }
            }
            // The check under the shared lock, the reply under the
            // exclusive one — and neither touches the device's own state.
            Self::Plain(d, cookies) => {
                let incoming =
                    d.receive_shared(Some(&cookies.read().unwrap()), t, src, datagram, stats);
                if let Incoming::CookieRequired(ch) = incoming {
                    let tx = d
                        .cookie_reply_shared(&mut cookies.write().unwrap(), t, &ch, out, rng, stats)
                        .unwrap();
                    black_box(tx.datagram);
                }
            }
        }
    }
}

/// Busy for about `ns` nanoseconds without holding anything: the receive
/// syscall a real I/O thread makes between two datagrams.
#[inline(never)]
fn io_gap(ns: u64) {
    if ns == 0 {
        return;
    }
    let t = Instant::now();
    while (t.elapsed().as_nanos() as u64) < ns {
        std::hint::spin_loop();
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let workers: usize = a[1].parse().unwrap();
    let junk_threads: usize = a[2].parse().unwrap();
    let junk_kind = a[3].clone();
    let per_worker: usize = a[4].parse().unwrap();
    let sharing = a.get(5).cloned().unwrap_or_else(|| "shared".into());
    let io_ns: u64 = a.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);
    // Stop after this many seconds even if packets are left.
    let max_secs: f64 = a.get(7).and_then(|s| s.parse().ok()).unwrap_or(1e9);
    // Unlocked time per junk datagram (default: the same I/O gap).
    let junk_gap_ns: u64 = a.get(8).and_then(|s| s.parse().ok()).unwrap_or(io_ns);

    let mut rng = DeterministicRng::new(0x10c4);
    let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
    let t = Ticks::from_nanos(1000);
    let src: SocketAddr = addr(9, 4000);
    let server_key = StaticSecret::generate(&mut rng).unwrap();
    let server_pub = server_key.public_key();
    let mut server = Device::<P>::with_provider(server_key, wall, &mut rng).unwrap();

    const PAYLOAD: usize = 64;
    const STRIDE: usize = 128;
    let mut jobs: Vec<(Tunnel<P>, Vec<u8>, usize)> = Vec::new();
    for i in 0..workers {
        let key = StaticSecret::generate(&mut rng).unwrap();
        let mut tunnel = server
            .tunnel(
                PeerId::new(i as u32).unwrap(),
                PeerConfig::new(key.public_key()),
                &mut rng,
            )
            .unwrap();
        let mut cfg = PeerConfig::new(server_pub);
        cfg.endpoint = Some(addr(1, 51820));
        let mut cdev = Device::<P>::with_provider(key, wall, &mut rng).unwrap();
        let mut ctun = cdev.tunnel(PeerId::new(0).unwrap(), cfg, &mut rng).unwrap();
        let (mut buf, mut out) = ([0u8; 256], [0u8; 256]);
        ctun.request_handshake(t);
        let mut init = match ctun.poll(t, &mut buf, &mut rng).unwrap() {
            PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
            other => panic!("{other:?}"),
        };
        let mut resp = match server.receive(t, src, false, &mut init) {
            Incoming::Initiation(init) => {
                match tunnel
                    .handle_initiation(t, &init, &mut out, &mut rng)
                    .unwrap()
                    .received
                {
                    Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        };
        let h = cdev
            .receive_for(
                &mut ctun,
                t,
                addr(1, 51820),
                false,
                &mut resp,
                &mut out,
                &mut rng,
            )
            .unwrap();
        assert!(matches!(h.received, Received::HandshakeComplete));
        let mut wire = vec![0u8; per_worker * STRIDE];
        let mut n = 0;
        for chunk in wire.chunks_exact_mut(STRIDE) {
            n = match ctun.encapsulate(t, &[0xdd; PAYLOAD], chunk).unwrap() {
                Encapsulated::Transport(tx) => tx.datagram.len(),
                other => panic!("{other:?}"),
            };
        }
        jobs.push((tunnel, wire, n));
    }
    // Under load, with a cookie secret in place, as it would be mid-attack.
    let mut cookies = CookieState::new();
    if junk_kind == "cookie" {
        let mut d = forged_initiation(&server_pub, &mut rng);
        let mut out = [0u8; 128];
        if let Incoming::CookieRequired(ch) = server.receive(t, src, true, &mut d) {
            let _ = server.cookie_reply(t, &ch, &mut out, &mut rng).unwrap();
        }
        let mut stats = DeviceStats::default();
        let mut d = forged_initiation(&server_pub, &mut rng);
        if let Incoming::CookieRequired(ch) =
            server.receive_shared(Some(&cookies), t, src, &mut d, &mut stats)
        {
            let _ = server
                .cookie_reply_shared(&mut cookies, t, &ch, &mut out, &mut rng, &mut stats)
                .unwrap();
        }
    }

    let shared = Arc::new(match sharing.as_str() {
        "shared" => Shared::Plain(server, RwLock::new(cookies)),
        "rwlock" => Shared::RwLock(RwLock::new(server)),
        "mutex" => Shared::Mutex(Mutex::new(server)),
        other => panic!("sharing {other}"),
    });
    let barrier = Arc::new(Barrier::new(workers + junk_threads + 1));
    let stop = Arc::new(AtomicBool::new(false));
    let junk_done = Arc::new(AtomicU64::new(0));

    let mut junk_handles = Vec::new();
    for j in 0..junk_threads {
        let (shared, barrier, stop, junk_done, kind) = (
            Arc::clone(&shared),
            Arc::clone(&barrier),
            Arc::clone(&stop),
            Arc::clone(&junk_done),
            junk_kind.clone(),
        );
        junk_handles.push(std::thread::spawn(move || {
            let mut rng = DeterministicRng::new(77 + j as u64);
            let mut bad = forged_initiation(&server_pub, &mut rng);
            let mut good = bad;
            bad[120] ^= 1;
            let mut garbage = [0xffu8; 40];
            let mut out = [0u8; 128];
            let from = addr(66, 6666);
            let mut stats = DeviceStats::default();
            barrier.wait();
            let mut done = 0u64;
            while !stop.load(Ordering::Relaxed) {
                io_gap(junk_gap_ns);
                match kind.as_str() {
                    "garbage" => {
                        black_box(shared.receive(t, from, false, &mut garbage, &mut stats));
                    }
                    "badmac1" => {
                        black_box(shared.receive(t, from, false, &mut bad, &mut stats));
                    }
                    "identify" => {
                        // Not under load: `receive` (cheap), then the
                        // X25519 of `identify`, for which the device is
                        // shared in every arrangement.
                        let incoming = shared.receive(t, from, false, &mut good, &mut stats);
                        if let Incoming::Initiation(mut init) = incoming {
                            let r = shared.shared(|d| d.identify(&mut init));
                            black_box(r.is_err());
                        }
                    }
                    "cookie" => {
                        shared.challenge(t, from, &mut good, &mut out, &mut rng, &mut stats);
                    }
                    _ => std::thread::yield_now(),
                }
                done += 1;
            }
            junk_done.fetch_add(done, Ordering::Relaxed);
        }));
    }

    let mut handles = Vec::new();
    for (mut tunnel, mut wire, n) in jobs {
        let (shared, barrier) = (Arc::clone(&shared), Arc::clone(&barrier));
        handles.push(std::thread::spawn(move || {
            let mut stats = DeviceStats::default();
            barrier.wait();
            let t0 = Instant::now();
            let mut done = 0u64;
            for chunk in wire.chunks_exact_mut(STRIDE) {
                if done % 64 == 0 && t0.elapsed().as_secs_f64() > max_secs {
                    break;
                }
                io_gap(io_ns);
                let datagram = &mut chunk[..n];
                // A lock, if there is one, is held for `receive` only;
                // what it returns borrows the datagram, not the device.
                let incoming = shared.receive(t, src, false, datagram, &mut stats);
                match incoming {
                    Incoming::ForPeer(_, pkt) => match tunnel.handle(t, src, pkt).unwrap().received
                    {
                        Received::Data(p) => {
                            black_box(p);
                        }
                        other => panic!("{other:?}"),
                    },
                    other => panic!("{other:?}"),
                }
                done += 1;
            }
            (done, t0.elapsed().as_secs_f64())
        }));
    }
    barrier.wait();
    let t0 = Instant::now();
    let results: Vec<(u64, f64)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let wall_s = t0.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    for h in junk_handles {
        let _ = h.join();
    }
    let rate: f64 = results.iter().map(|(n, s)| *n as f64 / s).sum();
    println!(
        "workers={workers} junk={junk_threads}x{junk_kind} sharing={sharing}: legit {:.0} pkt/s total ({:.0}/s per worker); junk handled {:.3} M/s",
        rate,
        rate / workers as f64,
        junk_done.load(Ordering::Relaxed) as f64 / wall_s / 1e6,
    );
}
