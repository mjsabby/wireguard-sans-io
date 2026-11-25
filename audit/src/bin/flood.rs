//! A loopback rig for the tokio event loop
//! (`wireguard_embed::tokio::AsyncTunn`), as three processes so that each
//! can be given cores of its own (`scripts/flood_rig.sh` does):
//!
//!   flood server <port>                         the victim: one peer, echoes what it decrypts
//!   flood client <server-port> <pps> <payload> <secs>   the legitimate peer: pings, reports loss and RTT
//!   flood attack <server-port> <kind> <threads> <pps-per-thread|0> <secs> [sources]
//!
//! Attack kinds (what the sender has to know):
//!   garbage   40 bytes of 0xff                       (nothing)
//!   badmac1   handshake-shaped, wrong mac1           (nothing)
//!   junk4     transport-shaped, random index, 1452 B (nothing)
//!   init      initiation, valid mac1, random body    (the server's public key)
//!
//! The server's limiter is the default one, or what `WG_LIMITER` says:
//! `count:<n>`, `budget:<ms>`, `both:<n>:<ms>`, with `,replies:<per-second>`
//! appended for a cap on cookie replies.
//!
//! Keys are fixed (seeded): this is a test rig.

use std::net::{SocketAddr, UdpSocket as StdUdp};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use wireguard_audit::forged_initiation;
use wireguard_embed::tokio::AsyncTunn;
use wireguard_embed::{RateLimiter, Tunn};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{EntropySource, StaticSecret};

fn keys() -> (StaticSecret, StaticSecret) {
    let mut rng = DeterministicRng::new(0x5e7);
    let mut s = [0u8; 32];
    let mut c = [0u8; 32];
    rng.fill(&mut s).unwrap();
    rng.fill(&mut c).unwrap();
    (StaticSecret::from_bytes(s), StaticSecret::from_bytes(c))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => server(args[2].parse().unwrap()),
        Some("client") => client(
            args[2].parse().unwrap(),
            args[3].parse().unwrap(),
            args[4].parse().unwrap(),
            args[5].parse().unwrap(),
        ),
        Some("attack") => attack(
            args[2].parse().unwrap(),
            &args[3],
            args[4].parse().unwrap(),
            args[5].parse().unwrap(),
            args[6].parse().unwrap(),
            args.get(7).and_then(|s| s.parse().ok()).unwrap_or(1),
        ),
        _ => eprintln!("usage: see the source"),
    }
}

fn runtime(workers: usize) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------- server

fn server(port: u16) {
    let (server_key, client_key) = keys();
    // WG_LIMITER=default | count:<n> | budget:<ms> | both:<n>:<ms>,
    // each optionally followed by ,replies:<per-second>
    let spec = std::env::var("WG_LIMITER").unwrap_or_else(|_| "default".into());
    let (signal, replies) = match spec.split_once(",replies:") {
        Some((signal, cap)) => (signal, Some(cap.parse::<u64>().unwrap())),
        None => (spec.as_str(), None),
    };
    let parts: Vec<&str> = signal.split(':').collect();
    let limiter = match parts.as_slice() {
        ["count", n] => RateLimiter::new(n.parse().unwrap()),
        ["budget", ms] => RateLimiter::with_budget(Duration::from_millis(ms.parse().unwrap())),
        ["both", n, ms] => RateLimiter::with_limits(
            n.parse().unwrap(),
            Duration::from_millis(ms.parse().unwrap()),
        ),
        _ => RateLimiter::default(),
    };
    let limiter = Arc::new(match replies {
        Some(per_second) => limiter.with_cookie_reply_limit(per_second),
        None => limiter,
    });
    println!("[srv] limiter: {spec}");
    let tunn = Tunn::new(
        server_key,
        client_key.public_key(),
        None,
        None,
        None,
        Some(Arc::clone(&limiter)),
    )
    .unwrap();
    runtime(2).block_on(async move {
        let socket = Arc::new(
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port)))
                .await
                .unwrap(),
        );
        let (driver, mut chans, to_net_rx, from_net_tx) = AsyncTunn::channels(tunn, socket, 1024);
        let stats = driver.loop_stats();
        tokio::spawn(driver.run(to_net_rx, from_net_tx));
        // Echo: whatever the peer sent goes straight back.
        let echoed = Arc::new(AtomicU64::new(0));
        let e2 = Arc::clone(&echoed);
        tokio::spawn(async move {
            while let Some(packet) = chans.from_net.recv().await {
                e2.fetch_add(1, Ordering::Relaxed);
                let _ = chans.to_net.try_send(packet);
            }
        });
        // Once a second: what arrived, by what became of it, as rates.
        let mut last = [0u64; 7];
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        let t0 = Instant::now();
        loop {
            // The load signal, sampled a hundred times in that second.
            let started = Instant::now();
            let (mut loaded, mut samples) = (0u32, 0u32);
            while started.elapsed() < Duration::from_secs(1) {
                tick.tick().await;
                samples += 1;
                loaded += u32::from(limiter.is_under_load());
            }
            let secs = started.elapsed().as_secs_f64();
            let d = stats.device_stats();
            let t = stats.tunnel_stats();
            let now = [
                d.malformed,
                d.mac1_failures,
                d.initiations,
                d.cookies_required,
                d.cookies_sent,
                t.handshakes_responded,
                echoed.load(Ordering::Relaxed),
            ];
            let rate = |i: usize| ((now[i] - last[i]) as f64 / secs).round() as u64;
            println!(
                "[srv {:>3}s] malformed/s={} mac1fail/s={} init-passed/s={} cookie-required/s={} cookies/s={} hs-resp/s={} echoed/s={} auth_fail={} tun_drops={} egress_drops={} hs_drops={} cookie_drops={} under_load={}%",
                t0.elapsed().as_secs(),
                rate(0),
                rate(1),
                rate(2),
                rate(3),
                rate(4),
                rate(5),
                rate(6),
                t.auth_failures,
                stats.tun_drops(),
                stats.egress_drops(),
                stats.handshake_drops(),
                stats.cookie_reply_drops(),
                loaded * 100 / samples.max(1),
            );
            last = now;
        }
    });
}

// ---------------------------------------------------------------- client

/// A minimal IPv4 header so the driver's padding trim has a length to go
/// by; then a sequence number and a send time.
fn ping(buf: &mut [u8], len: usize, seq: u64, sent_ns: u64) {
    buf[..len].fill(0);
    buf[0] = 0x45;
    buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    buf[20..28].copy_from_slice(&seq.to_le_bytes());
    buf[28..36].copy_from_slice(&sent_ns.to_le_bytes());
}

fn client(server_port: u16, pps: u64, payload: usize, secs: u64) {
    assert!(payload >= 36);
    let (server_key, client_key) = keys();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], server_port));
    let tunn = Tunn::new(
        client_key,
        server_key.public_key(),
        None,
        None,
        Some(server_addr),
        None,
    )
    .unwrap();
    runtime(2).block_on(async move {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (driver, mut chans, to_net_rx, from_net_tx) = AsyncTunn::channels(tunn, socket, 1024);
        let pool = Arc::clone(driver.pool());
        let stats = driver.loop_stats();
        tokio::spawn(driver.run(to_net_rx, from_net_tx));

        let epoch = Instant::now();
        const SLOT_MS: u64 = 50;
        let slots = (secs * 1000 / SLOT_MS) as usize + 2;
        // per slot: sent, received, rtt sum (µs), rtt max (µs)
        let sent: Arc<Vec<AtomicU64>> = Arc::new((0..slots).map(|_| AtomicU64::new(0)).collect());
        let recv: Arc<Vec<AtomicU64>> = Arc::new((0..slots).map(|_| AtomicU64::new(0)).collect());
        let rtt_max: Arc<Vec<AtomicU64>> = Arc::new((0..slots).map(|_| AtomicU64::new(0)).collect());
        let first_echo_ns = Arc::new(AtomicU64::new(0));
        let rtts = Arc::new(std::sync::Mutex::new(Vec::<u32>::with_capacity(1 << 20)));

        let (r2, m2, f2, rt2) = (
            Arc::clone(&recv),
            Arc::clone(&rtt_max),
            Arc::clone(&first_echo_ns),
            Arc::clone(&rtts),
        );
        tokio::spawn(async move {
            while let Some(packet) = chans.from_net.recv().await {
                if packet.len() < 36 {
                    continue;
                }
                let now_ns = epoch.elapsed().as_nanos() as u64;
                let sent_ns = u64::from_le_bytes(packet[28..36].try_into().unwrap());
                let rtt_us = now_ns.saturating_sub(sent_ns) / 1000;
                let slot = (sent_ns / 1_000_000 / SLOT_MS) as usize;
                if let Some(c) = r2.get(slot) {
                    c.fetch_add(1, Ordering::Relaxed);
                    m2[slot].fetch_max(rtt_us, Ordering::Relaxed);
                }
                let _ = f2.compare_exchange(0, now_ns, Ordering::Relaxed, Ordering::Relaxed);
                rt2.lock().unwrap().push(rtt_us.min(u32::MAX as u64) as u32);
            }
        });

        let interval = Duration::from_nanos(1_000_000_000 / pps.max(1));
        let mut next = tokio::time::Instant::now();
        let mut seq = 0u64;
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            let now_ns = epoch.elapsed().as_nanos() as u64;
            let mut buf = pool.get();
            ping(buf.spare_mut(), payload, seq, now_ns);
            buf.set_len(payload);
            seq += 1;
            let slot = (now_ns / 1_000_000 / SLOT_MS) as usize;
            if let Some(c) = sent.get(slot) {
                c.fetch_add(1, Ordering::Relaxed);
            }
            let _ = chans.to_net.try_send(buf);
            next += interval;
            tokio::time::sleep_until(next).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        let first = first_echo_ns.load(Ordering::Relaxed);
        println!(
            "[cli] time to first echo (handshake + round trip): {:.1} ms",
            first as f64 / 1e6
        );
        // Per-second summary and the worst 50 ms slots.
        let per_sec = (1000 / SLOT_MS) as usize;
        let mut worst: Vec<(usize, u64, u64, u64)> = Vec::new();
        for s in 0..secs as usize {
            let (mut st, mut rc, mut mx) = (0u64, 0u64, 0u64);
            let mut dead_slots = 0;
            for k in 0..per_sec {
                let i = s * per_sec + k;
                let (a, b, c) = (
                    sent[i].load(Ordering::Relaxed),
                    recv[i].load(Ordering::Relaxed),
                    rtt_max[i].load(Ordering::Relaxed),
                );
                st += a;
                rc += b;
                mx = mx.max(c);
                if a > 0 && b * 2 < a {
                    dead_slots += 1;
                }
                if a > 0 {
                    worst.push((i, a, b, c));
                }
            }
            println!(
                "[cli {s:>3}s] sent={st} echoed={rc} loss={:.1}% max_rtt={:.2}ms slots(50ms)-with->50%-loss={dead_slots}/{per_sec}",
                100.0 * (st.saturating_sub(rc)) as f64 / st.max(1) as f64,
                mx as f64 / 1000.0
            );
        }
        let mut all = rtts.lock().unwrap().clone();
        all.sort_unstable();
        let q = |p: f64| -> f64 {
            if all.is_empty() {
                return f64::NAN;
            }
            all[((all.len() - 1) as f64 * p) as usize] as f64 / 1000.0
        };
        let total_sent: u64 = sent.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        println!(
            "[cli] total sent={} echoed={} loss={:.2}% rtt p50={:.3}ms p99={:.3}ms p99.9={:.3}ms max={:.3}ms",
            total_sent,
            all.len(),
            100.0 * (total_sent as f64 - all.len() as f64) / total_sent.max(1) as f64,
            q(0.5),
            q(0.99),
            q(0.999),
            q(1.0)
        );
        // The loss pattern over one stretch of the run, slot by slot.
        let from = (secs as usize / 2) * per_sec;
        let line: String = (from..(from + 3 * per_sec).min(slots))
            .map(|i| {
                let (a, b) = (sent[i].load(Ordering::Relaxed), recv[i].load(Ordering::Relaxed));
                if a == 0 {
                    ' '
                } else {
                    match 10 * b / a {
                        10.. => '.',
                        8..=9 => ':',
                        5..=7 => 'o',
                        1..=4 => 'X',
                        _ => '#',
                    }
                }
            })
            .collect();
        println!("[cli] 3 s of 50 ms slots from t={}s ('.'=all echoed ':'>=80% 'o'>=50% 'X'<50% '#'=none):", secs / 2);
        println!("[cli] |{line}|");
        println!(
            "[cli] client loop: tun_drops={} send_errors={} queue_drops={}",
            stats.tun_drops(),
            stats.send_errors(),
            stats.queue_drops()
        );
    });
}

// ---------------------------------------------------------------- attacker

fn attack(server_port: u16, kind: &str, threads: usize, pps: u64, secs: u64, sources: usize) {
    let (server_key, _) = keys();
    let server_pub = server_key.public_key();
    let dst = SocketAddr::from(([127, 0, 0, 1], server_port));
    let stop = Arc::new(AtomicBool::new(false));
    let total = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for th in 0..threads {
        let (stop, total, kind) = (Arc::clone(&stop), Arc::clone(&total), kind.to_string());
        handles.push(std::thread::spawn(move || {
            let mut rng = DeterministicRng::new(0xbad + th as u64);
            // Many source addresses: all of 127/8 is this host.
            let socks: Vec<StdUdp> = (0..sources.max(1))
                .map(|i| {
                    let n = th * sources + i + 2;
                    let ip = [127, 1 + (n >> 16) as u8, (n >> 8) as u8, n as u8];
                    let s = StdUdp::bind(SocketAddr::from((ip, 0))).unwrap();
                    s.set_nonblocking(true).unwrap();
                    s
                })
                .collect();
            // A few thousand distinct datagrams, so that nothing is cached
            // on the far side that a real flood would not have.
            let datagrams: Vec<Vec<u8>> = (0..2048)
                .map(|_| match kind.as_str() {
                    "garbage" => vec![0xffu8; 40],
                    "badmac1" => {
                        let mut d = forged_initiation(&server_pub, &mut rng).to_vec();
                        d[120] ^= 1;
                        d
                    }
                    "junk4" => {
                        let mut d = vec![0u8; 1452];
                        rng.fill(&mut d).unwrap();
                        d[0] = 4;
                        d[1] = 0;
                        d[2] = 0;
                        d[3] = 0;
                        d
                    }
                    "init" => forged_initiation(&server_pub, &mut rng).to_vec(),
                    other => panic!("kind {other}"),
                })
                .collect();
            let gap = if pps == 0 {
                None
            } else {
                Some(Duration::from_nanos(1_000_000_000 / pps))
            };
            let mut next = Instant::now();
            let (mut i, mut sent) = (0usize, 0u64);
            while !stop.load(Ordering::Relaxed) {
                let s = &socks[i % socks.len()];
                if s.send_to(&datagrams[i % datagrams.len()], dst).is_ok() {
                    sent += 1;
                }
                i += 1;
                if let Some(gap) = gap {
                    next += gap;
                    while Instant::now() < next {
                        std::hint::spin_loop();
                    }
                }
                if i % 4096 == 0 {
                    total.fetch_add(sent, Ordering::Relaxed);
                    sent = 0;
                    // Do not let cookie replies pile up in our own buffers.
                    let mut scratch = [0u8; 128];
                    for s in &socks {
                        while s.recv_from(&mut scratch).is_ok() {}
                    }
                }
            }
            total.fetch_add(sent, Ordering::Relaxed);
        }));
    }
    let t0 = Instant::now();
    let mut last = 0;
    while t0.elapsed() < Duration::from_secs(secs) {
        std::thread::sleep(Duration::from_secs(1));
        let now = total.load(Ordering::Relaxed);
        println!("[atk] {kind}: {} pps", now - last);
        last = now;
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
}
