//! What a flood of handshake messages costs a tunnel that is up.
//!
//! Anyone who knows a public key can send handshake initiations that
//! pass `mac1`, at whatever rate their uplink allows. The protocol's
//! answer is the cookie: under load, such a message gets a cookie reply
//! and nothing else. That bounds what one message costs — it says nothing
//! about the session that is already up, whose packets arrive on the same
//! socket and are served by the same loop. These tests measure that part:
//! a server (an [`AsyncTunn`] that echoes what it decrypts), its peer
//! (pinging through the tunnel two thousand times a second) and an
//! attacker (threads sending forged initiations from other sockets), on
//! loopback, in real time.
//!
//! They are ignored by default, because they are about time: they need
//! a machine with eight idle cores, and say nothing on a busy or a
//! smaller one.
//!
//! ```sh
//! cargo test --release -p wireguard-embed --features async --test flood -- --ignored --nocapture
//! ```
//!
//! What they showed when they were written (16 cores at 4.5 GHz; the
//! peer's packets lost while the flood lasted), before and after the
//! loop learned to put traffic first (`src/tokio.rs`, "Traffic first")
//! and the load signal to spend its budget evenly
//! (`src/rate_limiter.rs`):
//!
//! | forged initiations a second | before | after |
//! |---|---|---|
//! | 150,000 | 7–9 %: a tenth of every second, at a stretch | none |
//! | 400,000 | all | under half a percent |
//! | 800,000 | all | a third |
//! | 3,000,000 (four threads, flat out) | all | three quarters |
//!
//! The last two are more than one loop can look at — about 540,000 a
//! second here, a third of its time going to cookie replies — and what
//! is lost is what the socket's buffer had no room for: the peer's
//! datagrams at the same odds as the attacker's. A larger buffer does
//! not change that; fewer datagrams per core do (a second socket and
//! loop on the same port, a filter in front).
//!
//! `audit/src/bin/flood.rs` is the same rig as three processes
//! (`scripts/flood_rig.sh`), for giving each cores of its own and for
//! `perf`.
#![cfg(feature = "async")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::UdpSocket as StdUdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use wireguard_embed::Tunn;
use wireguard_embed::core::crypto::blake2s;
use wireguard_embed::core::testing::DeterministicRng;
use wireguard_embed::core::{EntropySource, PublicKey, StaticSecret};
use wireguard_embed::tokio::AsyncTunn;

/// Pings through the tunnel, a second.
const PINGS: u64 = 2_000;
/// The length of a ping: an IPv4 header's worth, a sequence number and
/// the time it was sent.
const PING_LEN: usize = 64;
/// Results are kept per slot of this many milliseconds.
const SLOT_MS: u64 = 50;
/// The session is up and quiet for this long before the flood starts.
const LEAD: Duration = Duration::from_millis(1500);

/// One test at a time: they measure, and would measure each other.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// A handshake initiation with a valid `mac1` for `responder` and random
/// contents otherwise.
fn forged_initiation(responder: &PublicKey, rng: &mut DeterministicRng) -> Vec<u8> {
    let mut m = vec![0u8; 148];
    rng.fill(&mut m[4..116]).unwrap();
    m[0] = 1;
    let key = blake2s::hash(&[b"mac1----", responder.as_bytes()]);
    let mac = blake2s::mac(&key, &[&m[..116]]);
    m[116..132].copy_from_slice(&mac);
    m
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// What one slot of the run saw: pings sent in it, how many of those
/// came back, and the longest any of them took (µs).
#[derive(Clone, Copy, Debug, Default)]
struct Slot {
    sent: u64,
    echoed: u64,
    worst_us: u64,
}

struct Outcome {
    /// The slots during which the flood was running.
    flood: Vec<Slot>,
    /// The slots before it.
    quiet: Vec<Slot>,
    /// Forged initiations the attacker sent, a second.
    sent_pps: u64,
    /// … and how many of them the server's loop got to see, a second.
    seen_pps: u64,
    /// Cookie replies the server sent, a second.
    cookies_pps: u64,
}

impl Outcome {
    fn lost(slots: &[Slot]) -> f64 {
        let sent: u64 = slots.iter().map(|s| s.sent).sum();
        let echoed: u64 = slots.iter().map(|s| s.echoed).sum();
        100.0 * sent.saturating_sub(echoed) as f64 / sent.max(1) as f64
    }

    fn worst_ms(slots: &[Slot]) -> f64 {
        slots.iter().map(|s| s.worst_us).max().unwrap_or(0) as f64 / 1000.0
    }

    /// The smallest share of its pings that any stretch of `slots`
    /// consecutive slots got back.
    fn worst_stretch(&self, slots: usize) -> f64 {
        self.flood
            .chunks(slots)
            .filter(|chunk| chunk.len() == slots)
            .map(|chunk| 100.0 - Self::lost(chunk))
            .fold(100.0, f64::min)
    }

    fn print(&self, what: &str) {
        let picture: String = self
            .flood
            .iter()
            .map(|s| match (10 * s.echoed).checked_div(s.sent) {
                None => ' ',
                Some(10..) => '.',
                Some(8..=9) => ':',
                Some(5..=7) => 'o',
                Some(1..=4) => 'X',
                Some(_) => '#',
            })
            .collect();
        println!(
            "{what}: {} forged initiations a second sent, {} seen by the loop, {} cookie replies a second",
            self.sent_pps, self.seen_pps, self.cookies_pps
        );
        println!(
            "  before the flood: {:.2} % of pings lost, slowest {:.2} ms",
            Self::lost(&self.quiet),
            Self::worst_ms(&self.quiet)
        );
        println!(
            "  during the flood: {:.2} % of pings lost, slowest {:.2} ms",
            Self::lost(&self.flood),
            Self::worst_ms(&self.flood)
        );
        println!(
            "  {SLOT_MS} ms slots ('.' all echoed, ':' ≥ 80 %, 'o' ≥ 50 %, 'X' < 50 %, '#' none):"
        );
        println!("  |{picture}|");
    }
}

/// A server, its peer and `threads` attacker threads sending
/// `pps_per_thread` forged initiations a second each (0: as many as they
/// can) for `secs` seconds.
fn flood(threads: usize, pps_per_thread: u64, secs: u64) -> Outcome {
    let mut rng = DeterministicRng::new(0x5e7);
    let (mut server_key, mut client_key) = ([0u8; 32], [0u8; 32]);
    rng.fill(&mut server_key).unwrap();
    rng.fill(&mut client_key).unwrap();
    let (server_key, client_key) = (
        StaticSecret::from_bytes(server_key),
        StaticSecret::from_bytes(client_key),
    );
    let (server_public, client_public) = (server_key.public_key(), client_key.public_key());

    // The server: the default limiter, and an echo on the TUN side.
    let server_runtime = runtime();
    let (server_addr, server_stats) = server_runtime.block_on(async {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let tunn = Tunn::new(server_key, client_public, None, None, None, None).unwrap();
        let (driver, mut channels, to_net, from_net) = AsyncTunn::channels(tunn, socket, 1024);
        let stats = driver.loop_stats();
        tokio::spawn(driver.run(to_net, from_net));
        tokio::spawn(async move {
            while let Some(packet) = channels.from_net.recv().await {
                let _ = channels.to_net.try_send(packet);
            }
        });
        (addr, stats)
    });

    // The attacker's datagrams: a few thousand different ones, so that
    // nothing is cached on the far side that a real flood would not have.
    let datagrams: Arc<Vec<Vec<u8>>> = Arc::new(
        (0..2048)
            .map(|_| forged_initiation(&server_public, &mut rng))
            .collect(),
    );
    let stop = Arc::new(AtomicBool::new(false));
    let forged = Arc::new(AtomicU64::new(0));
    let attack = |thread: usize| {
        let (datagrams, stop, forged) = (datagrams.clone(), stop.clone(), forged.clone());
        std::thread::spawn(move || {
            let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            let gap =
                (pps_per_thread > 0).then(|| Duration::from_nanos(1_000_000_000 / pps_per_thread));
            let mut next = Instant::now();
            let (mut i, mut sent) = (thread * 97, 0u64);
            let mut scratch = [0u8; 128];
            while !stop.load(Ordering::Relaxed) {
                if socket
                    .send_to(&datagrams[i % datagrams.len()], server_addr)
                    .is_ok()
                {
                    sent += 1;
                }
                i += 1;
                if let Some(gap) = gap {
                    next += gap;
                    while Instant::now() < next {
                        std::hint::spin_loop();
                    }
                }
                if i % 1024 == 0 {
                    forged.fetch_add(sent, Ordering::Relaxed);
                    sent = 0;
                    // The cookie replies are not to pile up here.
                    while socket.recv_from(&mut scratch).is_ok() {}
                }
            }
            forged.fetch_add(sent, Ordering::Relaxed);
        })
    };

    // The peer: pings, and notes when each comes back.
    let run = LEAD + Duration::from_secs(secs);
    let slots = (run.as_millis() as u64 / SLOT_MS) as usize;
    let table: Arc<Vec<[AtomicU64; 3]>> = Arc::new(
        (0..slots + 1)
            .map(|_| [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)])
            .collect(),
    );
    let client_runtime = runtime();
    let (flood_from, flood_until, seen, cookies, attackers) = client_runtime.block_on(async {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tunn = Tunn::new(
            client_key,
            server_public,
            None,
            None,
            Some(server_addr),
            None,
        )
        .unwrap();
        let (driver, mut channels, to_net, from_net) = AsyncTunn::channels(tunn, socket, 1024);
        let pool = driver.pool().clone();
        tokio::spawn(driver.run(to_net, from_net));

        // The session first: pings until one comes back.
        let up = tokio::time::Instant::now();
        loop {
            let mut ping = pool.get();
            ping.spare_mut()[..PING_LEN].fill(0);
            ping.spare_mut()[0] = 0x45;
            ping.spare_mut()[2..4].copy_from_slice(&(PING_LEN as u16).to_be_bytes());
            ping.spare_mut()[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
            ping.set_len(PING_LEN);
            let _ = channels.to_net.try_send(ping);
            let echo = tokio::time::timeout(Duration::from_millis(50), channels.from_net.recv());
            if echo.await.is_ok() {
                break;
            }
            assert!(up.elapsed() < Duration::from_secs(10), "no session");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        while channels.from_net.try_recv().is_ok() {}

        let epoch = Instant::now();
        let echoes = table.clone();
        tokio::spawn(async move {
            while let Some(packet) = channels.from_net.recv().await {
                if packet.len() < 36 {
                    continue;
                }
                let sent_ns = u64::from_le_bytes(packet[28..36].try_into().unwrap());
                let took_us = (epoch.elapsed().as_nanos() as u64).saturating_sub(sent_ns) / 1000;
                if let Some(slot) = echoes.get((sent_ns / 1_000_000 / SLOT_MS) as usize) {
                    slot[1].fetch_add(1, Ordering::Relaxed);
                    slot[2].fetch_max(took_us, Ordering::Relaxed);
                }
            }
        });

        let gap = Duration::from_nanos(1_000_000_000 / PINGS);
        let mut next = tokio::time::Instant::now();
        let mut attackers = Vec::new();
        let mut flood_from = None;
        let (mut seen, mut cookies) = (0, 0);
        let mut seq = 0u64;
        while epoch.elapsed() < run {
            if flood_from.is_none() && epoch.elapsed() >= LEAD {
                let stats = server_stats.device_stats();
                seen = stats.initiations + stats.cookies_required;
                cookies = stats.cookies_sent;
                attackers.extend((0..threads).map(&attack));
                flood_from = Some(epoch.elapsed());
            }
            let now_ns = epoch.elapsed().as_nanos() as u64;
            let mut ping = pool.get();
            let bytes = &mut ping.spare_mut()[..PING_LEN];
            bytes.fill(0);
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&(PING_LEN as u16).to_be_bytes());
            bytes[20..28].copy_from_slice(&seq.to_le_bytes());
            bytes[28..36].copy_from_slice(&now_ns.to_le_bytes());
            ping.set_len(PING_LEN);
            seq += 1;
            if let Some(slot) = table.get((now_ns / 1_000_000 / SLOT_MS) as usize) {
                slot[0].fetch_add(1, Ordering::Relaxed);
            }
            let _ = channels.to_net.try_send(ping);
            next += gap;
            tokio::time::sleep_until(next).await;
        }
        let flood_until = epoch.elapsed();
        let stats = server_stats.device_stats();
        seen = stats.initiations + stats.cookies_required - seen;
        cookies = stats.cookies_sent - cookies;
        stop.store(true, Ordering::Relaxed);
        // What is still on its way back.
        tokio::time::sleep(Duration::from_millis(300)).await;
        (flood_from.unwrap(), flood_until, seen, cookies, attackers)
    });
    for attacker in attackers {
        attacker.join().unwrap();
    }

    let slot = |i: usize| Slot {
        sent: table[i][0].load(Ordering::Relaxed),
        echoed: table[i][1].load(Ordering::Relaxed),
        worst_us: table[i][2].load(Ordering::Relaxed),
    };
    // Whole slots only: the one the flood began in belongs to neither.
    let first = (flood_from.as_millis() as u64 / SLOT_MS) as usize;
    let last = (flood_until.as_millis() as u64 / SLOT_MS) as usize;
    let flooded = (flood_until - flood_from).as_secs_f64();
    Outcome {
        quiet: (0..first).map(slot).collect(),
        flood: (first + 1..last.min(slots)).map(slot).collect(),
        sent_pps: (forged.load(Ordering::Relaxed) as f64 / flooded) as u64,
        seen_pps: (seen as f64 / flooded) as u64,
        cookies_pps: (cookies as f64 / flooded) as u64,
    }
}

/// 150,000 forged initiations a second — a tenth of what one core can
/// send — are all looked at, all refused, and cost the session nothing:
/// no packet lost, none kept waiting.
#[test]
#[ignore = "about time: needs eight idle cores"]
fn a_flood_the_loop_can_look_at_costs_the_session_nothing() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let outcome = flood(2, 75_000, 6);
    outcome.print("150,000 a second");
    assert!(
        outcome.sent_pps > 135_000,
        "this machine did not send the flood ({} a second): nothing to say",
        outcome.sent_pps
    );
    assert!(
        outcome.seen_pps * 10 > outcome.sent_pps * 9,
        "the loop saw {} of {} a second",
        outcome.seen_pps,
        outcome.sent_pps
    );
    assert!(
        Outcome::lost(&outcome.quiet) < 0.5 && Outcome::worst_ms(&outcome.quiet) < 20.0,
        "this machine is too busy to say anything: pings were lost or late before the flood"
    );
    assert!(
        Outcome::lost(&outcome.flood) < 0.5,
        "{:.2} % of the session's packets lost",
        Outcome::lost(&outcome.flood)
    );
    assert!(
        Outcome::worst_ms(&outcome.flood) < 20.0,
        "a packet of the session's took {:.1} ms",
        Outcome::worst_ms(&outcome.flood)
    );
}

/// More than the loop can look at: the socket's buffer overflows, and
/// what does not fit is lost — the session's packets at the same odds as
/// the forged ones, and no worse. That is the test: of the session's
/// packets, in every half second, at least half the share gets through
/// that the flood's own datagrams get (it used to be none of them), and
/// those that do are not kept waiting.
#[test]
#[ignore = "about time: needs eight idle cores"]
fn a_flood_the_loop_cannot_keep_up_with_is_not_a_blackout() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    for (what, pps_per_thread, at_least) in [
        ("400,000 a second", 100_000, 360_000),
        ("800,000 a second", 200_000, 720_000),
        ("all that four threads can send", 0, 800_000),
    ] {
        let outcome = flood(4, pps_per_thread, 6);
        outcome.print(what);
        assert!(
            outcome.sent_pps > at_least,
            "this machine did not send the flood ({} a second): nothing to say",
            outcome.sent_pps
        );
        assert!(
            Outcome::lost(&outcome.quiet) < 0.5 && Outcome::worst_ms(&outcome.quiet) < 20.0,
            "this machine is too busy to say anything: pings were lost or late before the flood"
        );
        let floods_share = 100.0 * (outcome.seen_pps as f64 / outcome.sent_pps as f64).min(1.0);
        let worst = outcome.worst_stretch((500 / SLOT_MS) as usize);
        assert!(
            worst > floods_share / 2.0,
            "{what}: a half second in which {worst:.1} % of the session's packets got through, \
             and {floods_share:.1} % of the flood"
        );
        assert!(
            Outcome::worst_ms(&outcome.flood) < 50.0,
            "{what}: a packet of the session's took {:.1} ms",
            Outcome::worst_ms(&outcome.flood)
        );
    }
}
