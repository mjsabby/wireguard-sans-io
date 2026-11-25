//! UDP-loopback throughput harness — the *out-of-process* benchmark, for
//! comparing implementations that can't be linked into the same binary
//! (notably `wireguard-go`).
//!
//! Two modes:
//!
//! * `udp_throughput pump <endpoint> <our_priv_b64> <peer_pub_b64> <secs> [window]`
//!     — initiator: handshakes with `<endpoint>`, then sends 1420-byte
//!     IPv4 packets for `<secs>` seconds, as fast as their echoes come
//!     back (a window of them in flight: 64, or `[window]`), and reports
//!     MB/s + pps based on decrypted echoes received back, and how many
//!     were not echoed.
//!
//! * `udp_throughput echo <listen_port> <our_priv_b64> <peer_pub_b64>`
//!     — responder: listens, handshakes, decrypts every transport packet
//!     and re-encrypts it back. This is what you point `pump` at when
//!     measuring `wireguard-embed` itself; for `wireguard-go` / kernel /
//!     `boringtun-cli`, point `pump` at *their* UDP port instead and let
//!     a TUN-side `socat` or `iperf` do the echoing.
//!
//! Typical comparison:
//!
//! ```text
//! # 1. wireguard-embed (this crate)
//! cargo run -p wireguard-bench --release --bin udp_throughput -- \
//!     echo 51900 <B_PRIV> <A_PUB>      &
//! cargo run -p wireguard-bench --release --bin udp_throughput -- \
//!     pump 127.0.0.1:51900 <A_PRIV> <B_PUB> 10
//!
//! # 2. wireguard-go (userspace)
//! wireguard-go wg0 ; wg set wg0 ... ; ip addr add 10.9.0.1/24 dev wg0
//! # echo via:  socat -u TUN:10.9.0.2/24,iff-up UDP-RECVFROM:0,fork ...
//! # then pump at wg0's listen-port.
//!
//! # 3. kernel
//! # set up wg0 via `ip link add ... type wireguard`, same as above.
//! ```
//!
//! `scripts/perf_vs_kernel.sh` does all three, in a network namespace
//! of its own, with IP forwarding as the echo: an interface whose route
//! for the pump's addresses is itself sends what it decrypts straight
//! back to the peer it came from.
//!
//! All three then carry identical UDP/syscall overhead, so the numbers
//! are comparable.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use wireguard_embed::{Tunn, TunnResult};
use wireguard_sans_io::{PublicKey, StaticSecret};

const PKT_LEN: usize = 1420;
/// Where the pump writes a packet's sequence number: the first eight bytes
/// after the IPv4 header. An echo brings it back.
const SEQ: std::ops::Range<usize> = 20..28;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("pump") => pump(&args[2..]),
        Some("echo") => echo(&args[2..]),
        _ => {
            eprintln!(
                "usage:\n  {0} pump <endpoint> <priv_b64> <peer_pub_b64> <secs> [window]\n  {0} echo <port> <priv_b64> <peer_pub_b64>",
                args.first().map(String::as_str).unwrap_or("udp_throughput")
            );
            std::process::exit(2);
        }
    }
}

fn b64(s: &str) -> [u8; 32] {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let lk = |c: u8| T.iter().position(|&x| x == c).unwrap() as u8;
    let s = s.trim().trim_end_matches('=');
    let mut out = Vec::with_capacity(32);
    for chunk in s.as_bytes().chunks(4) {
        let (mut acc, mut bits) = (0u32, 0u32);
        for &c in chunk {
            acc = (acc << 6) | u32::from(lk(c));
            bits += 6;
        }
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out.try_into().expect("32-byte key")
}

/// The packet the pump sends: an IPv4 header a router accepts — the
/// kernel's WireGuard hands what it decrypts to the kernel's IP stack,
/// which forwards nothing with a wrong header checksum — from 10.9.0.2 to
/// 10.9.0.1, and a payload that is no protocol's. (Protocol 253 is one of
/// the two numbers reserved for experiments: nothing along the way has
/// an opinion about its contents.)
fn make_packet() -> Vec<u8> {
    let mut p = vec![0u8; PKT_LEN];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(PKT_LEN as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 253;
    p[12..16].copy_from_slice(&[10, 9, 0, 2]);
    p[16..20].copy_from_slice(&[10, 9, 0, 1]);
    let sum: u32 = p[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    let folded = (sum & 0xffff) + (sum >> 16);
    let checksum = !((folded & 0xffff) + (folded >> 16)) as u16;
    p[10..12].copy_from_slice(&checksum.to_be_bytes());
    for (i, b) in p[20..].iter_mut().enumerate() {
        *b = i as u8;
    }
    p
}

/// How many packets the pump keeps in flight unless told otherwise.
const WINDOW: u64 = 64;

fn pump(args: &[String]) {
    let endpoint: SocketAddr = args[0].parse().expect("endpoint");
    let priv_key = StaticSecret::from_bytes(b64(&args[1]));
    let peer_pub = PublicKey::from_bytes(b64(&args[2]));
    let secs: u64 = args[3].parse().expect("secs");
    let window: u64 = args.get(4).map_or(WINDOW, |w| w.parse().expect("window"));

    let mut tunn = Tunn::new(priv_key, peer_pub, None, None, Some(endpoint), None).unwrap();
    // The socket is connected: it can only hear from, and send to,
    // `endpoint`, so the destination the tunnel attaches to each datagram
    // is always that address and plain `send` is right.
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect(endpoint).unwrap();
    sock.set_nonblocking(true).unwrap();
    let (mut tx, mut rx, mut out) = (vec![0u8; 2048], vec![0u8; 2048], vec![0u8; 2048]);

    // Handshake.
    if let TunnResult::WriteToNetwork(w, _) = tunn.format_handshake_initiation(&mut tx) {
        sock.send(w).unwrap();
    }
    let start = Instant::now();
    while !tunn.is_established() && start.elapsed() < Duration::from_secs(10) {
        if let Ok(n) = sock.recv(&mut rx) {
            if let TunnResult::WriteToNetwork(w, _) = tunn.decapsulate(endpoint, &rx[..n], &mut out)
            {
                sock.send(w).unwrap();
            }
        }
        run_timers(&mut tunn, &mut tx, |w, _| {
            let _ = sock.send(w);
        });
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(tunn.is_established(), "handshake failed");
    eprintln!("[pump] handshake complete; sending {PKT_LEN}-byte packets for {secs}s");

    // Send + count echoes. A window of packets in flight keeps the pump
    // from merely filling socket buffers: no more than `WINDOW` packets
    // are out that have neither come back nor been lost. Every packet
    // carries a sequence number, which its echo brings back, and that is
    // how a loss is seen — an echo arrives for a later packet, so the ones
    // before it that are still missing are not coming — and its place in
    // the window freed. Only when the last packets sent are lost is there
    // no later echo to say so: if the window is full and nothing has come
    // back for `STALL`, everything in it is taken for lost.
    //
    // The window is small enough for a burst of it to fit a socket buffer
    // of the default size (some 90 datagrams of this length on Linux): a
    // larger one overflows the other end's buffer on every burst, and the
    // pump then measures how fast packets can be thrown away.
    //
    // (The window used to be 256 and to count every packet sent and not
    // echoed, for ever: each loss made it one smaller — which is how it
    // came down to a size that worked — after 256 losses the pump
    // stopped, and the figure it printed depended on how long it had run.)
    //
    // How many datagrams fit depends on who sent them: the buffer is
    // charged with the memory a datagram's buffer holds, not with its
    // length, and one the kernel's WireGuard has forwarded holds about
    // twice what one from a `send` call does. Hence the argument: 32
    // against the kernel (`scripts/perf_vs_kernel.sh` uses that for
    // every peer, so that they are compared at the same window).
    const STALL: Duration = Duration::from_millis(20);
    let mut packet = make_packet();
    let (mut sent, mut recvd, mut bytes_rx) = (0u64, 0u64, 0u64);
    // Packets given up for lost, and the sequence number the next echo
    // has if nothing was lost before it.
    let (mut lost, mut expected) = (0u64, 0u64);
    let mut stalls = 0u64;
    let mut last_echo = Instant::now();
    let until = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < until {
        while sent.saturating_sub(recvd + lost) < window {
            packet[SEQ].copy_from_slice(&sent.to_le_bytes());
            match tunn.encapsulate(&packet, &mut tx) {
                TunnResult::WriteToNetwork(w, _) => {
                    if sock.send(w).is_ok() {
                        sent += 1;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        while let Ok(n) = sock.recv(&mut rx) {
            match tunn.decapsulate(endpoint, &rx[..n], &mut out) {
                TunnResult::WriteToTunnel(d) => {
                    recvd += 1;
                    bytes_rx += d.len() as u64;
                    last_echo = Instant::now();
                    let seq = d
                        .get(SEQ)
                        .and_then(|b| <[u8; 8]>::try_from(b).ok())
                        .map_or(expected, u64::from_le_bytes)
                        .min(sent.saturating_sub(1));
                    if seq >= expected {
                        // The ones between were lost on the way.
                        lost += seq - expected;
                        expected = seq + 1;
                    } else {
                        // One that had been given up for lost after all
                        // (or a duplicate).
                        lost = lost.saturating_sub(1);
                    }
                }
                TunnResult::WriteToNetwork(w, _) => {
                    let _ = sock.send(w);
                }
                _ => {}
            }
        }
        if sent.saturating_sub(recvd + lost) >= window && last_echo.elapsed() >= STALL {
            lost = sent.saturating_sub(recvd);
            expected = sent;
            stalls += 1;
            last_echo = Instant::now();
        }
        // Rekeys and keepalives come from the timers, never from
        // `encapsulate`; once per burst is plenty.
        run_timers(&mut tunn, &mut tx, |w, _| {
            let _ = sock.send(w);
        });
    }
    let dt = secs as f64;
    println!(
        "[pump] sent {sent} pkts, echoed {recvd} pkts ({:.1}% not echoed; the window was \
         written off {stalls} time(s) when nothing came back for {} ms)",
        100.0 * (sent - recvd) as f64 / sent.max(1) as f64,
        STALL.as_millis()
    );
    println!(
        "[pump] throughput: {:.1} MB/s ({:.1} Mbit/s) decrypted, {:.0} pps",
        bytes_rx as f64 / dt / 1e6,
        bytes_rx as f64 * 8.0 / dt / 1e6,
        recvd as f64 / dt
    );
}

fn echo(args: &[String]) {
    let port: u16 = args[0].parse().expect("port");
    let priv_key = StaticSecret::from_bytes(b64(&args[1]));
    let peer_pub = PublicKey::from_bytes(b64(&args[2]));

    // No endpoint: the tunnel learns where the pump is from its handshake
    // and says where every datagram goes.
    let mut tunn = Tunn::new(priv_key, peer_pub, None, None, None, None).unwrap();
    let sock = UdpSocket::bind(("0.0.0.0", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
    let (mut rx, mut out, mut tx) = (vec![0u8; 2048], vec![0u8; 2048], vec![0u8; 2048]);
    eprintln!("[echo] listening on 0.0.0.0:{port}");

    let mut since_timers = 0u32;
    loop {
        if let Ok((n, from)) = sock.recv_from(&mut rx) {
            match tunn.decapsulate(from, &rx[..n], &mut out) {
                TunnResult::WriteToNetwork(w, to) => {
                    let _ = sock.send_to(w, to);
                }
                TunnResult::WriteToTunnel(d) => {
                    // Echo: re-encrypt the same plaintext back.
                    if let TunnResult::WriteToNetwork(w, to) = tunn.encapsulate(d, &mut tx) {
                        let _ = sock.send_to(w, to);
                    }
                }
                _ => {}
            }
            // Under a flood the read never times out: run the timers
            // every so often anyway.
            since_timers += 1;
            if since_timers < 256 {
                continue;
            }
        }
        since_timers = 0;
        run_timers(&mut tunn, &mut tx, |w, to| {
            let _ = sock.send_to(w, to);
        });
    }
}

/// Send everything the tunnel's timers have due.
fn run_timers(tunn: &mut Tunn, buf: &mut [u8], mut send: impl FnMut(&[u8], SocketAddr)) {
    // Bounded, so a persistent local fault cannot spin here.
    for _ in 0..16 {
        match tunn.update_timers(buf) {
            TunnResult::WriteToNetwork(w, to) => send(w, to),
            TunnResult::Done => break,
            _ => {}
        }
    }
}
