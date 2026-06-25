//! UDP-loopback throughput harness — the *out-of-process* benchmark, for
//! comparing implementations that can't be linked into the same binary
//! (notably `wireguard-go`).
//!
//! Two modes:
//!
//! * `udp_throughput pump <endpoint> <our_priv_b64> <peer_pub_b64> <secs>`
//!     — initiator: handshakes with `<endpoint>`, then floods 1420-byte
//!     IPv4 packets for `<secs>` seconds and reports MB/s + pps based on
//!     decrypted echoes received back.
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
//! All three then carry identical UDP/syscall overhead, so the numbers
//! are comparable.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use wireguard_embed::{Tunn, TunnResult};
use wireguard_sans_io::{PublicKey, StaticSecret};

const PKT_LEN: usize = 1420;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("pump") => pump(&args[2..]),
        Some("echo") => echo(&args[2..]),
        _ => {
            eprintln!(
                "usage:\n  {0} pump <endpoint> <priv_b64> <peer_pub_b64> <secs>\n  {0} echo <port> <priv_b64> <peer_pub_b64>",
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

fn make_packet() -> Vec<u8> {
    let mut p = vec![0u8; PKT_LEN];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(PKT_LEN as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&[10, 9, 0, 2]);
    p[16..20].copy_from_slice(&[10, 9, 0, 1]);
    for (i, b) in p[20..].iter_mut().enumerate() {
        *b = i as u8;
    }
    p
}

fn pump(args: &[String]) {
    let endpoint: SocketAddr = args[0].parse().expect("endpoint");
    let priv_key = StaticSecret::from_bytes(b64(&args[1]));
    let peer_pub = PublicKey::from_bytes(b64(&args[2]));
    let secs: u64 = args[3].parse().expect("secs");

    let mut tunn = Tunn::new(priv_key, peer_pub, None, None, None).unwrap();
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect(endpoint).unwrap();
    sock.set_nonblocking(true).unwrap();
    let (mut tx, mut rx, mut out) = (vec![0u8; 2048], vec![0u8; 2048], vec![0u8; 2048]);

    // Handshake.
    if let TunnResult::WriteToNetwork(w) = tunn.format_handshake_initiation(&mut tx) {
        sock.send(w).unwrap();
    }
    let start = Instant::now();
    while !tunn.is_established() && start.elapsed() < Duration::from_secs(10) {
        if let Ok(n) = sock.recv(&mut rx) {
            if let TunnResult::WriteToNetwork(w) =
                tunn.decapsulate(Some(endpoint), &rx[..n], &mut out)
            {
                sock.send(w).unwrap();
            }
        }
        if let TunnResult::WriteToNetwork(w) = tunn.update_timers(&mut tx) {
            sock.send(w).unwrap();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(tunn.is_established(), "handshake failed");
    eprintln!("[pump] handshake complete; flooding {PKT_LEN}-byte packets for {secs}s");

    // Flood + count echoes.
    let packet = make_packet();
    let (mut sent, mut recvd, mut bytes_rx) = (0u64, 0u64, 0u64);
    let inflight_cap = 256u64; // crude window so we don't just fill the socket buffer
    let until = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < until {
        while sent.saturating_sub(recvd) < inflight_cap {
            match tunn.encapsulate(&packet, &mut tx) {
                TunnResult::WriteToNetwork(w) => {
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
            match tunn.decapsulate(Some(endpoint), &rx[..n], &mut out) {
                TunnResult::WriteToTunnel(d) => {
                    recvd += 1;
                    bytes_rx += d.len() as u64;
                }
                TunnResult::WriteToNetwork(w) => {
                    let _ = sock.send(w);
                }
                _ => {}
            }
        }
    }
    let dt = secs as f64;
    println!(
        "[pump] sent {sent} pkts, echoed {recvd} pkts ({:.1}% loss)",
        100.0 * (sent - recvd) as f64 / sent.max(1) as f64
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

    let mut tunn = Tunn::new(priv_key, peer_pub, None, None, None).unwrap();
    let sock = UdpSocket::bind(("0.0.0.0", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
    let (mut rx, mut out, mut tx) = (vec![0u8; 2048], vec![0u8; 2048], vec![0u8; 2048]);
    eprintln!("[echo] listening on 0.0.0.0:{port}");

    let mut peer: Option<SocketAddr> = None;
    loop {
        match sock.recv_from(&mut rx) {
            Ok((n, from)) => {
                peer = Some(from);
                match tunn.decapsulate(Some(from), &rx[..n], &mut out) {
                    TunnResult::WriteToNetwork(w) => {
                        let _ = sock.send_to(w, from);
                    }
                    TunnResult::WriteToTunnel(d) => {
                        // Echo: re-encrypt the same plaintext back.
                        let d = d.to_vec();
                        if let TunnResult::WriteToNetwork(w) = tunn.encapsulate(&d, &mut tx) {
                            let _ = sock.send_to(w, from);
                        }
                    }
                    _ => {}
                }
            }
            Err(_) => {
                if let Some(from) = peer {
                    if let TunnResult::WriteToNetwork(w) = tunn.update_timers(&mut tx) {
                        let _ = sock.send_to(w, from);
                    }
                }
            }
        }
    }
}
