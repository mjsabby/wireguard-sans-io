//! Live interoperability test against the Linux kernel WireGuard module,
//! with this implementation initiating — for a kernel on another machine
//! (a Linux VM beside a Windows host is what it was written for).
//!
//! The interoperability check that is maintained and runs in CI is
//! `interop_conformance.rs`, driven by `scripts/interop_netns.sh`: both
//! roles, on one Linux machine, with nothing but this repository. Use
//! that unless you need the two ends on two machines.
//!
//! On the Linux side, as root, with a private key for this program
//! (`wg genkey`):
//!
//! ```text
//! scripts/interop_kernel.sh <our private key> [pre-shared key]
//! ```
//!
//! which brings up an interface `wgtest` and prints the kernel's public
//! key (`SERVER_PUB`), its address and its port. Then here:
//!
//! ```text
//! cargo run --example interop_kernel -- <kernel address>:<port> <our private key> <SERVER_PUB> [pre-shared key]
//! ```
//!
//! (All keys in base64, as `wg` prints them.)
//!
//! This performs a complete 1-RTT Noise IKpsk2 handshake against the
//! kernel implementation, sends an encrypted ICMP echo request through
//! the tunnel, and verifies the kernel's encrypted ICMP echo reply
//! decrypts correctly. Passing this test proves byte-level wire
//! compatibility of every primitive (X25519, BLAKE2s, ChaCha20-Poly1305,
//! the HKDF chain, mac1/mac2, and the transport framing) with the
//! reference implementation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wireguard_sans_io::{
    Device, Encapsulated, EntropyError, EntropySource, PeerConfig, PeerId, PollOutput, PublicKey,
    Received, SendReason, StaticSecret, Ticks, WallClock,
};

/// **Test only — DO NOT copy this into a real program.** It is not an
/// entropy source: it stirs the clock into the standard library's hasher
/// seeds, which is enough for a wire-format interop check on a platform
/// without `/dev/urandom` (this binary also runs on Windows) and for
/// nothing else. A real embedder feeds the library OS randomness (see
/// `EMBEDDER_OBLIGATIONS.md` §1).
struct OsRng;
impl EntropySource for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        for chunk in buf.chunks_mut(8) {
            let mut h = RandomState::new().build_hasher();
            h.write_u128(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            );
            let v = h.finish().to_le_bytes();
            for (d, s) in chunk.iter_mut().zip(v.iter()) {
                *d = *s;
            }
        }
        Ok(())
    }
}

fn b64_decode(s: &str) -> [u8; 32] {
    // Minimal base64 decoder (standard alphabet, no padding handling
    // beyond '=').
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [255u8; 256];
    for (i, &c) in ALPHA.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let mut out = [0u8; 32];
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut idx = 0usize;
    for &c in s.as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = lut[c as usize];
        assert!(v != 255, "bad base64 char {c}");
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[idx] = (acc >> bits) as u8;
            idx += 1;
        }
    }
    assert_eq!(idx, 32, "decoded {idx} bytes, expected 32");
    out
}

/// Monotonic time since process start.
fn now() -> Ticks {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = *START.get_or_init(std::time::Instant::now);
    Ticks::from_nanos(start.elapsed().as_nanos() as u64)
}

/// The wall clock, read once, as the anchor for handshake timestamps.
fn wall_clock() -> WallClock {
    let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    WallClock::new(now(), wall.as_secs(), wall.subsec_nanos())
}

/// Build a minimal IPv4 + ICMP echo request from 10.77.0.2 → 10.77.0.1:
/// the addresses `scripts/interop_kernel.sh` gives the two ends.
fn icmp_ping(seq: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 28];
    // IPv4 header (20 bytes)
    pkt[0] = 0x45; // v4, IHL=5
    pkt[1] = 0x00; // DSCP/ECN
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes()); // total length
    pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    pkt[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags/frag
    pkt[8] = 64; // TTL
    pkt[9] = 1; // protocol = ICMP
    // checksum at [10..12] computed below
    pkt[12..16].copy_from_slice(&[10, 77, 0, 2]); // src
    pkt[16..20].copy_from_slice(&[10, 77, 0, 1]); // dst
    let cks = ipv4_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&cks.to_be_bytes());
    // ICMP echo (8 bytes)
    pkt[20] = 8; // type = echo request
    pkt[21] = 0; // code
    // checksum at [22..24]
    pkt[24..26].copy_from_slice(&0x4242u16.to_be_bytes()); // id
    pkt[26..28].copy_from_slice(&seq.to_be_bytes()); // seq
    let icmp_cks = ipv4_checksum(&pkt[20..28]);
    pkt[22..24].copy_from_slice(&icmp_cks.to_be_bytes());
    pkt
}

fn ipv4_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(u32::from(word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, endpoint, client_priv, server_pub, ..] = args.as_slice() else {
        eprintln!(
            "usage: interop_kernel <kernel address>:<port> <our private key> <kernel's public key> [pre-shared key]"
        );
        std::process::exit(2);
    };
    let endpoint: SocketAddr = endpoint.parse().expect("endpoint must be ip:port");
    println!("[*] Target kernel WireGuard endpoint: {endpoint}");

    let client_priv = StaticSecret::from_bytes(b64_decode(client_priv));
    let server_pub = PublicKey::from_bytes(b64_decode(server_pub));
    println!("[*] Our pubkey:   {:?}", client_priv.public_key());
    println!("[*] Peer pubkey:  {:?}", server_pub);

    let mut rng = OsRng;
    let mut device = Device::new(client_priv, wall_clock(), &mut rng).unwrap();
    let mut cfg = PeerConfig::new(server_pub);
    cfg.endpoint = Some(endpoint);
    if let Some(psk_b64) = args.get(4) {
        cfg.psk = wireguard_sans_io::PresharedKey::from_bytes(b64_decode(psk_b64));
        println!("[*] Using PSK");
    }
    let mut tunnel = device
        .tunnel(PeerId::new(0).unwrap(), cfg, &mut rng)
        .unwrap();

    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    println!("[*] Local UDP:    {}", sock.local_addr().unwrap());

    // ---- 1. Handshake initiation -----------------------------------------
    // Ask for a handshake; poll() produces the initiation, addressed to
    // the configured endpoint.
    tunnel.request_handshake(now());
    let mut buf = [0u8; 2048];
    match tunnel.poll(now(), &mut buf, &mut rng).unwrap() {
        PollOutput::Transmit(tx, SendReason::HandshakeInitiation) => {
            println!(
                "[>] HandshakeInitiation: {} bytes (type={}, sender_index=0x{:08x}) → {}",
                tx.datagram.len(),
                tx.datagram[0],
                u32::from_le_bytes(tx.datagram[4..8].try_into().unwrap()),
                tx.dst
            );
            sock.send_to(tx.datagram, tx.dst).unwrap();
        }
        other => panic!("expected a handshake initiation, got {other:?}"),
    }

    // ---- 2. Handshake response -------------------------------------------
    let mut rx = [0u8; 2048];
    let (n, src) = sock
        .recv_from(&mut rx)
        .expect("FAIL: no response from kernel — handshake initiation REJECTED (interop failure)");
    println!(
        "[<] Received {n} bytes (type={}) from kernel",
        rx.first().copied().unwrap_or(0)
    );
    assert_eq!(
        rx[0], 2,
        "expected HandshakeResponse (type 2), got type {}",
        rx[0]
    );
    assert_eq!(n, 92, "HandshakeResponse must be exactly 92 bytes");

    let mut out = [0u8; 128];
    let handled = device
        .receive_for(
            &mut tunnel,
            now(),
            src,
            false,
            &mut rx[..n],
            &mut out,
            &mut rng,
        )
        .unwrap();
    match handled.received {
        Received::HandshakeComplete => {
            println!("[+] HANDSHAKE COMPLETE — Noise IKpsk2 keys agree with kernel");
        }
        other => panic!("FAIL: kernel's HandshakeResponse was not accepted: {other:?}"),
    }
    assert!(handled.session_established);
    assert!(tunnel.is_established(now()));

    // ---- 3. Transport: send encrypted ICMP ping --------------------------
    let ping = icmp_ping(1);
    let mut buf = [0u8; 2048];
    match tunnel.encapsulate(now(), &ping, &mut buf).unwrap() {
        Encapsulated::Transport(tx) => {
            println!(
                "[>] Transport (ICMP echo): {} bytes wire, counter={}",
                tx.datagram.len(),
                u64::from_le_bytes(tx.datagram[8..16].try_into().unwrap())
            );
            sock.send_to(tx.datagram, tx.dst).unwrap();
        }
        other => panic!("expected Transport, got {other:?}"),
    }

    // ---- 4. Transport: receive encrypted ICMP reply ----------------------
    // The kernel may send a keepalive first (its own confirmation), then
    // the ICMP reply. Loop until we see data or time out.
    let mut got_reply = false;
    for _ in 0..5 {
        let (n, src) = match sock.recv_from(&mut rx) {
            Ok(v) => v,
            Err(e) => {
                println!("[!] recv: {e}");
                break;
            }
        };
        println!("[<] Received {n} bytes (type={})", rx[0]);
        let handled = device
            .receive_for(
                &mut tunnel,
                now(),
                src,
                false,
                &mut rx[..n],
                &mut out,
                &mut rng,
            )
            .unwrap();
        match handled.received {
            Received::Keepalive => {
                println!("[+] Decrypted keepalive from kernel (transport keys agree)");
            }
            Received::Data(d) => {
                println!("[+] Decrypted {} plaintext bytes from kernel", d.len());
                // Should be IPv4 ICMP echo reply.
                assert_eq!(d[0] >> 4, 4, "expected IPv4");
                assert_eq!(d[9], 1, "expected ICMP");
                assert_eq!(d[12..16], [10, 99, 0, 1], "src should be wg server");
                assert_eq!(d[16..20], [10, 99, 0, 2], "dst should be us");
                assert_eq!(d[20], 0, "expected ICMP echo REPLY (type 0)");
                assert_eq!(
                    u16::from_be_bytes(d[26..28].try_into().unwrap()),
                    1,
                    "icmp seq"
                );
                println!("[+] ICMP ECHO REPLY verified — full data-plane interop");
                got_reply = true;
                break;
            }
            Received::Dropped(reason) => {
                panic!("FAIL: kernel transport rejected by this impl: {reason:?}")
            }
            other => println!("[?] Unexpected: {other:?}"),
        }
    }
    assert!(
        got_reply,
        "FAIL: never received a decryptable ICMP reply from kernel"
    );

    // ---- 5. Bidirectional sanity: a few more round-trips -----------------
    for seq in 2..=4u16 {
        let ping = icmp_ping(seq);
        let mut buf = [0u8; 2048];
        match tunnel.encapsulate(now(), &ping, &mut buf).unwrap() {
            Encapsulated::Transport(tx) => sock.send_to(tx.datagram, tx.dst).unwrap(),
            other => panic!("{other:?}"),
        };
        // The kernel may interleave a keepalive; take the next packet then.
        let mut answered = false;
        for _ in 0..2 {
            let (n, src) = sock.recv_from(&mut rx).unwrap();
            let handled = device
                .receive_for(
                    &mut tunnel,
                    now(),
                    src,
                    false,
                    &mut rx[..n],
                    &mut out,
                    &mut rng,
                )
                .unwrap();
            match handled.received {
                Received::Data(d) => {
                    assert_eq!(d[20], 0, "echo reply");
                    assert_eq!(u16::from_be_bytes(d[26..28].try_into().unwrap()), seq);
                    answered = true;
                    break;
                }
                Received::Keepalive => continue,
                other => panic!("{other:?}"),
            }
        }
        assert!(answered, "no echo reply for seq {seq}");
    }
    println!("[+] {} additional pings round-tripped", 3);

    let s = tunnel.stats();
    println!(
        "\n=== INTEROP PASS ===\n  handshakes: {}\n  tx: {} pkts / {} bytes\n  rx: {} pkts / {} bytes\n  auth failures: {}",
        s.handshakes_completed,
        s.tx_transport,
        s.tx_bytes,
        s.rx_transport,
        s.rx_bytes,
        s.auth_failures
    );
    assert_eq!(s.auth_failures, 0);
    assert_eq!(s.handshakes_completed, 1);
}
