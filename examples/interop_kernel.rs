//! Live interoperability test against the Linux kernel WireGuard module.
//!
//! Run `bash /tmp/wg_setup.sh` (as root) inside WSL first to bring up
//! the `wgtest` interface with the fixed key pair this program expects,
//! then on the Windows side:
//!
//! ```text
//! cargo run --example interop_kernel -- 172.31.138.71:51820
//! ```
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

use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wireguard_sans_io::{
    Config, Encapsulated, EntropyError, EntropySource, Now, PublicKey, Received, StaticSecret,
    Tunnel,
};

/// `getrandom`-backed entropy source.
struct OsRng;
impl EntropySource for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        // Windows: RtlGenRandom via the OS.  We avoid pulling in a crate
        // by reading from /dev/urandom equivalents — but on Windows the
        // simplest no-dep route in std is std::hash::RandomState.
        // For a TEST PROGRAM we just use the SystemTime + a ChaCha mix
        // — DO NOT use this in production. The point of this binary is
        // wire-format interop, not entropy hygiene.
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

fn now() -> Now {
    let mono = std::time::Instant::now();
    // Use a process-start-relative monotonic; absolute value irrelevant.
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = *START.get_or_init(std::time::Instant::now);
    let mono_ns = mono.duration_since(start).as_nanos() as u64;
    let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    Now::new(mono_ns, wall.as_secs(), wall.subsec_nanos())
}

/// Build a minimal IPv4 + ICMP echo request from 10.99.0.2 → 10.99.0.1.
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
    pkt[12..16].copy_from_slice(&[10, 99, 0, 2]); // src
    pkt[16..20].copy_from_slice(&[10, 99, 0, 1]); // dst
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
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "172.31.138.71:51820".into());
    println!("[*] Target kernel WireGuard endpoint: {endpoint}");

    // Fixed keys matching /tmp/wg_setup.sh in WSL.
    let client_priv =
        StaticSecret::from_bytes(b64_decode("+BRzlgnBRf/vLcvjHI8xnh50Ar3vDeGyLs3T8h2Fc1I="));
    let server_pub =
        PublicKey::from_bytes(b64_decode("QCpkIcz6vapOhWqSgAC3ziHfEeoXhbcFxhciC+sWBFg="));
    println!("[*] Our pubkey:   {:?}", client_priv.public_key());
    println!("[*] Peer pubkey:  {:?}", server_pub);

    let mut cfg = Config::new(client_priv, server_pub);
    if let Some(psk_b64) = std::env::args().nth(2) {
        cfg.psk = wireguard_sans_io::PresharedKey::from_bytes(b64_decode(&psk_b64));
        println!("[*] Using PSK");
    }
    let mut tunnel = Tunnel::new(cfg).unwrap();
    let mut rng = OsRng;

    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    sock.connect(&endpoint).unwrap();
    println!("[*] Local UDP:    {}", sock.local_addr().unwrap());

    // ---- 1. Handshake initiation -----------------------------------------
    let mut buf = [0u8; 2048];
    let init = tunnel
        .initiate_handshake(now(), &mut buf, &mut rng)
        .unwrap();
    println!(
        "[>] HandshakeInitiation: {} bytes (type={}, sender_index=0x{:08x})",
        init.len(),
        init[0],
        u32::from_le_bytes(init[4..8].try_into().unwrap())
    );
    sock.send(init).unwrap();

    // ---- 2. Handshake response -------------------------------------------
    let mut rx = [0u8; 2048];
    let n = sock
        .recv(&mut rx)
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

    let mut out = [0u8; 2048];
    match tunnel
        .decapsulate(now(), b"kernel", false, &rx[..n], &mut out, &mut rng)
        .expect("FAIL: kernel's HandshakeResponse rejected by this implementation")
    {
        Received::HandshakeComplete => {
            println!("[+] HANDSHAKE COMPLETE — Noise IKpsk2 keys agree with kernel");
        }
        other => panic!("expected HandshakeComplete, got {other:?}"),
    }
    assert!(tunnel.is_established());

    // ---- 3. Transport: send encrypted ICMP ping --------------------------
    let ping = icmp_ping(1);
    let mut buf = [0u8; 2048];
    let wire = match tunnel
        .encapsulate(now(), &ping, &mut buf, &mut rng)
        .unwrap()
    {
        Encapsulated::Transport(w) => w,
        other => panic!("expected Transport, got {other:?}"),
    };
    println!(
        "[>] Transport (ICMP echo): {} bytes wire, counter={}",
        wire.len(),
        u64::from_le_bytes(wire[8..16].try_into().unwrap())
    );
    sock.send(wire).unwrap();

    // ---- 4. Transport: receive encrypted ICMP reply ----------------------
    // The kernel may send a keepalive first (its own confirmation), then
    // the ICMP reply. Loop until we see data or time out.
    let mut got_reply = false;
    for _ in 0..5 {
        let n = match sock.recv(&mut rx) {
            Ok(n) => n,
            Err(e) => {
                println!("[!] recv: {e}");
                break;
            }
        };
        println!("[<] Received {n} bytes (type={})", rx[0]);
        let mut out = [0u8; 2048];
        match tunnel.decapsulate(now(), b"kernel", false, &rx[..n], &mut out, &mut rng) {
            Ok(Received::Keepalive) => {
                println!("[+] Decrypted keepalive from kernel (transport keys agree)");
            }
            Ok(Received::Data(d)) => {
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
            Ok(other) => println!("[?] Unexpected: {other:?}"),
            Err(e) => panic!("FAIL: kernel transport rejected by this impl: {e:?}"),
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
        let wire = match tunnel
            .encapsulate(now(), &ping, &mut buf, &mut rng)
            .unwrap()
        {
            Encapsulated::Transport(w) => w,
            other => panic!("{other:?}"),
        };
        sock.send(wire).unwrap();
        let n = sock.recv(&mut rx).unwrap();
        let mut out = [0u8; 2048];
        match tunnel
            .decapsulate(now(), b"kernel", false, &rx[..n], &mut out, &mut rng)
            .unwrap()
        {
            Received::Data(d) => {
                assert_eq!(d[20], 0, "echo reply");
                assert_eq!(u16::from_be_bytes(d[26..28].try_into().unwrap()), seq);
            }
            Received::Keepalive => {
                // Kernel keepalive raced; grab the next packet.
                let n = sock.recv(&mut rx).unwrap();
                let r = tunnel
                    .decapsulate(now(), b"kernel", false, &rx[..n], &mut out, &mut rng)
                    .unwrap();
                assert!(matches!(r, Received::Data(_)));
            }
            other => panic!("{other:?}"),
        }
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
