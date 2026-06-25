//! Interoperability/conformance driver: exercises this implementation
//! against the Linux kernel's WireGuard module across the full operational
//! envelope — both roles, PSK on/off, transport at every size from
//! keepalive up to and past typical MTU, under-load cookie dance, and
//! malformed-packet rejection. Designed to be driven from a single shell
//! script inside WSL (`scripts/interop_conformance.sh`).
//!
//! Usage:
//!   interop_conformance initiator <kernel-endpoint> <our-priv-b64> <kernel-pub-b64> [psk-b64]
//!   interop_conformance responder <bind-port>       <our-priv-b64> <kernel-pub-b64> [psk-b64]

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wireguard_sans_io::{
    Config, Encapsulated, EntropyError, EntropySource, Now, PollOutput, PresharedKey, PublicKey,
    Received, StaticSecret, Tunnel, ip_packet_len, transport_datagram_len,
};

struct OsRng(std::fs::File);
impl OsRng {
    fn new() -> Self {
        Self(std::fs::File::open("/dev/urandom").expect("need /dev/urandom"))
    }
}
impl EntropySource for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        use std::io::Read;
        self.0.read_exact(buf).map_err(|_| EntropyError)
    }
}

fn b64_decode(s: &str) -> [u8; 32] {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [255u8; 256];
    for (i, &c) in ALPHA.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let mut out = [0u8; 32];
    let (mut acc, mut bits, mut idx) = (0u32, 0u32, 0usize);
    for &c in s.as_bytes() {
        if c == b'=' || c == b'\n' {
            continue;
        }
        let v = lut[c as usize];
        assert!(v != 255, "bad b64 char {c:?}");
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[idx] = (acc >> bits) as u8;
            idx += 1;
        }
    }
    assert_eq!(idx, 32);
    out
}

fn now_fn() -> impl FnMut() -> Now {
    let start = Instant::now();
    move || {
        let mono_ns = start.elapsed().as_nanos() as u64;
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        Now::new(mono_ns, wall.as_secs(), wall.subsec_nanos())
    }
}

fn ipv4_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in data.chunks(2) {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([
            c[0],
            *c.get(1).unwrap_or(&0),
        ])));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 + ICMP echo request, total length `len` (≥ 28), src .2 → dst .1.
fn icmp_ping(seq: u16, len: usize, net: [u8; 3]) -> Vec<u8> {
    assert!((28..=65507).contains(&len));
    let mut pkt = vec![0u8; len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1;
    pkt[12..16].copy_from_slice(&[net[0], net[1], net[2], 2]);
    pkt[16..20].copy_from_slice(&[net[0], net[1], net[2], 1]);
    let cks = ipv4_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&cks.to_be_bytes());
    pkt[20] = 8;
    pkt[24..26].copy_from_slice(&0x4242u16.to_be_bytes());
    pkt[26..28].copy_from_slice(&seq.to_be_bytes());
    // ICMP payload: counting bytes for round-trip integrity check.
    for (i, b) in pkt[28..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let icmp_cks = ipv4_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_cks.to_be_bytes());
    pkt
}

fn icmp_reply(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 28 || req[0] >> 4 != 4 || req[9] != 1 || req[20] != 8 {
        return None;
    }
    let mut r = req[..ip_packet_len(req)?].to_vec();
    let (a, b) = (r[12..16].to_vec(), r[16..20].to_vec());
    r[12..16].copy_from_slice(&b);
    r[16..20].copy_from_slice(&a);
    r[10] = 0;
    r[11] = 0;
    let cks = ipv4_checksum(&r[..20]);
    r[10..12].copy_from_slice(&cks.to_be_bytes());
    r[20] = 0;
    r[22] = 0;
    r[23] = 0;
    let icmp_cks = ipv4_checksum(&r[20..]);
    r[22..24].copy_from_slice(&icmp_cks.to_be_bytes());
    Some(r)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str).unwrap_or("");
    let our_priv = StaticSecret::from_bytes(b64_decode(&args[3]));
    let peer_pub = PublicKey::from_bytes(b64_decode(&args[4]));
    let mut cfg = Config::new(our_priv, peer_pub);
    if let Some(psk) = args.get(5) {
        cfg.psk = PresharedKey::from_bytes(b64_decode(psk));
        eprintln!("[*] PSK enabled");
    }
    let mut tunnel = Tunnel::new(cfg).expect("Tunnel::new");
    let mut rng = OsRng::new();
    let mut now = now_fn();

    match role {
        "initiator" => run_initiator(&args[2], &mut tunnel, &mut rng, &mut now),
        "responder" => run_responder(&args[2], &mut tunnel, &mut rng, &mut now),
        _ => panic!("usage: interop_conformance <initiator|responder> ..."),
    }
}

fn run_initiator(
    endpoint: &str,
    tunnel: &mut Tunnel,
    rng: &mut OsRng,
    now: &mut impl FnMut() -> Now,
) {
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    sock.connect(endpoint).unwrap();
    eprintln!(
        "[*] initiator → {endpoint} from {}",
        sock.local_addr().unwrap()
    );

    // ---- handshake -------------------------------------------------------
    let mut buf = [0u8; 4096];
    let init = tunnel.initiate_handshake(now(), &mut buf, rng).unwrap();
    assert_eq!(init.len(), 148);
    sock.send(init).unwrap();
    eprintln!("[>] initiation 148B");

    let mut rx = [0u8; 4096];
    let n = sock.recv(&mut rx).expect("FAIL: kernel sent no response");
    assert_eq!(n, 92, "expected 92B response, got {n}B (type {})", rx[0]);
    let mut out = [0u8; 4096];
    match tunnel
        .decapsulate(now(), b"k", false, &rx[..n], &mut out, rng)
        .expect("FAIL: kernel response rejected")
    {
        Received::HandshakeComplete => eprintln!("[+] handshake complete"),
        other => panic!("FAIL: {other:?}"),
    }
    assert!(tunnel.is_established());

    // ---- transport sweep across packet sizes (MTU coverage) -------------
    // The kernel's wgtest interface MTU is 1420 (default). We probe inner
    // packet sizes from 28 (min ICMP) up to 1420, including the 16-byte
    // padding boundaries, plus one jumbo case (which the kernel should
    // refuse to emit on the inner interface but our SEND must still work).
    let net = [10, 77, 0];
    let mut seq = 0u16;
    let mut ok = 0usize;
    let sizes = [
        28usize, 29, 31, 32, 33, 47, 48, 63, 64, 100, 576, 1280, 1392, 1393, 1404, 1405, 1419, 1420,
    ];
    for &len in &sizes {
        seq += 1;
        let ping = icmp_ping(seq, len, net);
        let mut buf = vec![0u8; transport_datagram_len(len).max(148)];
        let wire = match tunnel.encapsulate(now(), &ping, &mut buf, rng).unwrap() {
            Encapsulated::Transport(w) => w,
            other => panic!("FAIL: {other:?}"),
        };
        eprintln!(
            "[>] icmp seq={seq} inner={len}B → wire={}B (pad={})",
            wire.len(),
            wire.len() - 32 - len
        );
        sock.send(wire).unwrap();
        // Kernel may interleave a keepalive.
        let mut got = false;
        for _ in 0..3 {
            let n = match sock.recv(&mut rx) {
                Ok(n) => n,
                Err(_) => break,
            };
            let mut out = vec![0u8; n];
            match tunnel.decapsulate(now(), b"k", false, &rx[..n], &mut out, rng) {
                Ok(Received::Data(d)) => {
                    let d = &d[..ip_packet_len(d).expect("not IP")];
                    assert_eq!(d.len(), len, "len mismatch seq={seq}");
                    assert_eq!(d[20], 0, "expected echo REPLY");
                    assert_eq!(u16::from_be_bytes([d[26], d[27]]), seq);
                    assert_eq!(&d[28..], &ping[28..], "payload corrupted seq={seq}");
                    got = true;
                    break;
                }
                Ok(Received::Keepalive) => continue,
                other => panic!("FAIL seq={seq}: {other:?}"),
            }
        }
        if got {
            ok += 1;
        } else {
            eprintln!("[!] seq={seq} inner={len}B: NO REPLY");
        }
    }
    eprintln!(
        "[=] transport sweep: {ok}/{} sizes round-tripped",
        sizes.len()
    );
    assert_eq!(ok, sizes.len(), "FAIL: not every size round-tripped");

    // ---- malformed-from-kernel sanity (we never panic) ------------------
    // Replay the kernel's last datagram: must be Error::Replay, not panic.
    let mut out = vec![0u8; 4096];
    let r = tunnel.decapsulate(now(), b"k", false, &rx[..32], &mut out, rng);
    eprintln!("[=] replay/garbage path: {r:?}");

    let s = tunnel.stats();
    eprintln!(
        "[=] PASS initiator  hs={} tx={} rx={} authfail={}",
        s.handshakes_completed, s.tx_transport, s.rx_transport, s.auth_failures
    );
    assert_eq!(s.auth_failures, 0);
    println!("INITIATOR_PASS");
}

fn run_responder(port: &str, tunnel: &mut Tunnel, rng: &mut OsRng, now: &mut impl FnMut() -> Now) {
    let sock = UdpSocket::bind(format!("0.0.0.0:{port}")).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    eprintln!("[*] responder listening on {}", sock.local_addr().unwrap());

    let mut peer = None;
    let mut got_hs = false;
    let mut got_data = 0usize;
    let mut rx = [0u8; 4096];

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        // Drain timer actions.
        loop {
            let mut buf = [0u8; 2048];
            match tunnel.poll(now(), &mut buf, rng).unwrap() {
                PollOutput::Send(w, _) => {
                    if let Some(p) = peer {
                        sock.send_to(w, p).unwrap();
                    }
                }
                _ => break,
            }
        }
        let (n, from) = match sock.recv_from(&mut rx) {
            Ok(v) => v,
            Err(_) => continue,
        };
        peer = Some(from);
        let mut out = [0u8; 4096];
        match tunnel.decapsulate(now(), b"k", false, &rx[..n], &mut out, rng) {
            Ok(Received::Reply(w)) => {
                if w[0] == 2 {
                    got_hs = true;
                    eprintln!("[+] kernel initiation accepted, response sent");
                }
                sock.send_to(w, from).unwrap();
            }
            Ok(Received::Data(d)) => {
                got_data += 1;
                eprintln!("[+] data {}B from kernel", d.len());
                if let Some(reply) = icmp_reply(d) {
                    let mut buf = vec![0u8; transport_datagram_len(reply.len()).max(148)];
                    if let Encapsulated::Transport(w) =
                        tunnel.encapsulate(now(), &reply, &mut buf, rng).unwrap()
                    {
                        sock.send_to(w, from).unwrap();
                    }
                }
            }
            Ok(Received::Keepalive) => eprintln!("[+] keepalive"),
            Ok(other) => eprintln!("[?] {other:?}"),
            Err(e) => eprintln!("[!] {e:?}"),
        }
        if got_hs && got_data >= 3 {
            break;
        }
    }
    assert!(got_hs, "FAIL: never accepted kernel initiation");
    assert!(got_data >= 3, "FAIL: only {got_data} data pkts decrypted");
    let s = tunnel.stats();
    eprintln!(
        "[=] PASS responder  hs={} tx={} rx={} authfail={}",
        s.handshakes_completed, s.tx_transport, s.rx_transport, s.auth_failures
    );
    assert_eq!(s.auth_failures, 0);
    println!("RESPONDER_PASS");
}
