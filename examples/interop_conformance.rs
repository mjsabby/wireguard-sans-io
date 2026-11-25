//! Interoperability/conformance driver: exercises this implementation
//! against the Linux kernel's WireGuard module across the full operational
//! envelope — both roles, PSK on/off, transport at every size from
//! keepalive up to and past typical MTU, the under-load cookie dance, and
//! the timer behaviour of long one-way flows. Driven by
//! `scripts/interop_netns.sh` (unprivileged, in a network namespace) or
//! `scripts/interop_conformance.sh` (root, with wireguard-tools).
//!
//! Usage:
//!   interop_conformance initiator        <kernel-endpoint> <our-priv-b64> <kernel-pub-b64> [psk-b64]
//!   interop_conformance responder        <bind-port>       <our-priv-b64> <kernel-pub-b64> [psk-b64]
//!   interop_conformance responder-cookie <bind-port>       <our-priv-b64> <kernel-pub-b64> [psk-b64]
//!   interop_conformance sink   <seconds> <bind-port>       <our-priv-b64> <kernel-pub-b64>
//!   interop_conformance source <seconds> <kernel-endpoint> <our-priv-b64> <kernel-pub-b64>
//!   interop_conformance crossed <bind-port> <kernel-endpoint> <our-priv-b64> <kernel-pub-b64>
//!   interop_conformance crossed-either <bind-port> <peer-endpoint> <our-priv-b64> <peer-pub-b64>
//!
//! * `responder-cookie` answers the kernel's first initiation as if under
//!   load, so the kernel has to complete the cookie dance.
//! * `sink` receives a one-way stream from the kernel for `<seconds>` and
//!   sends nothing but what the protocol requires: it must emit a
//!   keepalive every Keepalive-Timeout, and the kernel must not start a
//!   new handshake.
//! * `source` streams one way *to* the kernel for `<seconds>`: the kernel
//!   answers with keepalives, and we must not start a new handshake.
//! * `crossed` makes both sides initiate at once: the kernel's initiation
//!   is left unread until ours is on the wire. The kernel answers ours and
//!   drops its own; we answer the kernel's and keep ours, so our handshake
//!   must complete with the kernel's answer — one round trip, nothing
//!   retransmitted.
//! * `crossed-either` is `crossed` against a peer that may keep either of
//!   the two handshakes, or both, as wireguard-go does
//!   (`scripts/interop_wireguard_go.sh`): it has several handshake
//!   workers, and they take the two messages we send it at once. Which
//!   handshake completed is therefore reported and not required. Required
//!   is what does not depend on it: a session is there at once, nothing
//!   was retransmitted, and the peer's pings are answered from the first
//!   one on, none missing.

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

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wireguard_sans_io::{
    Device, Encapsulated, EntropyError, EntropySource, Handled, PeerConfig, PeerId, PollOutput,
    PresharedKey, PublicKey, Received, SendReason, StaticSecret, Ticks, Tunnel, WallClock,
    ip_packet_len, transport_datagram_len,
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

/// IPv4 + UDP datagram src .2:9999 → dst .1:9999 with `payload_len`
/// payload bytes (UDP checksum 0 = none).
fn udp_packet(seq: u16, payload_len: usize, net: [u8; 3]) -> Vec<u8> {
    let len = 28 + payload_len;
    let mut pkt = vec![0u8; len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&seq.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[net[0], net[1], net[2], 2]);
    pkt[16..20].copy_from_slice(&[net[0], net[1], net[2], 1]);
    let cks = ipv4_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&cks.to_be_bytes());
    pkt[20..22].copy_from_slice(&9999u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&9999u16.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
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

/// Everything one endpoint needs: the core's device and tunnel, a socket,
/// a clock and an entropy source — the whole embedder, in one struct.
struct Endpoint {
    device: Device,
    tunnel: Tunnel,
    sock: UdpSocket,
    rng: OsRng,
    start: Instant,
    /// What `pump` sent, by reason.
    sent: Vec<(Duration, SendReason)>,
}

impl Endpoint {
    fn new(
        our_priv: StaticSecret,
        peer_pub: PublicKey,
        psk: Option<PresharedKey>,
        bind: &str,
        peer_endpoint: Option<SocketAddr>,
    ) -> Self {
        let mut rng = OsRng::new();
        let start = Instant::now();
        // The wall clock is read once, as the anchor for handshake
        // timestamps.
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let wall_clock = WallClock::new(Ticks::ZERO, wall.as_secs(), wall.subsec_nanos());
        let device = Device::new(our_priv, wall_clock, &mut rng).expect("Device::new");
        let mut cfg = PeerConfig::new(peer_pub);
        if let Some(psk) = psk {
            cfg.psk = psk;
        }
        cfg.endpoint = peer_endpoint;
        let tunnel = device
            .tunnel(PeerId::new(0).unwrap(), cfg, &mut rng)
            .expect("Device::tunnel");
        let sock = UdpSocket::bind(bind).unwrap();
        Self {
            device,
            tunnel,
            sock,
            rng,
            start,
            sent: Vec::new(),
        }
    }

    fn now(&self) -> Ticks {
        Ticks::from_nanos(self.start.elapsed().as_nanos() as u64)
    }

    /// Run everything the tunnel wants to do right now: the only place
    /// handshake initiations, retransmissions and keepalives come from.
    fn pump(&mut self) {
        loop {
            let mut buf = [0u8; 256];
            let now = self.now();
            match self.tunnel.poll(now, &mut buf, &mut self.rng).unwrap() {
                PollOutput::Transmit(tx, why) => {
                    self.sock.send_to(tx.datagram, tx.dst).unwrap();
                    self.sent.push((self.start.elapsed(), why));
                    eprintln!("[>] {why:?} {}B → {}", tx.datagram.len(), tx.dst);
                }
                PollOutput::HandshakeExpired => eprintln!("[!] handshake attempt expired"),
                PollOutput::SessionsExpired => eprintln!("[!] sessions expired"),
                _ => break,
            }
        }
    }

    /// How long to block in `recv`: until the tunnel's next wake-up, but
    /// at most `cap`.
    fn recv_timeout(&self, cap: Duration) -> Duration {
        let until_wake = self.tunnel.next_wake().map_or(cap, |wake| {
            Duration::from_nanos(wake.nanos().saturating_sub(self.now().nanos()))
        });
        until_wake.min(cap).max(Duration::from_millis(1))
    }

    /// Wait up to `cap` for one datagram. `None` on timeout.
    fn recv(&mut self, rx: &mut [u8], cap: Duration) -> Option<(usize, SocketAddr)> {
        self.pump();
        self.sock
            .set_read_timeout(Some(self.recv_timeout(cap)))
            .unwrap();
        self.sock.recv_from(rx).ok()
    }

    /// Feed one datagram to the core. Transport data is decrypted in
    /// place; a handshake response or cookie reply lands in `out`.
    fn handle<'a>(
        &mut self,
        src: SocketAddr,
        under_load: bool,
        datagram: &'a mut [u8],
        out: &'a mut [u8],
    ) -> Handled<'a> {
        let now = self.now();
        self.device
            .receive_for(
                &mut self.tunnel,
                now,
                src,
                under_load,
                datagram,
                out,
                &mut self.rng,
            )
            .expect("local fault on the receive path")
    }

    /// Encrypt and send one inner packet.
    fn send(&mut self, packet: &[u8]) -> bool {
        let mut buf = vec![0u8; transport_datagram_len(packet.len())];
        let now = self.now();
        match self.tunnel.encapsulate(now, packet, &mut buf).unwrap() {
            Encapsulated::Transport(tx) => {
                self.sock.send_to(tx.datagram, tx.dst).unwrap();
                true
            }
            other => {
                eprintln!("[!] not sent: {other:?}");
                false
            }
        }
    }

    fn count(&self, why: SendReason) -> usize {
        self.sent.iter().filter(|(_, w)| *w == why).count()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str).unwrap_or("");
    // `sink`/`source` take a leading <seconds>, `crossed` a leading
    // <bind-port>.
    let (seconds, bind_port, rest) = match role {
        "sink" | "source" => (args[2].parse::<u64>().expect("seconds"), "", &args[3..]),
        "crossed" | "crossed-either" => (0, args[2].as_str(), &args[3..]),
        _ => (0, "", &args[2..]),
    };
    let target = rest[0].as_str();
    let our_priv = StaticSecret::from_bytes(b64_decode(&rest[1]));
    let peer_pub = PublicKey::from_bytes(b64_decode(&rest[2]));
    let psk = rest.get(3).map(|p| PresharedKey::from_bytes(b64_decode(p)));
    if psk.is_some() {
        eprintln!("[*] PSK enabled");
    }

    match role {
        "initiator" => run_initiator(target, our_priv, peer_pub, psk),
        "responder" => run_responder(target, our_priv, peer_pub, psk, false),
        "responder-cookie" => run_responder(target, our_priv, peer_pub, psk, true),
        "sink" => run_sink(seconds, target, our_priv, peer_pub),
        "source" => run_source(seconds, target, our_priv, peer_pub),
        "crossed" => run_crossed(bind_port, target, our_priv, peer_pub, false),
        "crossed-either" => run_crossed(bind_port, target, our_priv, peer_pub, true),
        _ => panic!(
            "usage: interop_conformance \
             <initiator|responder|responder-cookie|sink|source|crossed|crossed-either> ..."
        ),
    }
}

/// Handshake as initiator; returns once the session is established.
fn handshake_as_initiator(ep: &mut Endpoint) {
    let now = ep.now();
    ep.tunnel.request_handshake(now);
    let mut rx = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        let Some((n, src)) = ep.recv(&mut rx, Duration::from_secs(1)) else {
            continue;
        };
        let mut out = [0u8; 128];
        let handled = ep.handle(src, false, &mut rx[..n], &mut out);
        if let Received::HandshakeComplete = handled.received {
            assert!(handled.session_established);
            eprintln!("[+] handshake complete");
            assert_eq!(ep.tunnel.endpoint(), Some(src));
            return;
        }
        eprintln!("[?] while handshaking: {:?}", handled.received);
    }
    panic!("FAIL: kernel never completed the handshake");
}

fn run_initiator(
    endpoint: &str,
    our_priv: StaticSecret,
    peer_pub: PublicKey,
    psk: Option<PresharedKey>,
) {
    let endpoint: SocketAddr = endpoint.parse().expect("endpoint");
    let mut ep = Endpoint::new(our_priv, peer_pub, psk, "0.0.0.0:0", Some(endpoint));
    eprintln!(
        "[*] initiator → {endpoint} from {}",
        ep.sock.local_addr().unwrap()
    );
    handshake_as_initiator(&mut ep);

    // ---- transport sweep across packet sizes (MTU coverage) -------------
    // The kernel's interface MTU is 1420 (default). We probe inner packet
    // sizes from 28 (min ICMP) up to 1420, including the 16-byte padding
    // boundaries.
    let net = [10, 77, 0];
    let mut seq = 0u16;
    let mut ok = 0usize;
    let sizes = [
        28usize, 29, 31, 32, 33, 47, 48, 63, 64, 100, 576, 1280, 1392, 1393, 1404, 1405, 1419, 1420,
    ];
    let mut rx = [0u8; 4096];
    for &len in &sizes {
        seq += 1;
        let ping = icmp_ping(seq, len, net);
        assert!(ep.send(&ping), "FAIL: no session for seq={seq}");
        // The kernel may interleave a keepalive.
        let mut got = false;
        for _ in 0..4 {
            let Some((n, src)) = ep.recv(&mut rx, Duration::from_secs(3)) else {
                break;
            };
            let mut out = [0u8; 128];
            match ep.handle(src, false, &mut rx[..n], &mut out).received {
                Received::Data(d) => {
                    let d = &d[..ip_packet_len(d).expect("not IP")];
                    assert_eq!(d.len(), len, "len mismatch seq={seq}");
                    assert_eq!(d[20], 0, "expected echo REPLY");
                    assert_eq!(u16::from_be_bytes([d[26], d[27]]), seq);
                    assert_eq!(&d[28..], &ping[28..], "payload corrupted seq={seq}");
                    got = true;
                    break;
                }
                Received::Keepalive => continue,
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

    // ---- hostile input from the peer's address never faults -------------
    let src = ep.tunnel.endpoint().unwrap();
    for junk in [&rx[..0], &rx[..31], &rx[..32], &[0xffu8; 200][..]] {
        let mut copy = junk.to_vec();
        let mut out = [0u8; 128];
        let handled = ep.handle(src, false, &mut copy, &mut out);
        assert!(matches!(handled.received, Received::Dropped(_)));
    }

    let s = ep.tunnel.stats();
    eprintln!(
        "[=] PASS initiator  hs={} tx={} rx={}",
        s.handshakes_completed, s.tx_transport, s.rx_transport
    );
    assert_eq!(s.handshakes_completed, 1);
    println!("INITIATOR_PASS");
}

fn run_responder(
    port: &str,
    our_priv: StaticSecret,
    peer_pub: PublicKey,
    psk: Option<PresharedKey>,
    cookie_first: bool,
) {
    // A pure responder: no endpoint configured, learned from the kernel's
    // handshake.
    let mut ep = Endpoint::new(our_priv, peer_pub, psk, &format!("0.0.0.0:{port}"), None);
    eprintln!(
        "[*] responder listening on {}",
        ep.sock.local_addr().unwrap()
    );

    let mut got_hs = false;
    let mut got_data = 0usize;
    let mut cookies_sent = 0usize;
    let mut rx = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        let Some((n, src)) = ep.recv(&mut rx, Duration::from_secs(1)) else {
            continue;
        };
        // In `responder-cookie` mode pretend to be under load until the
        // first cookie has gone out; the kernel must come back with a
        // valid mac2 (which is then checked for real: still under load).
        let under_load = cookie_first && !got_hs;
        let mut out = [0u8; 128];
        let reply = {
            let handled = ep.handle(src, under_load, &mut rx[..n], &mut out);
            match handled.received {
                Received::HandshakeResponse(tx) => {
                    got_hs = true;
                    eprintln!("[+] kernel initiation accepted, response → {}", tx.dst);
                    Some((tx.datagram.to_vec(), tx.dst, None))
                }
                Received::CookieReply(tx) => {
                    cookies_sent += 1;
                    eprintln!("[+] under load: cookie reply → {}", tx.dst);
                    Some((tx.datagram.to_vec(), tx.dst, None))
                }
                Received::Data(d) => {
                    got_data += 1;
                    eprintln!("[+] data {}B from kernel", d.len());
                    icmp_reply(d).map(|r| (Vec::new(), src, Some(r)))
                }
                Received::Keepalive => {
                    eprintln!("[+] keepalive");
                    None
                }
                other => {
                    eprintln!("[?] {other:?}");
                    None
                }
            }
        };
        match reply {
            Some((_, _, Some(inner))) => {
                ep.send(&inner);
            }
            Some((datagram, dst, None)) => {
                ep.sock.send_to(&datagram, dst).unwrap();
            }
            None => {}
        }
        if got_hs && got_data >= 3 {
            break;
        }
    }
    assert!(got_hs, "FAIL: never accepted kernel initiation");
    assert!(got_data >= 3, "FAIL: only {got_data} data pkts decrypted");
    if cookie_first {
        assert!(cookies_sent >= 1, "FAIL: no cookie reply was sent");
        assert!(
            ep.device.stats().cookies_sent >= 1 && ep.device.stats().initiations >= 1,
            "FAIL: the kernel never came back with a valid mac2"
        );
        eprintln!("[+] cookie dance completed ({cookies_sent} cookie replies)");
    }
    let s = ep.tunnel.stats();
    eprintln!(
        "[=] PASS responder  hs={} tx={} rx={} authfail={}",
        s.handshakes_completed, s.tx_transport, s.rx_transport, s.auth_failures
    );
    assert_eq!(s.auth_failures, 0);
    println!("RESPONDER_PASS");
}

/// Receive a one-way stream from the kernel and send only what the
/// protocol requires.
fn run_sink(seconds: u64, port: &str, our_priv: StaticSecret, peer_pub: PublicKey) {
    let mut ep = Endpoint::new(our_priv, peer_pub, None, &format!("0.0.0.0:{port}"), None);
    eprintln!(
        "[*] sink on {} for {seconds}s",
        ep.sock.local_addr().unwrap()
    );
    let mut rx = [0u8; 4096];
    let mut initiations = Vec::new();
    let mut data = 0usize;
    let mut first_data = None;
    let mut last_data = None;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        let Some((n, src)) = ep.recv(&mut rx, Duration::from_millis(200)) else {
            continue;
        };
        let mut out = [0u8; 128];
        let reply = match ep.handle(src, false, &mut rx[..n], &mut out).received {
            Received::HandshakeResponse(tx) => {
                initiations.push(ep.start.elapsed());
                Some((tx.datagram.to_vec(), tx.dst))
            }
            Received::Data(_) => {
                data += 1;
                first_data.get_or_insert(ep.start.elapsed());
                last_data = Some(ep.start.elapsed());
                None
            }
            _ => None,
        };
        if let Some((datagram, dst)) = reply {
            ep.sock.send_to(&datagram, dst).unwrap();
        }
    }
    ep.pump();
    let keepalives: Vec<_> = ep
        .sent
        .iter()
        .filter(|(_, w)| *w == SendReason::Keepalive)
        .map(|(t, _)| t.as_secs_f32())
        .collect();
    let stream = last_data
        .unwrap_or_default()
        .saturating_sub(first_data.unwrap_or_default());
    eprintln!(
        "[=] sink: {data} data packets over {:.1}s; keepalives we sent at {keepalives:.1?}s; \
         kernel initiations at {:.1?}s",
        stream.as_secs_f32(),
        initiations
            .iter()
            .map(Duration::as_secs_f32)
            .collect::<Vec<_>>()
    );
    assert!(
        data > 20,
        "FAIL: the kernel's stream did not arrive ({data} packets)"
    );
    // One keepalive per Keepalive-Timeout (10 s) of unanswered data.
    let expected = stream.as_secs() / 10;
    assert!(
        keepalives.len() as u64 >= expected.max(1),
        "FAIL: sent {} keepalives during a {:.0}s one-way stream, expected ≥ {expected}",
        keepalives.len(),
        stream.as_secs_f32()
    );
    // …so the kernel's "stopped hearing back" timer never fires.
    assert_eq!(
        initiations.len(),
        1,
        "FAIL: the kernel re-handshook during the stream: {initiations:?}"
    );
    println!(
        "SINK_PASS keepalives={} initiations={}",
        keepalives.len(),
        initiations.len()
    );
}

/// Stream one way to the kernel; it answers with keepalives only.
fn run_source(seconds: u64, endpoint: &str, our_priv: StaticSecret, peer_pub: PublicKey) {
    let endpoint: SocketAddr = endpoint.parse().expect("endpoint");
    let mut ep = Endpoint::new(our_priv, peer_pub, None, "0.0.0.0:0", Some(endpoint));
    handshake_as_initiator(&mut ep);
    let net = [10, 77, 0];
    let mut rx = [0u8; 4096];
    let mut keepalives_received = Vec::new();
    let mut seq = 0u16;
    let mut next_send = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        if Instant::now() >= next_send {
            seq += 1;
            assert!(ep.send(&udp_packet(seq, 64, net)), "FAIL: lost the session");
            next_send += Duration::from_millis(250);
        }
        let wait = next_send.saturating_duration_since(Instant::now());
        let Some((n, src)) = ep.recv(&mut rx, wait) else {
            continue;
        };
        let mut out = [0u8; 128];
        match ep.handle(src, false, &mut rx[..n], &mut out).received {
            Received::Keepalive => keepalives_received.push(ep.start.elapsed().as_secs_f32()),
            Received::Data(d) => eprintln!("[?] unexpected data {}B from kernel", d.len()),
            other => eprintln!("[?] {other:?}"),
        }
    }
    ep.pump();
    let handshakes =
        ep.count(SendReason::HandshakeInitiation) + ep.count(SendReason::HandshakeRetransmit);
    eprintln!(
        "[=] source: sent {seq} data packets over {seconds}s; kernel keepalives at \
         {keepalives_received:.1?}s; handshake initiations we sent: {handshakes}"
    );
    assert!(
        keepalives_received.len() as u64 >= (seconds / 10).max(1),
        "FAIL: only {} keepalives from the kernel in {seconds}s",
        keepalives_received.len()
    );
    assert_eq!(
        handshakes, 1,
        "FAIL: we started a new handshake although the kernel was answering"
    );
    println!(
        "SOURCE_PASS keepalives={} initiations={handshakes}",
        keepalives_received.len()
    );
}

/// Both sides initiate at once (see the module docs). Passes if the
/// crossing really happened, our own handshake completed with the
/// kernel's answer, nothing was retransmitted, and traffic flows. With
/// `either_handshake` (`crossed-either`) the handshake that completes may
/// be the peer's as well, and no ping of the peer's may be missing.
fn run_crossed(
    bind_port: &str,
    kernel_endpoint: &str,
    our_priv: StaticSecret,
    peer_pub: PublicKey,
    either_handshake: bool,
) {
    let kernel: SocketAddr = kernel_endpoint.parse().expect("kernel endpoint");
    let mut ep = Endpoint::new(
        our_priv,
        peer_pub,
        None,
        &format!("0.0.0.0:{bind_port}"),
        Some(kernel),
    );
    eprintln!("[*] waiting for the kernel's initiation on udp/{bind_port}");

    // The kernel's initiation arrives — and stays unread in the socket.
    let mut peeked = [0u8; 256];
    ep.sock
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let (n, _) = ep
        .sock
        .peek_from(&mut peeked)
        .expect("FAIL: no initiation from the kernel");
    assert!(
        n == 148 && peeked[0] == 1,
        "FAIL: expected a handshake initiation first, got type {} ({n} B)",
        peeked[0]
    );
    // Ours goes out now: each side's initiation is in flight when the
    // other's arrives.
    let crossed_at = Instant::now();
    let now = ep.now();
    ep.tunnel.request_handshake(now);
    ep.pump();
    assert_eq!(ep.count(SendReason::HandshakeInitiation), 1);

    let mut answered_theirs = false;
    let mut dropped_responses = 0usize;
    let mut established_after: Option<Duration> = None;
    let mut completed_as_initiator = false;
    let mut echoes = 0usize;
    // The ICMP sequence numbers of the echoes answered.
    let mut echo_seqs = Vec::new();
    // Our index of the session the peer's initiation made (the sender
    // index of our answer), and whether the peer has sent on it: then
    // the peer's handshake completed, whatever became of ours.
    let mut their_session: Option<u32> = None;
    let mut peer_sent_on_its_own = false;
    let mut rx = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline && echoes < 3 {
        let Some((n, src)) = ep.recv(&mut rx, Duration::from_secs(1)) else {
            continue;
        };
        let message_type = rx[0];
        let receiver = u32::from_le_bytes([rx[4], rx[5], rx[6], rx[7]]);
        let mut out = [0u8; 128];
        enum Act {
            Reply(Vec<u8>, SocketAddr),
            Echo(Vec<u8>),
            Nothing,
        }
        let (act, established) = {
            let handled = ep.handle(src, false, &mut rx[..n], &mut out);
            if matches!(handled.received, Received::Data(_) | Received::Keepalive)
                && their_session == Some(receiver)
            {
                peer_sent_on_its_own = true;
            }
            let act = match handled.received {
                Received::HandshakeResponse(tx) => {
                    eprintln!("[+] answered the kernel's initiation");
                    Act::Reply(tx.datagram.to_vec(), tx.dst)
                }
                Received::HandshakeComplete => {
                    completed_as_initiator = true;
                    eprintln!("[+] our handshake completed");
                    Act::Nothing
                }
                Received::Dropped(reason) => {
                    eprintln!("[+] dropped a type-{message_type} message: {reason}");
                    if message_type == 2 {
                        dropped_responses += 1;
                    }
                    Act::Nothing
                }
                Received::Data(d) => icmp_reply(d).map_or(Act::Nothing, Act::Echo),
                _ => Act::Nothing,
            };
            (act, handled.session_established)
        };
        if established && established_after.is_none() {
            established_after = Some(crossed_at.elapsed());
            eprintln!(
                "[+] session established {:.2?} after the crossing",
                crossed_at.elapsed()
            );
        }
        match act {
            Act::Reply(datagram, dst) => {
                // The crossing: we answer the kernel's initiation while
                // our own is still unanswered.
                if !completed_as_initiator {
                    answered_theirs = true;
                }
                their_session = Some(u32::from_le_bytes([
                    datagram[4],
                    datagram[5],
                    datagram[6],
                    datagram[7],
                ]));
                ep.sock.send_to(&datagram, dst).unwrap();
            }
            Act::Echo(inner) => {
                if ep.send(&inner) {
                    echoes += 1;
                    echo_seqs.push(u16::from_be_bytes([inner[26], inner[27]]));
                }
            }
            Act::Nothing => {}
        }
    }
    ep.pump();

    let retransmits = ep.count(SendReason::HandshakeRetransmit);
    let s = ep.tunnel.stats();
    eprintln!(
        "[=] crossed: answered the kernel's initiation while ours was in flight: \
         {answered_theirs}; our handshake completed: {completed_as_initiator}, \
         {established_after:.2?} after the crossing; kernel responses dropped: \
         {dropped_responses}; our retransmissions: {retransmits}; handshakes completed: {}; \
         echoes answered: {echoes}",
        s.handshakes_completed,
    );
    // One loopback round trip after the crossing there is a session…
    let at_once = established_after.is_some_and(|d| d <= Duration::from_secs(1));
    if either_handshake {
        // …of either handshake, and no ping was lost on the way to it:
        // the peer's end numbers its pings from 1
        // (scripts/wg_netns_helper.py), and the first three were answered
        // — the one that set the peer's handshake off among them.
        eprintln!(
            "[=] crossed-either: our handshake completed: {completed_as_initiator}; the \
             peer's completed (it sent on the session of its own initiation): \
             {peer_sent_on_its_own}; sequence numbers of the echoes answered: {echo_seqs:?}"
        );
        assert!(
            answered_theirs && at_once && retransmits == 0 && echo_seqs == [1, 2, 3],
            "FAIL: the crossed handshakes left no session at once, or one that lost a ping"
        );
        println!("CROSSED_PASS");
        return;
    }
    // …of ours: the kernel answers our initiation and drops its own.
    assert!(
        answered_theirs
            && completed_as_initiator
            && at_once
            && dropped_responses == 0
            && retransmits == 0
            && s.handshakes_completed == 1
            && echoes >= 3,
        "FAIL: the crossed handshake did not resolve as expected"
    );
    println!("CROSSED_PASS");
}
