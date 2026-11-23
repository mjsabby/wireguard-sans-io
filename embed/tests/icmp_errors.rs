//! ICMP errors must not end the event loop, stop it listening, or cost
//! it the datagrams it sends.
//!
//! On Linux the kernel reports ICMP errors about a UDP socket's earlier
//! datagrams on the socket's next call — when the socket is connected, or
//! when it has `IP_RECVERR` set (which an embedder who wants path-MTU
//! discovery sets). Each kind of ICMP error becomes a different `errno`:
//! fragmentation needed is `EMSGSIZE`, protocol unreachable `ENOPROTOOPT`,
//! parameter problem `EPROTO`, administratively prohibited `EACCES`, and
//! so on. Any host that can reach ours can forge all of them, knowing no
//! more than our address and port. The loop therefore has to survive every
//! one — which is what the first group of tests checks, by forging them.
//!
//! One at a time is not all there is to it. With `IP_RECVERR` every error
//! is also kept in the socket's error queue, which is charged to the
//! socket's receive buffer: a few hundred that nobody reads, and the
//! socket receives nothing any more. And an error that is pending when
//! the loop *sends* fails that send. The second group forges them by the
//! thousand.
//!
//! Forging ICMP needs a raw socket, so the tests are ignored by default
//! and run inside a private network namespace:
//!
//! ```sh
//! scripts/driver_netns_tests.sh
//! ```
//!
//! (The one ICMP error that needs no forging — port unreachable — is
//! covered by an ordinary test in `src/tokio.rs`.)
#![cfg(all(feature = "async", target_os = "linux"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use wireguard_embed::core::{EntropySource, PublicKey, StaticSecret};
use wireguard_embed::tokio::{AsyncTunn, LoopStats, TunnChannels};
use wireguard_embed::{PooledBuf, SlabPool, Tunn, TunnResult};

/// Forge ICMP errors "about" a UDP datagram that `local` sent to
/// `remote`, and deliver them to `local`'s host from an unrelated address:
/// `count` of them at once if `rate` is 0, otherwise `rate` a second
/// until there have been `count`.
/// argv: local_ip local_port remote_ip remote_port type code count rate.
const FORGE_ICMP: &str = r"
import socket, struct, sys, time
lip, lport, rip, rport, typ, code = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
count, rate = int(sys.argv[7]), float(sys.argv[8])
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28 + 1456, 1, 0x4000, 64, 17, 0, socket.inet_aton(lip), socket.inet_aton(rip))
ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
udp = struct.pack('!HHHH', lport, rport, 8 + 1456, 0)
rest = struct.pack('!HH', 0, 1400) if (typ, code) == (3, 4) else struct.pack('!I', 0)
body = ip + udp
hdr = struct.pack('!BBH', typ, code, 0) + rest
hdr = struct.pack('!BBH', typ, code, csum(hdr + body)) + rest
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.bind(('127.0.0.99', 0))
start = time.monotonic()
for n in range(count):
    if rate:
        wait = start + n / rate - time.monotonic()
        if wait > 0: time.sleep(wait)
    s.sendto(hdr + body, (lip, 0))
";

/// The IPv6 counterpart (the kernel fills in the ICMPv6 checksum).
const FORGE_ICMP6: &str = r"
import socket, struct, sys, time
lip, lport, rip, rport, typ, code = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
count, rate = int(sys.argv[7]), float(sys.argv[8])
ip6 = struct.pack('!IHBB', 6 << 28, 8 + 1456, 17, 64) + socket.inet_pton(socket.AF_INET6, lip) + socket.inet_pton(socket.AF_INET6, rip)
udp = struct.pack('!HHHH', lport, rport, 8 + 1456, 0)
rest = struct.pack('!I', 1400 if typ == 2 else 0)
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
start = time.monotonic()
for n in range(count):
    if rate:
        wait = start + n / rate - time.monotonic()
        if wait > 0: time.sleep(wait)
    s.sendto(struct.pack('!BBH', typ, code, 0) + rest + ip6 + udp, (lip, 0))
";

/// `setsockopt(IP_RECVERR)` — or, on an IPv6 socket, `IPV6_RECVERR` — on
/// the socket passed as stdin.
const SET_RECVERR: &str = "import socket; s = socket.socket(fileno=0); \
                           v6 = s.family == socket.AF_INET6; \
                           s.setsockopt(41 if v6 else 0, 25 if v6 else 11, 1); s.detach()";

/// Print how much of its receive buffer the socket passed as stdin has
/// in use (`SO_MEMINFO`: `rmem_alloc`).
const RECEIVE_BUFFER_IN_USE: &str = "import socket, struct; s = socket.socket(fileno=0); \
                                     print(struct.unpack('9I', s.getsockopt(1, 55, 36))[0]); \
                                     s.detach()";

fn keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::from_bytes(wireguard_embed::OsEntropy.gen32().unwrap());
    let public = secret.public_key();
    (secret, public)
}

fn ip_packet(tag: u8) -> [u8; 60] {
    let mut p = [0u8; 60];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&60u16.to_be_bytes());
    p[59] = tag;
    p
}

/// The command that forges `count` ICMP errors of the given type and code
/// about a datagram from `local` to `remote` — all at once, or `rate` a
/// second.
fn forger(
    local: SocketAddr,
    remote: SocketAddr,
    (typ, code): (u8, u8),
    count: u32,
    rate: u32,
) -> Command {
    let script = if local.is_ipv6() {
        FORGE_ICMP6
    } else {
        FORGE_ICMP
    };
    let mut command = Command::new("python3");
    command.args(["-I", "-c", script]).args([
        local.ip().to_string(),
        local.port().to_string(),
        remote.ip().to_string(),
        remote.port().to_string(),
        typ.to_string(),
        code.to_string(),
        count.to_string(),
        rate.to_string(),
    ]);
    command
}

/// Forge `count` errors now, and wait until they have been sent.
fn forge_icmp(local: SocketAddr, remote: SocketAddr, typ: u8, code: u8, count: u32) {
    let out = forger(local, remote, (typ, code), count, 0)
        .output()
        .expect("python3");
    assert!(
        out.status.success(),
        "cannot forge ICMP here (a raw socket is needed): run these tests with \
         scripts/driver_netns_tests.sh\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Run `script` with `socket` as its standard input; what it prints.
fn python_on(socket: &std::net::UdpSocket, script: &str) -> String {
    let fd: OwnedFd = socket.try_clone().unwrap().into();
    let out = Command::new("python3")
        .args(["-I", "-c", script])
        .stdin(Stdio::from(fd))
        .output()
        .expect("python3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Every way the loop gets to hear of an ICMP error: on a call, as the
/// socket's pending error, or from the socket's error queue.
fn errors_heard(stats: &LoopStats) -> u64 {
    stats.recv_errors() + stats.error_queue_messages() + stats.send_retries()
}

/// How B's socket is set up.
#[derive(Clone, Copy)]
enum Socket {
    /// `connect()`ed to the peer: the kernel reports "hard" ICMP errors.
    Connected,
    /// Not connected, `IP_RECVERR` set: the kernel reports all of them.
    RecvErr,
}

/// One live tunnel on loopback: A (driven by hand) ↔ B (the event loop).
/// After a packet has gone through, one forged ICMP error of the given
/// type and code — about a datagram B supposedly sent to `claimed_remote`
/// (default: its peer) — arrives at B's host. The tunnel must then still
/// deliver, and the error must have been counted.
async fn the_loop_survives(
    bind: &str,
    socket: Socket,
    icmp_type: u8,
    icmp_code: u8,
    claimed_remote: Option<SocketAddr>,
) {
    let mut t = Tunnel::up(bind, socket, 16).await;
    assert_eq!(
        t.a_sends(1, 1).await,
        1,
        "the tunnel works before the ICMP error"
    );

    // The forged error.
    forge_icmp(
        t.addr_b,
        claimed_remote.unwrap_or(t.addr_a),
        icmp_type,
        icmp_code,
        1,
    );
    let stats = t.stats.clone();
    tokio::time::timeout(Duration::from_secs(2), async {
        while errors_heard(&stats) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the kernel did not report the ICMP error on this socket: the test is not testing");
    assert!(
        !t.task.is_finished(),
        "one forged ICMP error ended the event loop"
    );

    // The tunnel still delivers.
    assert_eq!(
        t.a_sends(2, 1).await,
        1,
        "no packet was delivered after the ICMP error"
    );
    assert!(!t.task.is_finished());
}

/// One live tunnel on loopback: A (driven by hand) ↔ B (the event loop).
struct Tunnel {
    tunn_a: Tunn,
    sock_a: UdpSocket,
    addr_a: SocketAddr,
    addr_b: SocketAddr,
    /// A second handle on B's socket, to ask the kernel about it.
    handle_b: std::net::UdpSocket,
    b: TunnChannels,
    stats: Arc<LoopStats>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Tunnel {
    /// Both ends bound to `bind`, B's socket set up as `socket` says, the
    /// handshake done.
    async fn up(bind: &str, socket: Socket, depth: usize) -> Self {
        let (a_sk, a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let sock_a = UdpSocket::bind(bind).await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();

        let std_b = std::net::UdpSocket::bind(bind).unwrap();
        let addr_b = std_b.local_addr().unwrap();
        match socket {
            Socket::Connected => std_b.connect(addr_a).unwrap(),
            Socket::RecvErr => {
                python_on(&std_b, SET_RECVERR);
            }
        }
        std_b.set_nonblocking(true).unwrap();
        let handle_b = std_b.try_clone().unwrap();
        let sock_b = Arc::new(UdpSocket::from_std(std_b).unwrap());

        let mut tunn_a = Tunn::new(a_sk, b_pk, None, None, Some(addr_b), None).unwrap();
        let tunn_b = Tunn::new(b_sk, a_pk, None, None, Some(addr_a), None).unwrap();
        let (driver, b, rx, tx) = AsyncTunn::channels(tunn_b, sock_b, depth);
        let stats = driver.loop_stats();
        let task = tokio::spawn(driver.run(rx, tx));

        // Handshake by hand.
        let (mut out, mut buf, mut wire) = (vec![0u8; 2048], vec![0u8; 2048], vec![0u8; 2048]);
        if let TunnResult::WriteToNetwork(d, to) = tunn_a.format_handshake_initiation(&mut out) {
            sock_a.send_to(d, to).await.unwrap();
        }
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), sock_a.recv_from(&mut wire))
            .await
            .expect("handshake response")
            .unwrap();
        if let TunnResult::WriteToNetwork(d, to) = tunn_a.decapsulate(from, &wire[..n], &mut buf) {
            sock_a.send_to(d, to).await.unwrap();
        }
        assert!(tunn_a.is_established());
        Self {
            tunn_a,
            sock_a,
            addr_a,
            addr_b,
            handle_b,
            b,
            stats,
            task,
        }
    }

    /// A sends `count` packets, tagged from `first_tag` on, a little
    /// apart. How many B's TUN side gets.
    async fn a_sends(&mut self, first_tag: u8, count: u8) -> usize {
        let mut out = vec![0u8; 2048];
        for i in 0..count {
            if let TunnResult::WriteToNetwork(d, to) =
                self.tunn_a.encapsulate(&ip_packet(first_tag + i), &mut out)
            {
                self.sock_a.send_to(d, to).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut got = 0;
        while got < usize::from(count) {
            match tokio::time::timeout(Duration::from_secs(2), self.b.from_net.recv()).await {
                Ok(Some(_)) => got += 1,
                _ => break,
            }
        }
        got
    }
}

const V4: &str = "127.0.0.1:0";
const V6: &str = "[::1]:0";

/// Port unreachable: `ECONNREFUSED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn port_unreachable_on_a_connected_socket() {
    the_loop_survives(V4, Socket::Connected, 3, 3, None).await;
}

/// Fragmentation needed — what every path-MTU change produces: `EMSGSIZE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn fragmentation_needed_on_a_connected_socket() {
    the_loop_survives(V4, Socket::Connected, 3, 4, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn fragmentation_needed_with_ip_recverr() {
    the_loop_survives(V4, Socket::RecvErr, 3, 4, None).await;
}

/// With `IP_RECVERR` on an unconnected socket the forger needs to know
/// nothing but the socket's own address and port: the error may claim to
/// be about a datagram to anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn an_error_about_a_datagram_that_was_never_sent() {
    let elsewhere = "192.0.2.77:9".parse().unwrap();
    the_loop_survives(V4, Socket::RecvErr, 3, 4, Some(elsewhere)).await;
}

/// Protocol unreachable: `ENOPROTOOPT`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn protocol_unreachable_on_a_connected_socket() {
    the_loop_survives(V4, Socket::Connected, 3, 2, None).await;
}

/// Parameter problem: `EPROTO`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn parameter_problem_with_ip_recverr() {
    the_loop_survives(V4, Socket::RecvErr, 12, 0, None).await;
}

/// ICMPv6 packet too big — routine on IPv6, where routers never fragment:
/// `EMSGSIZE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn v6_packet_too_big_on_a_connected_socket() {
    the_loop_survives(V6, Socket::Connected, 2, 0, None).await;
}

/// ICMPv6 administratively prohibited — what a firewall's REJECT sends:
/// `EACCES`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn v6_administratively_prohibited_on_a_connected_socket() {
    the_loop_survives(V6, Socket::Connected, 1, 1, None).await;
}

/// ICMPv6 port unreachable: `ECONNREFUSED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn v6_port_unreachable_on_a_connected_socket() {
    the_loop_survives(V6, Socket::Connected, 1, 4, None).await;
}

// ---- by the thousand --------------------------------------------------------

/// An address B never sent anything to. With `IP_RECVERR` on an
/// unconnected socket the forger can name anybody.
fn elsewhere(bind: &str) -> SocketAddr {
    if bind == V6 {
        "[2001:db8::77]:9".parse().unwrap()
    } else {
        "192.0.2.77:9".parse().unwrap()
    }
}

/// Two thousand forged errors at a socket with `IP_RECVERR`. The kernel
/// keeps each of them in the socket's error queue, charged to its receive
/// buffer; some two hundred fill it. Read by nobody, they left the socket
/// deaf for as long as the process lived: the tunnel was gone, on the
/// say-so of anyone who could send ICMP. The loop reads them.
async fn a_flood_does_not_deafen_the_socket(bind: &str, icmp: (u8, u8)) {
    let mut t = Tunnel::up(bind, Socket::RecvErr, 64).await;
    assert_eq!(
        t.a_sends(0, 20).await,
        20,
        "the tunnel works before the flood"
    );

    forge_icmp(t.addr_b, elsewhere(bind), icmp.0, icmp.1, 2000);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let read = t.stats.error_queue_messages();
    let in_use = python_on(&t.handle_b, RECEIVE_BUFFER_IN_USE);
    println!(
        "after 2000 forged errors: {read} read from the error queue; receive buffer in use: {in_use} bytes"
    );
    assert!(
        read >= 300,
        "the kernel queued {read} errors on this socket: fewer than fill its buffer, so the test is not testing"
    );
    assert_eq!(
        in_use, "0",
        "errors are still charged to the receive buffer"
    );
    assert_eq!(
        t.a_sends(20, 20).await,
        20,
        "the socket no longer receives: its receive buffer is full of ICMP errors nobody reads"
    );
    assert!(!t.task.is_finished());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn a_flood_of_errors_with_ip_recverr_does_not_deafen_the_socket() {
    a_flood_does_not_deafen_the_socket(V4, (3, 3)).await;
}

/// The same over IPv6, where "packet too big" is routine — routers never
/// fragment — and `IPV6_RECVERR` is how an application learns the path
/// MTU.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn a_flood_of_errors_with_ipv6_recverr_does_not_deafen_the_socket() {
    a_flood_does_not_deafen_the_socket(V6, (2, 0)).await;
}

/// The other direction. A pending ICMP error is also what the socket's
/// next *send* returns (Linux reports it on whichever call comes first),
/// and a datagram whose send fails is not sent. While three thousand
/// forged errors a second arrive, B's application sends a thousand
/// packets: how many get out? (It used to be one in five.)
async fn sends_get_through_a_flood(socket: Socket) {
    let mut t = Tunnel::up(V4, socket, 4096).await;
    assert_eq!(t.a_sends(0, 1).await, 1);
    // A connected socket only takes errors about datagrams to its peer.
    let claimed_remote = match socket {
        Socket::Connected => t.addr_a,
        Socket::RecvErr => elsewhere(V4),
    };
    let mut flood = forger(t.addr_b, claimed_remote, (3, 3), 9000, 3000)
        .spawn()
        .expect("python3");
    tokio::time::sleep(Duration::from_millis(700)).await;
    let heard_before = errors_heard(&t.stats);

    const PACKETS: u32 = 1000;
    let pool = SlabPool::for_wireguard();
    let to_net = t.b.to_net.clone();
    let sender = tokio::spawn(async move {
        for i in 0..PACKETS {
            let mut p = ip_packet(0);
            p[20..24].copy_from_slice(&i.to_be_bytes());
            to_net.send(PooledBuf::copy_from(&pool, &p)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    let (mut wire, mut buf) = (vec![0u8; 2048], vec![0u8; 2048]);
    let mut arrived = 0;
    while let Ok(Ok((n, from))) =
        tokio::time::timeout(Duration::from_millis(1500), t.sock_a.recv_from(&mut wire)).await
    {
        if let TunnResult::WriteToTunnel(_) = t.tunn_a.decapsulate(from, &wire[..n], &mut buf) {
            arrived += 1;
        }
    }
    sender.await.unwrap();
    let status = flood.wait().expect("python3");
    assert!(status.success(), "cannot forge ICMP here");
    let heard = errors_heard(&t.stats) - heard_before;
    println!(
        "{arrived}/{PACKETS} packets arrived while the loop heard of {heard} ICMP errors \
         (sends repeated: {}, given up: {})",
        t.stats.send_retries(),
        t.stats.send_errors()
    );
    assert!(heard >= 1000, "the flood did not reach the socket: {heard}");
    assert!(
        arrived >= PACKETS - PACKETS / 100,
        "forged ICMP errors cost {} of {PACKETS} outbound packets",
        PACKETS - arrived
    );
    assert!(!t.task.is_finished());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn sends_get_through_a_flood_of_errors_on_a_connected_socket() {
    sends_get_through_a_flood(Socket::Connected).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a raw socket: scripts/driver_netns_tests.sh"]
async fn sends_get_through_a_flood_of_errors_with_ip_recverr() {
    sends_get_through_a_flood(Socket::RecvErr).await;
}

/// No raw socket is needed to fill an error queue — only a peer that is
/// not there. B's own datagrams to a closed port each come back as "port
/// unreachable"; with `IP_RECVERR` each is queued. (This is the case that
/// needs no attacker: a peer that is down for a few minutes.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs python3 (to set a socket option): scripts/driver_netns_tests.sh"]
async fn a_peer_that_is_not_there_does_not_deafen_the_socket_either() {
    let mut t = Tunnel::up(V4, Socket::RecvErr, 64).await;
    assert_eq!(t.a_sends(0, 5).await, 5);
    // Somebody else's port, closed: every datagram sent there from B's
    // socket is answered with an ICMP error to B's socket.
    let closed = {
        let socket = std::net::UdpSocket::bind(V4).unwrap();
        socket.local_addr().unwrap()
    };
    // (A send that finds the error of the one before pending fails with
    // it — which is how the loop's own sends used to be lost; the loop
    // may also get to the error first. Either way the next one goes.)
    let mut sent = 0;
    for _ in 0..3000 {
        if t.handle_b.send_to(b"anyone there?", closed).is_ok() {
            sent += 1;
        }
    }
    assert!(sent >= 1000, "{sent} datagrams went out");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let read = t.stats.error_queue_messages();
    assert!(
        read >= 300,
        "{read} errors were queued: too few to test with"
    );
    assert_eq!(python_on(&t.handle_b, RECEIVE_BUFFER_IN_USE), "0");
    assert_eq!(t.a_sends(5, 20).await, 20);
}
