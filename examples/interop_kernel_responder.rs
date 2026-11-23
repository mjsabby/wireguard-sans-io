//! Responder-side interop: this implementation acts as the SERVER, the
//! Linux kernel acts as the CLIENT. Verifies that a kernel-generated
//! handshake initiation is accepted, our response is accepted by the
//! kernel, and bidirectional transport works.
//!
//! For a kernel on another machine; on one Linux machine, and in CI,
//! `interop_conformance.rs` with `scripts/interop_netns.sh` covers this
//! role as well, with nothing but this repository.
//!
//! Here, with a private key for this program (`wg genkey`) and the
//! kernel's public key (all keys in base64, as `wg` prints them):
//!
//! ```text
//! cargo run --example interop_kernel_responder -- 0.0.0.0:51821 <our private key> <kernel's public key>
//! ```
//!
//! On the Linux side, as root — 10.98.0.x are the addresses inside the
//! tunnel, and `<our public key>` is what `wg pubkey` (or this
//! repository's `pubkey` example) makes of our private key:
//!
//! ```text
//! wg genkey | tee kernel.key | wg pubkey     # the kernel's key pair; this prints its public key
//! ip link add wgresp type wireguard
//! ip addr add 10.98.0.2/24 dev wgresp
//! wg set wgresp private-key kernel.key peer <our public key> \
//!     endpoint <this program's address>:51821 allowed-ips 10.98.0.1/32
//! ip link set wgresp up
//! ping -c 4 10.98.0.1                        # makes the kernel initiate
//! ```

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
    Device, Encapsulated, EntropyError, EntropySource, PeerConfig, PeerId, PollOutput, PublicKey,
    Received, StaticSecret, Ticks, WallClock,
};

/// **Test only — DO NOT copy this into a real program.** It is not an
/// entropy source: it stirs the clock into the standard library's hasher
/// seeds, which is enough for a wire-format interop check on a platform
/// without `/dev/urandom` and for nothing else. A real embedder feeds the
/// library OS randomness (see `EMBEDDER_OBLIGATIONS.md` §1).
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
            chunk
                .iter_mut()
                .zip(h.finish().to_le_bytes().iter())
                .for_each(|(d, s)| *d = *s);
        }
        Ok(())
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
        if c == b'=' {
            continue;
        }
        let v = lut[c as usize];
        assert!(v != 255);
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[idx] = (acc >> bits) as u8;
            idx += 1;
        }
    }
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

/// Turn a received ICMP echo request into an echo reply (swap src/dst,
/// type 8→0, recompute checksums).
fn icmp_reply(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 28 || req[0] >> 4 != 4 || req[9] != 1 || req[20] != 8 {
        return None;
    }
    let mut r = req.to_vec();
    let ip_len = wireguard_sans_io::ip_packet_len(&r)?;
    r.truncate(ip_len);
    // Swap addresses.
    let (a, b) = (r[12..16].to_vec(), r[16..20].to_vec());
    r[12..16].copy_from_slice(&b);
    r[16..20].copy_from_slice(&a);
    r[10] = 0;
    r[11] = 0;
    let cks = ipv4_checksum(&r[..20]);
    r[10..12].copy_from_slice(&cks.to_be_bytes());
    // ICMP type 8→0, recompute icmp checksum over icmp body.
    r[20] = 0;
    r[22] = 0;
    r[23] = 0;
    let icmp_cks = ipv4_checksum(&r[20..]);
    r[22..24].copy_from_slice(&icmp_cks.to_be_bytes());
    Some(r)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, bind, server_priv, client_pub, ..] = args.as_slice() else {
        eprintln!(
            "usage: interop_kernel_responder <address to bind>:<port> <our private key> <kernel's public key>"
        );
        std::process::exit(2);
    };
    println!("[*] Responder binding on {bind}");

    // We are the SERVER now. Kernel is the CLIENT.
    let server_priv = StaticSecret::from_bytes(b64_decode(server_priv));
    let client_pub = PublicKey::from_bytes(b64_decode(client_pub));
    let mut rng = OsRng;
    // A pure responder: no endpoint configured. The tunnel learns the
    // kernel's address from its (authenticated) handshake initiation.
    let mut device = Device::new(server_priv, wall_clock(), &mut rng).unwrap();
    let mut tunnel = device
        .tunnel(
            PeerId::new(0).unwrap(),
            PeerConfig::new(client_pub),
            &mut rng,
        )
        .unwrap();

    let sock = UdpSocket::bind(bind).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    println!(
        "[*] Listening on {} — start the kernel client now",
        sock.local_addr().unwrap()
    );

    let mut got_handshake = false;
    let mut got_data = false;
    let mut rx = [0u8; 2048];

    for _ in 0..50 {
        // Drain timer-driven actions. Each datagram carries its own
        // destination: the peer's endpoint as the core tracks it.
        loop {
            let mut buf = [0u8; 2048];
            match tunnel.poll(now(), &mut buf, &mut rng).unwrap() {
                PollOutput::Transmit(tx, why) => {
                    println!("[>] poll/{why:?}: {} bytes → {}", tx.datagram.len(), tx.dst);
                    sock.send_to(tx.datagram, tx.dst).unwrap();
                }
                PollOutput::Idle => break,
                other => println!("[!] {other:?}"),
            }
        }

        let (n, from) = match sock.recv_from(&mut rx) {
            Ok(v) => v,
            Err(_) => {
                if got_handshake && got_data {
                    break;
                }
                println!("[!] timeout waiting for kernel");
                continue;
            }
        };
        println!("[<] {n} bytes (type={}) from {from}", rx[0]);
        let mut out = [0u8; 128];
        // What to answer with, extracted before the buffers are reused.
        let mut inner_reply = None;
        match device
            .receive_for(
                &mut tunnel,
                now(),
                from,
                false,
                &mut rx[..n],
                &mut out,
                &mut rng,
            )
            .unwrap()
            .received
        {
            Received::HandshakeResponse(tx) => {
                println!(
                    "[>] HandshakeResponse: {} bytes → {}",
                    tx.datagram.len(),
                    tx.dst
                );
                sock.send_to(tx.datagram, tx.dst).unwrap();
                got_handshake = true;
                println!("[+] Kernel initiation ACCEPTED, response sent");
            }
            Received::CookieReply(tx) => {
                println!("[>] CookieReply: {} bytes → {}", tx.datagram.len(), tx.dst);
                sock.send_to(tx.datagram, tx.dst).unwrap();
            }
            Received::Data(d) => {
                println!("[+] Decrypted {} plaintext bytes from kernel", d.len());
                got_data = true;
                inner_reply = icmp_reply(d);
            }
            Received::Keepalive => {
                println!("[+] Decrypted keepalive (kernel confirmed our response)");
            }
            Received::HandshakeComplete => {
                println!("[+] HandshakeComplete (we initiated?)");
                got_handshake = true;
            }
            Received::CookieStored => println!("[+] CookieStored"),
            Received::Dropped(reason) => println!("[!] dropped: {reason:?}"),
            other => println!("[?] {other:?}"),
        }
        if let Some(reply) = inner_reply {
            let mut buf = [0u8; 2048];
            match tunnel.encapsulate(now(), &reply, &mut buf).unwrap() {
                Encapsulated::Transport(tx) => {
                    println!("[>] ICMP reply: {} bytes → {}", tx.datagram.len(), tx.dst);
                    sock.send_to(tx.datagram, tx.dst).unwrap();
                }
                other => panic!("{other:?}"),
            }
        }
        if got_handshake && got_data && tunnel.stats().tx_transport >= 1 {
            break;
        }
    }

    assert!(
        got_handshake,
        "FAIL: never accepted a kernel handshake initiation"
    );
    assert!(got_data, "FAIL: never decrypted kernel transport data");
    println!(
        "\n=== RESPONDER INTEROP PASS ===\n  stats: {:?}\n  device: {:?}",
        tunnel.stats(),
        device.stats()
    );
}
