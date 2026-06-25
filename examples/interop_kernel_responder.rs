//! Responder-side interop: this implementation acts as the SERVER, the
//! Linux kernel acts as the CLIENT. Verifies that a kernel-generated
//! handshake initiation is accepted, our response is accepted by the
//! kernel, and bidirectional transport works.
//!
//! Setup (in WSL as root):
//! ```text
//! bash /tmp/wg_responder_setup.sh <windows-host-ip> <our-port>
//! ping -c 4 10.98.0.1   # this triggers the kernel to initiate
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
    Config, Encapsulated, EntropyError, EntropySource, Now, PollOutput, PublicKey, Received,
    StaticSecret, Tunnel,
};

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

fn now() -> Now {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = *START.get_or_init(std::time::Instant::now);
    let mono_ns = std::time::Instant::now().duration_since(start).as_nanos() as u64;
    let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    Now::new(mono_ns, wall.as_secs(), wall.subsec_nanos())
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
    let bind = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:51821".into());
    println!("[*] Responder binding on {bind}");

    // We are the SERVER now. Kernel is the CLIENT.
    let server_priv =
        StaticSecret::from_bytes(b64_decode("aFGpcWCk9YyV4nbaIeCz5IMC7iXY3UYmcBvRMFzwnVU="));
    // CLIENT_PUB from setup script.
    let client_pub =
        PublicKey::from_bytes(b64_decode("ZZO7mwCUa2iO43fhcd/MYMDtoriAPvpE4oLROBKR/k0="));
    let mut tunnel = Tunnel::new(Config::new(server_priv, client_pub)).unwrap();
    let mut rng = OsRng;

    let sock = UdpSocket::bind(&bind).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    println!(
        "[*] Listening on {} — start the kernel client now",
        sock.local_addr().unwrap()
    );

    let mut peer_addr = None;
    let mut got_handshake = false;
    let mut got_data = false;
    let mut rx = [0u8; 2048];

    for _ in 0..50 {
        // Drain timer-driven actions.
        loop {
            let mut buf = [0u8; 2048];
            match tunnel.poll(now(), &mut buf, &mut rng).unwrap() {
                PollOutput::Send(w, why) => {
                    if let Some(addr) = peer_addr {
                        println!("[>] poll/{why:?}: {} bytes", w.len());
                        sock.send_to(w, addr).unwrap();
                    }
                }
                _ => break,
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
        peer_addr = Some(from);
        println!("[<] {n} bytes (type={}) from {from}", rx[0]);
        let mut out = [0u8; 2048];
        let remote = format!("{from}");
        match tunnel.decapsulate(
            now(),
            remote.as_bytes(),
            false,
            &rx[..n],
            &mut out,
            &mut rng,
        ) {
            Ok(Received::Reply(w)) => {
                let kind = match w[0] {
                    2 => "HandshakeResponse",
                    3 => "CookieReply",
                    _ => "?",
                };
                println!("[>] {kind}: {} bytes", w.len());
                sock.send_to(w, from).unwrap();
                if w[0] == 2 {
                    got_handshake = true;
                    println!("[+] Kernel initiation ACCEPTED, response sent");
                }
            }
            Ok(Received::Data(d)) => {
                println!("[+] Decrypted {} plaintext bytes from kernel", d.len());
                got_data = true;
                if let Some(reply) = icmp_reply(d) {
                    let mut buf = [0u8; 2048];
                    match tunnel
                        .encapsulate(now(), &reply, &mut buf, &mut rng)
                        .unwrap()
                    {
                        Encapsulated::Transport(w) => {
                            println!("[>] ICMP reply: {} bytes", w.len());
                            sock.send_to(w, from).unwrap();
                        }
                        other => panic!("{other:?}"),
                    }
                }
            }
            Ok(Received::Keepalive) => {
                println!("[+] Decrypted keepalive (kernel confirmed our response)");
            }
            Ok(Received::HandshakeComplete) => {
                println!("[+] HandshakeComplete (we initiated?)");
                got_handshake = true;
            }
            Ok(Received::CookieStored) => println!("[+] CookieStored"),
            Err(e) => {
                println!("[!] decapsulate error: {e:?}");
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
        "\n=== RESPONDER INTEROP PASS ===\n  stats: {:?}",
        tunnel.stats()
    );
}
