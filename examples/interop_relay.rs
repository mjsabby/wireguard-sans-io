//! Responder-side interop via stdin/stdout hex relay: for a kernel whose
//! datagrams cannot reach this program directly (it was written for a
//! Windows host whose firewall blocked inbound UDP from the Linux VM
//! beside it). The kernel is set up as for `interop_kernel_responder.rs`,
//! with the relay's UDP port as the peer's endpoint.
//!
//! ```text
//! interop_relay <our private key> <kernel's public key>      # keys in base64
//! ```
//!
//! Protocol on stdio: each line is `<direction><hex>` where direction is
//! `>` (datagram FROM kernel, feed to tunnel) and the program prints
//! `<<hex>` for each datagram TO send to the kernel.
//!
//! The relay itself is not part of this repository; it is a few lines in
//! any language: read datagrams from a UDP socket and write each as `>`,
//! its bytes in hex and a newline to this program's standard input; for
//! every line on its standard output that starts with `<`, send the
//! decoded bytes to the address the last datagram came from.

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

use std::io::{BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

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
        acc = (acc << 6) | u32::from(lut[c as usize]);
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

fn icmp_reply(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 28 || req[0] >> 4 != 4 || req[9] != 1 || req[20] != 8 {
        return None;
    }
    let mut r = req.to_vec();
    let ip_len = wireguard_sans_io::ip_packet_len(&r)?;
    r.truncate(ip_len);
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
    let [_, server_priv, client_pub, ..] = args.as_slice() else {
        eprintln!("usage: interop_relay <our private key> <kernel's public key>");
        std::process::exit(2);
    };
    let server_priv = StaticSecret::from_bytes(b64_decode(server_priv));
    let client_pub = PublicKey::from_bytes(b64_decode(client_pub));
    let mut rng = OsRng;
    let mut device = Device::new(server_priv, wall_clock(), &mut rng).unwrap();
    let mut tunnel = device
        .tunnel(
            PeerId::new(0).unwrap(),
            PeerConfig::new(client_pub),
            &mut rng,
        )
        .unwrap();
    // Everything arrives through the relay, so every datagram has the
    // same (nominal) source address; replies go back the same way.
    let relay: std::net::SocketAddr = "127.0.0.1:51820".parse().unwrap();

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut events: Vec<String> = vec![];

    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "POLL" {
            loop {
                let mut buf = [0u8; 2048];
                match tunnel.poll(now(), &mut buf, &mut rng).unwrap() {
                    PollOutput::Transmit(tx, why) => {
                        events.push(format!("poll/{why:?}"));
                        writeln!(stdout, "<{}", hex(tx.datagram)).unwrap();
                    }
                    PollOutput::Idle => break,
                    other => events.push(format!("poll/{other:?}")),
                }
            }
            stdout.flush().unwrap();
            continue;
        }
        if line == "DONE" {
            writeln!(stdout, "EVENTS={}", events.join(",")).unwrap();
            writeln!(stdout, "STATS={:?}", tunnel.stats()).unwrap();
            stdout.flush().unwrap();
            break;
        }
        let mut datagram = unhex(&line[1..]);
        let mut out = [0u8; 128];
        let mut inner_reply = None;
        match device
            .receive_for(
                &mut tunnel,
                now(),
                relay,
                false,
                &mut datagram,
                &mut out,
                &mut rng,
            )
            .unwrap()
            .received
        {
            Received::HandshakeResponse(tx) | Received::CookieReply(tx) => {
                events.push(format!("Reply/type{}", tx.datagram[0]));
                writeln!(stdout, "<{}", hex(tx.datagram)).unwrap();
            }
            Received::Data(d) => {
                events.push(format!("Data/{}B", d.len()));
                inner_reply = icmp_reply(d);
            }
            Received::Keepalive => events.push("Keepalive".into()),
            Received::HandshakeComplete => events.push("HandshakeComplete".into()),
            Received::CookieStored => events.push("CookieStored".into()),
            Received::Dropped(reason) => {
                events.push(format!("DROP/{reason:?}"));
                writeln!(stdout, "!{reason:?}").unwrap();
            }
            other => events.push(format!("{other:?}")),
        }
        if let Some(reply) = inner_reply {
            let mut buf = [0u8; 2048];
            if let Encapsulated::Transport(tx) =
                tunnel.encapsulate(now(), &reply, &mut buf).unwrap()
            {
                writeln!(stdout, "<{}", hex(tx.datagram)).unwrap();
            }
        }
        stdout.flush().unwrap();
    }
}
