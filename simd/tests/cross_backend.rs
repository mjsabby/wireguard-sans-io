//! Cross-backend protocol correctness: a device on the scalar keystream
//! and a device on `Best` (`Avx2x8` or `Detect` on x86_64, `Neon` on
//! aarch64) complete a handshake and exchange transport data in BOTH
//! directions.
//!
//! This is the strongest correctness check the SIMD code can have:
//! it proves byte-for-byte wire-format equivalence with the
//! scalar path through the *entire* protocol stack (handshake, AEAD,
//! padding, replay), not just the keystream in isolation.

use std::net::SocketAddr;

use wireguard_chacha_simd::Best;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    ChaChaImpl, Device, Encapsulated, InTree, PeerConfig, PeerId, PollOutput, Received, Scalar,
    StaticSecret, Ticks, Tunnel, WallClock,
};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// One endpoint on keystream backend `C`.
struct Side<C: ChaChaImpl> {
    device: Device<InTree<C>>,
    tunnel: Tunnel<InTree<C>>,
    addr: SocketAddr,
}

impl<C: ChaChaImpl> Side<C> {
    fn new(
        key: StaticSecret,
        peer: wireguard_sans_io::PublicKey,
        addr: SocketAddr,
        peer_addr: SocketAddr,
        rng: &mut DeterministicRng,
    ) -> Self {
        let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
        let device = Device::<InTree<C>>::with_provider(key, wall, rng).unwrap();
        let mut cfg = PeerConfig::new(peer);
        cfg.endpoint = Some(peer_addr);
        let tunnel = device.tunnel(PeerId::new(0).unwrap(), cfg, rng).unwrap();
        Self {
            device,
            tunnel,
            addr,
        }
    }

    /// Deliver a datagram; returns (reply to send, decrypted payload,
    /// whether it was a keepalive).
    fn deliver(
        &mut self,
        from: SocketAddr,
        datagram: &[u8],
        rng: &mut DeterministicRng,
    ) -> (Option<Vec<u8>>, Option<Vec<u8>>, bool) {
        let mut copy = datagram.to_vec();
        let mut out = [0u8; 128];
        let handled = self
            .device
            .receive_for(
                &mut self.tunnel,
                Ticks::ZERO,
                from,
                false,
                &mut copy,
                &mut out,
                rng,
            )
            .unwrap();
        match handled.received {
            Received::HandshakeResponse(tx) => (Some(tx.datagram.to_vec()), None, false),
            Received::Data(d) => (None, Some(d.to_vec()), false),
            Received::Keepalive => (None, None, true),
            Received::HandshakeComplete => (None, None, false),
            other => panic!("{}: unexpected {other:?}", C::name()),
        }
    }

    /// Deliver a datagram that must be rejected; returns the buffer as
    /// the receive path left it.
    fn deliver_forgery(
        &mut self,
        from: SocketAddr,
        datagram: &[u8],
        rng: &mut DeterministicRng,
    ) -> Vec<u8> {
        let mut copy = datagram.to_vec();
        let mut out = [0xeeu8; 128];
        let handled = self
            .device
            .receive_for(
                &mut self.tunnel,
                Ticks::ZERO,
                from,
                false,
                &mut copy,
                &mut out,
                rng,
            )
            .unwrap();
        assert!(
            matches!(handled.received, Received::Dropped(_)),
            "{}: forgery accepted: {:?}",
            C::name(),
            handled.received
        );
        assert!(out.iter().all(|&x| x == 0xee), "output dirtied");
        copy
    }

    fn poll(&mut self, rng: &mut DeterministicRng) -> Vec<u8> {
        let mut buf = [0u8; 256];
        match self.tunnel.poll(Ticks::ZERO, &mut buf, rng).unwrap() {
            PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
            other => panic!("{}: expected a datagram, got {other:?}", C::name()),
        }
    }

    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; payload.len() + 64];
        match self
            .tunnel
            .encapsulate(Ticks::ZERO, payload, &mut buf)
            .unwrap()
        {
            Encapsulated::Transport(tx) => tx.datagram.to_vec(),
            other => panic!("{}: len={}: {other:?}", C::name(), payload.len()),
        }
    }
}

/// Run a full handshake (A initiates) + bidirectional transport at
/// every interesting payload length, with A on backend `CA` and B on
/// backend `CB`.
fn cross_backend_roundtrip<CA: ChaChaImpl, CB: ChaChaImpl>() {
    let mut rng = DeterministicRng::new(0xc0ffee);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();
    let (a_addr, b_addr) = (addr("192.0.2.1:51820"), addr("192.0.2.2:51820"));

    let mut a = Side::<CA>::new(a_key, b_pub, a_addr, b_addr, &mut rng);
    let mut b = Side::<CB>::new(b_key, a_pub, b_addr, a_addr, &mut rng);

    // Handshake: A → init → B → resp → A → keepalive → B.
    a.tunnel.request_handshake(Ticks::ZERO);
    let init = a.poll(&mut rng);
    let (resp, _, _) = b.deliver(a.addr, &init, &mut rng);
    let resp = resp.expect("handshake response");
    let (none, _, _) = a.deliver(b.addr, &resp, &mut rng);
    assert!(none.is_none());
    let ka = a.poll(&mut rng);
    let (_, _, is_keepalive) = b.deliver(a.addr, &ka, &mut rng);
    assert!(is_keepalive);
    assert!(a.tunnel.is_established(Ticks::ZERO) && b.tunnel.is_established(Ticks::ZERO));

    // Transport, both directions, at lengths spanning the SIMD stride
    // seams (4-block = 256, 8-block = 512), the provider's scalar cut-off
    // (64), and the WireGuard padding boundary (16) and MTUs.
    for len in [
        0usize, 1, 15, 16, 17, 47, 48, 49, 63, 64, 65, 79, 80, 81, 127, 128, 255, 256, 257, 384,
        511, 512, 513, 1024, 1280, 1350, 1420, 2000,
    ] {
        let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();

        // A (CA) encrypts → B (CB) decrypts.
        let wire = a.seal(&payload);
        let (_, data, is_keepalive) = b.deliver(a.addr, &wire, &mut rng);
        match data {
            Some(d) => {
                assert_eq!(
                    &d[..len],
                    &payload[..],
                    "{}→{} len={len}: payload mismatch",
                    CA::name(),
                    CB::name()
                );
                assert!(
                    d[len..].iter().all(|&b| b == 0),
                    "{}→{} len={len}: non-zero padding",
                    CA::name(),
                    CB::name()
                );
            }
            None => assert!(
                is_keepalive && len == 0,
                "{}→{} len={len}",
                CA::name(),
                CB::name()
            ),
        }

        // B (CB) encrypts → A (CA) decrypts.
        let wire = b.seal(&payload);
        let (_, data, is_keepalive) = a.deliver(b.addr, &wire, &mut rng);
        match data {
            Some(d) => {
                assert_eq!(&d[..len], &payload[..]);
                assert!(d[len..].iter().all(|&b| b == 0));
            }
            None => assert!(
                is_keepalive && len == 0,
                "{}→{} len={len}",
                CB::name(),
                CA::name()
            ),
        }
    }
}

#[test]
fn scalar_to_best() {
    eprintln!("Scalar ↔ {} ({})", Best::name(), std::env::consts::ARCH);
    cross_backend_roundtrip::<Scalar, Best>();
}

#[test]
fn best_to_scalar() {
    cross_backend_roundtrip::<Best, Scalar>();
}

#[test]
fn best_to_best() {
    cross_backend_roundtrip::<Best, Best>();
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[test]
fn avx2_8way_to_detect_and_back() {
    use wireguard_chacha_simd::{Avx2x8, Detect};
    cross_backend_roundtrip::<Avx2x8, Detect>();
    cross_backend_roundtrip::<Detect, Avx2x8>();
    cross_backend_roundtrip::<Avx2x8, Scalar>();
}

/// The run-time choice (what `Best` is in a build without AVX2 enabled):
/// whichever keystream it picks on this CPU, the wire is the same.
#[cfg(target_arch = "x86_64")]
#[test]
fn detect_to_scalar_and_back() {
    use wireguard_chacha_simd::Detect;
    cross_backend_roundtrip::<Detect, Scalar>();
    cross_backend_roundtrip::<Scalar, Detect>();
    cross_backend_roundtrip::<Detect, Best>();
}

/// The datagrams themselves are identical across backends: same keys,
/// same entropy, same inputs ⇒ byte-for-byte the same wire output.
#[test]
fn wire_output_is_byte_identical_across_backends() {
    fn transcript<C: ChaChaImpl>() -> Vec<Vec<u8>> {
        let mut rng = DeterministicRng::new(0xfeedface);
        let a_key = StaticSecret::generate(&mut rng).unwrap();
        let b_key = StaticSecret::generate(&mut rng).unwrap();
        let (a_pub, b_pub) = (a_key.public_key(), b_key.public_key());
        let (a_addr, b_addr) = (addr("192.0.2.1:51820"), addr("192.0.2.2:51820"));
        let mut a = Side::<C>::new(a_key, b_pub, a_addr, b_addr, &mut rng);
        let mut b = Side::<C>::new(b_key, a_pub, b_addr, a_addr, &mut rng);
        let mut wires = Vec::new();
        a.tunnel.request_handshake(Ticks::ZERO);
        let init = a.poll(&mut rng);
        let resp = b.deliver(a.addr, &init, &mut rng).0.unwrap();
        a.deliver(b.addr, &resp, &mut rng);
        wires.push(init);
        wires.push(resp);
        for len in [0usize, 1, 64, 65, 300, 1420] {
            let wire = a.seal(&vec![0x6bu8; len]);
            b.deliver(a.addr, &wire, &mut rng);
            wires.push(wire);
        }
        wires
    }
    assert_eq!(transcript::<Scalar>(), transcript::<Best>());
}

/// Bit-flip storm on `Best`-encrypted transport: every single-bit
/// corruption must be rejected by a scalar receiver (proves the SIMD
/// path produces correctly-tagged ciphertext, not just "decryptable by
/// itself" ciphertext), and a rejected datagram is never decrypted — by
/// either backend.
#[test]
fn simd_ciphertext_is_authenticated_by_scalar_and_vice_versa() {
    fn storm<CA: ChaChaImpl, CB: ChaChaImpl>() {
        let mut rng = DeterministicRng::new(0xfee1dead);
        let a_key = StaticSecret::generate(&mut rng).unwrap();
        let b_key = StaticSecret::generate(&mut rng).unwrap();
        let (a_pub, b_pub) = (a_key.public_key(), b_key.public_key());
        let (a_addr, b_addr) = (addr("192.0.2.1:51820"), addr("192.0.2.2:51820"));
        let mut a = Side::<CA>::new(a_key, b_pub, a_addr, b_addr, &mut rng);
        let mut b = Side::<CB>::new(b_key, a_pub, b_addr, a_addr, &mut rng);

        // Establish.
        a.tunnel.request_handshake(Ticks::ZERO);
        let init = a.poll(&mut rng);
        let resp = b.deliver(a.addr, &init, &mut rng).0.unwrap();
        a.deliver(b.addr, &resp, &mut rng);
        let ka = a.poll(&mut rng);
        b.deliver(a.addr, &ka, &mut rng);

        // Flip every bit; the receiver must reject every one and leave
        // the datagram exactly as it arrived.
        let wire = a.seal(&[0xab; 200]);
        for byte in 0..wire.len() {
            for bit in 0..8 {
                let mut bad = wire.clone();
                bad[byte] ^= 1 << bit;
                let after = b.deliver_forgery(a.addr, &bad, &mut rng);
                assert_eq!(after, bad, "byte {byte} bit {bit}: buffer modified");
            }
        }
        // Pristine still works.
        let (_, data, _) = b.deliver(a.addr, &wire, &mut rng);
        assert_eq!(&data.unwrap()[..200], &[0xab; 200]);
    }
    storm::<Best, Scalar>();
    storm::<Scalar, Best>();
}
