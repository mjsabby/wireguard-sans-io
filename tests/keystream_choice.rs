//! Which keystream an AEAD takes when the provider is `InTree<C>`.
//!
//! `C` is a keystream backend — in practice one of the SIMD ones, which
//! are the only `unsafe` code there is — and the rule is in
//! `src/crypto/provider.rs`:
//!
//! * the handshake's AEADs are the scalar keystream's whatever `C` is:
//!   no handshake secret goes through a backend;
//! * transport data of more than 64 bytes is `C`'s;
//! * transport data of up to 64 bytes is `C`'s if `C` asks for it
//!   ([`ChaChaImpl::SMALL_PACKETS`]: a backend with a kernel for a block
//!   or two) and the scalar keystream's if not (a backend that only has
//!   strides is slower at it).
//!
//! The two backends here are the scalar keystream, counting how often
//! they are asked.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use core::sync::atomic::{AtomicUsize, Ordering};

use common::{Opts, Polled, Rx, new_pair_opts_with};
use wireguard_sans_io::{ChaChaImpl, InTree, Scalar, SendReason};

static PAIRS: AtomicUsize = AtomicUsize::new(0);
static STRIDES: AtomicUsize = AtomicUsize::new(0);

macro_rules! counted_backend {
    ($name:ident, $calls:ident, $small:expr) => {
        struct $name;
        impl ChaChaImpl for $name {
            const SMALL_PACKETS: bool = $small;

            fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
                $calls.fetch_add(1, Ordering::Relaxed);
                Scalar::apply_keystream(key, nonce, counter, buf);
            }
            fn seal_keystream(
                key: &[u8; 32],
                nonce: &[u8; 12],
                buf: &mut [u8],
                otk: &mut [u8; 32],
            ) {
                $calls.fetch_add(1, Ordering::Relaxed);
                Scalar::seal_keystream(key, nonce, buf, otk);
            }
            fn open_keystream<F: FnOnce(&[u8; 32], &[u8]) -> bool>(
                key: &[u8; 32],
                nonce: &[u8; 12],
                buf: &mut [u8],
                verify: F,
            ) -> bool {
                $calls.fetch_add(1, Ordering::Relaxed);
                Scalar::open_keystream(key, nonce, buf, verify)
            }
            fn name() -> &'static str {
                stringify!($name)
            }
        }
    };
}
counted_backend!(Pairs, PAIRS, true);
counted_backend!(Strides, STRIDES, false);

/// A handshake, the keepalive that confirms it, and packets on both
/// sides of the 64-byte line — and for each of them whether the backend
/// was asked. (One test per backend: each has a counter of its own.)
fn the_backend_is_asked_for<C: ChaChaImpl>(calls: &AtomicUsize, small: bool) {
    let asked = || calls.load(Ordering::Relaxed);
    let mut pair = new_pair_opts_with::<InTree<C>>(0x5ca1a2, Opts::default());

    // The handshake: the static key and the timestamp sealed and opened,
    // and the empty AEAD of the response sealed and opened — six AEADs
    // under handshake keys, with the transcript as associated data.
    let initiation = pair.a_initiates();
    let response = match pair.deliver_to_b(&initiation).rx {
        Rx::Response(wire) => wire,
        other => panic!("expected a response, got {other:?}"),
    };
    assert_eq!(pair.deliver_to_a(&response).rx, Rx::HandshakeComplete);
    assert_eq!(asked(), 0, "a handshake AEAD went through the backend");

    // The keepalive that confirms the session: transport data, none of it.
    let now = pair.clock.now();
    let keepalive = match pair.a.poll(now, &mut pair.rng) {
        Polled::Transmit(wire, SendReason::Keepalive, _) => wire,
        other => panic!("expected a keepalive, got {other:?}"),
    };
    assert_eq!(asked(), usize::from(small), "sealing a keepalive");
    assert_eq!(pair.deliver_to_b(&keepalive).rx, Rx::Keepalive);
    assert_eq!(asked(), 2 * usize::from(small), "opening a keepalive");

    // Packets: up to 64 bytes are small; 65 — 80 on the wire, padded —
    // and more are the backend's whoever it is.
    for (len, backend) in [
        (1usize, small),
        (16, small),
        (49, small),
        (64, small),
        (65, true),
        (200, true),
        (1420, true),
    ] {
        let before = asked();
        let payload = vec![0xabu8; len];
        let wire = pair.seal_from_a(&payload);
        assert_eq!(
            asked() - before,
            usize::from(backend),
            "sealing {len} bytes"
        );
        match pair.deliver_to_b(&wire).rx {
            Rx::Data(plain) => assert_eq!(plain[..len], payload[..]),
            other => panic!("{len} bytes: {other:?}"),
        }
        assert_eq!(
            asked() - before,
            2 * usize::from(backend),
            "opening {len} bytes"
        );
        // A forgery of the same size is turned away by the same
        // keystream that would have opened it.
        let mut forged = pair.seal_from_a(&payload);
        let before = asked();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(matches!(pair.deliver_to_b(&forged).rx, Rx::Dropped(_)));
        assert_eq!(
            asked() - before,
            usize::from(backend),
            "refusing {len} bytes"
        );
    }
}

#[test]
fn a_backend_with_a_kernel_for_small_packets_gets_them_and_no_handshake() {
    the_backend_is_asked_for::<Pairs>(&PAIRS, true);
}

#[test]
fn a_backend_without_one_gets_what_is_above_64_bytes_and_no_handshake() {
    the_backend_is_asked_for::<Strides>(&STRIDES, false);
}

/// The default is not to ask: a backend written before there was the
/// question behaves as it always did.
#[test]
fn small_packets_are_not_a_backends_unless_it_says_so() {
    struct Old;
    impl ChaChaImpl for Old {
        fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
            Scalar::apply_keystream(key, nonce, counter, buf);
        }
        fn name() -> &'static str {
            "old"
        }
    }
    const { assert!(!Old::SMALL_PACKETS) };
    const { assert!(!Scalar::SMALL_PACKETS) };
}
