//! What do creating and dropping a `wireguard-embed` tunnel leave of its
//! keys on the stack?
//!
//! `Tunn::new` takes the static private key and the pre-shared key by
//! value (BoringTun's signature). The driver keeps them where they
//! arrive, hands them on by reference, builds the device and the tunnel
//! behind two boxes, overwrites the frames it built them in, and wipes
//! the two values it was given. So after `Tunn::new` has returned the
//! keys are on the heap, in the tunnel, and nowhere in the driver's dead
//! frames; and after the `Tunn` has been dropped they are nowhere.
//!
//! The two values `Tunn::new` is given lie in its caller's frame, and
//! wiping them is the driver's job. Here they come from the heap straight
//! into the call, so in an optimised build nothing else of the keys is in
//! that frame, and whatever is found anywhere counts. Without an
//! optimiser the compiler puts temporaries of its own there on the way
//! into the call; then only what lies beneath the caller's frame is
//! counted, and the rest reported. (That is the general rule for a value
//! given away by value: it is copied out of wherever the caller had it,
//! and a callee can wipe the copy it received, not the original.
//! `Tunn::with_keys` takes references, for a caller that wants to hold
//! the one copy and wipe it itself.)
//!
//! Exit status as for `stack_residue`: 0 nothing found in the driver's
//! frames, 1 something found, 2 the probe does not work.

use std::hint::black_box;
use std::net::SocketAddr;
use std::process::ExitCode;

use wireguard_embed::core::crypto::x25519;
use wireguard_embed::core::{PresharedKey, PublicKey, StaticSecret};
use wireguard_embed::{Tunn, TunnResult};
use wireguard_probes::{Scan, call_deep, frame_end, paint, reference};

#[inline(never)]
fn leaves_a_copy_behind(secret: &[u8; 32]) -> u8 {
    let copy = *secret;
    black_box(&copy);
    copy.iter().fold(0, |acc, b| acc ^ b)
}

type Made = Result<Tunn, wireguard_embed::core::Error>;
type NewFn = fn(
    StaticSecret,
    PublicKey,
    Option<[u8; 32]>,
    Option<u16>,
    Option<SocketAddr>,
    Option<std::sync::Arc<wireguard_embed::RateLimiter>>,
) -> Made;
type WithPoolFn = fn(
    StaticSecret,
    PublicKey,
    Option<[u8; 32]>,
    Option<u16>,
    Option<SocketAddr>,
    Option<std::sync::Arc<wireguard_embed::RateLimiter>>,
    std::sync::Arc<wireguard_embed::SlabPool>,
) -> Made;

/// A tunnel that has its keys makes an initiation.
fn works(tunn: &mut Tunn) -> bool {
    let mut out = vec![0u8; 256];
    matches!(
        tunn.format_handshake_initiation(&mut out),
        TunnResult::WriteToNetwork(datagram, _) if datagram.len() == 148
    )
}

fn main() -> ExitCode {
    let mut scan = Scan::new();

    let planted: [u8; 32] = core::array::from_fn(|i| 0xc0 ^ (i as u8).wrapping_mul(29));
    paint();
    call_deep(|| black_box(leaves_a_copy_behind(black_box(&planted))));
    scan.take();
    scan.needles.add("positive control", &planted);
    if scan.needles.found_in(&scan.snap).is_empty() {
        println!("RESULT: the probe does not work on this target; nothing can be concluded");
        return ExitCode::from(2);
    }
    println!(
        "positive control (a function that leaves a secret in its frame): found, as it must be"
    );
    scan.needles = wireguard_probes::Needles::default();

    // The keys, on the heap.
    let key: [u8; 32] = core::array::from_fn(|i| 0x31 ^ (i as u8).wrapping_mul(41));
    let psk: [u8; 32] = core::array::from_fn(|i| 0x9d ^ (i as u8).wrapping_mul(3));
    let peer_secret: [u8; 32] = core::array::from_fn(|i| 0x52 ^ (i as u8).wrapping_mul(19));
    let peer = PublicKey::from_bytes(x25519::x25519_base(&peer_secret));
    let endpoint: SocketAddr = "192.0.2.7:51820".parse().unwrap();

    scan.needles.add("the static private key", &key);
    scan.needles
        .add("the static private key, clamped", &reference::clamp(&key));
    scan.needles.add("the pre-shared key", &psk);
    let shared = x25519::x25519(&key, peer.as_bytes());
    scan.needles.add("DH(static, static)", &shared);
    scan.needles.add_words(
        "DH(static, static), as limbs",
        &reference::from_bytes(&shared),
    );

    // ---- by reference: nothing anywhere on the stack ------------------------
    let secret_ref: Box<StaticSecret> = Box::new(StaticSecret::from_bytes(key));
    let psk_ref: Box<PresharedKey> = Box::new(PresharedKey::from_bytes(psk));
    paint();
    let mut tunn: Box<Tunn> = call_deep(|| {
        Box::new(
            Tunn::with_keys(
                black_box(&secret_ref),
                peer,
                Some(black_box(&psk_ref)),
                Some(25),
                Some(endpoint),
                None,
                None,
            )
            .unwrap(),
        )
    });
    scan.take();
    scan.report("Tunn::with_keys (the keys by reference)");
    assert!(works(&mut tunn), "the tunnel made no initiation");
    paint();
    call_deep(|| drop(tunn));
    scan.take();
    scan.report("dropping that Tunn");

    // ---- by value: nothing in the driver's frames, nor where the keys arrived
    // Each constructor is the last thing its caller does — the tunnel is
    // put on the heap only after the snapshot — so that nothing the
    // caller does afterwards writes over the two arguments it passed, and
    // what the driver left in them is what is seen. And each is called
    // through a pointer the optimiser cannot see through: as the function
    // it is for any caller, not as whatever it becomes when it is folded
    // into this one (where an argument nothing wipes need not be copied
    // at all). The call is made two `call_deep`s down: the compiler folds
    // the closure into the inner one, whose frame — the two arguments in
    // it, wherever in it they were put — then lies below the outer one's
    // spacer, clear of what taking the snapshot writes.
    let new_fn: NewFn = black_box(Tunn::new);
    let with_pool_fn: WithPoolFn = black_box(Tunn::with_pool);
    let mut by_value = |with_pool: bool| -> Box<Tunn> {
        let secret: Box<StaticSecret> = Box::new(StaticSecret::from_bytes(key));
        let psk_box: Box<[u8; 32]> = Box::new(psk);
        let pool = wireguard_embed::SlabPool::for_wireguard();
        let mut caller = 0usize;
        paint();
        let made = if with_pool {
            call_deep(|| {
                call_deep(|| {
                    caller = frame_end();
                    with_pool_fn(
                        *secret,
                        peer,
                        Some(*black_box(&*psk_box)),
                        Some(25),
                        Some(endpoint),
                        None,
                        pool,
                    )
                })
            })
        } else {
            call_deep(|| {
                call_deep(|| {
                    caller = frame_end();
                    new_fn(
                        *secret,
                        peer,
                        Some(*black_box(&*psk_box)),
                        Some(25),
                        Some(endpoint),
                        None,
                    )
                })
            })
        };
        scan.take();
        let what = if with_pool {
            "Tunn::with_pool (the keys by value)"
        } else {
            "Tunn::new (the keys by value)"
        };
        if scan.unoptimised {
            scan.report_below(what, caller);
        } else {
            scan.report(what);
        }
        Box::new(made.unwrap())
    };
    drop(by_value(true));
    let mut tunn = by_value(false);

    paint();
    let initiated = call_deep(|| works(&mut tunn));
    scan.take();
    assert!(initiated, "the tunnel made no initiation");
    scan.report("Tunn::format_handshake_initiation");

    paint();
    call_deep(|| drop(tunn));
    scan.take();
    scan.report("dropping the Tunn");

    if scan.not_counted > 0 {
        println!(
            "NOTE: {} finding(s) of word forms and parts in this unoptimised build were not counted (see the top of probes/src/bin/stack_residue.rs)",
            scan.not_counted
        );
    }
    if scan.findings == 0 {
        println!("RESULT: the driver left none of its keys on the stack");
        ExitCode::SUCCESS
    } else {
        println!("RESULT: {} finding(s)", scan.findings);
        ExitCode::FAILURE
    }
}
