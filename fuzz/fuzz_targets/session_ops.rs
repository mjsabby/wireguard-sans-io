//! Structured, coverage-guided protocol fuzzing: the fuzzer drives two
//! real endpoints through an op interpreter (send / deliver / corrupt /
//! reorder / drop / advance time / poll / under-load / roam / reset), the
//! corpus-guided twin of `tests/protocol_fuzz.rs`.
//!
//! Invariants, checked after every op:
//!
//! * every payload delivered as data is byte-exact one that the peer
//!   actually encapsulated, and no datagram is accepted twice (the replay
//!   oracle: duplicates are part of what the fuzzer can do);
//! * both receive paths behave the same: each delivery goes through the
//!   single-call path or, at the fuzzer's choice, the two-step routing
//!   path (`Device::receive` → `identify` / peer id → tunnel);
//! * a dropped datagram leaves its buffer and the output buffer untouched
//!   (asserted inside the shared harness on every delivery);
//! * each tunnel's timers equal the reference model's
//!   (`tests/common/timer_model.rs`) — the timing oracle;
//! * a tunnel that reports `Idle` has no wake-up due;
//! * no call reports a local fault.
#![no_main]

#[path = "../../tests/common/mod.rs"]
mod common;

use std::collections::VecDeque;
use std::net::SocketAddr;

use arbitrary::Arbitrary;
use common::{Endpoint, a_addr, b_addr, fingerprint};
use libfuzzer_sys::fuzz_target;
use wireguard_sans_io::EntropySource;
use wireguard_sans_io::testing::DeterministicRng;

#[derive(Arbitrary, Debug)]
enum Op {
    SendA {
        len: u16,
    },
    SendB {
        len: u16,
    },
    DeliverToA {
        pick: u8,
        corrupt_pos: u16,
        corrupt_val: u8,
        duplicate: bool,
        under_load: bool,
        roam: u8,
        routed: bool,
    },
    DeliverToB {
        pick: u8,
        corrupt_pos: u16,
        corrupt_val: u8,
        duplicate: bool,
        under_load: bool,
        roam: u8,
        routed: bool,
    },
    DropToA {
        pick: u8,
    },
    DropToB {
        pick: u8,
    },
    AdvanceMillis(u16),
    AdvanceSeconds(u8),
    PollA,
    PollB,
    InitiateA,
    InitiateB,
    ResetA,
    ResetB,
}

#[derive(Arbitrary, Debug)]
struct Scenario {
    keepalive_a: Option<u8>,
    keepalive_b: Option<u8>,
    ops: Vec<Op>,
}

fuzz_target!(|scenario: Scenario| {
    if scenario.ops.len() > 256 {
        return;
    }
    let ka = |k: Option<u8>| k.filter(|s| *s != 0).map(u16::from);
    let (ka_a, ka_b) = (ka(scenario.keepalive_a), ka(scenario.keepalive_b));
    let mut keyrng = DeterministicRng::new(0x6b6579);
    let (a_key, a_pub) = common::keypair(&mut keyrng);
    let (b_key, b_pub) = common::keypair(&mut keyrng);
    let mut a = Endpoint::new(
        "A",
        common::side(
            a_key,
            b_pub,
            a_addr(),
            Some(b_addr()),
            None,
            ka_a,
            &mut keyrng,
        ),
        ka_a,
        3,
    );
    let mut b = Endpoint::new(
        "B",
        common::side(
            b_key,
            a_pub,
            b_addr(),
            Some(a_addr()),
            None,
            ka_b,
            &mut keyrng,
        ),
        ka_b,
        5,
    );

    let mut to_a: VecDeque<Vec<u8>> = VecDeque::new();
    let mut to_b: VecDeque<Vec<u8>> = VecDeque::new();
    let mut mono: u64 = 0;

    for op in scenario.ops {
        match op {
            Op::SendA { len } | Op::SendB { len } => {
                let from_a = matches!(op, Op::SendA { .. });
                let len = usize::from(len) % 1024;
                let mut payload = vec![0u8; len];
                let (ep, queue) = if from_a {
                    (&mut a, &mut to_b)
                } else {
                    (&mut b, &mut to_a)
                };
                ep.rng.fill(&mut payload).unwrap();
                if let Some(w) = ep.send(mono, &payload) {
                    queue.push_back(w);
                }
            }
            Op::DeliverToA {
                pick,
                corrupt_pos,
                corrupt_val,
                duplicate,
                under_load,
                roam,
                routed,
            }
            | Op::DeliverToB {
                pick,
                corrupt_pos,
                corrupt_val,
                duplicate,
                under_load,
                roam,
                routed,
            } => {
                let to_a_side = matches!(op, Op::DeliverToA { .. });
                let queue = if to_a_side { &mut to_a } else { &mut to_b };
                if queue.is_empty() {
                    continue;
                }
                let idx = usize::from(pick) % queue.len();
                let mut datagram = queue.remove(idx).unwrap();
                if duplicate {
                    queue.push_back(datagram.clone());
                }
                if corrupt_val != 0 && !datagram.is_empty() {
                    let pos = usize::from(corrupt_pos) % datagram.len();
                    datagram[pos] ^= corrupt_val;
                }
                let (ep, peer, reply_queue, home) = if to_a_side {
                    (&mut a, &b, &mut to_b, b_addr())
                } else {
                    (&mut b, &a, &mut to_a, a_addr())
                };
                // Mostly from the peer's real address, sometimes from
                // another one (NAT rebinding, or an off-path replay).
                let src: SocketAddr = if roam < 224 {
                    home
                } else {
                    SocketAddr::new(home.ip(), 40_000 + u16::from(roam))
                };
                let (reply, data) = ep.deliver(mono, src, under_load, &datagram, routed);
                if let Some(d) = data {
                    assert!(
                        peer.sent.contains(&fingerprint(&d)),
                        "delivered a never-sent payload"
                    );
                }
                if let Some(w) = reply {
                    reply_queue.push_back(w);
                }
            }
            Op::DropToA { pick } => {
                if !to_a.is_empty() {
                    let idx = usize::from(pick) % to_a.len();
                    to_a.remove(idx);
                }
            }
            Op::DropToB { pick } => {
                if !to_b.is_empty() {
                    let idx = usize::from(pick) % to_b.len();
                    to_b.remove(idx);
                }
            }
            Op::AdvanceMillis(ms) => mono += u64::from(ms) * 1_000_000,
            Op::AdvanceSeconds(s) => mono += u64::from(s) * 1_000_000_000,
            Op::PollA => to_b.extend(a.poll_to_idle(mono)),
            Op::PollB => to_a.extend(b.poll_to_idle(mono)),
            Op::InitiateA | Op::InitiateB => {
                let ep = if matches!(op, Op::InitiateA) {
                    &mut a
                } else {
                    &mut b
                };
                ep.side
                    .tunnel
                    .request_handshake(wireguard_sans_io::Ticks::from_nanos(mono));
                ep.check(mono, "request_handshake");
            }
            Op::ResetA | Op::ResetB => {
                let (ep, peer) = if matches!(op, Op::ResetA) {
                    (&mut a, &mut b)
                } else {
                    (&mut b, &mut a)
                };
                ep.side.tunnel.reset();
                ep.model.reset();
                ep.check(mono, "reset");
                // Payloads the peer encrypted for the wiped sessions can
                // never be delivered now; nothing to assert about them.
                let _ = peer;
            }
        }
        while to_a.len() > 32 {
            to_a.pop_front();
        }
        while to_b.len() > 32 {
            to_b.pop_front();
        }
    }
});
