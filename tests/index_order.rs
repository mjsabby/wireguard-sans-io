//! Session indices on the wire: how they recur, and whether the next one
//! can be predicted from what has been seen.
//!
//! What `src/index.rs` says under "What an observer sees": a tunnel has
//! 4096 indices and goes through all of them, once each, in rounds; a
//! recording of them tells an observer which values they are, but not
//! which one comes next — the order of a round is a keyed permutation
//! under a key drawn for that round.
//!
//! That was once not so. The order of a round used to be
//! `slot = step × n + offset (mod 4096)`; two such orders are related by
//! an affine map of the position, so with one round on record and two
//! consecutive indices of the current round, every later index followed
//! (`A[2·pos(B[m]) − pos(B[m−1]) mod 4096]`). The predictor below is that
//! attack. It is kept, with a control that shows what it finds when there
//! is something to find, so that an order with such a relation between
//! rounds does not come back.
//!
//! Everything here goes through the public API only: the indices are read
//! off the wire (bytes 4..8 of the handshake messages the tunnel sends).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

mod common;
use std::collections::HashMap;

use common::{Rx, S, new_pair};
use wireguard_sans_io::Ticks;

const ROUND: usize = 4096;

fn sender_index(datagram: &[u8]) -> u32 {
    u32::from_le_bytes(datagram[4..8].try_into().unwrap())
}

/// What an eavesdropper does: with one complete round on record (in the
/// order it was sent), predict each index from the two before it.
/// Returns (predictions made, predictions that were right).
fn predict_from_recording(recorded_round: &[u32], later: &[u32]) -> (usize, usize) {
    assert_eq!(recorded_round.len(), ROUND);
    let pos: HashMap<u32, usize> = recorded_round
        .iter()
        .enumerate()
        .map(|(n, &index)| (index, n))
        .collect();
    assert_eq!(pos.len(), ROUND, "a round uses every index once");
    let (mut made, mut right) = (0, 0);
    for w in later.windows(3) {
        let (Some(&p0), Some(&p1)) = (pos.get(&w[0]), pos.get(&w[1])) else {
            continue;
        };
        // The positions form an arithmetic progression modulo 4096.
        let next = (2 * p1 + ROUND - p0) % ROUND;
        made += 1;
        right += usize::from(recorded_round[next] == w[2]);
    }
    (made, right)
}

/// A tunnel that keeps retransmitting to a peer that does not answer (the
/// README's "under six hours" case): the indices of its initiations.
fn retransmitting_tunnel_indices(seed: u64, count: usize) -> Vec<u32> {
    let mut p = new_pair(seed);
    let mut out = Vec::with_capacity(count);
    for i in 0..count as u64 {
        // Every six seconds the retransmission is due; asking for a
        // handshake keeps the attempt alive.
        let now = Ticks::from_nanos(i * 6 * S);
        let init = p.a.initiate(now, &mut p.rng);
        out.push(sender_index(&init));
    }
    out
}

/// The indices a *responder* puts into its handshake responses, for a peer
/// that sends an initiation every 20 ms (the README's "82 seconds" case).
fn responding_tunnel_indices(seed: u64, count: usize) -> Vec<u32> {
    let mut p = new_pair(seed);
    let mut out = Vec::with_capacity(count);
    for i in 0..count as u64 {
        // A's initiations are paced by Rekey-Timeout, so drive A's clock
        // six seconds a step; B (the device under observation) sees them
        // 20 ms apart, the fastest it accepts them.
        let a_now = Ticks::from_nanos(i * 6 * S);
        let b_now = Ticks::from_nanos(i * 20_000_000);
        let init = p.a.initiate(a_now, &mut p.rng);
        let info = p.b.recv_from(b_now, p.a.addr, false, &init, &mut p.rng);
        match info.rx {
            Rx::Response(resp) => out.push(sender_index(&resp)),
            other => panic!("initiation {i}: {other:?}"),
        }
    }
    out
}

/// With one round on record, the two indices before it do not say which
/// index comes next. (Against the old order this predicted 8188 of 8190.)
#[test]
fn a_recording_of_one_round_does_not_say_which_index_comes_next() {
    let mut results = Vec::new();
    for (what, indices) in [
        (
            "initiator that keeps retransmitting",
            retransmitting_tunnel_indices(0x51, 3 * ROUND),
        ),
        (
            "responder answering initiations",
            responding_tunnel_indices(0x52, 3 * ROUND),
        ),
    ] {
        // The eavesdropper recorded the first 4096 handshake messages…
        let (recorded, later) = indices.split_at(ROUND);
        // …and now predicts, for each later index, from the two before it.
        let (made, right) = predict_from_recording(recorded, later);
        eprintln!(
            "{what}: {right} of {made} later indices predicted exactly \
             ({:.2} %); chance would be {:.2} of {made}",
            100.0 * right as f64 / made as f64,
            made as f64 / ROUND as f64
        );
        results.push((what, made, right));
    }
    // If the order of each round really were "drawn afresh" in a way that
    // a recording says nothing about, a guess would be right once in 4096
    // tries: about two of these 8190.
    for (what, made, right) in results {
        assert!(
            right < 40,
            "{what}: the recording predicted {right} of {made} later indices"
        );
    }
}

/// Control for the predictor, both ways. Against rounds that are related
/// the way the old ones were (the same 4096 values in the order
/// `step × n + offset`) it predicts every index; against rounds in an
/// unrelated order (a seeded shuffle) it predicts nothing. So the test
/// above can fail, and can pass.
#[test]
fn control_the_predictor_finds_an_affine_order_and_nothing_in_a_shuffle() {
    let indices = retransmitting_tunnel_indices(0x51, ROUND);
    let affine: Vec<u32> = (0..2 * ROUND)
        .map(|m| {
            let (step, offset) = if m < ROUND { (1237, 3001) } else { (2999, 77) };
            indices[(step * (m % ROUND) + offset) % ROUND]
        })
        .collect();
    let (made, right) = predict_from_recording(&indices, &affine);
    assert!(made > 8000);
    // All but the two triples that straddle the change of round.
    assert!(right >= made - 2, "{right} of {made}");
    shuffled_rounds_control();
}

fn shuffled_rounds_control() {
    let indices = retransmitting_tunnel_indices(0x51, ROUND);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut later = Vec::new();
    for _ in 0..2 {
        let mut round = indices.clone();
        for i in (1..round.len()).rev() {
            round.swap(i, (next() % (i as u64 + 1)) as usize);
        }
        later.extend(round);
    }
    let (made, right) = predict_from_recording(&indices, &later);
    eprintln!("shuffled rounds: {right} of {made} predicted");
    assert!(made > 8000);
    assert!(right < 40, "{right} of {made}");
}

/// What is true (and documented): the indices of one tunnel are the same
/// 4096 values in every round, each exactly once.
#[test]
fn the_rounds_are_permutations_of_the_same_4096_values() {
    let indices = retransmitting_tunnel_indices(0x53, 3 * ROUND);
    let mut first: Vec<u32> = indices[..ROUND].to_vec();
    first.sort_unstable();
    first.dedup();
    assert_eq!(first.len(), ROUND);
    for round in indices.chunks(ROUND).skip(1) {
        let mut sorted = round.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        // A live index is skipped (and its slot spent), so a round as
        // seen on the wire can be one short at its boundary.
        assert!(sorted.len() >= ROUND - 2);
        assert!(sorted.iter().all(|i| first.binary_search(i).is_ok()));
    }
}

/// What a prediction would buy. A forged handshake response costs the
/// receiving tunnel two X25519 if — and only if — it names the index of
/// the initiation in flight (tests/cost.rs,
/// `a_response_costs_diffie_hellman_only_for_the_initiation_in_flight`);
/// the documentation's position is that this takes someone "on the path,
/// reading live indices off the wire".
///
/// Here the sender is NOT on the path any more. It holds a recording of
/// one earlier round, saw two handshake messages of the current round,
/// and from then on sends blind — one forged response per initiation of
/// the victim, to the index the old order would have made it compute in
/// advance. (Then, every one of them hit.) It does no better than a
/// sender that only knows the 4096 values, which hits one time in 4096.
#[test]
fn blind_forged_responses_find_the_handshake_in_flight_by_chance_only() {
    use common::counting::spent;
    use common::new_counting_pair;
    use wireguard_sans_io::consts::LABEL_MAC1;
    use wireguard_sans_io::crypto::blake2s;
    use wireguard_sans_io::{DropReason, EntropySource};

    let mut p = new_counting_pair(0x54);
    let victim_public = p.a.device.public_key();
    let mac1_key = blake2s::hash(&[LABEL_MAC1, victim_public.as_bytes()]);
    let mut attacker_rng = wireguard_sans_io::testing::DeterministicRng::new(0xa77ac);
    let mut forged_response = |receiver_index: u32| -> Vec<u8> {
        let mut msg = vec![0u8; 92];
        attacker_rng.fill(&mut msg[..60]).unwrap();
        msg[..4].copy_from_slice(&[2, 0, 0, 0]);
        msg[8..12].copy_from_slice(&receiver_index.to_le_bytes());
        let mac1 = blake2s::mac(&mac1_key, &[&msg[..60]]);
        msg[60..76].copy_from_slice(&mac1);
        msg
    };

    // Phase 1 (on the path): one round recorded, then two more messages.
    let step = std::cell::Cell::new(0u64);
    let next_initiation = |p: &mut common::Pair<common::counting::Counting>| -> (u32, Ticks) {
        let now = Ticks::from_nanos(step.get() * 6 * S);
        step.set(step.get() + 1);
        (sender_index(&p.a.initiate(now, &mut p.rng)), now)
    };
    let recorded: Vec<u32> = (0..ROUND).map(|_| next_initiation(&mut p).0).collect();
    let pos: HashMap<u32, usize> = recorded.iter().enumerate().map(|(n, &i)| (i, n)).collect();
    let seen = [next_initiation(&mut p).0, next_initiation(&mut p).0];
    let (p0, p1) = (pos[&seen[0]], pos[&seen[1]]);
    let stride = (p1 + ROUND - p0) % ROUND;

    // Phase 2 (off the path): for each of the victim's next 500
    // initiations, one forged response to the index computed in advance,
    // and — for comparison — one to an index picked among the 4096.
    let (mut informed_hits, mut blind_hits, mut dh) = (0u32, 0u32, 0u32);
    let mut pick = 0x1234_5678u64;
    for k in 1..=500usize {
        let (actual, now) = next_initiation(&mut p);
        let predicted = recorded[(p1 + k * stride) % ROUND];
        let _ = spent();
        let rx =
            p.a.recv_from(
                now,
                common::x_addr(),
                false,
                &forged_response(predicted),
                &mut p.rng,
            )
            .rx;
        let cost = spent();
        if rx == Rx::Dropped(DropReason::AuthFailure) {
            assert_eq!(predicted, actual);
            assert_eq!(cost.x25519, 2, "{cost:?}");
            informed_hits += 1;
            dh += cost.x25519;
        }
        pick = pick.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let guess = recorded[(pick >> 33) as usize % ROUND];
        let _ = spent();
        let rx =
            p.a.recv_from(
                now,
                common::x_addr(),
                false,
                &forged_response(guess),
                &mut p.rng,
            )
            .rx;
        if rx == Rx::Dropped(DropReason::AuthFailure) {
            blind_hits += 1;
        } else {
            assert_eq!(rx, Rx::Dropped(DropReason::NoPendingHandshake));
            assert_eq!(spent().x25519, 0);
        }
    }
    eprintln!(
        "500 initiations of the victim, one forged response each, sent blind:\n  \
         with the recording + two observations: {informed_hits} hit ({dh} X25519 spent by the victim)\n  \
         knowing only the 4096 values:          {blind_hits} hit"
    );
    // The documented position: without being on the path, a forged
    // response finds the handshake in flight by chance only.
    assert!(
        informed_hits < 5,
        "{informed_hits} of 500 blind forged responses hit the handshake in flight"
    );
}
