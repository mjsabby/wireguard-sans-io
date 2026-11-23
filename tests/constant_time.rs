//! Empirical (dudect-style) timing smoke tests for the constant-time
//! claims: Welch's t-test between two input classes that a variable-time
//! implementation would distinguish trivially.
//!
//! These are statistical wall-clock measurements: inherently noisy and
//! environment-dependent, so they are `#[ignore]`d by default and run
//! explicitly with
//! `cargo test --release --test constant_time -- --ignored --nocapture`.
//! They are a tripwire, not a proof: a |t| in the hundreds (an early-exit
//! memcmp shows ~1000+) means a real problem, single digits are noise.
//!
//! Each test first shows that it *can* see a leak — it measures something
//! that leaks on purpose — and refuses to conclude anything if it cannot
//! (a machine that is too busy, a build that is not optimised). A timing
//! test without that step passes just as happily when it is blind.
//!
//! The check that does not depend on a quiet machine is
//! `scripts/check_constant_flow.sh`: it counts the basic blocks each
//! secret-handling function executes, under an emulator, for different
//! secrets — exact, repeatable, and what CI runs. It sees control flow
//! only; these tests see time, whatever its cause, when they see
//! anything.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Instant;

use wireguard_sans_io::crypto::ct;
use wireguard_sans_io::crypto::x25519;

/// Welch's t statistic between two sample sets of nanosecond timings.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let var = |v: &[f64], m: f64| {
        v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() as f64 - 1.0)
    };
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    (ma - mb) / ((va / a.len() as f64) + (vb / b.len() as f64)).sqrt()
}

/// [`welch_t`] after dropping the slowest tenth of each class: timings
/// have a long right tail (interrupts, other processes) that says nothing
/// about the code being measured and only blunts the statistic.
fn trimmed_welch_t(a: &[f64], b: &[f64]) -> f64 {
    let trim = |v: &[f64]| {
        let mut v = v.to_vec();
        v.sort_by(f64::total_cmp);
        v.truncate(v.len() * 9 / 10);
        v
    };
    welch_t(&trim(a), &trim(b))
}

/// Time `f(0)` and `f(1)` — two classes of input — interleaved, and
/// alternating which goes first (the dudect discipline): running the
/// classes back-to-back lets CPU frequency drift show up as a bogus
/// difference; so can always measuring one of them second.
fn two_class_samples(mut f: impl FnMut(usize), rounds: usize, calls: usize) -> [Vec<f64>; 2] {
    let mut samples = [Vec::with_capacity(rounds), Vec::with_capacity(rounds)];
    for i in 0..rounds + 50 {
        let order = if i % 2 == 0 { [0, 1] } else { [1, 0] };
        for class in order {
            let t0 = Instant::now();
            for _ in 0..calls {
                f(class);
            }
            let dt = t0.elapsed().as_nanos() as f64;
            if i >= 50 {
                samples[class].push(dt);
            }
        }
    }
    samples
}

/// Time a comparison of two 4 KiB buffers that differ in the first byte
/// (first result) or in the last byte (second result).
///
/// Both classes are measured in the **same two buffers**: only the
/// position of the differing byte changes between samples. Comparing one
/// buffer against two *different* others also measures where the allocator
/// happened to put them — on some machines that address relationship alone
/// is worth 20 % of the run time, far more than any signal this test is
/// after, in a function that reads every byte regardless.
fn position_samples(compare: impl Fn(&[u8], &[u8]) -> bool, rounds: usize) -> (Vec<f64>, Vec<f64>) {
    position_samples_of::<4096>(compare, rounds, 32)
}

/// [`position_samples`] for buffers of `N` bytes, `calls` comparisons per
/// sample.
fn position_samples_of<const N: usize>(
    compare: impl Fn(&[u8], &[u8]) -> bool,
    rounds: usize,
    calls: usize,
) -> (Vec<f64>, Vec<f64>) {
    let base = vec![0x5au8; N];
    let mut other = base.clone();
    let mut first = Vec::with_capacity(rounds);
    let mut last = Vec::with_capacity(rounds);
    for i in 0..rounds + 100 {
        // Interleaved, and alternating which class goes first, so neither
        // frequency drift nor the order within a round can show up as a
        // difference.
        let order = if i % 2 == 0 { [0, N - 1] } else { [N - 1, 0] };
        for differ_at in order {
            other[0] = base[0];
            other[N - 1] = base[N - 1];
            other[differ_at] ^= 1;
            let t0 = Instant::now();
            for _ in 0..calls {
                std::hint::black_box(compare(
                    std::hint::black_box(&base),
                    std::hint::black_box(&other),
                ));
            }
            let dt = t0.elapsed().as_nanos() as f64;
            if i >= 100 {
                if differ_at == 0 {
                    first.push(dt);
                } else {
                    last.push(dt);
                }
            }
        }
    }
    (first, last)
}

#[test]
#[ignore = "statistical timing test; run explicitly in --release on a quiet machine"]
#[allow(clippy::print_stdout)] // the two statistics, for whoever runs the tripwire
fn ct_eq_timing_independent_of_difference_position() {
    // Class A: differs in the first byte. Class B: differs in the last.
    // An early-exit comparison times these very differently. 4 KiB
    // buffers give the early exit thousands of bytes of head start.
    let (a, b) = position_samples(ct::ct_eq, 4000);
    let t = welch_t(&a, &b);

    // Sanity: the harness CAN detect a leaky comparison — the standard
    // slice equality (libc memcmp, early exit).
    let (a, b) = position_samples(|x, y| x == y, 4000);
    let t_leaky = welch_t(&a, &b);
    println!(
        "ct_eq |t| = {:.1}; early-exit memcmp |t| = {:.1}",
        t.abs(),
        t_leaky.abs()
    );
    assert!(
        t_leaky.abs() > 10.0,
        "harness failed to flag memcmp (|t| = {:.1}); \
         environment too noisy for this test to mean anything",
        t_leaky.abs()
    );
    assert!(
        t.abs() < 30.0,
        "ct_eq timing differs by position: |t| = {:.1} (leaky memcmp scored {:.1})",
        t.abs(),
        t_leaky.abs()
    );
}

/// A comparison that stops at the first difference, one byte at a time
/// (what `==` on two short arrays is *not*: the compiler compares those
/// a word at a time, all of them).
fn early_exit(a: &[u8], b: &[u8]) -> bool {
    for (x, y) in a.iter().zip(b) {
        if std::hint::black_box(*x) != *y {
            return false;
        }
    }
    true
}

/// The same at the lengths the protocol compares: 16 bytes (`mac1`,
/// `mac2`, an AEAD tag) and 32. A comparison that leaked only at these
/// lengths would pass the 4 KiB test above.
#[test]
#[ignore = "statistical timing test; run explicitly in --release on a quiet machine"]
#[allow(clippy::print_stdout)] // the statistics, for whoever runs the tripwire
fn ct_eq_timing_independent_of_difference_position_at_protocol_lengths() {
    fn at<const N: usize>() {
        let (a, b) = position_samples_of::<N>(ct::ct_eq, 4000, 512);
        let t = trimmed_welch_t(&a, &b);
        let (a, b) = position_samples_of::<N>(early_exit, 4000, 512);
        let t_leaky = trimmed_welch_t(&a, &b);
        println!(
            "{N} bytes: ct_eq |t| = {:.1}; early-exit loop |t| = {:.1}",
            t.abs(),
            t_leaky.abs()
        );
        assert!(
            t_leaky.abs() > 10.0,
            "harness failed to flag an early exit over {N} bytes (|t| = {:.1}); \
             environment too noisy for this test to mean anything",
            t_leaky.abs()
        );
        assert!(
            t.abs() < t_leaky.abs() / 2.0 && t.abs() < 30.0,
            "ct_eq timing over {N} bytes differs by position: |t| = {:.1} (an early exit \
             scored {:.1})",
            t.abs(),
            t_leaky.abs()
        );
    }
    at::<16>();
    at::<32>();
}

/// A little work whose amount is known: `n` rounds of a multiply-add
/// chain the optimiser cannot shorten.
fn spin(n: u64) -> u64 {
    let mut acc = 1u64;
    for _ in 0..n {
        acc = std::hint::black_box(acc)
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
    }
    acc
}

/// How many times the bit changes along the (clamped) scalar, top to
/// bottom — the number of ladder steps at which the Montgomery ladder's
/// conditional swap actually swaps.
fn transitions(scalar: &[u8; 32]) -> u32 {
    let k = x25519::clamp_scalar(*scalar);
    let bit = |i: usize| (k[i >> 3] >> (i & 7)) & 1;
    let mut previous = 0;
    let mut count = 0;
    for i in (0..255).rev() {
        if bit(i) != previous {
            count += 1;
        }
        previous = bit(i);
    }
    count
}

/// X25519 must take the same time whatever the scalar. Two things about
/// a scalar could show in the timing of a careless ladder, and the two
/// pairs of classes below differ in one each:
///
/// * its **weight** — the number of one bits — if the work of a ladder
///   step depended on the bit;
/// * its number of bit **transitions**, if the conditional swap (which
///   swaps exactly when the bit changes) took longer when it swaps. A
///   scalar of all ones and one of all zeros have the same two
///   transitions, so a test that only compares those two is blind to a
///   leaky swap; `0x55…` has some 250.
///
/// The control: the same scalar in both classes, with one class given 1 %
/// more work. If that does not show, nothing can be concluded and the
/// test fails for that reason; if it shows, the real comparisons must
/// score well below it.
#[test]
#[ignore = "statistical timing test; run explicitly in --release on a quiet machine"]
#[allow(clippy::print_stdout)] // the statistics, for whoever runs the tripwire
fn x25519_timing_independent_of_the_scalar() {
    const ROUNDS: usize = 2500;
    const CALLS: usize = 8;
    let u = x25519::BASEPOINT;
    let zeros = [0u8; 32];
    let ones = [0xffu8; 32];
    let alternating = [0x55u8; 32];
    assert!(
        transitions(&ones) <= 2 && transitions(&zeros) <= 2,
        "the weight classes must not differ in transitions"
    );
    assert!(transitions(&alternating) > 200);

    let run = |scalars: [&[u8; 32]; 2], extra: [u64; 2]| {
        let [a, b] = two_class_samples(
            |class| {
                std::hint::black_box(x25519::x25519(
                    std::hint::black_box(scalars[class]),
                    std::hint::black_box(&u),
                ));
                std::hint::black_box(spin(std::hint::black_box(extra[class])));
            },
            ROUNDS,
            CALLS,
        );
        trimmed_welch_t(&a, &b)
    };

    // Calibrate the control: how many `spin` rounds are 1 % of one X25519?
    let time = |f: &mut dyn FnMut(), n: u32| {
        let t0 = Instant::now();
        for _ in 0..n {
            f();
        }
        t0.elapsed().as_nanos() as f64 / f64::from(n)
    };
    let per_x25519 = time(
        &mut || {
            std::hint::black_box(x25519::x25519(std::hint::black_box(&ones), &u));
        },
        400,
    );
    let per_spin_round = time(
        &mut || {
            std::hint::black_box(spin(std::hint::black_box(10_000)));
        },
        400,
    ) / 10_000.0;
    let one_percent = ((per_x25519 / 100.0) / per_spin_round).round().max(1.0) as u64;

    let t_control = run([&ones, &ones], [0, one_percent]);
    let t_weight = run([&zeros, &ones], [0, 0]);
    let t_transitions = run([&ones, &alternating], [0, 0]);
    println!(
        "x25519: {per_x25519:.0} ns; control (+1 % = {one_percent} spin rounds) |t| = {:.1}; \
         weight |t| = {:.1}; transitions |t| = {:.1}",
        t_control.abs(),
        t_weight.abs(),
        t_transitions.abs()
    );
    assert!(
        t_control.abs() > 10.0,
        "a planted 1 % timing difference was not detected (|t| = {:.1}): this machine is too \
         noisy, or the build is not optimised, for the test to mean anything",
        t_control.abs()
    );
    let limit = t_control.abs() / 2.0;
    assert!(
        t_weight.abs() < limit,
        "x25519 timing depends on the scalar's weight: |t| = {:.1}, where a 1 % difference \
         scores {:.1}",
        t_weight.abs(),
        t_control.abs()
    );
    assert!(
        t_transitions.abs() < limit,
        "x25519 timing depends on the scalar's bit transitions (a leaky conditional swap?): \
         |t| = {:.1}, where a 1 % difference scores {:.1}",
        t_transitions.abs(),
        t_control.abs()
    );
}
