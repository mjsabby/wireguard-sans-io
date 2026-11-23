//! Which secrets are still readable in dead stack memory after a public
//! API call has returned?
//!
//! Method. The devices, tunnels and the entropy source live on the heap.
//! Before each call the stack below `main` is painted; after the call has
//! returned, the same region is copied out and searched for every secret
//! the call handled. This program computes those secrets itself, from the
//! static keys and the entropy it handed out, by following whitepaper
//! §5.4.2–§5.4.6 step by step — independently of the code under test, and
//! only *after* the snapshot was taken, so that nothing it finds can be
//! its own.
//!
//! What is looked for:
//!
//! * the secrets as byte strings: private keys (as given and as the
//!   ladder uses them), Diffie-Hellman results, chaining keys, the
//!   handshake's AEAD keys, the pseudo-random key of every KDF step,
//!   transport keys, the one-time authenticator key of every packet, the
//!   keystream, cookies and the cookie secret — and, after a forgery was
//!   rejected, the tag that would have authenticated it. Whole, and in
//!   part: eight bytes of one in a row, anywhere in it, are a find —
//!   what is left of a copy when something has since written over the
//!   rest;
//! * the same in the forms the arithmetic has them in: Diffie-Hellman
//!   results as field-element limbs, the ladder's last intermediate
//!   values, the authenticator key as the words Poly1305 computes with
//!   and what it has accumulated, the words of a cipher key and of the
//!   cipher's state before the key is added back, a hash's state between
//!   two blocks and every word its working vector takes inside the
//!   rounds. A compiler keeps such words wherever it likes, so they are
//!   looked for one by one as well as side by side: one 64-bit word
//!   found is a find, two 32-bit words of a key or a state, any one word
//!   from inside a hash's rounds;
//! * for the curve arithmetic, whose base-point ladder the probe's own
//!   arithmetic does not follow: that the stack it used is overwritten
//!   at all (no more than a quarter of it anything but zero);
//! * and of a hasher or an authenticator that has finished and is still
//!   alive: its own memory.
//!
//! Which calls: the primitives by themselves, the way an embedder (or a
//! provider built from some of them) calls them — X25519, the hashes and
//! the key derivation, the cipher with every keystream backend there is
//! here, the AEADs; key generation and the constructors; then a tunnel's
//! whole life — twice, with the default provider and with the SIMD
//! keystream that `wireguard-embed` uses.
//!
//! The primitives are called directly because inside a tunnel one call's
//! leftovers are often overwritten by the next call's frames: there the
//! probe would not notice a wipe that had gone missing, only a later
//! change of the call order would. Called alone, each has to clean up
//! after itself.
//!
//! A function that returns a secret-bearing value *by value* writes it
//! into its caller's frame; what the caller does with it from there is
//! the caller's business (here: move it to the heap, which leaves the
//! copy). For those calls the search separates the two: what is below the
//! caller's frame is the library's and counts, what is in it is reported
//! and does not.
//!
//! Exit status: 0 if no tracked secret was found in the library's dead
//! frames after any call, 1 if one was, 2 if the probe itself does not
//! work (it must find what is left behind on purpose).
//!
//! What a pass means, and does not: this target, this compiler, these
//! optimisation settings (the script runs three). Registers are out of
//! reach, and so is whatever a different compiler makes of the same
//! source. In an unoptimised build (`WG_PROBE_UNOPTIMISED=1`) the word
//! forms are reported but not counted, and neither is a part of a byte
//! string (which there is a word loaded from it): without an optimiser
//! every expression of the arithmetic has a stack slot of its own, in
//! frames that lie deeper than the library overwrites. Byte strings
//! whole count in every build.

use std::hint::black_box;
use std::net::SocketAddr;
use std::process::ExitCode;

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use wireguard_chacha_simd::Avx2x8;
use wireguard_chacha_simd::Best;
use wireguard_probes::{
    Found, Needles, Recorded, Scan, bytes_of, call_deep, frame_end, paint, reference,
};
use wireguard_sans_io::crypto::{aead, blake2s, chacha20, ct, kdf, poly1305, siphash, x25519};
use wireguard_sans_io::{
    ChaChaImpl, CryptoProvider, Device, Encapsulated, InTree, Incoming, PeerConfig, PeerId,
    PollOutput, PresharedKey, Received, StaticSecret, Ticks, Tunnel, WallClock,
};

/// The ephemeral private key behind an ephemeral public key seen on the
/// wire: it is one of the 32-byte values the entropy source handed out.
fn ephemeral_for(log: &[Vec<u8>], public: &[u8]) -> [u8; 32] {
    log.iter()
        .filter_map(|r| <[u8; 32]>::try_from(r.as_slice()).ok())
        .find(|sk| x25519::x25519_base(sk) == public)
        .expect("the ephemeral private key is in the entropy log")
}

/// A function that leaves a secret in its dead stack frame: the positive
/// control. If the scan does not find this, the scan is broken.
#[inline(never)]
fn leaves_a_copy_behind(secret: &[u8; 32]) -> u8 {
    let copy = *secret;
    black_box(&copy);
    copy.iter().fold(0, |acc, b| acc ^ b)
}

/// As [`leaves_a_copy_behind`], and then writes over the first nine
/// bytes of the copy: what a caller does that uses the place again.
#[inline(never)]
fn leaves_most_of_a_copy_behind(secret: &[u8; 32]) -> u8 {
    let mut copy = *secret;
    black_box(&copy);
    let sum = copy.iter().fold(0, |acc, b| acc ^ b);
    for byte in &mut copy[..9] {
        // SAFETY: a volatile store into a live local.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    black_box(&copy);
    sum
}

/// Paint the stack beneath `main` in `colour`. (A function of its own,
/// never inlined, so that the paint starts where `paint()` starts it.)
#[inline(never)]
fn paint_scrub_range(colour: u8) {
    wireguard_probes::paint_with(colour);
}

/// A function that uses four kilobytes of stack without writing to them,
/// and says where its frame ends: what the scrub's own check has it
/// overwrite.
#[inline(never)]
fn leaves_its_frame_alone() -> usize {
    let frame = core::mem::MaybeUninit::<[u8; 4096]>::uninit();
    black_box(&frame);
    ct::stack_mark()
}

/// The same for the word forms: two words of a value, apart from each
/// other and from the rest of it.
#[inline(never)]
fn leaves_two_words_behind(words: &[u64; 5]) -> u64 {
    let [first, _, third, _, _] = *words;
    let (a, gap, b) = (first, [0x11u8; 24], third);
    black_box((&a, &gap, &b));
    a ^ b
}

/// The one-time Poly1305 key of an AEAD call (RFC 8439 §2.6).
fn one_time_key(key: &[u8; 32], counter: u64) -> [u8; 32] {
    let block = chacha20::block(key, 0, &aead::nonce_from_counter(counter));
    block[..32].try_into().unwrap()
}

/// The AEAD's tag over `aad` and `ciphertext` (RFC 8439 §2.8).
fn tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    let mut mac = poly1305::Poly1305::new(otk);
    mac.update_padded(aad)
        .update_padded(ciphertext)
        .update(&lengths);
    mac.finalize()
}

fn main() -> ExitCode {
    let mut scan = Scan::new();

    // ---- 0. the probe finds what is left behind on purpose ---------------
    let planted: [u8; 32] = core::array::from_fn(|i| 0xc0 ^ (i as u8).wrapping_mul(29));
    paint();
    call_deep(|| black_box(leaves_a_copy_behind(black_box(&planted))));
    scan.take();
    scan.needles.add("positive control", &planted);
    let bytes_found = !scan.needles.found_in(&scan.snap).is_empty();
    let words: [u64; 5] =
        core::array::from_fn(|i| 0x0123_4567_89ab_cdef_u64.rotate_left(i as u32 * 9));
    paint();
    call_deep(|| black_box(leaves_two_words_behind(black_box(&words))));
    scan.take();
    scan.needles = Needles::default();
    scan.needles.add_words("positive control", &words);
    let words_found = matches!(
        scan.needles.found_in(&scan.snap).first(),
        Some((_, Found::Scattered(2, 5, _)))
    );
    // What is left of a copy something has since written over the
    // beginning of: the rest of it is still a find.
    paint();
    call_deep(|| black_box(leaves_most_of_a_copy_behind(black_box(&planted))));
    scan.take();
    scan.needles = Needles::default();
    scan.needles.add("positive control", &planted);
    let part_found = matches!(
        scan.needles.found_in(&scan.snap).first(),
        Some((_, Found::Part(23, 32, _)))
    );
    println!(
        "positive controls (a secret left in a frame; two words of one, apart; one with its beginning written over): {}",
        if bytes_found && words_found && part_found {
            "found, as they must be"
        } else {
            "NOT FOUND"
        }
    );
    if !(bytes_found && words_found && part_found) {
        println!("RESULT: the probe does not work on this target; nothing can be concluded");
        return ExitCode::from(2);
    }
    scan.needles = Needles::default();

    // ---- 0a. what the probe itself adds to every depth it prints ----------
    // "N bytes of stack used" below is measured from the frame the call
    // was made through: `call_deep`'s spacer and the little a closure
    // needs are part of it. A call that does nothing says how much that
    // is at least.
    paint();
    call_deep(|| {
        black_box(());
    });
    scan.take();
    println!(
        "the probe's own frames, part of every depth below: {} bytes",
        wireguard_probes::depth(&scan.snap)
    );

    // ---- 0b. the scrub overwrites every byte it is asked to ----------------
    // A function with four kilobytes of frame it does not write to — so
    // that the paint is still there — says how deep it went; the scrub
    // is asked to overwrite down to there; and then no painted byte may
    // be left between that address and the frame the scrub was called
    // from. Twice, with two colours of paint: what the scrub's frames
    // write is zeros, return addresses and saved registers, and a byte of
    // an address can be the colour of the paint by chance — but not of
    // both.
    let mut untouched: Option<Vec<usize>> = None;
    let mut asked = 0;
    for colour in [wireguard_probes::PAINT_BYTE, !wireguard_probes::PAINT_BYTE] {
        paint_scrub_range(colour);
        let (low, top) = call_deep(|| {
            let top = ct::stack_mark();
            let low = black_box(leaves_its_frame_alone());
            ct::scrub_stack_to(low);
            (low, top)
        });
        scan.take();
        asked = top - low;
        let still: Vec<usize> = (low..top)
            .filter(|at| scan.snap[at - scan.start] == colour)
            .collect();
        untouched = Some(match untouched {
            None => still,
            Some(before) => before.into_iter().filter(|at| still.contains(at)).collect(),
        });
    }
    let untouched = untouched.unwrap_or_default();
    println!(
        "the scrub, asked to overwrite {asked} bytes of stack: {}",
        if untouched.is_empty() {
            "none left as it was".to_string()
        } else {
            format!("{} BYTES LEFT AS THEY WERE", untouched.len())
        }
    );
    if !untouched.is_empty() {
        println!("RESULT: the stack scrub leaves gaps; what it is relied on for does not hold");
        return ExitCode::FAILURE;
    }

    println!("---- X25519");
    curve(&mut scan);
    scan.needles = Needles::default();
    println!("---- hashes and key derivation");
    hashes(&mut scan);
    scan.needles = Needles::default();
    println!(
        "---- cipher and AEAD, {}",
        wireguard_sans_io::Scalar::name()
    );
    ciphers::<wireguard_sans_io::Scalar>(&mut scan);
    scan.needles = Needles::default();
    println!("---- cipher and AEAD, {}", KeystreamOnly::name());
    ciphers::<KeystreamOnly>(&mut scan);
    scan.needles = Needles::default();
    if scan.unoptimised {
        // Without an optimiser every intrinsic of a vector kernel is a
        // function call and every register a stack slot, in frames tens
        // of kilobytes deep: not a build anyone runs, and not one the
        // kernels' clean-up is made for. (The tunnel's life below runs
        // with the vector keystream in this build too.)
        println!(
            "---- cipher and AEAD, {}: not looked at in an unoptimised build",
            Best::name()
        );
    } else {
        println!("---- cipher and AEAD, {}", Best::name());
        ciphers::<Best>(&mut scan);
        scan.needles = Needles::default();
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        {
            println!("---- cipher and AEAD, {}", Avx2x8::name());
            ciphers::<Avx2x8>(&mut scan);
            scan.needles = Needles::default();
        }
    }
    println!("---- XChaCha20-Poly1305");
    extended_nonce(&mut scan);
    scan.needles = Needles::default();
    println!("---- key generation and construction");
    construction(&mut scan);
    scan.needles = Needles::default();
    println!(
        "---- a tunnel's life, default provider ({})",
        InTree::<wireguard_sans_io::Scalar>::name()
    );
    life::<InTree, wireguard_sans_io::Scalar>(&mut scan);
    scan.needles = Needles::default();
    println!(
        "---- a tunnel's life, SIMD keystream ({})",
        InTree::<Best>::name()
    );
    life::<InTree<Best>, Best>(&mut scan);

    if scan.not_counted > 0 {
        println!(
            "NOTE: {} finding(s) of word forms and parts in this unoptimised build were not counted (see the top of probes/src/bin/stack_residue.rs)",
            scan.not_counted
        );
    }
    if scan.findings == 0 {
        println!("RESULT: no tracked secret was left on the stack by any call");
        ExitCode::SUCCESS
    } else {
        println!(
            "RESULT: {} secret{} left on the stack",
            scan.findings,
            if scan.findings == 1 { "" } else { "s" }
        );
        ExitCode::FAILURE
    }
}

/// The curve arithmetic by itself: the result, and everything the ladder
/// had in its hands when it finished.
fn curve(scan: &mut Scan) {
    let secret: Box<[u8; 32]> =
        Box::new(core::array::from_fn(|i| 0x11 ^ (i as u8).wrapping_mul(73)));
    let other: [u8; 32] = core::array::from_fn(|i| 0x77 ^ (i as u8).wrapping_mul(31));
    let public: Box<[u8; 32]> = Box::new(x25519::x25519_base(&other));
    let mut out = Box::new([0u8; 32]);

    paint();
    call_deep(|| x25519::x25519_into(black_box(&secret), black_box(&public), &mut out));
    scan.take();
    let result = *out;
    let (x2, z2, products) = reference::ladder(&secret, &public, 2);
    let inverse = reference::invert(z2);
    assert_eq!(
        reference::mul(x2, inverse),
        reference::from_bytes(&result),
        "the probe's own ladder disagrees with the library's result"
    );
    let n = &mut scan.needles;
    n.add("the shared secret", &result);
    n.add_words(
        "the shared secret, as limbs",
        &reference::from_bytes(&result),
    );
    n.add_words("the ladder's X2", &x2);
    n.add_words("the ladder's Z2", &z2);
    n.add_words("1/Z2", &inverse);
    for (name, value) in &products {
        n.add_words(name, value);
    }
    n.add("the scalar", &*secret);
    n.add("the scalar, clamped", &reference::clamp(&secret));
    scan.report("x25519_into");
    scan.expect_overwritten("x25519_into");

    paint();
    let (by_value, caller) = call_deep(|| {
        let caller = frame_end();
        (
            black_box(x25519::x25519(black_box(&secret), black_box(&public))),
            caller,
        )
    });
    scan.take();
    assert_eq!(by_value, result);
    scan.report_below("x25519 (the result by value)", caller);
    scan.expect_overwritten("x25519");

    paint();
    let ok =
        call_deep(|| x25519::shared_secret_into(black_box(&secret), black_box(&public), &mut out));
    scan.take();
    assert!(ok);
    scan.report("shared_secret_into");
    scan.expect_overwritten("shared_secret_into");

    paint();
    let (by_value, caller) = call_deep(|| {
        let caller = frame_end();
        (
            black_box(x25519::shared_secret(
                black_box(&secret),
                black_box(&public),
            )),
            caller,
        )
    });
    scan.take();
    assert_eq!(by_value, Ok(result));
    scan.report_below("shared_secret (the result by value)", caller);
    scan.expect_overwritten("shared_secret");

    // The public key of a private key: the scalar is the secret.
    paint();
    let public_key = call_deep(|| black_box(x25519::x25519_base(black_box(&secret))));
    scan.take();
    black_box(public_key);
    // The base-point ladder is another algorithm, which the probe's own
    // arithmetic does not follow: here the overwriting is all there is to
    // go by, besides the scalar.
    scan.report("x25519_base");
    scan.expect_overwritten("x25519_base");
}

/// A value that is on the heap and nowhere else: what the calls under
/// test are given their secrets in.
fn heap<const N: usize>(seed: u8, step: u8) -> Box<[u8; N]> {
    let mut bytes = Box::new([0u8; N]);
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed ^ (i as u8).wrapping_mul(step);
    }
    bytes
}

/// `bytes`, zero-padded to a hash block.
fn block_of(bytes: &[u8]) -> [u8; 64] {
    let mut block = [0u8; 64];
    block[..bytes.len()].copy_from_slice(bytes);
    block
}

/// A hash's working vector, whole and in halves (a compiler need not
/// keep sixteen words side by side).
fn add_working_vector(needles: &mut Needles, name: &str, v: &[u32; 16]) {
    needles.add_words32(
        &format!("{name}: the working vector, word by word"),
        &reference::words_le(v),
    );
    needles.add(
        &format!("{name}: the working vector"),
        &reference::words_le(v),
    );
    needles.add(
        &format!("{name}: the working vector, first half"),
        &reference::words_le(&v[..8]),
    );
    needles.add(
        &format!("{name}: the working vector, second half"),
        &reference::words_le(&v[8..]),
    );
}

/// The one-time authenticator key `otk` in the forms Poly1305 has it in.
fn add_authenticator(needles: &mut Needles, which: &str, otk: &[u8]) {
    needles.add(&format!("one-time authenticator key of {which}"), otk);
    let half = |at: usize| u64::from_le_bytes(otk[at..at + 8].try_into().unwrap());
    needles.add_words(
        &format!("authenticator key of {which}, as Poly1305 has it (r, clamped)"),
        &[
            half(0) & 0x0fff_fffc_0fff_ffff,
            half(8) & 0x0fff_fffc_0fff_fffc,
        ],
    );
    needles.add_words(
        &format!("authenticator key of {which}, as Poly1305 has it (s)"),
        &[half(16), half(24)],
    );
}

/// What Poly1305 has accumulated when it is done, for a message whose
/// `tag` under the one-time key `otk` is known: the tag is that sum plus
/// the second half of the key, so whoever finds the sum next to a tag
/// that was sent has that half.
fn add_accumulator(needles: &mut Needles, which: &str, otk: &[u8], tag: &[u8]) {
    let s = u128::from_le_bytes(otk[16..32].try_into().unwrap());
    let h = u128::from_le_bytes(tag.try_into().unwrap()).wrapping_sub(s);
    needles.add_words(
        &format!("what Poly1305 had accumulated for {which}"),
        &[h as u64, (h >> 64) as u64],
    );
}

/// The hashes and the key derivation, each by itself.
#[allow(clippy::too_many_lines)]
fn hashes(scan: &mut Scan) {
    let key = heap::<32>(0x3c, 59);
    let msg = heap::<32>(0x81, 23);
    let mut out = Box::new([0u8; 32]);
    let mut tag = Box::new([0u8; 16]);

    // ---- HMAC (RFC 2104) ------------------------------------------------------
    paint();
    call_deep(|| kdf::hmac_into(black_box(&key[..]), &[black_box(&msg[..])], &mut out));
    scan.take();
    {
        // The same by hand, with the probe's own compression function for
        // what lies between the blocks.
        let (mut ipad, mut opad) = ([0x36u8; 64], [0x5cu8; 64]);
        for i in 0..32 {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }
        // Every word the four compressions had in their working vectors
        // on the way, as well as what they ended with.
        let mut inside = Vec::new();
        let mut h = reference::blake2s_start(32, 0);
        let v_inner_key = reference::blake2s_trace(&mut h, &ipad, 64, false, &mut inside);
        let inner_state = h;
        let v_inner_msg =
            reference::blake2s_trace(&mut h, &block_of(&msg[..]), 96, true, &mut inside);
        let inner_digest = reference::words_le(&h);
        let mut h = reference::blake2s_start(32, 0);
        let v_outer_key = reference::blake2s_trace(&mut h, &opad, 64, false, &mut inside);
        let outer_state = h;
        let v_outer_msg =
            reference::blake2s_trace(&mut h, &block_of(&inner_digest), 96, true, &mut inside);
        scan.expect_none_of("HMAC", &inside);
        assert_eq!(
            reference::words_le(&h),
            out[..],
            "the probe's own HMAC disagrees with the library's"
        );
        let n = &mut scan.needles;
        n.add("HMAC: the key", &key[..]);
        n.add("HMAC: the message", &msg[..]);
        n.add("HMAC: the key, padded for the inner hash", &ipad[..32]);
        n.add("HMAC: the key, padded for the outer hash", &opad[..32]);
        n.add(
            "HMAC: the inner hash's state after the key block",
            &reference::words_le(&inner_state),
        );
        n.add(
            "HMAC: the outer hash's state after the key block",
            &reference::words_le(&outer_state),
        );
        n.add("HMAC: the inner digest", &inner_digest);
        n.add("HMAC: the result", &out[..]);
        add_working_vector(n, "HMAC, inner hash, key block", &v_inner_key);
        add_working_vector(n, "HMAC, inner hash, message", &v_inner_msg);
        add_working_vector(n, "HMAC, outer hash, key block", &v_outer_key);
        add_working_vector(n, "HMAC, outer hash, inner digest", &v_outer_msg);
    }
    scan.report("kdf::hmac_into");

    let long = heap::<100>(0x17, 11);
    paint();
    call_deep(|| kdf::hmac_into(black_box(&long[..]), &[black_box(&msg[..])], &mut out));
    scan.take();
    {
        let hashed = blake2s::hash(&[&long[..]]);
        let n = &mut scan.needles;
        n.add("HMAC: a key longer than a block, hashed", &hashed);
        n.add(
            "HMAC: a key longer than a block (its first 64 bytes)",
            &long[..64],
        );
        n.add("HMAC: a key longer than a block (its end)", &long[64..]);
        let padded: Vec<u8> = hashed.iter().map(|b| b ^ 0x36).collect();
        n.add("HMAC: the hashed key, padded for the inner hash", &padded);
        n.add("HMAC: the result for the long key", &out[..]);
    }
    scan.report("kdf::hmac_into, a key longer than a block");

    paint();
    let (by_value, caller) = call_deep(|| {
        let caller = frame_end();
        (
            black_box(kdf::hmac(black_box(&key[..]), &[black_box(&msg[..])])),
            caller,
        )
    });
    scan.take();
    black_box(by_value);
    scan.needles.add("HMAC: the result", &by_value);
    scan.report_convenience("kdf::hmac (the result by value)", caller);

    // ---- Kdf_n -----------------------------------------------------------------
    let (mut t1, mut t2, mut t3) = (
        Box::new([0u8; 32]),
        Box::new([0u8; 32]),
        Box::new([0u8; 32]),
    );
    paint();
    call_deep(|| {
        kdf::kdf_into::<InTree, 3>(
            black_box(&key),
            black_box(&msg[..]),
            [&mut t1, &mut t2, &mut t3],
        );
    });
    scan.take();
    {
        let prk = kdf::hmac(&key[..], &[&msg[..]]);
        assert_eq!(*t2, kdf::hmac(&prk, &[&t1[..], &[2]]));
        let n = &mut scan.needles;
        n.add("KDF: the pseudo-random key", &prk);
        n.add("KDF: the first output", &t1[..]);
        n.add("KDF: the second output", &t2[..]);
        n.add("KDF: the third output", &t3[..]);
    }
    scan.report("kdf::kdf_into, three outputs");

    let mut chain = heap::<32>(0x3c, 59);
    paint();
    call_deep(|| {
        kdf::kdf_chain::<InTree, 2>(&mut chain, black_box(&msg[..]), [&mut t2, &mut t3]);
    });
    scan.take();
    assert_eq!(
        *chain, *t1,
        "kdf_chain's first output is the new chaining key"
    );
    scan.report("kdf::kdf_chain, the chaining key and two outputs");

    paint();
    let (by_value, caller) = call_deep(|| {
        let caller = frame_end();
        (
            black_box(kdf::kdf3(black_box(&key), black_box(&msg[..]))),
            caller,
        )
    });
    scan.take();
    black_box(by_value);
    scan.report_convenience("kdf::kdf3 (the outputs by value)", caller);

    // ---- BLAKE2s, keyed and not ---------------------------------------------------
    paint();
    call_deep(|| blake2s::mac_into(black_box(&key[..]), &[black_box(&msg[..])], &mut tag));
    scan.take();
    let mut keyed = Box::new([0u32; 8]);
    {
        blake2s::mac_key_state(&key, &mut keyed);
        let mut h = reference::blake2s_start(16, 32);
        let v_key = reference::blake2s_compress(&mut h, &block_of(&key[..]), 64, false);
        assert_eq!(
            h, *keyed,
            "the probe's own keyed hash disagrees with the library's"
        );
        let v_msg = reference::blake2s_compress(&mut h, &block_of(&msg[..]), 96, true);
        assert_eq!(reference::words_le(&h)[..16], tag[..]);
        let n = &mut scan.needles;
        n.add(
            "keyed hash: the state after the key block",
            &reference::words_le(&keyed[..]),
        );
        n.add("keyed hash: the tag", &tag[..]);
        n.add(
            "keyed hash: the rest of the state the tag is cut from",
            &reference::words_le(&h)[16..],
        );
        add_working_vector(n, "keyed hash, key block", &v_key);
        add_working_vector(n, "keyed hash, message", &v_msg);
    }
    scan.report("blake2s::mac_into");

    // A key longer than the 32 bytes the keyed hash takes is hashed
    // down first: that digest is the key from then on.
    paint();
    call_deep(|| blake2s::mac_into(black_box(&long[..]), &[black_box(&msg[..])], &mut tag));
    scan.take();
    scan.needles
        .add("keyed hash: the tag under the long key", &tag[..]);
    scan.report("blake2s::mac_into, a key longer than 32 bytes");

    // The streaming keyed hash, as a value of the caller's: made (it
    // comes back by value, without the key — that is borrowed until the
    // first input), fed, and then given up or finished. The key — or, of
    // one too long, the digest that stands in for it — goes into the
    // hasher where the caller has it and is wiped there: nothing is left
    // in anybody's frame, the caller's included, in any build.
    for (what, the_key) in [("a key", &key[..]), ("a long key", &long[..])] {
        paint();
        call_deep(|| {
            let mut mac = blake2s::Blake2sMac::new(black_box(the_key));
            mac.update(black_box(&[0x01u8]));
        });
        scan.take();
        scan.report(&format!("Blake2sMac::new with {what}, fed, then dropped"));

        let mut streamed = Box::new([0u8; 16]);
        paint();
        call_deep(|| {
            let mut mac = blake2s::Blake2sMac::new(black_box(the_key));
            mac.update(black_box(&msg[..16]))
                .update(black_box(&msg[16..]));
            mac.finalize_into(&mut streamed);
        });
        scan.take();
        blake2s::mac_into(the_key, &[&msg[..]], &mut tag);
        assert_eq!(*streamed, *tag, "the streaming keyed hash disagrees");
        scan.report(&format!("Blake2sMac::new with {what}, fed, finalize_into"));

        // The key is taken in and nothing else happens: no block is
        // compressed, so no frame is overwritten afterwards that might
        // happen to cover what taking the key in left.
        let mut kept = Box::new(blake2s::Blake2sMac::new(the_key));
        paint();
        call_deep(|| {
            kept.update(black_box(&[]));
        });
        scan.take();
        scan.report(&format!(
            "Blake2sMac::update with no input, {what} taken in"
        ));
        drop(kept);
    }

    paint();
    call_deep(|| blake2s::mac_key_state(black_box(&key), &mut keyed));
    scan.take();
    scan.report("blake2s::mac_key_state");
    {
        let mut inside = Vec::new();
        let mut h = reference::blake2s_start(16, 32);
        reference::blake2s_trace(&mut h, &block_of(&key[..]), 64, false, &mut inside);
        scan.expect_none_of("the keyed hash's key block", &inside);
    }

    paint();
    call_deep(|| {
        blake2s::mac_keyed(
            black_box(&key),
            black_box(&keyed),
            &[black_box(&msg[..])],
            &mut tag,
        );
    });
    scan.take();
    scan.report("blake2s::mac_keyed");

    paint();
    let (by_value, caller) = call_deep(|| {
        let caller = frame_end();
        (
            black_box(blake2s::mac(black_box(&key[..]), &[black_box(&msg[..])])),
            caller,
        )
    });
    scan.take();
    black_box(by_value);
    scan.report_convenience("blake2s::mac (the tag by value)", caller);

    // A hash over secrets, as the handshake's chaining hash is.
    paint();
    call_deep(|| blake2s::hash_into(&[black_box(&key[..]), black_box(&msg[..])], &mut out));
    scan.take();
    {
        let mut both = [0u8; 64];
        both[..32].copy_from_slice(&key[..]);
        both[32..].copy_from_slice(&msg[..]);
        let mut h = reference::blake2s_start(32, 0);
        let v = reference::blake2s_compress(&mut h, &both, 64, true);
        assert_eq!(reference::words_le(&h), out[..]);
        let n = &mut scan.needles;
        n.add("hash: the digest of two secrets", &out[..]);
        add_working_vector(n, "hash of two secrets", &v);
    }
    scan.report("blake2s::hash_into");

    // A hasher fed piece by piece: the call that compresses a block of
    // secrets leaves nothing of that on the stack, whether or not the
    // hasher is ever finished.
    let mut fed = Box::new(blake2s::Blake2s256::new());
    fed.update(&key[..]).update(&msg[..]);
    paint();
    call_deep(|| {
        fed.update(black_box(&[0x77u8]));
    });
    scan.take();
    {
        let mut both = [0u8; 64];
        both[..32].copy_from_slice(&key[..]);
        both[32..].copy_from_slice(&msg[..]);
        let mut inside = Vec::new();
        let mut h = reference::blake2s_start(32, 0);
        let v = reference::blake2s_trace(&mut h, &both, 64, false, &mut inside);
        add_working_vector(&mut scan.needles, "hash fed piece by piece", &v);
        scan.needles.add(
            "hash fed piece by piece: the state after a block of secrets",
            &reference::words_le(&h),
        );
        scan.report("Blake2s256::update, the call that compresses a block");
        scan.expect_none_of("a hash fed piece by piece", &inside);
    }
    drop(fed);

    // A hasher that has finished and is still there holds nothing of
    // what went through it (its memory is read, not the stack).
    let mut hasher = Box::new(blake2s::Blake2s256::new());
    hasher.update(&key[..]).update(&msg[..]);
    hasher.finalize_into(&mut out);
    scan.report_value("a Blake2s256 after finalize_into", &bytes_of(&*hasher));
    drop(hasher);

    paint();
    let (by_value, caller) = call_deep(|| {
        let caller = frame_end();
        (
            black_box(blake2s::hash(&[black_box(&key[..]), black_box(&msg[..])])),
            caller,
        )
    });
    scan.take();
    black_box(by_value);
    scan.report_convenience("blake2s::hash (the digest by value)", caller);

    // ---- SipHash (the index table's keyed hash) -------------------------------------
    // Its state is not wiped after use (the README says which two keys
    // pass through it, and why that is accepted): looked for in the forms
    // the computation has, which an optimised build keeps in registers.
    let sip = heap::<16>(0x6e, 37);
    paint();
    let digest = call_deep(|| black_box(siphash::siphash24(black_box(&sip), black_box(&msg[..]))));
    scan.take();
    black_box(digest);
    {
        let k0 = u64::from_le_bytes(sip[..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(sip[8..].try_into().unwrap());
        let n = &mut scan.needles;
        n.add_words("SipHash: the key, as words", &[k0, k1]);
        n.add_words(
            "SipHash: the key in the initial state",
            &[
                k0 ^ 0x736f_6d65_7073_6575,
                k1 ^ 0x646f_7261_6e64_6f6d,
                k0 ^ 0x6c79_6765_6e65_7261,
                k1 ^ 0x7465_6462_7974_6573,
            ],
        );
    }
    scan.report("siphash::siphash24");

    // ---- Poly1305 -----------------------------------------------------------------------
    let data = heap::<100>(0x09, 5);
    paint();
    let (by_value, caller) = call_deep(|| {
        let caller = frame_end();
        (
            black_box(poly1305::poly1305(black_box(&key), black_box(&data[..]))),
            caller,
        )
    });
    scan.take();
    black_box(by_value);
    add_authenticator(&mut scan.needles, "a direct call", &key[..]);
    scan.report_convenience("poly1305::poly1305 (the tag by value)", caller);

    // The authenticator as a value of the caller's: made, used and
    // dropped in one place, it wipes itself there. (`new` hands it over
    // by value, like the conveniences above.)
    paint();
    call_deep(|| {
        let mut mac = poly1305::Poly1305::new(black_box(&key));
        mac.update(black_box(&data[..]));
        mac.finalize_into(&mut tag);
    });
    scan.take();
    scan.report_convenience(
        "Poly1305::new + update + finalize_into, in one frame",
        usize::MAX,
    );

    // One that is given up before it has finished wipes itself as it is
    // dropped — where it is: it goes out of scope here (handing it to
    // `drop` would move it, and leave this copy behind).
    paint();
    call_deep(|| {
        let mut mac = poly1305::Poly1305::new(black_box(&key));
        mac.update(black_box(&data[..]));
    });
    scan.take();
    scan.report_convenience("Poly1305::new + update, then dropped", usize::MAX);

    // And an authenticator that has finished and is still there holds
    // nothing of its key.
    let mut mac = Box::new(poly1305::Poly1305::new(&key));
    mac.update(&data[..]);
    mac.finalize_into(&mut tag);
    scan.report_value("a Poly1305 after finalize_into", &bytes_of(&*mac));
}

/// A backend that is a keystream and nothing else: the calls an AEAD
/// makes are then the ones the `ChaChaImpl` trait provides, which no
/// backend of this repository uses any more — an embedder's may.
struct KeystreamOnly;

impl ChaChaImpl for KeystreamOnly {
    fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        chacha20::xor_in_place(key, counter, nonce, buf);
    }
    fn name() -> &'static str {
        "a backend with the trait's own combined calls"
    }
}

/// A ChaCha20 state after the rounds, before the input state is added
/// back: the keystream block minus the input state.
fn worked_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> Vec<u8> {
    let block = chacha20::block(key, counter, nonce);
    let mut state = Vec::with_capacity(64);
    state.extend_from_slice(b"expand 32-byte k");
    state.extend_from_slice(key);
    state.extend_from_slice(&counter.to_le_bytes());
    state.extend_from_slice(nonce);
    block
        .chunks(4)
        .zip(state.chunks(4))
        .flat_map(|(b, s)| {
            u32::from_le_bytes(b.try_into().unwrap())
                .wrapping_sub(u32::from_le_bytes(s.try_into().unwrap()))
                .to_le_bytes()
        })
        .collect()
}

/// Keystream block `counter`, whole and in halves, and the state it was
/// made from.
fn add_block(needles: &mut Needles, key: &[u8; 32], counter: u32, nonce: &[u8; 12], what: &str) {
    let block = chacha20::block(key, counter, nonce);
    needles.add(&format!("keystream block {counter} ({what})"), &block);
    needles.add(
        &format!("keystream block {counter} ({what}), first half"),
        &block[..32],
    );
    needles.add(
        &format!("keystream block {counter} ({what}), second half"),
        &block[32..],
    );
    let worked = worked_state(key, counter, nonce);
    needles.add_words32(
        &format!("block {counter} before the key is added back ({what}), word by word"),
        &worked,
    );
    needles.add_words32(
        &format!("keystream block {counter} ({what}), word by word"),
        &block,
    );
    needles.add(
        &format!("block {counter} before the key is added back ({what})"),
        &worked,
    );
    needles.add(
        &format!("block {counter} before the key is added back ({what}), first half"),
        &worked[..32],
    );
    needles.add(
        &format!("block {counter} before the key is added back ({what}), second half"),
        &worked[32..],
    );
}

/// What a keystream call for `len` bytes from block `first` on worked
/// with: its first and last block, and the one after — a backend that
/// computes several blocks at a time computes more than it uses.
fn add_stream(needles: &mut Needles, key: &[u8; 32], nonce: &[u8; 12], first: u32, len: usize) {
    if len == 0 {
        return;
    }
    let last = first + ((len - 1) / 64) as u32;
    add_block(needles, key, first, nonce, &format!("first of {len} bytes"));
    add_block(needles, key, last, nonce, &format!("last of {len} bytes"));
    add_block(
        needles,
        key,
        last + 1,
        nonce,
        &format!("one past the last of {len} bytes"),
    );
}

/// The cipher and the AEAD with keystream backend `C`, each call by
/// itself.
#[allow(clippy::too_many_lines)]
fn ciphers<C: ChaChaImpl>(scan: &mut Scan) {
    let key = heap::<32>(0xa7, 47);
    let nonce: [u8; 12] = [0, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    let mut data = vec![0x42u8; 8192];
    let mut otk = Box::new([0u8; 32]);
    let mut block = Box::new([0u8; 64]);
    let name = C::name();
    scan.needles.add("the cipher key", &key[..]);
    scan.needles
        .add_words32("the cipher key, word by word", &key[..]);

    if name == wireguard_sans_io::Scalar::name() {
        // The block function and its callers, which no backend replaces.
        paint();
        call_deep(|| chacha20::block_into(black_box(&key), 5, &nonce, &mut block));
        scan.take();
        add_block(&mut scan.needles, &key, 5, &nonce, "asked for");
        scan.report("chacha20::block_into");

        paint();
        call_deep(|| chacha20::one_time_key_into(black_box(&key), &nonce, &mut otk));
        scan.take();
        add_block(&mut scan.needles, &key, 0, &nonce, "the one-time key's");
        add_authenticator(&mut scan.needles, "a direct call", &otk[..]);
        scan.report("chacha20::one_time_key_into");

        for len in [37usize, 64, 150] {
            paint();
            call_deep(|| chacha20::xor_in_place(black_box(&key), 1, &nonce, &mut data[..len]));
            scan.take();
            add_stream(&mut scan.needles, &key, &nonce, 1, len);
            scan.report(&format!("chacha20::xor_in_place, {len} bytes"));
        }
    }

    // ---- the keystream ------------------------------------------------------------
    for len in [37usize, 190, 600, 1000, 1420, 2048, 2300, 4133] {
        paint();
        call_deep(|| C::apply_keystream(black_box(&key), &nonce, 1, &mut data[..len]));
        scan.take();
        add_stream(&mut scan.needles, &key, &nonce, 1, len);
        scan.report(&format!("{name}: apply_keystream, {len} bytes"));
    }

    // ---- the calls an AEAD makes ------------------------------------------------------
    add_block(&mut scan.needles, &key, 0, &nonce, "the one-time key's");
    for len in [0usize, 32, 300, 1420, 3000] {
        paint();
        call_deep(|| C::seal_keystream(black_box(&key), &nonce, &mut data[..len], &mut otk));
        scan.take();
        add_authenticator(&mut scan.needles, "a keystream call", &otk[..]);
        add_stream(&mut scan.needles, &key, &nonce, 1, len);
        scan.report(&format!("{name}: seal_keystream, {len} bytes"));
        for verdict in [false, true] {
            paint();
            let got = call_deep(|| {
                C::open_keystream(black_box(&key), &nonce, &mut data[..len], |otk, _| {
                    black_box(otk);
                    verdict
                })
            });
            scan.take();
            assert_eq!(got, verdict);
            scan.report(&format!(
                "{name}: open_keystream, {len} bytes, {}",
                if verdict { "accepted" } else { "refused" }
            ));
        }
    }

    // ---- the AEAD ---------------------------------------------------------------------
    let aad = [0x11u8; 32];
    let other_aad = [0x12u8; 32];
    for len in [0usize, 32, 1420] {
        let plaintext = vec![0x42u8; len];
        let mut sealed = vec![0u8; len + 16];
        let mut opened = vec![0u8; len];
        paint();
        call_deep(|| {
            aead::seal_with::<C>(black_box(&key), &nonce, &aad, &plaintext, &mut sealed).unwrap();
        });
        scan.take();
        add_stream(&mut scan.needles, &key, &nonce, 1, len);
        add_accumulator(
            &mut scan.needles,
            &format!("{len} sealed bytes"),
            &otk[..],
            &sealed[len..],
        );
        scan.report(&format!("aead::seal_with::<{name}>, {len} bytes"));

        // The same ciphertext under other associated data: refused, and
        // the tag that would have passed is nobody's to know.
        let would_pass = tag(&otk, &other_aad, &sealed[..len]);
        paint();
        let refused = call_deep(|| {
            aead::open_with::<C>(black_box(&key), &nonce, &other_aad, &sealed, &mut opened).is_err()
        });
        scan.take();
        assert!(refused);
        scan.needles.add(
            &format!("the tag that authenticates {len} bytes under other associated data"),
            &would_pass,
        );
        scan.report(&format!("aead::open_with::<{name}>, {len} bytes, refused"));

        paint();
        call_deep(|| {
            aead::open_with::<C>(black_box(&key), &nonce, &aad, &sealed, &mut opened).unwrap();
        });
        scan.take();
        assert_eq!(opened, plaintext);
        scan.report(&format!("aead::open_with::<{name}>, {len} bytes"));

        let mut buf = vec![0x42u8; len + 16];
        paint();
        call_deep(|| {
            aead::seal_in_place_with::<C>(black_box(&key), &nonce, &aad, len, &mut buf).unwrap();
        });
        scan.take();
        assert_eq!(buf, sealed);
        scan.report(&format!("aead::seal_in_place_with::<{name}>, {len} bytes"));

        paint();
        let refused = call_deep(|| {
            aead::open_in_place_with::<C>(black_box(&key), &nonce, &other_aad, &mut buf).is_err()
        });
        scan.take();
        assert!(refused);
        assert_eq!(buf, sealed, "a refused message was changed");
        scan.report(&format!(
            "aead::open_in_place_with::<{name}>, {len} bytes, refused"
        ));

        paint();
        call_deep(|| {
            aead::open_in_place_with::<C>(black_box(&key), &nonce, &aad, &mut buf).unwrap();
        });
        scan.take();
        assert_eq!(buf[..len], plaintext[..]);
        scan.report(&format!("aead::open_in_place_with::<{name}>, {len} bytes"));
    }
}

/// XChaCha20-Poly1305 (the cookie reply's AEAD): the subkey on top of
/// everything the plain AEAD has.
fn extended_nonce(scan: &mut Scan) {
    let key = heap::<32>(0x5b, 61);
    let xnonce: [u8; 24] = core::array::from_fn(|i| 0xe0 ^ (i as u8).wrapping_mul(7));
    let aad = [0x21u8; 16];
    let other_aad = [0x22u8; 16];
    let len = 16usize;
    let plaintext = vec![0x42u8; len];
    let mut sealed = vec![0u8; len + 16];
    let mut opened = vec![0u8; len];

    paint();
    call_deep(|| {
        aead::xseal(black_box(&key), &xnonce, &aad, &plaintext, &mut sealed).unwrap();
    });
    scan.take();
    let subkey = chacha20::hchacha20(&key, xnonce[..16].try_into().unwrap());
    let mut sub_nonce = [0u8; 12];
    sub_nonce[4..].copy_from_slice(&xnonce[16..]);
    let otk = one_time_key(
        &subkey,
        u64::from_le_bytes(xnonce[16..].try_into().unwrap()),
    );
    assert_eq!(tag(&otk, &aad, &sealed[..len]), sealed[len..]);
    {
        let n = &mut scan.needles;
        n.add("XChaCha20: the key", &key[..]);
        n.add("XChaCha20: the subkey", &subkey);
        // HChaCha20 is the block function without the last addition, on
        // the key and the first sixteen bytes of the nonce.
        let counter = u32::from_le_bytes(xnonce[..4].try_into().unwrap());
        let worked = worked_state(&key, counter, xnonce[4..16].try_into().unwrap());
        n.add("XChaCha20: the state the subkey is cut from", &worked);
        n.add(
            "XChaCha20: the part of that state that is not the subkey",
            &worked[16..48],
        );
        add_block(n, &subkey, 0, &sub_nonce, "the one-time key's");
        add_authenticator(n, "the XChaCha20 message", &otk);
        add_stream(n, &subkey, &sub_nonce, 1, len);
        n.add(
            "the tag that authenticates it under other associated data",
            &tag(&otk, &other_aad, &sealed[..len]),
        );
    }
    scan.report("aead::xseal");

    paint();
    let refused = call_deep(|| {
        aead::xopen(black_box(&key), &xnonce, &other_aad, &sealed, &mut opened).is_err()
    });
    scan.take();
    assert!(refused);
    scan.report("aead::xopen, refused");

    paint();
    call_deep(|| {
        aead::xopen(black_box(&key), &xnonce, &aad, &sealed, &mut opened).unwrap();
    });
    scan.take();
    assert_eq!(opened, plaintext);
    scan.report("aead::xopen");

    let mut buf = vec![0x42u8; len + 16];
    paint();
    call_deep(|| {
        aead::xseal_in_place(black_box(&key), &xnonce, &aad, len, &mut buf).unwrap();
    });
    scan.take();
    assert_eq!(buf, sealed);
    scan.report("aead::xseal_in_place");

    paint();
    let refused =
        call_deep(|| aead::xopen_in_place(black_box(&key), &xnonce, &other_aad, &mut buf).is_err());
    scan.take();
    assert!(refused);
    scan.report("aead::xopen_in_place, refused");

    paint();
    call_deep(|| {
        aead::xopen_in_place(black_box(&key), &xnonce, &aad, &mut buf).unwrap();
    });
    scan.take();
    scan.report("aead::xopen_in_place");

    let mut subkey_out = Box::new([0u8; 32]);
    paint();
    call_deep(|| {
        chacha20::hchacha20_into(
            black_box(&key),
            xnonce[..16].try_into().unwrap(),
            &mut subkey_out,
        );
    });
    scan.take();
    assert_eq!(*subkey_out, subkey);
    scan.report("chacha20::hchacha20_into");

    paint();
    let (by_value, caller) = call_deep(|| {
        let caller = frame_end();
        (
            black_box(chacha20::hchacha20(
                black_box(&key),
                xnonce[..16].try_into().unwrap(),
            )),
            caller,
        )
    });
    scan.take();
    black_box(by_value);
    scan.report_convenience("chacha20::hchacha20 (the subkey by value)", caller);
}

/// Key generation and the constructors: in place, and by value.
fn construction(scan: &mut Scan) {
    let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
    let mut rng = Box::new(Recorded::new(0x5eed));
    let peer_public = StaticSecret::from_bytes([0x33; 32]).public_key();
    let psk: [u8; 32] = core::array::from_fn(|i| 0xd0 ^ (i as u8).wrapping_mul(17));

    // The generated values come back by value; the caller here moves
    // them to the heap.
    paint();
    let (secret, caller): (Box<StaticSecret>, usize) = call_deep(|| {
        let caller = frame_end();
        (Box::new(StaticSecret::generate(&mut *rng).unwrap()), caller)
    });
    scan.take();
    let drawn: [u8; 32] = rng.log.last().unwrap().as_slice().try_into().unwrap();
    let clamped = reference::clamp(&drawn);
    scan.needles
        .add("the generated private key, as drawn", &drawn);
    scan.needles
        .add("the generated private key, clamped", &clamped);
    scan.report_below("StaticSecret::generate", caller);

    paint();
    let (generated_psk, caller): (Box<PresharedKey>, usize) = call_deep(|| {
        let caller = frame_end();
        (Box::new(PresharedKey::generate(&mut *rng).unwrap()), caller)
    });
    scan.take();
    scan.needles
        .add("the generated pre-shared key", rng.log.last().unwrap());
    scan.report_below("PresharedKey::generate", caller);
    drop(generated_psk);

    // In place: nothing is returned, nothing may be left anywhere.
    let mut device_slot: Box<Option<Device>> = Box::new(None);
    paint();
    call_deep(|| {
        Device::new_in(&mut device_slot, &secret, wall, &mut *rng).unwrap();
    });
    scan.take();
    scan.report("Device::new_in");

    let shared = x25519::x25519(&clamped, peer_public.as_bytes());
    scan.needles.add("the pre-shared key", &psk);
    scan.needles.add("DH(static, static)", &shared);
    scan.needles.add_words(
        "DH(static, static), as limbs",
        &reference::from_bytes(&shared),
    );
    let mut config: Box<PeerConfig> = Box::new(PeerConfig::new(peer_public));
    config.psk = PresharedKey::from_bytes(psk);
    let device = device_slot.as_ref().as_ref().unwrap();
    let mut tunnel_slot: Box<Option<Tunnel>> = Box::new(None);
    paint();
    call_deep(|| {
        device
            .tunnel_in(
                &mut tunnel_slot,
                PeerId::new(1).unwrap(),
                &config,
                &mut *rng,
            )
            .unwrap();
    });
    scan.take();
    scan.report("Device::tunnel_in");

    // By value: the library's frames are clean; the frame of whoever
    // receives the value is not, and cannot be made so from inside.
    paint();
    let (by_value, caller): (Box<Device>, usize) = call_deep(|| {
        let caller = frame_end();
        (
            Box::new(Device::new((*secret).clone(), wall, &mut *rng).unwrap()),
            caller,
        )
    });
    scan.take();
    scan.report_below("Device::new (by value)", caller);

    paint();
    let (tunnel, caller): (Box<Tunnel>, usize) = call_deep(|| {
        let mut config = PeerConfig::new(peer_public);
        config.psk = PresharedKey::from_bytes(black_box(psk));
        let caller = frame_end();
        (
            Box::new(
                device
                    .tunnel(PeerId::new(2).unwrap(), config, &mut *rng)
                    .unwrap(),
            ),
            caller,
        )
    });
    scan.take();
    scan.report_below("Device::tunnel (by value)", caller);
    black_box((&tunnel, &by_value));
}

/// A tunnel's life with provider `P` (whose keystream is `C`).
#[allow(clippy::too_many_lines)]
fn life<P: CryptoProvider, C: ChaChaImpl>(scan: &mut Scan) {
    let mut rng = Box::new(Recorded::new(0x57ac));
    let a_sk: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let b_sk: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(0xf5));
    let psk = [0x5au8; 32];
    let a_pub = x25519::x25519_base(&a_sk);
    let b_pub = x25519::x25519_base(&b_sk);
    let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
    let now = Ticks::from_secs(1);
    let a_addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
    let b_addr: SocketAddr = "192.0.2.2:51820".parse().unwrap();
    let id = PeerId::new(0).unwrap();

    let mut a_dev: Box<Device<P>> =
        Box::new(Device::with_provider(StaticSecret::from_bytes(a_sk), wall, &mut *rng).unwrap());
    let mut b_dev: Box<Device<P>> =
        Box::new(Device::with_provider(StaticSecret::from_bytes(b_sk), wall, &mut *rng).unwrap());
    let mut cfg = PeerConfig::new(b_pub.into());
    cfg.psk = PresharedKey::from_bytes(psk);
    cfg.endpoint = Some(b_addr);
    let mut a: Box<Tunnel<P>> = Box::new(a_dev.tunnel(id, cfg, &mut *rng).unwrap());
    let mut cfg = PeerConfig::new(a_pub.into());
    cfg.psk = PresharedKey::from_bytes(psk);
    let mut b: Box<Tunnel<P>> = Box::new(b_dev.tunnel(id, cfg, &mut *rng).unwrap());

    let mut init = vec![0u8; 148];
    let mut resp = vec![0u8; 92];
    let mut wire = vec![0u8; 2048];
    let mut out = vec![0u8; 256];

    // ---- 1. initiator: poll() builds the initiation -------------------------
    a.request_handshake(now);
    paint();
    call_deep(|| match a.poll(now, &mut out, &mut *rng).unwrap() {
        PollOutput::Transmit(tx, _) => init.copy_from_slice(tx.datagram),
        other => panic!("{other:?}"),
    });
    scan.take();
    let init_wire = init.clone();

    // The initiator's secrets (whitepaper §5.4.2).
    let e_i = ephemeral_for(&rng.log, &init[8..40]);
    let e_i_pub: [u8; 32] = init[8..40].try_into().unwrap();
    let c0 = blake2s::hash(&[b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"]);
    let mut h = blake2s::hash(&[&c0, b"WireGuard v1 zx2c4 Jason@zx2c4.com"]);
    h = blake2s::hash(&[&h, &b_pub]);
    let c1 = kdf::kdf1(&c0, &e_i_pub);
    h = blake2s::hash(&[&h, &e_i_pub]);
    let es = x25519::x25519(&e_i, &b_pub);
    let (c2, k1) = kdf::kdf2(&c1, &es);
    h = blake2s::hash(&[&h, &init[40..88]]);
    // What the timestamp's AEAD authenticates along with it.
    let h_timestamp = h;
    let ss = x25519::x25519(&a_sk, &b_pub);
    let (c3, k2) = kdf::kdf2(&c2, &ss);
    h = blake2s::hash(&[&h, &init[88..116]]);
    // The probe's AEAD is the library's: the genuine tag comes out.
    assert_eq!(
        tag(&one_time_key(&k2, 0), &h_timestamp, &init[88..100]),
        init[100..116]
    );
    let n = &mut scan.needles;
    n.add("initiator's ephemeral private key", &e_i);
    n.add(
        "initiator's ephemeral private key, clamped",
        &reference::clamp(&e_i),
    );
    n.add("DH es", &es);
    n.add_words("DH es, as limbs", &reference::from_bytes(&es));
    n.add("DH ss (static-static)", &ss);
    n.add_words("DH ss, as limbs", &reference::from_bytes(&ss));
    n.add("chaining key after e", &c1);
    n.add("chaining key after es", &c2);
    n.add("chaining key after ss", &c3);
    n.add("KDF pseudo-random key of (C, es)", &kdf::hmac(&c1, &[&es]));
    n.add("KDF pseudo-random key of (C, ss)", &kdf::hmac(&c2, &[&ss]));
    n.add("AEAD key for the static key", &k1);
    n.add("AEAD key for the timestamp", &k2);
    n.add(
        "one-time authenticator key of the static key's AEAD",
        &one_time_key(&k1, 0),
    );
    n.add(
        "one-time authenticator key of the timestamp's AEAD",
        &one_time_key(&k2, 0),
    );
    n.add("static private key A", &a_sk);
    n.add("static private key A, clamped", &reference::clamp(&a_sk));
    n.add("static private key B", &b_sk);
    n.add("static private key B, clamped", &reference::clamp(&b_sk));
    n.add("pre-shared key", &psk);
    scan.report("Tunnel::poll building an initiation");

    // ---- 2. responder: receive, identify, handle_initiation -----------------
    paint();
    call_deep(|| {
        let Incoming::Initiation(mut initiation) = b_dev.receive(now, a_addr, false, &mut init)
        else {
            panic!("expected an initiation")
        };
        b_dev.identify(&mut initiation).unwrap();
        // The identified initiation is a live value in this frame; the
        // snapshot below is taken after it has been dropped.
        match b
            .handle_initiation(now, &initiation, &mut out, &mut *rng)
            .unwrap()
            .received
        {
            Received::HandshakeResponse(tx) => resp.copy_from_slice(tx.datagram),
            other => panic!("{other:?}"),
        }
    });
    scan.take();

    // Whitepaper §5.4.3 and §5.4.5.
    let e_r = ephemeral_for(&rng.log, &resp[12..44]);
    let e_r_pub: [u8; 32] = resp[12..44].try_into().unwrap();
    let c4 = kdf::kdf1(&c3, &e_r_pub);
    let h_before_tau = blake2s::hash(&[&h, &e_r_pub]);
    let ee = x25519::x25519(&e_i, &e_r_pub);
    let c5 = kdf::kdf1(&c4, &ee);
    let se = x25519::x25519(&a_sk, &e_r_pub);
    let c6 = kdf::kdf1(&c5, &se);
    let (c7, tau, k3) = kdf::kdf3(&c6, &psk);
    let h_tau = blake2s::hash(&[&h_before_tau, &tau]);
    let (t_i, t_r) = kdf::kdf2(&c7, &[]);
    let n = &mut scan.needles;
    n.add("responder's ephemeral private key", &e_r);
    n.add(
        "responder's ephemeral private key, clamped",
        &reference::clamp(&e_r),
    );
    n.add("DH ee", &ee);
    n.add_words("DH ee, as limbs", &reference::from_bytes(&ee));
    n.add("DH se", &se);
    n.add_words("DH se, as limbs", &reference::from_bytes(&se));
    n.add("chaining key after e (response)", &c4);
    n.add("chaining key after ee", &c5);
    n.add("chaining key after se", &c6);
    n.add("final chaining key", &c7);
    n.add("KDF pseudo-random key of (C, ee)", &kdf::hmac(&c4, &[&ee]));
    n.add("KDF pseudo-random key of (C, se)", &kdf::hmac(&c5, &[&se]));
    n.add(
        "KDF pseudo-random key of (C, psk)",
        &kdf::hmac(&c6, &[&psk]),
    );
    n.add(
        "KDF pseudo-random key of the transport keys",
        &kdf::hmac(&c7, &[&[]]),
    );
    n.add("tau (from the pre-shared key)", &tau);
    n.add("AEAD key for the empty payload", &k3);
    n.add(
        "one-time authenticator key of the empty payload's AEAD",
        &one_time_key(&k3, 0),
    );
    n.add("hash after mixing tau", &h_tau);
    n.add("transport key, initiator to responder", &t_i);
    n.add("transport key, responder to initiator", &t_r);
    // A keystream kernel has the key as words, one to a register.
    n.add_words32("transport key, initiator to responder, word by word", &t_i);
    n.add_words32("transport key, responder to initiator, word by word", &t_r);
    scan.report("Device::receive + Device::identify + Tunnel::handle_initiation");

    // ---- 3. initiator: a forged response (valid mac1, bad tag) ---------------
    // mac1 needs only A's public key. The initiator derives the same
    // secrets as for the genuine response and then rejects it.
    let mut forged = resp.clone();
    forged[44] ^= 1;
    let mac1_key = blake2s::hash(&[b"mac1----", &a_pub]);
    let mac1 = blake2s::mac(&mac1_key, &[&forged[..60]]);
    forged[60..76].copy_from_slice(&mac1);
    paint();
    let rejected = call_deep(|| {
        let handled = a_dev
            .receive_for(&mut a, now, b_addr, false, &mut forged, &mut out, &mut *rng)
            .unwrap();
        matches!(handled.received, Received::Dropped(_))
    });
    scan.take();
    assert!(rejected, "the forged response was not rejected");
    scan.report("receive_for(a forged handshake response), rejected");

    // ---- 4. initiator: the genuine response -----------------------------------
    paint();
    call_deep(|| {
        let handled = a_dev
            .receive_for(&mut a, now, b_addr, false, &mut resp, &mut out, &mut *rng)
            .unwrap();
        assert!(matches!(handled.received, Received::HandshakeComplete));
    });
    scan.take();
    scan.report("receive_for(the handshake response), handshake complete");

    // ---- 5. transport, both sizes of AEAD input ---------------------------------
    for payload_len in [32usize, 1400] {
        paint();
        let len = call_deep(|| {
            match a
                .encapsulate(now, &vec![0x42u8; payload_len], &mut wire)
                .unwrap()
            {
                Encapsulated::Transport(tx) => tx.datagram.len(),
                other => panic!("{other:?}"),
            }
        });
        scan.take();
        // What this packet's AEAD worked with (whitepaper §5.4.6).
        let counter = u64::from_le_bytes(wire[8..16].try_into().unwrap());
        let otk = one_time_key(&t_i, counter);
        assert_eq!(tag(&otk, &[], &wire[16..len - 16]), wire[len - 16..len]);
        let n = &mut scan.needles;
        let which = format!("the {payload_len}-byte packet");
        n.add(&format!("one-time authenticator key of {which}"), &otk);
        let half = |at: usize| u64::from_le_bytes(otk[at..at + 8].try_into().unwrap());
        n.add_words(
            &format!("authenticator key of {which}, as Poly1305 has it (r, clamped)"),
            &[
                half(0) & 0x0fff_fffc_0fff_ffff,
                half(8) & 0x0fff_fffc_0fff_fffc,
            ],
        );
        n.add_words(
            &format!("authenticator key of {which}, as Poly1305 has it (s)"),
            &[half(16), half(24)],
        );
        add_accumulator(n, which.as_str(), &otk, &wire[len - 16..len]);
        let nonce = aead::nonce_from_counter(counter);
        n.add(
            &format!("keystream of {which} (its first block)"),
            &chacha20::block(&t_i, 1, &nonce),
        );
        if payload_len > 128 {
            n.add(
                &format!("keystream of {which} (its third block)"),
                &chacha20::block(&t_i, 3, &nonce),
            );
        }
        scan.report(&format!("Tunnel::encapsulate, {payload_len} bytes"));

        // A copy with one bit of the ciphertext changed: rejected — and
        // the tag that would have made it pass must not be lying about.
        let mut flipped = wire[..len].to_vec();
        flipped[16] ^= 0x80;
        let would_pass = tag(&otk, &[], &flipped[16..len - 16]);
        paint();
        let rejected = call_deep(|| {
            let handled = b_dev
                .receive_for(
                    &mut b,
                    now,
                    a_addr,
                    false,
                    &mut flipped,
                    &mut out,
                    &mut *rng,
                )
                .unwrap();
            matches!(handled.received, Received::Dropped(_))
        });
        scan.take();
        assert!(rejected, "the forged packet was not rejected");
        scan.needles.add(
            &format!("the tag that authenticates a forged copy of {which}"),
            &would_pass,
        );
        scan.report(&format!(
            "receive_for(transport data with a flipped bit), {payload_len} bytes, rejected"
        ));

        paint();
        call_deep(|| {
            let handled = b_dev
                .receive_for(
                    &mut b,
                    now,
                    a_addr,
                    false,
                    &mut wire[..len],
                    &mut out,
                    &mut *rng,
                )
                .unwrap();
            assert!(matches!(handled.received, Received::Data(_)));
        });
        scan.take();
        scan.report(&format!("receive_for(transport data), {payload_len} bytes"));
    }

    // ---- 6. a recorded initiation with its timestamp changed -------------------
    // It decrypts as far as the static key and is rejected at the
    // timestamp. The tag that authenticates the changed timestamp is
    // what would let a recording be played again.
    let mut forged = init_wire.clone();
    forged[88] ^= 0x01;
    let mac1_key = blake2s::hash(&[b"mac1----", &b_pub]);
    let mac1 = blake2s::mac(&mac1_key, &[&forged[..116]]);
    forged[116..132].copy_from_slice(&mac1);
    let would_pass = tag(&one_time_key(&k2, 0), &h_timestamp, &forged[88..100]);
    let soon = Ticks::from_secs(20);
    paint();
    let rejected = call_deep(|| {
        let handled = b_dev
            .receive_for(
                &mut b,
                soon,
                a_addr,
                false,
                &mut forged,
                &mut out,
                &mut *rng,
            )
            .unwrap();
        matches!(handled.received, Received::Dropped(_))
    });
    scan.take();
    assert!(
        rejected,
        "the initiation with a changed timestamp was not rejected"
    );
    scan.needles.add(
        "the tag that authenticates a changed timestamp",
        &would_pass,
    );
    scan.report("receive_for(an initiation with a changed timestamp), rejected");

    // ---- 7. an initiation the tunnel identifies itself (one peer) --------------
    let later = Ticks::from_secs(100);
    a.request_handshake(later);
    let mut init2 = match a.poll(later, &mut out, &mut *rng).unwrap() {
        PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
        other => panic!("{other:?}"),
    };
    let init2_wire = init2.clone();
    paint();
    let resp2 = call_deep(|| {
        match b_dev
            .receive_for(
                &mut b, later, a_addr, false, &mut init2, &mut out, &mut *rng,
            )
            .unwrap()
            .received
        {
            Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
            other => panic!("{other:?}"),
        }
    });
    scan.take();
    {
        let e_i = ephemeral_for(&rng.log, &init2_wire[8..40]);
        let e_r = ephemeral_for(&rng.log, &resp2[12..44]);
        let e_i_pub: [u8; 32] = init2_wire[8..40].try_into().unwrap();
        let e_r_pub: [u8; 32] = resp2[12..44].try_into().unwrap();
        let c = kdf::kdf1(&c0, &e_i_pub);
        let es = x25519::x25519(&e_i, &b_pub);
        let (c, k1) = kdf::kdf2(&c, &es);
        let (c_ss, k2) = kdf::kdf2(&c, &ss);
        let c = kdf::kdf1(&c_ss, &e_r_pub);
        let ee = x25519::x25519(&e_i, &e_r_pub);
        let c = kdf::kdf1(&c, &ee);
        let se = x25519::x25519(&a_sk, &e_r_pub);
        let c_se = kdf::kdf1(&c, &se);
        let (c, tau, k3) = kdf::kdf3(&c_se, &psk);
        let (t_i, t_r) = kdf::kdf2(&c, &[]);
        let n = &mut scan.needles;
        n.add("second handshake: initiator's ephemeral private key", &e_i);
        n.add("second handshake: responder's ephemeral private key", &e_r);
        n.add("second handshake: DH es", &es);
        n.add_words(
            "second handshake: DH es, as limbs",
            &reference::from_bytes(&es),
        );
        n.add("second handshake: DH ee", &ee);
        n.add_words(
            "second handshake: DH ee, as limbs",
            &reference::from_bytes(&ee),
        );
        n.add("second handshake: DH se", &se);
        n.add_words(
            "second handshake: DH se, as limbs",
            &reference::from_bytes(&se),
        );
        n.add("second handshake: chaining key after ss", &c_ss);
        n.add("second handshake: final chaining key", &c);
        n.add(
            "second handshake: KDF pseudo-random key of (C, psk)",
            &kdf::hmac(&c_se, &[&psk]),
        );
        n.add(
            "second handshake: KDF pseudo-random key of the transport keys",
            &kdf::hmac(&c, &[&[]]),
        );
        n.add("second handshake: AEAD key for the static key", &k1);
        n.add("second handshake: AEAD key for the timestamp", &k2);
        n.add("second handshake: AEAD key for the empty payload", &k3);
        n.add("second handshake: tau", &tau);
        n.add(
            "second handshake: transport key, initiator to responder",
            &t_i,
        );
        n.add(
            "second handshake: transport key, responder to initiator",
            &t_r,
        );
    }
    scan.report("receive_for(an initiation), identified by the tunnel");
    let mut resp2 = resp2;
    paint();
    call_deep(|| {
        let handled = a_dev
            .receive_for(
                &mut a, later, b_addr, false, &mut resp2, &mut out, &mut *rng,
            )
            .unwrap();
        assert!(matches!(handled.received, Received::HandshakeComplete));
    });
    scan.take();
    scan.report("receive_for(the second handshake response)");

    // ---- 8. cookies under load ------------------------------------------------------
    let t = Ticks::from_secs(200);
    a.request_handshake(t);
    let mut init3 = match a.poll(t, &mut out, &mut *rng).unwrap() {
        PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
        other => panic!("{other:?}"),
    };
    let log_before = rng.log.len();
    paint();
    let mut cookie_reply = call_deep(|| match b_dev.receive(t, a_addr, true, &mut init3) {
        Incoming::CookieRequired(challenge) => b_dev
            .cookie_reply(t, &challenge, &mut out, &mut *rng)
            .unwrap()
            .datagram
            .to_vec(),
        other => panic!("{other:?}"),
    });
    scan.take();
    let secret: [u8; 32] = rng.log[log_before].as_slice().try_into().unwrap();
    let cookie = blake2s::mac(&secret, &[&[192, 0, 2, 1, 0xca, 0x6c]]);
    scan.needles.add("cookie secret", &secret);
    scan.needles.add("cookie for the source address", &cookie);
    scan.report("Device::receive under load + Device::cookie_reply");

    paint();
    call_deep(|| {
        let handled = a_dev
            .receive_for(
                &mut a,
                t,
                b_addr,
                false,
                &mut cookie_reply,
                &mut out,
                &mut *rng,
            )
            .unwrap();
        assert!(matches!(handled.received, Received::CookieStored));
    });
    scan.take();
    scan.report("receive_for(a cookie reply), cookie stored");

    let retry = Ticks::from_secs(206);
    paint();
    let mut init4 = call_deep(|| match a.poll(retry, &mut out, &mut *rng).unwrap() {
        PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
        other => panic!("{other:?}"),
    });
    scan.take();
    scan.report("Tunnel::poll retransmitting with mac2");

    // The same message with a wrong mac2: refused — and the mac2 that
    // would have been right is the proof of address it lacks.
    let right_mac2: [u8; 16] = init4[132..148].try_into().unwrap();
    let mut wrong = init4.clone();
    wrong[132] ^= 1;
    paint();
    let refused = call_deep(|| {
        matches!(
            b_dev.receive(retry, a_addr, true, &mut wrong),
            Incoming::CookieRequired(_)
        )
    });
    scan.take();
    assert!(refused, "a wrong mac2 was accepted");
    scan.needles
        .add("the mac2 that proves the source address", &right_mac2);
    scan.report("Device::receive under load, wrong mac2");

    paint();
    let passed = call_deep(|| {
        matches!(
            b_dev.receive(retry, a_addr, true, &mut init4),
            Incoming::Initiation(_)
        )
    });
    scan.take();
    assert!(passed, "the cookie was not accepted");
    scan.report("Device::receive under load, valid mac2");

    // ---- 9. a long run, reset, drop ---------------------------------------------------
    paint();
    call_deep(|| {
        for round in 0..2000u64 {
            let t = Ticks::from_nanos(210_000_000_000 + round * 1_000_000);
            let len = match a.encapsulate(t, &[0x42u8; 1400], &mut wire).unwrap() {
                Encapsulated::Transport(tx) => tx.datagram.len(),
                other => panic!("{other:?}"),
            };
            let _ = b_dev
                .receive_for(
                    &mut b,
                    t,
                    a_addr,
                    false,
                    &mut wire[..len],
                    &mut out,
                    &mut *rng,
                )
                .unwrap();
            let len = match b.encapsulate(t, &[0x24u8; 64], &mut wire).unwrap() {
                Encapsulated::Transport(tx) => tx.datagram.len(),
                other => panic!("{other:?}"),
            };
            let _ = a_dev
                .receive_for(
                    &mut a,
                    t,
                    b_addr,
                    false,
                    &mut wire[..len],
                    &mut out,
                    &mut *rng,
                )
                .unwrap();
            while !matches!(a.poll(t, &mut out, &mut *rng).unwrap(), PollOutput::Idle) {}
            while !matches!(b.poll(t, &mut out, &mut *rng).unwrap(), PollOutput::Idle) {}
        }
    });
    scan.take();
    scan.report("8000 transport calls and polls on both tunnels");

    paint();
    call_deep(|| {
        a.reset();
        b.reset();
    });
    scan.take();
    scan.report("Tunnel::reset on both tunnels");

    paint();
    call_deep(|| {
        drop(a);
        drop(b);
        drop(a_dev);
        drop(b_dev);
    });
    scan.take();
    scan.report("dropping both tunnels and both devices");
    let _ = C::name();
}
