//! Property-fuzz the crypto layer: seal/open round-trips, in-place vs
//! copying agreement in both directions, forgery rejection without
//! touching the buffer, the provider seam, and X25519 commutativity, all
//! on fuzzer-chosen inputs.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wireguard_sans_io::crypto::{CryptoProvider, InTree, aead, siphash, x25519};

fuzz_target!(|input: ([u8; 32], [u8; 32], u64, &[u8], &[u8])| {
    let (key, key2, counter, aad, plaintext) = input;
    if plaintext.len() > 4096 {
        return;
    }
    let nonce = aead::nonce_from_counter(counter);

    // seal → open round-trip.
    let mut sealed = vec![0u8; plaintext.len() + aead::TAG_LEN];
    let n = aead::seal(&key, &nonce, aad, plaintext, &mut sealed).unwrap();
    assert_eq!(n, sealed.len());
    let mut opened = vec![0u8; plaintext.len()];
    assert_eq!(
        aead::open(&key, &nonce, aad, &sealed, &mut opened),
        Ok(plaintext.len())
    );
    assert_eq!(opened, plaintext);

    // In-place sealing must agree byte-for-byte…
    let mut inplace = vec![0u8; plaintext.len() + aead::TAG_LEN];
    inplace[..plaintext.len()].copy_from_slice(plaintext);
    aead::seal_in_place(&key, &nonce, aad, plaintext.len(), &mut inplace).unwrap();
    assert_eq!(inplace, sealed);
    // …and so must in-place opening.
    assert_eq!(
        aead::open_in_place(&key, &nonce, aad, &mut inplace),
        Ok(plaintext.len())
    );
    assert_eq!(&inplace[..plaintext.len()], plaintext);

    // The provider seam is the same function.
    let mut via_provider = vec![0u8; plaintext.len() + aead::TAG_LEN];
    via_provider[..plaintext.len()].copy_from_slice(plaintext);
    <InTree as CryptoProvider>::seal_in_place(
        &key,
        counter,
        aad,
        plaintext.len(),
        &mut via_provider,
    )
    .unwrap();
    assert_eq!(via_provider, sealed);
    assert_eq!(
        <InTree as CryptoProvider>::open_in_place(&key, counter, aad, &mut via_provider),
        Some(plaintext.len())
    );
    assert_eq!(&via_provider[..plaintext.len()], plaintext);

    // A different key or nonce must not open it — and an in-place open
    // that fails leaves the buffer exactly as it was.
    if key2 != key {
        let mut out = vec![0u8; plaintext.len()];
        assert!(aead::open(&key2, &nonce, aad, &sealed, &mut out).is_err());
        let mut buf = sealed.clone();
        assert!(aead::open_in_place(&key2, &nonce, aad, &mut buf).is_err());
        assert_eq!(buf, sealed);
    }
    let other_nonce = aead::nonce_from_counter(counter.wrapping_add(1));
    let mut out = vec![0u8; plaintext.len()];
    assert!(aead::open(&key, &other_nonce, aad, &sealed, &mut out).is_err());
    let mut buf = sealed.clone();
    assert_eq!(
        <InTree as CryptoProvider>::open_in_place(&key, counter.wrapping_add(1), aad, &mut buf),
        None
    );
    assert_eq!(buf, sealed);

    // Tag truncation must fail.
    assert!(aead::open(&key, &nonce, aad, &sealed[..sealed.len() - 1], &mut out).is_err());
    let mut truncated = sealed[..sealed.len() - 1].to_vec();
    assert!(aead::open_in_place(&key, &nonce, aad, &mut truncated).is_err());

    // X25519: commutativity on fuzzer keys (the core algebraic property),
    // plus clamping idempotence.
    let ga = x25519::x25519_base(&key);
    let gb = x25519::x25519_base(&key2);
    assert_eq!(x25519::x25519(&key, &gb), x25519::x25519(&key2, &ga));
    let clamped = x25519::clamp_scalar(key);
    assert_eq!(x25519::clamp_scalar(clamped), clamped);
    assert_eq!(x25519::x25519_base(&clamped), ga);

    // SipHash-2-4 against a second implementation, written here from the
    // reference description, on both fuzzer-chosen inputs.
    let k16: [u8; 16] = key[..16].try_into().unwrap();
    assert_eq!(
        siphash::siphash24(&k16, plaintext),
        reference_siphash24(&k16, plaintext)
    );
    assert_eq!(
        siphash::siphash24(&k16, aad),
        reference_siphash24(&k16, aad)
    );
});

/// SipHash-2-4 (Aumasson & Bernstein), straight from the paper: the
/// oracle the in-tree implementation is compared with.
fn reference_siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13);
        v[1] ^= v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16);
        v[3] ^= v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21);
        v[3] ^= v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17);
        v[1] ^= v[2];
        v[2] = v[2].rotate_left(32);
    }
    let k0 = u64::from_le_bytes(key[..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..].try_into().unwrap());
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let mut blocks = data.chunks_exact(8);
    for block in blocks.by_ref() {
        let m = u64::from_le_bytes(block.try_into().unwrap());
        v[3] ^= m;
        round(&mut v);
        round(&mut v);
        v[0] ^= m;
    }
    // The last block: the remaining bytes, and the length in the top byte.
    let mut last = [0u8; 8];
    let tail = blocks.remainder();
    last[..tail.len()].copy_from_slice(tail);
    last[7] = data.len() as u8;
    let m = u64::from_le_bytes(last);
    v[3] ^= m;
    round(&mut v);
    round(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}
