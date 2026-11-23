//! SipHash-2-4 with 64-bit output (Aumasson & Bernstein, 2012).
//!
//! This is **not** part of the WireGuard protocol and never touches its
//! keys or its traffic. It has two jobs here, both this implementation's
//! own business:
//!
//! * it is the keyed round function of the session-index codec
//!   ([`crate::PeerId`] in `src/index.rs`), which makes the 32-bit indices
//!   we put on the wire look random while letting a [`crate::Device`]
//!   route them without a table;
//! * the nonces of cookie replies are derived with it from a counter
//!   (`src/cookie.rs`), so that they do not repeat and do not count the
//!   replies in public either.
//!
//! The Linux implementation uses the same function for another purpose:
//! it keys the hash table it looks peers up in by *public key* with it
//! (and the table of its rate limiter with the smaller HalfSipHash). Its
//! session indices are random numbers kept in a plain table — which is
//! what the codec here does without.
//!
//! Validated against the reference vectors from the SipHash paper and
//! reference implementation.

/// One SipRound.
#[inline]
const fn sipround(v: [u64; 4]) -> [u64; 4] {
    let [mut v0, mut v1, mut v2, mut v3] = v;
    v0 = v0.wrapping_add(v1);
    v1 = v1.rotate_left(13);
    v1 ^= v0;
    v0 = v0.rotate_left(32);
    v2 = v2.wrapping_add(v3);
    v3 = v3.rotate_left(16);
    v3 ^= v2;
    v0 = v0.wrapping_add(v3);
    v3 = v3.rotate_left(21);
    v3 ^= v0;
    v2 = v2.wrapping_add(v1);
    v1 = v1.rotate_left(17);
    v1 ^= v2;
    v2 = v2.rotate_left(32);
    [v0, v1, v2, v3]
}

/// Absorb one message word: `c = 2` compression rounds.
#[inline]
const fn absorb(mut v: [u64; 4], m: u64) -> [u64; 4] {
    v[3] ^= m;
    v = sipround(sipround(v));
    v[0] ^= m;
    v
}

/// SipHash-2-4 of `data` under a 128-bit `key`.
#[must_use]
pub fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    let [k0, k1] = key_words(key);
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];

    let mut rest = data;
    while let Some((word, tail)) = rest.split_first_chunk::<8>() {
        v = absorb(v, u64::from_le_bytes(*word));
        rest = tail;
    }
    // Final word: the 0–7 leftover bytes, then the message length mod 256
    // in the top byte.
    let mut last = [0u8; 8];
    for (d, s) in last.iter_mut().zip(rest.iter()) {
        *d = *s;
    }
    let [l0, l1, l2, l3, l4, l5, l6, _] = last;
    // `& 0xff` makes the narrowing exact.
    let len_byte = (data.len() & 0xff) as u8;
    v = absorb(
        v,
        u64::from_le_bytes([l0, l1, l2, l3, l4, l5, l6, len_byte]),
    );

    // Finalization: `d = 4` rounds.
    v[2] ^= 0xff;
    v = sipround(sipround(sipround(sipround(v))));
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// The two words SipHash works with, from the sixteen bytes of a key.
#[must_use]
pub const fn key_words(key: &[u8; 16]) -> [u64; 2] {
    let [
        a0,
        a1,
        a2,
        a3,
        a4,
        a5,
        a6,
        a7,
        b0,
        b1,
        b2,
        b3,
        b4,
        b5,
        b6,
        b7,
    ] = *key;
    [
        u64::from_le_bytes([a0, a1, a2, a3, a4, a5, a6, a7]),
        u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]),
    ]
}

/// SipHash-2-4 of a three-byte message, under a key given as its two
/// words ([`key_words`]): the same function as [`siphash24`] on
/// `&[a, b, c]`, for callers that hash very little very often.
///
/// A message shorter than eight bytes shares its one word with the length
/// byte, so there is a single absorption before the finalisation — six
/// SipRounds, where an eight-byte message takes eight — and nothing is
/// loaded from or stored to memory on the way.
#[inline]
#[must_use]
pub const fn siphash24_3(key: [u64; 2], msg: [u8; 3]) -> u64 {
    let [k0, k1] = key;
    let [a, b, c] = msg;
    let mut v = absorb(
        [
            k0 ^ 0x736f_6d65_7073_6575,
            k1 ^ 0x646f_7261_6e64_6f6d,
            k0 ^ 0x6c79_6765_6e65_7261,
            k1 ^ 0x7465_6462_7974_6573,
        ],
        // The three bytes, and the length in the top byte.
        u64::from_le_bytes([a, b, c, 0, 0, 0, 0, 3]),
    );
    v[2] ^= 0xff;
    v = sipround(sipround(sipround(sipround(v))));
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;
    use std::vec::Vec;

    /// The three-byte form is SipHash-2-4, not a variant of it.
    #[test]
    fn the_three_byte_form_is_the_same_function() {
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        let words = key_words(&key);
        assert_eq!(
            words,
            [
                u64::from_le_bytes(key[..8].try_into().unwrap_or([0; 8])),
                u64::from_le_bytes(key[8..].try_into().unwrap_or([0; 8]))
            ]
        );
        for a in 0..=255u8 {
            for (b, c) in [(0u8, 0u8), (1, 2), (0xff, 0xfe), (a, a.wrapping_mul(3))] {
                assert_eq!(siphash24_3(words, [a, b, c]), siphash24(&key, &[a, b, c]));
                assert_eq!(siphash24_3(words, [c, a, b]), siphash24(&key, &[c, a, b]));
                assert_eq!(siphash24_3(words, [b, c, a]), siphash24(&key, &[b, c, a]));
            }
        }
        // The reference vector for the message 00 01 02 under 00 … 0f.
        let mut k = [0u8; 16];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(siphash24_3(key_words(&k), [0, 1, 2]), 0x8567_6696_d7fb_7e2d);
    }

    /// Reference outputs for key `00 01 … 0f` and messages `00 01 … (n−1)`
    /// for `n = 0..=16`: the first entries of the SipHash-2-4 64-bit table
    /// in the reference implementation's `vectors.h` (also the Linux
    /// kernel's `test_vectors_siphash`). Entry 15 is the worked example in
    /// Appendix A of the SipHash paper.
    const REFERENCE: [u64; 17] = [
        0x726f_db47_dd0e_0e31,
        0x74f8_39c5_93dc_67fd,
        0x0d6c_8009_d9a9_4f5a,
        0x8567_6696_d7fb_7e2d,
        0xcf27_94e0_2771_87b7,
        0x1876_5564_cd99_a68d,
        0xcbc9_466e_58fe_e3ce,
        0xab02_00f5_8b01_d137,
        0x93f5_f579_9a93_2462,
        0x9e00_82df_0ba9_e4b0,
        0x7a5d_bbc5_94dd_b9f3,
        0xf4b3_2f46_226b_ada7,
        0x751e_8fbc_860e_e5fb,
        0x14ea_5627_c084_3d90,
        0xf723_ca90_8e7a_f2ee,
        0xa129_ca61_49be_45e5,
        0x3f2a_cc7f_57c2_9bdb,
    ];

    fn key() -> [u8; 16] {
        let mut k = [0u8; 16];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn reference_vectors() {
        let key = key();
        for (n, expected) in REFERENCE.iter().enumerate() {
            let msg: Vec<u8> = (0..n).map(|i| i as u8).collect();
            assert_eq!(siphash24(&key, &msg), *expected, "message length {n}");
        }
        // The last entry of the reference table (63-byte message).
        let msg: Vec<u8> = (0..63u8).collect();
        assert_eq!(siphash24(&key, &msg), 0x958a_324c_eb06_4572);
    }

    #[test]
    fn key_and_message_sensitivity() {
        let k = key();
        let base = siphash24(&k, b"index");
        let mut k2 = k;
        k2[15] ^= 1;
        assert_ne!(siphash24(&k2, b"index"), base);
        assert_ne!(siphash24(&k, b"indey"), base);
        // Length is bound in: a trailing zero byte changes the output.
        assert_ne!(siphash24(&k, b"index\0"), base);
    }
}
