//! Bytes to words, words to bytes, and copies — written with iterators
//! and the slice methods that return an `Option`, and nothing else.
//!
//! The obvious tools each carry a panic: `chunks_exact` for a chunk size
//! of zero, `split_at` for a split point past the end,
//! `copy_from_slice` for lengths that differ. With the constant shapes
//! they would be used with here, none of them can fire, and a compiler
//! that optimises for speed removes them. One that optimises for size
//! keeps the library functions as they are, check and panic included —
//! and "no panic machinery in the image" stops being true although
//! nothing about the code has changed. What cannot panic by construction
//! does not depend on the optimiser. (`clippy.toml` keeps those methods
//! out of the library.)

/// Read little-endian words from the front of `bytes` into `words`: as
/// many as both hold.
#[inline(always)]
pub(crate) fn load_le32<'a>(words: impl IntoIterator<Item = &'a mut u32>, bytes: &[u8]) {
    let mut rest = bytes;
    for word in words {
        let Some((chunk, tail)) = rest.split_first_chunk::<4>() else {
            return;
        };
        *word = u32::from_le_bytes(*chunk);
        rest = tail;
    }
}

/// [`load_le32`] for 64-bit words.
#[inline(always)]
pub(crate) fn load_le64<'a>(words: impl IntoIterator<Item = &'a mut u64>, bytes: &[u8]) {
    let mut rest = bytes;
    for word in words {
        let Some((chunk, tail)) = rest.split_first_chunk::<8>() else {
            return;
        };
        *word = u64::from_le_bytes(*chunk);
        rest = tail;
    }
}

/// Write `words` to the front of `out`, little-endian: as many whole
/// words as fit.
#[inline(always)]
pub(crate) fn store_le32(out: &mut [u8], words: impl IntoIterator<Item = u32>) {
    let mut rest = out;
    for word in words {
        let Some((chunk, tail)) = core::mem::take(&mut rest).split_first_chunk_mut::<4>() else {
            return;
        };
        *chunk = word.to_le_bytes();
        rest = tail;
    }
}

/// [`store_le32`] for 64-bit words.
#[inline(always)]
pub(crate) fn store_le64(out: &mut [u8], words: impl IntoIterator<Item = u64>) {
    let mut rest = out;
    for word in words {
        let Some((chunk, tail)) = core::mem::take(&mut rest).split_first_chunk_mut::<8>() else {
            return;
        };
        *chunk = word.to_le_bytes();
        rest = tail;
    }
}

/// Copy `src` to the front of `dst`: as many bytes as both hold.
#[inline(always)]
pub(crate) fn copy(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d = *s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_round_trip_and_short_buffers_are_not_overrun() {
        let bytes: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut words = [0u32; 4];
        load_le32(words.iter_mut(), &bytes);
        assert_eq!(words, [0x0302_0100, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c]);
        let mut back = [0u8; 16];
        store_le32(&mut back, words);
        assert_eq!(back, bytes);

        let mut wide = [0u64; 2];
        load_le64(wide.iter_mut(), &bytes);
        assert_eq!(wide, [0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908]);
        let mut back = [0u8; 16];
        store_le64(&mut back, wide);
        assert_eq!(back, bytes);

        // Fewer bytes than words: the words without bytes are left alone,
        // and a trailing part of a word is not read.
        let mut words = [0xffff_ffffu32; 4];
        load_le32(words.iter_mut(), &bytes[..7]);
        assert_eq!(words, [0x0302_0100, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff]);
        // Fewer words than bytes: the rest of the buffer is left alone;
        // more words than fit: whole words only.
        let mut out = [0xeeu8; 10];
        store_le32(&mut out, [0x0403_0201, 0x0807_0605, 0x0c0b_0a09]);
        assert_eq!(out, [1, 2, 3, 4, 5, 6, 7, 8, 0xee, 0xee]);
        let mut out = [0xeeu8; 9];
        store_le64(&mut out, [0x0807_0605_0403_0201, 1]);
        assert_eq!(out, [1, 2, 3, 4, 5, 6, 7, 8, 0xee]);

        let mut dst = [0u8; 4];
        copy(&mut dst, &[1, 2, 3, 4, 5, 6]);
        assert_eq!(dst, [1, 2, 3, 4]);
        copy(&mut dst, &[9]);
        assert_eq!(dst, [9, 2, 3, 4]);
        copy(&mut dst, &[]);
        assert_eq!(dst, [9, 2, 3, 4]);
    }
}
