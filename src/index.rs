//! Session indices: which peer owns which 32-bit index, with no table.
//!
//! Every WireGuard message except a handshake initiation is addressed by a
//! 32-bit *receiver index* that the receiving side chose earlier. An
//! endpoint with several peers must map that index back to the right peer.
//! The reference implementations draw indices at random and keep a hash
//! table; that needs an allocator and a table that every peer's state
//! machine has to update.
//!
//! This crate instead makes the index *self-describing*:
//!
//! ```text
//!   index = E_k( peer_id (20 bits) ∥ slot (12 bits) )
//! ```
//!
//! * `peer_id` is the caller's own name for the peer ([`PeerId`]), fixed
//!   when the [`crate::Tunnel`] is created;
//! * `slot` is chosen by the tunnel, a different one for every handshake
//!   message it sends, so one tunnel never has two live sessions with the
//!   same index;
//! * `E_k` is a keyed permutation of 32-bit values, with a 128-bit key `k`
//!   drawn from the entropy source when the [`crate::Device`] is created.
//!   The device and each of its tunnels hold a copy (a tunnel makes its
//!   own indices); it goes nowhere else.
//!
//! [`crate::Device::receive`] inverts `E_k` and hands back the [`PeerId`]:
//! routing costs six short SipHash computations and no memory, two tunnels
//! can never collide, and nothing has to be kept in sync.
//!
//! # What an observer sees
//!
//! Without `k`, an index says nothing about the peer it belongs to, and
//! indices that have not been seen yet cannot be told from random 32-bit
//! values. So an observer cannot link two sessions of one peer by their
//! indices, and cannot guess a live index better than by chance (a
//! handful of live ones among 2³²). This is the property the reference
//! implementations get from drawing indices at random.
//!
//! One difference remains and is inherent to routing without a table. A
//! tunnel has 4096 indices and takes a new one for every handshake message
//! it sends — an initiation, each retransmission of it, each response —
//! so 4096 such messages later its indices come round again:
//!
//! * after about six days at the usual one handshake every two minutes;
//! * after under six hours for a tunnel that keeps retransmitting an
//!   initiation nobody answers (one every five seconds);
//! * after as little as 82 seconds if the peer sends initiations as fast
//!   as they are accepted (50 a second) — which only the peer itself can
//!   do.
//!
//! Someone who has recorded a tunnel's indices can from then on recognise
//! them: link that peer's sessions, and know the 4096 values among which
//! its live indices are. A forged datagram addressed to a live index costs
//! the receiver one Poly1305 pass before it is dropped (a forged handshake
//! response that hits the handshake in flight: two X25519) — which is what
//! anyone on the path, reading live indices off the wire, can make any
//! implementation do. Creating a new [`crate::Device`] (a new `k`) starts
//! over.
//!
//! What the recording is not meant to say is which index comes *next*.
//! The order in which a tunnel goes through its indices is a keyed
//! pseudo-random permutation of them, under a key drawn afresh for every
//! round (see [`IndexAllocator`]): two rounds are not related in any way
//! that is known to be computable from one of them and a part of the
//! other. (An earlier allocator used `slot = step·n + offset`; two such
//! rounds are affinely related, and one recorded round plus two
//! consecutive indices of the current one gave away every later index.)
//! Two limits. Towards the end of a round few indices are left, and
//! someone who has seen all the others knows which — but has then been
//! watching all along. And the claim is about effort, not information: a
//! permutation of 4096 values from a 128-bit key is one of far fewer than
//! there are, and a few hundred known positions determine it in
//! principle. No way of using that is known for this construction; if one
//! were found, the consequence would be the one above — forged handshake
//! responses that find the handshake in flight without being on the path,
//! two X25519 each, for as long as the device is not under load.
//!
//! # The permutation
//!
//! `E_k` is a six-round balanced Feistel network on two 16-bit halves whose
//! round function is SipHash-2-4 under `k` (domain-separated by the round
//! number), truncated to 16 bits. A Feistel network is a permutation for
//! any round function; six rounds with a pseudorandom round function leave
//! no generic distinguisher short of the full 2³² codebook, and one tunnel
//! only ever exposes 4096 of its inputs.
//!
//! This is defence in depth, not a confidentiality mechanism: if `E_k` were
//! broken outright, indices would become linkable and predictable — the
//! situation of implementations that put a peer number in the index in the
//! clear — and nothing else about the protocol would change.

use crate::Error;
use crate::crypto::ct;
use crate::crypto::siphash::{key_words, siphash24_3};
use crate::entropy::EntropySource;

/// The caller's name for one peer of a [`crate::Device`]: any number below
/// 2²⁰ (1 048 576, the Linux implementation's peer limit).
///
/// It is the key of *your* peer table. [`crate::Device::receive`] returns
/// it for every datagram addressed to one of that peer's sessions, so a
/// plain array or map lookup finds the [`crate::Tunnel`].
///
/// Two tunnels alive at the same time on one device must not share a
/// `PeerId`. (They cannot, if the id is the key you store them under.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(u32);

impl PeerId {
    /// Number of bits in a peer id.
    pub const BITS: u32 = 20;
    /// The largest valid value, `2²⁰ − 1`.
    pub const MAX: u32 = (1 << Self::BITS) - 1;

    /// A peer id, or `None` if `value` exceeds [`PeerId::MAX`].
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    /// The numeric value, always `<= PeerId::MAX`.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Bits of the per-tunnel slot counter.
const SLOT_BITS: u32 = 32 - PeerId::BITS;
/// Mask of the slot counter.
const SLOT_MASK: u32 = (1 << SLOT_BITS) - 1;
/// Feistel rounds.
const ROUNDS: u8 = 6;

/// Sixteen bytes from the entropy source as the two words of a SipHash
/// key; the bytes are wiped.
fn draw_key(rng: &mut dyn EntropySource) -> Result<[u64; 2], Error> {
    let mut bytes = [0u8; 16];
    let drawn = rng.fill(&mut bytes);
    let key = key_words(&bytes);
    ct::wipe_array(&mut bytes);
    match drawn {
        Ok(()) => Ok(key),
        Err(_) => Err(Error::EntropyFailure),
    }
}

/// The keyed permutation between `(peer, slot)` and a wire index.
#[derive(Clone)]
pub(crate) struct IndexCodec {
    /// The SipHash key, as the two words the function works with: every
    /// datagram a device receives is routed through this.
    key: [u64; 2],
}

impl IndexCodec {
    /// No key yet.
    pub(crate) const BLANK: Self = Self { key: [0; 2] };

    /// Draw a fresh codec key.
    #[cfg(test)]
    pub(crate) fn generate(rng: &mut dyn EntropySource) -> Result<Self, Error> {
        Ok(Self {
            key: draw_key(rng)?,
        })
    }

    /// Draw a fresh codec key into this codec.
    pub(crate) fn regenerate(&mut self, rng: &mut dyn EntropySource) -> Result<(), Error> {
        self.key = draw_key(rng)?;
        Ok(())
    }

    /// The Feistel round function: 16 bits in, 16 bits out. The message is
    /// the round number and the two bytes of the half — three bytes, the
    /// shortest SipHash computation there is.
    #[inline(always)]
    fn round(&self, round: u8, half: u16) -> u16 {
        let [h0, h1] = half.to_le_bytes();
        let out = siphash24_3(self.key, [round, h0, h1]);
        // `& 0xffff` makes the narrowing exact.
        (out & 0xffff) as u16
    }

    fn permute(&self, value: u32) -> u32 {
        let [b0, b1, b2, b3] = value.to_be_bytes();
        let mut left = u16::from_be_bytes([b0, b1]);
        let mut right = u16::from_be_bytes([b2, b3]);
        for round in 0..ROUNDS {
            let next = left ^ self.round(round, right);
            left = right;
            right = next;
        }
        let [l0, l1] = left.to_be_bytes();
        let [r0, r1] = right.to_be_bytes();
        u32::from_be_bytes([l0, l1, r0, r1])
    }

    fn unpermute(&self, value: u32) -> u32 {
        let [b0, b1, b2, b3] = value.to_be_bytes();
        let mut left = u16::from_be_bytes([b0, b1]);
        let mut right = u16::from_be_bytes([b2, b3]);
        for round in (0..ROUNDS).rev() {
            let previous = right ^ self.round(round, left);
            right = left;
            left = previous;
        }
        let [l0, l1] = left.to_be_bytes();
        let [r0, r1] = right.to_be_bytes();
        u32::from_be_bytes([l0, l1, r0, r1])
    }

    /// The wire index for `slot` of `peer`.
    pub(crate) fn encode(&self, peer: PeerId, slot: u16) -> u32 {
        // `peer.get() <= PeerId::MAX`, so the shift cannot lose bits.
        self.permute((peer.get() << SLOT_BITS) | (u32::from(slot) & SLOT_MASK))
    }

    /// The peer a wire index belongs to. Total: every 32-bit value decodes
    /// to *some* peer id; the tunnel it names then checks whether the index
    /// is one of its live ones.
    pub(crate) fn decode(&self, index: u32) -> PeerId {
        PeerId(self.unpermute(index) >> SLOT_BITS)
    }
}

impl Drop for IndexCodec {
    fn drop(&mut self) {
        ct::wipe_words(&mut self.key);
    }
}

impl core::fmt::Debug for IndexCodec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IndexCodec")
    }
}

/// Rounds of the Feistel network that orders a round of indices.
const ORDER_ROUNDS: u8 = 8;

/// One tunnel's supply of fresh indices.
///
/// The tunnel's 4096 slots are handed out in rounds: each round uses every
/// slot once, so an index does not come back before the round is over.
///
/// The order of a round is a keyed permutation of the slots, under a key
/// drawn for that round: the n-th index of the round is that of slot
/// `P(n)`, where `P` is an eight-round balanced Feistel network on two
/// 6-bit halves with SipHash-2-4 under the round's key as its round
/// function. (A Feistel network is a permutation whatever its round
/// function is.) What that is good for, and its limits, is in the module
/// documentation under "What an observer sees"; the wire never shows a
/// slot, only `E_k` of it.
pub(crate) struct IndexAllocator {
    codec: IndexCodec,
    peer: PeerId,
    /// How many slots of the current round have been handed out.
    used: u16,
    /// The key of the current round's order.
    order: [u64; 2],
}

impl core::fmt::Debug for IndexAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Not the order key: what comes next is nobody's business.
        f.debug_struct("IndexAllocator")
            .field("peer", &self.peer)
            .field("used", &self.used)
            .finish_non_exhaustive()
    }
}

impl Drop for IndexAllocator {
    fn drop(&mut self) {
        ct::wipe_words(&mut self.order);
    }
}

impl IndexAllocator {
    /// An allocator for nobody, with no key.
    pub(crate) const BLANK: Self = Self {
        codec: IndexCodec::BLANK,
        peer: PeerId(0),
        used: 0,
        order: [0; 2],
    };

    /// An allocator for `peer`. Its first round is in a random order, too,
    /// so a tunnel re-created under the same device does not start with
    /// its predecessor's first indices.
    #[cfg(test)]
    pub(crate) fn new(
        codec: IndexCodec,
        peer: PeerId,
        rng: &mut dyn EntropySource,
    ) -> Result<Self, Error> {
        let mut allocator = Self::BLANK;
        allocator.init(&codec, peer, rng)?;
        Ok(allocator)
    }

    /// Make this the allocator for `peer` under `codec`'s key, at the
    /// start of a round in a freshly drawn order — in place, so that
    /// neither key is copied anywhere but here.
    ///
    /// # Errors
    /// [`Error::EntropyFailure`]; the allocator is then as it was.
    pub(crate) fn init(
        &mut self,
        codec: &IndexCodec,
        peer: PeerId,
        rng: &mut dyn EntropySource,
    ) -> Result<(), Error> {
        self.order = draw_key(rng)?;
        self.codec.key = codec.key;
        self.peer = peer;
        self.used = 0;
        Ok(())
    }

    /// [`SLOT_MASK`] as a `u16` (it is 12 bits wide).
    const SLOT_MASK_U16: u16 = SLOT_MASK as u16;

    /// The slot of the `n`-th index of the current round (`n < 4096`).
    fn slot(&self, n: u16) -> u16 {
        let mut left = (n >> 6) & 0x3f;
        let mut right = n & 0x3f;
        for round in 0..ORDER_ROUNDS {
            // `right < 64` and `& 0x3f`: both narrowings are exact.
            let f = siphash24_3(self.order, [round, right as u8, 0]) & 0x3f;
            let next = left ^ (f as u16);
            left = right;
            right = next;
        }
        (left << 6) | right
    }

    /// The peer this allocator encodes.
    pub(crate) fn peer(&self) -> PeerId {
        self.peer
    }

    /// A fresh index, different from every index in `in_use`.
    ///
    /// Distinct slots give distinct indices, so within a round
    /// `in_use.len()` live indices can rule out at most that many
    /// candidates — and twice that many where the end of one round and the
    /// start of the next are both tried.
    ///
    /// # Errors
    /// [`Error::EntropyFailure`] when a new round has to be started and
    /// its order cannot be drawn; nothing has changed then.
    pub(crate) fn allocate(
        &mut self,
        in_use: &[Option<u32>],
        rng: &mut dyn EntropySource,
    ) -> Result<u32, Error> {
        for _ in 0..=in_use.len().saturating_mul(2) {
            if self.used > Self::SLOT_MASK_U16 {
                // Every slot has been used: the next round, in a new order.
                self.order = draw_key(rng)?;
                self.used = 0;
            }
            let slot = self.slot(self.used);
            self.used = self.used.saturating_add(1);
            let index = self.codec.encode(self.peer, slot);
            if !in_use.iter().flatten().any(|&live| live == index) {
                return Ok(index);
            }
        }
        Err(Error::Internal)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::testing::{DeterministicRng, FailingRng};
    use std::collections::HashSet;
    use std::vec::Vec;

    fn codec(key: [u8; 16]) -> IndexCodec {
        IndexCodec {
            key: key_words(&key),
        }
    }

    fn key_0_to_f() -> [u8; 16] {
        let mut k = [0u8; 16];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn peer_id_bounds() {
        assert_eq!(PeerId::MAX, 1_048_575);
        assert_eq!(PeerId::new(0).map(PeerId::get), Some(0));
        assert_eq!(PeerId::new(PeerId::MAX).map(PeerId::get), Some(PeerId::MAX));
        assert_eq!(PeerId::new(PeerId::MAX + 1), None);
        assert_eq!(PeerId::new(u32::MAX), None);
        assert_eq!(SLOT_BITS, 12);
        assert_eq!(SLOT_MASK, 0xfff);
    }

    /// Known answers computed by an independent implementation of the same
    /// construction (Python, written from the SipHash paper), pinning the
    /// exact bit layout: big-endian halves; the message is the round
    /// number, then the half's low and high byte; low 16 bits of the
    /// SipHash output.
    #[test]
    fn known_answers() {
        let c = codec(key_0_to_f());
        for (peer, slot, expected) in KNOWN_ANSWERS {
            let id = PeerId::new(peer).unwrap();
            assert_eq!(
                c.encode(id, slot),
                expected,
                "encode(peer={peer}, slot={slot})"
            );
            assert_eq!(c.decode(expected), id, "decode({expected:#010x})");
        }
    }

    /// `(peer, slot, index)` under the key `00 01 … 0f`.
    const KNOWN_ANSWERS: [(u32, u16, u32); 6] = [
        (0, 0x000, 0xbd51_d88a),
        (0, 0x001, 0xf67d_aeaf),
        (1, 0x000, 0xd604_72a6),
        (1234, 0xabc, 0x29bd_0978),
        (1_048_575, 0xfff, 0xc000_7d36),
        (65_536, 0x800, 0xc269_1d9b),
    ];

    #[test]
    fn decode_inverts_encode_for_every_slot_of_many_peers() {
        let mut rng = DeterministicRng::new(0x1d);
        let c = IndexCodec::generate(&mut rng).unwrap();
        for peer in [0u32, 1, 2, 255, 256, 65_535, 65_536, 999_999, PeerId::MAX] {
            let id = PeerId::new(peer).unwrap();
            for slot in 0..=0xfffu16 {
                assert_eq!(c.decode(c.encode(id, slot)), id, "peer={peer} slot={slot}");
            }
        }
    }

    #[test]
    fn permutation_is_a_bijection_on_a_dense_sample() {
        // unpermute(permute(x)) == x and permute(unpermute(y)) == y, and no
        // two inputs of a dense block share an output.
        let c = codec(key_0_to_f());
        let mut seen = HashSet::new();
        for x in (0..200_000u32).chain(u32::MAX - 1000..=u32::MAX) {
            let y = c.permute(x);
            assert_eq!(c.unpermute(y), x);
            assert_eq!(c.permute(c.unpermute(x)), x);
            assert!(seen.insert(y), "collision at {x}");
        }
    }

    #[test]
    fn indices_look_unrelated_to_their_peer() {
        // Consecutive slots of one peer and the same slot of consecutive
        // peers must differ in about half their bits, not in one or two.
        let c = codec(key_0_to_f());
        let id = |v| PeerId::new(v).unwrap();
        let mut total = 0u32;
        let mut pairs = 0u32;
        for i in 0..512u32 {
            total += (c.encode(id(7), i as u16) ^ c.encode(id(7), i as u16 + 1)).count_ones();
            total += (c.encode(id(i), 3) ^ c.encode(id(i + 1), 3)).count_ones();
            pairs += 2;
        }
        let mean = f64::from(total) / f64::from(pairs);
        assert!(
            (14.0..18.0).contains(&mean),
            "mean Hamming distance {mean:.2}, expected ≈ 16"
        );
        // A different key gives a different mapping.
        let mut other = key_0_to_f();
        other[0] ^= 1;
        assert_ne!(c.encode(id(1), 1), codec(other).encode(id(1), 1));
    }

    #[test]
    fn allocator_never_returns_a_live_index_and_uses_every_slot_once_a_round() {
        let mut rng = DeterministicRng::new(0xa110c);
        let c = IndexCodec::generate(&mut rng).unwrap();
        let peer = PeerId::new(1234).unwrap();
        let mut a = IndexAllocator::new(c.clone(), peer, &mut rng).unwrap();
        assert_eq!(a.peer(), peer);

        // 4096 consecutive allocations are pairwise distinct (one full
        // round), and all decode to the peer.
        let round = |a: &mut IndexAllocator, rng: &mut DeterministicRng| -> Vec<u32> {
            (0..4096).map(|_| a.allocate(&[], rng).unwrap()).collect()
        };
        let first = round(&mut a, &mut rng);
        let all: HashSet<u32> = first.iter().copied().collect();
        assert_eq!(all.len(), 4096);
        assert!(first.iter().all(|&i| c.decode(i) == peer));
        // They are the indices of the 4096 slots, each once.
        let slots: HashSet<u32> = (0..4096u16).map(|slot| c.encode(peer, slot)).collect();
        assert_eq!(all, slots);

        // The next rounds use the same indices — each exactly once again —
        // in another order: a recording of one round does not say what
        // comes next in another.
        let mut rounds = std::vec![first];
        for _ in 0..3 {
            let next = round(&mut a, &mut rng);
            assert_eq!(next.iter().copied().collect::<HashSet<u32>>(), all);
            for earlier in &rounds {
                let same_place = next.iter().zip(earlier).filter(|(x, y)| x == y).count();
                assert!(same_place < 40, "{same_place} of 4096 in the same place");
                // Not the same order from another starting point either:
                // the index that follows a given one differs nearly always.
                let follows = |seq: &[u32]| -> std::collections::HashMap<u32, u32> {
                    seq.windows(2).map(|w| (w[0], w[1])).collect()
                };
                let (a_next, b_next) = (follows(&next), follows(earlier));
                let same_successor = a_next
                    .iter()
                    .filter(|(k, v)| b_next.get(*k) == Some(*v))
                    .count();
                assert!(
                    same_successor < 40,
                    "{same_successor} of 4095 followed by the same index"
                );
            }
            rounds.push(next);
        }

        // Another allocator of the same peer starts somewhere else.
        let mut b = IndexAllocator::new(c.clone(), peer, &mut rng).unwrap();
        assert_ne!(
            (0..8)
                .map(|_| b.allocate(&[], &mut rng).unwrap())
                .collect::<Vec<_>>(),
            rounds[0][..8]
        );

        // With some indices live, the allocator skips exactly those.
        let mut b = IndexAllocator::new(c.clone(), peer, &mut rng).unwrap();
        b.used = 5;
        let upcoming: Vec<u32> = {
            let mut probe = IndexAllocator {
                codec: c.clone(),
                peer,
                used: b.used,
                order: b.order,
            };
            (0..6)
                .map(|_| probe.allocate(&[], &mut rng).unwrap())
                .collect()
        };
        let live = [
            Some(upcoming[0]),
            None,
            Some(upcoming[1]),
            Some(upcoming[2]),
        ];
        assert_eq!(b.allocate(&live, &mut rng).unwrap(), upcoming[3]);
        assert_eq!(b.allocate(&live, &mut rng).unwrap(), upcoming[4]);
    }

    /// The end of a round, with every index that is left in it live: the
    /// next round is started, and its first indices may be live ones as
    /// well (a round contains every index). Whatever the new order is, an
    /// index that is not live comes out.
    #[test]
    fn allocation_across_the_end_of_a_round_skips_live_indices_twice() {
        let c = codec(key_0_to_f());
        let peer = PeerId::new(99).unwrap();
        let mut hit_a_live_index_again = 0;
        for seed in 0..30_000u64 {
            let mut rng = DeterministicRng::new(seed);
            let mut a = IndexAllocator::new(c.clone(), peer, &mut rng).unwrap();
            a.used = 4092;
            let live: Vec<Option<u32>> = (4092..4096u16)
                .map(|n| Some(c.encode(peer, a.slot(n))))
                .collect();
            let got = a.allocate(&live, &mut rng);
            assert!(got.is_ok(), "seed {seed}: {got:?}");
            let got = got.unwrap();
            assert!(!live.contains(&Some(got)), "seed {seed}");
            assert_eq!(c.decode(got), peer);
            hit_a_live_index_again += usize::from(a.used > 1);
        }
        // The case this is about did come up.
        assert!(hit_a_live_index_again > 5, "{hit_a_live_index_again}");
    }

    /// The order of a round, against the independent model the codec's
    /// known answers come from: the first and the last slots of a round
    /// under the order key `f0 f1 … ff`.
    #[test]
    fn the_order_of_a_round_is_the_documented_permutation() {
        let order_key: [u8; 16] = core::array::from_fn(|i| 0xf0 ^ (i as u8));
        let a = IndexAllocator {
            codec: codec(key_0_to_f()),
            peer: PeerId::new(1).unwrap(),
            used: 0,
            order: key_words(&order_key),
        };
        let order: Vec<u16> = (0..4096).map(|n| a.slot(n)).collect();
        assert_eq!(
            order[..8],
            [0xe95, 0xdfe, 0xc33, 0xaca, 0x249, 0x75e, 0xe12, 0x4ff]
        );
        assert_eq!(order[4092..], [0xb66, 0x34d, 0x2e6, 0x1ef]);
    }

    /// Every round is a permutation of the slots, whatever its key; and
    /// two rounds have nothing simple to do with each other.
    #[test]
    fn every_order_is_a_permutation_and_no_two_are_related_by_position() {
        let mut rng = DeterministicRng::new(0x0bde);
        let c = codec(key_0_to_f());
        let peer = PeerId::new(5).unwrap();
        let mut orders: Vec<Vec<u16>> = Vec::new();
        for _ in 0..12 {
            let a = IndexAllocator::new(c.clone(), peer, &mut rng).unwrap();
            let order: Vec<u16> = (0..4096).map(|n| a.slot(n)).collect();
            let mut seen = [false; 4096];
            for &slot in &order {
                assert!(slot < 4096);
                assert!(!seen[usize::from(slot)], "slot {slot} twice");
                seen[usize::from(slot)] = true;
            }
            orders.push(order);
        }
        // The allocator this replaced had `slot = step·n + offset`: in the
        // positions of one round the next is an arithmetic progression,
        // and two consecutive slots give away the rest. Here that
        // prediction is right about as often as a guess among 4096.
        for (i, recorded) in orders.iter().enumerate() {
            let mut position = std::vec![0usize; 4096];
            for (n, &slot) in recorded.iter().enumerate() {
                position[usize::from(slot)] = n;
            }
            for later in orders.iter().skip(i + 1) {
                let predicted = later
                    .windows(3)
                    .filter(|w| {
                        let (p0, p1) = (position[usize::from(w[0])], position[usize::from(w[1])]);
                        recorded[(2 * p1 + 4096 - p0) % 4096] == w[2]
                    })
                    .count();
                assert!(predicted < 12, "{predicted} of 4094 predicted");
                // Nor is it the same order shifted, reversed or scaled:
                // the differences between consecutive positions take
                // nearly as many values as there are of them.
                let mut steps: Vec<usize> = later
                    .windows(2)
                    .map(|w| {
                        (position[usize::from(w[1])] + 4096 - position[usize::from(w[0])]) % 4096
                    })
                    .collect();
                steps.sort_unstable();
                steps.dedup();
                assert!(steps.len() > 2000, "{} distinct steps", steps.len());
            }
        }
    }

    /// A round cannot be started without entropy for its order: the
    /// allocation fails and can be repeated.
    #[test]
    fn a_new_round_needs_entropy_and_fails_cleanly_without_it() {
        let mut rng = DeterministicRng::new(0xa110d);
        let c = IndexCodec::generate(&mut rng).unwrap();
        let mut a = IndexAllocator::new(c, PeerId::new(7).unwrap(), &mut rng).unwrap();
        let first: HashSet<u32> = (0..4096)
            .map(|_| a.allocate(&[], &mut FailingRng).unwrap())
            .collect();
        assert_eq!(first.len(), 4096, "no entropy is needed within a round");
        assert_eq!(a.allocate(&[], &mut FailingRng), Err(Error::EntropyFailure));
        assert_eq!(a.allocate(&[], &mut FailingRng), Err(Error::EntropyFailure));
        assert!(first.contains(&a.allocate(&[], &mut rng).unwrap()));
    }

    #[test]
    fn entropy_failure_is_reported() {
        assert_eq!(
            IndexCodec::generate(&mut FailingRng).map(|_| ()),
            Err(Error::EntropyFailure)
        );
        let c = codec([1; 16]);
        assert_eq!(
            IndexAllocator::new(c, PeerId::new(1).unwrap(), &mut FailingRng).map(|_| ()),
            Err(Error::EntropyFailure)
        );
    }
}
