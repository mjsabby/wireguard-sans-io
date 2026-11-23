//! Cookie MACs and the cookie reply message (whitepaper §5.3, §5.4.4,
//! §5.4.7): WireGuard's CPU-exhaustion (DoS) defence.
//!
//! * `mac1` is mandatory on every handshake message and is checked
//!   *before* any expensive Diffie-Hellman work, in constant time, and
//!   failures are dropped silently.
//! * `mac2` proves IP ownership when the receiver is under load, using a
//!   cookie minted from a rotating secret and the sender's endpoint, and
//!   delivered encrypted (XChaCha20-Poly1305) bound to the provoking
//!   message's `mac1`.
//!
//! The state splits along who the keys belong to:
//!
//! * everything keyed by **our own** public key — verifying `mac1`,
//!   minting cookies, sealing cookie replies — is the same for every peer
//!   and lives once, in the [`crate::Device`] ([`DeviceMacKeys`],
//!   [`CookieJar`]);
//! * everything keyed by **the peer's** public key — computing the `mac1`
//!   and `mac2` we send, opening cookie replies we receive — lives in that
//!   peer's [`crate::Tunnel`] ([`PeerMacKeys`], [`LastCookie`]).

use core::net::{IpAddr, SocketAddr};

use crate::Error;
use crate::consts::{
    COOKIE_LIFETIME, COOKIE_REPLY_LEN, COOKIE_SECRET_GRACE, LABEL_COOKIE, LABEL_MAC1,
};
use crate::crypto::{CryptoProvider, ct, siphash};
use crate::entropy::EntropySource;
use crate::keys::PublicKey;
use crate::message::{self, CookieReply};
use crate::time::Ticks;

/// MAC and cookie keys derived from **our own** static public key
/// (whitepaper §5.4.4/§5.4.7 note that these hashes "can be pre-computed").
/// Shared by every peer of a device.
#[derive(Clone)]
pub(crate) struct DeviceMacKeys {
    /// `Hash(Label-Mac1 ∥ our_public)`: verifies `mac1` on messages we
    /// receive.
    mac1_recv: [u8; 32],
    /// What the provider made of that key for repeated use
    /// ([`CryptoProvider::mac_prepare`]): every handshake message that
    /// arrives, genuine or not, is checked with it first.
    mac1_recv_state: [u32; 8],
    /// `Hash(Label-Cookie ∥ our_public)`: encrypts cookie replies we send.
    cookie_send: [u8; 32],
}

/// `Hash(label ∥ public)`: the MAC and cookie keys are derived from public
/// keys, so — unlike everything in [`crate::noise`] — they are not secret.
fn label_hash<P: CryptoProvider>(label: &[u8], public: &PublicKey) -> [u8; 32] {
    let mut out = [0u8; 32];
    P::hash(&[label, public.as_bytes()], &mut out);
    out
}

impl DeviceMacKeys {
    /// Not derived yet.
    pub(crate) const BLANK: Self = Self {
        mac1_recv: [0u8; 32],
        mac1_recv_state: [0u32; 8],
        cookie_send: [0u8; 32],
    };

    pub(crate) fn new<P: CryptoProvider>(local_public: &PublicKey) -> Self {
        let mac1_recv = label_hash::<P>(LABEL_MAC1, local_public);
        let mut mac1_recv_state = [0u32; 8];
        P::mac_prepare(&mac1_recv, &mut mac1_recv_state);
        Self {
            mac1_recv,
            mac1_recv_state,
            cookie_send: label_hash::<P>(LABEL_COOKIE, local_public),
        }
    }
}

impl core::fmt::Debug for DeviceMacKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DeviceMacKeys")
    }
}

/// MAC and cookie keys derived from **the peer's** static public key.
#[derive(Clone)]
pub(crate) struct PeerMacKeys {
    /// `Hash(Label-Mac1 ∥ peer_public)`: keys `mac1` on messages we send.
    mac1_send: [u8; 32],
    /// What the provider made of that key for repeated use
    /// ([`CryptoProvider::mac_prepare`]).
    mac1_send_state: [u32; 8],
    /// `Hash(Label-Cookie ∥ peer_public)`: decrypts cookie replies we
    /// receive.
    cookie_recv: [u8; 32],
}

impl PeerMacKeys {
    /// Not derived yet.
    pub(crate) const BLANK: Self = Self {
        mac1_send: [0u8; 32],
        mac1_send_state: [0u32; 8],
        cookie_recv: [0u8; 32],
    };

    pub(crate) fn new<P: CryptoProvider>(peer_public: &PublicKey) -> Self {
        let mac1_send = label_hash::<P>(LABEL_MAC1, peer_public);
        let mut mac1_send_state = [0u32; 8];
        P::mac_prepare(&mac1_send, &mut mac1_send_state);
        Self {
            mac1_send,
            mac1_send_state,
            cookie_recv: label_hash::<P>(LABEL_COOKIE, peer_public),
        }
    }
}

impl core::fmt::Debug for PeerMacKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PeerMacKeys")
    }
}

/// The canonical byte encoding of a source address that cookies are bound
/// to (whitepaper §5.4.7, `A_remote`): the IP address followed by the port
/// in network byte order — 6 bytes for IPv4, 18 for IPv6.
///
/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, what a dual-stack socket
/// reports for an IPv4 sender) encodes exactly like the IPv4 address it
/// maps, so the same host gets the same cookie whichever way the socket
/// names it.
#[derive(Clone, Copy)]
pub(crate) struct RemoteBytes {
    bytes: [u8; 18],
    len: usize,
}

impl RemoteBytes {
    pub(crate) fn new(addr: SocketAddr) -> Self {
        let mut bytes = [0u8; 18];
        let v4 = match addr.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        };
        let ip_len = match (v4, addr.ip()) {
            (Some(v4), _) => {
                for (d, s) in bytes.iter_mut().zip(v4.octets().iter()) {
                    *d = *s;
                }
                4usize
            }
            (None, IpAddr::V6(v6)) => {
                for (d, s) in bytes.iter_mut().zip(v6.octets().iter()) {
                    *d = *s;
                }
                16usize
            }
            // Unreachable: a V4 address always yields `Some` above.
            (None, IpAddr::V4(_)) => 0usize,
        };
        for (d, s) in bytes
            .iter_mut()
            .skip(ip_len)
            .zip(addr.port().to_be_bytes().iter())
        {
            *d = *s;
        }
        Self {
            bytes,
            len: ip_len.saturating_add(2),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

/// The most recent cookie a peer sent us (initiator side of the cookie
/// dance). Used to fill `mac2` while fresh (`< COOKIE_LIFETIME`).
///
/// One place for the cookie, inside the tunnel: it is written there by
/// reference and wiped there.
pub(crate) struct LastCookie {
    value: [u8; 16],
    received_at: Option<Ticks>,
}

impl LastCookie {
    /// No cookie.
    pub(crate) const fn none() -> Self {
        Self {
            value: [0; 16],
            received_at: None,
        }
    }

    /// Keep `value`, received at `now`.
    pub(crate) fn store(&mut self, value: &[u8; 16], now: Ticks) {
        ct::copy_secret(&mut self.value, value);
        self.received_at = Some(now);
    }

    /// Forget the cookie, wiping it where it lies.
    pub(crate) fn clear(&mut self) {
        ct::wipe_array(&mut self.value);
        self.received_at = None;
    }

    #[cfg(test)]
    pub(crate) fn is_some(&self) -> bool {
        self.received_at.is_some()
    }

    pub(crate) fn fresh_value(&self, now: Ticks) -> Option<&[u8; 16]> {
        let received_at = self.received_at?;
        (now.since(received_at) < COOKIE_LIFETIME).then_some(&self.value)
    }
}

impl Drop for LastCookie {
    fn drop(&mut self) {
        self.clear();
    }
}

impl core::fmt::Debug for LastCookie {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LastCookie")
    }
}

/// The responder's rotating cookie secret (`R_m`, whitepaper §5.4.7): a
/// random value that changes every two minutes.
///
/// A secret mints cookies for one [`COOKIE_LIFETIME`] and is honoured for
/// [`COOKIE_SECRET_GRACE`] more — whether or not anything has been minted
/// since (rotation itself happens when the next cookie is minted, because
/// that is where the entropy source is at hand). The secret before the
/// current one is kept for that: a cookie handed out just before a
/// rotation is still good for the retransmission it was asked for.
///
/// A cookie proves that its holder received something at the address it
/// names, some time while its secret was in use. It does not prove that a
/// particular message is recent: `mac2` covers a message, not when it was
/// sent, so a recording of a message with a valid `mac2` passes this check
/// until the secret behind it is no longer honoured.
pub(crate) struct CookieJar {
    secret: [u8; 32],
    previous: [u8; 32],
    /// `previous` holds a real (random) secret. False until the *second*
    /// rotation, so the all-zero pre-prime value is never accepted.
    has_previous: bool,
    /// When `secret` was drawn.
    rotated_at: Ticks,
    /// When `previous` was drawn.
    previous_rotated_at: Ticks,
    primed: bool,
    /// Cookie-reply nonces. XChaCha20 needs a nonce that does not repeat
    /// under `cookie_send`, and drawing 24 bytes of entropy for every
    /// reply would be the dominant cost under a flood (and can stall a
    /// constrained HWRNG). A counter would do for uniqueness — but it
    /// would be on the wire, telling anyone how many replies this device
    /// has sent, which is how loaded it is. So a nonce is a pseudo-random
    /// function of the counter, under a key drawn once when the jar is
    /// first used: as good as a random nonce to everyone else, and free.
    nonce_key: [u8; 16],
    nonce_counter: u64,
}

impl CookieJar {
    pub(crate) const fn new() -> Self {
        Self {
            secret: [0u8; 32],
            previous: [0u8; 32],
            has_previous: false,
            rotated_at: Ticks::ZERO,
            previous_rotated_at: Ticks::ZERO,
            primed: false,
            nonce_key: [0u8; 16],
            nonce_counter: 0,
        }
    }

    fn rotate_if_needed(&mut self, now: Ticks, rng: &mut dyn EntropySource) -> Result<(), Error> {
        if self.primed && now.since(self.rotated_at) < COOKIE_LIFETIME {
            return Ok(());
        }
        // The new secret is drawn straight into the place of the previous
        // one, and the two then change places: neither is ever anywhere
        // but in the jar. The previous secret can be written over because
        // it is past being honoured — it was drawn a lifetime or more
        // before the current one, which is itself a lifetime old.
        //
        // All the entropy is drawn before anything is committed, so a
        // failure leaves the current secret, and whether the jar is
        // primed, as they were (the next call tries again from scratch).
        self.has_previous = false;
        let mut drawn = rng.fill(&mut self.previous);
        if drawn.is_ok() && !self.primed {
            // First prime: the key the nonces are derived with. A fixed
            // one would make two runs under the same static key repeat
            // their nonces under the deterministic `cookie_send` key
            // (keystream and Poly1305 one-time-key reuse), and would make
            // the counter readable again. Failing closed costs nothing the
            // caller wouldn't lose anyway: the handshake response that
            // follows needs entropy too.
            drawn = rng.fill(&mut self.nonce_key);
        }
        if drawn.is_err() {
            ct::wipe_array(&mut self.previous);
            if !self.primed {
                ct::wipe_array(&mut self.nonce_key);
            }
            return Err(Error::EntropyFailure);
        }
        ct::swap_secret(&mut self.secret, &mut self.previous);
        self.previous_rotated_at = self.rotated_at;
        self.has_previous = self.primed; // true from the second rotation on
        self.rotated_at = now;
        if !self.primed {
            self.nonce_counter = 0;
        }
        self.primed = true;
        Ok(())
    }

    /// The next 24-byte XChaCha20 nonce: three SipHash-2-4 outputs over
    /// the reply counter. (2⁶⁴ replies are out of reach; the counter
    /// wrapping would repeat nonces.)
    fn next_nonce(&mut self) -> [u8; 24] {
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let mut input = [0u8; 9];
        if let Some(counter) = input.first_chunk_mut::<8>() {
            *counter = self.nonce_counter.to_le_bytes();
        }
        // Three words, each of its own input: counter ∥ 0, 1, 2.
        let mut words = [0u64; 3];
        for (part, word) in (0u8..).zip(words.iter_mut()) {
            if let Some(last) = input.last_mut() {
                *last = part;
            }
            *word = siphash::siphash24(&self.nonce_key, &input);
        }
        let [w0, w1, w2] = words.map(u64::to_le_bytes);
        let mut out = [0u8; 24];
        for (o, b) in out.iter_mut().zip(w0.iter().chain(&w1).chain(&w2)) {
            *o = *b;
        }
        out
    }

    /// `τ := Mac(R_m, A_remote)`: the cookie for a remote endpoint,
    /// written to `cookie`.
    fn mint<P: CryptoProvider>(
        &mut self,
        now: Ticks,
        rng: &mut dyn EntropySource,
        remote: &[u8],
        cookie: &mut [u8; 16],
    ) -> Result<(), Error> {
        self.rotate_if_needed(now, rng)?;
        P::mac(&self.secret, &[remote], cookie);
        Ok(())
    }

    /// Does `mac2` prove possession of a cookie we minted for `remote`
    /// from a secret that is still honoured? Constant time in the cookie
    /// and in `mac2`.
    ///
    /// Which secrets are tried depends on the time alone: the current one
    /// while it is honoured, and the one before it only in the short while
    /// after a rotation in which it still is (and never the all-zero value
    /// that stands in its place before the second rotation). Most of the
    /// time that is one secret, three hash calls less than trying both.
    pub(crate) fn verify_mac2<P: CryptoProvider>(
        &self,
        now: Ticks,
        remote: &[u8],
        beta: &[u8],
        mac2: &[u8; 16],
    ) -> bool {
        if !self.primed {
            return false;
        }
        let honoured = |drawn_at: Ticks| {
            now.since(drawn_at) < COOKIE_LIFETIME.saturating_add(COOKIE_SECRET_GRACE)
        };
        let mut proven = false;
        if honoured(self.rotated_at) {
            proven |= Self::proves::<P>(&self.secret, remote, beta, mac2);
        }
        if self.has_previous && honoured(self.previous_rotated_at) {
            proven |= Self::proves::<P>(&self.previous, remote, beta, mac2);
        }
        proven
    }

    /// Is `mac2` what the cookie that `secret` gives `remote` makes of
    /// `beta`? The cookie and the `mac2` it leads to are wiped before
    /// returning: a cookie is a credential, and the `mac2` we expect is
    /// what a holder of the cookie would have to send.
    fn proves<P: CryptoProvider>(
        secret: &[u8; 32],
        remote: &[u8],
        beta: &[u8],
        mac2: &[u8; 16],
    ) -> bool {
        let mut cookie = [0u8; 16];
        let mut expected = [0u8; 16];
        P::mac(secret, &[remote], &mut cookie);
        P::mac(&cookie, &[beta], &mut expected);
        let proven = ct::ct_eq(&expected, mac2);
        ct::wipe_array(&mut cookie);
        ct::wipe_array(&mut expected);
        proven
    }
}

impl Drop for CookieJar {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.secret);
        ct::wipe_array(&mut self.previous);
        ct::wipe_array(&mut self.nonce_key);
    }
}

impl core::fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CookieJar")
    }
}

/// Fill the `mac1` and `mac2` slots of an outgoing handshake message
/// (whitepaper §5.4.4). Returns the `mac1` value, which the caller stores
/// to authenticate a possible cookie reply.
///
/// # Errors
/// `BufferTooSmall` if `msg` is not handshake-message sized (internal
/// misuse).
pub(crate) fn apply_macs<P: CryptoProvider>(
    keys: &PeerMacKeys,
    cookie: &LastCookie,
    now: Ticks,
    msg: &mut [u8],
) -> Result<[u8; 16], Error> {
    let slots = message::mac_slots(msg)?;
    P::mac_prepared(
        &keys.mac1_send,
        &keys.mac1_send_state,
        &[slots.alpha],
        slots.mac1,
    );
    // msg.mac2 := Mac(L, msgβ) when the cookie is fresh, else 0^16.
    match cookie.fresh_value(now) {
        Some(value) => P::mac(value, &[slots.alpha, slots.mac1], slots.mac2),
        None => *slots.mac2 = [0u8; 16],
    }
    Ok(*slots.mac1)
}

/// Verify `mac1` of a received handshake message, constant time.
pub(crate) fn verify_mac1<P: CryptoProvider>(
    keys: &DeviceMacKeys,
    alpha: &[u8],
    mac1: &[u8; 16],
) -> bool {
    let mut expected = [0u8; 16];
    P::mac_prepared(
        &keys.mac1_recv,
        &keys.mac1_recv_state,
        &[alpha],
        &mut expected,
    );
    ct::ct_eq(&expected, mac1)
}

/// Build a cookie reply (whitepaper §5.4.7) for a message whose `mac1`
/// validated but whose `mac2` did not while under load.
///
/// # Errors
/// `BufferTooSmall`, `EntropyFailure`.
#[allow(clippy::too_many_arguments)] // internal plumbing; every argument is distinct state
pub(crate) fn build_cookie_reply<P: CryptoProvider>(
    keys: &DeviceMacKeys,
    jar: &mut CookieJar,
    now: Ticks,
    rng: &mut dyn EntropySource,
    peer_sender_index: u32,
    their_mac1: &[u8; 16],
    remote: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < COOKIE_REPLY_LEN {
        return Err(Error::BufferTooSmall);
    }
    // The cookie is minted straight into the first half of the buffer it
    // is then sealed in: the plaintext cookie exists in that one place,
    // and only until the seal has turned it into ciphertext.
    let mut encrypted = [0u8; 32];
    let minted = match encrypted.first_chunk_mut::<16>() {
        Some(cookie) => jar.mint::<P>(now, rng, remote, cookie),
        None => Err(Error::Internal),
    };
    if let Err(e) = minted {
        ct::wipe_array(&mut encrypted);
        return Err(e);
    }
    let nonce = jar.next_nonce();
    let sealed = P::xseal_in_place(&keys.cookie_send, &nonce, their_mac1, 16, &mut encrypted);
    if sealed != Ok(32) {
        ct::wipe_array(&mut encrypted);
        return Err(Error::Internal);
    }
    message::build_cookie_reply(out, peer_sender_index, &nonce, &encrypted)?;
    Ok(COOKIE_REPLY_LEN)
}

/// Decrypt and authenticate a received cookie reply against the `mac1` of
/// a handshake message we sent (whitepaper §5.4.7: the AEAD's additional
/// data binds the reply to our message). If it authenticates the cookie
/// is stored in `cookie` and `true` is returned; otherwise `cookie` is
/// left as it was.
pub(crate) fn consume_cookie_reply<P: CryptoProvider>(
    keys: &PeerMacKeys,
    sent_mac1: &[u8; 16],
    msg: &CookieReply<'_>,
    now: Ticks,
    cookie: &mut LastCookie,
) -> bool {
    let mut buf = *msg.encrypted_cookie;
    let opened = P::xopen_in_place(&keys.cookie_recv, msg.nonce, sent_mac1, &mut buf);
    let accepted = match buf.first_chunk::<16>() {
        Some(value) if opened == Some(16) => {
            cookie.store(value, now);
            true
        }
        _ => false,
    };
    ct::wipe_array(&mut buf);
    accepted
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::unreachable,
        clippy::panic
    )]
    use super::*;
    use crate::StaticSecret;
    use crate::consts::HANDSHAKE_INITIATION_LEN;
    use crate::crypto::{InTree, blake2s};
    use crate::message::{Packet, parse};
    use crate::testing::DeterministicRng;
    use std::vec;

    type P = InTree;

    /// (initiator's keys for talking to the responder, the responder's own
    /// device keys).
    fn keypairs() -> (PeerMacKeys, DeviceMacKeys) {
        let mut rng = DeterministicRng::new(0xc00c1e);
        let _initiator = StaticSecret::generate(&mut rng).unwrap().public_key();
        let responder = StaticSecret::generate(&mut rng).unwrap().public_key();
        (
            PeerMacKeys::new::<P>(&responder),
            DeviceMacKeys::new::<P>(&responder),
        )
    }

    fn blank_initiation() -> std::vec::Vec<u8> {
        let mut msg = vec![0u8; HANDSHAKE_INITIATION_LEN];
        message::build_initiation(&mut msg, 7, &[1; 32], &[2; 48], &[3; 28]).unwrap();
        msg
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Mint a cookie as a value (the library itself never does).
    fn mint(
        jar: &mut CookieJar,
        now: Ticks,
        rng: &mut DeterministicRng,
        remote: &[u8],
    ) -> [u8; 16] {
        let mut cookie = [0u8; 16];
        jar.mint::<P>(now, rng, remote, &mut cookie).unwrap();
        cookie
    }

    /// A stored cookie with this value.
    fn stored(value: [u8; 16], now: Ticks) -> LastCookie {
        let mut cookie = LastCookie::none();
        cookie.store(&value, now);
        cookie
    }

    #[test]
    fn mac1_roundtrip_and_direction() {
        let (ours, theirs) = keypairs();
        let mut msg = blank_initiation();
        apply_macs::<P>(&ours, &LastCookie::none(), Ticks::ZERO, &mut msg).unwrap();
        let parsed = match parse(&msg).unwrap() {
            Packet::HandshakeInitiation(m) => m,
            _ => unreachable!(),
        };
        // The receiver verifies with the key derived from ITS public key.
        assert!(verify_mac1::<P>(&theirs, parsed.alpha, parsed.mac1));
        // A device with a different public key does not.
        let mut rng = DeterministicRng::new(1);
        let other =
            DeviceMacKeys::new::<P>(&StaticSecret::generate(&mut rng).unwrap().public_key());
        assert!(!verify_mac1::<P>(&other, parsed.alpha, parsed.mac1));
        // mac2 is zero without a cookie.
        assert_eq!(parsed.mac2, &[0u8; 16]);
        // Any body tamper breaks mac1.
        for byte in 0..116 {
            let mut bad = msg.clone();
            bad[byte] ^= 0x80;
            let p = match parse(&bad) {
                Ok(Packet::HandshakeInitiation(m)) => m,
                _ => continue, // header tampering may fail parsing: fine
            };
            assert!(!verify_mac1::<P>(&theirs, p.alpha, p.mac1), "byte {byte}");
        }
    }

    #[test]
    fn cookie_reply_dance_end_to_end() {
        // "We" are the loaded responder; "peer" sent an initiation with a
        // valid mac1 and no mac2.
        let mut rng = DeterministicRng::new(0xfeed);
        let (peer_keys, our_keys) = keypairs();
        let now = Ticks::from_secs(100);
        let remote = RemoteBytes::new(addr("192.0.2.33:51820"));

        let mut init = blank_initiation();
        let peer_mac1 = apply_macs::<P>(&peer_keys, &LastCookie::none(), now, &mut init).unwrap();

        // Under load: we answer with a cookie reply instead of processing.
        let mut jar = CookieJar::new();
        let mut reply = vec![0u8; COOKIE_REPLY_LEN];
        let n = build_cookie_reply::<P>(
            &our_keys,
            &mut jar,
            now,
            &mut rng,
            7,
            &peer_mac1,
            remote.as_slice(),
            &mut reply,
        )
        .unwrap();
        assert_eq!(n, COOKIE_REPLY_LEN);

        // Peer consumes the reply...
        let parsed = match parse(&reply).unwrap() {
            Packet::CookieReply(m) => m,
            _ => unreachable!(),
        };
        let mut cookie = LastCookie::none();
        assert!(consume_cookie_reply::<P>(
            &peer_keys,
            &peer_mac1,
            &parsed,
            now,
            &mut cookie
        ));
        assert!(cookie.is_some());

        // ...and retransmits with mac2 filled.
        let mut retry = blank_initiation();
        apply_macs::<P>(&peer_keys, &cookie, now.add_nanos(1), &mut retry).unwrap();
        let parsed = match parse(&retry).unwrap() {
            Packet::HandshakeInitiation(m) => m,
            _ => unreachable!(),
        };
        assert_ne!(parsed.mac2, &[0u8; 16]);
        assert!(verify_mac1::<P>(&our_keys, parsed.alpha, parsed.mac1));
        assert!(jar.verify_mac2::<P>(now, remote.as_slice(), parsed.beta, parsed.mac2));

        // mac2 does not verify for a different remote address (IP
        // ownership proof), a different port, nor for tampered bodies.
        for other in ["198.51.100.9:7", "192.0.2.33:51821", "[2001:db8::1]:51820"] {
            assert!(
                !jar.verify_mac2::<P>(
                    now,
                    RemoteBytes::new(addr(other)).as_slice(),
                    parsed.beta,
                    parsed.mac2
                ),
                "{other}"
            );
        }
        let mut other_beta = parsed.beta.to_vec();
        other_beta[10] ^= 1;
        assert!(!jar.verify_mac2::<P>(now, remote.as_slice(), &other_beta, parsed.mac2));
    }

    #[test]
    fn forged_cookie_replies_rejected() {
        let mut rng = DeterministicRng::new(3);
        let (peer_keys, our_keys) = keypairs();
        let now = Ticks::ZERO;
        let mac1 = [0xaa; 16];
        let mut jar = CookieJar::new();
        let mut reply = vec![0u8; COOKIE_REPLY_LEN];
        build_cookie_reply::<P>(
            &our_keys, &mut jar, now, &mut rng, 1, &mac1, b"r", &mut reply,
        )
        .unwrap();

        // Wrong binding mac1 (attacker did not see our message).
        let parsed = match parse(&reply).unwrap() {
            Packet::CookieReply(m) => m,
            _ => unreachable!(),
        };
        // A reply that does not open leaves the cookie we hold alone.
        let mut cookie = stored([9; 16], now);
        assert!(!consume_cookie_reply::<P>(
            &peer_keys,
            &[0xbb; 16],
            &parsed,
            now,
            &mut cookie
        ));
        assert_eq!(cookie.fresh_value(now), Some(&[9; 16]));
        // Bit flips anywhere in nonce or ciphertext.
        for byte in 8..COOKIE_REPLY_LEN {
            let mut bad = reply.clone();
            bad[byte] ^= 1;
            let parsed = match parse(&bad).unwrap() {
                Packet::CookieReply(m) => m,
                _ => unreachable!(),
            };
            assert!(
                !consume_cookie_reply::<P>(&peer_keys, &mac1, &parsed, now, &mut cookie),
                "byte {byte}"
            );
            assert_eq!(cookie.fresh_value(now), Some(&[9; 16]), "byte {byte}");
        }
        // The genuine reply with the right binding works.
        let parsed = match parse(&reply).unwrap() {
            Packet::CookieReply(m) => m,
            _ => unreachable!(),
        };
        assert!(consume_cookie_reply::<P>(
            &peer_keys,
            &mac1,
            &parsed,
            now,
            &mut cookie
        ));
        assert_ne!(
            cookie.fresh_value(now),
            Some(&[9; 16]),
            "the new cookie replaced the old one"
        );
        // Too-small output buffer is a local fault, reported before any
        // entropy is drawn or state changes.
        let mut tiny = [0u8; COOKIE_REPLY_LEN - 1];
        let mut fresh = CookieJar::new();
        assert_eq!(
            build_cookie_reply::<P>(
                &our_keys, &mut fresh, now, &mut rng, 1, &mac1, b"r", &mut tiny
            ),
            Err(Error::BufferTooSmall)
        );
        assert!(!fresh.primed);
    }

    #[test]
    fn cookies_expire_and_secrets_rotate() {
        let mut rng = DeterministicRng::new(11);
        let now = Ticks::from_secs(1000);
        let none = LastCookie::none();
        assert!(!none.is_some() && none.fresh_value(now).is_none());
        let mut cookie = stored([7; 16], now);
        assert!(cookie.is_some());
        assert_eq!(cookie.fresh_value(now), Some(&[7; 16]));
        assert!(
            cookie
                .fresh_value(now.add_nanos(COOKIE_LIFETIME - 1))
                .is_some()
        );
        assert!(cookie.fresh_value(now.add_nanos(COOKIE_LIFETIME)).is_none());
        // Clearing wipes the value where it lies.
        cookie.clear();
        assert!(!cookie.is_some() && cookie.fresh_value(now).is_none());
        assert_eq!(cookie.value, [0u8; 16]);

        // Jar: a cookie minted now verifies now and within one rotation,
        // but not after two.
        let mut jar = CookieJar::new();
        let remote = b"10.0.0.1:1";
        let beta = b"some message beta bytes";
        let c = mint(&mut jar, now, &mut rng, remote);
        let mac2 = blake2s::mac(&c, &[beta.as_slice()]);
        assert!(jar.verify_mac2::<P>(now, remote, beta, &mac2));
        // Force one rotation: old secret moves to `previous`, still valid.
        let later = now.add_nanos(COOKIE_LIFETIME);
        let _ = mint(&mut jar, later, &mut rng, remote);
        assert!(
            jar.verify_mac2::<P>(later, remote, beta, &mac2),
            "previous secret"
        );
        // Second rotation: gone.
        let later = now.add_nanos(2 * COOKIE_LIFETIME);
        let _ = mint(&mut jar, later, &mut rng, remote);
        assert!(
            !jar.verify_mac2::<P>(later, remote, beta, &mac2),
            "two rotations"
        );
    }

    /// A secret stops verifying a lifetime and the grace after it was
    /// drawn even if nothing is minted in the meantime (rotation happens at
    /// the next mint), and a late rotation does not bring it back as
    /// `previous`.
    #[test]
    fn a_secret_ages_out_without_being_rotated() {
        let mut rng = DeterministicRng::new(12);
        let drawn = Ticks::from_secs(50);
        let mut jar = CookieJar::new();
        let remote = b"10.0.0.1:1";
        let beta = b"some message beta bytes";
        // Two rotations first, so `previous` is a real secret throughout.
        let _ = mint(&mut jar, Ticks::ZERO, &mut rng, remote);
        let c = mint(&mut jar, drawn, &mut rng, remote);
        // (not a rotation: 50 s < COOKIE_LIFETIME, same secret as at 0)
        let mac2 = blake2s::mac(&c, &[beta.as_slice()]);
        let dies = Ticks::ZERO.add_nanos(COOKIE_LIFETIME + COOKIE_SECRET_GRACE);
        assert!(jar.verify_mac2::<P>(drawn, remote, beta, &mac2));
        assert!(jar.verify_mac2::<P>(Ticks::from_nanos(dies.nanos() - 1), remote, beta, &mac2));
        assert!(
            !jar.verify_mac2::<P>(dies, remote, beta, &mac2),
            "nothing was minted since, but the secret is past its time"
        );
        // Hours later load returns and a cookie is minted: the old secret
        // becomes `previous`, and stays dead.
        let hours_later = Ticks::from_secs(7200);
        let fresh = mint(&mut jar, hours_later, &mut rng, remote);
        assert_ne!(fresh, c);
        assert!(!jar.verify_mac2::<P>(hours_later, remote, beta, &mac2));
        let fresh_mac2 = blake2s::mac(&fresh, &[beta.as_slice()]);
        assert!(jar.verify_mac2::<P>(hours_later, remote, beta, &fresh_mac2));
    }

    /// After a rotation the secret before is honoured for the grace — a
    /// cookie handed out just before the rotation is good for the
    /// retransmission it was asked for — and not a nanosecond longer.
    #[test]
    fn the_previous_secret_is_honoured_for_the_grace_only() {
        let mut rng = DeterministicRng::new(13);
        let mut jar = CookieJar::new();
        let remote = b"10.0.0.1:1";
        let beta = b"some message beta bytes";
        let _ = mint(&mut jar, Ticks::ZERO, &mut rng, remote);
        // A second secret, so that the one before it is a real one; a
        // cookie from it at the last moment it makes any.
        let drawn = Ticks::ZERO.add_nanos(COOKIE_LIFETIME);
        let _ = mint(&mut jar, drawn, &mut rng, remote);
        let last_minute = Ticks::from_nanos(drawn.nanos() + COOKIE_LIFETIME - 1);
        let old = mint(&mut jar, last_minute, &mut rng, remote);
        let old_mac2 = blake2s::mac(&old, &[beta.as_slice()]);
        let secret_before = jar.secret;
        // The rotation.
        let rotation = drawn.add_nanos(COOKIE_LIFETIME);
        let new = mint(&mut jar, rotation, &mut rng, remote);
        assert_ne!(new, old);
        assert_eq!(jar.previous, secret_before, "the secrets changed places");
        assert_ne!(jar.secret, secret_before);
        let new_mac2 = blake2s::mac(&new, &[beta.as_slice()]);
        let grace_ends = rotation.add_nanos(COOKIE_SECRET_GRACE);
        let just_before = Ticks::from_nanos(grace_ends.nanos() - 1);
        assert!(jar.verify_mac2::<P>(rotation, remote, beta, &old_mac2));
        assert!(jar.verify_mac2::<P>(just_before, remote, beta, &old_mac2));
        assert!(!jar.verify_mac2::<P>(grace_ends, remote, beta, &old_mac2));
        // The new one is unaffected by any of that.
        for at in [rotation, just_before, grace_ends] {
            assert!(jar.verify_mac2::<P>(at, remote, beta, &new_mac2));
        }
    }

    /// A rotation that cannot get its entropy changes nothing that
    /// matters: the secret in use stays, cookies from it keep verifying,
    /// and the next attempt rotates.
    #[test]
    fn a_failed_rotation_leaves_the_secret_in_use_alone() {
        struct Failing;
        impl crate::EntropySource for Failing {
            fn fill(&mut self, buf: &mut [u8]) -> Result<(), crate::EntropyError> {
                // Half written, then the failure: the worst a source may do.
                let half = buf.len() / 2;
                buf[..half].fill(0xee);
                Err(crate::EntropyError)
            }
        }
        let mut rng = DeterministicRng::new(14);
        let mut jar = CookieJar::new();
        let remote = b"10.0.0.1:1";
        let beta = b"some message beta bytes";
        let _ = mint(&mut jar, Ticks::ZERO, &mut rng, remote);
        let drawn = Ticks::ZERO.add_nanos(COOKIE_LIFETIME);
        let cookie = mint(&mut jar, drawn, &mut rng, remote);
        let mac2 = blake2s::mac(&cookie, &[beta.as_slice()]);
        let secret = jar.secret;

        let due = drawn.add_nanos(COOKIE_LIFETIME);
        assert_eq!(
            jar.mint::<P>(due, &mut Failing, remote, &mut [0u8; 16])
                .err(),
            Some(Error::EntropyFailure)
        );
        assert_eq!(jar.secret, secret);
        assert_eq!(jar.rotated_at, drawn);
        assert!(jar.primed);
        // What was half drawn is not kept, and not taken for a secret.
        assert_eq!(jar.previous, [0u8; 32]);
        assert!(!jar.has_previous);
        assert!(jar.verify_mac2::<P>(due, remote, beta, &mac2));
        // A forgery keyed on the wiped place of the previous secret gets
        // nowhere.
        let zero_cookie = blake2s::mac(&[0u8; 32], &[remote.as_slice()]);
        let zero_mac2 = blake2s::mac(&zero_cookie, &[beta.as_slice()]);
        assert!(!jar.verify_mac2::<P>(due, remote, beta, &zero_mac2));
        // With entropy again: a new secret, the old one behind it.
        let fresh = mint(&mut jar, due, &mut rng, remote);
        assert_ne!(fresh, cookie);
        assert_eq!(jar.previous, secret);
        assert!(jar.has_previous);
        assert!(jar.verify_mac2::<P>(due, remote, beta, &mac2));
    }

    #[test]
    fn unprimed_jar_rejects_all_mac2() {
        let jar = CookieJar::new();
        assert!(!jar.verify_mac2::<P>(Ticks::ZERO, b"r", b"beta", &[0u8; 16]));
        // All-zero mac2 (the "no cookie" wire value) must never verify.
        let mut rng = DeterministicRng::new(1);
        let mut jar = CookieJar::new();
        let _ = mint(&mut jar, Ticks::ZERO, &mut rng, b"r");
        assert!(!jar.verify_mac2::<P>(Ticks::ZERO, b"r", b"beta", &[0u8; 16]));
    }

    /// Regression: after the first rotation `previous` is the all-zero
    /// pre-prime value, which an attacker can key against without any
    /// secret knowledge. `has_previous` must mask it.
    #[test]
    fn jar_rejects_mac2_keyed_on_all_zero_previous() {
        let mut rng = DeterministicRng::new(0xa7);
        let mut jar = CookieJar::new();
        let _ = mint(&mut jar, Ticks::ZERO, &mut rng, b"x");
        let remote = b"203.0.113.5:51820";
        let beta = b"some 116- or 76-byte msg-beta prefix the attacker built";
        let forged_cookie = blake2s::mac(&[0u8; 32], &[remote.as_slice()]);
        let forged_mac2 = blake2s::mac(&forged_cookie, &[beta.as_slice()]);
        assert!(
            !jar.verify_mac2::<P>(Ticks::ZERO, remote, beta, &forged_mac2),
            "all-zero `previous` must never be accepted as a mac2 key"
        );
        // After a real second rotation, the (now random) previous works.
        let c = mint(&mut jar, Ticks::ZERO, &mut rng, remote);
        let real_mac2 = blake2s::mac(&c, &[beta.as_slice()]);
        let later = Ticks::ZERO.add_nanos(COOKIE_LIFETIME);
        let _ = mint(&mut jar, later, &mut rng, remote);
        assert!(
            jar.verify_mac2::<P>(later, remote, beta, &real_mac2),
            "real previous"
        );
    }

    /// Regression: entropy failure while drawing the nonce key at the
    /// first prime must fail closed (not silently fall back to an
    /// all-zero key, which would repeat XChaCha20 nonces across restarts).
    #[test]
    fn jar_prime_fails_closed_on_nonce_seed_entropy_failure() {
        // Succeeds for the 32-byte secret, then fails for the 16-byte
        // nonce key.
        struct OneShotRng {
            inner: DeterministicRng,
            calls: u32,
        }
        impl crate::EntropySource for OneShotRng {
            fn fill(&mut self, buf: &mut [u8]) -> Result<(), crate::EntropyError> {
                self.calls = self.calls.saturating_add(1);
                if self.calls == 1 {
                    self.inner.fill(buf)
                } else {
                    Err(crate::EntropyError)
                }
            }
        }
        let mut bad = OneShotRng {
            inner: DeterministicRng::new(7),
            calls: 0,
        };
        let mut jar = CookieJar::new();
        // Prime fails on the nonce key → EntropyFailure, NOT a primed
        // jar with an all-zero key.
        assert_eq!(
            jar.mint::<P>(Ticks::ZERO, &mut bad, b"r", &mut [0u8; 16])
                .err(),
            Some(Error::EntropyFailure)
        );
        assert!(!jar.primed, "jar must not commit a half-prime");
        assert!(
            !jar.verify_mac2::<P>(Ticks::ZERO, b"r", b"beta", &[0u8; 16]),
            "unprimed jar accepts nothing"
        );
        // A subsequent call with working entropy primes cleanly.
        let mut good = DeterministicRng::new(8);
        assert!(
            jar.mint::<P>(Ticks::ZERO, &mut good, b"r", &mut [0u8; 16])
                .is_ok()
        );
        assert!(jar.primed);
        assert_ne!(jar.nonce_key, [0u8; 16], "the nonce key must be drawn");
    }

    /// Cookie-reply nonces take no entropy per reply, never repeat — and
    /// say nothing about how many replies have been sent: as integers
    /// they are nowhere near each other, and every one of their 192 bits
    /// changes from reply to reply about half the time. (A counter — what
    /// this used to be — fails all three of the last checks.)
    #[test]
    fn cookie_reply_nonces_are_unique_free_and_not_a_counter() {
        /// Fails once the jar is primed: per-reply entropy would show.
        struct PrimeOnly(DeterministicRng, u32);
        impl crate::EntropySource for PrimeOnly {
            fn fill(&mut self, buf: &mut [u8]) -> Result<(), crate::EntropyError> {
                self.1 = self.1.saturating_add(1);
                self.0.fill(buf)
            }
        }
        let keys = DeviceMacKeys::new::<P>(&PublicKey::from_bytes([9; 32]));
        let mut rng = PrimeOnly(DeterministicRng::new(5), 0);
        let mut jar = CookieJar::new();
        let mut nonces: std::vec::Vec<[u8; 24]> = std::vec::Vec::new();
        let mut draws_after_first = None;
        for i in 0..2000u32 {
            let mut out = [0u8; COOKIE_REPLY_LEN];
            let n = build_cookie_reply::<P>(
                &keys,
                &mut jar,
                Ticks::ZERO,
                &mut rng,
                i,
                &[7; 16],
                b"remote",
                &mut out,
            )
            .unwrap();
            assert_eq!(n, COOKIE_REPLY_LEN);
            nonces.push(out[8..32].try_into().unwrap());
            draws_after_first.get_or_insert(rng.1);
        }
        assert_eq!(
            Some(rng.1),
            draws_after_first,
            "entropy was drawn for a reply after the first"
        );
        let distinct: std::collections::HashSet<_> = nonces.iter().collect();
        assert_eq!(distinct.len(), nonces.len(), "a nonce repeated");

        // Not a counter, in any byte order or position: consecutive nonces
        // share no 8-byte word…
        for pair in nonces.windows(2) {
            for word in 0..3 {
                assert_ne!(
                    pair[0][word * 8..word * 8 + 8],
                    pair[1][word * 8..word * 8 + 8],
                    "consecutive nonces share a word"
                );
            }
        }
        // …and every bit flips between consecutive replies between a
        // third and two thirds of the time.
        for bit in 0..192 {
            let flips = nonces
                .windows(2)
                .filter(|p| (p[0][bit / 8] ^ p[1][bit / 8]) >> (bit % 8) & 1 == 1)
                .count();
            assert!(
                (nonces.len() / 3..nonces.len() * 2 / 3).contains(&flips),
                "bit {bit} flipped {flips} times in {} replies",
                nonces.len()
            );
        }

        // Another run (another key) under the same static key: no nonce
        // in common, although both count from the same place.
        let mut rng2 = DeterministicRng::new(6);
        let mut jar2 = CookieJar::new();
        let _ = mint(&mut jar2, Ticks::ZERO, &mut rng2, b"r"); // primes
        assert_eq!(jar2.nonce_counter, 0);
        for _ in 0..2000 {
            assert!(!distinct.contains(&jar2.next_nonce()));
        }
    }

    #[test]
    fn remote_bytes_encoding_is_canonical() {
        // IPv4: 4 address bytes + big-endian port.
        let v4 = RemoteBytes::new(addr("192.0.2.7:51820"));
        assert_eq!(v4.as_slice(), &[192, 0, 2, 7, 0xca, 0x6c]);
        // IPv6: 16 address bytes + big-endian port.
        let v6 = RemoteBytes::new(addr("[2001:db8::1]:258"));
        assert_eq!(v6.as_slice().len(), 18);
        assert_eq!(&v6.as_slice()[..4], &[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(v6.as_slice()[15], 1);
        assert_eq!(&v6.as_slice()[16..], &[1, 2]);
        // An IPv4-mapped IPv6 address is the same host as the IPv4 one.
        let mapped = RemoteBytes::new(addr("[::ffff:192.0.2.7]:51820"));
        assert_eq!(mapped.as_slice(), v4.as_slice());
        // Port and address both matter.
        assert_ne!(
            RemoteBytes::new(addr("192.0.2.7:51821")).as_slice(),
            v4.as_slice()
        );
        assert_ne!(
            RemoteBytes::new(addr("192.0.2.8:51820")).as_slice(),
            v4.as_slice()
        );
        // An IPv4-compatible (not -mapped) IPv6 address stays IPv6.
        assert_eq!(
            RemoteBytes::new(addr("[::192.0.2.7]:1")).as_slice().len(),
            18
        );
    }
}
