//! The Noise IKpsk2 handshake, exactly as laid out in whitepaper
//! §5.4.2–§5.4.5.
//!
//! This module is pure key-schedule mechanics: it neither checks macs
//! (that is [`crate::cookie`]'s job, done *before* any function here runs)
//! nor enforces timestamp monotonicity or rate limits (the
//! [`crate::tunnel`] layer does, on the results).
//!
//! Consuming an initiation is split in two, along the line where the
//! initiator's identity becomes known:
//!
//! 1. [`identify_initiation`] — needs only the local static key, so it can
//!    run before anyone knows who is calling. One Diffie-Hellman (`es`)
//!    and one AEAD reveal the initiator's static public key
//!    ([`Identity`]).
//! 2. [`consume_initiation_finish`] — run by the [`crate::Tunnel`] for that
//!    public key, using its precomputed `DH(S_priv_local, S_pub_peer)`.
//!
//! So one initiation costs one X25519 before the peer is identified, no
//! matter how many peers are configured, and the long-term static private
//! key is never used against an unverified static key.
//!
//! # Where the secrets are
//!
//! Every function here writes its results through `&mut` parameters into
//! storage the caller owns and wipes — the tunnel's own state, or one
//! local that is wiped when it goes out of scope — and returns nothing
//! secret by value. Rust moves and returns are byte copies that leave the
//! original bytes behind, where no later wipe finds them; a secret that is
//! written once, into the place it stays in, has no such copies. Working
//! values (Diffie-Hellman results, the keys of the three handshake AEADs,
//! `τ`) live in [`Secret`] locals, which wipe themselves on every way out
//! of a function.

use crate::Error;
use crate::consts::{CONSTRUCTION, HANDSHAKE_INITIATION_LEN, HANDSHAKE_RESPONSE_LEN, IDENTIFIER};
use crate::crypto::{CryptoProvider, ct, kdf};
use crate::entropy::EntropySource;
use crate::error::DropReason;
use crate::keys::{PresharedKey, PublicKey, StaticSecret};
use crate::message::{self, HandshakeInitiation, HandshakeResponse};
use crate::time::Tai64N;

/// A 32-byte working secret on the stack. It is created zeroed, filled in
/// place through a reference, never moved, and wiped where it lies when
/// it goes out of scope — on the normal path and on every early return.
struct Secret([u8; 32]);

impl Secret {
    const fn zero() -> Self {
        Self([0u8; 32])
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.0);
    }
}

/// Why a handshake step did not produce a result: the peer's message is
/// to be dropped, or something local went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reject {
    /// Drop the datagram silently.
    Drop(DropReason),
    /// A local fault.
    Fault(Error),
}

impl From<Error> for Reject {
    fn from(e: Error) -> Self {
        Self::Fault(e)
    }
}

impl From<DropReason> for Reject {
    fn from(r: DropReason) -> Self {
        Self::Drop(r)
    }
}

/// Copy `src` over the start of `dst` (as much as both hold).
fn copy_prefix(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
}

/// `Hash(Construction)` and `Hash(C0 ∥ Identifier)`: the same for every
/// handshake, computed once.
#[derive(Clone)]
pub(crate) struct HandshakeConstants {
    pub ck0: [u8; 32],
    pub h0: [u8; 32],
}

impl HandshakeConstants {
    /// Not computed yet.
    pub(crate) const BLANK: Self = Self {
        ck0: [0u8; 32],
        h0: [0u8; 32],
    };

    pub(crate) fn new<P: CryptoProvider>() -> Self {
        let mut constants = Self::BLANK;
        P::hash(&[CONSTRUCTION], &mut constants.ck0);
        P::hash(&[&constants.ck0, IDENTIFIER], &mut constants.h0);
        constants
    }
}

impl core::fmt::Debug for HandshakeConstants {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HandshakeConstants")
    }
}

/// Initiator state held between sending an initiation and receiving the
/// matching response.
pub(crate) struct InFlightInitiation {
    pub local_index: u32,
    eph_secret: [u8; 32],
    chain: [u8; 32],
    hash: [u8; 32],
}

impl InFlightInitiation {
    /// No handshake: all zero.
    pub(crate) const fn blank() -> Self {
        Self {
            local_index: 0,
            eph_secret: [0; 32],
            chain: [0; 32],
            hash: [0; 32],
        }
    }

    /// Copy `other` into `self` — straight from one place to the other —
    /// and wipe `other`.
    pub(crate) fn take_from(&mut self, other: &mut Self) {
        self.local_index = other.local_index;
        ct::copy_secret(&mut self.eph_secret, &other.eph_secret);
        ct::copy_secret(&mut self.chain, &other.chain);
        ct::copy_secret(&mut self.hash, &other.hash);
        other.wipe();
    }

    /// Zero everything where it lies.
    pub(crate) fn wipe(&mut self) {
        self.local_index = 0;
        ct::wipe_array(&mut self.eph_secret);
        ct::wipe_array(&mut self.chain);
        ct::wipe_array(&mut self.hash);
    }

    /// Does this hold nothing? (For tests of the wiping.)
    #[cfg(test)]
    pub(crate) fn is_blank(&self) -> bool {
        self.local_index == 0
            && self.eph_secret == [0; 32]
            && self.chain == [0; 32]
            && self.hash == [0; 32]
    }
}

impl Drop for InFlightInitiation {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl core::fmt::Debug for InFlightInitiation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InFlightInitiation(index={})", self.local_index)
    }
}

/// The transport keys a completed handshake yields (whitepaper §5.4.5).
#[repr(C)] // part of a session's hand-made layout: see `Session`
pub(crate) struct SessionKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
    pub local_index: u32,
    pub peer_index: u32,
    pub is_initiator: bool,
}

impl SessionKeys {
    /// No keys: all zero.
    pub(crate) const fn blank() -> Self {
        Self {
            send: [0; 32],
            recv: [0; 32],
            local_index: 0,
            peer_index: 0,
            is_initiator: false,
        }
    }

    /// Copy `other` into `self` — straight from one place to the other —
    /// and wipe `other`. Keys are never moved as a value: a moved value
    /// leaves its bytes behind wherever it was.
    pub(crate) fn take_from(&mut self, other: &mut Self) {
        ct::copy_secret(&mut self.send, &other.send);
        ct::copy_secret(&mut self.recv, &other.recv);
        self.local_index = other.local_index;
        self.peer_index = other.peer_index;
        self.is_initiator = other.is_initiator;
        other.wipe();
    }

    /// Zero everything where it lies.
    pub(crate) fn wipe(&mut self) {
        ct::wipe_array(&mut self.send);
        ct::wipe_array(&mut self.recv);
        self.local_index = 0;
        self.peer_index = 0;
        self.is_initiator = false;
    }

    /// Does this hold nothing? (For tests of the wiping.)
    #[cfg(test)]
    pub(crate) fn is_blank(&self) -> bool {
        self.send == [0; 32]
            && self.recv == [0; 32]
            && self.local_index == 0
            && self.peer_index == 0
            && !self.is_initiator
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SessionKeys(local={}, peer={}, initiator={})",
            self.local_index, self.peer_index, self.is_initiator
        )
    }
}

/// `H := Hash(H ∥ part)`, the Noise mixHash operation.
fn mix_hash<P: CryptoProvider>(h: &mut [u8; 32], part: &[u8]) {
    let mut next = Secret::zero();
    P::hash(&[h.as_slice(), part], &mut next.0);
    ct::copy_secret(h, &next.0);
}

/// Build a handshake initiation (whitepaper §5.4.2) into `out` with zeroed
/// mac fields, drawing the ephemeral key from `rng`. `precomputed_ss` is
/// `DH(S_priv_local, S_pub_peer)`, computed once at tunnel construction.
///
/// The handshake state is written into `state`, which holds it on success
/// and is all-zero on failure.
///
/// # Errors
/// `BufferTooSmall`; `EntropyFailure`; `InvalidPublicKey` if the
/// configured peer key is low-order (configuration error, no message
/// emitted).
#[allow(clippy::too_many_arguments)] // internal plumbing; every argument is distinct state
pub(crate) fn create_initiation<P: CryptoProvider>(
    constants: &HandshakeConstants,
    local_public: &PublicKey,
    peer_public: &PublicKey,
    precomputed_ss: &[u8; 32],
    local_index: u32,
    timestamp: Tai64N,
    rng: &mut dyn EntropySource,
    out: &mut [u8],
    state: &mut InFlightInitiation,
) -> Result<(), Error> {
    state.wipe();
    let result = build_initiation::<P>(
        constants,
        local_public,
        peer_public,
        precomputed_ss,
        local_index,
        timestamp,
        rng,
        out,
        state,
    );
    if result.is_err() {
        state.wipe();
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn build_initiation<P: CryptoProvider>(
    constants: &HandshakeConstants,
    local_public: &PublicKey,
    peer_public: &PublicKey,
    precomputed_ss: &[u8; 32],
    local_index: u32,
    timestamp: Tai64N,
    rng: &mut dyn EntropySource,
    out: &mut [u8],
    state: &mut InFlightInitiation,
) -> Result<(), Error> {
    // Check buffer up front so we never compute secrets we then discard.
    if out.len() < HANDSHAKE_INITIATION_LEN {
        return Err(Error::BufferTooSmall);
    }
    // The ephemeral private key is drawn straight into the state.
    rng.fill(&mut state.eph_secret)
        .map_err(|_| Error::EntropyFailure)?;
    state.local_index = local_index;
    ct::copy_secret(&mut state.chain, &constants.ck0);
    ct::copy_secret(&mut state.hash, &constants.h0);
    mix_hash::<P>(&mut state.hash, peer_public.as_bytes());

    let eph_public = P::x25519_public(&state.eph_secret);
    kdf::kdf_chain::<P, 0>(&mut state.chain, &eph_public, []);
    mix_hash::<P>(&mut state.hash, &eph_public);

    // es
    let mut dh = Secret::zero();
    let mut k = Secret::zero();
    if !P::x25519(&state.eph_secret, peer_public.as_bytes(), &mut dh.0) {
        return Err(Error::InvalidPublicKey);
    }
    kdf::kdf_chain::<P, 1>(&mut state.chain, &dh.0, [&mut k.0]);
    let mut encrypted_static = [0u8; 48];
    copy_prefix(&mut encrypted_static, local_public.as_bytes());
    P::seal_in_place(&k.0, 0, &state.hash, 32, &mut encrypted_static)?;
    mix_hash::<P>(&mut state.hash, &encrypted_static);

    // ss (precomputed once at tunnel construction; never changes)
    kdf::kdf_chain::<P, 1>(&mut state.chain, precomputed_ss, [&mut k.0]);
    let mut encrypted_timestamp = [0u8; 28];
    copy_prefix(&mut encrypted_timestamp, timestamp.as_bytes());
    P::seal_in_place(&k.0, 0, &state.hash, 12, &mut encrypted_timestamp)?;
    mix_hash::<P>(&mut state.hash, &encrypted_timestamp);

    message::build_initiation(
        out,
        local_index,
        &eph_public,
        &encrypted_static,
        &encrypted_timestamp,
    )?;
    Ok(())
}

/// What the `es` step of a received initiation reveals: the static public
/// key the initiator claims, and the handshake state up to that point.
///
/// At this point the sender has shown that it knows *our* public key and
/// holds the private key for the ephemeral it sent; it has **not** yet
/// been shown to hold the private key for `static_public` (that is what
/// [`consume_initiation_finish`] verifies), and the message may be a
/// replay.
pub(crate) struct Identity {
    /// Filled in (by [`identify_initiation`]).
    pub known: bool,
    pub static_public: [u8; 32],
    chain: [u8; 32],
    hash: [u8; 32],
}

impl Identity {
    /// Nothing known: all zero.
    pub(crate) const fn blank() -> Self {
        Self {
            known: false,
            static_public: [0; 32],
            chain: [0; 32],
            hash: [0; 32],
        }
    }

    /// Zero everything where it lies.
    pub(crate) fn wipe(&mut self) {
        self.known = false;
        ct::wipe_array(&mut self.static_public);
        ct::wipe_array(&mut self.chain);
        ct::wipe_array(&mut self.hash);
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity(known={})", self.known)
    }
}

/// First half of processing a received initiation (whitepaper §5.4.2,
/// responder side): the `es` Diffie-Hellman and the AEAD that reveals the
/// initiator's static public key. `mac1` must already have been verified
/// by the caller.
///
/// The result is written into `identity`, which is all-zero (and not
/// `known`) on failure.
///
/// # Errors
/// `InvalidPublicKey` for a low-order ephemeral; `AuthFailure` if the
/// static key does not decrypt (forgery, or a message for another
/// responder).
pub(crate) fn identify_initiation<P: CryptoProvider>(
    constants: &HandshakeConstants,
    local_static: &StaticSecret,
    local_public: &PublicKey,
    msg: &HandshakeInitiation<'_>,
    identity: &mut Identity,
) -> Result<(), DropReason> {
    identity.wipe();
    let result = reveal_identity::<P>(constants, local_static, local_public, msg, identity);
    if result.is_err() {
        identity.wipe();
    }
    result
}

fn reveal_identity<P: CryptoProvider>(
    constants: &HandshakeConstants,
    local_static: &StaticSecret,
    local_public: &PublicKey,
    msg: &HandshakeInitiation<'_>,
    identity: &mut Identity,
) -> Result<(), DropReason> {
    ct::copy_secret(&mut identity.chain, &constants.ck0);
    ct::copy_secret(&mut identity.hash, &constants.h0);
    mix_hash::<P>(&mut identity.hash, local_public.as_bytes());

    kdf::kdf_chain::<P, 0>(&mut identity.chain, msg.ephemeral, []);
    mix_hash::<P>(&mut identity.hash, msg.ephemeral);

    // es (from the responder's side: DH(S_priv_r, E_pub_i)).
    let mut dh = Secret::zero();
    let mut k = Secret::zero();
    if !P::x25519(local_static.as_bytes(), msg.ephemeral, &mut dh.0) {
        return Err(DropReason::InvalidPublicKey);
    }
    kdf::kdf_chain::<P, 1>(&mut identity.chain, &dh.0, [&mut k.0]);
    // The decrypted identity is hidden on the wire: the working copy is
    // wiped as well.
    let mut opened_static = *msg.encrypted_static;
    let opened = P::open_in_place(&k.0, 0, &identity.hash, &mut opened_static);
    let decrypted = opened == Some(32);
    if decrypted {
        copy_prefix(&mut identity.static_public, &opened_static);
    }
    ct::wipe_array(&mut opened_static);
    if !decrypted {
        return Err(DropReason::AuthFailure);
    }
    mix_hash::<P>(&mut identity.hash, msg.encrypted_static);
    identity.known = true;
    Ok(())
}

/// Everything a verified-and-decrypted initiation tells the responder.
/// Consumed by [`create_response`].
pub(crate) struct ConsumedInitiation {
    /// The initiator's session index.
    pub peer_index: u32,
    /// Decrypted TAI64N timestamp. The caller **must** enforce strict
    /// monotonicity per peer before responding.
    pub timestamp: Tai64N,
    /// The initiator's static public key — verified to equal the
    /// configured peer; kept because [`create_response`] needs it for the
    /// `se` step.
    static_public: [u8; 32],
    eph_public: [u8; 32],
    chain: [u8; 32],
    hash: [u8; 32],
}

impl ConsumedInitiation {
    /// Nothing consumed: all zero.
    pub(crate) fn blank() -> Self {
        Self {
            peer_index: 0,
            timestamp: Tai64N::from_bytes([0; 12]),
            static_public: [0; 32],
            eph_public: [0; 32],
            chain: [0; 32],
            hash: [0; 32],
        }
    }

    fn wipe(&mut self) {
        self.peer_index = 0;
        self.timestamp = Tai64N::from_bytes([0; 12]);
        ct::wipe_array(&mut self.static_public);
        ct::wipe_array(&mut self.eph_public);
        ct::wipe_array(&mut self.chain);
        ct::wipe_array(&mut self.hash);
    }
}

impl Drop for ConsumedInitiation {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl core::fmt::Debug for ConsumedInitiation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ConsumedInitiation(peer_index={})", self.peer_index)
    }
}

/// Second half of processing a received initiation: verify the initiator
/// is the configured peer, then the `ss` step and the timestamp AEAD.
///
/// `precomputed_ss` is `DH(S_priv_local, S_pub_peer)`, computed once at
/// tunnel construction. The identity check comes first, so `precomputed_ss`
/// is exactly `DH(S_priv_r, static_public)` — no recomputation, and the
/// static private key is never used against an attacker-chosen static
/// key. This matches BoringTun and the kernel.
///
/// The result is written into `consumed`, which is all-zero on failure.
///
/// # Errors
/// `UnknownPeer` if the initiation's static key is not `peer_public`;
/// `AuthFailure` if the timestamp does not decrypt (the sender does not
/// hold the private key it claims).
pub(crate) fn consume_initiation_finish<P: CryptoProvider>(
    msg: &HandshakeInitiation<'_>,
    identity: &Identity,
    peer_public: &PublicKey,
    precomputed_ss: &[u8; 32],
    consumed: &mut ConsumedInitiation,
) -> Result<(), DropReason> {
    consumed.wipe();
    let result = finish_initiation::<P>(msg, identity, peer_public, precomputed_ss, consumed);
    if result.is_err() {
        consumed.wipe();
    }
    result
}

fn finish_initiation<P: CryptoProvider>(
    msg: &HandshakeInitiation<'_>,
    identity: &Identity,
    peer_public: &PublicKey,
    precomputed_ss: &[u8; 32],
    consumed: &mut ConsumedInitiation,
) -> Result<(), DropReason> {
    if !identity.known || !ct::ct_eq(&identity.static_public, peer_public.as_bytes()) {
        return Err(DropReason::UnknownPeer);
    }
    ct::copy_secret(&mut consumed.chain, &identity.chain);
    ct::copy_secret(&mut consumed.hash, &identity.hash);

    // ss (precomputed once at tunnel construction; never changes).
    let mut k = Secret::zero();
    kdf::kdf_chain::<P, 1>(&mut consumed.chain, precomputed_ss, [&mut k.0]);
    let mut opened_timestamp = *msg.encrypted_timestamp;
    let opened = P::open_in_place(&k.0, 0, &consumed.hash, &mut opened_timestamp);
    if opened != Some(12) {
        return Err(DropReason::AuthFailure);
    }
    let (timestamp, _tag) = opened_timestamp
        .split_first_chunk::<12>()
        .ok_or(DropReason::AuthFailure)?;
    mix_hash::<P>(&mut consumed.hash, msg.encrypted_timestamp);

    consumed.peer_index = msg.sender_index;
    consumed.timestamp = Tai64N::from_bytes(*timestamp);
    ct::copy_secret(&mut consumed.static_public, &identity.static_public);
    ct::copy_secret(&mut consumed.eph_public, msg.ephemeral);
    Ok(())
}

/// Build the handshake response (whitepaper §5.4.3) and derive transport
/// keys (§5.4.5), responder side. The ephemeral key is drawn from `rng`.
///
/// The transport keys are written into `keys`, which is all-zero on
/// failure.
///
/// # Errors
/// `Fault(BufferTooSmall)`; `Fault(EntropyFailure)`;
/// `Drop(InvalidPublicKey)` for a low-order initiator ephemeral.
pub(crate) fn create_response<P: CryptoProvider>(
    consumed: &ConsumedInitiation,
    psk: &PresharedKey,
    local_index: u32,
    rng: &mut dyn EntropySource,
    out: &mut [u8],
    keys: &mut SessionKeys,
) -> Result<(), Reject> {
    keys.wipe();
    if out.len() < HANDSHAKE_RESPONSE_LEN {
        return Err(Reject::Fault(Error::BufferTooSmall));
    }
    let mut eph_secret = Secret::zero();
    rng.fill(&mut eph_secret.0)
        .map_err(|_| Reject::Fault(Error::EntropyFailure))?;

    let mut ck = Secret::zero();
    let mut h = Secret::zero();
    ct::copy_secret(&mut ck.0, &consumed.chain);
    ct::copy_secret(&mut h.0, &consumed.hash);

    let eph_public = P::x25519_public(&eph_secret.0);
    kdf::kdf_chain::<P, 0>(&mut ck.0, &eph_public, []);
    mix_hash::<P>(&mut h.0, &eph_public);

    // ee
    let mut dh = Secret::zero();
    if !P::x25519(&eph_secret.0, &consumed.eph_public, &mut dh.0) {
        return Err(Reject::Drop(DropReason::InvalidPublicKey));
    }
    kdf::kdf_chain::<P, 0>(&mut ck.0, &dh.0, []);
    // se (responder side: DH(E_priv_r, S_pub_i)). `static_public` is the
    // configured peer key, validated when the tunnel was built, so a
    // zero result here would be an internal inconsistency.
    if !P::x25519(&eph_secret.0, &consumed.static_public, &mut dh.0) {
        return Err(Reject::Fault(Error::Internal));
    }
    kdf::kdf_chain::<P, 0>(&mut ck.0, &dh.0, []);

    // psk2
    let mut tau = Secret::zero();
    let mut k = Secret::zero();
    kdf::kdf_chain::<P, 2>(&mut ck.0, psk.as_bytes(), [&mut tau.0, &mut k.0]);
    mix_hash::<P>(&mut h.0, &tau.0);

    let mut encrypted_nothing = [0u8; 16];
    P::seal_in_place(&k.0, 0, &h.0, 0, &mut encrypted_nothing)?;
    mix_hash::<P>(&mut h.0, &encrypted_nothing);

    message::build_response(
        out,
        local_index,
        consumed.peer_index,
        &eph_public,
        &encrypted_nothing,
    )?;

    // (T_send_i = T_recv_r, T_recv_i = T_send_r) := Kdf2(C, ε), each key
    // written straight into the place it is used from.
    kdf::kdf_into::<P, 2>(&ck.0, &[], [&mut keys.recv, &mut keys.send]);
    keys.local_index = local_index;
    keys.peer_index = consumed.peer_index;
    keys.is_initiator = false;
    Ok(())
}

/// Process the handshake response (whitepaper §5.4.3, initiator side) and
/// derive transport keys. The caller has already matched
/// `msg.receiver_index` to `inflight.local_index`; `mac1` was verified by
/// the device.
///
/// The transport keys are written into `keys`, which is all-zero on
/// failure.
///
/// # Errors
/// `AuthFailure` if the final AEAD fails (wrong PSK, tampering, wrong
/// responder); `InvalidPublicKey` for a low-order responder ephemeral.
pub(crate) fn consume_response<P: CryptoProvider>(
    inflight: &InFlightInitiation,
    local_static: &StaticSecret,
    psk: &PresharedKey,
    msg: &HandshakeResponse<'_>,
    keys: &mut SessionKeys,
) -> Result<(), DropReason> {
    keys.wipe();
    let mut ck = Secret::zero();
    let mut h = Secret::zero();
    ct::copy_secret(&mut ck.0, &inflight.chain);
    ct::copy_secret(&mut h.0, &inflight.hash);

    kdf::kdf_chain::<P, 0>(&mut ck.0, msg.ephemeral, []);
    mix_hash::<P>(&mut h.0, msg.ephemeral);

    // ee
    let mut dh = Secret::zero();
    if !P::x25519(&inflight.eph_secret, msg.ephemeral, &mut dh.0) {
        return Err(DropReason::InvalidPublicKey);
    }
    kdf::kdf_chain::<P, 0>(&mut ck.0, &dh.0, []);
    // se (initiator side: DH(S_priv_i, E_pub_r)).
    if !P::x25519(local_static.as_bytes(), msg.ephemeral, &mut dh.0) {
        return Err(DropReason::InvalidPublicKey);
    }
    kdf::kdf_chain::<P, 0>(&mut ck.0, &dh.0, []);

    // psk2
    let mut tau = Secret::zero();
    let mut k = Secret::zero();
    kdf::kdf_chain::<P, 2>(&mut ck.0, psk.as_bytes(), [&mut tau.0, &mut k.0]);
    mix_hash::<P>(&mut h.0, &tau.0);

    let mut nothing = *msg.encrypted_nothing;
    if P::open_in_place(&k.0, 0, &h.0, &mut nothing) != Some(0) {
        return Err(DropReason::AuthFailure);
    }

    kdf::kdf_into::<P, 2>(&ck.0, &[], [&mut keys.send, &mut keys.recv]);
    keys.local_index = inflight.local_index;
    keys.peer_index = msg.sender_index;
    keys.is_initiator = true;
    Ok(())
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
    use crate::crypto::{InTree, x25519};
    use crate::message::{Packet, parse};
    use crate::testing::DeterministicRng;
    use std::vec;

    type P = InTree;

    struct Party {
        secret: StaticSecret,
        public: PublicKey,
    }

    fn party(rng: &mut DeterministicRng) -> Party {
        let secret = StaticSecret::generate(rng).unwrap();
        let public = secret.public_key();
        Party { secret, public }
    }

    fn ss(a: &Party, b: &Party) -> [u8; 32] {
        x25519::shared_secret(a.secret.as_bytes(), b.public.as_bytes()).unwrap()
    }

    /// Both halves of consuming an initiation, as device + tunnel run them.
    fn consume_initiation(
        constants: &HandshakeConstants,
        responder: &Party,
        configured_peer: &Party,
        msg: &HandshakeInitiation<'_>,
    ) -> Result<ConsumedInitiation, DropReason> {
        let mut identity = Identity::blank();
        identify_initiation::<P>(
            constants,
            &responder.secret,
            &responder.public,
            msg,
            &mut identity,
        )?;
        let mut consumed = ConsumedInitiation::blank();
        consume_initiation_finish::<P>(
            msg,
            &identity,
            &configured_peer.public,
            &ss(responder, configured_peer),
            &mut consumed,
        )?;
        Ok(consumed)
    }

    /// `from` builds an initiation for `to`, claiming the static-static
    /// secret `ss`.
    #[allow(clippy::too_many_arguments)]
    fn initiate(
        constants: &HandshakeConstants,
        from: &Party,
        to: &Party,
        ss: &[u8; 32],
        index: u32,
        timestamp: Tai64N,
        rng: &mut DeterministicRng,
        wire: &mut [u8],
    ) -> Result<InFlightInitiation, Error> {
        let mut state = InFlightInitiation::blank();
        create_initiation::<P>(
            constants,
            &from.public,
            &to.public,
            ss,
            index,
            timestamp,
            rng,
            wire,
            &mut state,
        )?;
        Ok(state)
    }

    fn run_handshake(psk_i: &PresharedKey, psk_r: &PresharedKey) -> Result<(), Reject> {
        let mut rng = DeterministicRng::new(0xabcdef);
        let constants = HandshakeConstants::new::<P>();
        let init = party(&mut rng);
        let resp = party(&mut rng);

        // Initiator → initiation.
        let mut wire1 = vec![0u8; HANDSHAKE_INITIATION_LEN];
        let inflight = initiate(
            &constants,
            &init,
            &resp,
            &ss(&init, &resp),
            0x1111,
            Tai64N::from_unix(1_700_000_000, 0),
            &mut rng,
            &mut wire1,
        )?;

        // Responder consumes and responds.
        let parsed = match parse(&wire1)? {
            Packet::HandshakeInitiation(m) => m,
            _ => return Err(Error::Internal.into()),
        };
        let mut identity = Identity::blank();
        identify_initiation::<P>(
            &constants,
            &resp.secret,
            &resp.public,
            &parsed,
            &mut identity,
        )?;
        assert!(identity.known);
        assert_eq!(&identity.static_public, init.public.as_bytes());
        let mut consumed = ConsumedInitiation::blank();
        consume_initiation_finish::<P>(
            &parsed,
            &identity,
            &init.public,
            &ss(&resp, &init),
            &mut consumed,
        )?;
        assert_eq!(consumed.peer_index, 0x1111);
        assert_eq!(
            consumed.timestamp,
            Tai64N::from_unix(1_700_000_000, 0),
            "timestamp must round-trip"
        );

        let mut wire2 = vec![0u8; HANDSHAKE_RESPONSE_LEN];
        let mut resp_keys = SessionKeys::blank();
        create_response::<P>(
            &consumed,
            psk_r,
            0x2222,
            &mut rng,
            &mut wire2,
            &mut resp_keys,
        )?;

        // Initiator consumes the response.
        let parsed = match parse(&wire2)? {
            Packet::HandshakeResponse(m) => m,
            _ => return Err(Error::Internal.into()),
        };
        assert_eq!(parsed.receiver_index, 0x1111);
        let mut init_keys = SessionKeys::blank();
        let outcome =
            consume_response::<P>(&inflight, &init.secret, psk_i, &parsed, &mut init_keys);
        if outcome.is_err() {
            assert!(init_keys.is_blank(), "a failed response leaves no keys");
        }
        outcome?;

        // Key agreement, direction-crossed.
        assert_eq!(init_keys.send, resp_keys.recv);
        assert_eq!(init_keys.recv, resp_keys.send);
        assert_ne!(init_keys.send, init_keys.recv, "directions must differ");
        assert!(init_keys.is_initiator && !resp_keys.is_initiator);
        assert_eq!(init_keys.peer_index, 0x2222);
        assert_eq!(resp_keys.peer_index, 0x1111);
        Ok(())
    }

    #[test]
    fn full_handshake_agrees_without_psk() {
        run_handshake(&PresharedKey::default(), &PresharedKey::default()).unwrap();
    }

    #[test]
    fn full_handshake_agrees_with_psk() {
        let psk = PresharedKey::from_bytes([0x42; 32]);
        run_handshake(&psk.clone(), &psk).unwrap();
    }

    #[test]
    fn psk_mismatch_fails_closed() {
        let a = PresharedKey::from_bytes([1; 32]);
        let b = PresharedKey::from_bytes([2; 32]);
        assert_eq!(
            run_handshake(&a, &b),
            Err(Reject::Drop(DropReason::AuthFailure))
        );
        // Zero vs non-zero also fails (psk-mode mismatch).
        assert_eq!(
            run_handshake(&PresharedKey::default(), &PresharedKey::from_bytes([3; 32])),
            Err(Reject::Drop(DropReason::AuthFailure))
        );
    }

    #[test]
    fn initiation_for_wrong_responder_fails() {
        let mut rng = DeterministicRng::new(7);
        let constants = HandshakeConstants::new::<P>();
        let init = party(&mut rng);
        let resp = party(&mut rng);
        let mallory = party(&mut rng);

        let mut wire = vec![0u8; HANDSHAKE_INITIATION_LEN];
        initiate(
            &constants,
            &init,
            &resp,
            &ss(&init, &resp),
            1,
            Tai64N::from_unix(0, 0),
            &mut rng,
            &mut wire,
        )
        .unwrap();
        let parsed = match parse(&wire).unwrap() {
            Packet::HandshakeInitiation(m) => m,
            _ => unreachable!(),
        };
        // Mallory (not the addressed responder) cannot even decrypt the
        // initiator's identity.
        assert_eq!(
            consume_initiation(&constants, &mallory, &init, &parsed).err(),
            Some(DropReason::AuthFailure)
        );
        // Correct responder, but the tunnel it is handed to is configured
        // for a different peer: rejected as UnknownPeer, before the `ss`
        // step.
        assert_eq!(
            consume_initiation(&constants, &resp, &mallory, &parsed).err(),
            Some(DropReason::UnknownPeer)
        );
    }

    /// An initiation built with a static key the sender does not hold the
    /// private half of: the identity decrypts (anyone can encrypt a public
    /// key), but the `ss`-keyed timestamp cannot be produced.
    #[test]
    fn claimed_identity_without_its_private_key_fails_at_the_timestamp() {
        let mut rng = DeterministicRng::new(8);
        let constants = HandshakeConstants::new::<P>();
        let victim = party(&mut rng); // the configured peer being impersonated
        let resp = party(&mut rng);
        let mallory = party(&mut rng);

        // Mallory claims the victim's public key but can only compute
        // DH(mallory_priv, resp_pub) for the `ss` step.
        let mut wire = vec![0u8; HANDSHAKE_INITIATION_LEN];
        initiate(
            &constants,
            &victim,
            &resp,
            &ss(&mallory, &resp),
            1,
            Tai64N::from_unix(5, 0),
            &mut rng,
            &mut wire,
        )
        .unwrap();
        let parsed = match parse(&wire).unwrap() {
            Packet::HandshakeInitiation(m) => m,
            _ => unreachable!(),
        };
        let mut identity = Identity::blank();
        identify_initiation::<P>(
            &constants,
            &resp.secret,
            &resp.public,
            &parsed,
            &mut identity,
        )
        .unwrap();
        assert_eq!(
            &identity.static_public,
            victim.public.as_bytes(),
            "identity is claimed"
        );
        let mut consumed = ConsumedInitiation::blank();
        assert_eq!(
            consume_initiation_finish::<P>(
                &parsed,
                &identity,
                &victim.public,
                &ss(&resp, &victim),
                &mut consumed
            )
            .err(),
            Some(DropReason::AuthFailure),
            "…but not proven"
        );
        assert_eq!(consumed.chain, [0u8; 32], "nothing is left of the attempt");
        assert_eq!(consumed.hash, [0u8; 32]);
    }

    #[test]
    fn tampered_initiation_fields_fail() {
        let mut rng = DeterministicRng::new(9);
        let constants = HandshakeConstants::new::<P>();
        let init = party(&mut rng);
        let resp = party(&mut rng);

        let mut wire = vec![0u8; HANDSHAKE_INITIATION_LEN];
        initiate(
            &constants,
            &init,
            &resp,
            &ss(&init, &resp),
            1,
            Tai64N::from_unix(0, 0),
            &mut rng,
            &mut wire,
        )
        .unwrap();
        // Flip one bit in every non-mac byte: consume must fail (macs are
        // checked by the device; here even without them nothing forged may
        // pass the AEADs).
        for byte in 8..116 {
            let mut bad = wire.clone();
            bad[byte] ^= 1;
            let parsed = match parse(&bad).unwrap() {
                Packet::HandshakeInitiation(m) => m,
                _ => unreachable!(),
            };
            let r = consume_initiation(&constants, &resp, &init, &parsed);
            assert!(r.is_err(), "tamper at byte {byte} accepted");
        }
    }

    #[test]
    fn low_order_ephemerals_are_rejected() {
        let mut rng = DeterministicRng::new(10);
        let constants = HandshakeConstants::new::<P>();
        let init = party(&mut rng);
        let resp = party(&mut rng);
        let mut wire = vec![0u8; HANDSHAKE_INITIATION_LEN];
        let inflight = initiate(
            &constants,
            &init,
            &resp,
            &ss(&init, &resp),
            1,
            Tai64N::from_unix(0, 0),
            &mut rng,
            &mut wire,
        )
        .unwrap();
        // Initiation with an all-zero ephemeral: rejected at the device's
        // step, before any AEAD.
        let mut bad = wire.clone();
        bad[8..40].fill(0);
        let parsed = match parse(&bad).unwrap() {
            Packet::HandshakeInitiation(m) => m,
            _ => unreachable!(),
        };
        let mut identity = Identity::blank();
        assert_eq!(
            identify_initiation::<P>(
                &constants,
                &resp.secret,
                &resp.public,
                &parsed,
                &mut identity
            )
            .err(),
            Some(DropReason::InvalidPublicKey)
        );
        assert!(!identity.known);
        assert_eq!(identity.chain, [0u8; 32], "nothing is left of the attempt");
        assert_eq!(identity.hash, [0u8; 32]);
        // Response with an all-zero ephemeral: rejected by the initiator.
        let mut resp_wire = vec![0u8; HANDSHAKE_RESPONSE_LEN];
        message::build_response(&mut resp_wire, 2, 1, &[0u8; 32], &[0u8; 16]).unwrap();
        let parsed = match parse(&resp_wire).unwrap() {
            Packet::HandshakeResponse(m) => m,
            _ => unreachable!(),
        };
        let mut keys = SessionKeys::blank();
        assert_eq!(
            consume_response::<P>(
                &inflight,
                &init.secret,
                &PresharedKey::default(),
                &parsed,
                &mut keys
            )
            .err(),
            Some(DropReason::InvalidPublicKey)
        );
        assert!(keys.is_blank());
    }

    #[test]
    fn buffers_too_small_are_local_faults() {
        let mut rng = DeterministicRng::new(12);
        let constants = HandshakeConstants::new::<P>();
        let init = party(&mut rng);
        let resp = party(&mut rng);
        let mut tiny = [0u8; HANDSHAKE_INITIATION_LEN - 1];
        assert_eq!(
            initiate(
                &constants,
                &init,
                &resp,
                &ss(&init, &resp),
                1,
                Tai64N::from_unix(0, 0),
                &mut rng,
                &mut tiny,
            )
            .err(),
            Some(Error::BufferTooSmall)
        );
        let mut wire = vec![0u8; HANDSHAKE_INITIATION_LEN];
        initiate(
            &constants,
            &init,
            &resp,
            &ss(&init, &resp),
            1,
            Tai64N::from_unix(0, 0),
            &mut rng,
            &mut wire,
        )
        .unwrap();
        let parsed = match parse(&wire).unwrap() {
            Packet::HandshakeInitiation(m) => m,
            _ => unreachable!(),
        };
        let consumed = consume_initiation(&constants, &resp, &init, &parsed).unwrap();
        let mut tiny = [0u8; HANDSHAKE_RESPONSE_LEN - 1];
        let mut keys = SessionKeys::blank();
        assert_eq!(
            create_response::<P>(
                &consumed,
                &PresharedKey::default(),
                2,
                &mut rng,
                &mut tiny,
                &mut keys
            )
            .err(),
            Some(Reject::Fault(Error::BufferTooSmall))
        );
        assert!(keys.is_blank());
    }

    #[test]
    fn chain_constants_match_reference_implementations() {
        // These exact bytes appear as precomputed constants in BoringTun
        // (cloudflare/boringtun src/noise/handshake.rs: INITIAL_CHAIN_KEY
        // and INITIAL_CHAIN_HASH). Agreeing with them anchors our whole
        // BLAKE2s + construction-string pipeline to a third party.
        let c = HandshakeConstants::new::<P>();
        assert_eq!(
            c.ck0,
            [
                0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25,
                0xd2, 0xd0, 0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98,
                0x8b, 0x78, 0xcd, 0x36
            ]
        );
        assert_eq!(
            c.h0,
            [
                0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a,
                0xd5, 0x32, 0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7, 0x0e, 0xe1, 0x9c, 0x65,
                0xba, 0x07, 0x9e, 0xf3
            ]
        );
    }

    #[test]
    fn fresh_entropy_gives_fresh_sessions() {
        // Two handshakes between the same parties must never share keys
        // (forward secrecy comes from the ephemerals).
        let mut rng = DeterministicRng::new(0x5151);
        let constants = HandshakeConstants::new::<P>();
        let init = party(&mut rng);
        let resp = party(&mut rng);
        let mut keys = vec![];
        for i in 0..2 {
            let mut w1 = vec![0u8; HANDSHAKE_INITIATION_LEN];
            let inflight = initiate(
                &constants,
                &init,
                &resp,
                &ss(&init, &resp),
                i,
                Tai64N::from_unix(i.into(), 0),
                &mut rng,
                &mut w1,
            )
            .unwrap();
            let parsed = match parse(&w1).unwrap() {
                Packet::HandshakeInitiation(m) => m,
                _ => unreachable!(),
            };
            let consumed = consume_initiation(&constants, &resp, &init, &parsed).unwrap();
            let mut w2 = vec![0u8; HANDSHAKE_RESPONSE_LEN];
            let mut rk = SessionKeys::blank();
            create_response::<P>(
                &consumed,
                &PresharedKey::default(),
                i,
                &mut rng,
                &mut w2,
                &mut rk,
            )
            .unwrap();
            let parsed = match parse(&w2).unwrap() {
                Packet::HandshakeResponse(m) => m,
                _ => unreachable!(),
            };
            let mut ik = SessionKeys::blank();
            consume_response::<P>(
                &inflight,
                &init.secret,
                &PresharedKey::default(),
                &parsed,
                &mut ik,
            )
            .unwrap();
            assert_eq!((ik.send, ik.recv), (rk.recv, rk.send));
            keys.push((ik.send, ik.recv));
        }
        assert_ne!(keys[0], keys[1]);
    }

    /// A failure leaves nothing in the caller's storage: no half-built
    /// in-flight state, whatever the reason.
    #[test]
    fn a_failed_initiation_leaves_the_state_blank() {
        let mut rng = DeterministicRng::new(13);
        let constants = HandshakeConstants::new::<P>();
        let init = party(&mut rng);
        let resp = party(&mut rng);
        let mut state = InFlightInitiation::blank();
        // Entropy failure, before anything is computed.
        let mut wire = vec![0u8; HANDSHAKE_INITIATION_LEN];
        assert_eq!(
            create_initiation::<P>(
                &constants,
                &init.public,
                &resp.public,
                &ss(&init, &resp),
                7,
                Tai64N::from_unix(0, 0),
                &mut crate::testing::FailingRng,
                &mut wire,
                &mut state,
            ),
            Err(Error::EntropyFailure)
        );
        assert!(state.is_blank());
        // A low-order peer key: fails after the ephemeral was drawn.
        let low_order = PublicKey::from_bytes([0u8; 32]);
        assert_eq!(
            create_initiation::<P>(
                &constants,
                &init.public,
                &low_order,
                &[1u8; 32],
                7,
                Tai64N::from_unix(0, 0),
                &mut rng,
                &mut wire,
                &mut state,
            ),
            Err(Error::InvalidPublicKey)
        );
        assert!(state.is_blank());
        // And a state that held an earlier handshake is replaced, not
        // mixed: a second success overwrites every field.
        create_initiation::<P>(
            &constants,
            &init.public,
            &resp.public,
            &ss(&init, &resp),
            7,
            Tai64N::from_unix(0, 0),
            &mut rng,
            &mut wire,
            &mut state,
        )
        .unwrap();
        let first = (state.eph_secret, state.chain, state.hash);
        create_initiation::<P>(
            &constants,
            &init.public,
            &resp.public,
            &ss(&init, &resp),
            8,
            Tai64N::from_unix(1, 0),
            &mut rng,
            &mut wire,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.local_index, 8);
        assert_ne!(state.eph_secret, first.0);
        assert_ne!(state.chain, first.1);
        assert_ne!(state.hash, first.2);
    }

    /// `take_from` leaves the source wiped; `wipe` leaves nothing.
    #[test]
    fn key_bearing_values_are_taken_and_wiped_in_place() {
        let mut a = SessionKeys {
            send: [1; 32],
            recv: [2; 32],
            local_index: 3,
            peer_index: 4,
            is_initiator: true,
        };
        let mut b = SessionKeys::blank();
        b.take_from(&mut a);
        assert!(a.is_blank(), "the source is wiped");
        assert_eq!((b.send, b.recv), ([1; 32], [2; 32]));
        assert_eq!((b.local_index, b.peer_index, b.is_initiator), (3, 4, true));
        b.wipe();
        assert!(b.is_blank());

        let mut x = InFlightInitiation {
            local_index: 9,
            eph_secret: [5; 32],
            chain: [6; 32],
            hash: [7; 32],
        };
        let mut y = InFlightInitiation::blank();
        y.take_from(&mut x);
        assert!(x.is_blank(), "the source is wiped");
        assert_eq!(y.local_index, 9);
        assert_eq!((y.eph_secret, y.chain, y.hash), ([5; 32], [6; 32], [7; 32]));
        y.wipe();
        assert!(y.is_blank());
    }
}
