//! Error and drop-reason types.
//!
//! The crate separates two things that are easy to conflate:
//!
//! * [`Error`] — a **local fault**: the caller's buffer, the caller's
//!   entropy source, the caller's configuration, or a bug in this crate.
//!   Nothing a remote party sends can produce one, so propagating it with
//!   `?` out of a receive loop is safe.
//! * [`DropReason`] — why an **inbound datagram was rejected**. Rejecting
//!   datagrams is the expected steady state on the open internet, so it is
//!   never an `Err`: it is reported inside the `Ok` value
//!   ([`crate::Incoming::Dropped`], [`crate::Received::Dropped`]).

use core::fmt;

/// A local fault. Never caused by a remote party.
///
/// An operation that returns `Err` has sent nothing and lost nothing, and
/// may be repeated once the fault is fixed. With two exceptions, both
/// harmless and documented on [`crate::Tunnel`] ("Errors and state"), it
/// has also left the protocol state exactly as it was: a session index
/// that was reserved is not used again, and [`crate::Tunnel::poll`] has
/// dealt with the timers that were due before the step that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The provided output buffer is too small for the message that needs
    /// to be written. The required sizes are fixed and documented on each
    /// method; see also [`crate::transport_datagram_len`].
    BufferTooSmall,
    /// The configured [`crate::EntropySource`] reported failure. No message
    /// was produced.
    EntropyFailure,
    /// A configured public key cannot work: the peer's key equals our own,
    /// or it is a low-order point (the shared secret would be all-zero).
    InvalidPublicKey,
    /// The payload is longer than one ChaCha20-Poly1305 message can be
    /// ([`crate::crypto::aead::MAX_MESSAGE_LEN`], a little under 256 GiB).
    /// Nothing was encrypted.
    MessageTooLong,
    /// An internal invariant did not hold. This is a defensive replacement
    /// for `panic!`: it should never be observed, and observing it
    /// indicates a bug in this crate. The state machine remains in a safe
    /// state.
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::BufferTooSmall => "output buffer too small",
            Self::EntropyFailure => "entropy source failed",
            Self::InvalidPublicKey => "configured public key is unusable",
            Self::MessageTooLong => "payload too long for one AEAD message",
            Self::Internal => "internal invariant violated (bug in wireguard-sans-io)",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}

/// Why an inbound datagram was dropped.
///
/// Every variant is reachable by a remote party. When a datagram is
/// dropped **nothing is sent in response and no protocol state changes**
/// (WireGuard stays silent toward unauthenticated senders); only the
/// failure counters in [`crate::Stats`] / [`crate::DeviceStats`] move.
///
/// Do **not** surface the specific variant to untrusted observers (public
/// logs, per-variant metrics): which variant fires is itself an oracle
/// (for example `InvalidMac1` versus `AuthFailure` confirms knowledge of
/// this endpoint's static public key). The "silent" guarantee covers what
/// is *sent*, not the time taken — which inherently differs between
/// variants — so timing-based probing is a property of the protocol, not
/// of this implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DropReason {
    /// Structurally not a WireGuard message: bad length, unknown type, or
    /// non-zero reserved bytes.
    Malformed,
    /// The `mac1` of a handshake message is wrong: the sender does not know
    /// our public key (whitepaper §5.3).
    InvalidMac1,
    /// AEAD or handshake authentication failed.
    AuthFailure,
    /// A handshake initiation names a static key other than the one
    /// configured for the tunnel it was handed to. (Its sender knows our
    /// public key and holds the ephemeral key it sent; that it holds the
    /// static key it names has not been checked at this point — the
    /// tunnel refuses before the step that would.)
    UnknownPeer,
    /// A handshake initiation carried a TAI64N timestamp not greater than
    /// one already accepted from this peer: a replayed or reordered
    /// initiation (whitepaper §5.1).
    ReplayedTimestamp,
    /// A valid, fresh handshake initiation arrived less than
    /// 1/[`crate::consts::INITIATIONS_PER_SECOND`] s after the previous one
    /// from the same peer.
    InitiationFlood,
    /// The receiver index does not belong to any live session or in-flight
    /// handshake of the tunnel it was routed to.
    UnknownIndex,
    /// The transport counter was already received or is older than the
    /// replay window (whitepaper §5.4.6).
    Replay,
    /// The session the datagram belongs to is past `REJECT_AFTER_TIME`, or
    /// the counter is at or beyond `REJECT_AFTER_MESSAGES` (whitepaper
    /// §6.2).
    Expired,
    /// A handshake response or cookie reply arrived but no matching
    /// handshake is in flight (for example a replayed response).
    NoPendingHandshake,
    /// A cookie reply failed to decrypt against the `mac1` of the last
    /// handshake message we sent.
    InvalidCookie,
    /// A received ephemeral public key is a low-order point (the shared
    /// secret would be all-zero).
    InvalidPublicKey,
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Malformed => "not a structurally valid WireGuard message",
            Self::InvalidMac1 => "handshake message has invalid mac1",
            Self::AuthFailure => "authentication failed",
            Self::UnknownPeer => "handshake initiation names a different static key",
            Self::ReplayedTimestamp => "handshake initiation timestamp not newer than last",
            Self::InitiationFlood => "handshake initiations arriving too fast",
            Self::UnknownIndex => "receiver index does not match any session",
            Self::Replay => "transport counter outside replay window",
            Self::Expired => "session exceeded reject-after limits",
            Self::NoPendingHandshake => "no matching in-flight handshake",
            Self::InvalidCookie => "cookie reply failed authentication",
            Self::InvalidPublicKey => "ephemeral public key is a low-order point",
        };
        f.write_str(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::{DropReason, Error};

    #[test]
    fn display_is_total_and_distinct() {
        use std::collections::HashSet;
        use std::string::ToString;
        let errors = [
            Error::BufferTooSmall,
            Error::EntropyFailure,
            Error::InvalidPublicKey,
            Error::MessageTooLong,
            Error::Internal,
        ];
        let drops = [
            DropReason::Malformed,
            DropReason::InvalidMac1,
            DropReason::AuthFailure,
            DropReason::UnknownPeer,
            DropReason::ReplayedTimestamp,
            DropReason::InitiationFlood,
            DropReason::UnknownIndex,
            DropReason::Replay,
            DropReason::Expired,
            DropReason::NoPendingHandshake,
            DropReason::InvalidCookie,
            DropReason::InvalidPublicKey,
        ];
        let rendered: HashSet<_> = errors
            .iter()
            .map(ToString::to_string)
            .chain(drops.iter().map(ToString::to_string))
            .collect();
        assert_eq!(
            rendered.len(),
            errors.len() + drops.len(),
            "messages must be unique"
        );
    }
}
