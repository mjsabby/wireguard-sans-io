//! A sans-I/O implementation of the WireGuard® protocol.
//!
//! This crate implements the complete WireGuard protocol logic — the
//! Noise IKpsk2 handshake, cookie-based DoS mitigation, transport data
//! encryption with replay protection, peer routing, endpoint roaming, and
//! the whitepaper §6 timer state machine — without performing any I/O,
//! taking any locks, reading any clocks, or allocating any memory.
//!
//! # Shape
//!
//! * A [`Device`] is one local identity (one static key, usually one UDP
//!   socket). Every received datagram goes to [`Device::receive`], which
//!   does everything that has to happen before the peer is known and
//!   says which peer the datagram is for.
//! * A [`Tunnel`] is the state machine for one peer: handshake, sessions,
//!   endpoint, timers. The device creates it; you store it, keyed by a
//!   [`PeerId`] of your choosing.
//!
//! "Sans-I/O" means no I/O in the core. It does not mean less protocol in
//! the core: everything that is a protocol rule — who a datagram is for,
//! when an endpoint may move, when a keepalive is due — is decided here,
//! where a deterministic test can reach it.
//!
//! # Design rules
//!
//! * **Sans-I/O**: the library never touches sockets or clocks. Callers
//!   feed in datagrams, buffers, the current monotonic time ([`Ticks`]) and
//!   entropy ([`EntropySource`]); the library hands back datagrams to send
//!   — each with its destination ([`Transmit`]) — and plaintext that was
//!   received. This makes every protocol state, including every timer
//!   expiry, reachable and assertable from deterministic tests.
//! * **`#![no_std]`, no allocator**: all state lives in [`Device`] and
//!   [`Tunnel`] (plain values) and in caller-provided buffers. The crate
//!   does not link `alloc`, so it *cannot* allocate; CI links an image
//!   that uses every public entry point for a target without `std`, and
//!   without an allocator, to show it.
//! * **`#![forbid(unsafe_code)]`** — enforced at the crate root and in CI;
//!   there are no dependencies, so the guarantee covers every line of code
//!   involved, including all cryptography of the default
//!   [`crypto::CryptoProvider`].
//! * **Panic-free**: the source constructs that panic are forbidden by
//!   `clippy` lints (no indexing, no unchecked arithmetic, no `unwrap`),
//!   and CI searches the optimised machine code of that same image —
//!   every public entry point, the default provider — for Rust's panic
//!   machinery: there is none. (The claim is about optimised builds of
//!   the default provider. An unoptimised build keeps bounds checks the
//!   optimiser would have proven dead; they cannot fire.)
//! * **Rejecting a datagram is not an error**: whatever a remote party
//!   sends is reported in the `Ok` value ([`DropReason`]). [`Error`] is
//!   reserved for local faults, so `?` in a receive loop is safe.
//! * **Defensive**: incoming data is authenticated before it is parsed any
//!   further or allowed to mutate state; a forgery never leaves plaintext
//!   in a buffer; nothing expensive is computed for an unauthenticated
//!   sender before the caller has had the chance to refuse
//!   ([`Device::identify`]); secret material is compared in constant time.
//! * **Secrets are written once and wiped where they lie**: session keys
//!   and handshake state are derived straight into the [`Tunnel`] and are
//!   never moved as values; working copies are zeroed before a call
//!   returns; everything is wiped on rotation, expiry, `reset` and drop.
//!   This is best effort — safe Rust cannot dictate what a compiler
//!   spills — and it is measured rather than assumed: see "Secrets in
//!   memory" in the README.
//!
//! # Quick start
//!
//! See [`Tunnel`] for a complete two-peer example and [`Device`] for a
//! multi-peer receive path.
//!
//! WireGuard is a registered trademark of Jason A. Donenfeld. This crate is
//! an independent implementation of the published protocol.

#![no_std]
#![forbid(unsafe_code)]
// The panic-freedom wall of `Cargo.toml`, continued: the slice methods
// listed in `clippy.toml`. (Here rather than there, so that it holds for
// the library and not for its tests.)
#![cfg_attr(not(test), deny(clippy::disallowed_methods))]

#[cfg(test)]
extern crate std;

pub mod consts;
mod cookie;
pub mod crypto;
mod debug;
mod device;
mod entropy;
mod error;
mod index;
mod keys;
pub mod message;
mod noise;
pub mod replay;
mod session;
pub mod testing;
mod time;
mod timers;
mod tunnel;

pub use crypto::chacha20::{ChaChaImpl, Scalar};
pub use crypto::{CryptoProvider, InTree};
pub use device::{
    CookieChallenge, CookieState, Device, DeviceStats, Incoming, Initiation, PeerPacket,
};
pub use entropy::{EntropyError, EntropySource};
pub use error::{DropReason, Error};
pub use index::PeerId;
pub use keys::{PresharedKey, PublicKey, StaticSecret};
pub use message::{PacketKind, ip_packet_addresses, ip_packet_len, peek};
pub use time::{Tai64N, Ticks, WallClock};
pub use timers::Timer;
pub use tunnel::{
    Encapsulated, Handled, PeerConfig, PollOutput, Received, SendReason, Stats, Transmit, Tunnel,
    padded_len, transport_datagram_len,
};
