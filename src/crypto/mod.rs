//! In-tree cryptographic primitives.
//!
//! Everything WireGuard needs — BLAKE2s (plain, keyed, HMAC, and the HKDF
//! chain), ChaCha20, Poly1305, the ChaCha20-Poly1305 and
//! XChaCha20-Poly1305 AEADs, and X25519 — implemented in safe, panic-free,
//! allocation-free Rust with no dependencies.
//!
//! The protocol code does not call these modules directly. It goes through
//! [`CryptoProvider`], whose default implementation, [`InTree`], is built
//! from them; a different provider replaces all of them at once, for a
//! [`crate::Device`] and its tunnels.
//!
//! Two things are outside that seam, and stay in-tree whatever the
//! provider:
//!
//! * [`crate::StaticSecret::public_key`], a convenience on a key type
//!   that knows no provider. `StaticSecret::public_key_with` and
//!   [`crate::Device::public_key`] are the provider's.
//! * [`siphash`], which is not one of WireGuard's primitives. Session
//!   indices and the nonces of cookie replies are derived with it; both
//!   are this implementation's own choices and have no effect on the wire
//!   format.
//!
//! # Hazardous materials
//!
//! These modules are exported so that tests, fuzz targets and benchmarks
//! can exercise them directly, and because having the primitives directly
//! inspectable is useful.
//! They are **hard to use correctly in isolation** (nonce discipline, key
//! separation, etc. are the caller's problem at this layer). Use
//! [`crate::Tunnel`] unless you know exactly why you need these.
//!
//! # Constant-time discipline
//!
//! No secret-dependent branches and no secret-dependent memory indexing
//! anywhere in this module tree. Comparisons of secret material go through
//! [`ct`]. (As with every constant-time claim in any language, the
//! compiler has the last word; [`ct`] uses `core::hint::black_box` as a
//! best-effort optimization barrier. `scripts/check_constant_flow.sh`
//! counts the basic blocks each secret-handling operation executes, for
//! different secrets, in the build it is run on — they must not differ —
//! and the timing tests in `tests/constant_time.rs` spot-check the
//! result on real hardware.)
//!
//! Limb arithmetic — X25519 and Poly1305 — is fixed-shape operations on
//! `u64`/`u128`, and multiplications of secret limbs are most of it. That
//! is constant time exactly where the machine multiplies in constant
//! time, which is a property of the processor and not of this code:
//!
//! * It holds on x86-64, on AArch64, and on the ARM cores with a
//!   single-cycle or fixed-length multiplier (Cortex-M0/M0+, M4, M7, M23,
//!   M33; Cortex-A).
//! * It does **not** hold where there is no multiply instruction and the
//!   compiler calls a routine instead: RISC-V without the `M` (or
//!   `Zmmul`) extension — `riscv32i`, `riscv32e` — gets
//!   compiler-builtins' shift-and-add loop, which runs for as long as
//!   its operands have bits. Counted under emulation, the instructions of
//!   one X25519 there vary with the private key.
//! * It does not hold either on processors whose multiplier finishes
//!   early for small operands — the long multiply of the Cortex-M3
//!   (`UMULL`, three to five cycles by its manual) and of older ARM
//!   cores are the usual examples. An instruction count does not show
//!   this; a cycle count does.
//!
//! On such a machine the time of a handshake depends on private-key and
//! shared-secret limbs. Whether that matters is a question of who can
//! time it and how well; this crate does nothing about it (a
//! multiplication built from additions alone would, at many times the
//! cost), and an embedder for whom it matters supplies a
//! [`CryptoProvider`] made for that processor.
//!
//! # What a call leaves behind
//!
//! Nothing, on the stack, of the secrets it worked with — for the
//! functions that write their result through a `&mut` parameter (the
//! `…_into` forms, the AEADs, the keystream calls), which are the ones
//! the protocol code uses:
//!
//! * key material a function unpacks, cipher and hash state, padded
//!   keys, intermediate digests and one-time keys each live in one local
//!   that is zeroed on every way out;
//! * where the arithmetic keeps secrets in registers and a compiler
//!   parks registers in the stack frame — the Montgomery ladder, the
//!   sixteen-word states of the cipher and of the hash on a machine with
//!   fewer registers than that, the tag of a forgery — the frame itself
//!   is overwritten once the function has returned
//!   ([`ct::scrub_stack_to`]).
//!
//! `scripts/check_secret_residue.sh` checks this on the stack itself,
//! call by call, in three builds (see `probes/`).
//!
//! The functions that *return* a result (`blake2s::hash`, `blake2s::mac`,
//! `kdf::hmac`, `kdf::kdf1` to `kdf3`, `chacha20::block`,
//! `chacha20::hchacha20`, `poly1305::poly1305`, the `finalize` methods)
//! are conveniences for results that are public, and for tests. A value
//! returned is a value copied: it is wherever the caller received it and
//! wherever the caller moves it on from, and in a build short of full
//! optimisation also in the dead frame of the function that returned it.
//! For a result that is a secret, use the form that writes in place.
//! (Two that return secrets by value do clean up their own frames,
//! because nothing else can: [`x25519::x25519`] and
//! [`x25519::shared_secret`]. The caller's copy is still the caller's.)
//!
//! A hasher or an authenticator that is kept between calls
//! ([`blake2s::Blake2s256`], [`blake2s::Blake2sMac`],
//! [`poly1305::Poly1305`]) holds what it has absorbed until it is
//! finished or dropped; both wipe it where it lies. Moving one that has
//! absorbed a secret copies the secret, like any move. Making one does
//! not have to: `Blake2sMac` borrows its key and takes it in with its
//! first input, where the hasher then is; `Poly1305::new` hands its
//! state back with the key inside, and is a convenience in the sense
//! above.
//!
//! [`siphash`] is outside all of this: its state is not wiped after use.
//! The two keys that pass through it (session indices, cookie-reply
//! nonces) protect nothing but the look of those values.

pub mod aead;
pub mod blake2s;
mod bytes;
pub mod chacha20;
pub mod ct;
pub mod kdf;
pub mod poly1305;
mod provider;
pub mod siphash;
pub mod x25519;

pub use provider::{CryptoProvider, InTree};
