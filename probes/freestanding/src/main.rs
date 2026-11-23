//! See `Cargo.toml`. Everything here is reached from `_start`, and every
//! input is opaque to the optimiser — the bytes, and the *lengths*: a
//! buffer is handed over as a prefix of unknown length (possibly empty),
//! a length argument as any `usize` at all. So nothing in the library can
//! be compiled on the assumption that a caller's buffer is large enough.
//!
//! Two things put the library's code into the image:
//!
//! * `keep.rs` (generated: `scripts/probe_api.py`) takes the address of
//!   every public function, method and trait-implementation method — 368
//!   of them — for three crypto providers. Each then exists as a function
//!   of its own, compiled for any arguments.
//! * the calls below go through the same API the way a caller does, so
//!   that what the generic protocol code makes of each provider is in the
//!   image as well, and so that the whole of it has to link without `std`
//!   and without an allocator (`scripts/check_no_std.sh`).
//!
//! Everything the library can print (`Debug`, `Display`) is printed.
//!
//! Nothing in *this* file may be able to panic: no indexing, no unchecked
//! arithmetic, no `unwrap`. (An image built from this file with the
//! library's part taken out has no panic machinery in it; the script
//! checks that it can tell.)
#![no_std]
#![no_main]

#[cfg(feature = "canary-alloc")]
extern crate alloc;
#[cfg(feature = "canary-std")]
extern crate std;

mod keep;

use core::fmt::{self, Write};
use core::hash::{Hash, Hasher};
use core::hint::black_box;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::num::NonZeroU16;
use core::panic::PanicInfo;

use wg::crypto::{aead, blake2s, chacha20, ct, kdf, poly1305, siphash, x25519};
use wg::{
    ChaChaImpl, CryptoProvider, Device, EntropyError, EntropySource, Error, InTree, Incoming,
    PeerConfig, PeerId, PresharedKey, PublicKey, StaticSecret, Ticks, Timer, Tunnel, WallClock,
};
use wireguard_sans_io as wg;

/// The handler has to exist for the image to link. If the core is
/// panic-free as built, nothing refers to it and the linker drops it —
/// which is what `scripts/check_no_panic.sh` looks for.
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

/// Bytes, numbers and lengths the optimiser knows nothing about.
struct Opaque(u64);

impl Opaque {
    fn byte(&mut self) -> u8 {
        self.0 = black_box(self.0)
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 56) as u8
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.byte();
        }
    }

    fn number(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);
        black_box(u64::from_le_bytes(bytes))
    }

    /// Any `usize` at all, `usize::MAX` included.
    fn size(&mut self) -> usize {
        black_box(self.number() as usize)
    }

    fn flag(&mut self) -> bool {
        self.byte() & 1 == 1
    }

    fn addr(&mut self) -> SocketAddr {
        let port = self.number() as u16;
        if self.flag() {
            let ip = Ipv4Addr::new(self.byte(), self.byte(), self.byte(), self.byte());
            SocketAddr::new(IpAddr::V4(ip), port)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(self.array::<16>())), port)
        }
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes = [0u8; N];
        self.fill(&mut bytes);
        bytes
    }

    fn ticks(&mut self) -> Ticks {
        Ticks::from_nanos(self.number())
    }

    /// A prefix of `buf` whose length the optimiser cannot know: anything
    /// from nothing to all of it.
    fn prefix<'a>(&mut self, buf: &'a [u8]) -> &'a [u8] {
        let n = self.size();
        match buf.len().checked_add(1).and_then(|m| n.checked_rem(m)) {
            Some(k) => buf.get(..k).unwrap_or(&[]),
            None => &[],
        }
    }

    fn prefix_mut<'a>(&mut self, buf: &'a mut [u8]) -> &'a mut [u8] {
        let n = self.size();
        match buf.len().checked_add(1).and_then(|m| n.checked_rem(m)) {
            Some(k) => match buf.get_mut(..k) {
                Some(prefix) => prefix,
                None => &mut [],
            },
            None => &mut [],
        }
    }
}

impl EntropySource for Opaque {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        if self.byte() == 0 {
            return Err(EntropyError);
        }
        Opaque::fill(self, buf);
        Ok(())
    }
}

/// Where formatted output goes.
struct Sink(u64);

impl fmt::Write for Sink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            self.0 = self.0.wrapping_mul(31).wrapping_add(u64::from(b));
        }
        if black_box(self.0) == 0x1234 {
            return Err(fmt::Error);
        }
        Ok(())
    }
}

/// A hasher, for the `Hash` implementations.
struct Fnv(u64);

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
        }
    }
}

// ---------------------------------------------------------------------------
// Providers other than the default
// ---------------------------------------------------------------------------

/// A keystream backend of the embedder's own (what `simd/` is): here the
/// scalar one, behind a call the optimiser cannot see through. It
/// implements the one required method, so the provided ones — the
/// combined calls the AEAD makes — are the trait's.
struct OwnKeystream;

impl ChaChaImpl for OwnKeystream {
    fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        let apply: fn(&[u8; 32], u32, &[u8; 12], &mut [u8]) = black_box(chacha20::xor_in_place);
        apply(key, counter, nonce, buf);
    }

    fn name() -> &'static str {
        black_box("own")
    }
}

/// A provider whose every result is opaque to the optimiser: whatever the
/// protocol code does with what a provider returns, it has to be compiled
/// for any value — a length that is too long, a "success" that is not.
/// (It is not a cryptographic provider. It meets the one requirement that
/// matters here: it cannot panic.) The two provided methods are left to
/// the trait.
struct OpaqueProvider;

fn mix(seed: u64, parts: &[&[u8]], out: &mut [u8]) {
    let mut state = black_box(seed);
    for part in parts {
        for b in part.iter() {
            state = (state ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
        }
    }
    for o in out.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        *o = black_box((state >> 56) as u8);
    }
}

impl CryptoProvider for OpaqueProvider {
    fn name() -> &'static str {
        black_box("opaque")
    }

    fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        mix(1, &[secret], &mut out);
        out
    }

    fn x25519(secret: &[u8; 32], public: &[u8; 32], out: &mut [u8; 32]) -> bool {
        mix(2, &[secret, public], out);
        black_box(out.first().copied().unwrap_or(0) & 1 == 0)
    }

    fn hash(parts: &[&[u8]], out: &mut [u8; 32]) {
        mix(3, parts, out);
    }

    fn mac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 16]) {
        mix(4, &[key], out);
        mix(5, parts, out);
    }

    fn hmac(key: &[u8], parts: &[&[u8]], out: &mut [u8; 32]) {
        mix(6, &[key], out);
        mix(7, parts, out);
    }

    fn seal_in_place(
        key: &[u8; 32],
        counter: u64,
        aad: &[u8],
        pt_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        mix(counter, &[key, aad], buf);
        // Any length, or an error: nothing the caller may rely on.
        black_box(if buf.len() & 1 == 0 {
            Ok(black_box(pt_len.wrapping_mul(3)))
        } else {
            Err(Error::MessageTooLong)
        })
    }

    fn open_in_place(key: &[u8; 32], counter: u64, aad: &[u8], buf: &mut [u8]) -> Option<usize> {
        mix(counter, &[key, aad], buf);
        black_box(Some(black_box(buf.len().wrapping_mul(7))))
    }

    fn xseal_in_place(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        pt_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        mix(8, &[key, nonce, aad], buf);
        black_box(Ok(black_box(pt_len.wrapping_mul(5))))
    }

    fn xopen_in_place(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Option<usize> {
        mix(9, &[key, nonce, aad], buf);
        black_box(Some(black_box(buf.len().wrapping_mul(11))))
    }
}

// ---------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------

/// `{:?}` and `{:#?}` of a value.
macro_rules! show {
    ($sink:expr, $value:expr) => {{
        let _ = write!($sink, "{:?}", $value);
        let _ = write!($sink, "{:#?}", $value);
    }};
}

/// `{}` of a value, plain and padded.
macro_rules! display {
    ($sink:expr, $value:expr) => {{
        let _ = write!($sink, "{}", $value);
        let _ = write!($sink, "{:>40}", $value);
    }};
}

// ---------------------------------------------------------------------------
// `Device`, `Tunnel` and the free functions, for one provider
// ---------------------------------------------------------------------------

#[inline(never)]
fn call_core<P: CryptoProvider>(o: &mut Opaque, sink: &mut Sink) -> Option<()> {
    let mut rng = Opaque(o.number());
    let wall = WallClock::new(o.ticks(), o.number(), o.number() as u32);
    let src = o.addr();
    let local = StaticSecret::from_bytes(o.array());

    // Both ways of making a device: returned by value, and built in place.
    let mut by_value: Device<P> = Device::<P>::with_provider(local.clone(), wall, &mut rng).ok()?;
    black_box(by_value.public_key());
    by_value.set_wall_clock(wall);
    show!(sink, by_value);
    let mut device_slot: Option<Device<P>> = None;
    let device = Device::<P>::with_provider_in(&mut device_slot, &local, wall, &mut rng).ok()?;
    show!(sink, device);

    let mut config = PeerConfig::new(PublicKey::from_bytes(o.array()));
    config.psk = PresharedKey::from_bytes(o.array());
    config.persistent_keepalive = NonZeroU16::new(o.number() as u16);
    config.mtu = NonZeroU16::new(o.number() as u16);
    config.endpoint = o.flag().then(|| o.addr());
    show!(sink, config);
    let id = PeerId::new(o.number() as u32)?;

    // And of making a tunnel.
    let mut tunnel_slot: Option<Tunnel<P>> = None;
    let in_place = device
        .tunnel_in(&mut tunnel_slot, id, &config, &mut rng)
        .ok()?;
    black_box(in_place.peer_id());
    let mut tunnel: Tunnel<P> = device.tunnel(id, config, &mut rng).ok()?;
    show!(sink, tunnel);

    let mut datagram_buf = [0u8; 2048];
    let mut out_buf = [0u8; 2048];
    let mut payload_buf = [0u8; 1600];
    o.fill(&mut datagram_buf);
    o.fill(&mut payload_buf);

    // The receive path, in both shapes. Every buffer is a prefix of
    // unknown length.
    {
        let datagram = o.prefix_mut(&mut datagram_buf);
        let out = o.prefix_mut(&mut out_buf);
        let incoming = device.receive(o.ticks(), src, o.flag(), datagram);
        show!(sink, incoming);
        match incoming {
            Incoming::Initiation(mut initiation) => {
                black_box(initiation.src());
                black_box(initiation.source_verified());
                black_box(initiation.sender_index());
                black_box(device.identify(&mut initiation).ok());
                black_box(initiation.peer_public());
                show!(sink, initiation);
                let handled = tunnel.handle_initiation(o.ticks(), &initiation, out, &mut rng);
                show!(sink, handled);
                if let Ok(handled) = handled {
                    black_box(handled.received.is_authenticated());
                    black_box((handled.session_established, handled.endpoint_changed));
                }
            }
            Incoming::ForPeer(peer, packet) => {
                black_box(peer.get());
                black_box(packet.is_handshake());
                black_box(packet.source_verified());
                show!(sink, packet);
                let handled = tunnel.handle(o.ticks(), src, packet);
                show!(sink, handled);
                if let Ok(handled) = handled {
                    black_box(handled.received.is_authenticated());
                }
            }
            Incoming::CookieRequired(challenge) => {
                black_box(challenge.src());
                show!(sink, challenge);
                let reply = device.cookie_reply(o.ticks(), &challenge, out, &mut rng);
                show!(sink, reply);
            }
            Incoming::Dropped(reason) => {
                show!(sink, reason);
                display!(sink, reason);
            }
            _ => {}
        }
    }
    {
        o.fill(&mut datagram_buf);
        let datagram = o.prefix_mut(&mut datagram_buf);
        let out = o.prefix_mut(&mut out_buf);
        let handled = device.receive_for(
            &mut tunnel,
            o.ticks(),
            src,
            o.flag(),
            datagram,
            out,
            &mut rng,
        );
        show!(sink, handled);
        black_box(handled.is_ok());
    }

    // The send path.
    {
        let payload = o.prefix(&payload_buf);
        let out = o.prefix_mut(&mut out_buf);
        let sent = tunnel.encapsulate(o.ticks(), payload, out);
        show!(sink, sent);
        black_box(sent.is_ok());
    }
    {
        // Any buffer, and any claim about how much of it is payload.
        let buf = o.prefix_mut(&mut out_buf);
        let sent = tunnel.encapsulate_in_place(o.ticks(), buf, o.size());
        show!(sink, sent);
        black_box(sent.is_ok());
    }

    // Timers and control.
    {
        let out = o.prefix_mut(&mut out_buf);
        let polled = tunnel.poll(o.ticks(), out, &mut rng);
        show!(sink, polled);
        black_box(polled.is_ok());
    }
    black_box(tunnel.next_wake());
    for timer in Timer::ALL {
        black_box(tunnel.timer(timer));
        show!(sink, timer);
    }
    tunnel.request_handshake(o.ticks());
    black_box(tunnel.is_established(o.ticks()));
    // An instant beyond `Ticks::MAX`, as a caller with a broken clock
    // would pass it.
    black_box(tunnel.is_established(Ticks::from_nanos(Ticks::MAX.nanos() | o.number())));
    black_box(tunnel.endpoint());
    tunnel.set_endpoint(o.addr());
    black_box(tunnel.peer_id());
    black_box(tunnel.peer_public());
    let stats = tunnel.stats();
    show!(sink, stats);
    tunnel.set_mtu(NonZeroU16::new(o.number() as u16));
    black_box(tunnel.mtu());
    tunnel.set_wall_clock(wall);
    tunnel.reset();
    let device_stats = device.stats();
    show!(sink, device_stats);

    // Free functions.
    black_box(wg::peek(o.prefix(&datagram_buf)).ok());
    black_box(wg::ip_packet_len(o.prefix(&payload_buf)));
    black_box(wg::ip_packet_addresses(o.prefix(&payload_buf)));
    black_box(wg::padded_len(o.size(), NonZeroU16::new(o.number() as u16)));
    black_box(wg::transport_datagram_len(o.size()));
    if let Ok(generated) = StaticSecret::generate(&mut rng) {
        black_box((generated.public_key(), generated.public_key_with::<P>()));
        show!(sink, generated);
    }
    let psk = PresharedKey::generate(&mut rng).ok();
    show!(sink, psk);

    // ---- canaries: each plants what the checks exist to find --------------
    #[cfg(feature = "canary-panic")]
    {
        // An unchecked index with an index nobody can bound.
        let index = o.size();
        black_box(payload_buf[index]);
    }
    #[cfg(feature = "canary-alloc")]
    {
        black_box(alloc::vec![o.byte(); o.size() % 64]);
    }
    #[cfg(feature = "canary-std")]
    {
        black_box(std::time::Instant::now());
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Everything public that is not `Device` or `Tunnel`
// ---------------------------------------------------------------------------

#[inline(never)]
fn call_rest<P: CryptoProvider, C: ChaChaImpl>(o: &mut Opaque, sink: &mut Sink) {
    let mut a = [0u8; 300];
    let mut b = [0u8; 300];
    let mut c = [0u8; 300];
    o.fill(&mut a);
    o.fill(&mut b);
    o.fill(&mut c);
    let key: [u8; 32] = o.array();
    let nonce: [u8; 12] = o.array();
    let xnonce: [u8; 24] = o.array();

    // ---- aead -----------------------------------------------------------
    black_box(aead::nonce_from_counter(o.number()));
    {
        let sealed = aead::seal(
            &key,
            &nonce,
            o.prefix(&a),
            o.prefix(&b),
            o.prefix_mut(&mut c),
        );
        show!(sink, sealed);
        black_box(
            aead::seal_with::<C>(
                &key,
                &nonce,
                o.prefix(&a),
                o.prefix(&b),
                o.prefix_mut(&mut c),
            )
            .is_ok(),
        );
        let opened = aead::open(
            &key,
            &nonce,
            o.prefix(&a),
            o.prefix(&b),
            o.prefix_mut(&mut c),
        );
        show!(sink, opened);
        if let Err(error) = opened {
            display!(sink, error);
            let error: &dyn core::error::Error = &error;
            black_box(error.source().is_some());
        }
        black_box(
            aead::open_with::<C>(
                &key,
                &nonce,
                o.prefix(&a),
                o.prefix(&b),
                o.prefix_mut(&mut c),
            )
            .is_ok(),
        );
        black_box(
            aead::seal_in_place(&key, &nonce, o.prefix(&a), o.size(), o.prefix_mut(&mut c)).is_ok(),
        );
        black_box(
            aead::seal_in_place_with::<C>(
                &key,
                &nonce,
                o.prefix(&a),
                o.size(),
                o.prefix_mut(&mut c),
            )
            .is_ok(),
        );
        black_box(aead::open_in_place(&key, &nonce, o.prefix(&a), o.prefix_mut(&mut c)).is_ok());
        black_box(
            aead::open_in_place_with::<C>(&key, &nonce, o.prefix(&a), o.prefix_mut(&mut c)).is_ok(),
        );
        black_box(
            aead::xseal(
                &key,
                &xnonce,
                o.prefix(&a),
                o.prefix(&b),
                o.prefix_mut(&mut c),
            )
            .is_ok(),
        );
        black_box(
            aead::xopen(
                &key,
                &xnonce,
                o.prefix(&a),
                o.prefix(&b),
                o.prefix_mut(&mut c),
            )
            .is_ok(),
        );
        black_box(
            aead::xseal_in_place(&key, &xnonce, o.prefix(&a), o.size(), o.prefix_mut(&mut c))
                .is_ok(),
        );
        black_box(aead::xopen_in_place(&key, &xnonce, o.prefix(&a), o.prefix_mut(&mut c)).is_ok());
    }

    // ---- the provider, as a trait -----------------------------------------
    {
        black_box(P::name());
        black_box(P::x25519_public(&key));
        let mut out32 = [0u8; 32];
        let mut out16 = [0u8; 16];
        black_box(P::x25519(&key, &o.array(), &mut out32));
        P::hash(&[o.prefix(&a), o.prefix(&b)], &mut out32);
        P::mac(o.prefix(&a), &[o.prefix(&b), o.prefix(&c)], &mut out16);
        let mut prepared = [0u32; 8];
        P::mac_prepare(&key, &mut prepared);
        P::mac_prepared(&key, &prepared, &[o.prefix(&a), o.prefix(&b)], &mut out16);
        P::hmac(o.prefix(&a), &[o.prefix(&b), o.prefix(&c)], &mut out32);
        black_box(
            P::seal_in_place(
                &key,
                o.number(),
                o.prefix(&a),
                o.size(),
                o.prefix_mut(&mut c),
            )
            .ok(),
        );
        black_box(P::open_in_place(
            &key,
            o.number(),
            o.prefix(&a),
            o.prefix_mut(&mut c),
        ));
        black_box(
            P::xseal_in_place(&key, &xnonce, o.prefix(&a), o.size(), o.prefix_mut(&mut c)).ok(),
        );
        black_box(P::xopen_in_place(
            &key,
            &xnonce,
            o.prefix(&a),
            o.prefix_mut(&mut c),
        ));
        black_box((out32, out16));

        black_box(C::name());
        C::apply_keystream(&key, &nonce, o.number() as u32, o.prefix_mut(&mut c));
        let mut one_time_key = [0u8; 32];
        C::seal_keystream(&key, &nonce, o.prefix_mut(&mut c), &mut one_time_key);
        let accept = o.flag();
        black_box(C::open_keystream(
            &key,
            &nonce,
            o.prefix_mut(&mut c),
            |_key, _ciphertext| black_box(accept),
        ));
        black_box(InTree::<C>::SCALAR_BELOW);
        let provider: InTree<C> = InTree::default();
        let copy = provider.clone();
        show!(sink, copy);
        let scalar = wg::Scalar::default();
        show!(sink, scalar);
    }

    // ---- blake2s ----------------------------------------------------------
    {
        let mut hash = blake2s::Blake2s256::new();
        hash.update(o.prefix(&a)).update(o.prefix(&b));
        let mut second = hash.clone();
        show!(sink, second);
        black_box(hash.finalize());
        let mut out32 = [0u8; 32];
        second.finalize_into(&mut out32);
        second.update(o.prefix(&a));
        second.finalize_into(&mut out32);
        black_box(blake2s::Blake2s256::default().finalize());
        // Any key length, more than 32 bytes included.
        let mut mac = blake2s::Blake2sMac::new(o.prefix(&a));
        // A copy from before the key has gone in, and one from after.
        let unfed = mac.clone();
        mac.update(o.prefix(&b));
        let mut second = mac.clone();
        show!(sink, second);
        black_box(mac.finalize());
        black_box(unfed.finalize());
        let mut out16 = [0u8; 16];
        second.finalize_into(&mut out16);
        black_box(out16);
        black_box(blake2s::hash(&[o.prefix(&a), o.prefix(&b)]));
        blake2s::hash_into(&[o.prefix(&a)], &mut out32);
        black_box(blake2s::mac(o.prefix(&a), &[o.prefix(&b)]));
        let mut out16 = [0u8; 16];
        blake2s::mac_into(o.prefix(&a), &[o.prefix(&b)], &mut out16);
        let mut state = [0u32; 8];
        blake2s::mac_key_state(&key, &mut state);
        blake2s::mac_keyed(&key, &state, &[o.prefix(&a), o.prefix(&b)], &mut out16);
        black_box((out32, out16));
    }

    // ---- chacha20 ---------------------------------------------------------
    {
        black_box(chacha20::block(&key, o.number() as u32, &nonce));
        let mut out64 = [0u8; 64];
        chacha20::block_into(&key, o.number() as u32, &nonce, &mut out64);
        black_box(chacha20::hchacha20(&key, &o.array()));
        let mut subkey = [0u8; 32];
        chacha20::hchacha20_into(&key, &o.array(), &mut subkey);
        chacha20::xor_in_place(&key, o.number() as u32, &nonce, o.prefix_mut(&mut c));
        let mut one_time_key = [0u8; 32];
        chacha20::one_time_key_into(&key, &nonce, &mut one_time_key);
        black_box((out64, one_time_key, subkey));
    }

    // ---- ct -----------------------------------------------------------------
    {
        black_box(ct::ct_eq(o.prefix(&a), o.prefix(&b)));
        black_box(ct::ct_is_zero(o.prefix(&a)));
        ct::wipe(o.prefix_mut(&mut c));
        let mut x: [u8; 32] = o.array();
        let mut y: [u8; 32] = o.array();
        ct::copy_secret(&mut x, &y);
        ct::swap_secret(&mut x, &mut y);
        ct::wipe_array(&mut x);
        let mut words = [o.number(); 5];
        ct::wipe_words(&mut words);
        black_box((x, y, words));
        // Any address at all for the stack to be scrubbed down to.
        black_box(ct::stack_mark());
        ct::scrub_stack_to(o.size());
        let mut scrub = ct::ScrubOnDrop::new();
        *scrub.low() = o.size();
        show!(sink, scrub);
        drop(scrub);
        drop(ct::ScrubOnDrop::default());
    }

    // ---- kdf ----------------------------------------------------------------
    {
        black_box(kdf::hmac(o.prefix(&a), &[o.prefix(&b), o.prefix(&c)]));
        let mut out32 = [0u8; 32];
        kdf::hmac_into(o.prefix(&a), &[o.prefix(&b)], &mut out32);
        black_box(kdf::kdf1(&key, o.prefix(&a)));
        black_box(kdf::kdf2(&key, o.prefix(&a)));
        black_box(kdf::kdf3(&key, o.prefix(&a)));
        let (mut t1, mut t2, mut t3) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        kdf::kdf_into::<P, 3>(&key, o.prefix(&a), [&mut t1, &mut t2, &mut t3]);
        kdf::kdf_into::<P, 0>(&key, o.prefix(&a), []);
        let mut chain: [u8; 32] = o.array();
        kdf::kdf_chain::<P, 2>(&mut chain, o.prefix(&a), [&mut t1, &mut t2]);
        kdf::kdf_chain::<P, 0>(&mut chain, o.prefix(&a), []);
        black_box((t1, t2, t3, chain, out32));
    }

    // ---- poly1305 -------------------------------------------------------------
    {
        let mut mac = poly1305::Poly1305::new(&key);
        mac.update(o.prefix(&a))
            .update_padded(o.prefix(&b))
            .update(o.prefix(&c));
        let mut second = mac.clone();
        show!(sink, second);
        black_box(mac.finalize());
        let mut out16 = [0u8; 16];
        second.finalize_into(&mut out16);
        black_box(out16);
        black_box(poly1305::poly1305(&key, o.prefix(&a)));
    }

    // ---- siphash, x25519 ----------------------------------------------------
    {
        let sip_key: [u8; 16] = o.array();
        black_box(siphash::siphash24(&sip_key, o.prefix(&a)));
        black_box(siphash::siphash24_3(
            siphash::key_words(&sip_key),
            o.array(),
        ));
        black_box(x25519::clamp_scalar(o.array()));
        let mut scalar: [u8; 32] = o.array();
        x25519::clamp_in_place(&mut scalar);
        black_box(x25519::x25519(&key, &o.array()));
        black_box(x25519::x25519_base(&key));
        let mut out32 = [0u8; 32];
        x25519::x25519_into(&key, &o.array(), &mut out32);
        let shared = x25519::shared_secret(&key, &o.array());
        show!(sink, shared);
        if let Err(error) = shared {
            display!(sink, error);
            let error: &dyn core::error::Error = &error;
            black_box(error.source().is_some());
        }
        black_box(x25519::shared_secret_into(&key, &o.array(), &mut out32));
        black_box((x25519::BASEPOINT, out32, scalar));
    }

    // ---- message ----------------------------------------------------------------
    {
        use wg::message;
        let parsed = message::parse(o.prefix(&a));
        show!(sink, parsed);
        black_box(parsed.is_ok());
        let kind = message::peek(o.prefix(&a));
        show!(sink, kind);
        if let Ok(kind) = kind {
            black_box(kind == kind.clone());
        }
        let built = message::build_initiation(
            o.prefix_mut(&mut c),
            o.number() as u32,
            &o.array(),
            &o.array(),
            &o.array(),
        );
        show!(sink, built);
        black_box(
            message::build_response(
                o.prefix_mut(&mut c),
                o.number() as u32,
                o.number() as u32,
                &o.array(),
                &o.array(),
            )
            .is_ok(),
        );
        black_box(
            message::build_cookie_reply(
                o.prefix_mut(&mut c),
                o.number() as u32,
                &o.array(),
                &o.array(),
            )
            .is_ok(),
        );
        black_box(
            message::write_transport_header(o.prefix_mut(&mut c), o.number() as u32, o.number())
                .is_ok(),
        );
        let slots = message::mac_slots(o.prefix_mut(&mut c));
        show!(sink, slots);
        black_box(slots.is_ok());
        black_box(message::ip_packet_len(o.prefix(&a)));
        black_box(message::ip_packet_addresses(o.prefix(&a)));
        black_box((
            message::TYPE_HANDSHAKE_INITIATION,
            message::TYPE_HANDSHAKE_RESPONSE,
            message::TYPE_COOKIE_REPLY,
            message::TYPE_TRANSPORT_DATA,
        ));
    }

    // ---- replay -------------------------------------------------------------------
    {
        use wg::replay::ReplayWindow;
        let mut window = ReplayWindow::new();
        for _ in 0..4 {
            black_box(window.check(o.number()));
            black_box(window.accept(o.number()));
            black_box(window.greatest());
        }
        let copy = window.clone();
        show!(sink, copy);
        black_box(ReplayWindow::default().greatest());
        black_box(wg::replay::WINDOW_BITS);
    }

    // ---- testing --------------------------------------------------------------------
    {
        use wg::testing::{DeterministicRng, FailingRng};
        let mut rng = DeterministicRng::new(o.number());
        black_box(rng.next_u64());
        black_box(EntropySource::fill(&mut rng, o.prefix_mut(&mut c)).is_ok());
        black_box(rng.gen32().ok());
        let copy = rng.clone();
        show!(sink, copy);
        let mut failing = FailingRng::default();
        black_box(EntropySource::fill(&mut failing, o.prefix_mut(&mut c)).is_ok());
        black_box(failing.gen32().ok());
        show!(sink, failing);
        let as_trait: &mut dyn EntropySource = &mut rng;
        black_box(as_trait.gen32().ok());
        show!(sink, as_trait);
    }

    // ---- keys, time, ids, errors ----------------------------------------------------
    {
        let secret = StaticSecret::from(o.array::<32>());
        let copy = secret.clone();
        show!(sink, copy);
        let public = PublicKey::from(o.array::<32>());
        black_box(public.as_bytes());
        black_box(public == PublicKey::from_bytes(o.array()));
        black_box(public.cmp(&PublicKey::from_bytes(o.array())));
        show!(sink, public);
        let psk = PresharedKey::from(o.array::<32>());
        let copy = psk.clone();
        show!(sink, copy);
        black_box(&PresharedKey::default());

        let t = o.ticks();
        let u = Ticks::from_secs(o.number());
        black_box((
            t.nanos(),
            t.add_nanos(o.number()),
            t.since(u),
            t.min(u),
            t.max(u),
        ));
        black_box((
            t == u,
            t < u,
            t.cmp(&u),
            Ticks::default(),
            Ticks::ZERO,
            Ticks::MAX,
        ));
        show!(sink, t);
        let mut hasher = Fnv(o.number());
        t.hash(&mut hasher);
        public.hash(&mut hasher);
        let wall = WallClock::new(t, o.number(), o.number() as u32);
        black_box(wall.unix_at(u));
        let stamp = wall.tai64n(u);
        black_box((
            stamp.as_bytes(),
            stamp.tick(),
            stamp == stamp.tick(),
            stamp < stamp.tick(),
        ));
        black_box(wg::Tai64N::from_bytes(o.array()));
        black_box(wg::Tai64N::from_unix(o.number(), o.number() as u32));
        stamp.hash(&mut hasher);
        show!(sink, stamp);
        show!(sink, wall);
        black_box(wall == wall.clone());

        let id = PeerId::new(o.number() as u32);
        show!(sink, id);
        if let Some(id) = id {
            black_box((
                id.get(),
                id == id,
                id < id,
                id.cmp(&id),
                PeerId::BITS,
                PeerId::MAX,
            ));
            id.hash(&mut hasher);
        }
        for error in [
            Error::BufferTooSmall,
            Error::EntropyFailure,
            Error::InvalidPublicKey,
            Error::MessageTooLong,
            Error::Internal,
        ] {
            let error = black_box(error);
            show!(sink, error);
            display!(sink, error);
            error.hash(&mut hasher);
            let error: &dyn core::error::Error = &error;
            black_box(error.source().is_some());
        }
        let no_entropy = black_box(EntropyError);
        show!(sink, no_entropy);
        display!(sink, no_entropy);
        let no_entropy: &dyn core::error::Error = &no_entropy;
        black_box(no_entropy.source().is_some());
        for timer in Timer::ALL {
            timer.hash(&mut hasher);
        }
        black_box(hasher.finish());
        black_box((
            wg::consts::CONSTRUCTION,
            wg::consts::IDENTIFIER,
            wg::consts::REKEY_AFTER_MESSAGES,
            wg::consts::REJECT_AFTER_MESSAGES,
        ));
    }
}

// ---------------------------------------------------------------------------

/// The whole API, for one provider and one keystream.
#[inline(never)]
fn run<P: CryptoProvider, C: ChaChaImpl>(o: &mut Opaque, sink: &mut Sink) {
    black_box(call_core::<P>(o, sink));
    call_rest::<P, C>(o, sink);
    keep::keep_api::<P, C, Fnv>();
    keep::keep_traits::<P, C, Fnv>();
    keep::keep_fmt::<P, C, Fnv>();
    // What a type does when it is dropped, where that is not a `Drop`
    // implementation of its own (which the generated list has) but its
    // fields'.
    macro_rules! k {
        ($e:expr) => {
            black_box($e as *const ());
        };
    }
    k!(core::ptr::drop_in_place::<Tunnel<P>>);
    k!(core::ptr::drop_in_place::<Device<P>>);
    k!(core::ptr::drop_in_place::<Option<Tunnel<P>>>);
    k!(core::ptr::drop_in_place::<Option<Device<P>>>);
    k!(core::ptr::drop_in_place::<wg::Initiation<'static>>);
    k!(core::ptr::drop_in_place::<wg::Incoming<'static>>);
    k!(core::ptr::drop_in_place::<wg::PeerConfig>);
    k!(core::ptr::drop_in_place::<blake2s::Blake2s256>);
    k!(core::ptr::drop_in_place::<blake2s::Blake2sMac<'static>>);
    k!(core::ptr::drop_in_place::<poly1305::Poly1305>);
    k!(<dyn EntropySource as fmt::Debug>::fmt);
}

/// The entry point: the root everything else is reachable from.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut opaque = Opaque(black_box(0x9e37_79b9_7f4a_7c15));
    let mut sink = Sink(0);
    loop {
        // The default provider; the default provider with a keystream of
        // the embedder's; and a provider that is not ours at all.
        run::<InTree, wg::Scalar>(&mut opaque, &mut sink);
        run::<InTree<OwnKeystream>, OwnKeystream>(&mut opaque, &mut sink);
        run::<OpaqueProvider, OwnKeystream>(&mut opaque, &mut sink);
        black_box(opaque.byte());
        black_box(sink.0);
    }
}
