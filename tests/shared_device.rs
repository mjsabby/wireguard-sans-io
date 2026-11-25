//! One device, several threads.
//!
//! `Device::receive` takes `&mut self`. Behind a lock that puts every
//! datagram of every peer in one queue — and behind a reader-writer lock
//! held *shared* across `Device::identify`, as this library used to
//! recommend, every `receive` waits out the X25519 of whichever handshake
//! initiation another thread is looking at: a few tens of thousands of
//! forged initiations a second, from anyone who knows the public key,
//! stopped the routing of all peers.
//!
//! `Device::receive_shared` and `Device::cookie_reply_shared` take
//! `&self`: the device is shared by plain reference, and what changes —
//! the counters, the cookie state — is the caller's. These tests hold the
//! shared calls to three things:
//!
//! * they say, cost and count exactly what the `&mut` calls do;
//! * a device really is shared without a lock (it is `Sync`, and threads
//!   receive, identify and make tunnels on it at once);
//! * the one difference — a shared cookie state has its clock read, not
//!   moved — is the one documented.
//!
//! What cannot be asserted without a stopwatch (that routing no longer
//! waits for another thread's `identify`) is measured by the last test,
//! which is not run by default.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use common::counting::{Counting, spent};
use common::{Polled, Side, Tx, a_addr, b_addr, id, keypair, side_with, wall, x_addr};
use wireguard_sans_io::consts::{COOKIE_LIFETIME, COOKIE_SECRET_GRACE, LABEL_MAC1, REKEY_TIMEOUT};
use wireguard_sans_io::crypto::blake2s;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    CookieState, CryptoProvider, Device, DeviceStats, DropReason, Encapsulated, EntropySource,
    InTree, Incoming, PeerConfig, PollOutput, PublicKey, Received, StaticSecret, Ticks, Tunnel,
};

const S: u64 = 1_000_000_000;

/// A handshake initiation with a random body and a valid `mac1` for
/// `responder`: what anyone who knows the responder's public key can send.
fn forged_initiation(responder: &PublicKey, rng: &mut DeterministicRng) -> Vec<u8> {
    let mut msg = vec![0u8; 148];
    rng.fill(&mut msg[..116]).unwrap();
    msg[..4].copy_from_slice(&[1, 0, 0, 0]);
    let mac1_key = blake2s::hash(&[LABEL_MAC1, responder.as_bytes()]);
    let mac1 = blake2s::mac(&mac1_key, &[&msg[..116]]);
    msg[116..132].copy_from_slice(&mac1);
    msg
}

/// A client, and the same responder twice: made from the same key with
/// the same entropy, so that the two are the same device with the same
/// tunnel — one to be called through `&mut`, one through `&`.
struct Twins<P: CryptoProvider> {
    a: Side<P>,
    owned: Side<P>,
    shared: Side<P>,
    /// The cookie state and the counters that go with `shared`.
    cookies: CookieState,
    stats: DeviceStats,
    /// Entropy for the client, and one stream for each responder: the two
    /// are kept in step, so equal behaviour stays equal.
    rng_a: DeterministicRng,
    rng_owned: DeterministicRng,
    rng_shared: DeterministicRng,
}

fn twins<P: CryptoProvider>(seed: u64) -> Twins<P> {
    let mut rng = DeterministicRng::new(seed);
    let (a_key, a_pub) = keypair(&mut rng);
    let (b_key, b_pub) = keypair(&mut rng);
    let a = side_with(a_key, b_pub, a_addr(), Some(b_addr()), None, None, &mut rng);
    let (mut rng_owned, mut rng_shared) = (rng.clone(), rng.clone());
    let owned = side_with(
        b_key.clone(),
        a_pub,
        b_addr(),
        None,
        None,
        None,
        &mut rng_owned,
    );
    let shared = side_with(b_key, a_pub, b_addr(), None, None, None, &mut rng_shared);
    Twins {
        a,
        owned,
        shared,
        cookies: CookieState::new(),
        stats: DeviceStats::default(),
        rng_a: rng,
        rng_owned,
        rng_shared,
    }
}

/// What became of a datagram: the device's verdict as it prints, and what
/// the tunnel (or the device, for a cookie reply) made of it.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    incoming: String,
    /// A datagram to send back, if any.
    reply: Option<Vec<u8>>,
    /// Decrypted data, if any.
    data: Option<Vec<u8>>,
    dropped: Option<DropReason>,
}

/// Act on an `Incoming` the way a server with one peer in its table does.
fn act<P: CryptoProvider>(
    device: &Device<P>,
    tunnel: &mut Tunnel<P>,
    incoming: Incoming<'_>,
    now: Ticks,
    src: SocketAddr,
    rng: &mut DeterministicRng,
    cookie_reply: impl FnOnce(&wireguard_sans_io::CookieChallenge, &mut [u8]) -> Vec<u8>,
) -> Outcome {
    let printed = format!("{incoming:?}");
    let mut out = [0u8; 256];
    let (reply, data, dropped) = match incoming {
        Incoming::Initiation(mut init) => match device.identify(&mut init) {
            Ok(public) if public == tunnel.peer_public() => {
                match tunnel
                    .handle_initiation(now, &init, &mut out, rng)
                    .unwrap()
                    .received
                {
                    Received::HandshakeResponse(tx) => (Some(tx.datagram.to_vec()), None, None),
                    Received::Dropped(why) => (None, None, Some(why)),
                    other => panic!("{other:?}"),
                }
            }
            Ok(_) => (None, None, Some(DropReason::UnknownPeer)),
            Err(why) => (None, None, Some(why)),
        },
        Incoming::ForPeer(peer, packet) => {
            assert_eq!(peer, tunnel.peer_id(), "routed to the tunnel's own id");
            match tunnel.handle(now, src, packet).unwrap().received {
                Received::Data(d) => (None, Some(d.to_vec()), None),
                Received::Dropped(why) => (None, None, Some(why)),
                _ => (None, None, None),
            }
        }
        Incoming::CookieRequired(challenge) => {
            (Some(cookie_reply(&challenge, &mut out)), None, None)
        }
        Incoming::Dropped(why) => (None, None, Some(why)),
        other => panic!("{other:?}"),
    };
    Outcome {
        incoming: printed,
        reply,
        data,
        dropped,
    }
}

impl<P: CryptoProvider> Twins<P> {
    /// One datagram to both responders: through `&mut` to one, through `&`
    /// to the other. They must agree, and the agreed outcome is returned.
    fn deliver(
        &mut self,
        now: Ticks,
        src: SocketAddr,
        under_load: bool,
        datagram: &[u8],
    ) -> Outcome {
        let (mut d1, mut d2) = (datagram.to_vec(), datagram.to_vec());

        let incoming = self.owned.device.receive(now, src, under_load, &mut d1);
        // (The device is borrowed mutably only for `receive` and for a
        // cookie reply; `Incoming` borrows the datagram alone.)
        let printed = format!("{incoming:?}");
        let owned = match incoming {
            Incoming::CookieRequired(challenge) => {
                let mut out = [0u8; 256];
                let reply = self
                    .owned
                    .device
                    .cookie_reply(now, &challenge, &mut out, &mut self.rng_owned)
                    .unwrap()
                    .datagram
                    .to_vec();
                Outcome {
                    incoming: printed,
                    reply: Some(reply),
                    data: None,
                    dropped: None,
                }
            }
            incoming => act(
                &self.owned.device,
                &mut self.owned.tunnel,
                incoming,
                now,
                src,
                &mut self.rng_owned,
                |_, _| unreachable!(),
            ),
        };

        let device = &self.shared.device;
        let incoming = device.receive_shared(
            under_load.then_some(&self.cookies),
            now,
            src,
            &mut d2,
            &mut self.stats,
        );
        let printed = format!("{incoming:?}");
        let shared = match incoming {
            Incoming::CookieRequired(challenge) => {
                let mut out = [0u8; 256];
                let reply = device
                    .cookie_reply_shared(
                        &mut self.cookies,
                        now,
                        &challenge,
                        &mut out,
                        &mut self.rng_shared,
                        &mut self.stats,
                    )
                    .unwrap()
                    .datagram
                    .to_vec();
                Outcome {
                    incoming: printed,
                    reply: Some(reply),
                    data: None,
                    dropped: None,
                }
            }
            incoming => act(
                device,
                &mut self.shared.tunnel,
                incoming,
                now,
                src,
                &mut self.rng_shared,
                |_, _| unreachable!(),
            ),
        };

        assert_eq!(owned, shared, "the two ways of receiving disagree");
        assert_eq!(d1, d2, "…about what the datagram holds afterwards");
        owned
    }

    /// The counters agree as well: the shared device's are the caller's,
    /// and its own have not moved.
    fn check_stats(&self) {
        assert_eq!(self.owned.device.stats(), self.stats);
        assert_eq!(self.shared.device.stats(), DeviceStats::default());
    }
}

fn transmit(polled: Polled) -> Vec<u8> {
    match polled {
        Polled::Transmit(datagram, _, _) => datagram,
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------

/// `Device`, `Tunnel` and `CookieState` cross threads, and a device is
/// shared between them by reference. A compile-time fact: this test is its
/// own proof by building.
#[test]
fn a_device_is_send_and_sync() {
    fn send_and_sync<T: Send + Sync>() {}
    send_and_sync::<Device>();
    send_and_sync::<Device<Counting>>();
    send_and_sync::<Tunnel>();
    send_and_sync::<CookieState>();
    send_and_sync::<DeviceStats>();
    // A provider is a type that is never made: it has no say in this.
    struct NotSync(#[allow(dead_code)] std::cell::Cell<u8>);
    fn provider_is_irrelevant<P: 'static>() {
        send_and_sync::<std::marker::PhantomData<fn() -> P>>();
    }
    provider_is_irrelevant::<NotSync>();
}

/// A whole life of a tunnel — garbage, forgeries, the cookie dance under
/// load, a handshake, data both ways, replays — delivered to the same
/// responder through `&mut` and through `&`: every verdict, every reply
/// byte and every counter is the same.
#[test]
fn a_shared_device_says_what_an_owned_one_says() {
    for seed in 0..6u64 {
        let mut t = twins::<InTree>(0x5a00 + seed);
        let b_pub = t.owned.device.public_key();
        let mut junk = DeterministicRng::new(seed);
        let mut now = Ticks::from_secs(100);

        // Nothing that knows a key.
        for len in [0usize, 1, 3, 4, 31, 32, 64, 92, 148, 149, 300] {
            for first in [0u8, 1, 2, 3, 4, 5, 0xff] {
                let mut d = vec![0u8; len];
                junk.fill(&mut d).unwrap();
                if let Some(b) = d.first_mut() {
                    *b = first;
                }
                for under_load in [false, true] {
                    let out = t.deliver(now, x_addr(), under_load, &d);
                    assert!(out.reply.is_none() && out.data.is_none(), "{out:?}");
                }
            }
        }
        // A well-formed handshake message with a wrong mac1; one with a
        // right one (it gets as far as `identify`, and no further).
        let mut bad = forged_initiation(&b_pub, &mut junk);
        bad[120] ^= 1;
        assert_eq!(
            t.deliver(now, x_addr(), false, &bad).dropped,
            Some(DropReason::InvalidMac1)
        );
        let forged = forged_initiation(&b_pub, &mut junk);
        assert_eq!(
            t.deliver(now, x_addr(), false, &forged).dropped,
            Some(DropReason::AuthFailure)
        );
        // Under load the forgery earns a cookie reply — the same one,
        // byte for byte, from both.
        let reply = t.deliver(now, x_addr(), true, &forged).reply.unwrap();
        assert_eq!(reply.len(), 64);

        // The peer's handshake under load: a cookie reply first, then —
        // one Rekey-Timeout later, with the cookie — a response.
        let init = t.a.initiate(now, &mut t.rng_a);
        let cookie_reply = t.deliver(now, a_addr(), true, &init).reply.unwrap();
        assert_eq!(cookie_reply.len(), 64);
        let mut copy = cookie_reply.clone();
        let mut scratch = [0u8; 128];
        let stored =
            t.a.device
                .receive_for(
                    &mut t.a.tunnel,
                    now,
                    b_addr(),
                    false,
                    &mut copy,
                    &mut scratch,
                    &mut t.rng_a,
                )
                .unwrap();
        assert!(
            matches!(stored.received, Received::CookieStored),
            "{stored:?}"
        );
        now = now.add_nanos(REKEY_TIMEOUT + S);
        let retry = transmit(t.a.poll(now, &mut t.rng_a));
        assert_eq!(retry.len(), 148);
        // From another address the same message proves nothing…
        assert_eq!(
            t.deliver(now, x_addr(), true, &retry)
                .reply
                .map(|r| r.len()),
            Some(64)
        );
        // …from its own it is let through, and answered.
        let out = t.deliver(now, a_addr(), true, &retry);
        assert!(out.incoming.contains("source_verified: true"), "{out:?}");
        let response = out.reply.expect("a handshake response");
        assert_eq!(response.len(), 92);
        // Played again: the timestamp is not new.
        assert_eq!(
            t.deliver(now, a_addr(), true, &retry).dropped,
            Some(DropReason::ReplayedTimestamp)
        );

        // The initiator completes; data flows; replays and forgeries of
        // it are refused alike.
        let mut copy = response.clone();
        let done =
            t.a.device
                .receive_for(
                    &mut t.a.tunnel,
                    now,
                    b_addr(),
                    false,
                    &mut copy,
                    &mut scratch,
                    &mut t.rng_a,
                )
                .unwrap();
        assert!(
            matches!(done.received, Received::HandshakeComplete),
            "{done:?}"
        );
        let keepalive = transmit(t.a.poll(now, &mut t.rng_a));
        let out = t.deliver(now, a_addr(), false, &keepalive);
        assert!(out.dropped.is_none(), "{out:?}");
        for n in 0..40usize {
            let payload = vec![n as u8; 1 + 37 * n];
            let Tx::Transport(wire) = t.a.send(now, &payload) else {
                panic!("no session")
            };
            let out = t.deliver(now, a_addr(), n % 3 == 0, &wire);
            assert_eq!(
                out.data.as_deref().map(|d| &d[..payload.len()]),
                Some(&payload[..])
            );
            assert_eq!(
                t.deliver(now, a_addr(), false, &wire).dropped,
                Some(DropReason::Replay)
            );
            let mut forged = wire.clone();
            *forged.last_mut().unwrap() ^= 0x80;
            forged[8] ^= 0x40; // a counter not seen yet
            assert_eq!(
                t.deliver(now, x_addr(), false, &forged).dropped,
                Some(DropReason::AuthFailure)
            );
        }
        t.check_stats();
        // Something was counted in every column.
        let s = t.stats;
        for count in [
            s.malformed,
            s.mac1_failures,
            s.initiations,
            s.cookies_required,
            s.cookies_sent,
            s.routed,
        ] {
            assert!(count > 0, "{s:?}");
        }
    }
}

/// The shared calls cost what the others cost, operation for operation:
/// no keyed hash more, and no Diffie-Hellman anywhere in `receive`.
#[test]
fn receiving_on_a_shared_device_costs_what_it_costs_on_an_owned_one() {
    let mut t = twins::<Counting>(0xc057);
    let b_pub = t.owned.device.public_key();
    let mut junk = DeterministicRng::new(9);
    let now = Ticks::from_secs(50);
    let genuine = t.a.initiate(now, &mut t.rng_a);
    let forged = forged_initiation(&b_pub, &mut junk);
    let mut bad = forged.clone();
    bad[120] ^= 1;
    // Prime both cookie secrets (the first reply draws them).
    let _ = t.deliver(now, x_addr(), true, &forged);

    for (what, datagram, under_load) in [
        ("garbage", vec![0xffu8; 40], false),
        ("garbage under load", vec![0xffu8; 40], true),
        ("bad mac1", bad.clone(), false),
        ("bad mac1 under load", bad, true),
        ("forged initiation", forged.clone(), false),
        ("forged initiation under load", forged, true),
        ("genuine initiation", genuine.clone(), false),
        ("genuine initiation under load", genuine, true),
    ] {
        let _ = spent();
        let mut d = datagram.clone();
        drop(t.owned.device.receive(now, a_addr(), under_load, &mut d));
        let owned = spent();
        let mut d = datagram.clone();
        let mut stats = DeviceStats::default();
        drop(t.shared.device.receive_shared(
            under_load.then_some(&t.cookies),
            now,
            a_addr(),
            &mut d,
            &mut stats,
        ));
        let shared = spent();
        assert_eq!(owned, shared, "{what}");
        assert!(shared.only_macs(), "{what}: {shared:?}");
        assert!(shared.mac <= 3, "{what}: {shared:?}");
    }
}

/// A shared cookie state has its clock read, an owned one has it moved.
/// Either way a clock that goes backwards makes no secret younger; the
/// difference shows only after one that has run ahead.
#[test]
fn a_shared_cookie_state_reads_its_clock_and_an_owned_one_moves_it() {
    let mut t = twins::<InTree>(0xc10c);
    let b_pub = t.owned.device.public_key();
    let mut junk = DeterministicRng::new(3);
    let forged = forged_initiation(&b_pub, &mut junk);
    let minted = Ticks::from_secs(1000);

    // A cookie for a_addr from both, minted at 1000 s, and a message that
    // carries it.
    let init = t.a.initiate(minted, &mut t.rng_a);
    let reply = t.deliver(minted, a_addr(), true, &init).reply.unwrap();
    let mut copy = reply;
    let mut scratch = [0u8; 128];
    let stored =
        t.a.device
            .receive_for(
                &mut t.a.tunnel,
                minted,
                b_addr(),
                false,
                &mut copy,
                &mut scratch,
                &mut t.rng_a,
            )
            .unwrap();
    assert!(matches!(stored.received, Received::CookieStored));
    let with_cookie = transmit(t.a.poll(minted.add_nanos(REKEY_TIMEOUT + S), &mut t.rng_a));

    let verified = |cookies: &CookieState, device: &Device, now: Ticks| -> bool {
        let mut d = with_cookie.clone();
        let mut stats = DeviceStats::default();
        matches!(
            device.receive_shared(Some(cookies), now, a_addr(), &mut d, &mut stats),
            Incoming::Initiation(_)
        )
    };
    let honoured_until = minted.add_nanos(COOKIE_LIFETIME + COOKIE_SECRET_GRACE);
    let just_before = Ticks::from_nanos(honoured_until.nanos() - 1);

    // Shared: honoured for its lifetime and the grace, and not after.
    assert!(verified(&t.cookies, &t.shared.device, minted));
    assert!(verified(&t.cookies, &t.shared.device, just_before));
    assert!(!verified(&t.cookies, &t.shared.device, honoured_until));
    // A clock that goes backwards — or is out of range — reads as the
    // last instant the state was moved to: the secret gets no younger.
    assert!(verified(&t.cookies, &t.shared.device, Ticks::ZERO));
    assert!(verified(
        &t.cookies,
        &t.shared.device,
        Ticks::from_nanos(u64::MAX)
    ));
    // And a shared look at a late instant has moved nothing: the next
    // one, at an earlier instant, is judged by its own time.
    assert!(!verified(
        &t.cookies,
        &t.shared.device,
        Ticks::from_secs(5000)
    ));
    assert!(verified(&t.cookies, &t.shared.device, just_before));

    // The owned device moves its clock with every look under load: after
    // one at a late instant, time does not go back for it.
    let look = |device: &mut Device, now: Ticks| -> bool {
        let mut d = with_cookie.clone();
        matches!(
            device.receive(now, a_addr(), true, &mut d),
            Incoming::Initiation(_)
        )
    };
    assert!(look(&mut t.owned.device, just_before));
    assert!(!look(&mut t.owned.device, Ticks::from_secs(5000)));
    assert!(!look(&mut t.owned.device, just_before));

    // Making a reply moves a shared state's clock too (it is held
    // exclusively for that), and draws the next secret when one is due.
    let mut out = [0u8; 128];
    let mut d = forged.clone();
    let mut stats = DeviceStats::default();
    let late = Ticks::from_secs(5000);
    let Incoming::CookieRequired(challenge) =
        t.shared
            .device
            .receive_shared(Some(&t.cookies), late, x_addr(), &mut d, &mut stats)
    else {
        panic!("a forged initiation under load is asked for a cookie")
    };
    t.shared
        .device
        .cookie_reply_shared(
            &mut t.cookies,
            late,
            &challenge,
            &mut out,
            &mut t.rng_shared,
            &mut stats,
        )
        .unwrap();
    assert_eq!((stats.cookies_required, stats.cookies_sent), (1, 1));
    assert!(!verified(&t.cookies, &t.shared.device, just_before));
}

/// Counters are the caller's: one set per thread, and `merge` adds them
/// up — saturating, like every counter here.
#[test]
fn counters_of_several_threads_add_up() {
    let mut a = DeviceStats::default();
    a.malformed = 3;
    a.routed = u64::MAX - 1;
    let mut b = DeviceStats::default();
    b.malformed = 4;
    b.mac1_failures = 5;
    b.initiations = 6;
    b.cookies_required = 7;
    b.cookies_sent = 8;
    b.routed = 9;
    a.merge(&b);
    assert_eq!(
        (
            a.malformed,
            a.mac1_failures,
            a.initiations,
            a.cookies_required,
            a.cookies_sent
        ),
        (7, 5, 6, 7, 8)
    );
    assert_eq!(a.routed, u64::MAX);
}

// ---------------------------------------------------------------------------
// Threads.

/// One peer of the shared server, with the client that talks to it.
struct Peer {
    client_device: Device,
    client: Tunnel,
    server: Tunnel,
    public: PublicKey,
    addr: SocketAddr,
}

fn peer(server: &Device, server_pub: PublicKey, n: u32, rng: &mut DeterministicRng) -> Peer {
    let key = StaticSecret::generate(rng).unwrap();
    let public = key.public_key();
    let addr = SocketAddr::from(([198, 51, 100, (n % 250) as u8 + 1], 40_000 + n as u16));
    // Tunnels are made on the shared device from whichever thread wants
    // one: `Device::tunnel` takes `&self`.
    let server_tunnel = server.tunnel(id(n), PeerConfig::new(public), rng).unwrap();
    let client_device = Device::new(key, wall(), rng).unwrap();
    let mut cfg = PeerConfig::new(server_pub);
    cfg.endpoint = Some(b_addr());
    let client = client_device.tunnel(id(0), cfg, rng).unwrap();
    Peer {
        client_device,
        client,
        server: server_tunnel,
        public,
        addr,
    }
}

impl Peer {
    /// A handshake and `packets` data packets, the server's half through
    /// the shared device. Returns how many packets came out right.
    fn run(
        &mut self,
        device: &Device,
        cookies: &RwLock<CookieState>,
        under_load: &AtomicBool,
        stats: &mut DeviceStats,
        packets: usize,
        rng: &mut DeterministicRng,
    ) -> usize {
        let mut now = Ticks::from_secs(10);
        let (mut buf, mut out) = ([0u8; 256], [0u8; 256]);
        let mut delivered = 0;
        self.client.request_handshake(now);
        // The handshake, however many rounds the load signal makes of it.
        for _round in 0..8 {
            let mut init = match self.client.poll(now, &mut buf, rng).unwrap() {
                PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
                other => panic!("{other:?}"),
            };
            let loaded = under_load.load(Ordering::Relaxed);
            let guard = loaded.then(|| cookies.read().unwrap());
            let incoming =
                device.receive_shared(guard.as_deref(), now, self.addr, &mut init, stats);
            let mut reply = match incoming {
                Incoming::Initiation(mut initiation) => {
                    drop(guard);
                    assert_eq!(device.identify(&mut initiation), Ok(self.public));
                    match self
                        .server
                        .handle_initiation(now, &initiation, &mut out, rng)
                        .unwrap()
                        .received
                    {
                        Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
                        other => panic!("{other:?}"),
                    }
                }
                Incoming::CookieRequired(challenge) => {
                    drop(guard);
                    let mut state = cookies.write().unwrap();
                    device
                        .cookie_reply_shared(&mut state, now, &challenge, &mut out, rng, stats)
                        .unwrap()
                        .datagram
                        .to_vec()
                }
                other => panic!("{other:?}"),
            };
            let handled = self
                .client_device
                .receive_for(
                    &mut self.client,
                    now,
                    b_addr(),
                    false,
                    &mut reply,
                    &mut out,
                    rng,
                )
                .unwrap();
            match handled.received {
                Received::HandshakeComplete => break,
                Received::CookieStored => now = now.add_nanos(REKEY_TIMEOUT + S),
                other => panic!("{other:?}"),
            }
        }
        assert!(
            self.client.is_established(now),
            "no session after eight rounds"
        );
        for n in 0..packets {
            let payload = [(n % 251) as u8; 48];
            let mut wire = [0u8; 128];
            let len = match self.client.encapsulate(now, &payload, &mut wire).unwrap() {
                Encapsulated::Transport(tx) => tx.datagram.len(),
                other => panic!("{other:?}"),
            };
            match device.receive_shared(None, now, self.addr, &mut wire[..len], stats) {
                Incoming::ForPeer(peer, packet) => {
                    assert_eq!(peer, self.server.peer_id());
                    match self.server.handle(now, self.addr, packet).unwrap().received {
                        Received::Data(data) if data == payload => delivered += 1,
                        other => panic!("{other:?}"),
                    }
                }
                other => panic!("{other:?}"),
            }
        }
        delivered
    }
}

/// Six peers on six threads, a seventh thread that does nothing but feed
/// the device forged initiations (and identifies every one of them), an
/// eighth that turns the load signal on and off: one device between them
/// all, by reference. Every handshake completes and every packet arrives.
#[test]
fn threads_receive_identify_and_make_tunnels_on_one_device_at_once() {
    const PEERS: u32 = 6;
    const PACKETS: usize = 400;
    let mut rng = DeterministicRng::new(0x7ead);
    let (server_key, server_pub) = keypair(&mut rng);
    let device = Device::new(server_key, wall(), &mut rng).unwrap();
    let cookies = RwLock::new(CookieState::new());
    let under_load = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    let totals = Mutex::new(DeviceStats::default());
    let delivered = AtomicU64::new(0);

    // (References, so that every thread's closure can take them by move.)
    let (device, cookies, under_load, done, totals, delivered) =
        (&device, &cookies, &under_load, &done, &totals, &delivered);
    std::thread::scope(|threads| {
        for n in 0..PEERS {
            threads.spawn(move || {
                let mut rng = DeterministicRng::new(1000 + u64::from(n));
                let mut stats = DeviceStats::default();
                let mut peer = peer(device, server_pub, n, &mut rng);
                let got = peer.run(device, cookies, under_load, &mut stats, PACKETS, &mut rng);
                delivered.fetch_add(got as u64, Ordering::Relaxed);
                totals.lock().unwrap().merge(&stats);
            });
        }
        // What anyone who knows the public key can send, as fast as one
        // thread can take it — X25519 and all.
        threads.spawn(move || {
            let mut rng = DeterministicRng::new(0xbad);
            let mut stats = DeviceStats::default();
            let mut out = [0u8; 128];
            let mut forged = 0u64;
            while !done.load(Ordering::Relaxed) || forged < 50 {
                let mut d = forged_initiation(&server_pub, &mut rng);
                let loaded = under_load.load(Ordering::Relaxed);
                let guard = loaded.then(|| cookies.read().unwrap());
                match device.receive_shared(
                    guard.as_deref(),
                    Ticks::from_secs(10),
                    x_addr(),
                    &mut d,
                    &mut stats,
                ) {
                    Incoming::Initiation(mut init) => {
                        drop(guard);
                        assert_eq!(device.identify(&mut init), Err(DropReason::AuthFailure));
                    }
                    Incoming::CookieRequired(challenge) => {
                        drop(guard);
                        let mut state = cookies.write().unwrap();
                        device
                            .cookie_reply_shared(
                                &mut state,
                                Ticks::from_secs(10),
                                &challenge,
                                &mut out,
                                &mut rng,
                                &mut stats,
                            )
                            .unwrap();
                    }
                    other => panic!("{other:?}"),
                }
                forged += 1;
            }
            totals.lock().unwrap().merge(&stats);
        });
        threads.spawn(move || {
            while !done.load(Ordering::Relaxed) {
                under_load.fetch_xor(true, Ordering::Relaxed);
                std::thread::sleep(Duration::from_micros(300));
            }
        });
        // The peers' threads end by themselves; the other two when told.
        // (A scope joins everything; so the telling is done by a thread
        // that waits for the count.)
        threads.spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(120);
            while delivered.load(Ordering::Relaxed) < u64::from(PEERS) * PACKETS as u64
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            done.store(true, Ordering::Relaxed);
        });
    });

    assert_eq!(
        delivered.load(Ordering::Relaxed),
        u64::from(PEERS) * PACKETS as u64
    );
    let totals = *totals.lock().unwrap();
    assert_eq!(totals.routed, u64::from(PEERS) * PACKETS as u64);
    assert!(totals.initiations >= u64::from(PEERS), "{totals:?}");
    assert_eq!(totals.cookies_required, totals.cookies_sent, "{totals:?}");
    assert_eq!((totals.malformed, totals.mac1_failures), (0, 0));
    // The device's own counters are for the `&mut` calls: untouched.
    assert_eq!(device.stats(), DeviceStats::default());
}

/// The measurement behind this file (timing: not run by default).
///
/// Four threads route genuine 64-byte packets, each for its own peer, on
/// one device; then the same again while a fifth thread does nothing but
/// `identify` forged initiations — one X25519 after another — and a
/// sixth answers cookie-less initiations under load. With the device
/// behind a lock, as it had to be while `receive` took `&mut self`, the
/// first of those took routing from 7.4 million packets a second to under
/// 600 and the second to under a million, on the machine this was written
/// on (`audit/src/bin/lock_scaling.rs` still measures that arrangement).
/// Shared by reference, neither is in the way: the test asks for nine
/// tenths of the undisturbed rate, and says what it measured.
///
/// ```sh
/// cargo test --release --test shared_device -- --ignored --nocapture
/// ```
#[test]
#[ignore = "timing: run on a quiet machine with at least six cores"]
#[allow(clippy::print_stdout)] // the rates, for whoever runs the measurement
fn routing_does_not_wait_for_another_threads_handshake_work() {
    const WORKERS: u32 = 4;
    const SECONDS: f64 = 1.5;
    let mut rng = DeterministicRng::new(0x5ca1e);
    let (server_key, server_pub) = keypair(&mut rng);
    let device = Device::new(server_key, wall(), &mut rng).unwrap();
    let cookies = RwLock::new(CookieState::new());
    let now = Ticks::from_secs(10);

    // Every worker's packets are encrypted before the clock starts.
    let mut jobs = Vec::new();
    for n in 0..WORKERS {
        let mut p = peer(&device, server_pub, n, &mut rng);
        let quiet = AtomicBool::new(false);
        let mut stats = DeviceStats::default();
        assert_eq!(p.run(&device, &cookies, &quiet, &mut stats, 1, &mut rng), 1);
        let packets = 6_000_000usize;
        let mut wire = vec![0u8; packets * 96];
        for chunk in wire.chunks_exact_mut(96) {
            match p.client.encapsulate(now, &[0xdd; 64], chunk).unwrap() {
                Encapsulated::Transport(tx) => assert_eq!(tx.datagram.len(), 96),
                other => panic!("{other:?}"),
            }
        }
        jobs.push((p, wire));
    }

    let mut rates = Vec::new();
    for disturbed in [false, true] {
        let stop = AtomicBool::new(false);
        let (identified, replied) = (AtomicU64::new(0), AtomicU64::new(0));
        let (routed, elapsed): (u64, f64) = std::thread::scope(|threads| {
            if disturbed {
                let (device, cookies, stop, identified, replied) =
                    (&device, &cookies, &stop, &identified, &replied);
                threads.spawn(move || {
                    let mut rng = DeterministicRng::new(1);
                    let mut stats = DeviceStats::default();
                    let mut d = forged_initiation(&server_pub, &mut rng);
                    while !stop.load(Ordering::Relaxed) {
                        if let Incoming::Initiation(mut init) =
                            device.receive_shared(None, now, x_addr(), &mut d, &mut stats)
                        {
                            let _ = device.identify(&mut init);
                            identified.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
                threads.spawn(move || {
                    let mut rng = DeterministicRng::new(2);
                    let mut stats = DeviceStats::default();
                    let mut out = [0u8; 128];
                    let mut d = forged_initiation(&server_pub, &mut rng);
                    while !stop.load(Ordering::Relaxed) {
                        let guard = cookies.read().unwrap();
                        let incoming =
                            device.receive_shared(Some(&guard), now, x_addr(), &mut d, &mut stats);
                        if let Incoming::CookieRequired(challenge) = incoming {
                            drop(guard);
                            let mut state = cookies.write().unwrap();
                            let _ = device.cookie_reply_shared(
                                &mut state, now, &challenge, &mut out, &mut rng, &mut stats,
                            );
                            replied.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
            let workers: Vec<_> = jobs
                .iter_mut()
                .map(|(p, wire)| {
                    let (device, stop) = (&device, &stop);
                    // A fresh stretch of packets for each of the two runs.
                    let half = wire.len() / 2;
                    let part = if disturbed {
                        &mut wire[half..]
                    } else {
                        &mut wire[..half]
                    };
                    let (tunnel, addr) = (&mut p.server, p.addr);
                    threads.spawn(move || {
                        let mut stats = DeviceStats::default();
                        let start = Instant::now();
                        let mut done = 0u64;
                        for datagram in part.chunks_exact_mut(96) {
                            if done % 256 == 0 && start.elapsed().as_secs_f64() > SECONDS {
                                break;
                            }
                            match device.receive_shared(None, now, addr, datagram, &mut stats) {
                                Incoming::ForPeer(_, packet) => {
                                    let handled = tunnel.handle(now, addr, packet).unwrap();
                                    assert!(matches!(handled.received, Received::Data(_)));
                                }
                                other => panic!("{other:?}"),
                            }
                            done += 1;
                        }
                        stop.store(true, Ordering::Relaxed);
                        let elapsed = start.elapsed().as_secs_f64();
                        ((done as f64 / elapsed) as u64, elapsed)
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|w| w.join().unwrap())
                .fold((0, 0.0), |(rate, longest), (r, e)| {
                    (rate + r, f64::max(longest, e))
                })
        });
        println!(
            "{} routed {:.2} M packets/s on {WORKERS} threads{}",
            if disturbed {
                "disturbed:  "
            } else {
                "undisturbed:"
            },
            routed as f64 / 1e6,
            if disturbed {
                format!(
                    " (next to {:.0} identify/s and {:.0} cookie replies/s)",
                    identified.load(Ordering::Relaxed) as f64 / elapsed,
                    replied.load(Ordering::Relaxed) as f64 / elapsed
                )
            } else {
                String::new()
            }
        );
        rates.push(routed);
    }
    assert!(
        rates[1] * 10 >= rates[0] * 9,
        "routing fell from {} to {} packets a second next to handshake work",
        rates[0],
        rates[1]
    );
}
