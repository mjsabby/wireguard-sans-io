# Embedder Obligations — `wireguard-sans-io`

**Status:** Normative · **Audience:** System integrators deploying this
library in safety- or security-critical contexts

This library is **sans-I/O**: it implements the WireGuard protocol and
performs no I/O. Sockets, clocks, randomness, scheduling, MTU and rate
limiting are the embedder's. The library's guarantees hold **only if every
obligation below is met**. Each item states what breaks if it is not.

The protocol itself is *not* on this list. Which peer a datagram is for,
where a peer currently is (roaming), when a session is usable, and every
timer are decided inside the library; §11 says what you must not
re-implement around it.

Obligations are tagged by the consequence of violation:
**[CONF]** confidentiality loss · **[INTEG]** integrity/forgery ·
**[AVAIL]** denial of service · **[INTEROP]** wire incompatibility.

---

## 1. Entropy (`EntropySource`)

### 1.1 [CONF] MUST be cryptographically secure

Ephemeral X25519 secrets, the key that makes session indices routable,
cookie secrets and the cookie-reply nonce seed are drawn directly from
`EntropySource::fill()`. A predictable source **destroys forward secrecy
entirely** — an attacker who can predict the ephemeral recovers every
session key.

| Platform | Use |
|---|---|
| Linux/macOS/BSD | `getrandom(2)` |
| Windows | `BCryptGenRandom` / `RtlGenRandom` |
| Embedded | Hardware TRNG, **health-checked** (NIST SP 800-90B), seeded before the first `Device` is created |

```rust
struct OsRng;
impl EntropySource for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(buf).map_err(|_| EntropyError)
    }
}
```

**MUST NOT** use: `DeterministicRng` (test-only), any LCG/xorshift,
`SystemTime`-derived values, or the `OsRng` of the three examples
`interop_kernel.rs`, `interop_kernel_responder.rs` and `interop_relay.rs`
(clock-derived, and marked test-only where it is defined; the fourth,
`interop_conformance.rs`, reads `/dev/urandom`).

### 1.2 [INTEG] Devices that share a static key MUST draw independent entropy

Every `Device` created with the **same local static key** — the same
identity on two sockets, in two processes, in a cloned VM, or after a
restart — uses the same cookie-reply AEAD key
(`Hash(LABEL_COOKIE ‖ local_public)`). Its nonce counter is seeded from
the entropy source. Two such devices fed identical entropy seed
identically and collide → Poly1305 one-time-key reuse →
**cookie-reply forgery** by anyone observing two replies.
(Demonstrated in `tests/attack_resistance.rs`.)

A source that meets 1.1 meets this. It is listed separately because the
failure it describes — a snapshot restored twice, a PRNG seeded from a
constant — passes every functional test.

### 1.3 [AVAIL] MUST return `Err(EntropyError)` rather than weak bytes

The library treats `EntropyError` as a hard, recoverable failure of the
operation at hand (`Error::EntropyFailure`; nothing is committed and the
call can be repeated). Returning `Ok` with low-entropy bytes is silent and
catastrophic.

---

## 2. Time (`Ticks`, `WallClock`)

### 2.1 [AVAIL] `now` MUST be monotonic non-decreasing

All timers (rekey, retransmit, keepalive, expiry, discard) and the age of
cookies are driven by the `Ticks` value passed to each call. A `Tunnel`
clamps regressions defensively, but a clock that jumps backward degrades
to "time stands still": no rekeys, no expiry, no retransmits. Derive it
from a monotonic clock, never from wall time, and use **one** clock for
the device and all of its tunnels.

### 2.1a [CONF] [AVAIL] On a machine that can be suspended, `now` SHOULD count the time spent suspended

WireGuard's lifetimes are in real time: the peer stops accepting a
session three minutes after it was created, whether or not this machine
was awake. `CLOCK_MONOTONIC` on Linux — which is what
`std::time::Instant` reads — stands still during a suspend. A tunnel on
that clock wakes up believing its session is as young as when the lid was
closed: it sends on keys the peer has expired, everything it sends is
lost until the dead-peer timer starts a handshake fifteen seconds later,
and keys that were to be wiped three or nine minutes after their creation
are still in memory hours later. Use the clock that goes on counting:
`CLOCK_BOOTTIME` on Linux and Android (what the kernel's WireGuard uses;
it also discards its sessions when the machine suspends). Timers that
came due during the suspend are then served by the first `poll` after it.
If the platform has no such clock, call `Tunnel::reset()` on resume.
(`wireguard-embed` uses `CLOCK_BOOTTIME` where there is one.)

### 2.2 [AVAIL] The `WallClock` anchor MUST be approximately real

The wall clock is read once: `WallClock::new(at, unix_secs, unix_nanos)`
says what the Unix time was at monotonic instant `at`. It is used **only**
to build the TAI64N timestamp in handshake initiations, which the peer
requires to increase from one initiation to the next.

* Within one run the library guarantees that: timestamps are derived from
  the monotonic clock and ratcheted strictly past the last one sent, so a
  wall clock that is stepped while the process runs has no effect (unless
  you pass the new reading in with `set_wall_clock`, and even then
  timestamps never go back).
* **Across restarts it is yours to guarantee.** If one run was anchored
  far in the future (an unset RTC, a GPS rollover), the peer remembers
  that timestamp, and every initiation of the next, correctly anchored
  run is rejected as a replay until real time catches up. Nothing on our
  side can undo that; the *peer* has to forget the tunnel.

Do not create a `Device` before the platform knows the time, or — if it
must run before that — make sure the anchor errs towards the past, and
call `set_wall_clock` (on the device, for tunnels created later, and on
every existing tunnel) once the time is known.

### 2.3 [AVAIL] MUST keep `Ticks` in range

`Ticks` is `u64` nanoseconds; instants up to `Ticks::MAX` (2⁶³ − 1 ns,
292 years after your epoch) are times. A larger value is not: it comes
from a unit mix-up — `Ticks::from_secs(milliseconds)` saturates to the
largest value there is — or from a variable that was never set. The
library treats such an instant as it treats one that goes backwards:
**for that call, no time has passed.** Nothing is destroyed by it (taken
at face value it would expire every session and make every timer due,
for ever), and nothing recovers by it either: while the clock stays out
of range the tunnel stands still — no retransmission, no keepalive, no
rekey — and `Tunnel::next_wake()` is, by your clock, always in the past,
so a loop that sleeps until then spins without sending anything. Use an
epoch at process start, and a single unit.

A reading that is in range but *ahead of the truth* — a glitch, an offset
applied twice, `Ticks::MAX` itself — is a time like any other, and the
tunnel acts on it: sessions that are too old by that reading expire, and
timers that are due by it fire. After that, since time never goes back,
the tunnel stands still until your clock has caught up with the reading:
for a reading an hour ahead, an hour without retransmissions, keepalives
or rekeying. Nothing in the library can tell such a reading from the
passage of time; do not pass one.

---

## 3. Load signalling and rate limiting

### 3.1 [AVAIL] MUST assert `under_load = true` when handshake volume is high

When `under_load == false`, anyone who knows this endpoint's **public**
key can send initiations that pass `mac1`, and each one that is then
identified (`Device::identify`, or inside `Device::receive_for`) costs one
X25519 (~20 µs) — ~50 k packets/s saturates one core. With
`under_load = true`, a handshake message without a valid `mac2` gets no
further than `Device::receive`, which returns `Incoming::CookieRequired`;
that costs a few MACs, and the reply (`Device::cookie_reply`) one more MAC
and a 16-byte AEAD.

A correct trigger says that this machine has more handshake work than it
can do: the depth of the queue handshake messages wait in (the kernel:
512 of them), or the time spent on handshake messages **that passed
`mac1`** (`wireguard-embed`: more than a tenth of the time — a budget
that fills at a tenth of a second per second and holds ten milliseconds —
and then for a second at the least, so that a flood does not get the
signal to switch off and on). The rate of such messages works if the
threshold is well above what your peers themselves send. Measure after `receive`, not before:
counting anything shaped like a handshake message lets someone who does
not even know your public key keep you "under load".

Being under load has a price, which is why the trigger should not be
hair-fine. A handshake that meets a cookie reply starts over one
`Rekey-Timeout` later: every genuine handshake then takes five seconds
longer, in either role. And for as long as cookies are demanded, someone
who can see your peer's handshake messages and inject datagrams — without
being able to drop any — can keep handshakes from completing altogether,
by racing forged cookie replies: the key they are sealed with derives
from a public key. A threshold of ten handshake messages a second
(BoringTun's per-peer default) hands that position to anyone who knows
your public key and can send thirty datagrams a second.

### 3.2 [AVAIL] MUST rate-limit per source address — and ONLY sources a cookie has proven

The cookie mechanism only proves address ownership; it does **not** limit
how many handshakes a single owned address can ask for. A botnet (or one
host not spoofing) with a valid `mac2` still gets one X25519 per
datagram. The kernel pairs cookies with a token-bucket rate limiter
(`ratelimiter.c`, 20 pkt/s + 5 burst per address, IPv6 by /64). This
library cannot keep one (it would need a per-address table), but it gives
the limiter its place and its signal:

```rust
match device.receive(now, src, under_load, &mut datagram) {
    Incoming::Initiation(mut init) => {
        if init.source_verified() && !limiter.allow(init.src().ip()) {
            return; // dropped before any Diffie-Hellman
        }
        let Ok(public_key) = device.identify(&mut init) else { return };
        // … look the peer up, tunnel.handle_initiation(now, &init, …)
    }
    Incoming::ForPeer(id, packet) => {
        if packet.is_handshake() && packet.source_verified() && !limiter.allow(src.ip()) {
            return;
        }
        // … tunnel.handle(now, src, packet)
    }
    // …
}
```

**MUST NOT** consult a per-source limiter for a message whose source is
not verified — and in particular **MUST NOT put one in front of
`Device::receive`**. Before the cookie check a source address is whatever
the sender wrote into the packet: a limiter keyed on it lets anyone who
knows your public key spend the allowance of an address of their
choosing, and the peer at that address is locked out for as long as the
flood lasts. `source_verified()` is true exactly when the message arrived
under load with a valid cookie. When not under load there is nothing to
key a limit on; the remedy for too many handshakes is 3.1.

What "verified" does not mean: that the message is fresh. `mac2` covers
the message, not the moment, so a cookie-bearing message that was
*recorded* and is replayed from the same (forged) address is verified
again for as long as the secret behind its cookie is honoured — up to 130
seconds after the secret was drawn (the kernel: 120). Each replay takes a
token from that address's bucket. Someone who can record a peer's
handshake messages and forge its address can so have that peer's own
handshakes refused while you are under load. A per-source limit has this
price in every implementation; the alternative, no limit, is one cookie
buying unlimited X25519.

`Device::receive_for` is a single call and leaves no room for the limit:
use it only where one cookie buying unlimited X25519 is acceptable.
(Demonstrated, with exact operation counts, in `tests/cost.rs`;
`wireguard-embed` implements the limiter.)

With a single peer you can have both the limit and the cheaper call:
`peek` at the datagram, take the two-step path for handshake messages and
`receive_for` for everything else. `receive_for` does not decode the
receiver index into a peer id — there is nothing to route — which saves
a transport datagram most of what `receive` costs (3.4).
`wireguard-embed` does this; its data path touches neither the limiter
nor the index codec (`DeviceStats::routed` stays where it is).

Do not use `peek` for anything else in front of `receive`. It says what a
datagram *claims* to be, before anything has been checked: counting such
claims as load, or limiting sources by them, is what 3.1 and this section
forbid.

### 3.3 [AVAIL] SHOULD bound the maximum datagram size accepted from the network

What an unwelcome datagram costs before it is rejected depends on how far
it gets. On one x86-64 core, with the default provider, in cycles (a
handshake, for scale, is about 430,000 on each side):

| what arrives | cost to the receiver |
|---|---:|
| garbage: too short, an unknown type | 17 |
| transport data for an index that is not one of yours | 80 with `receive_for`, 215 routed by `Device::receive` |
| a handshake message with a wrong `mac1` | 800 |
| under load, a handshake message without a cookie | 860 — and 4,200 more for the cookie reply |
| transport data with a live index, an unseen counter and a wrong tag | 1,800 at 1452 bytes; 63,000 at 65,507 |
| an initiation with a forged body under a valid `mac1` (needs your public key) | 118,000: one X25519 |
| a recorded initiation of the peer's, played again | 125,000 |
| a forged response to an initiation of yours that is in flight (needs your public key and the index, which is on the wire) | 234,000: two X25519 |

The handshake lines are what the load signal and the per-source limit of
§3.1 and §3.2 are for. The transport line has no such defence in front of
it — nothing limits transport data — and its cost is yours to bound: a
forged datagram with a live index and an unseen counter costs one
Poly1305 pass over all of it, which at 64 KiB is half an X25519. Clamp
receives to the path MTU (or at most a few KB) rather than accepting
64 KiB UDP datagrams.

### 3.4 [AVAIL] If receiving on several threads, MUST share the device by reference, not behind a lock

Everything a `Device` needs in order to route is fixed when it is made.
What changes while it receives is its counters and — under load only —
the cookie secret. `Device::receive` and `Device::cookie_reply` keep both
inside the device, and therefore take `&mut self`: they are the calls for
one thread. With several threads use the pair that takes `&self`:

```rust
let device: Arc<Device> = …;                 // shared; no lock
let cookies: RwLock<CookieState> = …;        // the only lock, and only under load
// per thread:
let mut stats = DeviceStats::default();
let guard = under_load().then(|| cookies.read().unwrap());
match device.receive_shared(guard.as_deref(), now, src, &mut datagram, &mut stats) {
    Incoming::ForPeer(id, packet) => { /* that peer's tunnel, under its own lock */ }
    Incoming::Initiation(mut init) => {
        drop(guard);
        // (the per-source limit of 3.2 goes here)
        let Ok(public_key) = device.identify(&mut init) else { return };
        // … look the peer up; tunnel.handle_initiation(now, &init, …)
    }
    Incoming::CookieRequired(challenge) => {
        drop(guard);
        let tx = device.cookie_reply_shared(
            &mut cookies.write().unwrap(), now, &challenge, &mut out, &mut rng, &mut stats)?;
        // … send it, or do not: see 3.5
    }
    _ => {}
}
```

`receive_shared` does what `receive` does, at the same cost (a few dozen
nanoseconds for a transport datagram; one keyed hash for a handshake
message, three under load, five in the ten seconds after the cookie
secret has changed), and `identify` — the one X25519 an initiation costs
before its peer is known — takes `&self` as well. So no datagram waits
for another thread: transport data touches no lock but its tunnel's, and
handshake arithmetic runs next to it.

**Do not put the device itself behind a lock** — neither a mutex nor a
reader-writer lock. A mutex makes one queue of every datagram of every
peer. A reader-writer lock held exclusively for `receive` and *shared*
for `identify` — what this section used to prescribe — is worse than it
looks: a shared hold keeps writers out, and `receive` is a writer, so
every datagram of every peer waits for whichever initiation is being
identified. Measured on four receive threads: one more thread fed forged
initiations — 29,000 a second, 34 Mbit/s, from anyone who knows the
public key — took routing from 7.4 million packets a second to under
600; half a million valid-`mac1` messages a second under load (the cookie
check and the reply inside the lock) took it to under a million.
(`audit/src/bin/lock_scaling.rs` measures the device behind either lock
and shared by reference; `tests/shared_device.rs` is about the shared
calls, and its last test times them.)

One `CookieState` per device, not one per thread: a cookie is good only
for the state that made it. One device, not one per thread either: the
key that makes session indices routable is the device's.

### 3.5 [AVAIL] SHOULD bound what is spent on cookie replies

Under load every handshake message that passes `mac1` without a cookie is
answered with a cookie reply — 64 bytes to an address its sender chose,
at the cost of a keyed hash and a 16-byte AEAD, and of a place in the
socket's way out. The protocol asks for the reply; nothing obliges you to
make one for every such message, and a flood of them should not come
before what the tunnel itself has to send. Make replies with what is left
over: after transport data and after handshake messages that carry a
cookie, as many as there is time and room for, dropping the rest (the
sender retransmits in five seconds — and whoever holds a cookie by then
is let through). On an uplink that is much narrower than the downlink,
cap them outright. (`wireguard-embed`'s event loop does the first by
itself; `RateLimiter::with_cookie_reply_limit` is the cap.)

Do **not** limit replies per source address: that address is unproven, so
anyone who knows your public key could use up the replies of an address
of their choosing — and the peer at that address, who needs one to get
through while you are under load, would never see it.

---

## 4. MTU and fragmentation

> WireGuard the protocol has **no** MTU negotiation, discovery, or
> backoff mechanism. There is no message type, header field, or
> signalling for it. Each side independently configures its tunnel MTU;
> if either side gets it wrong, full-size packets are silently dropped.

### 4.1 [AVAIL] [INTEROP] MUST set `PeerConfig::mtu` to the tunnel-interface MTU

`encapsulate()` zero-pads plaintext to the next multiple of 16, clamped
to the configured MTU (whitepaper §5.4.6; matches kernel
`calculate_skb_padding` and wireguard-go `calculatePaddingSize`).
With `mtu = None` the clamp is disabled, which is correct
**only** if the tunnel-interface MTU is itself a multiple of 16;
otherwise inner packets in `(mtu − mtu%16, mtu]` are padded past MTU →
outer datagram exceeds path MTU → dropped (DF) or fragmented.

```rust
let mut config = PeerConfig::new(peer_public);
config.mtu = NonZeroU16::new(1420);          // = TUN-device MTU
// after a path-MTU change:
tunnel.set_mtu(NonZeroU16::new(new_mtu));
```

| Outer path MTU | Overhead (v4 / v6) | Recommended tunnel MTU |
|---:|---:|---:|
| 1500 (Ethernet) | 60 / 80 | 1440 / **1420** |
| 1492 (PPPoE) | 60 / 80 | 1432 / 1412 |
| 1480 (RFC 4459) | 60 / 80 | 1420 / 1400 |
| 1280 (IPv6 min) | 60 / 80 | 1220 / 1200 |

Set the same value on the TUN/TAP device and in `PeerConfig::mtu`.

### 4.2 [AVAIL] MUST handle outer-path ICMP Fragmentation-Needed

When the outer path MTU shrinks (route change, VPN-in-VPN), the network
returns ICMP type 3/code 4 (v4) or PTB (v6) to the *outer* socket. The
library never sees these. The embedder must:
1. Receive outer ICMP on the UDP socket (`IP_RECVERR` / `IPV6_RECVERR`
   on Linux) — and, having asked for the errors, **read them**: see 4.4.
2. Reduce the tunnel-interface MTU accordingly (`Tunnel::set_mtu`).
3. Synthesize an *inner* ICMP Fragmentation-Needed back to the original
   inner sender so its PMTUD works.

Without this, a path-MTU reduction is a permanent black-hole for
full-size traffic — if outer packets carry DF (4.3).

### 4.3 [AVAIL] SHOULD NOT rely on outer fragmentation

Relying on IP fragmentation for tunnel traffic is fragile (NAT/firewall
reassembly limits, fragment drops kill the whole datagram) and an
amplification-attack surface: size the tunnel MTU so that outer packets
fit the path (4.1). Whether to set DF on outer packets is a choice with
two sides. Set (`IP_PMTUDISC_DO` on Linux), an oversized outer packet is
dropped with an ICMP error — which 4.2 obliges you to act on, or
full-size traffic is black-holed. Clear, routers fragment it and the
tunnel keeps working through a wrong MTU, at the costs above. (The Linux
implementation sends its outer packets with DF clear.)

### 4.4 [AVAIL] MUST NOT let an error from the socket end the receive loop, deafen the socket, or cost a datagram

With `IP_RECVERR`, or on a connected socket, the kernel reports ICMP
errors about earlier datagrams on the socket's next call, each kind as
its own `errno`: `EMSGSIZE` (fragmentation needed / packet too big),
`ECONNREFUSED`, `EHOSTUNREACH`, `ENETUNREACH`, `ENOPROTOOPT`, `EPROTO`,
`EACCES` (administratively prohibited) and others. Every one of them can
be forged by any host that can reach yours, knowing only your address and
port. Three things follow.

* **The loop goes on.** A receive loop that returns on "unexpected"
  errors can be shut down from outside with a single packet. Count the
  error, act on it if you do path-MTU discovery (4.2), and receive again.
  A whitelist of "harmless" errors is the wrong shape: it is the unlisted
  ones that end the tunnel.
* **With `IP_RECVERR` / `IPV6_RECVERR`: read the error queue.** Linux
  also *keeps* every such error, in the socket's error queue
  (`recvmsg(…, MSG_ERRQUEUE)`), and what is in that queue is charged to
  the socket's receive buffer. Unread, about two hundred errors fill it —
  and from then on the kernel drops every datagram that arrives for the
  socket, until the process restarts. Forged errors do it in a moment; a
  peer that is down for a few minutes does it without any attacker.
  Whenever the socket reports an error, read the queue until it is empty.
* **Repeat a send that fails.** The pending error is reported on
  whichever call comes next. If that is a send, the datagram is *not
  sent* — the error was about an earlier one. Under a stream of forged
  errors four sends in five fail this way. Take the error and send again
  (two or three attempts tell an old error from this datagram's own).

If a socket does nothing but fail — error after error with no datagram
and no "nothing to read" in between — back off briefly rather than spin;
ICMP errors alone do not look like that, however many there are, and
should not get the socket left alone. (`wireguard-embed`'s event loop
does all of this; `embed/tests/icmp_errors.rs` forges nine kinds of error
against it, and thousands of them at a time.)

---

## 5. Addresses

### 5.1 [INTEG] [AVAIL] MUST pass the datagram's real source address

`Device::receive` / `receive_for` and `Tunnel::handle` take `src`, the
address the datagram arrived from (an initiation carries the `src` that
was given to `receive` with it to `Tunnel::handle_initiation`). Two
things depend on it:

* **Cookies** are `MAC(secret, src)`. A constant or made-up `src` means a
  cookie no longer proves address ownership and the under-load defence is
  void: one cookie validates from every spoofed address.
* **The peer's endpoint** is set to `src` when — and only when — the
  datagram proves the peer is there (`Tunnel::endpoint` has the rule: a
  response to our initiation, transport data; not a cookie reply; an
  initiation once the peer has shown that its initiations are live, or
  for a tunnel that has no endpoint — otherwise its source is tried, not
  trusted). A wrong `src` sends the peer's traffic to the wrong place.

For cookies the library canonicalises the address itself (an IPv4-mapped
IPv6 address and the plain IPv4 address are the same remote), so pass
whatever the socket reports. The endpoint is kept as it was passed: the
same peer seen as `192.0.2.1` and later as `::ffff:192.0.2.1` counts as
having moved, which is harmless but shows up as `endpoint_changed`.

### 5.2 [INTEG] MUST send every `Transmit` to its `dst`

Every datagram the library hands out comes as a `Transmit { dst,
datagram }`. Send it there, and nowhere else. In particular **do not keep
your own notion of the peer's address** ("reply to whoever I last heard
from"): a reply to an unauthenticated handshake message — a cookie reply
under load — is addressed to the sender of that message, who has proven
nothing, and must not become the destination of the peer's traffic.

`Tunnel::set_endpoint` is for configuration and out-of-band discovery
only.

### 5.3 [AVAIL] On a host with several addresses, SHOULD send from the address the peer contacted

A `Transmit` says where a datagram goes, not which local address it
leaves from: the library does not know which of the host's addresses a
datagram arrived at. On a socket bound to all of them the system chooses
the source of each outgoing datagram from its routing table, and that
need not be the address the peer wrote to — the peer then gets its
handshake response from an address it never contacted, and a NAT or
stateful firewall on the way may drop it. (The Linux implementation
remembers the local address per peer.) Bind one socket per local address
the peers use, or record the destination address of incoming datagrams
(`IP_PKTINFO` / `IPV6_RECVPKTINFO`) and send replies from it.

---

## 6. Buffer sizing

Every size is fixed in advance; none depends on what a remote party sends.

| Call | Buffer |
|---|---|
| `Tunnel::encapsulate` | `out`: `transport_datagram_len(payload.len())` |
| `Tunnel::encapsulate_in_place` | `buf`: 16 bytes of headroom + payload + padding + 16 |
| `Device::receive`, `Device::identify`, `Tunnel::handle` | none — transport data is decrypted inside the datagram |
| `Tunnel::handle_initiation`, `Device::receive_for` | `out`: 92 |
| `Device::cookie_reply` | `out`: 64 |
| `Tunnel::poll` | `out`: 148 |

An undersized buffer returns `Error::BufferTooSmall`; no protocol state
has changed and the call may be repeated. `Error` is **never** caused by a
remote party: it is a local sizing bug, an entropy failure, or an internal
inconsistency. Handle it as such — do not log it as an attack, and do not
let it tear down a receive loop that hostile datagrams could then never
reach.

The datagram buffer passed to the receive calls is modified only when
authenticated transport data is decrypted in it. A forgery leaves it
exactly as it arrived.

---

## 7. Information exposure

### 7.1 [CONF] MUST NOT expose `DropReason` to untrusted observers

Why a datagram was dropped is an oracle: `InvalidMac1` vs `AuthFailure`
confirms whether the sender knows this endpoint's static public key;
`UnknownIndex` vs `AuthFailure` leaks live session indices; `Replay` vs
`AuthFailure` leaks counter state. Log/export at most "datagram rejected".
The specific reason is fine in a local-only debug log.

### 7.2 [CONF] MUST NOT expose unaggregated failure counters publicly

`Stats::{auth_failures, replays_dropped}` and
`DeviceStats::{malformed, mac1_failures, initiations, cookies_required,
cookies_sent, routed}` are attacker-influenceable and act as exact oracles if
readable unauthenticated (see the docstrings) — as is whatever you count
yourself from the result of `Device::identify`. Aggregate across peers and
time-bucket before exporting to any metrics endpoint that is not itself
behind the tunnel.

### 7.3 [CONF] MUST NOT log key material, payloads or library internals via `{:?}` to persistent storage

The library's own `Debug` impls redact keys, and print a decrypted
payload (`Received::Data`, `Handled`, the driver's `TunnResult`) and a
datagram (`Transmit`) as their size. That covers the library's types
only. The slices they lend you are plain bytes: `{:?}` of
`handled.received`'s payload, or of the packet a `WriteToTunnel` carries,
prints it all — and your own wrappers redact nothing. Check every `{:?}`
of what you take out of a receive result, and every `derive(Debug)` on a
struct that holds a `StaticSecret`, `PresharedKey`, `[u8; 32]` key,
`Device` or `Tunnel`.

---

## 8. Scheduling

### 8.1 [AVAIL] MUST call `poll()` after every other tunnel call and at every `next_wake()` deadline

`Tunnel::poll` is the only place handshake initiations, retransmissions,
keepalives and expiry happen. `encapsulate` never produces an initiation
itself: with no session it reports `NoSession` and arms a timer for "now".
A caller that only calls `encapsulate` and the receive functions never
handshakes, never retransmits and never rekeys.

```rust
loop {
    let timeout = tunnel
        .next_wake()
        .map(|wake| Duration::from_nanos(wake.since(now())));
    if let Some((n, src)) = socket.recv_timeout(&mut datagram, timeout)? {
        let handled = device.receive_for(
            &mut tunnel, now(), src, under_load(), &mut datagram[..n], &mut out, &mut rng,
        )?;
        // … act on `handled` …
    }
    loop {
        match tunnel.poll(now(), &mut buf, &mut rng)? {
            PollOutput::Transmit(tx, _) => socket.send_to(tx.datagram, tx.dst)?,
            PollOutput::Idle => break,
            _ => {} // HandshakeExpired / SessionsExpired: see §8.4
        }
    }
}
```

### 8.2 [AVAIL] MUST loop `poll()` until `Idle`

`poll()` performs **at most one** action per call. A single call after a
long sleep may leave further actions pending.

### 8.3 [AVAIL] MUST NOT busy-spin when `next_wake()` is in the past

`next_wake()` may legitimately return an instant ≤ now (immediately after
a call arms a deadline for "now"). The correct response is to `poll()`
immediately, **not** to sleep for a negative duration. After `poll()`
returns `Idle`, `next_wake()` is `None` or strictly in the future
(regression-locked by `tests/busy_loop_regression.rs`).

If `poll()` returns `Err`, the action that failed stays due. Do not retry
in a tight loop: a persistent local fault (an entropy source that keeps
failing) would spin. Back off.

### 8.4 [AVAIL] MUST act on what the outcomes report

* `Encapsulated::NoSession` / `NoEndpoint`: **the packet was not
  consumed.** Hold it (in a bounded queue) or drop it. If you hold it,
  give it a deadline of its own — `Rekey-Attempt-Time`, ninety seconds —
  and drop it then: `HandshakeExpired` below does not come for every
  packet. The handshake attempt starts over with each packet that finds
  no session, so a trickle of them keeps the attempt, and the packets
  held before, alive indefinitely; and with `NoEndpoint` there is no
  attempt at all. A queue without deadlines sends hour-old packets when
  the peer finally turns up.
* `Handled::session_established`: a session became usable for sending —
  in either role. Send what you were holding. A responder learns this
  from the peer's first transport message, which may equally be a
  keepalive (`Received::Keepalive`) or data (`Received::Data`).
* `PollOutput::HandshakeExpired`: the handshake attempt was abandoned
  after `Rekey-Attempt-Time`. Drop what you were holding (whitepaper
  §6.4).

---

## 9. Peers

### 9.1 [INTEG] MUST give every live tunnel of a device its own `PeerId`

`Device::receive` names the peer a datagram is for by the `PeerId` you
passed to `Device::tunnel`. Two live tunnels with the same id share their
index space, and datagrams for one are routed to the other (which rejects
them — the failure is loss of connectivity, not a confidentiality
problem). Use the key of your peer table as the id and this cannot happen.

### 9.2 [INTEG] MUST treat `Incoming::ForPeer` and `Incoming::Initiation` as unauthenticated routing hints

The `PeerId` in `ForPeer` is decoded from a 32-bit field anyone can set;
the public key `Device::identify` returns for an `Initiation` was
decrypted from a message whose sender has not yet been shown to hold the
matching private key. Both tell you *which tunnel to ask*; the tunnel's
answer (`Handled`) is the verdict.

* An id or public key that is not in your table: drop the datagram. Look
  it up with a fallible operation (`get`), never by indexing or
  `expect`: both values are the sender's choice, and a panic here is a
  remote crash.
* Do not create peers, update per-peer state, or log "peer X connected"
  from the routing step.

### 9.3 [INTEG] MUST NOT route by source address

WireGuard peers roam. Routing a datagram to a tunnel because of where it
came from lets an attacker steer datagrams to the wrong tunnel and breaks
every peer that changes address. `Device::receive` is the only router.

---

## 10. Lifecycle and secrets in memory

What the library does about key material in memory, so that the items
below can be read against it:

* Session keys and handshake state are derived straight into storage
  inside the `Tunnel` and never moved as values. They are wiped there when
  a session is rotated out, when a session expires unused, at the §6.3 key
  wipe (`PollOutput::SessionsExpired`), on `reset()`, and on drop.
* Working copies — Diffie-Hellman results, chaining keys, the handshake's
  AEAD keys, cipher and hash state — are zeroed before the call that used
  them returns. Where a compiler keeps a secret in registers and parks
  registers on the stack (the curve arithmetic, the states of the cipher
  and of the hash, the vector registers of the SIMD keystreams), the
  stack frame is overwritten once the function has returned.
* `scripts/check_secret_residue.sh` measures both, in an unoptimised
  build and in the dev and release profiles (the last with this
  repository's compiler flags and without): after each kind of public
  call — the primitives by themselves, the constructors, a tunnel's whole
  life, the driver's constructors — no secret the call handled is found
  in dead stack memory, as the bytes it is (all of them, or any eight in
  a row) or as the words the arithmetic had it in; and a tunnel's own
  bytes hold exactly the secrets its current state needs — none once it
  is dropped.

That is **best effort**, as it is in any language without control over
the compiler's temporaries: the measurement is of the stack, on x86-64
(and of the release build on aarch64 under emulation), with the compiler
it was run with. Registers are outside it, and so are other targets; an
unoptimised build is held to less (the README says what). The
obligations that remain yours:

### 10.1 [CONF] MUST drop `Device`/`Tunnel`/keys for secret wiping to run

The static key, the pre-shared key and the precomputed static-static
secret live as long as the value that holds them and are wiped in `Drop`
(session keys too, if any are left). A value leaked (`mem::forget`,
`Box::leak`, stored in a `static`) is never wiped. On process termination
without unwind (SIGKILL, `_exit`, power loss), nothing is wiped — assume
RAM is recoverable and treat physical access accordingly.

### 10.2 [AVAIL] `reset()` does NOT clear the peer's greatest timestamp

This is deliberate (replay protection across reset). To recover from a
poisoned timestamp (the peer once sent a far-future TAI64N and is now
rejected), **drop the `Tunnel` and create a fresh one with
`Device::tunnel`** — `reset()` is not sufficient. Note what a fresh
tunnel gives up: it has no greatest timestamp, so an initiation recorded
from the peer before the re-creation (or before a restart) is accepted
once more if replayed, from any address — and so is each later recording
after it, in order. What a replay gets the replayer:

* one handshake response (92 bytes, to its own address). The session it
  sets up is never used;
* our own next initiation held back by `Rekey-Timeout`, as after any
  response — but by no more than fifteen seconds for a whole series of
  replays, however many recordings there are;
* its address tried: every other initiation of ours goes there (and gets
  no answer) until the peer is heard from. The tunnel's endpoint stays
  where it is — an initiation does not move a known endpoint before the
  peer has shown that its initiations are live.

A tunnel configured without an endpoint has none to keep and takes the
replayer's address as a first guess, until the real peer is heard from;
give the tunnel the peer's endpoint if you know it. (Linux moves the
endpoint in both cases, and has no bound on the hold.)

### 10.3 [CONF] MUST treat `StaticSecret` as move-once

`StaticSecret` is `Clone` for ergonomic configuration; every clone is an
independent copy that must be dropped for wiping. The `Device` keeps one
and gives one to each `Tunnel` it creates (the initiator side of the
handshake needs it). Prefer constructing the secret once, where it is to
stay, and handing it over by reference — `Device::new_in`, and
`Tunn::with_keys` in `wireguard-embed` — or moving it once into
`Device::new`. (A value given away by value is copied out of wherever
you had it: the callee wipes the copy it received, and cannot reach
yours.) Never store the raw `[u8; 32]` representation alongside.

### 10.4 [CONF] SHOULD NOT move a `Device`, `Tunnel` or identified `Initiation` once it holds secrets

A Rust move is a byte copy; the bytes it copied *from* stay where they
were until something overwrites them, and no destructor runs for them.
The library avoids such moves internally. It cannot avoid yours:

* Put a `Tunnel` where it will live (its slot in the peer table, its
  `Box`) **before** its first handshake. Moved later — a `Vec` that
  reallocates, a value returned up the stack — it leaves a copy of its
  session keys behind. Long-term keys — the static key, the pre-shared
  key, the static-static secret — are in it from construction, and so in
  whatever it is moved out of: `Device::tunnel` and `Device::new` return
  by value, and the caller's frame keeps a copy. Where that matters,
  construct in place: `Device::new_in` and `Device::tunnel_in` build a
  device and a tunnel inside an `Option` slot that is already where they
  are to live (and need an eighth of the stack `Device::tunnel` does:
  see *How much stack* in the README).
* An `Initiation` holds handshake state after `Device::identify`. Pass it
  on by reference, as the API asks, and let it go out of scope; it is
  wiped when dropped. Do not store or queue identified initiations.
* Decrypted packets are yours from the moment `Received::Data` hands them
  out, as is the receive buffer they are in.

### 10.5 [CONF] SHOULD keep key-bearing memory out of swap and core dumps

Wiping in place does nothing for a page that was written to swap or to a
core file while the key was live. Where the platform allows it: lock the
pages that hold the `Device` and `Tunnel`s (`mlock`), exclude them from
core dumps (`MADV_DONTDUMP`, or disable core dumps for the process), and
disable or encrypt hibernation images.

---

## 11. What this library does, and does NOT do

Done by the library — **do not re-implement these around it**:

- Routing a datagram to its peer (`Device::receive`).
- Tracking the peer's endpoint, including roaming (every `Transmit`
  carries the destination).
- Deciding when a session is usable, in both roles
  (`Handled::session_established`).
- All timers (`Tunnel::poll`, `Tunnel::next_wake`).

Not done — the embedder is solely responsible for all of the following:

- UDP socket I/O, including outer DF, ECN, DSCP, `IP_RECVERR`.
- Tunnel-interface (TUN/TAP) creation, MTU configuration, route install.
- Cryptokey routing (allowed-IPs filtering on inner src/dst — **MUST**
  be enforced by the embedder, otherwise a peer can spoof any inner
  source address). `ip_packet_addresses` reads the two addresses out of
  a packet; the table of who may use which is yours.
- Trimming padding from received packets (`ip_packet_len`) before handing
  them to the TUN device.
- Path-MTU discovery, ICMP relay, fragmentation.
- The `under_load` signal and per-source rate limiting.
- Queueing packets while no session exists.
- The peer table itself (id → tunnel, public key → id).
- Persistent storage of keys/state across restarts.
- Constant-time guarantees against an attacker with cycle-accurate
  timing of the embedder's network stack.

`wireguard-embed` (in `embed/`) provides, for the single-peer case: a
clock that meets §2.1a, OS entropy, the load signal and the per-source
handshake limit of §3, a packet queue with the deadlines of §8.4, a
default tunnel MTU for §4.1 (1420; `Tunn::set_mtu` for anything else),
and a tokio event loop that meets §4.4. Path-MTU discovery (§4.2),
the choice of local address (§5.3) and cryptokey routing remain yours
there too.

---

## 12. Compliance checklist

For a flight-critical deployment, every line below should trace to a
test in the integrating system's test suite.

- [ ] `EntropySource` is OS/hardware CSPRNG, health-checked, never a PRNG
- [ ] No two devices with the same static key can ever see the same entropy stream (snapshots, clones)
- [ ] `now` from a monotonic clock — one that counts time spent suspended (`CLOCK_BOOTTIME`) where the machine can be — with a process-relative epoch, one unit (below `Ticks::MAX`), one clock for device and tunnels, and never a reading ahead of the truth
- [ ] `WallClock` anchored only once the real time is known (or erring towards the past)
- [ ] `under_load` asserted when handshake work exceeds what the machine can do (time spent on it, or queue depth) — not at a handful of messages a second
- [ ] Load signal measures only handshake messages that passed `mac1`
- [ ] Per-source token bucket consulted **only** for cookie-verified handshake messages (`source_verified()`), between `Device::receive` and `Device::identify` — never in front of `receive`
- [ ] Several receive threads: the device shared by reference (`receive_shared`, `cookie_reply_shared`, `identify`), no lock around it; one `CookieState`, its lock taken only under load
- [ ] Cookie replies made with what is left over after traffic and proven handshakes — capped on a narrow uplink, never limited per source address
- [ ] No socket error ends the receive loop; ICMP errors are counted (and used for PMTU), not fatal
- [ ] With `IP_RECVERR` / `IPV6_RECVERR`: the socket's error queue is read empty whenever the socket reports an error
- [ ] A send that fails is repeated (the error may be an earlier datagram's)
- [ ] `PeerConfig::mtu` set equal to the TUN-device MTU; `set_mtu()` on PMTU change
- [ ] Outer packets fit the path; if they carry DF, outer ICMP Frag-Needed is received and relayed inward
- [ ] Receive buffer clamped to a few KB
- [ ] `src` is the address the datagram actually arrived from
- [ ] Every `Transmit` sent to its own `dst`; no embedder-side peer address
- [ ] On a host with several addresses: replies leave from the address the peer contacted
- [ ] `poll()` looped to `Idle` after every tunnel call and every wake-up; back-off on `Err`
- [ ] Held packets sent on `session_established`, dropped on `HandshakeExpired` — and each after ninety seconds at the latest
- [ ] `Error` handled as a local fault; `DropReason` collapsed before logging/export
- [ ] `Stats` / `DeviceStats` failure counters aggregated/authenticated before export
- [ ] No `derive(Debug)` on embedder structs holding secrets
- [ ] One `PeerId` per live tunnel; unknown ids and public keys dropped
- [ ] Routing only through `Device::receive`, never by source address
- [ ] Allowed-IPs (cryptokey routing) enforced on every decrypted inner packet (`ip_packet_addresses`)
- [ ] Padding trimmed (`ip_packet_len`) before delivery
- [ ] `Device` and `Tunnel`s dropped (not leaked) on shutdown / reconfiguration
- [ ] `Device` and `Tunnel`s constructed where they live (`new_in`, `tunnel_in`), or at least placed there before their first handshake; identified `Initiation`s never stored
- [ ] Key-bearing memory locked and excluded from core dumps where the platform allows
- [ ] Peer lookups by id / public key are fallible (`get`), never indexing or `expect`
- [ ] Timestamp poisoning recovered by a new `Tunnel`, not `reset()`; peers' endpoints configured where they are known
