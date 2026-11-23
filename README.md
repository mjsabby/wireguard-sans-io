# wireguard-sans-io

A **sans-I/O**, **`#![no_std]`**, **zero-allocation**, **zero-dependency**,
**panic-free** implementation of the WireGuard® protocol in Rust 2024.

The library implements the complete protocol — the Noise IKpsk2 handshake,
cookie-based DoS mitigation, transport encryption with replay protection,
routing of datagrams to peers, endpoint roaming, and the whitepaper §6
timer state machine — without ever touching a socket, reading a clock,
spawning a thread, or allocating a byte. Callers feed in datagrams, buffers,
the current time and entropy; the library hands back datagrams to send —
each with its destination — and plaintext that was received.

"Sans-I/O" means no I/O in the core. It does not mean less protocol in the
core: which peer a datagram is for, where a peer currently is, when a
session becomes usable and when a keepalive is due are all decided here,
where a deterministic test can reach them.

```rust
use wireguard_sans_io::{
    Device, Encapsulated, PeerConfig, PeerId, PollOutput, Received, WallClock,
};

// One Device per local key, one Tunnel per peer.
let mut device = Device::new(local_secret, WallClock::new(now, unix_secs, unix_nanos), &mut rng)?;
let mut config = PeerConfig::new(peer_public);
config.endpoint = Some(peer_addr); // if known; otherwise learned from the peer
let mut tunnel = device.tunnel(PeerId::new(0).unwrap(), config, &mut rng)?;

// Send: plaintext in; datagram and destination out.
match tunnel.encapsulate(now, packet, &mut buf)? {
    Encapsulated::Transport(tx) => socket.send_to(tx.datagram, tx.dst)?,
    _ => hold(packet), // no session yet: poll() below sends the handshake
}

// Receive: one call; transport data is decrypted in place.
let handled = device.receive_for(&mut tunnel, now, src, under_load, &mut datagram, &mut out, &mut rng)?;
match handled.received {
    Received::Data(plain) => deliver(plain),
    Received::HandshakeResponse(tx) | Received::CookieReply(tx) => {
        socket.send_to(tx.datagram, tx.dst)?
    }
    Received::Dropped(_why) => {} // whatever a remote party sends is never an Err
    _ => {}
}
if handled.session_established {
    send_held_packets();
}

// Everything the tunnel sends on its own initiative comes from poll().
loop {
    match tunnel.poll(now, &mut buf, &mut rng)? {
        PollOutput::Transmit(tx, _why) => socket.send_to(tx.datagram, tx.dst)?,
        PollOutput::HandshakeExpired => drop_held_packets(),
        PollOutput::Idle => break,
        _ => {}
    }
}
sleep_until(tunnel.next_wake());
```

Complete runnable examples live in the `Tunnel` rustdoc (two peers) and the
`Device` rustdoc (a server with several peers); both run as doctests.

## Two types

| | owns | calls |
|---|---|---|
| `Device` | one local identity: the static key, the `mac1`/cookie state keyed by it, the key that makes session indices routable | `receive` + `identify` (several peers) or `receive_for` (one peer); `cookie_reply`; `tunnel` |
| `Tunnel` | one peer: handshake, sessions, endpoint, timers | `encapsulate`; `handle` / `handle_initiation`; `poll`; `next_wake` |

A `Tunnel` does not borrow its `Device`: store tunnels wherever you like
(a `Vec`, a map, one per task), keyed by a `PeerId` you choose.

## Design rules

| Rule | Enforcement |
|---|---|
| No I/O, no clocks, no global state | API shape: time (`Ticks`) and entropy (`EntropySource`) are arguments; outputs go to caller buffers |
| `#![no_std]`, no `alloc` | `scripts/check_no_std.sh` links an image that goes through every public entry point for a target that has no `std`, without an allocator. (Compiling the library for such a target would not show it: those targets still ship `alloc`.) All state is in the values themselves: a `Tunnel` is 4736 bytes (three sessions, each with a 1 KiB replay window), a `Device` 432 — a test holds them to that, to the byte |
| No `unsafe` | `#![forbid(unsafe_code)]` + **zero dependencies**, so the guarantee covers every line involved, including all cryptography of the default provider |
| No panics | Clippy deny-wall (`indexing_slicing`, `arithmetic_side_effects`, `unwrap_used`, …, and the slice methods that panic on a length) **and** `scripts/check_no_panic.sh`, which searches a linked image for Rust's panic machinery. The image has every public function, method and trait implementation of the core in it (the list is generated from rustdoc and compared), for three crypto providers, called with buffers whose lengths the optimiser cannot know, and prints everything that can be printed. There is none in it at any optimisation level from 1 up, for speed or for size, with or without link-time optimisation (ten configurations). The claim is about optimised code: without an optimiser the panic branches of libcore's own formatting are still there, and a build with overflow checks keeps what it was asked to keep |
| Outcomes say what happened | Every datagram comes back with its destination (`Transmit`); every received datagram comes back as a `Handled` saying what it was, whether a session just became usable and whether the peer moved. Rejecting a datagram is not an error: `Error` is for local faults only, so `?` in a receive loop is safe |
| Defensive | `mac1` verified before any expensive work, and no Diffie-Hellman operation before the caller has had its say (`Device::identify`); verify-then-decrypt AEAD (a forgery leaves the buffer as it arrived); replay window advanced only post-authentication; constant-time comparisons; secrets written once and wiped where they lie (see *Secrets in memory*); monotonicity clamp on hostile clocks; internal invariant failures surface as `Error::Internal`, never as panics |
| Checks can fail | Each of the scripts above — and those under *Testing* that look at what a build contains — first shows that it can fail: a variant with the defect planted (a panic, in the probe and at three places in the library; an allocation; a use of `std`), or a control that must be flagged (a secret left on the stack, a branch on a secret). It refuses to pass unless it catches it |

## Embedding guide

The core is the protocol state machine and nothing else. Sockets, the
clock, entropy, the load signal and (if you want one) a packet queue are
yours. The `wireguard-embed` crate in `embed/` supplies all of them for
`std` (and a tokio event loop) if you would rather not; this section is for
driving the core directly. `EMBEDDER_OBLIGATIONS.md` is the normative list
of what the library relies on you for.

### One peer

The loop is the snippet at the top: `receive_for` for every datagram,
`encapsulate` for every outgoing packet, `poll` until `Idle` after both and
whenever `next_wake()` falls due. Three rules cover everything:

1. **Send every `Transmit` to its `dst`.** The tunnel tracks the peer's
   endpoint and moves it only when the peer proves where it is (roaming).
   A reply to a handshake message — a response to an initiation, a cookie
   reply under load — is addressed to whoever sent that message, which is
   not necessarily where the peer's traffic goes. Do not keep your own
   idea of the peer's address.
2. **Pass the datagram's real source address.** Cookies are bound to it
   and the endpoint is learned from it.
3. **Call `poll` until `Idle`** after every other call and whenever
   `next_wake()` is due. It is the only place handshake initiations,
   retransmissions and keepalives come from.

### Several peers

`Device::receive` does the cheap checks that come before the peer is
known, and says what the datagram is and whom it is for:

```rust
match device.receive(now, src, under_load, &mut datagram) {
    // Transport data, a handshake response or a cookie reply: the peer id
    // is decoded from the receiver index.
    Incoming::ForPeer(id, packet) => match peers.get_mut(&id) {
        Some(tunnel) => act_on(tunnel.handle(now, src, packet)?),
        None => {} // not one of ours
    },
    // A handshake initiation. Nothing expensive has happened yet.
    Incoming::Initiation(mut init) => {
        // (A per-source limit goes here: see "Handshake rate limiting".)
        // One X25519 reveals which peer claims to be calling…
        let Ok(public_key) = device.identify(&mut init) else { return };
        // …and that key finds the tunnel. Unknown key: nothing was sent,
        // nothing changed.
        let Some(tunnel) = by_public_key.get_mut(&public_key) else { return };
        act_on(tunnel.handle_initiation(now, &init, &mut out, &mut rng)?)
    }
    // Under load, a handshake message without a valid cookie.
    Incoming::CookieRequired(challenge) => {
        let tx = device.cookie_reply(now, &challenge, &mut out, &mut rng)?;
        socket.send_to(tx.datagram, tx.dst)?;
    }
    Incoming::Dropped(_why) => {}
    _ => {}
}
```

Everything in a datagram is its sender's choice: look peers up with `get`,
not by indexing, and treat "no such peer" as a drop.

The cost of a handshake initiation is the same however many peers are
configured, and it is spent in two visible steps. `receive` costs one
keyed hash — three under load, five in the ten seconds after the cookie
secret has changed — and never a Diffie-Hellman operation. `identify` —
**one** X25519 and one AEAD — reveals the initiator's public key; the
tunnel for that key does the rest (two more X25519 and a key generation,
but only for an initiation that has authenticated). `tests/cost.rs` pins
those numbers with a counting crypto provider.

`Device::receive` takes `&mut self` and is cheap; `Device::identify` takes
`&self`. What both return borrows only the datagram. With several receive
threads, hold the device's lock for `receive` and share it for `identify`,
then call into the tunnel under the tunnel's own lock: the expensive work
then runs in parallel.

### Session indices: routing without a table

Every message except an initiation is addressed by a 32-bit receiver index.
The reference implementations draw indices at random and keep a hash table
from index to peer. Here the index *is* the route:
`index = E_k(peer_id ∥ slot)`, where `E_k` is a keyed permutation of 32-bit
values whose key is drawn when the `Device` is created. The device inverts
it — six short SipHash computations, about 40 ns — and nothing has to be
allocated or kept in sync.

To an observer without the key, indices look random: they do not reveal the
peer, and one that has not been seen before cannot be told from a random
number, so they neither link two sessions of one peer nor let anyone guess
a live index. One difference from random indices remains: a tunnel has
4096 of them and takes a new one for every handshake message it sends, so
4096 messages later they come round again (in a different order each
round) — after about six days at one handshake every two minutes, under
six hours for a tunnel that keeps retransmitting to a peer that does not
answer, and as little as 82 seconds if the peer itself sends initiations as
fast as they are accepted. Whoever has recorded a tunnel's indices can then
recognise them, and knows the 4096 values among which the live ones are;
what that buys is what anyone on the path can do in any implementation —
address a forged datagram to a live session, which costs the receiver one
Poly1305 pass. A new `Device` starts over. See `src/index.rs`.

`PeerId` is your name for a peer: any number below 2²⁰. Two tunnels alive
at the same time on one device must not share one.

### Timers: `poll()` + `next_wake()`

`next_wake()` is the earliest instant `poll` has work; `None` means nothing
is armed — sleep until the next packet. An instant that is not in the
future means "poll now". Once `poll` has returned `Idle`, `next_wake()` is
`None` or strictly later than `now`, so a loop that sleeps until
`next_wake()` cannot spin. Callers that prefer a fixed tick can call `poll`
once a second instead; `next_wake()` lets battery- and tickless-sensitive
embedders sleep exactly.

### Packets while no session exists

`encapsulate` returns `NoSession` (or `NoEndpoint`) when there is no usable
session — **the payload is not consumed**, and a handshake has been
requested. The core does not queue packets (it cannot allocate). Keep a
small bounded queue, send it when a `Handled` reports
`session_established` — which happens in both roles: as initiator when the
response arrives, as responder when the peer's first transport message
confirms the session — and drop it on `PollOutput::HandshakeExpired`.

Give each held packet a deadline of its own as well (ninety seconds,
`Rekey-Attempt-Time`, is the protocol's figure). `HandshakeExpired` does
not cover every packet: the attempt it ends starts over with every
`encapsulate` that finds no session, so a trickle of packets keeps it —
and the packets queued before — alive for as long as it lasts; and a
tunnel that does not know where its peer is (`NoEndpoint`) makes no
attempt that could expire. Without a deadline, packets from an hour ago
go out when the peer turns up. `wireguard-embed` does all of this.

### Handshake rate limiting

Anyone who knows your *public* key can send initiations that pass `mac1`,
and each one you `identify` costs an X25519 (≈ 20 µs on this machine). The
library keeps no per-address state; the defence has two steps, and their
order matters:

1. **Decide `under_load`.** While it is `true`, handshake messages without
   a valid `mac2` are not processed; `Device::receive` returns
   `CookieRequired`, and checking the message and building the reply
   costs a handful of MACs and one 16-byte AEAD. A cookie proves that its
   holder receives datagrams at the address it sends from.

   The signal should say that *this machine* has more handshake work
   than it can do, because asserting it is not free: a handshake that
   meets a cookie reply starts over one `Rekey-Timeout` later — five
   seconds, in either role — and for as long as cookies are demanded,
   someone who can see the peer's handshake messages and inject
   datagrams (without being able to drop any) can keep handshakes from
   completing by racing forged cookie replies, since the key those are
   sealed with derives from a public key. So: the time spent on
   handshake messages that passed `mac1` (`wireguard-embed`: more than a
   tenth of a second in one second), or the depth of the queue they wait
   in (the kernel's choice: 512 of them). A count of messages per second
   works too if the threshold is far above what the peers themselves
   send; BoringTun's ten a second is what anyone who knows the public
   key can send.
2. **Limit per source address — but only sources a cookie has proven.**
   A real host at a routable address can complete the cookie dance and
   then flood with a valid `mac2`; without a limit one cookie buys
   unlimited X25519. `Initiation::source_verified()` (and
   `PeerPacket::source_verified()` for handshake responses) says that the
   cookie was checked; keep a token bucket per such address — the kernel
   allows 20 handshake messages per second with a burst of 5 — and
   consult it between `receive` and `identify`.

**Do not put a per-source limiter in front of `receive`,** or apply one to
a source that is not verified. An unproven source address costs nothing to
forge: such a limiter lets anyone who knows your public key use up the
allowance of an address of their choosing — and lock that peer out. (When
not under load there is nothing to key a limit on; the remedy for too many
handshakes is to assert `under_load`.) A verified source is not proof for
ever, either: `mac2` covers the message, not when it was sent, so a
*recorded* cookie-bearing message replayed from the peer's (forged)
address counts as verified for as long as the cookie's secret is honoured
— up to 130 seconds — and spends that address's allowance. Someone who
can record the peer's handshake messages and forge its address can
therefore have the peer's own handshakes refused while the device is
under load; that is the price of a per-source limit, here as in the
kernel (120 seconds there). `Device::receive_for` is one call
and so leaves no room for a limit; use the two-step path where it matters.
`wireguard-embed` implements both steps — and, having a single peer,
takes them for handshake messages only: everything else goes through
`receive_for`, which has nothing to route and skips the index decoding.

Transport data needs no rate limiting: a forged datagram costs at most one
Poly1305 pass over it, and nothing at all if its index is unknown or its
counter was already seen.

### How much stack

The core allocates nothing, so what a call needs it takes from the stack.
Measured — by `probes/`, which prints the depth of every call it makes
and how much of it is the probe's own — in the release build on x86-64,
with this repository's compiler flags and without, the larger of the two
rounded up (on aarch64 about a fifth more):

| call | stack |
|---|---|
| transport data, either direction | 2.6 KiB; 5.3 KiB with the AVX-512 keystream of `wireguard-chacha-simd`, which goes through a 2 KiB buffer |
| a handshake message, either role | 3.9 KiB |
| `Device::new_in`, `Device::tunnel_in` | 2.1 KiB, 2.3 KiB |
| `Device::new`, `Device::tunnel` (by value) | 3.4 KiB, 16.5 KiB — a `Tunnel` is 4.7 KiB, and a value that is returned is built in one frame and copied into the next |

A build that optimises little needs more — at `opt-level = 1` a packet
with the SIMD keystream already takes 16 KiB — and one that does not
optimise at all several times as much: 12 KiB for a handshake or a
packet at `opt-level = 0` (76 KiB for a packet with the SIMD keystream,
whose intrinsics are function calls there), 23 KiB for
`Device::tunnel_in`.
Part of every figure is cleaning up: the frames that held key material
in registers the compiler parked are overwritten afterwards, by a
function that uses as much stack as it overwrites (see *Secrets in
memory*).

### Crypto providers

`Device<P>` and `Tunnel<P>` are generic over a `CryptoProvider` (AEAD, DH,
hash, MAC); the wire format is the same for every provider. The default,
`InTree`, is this crate's own safe-Rust implementation. `InTree<C>` swaps
only the ChaCha20 keystream used for transport data — and, with it, where
the AEAD's one-time authenticator key comes from, which a wide keystream
produces along with the first blocks of the packet. `wireguard-chacha-simd`
(in `simd/`) provides AVX-512, AVX2 and NEON keystreams, validated against
the scalar one. On x86_64 its `Best` asks the CPU when the program runs
and uses the widest of AVX-512, AVX2 and the scalar keystream that it
has — so a crate that depends on it, or on `wireguard-embed`, builds
without special flags and runs on any x86_64.

A provider must be constant-time in the secrets it handles. The default
one is, where the processor's multiplier is: see `src/crypto/mod.rs` for
the targets where that holds and the two kinds where it does not (no
multiply instruction; a multiplier that finishes early on small
operands).

One cargo feature, on by default: `x25519-table`. Making a key pair —
which every handshake message does once — then uses a ladder built for
the base point, about 40 % cheaper than the general one, for 10 KiB of
constants; equally constant-time. Where 10 KiB of flash matter more,
build with `default-features = false`.

## Protocol notes

Where the whitepaper leaves a choice, this is what the implementation does.

* **Timers** are the five of the Linux implementation (`timers.c`), armed
  and cancelled by the same events, and are checked after every operation
  in the simulation and fuzz tests against a model that is written from
  `timers.c` with its own copy of the whitepaper's constants
  (`tests/common/timer_model.rs`). They are not identical to Linux in
  every respect. The differences, all deliberate:
  1. the dead-peer ("new handshake") timer is 15 s plus up to 333 ms of
     jitter, as in Linux — but the jitter is drawn once per handshake and
     used for every arming until the next, where Linux draws it each time
     (the timer is armed in `encapsulate`, where no entropy source is at
     hand). Two ends that lose each other at the same instant are kept
     apart just the same;
  2. a handshake attempt is abandoned after `Rekey-Attempt-Time` (90 s,
     which with the jitter is 17 or 18 initiations), as the whitepaper
     words it; Linux counts retries and stops after 20 initiations, some
     100 s;
  3. keys are wiped `3 × Reject-After-Time` after the newest *confirmed*
     session was created. Linux restarts that timer whenever a session is
     derived, including each time it answers an initiation — so a peer
     that keeps sending initiations it never completes postpones the wipe
     for as long as it likes;
  4. the key wipe leaves a handshake that is under way alone: an initiation
     of ours in flight still completes when its response arrives, and a
     session we have just answered still works when the peer starts using
     it (it expires by itself, `Reject-After-Time` after we answered, if
     the peer never does). Linux wipes the handshake as well, and the peer
     — or we — start over seconds later;
  5. a handshake that is wanted less than `Rekey-Timeout` after the last
     handshake message of ours — an initiation or, as in Linux, a
     response — is sent when that time has passed; Linux drops the request
     and relies on a later event to ask again. A response that the peer
     never follows up (no packet on the session it set up) holds our own
     initiation back like any other, but a run of such responses does so
     for fifteen seconds at the most (three times `Rekey-Timeout`): the
     responses a replayed recording gets, or a peer whose every handshake
     dies on the way back, cannot postpone ours for as long as they keep
     coming. Linux has no such bound;
  6. two things that cannot be seen on the wire: giving up a handshake
     attempt does not start the key-wipe timer (Linux starts it there if
     it is not running; here it runs exactly when there is a session to
     wipe), and the key wipe cancels the keepalive and dead-peer timers of
     the sessions it has wiped;
  7. giving up a handshake attempt restarts a persistent keepalive that
     has already fired. Because the attempt is measured in time (2), it
     can be abandoned without another initiation having gone out — when
     nothing ran for longer than `Rekey-Attempt-Time`, as on a machine
     that was suspended. The persistent keepalive timer is restarted by
     every message sent; had it fired during the attempt, it would be left
     idle, and a tunnel that is meant to keep itself up would have no
     timer at all. (Linux gives up by count, and so only after a
     retransmission that has just restarted the timer.)
  8. a handshake response is accepted until the retransmission of its
     initiation is due, and not after the attempt was given up. Linux
     accepts it for as long as the handshake state is the one it sent —
     also when the retransmission was held back, or its timer has not run
     yet;
  9. answering an initiation leaves the previous session where it is
     (Linux drops it there), and completing a handshake of our own leaves
     alone a session we have answered that the peer has not used yet
     (Linux makes it the previous one). Packets still on their way under
     the older keys are accepted until those expire;
  10. when the peer's first packet on a session we answered makes that
      session the current one, an initiation of ours that is in flight is
      dropped — its response would give a second session for the same
      moment. Linux keeps the handshake, and a response that was on its
      way still completes there.

  What difference 5 and the crossed-handshake rule below cost, measured
  against a model of Linux over 20,000 random schedules: about 18 % more
  initiations than Linux sends in the same seat — never two within
  `Rekey-Timeout` — most of them on paths that are dead in one direction,
  where this implementation goes on asking every five seconds for as long
  as its application sends and Linux, having answered the peer, goes
  quiet.

  One thing Linux does that is *not* a difference although it reads like
  one: its "need another keepalive" flag re-arms the keepalive timer, and
  the keepalive it has just sent cancels it again. Data at 0 s and 5 s
  followed by silence gets one keepalive from a Linux peer, at 10 s — as
  from this implementation.
* **Crossed handshakes.** When both sides initiate before either hears the
  other, this implementation answers the peer's initiation and keeps its
  own in flight. The Linux implementation runs one handshake per peer: it
  answers ours and drops its own, so against it our handshake completes
  within one round trip. (Dropping ours as well would leave neither side
  with a session until a retransmission five seconds later, and while both
  sides have traffic queued those cross again. Against the kernel over a
  200 ms link with traffic both ways: a session after 0.4 s this way, none
  after 30 s that way.) With this implementation on both ends both
  handshakes complete, and both sides then settle on the same one of the
  two sessions — the one with the smaller pair of indices — so exactly one
  side is its initiator and rekeys it. (Nearly always. When the network
  reorders the four messages, holds one of them back for seconds, or the
  path takes about as long as a retransmission, each end can come to
  send on the session it initiated itself. Nothing is lost — each
  receives on both — but two key pairs are in use, and each end rekeys
  its own, until the first rekey two minutes later settles it. This
  happens between two ends of this implementation only: in 20,000
  schedules against a model of Linux, and in the runs against the
  kernel, never.) A handshake started only after
  answering the peer's is not a crossing: it yields the newer session, the
  peer switches to it, and so it is kept. And where the two sides disagree
  about whether their handshakes crossed at all — the network held one
  initiation back until the other handshake was complete — what the peer
  actually sends on decides: a side that stepped down from its own, newer
  session and then receives on it goes back to it. All of this is decided
  by the order of events, never by timestamps.
* **The endpoint** moves to the source of a message that only the live
  peer can have sent from there: a response to our initiation, and
  transport data (for a session we answered, the first packet on it). A
  handshake initiation is answered where it came from. Whether it also
  moves the endpoint — as every accepted initiation does in the Linux
  implementation — depends on what the tunnel knows:
  * *The peer has used a session that an initiation of its own created*
    — which no recording can do. From then on the timestamps this tunnel
    holds are tied to real time, a recording cannot pass for a new
    initiation, and an accepted initiation moves the endpoint, as in
    Linux: a peer that roams and then initiates is followed at once,
    whether or not its next packet arrives. (What is left is what Linux
    has too: an initiation that was made later but never reached us can
    be delivered by someone else, from somewhere else.)
  * *It has not* — a tunnel created a moment ago (after a restart, say),
    or one whose peer has only ever answered. An initiation proves who
    made it, not when, and this tunnel has nothing to tell a recording
    by: moving the endpoint would let anyone holding one recorded
    initiation redirect the tunnel until the peer next speaks, which for
    a peer that waits to be called is never. The endpoint stays, and the
    initiation's source is remembered as a *candidate*: our own
    initiations go to the candidate and to the endpoint in turn, the
    candidate first, until one of them is answered — an answer is proof,
    and moves the endpoint as always. A peer that has really moved is
    found with the first of them; a replayed recording costs one
    `Rekey-Timeout`.
  * *The tunnel has no endpoint.* It takes the initiation's source as a
    first guess.
* **Cookies** are minted under a secret that is replaced every two
  minutes and honoured for ten seconds more — time for a peer that was
  handed a cookie just before the change to use it once. A cookie is
  therefore good for between ten seconds and 130 after it was minted
  (Linux: up to 120; this implementation used to honour the previous
  secret for a full second lifetime, which also gave a recorded
  cookie-bearing message four minutes). A cookie reply is accepted once
  per handshake message sent (as in Linux), and its nonce is
  pseudo-random rather than a counter.
* **What `mac1` protects, and what it does not.** The sender index in a
  handshake message is not part of the Noise transcript; `mac1` is the only
  thing that covers it, and `mac1` is keyed by a public key. Someone in the
  path who knows that key can therefore change the index and fix up
  `mac1`; the message is still accepted, the handshake it belongs to then
  fails to complete, and the dead-peer timer starts another. This is the
  protocol (every implementation accepts such a message), and no more than
  an attacker in the path can do by dropping the datagram; the fuzz
  targets' outcome predictor has to know it.
* **Session indices** are a keyed permutation of `(peer id, slot)`; see
  above.

## The other crates

| | |
|---|---|
| `embed/` — `wireguard-embed` | `std` driver with BoringTun-style ergonomics: `Tunn` (a clock that counts time spent suspended, OS entropy, load signal and per-source handshake limit, packet queue, buffer pool, tunnel MTU) and, behind the `async` feature, a tokio event loop (`AsyncTunn`) that no datagram, ICMP error, slow reader or slow link can stop — or stop listening. Uses the SIMD keystream. Its dependencies: `getrandom`; on Linux and Android `rustix` (the boot-time clock, and the socket's error queue); `tokio` with `async`. |
| `simd/` — `wireguard-chacha-simd` | AVX-512 / AVX2 / NEON ChaCha20 keystreams; the only `unsafe` in the library crates. A kernel's stack frame — where a compiler parks the registers it has no room for, key words among them — is overwritten after the last stride. |
| `bench/` | Criterion comparison against BoringTun and a UDP throughput harness (its own workspace; see `bench/README.md`). |
| `fuzz/` | Six libFuzzer targets, with a small checked-in seed corpus each. The handshake targets predict the outcome of every input independently and compare; the session target checks, among other things, that no datagram is ever accepted twice. |
| `probes/` | Checks that have to look at memory or at linked machine code, which the core — `unsafe` forbidden for all its targets — cannot host: the stack and memory residue probes for the core and the driver, the program whose basic blocks are counted, and the freestanding image behind the panic and `no_std` checks. |

## Testing

```sh
cargo test                                               # core: unit, integration and doc tests
cargo test -p wireguard-embed --features async           # std driver and tokio loop
cargo test -p wireguard-chacha-simd                      # SIMD keystreams against the scalar one
scripts/check_no_panic.sh                                # no panic machinery in the optimised image
scripts/check_no_std.sh                                  # links without std and without an allocator
scripts/check_secret_residue.sh                          # secrets left on the stack / in a tunnel
scripts/check_wipes_matter.py                            # …and that it would notice: each wipe removed in turn (an hour)
scripts/check_constant_flow.sh                           # the same path through the code for every secret (qemu-user)
cargo test --release --test constant_time -- --ignored   # timing tripwires, on a quiet machine
scripts/driver_netns_tests.sh                            # forged ICMP against the event loop; no root needed
scripts/fuzz_all.sh 120                                  # 6 × 120 s guided fuzz (nightly, cargo-fuzz)
scripts/interop_netns.sh                                 # against the Linux kernel; no root needed
scripts/interop_wg_tool.sh 64                            # against wireguard-tools
scripts/coverage.sh                                      # coverage table; fails below 94 % of the library's lines
cargo run --release --example perf                       # benchmarks: the core
(cd bench && cargo bench)                                # benchmarks: the driver, against BoringTun
```

No test in the default suite depends on how long something takes. What
an unauthenticated sender can make the receiver compute is asserted as an
exact count of cryptographic operations (`tests/cost.rs`). That secrets
do not steer the code is checked by counting, too:
`scripts/check_constant_flow.sh` runs each secret-handling operation —
the curve arithmetic, the symmetric primitives and the AEAD with both
keystreams, the comparisons at the lengths the protocol uses, the checks
of `mac1` and `mac2`, a whole handshake — under an emulator that reports
every basic block executed, for eight secrets each, and the counts must
be equal; two operations that branch on their secret must be reported.
What that cannot see (an instruction that takes longer for some
operands) is what the timing tests in `tests/constant_time.rs` are
tripwires for; they are not run by default, each first measures
something that leaks on purpose, and says so if it cannot see that.

Behaviour is pinned by the tests to the extent mutation testing shows:
defects planted one at a time — in the protocol code, the driver and its
event loop — are caught, and the ones that were not when this was first
done each have a test now (`tests/pinned_behaviour.rs`). The wire format
has known answers of its own (`tests/known_answers.rs`, from an
independent model: `scripts/handshake_model.py`), so that a change both
ends make alike does not pass for compatibility.

`scripts/interop_netns.sh` runs eight scenarios against the kernel's
WireGuard inside a private user and network namespace: handshakes in both
roles with and without a pre-shared key, the cookie dance, crossed
handshakes (both sides initiate at once), and 35-second one-way streams in
both directions, where the passive-keepalive timer of the receiving
implementation has to satisfy the dead-peer timer of the sending one: a
keepalive every ten seconds, and no new handshake. (Rekeying — two minutes
into a session — is not in these runs.) A scenario that fails is reported
and the others still run. The same script is what CI runs.

## Performance

Measured by `examples/perf.rs` on this machine (x86_64, one core, the
default provider: safe, scalar code — no SIMD, no `unsafe`; medians of
three runs):

```
blake2s-256 (1 KiB)                          1020 MB/s
chacha20 keystream (1 KiB)                   1295 MB/s
poly1305 (1 KiB)                             5989 MB/s
chacha20poly1305 seal (1 KiB)                 996 MB/s
chacha20poly1305 seal (64 B)                  512 MB/s
x25519 scalar mult                          50525 op/s   (19.8 µs)
full 1-RTT handshake, with setup             4055 /s     (247 µs)
device.receive: route a transport datagram     38 ns
encapsulate + receive (64 B)                  234 MB/s   (0.27 µs a packet)
encapsulate only (1420 B)                     978 MB/s   (≈ 7.8 Gbit/s)
encapsulate_in_place only (1420 B)            985 MB/s
receive only (1420 B)                         938 MB/s
```

What two of the lines measure. The handshake line is the whole of it,
setup included: two public keys are derived, two devices and two tunnels
made, then both sides run the handshake and the first packet confirms it.
The handshake proper is about two thirds of the figure — 430,000 cycles
a side — and the setup the rest. The `poly1305` line is the one-shot
function by itself; what a packet pays for authentication is in the two
`seal` lines. Times here move by a tenth with the machine's clock; cycle
counts, where this document gives them, repeat to within one percent.

These are the core's numbers. The driver (`wireguard-embed`: the same
protocol code with an AVX-512, AVX2 or NEON keystream, plus what a driver
adds per packet) is measured separately, next to BoringTun, in `bench/` —
a change to the driver's receive path does not show here. There, on this
machine, a 1420-byte packet takes 0.46 µs to encapsulate (a sixth less
than BoringTun) and a 64-byte one 0.16 µs (the same).

For profiling: `cargo build --profile profiling --example perf`, then
`perf record --call-graph dwarf -- target/profiling/examples/perf`.

## Secrets in memory

Forward secrecy is only as good as the erasure of old keys, so where key
material is at any moment is part of the design:

* **Written once, wiped in place.** Session keys and handshake state are
  derived straight into storage inside the `Tunnel` and never moved as
  values (a Rust move is a byte copy that leaves the original behind).
  Rotating sessions changes which storage cell has which role, not where a
  key is. A session's keys are wiped when it is rotated out, when it
  expires unused, at the §6.3 key wipe, on `reset()`, and when the tunnel
  is dropped — which also wipes the static key, the pre-shared key and the
  static-static secret. A device and a tunnel can be built where they are
  going to live (`Device::new_in`, `Device::tunnel_in`); the constructors
  that return them by value leave nothing in their own frames, and the
  copy in the frame that receives them is the receiver's.
* **Working values are wiped before a call returns.** Diffie-Hellman
  results, chaining keys, the handshake's AEAD keys, cipher and hash state
  that held key material: each lives in one local that is zeroed on every
  way out. Functions that produce secrets write them through `&mut`
  parameters — the `CryptoProvider` trait included — so no copy is left in
  a return slot.
* **What the compiler parks on the stack is overwritten too.** Where the
  arithmetic has a secret in registers and there are not enough of them —
  the field elements of the Montgomery ladder, the sixteen-word states of
  the cipher and of the hash on a machine with fifteen registers, the
  vector registers of the SIMD keystreams (the same key word in every
  lane), the tag that would have authenticated a forgery — the compiler
  keeps some in the stack frame, in slots no statement can name. Those
  functions are compiled as functions of their own, and their frames are
  overwritten once they have returned.
* **Measured, not assumed.** `scripts/check_secret_residue.sh` runs three
  probes (`probes/`), each in an unoptimised build, the dev profile and
  the release profile — the last both with this repository's compiler
  flags and with none, which is how a crate that depends on the library
  is built — and the first of them once more for aarch64, under
  emulation, where that is installed. One paints the stack, makes
  each kind of public call — every primitive by itself, the constructors,
  a tunnel's whole life with the default keystream and with the SIMD one
  — and searches the dead stack for every secret the call handled, which
  it computes independently: as the bytes it is — whole, or any eight of
  them in a row, which is what is left of a copy once something else has
  written over the rest — and in the forms the arithmetic had it in (a
  single limb of a field element or half of an authenticator key counts
  as found; so do two words of a cipher key or state, and any one word
  that a hash's working vector held inside its rounds). The second reads
  a tunnel's own bytes at each stage of its life: it holds exactly the
  secrets that stage needs, and nothing once dropped. The third does what
  the first does for `wireguard-embed`'s constructors. All of them first
  prove they can see what they look for, and that the stack scrub leaves
  no byte of its range as it was.
* **Each wipe is there for something that can be seen.**
  `scripts/check_wipes_matter.py` removes the wipes one at a time and runs
  the probes: of 154 statements that zero key material or overwrite a
  frame, the removal of any one of 100 makes the check fail. The other
  54 are listed in the script, each with its reason: 30 are second lines
  of defence (a buffer zeroed inside a frame that is overwritten as a
  whole anyway, a slot wiped again before it is filled), 12 are on paths
  nothing here can take (the cipher failing to seal sixteen bytes), 9
  wipe what is not a secret (a public key, a transcript hash, a buffer
  of ciphertext) and 3 are the arithmetic of 32-bit targets.
* **What it costs.** A handshake takes about 3 % longer than it does in a
  build where every wipe and every overwriting of a frame is taken out.
  On a packet the difference is within what two builds differ by anyway
  — in the core, and in the driver at 64 B, the build that wipes is as
  often the faster of the two — except in the driver at 1420 B, where it
  is about 2 % (the frame of the SIMD kernel, overwritten once a packet).

The limits. This is best effort, on the targets and with the compiler it
was measured with (x86-64; aarch64 under emulation). What is in a
register when a call returns stays there until other code overwrites it.
An unoptimised build is held to less: there every expression of the
arithmetic has a stack slot of its own, deeper than the library
overwrites, so the word forms — and pieces of a byte string, which there
are words loaded from it — are reported and not counted, and the SIMD
keystreams are not looked at by themselves. The functions that *return* a
result that may be a secret (`blake2s::hash`, `kdf::kdf3`, …) are
conveniences for public values and for tests — short of full
optimisation the result is in their dead frame as well as in the
caller's — and each has a form that writes in place. Two keys are not
treated as secrets of this kind: the one behind the session indices and
the one behind cookie-reply nonces are wiped when their owner is dropped,
but the SipHash state they pass through is not scrubbed after each use —
nothing but the look of indices and nonces depends on them. What the
library hands to you is yours to protect: decrypted packets, an
`Initiation` after `identify` (wiped when dropped; pass it on by
reference and let it go out of scope), and the `Device` and `Tunnel`
themselves — move them before the first handshake, not after, and see
`EMBEDDER_OBLIGATIONS.md` §10 for swap, core dumps and the rest.

## Security model & limitations

* **Entropy is the caller's responsibility** (`EntropySource`): feed it
  OS randomness; everything rests on it.
* **Cryptokey routing** (allowed IPs on inner packets) and the per-source
  handshake limit are embedder concerns: both need tables the core cannot
  allocate. For the limit the core provides the place and the signal
  (*Handshake rate limiting* above), and `wireguard-embed` an
  implementation. For cryptokey routing it provides `ip_packet_addresses`
  (the source and destination of an inner packet) and nothing more —
  `wireguard-embed` does not filter either: what it hands to your TUN
  device is authenticated as coming from the peer, with whatever source
  address the peer wrote into it.
* `EMBEDDER_OBLIGATIONS.md` lists everything else the library's guarantees
  depend on.

WireGuard is a registered trademark of Jason A. Donenfeld. This crate is an
independent implementation of the published protocol and is not affiliated
with or endorsed by the WireGuard project.

## License

MIT OR Apache-2.0.
