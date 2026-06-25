# Embedder Obligations — `wireguard-sans-io`

**Status:** Normative · **Audience:** System integrators deploying this
library in safety- or security-critical contexts

This library is **sans-I/O**: it implements the WireGuard protocol state
machine and nothing else. Every interaction with the outside world —
sockets, clocks, randomness, scheduling, routing, MTU, rate limiting —
is the embedder's responsibility. The library's security guarantees hold
**only if every obligation below is met**. Each item states what breaks
if it is not.

Obligations are tagged by the consequence of violation:
**[CONF]** confidentiality loss · **[INTEG]** integrity/forgery ·
**[AVAIL]** denial of service · **[INTEROP]** wire incompatibility.

---

## 1. Entropy (`EntropySource`)

### 1.1 [CONF] MUST be cryptographically secure

Ephemeral X25519 secrets, session indices, cookie secrets, and the
cookie-reply nonce seed are drawn directly from `EntropySource::fill()`.
A predictable source **destroys forward secrecy entirely** — an attacker
who can predict the ephemeral recovers every session key.

| Platform | Use |
|---|---|
| Linux/macOS/BSD | `getrandom(2)` |
| Windows | `BCryptGenRandom` / `RtlGenRandom` |
| Embedded | Hardware TRNG, **health-checked** (NIST SP 800-90B), seeded before first `Tunnel` call |

```rust
struct OsRng;
impl EntropySource for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(buf).map_err(|_| EntropyError)
    }
}
```

**MUST NOT** use: `DeterministicRng` (test-only), any LCG/xorshift,
`SystemTime`-derived values, or the example `OsRng` in
`examples/interop_*.rs` (which is explicitly marked test-only).

### 1.2 [INTEG] MUST NOT share entropy state across `Tunnel`s on the same interface

Multiple `Tunnel` instances configured with the **same local static key**
share the same `cookie_send` AEAD key
(`Hash(LABEL_COOKIE ‖ local_public)`). If they are also fed from
`EntropySource` instances with identical state, their cookie-reply nonce
counters seed identically and collide → Poly1305 one-time-key reuse →
**cookie-reply forgery** by anyone observing two replies.
(Demonstrated in `tests/attack_resistance.rs`.)

Either pass **one shared `&mut dyn EntropySource`** to every tunnel on
the interface, or guarantee each instance has independent state (e.g.
each opens its own `/dev/urandom` handle).

### 1.3 [AVAIL] MUST return `Err(EntropyError)` rather than weak bytes

The library treats `EntropyError` as a hard, recoverable failure of the
operation at hand. Returning `Ok` with low-entropy bytes is silent and
catastrophic.

---

## 2. Time (`Now`)

### 2.1 [AVAIL] `ticks` MUST be monotonic non-decreasing

All §6 timers (rekey, retransmit, keepalive, expiry, discard) are driven
by `Now::ticks`. The library clamps regressions defensively, but a clock
that jumps backward degrades to "time stands still": no rekeys, no
expiry, no retransmits. Derive `ticks` from `CLOCK_MONOTONIC` /
`Instant`, never from wall time.

### 2.2 [AVAIL] `unix_secs` MUST be approximately real and non-decreasing

`unix_secs`/`unix_nanos` are used **only** to build the outbound TAI64N
handshake timestamp. The library ratchets outbound timestamps past the
last one sent (so a *frozen* wall clock is harmless), but a wall clock
that **steps far into the future and then back** poisons the *peer's*
`greatest_timestamp`: every subsequent initiation we send is rejected by
a kernel/wireguard-go peer as `ReplayedTimestamp` until real time
catches up. This is unrecoverable short of the *peer* dropping its
`Tunnel`.

On platforms subject to NTP step-correction, GPS-week rollover, or
operator clock changes, clamp `unix_secs` to be non-decreasing in the
embedder before passing it in.

### 2.3 [AVAIL] MUST NOT saturate `ticks`

`Ticks` is `u64` nanoseconds (584-year range). If the embedder's
monotonic source has a different epoch and reaches `u64::MAX`, all timer
arithmetic saturates and the tunnel stops rekeying. Use a process-start
relative epoch.

---

## 3. Load signalling and rate limiting

### 3.1 [AVAIL] MUST assert `under_load = true` when handshake volume is high

When `under_load == false`, anyone who knows this endpoint's **public**
key can force ≥ 1 X25519 (~24 µs) per forged 148-byte initiation —
~40 k packets/s saturates one core. Setting `under_load = true` reduces
this to one BLAKE2s + one XChaCha (~1 µs) by engaging the cookie dance.

A correct trigger: socket receive-queue depth > N, or
handshake-packet rate > M/s. The kernel uses receive-queue length; a
fixed threshold of ~50 in-flight handshake packets is reasonable.

### 3.2 [AVAIL] MUST implement per-source-IP rate limiting

The cookie mechanism only proves IP ownership; it does **not** limit how
many handshakes a single owned IP can complete. A botnet (or one host
not spoofing) with valid mac2 still forces full Noise processing
(~5× X25519 ≈ 120 µs/packet). The kernel pairs cookies with a
token-bucket rate limiter (`ratelimiter.c`, 20 pkt/s + 5 burst per IP).
This library cannot do that (it would require per-IP allocation); the
embedder must.

### 3.3 [AVAIL] SHOULD bound the maximum datagram size accepted from the network

A forged transport datagram with a known receiver index costs one
Poly1305 over its full ciphertext before rejection. Clamp receives to
the path MTU (or at most a few KB) rather than accepting 64 KiB UDP
datagrams.

---

## 4. MTU and fragmentation

> WireGuard the protocol has **no** MTU negotiation, discovery, or
> backoff mechanism. There is no message type, header field, or
> signalling for it. Each side independently configures its tunnel MTU;
> if either side gets it wrong, full-size packets are silently dropped.

### 4.1 [AVAIL] [INTEROP] MUST set `Config::mtu` to the tunnel-interface MTU

`encapsulate()` zero-pads plaintext to the next multiple of 16, clamped
to `Config::mtu` (whitepaper §5.4.6; matches kernel
`calculate_skb_padding` and wireguard-go `calculatePaddingSize`).
With `mtu = None` the clamp is disabled, which is correct
**only** if the tunnel-interface MTU is itself a multiple of 16;
otherwise inner packets in `(mtu − mtu%16, mtu]` are padded past MTU →
outer datagram exceeds path MTU → dropped (DF) or fragmented.

```rust
let mut cfg = Config::new(local, peer);
cfg.mtu = NonZeroU16::new(1420);            // = TUN-device MTU
// after PMTU change:
tunnel.set_mtu(NonZeroU16::new(new_mtu));
```

| Outer path MTU | Overhead (v4 / v6) | Recommended tunnel MTU |
|---:|---:|---:|
| 1500 (Ethernet) | 60 / 80 | 1440 / **1420** |
| 1492 (PPPoE) | 60 / 80 | 1432 / 1412 |
| 1480 (RFC 4459) | 60 / 80 | 1420 / 1400 |
| 1280 (IPv6 min) | 60 / 80 | 1220 / 1200 |

Set the same value on the TUN/TAP device and in `Config::mtu`. The
kernel's default of 1420 is fine **once `Config::mtu` is set**.

### 4.2 [AVAIL] MUST handle outer-path ICMP Fragmentation-Needed

When the outer path MTU shrinks (route change, VPN-in-VPN), the network
returns ICMP type 3/code 4 (v4) or PTB (v6) to the *outer* socket. The
library never sees these. The embedder must:
1. Receive outer ICMP on the UDP socket (`IP_RECVERR` on Linux).
2. Reduce the tunnel-interface MTU accordingly.
3. Synthesize an *inner* ICMP Fragmentation-Needed back to the original
   inner sender so its PMTUD works.

Without this, a path-MTU reduction is a permanent black-hole for
full-size traffic.

### 4.3 [AVAIL] MUST NOT rely on outer fragmentation

Set DF on outer packets (the kernel does). Relying on IP fragmentation
for tunnel traffic is fragile (NAT/firewall reassembly limits, fragment
drops kill the whole datagram) and an amplification-attack surface.

### 4.4 [AVAIL] On receive, MUST size `out` for the *received* datagram

`decapsulate()` returns `Error::BufferTooSmall` (recoverable, replay
window not advanced) if `out.len() < datagram.len() − 32`. Allocate
`out` ≥ the receive buffer size, not the tunnel MTU — a peer with a
larger MTU can legitimately send larger packets.

---

## 5. Remote-address encoding (`remote: &[u8]`)

### 5.1 [AVAIL] MUST be a stable, complete encoding of source IP + port

The cookie value is `MAC(R_m, remote)`. If `remote` is empty, constant,
or omits the port, the cookie no longer proves IP ownership and the
under-load defence is void: one attacker on one address obtains a cookie
that validates from *every* spoofed address.

```rust
// Correct:
let remote = match src_addr {
    SocketAddr::V4(a) => {
        let mut r = [0u8; 6];
        r[..4].copy_from_slice(&a.ip().octets());
        r[4..].copy_from_slice(&a.port().to_be_bytes());
        r.to_vec()
    }
    SocketAddr::V6(a) => {
        let mut r = [0u8; 18];
        r[..16].copy_from_slice(&a.ip().octets());
        r[16..].copy_from_slice(&a.port().to_be_bytes());
        r.to_vec()
    }
};
```

### 5.2 [AVAIL] MUST be the same encoding for `decapsulate()` and the cookie path

A v4-mapped-v6 address encoded one way on receipt and another on
verification breaks mac2 for dual-stack peers. Pick one canonical form.

---

## 6. Buffer sizing

| Call | Minimum `out` length |
|---|---|
| `encapsulate()` | `max(148, transport_datagram_len(payload.len()))` |
| `decapsulate()` | `max(92, datagram.len().saturating_sub(32))` |
| `poll()` | `148` |
| `initiate_handshake()` | `148` |

Undersized buffers return `Error::BufferTooSmall`; no state is mutated
and the call may be retried. **Do not** treat `BufferTooSmall` as an
attacker signal — it is a local sizing bug.

---

## 7. Information exposure

### 7.1 [CONF] MUST NOT expose attacker-triggerable `Error` variants to untrusted observers

The specific variant returned by `decapsulate()` is an oracle:
`InvalidMac1` vs `AuthFailure` confirms whether the sender knows this
endpoint's static public key; `UnknownReceiverIndex` vs `AuthFailure`
leaks live session indices; `Replay` vs `AuthFailure` leaks counter
state. Log/export at most "datagram rejected" for all
attacker-triggerable variants. The full variant is fine in a
local-only debug log.

### 7.2 [CONF] MUST NOT expose unaggregated `Stats` failure counters publicly

`mac1_failures`, `auth_failures`, `replays_dropped`, `cookies_sent` are
attacker-influenceable and act as exact oracles if readable
unauthenticated (see the docstring on `Stats`). Aggregate across peers
and time-bucket before exporting to any metrics endpoint that is not
itself behind the tunnel.

### 7.3 [CONF] MUST NOT log key material or `Tunnel` internals via `{:?}` to persistent storage

The library's `Debug` impls redact secrets, but the embedder's own
wrappers might not. Check every `derive(Debug)` on a struct that holds a
`StaticSecret`, `PresharedKey`, `[u8; 32]` key, or `Tunnel`.

---

## 8. Scheduling

### 8.1 [AVAIL] MUST drive `poll()` at or after every `next_wake()` deadline

`poll()` is the only place retransmissions, rekeys, keepalives, and
session expiry happen. A caller that only calls `encapsulate`/
`decapsulate` will never retransmit a lost handshake and never rekey.

```rust
loop {
    let timeout = tunnel.next_wake()
        .map(|w| w.nanos().saturating_sub(now().ticks.nanos()))
        .map(Duration::from_nanos);
    match socket.recv_timeout(timeout) {
        Ok(dgram) => { /* decapsulate */ }
        Err(Timeout) => {}
    }
    while let PollOutput::Send(wire, _) = tunnel.poll(now(), &mut buf, &mut rng)? {
        socket.send(wire)?;
    }
}
```

### 8.2 [AVAIL] MUST loop `poll()` until `Idle`

`poll()` performs **at most one** action per call. A single call after a
long sleep may leave further actions pending.

### 8.3 [AVAIL] MUST NOT busy-spin when `next_wake()` is in the past

`next_wake()` may legitimately return an instant ≤ now (e.g. immediately
after `decapsulate()` arms a deadline). The correct response is to
`poll()` immediately, **not** to sleep for a negative duration.
After `poll()` returns `Idle`, `next_wake()` is guaranteed to be `None`
or strictly in the future (regression-locked by
`tests/busy_loop_regression.rs`).

---

## 9. Multi-peer routing

### 9.1 [INTEG] MUST route by `peek()` receiver-index, not by source address

A `Tunnel` is one peer. With multiple peers on one socket, use
`message::peek()` to extract the receiver index and dispatch to the
owning `Tunnel`. **Never** route by UDP source address — WireGuard peers
roam, and source-address routing lets an attacker steer your replies.

### 9.2 [AVAIL] Handshake initiations have no receiver index

`PacketKind::HandshakeInitiation` must be offered to every configured
`Tunnel` (or to the one whose `mac1` validates — but that requires a
shared mac1-key table the embedder builds itself). The cheap path is to
try each tunnel; `InvalidMac1` is ~1 µs.

---

## 10. Lifecycle

### 10.1 [CONF] MUST drop `Tunnel`/keys for secret wiping to run

Secret zeroization happens in `Drop`. A `Tunnel` leaked
(`mem::forget`, `Box::leak`, stored in a `static`) is never wiped.
On process termination without unwind (SIGKILL, `_exit`, power loss),
nothing is wiped — assume RAM is recoverable and treat physical access
accordingly.

### 10.2 [AVAIL] `reset()` does NOT clear `greatest_timestamp`

This is deliberate (replay protection across reset). To recover from a
poisoned timestamp (peer sent a far-future TAI64N and is now stuck),
**drop the `Tunnel` and `Tunnel::new()` a fresh one** — `reset()` is not
sufficient.

### 10.3 [CONF] MUST treat `StaticSecret` as move-once

`StaticSecret` is `Clone` for ergonomic configuration; every clone is an
independent copy that must be dropped for wiping. Prefer constructing
once and moving into `Config`. Never store the raw `[u8; 32]`
representation alongside.

---

## 11. What this library does NOT do

The embedder is solely responsible for all of the following; the library
provides no mechanism for any of them:

- UDP socket I/O, including outer DF, ECN, DSCP, `IP_RECVERR`.
- Tunnel-interface (TUN/TAP) creation, MTU configuration, route install.
- Cryptokey routing (allowed-IPs filtering on inner src/dst — **MUST**
  be enforced by the embedder, otherwise a peer can spoof any inner
  source address).
- Path-MTU discovery, ICMP relay, fragmentation.
- Per-source rate limiting.
- Multi-peer index→tunnel demultiplexing tables.
- Persistent storage of keys/state across restarts.
- Endpoint roaming (updating where to `send()` after the peer's source
  address changes — track the source of the last *authenticated* packet).
- Constant-time guarantees against an attacker with cycle-accurate
  timing of the embedder's network stack.

---

## 12. Compliance checklist

For a flight-critical deployment, every line below should trace to a
test in the integrating system's test suite.

- [ ] `EntropySource` is OS/hardware CSPRNG, health-checked, never a PRNG
- [ ] One entropy state per interface (not per tunnel) **or** all tunnels share one `&mut`
- [ ] `Now::ticks` from `CLOCK_MONOTONIC`, process-relative epoch
- [ ] `Now::unix_secs` clamped non-decreasing in the embedder
- [ ] `under_load` asserted when handshake-packet rate exceeds threshold
- [ ] Per-source-IP token-bucket rate limiter in front of `decapsulate()`
- [ ] `Config::mtu` set equal to the TUN-device MTU; `set_mtu()` on PMTU change
- [ ] Outer ICMP Frag-Needed received and relayed inward
- [ ] DF set on outer UDP
- [ ] Receive buffer clamped to a few KB
- [ ] `remote` = canonical IP‖port bytes, same encoding everywhere
- [ ] `decapsulate()` `out` buffer ≥ receive-buffer size
- [ ] `poll()` looped to `Idle` after every wake-up and every I/O event
- [ ] Attacker-triggerable `Error` variants collapsed before logging/export
- [ ] `Stats` failure counters aggregated/authenticated before export
- [ ] No `derive(Debug)` on embedder structs holding secrets
- [ ] Multi-peer routing by `peek()` index, never by source address
- [ ] Allowed-IPs (cryptokey routing) enforced on every decrypted inner packet
- [ ] Peer endpoint updated only from *authenticated* packets
- [ ] `Tunnel` dropped (not leaked) on shutdown / reconfiguration
- [ ] Timestamp poisoning recovered by `Tunnel::new()`, not `reset()`
