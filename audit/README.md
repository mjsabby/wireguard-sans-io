# wireguard-audit

What an adversarial review of this repository measured and compared,
kept so that it can be run again — after a change to the receive path,
on another CPU, against another version of somebody else's code.

It is a workspace of its own (like `bench/` and `fuzz/`): the reference
implementations it compares with come from the registry, and nothing the
library builds or tests may depend on fetching anything. Run its `cargo`
commands from this directory; the scripts are run from anywhere.

| | |
|---|---|
| `tests/crypto_differential.rs` | every in-tree primitive against an independent implementation, and against the Wycheproof vectors |
| `src/bin/attack_cost.rs` + `scripts/perf_attack_cost.sh` | what each kind of datagram costs its receiver, in hardware counters |
| `src/bin/many_peers.rs` + `scripts/perf_many_peers.sh` | the receive path when the tunnels do not fit the cache |
| `src/bin/flood.rs` + `scripts/flood_rig.sh` | a tunnel that is up, and a flood at its socket: server, peer and attacker as three processes |
| `src/bin/lock_scaling.rs` | one `Device` on several threads, shared by reference or behind a lock, next to threads that feed it junk |
| `src/bin/udp_stack_cost.rs` | what a datagram costs the kernel: one call each, many per call, or a train of segments |
| `examples/crypto_speed.rs` | the primitives next to the reference implementations' speed |

Three more parts of the same review live where the default test runs
find them: `tests/shared_device.rs` (one `Device` on several threads),
`embed/tests/hostile_network.rs` (two tunnels on a network that
reorders, replays, forges and corrupts) and `embed/tests/flood.rs` (the
flood rig in one process, with thresholds). And two are scripts about
other people's implementations: `scripts/interop_wireguard_go.sh` (the
scenarios of the kernel interoperability script, against wireguard-go)
and `scripts/perf_vs_kernel.sh` (the data path next to the kernel's;
`bench/README.md` has what it showed).

The figures below are from one machine — a Zen 3 (sixteen cores at up
to 4.5 GHz, AVX2 and no AVX-512), Linux 7.3, Rust 1.100 — and are here
to say what to expect and what to compare a rerun with. Cycle counts repeat to within a percent or two between runs
of one build; between builds a function's cost moves by a few percent
with where the linker put it; times move more.

## The primitives against other implementations

```sh
cargo test                     # a few seconds
AUDIT_ITERS=200000 cargo test  # ten times the random cases
```

| | against | cases by default |
|---|---|---|
| ChaCha20-Poly1305: seal (scalar and SIMD keystream), open, and that a flipped bit is rejected with the buffer untouched | `chacha20poly1305` | every length to 2,200 bytes, then random ones to 70,000 |
| ChaCha20 keystream at block counters 0, 1, just short of wrapping, anywhere | `chacha20` | 6,000 |
| XChaCha20-Poly1305 (cookie replies) | `chacha20poly1305` | 5,000 |
| Poly1305: one-shot, streamed in ragged pieces, padded; all-ones blocks, the largest `r`, `s = 2^128 − 1` | `poly1305` | 20,000 |
| BLAKE2s-256, the keyed 16-byte MAC at four key lengths, the prepared-state MAC, HMAC-BLAKE2s | `blake2`, `hmac` | 20,000 |
| SipHash-2-4 | `siphasher` | 20,000 |
| X25519: the ladder and the fixed-base table; zero and all-ones scalars, the ignored top bit, non-canonical coordinates, small points | `x25519-dalek` | 20,000 |
| X25519, ChaCha20-Poly1305, XChaCha20-Poly1305 | Wycheproof | all vectors of this construction's sizes |

For X25519 the Wycheproof run also checks that the vectors whose shared
secret is all zero — the low-order points — are exactly the ones
`x25519::shared_secret` refuses. No mismatch has been found.

## What a datagram costs its receiver

```sh
CPU=4 scripts/perf_attack_cost.sh             # every scenario, both providers
CPU=4 scripts/perf_attack_cost.sh badtag-256  # one, at another length
```

One run per scenario under `perf stat`, which the program tells when its
measured loop begins and ends. User-space cycles per datagram; where one
figure is given, the scalar provider and the one with the SIMD keystream
(AVX2 here) agree to within a few percent.

| the sender knows | datagram | what the receiver does | cycles |
|---|---|---|---:|
| nothing | 40 bytes of noise | looks at the first four | 30 |
| | a handshake message with a wrong `mac1` | one keyed hash | 1,050 |
| | transport data for an index nobody has (`receive_for`) | compares the index | 70 |
| | the same, routed (`receive`) | decodes the index | 280 |
| | transport data with a peer's index and a wrong tag, 64 bytes | the authenticator key, Poly1305 over it | 650 |
| | the same, 1452 bytes | | 2,000 (SIMD: 2,200) |
| something recorded | a transport datagram, again | checks the replay window | 67 |
| | a peer's initiation, again | `mac1`, one X25519, then the timestamp | 159,000 |
| the public key | an initiation, under load, no cookie yet issued | `mac1` | 1,140 |
| | the same once a cookie secret exists | `mac1`, the cookie, `mac2` | 3,900 |
| | … and the cookie reply | + XChaCha20-Poly1305 | 6,300 |
| | an initiation, not under load | `mac1`, one X25519 | 152,000 |
| | a response for an index seen on the wire | `mac1`, two X25519 | 300,000 |
| the keys (the peer) | 64 bytes of data, received | | 610 (scalar: 970) |
| | 1420 bytes of data, received | | 3,500 (scalar: 9,200) |
| | an initiation (the responder's half of a handshake) | three X25519 and a key generation | 554,000 |

(Sending: 610 cycles for 64 bytes — 920 scalar — and 3,460 for 1420 —
9,340 scalar. Both halves of a handshake, without setup: 1,107,000.)

The 64-byte figures with the SIMD keystream were the scalar ones until
that keystream had a kernel for two blocks: a packet that small is
block 0 for the authenticator key and one block of stream, and a stride
of eight is no way to make two. By size, sending (the SIMD provider,
before and after):

| bytes | 16 | 64 | 80 | 128 | 192 | 256 | 576 | 1280 | 1420 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| before | 870 | 920 | 890 | 970 | 1,070 | 1,120 | 2,150 | 3,340 | 3,460 |
| after | 560 | 610 | 700 | 750 | 880 | 1,010 | 1,740 | 3,190 | 3,460 |

What follows from the table: nothing that knows no key costs more than
a pass of Poly1305 over what it sent, and the rows that cost real work —
handshake messages with a valid `mac1` — are what the load signal and
the cookie are for. The cookie check is not free
either: a flood of initiations under load costs 3,900 cycles apiece
before any reply, which is what bounds one event loop at about half a
million of them a second (below).

## Many peers

```sh
CPU=4 scripts/perf_many_peers.sh              # 1, 100, 10,000 and 100,000 peers
```

A 64-byte packet from each peer in turn, in random order, received and
routed by index (`Device::receive`, then the peer's `Tunnel` out of a
`Vec`):

| peers | cycles | L1 misses | LLC misses | dTLB misses |
|---:|---:|---:|---:|---:|
| 1 | 1,220 | 2 | 0 | 0 |
| 100 | 1,240 | 9 | 0.1 | 0 |
| 10,000 | 1,450 | 11 | 8.4 | 1.2 |
| 100,000 | 2,070 | 11 | 8.9 | 1.2 |

The instructions are the same in every row (3,889); what grows is the
wait for a tunnel that is not in the cache — nine lines of its 4.6 KiB
are touched per packet, all of them missed once the tunnels outgrow the
last-level cache. For 1420-byte packets the same eight hundred cycles
are a quarter on top instead of two thirds.

Nothing has been done about it, and two things were looked at. The
layout is by hand already: `Tunnel` is `repr(C)`, its fields are in the
order of how often a packet needs them, and a test holds it to that —
line 0, two lines of timers, one of counters, one that says which
session cell has which role, two of the cell's keys and counters, a
word of its replay bitmap. What is left to pack is the timer table (two
lines that could be one, with timers that are a number and not an
`Option`) and the two lines of a cell: a line or two of eight or nine,
for a change to how timers and sessions are represented. And the lines
can be asked for early, so that they arrive together — which was tried,
with a version of `many_peers` that routes a batch of packets first,
reads a byte of each line their tunnels will need, and only then
handles them: 2,060 cycles became 1,930 to 1,980 with batches of 4 to
64, and 2,030 when a packet warms only its own tunnel. (It read twelve
lines a tunnel where a packet uses eight or nine: which of a tunnel's
three session cells a packet is for is not known from outside. A
tunnel that warmed itself could do better than that; by how much has
not been tried.) Neither looked worth what it changes — and the case
is the worst there is, packets from a hundred thousand peers in random
order, which traffic with any trains in it is not.

## A flood at a tunnel that is up

```sh
SERVER_CPUS=8,9 CLIENT_CPUS=10,11 ATTACK_CPUS=12-15,28-31 \
    scripts/flood_rig.sh init 4 100000           # 400,000 forged initiations a second
LEAD=0 scripts/flood_rig.sh init 4 100000        # the same, there before the handshake
scripts/flood_rig.sh junk4 8 0                   # as much key-less junk as eight threads send
cargo test --release -p wireguard-embed --features async --test flood -- --ignored --nocapture
```

The server is `wireguard_embed::tokio::AsyncTunn` with the default
limiter, echoing; its peer pings through the tunnel 2,000 times a
second; the attacker sends handshake initiations with a valid `mac1` —
what anyone who knows the server's public key can make — from other
sockets. The peer's loss and worst round trip while the flood lasts:

| forged initiations a second | as reviewed | now |
|---:|---|---|
| 150,000 | 7–9 % lost, in one stretch of 100–150 ms every second | none lost; under 2 ms |
| 400,000 | all lost | none lost; under 2 ms |
| 500,000 | all lost | 0.04 % |
| 600,000 | all lost | 12 % |
| 800,000 | all lost | 27 % |
| 3,000,000 | all lost | 74 % |

(The last row is from the in-process test, whose attacker shares the
machine less politely; the others from the three processes, pinned.)

Two things were wrong and are fixed. The load signal used to give a
flood a tenth of every second, all of it at the start of the second —
a hundred milliseconds of X25519 on someone else's behalf, during
which the loop read nothing (`embed/src/rate_limiter.rs` now spends the
budget as it accrues, ten milliseconds at the most at once, and holds
the signal for a second). And the loop dealt with every datagram in
full in the order it came, cookie replies included, so that above
400,000 a second it did nothing else (`embed/src/tokio.rs`, "Traffic
first": handshake messages are only looked at on arrival, and their
work and the replies get the time traffic leaves, a third of the loop
at the most).

What is left above half a million a second is not the loop's choice:
it is looking at about 540,000 datagrams a second, the rest do not fit
the socket's buffer, and the peer's datagrams are dropped there at the
same odds as the attacker's.

Floods of datagrams that need no key cost the session next to nothing,
then as now, up to what the loop can read: 0.1 % of its packets with 2.9
million datagrams of noise a second or 2.7 million of transport data for
an index nobody has, and with 1.6 million handshake messages with a
wrong `mac1`. Those cost a keyed hash each, and from about 1.75 million
a second the buffer overflows for them as well (a tenth of the peer's
packets lost at two million).

A new handshake during such a flood takes five seconds longer than
without it, as the protocol has it: the first initiation is answered
with a cookie, and the one that carries it comes a `Rekey-Timeout`
later.

## What a datagram costs the kernel

```sh
cd audit && cargo build --release --bin udp_stack_cost
target/release/udp_stack_cost drain 1 4 148 3    # one recvfrom per datagram, four threads sending
target/release/udp_stack_cost drain 32 4 148 3   # recvmmsg, 32 at a time
target/release/udp_stack_cost send one 1452 3    # one sendto per datagram
target/release/udp_stack_cost send mmsg 1452 3   # sendmmsg, 32 at a time
target/release/udp_stack_cost send gso 1452 3    # one sendmsg per train of 32 (UDP_SEGMENT)
target/release/udp_stack_cost send gso 1452 3 gro   # …and the reader takes trains (UDP_GRO)
```

The event loop makes one system call per datagram, and under a flood
two fifths of its time is the kernel's. This is what there is to be had
from not doing that, on loopback, one thread each side, per datagram:

| | 148 or 96 bytes | 1452 bytes |
|---|---:|---:|
| receiving, one `recvfrom` each | 330 ns | 355 ns |
| receiving, `recvmmsg` of 32 | 333 ns | 360 ns |
| sending, one `sendto` each | 1,510 ns | 1,560 ns |
| sending, `sendmmsg` of 32 | 1,470 ns | 1,540 ns |
| sending, trains of 32 segments (`UDP_SEGMENT`) | 280 ns | 350 ns |
| … to a reader that takes trains (`UDP_GRO`) | 58 ns | 126 ns |

Batching the *calls* buys nothing here: what a datagram costs is its
trip through the UDP and IP layers, a buffer of its own, a wake-up for
whoever is waiting — not the crossing into the kernel (this is an AMD
CPU; where the crossing itself is dear the first four rows will differ
some). Batching the *datagrams* is another matter: a train of
equal-sized segments to one address goes through the stack once and is
cut up at the last moment, or not at all if the reader asked for trains.
That is a factor of five on sending and of twelve to twenty-five end to
end — on loopback, where the sender also does the receiver's
bookkeeping; a network card's share is smaller. It is also what a
tunnel's traffic looks like (one peer, one address, full-sized packets)
and what a flood does not (every datagram from somewhere else): it
would raise what the driver carries, not what it withstands.

The driver does none of it. Its sockets go through `tokio` and, for
what `tokio` lacks, `rustix`, which has `sendmmsg` and neither
`recvmmsg` nor the two socket options; the crate forbids `unsafe`, and
this program is here because it had to call the C library to find out.

## One device, several threads

`tests/shared_device.rs`, in the core's own test suite, says what a
shared device has to do (the same verdicts and the same cost as an owned
one, from any number of threads); its timed part is ignored by default.
`src/bin/lock_scaling.rs` measures the arrangements next to each other:

```sh
cargo test --release --test shared_device -- --ignored --nocapture
cd audit && cargo build --release --bin lock_scaling
# <receive threads> <junk threads> <kind of junk> <packets> <sharing> <ns between datagrams> <seconds>
target/release/lock_scaling 4 1 identify 4000000 rwlock 200 3
target/release/lock_scaling 4 1 identify 4000000 shared 200 3
```

Four threads receiving 64-byte packets on one `Device`, each for its own
peer, 200 ns apart (the receive call an I/O thread makes between two
datagrams), and one more thread feeding the same device what an attacker
would send. Packets a second, all four threads together:

| the fifth thread sends | `RwLock<Device>` | `Mutex<Device>` | `&Device`, `receive_shared` |
|---|---:|---:|---:|
| nothing | 7,360,000 | 7,230,000 | 7,840,000 |
| initiations with a valid `mac1`, not under load (29,000 a second) | 570 | 70 | 7,860,000 |
| the same under load: a cookie check and a reply each (half a million a second) | 740,000 | 940,000 | 7,920,000 |
| handshake messages with a wrong `mac1` (one to two million a second) | 3,300,000 | 3,490,000 | 7,890,000 |

`Device::receive` takes `&mut self`, so with a device behind a lock
every thread's every datagram went through that lock — which is what the
README told embedders to build — and a thread that held it for an
X25519, or only shared it while four others wanted it exclusively, held
up all traffic: one sender who knows the public key, on one core.
`Device::receive_shared` takes `&self`. The two things that change when a
datagram arrives are the caller's: the counters (`DeviceStats`, one per
thread) and the cookie secrets (`CookieState`, behind a lock that only
handshake messages under load take, shared except for the instant a
reply is made).
