#!/usr/bin/env python3
"""An independent model of the WireGuard handshake, for known answers.

Written from the whitepaper (§5.4.2 - §5.4.6) and from RFC 7748, RFC 8439 and
RFC 7693, with nothing but the Python standard library: X25519, ChaCha20 and
Poly1305 are the RFCs' reference arithmetic on Python integers; BLAKE2s and
HMAC are `hashlib` / `hmac`. It shares no code and no author's assumptions
with the Rust implementation, which is the point: `tests/known_answers.rs`
holds what this prints, and the library has to produce the same bytes.

    scripts/handshake_model.py [--initiator-index N] [--responder-index N]

The two indices are the one thing the model cannot know: each side chooses
its own, by a scheme that is this implementation's business
(`src/index.rs`). They are read off the library's messages (bytes 4..8,
little endian) and passed in; the test prints them when it fails.

Everything else is fixed here and repeated in the test: the static keys, the
pre-shared key, the ephemeral keys (what the test's scripted entropy source
hands out), the time.
"""
import argparse
import hashlib
import hmac
import struct

# --------------------------------------------------------------------- X25519
P = 2**255 - 19
A24 = 121665


def x25519(k: bytes, u: bytes) -> bytes:
    """RFC 7748 §5: the ladder on integers."""
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
    scalar = int.from_bytes(kb, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


BASE = (9).to_bytes(32, "little")

# ---------------------------------------------------------- ChaCha20-Poly1305
M32 = 0xFFFFFFFF


def _rotl(v, n):
    return ((v << n) & M32) | (v >> (32 - n))


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & M32; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & M32; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32; s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    init = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key)) \
        + [counter] + list(struct.unpack("<3I", nonce))
    s = init[:]
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12); _quarter(s, 1, 5, 9, 13)
        _quarter(s, 2, 6, 10, 14); _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15); _quarter(s, 1, 6, 11, 12)
        _quarter(s, 2, 7, 8, 13); _quarter(s, 3, 4, 9, 14)
    return struct.pack("<16I", *[(x + y) & M32 for x, y in zip(s, init)])


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], block))
    return bytes(out)


def poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        acc = (acc + int.from_bytes(chunk + b"\x01", "little")) * r % ((1 << 130) - 5)
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(x: bytes) -> bytes:
    return b"\x00" * (-len(x) % 16)


def aead(key: bytes, counter: int, plaintext: bytes, aad: bytes) -> bytes:
    """`Aead(key, counter, plain, auth)` of the whitepaper: RFC 8439 with
    the nonce 0^32 || LE64(counter)."""
    nonce = b"\x00" * 4 + struct.pack("<Q", counter)
    otk = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20(key, 1, nonce, plaintext)
    mac_data = aad + _pad16(aad) + ciphertext + _pad16(ciphertext) \
        + struct.pack("<QQ", len(aad), len(ciphertext))
    return ciphertext + poly1305(otk, mac_data)


# ------------------------------------------------------------ BLAKE2s, Kdf
def Hash(*parts: bytes) -> bytes:
    return hashlib.blake2s(b"".join(parts)).digest()


def Mac(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def Hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def Kdf(key: bytes, data: bytes, n: int):
    t0 = Hmac(key, data)
    out, previous = [], b""
    for i in range(1, n + 1):
        previous = Hmac(t0, previous + bytes([i]))
        out.append(previous)
    return out


CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"


def tai64n(unix_secs: int, unix_nanos: int) -> bytes:
    """§5.1: seconds since the TAI epoch as existing implementations label
    them (2^62 + 10 + Unix seconds), then nanoseconds, both big endian; the
    low 24 bits of the nanoseconds are cleared, as the whitepaper allows
    and the reference implementations do."""
    return struct.pack(">QI", (1 << 62) + 10 + unix_secs, unix_nanos & 0xFF000000)


def initiation(index, s_priv_i, s_pub_r, e_priv_i, timestamp):
    """§5.4.2. Returns the 148-byte message and the (C, H) it leaves."""
    s_pub_i = x25519(s_priv_i, BASE)
    c = Hash(CONSTRUCTION)
    h = Hash(c, IDENTIFIER)
    h = Hash(h, s_pub_r)
    e_pub_i = x25519(e_priv_i, BASE)
    (c,) = Kdf(c, e_pub_i, 1)
    h = Hash(h, e_pub_i)
    c, k = Kdf(c, x25519(e_priv_i, s_pub_r), 2)
    enc_static = aead(k, 0, s_pub_i, h)
    h = Hash(h, enc_static)
    c, k = Kdf(c, x25519(s_priv_i, s_pub_r), 2)
    enc_timestamp = aead(k, 0, timestamp, h)
    h = Hash(h, enc_timestamp)
    msg = b"\x01\x00\x00\x00" + struct.pack("<I", index) + e_pub_i + enc_static + enc_timestamp
    assert len(msg) == 116
    msg += Mac(Hash(LABEL_MAC1, s_pub_r), msg) + b"\x00" * 16
    return msg, c, h


def response(index, initiator_index, c, h, s_pub_i, e_pub_i, e_priv_r, psk):
    """§5.4.3, continuing from the initiation's (C, H). Returns the 92-byte
    message and the final chaining key."""
    e_pub_r = x25519(e_priv_r, BASE)
    (c,) = Kdf(c, e_pub_r, 1)
    h = Hash(h, e_pub_r)
    (c,) = Kdf(c, x25519(e_priv_r, e_pub_i), 1)
    (c,) = Kdf(c, x25519(e_priv_r, s_pub_i), 1)
    c, tau, k = Kdf(c, psk, 3)
    h = Hash(h, tau)
    enc_empty = aead(k, 0, b"", h)
    msg = b"\x02\x00\x00\x00" + struct.pack("<II", index, initiator_index) + e_pub_r + enc_empty
    assert len(msg) == 60
    msg += Mac(Hash(LABEL_MAC1, s_pub_i), msg) + b"\x00" * 16
    return msg, c


def transport(receiver_index, key, counter, payload):
    """§5.4.6: the payload zero-padded to a multiple of 16 bytes."""
    padded = payload + _pad16(payload)
    return b"\x04\x00\x00\x00" + struct.pack("<IQ", receiver_index, counter) + aead(key, counter, padded, b"")


def self_test():
    # RFC 7748 §5.2 and §6.1.
    assert x25519(bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                  bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")).hex() \
        == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    assert x25519(bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), BASE).hex() \
        == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    # RFC 8439 §2.8.2.
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
          b"sunscreen would be it.")
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, pt)
    tag = poly1305(otk, aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct)))
    assert ct[:16].hex() == "d31a8d34648e60db7b86afbc53ef7ec2"
    assert tag.hex() == "1ae10b594f09e26a7e902ecbd0600691"
    # RFC 7693 Appendix B.
    assert Hash(b"abc").hex() == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"


# The fixed inputs — the same in tests/known_answers.rs.
S_PRIV_I = bytes(range(0x01, 0x21))
S_PRIV_R = bytes(range(0xA1, 0xC1))
E_PRIV_I = bytes(range(0x40, 0x60))   # what the initiator's entropy source hands out
E_PRIV_R = bytes(range(0x80, 0xA0))   # what the responder's does
PSK = bytes([0x77]) * 32
UNIX_SECS, UNIX_NANOS = 1_700_000_003, 0x12345678
PAYLOAD_I = b"known answer: initiator to responder"   # 36 bytes, padded to 48
PAYLOAD_R = b"and back"                               # 8 bytes, padded to 16


def vectors(initiator_index, responder_index, psk):
    s_pub_i, s_pub_r = x25519(S_PRIV_I, BASE), x25519(S_PRIV_R, BASE)
    init, c, h = initiation(initiator_index, S_PRIV_I, s_pub_r, E_PRIV_I, tai64n(UNIX_SECS, UNIX_NANOS))
    resp, c = response(responder_index, initiator_index, c, h, s_pub_i, x25519(E_PRIV_I, BASE), E_PRIV_R, psk)
    send_i, send_r = Kdf(c, b"", 2)
    return {
        "initiation": init,
        "response": resp,
        "data_i": transport(responder_index, send_i, 0, PAYLOAD_I),
        "data_r": transport(initiator_index, send_r, 0, PAYLOAD_R),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--initiator-index", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--responder-index", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--no-psk-initiator-index", type=lambda v: int(v, 0), default=None)
    ap.add_argument("--no-psk-responder-index", type=lambda v: int(v, 0), default=None)
    args = ap.parse_args()
    self_test()
    print(f"initiator's static public key: {x25519(S_PRIV_I, BASE).hex()}")
    print(f"responder's static public key: {x25519(S_PRIV_R, BASE).hex()}")
    cases = [("with the pre-shared key", args.initiator_index, args.responder_index, PSK)]
    if args.no_psk_initiator_index is not None:
        cases.append(("without a pre-shared key", args.no_psk_initiator_index,
                      args.no_psk_responder_index or 0, bytes(32)))
    for name, i, r, psk in cases:
        print(f"\n{name} (indices {i:#010x}, {r:#010x}):")
        for what, value in vectors(i, r, psk).items():
            print(f"  {what} ({len(value)} bytes): {value.hex()}")


if __name__ == "__main__":
    main()
