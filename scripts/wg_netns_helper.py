#!/usr/bin/env python3
"""Helper for scripts/interop_netns.sh: configure a kernel WireGuard
interface and generate traffic through it, with nothing but the Python
standard library (no wireguard-tools, no ping, no root).

    wg_netns_helper.py genkey
    wg_netns_helper.py set <ifname> --private-key B64 [--listen-port N]
                           --peer B64 [--psk B64] [--endpoint IP:PORT]
                           [--allowed-ip A.B.C.D/N] [--keepalive SECONDS]
    wg_netns_helper.py show <ifname>
    wg_netns_helper.py ping <dst-ip> <count> <interval-seconds>
    wg_netns_helper.py udp-stream <dst-ip> <port> <seconds> <interval-seconds>
    wg_netns_helper.py udp-sink <bind-ip> <port> <seconds>

`set`/`show` speak the kernel's generic-netlink WireGuard API
(include/uapi/linux/wireguard.h) directly.
"""
import base64
import os
import socket
import struct
import sys
import time

# --- netlink plumbing -------------------------------------------------------
NETLINK_GENERIC = 16
NLM_F_REQUEST, NLM_F_ACK, NLM_F_DUMP = 0x1, 0x4, 0x300
NLMSG_ERROR, NLMSG_DONE = 2, 3
GENL_ID_CTRL, CTRL_CMD_GETFAMILY = 0x10, 3
CTRL_ATTR_FAMILY_ID, CTRL_ATTR_FAMILY_NAME = 1, 2
NLA_F_NESTED = 0x8000

# include/uapi/linux/wireguard.h
WG_CMD_GET_DEVICE, WG_CMD_SET_DEVICE = 0, 1
WGDEVICE_A_IFNAME, WGDEVICE_A_PRIVATE_KEY, WGDEVICE_A_PUBLIC_KEY = 2, 3, 4
WGDEVICE_A_LISTEN_PORT, WGDEVICE_A_PEERS = 6, 8
WGPEER_A_PUBLIC_KEY, WGPEER_A_PRESHARED_KEY, WGPEER_A_ENDPOINT = 1, 2, 4
WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, WGPEER_A_LAST_HANDSHAKE_TIME = 5, 6
WGPEER_A_RX_BYTES, WGPEER_A_TX_BYTES, WGPEER_A_ALLOWEDIPS = 7, 8, 9
WGALLOWEDIP_A_FAMILY, WGALLOWEDIP_A_IPADDR, WGALLOWEDIP_A_CIDR_MASK = 1, 2, 3


def attr(kind, payload):
    length = 4 + len(payload)
    return struct.pack("HH", length, kind) + payload + b"\0" * (-length % 4)


def nested(kind, payload):
    return attr(kind | NLA_F_NESTED, payload)


def parse_attrs(data):
    out = []
    while len(data) >= 4:
        length, kind = struct.unpack_from("HH", data)
        if length < 4:
            break
        out.append((kind & 0x3FFF, data[4:length]))
        data = data[(length + 3) & ~3 :]
    return out


class Genl:
    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.sock.bind((0, 0))
        self.seq = 0
        self.family = self._resolve("wireguard")

    def _send(self, family, cmd, flags, payload):
        self.seq += 1
        body = struct.pack("BBH", cmd, 1, 0) + payload
        header = struct.pack("IHHII", 16 + len(body), family, flags, self.seq, 0)
        self.sock.send(header + body)

    def _messages(self):
        """Yield (type, payload) until an ACK/DONE/error for the request."""
        while True:
            data = self.sock.recv(65536)
            while len(data) >= 16:
                length, kind, _flags, _seq, _pid = struct.unpack_from("IHHII", data)
                payload = data[16:length]
                if kind == NLMSG_ERROR:
                    (errno,) = struct.unpack_from("i", payload)
                    if errno != 0:
                        raise OSError(-errno, "netlink: " + os.strerror(-errno))
                    return
                if kind == NLMSG_DONE:
                    return
                yield kind, payload
                data = data[(length + 3) & ~3 :]

    def _resolve(self, name):
        self._send(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            NLM_F_REQUEST | NLM_F_ACK,
            attr(CTRL_ATTR_FAMILY_NAME, name.encode() + b"\0"),
        )
        family = None
        for _kind, payload in self._messages():
            for kind, value in parse_attrs(payload[4:]):
                if kind == CTRL_ATTR_FAMILY_ID:
                    (family,) = struct.unpack("H", value[:2])
        if family is None:
            raise SystemExit("the kernel has no 'wireguard' generic-netlink family")
        return family

    def set_device(self, payload):
        self._send(self.family, WG_CMD_SET_DEVICE, NLM_F_REQUEST | NLM_F_ACK, payload)
        for _ in self._messages():
            pass

    def get_device(self, ifname):
        self._send(
            self.family,
            WG_CMD_GET_DEVICE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP,
            attr(WGDEVICE_A_IFNAME, ifname.encode() + b"\0"),
        )
        return [parse_attrs(payload[4:]) for _kind, payload in self._messages()]


def key(b64):
    raw = base64.b64decode(b64)
    if len(raw) != 32:
        raise SystemExit("keys are 32 bytes of base64")
    return raw


def cmd_genkey(_args):
    raw = bytearray(os.urandom(32))
    raw[0] &= 248
    raw[31] = (raw[31] & 127) | 64
    print(base64.b64encode(bytes(raw)).decode())


def cmd_set(args):
    ifname = args.pop(0)
    opts = {}
    while args:
        name = args.pop(0)
        if not name.startswith("--"):
            raise SystemExit("unexpected argument " + name)
        opts[name[2:]] = args.pop(0)
    device = attr(WGDEVICE_A_IFNAME, ifname.encode() + b"\0")
    device += attr(WGDEVICE_A_PRIVATE_KEY, key(opts["private-key"]))
    if "listen-port" in opts:
        device += attr(WGDEVICE_A_LISTEN_PORT, struct.pack("H", int(opts["listen-port"])))
    peer = attr(WGPEER_A_PUBLIC_KEY, key(opts["peer"]))
    if "psk" in opts:
        peer += attr(WGPEER_A_PRESHARED_KEY, key(opts["psk"]))
    if "endpoint" in opts:
        host, port = opts["endpoint"].rsplit(":", 1)
        sockaddr = struct.pack("H", socket.AF_INET) + struct.pack("!H", int(port))
        sockaddr += socket.inet_aton(host) + b"\0" * 8
        peer += attr(WGPEER_A_ENDPOINT, sockaddr)
    if "keepalive" in opts:
        peer += attr(
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, struct.pack("H", int(opts["keepalive"]))
        )
    if "allowed-ip" in opts:
        host, mask = opts["allowed-ip"].split("/")
        allowed = attr(WGALLOWEDIP_A_FAMILY, struct.pack("H", socket.AF_INET))
        allowed += attr(WGALLOWEDIP_A_IPADDR, socket.inet_aton(host))
        allowed += attr(WGALLOWEDIP_A_CIDR_MASK, struct.pack("B", int(mask)))
        peer += nested(WGPEER_A_ALLOWEDIPS, nested(0, allowed))
    device += nested(WGDEVICE_A_PEERS, nested(0, peer))
    Genl().set_device(device)


def cmd_show(args):
    for message in Genl().get_device(args[0]):
        for kind, value in message:
            if kind == WGDEVICE_A_PUBLIC_KEY:
                print("public key:", base64.b64encode(value).decode())
            elif kind == WGDEVICE_A_LISTEN_PORT:
                print("listen port:", struct.unpack("H", value[:2])[0])
            elif kind == WGDEVICE_A_PEERS:
                for _idx, peer in parse_attrs(value):
                    for pkind, pvalue in parse_attrs(peer):
                        if pkind == WGPEER_A_PUBLIC_KEY:
                            print("peer:", base64.b64encode(pvalue).decode())
                        elif pkind == WGPEER_A_LAST_HANDSHAKE_TIME:
                            secs = struct.unpack("q", pvalue[:8])[0]
                            age = time.time() - secs if secs else None
                            print("  latest handshake:", "never" if age is None else "%.1fs ago" % age)
                        elif pkind == WGPEER_A_RX_BYTES:
                            print("  rx bytes:", struct.unpack("Q", pvalue[:8])[0])
                        elif pkind == WGPEER_A_TX_BYTES:
                            print("  tx bytes:", struct.unpack("Q", pvalue[:8])[0])


# --- traffic ------------------------------------------------------------------
def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def cmd_ping(args):
    dst, count, interval = args[0], int(args[1]), float(args[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    answered = set()

    def collect(until):
        while True:
            remaining = until - time.time()
            if remaining <= 0:
                return
            sock.settimeout(remaining)
            try:
                packet, _ = sock.recvfrom(2048)
            except socket.timeout:
                return
            icmp = packet[(packet[0] & 0xF) * 4 :]
            if len(icmp) >= 8 and icmp[0] == 0 and icmp[4:6] == b"\x42\x42":
                answered.add(struct.unpack("!H", icmp[6:8])[0])

    for seq in range(1, count + 1):
        body = struct.pack("!BBHHH", 8, 0, 0, 0x4242, seq) + bytes(range(32))
        body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
        sock.sendto(body, (dst, 0))
        collect(time.time() + interval)
    print("ping: %d/%d replies" % (len(answered), count))


def cmd_udp_stream(args):
    dst, port, seconds, interval = args[0], int(args[1]), float(args[2]), float(args[3])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end = time.time() + seconds
    sent = 0
    while time.time() < end:
        sock.sendto(b"one-way stream %06d" % sent, (dst, port))
        sent += 1
        time.sleep(interval)
    print("udp-stream: sent %d datagrams" % sent)


def cmd_udp_sink(args):
    bind, port, seconds = args[0], int(args[1]), float(args[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    sock.settimeout(0.5)
    end = time.time() + seconds
    received = 0
    while time.time() < end:
        try:
            sock.recvfrom(4096)
            received += 1
        except socket.timeout:
            pass
    print("udp-sink: received %d datagrams" % received)


COMMANDS = {
    "genkey": cmd_genkey,
    "set": cmd_set,
    "show": cmd_show,
    "ping": cmd_ping,
    "udp-stream": cmd_udp_stream,
    "udp-sink": cmd_udp_sink,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        raise SystemExit(__doc__)
    COMMANDS[sys.argv[1]](sys.argv[2:])
