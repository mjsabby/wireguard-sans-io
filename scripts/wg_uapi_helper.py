#!/usr/bin/env python3
"""Helper for scripts/interop_wireguard_go.sh: configure a userspace
WireGuard device (wireguard-go) over its UAPI socket, with nothing but the
Python standard library. The counterpart of `set` in
scripts/wg_netns_helper.py, which speaks netlink to the kernel; the options
are the same.

    wg_uapi_helper.py set <ifname> [--private-key B64] [--listen-port N]
                          [--peer B64 [--psk B64] [--endpoint IP:PORT]
                           [--allowed-ip A.B.C.D/N] [--keepalive SECONDS]]
    wg_uapi_helper.py get <ifname>

UAPI is the cross-platform configuration protocol
(https://www.wireguard.com/xplatform/): `key=value` lines over the
device's socket, /var/run/wireguard/<ifname>.sock. `get` prints what the
device answers, without the private key.

This is what wg(8) speaks to a userspace device, and `wg set` would do —
where it may: Ubuntu confines /usr/bin/wg with an AppArmor profile that
has no rule for that socket (seen on 26.04, where `wg show` of a
wireguard-go device ends in "Unable to access interface: Permission
denied"). Like scripts/interop_netns.sh, the wireguard-go script therefore
does without wireguard-tools.
"""
import base64
import os
import socket
import sys

SOCKET = "/var/run/wireguard/%s.sock"


def key(b64):
    raw = base64.b64decode(b64)
    if len(raw) != 32:
        raise SystemExit("keys are 32 bytes of base64")
    return raw.hex()


def transact(ifname, lines):
    """Send one operation; return the lines of the answer, less its status.

    An operation is its lines and an empty one; so is the answer, whose
    last line is `errno=N`.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(SOCKET % ifname)
    sock.sendall("".join(line + "\n" for line in lines + [""]).encode())
    answer = b""
    while not answer.endswith(b"\n\n"):
        chunk = sock.recv(65536)
        if not chunk:
            raise SystemExit("UAPI: the device closed the socket in mid-answer")
        answer += chunk
    answer = answer.decode().split("\n")[:-2]
    status = answer.pop() if answer else ""
    if not status.startswith("errno="):
        raise SystemExit("UAPI: no status in the answer")
    errno = abs(int(status[len("errno=") :]))
    if errno != 0:
        raise SystemExit("UAPI: %s: %s" % (lines[0], os.strerror(errno)))
    return answer


def cmd_set(args):
    ifname = args.pop(0)
    opts = {}
    while args:
        name = args.pop(0)
        if not name.startswith("--"):
            raise SystemExit("unexpected argument " + name)
        opts[name[2:]] = args.pop(0)
    lines = ["set=1"]
    if "private-key" in opts:
        lines.append("private_key=" + key(opts["private-key"]))
    if "listen-port" in opts:
        lines.append("listen_port=%d" % int(opts["listen-port"]))
    if "peer" in opts:
        lines.append("public_key=" + key(opts["peer"]))
        if "psk" in opts:
            lines.append("preshared_key=" + key(opts["psk"]))
        if "endpoint" in opts:
            lines.append("endpoint=" + opts["endpoint"])
        if "keepalive" in opts:
            lines.append("persistent_keepalive_interval=%d" % int(opts["keepalive"]))
        if "allowed-ip" in opts:
            lines += ["replace_allowed_ips=true", "allowed_ip=" + opts["allowed-ip"]]
    transact(ifname, lines)


def cmd_get(args):
    for line in transact(args[0], ["get=1"]):
        if not line.startswith("private_key="):
            print(line)


COMMANDS = {"set": cmd_set, "get": cmd_get}

if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in COMMANDS:
        raise SystemExit(__doc__)
    COMMANDS[sys.argv[1]](sys.argv[2:])
