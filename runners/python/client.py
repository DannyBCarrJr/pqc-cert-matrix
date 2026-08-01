#!/usr/bin/env python3
"""Test client for the Python runner. One test per invocation; exit 0 ok, 1 fail.

Stdlib only. Notes on cell semantics:
- parse uses ssl._ssl._test_decode_cert, the stdlib's own certificate decoder
  (private API, but the only cert decode the stdlib has; it backs getpeercert()).
- There is NO public offline chain-verification API in the stdlib; the runner
  emits skip for verify with that reason. That absence is itself a data point.
- handshake is fully public API: create_default_context + wrap_socket, with
  hostname checking on (Python's authentic validated-connection path).
"""
import socket
import ssl
import sys


def parse(leaf: str) -> None:
    d = ssl._ssl._test_decode_cert(leaf)
    print("parsed:", d.get("subject"))


def handshake(root: str, host: str, port: str) -> None:
    ctx = ssl.create_default_context(cafile=root)
    with socket.create_connection(("127.0.0.1", int(port))) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            print("handshake: OK", t.version(), t.cipher()[0])


try:
    cmd = sys.argv[1]
    if cmd == "parse":
        parse(sys.argv[2])
    elif cmd == "handshake":
        handshake(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        raise ValueError("usage: parse|handshake")
except Exception as e:
    print(f"{type(e).__name__}: {e}")
    sys.exit(1)
