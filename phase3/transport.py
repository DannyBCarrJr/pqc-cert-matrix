#!/usr/bin/env python3
"""Phase 3, step 2: what a post-quantum handshake actually puts on the wire.

Per chain, capture a real TLS 1.3 handshake and attribute every byte. The
handshake is captured with a key log so tshark can decrypt the encrypted flight
(in TLS 1.3 everything after ServerHello is encrypted, so without the key log the
Certificate message is just an opaque record).

Each chain runs twice: with certificate compression allowed, and with the server
forbidden from sending a compressed certificate (-no_tx_cert_comp). The pair
measures what RFC 8879 is worth on a live handshake rather than offline, which
checks the upper bounds in compressibility.py.

Capture point is loopback, deliberately. TLS record structure and handshake
message sizes are properties of the TLS implementation, not the path, so they are
exactly what a real network would carry. TCP segmentation is NOT, because
loopback MTU is 65536 and this host has segmentation offload enabled with no
passwordless sudo to turn it off. Segment counts are therefore computed from
measured byte totals against a stated MSS in icw.py, and labeled computed rather
than measured. Nothing here reports a measured segment count.

Output: phase3/transport.json and phase3/TRANSPORT.md (generated).

Run:  python3 phase3/transport.py
"""
import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUNDLES = ROOT / "results" / "bundles"
EVIDENCE = ROOT / "phase3" / "evidence"
PORT = 14435
IFACE = "lo"

# TLS handshake message types we attribute (RFC 8446 plus RFC 8879's type 25).
HS_NAMES = {
    1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
    8: "EncryptedExtensions", 11: "Certificate", 13: "CertificateRequest",
    15: "CertificateVerify", 20: "Finished", 25: "CompressedCertificate",
}

CHAINS = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "slhroot", "mixed", "catalyst"]

MODES = {
    # OpenSSL 3.5 negotiates certificate compression by default when both peers
    # support it. The "off" arm forbids the server from sending one, which
    # isolates the compression saving on an otherwise identical handshake.
    "compression": [],
    "no-compression": ["-no_tx_cert_comp"],
}


def wait_port(timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", PORT), 0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def tshark_fields(pcap: Path, keylog: Path, display: str, fields: list) -> list:
    """Run tshark with key-log decryption and return rows of split field values."""
    cmd = ["tshark", "-r", str(pcap), "-o", f"tls.keylog_file:{keylog}", "-Y", display, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True)
    rows = []
    for line in out.stdout.splitlines():
        if line.strip():
            rows.append([c.split(",") if c else [] for c in line.split("\t")])
    return rows


def capture_one(chain: str, mode: str, extra: list, ev: Path) -> dict:
    """One handshake, captured and attributed. Returns a result dict."""
    b = BUNDLES / chain
    ev.mkdir(parents=True, exist_ok=True)
    pcap, keylog = ev / "capture.pcap", ev / "keys.log"
    for stale in (pcap, keylog):
        stale.unlink(missing_ok=True)

    server = subprocess.Popen(
        ["openssl", "s_server", "-accept", str(PORT), "-quiet",
         "-cert", str(b / "leaf.crt"), "-key", str(b / "leaf.key"),
         "-cert_chain", str(b / "int.crt"), "-keylogfile", str(keylog), *extra],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    cap = None
    try:
        if not wait_port():
            return {"error": "server did not start"}
        cap = subprocess.Popen(
            ["dumpcap", "-i", IFACE, "-f", f"tcp port {PORT}", "-w", str(pcap), "-q"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.2)  # dumpcap needs to be live before the client connects
        client = subprocess.run(
            ["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}",
             "-servername", "matrix.test", "-CAfile", str(b / "root.crt")],
            input="", capture_output=True, text=True, timeout=30,
        )
        (ev / "client.txt").write_text(client.stdout + client.stderr)
        time.sleep(0.8)  # let the tail of the flight land in the capture
    finally:
        if cap:
            cap.terminate()
            cap.wait(timeout=5)
        server.terminate()
        server.wait(timeout=5)

    if not pcap.exists() or not keylog.exists():
        return {"error": "capture or keylog missing"}
    return analyze(pcap, keylog, ev)


def analyze(pcap: Path, keylog: Path, ev: Path) -> dict:
    """Attribute handshake bytes from a decrypted capture."""
    # Handshake messages, split by direction. Server port identifies the sender.
    messages = {"server": {}, "client": {}}
    for row in tshark_fields(pcap, keylog, "tls.handshake.type",
                             ["tcp.srcport", "tls.handshake.type", "tls.handshake.length"]):
        srcport, types, lengths = row[0], row[1], row[2]
        who = "server" if srcport and srcport[0] == str(PORT) else "client"
        for t, ln in zip(types, lengths):
            name = HS_NAMES.get(int(t), f"type{t}")
            messages[who][name] = messages[who].get(name, 0) + int(ln)

    # TLS records as they appear on the wire, and raw TCP payload per direction.
    records = {"server": [], "client": []}
    tcp_bytes = {"server": 0, "client": 0}
    for row in tshark_fields(pcap, keylog, "tcp.len > 0",
                             ["tcp.srcport", "tcp.len", "tls.record.length"]):
        srcport, tcplen, reclens = row[0], row[1], row[2]
        who = "server" if srcport and srcport[0] == str(PORT) else "client"
        tcp_bytes[who] += int(tcplen[0]) if tcplen else 0
        records[who] += [int(x) for x in reclens]

    # The server's first flight is what has to fit in the initial congestion
    # window: everything it sends before the client's Finished. NewSessionTicket
    # arrives after and is excluded, which is why it is subtracted here.
    srv = messages["server"]
    flight = sum(v for k, v in srv.items() if k != "NewSessionTicket")

    (ev / "records.txt").write_text(
        "server records: " + ", ".join(map(str, records["server"])) + "\n"
        "client records: " + ", ".join(map(str, records["client"])) + "\n"
    )
    return {
        "server_messages": srv,
        "client_messages": messages["client"],
        "server_flight_handshake_bytes": flight,
        "server_records": records["server"],
        "client_records": records["client"],
        "largest_server_record": max(records["server"], default=0),
        "server_tcp_bytes": tcp_bytes["server"],
        "client_tcp_bytes": tcp_bytes["client"],
        "compressed": "CompressedCertificate" in srv,
    }


def main() -> None:
    results = []
    for chain in CHAINS:
        if not (BUNDLES / chain / "leaf.key").exists():
            print(f"skip {chain}: no leaf key, cannot serve")
            continue
        for mode, extra in MODES.items():
            ev = EVIDENCE / chain / mode
            r = capture_one(chain, mode, extra, ev)
            r["chain"], r["mode"] = chain, mode
            results.append(r)
            if "error" in r:
                print(f"{chain:10s} {mode:15s} ERROR: {r['error']}")
                continue
            cert = r["server_messages"].get("Certificate") or \
                r["server_messages"].get("CompressedCertificate", 0)
            print(f"{chain:10s} {mode:15s} cert={cert:6d} "
                  f"cv={r['server_messages'].get('CertificateVerify', 0):5d} "
                  f"flight={r['server_flight_handshake_bytes']:6d} "
                  f"maxrec={r['largest_server_record']:6d} "
                  f"{'compressed' if r['compressed'] else ''}")

    (ROOT / "phase3" / "transport.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"\n{len(results)} captures -> phase3/transport.json, evidence in phase3/evidence/")


if __name__ == "__main__":
    if shutil.which("dumpcap") is None:
        sys.exit("dumpcap not found (install wireshark and join the wireshark group)")
    main()
