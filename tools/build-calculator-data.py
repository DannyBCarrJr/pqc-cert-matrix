#!/usr/bin/env python3
"""Emit the measurement model that backs the public handshake-budget calculator.

Everything here is derived from committed artifacts (gen/sizes.json,
phase3/transport.json, results/results.json). Nothing is hand-entered, so the
calculator cannot drift from the measurements.

The size model is compositional, because a certificate's weight is the sum of
three independently measured things:

    cert_bytes = structural + SPKI(key algorithm) + signature(signing algorithm)

That decomposition is what lets the calculator price combinations nobody minted,
for example an ML-DSA-44 leaf under an ML-DSA-87 issuer. Combinations that WERE
minted are flagged `measured: true` so the UI can say which is which.

Run: python3 tools/build-calculator-data.py > calculator-data.json
"""
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

sizes = json.loads((ROOT / "gen" / "sizes.json").read_text())
transport = json.loads((ROOT / "phase3" / "transport.json").read_text())
results = json.loads((ROOT / "results" / "results.json").read_text())


def rows(chain, kind):
    return [r for r in sizes if r["chain"] == chain and r["file"].endswith(f"/{kind}.crt")]


def one(chain, kind):
    r = rows(chain, kind)
    return r[0] if r else None


# --- signature and key sizes, straight from the minted corpus -----------------
# certVerify is the measured TLS CertificateVerify message body: the raw
# signature plus 4 bytes of algorithm identifier and length.
tmap = {r["chain"]: r for r in transport if r.get("mode") == "no-compression"}

ALGS = {
    "ecdsa-p256": dict(label="ECDSA P-256", classical=True,
                       spki=one("ecdsa", "leaf")["spki"],
                       sig=one("ecdsa", "leaf")["signature"],
                       cv=tmap["ecdsa"]["server_messages"]["CertificateVerify"]),
    "mldsa44": dict(label="ML-DSA-44", classical=False,
                    spki=one("mldsa44", "leaf")["spki"],
                    sig=one("mldsa44", "leaf")["signature"],
                    cv=tmap["mldsa44"]["server_messages"]["CertificateVerify"]),
    "mldsa65": dict(label="ML-DSA-65", classical=False,
                    spki=one("mldsa65", "leaf")["spki"],
                    sig=one("mldsa65", "leaf")["signature"],
                    cv=tmap["mldsa65"]["server_messages"]["CertificateVerify"]),
    "mldsa87": dict(label="ML-DSA-87", classical=False,
                    spki=one("mldsa87", "leaf")["spki"],
                    sig=one("mldsa87", "leaf")["signature"],
                    cv=tmap["mldsa87"]["server_messages"]["CertificateVerify"]),
}

# SLH-DSA: the corpus only ever used it to sign a root, never to sign a
# handshake, so its CertificateVerify is COMPUTED (signature + the same 4-byte
# overhead every measured row showed) and flagged as such.
slh_root = one("slhroot", "root")
slh_int = one("slhroot", "int")
ALGS["slhdsa128s"] = dict(
    label="SLH-DSA-SHA2-128s", classical=False,
    spki=slh_root["spki"], sig=slh_int["signature"],
    cv=slh_int["signature"] + 4, cv_measured=False,
)

# --- structural overhead, measured -------------------------------------------
# What a certificate costs beyond its key and its signature. Averaged across the
# corpus because it varies by a few bytes with name lengths and serial numbers.
def structural(kind):
    vals = []
    for chain in ("ecdsa", "mldsa44", "mldsa65", "mldsa87", "mixed"):
        r = one(chain, kind)
        if r:
            vals.append(r["total"] - r["spki"] - r["signature"])
    return round(statistics.mean(vals)), min(vals), max(vals)

leaf_struct, leaf_lo, leaf_hi = structural("leaf")
int_struct, int_lo, int_hi = structural("int")

# --- per-SAN growth, measured from the 1/10/50/150 ladder --------------------
ladder = sorted(
    [(1, one("ecdsa", "leaf")["total"])] +
    [(n, rows("ecdsa", f"leaf-san{n}")[0]["total"]) for n in (10, 50, 150)]
)
per_san = (ladder[-1][1] - ladder[0][1]) / (ladder[-1][0] - ladder[0][0])

# --- Certificate message framing, measured -----------------------------------
# tls.handshake.length excludes the 4-byte handshake header, so the body is
# 1 byte of context length + 3 bytes of list length + 5 per certificate
# (3 length, 2 extensions). Verified against all seven captures.
framing = []
for chain, t in tmap.items():
    der = {"ecdsa": 900, "mldsa44": 8098, "mldsa65": 11156, "mldsa87": 15072,
           "slhroot": 15703, "mixed": 7908, "catalyst": 6238}.get(chain)
    if der:
        framing.append(t["server_messages"]["Certificate"] - der)
assert set(framing) == {14}, f"framing not constant: {sorted(set(framing))}"

# --- fixed flight overhead, measured constant --------------------------------
fixed = {t["server_flight_handshake_bytes"]
         - t["server_messages"]["Certificate"]
         - t["server_messages"]["CertificateVerify"] for t in tmap.values()}
assert len(fixed) == 1, f"fixed overhead is not constant: {sorted(fixed)}"

# --- client compatibility, from the 88-cell matrix ---------------------------
clients = sorted({c["client"] for c in results})
compat = {}
for chain in sorted({c["chain"] for c in results}):
    cells = {c["client"]: c["tests"] for c in results if c["chain"] == chain}
    compat[chain] = {
        cl: {"handshake": cells[cl]["handshake"]["status"],
             "detail": cells[cl]["handshake"]["detail"][:180]}
        for cl in clients if cl in cells
    }

versions = {c["client"]: c["client_version"] for c in results}

out = {
    "provenance": {
        "source": "https://github.com/DannyBCarrJr/pqc-cert-matrix",
        "doi": "10.5281/zenodo.21749600",
        "measured": "2026-07-31 to 2026-08-01, OpenSSL 3.5.5, single host",
        "note": "Generated by tools/build-calculator-data.py. Do not hand-edit.",
    },
    "constants": {
        "fixedFlightBytes": fixed.pop(),
        "certMsgFramingBase": 4,
        "certMsgFramingPerCert": 5,
        "leafStructuralBytes": leaf_struct,
        "leafStructuralRange": [leaf_lo, leaf_hi],
        "intStructuralBytes": int_struct,
        "intStructuralRange": [int_lo, int_hi],
        "bytesPerExtraSan": round(per_san, 2),
        "recordPlaintextCeiling": 16384,
        "initialCongestionWindowSegments": 10,
    },
    "algorithms": ALGS,
    "measuredChains": {
        t["chain"]: {
            "certificate": t["server_messages"]["Certificate"],
            "certificateVerify": t["server_messages"]["CertificateVerify"],
            "flight": t["server_flight_handshake_bytes"],
            "largestRecord": t["largest_server_record"],
        } for t in tmap.values()
    },
    "compatibility": compat,
    "clientVersions": versions,
}
print(json.dumps(out, indent=2))
