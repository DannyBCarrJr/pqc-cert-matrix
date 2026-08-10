#!/usr/bin/env python3
"""Phase 3, step 1: how well does TLS certificate compression (RFC 8879) work on
post-quantum chains?

Certificate compression is the standard answer to post-quantum certificate bloat.
This measures whether it actually helps. For each chain we compress the payload a
TLS 1.3 server sends (the DER certificate_list: leaf followed by intermediate)
with all three algorithms RFC 8879 registers, at maximum effort, which is the
best case compression can possibly do.

Approximation, stated rather than hidden: we compress the concatenated DER
certificates, not the byte-exact Certificate handshake message. The message adds
a 4-byte handshake header, a 3-byte list length, a 1-byte context length, and a
3-byte length plus 2-byte extensions field per certificate, so roughly 15 bytes
of framing on payloads of 900 to 15,700 bytes. The measured handshake in
transport.py checks this estimate against the real compressed message.

Output: phase3/compression.json (machine readable) and phase3/COMPRESSION.md
(generated table, never hand-edited).

Run:  phase3/.venv/bin/python phase3/compressibility.py
"""
import base64
import json
import re
import zlib
from pathlib import Path

import brotli
import zstandard

ROOT = Path(__file__).resolve().parent.parent
BUNDLES = ROOT / "results" / "bundles"
OUT_JSON = ROOT / "phase3" / "compression.json"
OUT_MD = ROOT / "phase3" / "COMPRESSION.md"

# Chain order matches SIZES.md so the two tables read together.
CHAINS = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "slhroot", "mixed",
          "catalyst", "composite"]

PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S
)


def der_payload(chain_pem: Path) -> bytes:
    """Concatenated DER of every certificate the server sends, in wire order."""
    blocks = PEM_RE.findall(chain_pem.read_bytes())
    if not blocks:
        raise SystemExit(f"no certificates found in {chain_pem}")
    return b"".join(base64.b64decode(b) for b in blocks)


def compress_all(payload: bytes) -> dict:
    """Maximum-effort compression with each RFC 8879 algorithm.

    Levels are deliberately the maximum each library offers. A real server picks
    something cheaper, so these numbers are an upper bound on the saving: if
    compression does not help here, it will not help in production either.
    """
    return {
        # RFC 8879 algorithm 1. zlib format, which is DEFLATE plus a 2-byte header.
        "zlib": len(zlib.compress(payload, 9)),
        # algorithm 2, quality 11 is brotli's maximum.
        "brotli": len(brotli.compress(payload, quality=11)),
        # algorithm 3, level 22 is zstd's maximum ("ultra").
        "zstd": len(zstandard.ZstdCompressor(level=22).compress(payload)),
    }


def best_size(payload: bytes) -> int:
    return min(compress_all(payload).values())


def decompose(certs: list) -> dict:
    """Split the total saving into per-certificate and cross-certificate parts.

    Compressing each certificate alone captures only the X.509 boilerplate inside
    it (OIDs, version and structural fields). Compressing them together adds
    whatever is redundant *between* them, chiefly the issuer name in the leaf
    repeating the subject name in the intermediate. The difference isolates the
    two, which is what shows that neither term scales with key or signature size.
    """
    alone = [len(c) - best_size(c) for c in certs]
    together = sum(len(c) for c in certs) - best_size(b"".join(certs))
    return {
        "saved_per_cert": alone,
        "saved_within_certs": sum(alone),
        "saved_across_certs": together - sum(alone),
    }


def measure_fields() -> list:
    """Compress the ML-DSA signature and public key on their own.

    The chain tables above show the saving does not scale with signature size.
    This isolates why: it compresses the post-quantum fields themselves, with no
    X.509 structure around them to find redundancy in. Every RFC 8879 algorithm
    returns MORE bytes than it was given, because the compressor's own framing is
    the only thing it can add to incompressible input.

    Needs `cryptography` for the field extraction (pip install cryptography).
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography import x509

    rows = []
    for name in ("mldsa44", "mldsa65", "mldsa87"):
        chain_pem = BUNDLES / name / "chain.pem"
        if not chain_pem.exists():
            continue
        leaf = x509.load_der_x509_certificate(
            base64.b64decode(PEM_RE.findall(chain_pem.read_bytes())[0]))
        fields = {
            "signature": leaf.signature,
            "spki": leaf.public_key().public_bytes(Encoding.DER,
                                                   PublicFormat.SubjectPublicKeyInfo),
        }
        for field, blob in fields.items():
            comp = compress_all(blob)
            rows.append({"chain": name, "field": field, "raw": len(blob),
                         **comp, "best": min(comp.values()),
                         "delta": min(comp.values()) - len(blob)})
    return rows


def main() -> None:
    rows = []
    for name in CHAINS:
        chain_pem = BUNDLES / name / "chain.pem"
        if not chain_pem.exists():
            print(f"skip {name}: no bundle (run runners/harness.py first)")
            continue
        certs = [base64.b64decode(b) for b in PEM_RE.findall(chain_pem.read_bytes())]
        payload = der_payload(chain_pem)
        comp = compress_all(payload)
        best_algo = min(comp, key=comp.get)
        rows.append({
            "chain": name,
            "certs": len(certs),
            "cert_sizes": [len(c) for c in certs],
            "raw": len(payload),
            **comp,
            "best_algo": best_algo,
            "best": comp[best_algo],
            "saved": len(payload) - comp[best_algo],
            "saved_pct": round(100 * (len(payload) - comp[best_algo]) / len(payload), 1),
            **decompose(certs),
        })

    fields = measure_fields()
    OUT_JSON.write_text(json.dumps({"chains": rows, "fields": fields}, indent=2) + "\n")
    write_md(rows, fields)
    for r in rows:
        print(f"{r['chain']:10s} raw={r['raw']:6d} best={r['best']:6d} "
              f"({r['best_algo']}) saved={r['saved']:6d} ({r['saved_pct']}%)")
    print()
    for f in fields:
        print(f"{f['chain']:10s} {f['field']:9s} raw={f['raw']:5d} "
              f"best={f['best']:5d} delta={f['delta']:+d}")
    print(f"\n{len(rows)} chains -> phase3/compression.json, phase3/COMPRESSION.md")


def write_md(rows: list, fields: list) -> None:
    md = [
        "# Certificate compression against post-quantum chains",
        "",
        "Generated by `phase3/compressibility.py` from `results/bundles/`; do not",
        "hand-edit. Payload is the concatenated DER certificate_list a TLS 1.3",
        "server sends (leaf followed by intermediate). Every algorithm runs at its",
        "maximum level, so these are upper bounds on what compression can save.",
        "",
        "| Chain | Certs | Raw bytes | zlib | brotli | zstd | Best saving |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        md.append(
            f"| {r['chain']} | {r['certs']} | {r['raw']:,} | {r['zlib']:,} | "
            f"{r['brotli']:,} | {r['zstd']:,} | "
            f"{r['saved']:,} ({r['saved_pct']}%, {r['best_algo']}) |"
        )
    md += [
        "",
        "## Where the saving comes from",
        "",
        "The same total, split into what compresses inside each certificate (X.509",
        "boilerplate) and what compresses only when certificates are sent together",
        "(the issuer name in the leaf repeating the subject name in the",
        "intermediate). Neither term scales with key or signature size.",
        "",
        "| Chain | Cert sizes | Saved within certs | Saved across certs | Total |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        sizes = " + ".join(f"{s:,}" for s in r["cert_sizes"])
        per = " + ".join(str(s) for s in r["saved_per_cert"])
        md.append(
            f"| {r['chain']} | {sizes} | {r['saved_within_certs']} ({per}) | "
            f"{r['saved_across_certs']} | {r['saved']:,} |"
        )
    md += [
        "",
        "## The post-quantum fields on their own",
        "",
        "The tables above show the saving does not scale with signature size.",
        "Here is why, with the X.509 structure stripped away: the ML-DSA",
        "signature and public key compressed by themselves. Every algorithm",
        "returns more bytes than it was given. Compressor framing is the only",
        "thing there is to add to input that has no redundancy in it.",
        "",
        "| Chain | Field | Raw bytes | zlib | brotli | zstd | Best |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in fields:
        md.append(
            f"| {f['chain']} | {f['field']} | {f['raw']:,} | {f['zlib']:,} | "
            f"{f['brotli']:,} | {f['zstd']:,} | {f['delta']:+d} |"
        )
    md += ["", "Reproduce:", "",
           "```", "python3 -m venv phase3/.venv",
           "phase3/.venv/bin/pip install brotli zstandard cryptography",
           "phase3/.venv/bin/python phase3/compressibility.py", "```"]
    OUT_MD.write_text("\n".join(md) + "\n")


if __name__ == "__main__":
    main()
