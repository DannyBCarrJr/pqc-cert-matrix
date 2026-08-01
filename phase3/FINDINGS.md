# Phase 3 findings: transport

Run 2026-08-01. Phase 3 measures what post-quantum chains cost on the wire, as
opposed to Phase 2's question of whether clients accept them at all.

Status: **step 1 of 3 complete.**

1. Certificate compression (RFC 8879) against the corpus. DONE, below.
2. Captured handshakes: Certificate message size, record structure, TCP segment
   counts on a realistic MTU. NOT STARTED.
3. Initial congestion window analysis computed from step 2. NOT STARTED.

> **Novelty check owed before any of this is published.** That post-quantum keys
> and signatures are incompressible is a widely stated intuition, so the
> contribution here is the measured constant and the mechanism split, not the
> intuition. Add a section to `PRIOR-ART.md` before this reaches an article, the
> same way the Phase 2 claims were checked and two of them corrected.

## Certificate compression saves a constant, so it helps least where it is needed most

Certificate compression is the standard answer to post-quantum certificate bloat.
Measured against this corpus at maximum effort with all three algorithms RFC 8879
registers (zlib, brotli, zstd), it recovers **roughly 240 bytes from any chain**,
and that figure barely moves as the chain grows from 900 to 15,703 bytes.

| Chain | Raw bytes | Best saving |
|---|---|---|
| ecdsa | 900 | 242 (26.9%) |
| catalyst | 6,238 | 252 (4.0%) |
| mldsa44 | 8,098 | 248 (3.1%) |
| mldsa65 | 11,156 | 244 (2.2%) |
| mldsa87 | 15,072 | 237 (1.6%) |
| slhroot | 15,703 | 231 (1.5%) |

Because the saving is a constant and the payload is not, the benefit collapses
exactly as the certificates get large: **26.9% on the classical control, 1.5% on
the heaviest post-quantum chain.** Full table including all three algorithms:
`COMPRESSION.md`.

The single sharpest number: the SLH-DSA-signed intermediate in the slhroot chain
is 10,112 bytes and yields **35 bytes** to maximum-effort compression, which is
0.35% of itself.

## Why: the compressible part of a certificate does not scale

Splitting the total isolates two terms, neither of which grows with key or
signature size:

- **Inside each certificate, 73 to 126 bytes.** This is X.509 boilerplate: OIDs,
  version and structural DER fields. A 464-byte ECDSA leaf gives up 51 bytes; a
  10,112-byte SLH-DSA-signed intermediate gives up 35. Bigger certificate, no
  more compressible material.
- **Across certificates, 126 to 149 bytes**, present in every two-certificate
  chain and exactly **0** for the single self-signed composite. This is the
  redundancy between certificates, chiefly the issuer name in the leaf repeating
  the subject name in the intermediate. It appears only when there are two
  certificates to compare, which is the control proving the mechanism.

Everything else in a post-quantum certificate is key and signature material,
which is pseudorandom by construction and therefore incompressible. That is not a
weakness of any particular algorithm. Compressing an ML-DSA signature would mean
finding structure in the output of a function designed to have none.

## Operational reading

Certificate compression is worth enabling, because 240 bytes is free and it
recovers a quarter of a classical chain. It is not a post-quantum mitigation. Any
migration plan whose bloat answer is "we will turn on certificate compression"
is planning to recover 1.5 to 3% of the problem it is describing.

The three algorithms are also close to interchangeable here. zstd wins five rows,
brotli two, and the spread between best and worst on any post-quantum chain is
under 60 bytes. Algorithm choice is not where the decision is.

## Method and limits

Payload is the concatenated DER certificate_list a TLS 1.3 server sends, leaf
followed by intermediate, taken from `results/bundles/`. Compression runs at each
library's maximum level (zlib 9, brotli quality 11, zstd 22), which is an upper
bound: a production server picks something cheaper and saves less.

Stated approximation: this compresses the DER certificate_list rather than the
byte-exact Certificate handshake message, which adds roughly 15 bytes of framing
(handshake header, list length, per-certificate length and extensions fields).
Step 2 checks this estimate against a real compressed Certificate message on the
wire.

Not yet measured: whether each client in the fleet actually advertises
`compress_certificate`, and which algorithms it offers. That is a Phase 2 style
cross-stack question with a transport answer, and it belongs in step 2.

## Reproduce

```
python3 -m venv phase3/.venv
phase3/.venv/bin/pip install brotli zstandard
phase3/.venv/bin/python phase3/compressibility.py
```

Needs `results/bundles/` (created by `runners/harness.py`).
