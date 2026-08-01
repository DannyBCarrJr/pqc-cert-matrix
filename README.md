# PQC certificate compatibility matrix

**Status: private work in progress. Phases 0 and 1 complete (2026-07-31). Goes
public with the v1 client matrix.**

When a post-quantum or hybrid certificate chain hits real client software, what
actually happens? Vendors announce hybrid PQC certificates with zero published
measurements. This project answers with evidence: every cell is a script plus
captured output, rerunnable by any reader on stock tooling.

Companion to *Post-Quantum, Measured* (the same evidence standard: every claim
labeled Verified, Reported, or Proposed).

## What exists so far

- `gen/` mints the full chain corpus with stock OpenSSL 3.5.5: ECDSA control,
  pure ML-DSA-44/65/87, an SLH-DSA-SHA2-128s root variant, a mixed chain
  (classical root over ML-DSA), and SAN ladders. `gen/sizes.py` produces
  `SIZES.md` from measurements, never by hand.
- `phase0/` holds the feasibility work and `FINDINGS.md`, including the
  catalyst-style hybrid construction (classical cert carrying ML-DSA material in
  the ITU-T X.509 s9.8 alternative-signature extensions, with a correct alt
  signature).
- `composite/` mints a composite signature certificate
  (draft-ietf-lamps-pq-composite-sigs) via Bouncy Castle 1.82.
- `runners/` is the Phase 2 client harness: a runner contract (`CONTRACT.md`),
  per-client Docker runners, and `harness.py`, which generates `MATRIX.md`
  from `results/results.json`. First two columns (OpenSSL 3.0, GnuTLS) are live.
- `SCOPE.md` is the v1 plan: rows, the ten-stack client fleet, transport
  measurements, phases.

## Findings so far (details and evidence in phase0/FINDINGS.md)

1. A leaf certificate's post-quantum surcharge is constant: +5,127 bytes
   (ML-DSA-65 vs ECDSA P-256) across a 1-to-150 SAN ladder.
2. Pure ML-DSA-65, composite, and catalyst hybrid leaves all weigh within 150
   bytes of each other. Deployment shape is a validation-policy choice, not a
   size choice.
3. "SLH-DSA for roots" has a hidden wire cost: the root's 7,856-byte signature
   rides on the intermediate, making that chain the most expensive measured.
4. Go and OpenSSL both report unsupported PQ algorithms with trust-store-shaped
   errors, sending operators to debug the wrong layer.

## Reproduce

```
gen/mint-corpus.sh          # mint the corpus (keys are never committed)
python3 gen/sizes.py        # regenerate sizes.json and SIZES.md
phase0/mint-phase0.sh       # phase 0 corpus
python3 phase0/catalyst_build.py
```

Composite needs a JDK and the Bouncy Castle 1.82 jars in `composite/lib/`
(fetched from Maven Central; see `composite/CompositeCert.java`).
