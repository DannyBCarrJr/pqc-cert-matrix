# PQC certificate compatibility matrix

**Status: private work in progress. Phases 0, 1, and 2 complete (2026-07-31):
all ten v1 client columns are populated (80 cells). Goes public at Phase 4.**

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
  from `results/results.json`. All ten v1 columns are live: OpenSSL 3.0 and 3.5,
  GnuTLS, Go, Java 21, .NET 8, Python, Node, rustls, and Windows schannel,
  plus a Bouncy Castle certificate-path column as the composite control.
- `isolation/` is the schannel isolation study (2026-08-01): a second,
  independent TLS server (Bouncy Castle bctls 1.82) plus decoded-wire traces,
  which pin the schannel ML-DSA failure to the client's ClientHello rather
  than to one server's negotiation behavior. See `isolation/FINDINGS.md`.
- `SCOPE.md` is the v1 plan: rows, the ten-stack client fleet, transport
  measurements, phases.

## Headline findings (details and evidence in phase0/FINDINGS.md)

1. A leaf certificate's post-quantum surcharge is constant: +5,127 bytes
   (ML-DSA-65 vs ECDSA P-256) across a 1-to-150 SAN ladder.
2. Pure ML-DSA-65, composite, and catalyst hybrid leaves all weigh within 150
   bytes of each other. Deployment shape is a validation-policy choice, not a
   size choice.
3. "SLH-DSA for roots" has a hidden wire cost: the root's 7,856-byte signature
   rides on the intermediate, making that chain the most expensive measured.
4. Windows splits against itself: CNG offline-validates ML-DSA chains while
   schannel cannot connect to ML-DSA-authenticated servers, because its
   ClientHello never offers an ML-DSA signature scheme (isolated against two
   independent server implementations; schannel surfaces the server's
   negotiation abort as SSPI 0x80090326, SEC_E_ILLEGAL_MESSAGE). A certificate
   inventory check passes; the TLS connection still fails.
5. Your runtime decides PQ readiness, not your distro: Node 22 and Python 3.13
   (bundled OpenSSL 3.5.x) validate ML-DSA chains that the same host's system
   OpenSSL 3.0 and GnuTLS reject.
6. The catalyst hybrid passes every client. Composite verifies only under
   Bouncy Castle, the family that minted it, and fails the other ten: the
   composite OID families do not cross-verify.
7. Clients report unsupported PQ algorithms with trust-store-shaped errors that
   send operators to the wrong layer. Only rustls names the algorithm.

## Reproduce

```
gen/mint-corpus.sh          # mint the corpus (keys are never committed)
python3 gen/sizes.py        # regenerate sizes.json and SIZES.md
phase0/mint-phase0.sh       # phase 0 corpus
python3 phase0/catalyst_build.py
```

Composite needs a JDK and the Bouncy Castle 1.82 jars in `composite/lib/`
(fetched from Maven Central; see `composite/CompositeCert.java`).
