# PQC certificate compatibility matrix

Measured client behavior for post-quantum and hybrid X.509 certificate chains.

When a post-quantum or hybrid certificate chain hits real client software, what
actually happens? Vendors announce hybrid PQC certificates with no published
measurements. This project answers with evidence: **8 chain shapes across 11
client stacks, 88 cells**, every one a script plus captured output, rerunnable by
any reader on stock tooling.

Written up for a general audience at
[Hybrid certificates, weighed](https://carrdigital.dev/writing/hybrid-certificates-weighed/).
Companion to *Post-Quantum, Measured*, and it holds the same evidence standard:
every claim is labeled Verified, Reported, or Proposed.

**Read `PRIOR-ART.md` before citing anything here as new.** It records, per
finding, what published work already covers. It has demoted several of this
project's own claims, and two Phase 2 claims were outright wrong until it caught
them. That file is the most important one in the repo.

## Layout

- `gen/` mints the chain corpus with stock OpenSSL 3.5.5: ECDSA control, pure
  ML-DSA-44/65/87, an SLH-DSA-SHA2-128s root variant, a mixed chain (classical
  root over ML-DSA), and SAN ladders. `gen/sizes.py` generates `SIZES.md`.
- `phase0/` feasibility work and the catalyst-style hybrid construction (a
  classical certificate carrying ML-DSA material in the ITU-T X.509 s9.8
  alternative-signature extensions, with a correct alt signature).
- `composite/` mints a composite signature certificate
  (draft-ietf-lamps-pq-composite-sigs) via Bouncy Castle 1.82, with a negative
  control that proves the passing cell is a real cryptographic check.
- `runners/` the client harness: a runner contract (`CONTRACT.md`), per-client
  Docker runners, and `harness.py`, which generates `MATRIX.md` from
  `results/results.json`.
- `isolation/` a second, independent TLS server (Bouncy Castle bctls 1.82) plus
  decoded-wire traces, pinning the schannel ML-DSA failure to the client's
  ClientHello rather than to one server's negotiation behavior.
- `phase3/` transport: certificate compression measured offline and on the wire,
  key-log-decrypted handshake captures with per-message byte attribution, and a
  congestion window analysis.

## Findings

Client behavior (`MATRIX.md`, `phase0/FINDINGS.md`):

1. **Parsing never fails.** All 88 cells parse. Post-quantum certificates break
   validation, not parsers, so a parse-based inventory has a 100% false-pass rate.
2. **The catalyst hybrid passes every client**, because RFC 5280 requires
   verifiers to ignore non-critical extensions they do not recognize.
3. **Composite verifies only under Bouncy Castle**, the family that minted it,
   and fails the other ten: the composite OID families do not cross-verify.
4. **Windows splits against itself.** CNG offline-validates ML-DSA chains while
   schannel cannot connect to ML-DSA-authenticated servers, because its
   ClientHello never offers an ML-DSA signature scheme. A certificate inventory
   check passes; the TLS connection still fails.
5. **Your runtime decides readiness, not your distro.** Node 22 and Python 3.13
   (bundled OpenSSL 3.5.x) validate ML-DSA chains that the same host's system
   OpenSSL 3.0 and GnuTLS reject.
6. **Only rustls names the rejected algorithm.** Every other stack reports
   unsupported post-quantum algorithms with trust-store-shaped errors that send
   operators to the wrong layer.

Size and transport (`SIZES.md`, `phase3/FINDINGS.md`, `phase3/TRANSPORT.md`):

7. A leaf's post-quantum surcharge is constant: **+5,127 bytes** (ML-DSA-65
   against ECDSA P-256) across a 1-to-150 SAN ladder.
8. Pure ML-DSA-65, composite, and catalyst leaves weigh within 150 bytes of each
   other. Deployment shape is a validation-policy choice, not a size choice.
9. **CertificateVerify is the cost nobody counts**: 4,631 bytes for ML-DSA-87
   against ECDSA's 74, paid on every full handshake and absent from every
   certificate size table.
10. **The congestion window constrains the flight, not the chain.** mldsa65 is
    11,170 bytes of chain but a 15,739-byte server flight. Analyses that state a
    threshold on chain size understate it by roughly one signature.
11. **Certificate compression saves a constant**, about 240 bytes on this corpus
    regardless of chain size, because only X.509 boilerplate and issuer/subject
    redundancy compress. See the floor caveat in `phase3/FINDINGS.md`.
12. **"SLH-DSA for roots" has a hidden wire cost:** the root's 7,856-byte
    signature rides on the intermediate, which is transmitted. That makes it the
    most expensive certificate chain measured, though *not* the most expensive
    handshake, because its ML-DSA-65 leaf signs more cheaply than ML-DSA-87.

## Reproduce

```
gen/mint-corpus.sh                 # mint the corpus (keys are never committed)
python3 gen/sizes.py               # regenerate sizes.json and SIZES.md
python3 runners/harness.py         # client matrix -> results.json + MATRIX.md
python3 phase3/transport.py        # handshake captures (needs dumpcap)
python3 phase3/report.py           # regenerate TRANSPORT.md
```

Composite needs a JDK and the Bouncy Castle 1.82 jars in `composite/lib/`
(fetched from Maven Central; see `composite/CompositeCert.java`). Certificate
compression analysis needs a venv, per `phase3/FINDINGS.md`.

Measured on one machine: WSL2 Ubuntu for the Linux stacks, Windows 11 25H2 build
26200 for schannel. Limitations are stated in `SCOPE.md` rather than buried:
Apple stacks, NSS and Firefox, embedded stacks, and hardware key storage are all
untested.

## License

MIT.
