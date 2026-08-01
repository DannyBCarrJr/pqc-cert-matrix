# Phase 0 findings: feasibility confirmed, all five rows resolved

Run 2026-07-31 on stock OpenSSL 3.5.5, Go 1.26.0, pyca/cryptography 46.0.5, WSL2.
Evidence: `evidence/mint-phase0.txt`, `evidence/catalyst-build.txt`,
`evidence/go-parse.txt`. Regenerate everything with `mint-phase0.sh` then
`catalyst_build.py` (keys are gitignored; scripts recreate the corpus).

## Verdict

v1 proceeds at full scope. No kill switch triggered. No prior art preempts it.

## Prior art (none blocking)

- PKI Consortium PQCCM (pkic.org/wg/pqc/pqccm/): vendor self-reported, explicitly
  does not "review, vet, verify or test implementations or interoperability."
  Complementary, and a distribution channel for our results later.
- arXiv 2604.06100 (Delgado Jimenez): performance of ML-DSA/SLH-DSA placement,
  single stack (OpenSSL + oqsprovider). Cite it; it does not cover cross-client
  behavior. A measured multi-stack client matrix does not exist publicly.

## Row constructibility (Verified tonight unless marked)

| Row | Status | Evidence |
|---|---|---|
| ECDSA control chain | Minted, verifies | mint-phase0.txt |
| Pure ML-DSA-65 chain | Minted with stock OpenSSL, verifies | mint-phase0.txt |
| Catalyst hybrid leaf | Constructed (pyca + openssl pkeyutl -rawin), alt sig verifies over stripped TBS, classical chain validates | catalyst-build.txt |
| Mixed chain (EC root, ML-DSA below) | Minted, verifies | mint-phase0.txt |
| Composite (draft-ietf-lamps-pq-composite-sigs) | **Constructed later the same night** via Bouncy Castle 1.82 (JDK 17): MLDSA65-ECDSA-P256-SHA512 self-signed cert, BC self-verify OK, 5,628 bytes, sig OID 2.16.840.1.114027.80.9.1.8 (BC's draft-07 assignment; draft is at -19, skew tested in Phase 2). See `../composite/`. | ../composite/evidence-composite.txt |

## DER sizes (bytes), first data

| Chain | Root | Intermediate | Leaf |
|---|---|---|---|
| ECDSA control | 392 | 437 | 464 |
| Pure ML-DSA-65 | 5,521 | 5,565 | 5,591 |
| Mixed (EC root) | 392 | 2,318 | 5,589 |
| Catalyst hybrid | (reuses ECDSA CA) | | 5,736 |

Notable already: the mixed intermediate (ML-DSA key, ECDSA signature) is 2,318 bytes
vs 5,565 for its pure sibling, cleanly separating key bytes from signature bytes on
the wire. The catalyst leaf lands at 5,736, within ~150 bytes of a pure ML-DSA leaf:
the "keep a classical cert" hybrid saves almost nothing in size, it only changes who
can validate it. Both belong in article 3.

## First client data points (Go 1.26.0, crypto/x509)

- Parses ML-DSA certs without error; reports sigAlg=0, pubKeyAlg=0 (unknown).
- Verification of pure and mixed chains fails with
  `x509: certificate signed by unknown authority`. The error is misleading: the
  cause is unsupported algorithm, but the text sends operators to debug trust
  stores. Error-quality is a matrix column for exactly this reason.
- Catalyst chain: verify OK. Go ignores the unknown non-critical extensions.

Combined with OpenSSL's identical behavior, two independent stacks confirm the
industry's core hybrid claim ("classical clients ignore the alt extensions")
tonight. Eight stacks to go.

## rustls posture (Reported, not yet tested here)

ML-DSA support sits behind the aws-lc-rs-unstable feature (rustls docs; aws-lc-rs
issue #773 and imported mldsa-native backends). Phase 2 tests both with and without
the flag; the flag state IS the matrix cell.

## Phase 1 results (run the same night, see ../SIZES.md)

- Full corpus minted: ML-DSA-44/65/87, SLH-DSA-SHA2-128s root variant, control,
  mixed, SAN ladders. All verify. Generator: `../gen/mint-corpus.sh`.
- The book's constant replicates at corpus level: +5,127 bytes per leaf across the
  1-to-150 SAN ladder.
- **Same-weight finding:** pure ML-DSA-65 leaf 5,591 B, composite 5,628 B, catalyst
  5,736 B. The three deployment shapes are within 150 bytes of each other; the
  choice is about who can validate, not wire cost.
- **SLH-for-roots hidden cost:** the root's 7,856-byte SLH-DSA signature rides on
  the intermediate, which IS sent: slhroot is the most expensive chain measured
  (15,703 wire bytes), above pure ML-DSA-87.
- **Error-quality pattern, two stacks:** Go reports ML-DSA chains as
  `certificate signed by unknown authority`; OpenSSL reports the composite cert as
  `unable to get local issuer certificate` (with X509_PUBKEY_get0 decode errors
  underneath). Both errors point operators at trust stores when the cause is
  algorithm support.

## Phase 1 notes

- Add SLH-DSA root variant to the corpus generator (cheap now, matches the
  "SLH-DSA for roots" practitioner rule).
- Composite via Bouncy Castle: budget one evening, pin BC and draft versions in
  the evidence.
- The catalyst TBS-stripping verifier (proves the alt signature independently)
  becomes a small reusable tool in Phase 2.
