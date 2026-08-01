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

## Phase 2 early findings (first four client columns, 2026-07-31)

- **Parsing never fails.** Every client parses every chain, composite included.
  PQ certificates break validation, not parsers.
- **Catalyst full-passes everywhere measured** (GnuTLS, OpenSSL 3.0/3.5, Go):
  offline verify AND completed TLS 1.3 handshake. The hybrid compatibility claim
  is now measured, not asserted.
- **Composite validates nowhere**, including OpenSSL 3.5. Mintable (Bouncy
  Castle) but not consumable by any TLS stack tested so far.
- **The false-ok:** OpenSSL 3.0 s_client prints `Verify return code: 0 (ok)` on
  a handshake that died at alert 40 before any certificate was exchanged
  (evidence: results/evidence/mldsa65/openssl-3.0/handshake.txt). Health checks
  grepping the verify line pass on a dead connection.
- **Trust-anchor semantics diverge.** Go verifies the self-signed composite cert
  while reporting its algorithms as unknown: Go does not validate signatures on
  certs already in the root pool (axiomatic trust). OpenSSL and GnuTLS attempt
  to use the unknown key and fail. "Verify" does not mean the same thing across
  stacks for self-signed PQ certs.
- **Error text quality, ranked worst to least bad** for the same root cause (no
  ML-DSA support): Go handshake `remote error: tls: handshake failure`; GnuTLS
  `certificate is NOT trusted`; Go verify `certificate signed by unknown
  authority`; Java `CertPathValidatorException: signature check failed`;
  OpenSSL `X509_PUBKEY_get0 decode error` (at least it points at the key). None
  name the algorithm. **Java's is the most dangerous of the five**: "signature
  check failed" is the exact wording for a tampered or corrupt certificate, so
  an unsupported algorithm looks like an attack in the logs.
- **The runtime you deploy on matters more than the OS you deploy to.** Node 22
  (bundled OpenSSL 3.5.7) and Python 3.13 (linked 3.5.6) validate and complete
  handshakes on every ML-DSA chain, while Ubuntu 24.04's system OpenSSL 3.0 and
  GnuTLS fail all of them on the same host. An app's PQ readiness is a property
  of its runtime's crypto, not of the distro.
- **Python's stdlib has no offline chain-verification API at all** (skip, not
  fail). Code that needs to validate a chain outside a TLS connection reaches
  for a third-party library, which moves the PQ question to that dependency.
- **Strict mode is a real hybrid tripwire.** Python 3.13's default context sets
  `VERIFY_X509_STRICT`, which enforces RFC 5280 hygiene. The first catalyst cert
  built here (pyca, no SKI/AKI, because OpenSSL adds them automatically and pyca
  does not) failed Python's handshake with `Missing Authority Key Identifier`
  while passing all six other clients. Fixed by adding SKI/AKI in
  `catalyst_build.py` so the row isolates alt-extension handling; recorded
  because tooling that hand-builds hybrid certs can trip exactly this way, and
  the error names an extension rather than the real hygiene gap.
- **Node's `X509Certificate.verify` is a signature check, not path validation.**
  It returns true for ML-DSA chains via bundled OpenSSL 3.5, but it does not
  apply constraints, validity, or policy. The matrix marks it ok with this
  caveat; treat Node's verify column as weaker evidence than PKIX columns.
- **Java is the only client that surfaces the algorithm anywhere.** Its parse
  output prints the raw OID (2.16.840.1.101.3.4.3.18 for ML-DSA-65,
  2.16.840.1.114027.80.9.1.8 for the BC composite) instead of a name, because
  JDK 21 has no table entry for it. An operator with the OID can at least search
  for it; every other client discards the identity entirely.

## schannel / Windows CNG (build 26200, Windows 11 25H2) — the headline column

Tested from the Windows side of the machine via PowerShell against the WSL
`openssl s_server`. Nobody publishes this; every cell here is new.

- **The two halves of Windows crypto disagree.** CNG (the certificate stack)
  offline-validates ML-DSA-44/65/87 chains: `X509Chain.Build` returns true with
  only `UntrustedRoot` (the expected private-root artifact). schannel (the TLS
  stack) cannot handshake any of them: `AuthenticateAsClient` throws SSPI
  `SEC_E_MESSAGE_ALTERED` (Win32 0x80090326, "message received was unexpected or
  badly formatted") when the server sends an ML-DSA CertificateVerify. So on the
  same box, `certutil`-style cert validation says ML-DSA is fine while a TLS
  client refuses the connection. An inventory tool that checks cert parsing will
  green-light a rollout that then fails at the handshake.
- **CNG's PQ support is partial and silent about it.** ML-DSA validates;
  SLH-DSA and composite both throw `CryptographicException: Invalid algorithm
  specified` from the same `Build` call. "PQC support" on Windows is per-algorithm,
  not a single switch.
- **Catalyst is the only PQ-bearing chain that fully works on schannel.** It
  completes a real TLS 1.3 handshake (proto=Tls13, AES-256) because schannel sees
  an ordinary ECDSA cert and ignores the ML-DSA alt-extensions. On a TLS stack
  that cannot do post-quantum authentication yet, the classical-carrier hybrid is
  the only design that connects today. That is the strongest operational argument
  for catalyst-style certs, and it is measured, not asserted.
- **Registry lies:** `ProductName` still reads "Windows 10 Pro" on this Windows 11
  build; the runner reports `DisplayVersion` + `CurrentBuild` (25H2 / 26200)
  instead. Noted so the evidence is not misleading.
- **Tooling honesty note:** for the self-signed composite cert, PowerShell's
  `-File` host exits 0 with no output even though `Build` throws (confirmed via an
  inline `-Command` run). The runner backfills the confirmed error rather than
  record a blank cell; see `runners/schannel/run.sh`.

## Phase 1 notes

- Add SLH-DSA root variant to the corpus generator (cheap now, matches the
  "SLH-DSA for roots" practitioner rule).
- Composite via Bouncy Castle: budget one evening, pin BC and draft versions in
  the evidence.
- The catalyst TBS-stripping verifier (proves the alt signature independently)
  becomes a small reusable tool in Phase 2.
