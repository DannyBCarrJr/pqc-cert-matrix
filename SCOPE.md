# Hybrid certificate compatibility matrix, v1 scope

Drafted 2026-07-31. Status: **PHASES 0, 1, AND 2 COMPLETE (2026-07-31, one evening)**.
All five rows CONSTRUCTED including composite (BC 1.82, draft-07 OIDs). Corpus +
size tables at repo root (`SIZES.md`); findings in `phase0/FINDINGS.md`
(same-weight finding, SLH-root hidden wire cost, misleading-error pattern).
Moved out of pqc-lab into this dedicated repo 2026-07-31 (private until Phase 4).
All ten v1 client columns populated (80 cells, MATRIX.md).
schannel isolation CLOSED 2026-08-01 (`isolation/FINDINGS.md`): the ML-DSA
failure replicates against a second server implementation (bctls 1.82) and the
decoded ClientHello shows no ML-DSA signature scheme offered, so the causal
claim is publishable.
**Article 3 PUBLISHED 2026-08-01**: "Hybrid certificates, weighed" at
carrdigital.dev/writing/hybrid-certificates-weighed/ (carr-digital `790657d`),
built on the corrected PRIOR-ART thesis and citing all three papers. It states
publicly that this repo's scripts and evidence publish once the transport
measurements are done, so Phase 3 is now a commitment, not an option. Add the
repo link back into the article when Phase 4 lands.
**Phase 3 COMPLETE 2026-08-01** (`phase3/FINDINGS.md`, `phase3/TRANSPORT.md`):
compression measured offline and on the wire, key-log-decrypted captures
attributing every handshake message, congestion window analysis. Headline: the
extra round trip starts at ML-DSA-65. Two open items recorded rather than
guessed: why certificate compression never engages on stock OpenSSL, and a
prior-art check owed on the compression constant.
**Phase 4 DONE 2026-08-01.** Repo is PUBLIC at
github.com/DannyBCarrJr/pqc-cert-matrix, MIT. Before the flip, a pre-publication
audit found the checkout path (`/home/<alias>`) baked into 25 places across 11
evidence files AND into git history. Fixed at the source (the harness now redacts
the checkout path at collection, so future runs cannot reintroduce it), scrubbed
from all history with git-filter-repo, then the remote was deleted and recreated
so no pre-rewrite SHA survives. Verified with the same positive control used in
July: five old SHAs 404, current HEAD resolves. Article 3 now links the repo.
Remaining Phase 4 item: cross-links from the whitepaper and the public lab repo.
Owner: Danny. Flagship candidate for the "operational evidence layer" strategy;
feeds article 3 and the public lab repo.
**Compression addendum 2026-08-09** (`phase3/compressibility.py`): the ML-DSA
signature and SPKI now get compressed on their own, and every RFC 8879 algorithm
returns them 4 bytes larger. That is the assumption behind article 7, "The same
985 bytes" (carrdigital.dev/writing/the-same-985-bytes/), whose corpus half lives
in pqc-chain-budget. It also closed the caveat in `PRIOR-ART.md`: the 240-byte
constant here is a floor for these minimal lab chains and was low by 4x against
985 bytes on 8,152 real ones. Cite 985 for the real web, 240 only for the lab.

## The question v1 answers

Vendors are shipping "hybrid PQC certificates" (AppViewX and Sectigo announcements,
week of 2026-07-27) with zero published measurements. When a post-quantum or hybrid
certificate chain hits real client software, what actually happens? Parse failure,
validation failure, silent ignore, clean handshake? At what byte cost on the wire?
Nobody has published a reproducible answer across stacks. Every cell in this matrix is
a script plus captured output, labeled Verified, rerunnable by any reader. That
standard is the moat; a matrix without evidence is just another vendor table.

## What "hybrid certificate" means here (rows of the matrix)

Chain types, in v1 feasibility order:

1. **Classical baseline:** ECDSA P-256 chain (root, intermediate, leaf). Control row.
2. **Pure ML-DSA:** ML-DSA-44/65/87 chains. Stock OpenSSL 3.5.5 mints these today
   (the book's size measurements already did leaf-level work; chains extend it).
3. **Catalyst-style hybrid:** classical cert carrying the PQ material in the
   non-critical alternative-signature extensions (ITU-T X.509 s9.8:
   subjectAltPublicKeyInfo, altSignatureAlgorithm, altSignatureValue). Must be
   hand-constructed (script with pyca/cryptography or Bouncy Castle; the alt
   signature covers a modified TBS, so this is real work, budgeted in Phase 0).
   The industry's core compatibility claim, "classical clients just ignore the
   extensions," is exactly the untested claim this row tests.
4. **Composite signatures** (draft-ietf-lamps-pq-composite-sigs, e.g.
   MLDSA65-ECDSA-P256 under one OID): STRETCH. Stock OpenSSL does not mint these;
   Bouncy Castle probably can (UNVERIFIED, Phase 0 checks). If tooling fails, the row
   ships as "not constructible with open tooling as of <date>", which is itself a
   publishable finding against the vendor announcements.
5. **Mixed chains:** classical root signing ML-DSA intermediate and leaf (the
   realistic early-migration shape; roots move last).

SLH-DSA chains: v2. Chameleon/delta certs: v2. IP shape (1 SAN vs many): reuse the
book's SAN ladder only for the size table, not the client matrix.

## Client fleet (columns), v1 cap at ten

Docker CE for version pinning except where noted. Per client, capture: chain parse,
chain validation verdict, TLS 1.3 handshake outcome against a server presenting the
chain, exact error text on failure, and whether alt-extensions were ignored or fatal.

1. OpenSSL 3.0 LTS (the deployed mass) via s_client + verify
2. OpenSSL 3.5.5 (the PQ-aware present), same
3. GnuTLS (gnutls-cli + certtool)
4. Go crypto/tls + crypto/x509 (small test client; Go's PQ cert posture UNVERIFIED,
   Phase 0 checks current state)
5. Java 21 JSSE + keytool
6. .NET 8 on Linux
7. Python 3.x ssl module
8. Node.js 22
9. rustls (small client)
10. **Windows schannel**, tested from the Windows side of this machine via PowerShell
    against the WSL lab server. Nobody publishes schannel PQ behavior; cheapest
    unique row in the whole matrix.

Explicitly out of scope v1 (recorded as limitations, not silently dropped): Apple
SecureTransport/Network.framework (no macOS; iPhone-against-lab-endpoint is a v2
stretch), NSS/Firefox (v2), embedded stacks (mbedTLS, wolfSSL, v2), HSM key storage
(no hardware).

## Transport measurements (the bytes)

Per chain type, one server (nginx against system OpenSSL 3.5.5; openssl s_server as
fallback for chains nginx refuses), captured with tshark:

- Certificate message size and total handshake bytes
- TLS record count and flight structure; where fragmentation starts
- Does the server's first flight still fit the initial congestion window (the
  "extra round trip" threshold), stated with the measurement, not hand-waved
- QUIC's 3x amplification limit vs chain size: computed analysis in v1, measured
  QUIC handshakes in v2
- With and without TLS certificate compression where the client supports it

## Phases

- **Phase 0, feasibility (one evening):** prior-art sweep first (if a living public
  matrix already exists, pivot to extending it and say so). Then: mint one cert of
  each type or record exactly what fails; pick the catalyst construction tool; check
  Go/rustls current PQ cert posture. Kill switch: if rows 3 and 4 are both
  unconstructible, v1 ships as pure-ML-DSA matrix plus a "hybrid tooling gap"
  finding, which is still an article.
- **Phase 1, corpus + size table (one weekend):** scripted generation of all chains
  (`gen/`), DER size table extending the 5,125-byte constant to chain level.
- **Phase 2, client matrix (two to three weekends):** Docker fleet, one runner script
  per client, results as machine-readable JSON plus captured raw output in
  `evidence/`. Matrix table generated from JSON, never hand-edited.
- **Phase 3, transport (one to two weekends):** tshark captures per chain,
  fragmentation and flight analysis.
- **Phase 4, publish:** flip THIS repo public (history is matrix-only by
  construction), article 3 on carrdigital.dev with the first findings, links from
  the whitepaper and the public lab repo. Nothing enters the registered book
  manuscript (content freeze is load-bearing).

Ship article 3 after Phase 2 even if Phase 3 slips; client behavior alone is the
story vendors aren't telling.

## Acceptance criteria for "v1 done"

Every matrix cell is one of: Verified (script + output in evidence/), or an explicit
"not constructible / not testable" with the reason. No blank cells, no recalled
claims. A reader with Docker and OpenSSL 3.5 can rerun any cell in under an hour.

## Standing constraints

- All work on this machine, personal lab only; no employer material, tooling, or
  vendor-relationship knowledge. Public specs and open tooling exclusively.
- No vendor product testing in v1 (no AppViewX/Sectigo/etc. accounts): the matrix
  tests open-source stacks, so every cell stays reproducible by a stranger with no
  accounts.
- Writing style rules apply to everything published.
