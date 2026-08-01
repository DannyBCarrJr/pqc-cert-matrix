# Prior art, per finding

Searched 2026-07-31, after the v1 fleet was complete. Purpose: decide what this
project may claim as new. Verdicts are conservative on purpose. Anything marked
PREEMPTED or WEAKENED must be cited rather than claimed, in the article and
anywhere else.

## PREEMPTED, cite instead of claim

**Same-weight finding (pure vs composite vs catalyst leaves within ~150 bytes).**
Preempted by *Beyond Size: Do Hybrid PQC Certificates Actually Enforce the
Classical-PQC Binding? A Cost-and-Security Study*, Lee, Sim, Eum, Cho, Hyoung,
Seo, IACR ePrint 2026/1416, 2026-07-16 (https://eprint.iacr.org/2026/1416).
They measure Catalyst, Composite, Chameleon, and signature combiners and report
strategy sizes differing by under 4.4%. Our 150-byte spread is the same result
found independently two weeks later. Cite them; our contribution is at most a
replication on a different corpus.

**"Classical verifiers ignore the catalyst alt-extensions."** Same paper: nine
verifiers skip the ignored non-critical extensions. They also go further than we
did, with a security result we do not have: no stack can *mandate* the
classical-PQC binding, Bouncy Castle accepts a forged ML-DSA alt signature on its
default path, and wolfSSL cannot require an alt signature, so a stripped
certificate is silently accepted. Read this paper in full before publishing
anything about catalyst.

## WEAKENED, state precisely or not at all

**The Windows CNG/schannel split.** Microsoft's own scoping already says
schannel's post-quantum work is ML-KEM *key exchange* (KB5101650, July 2026
updates, three configurable ML-KEM groups, off by default, TLS 1.3 only), while
ML-DSA landed in CNG and AD CS issuance (GA May 2026, Windows Server 2025).
So a schannel client refusing an ML-DSA server certificate is the documented
scope boundary, not a hidden defect. What still appears unpublished is the
*measurement*: the exact failure mode (SSPI 0x80090326) and the asymmetry
demonstrated on one box, where the certificate stack validates the same chain the
TLS stack will not complete a handshake for. Publish it as a measured
demonstration with operational consequence, never as "we discovered Windows is
broken."

**Runtime beats distro.** The principle is documented for ML-KEM key exchange
(Node bundles its own OpenSSL: 20 ships 3.0.x and falls back to classical, 22
ships 3.5.x and negotiates X25519MLKEM768; Python normally links the system
OpenSSL). Our version concerns ML-DSA *certificate validation* rather than key
exchange, and the cross-stack measurement seems unpublished, but the idea is
well-trodden. Frame as confirmation, not discovery.

## UNVERIFIED, do not claim until checked

**SLH-DSA root wire cost** (root signature rides on the transmitted
intermediate, making slhroot the most expensive chain measured). arXiv 2604.06100
(*Signature Placement in Post-Quantum TLS Certificate Hierarchies*) covers
signature placement, chain and transport sizes, and has a section on placement,
exposure, and operational cost. The PDF text did not extract, so overlap is
unknown and plausibly high. Read the paper properly before claiming this.

## STILL APPEARS UNPUBLISHED

**A measured TLS 1.3 handshake compatibility matrix across many client stacks.**
The nearest neighbours each miss a different axis: IETF-Hackathon/pqc-certificates
does provider-to-provider *artifact* interop (certificates, CMS, CMP, JOSE/COSE)
rather than client TLS behaviour; PKI Consortium PQCCM is vendor self-reported and
explicitly not tested; IACR 2026/1416 analyses verifiers, not live handshakes;
arXiv 2604.06100 measures one stack (OpenSSL plus oqsprovider). No cross-stack
handshake matrix surfaced in any search.

**Measured schannel behaviour against an ML-DSA server certificate**, with the
error code. Nothing found, including in Microsoft's own material.

**Error-message taxonomy across stacks for the same unsupported-algorithm cause.**
Nothing found. Java's `signature check failed` wording (identical to a tampered
certificate) and rustls being the only stack that names the rejected OID and
lists supported algorithms both look unpublished.

## Adjacent work worth citing

- OpenSSL issue #28762, "ML-DSA signatures with not matching schemes in TLS are
  accepted": active correctness work in the same area.
- draft-reddy-tls-composite-mldsa (at -10): composite ML-DSA in TLS 1.3 is still
  an active draft, which is the standards-side explanation for our composite row
  failing everywhere.
- Bouncy Castle PQC Almanac: implementation-status reference.
