# Prior art, per finding

Searched 2026-07-31; updated the same day after reading IACR ePrint 2026/1416 in
full. Purpose: decide what this project may claim as new. Verdicts are
conservative on purpose. Anything marked PREEMPTED or CORRECTED must be cited or
fixed, never claimed.

## The paper that changes this project's thesis

*Beyond Size: Do Hybrid PQC Certificates Actually Enforce the Classical-PQC
Binding? A Cost-and-Security Study.* Minwoo Lee, Minjoo Sim, Siwoo Eum, Subeen
Cho, Yulim Hyoung, Hwajeong Seo (Hansung University). IACR ePrint 2026/1416,
2026-07-16. https://eprint.iacr.org/2026/1416

Their result: hybrid strategies mostly do not enforce the classical-PQC binding
they promise. Nine standard verifiers (OpenSSL, Go, Botan, GnuTLS, mbedTLS, NSS,
**Windows CryptoAPI**, Java SUN, BouncyCastle) silently accept a Catalyst
certificate whose ML-DSA alternative signature is garbage or forged, because a
non-critical extension is ignored by mandate. BouncyCastle accepts a forged alt
signature on its default JCA path and rejects the same certificate through its
opt-in API. wolfSSL, the only stack that checks a present alt signature by
default, cannot *require* one, so a stripped certificate is accepted (that
experimental path also shipped CVE-2026-5393). Composite binds structurally:
three verifiers across three OID families reject corruption of either half, but
those families do not cross-verify. Their conclusion is that Catalyst's
compatibility advantage is not a security equivalence, and pricing enforcement in
removes Catalyst from the top rank.

**Why this matters here.** Our matrix measured that Catalyst passes everything.
Their paper measured *why* that is dangerous. Read together, the honest thesis is
sharper than either alone: **the one hybrid design that works on every stack is
the one whose post-quantum half no deployed verifier checks.** Article 3 should
be built on that sentence, citing 2026/1416 for the security half and
contributing the live-handshake half.

## PREEMPTED, cite instead of claim

**Same-weight sizes.** They report the five strategies clustering in 5,579 to
5,823 bytes, a 4.4% spread, for the same reason we found (ML-DSA-65's 1,952-byte
key and 3,309-byte signature dominate). Our pure 5,591 / composite 5,628 /
catalyst 5,736 is an independent replication two weeks later, not a discovery.
Their Table 2 also matches our corpus closely on single certificates (ML-DSA-44
3,981 vs our 3,992; ML-DSA-65 5,510 vs 5,521; ML-DSA-87 7,468 vs 7,479;
SLH-DSA-128s 8,129 vs 8,144). Worth reporting as cross-validation of both labs.

**Classical verifiers ignore the catalyst alt-extensions**, including on Windows.
Preempted at the certificate-path layer, and their criticality flip (marking the
same content critical flips accept to reject on Go and Botan) is a cleaner
demonstration than anything we ran.

**Also relevant prior art they cite:** Ricchizzi et al., arXiv:2505.04333,
generate and validate Catalyst/Composite/Chameleon certificates and confirm
functional interoperability. Chen, arXiv:2511.00111, compares the three formats
on size and compute. Dubey and Varshney, arXiv:2606.16473, scanned 32,011 domains
in 2026 and found 49% hybrid PQ key exchange but **0% hybrid PQ certificate
adoption**, which is the best available framing statistic for why this work
matters.

## CORRECTED: a claim of ours that was wrong

**"Composite validates nowhere" is not true, and our framing was misleading.**
2026/1416 shows composite validates correctly and binds structurally within its
own OID family (oqsprovider, BouncyCastle, and the draft-lamps reference
implementation each reject corruption of either half). What actually happened in
our matrix is narrower: we minted with BouncyCastle 1.82 (draft-07 OIDs) and our
fleet contains **no verifier that knows that OID**, since our Java runner uses the
stock JDK SUN provider rather than BouncyCastle. The correct claim is that the
three composite OID families do not cross-verify, which is their finding, and that
our fleet happened to sit entirely outside the minting family. **FIXED 2026-07-31:** added the `bouncycastle` runner column (BC 1.82 as JCA
provider). Composite now verifies in its own family and fails in the other ten
columns, which states the cross-family gap accurately. A negative control
(`composite/negative-control.sh`) proves the passing cell can fail. The composite
row is now publishable.

## WEAKENED, state precisely or not at all

**The Windows CNG/schannel split.** Microsoft's documented scope already puts
schannel's post-quantum work at ML-KEM key exchange (KB5101650, July 2026, off by
default, TLS 1.3 only) while ML-DSA landed in CNG and AD CS issuance (GA May
2026). And 2026/1416 already tested Windows CryptoAPI at the certificate-path
layer. What remains unpublished is narrow but real: the **TLS handshake**
behaviour of schannel against an ML-DSA server certificate, with the failure mode
(SSPI 0x80090326), and the asymmetry demonstrated on one machine. Publish as a
measured demonstration of a documented boundary, never as a discovery.

**Runtime beats distro.** The principle is documented for ML-KEM key exchange
(Node bundles its own OpenSSL; Python normally links the system one). Ours is
about ML-DSA certificate validation instead, and the cross-stack measurement seems
unpublished, but frame it as confirmation.

**The OpenSSL "false ok".** Related but not identical to their live demo, where
`s_client` reports `Verify return code: 0 (ok)` while accepting a PQC-stripped
classical-only certificate (server flight 14,599 vs 18,411 bytes). Ours is that
the same line prints `0 (ok)` after a handshake died at alert 40 with no
certificate exchanged at all. Different mechanism, same misleading field. Cite
theirs alongside ours.

## STILL APPEARS UNPUBLISHED

**A measured TLS 1.3 handshake compatibility matrix across many client stacks.**
2026/1416 is explicitly a certificate-path and tamper study with one live
handshake demo; the IETF Hackathon repo does provider-to-provider artifact
interop; PQCCM is self-reported; arXiv 2604.06100 is single-stack performance. No
cross-stack handshake matrix surfaced in any search.

**schannel's TLS handshake behaviour with an ML-DSA server certificate**, with
the error code. They tested Windows CryptoAPI, not schannel TLS.

**rustls.** 2026/1416 names BoringSSL and rustls as future work. Our rustls column
fills part of a gap its authors flagged, and rustls turns out to have the best
error text in the fleet (names the rejected OID and enumerates supported
algorithms).

**Error-message taxonomy for unsupported-algorithm failures.** Their Table 1
surveys how stacks *surface the alt-signature extension*, which is adjacent but
different from how stacks *report a failure* on a pure ML-DSA chain. Java's
`signature check failed` (identical wording to a tampered certificate) and Go's
`unknown authority` appear unremarked anywhere.

**Go's axiomatic trust of a self-signed certificate in the root pool**, which
makes it report "verify OK" on a composite certificate whose algorithms it cannot
identify.

## RESOLVED: SLH-DSA root wire cost is substantially covered

arXiv 2604.06100 (Jose Luis Delgado, Universitat Oberta de Catalunya, v3
2026-05-19), *Signature Placement in Post-Quantum TLS Certificate Hierarchies*,
read in full 2026-07-31. Its Campaign C measures exactly our slhroot family
(SLH root, ML intermediate, ML leaf) and reports the transport difference
directly: depth 2 reads 39,962 bytes, depth 3 reads 28,947, an 11,015-byte drop,
because at depth 3 the observed chain is intermediate plus leaf and the heavy SLH
root certificate leaves the transmitted set entirely.

Our observation is the same phenomenon and their data supports the mechanism we
described (the SLH signature persists on the transmitted intermediate: their
depth-3 slhroot reads 28,947 bytes against a 16,008-byte all-ML baseline). Cite
them; do not claim it. Their treatment is also far deeper than ours, adding
latency, capacity, and cost-per-handshake analysis we did not attempt.

Their headline result is worth citing prominently in article 3 regardless: putting
SLH-DSA in the **leaf** produces a ~1.4 second handshake, roughly 1,700x baseline
latency, with the handshake becoming almost entirely server-bound (server
task-clock ~0.999 of elapsed time) and an infrastructure multiplier around 2,500x
to hold baseline throughput. Confining SLH-DSA to the root, which is what our
slhroot row does, is their "penalized but plausible" class.

## The strongest positioning statement available

**Both papers name this project's axis as their own open work.**

- IACR 2026/1416: "BoringSSL and rustls remain future work."
- arXiv 2604.06100, section 10.2 and 11.3: the study runs on a single stack
  (OpenSSL 3 plus oqsprovider) and states that "repeating the same
  hierarchy-sensitive analysis across other TLS libraries and post-quantum
  integrations would strengthen confidence in the generality of the structural
  findings."

Two independent 2026 papers, one security-focused and one performance-focused,
both stop at the same boundary: one implementation stack, or certificate-path
verification without live cross-stack handshakes. That boundary is exactly what
this repo crosses. Article 3 should say so plainly and cite both.
