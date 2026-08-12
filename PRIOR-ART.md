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
(SSPI 0x80090326 = SEC_E_ILLEGAL_MESSAGE), and the asymmetry demonstrated on one
machine. Since 2026-08-01 the mechanism is measured, not inferred
(`isolation/FINDINGS.md`): schannel's ClientHello offers no ML-DSA signature
scheme, so servers abort at negotiation before any certificate is sent; the
result replicates against two independent server implementations (OpenSSL,
bctls). Publish as a measured demonstration of a documented boundary, never as
a discovery.

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
the error code and the measured negotiation-level mechanism (no ML-DSA in the
ClientHello, verified against two server implementations plus a decoded wire
trace). They tested Windows CryptoAPI, not schannel TLS.

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

## Phase 3, transport (searched 2026-08-01)

Two Phase 3 headlines were checked. **Both are weaker than they looked**, and one
of them would have been an outright overclaim. Neither is dead, but both are now
refinements of published work rather than discoveries.

### Certificate compression: the qualitative claim is PREEMPTED, twice over, by the IETF

- **draft-ietf-uta-pqc-app-03**, *Post-Quantum Cryptography Recommendations for
  TLS-based Applications* (IETF UTA working group): certificate compression's
  "impact on PQ or PQ/T hybrid certificates is limited due to the larger sizes of
  public keys and signatures."
- **draft-ietf-tls-cert-abridge-02**, *Abridged Compression for WebPKI
  Certificates*: "most of the size of the certificate is in high entropy fields
  such as cryptographic keys and signatures", and post-quantum certificates
  "cannot be compressed with existing TLS Certificate Compression schemes."

That is our finding, stated in two IETF documents. The entire existence of
cert-abridge, and of Merkle Tree Certificates, is the standards community routing
around this exact problem. **Never present "compression does not help post-quantum
certificates" as a discovery.** Cite the drafts.

**What survives, narrowly.** No source found reports the saving as a
*size-independent constant*, and none decomposes it. Our contribution is
therefore the quantification, not the conclusion: roughly 240 bytes recovered from
every chain from 900 to 15,703 bytes, split into roughly 100 bytes inside the
certificates and roughly 140 across them, with the single self-signed composite
row saving exactly 0 across certificates as the control for the second term.

**A limitation the prior art exposes, and this must be stated wherever the number
appears.** cert-abridge reports a WebPKI median chain of 4,032 bytes compressing
to 3,243 with zstd, a saving of 789 bytes, more than three times our 240. Our
corpus is minimal by construction: short DNs, one SAN, two certificates, no SCTs,
no OCSP or CRL URLs. Real WebPKI certificates carry far more compressible
structure. **Our constant is a floor for minimal certificates, not a WebPKI
figure**, and publishing it without that caveat would understate compression's
real-world value and invite a correct rebuttal.

**That limitation is now closed, 2026-08-09, and the floor was low by a factor of
four.** `pqc-chain-budget/src/compress_chains.py` ran the same decomposition over
the 8,152 real chains that repo captured: median saving 985 bytes (28.6%), or 942
bytes with zstd alone against cert-abridge's 789. The decomposition also inverts
in scale, 515 bytes within certificates and 442 across them, against 100 and 140
here. Real certificates carry SANs, SCTs, and CRL URLs, and all of it compresses.
**Cite the 985-byte WebPKI figure, not the 240-byte lab constant, whenever the
subject is the real web.** The 240 remains correct for these minimal lab chains
and is what makes the size-independence visible, since it holds from 900 to
15,703 bytes of chain. Both numbers are real; they answer different questions.

### The extra round trip: PREEMPTED as a concept, survives only as a refinement

**Chou and Cao, arXiv:2604.24869, 2026-04-27**, *Network Impact of Post-Quantum
Certificate Chain sizes on Time to First Byte in TLS Deployments*. They already
do the congestion-window analysis: RFC 6928, "the initial congestion window (IW)
caps first-RTT transmission at 14KB, requiring an extra RTT if exceeded", with
measured RTT spikes "around 10KB and 40KB" of certificate chain. ML-DSA-44 with
one intermediate (about 7.9 KB) incurs no extra round trip; an SLH-DSA leaf at
16.6 KB does, raising time to first byte "by up to 1.5x". **They measured TTFB.
We deliberately did not measure latency at all.**

So "post-quantum chains blow the initial congestion window" is theirs, and our
ML-DSA-44-fits result is an independent replication of their result rather than a
new one.

**What survives.** They analyze the **certificate chain**, and they do not measure
CertificateVerify separately. The congestion window constrains the **server's
flight**, which is chain plus CertificateVerify plus ServerHello, EncryptedExtensions
and Finished. Our per-message attribution measures that difference directly:
mldsa65's chain is 11,170 bytes but its flight is 15,739, because CertificateVerify
adds 3,313. A threshold stated on chain size therefore understates the flight by
roughly one signature, which is 2,424 to 4,631 bytes across our corpus, and can
put a chain on the wrong side of a 14,600-byte window. That refinement is worth
publishing. The bare threshold claim is not.

### Re-verified 2026-08-01 against full texts, not summaries. Two more claims demoted.

Every source below was downloaded and searched directly, because an earlier pass in this
project relied on a summary and got a claim backwards. Method: fetch, strip markup, grep.

**Kampanakis and Childs-Klein (AWS), NDSS MADWeb 2024, "The impact of data-heavy,
post-quantum TLS 1.3 on the Time-To-Last-Byte" (eprint 2024/176).** Not previously in this
file, and it preempts more than the 2026 papers do. Verified in their text: they name
Certificate and CertificateVerify as "the largest messages", which "carry a certificate
chain and a signature of the TLS transcript"; they state that if those "message sizes were
to grow significantly, handshake speed would be impacted"; and they explicitly explore
"tweaking the TCP initial congestion window initcwnd" to compensate.
**Consequence: "CertificateVerify is large in post-quantum TLS" has been public since 2024
and must never be presented as a discovery.** Neither must "post-quantum handshakes
interact badly with the initial congestion window."

**Delgado Jiménez, arXiv:2604.06100.** Verified by grep: mentions CertificateVerify once,
descriptively, and reports **no byte figure for it**. A web summary attributed "3,309
bytes of CertificateVerify" to this paper; that is **not in the paper** and the attribution
was wrong. His measured transport variables are `bytes_read_mean`, `bytes_written_mean`,
`chain_bytes_unique` and `served_chain_der_bytes`, so aggregate and chain-level, not
per-message. He mentions congestion window **zero times**.

**Chou and Cao, arXiv:2604.24869.** Verified by grep: **zero occurrences of
"CertificateVerify"** in the full text. Their framing throughout is "certificate chain
sizes exceed transport layer data flight limits", and they cite the IW cap at 14KB.

### What survives Phase 3, stated conservatively

1. **Per-message byte attribution across a corpus of chain shapes**, from key-log
   decrypted captures. Delgado reports aggregate and chain bytes; Chou and Cao report chain
   size against TTFB; Kampanakis varies chain size as an input. None publish a per-message
   table across chain shapes.
2. **The chain-size budget is not a constant, and that is the useful result.** The window
   constrains the flight, and the flight exceeds the Certificate message by a measured
   3,680 bytes (ML-DSA-44) to 5,887 bytes (ML-DSA-87). So the usable certificate budget
   under a 14,600-byte IW10 moves from about 10,920 down to about 8,713 bytes purely as a
   function of which parameter set signs the handshake. This **explains** Chou and Cao's
   empirically observed spike "around 10KB" of chain rather than contradicting it, which is
   how it must be written.
3. **Catalyst's transport profile.** A 7,584-byte flight against pure ML-DSA-65's 15,739,
   because its CertificateVerify is ECDSA at 76 bytes: the post-quantum material is carried
   and never signed with. No prior art surfaced for this. It is also the same property
   article 3 already documented, measured a third way.
4. **Compression: the constant and the decomposition only.** The qualitative claim is
   preempted verbatim by two IETF drafts (quoted below). The 240-byte figure is a floor for
   minimal certificates and must always ship with the cert-abridge comparison.

### Verbatim quotes, checked against the actual draft text

- **draft-ietf-uta-pqc-app-03:** "While effective in many scenarios, its impact on PQ or
  PQ/T hybrid certificates is limited due to the larger sizes of public keys and signatures
  in PQC. These high-entropy fields, inherent to PQC algorithms, constrain the overall
  compression effectiveness."
- **draft-ietf-tls-cert-abridge-02:** post-quantum certificates "will be typically 10 to 40
  times their current size and cannot be compressed with existing TLS Certificate
  Compression schemes because most of the size of the certificate is in high entropy fields
  such as cryptographic keys and signatures."
- **cert-abridge size table** (p5 / p50 / p95, bytes): Original 2308 / 4032 / 5609; TLS
  Cert Compression (ZStandard) 1619 / 3243 / 3821. So 789 bytes saved at the median on real
  WebPKI chains, against our 240 on minimal lab chains.

### Still appears unpublished

Per-message byte attribution across a post-quantum corpus (ClientHello,
Certificate, CertificateVerify, flight total, record structure), from key-log
decrypted captures. Delgado reports aggregate bytes read; Chou and Cao report
chain sizes and TTFB. Neither separates CertificateVerify, which is the term that
matters for the window question.

### Closed 2026-08-10, was "open, not a claim"

Certificate compression never engaged in any **lab** capture despite both peers
advertising zlib and zstd. The hypothesis recorded here, that this Ubuntu build
sends a default preference order led by a brotli it does not carry so negotiation
fails rather than falling through, is **retracted as wrong**. Verified: the client
advertises exactly `zlib (1)` and `zstd (3)`, no order beyond that, and it does
receive a real zstd CompressedCertificate from 3 of the 842 TLS 1.3 servers in the
`pqc-chain-budget` subsample. The lab zero is a server-side property of those lab
servers, not a client defect and not an OpenSSL bug.

Nothing here becomes a novelty claim. Certificate compression on the live web is
already measured at far greater scale by cert-abridge, and the retraction is a
correction to our own record rather than a finding about anyone else's. The one
caveat still worth stating anywhere this is cited: the client offers zlib and zstd
only, so a brotli-only server reads as a non-engagement from this build.

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

**A current, named example of the inventory class this project's headline is
about. Added 2026-08-12.**

The headline here is that parsing never fails, so a parse-based inventory returns
a false pass. Until now that class was described generically. Wiz's PQC readiness
offering is a live instance of it, per its own product page read 2026-08-12: it
inventories by scanning code and container images for "libraries and primitives",
by reading Infrastructure as Code templates and host configuration, by inspecting
cloud services such as "AWS KMS, load balancers, and API gateways", and by
certificate and SSH key inspection covering "their respective algorithms and key
lengths". The page states no limitations.

**Two constraints on using this, both mandatory.**

First, name the method, never the product's competence. The defensible claim is
that configuration and certificate parsing cannot observe what a stack does at
handshake time, which is this repo's measured result across 88 cells. Writing that
a named vendor "has a 100% false-pass rate" asserts something about their product
that this repo has not measured, and it invites a rebuttal that costs more than the
sentence is worth. `AGENTS.md` already bans novelty superlatives here; treat vendor
accusations the same way.

Second, they do ship a live check, and omitting that would be unfair framing. Wiz
offers a separate PQC Tester described as scanning "your domain ... to see if your
server supports PQC key exchanges". That is a real handshake, so the honest
statement is narrower and still holds: the live check covers **key exchange**, and
the certificate path is covered by parsing. Key exchange is the half that already
works and gets measured everywhere; the certificate half is the one this project
found returns a false pass.

Reported, from a vendor page on one date. Vendor pages change without notice, so
re-read it immediately before any article cites it, and record the date read.

### Why the parse-based path is structural rather than lazy. Added 2026-08-12.

This is the strongest available framing for the headline, and it is stronger than
"tools take a shortcut", because it explains why they have no choice.

**In TLS 1.3 the certificate is not on the wire in the clear.** RFC 8446 section
4.4, quoted from the RFC text rather than recalled:

> TLS generally uses a common set of messages for authentication, key
> confirmation, and handshake integrity: Certificate, CertificateVerify, and
> Finished. ... These messages are encrypted under keys derived from the
> [sender]_handshake_traffic_secret.

Figure 1 of the same RFC writes the message as `{Certificate*}`, and its legend
defines `{}` as "messages protected using keys derived from a
[sender]_handshake_traffic_secret."

**The consequence for every inventory tool.** ClientHello and ServerHello are
plaintext, so a passive on-path observer can read `supported_groups`, the
negotiated `key_share`, the cipher suite, and the client's advertised
`signature_algorithms` and `signature_algorithms_cert`. It cannot read the
Certificate message. So passive traffic inspection can establish which key
exchange was negotiated and cannot establish which certificate chain was served.

That is why PQC readiness tooling converges on the same two methods, and it is not
carelessness:

- **Key exchange, measured live**, because it is visible without acting as a
  client. This is what Wiz's PQC Tester does, per the entry above.
- **Certificates, by parsing** files, configuration, and inventories, because that
  is the only remaining source when the wire will not show you.

Which leaves the actual behavior, what a stack does with a chain at handshake
time, reachable **only by completing a handshake as a client**. That is this
repo's method across 88 cells, and this is the argument for why the method is
necessary rather than merely unusual.

**Independent corroboration that the encryption holds in practice**, and not only
on paper: Luke Valenta (Cloudflare), `slides-125-plants-mtc-experiment-early-results-01.pdf`,
IETF 125, 2026-03-14, reporting on MTC served to 1000 Cloudflare-proxied domains
with Chrome as client on 50% of Chrome Beta 146+: "Middlebox interference thus far
is a non-factor (TLS 1.3 encrypts server cert)." A production deployment changing
certificate format entirely and drawing no middlebox reaction is measured evidence
that on-path devices are not reading these certificates.

**Stamps.** The RFC 8446 quotations are Reported, from the RFC text fetched and
grepped on 2026-08-12. The Cloudflare quotation is Reported, from the slide deck
downloaded from ietf.org/proceedings and read the same day. The claim that only an
active handshake reveals served-chain behavior is Verified here, across the 88
cells. The inference joining them, that parse-based inventory is forced rather than
chosen, is **Proposed**: it is an argument from the mechanism, and no tool vendor
has been asked to confirm it is their reason.

Cross-reference: the same mechanism sharpens `pqc-chain-selection`. A passive
observer sees the client's `signature_algorithms_cert` in the plaintext
ClientHello but cannot see which chain the server returned, so it cannot determine
whether the constraint was honored. The request is visible and the response is
not.

## Backported 2026-08-08 from the pqc-chain-budget sweeps

Six sources surfaced while sweeping the sibling project
(github.com/DannyBCarrJr/pqc-chain-budget) that this file was missing and that
bear on this repo's transport phase. Full verdicts and quotes live in that
repo's PRIOR-ART.md; entries here are the short form.

- **Nawrocki et al., CoNEXT 2022 (arXiv:2211.02421).** Real per-site chains,
  1M+ domains, evaluated against QUIC's 3x amplification budget: 35% of server
  certificates exceed it. Classical only (zero "quantum" hits, grepped). The
  nearest published method to any per-site budget analysis; cite wherever
  per-site framing appears.
- **Fastly (McManus), 2024-12-06, QUIC handshake compression study.** ~125,000
  real handshakes classified into three budget buckets (fits / needs
  compression / never fits). Classical only. Owns the per-sample budget
  classification.
- **Sikeridis, Huntley, Ott, Devetsikiotis, ePrint 2022/1556.** Tranco Top 10K
  chain-depth distribution, monthly 2022, plus PQ data-volume extrapolation
  for ICA suppression. The published depth baseline, with the caveat that its
  counting rule is unstated.
- **Kampanakis and Kallitsis, CSCML 2022.** PQ authentication bytes by ICA
  count, color-coded against the 14.5KB window: "When SCTs and/or OCSP staples
  are present Dilithium starts from ~15KB." Preempts any "ML-DSA-44 fits"
  framing stated without an SCT qualifier.
- **Cloudflare (Westerbaan and Valenta), 2024-11-07 and the 2025 state post.**
  Production-fleet median chain 3.2kB joined to an ML-DSA projection ("more
  than double the number of transmitted bytes" per non-resumed QUIC
  connection). Kills any "no one has projected PQ sizes on real chains" claim.
- **Kampanakis and Anastasova, PKIC PQC Conference 2025-01.** 15 named real
  sites through webpagetest.org with a constant +15KB PQ delta; per-site
  presentation on real sites exists in public.
- **Yao et al., "Chaos in the Chain", ACM IMC 2025 (10.1145/3730567.3732921).**
  Tranco 1M chain completeness: 89.9% omit the root, 1.3% serve no
  intermediate, 8.7% transmit the root. Zero PQ or size content. The current
  large-scale deployment baseline.
- **Ristic (Red Sift), 2026-08-03.** Modeled-chain arithmetic: the ML-DSA
  cryptography alone busts the 14KB window; closes by announcing a measured
  follow-up.

## Backported 2026-08-10 from the pqc-chain-selection re-sweep

One source, and it is a naming correction rather than a threat to any claim
here. Surfaced by a structured Crossref bibliographic query in the sibling
project (github.com/DannyBCarrJr/pqc-chain-selection), which four earlier web
and arXiv sweeps had missed. **Method note worth carrying: a Crossref query
indexes every publisher with a DOI, including ACM, and should lead future
sweeps in this repo ahead of web search.**

- **Paul, S., Kuzovkova, Y., Lahr, N., and Niederhagen, R. "Mixed Certificate
  Chains for the Transition to Post-Quantum Authentication in TLS 1.3."
  AsiaCCS 2022, pages 727 to 740. DOI 10.1145/3488932.3497755, also IACR
  ePrint 2021/1447.** They defined "mixed certificate chains" as using
  different signature algorithms within one certificate chain, and measured
  handshake time, communication size, code size, and peak memory with custom
  client and server programs on embedded targets. Their finding is that
  hash-based schemes at the root CA level only still give feasible connection
  establishment times.

  **This repo mints a chain it calls `mixed` (classical root over ML-DSA) and
  did not cite them.** That shape is an instance of their concept, inverted:
  they put the slow conservative algorithm at the root, this corpus puts the
  classical one there. Cite them wherever the term appears. They do not
  preempt anything measured here, because this repo measures client
  verification behavior across eleven stacks and they measured handshake cost
  on their own programs. Stamp: Reported, abstract and the authors' 2023 PKI
  Consortium deck read, ACM full text not obtained.
