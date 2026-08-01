# Phase 3 findings: transport

Run 2026-08-01. Phase 3 measures what post-quantum chains cost on the wire, as
opposed to Phase 2's question of whether clients accept them at all.

Status: **all three steps complete.**

1. Certificate compression (RFC 8879) against the corpus. DONE, below.
2. Captured, key-log-decrypted handshakes: per-message byte attribution and TLS
   record structure. DONE, `TRANSPORT.md`.
3. Initial congestion window analysis computed from step 2. DONE, `TRANSPORT.md`.

> **Novelty check DONE 2026-08-01, and it demoted two headlines.** See the
> Phase 3 section of `PRIOR-ART.md`. Short version: "compression does not help
> post-quantum certificates" is stated in two IETF drafts and must be cited, never
> claimed. "Post-quantum chains blow the initial congestion window" belongs to
> Chou and Cao (arXiv:2604.24869), who also measured time to first byte, which we
> did not. What survives is the quantification in both cases, and the caveats
> below are load-bearing.

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

## Prior art, and a caveat that must travel with the number

The qualitative result is not ours. **draft-ietf-uta-pqc-app-03** states that
compression's "impact on PQ or PQ/T hybrid certificates is limited due to the
larger sizes of public keys and signatures", and **draft-ietf-tls-cert-abridge-02**
says post-quantum certificates "cannot be compressed with existing TLS Certificate
Compression schemes". Cite them. What is ours is the constant, the split, and the
composite control.

**The 240-byte constant is a floor for minimal certificates, not a WebPKI
figure.** cert-abridge reports a median WebPKI chain compressing 4,032 to 3,243
bytes with zstd, saving 789 bytes, over three times ours. Our corpus has short
DNs, one SAN, two certificates, no SCTs and no OCSP or CRL URLs, so it carries far
less compressible structure than a real certificate. State this wherever the
number appears.

## Operational reading

Certificate compression is worth enabling, because the bytes are free and it
recovers a quarter of a classical chain. It is not a post-quantum mitigation. Any
migration plan whose bloat answer is "we will turn on certificate compression" is
planning to recover a low single-digit percentage of the problem it is describing,
and that conclusion holds even at the larger WebPKI saving, because the
denominator grows faster than the saving does.

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

## The window constrains the flight, not the chain

**Prior art first, because this one is mostly not ours.** Chou and Cao
(arXiv:2604.24869, 2026-04-27) already measured that post-quantum chains overrun
the initial congestion window, citing RFC 6928's roughly 14 KB first-RTT cap and
reporting round-trip spikes around 10 KB and 40 KB of chain, with an SLH-DSA leaf
raising time to first byte by up to 1.5x. They measured latency. We did not.

Our refinement is the term they leave out. They analyse **certificate chain
size**; the window actually constrains the **server's flight**, which is the chain
plus CertificateVerify plus ServerHello, EncryptedExtensions and Finished. For
mldsa65 that is 11,170 bytes of chain against a 15,739-byte flight, a difference
of one ML-DSA signature. A threshold stated on chain size understates the flight
by 2,424 to 4,631 bytes across this corpus, which is enough to put a chain on the
wrong side of a 14,600-byte window.

Our ML-DSA-44 result below is an independent replication of theirs, not a new
finding.

## Measured on flight bytes, the line falls at ML-DSA-65

Captured handshakes, decrypted with a key log so every message is attributed.
Full table in `TRANSPORT.md`. The server's first flight against a 10-segment
initial congestion window (RFC 6928, 14,600 bytes at a 1460-byte MSS):

| Chain | Server flight | Segments | Fits IW10 |
|---|---|---|---|
| ecdsa | 2,244 | 2 | yes |
| catalyst | 7,584 | 6 | yes |
| mldsa44 | 11,792 | 9 | yes |
| mixed | 12,491 | 9 | yes |
| mldsa65 | 15,739 | 11 | **no** |
| slhroot | 20,286 | 14 | **no** |
| mldsa87 | 20,973 | 15 | **no** |

ML-DSA-44 is the heaviest chain that still fits. From ML-DSA-65 up, the server
cannot finish its flight before waiting on the client's acknowledgement, which
costs a round trip on every full handshake. Segment counts are computed from
measured bytes rather than read off a capture, for the offload reason recorded in
`report.py`.

## CertificateVerify is the cost nobody counts

Certificate size tables stop at the chain. The handshake also carries a
CertificateVerify signature, paid on every full handshake, and it scales with the
signature algorithm:

| Chain | Certificate | CertificateVerify |
|---|---|---|
| ecdsa | 914 | 74 |
| catalyst | 6,252 | 76 |
| mldsa44 | 8,112 | 2,424 |
| mldsa65 | 11,170 | 3,313 |
| mldsa87 | 15,086 | 4,631 |

ML-DSA-87 adds 4,631 bytes of signature on top of its chain, 62 times ECDSA's 74.
Any migration estimate built from certificate sizes alone understates the wire
cost by roughly a signature per handshake.

**This corrects a Phase 1 claim.** `phase0/FINDINGS.md` called slhroot "the most
expensive chain measured" on certificate bytes, which is still true (15,717
against mldsa87's 15,086). At the handshake level it is not: slhroot's leaf is
ML-DSA-65, so its CertificateVerify is 3,313 against mldsa87's 4,631, and the
totals invert to 20,286 against 20,973. The most expensive certificate chain and
the most expensive handshake are different rows.

## Catalyst is half the flight, for the reason it is unprotected

Catalyst's server flight is 7,584 bytes against pure ML-DSA-65's 15,739. Its
certificate is large (6,252 bytes, carrying the ML-DSA key and signature in
extensions) but its CertificateVerify is **76 bytes**, because the handshake is
still authenticated with ECDSA. The post-quantum material is inert: carried, not
used, and therefore not paid for at signing time.

That is the same property measured three different ways now. Catalyst passes
every client because nothing checks its post-quantum half, and it is cheap on the
wire because nothing signs with it.

## Certificate compression is advertised and never delivered here

Measured, and not explained. In every capture the OpenSSL 3.5.5 client advertises
`compress_certificate` (extension 27) offering **zlib (1) and zstd (3)**, and the
same build reports `-DZLIB -DZSTD`. The server nonetheless never sends a
CompressedCertificate (handshake type 25). Three server postures were tried:
default, `-cert_comp`, and `-no_tx_cert_comp`. All three produced a byte-identical
11,170-byte uncompressed Certificate on the mldsa65 chain.

So on a stock distribution OpenSSL, with both peers advertising support,
certificate compression does not engage.

**This contradicts OpenSSL's own documentation**, which says no explicit
configuration is needed: "If a preference order is not specified, then the default
preference order is sent to the peer and the received peer's preference order will
be used when compressing a certificate." That default order is brotli, zlib, zstd.
Documented behaviour and measured behaviour disagree on this build.

**HYPOTHESIS, untested:** this Ubuntu build reports `-DZLIB -DZSTD` and no brotli,
while the default preference order leads with brotli, so the negotiation may fail
rather than fall through to an algorithm both peers actually have. Not published
as a mechanism, and deliberately not called an OpenSSL bug, until it is tested
against a second build. Open item for v2.

Taken with the step 1 numbers, the practical effect is the same either way: had it
engaged, it would have saved about 240 bytes of a 15,739-byte flight.

## Reproduce

```
# step 1, compressibility
python3 -m venv phase3/.venv
phase3/.venv/bin/pip install brotli zstandard
phase3/.venv/bin/python phase3/compressibility.py

# steps 2 and 3, captures and report
python3 phase3/transport.py   # needs dumpcap and membership in the wireshark group
python3 phase3/report.py
```

Needs `results/bundles/` (created by `runners/harness.py`).

The `keys.log` files under `evidence/` are committed on purpose so a reader can
decrypt the captures and check the attribution rather than trust this table. They
are per-session TLS traffic secrets from throwaway lab handshakes against test
certificates, not private keys, and they decrypt nothing but the pcap sitting next
to them.
