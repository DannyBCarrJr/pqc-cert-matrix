# Phase 3 findings: transport

Run 2026-08-01. Phase 3 measures what post-quantum chains cost on the wire, as
opposed to Phase 2's question of whether clients accept them at all.

Status: **all three steps complete.**

1. Certificate compression (RFC 8879) against the corpus. DONE, below.
2. Captured, key-log-decrypted handshakes: per-message byte attribution and TLS
   record structure. DONE, `TRANSPORT.md`.
3. Initial congestion window analysis computed from step 2. DONE, `TRANSPORT.md`.

> **Novelty check owed before any of this is published.** That post-quantum keys
> and signatures are incompressible is a widely stated intuition, so the
> contribution here is the measured constant and the mechanism split, not the
> intuition. Add a section to `PRIOR-ART.md` before this reaches an article, the
> same way the Phase 2 claims were checked and two of them corrected.

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

## Operational reading

Certificate compression is worth enabling, because 240 bytes is free and it
recovers a quarter of a classical chain. It is not a post-quantum mitigation. Any
migration plan whose bloat answer is "we will turn on certificate compression"
is planning to recover 1.5 to 3% of the problem it is describing.

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

## The extra round trip starts at ML-DSA-65

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
certificate compression does not engage. **Cause not isolated:** OpenSSL developer
man pages are not installed on this host, so attributing it to the build, to
`s_server`, or to a negotiation detail would be a guess. Open item for v2, worth
retesting against a second server implementation.

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
