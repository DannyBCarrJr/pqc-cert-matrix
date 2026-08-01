# schannel isolation: the failure is negotiation, not verification

Run 2026-08-01. Question: every Phase 2 handshake ran against one server
(OpenSSL 3.5.5 `s_server`), so the schannel failure on ML-DSA chains
(SSPI 0x80090326) could not be separated from that server's negotiation
behavior. This study separates them with a second, independent server
implementation and a decoded wire trace.

## Method

1. A TLS 1.3 server on Bouncy Castle's own TLS stack (bctls 1.82, JDK 21,
   `bctls-server/`), which shares no code with OpenSSL. bctls 1.82 carries the
   ML-DSA signature schemes as non-draft constants (mldsa44/65/87 =
   0x0904/0x0905/0x0906 in `org.bouncycastle.tls.SignatureScheme`).
2. Per chain: an OpenSSL 3.5.5 `s_client` control proves the server works
   before schannel is judged, then the schannel handshake reruns through the
   same `schannel.ps1` used in Phase 2. Orchestration: `run-isolation.sh`.
3. A rerun of the original failing pair (schannel vs `openssl s_server`) with
   `-trace`, which decodes the ClientHello and the server's response in
   plaintext. The handshake dies before any encryption starts, so the trace is
   complete evidence and no packet capture is needed.

## Results (evidence/<chain>/)

| Chain | openssl 3.5.5 control vs bctls | schannel vs bctls |
|---|---|---|
| ecdsa | ok | **ok** (TLS 1.3, AES-256) |
| mldsa44 / 65 / 87 | ok, `Signature type: mldsa*` | fail, 0x80090326 |
| slhroot | ok | fail, 0x80090326 |
| mixed | ok | fail, 0x80090326 |
| catalyst | ok | **ok** (TLS 1.3, AES-256) |

Identical pass/fail pattern and identical error code as Phase 2 against
OpenSSL. The server implementation does not change the outcome.

## The measured causal chain

The `-trace` rerun (`evidence/mldsa65/openssl-trace.txt`) shows the whole
mechanism in plaintext:

1. **schannel's ClientHello offers no post-quantum signature scheme.** Its
   signature_algorithms extension lists 12 schemes, all classical: RSA-PSS,
   RSA-PKCS1, ECDSA P-256/384/521, and legacy SHA-1 entries including
   `dsa_sha1`. No 0x0904/0x0905/0x0906. supported_groups is classical too
   (x25519, P-256, P-384) in this SslStream profile. The ecdsa control trace
   (`evidence/ecdsa/openssl-trace.txt`) shows the same 12-scheme hello in a
   run that succeeds, so the hello does not depend on the server's chain.
2. **A server holding only an ML-DSA credential must abort.** OpenSSL:
   `tls_choose_sigalg:no suitable signature algorithm`, then a fatal
   `handshake_failure(40)` alert immediately after the ClientHello. bctls:
   `found no selectable cipher suite among the 20 offered`, same alert (BC
   couples TLS 1.3 suite selection to having usable signing credentials).
   **Neither server ever sent a ServerHello, Certificate, or
   CertificateVerify.**
3. **schannel reports the alert as a malformed-message error.** Alert 40
   arriving where ServerHello was expected surfaces as SSPI 0x80090326,
   which is `SEC_E_ILLEGAL_MESSAGE` ("the message received was unexpected or
   badly formatted", confirmed on this box via `certutil -error`). Phase 2
   notes called the constant SEC_E_MESSAGE_ALTERED; that was wrong
   (SEC_E_MESSAGE_ALTERED is 0x8009030F) and is corrected everywhere.

So the corrected claim, now causal and measured: **schannel (SslStream
profile, Windows 11 25H2 build 26200) cannot connect to ML-DSA-authenticated
servers because it never offers an ML-DSA signature scheme in the first
place.** The failure happens at negotiation, before any certificate crosses
the wire. The earlier phrasing ("throws when the server sends an ML-DSA
CertificateVerify") described a message that was never sent and is retracted.

This matches Microsoft's documented scope (KB5101650: schannel PQ work is
ML-KEM key exchange; ML-DSA lives in CNG/AD CS), which is exactly why it is
published as a measured demonstration of a documented boundary, not a
discovery. Note the profile caveat: this hello is what .NET Framework
SslStream requested from schannel on build 26200 with defaults; other schannel
consumers or policy configurations could advertise differently.

## Side findings

- **bctls 1.82 is a working ML-DSA TLS 1.3 server.** It presented and signed
  with ML-DSA-44/65/87 leaves (and the slhroot chain's ML-DSA-65 leaf), and
  OpenSSL 3.5.5 completed every handshake, reporting `Signature type: mldsa*`
  and `X25519MLKEM768` for key exchange. That is a second server-side ML-DSA
  implementation for the lab, independent of OpenSSL.
- **Error quality, server side:** for the same client, bctls names the
  problem area (no selectable suite given the credentials) while OpenSSL names
  it precisely (`no suitable signature algorithm`). Client side, schannel's
  0x80090326 is corruption-shaped text for a clean negotiation rejection; it
  joins the error-taxonomy list next to Java's "signature check failed".
- **JDK 21 keystores cannot hold ML-DSA private keys** (the JDK gains ML-DSA
  at 24), so the server feeds BCJSSE an in-memory `X509ExtendedKeyManager`
  instead of a keystore. Reusable pattern for any pre-JDK-24 BC TLS work.

## Reproduce

```
isolation/run-isolation.sh    # bctls server image + all chains, both clients
isolation/trace-rerun.sh      # decoded-wire rerun vs openssl s_server -trace
```

Needs the Phase 2 bundles in `results/bundles/` (mint via `gen/mint-corpus.sh`
and `python3 runners/harness.py`), Docker, and the Windows side of the machine
for schannel. All captured output is committed under `evidence/`.
