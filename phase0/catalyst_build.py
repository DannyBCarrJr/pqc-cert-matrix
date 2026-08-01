#!/usr/bin/env python3
"""Phase 0: construct a catalyst-style hybrid certificate.

Classical ECDSA P-256 leaf carrying ML-DSA-65 material in the three non-critical
ITU-T X.509 s9.8 alternative-signature extensions:
  2.5.29.72 subjectAltPublicKeyInfo   (DER SubjectPublicKeyInfo of the ML-DSA key)
  2.5.29.73 altSignatureAlgorithm     (DER AlgorithmIdentifier, id-ml-dsa-65)
  2.5.29.74 altSignatureValue         (DER BIT STRING, ML-DSA-65 signature)

Per X.509 s9.8 the alt signature covers the TBSCertificate WITHOUT the
altSignatureValue extension. Construction: build the cert twice with identical
serial/validity/extensions, sign the first build's TBS with the ML-DSA key, append
that as the final extension, re-sign classically. A verifier reconstructs the
covered TBS by stripping the last extension (Phase 2 builds that verifier).

pyca/cryptography (46.0.5 here) has no ML-DSA, so key generation and signing shell
out to stock OpenSSL 3.5.5 (pkeyutl -rawin: ML-DSA is a one-shot algorithm).
Issuer: the Phase 0 ECDSA intermediate (mint-phase0.sh must run first).
"""
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier

HERE = Path(__file__).parent
CHAIN = HERE / "chains" / "ecdsa"
OUT = HERE / "chains" / "catalyst"
OUT.mkdir(parents=True, exist_ok=True)

OID_SAPKI = ObjectIdentifier("2.5.29.72")
OID_ALT_ALG = ObjectIdentifier("2.5.29.73")
OID_ALT_SIG = ObjectIdentifier("2.5.29.74")
# AlgorithmIdentifier ::= SEQUENCE { id-ml-dsa-65 }, params absent per FIPS 204 profile
ALT_ALG_DER = bytes.fromhex("300b0609608648016503040312")


def sh(*args: str) -> bytes:
    print("$", " ".join(args))
    return subprocess.run(args, check=True, capture_output=True).stdout


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def issuer_aki(ca_cert) -> x509.AuthorityKeyIdentifier:
    """AKI from the issuer's SKI when it has one, else derived from its key.

    RFC 5280 wants AKI on end-entity certs, and Python 3.13's default context
    enables VERIFY_X509_STRICT, which rejects chains without it. Omitting these
    made the catalyst row fail for a reason unrelated to the alt extensions.
    """
    try:
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value)
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())


def build(extra_ext: x509.UnrecognizedExtension | None, leaf_key, ca_cert, sapki: bytes):
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "matrix-hybrid.test")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(0x504D4D30)
        .not_valid_before(datetime(2026, 7, 31, tzinfo=timezone.utc))
        .not_valid_after(datetime(2026, 7, 31, tzinfo=timezone.utc) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("matrix-hybrid.test")]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(issuer_aki(ca_cert), critical=False)
        .add_extension(x509.UnrecognizedExtension(OID_SAPKI, sapki), critical=False)
        .add_extension(x509.UnrecognizedExtension(OID_ALT_ALG, ALT_ALG_DER), critical=False)
    )
    if extra_ext is not None:
        b = b.add_extension(extra_ext, critical=False)
    return b


def main() -> None:
    ca_key = serialization.load_pem_private_key((CHAIN / "int.key").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((CHAIN / "int.crt").read_bytes())

    # ML-DSA-65 alternative keypair via OpenSSL
    alt_key = OUT / "alt-mldsa65.key"
    sh("openssl", "genpkey", "-algorithm", "ML-DSA-65", "-out", str(alt_key))
    sapki = sh("openssl", "pkey", "-in", str(alt_key), "-pubout", "-outform", "DER")
    (OUT / "alt-mldsa65.pub.der").write_bytes(sapki)

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    (OUT / "leaf.key").write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    # Build 1: everything except altSignatureValue; its TBS is what the alt sig covers.
    cert1 = build(None, leaf_key, ca_cert, sapki).sign(ca_key, hashes.SHA256())
    tbs = OUT / "tbs-for-altsig.der"
    tbs.write_bytes(cert1.tbs_certificate_bytes)

    sig_file = OUT / "altsig.bin"
    sh("openssl", "pkeyutl", "-sign", "-inkey", str(alt_key), "-rawin",
       "-in", str(tbs), "-out", str(sig_file))
    sig = sig_file.read_bytes()
    print(f"ML-DSA-65 alt signature: {len(sig)} bytes")

    # altSignatureValue ::= BIT STRING (0 unused bits)
    alt_sig_der = b"\x03" + der_len(len(sig) + 1) + b"\x00" + sig

    cert2 = build(
        x509.UnrecognizedExtension(OID_ALT_SIG, alt_sig_der), leaf_key, ca_cert, sapki
    ).sign(ca_key, hashes.SHA256())
    out_pem = OUT / "leaf.crt"
    out_pem.write_bytes(cert2.public_bytes(serialization.Encoding.PEM))

    der_size = len(cert2.public_bytes(serialization.Encoding.DER))
    print(f"catalyst leaf DER size: {der_size} bytes")

    # Check 1: the ML-DSA signature verifies over the covered TBS.
    pub_pem = OUT / "alt-mldsa65.pub.pem"
    pub_pem.write_bytes(sh("openssl", "pkey", "-in", str(alt_key), "-pubout"))
    sh("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub_pem), "-rawin",
       "-in", str(tbs), "-sigfile", str(sig_file))
    print("alt signature verifies over TBS-without-altSignatureValue: OK")

    # Check 2: the classical path validates the chain, ignoring the unknown
    # non-critical extensions. This is the industry's core compatibility claim.
    print(
        subprocess.run(
            ["openssl", "verify", "-CAfile", str(CHAIN / "root.crt"),
             "-untrusted", str(CHAIN / "int.crt"), str(out_pem)],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    )


if __name__ == "__main__":
    sys.exit(main())
