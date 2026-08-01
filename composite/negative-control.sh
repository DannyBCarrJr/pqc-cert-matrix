#!/usr/bin/env bash
# Negative control for the Bouncy Castle composite cell.
#
# A passing "verify" is only evidence if it can fail. This flips one bit inside
# the composite certificate's trailing signature value (leaving DER framing
# intact) and confirms BC rejects it. Run after any change to the composite
# tooling or the bouncycastle runner.
#
# Expected: "SignatureException: certificate does not verify with supplied key",
# exit 1 from the client, and this script printing PASS.
set -euo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 - "$D" "$WORK" <<'PY'
import subprocess, sys
from pathlib import Path
repo, work = Path(sys.argv[1]), Path(sys.argv[2])
der = subprocess.run(
    ["openssl", "x509", "-in", str(repo / "composite/chains/composite-selfsigned.crt"),
     "-outform", "DER"], check=True, capture_output=True).stdout
b = bytearray(der)
idx = len(b) - 50           # inside the signature BIT STRING, clear of DER framing
b[idx] ^= 0x01
(work / "tampered.der").write_bytes(bytes(b))
subprocess.run(["openssl", "x509", "-inform", "DER", "-in", str(work / "tampered.der"),
                "-out", str(work / "leaf.crt")], check=True)
(work / "root.crt").write_bytes((work / "leaf.crt").read_bytes())
print(f"flipped one bit at offset {idx} of {len(b)}; certificate still DER-parses")
PY

docker image inspect pqm-runner-bouncycastle >/dev/null 2>&1 || \
  docker build -q -t pqm-runner-bouncycastle "$D/runners/bouncycastle" >/dev/null

set +e
OUT="$(docker run --rm -v "$WORK":/b:ro pqm-runner-bouncycastle \
        java -cp "/app/classes:/app/lib/*" Client verify /b/root.crt - /b/leaf.crt 2>&1)"
RC=$?
set -e
echo "$OUT"

if [ $RC -ne 0 ] && printf '%s' "$OUT" | grep -qi "does not verify"; then
  echo "PASS: Bouncy Castle rejects the tampered composite signature."
else
  echo "FAIL: tampered composite was accepted (rc=$RC). The composite cell is not trustworthy."
  exit 1
fi
