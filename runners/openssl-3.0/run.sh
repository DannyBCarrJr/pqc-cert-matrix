#!/usr/bin/env bash
# Runner: OpenSSL 3.0 LTS (the deployed mass), via ubuntu:24.04 (OpenSSL 3.0.x).
set -euo pipefail
BUNDLE="$(cd "$1" && pwd)"; SERVER="$2"; EV="$(mkdir -p "$3" && cd "$3" && pwd)"
LIB="$(cd "$(dirname "$0")/../lib" && pwd)"
IMG=pqm-runner-openssl30
HOST="${SERVER%%:*}"; [ "$SERVER" = "-" ] && HOST=matrix.test

docker image inspect "$IMG" >/dev/null 2>&1 || \
  docker build -q -t "$IMG" "$(dirname "$0")" >/dev/null

dock() {
  docker run --rm --network host --add-host "$HOST":127.0.0.1 \
    -v "$BUNDLE":/b:ro "$IMG" bash -c "$1"
}

VER="$(dock 'openssl version' | head -1)"

set +e
dock 'openssl x509 -in /b/leaf.crt -noout -text' > "$EV/parse.txt" 2>&1
PARSE_RC=$?

if [ -f "$BUNDLE/int.crt" ]; then
  dock 'openssl verify -CAfile /b/root.crt -untrusted /b/int.crt /b/leaf.crt' > "$EV/verify.txt" 2>&1
else
  dock 'openssl verify -CAfile /b/root.crt /b/leaf.crt' > "$EV/verify.txt" 2>&1
fi
VERIFY_RC=$?

if [ "$SERVER" != "-" ]; then
  dock "echo Q | openssl s_client -connect $SERVER -CAfile /b/root.crt -verify_return_error" > "$EV/handshake.txt" 2>&1
  HS_RC=$?
  HS_ARGS=(handshake "$HS_RC" "$EV/handshake.txt")
else
  HS_ARGS=(handshake skip "no server for this chain")
fi
set -e

python3 "$LIB/emit.py" "openssl-3.0" "$VER" \
  parse "$PARSE_RC" "$EV/parse.txt" \
  verify "$VERIFY_RC" "$EV/verify.txt" \
  "${HS_ARGS[@]}"
