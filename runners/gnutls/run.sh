#!/usr/bin/env bash
# Runner: GnuTLS (gnutls-cli + certtool), ubuntu:24.04 packages, image built once.
set -euo pipefail
BUNDLE="$(cd "$1" && pwd)"; SERVER="$2"; EV="$(mkdir -p "$3" && cd "$3" && pwd)"
LIB="$(cd "$(dirname "$0")/../lib" && pwd)"
IMG=pqm-runner-gnutls
HOST="${SERVER%%:*}"; [ "$SERVER" = "-" ] && HOST=matrix.test

docker image inspect "$IMG" >/dev/null 2>&1 || \
  docker build -q -t "$IMG" "$(dirname "$0")" >/dev/null

dock() {
  docker run --rm --network host --add-host "$HOST":127.0.0.1 \
    -v "$BUNDLE":/b:ro "$IMG" bash -c "$1"
}

VER="$(dock 'gnutls-cli --version' | head -1)"

set +e
dock 'certtool --certificate-info --infile /b/leaf.crt' > "$EV/parse.txt" 2>&1
PARSE_RC=$?

dock 'certtool --verify --load-ca-certificate /b/root.crt --infile /b/chain.pem' > "$EV/verify.txt" 2>&1
VERIFY_RC=$?

if [ "$SERVER" != "-" ]; then
  PORT="${SERVER##*:}"; HOST="${SERVER%%:*}"
  dock "echo | gnutls-cli --x509cafile /b/root.crt --port $PORT $HOST" > "$EV/handshake.txt" 2>&1
  HS_RC=$?
  HS_ARGS=(handshake "$HS_RC" "$EV/handshake.txt")
else
  HS_ARGS=(handshake skip "no server for this chain")
fi
set -e

python3 "$LIB/emit.py" "gnutls" "$VER" \
  parse "$PARSE_RC" "$EV/parse.txt" \
  verify "$VERIFY_RC" "$EV/verify.txt" \
  "${HS_ARGS[@]}"
