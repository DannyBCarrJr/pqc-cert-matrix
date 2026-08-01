#!/usr/bin/env bash
# Runner: OpenSSL 3.5 (the PQ-aware present), host binary, no container.
# Handshake connects by IP; like the openssl-3.0 runner, s_client does not do
# hostname verification, so the cell measures chain validation in TLS.
set -euo pipefail
BUNDLE="$(cd "$1" && pwd)"; SERVER="$2"; EV="$(mkdir -p "$3" && cd "$3" && pwd)"
LIB="$(cd "$(dirname "$0")/../lib" && pwd)"

VER="$(openssl version | head -1)"

set +e
openssl x509 -in "$BUNDLE/leaf.crt" -noout -text > "$EV/parse.txt" 2>&1
PARSE_RC=$?

if [ -f "$BUNDLE/int.crt" ]; then
  openssl verify -CAfile "$BUNDLE/root.crt" -untrusted "$BUNDLE/int.crt" "$BUNDLE/leaf.crt" > "$EV/verify.txt" 2>&1
else
  openssl verify -CAfile "$BUNDLE/root.crt" "$BUNDLE/leaf.crt" > "$EV/verify.txt" 2>&1
fi
VERIFY_RC=$?

if [ "$SERVER" != "-" ]; then
  PORT="${SERVER##*:}"
  echo Q | openssl s_client -connect "127.0.0.1:$PORT" -CAfile "$BUNDLE/root.crt" -verify_return_error > "$EV/handshake.txt" 2>&1
  HS_RC=$?
  HS_ARGS=(handshake "$HS_RC" "$EV/handshake.txt")
else
  HS_ARGS=(handshake skip "no server for this chain")
fi
set -e

python3 "$LIB/emit.py" "openssl-3.5" "$VER" \
  parse "$PARSE_RC" "$EV/parse.txt" \
  verify "$VERIFY_RC" "$EV/verify.txt" \
  "${HS_ARGS[@]}"
