#!/usr/bin/env bash
# Runner: Go stdlib (crypto/x509 + crypto/tls), host toolchain.
set -euo pipefail
BUNDLE="$(cd "$1" && pwd)"; SERVER="$2"; EV="$(mkdir -p "$3" && cd "$3" && pwd)"
LIB="$(cd "$(dirname "$0")/../lib" && pwd)"
CLIENT="$(dirname "$0")/client.go"

VER="$(go version | head -1)"

INT="-"
[ -f "$BUNDLE/int.crt" ] && INT="$BUNDLE/int.crt"

set +e
go run "$CLIENT" parse "$BUNDLE/leaf.crt" > "$EV/parse.txt" 2>&1
PARSE_RC=$?

go run "$CLIENT" verify "$BUNDLE/root.crt" "$INT" "$BUNDLE/leaf.crt" > "$EV/verify.txt" 2>&1
VERIFY_RC=$?

if [ "$SERVER" != "-" ]; then
  HOST="${SERVER%%:*}"; PORT="${SERVER##*:}"
  go run "$CLIENT" handshake "$BUNDLE/root.crt" "$HOST" "$PORT" > "$EV/handshake.txt" 2>&1
  HS_RC=$?
  HS_ARGS=(handshake "$HS_RC" "$EV/handshake.txt")
else
  HS_ARGS=(handshake skip "no server for this chain")
fi
set -e

python3 "$LIB/emit.py" "go" "$VER" \
  parse "$PARSE_RC" "$EV/parse.txt" \
  verify "$VERIFY_RC" "$EV/verify.txt" \
  "${HS_ARGS[@]}"
