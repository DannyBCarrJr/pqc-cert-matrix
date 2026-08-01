#!/usr/bin/env bash
# Runner: Node 22 (node:22-slim; Node statically bundles its own OpenSSL, so
# this column measures Node's crypto as shipped, independent of the distro).
set -euo pipefail
BUNDLE="$(cd "$1" && pwd)"; SERVER="$2"; EV="$(mkdir -p "$3" && cd "$3" && pwd)"
LIB="$(cd "$(dirname "$0")/../lib" && pwd)"
RDIR="$(cd "$(dirname "$0")" && pwd)"
IMG=node:22-slim
HOST="${SERVER%%:*}"; [ "$SERVER" = "-" ] && HOST=matrix.test

dock() {
  docker run --rm --network host --add-host "$HOST":127.0.0.1 \
    -v "$BUNDLE":/b:ro -v "$RDIR":/r:ro "$IMG" node /r/client.mjs "$@"
}

VER_ALL="$(docker run --rm "$IMG" node -e 'console.log(`Node ${process.version} (OpenSSL ${process.versions.openssl})`)')"
VER="${VER_ALL%%$'\n'*}"

INT="-"
[ -f "$BUNDLE/int.crt" ] && INT="/b/int.crt"

set +e
dock parse /b/leaf.crt > "$EV/parse.txt" 2>&1
PARSE_RC=$?

dock verify /b/root.crt "$INT" /b/leaf.crt > "$EV/verify.txt" 2>&1
VERIFY_RC=$?

if [ "$SERVER" != "-" ]; then
  PORT="${SERVER##*:}"
  dock handshake /b/root.crt "$HOST" "$PORT" > "$EV/handshake.txt" 2>&1
  HS_RC=$?
  HS_ARGS=(handshake "$HS_RC" "$EV/handshake.txt")
else
  HS_ARGS=(handshake skip "no server for this chain")
fi
set -e

python3 "$LIB/emit.py" "node" "$VER" \
  parse "$PARSE_RC" "$EV/parse.txt" \
  verify "$VERIFY_RC" "$EV/verify.txt" \
  "${HS_ARGS[@]}"
