#!/usr/bin/env bash
# Runner: Python stdlib ssl (python:3.13-slim; bundles the distro OpenSSL,
# which is the point: the column measures what a Python deploy actually gets).
set -euo pipefail
BUNDLE="$(cd "$1" && pwd)"; SERVER="$2"; EV="$(mkdir -p "$3" && cd "$3" && pwd)"
LIB="$(cd "$(dirname "$0")/../lib" && pwd)"
RDIR="$(cd "$(dirname "$0")" && pwd)"
IMG=python:3.13-slim
HOST="${SERVER%%:*}"; [ "$SERVER" = "-" ] && HOST=matrix.test

dock() {
  docker run --rm --network host --add-host "$HOST":127.0.0.1 \
    -v "$BUNDLE":/b:ro -v "$RDIR":/r:ro "$IMG" python3 /r/client.py "$@"
}

VER_ALL="$(docker run --rm "$IMG" python3 -c 'import ssl,sys; print(f"Python {sys.version.split()[0]} ({ssl.OPENSSL_VERSION})")')"
VER="${VER_ALL%%$'\n'*}"

set +e
dock parse /b/leaf.crt > "$EV/parse.txt" 2>&1
PARSE_RC=$?

if [ "$SERVER" != "-" ]; then
  PORT="${SERVER##*:}"
  dock handshake /b/root.crt "$HOST" "$PORT" > "$EV/handshake.txt" 2>&1
  HS_RC=$?
  HS_ARGS=(handshake "$HS_RC" "$EV/handshake.txt")
else
  HS_ARGS=(handshake skip "no server for this chain")
fi
set -e

python3 "$LIB/emit.py" "python" "$VER" \
  parse "$PARSE_RC" "$EV/parse.txt" \
  verify skip "stdlib has no offline chain-verification API" \
  "${HS_ARGS[@]}"
