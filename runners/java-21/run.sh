#!/usr/bin/env bash
# Runner: Java 21 LTS (JSSE + PKIX), eclipse-temurin:21, single-file launch.
set -euo pipefail
BUNDLE="$(cd "$1" && pwd)"; SERVER="$2"; EV="$(mkdir -p "$3" && cd "$3" && pwd)"
LIB="$(cd "$(dirname "$0")/../lib" && pwd)"
RDIR="$(cd "$(dirname "$0")" && pwd)"
IMG=eclipse-temurin:21
HOST="${SERVER%%:*}"; [ "$SERVER" = "-" ] && HOST=matrix.test

dock() {
  docker run --rm --network host --add-host "$HOST":127.0.0.1 \
    -v "$BUNDLE":/b:ro -v "$RDIR":/r:ro "$IMG" bash -c "$1"
}

VER_ALL="$(dock 'java -version 2>&1')"
VER="${VER_ALL%%$'\n'*}"

INT="-"
[ -f "$BUNDLE/int.crt" ] && INT="/b/int.crt"

set +e
dock 'java /r/Client.java parse /b/leaf.crt' > "$EV/parse.txt" 2>&1
PARSE_RC=$?

dock "java /r/Client.java verify /b/root.crt $INT /b/leaf.crt" > "$EV/verify.txt" 2>&1
VERIFY_RC=$?

if [ "$SERVER" != "-" ]; then
  PORT="${SERVER##*:}"
  dock "java /r/Client.java handshake /b/root.crt $HOST $PORT" > "$EV/handshake.txt" 2>&1
  HS_RC=$?
  HS_ARGS=(handshake "$HS_RC" "$EV/handshake.txt")
else
  HS_ARGS=(handshake skip "no server for this chain")
fi
set -e

python3 "$LIB/emit.py" "java-21" "$VER" \
  parse "$PARSE_RC" "$EV/parse.txt" \
  verify "$VERIFY_RC" "$EV/verify.txt" \
  "${HS_ARGS[@]}"
