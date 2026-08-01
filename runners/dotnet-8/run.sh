#!/usr/bin/env bash
# Runner: .NET 8 on Linux (managed X509Chain + SslStream over OpenSSL).
# Built once into an image so each cell is a fast `dotnet Client.dll` run.
set -euo pipefail
BUNDLE="$(cd "$1" && pwd)"; SERVER="$2"; EV="$(mkdir -p "$3" && cd "$3" && pwd)"
LIB="$(cd "$(dirname "$0")/../lib" && pwd)"
RDIR="$(cd "$(dirname "$0")" && pwd)"
IMG=pqm-runner-dotnet8
HOST="${SERVER%%:*}"; [ "$SERVER" = "-" ] && HOST=matrix.test

docker image inspect "$IMG" >/dev/null 2>&1 || \
  docker build -q -t "$IMG" "$RDIR" >/dev/null

dock() {
  docker run --rm --network host --add-host "$HOST":127.0.0.1 \
    -v "$BUNDLE":/b:ro "$IMG" dotnet /app/Client.dll "$@"
}

VER_ALL="$(docker run --rm "$IMG" dotnet --version)"
VER=".NET ${VER_ALL%%$'\n'*}"

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

python3 "$LIB/emit.py" "dotnet-8" "$VER" \
  parse "$PARSE_RC" "$EV/parse.txt" \
  verify "$VERIFY_RC" "$EV/verify.txt" \
  "${HS_ARGS[@]}"
