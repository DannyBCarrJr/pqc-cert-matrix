#!/usr/bin/env bash
# Runner: Bouncy Castle 1.82 as JCA provider (certificate-path only).
# This is the composite row's control: BC mints our composite certs, so its own
# verifier is the one that should recognize those OIDs. Handshake is skipped by
# design (BC's JSSE is a separate stack from the cert-path question here).
set -euo pipefail
BUNDLE="$(cd "$1" && pwd)"; SERVER="$2"; EV="$(mkdir -p "$3" && cd "$3" && pwd)"
LIB="$(cd "$(dirname "$0")/../lib" && pwd)"
RDIR="$(cd "$(dirname "$0")" && pwd)"
IMG=pqm-runner-bouncycastle

docker image inspect "$IMG" >/dev/null 2>&1 || \
  docker build -q -t "$IMG" "$RDIR" >/dev/null

dock() {
  docker run --rm -v "$BUNDLE":/b:ro "$IMG" \
    java -cp "/app/classes:/app/lib/*" Client "$@"
}

VER_ALL="$(docker run --rm "$IMG" bash -c 'ls /app/lib/bcprov-jdk18on-*.jar | sed "s|.*bcprov-jdk18on-||; s|\.jar||"')"
VER="Bouncy Castle ${VER_ALL%%$'\n'*} (JCA provider, JDK 21)"

INT="-"
[ -f "$BUNDLE/int.crt" ] && INT="/b/int.crt"

set +e
dock parse /b/leaf.crt > "$EV/parse.txt" 2>&1
PARSE_RC=$?

dock verify /b/root.crt "$INT" /b/leaf.crt > "$EV/verify.txt" 2>&1
VERIFY_RC=$?
set -e

python3 "$LIB/emit.py" "bouncycastle" "$VER" \
  parse "$PARSE_RC" "$EV/parse.txt" \
  verify "$VERIFY_RC" "$EV/verify.txt" \
  handshake skip "cert-path column by design; BC JSSE is a separate stack"
