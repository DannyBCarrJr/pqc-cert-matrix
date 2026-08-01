#!/usr/bin/env bash
# schannel isolation run: repeat the Phase 2 schannel handshake cells against a
# second, independent TLS server implementation (Bouncy Castle bctls 1.82,
# JDK 21, in Docker) instead of OpenSSL s_server.
#
# Per chain:
#   1. start the bctls server presenting that chain
#   2. control: openssl s_client 3.5.5 (known-good ML-DSA client) must complete
#      the handshake, proving the server itself works before schannel is judged
#   3. re-run the schannel handshake via the same schannel.ps1 used in Phase 2
#   4. keep the server's own log; its failure text is evidence too
#
# Evidence: isolation/evidence/<chain>/{chain-info,openssl-control,schannel,server-log}.txt
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=14434
IMG=pqm-bctls-server
PS='/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
SCRIPT_WIN="$(wslpath -w runners/schannel/schannel.ps1)"
WSLIP="$(ip -4 addr show eth0 | grep -o 'inet [0-9.]*' | awk '{print $2}')"
CHAINS=(ecdsa mldsa44 mldsa65 mldsa87 slhroot mixed catalyst)

docker build -q -t "$IMG" isolation/bctls-server

summary=()
for c in "${CHAINS[@]}"; do
  b="results/bundles/$c"
  ev="isolation/evidence/$c"
  mkdir -p "$ev"

  for part in root int leaf; do
    [ -f "$b/$part.crt" ] && printf '%s: %s\n' "$part" \
      "$(openssl x509 -in "$b/$part.crt" -noout -subject -nameopt oneline | sed 's/subject=//') sig=$(openssl x509 -in "$b/$part.crt" -noout -text | grep 'Signature Algorithm' | head -1 | awk '{print $NF}')"
  done > "$ev/chain-info.txt"

  args=("$PORT" /b/leaf.key /b/leaf.crt)
  [ -f "$b/int.crt" ] && args+=(/b/int.crt)
  cid=$(docker run -d --rm -p "$PORT:$PORT" -v "$PWD/$b":/b:ro "$IMG" "${args[@]}")
  up=0
  for _ in $(seq 50); do
    docker logs "$cid" 2>&1 | grep -q listening && { up=1; break; }
    sleep 0.2
  done
  if [ "$up" != 1 ]; then
    docker logs "$cid" > "$ev/server-log.txt" 2>&1 || true
    docker stop "$cid" >/dev/null 2>&1 || true
    summary+=("$c: SERVER FAILED TO START")
    continue
  fi

  host=matrix.test
  [ "$c" = catalyst ] && host=matrix-hybrid.test
  set +e
  timeout 20 openssl s_client -connect "127.0.0.1:$PORT" -servername "$host" \
    -CAfile "$b/root.crt" -verify_return_error -brief \
    </dev/null > "$ev/openssl-control.txt" 2>&1
  ctrl_rc=$?
  "$PS" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_WIN" \
    -Test handshake -ConnectIp "$WSLIP" -Host2 "$host" -Port "$PORT" \
    2>&1 | tr -d '\r' > "$ev/schannel.txt"
  sc_rc=$?
  set -e

  docker logs "$cid" > "$ev/server-log.txt" 2>&1 || true
  docker stop "$cid" >/dev/null 2>&1 || true

  ctrl=ok; [ "$ctrl_rc" -ne 0 ] && ctrl=FAIL
  sc=ok;   [ "$sc_rc"   -ne 0 ] && sc=FAIL
  summary+=("$c: openssl-control=$ctrl schannel=$sc | $(head -1 "$ev/schannel.txt")")
done

printf '\n== isolation summary (server: bctls 1.82 / JDK 21) ==\n'
printf '%s\n' "${summary[@]}"
