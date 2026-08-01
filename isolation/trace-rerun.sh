#!/usr/bin/env bash
# Decoded-wire rerun of the schannel vs openssl s_server pair, per chain:
# s_server -trace prints the ClientHello (signature_algorithms included) and
# the server's response in plaintext. The ML-DSA handshake dies at the
# ClientHello, before encryption starts, so this trace is complete evidence
# and needs no packet capture.
#
# s_server quits on stdin EOF, so it gets a long-lived stdin via process
# substitution; a plain `&` background under a non-interactive shell hands it
# /dev/null and it exits before the client connects.
#
# Evidence: isolation/evidence/<chain>/{openssl-trace,schannel-vs-openssl}.txt
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=14435
PS='/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
SW="$(wslpath -w runners/schannel/schannel.ps1)"
WSLIP="$(ip -4 addr show eth0 | grep -o 'inet [0-9.]*' | awk '{print $2}')"

chains=("$@")
[ ${#chains[@]} -eq 0 ] && chains=(mldsa65 ecdsa)
for c in "${chains[@]}"; do
  b="results/bundles/$c"
  ev="isolation/evidence/$c"
  mkdir -p "$ev"

  openssl s_server -accept "$PORT" -naccept 1 \
    -cert "$b/leaf.crt" -key "$b/leaf.key" -cert_chain "$b/int.crt" \
    -trace < <(sleep 300) > "$ev/openssl-trace.txt" 2>&1 &
  spid=$!
  for _ in $(seq 50); do
    ss -ltn "sport = :$PORT" | grep -q LISTEN && break
    sleep 0.2
  done

  set +e
  "$PS" -NoProfile -ExecutionPolicy Bypass -File "$SW" \
    -Test handshake -ConnectIp "$WSLIP" -Host2 matrix.test -Port "$PORT" \
    2>&1 | tr -d '\r' > "$ev/schannel-vs-openssl.txt"
  set -e

  sleep 1
  kill "$spid" 2>/dev/null || true
  wait "$spid" 2>/dev/null || true
  echo "$c: $(head -1 "$ev/schannel-vs-openssl.txt")"
done
