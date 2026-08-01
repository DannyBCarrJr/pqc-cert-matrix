#!/usr/bin/env bash
# Phase 0 feasibility: mint one chain per matrix row type with stock OpenSSL 3.5.5.
# Rows here: ecdsa (control), mldsa65 (pure PQ), mixed (ECDSA root -> ML-DSA int/leaf).
# The catalyst row is built by catalyst_build.py after this runs (reuses the ECDSA CA).
# All output captured to evidence/mint-phase0.txt.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
cd "$D"
mkdir -p evidence chains/ecdsa chains/mldsa65 chains/mixed

run() { echo "\$ $*"; "$@"; }

ext_int='basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign'
ext_leaf='basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:matrix.test'

genkey() {  # $1 algorithm, $2 outfile. EC needs a paramgen option, PQ algs do not.
  if [ "$1" = "EC" ]; then
    run openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2"
  else
    run openssl genpkey -algorithm "$1" -out "$2"
  fi
}

mint_chain() {  # $1 name, $2 root_alg, $3 int_alg, $4 leaf_alg
  local name="$1" d="chains/$1"
  echo "== chain: $name (root=$2 int=$3 leaf=$4) =="

  genkey "$2" "$d/root.key"
  genkey "$3" "$d/int.key"
  genkey "$4" "$d/leaf.key"

  run openssl req -x509 -new -key "$d/root.key" -out "$d/root.crt" \
      -subj "/CN=PQM Matrix $name Root" -days 90 \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
  run openssl req -new -key "$d/int.key" -out "$d/int.csr" -subj "/CN=PQM Matrix $name Intermediate"
  run openssl x509 -req -in "$d/int.csr" -CA "$d/root.crt" -CAkey "$d/root.key" \
      -out "$d/int.crt" -days 60 -extfile <(printf '%s\n' "$ext_int")
  run openssl req -new -key "$d/leaf.key" -out "$d/leaf.csr" -subj "/CN=matrix.test"
  run openssl x509 -req -in "$d/leaf.csr" -CA "$d/int.crt" -CAkey "$d/int.key" \
      -out "$d/leaf.crt" -days 30 -extfile <(printf '%s\n' "$ext_leaf")

  echo "-- verify --"
  run openssl verify -CAfile "$d/root.crt" -untrusted "$d/int.crt" "$d/leaf.crt"

  echo "-- DER sizes (bytes) --"
  for c in root int leaf; do
    printf "%s/%s: %s\n" "$name" "$c" "$(openssl x509 -in "$d/$c.crt" -outform DER | wc -c)"
  done
  echo
}

{
  openssl version
  echo
  mint_chain ecdsa   EC        EC        EC
  mint_chain mldsa65 ML-DSA-65 ML-DSA-65 ML-DSA-65
  mint_chain mixed   EC        ML-DSA-65 ML-DSA-65
} 2>&1 | tee evidence/mint-phase0.txt
