#!/usr/bin/env bash
# Phase 1: mint the full v1 chain corpus. Stock OpenSSL 3.5.5, no providers.
# Chains: ecdsa (control), mldsa44/65/87 (pure PQ), slhroot (SLH-DSA-SHA2-128s
# root over ML-DSA-65, the "SLH for roots" practitioner shape), mixed (EC root,
# ML-DSA-65 below). SAN ladder (10/50/150) on the ecdsa and mldsa65 leaves.
# Catalyst and composite rows are built by their own tools; see ../phase0 and
# ../composite. Output: chains/, evidence/mint-corpus.txt. Keys are gitignored;
# rerun this script to regenerate the corpus.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
cd "$D"
mkdir -p evidence

run() { echo "\$ $*"; "$@"; }

ext_int='basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign'

genkey() {  # $1 algorithm, $2 outfile
  if [ "$1" = "EC" ]; then
    run openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2"
  else
    run openssl genpkey -algorithm "$1" -out "$2"
  fi
}

san_list() {  # $1 count -> "DNS:matrix.test,DNS:alt1.matrix.test,..."
  local n="$1" out="DNS:matrix.test" i
  for ((i = 1; i < n; i++)); do out+=",DNS:alt${i}.matrix.test"; done
  printf '%s' "$out"
}

leaf_ext() {  # $1 san count
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$(san_list "$1")"
}

mint_chain() {  # $1 name, $2 root_alg, $3 int_alg, $4 leaf_alg
  local name="$1" d="chains/$1"
  mkdir -p "$d"
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
      -out "$d/leaf.crt" -days 30 -extfile <(leaf_ext 1)

  echo "-- verify --"
  run openssl verify -CAfile "$d/root.crt" -untrusted "$d/int.crt" "$d/leaf.crt"
  echo
}

mint_san_ladder() {  # $1 chain name (reuses that chain's int CA and leaf key)
  local d="chains/$1" n
  for n in 10 50 150; do
    echo "== SAN ladder: $1 leaf with $n SANs =="
    run openssl req -new -key "$d/leaf.key" -out "$d/leaf-san$n.csr" -subj "/CN=matrix.test"
    run openssl x509 -req -in "$d/leaf-san$n.csr" -CA "$d/int.crt" -CAkey "$d/int.key" \
        -out "$d/leaf-san$n.crt" -days 30 -extfile <(leaf_ext "$n")
    run openssl verify -CAfile "$d/root.crt" -untrusted "$d/int.crt" "$d/leaf-san$n.crt"
    echo
  done
}

{
  openssl version
  echo
  mint_chain ecdsa   EC                EC        EC
  mint_chain mldsa44 ML-DSA-44         ML-DSA-44 ML-DSA-44
  mint_chain mldsa65 ML-DSA-65         ML-DSA-65 ML-DSA-65
  mint_chain mldsa87 ML-DSA-87         ML-DSA-87 ML-DSA-87
  mint_chain slhroot SLH-DSA-SHA2-128s ML-DSA-65 ML-DSA-65
  mint_chain mixed   EC                ML-DSA-65 ML-DSA-65
  mint_san_ladder ecdsa
  mint_san_ladder mldsa65
} 2>&1 | tee evidence/mint-corpus.txt
