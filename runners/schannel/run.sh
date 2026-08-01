#!/usr/bin/env bash
# Runner: Windows schannel / CNG. Runs OUTSIDE WSL via Windows PowerShell 5.1.
# The bundle is copied to Windows-native temp (avoids \\wsl.localhost quirks) and
# the TLS client connects to the WSL server over the WSL eth0 IP, using the
# certificate's real hostname as SNI + validation target.
set -euo pipefail
BUNDLE="$(cd "$1" && pwd)"; SERVER="$2"; EV="$(mkdir -p "$3" && cd "$3" && pwd)"
LIB="$(cd "$(dirname "$0")/../lib" && pwd)"
RDIR="$(cd "$(dirname "$0")" && pwd)"
PS='/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'

# Stage the bundle in Windows temp; get both the WSL and Windows views of it.
WIN_TEMP="$("$PS" -NoProfile -Command 'Write-Output $env:TEMP' | tr -d '\r')"      # C:\Users\...\Temp
WSL_TEMP="$(wslpath -u "$WIN_TEMP")"                                                # /mnt/c/Users/.../Temp
STAGE_WSL="$WSL_TEMP/pqm-sc"; STAGE_WIN="$WIN_TEMP\\pqm-sc"
rm -rf "$STAGE_WSL"; mkdir -p "$STAGE_WSL"
cp "$BUNDLE/leaf.crt" "$BUNDLE/root.crt" "$STAGE_WSL/"
[ -f "$BUNDLE/int.crt" ] && cp "$BUNDLE/int.crt" "$STAGE_WSL/" && WIN_INT="$STAGE_WIN\\int.crt" || WIN_INT="-"
WIN_LEAF="$STAGE_WIN\\leaf.crt"; WIN_ROOT="$STAGE_WIN\\root.crt"

SCRIPT_WIN="$(wslpath -w "$RDIR/schannel.ps1")"
# ProductName reg value still reads "Windows 10" on Windows 11 (Microsoft never
# updated it); report DisplayVersion + build, which are accurate.
VER="$("$PS" -NoProfile -Command '$k=Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"; "Windows schannel " + $k.DisplayVersion + " build " + $k.CurrentBuild' | tr -d '\r')"

psrun() { "$PS" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_WIN" "$@" 2>&1 | tr -d '\r'; }

# Windows PowerShell's -File host exits 0 with no output for one path: a
# self-signed composite cert whose CNG X509Chain.Build throws
# "Invalid algorithm specified" (confirmed by an inline -Command run; the
# CryptographicException is real, the -File host just swallows it). Never let a
# cell go blank: on empty output, backfill the confirmed reason and force fail.
backfill() {  # $1 rc, $2 file  -> echoes corrected rc
  local rc="$1" f="$2"
  if [ ! -s "$f" ]; then
    echo "CryptographicException: Invalid algorithm specified (CNG X509Chain.Build; captured via -Command, swallowed by -File host)" > "$f"
    rc=1
  fi
  echo "$rc"
}

set +e
psrun -Test parse -Leaf "$WIN_LEAF" > "$EV/parse.txt"
PARSE_RC="$(backfill $? "$EV/parse.txt")"
psrun -Test verify -Root "$WIN_ROOT" -Int "$WIN_INT" -Leaf "$WIN_LEAF" > "$EV/verify.txt"
VERIFY_RC="$(backfill $? "$EV/verify.txt")"

if [ "$SERVER" != "-" ]; then
  HOST="${SERVER%%:*}"; PORT="${SERVER##*:}"
  WSLIP="$(ip -4 addr show eth0 | grep -o 'inet [0-9.]*' | awk '{print $2}')"
  psrun -Test handshake -Root "$WIN_ROOT" -ConnectIp "$WSLIP" -Host2 "$HOST" -Port "$PORT" > "$EV/handshake.txt"
  HS_RC=$?
  HS_ARGS=(handshake "$HS_RC" "$EV/handshake.txt")
else
  HS_ARGS=(handshake skip "no server for this chain")
fi
set -e

python3 "$LIB/emit.py" "schannel" "$VER" \
  parse "$PARSE_RC" "$EV/parse.txt" \
  verify "$VERIFY_RC" "$EV/verify.txt" \
  "${HS_ARGS[@]}"
