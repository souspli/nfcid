#!/usr/bin/env bash
# Build a Souspli passport-proof package from an NFC ID passport export.
#
#   zk/package.sh <passport-export.json> <out.json> --address 0x… --scope <text>
#                 [--subscope <text>] [--min-age N] [--nationality CAN,USA] [--pins <pins.json>]
#
# --address is the Souspli address the proofs are bound to. --scope decides the nullifier: one
# passport gives one nullifier per scope. The package holds proofs and public inputs only, and is
# written owner-only. See zk/README.md.
set -euo pipefail

if [ $# -lt 2 ]; then
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
EXPORT=$(realpath "$1")
OUT=$(realpath -m "$2")
shift 2
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=zk/setup.sh
. "$HERE/setup.sh"
[ -f "$EXPORT" ] || die "no such export: $EXPORT"

# Make --pins absolute: the tool runs from inside the checkout.
ARGS=()
while [ $# -gt 0 ]; do
  if [ "$1" = --pins ] && [ $# -ge 2 ]; then
    ARGS+=(--pins "$(realpath -m "$2")")
    shift 2
  else
    ARGS+=("$1")
    shift
  fi
done

mkdir -p "$(dirname "$OUT")"
(cd "$ZKP_DIR" && npx tsx nfcid-local/package.ts "$EXPORT" "$TRUST" "$OUT" "${ARGS[@]}" 2>&1 |
  grep -vE 'DEP0205|trace-deprecation') || die "package generation failed"
