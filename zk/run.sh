#!/usr/bin/env bash
# Generate, prove and verify zkPassport proofs from an NFC ID passport export.
#
#   zk/run.sh <passport-export.json> [out-dir]
#
# out-dir defaults to ~/nfcid-private/zk. Witnesses, proofs and public inputs are written there
# with owner-only permissions: witnesses contain passport data. See zk/README.md.
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
EXPORT=$(realpath "$1")
OUT=$(realpath -m "${2:-$HOME/nfcid-private/zk}")
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=zk/setup.sh
. "$HERE/setup.sh"
[ -f "$EXPORT" ] || die "no such export: $EXPORT"

# --- witnesses ------------------------------------------------------------------------------
mkdir -p "$OUT"
chmod 700 "$OUT"
rm -f "$OUT"/*.gz "$OUT/witnesses.json"
echo "== generating witnesses"
(cd "$ZKP_DIR" && npx tsx nfcid-local/witness.ts "$EXPORT" "$TRUST" "$OUT" 2>&1 |
  grep -vE 'DEP0205|trace-deprecation') || die "witness generation failed"

# --- prove and verify -----------------------------------------------------------------------
echo "== proving and verifying"
TIMES=$(mktemp -p "$OUT")
trap 'rm -f "$TIMES"' EXIT
printf '%-34s %-48s %8s %8s %9s %s\n' label circuit gates prove_s peak_MB result
FAILED=0
while IFS=$'\t' read -r label circuit; do
  d="$OUT/$label"
  mkdir -p "$d"
  program="$ZKP_DIR/target/$circuit.json"
  gates=$(bb gates -b "$program" 2>/dev/null | tr -d ' \n' | grep -oE '"circuit_size":[0-9]+' | cut -d: -f2)
  bb write_vk -b "$program" -o "$d" >/dev/null 2>&1 || { echo "$label: write_vk failed"; FAILED=1; continue; }
  if /usr/bin/time -o "$TIMES" -f '%e %M' bb prove -b "$program" -w "$OUT/$label.gz" -k "$d/vk" -o "$d" >/dev/null 2>&1 &&
    bb verify -k "$d/vk" -p "$d/proof" -i "$d/public_inputs" >/dev/null 2>&1; then
    result="verified"
  else
    result="FAILED"
    FAILED=1
  fi
  read -r secs kb <"$TIMES" || { secs="?"; kb=0; }
  printf '%-34s %-48s %8s %8s %9s %s\n' "$label" "$circuit" "$gates" "$secs" "$((kb / 1024))" "$result"
done < <(python3 -I -c 'import json,sys; [print(s["label"], s["circuit"], sep="\t") for s in json.load(open(sys.argv[1]))]' "$OUT/witnesses.json")

[ "$FAILED" = 0 ] || die "some proofs failed"
echo "all proofs verified; outputs in $OUT"
