#!/usr/bin/env bash
# Generate, prove and verify zkPassport proofs from an NFC ID passport export.
#
#   zk/run.sh <passport-export.json> [out-dir]
#
# out-dir defaults to ~/nfcid-private/zk. Witnesses, proofs and public inputs are written there
# with owner-only permissions: witnesses contain passport data. See zk/README.md.
#
# Environment:
#   ZKP_DIR   zkPassport circuits checkout (default ~/zk/zkpassport-circuits; cloned if missing)
set -euo pipefail

ZKP_REPO_URL=https://github.com/zkpassport/circuits.git
ZKP_COMMIT=4d90f1f8793b021925772ee2e0dba0588447b687 # release 0.23.0, 2026-11-16
NOIR_VERSION=1.0.0
BB_VERSION=6.0.0

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
EXPORT=$(realpath "$1")
OUT=$(realpath -m "${2:-$HOME/nfcid-private/zk}")
HERE=$(cd "$(dirname "$0")" && pwd)
TRUST="$HERE/../trust/canada"
ZKP_DIR=${ZKP_DIR:-$HOME/zk/zkpassport-circuits}
umask 077

die() { echo "error: $*" >&2; exit 1; }
[ -f "$EXPORT" ] || die "no such export: $EXPORT"

# --- toolchain ------------------------------------------------------------------------------
command -v nargo >/dev/null || die "nargo not found (need $NOIR_VERSION)"
command -v bb >/dev/null || die "bb not found (need $BB_VERSION)"
command -v npx >/dev/null || die "node/npx not found"
nargo --version | grep -q "nargo version = $NOIR_VERSION\$" || die "need nargo $NOIR_VERSION, have: $(nargo --version | head -1)"
[ "$(bb --version)" = "$BB_VERSION" ] || die "need bb $BB_VERSION, have: $(bb --version)"

# --- zkPassport checkout at the pinned commit ------------------------------------------------
if [ ! -d "$ZKP_DIR/.git" ]; then
  echo "== fetching zkPassport circuits $ZKP_COMMIT into $ZKP_DIR"
  mkdir -p "$ZKP_DIR"
  git -C "$ZKP_DIR" init -q
  git -C "$ZKP_DIR" fetch -q --depth 1 "$ZKP_REPO_URL" "$ZKP_COMMIT"
  git -C "$ZKP_DIR" checkout -q FETCH_HEAD
fi
HEAD_COMMIT=$(git -C "$ZKP_DIR" rev-parse HEAD)
[ "$HEAD_COMMIT" = "$ZKP_COMMIT" ] ||
  die "$ZKP_DIR is at $HEAD_COMMIT, expected $ZKP_COMMIT (not changing an existing checkout)"

if [ ! -d "$ZKP_DIR/node_modules" ]; then
  echo "== installing zkPassport's node dependencies (no install scripts)"
  (cd "$ZKP_DIR" && npm ci --ignore-scripts --no-audit --no-fund)
fi

# Keep our script out of zkPassport's git status.
grep -qx 'nfcid-local/' "$ZKP_DIR/.git/info/exclude" 2>/dev/null || echo 'nfcid-local/' >>"$ZKP_DIR/.git/info/exclude"
mkdir -p "$ZKP_DIR/nfcid-local"
cp "$HERE/witness.ts" "$ZKP_DIR/nfcid-local/witness.ts"

# --- compile the circuits witness.ts uses (the list lives only in witness.ts) -----------------
CIRCUITS=$(grep -oE 'circuit: "[a-z0-9_]+"' "$HERE/witness.ts" | cut -d'"' -f2 | sort -u)
for c in $CIRCUITS; do
  if [ ! -f "$ZKP_DIR/target/$c.json" ]; then
    echo "== compiling $c"
    (cd "$ZKP_DIR" && nargo compile --package "$c")
  fi
done

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
