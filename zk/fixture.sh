#!/usr/bin/env bash
# Make test fixtures from a synthetic passport: a made-up person under a made-up state
# certificate. Nothing in the output comes from a real passport, so it can be committed.
#
#   zk/fixture.sh <out-dir> [<name> --address 0x… --scope <text> [package.sh options]] …
#
# Writes <out-dir>/export.json and <out-dir>/trust/csca.pem once (kept if present, so later
# packages come from the same passport), then one <out-dir>/<name>.json proof package per
# group of arguments, and <out-dir>/pins.json for a verifier. Groups are separated by "--".
#
#   zk/fixture.sh fx  alice --address 0x… --scope s1 --min-age 18  --  bob --address 0x… --scope s1
set -euo pipefail

if [ $# -lt 1 ]; then
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
OUT=$(realpath -m "$1")
shift
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=zk/setup.sh
. "$HERE/setup.sh"
umask 022 # fixtures are public

mkdir -p "$OUT"
if [ ! -f "$OUT/export.json" ]; then
  (cd "$ZKP_DIR" && npx tsx nfcid-local/fixture.ts "$OUT" 2>&1 | grep -vE 'DEP0205|trace-deprecation') || die "fixture generation failed"
fi

CIRCUITS=(--dsc-circuit sig_check_dsc_tbs_700_rsa_pkcs_4096_sha256 --id-circuit sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256)
package() {
  local name=$1
  shift
  echo "== $name"
  (cd "$ZKP_DIR" && npx tsx nfcid-local/package.ts "$OUT/export.json" "$OUT/trust" "$OUT/$name.json" \
    --pins "$OUT/pins.json" "${CIRCUITS[@]}" "$@" 2>&1 | grep -vE 'DEP0205|trace-deprecation') || die "package $name failed"
  chmod 644 "$OUT/$name.json"
}

GROUP=()
for arg in "$@" --; do
  if [ "$arg" = -- ]; then
    [ ${#GROUP[@]} -eq 0 ] || package "${GROUP[@]}"
    GROUP=()
  else
    GROUP+=("$arg")
  fi
done
