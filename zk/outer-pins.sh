#!/usr/bin/env bash
# Print what a verifier of format-2 proof packages pins that depends on no passport: the root of
# zkPassport's circuit registry and the outer circuits' verification keys.
#
#   zk/outer-pins.sh > pins-outer.json
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=zk/setup.sh
. "$HERE/setup.sh" >&2
(cd "$ZKP_DIR" && npx tsx nfcid-local/outer-pins.ts 2> >(grep -vE 'DEP0205|trace-deprecation' >&2)) || die "could not compute the pins"
