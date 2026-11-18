# Sourced by run.sh and package.sh: checks the toolchain, prepares the zkPassport checkout at the
# pinned commit, copies this folder's scripts into it and compiles the circuits they name.
# Expects HERE (this folder). Sets ZKP_DIR and TRUST, and defines die().
#
# Environment:
#   ZKP_DIR   zkPassport circuits checkout (default ~/zk/zkpassport-circuits; cloned if missing)

ZKP_REPO_URL=https://github.com/zkpassport/circuits.git
ZKP_COMMIT=4d90f1f8793b021925772ee2e0dba0588447b687 # release 0.23.0, 2026-11-16
NOIR_VERSION=1.0.0
BB_VERSION=6.0.0

TRUST="$HERE/../trust/canada"
ZKP_DIR=${ZKP_DIR:-$HOME/zk/zkpassport-circuits}
umask 077

die() { echo "error: $*" >&2; exit 1; }

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
cp "$HERE"/*.ts "$ZKP_DIR/nfcid-local/"

# --- compile the circuits the scripts name (the list lives only in the .ts files) -------------
CIRCUITS=$(grep -ohE 'circuit: "[a-z0-9_]+"' "$HERE"/*.ts | cut -d'"' -f2 | sort -u)
for c in $CIRCUITS; do
  if [ ! -f "$ZKP_DIR/target/$c.json" ]; then
    echo "== compiling $c"
    (cd "$ZKP_DIR" && nargo compile --package "$c")
  fi
done
