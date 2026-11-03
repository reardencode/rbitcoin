#!/usr/bin/env bash
# A tree already at the pin must not fetch or clone. No network.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/core-functional/init-submodule.sh"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"

REAL_GIT="$(command -v git)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-init-submodule.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

mkdir -p "$WORKDIR/bin" "$WORKDIR/repo/src/test/data" "$WORKDIR/repo/test/functional/test_framework"
printf '{}\n' >"$WORKDIR/repo/src/test/data/script_tests.json"
printf '{}\n' >"$WORKDIR/repo/src/test/data/tx_valid.json"
printf '{}\n' >"$WORKDIR/repo/src/test/data/tx_invalid.json"
printf '{}\n' >"$WORKDIR/repo/src/test/data/sighash.json"
printf '{}\n' >"$WORKDIR/repo/src/test/data/bip341_wallet_vectors.json"
printf 'print(1)\n' >"$WORKDIR/repo/test/functional/test_runner.py"
printf '# framework\n' >"$WORKDIR/repo/test/functional/test_framework/__init__.py"
git -C "$WORKDIR/repo" init -q
git -C "$WORKDIR/repo" add -A
git -C "$WORKDIR/repo" -c user.email=t@example.com -c user.name=t commit -q -m pin
pin="$(git -C "$WORKDIR/repo" rev-parse HEAD)"

python3 - "$SCRIPT" "$WORKDIR/init-submodule.sh" "$pin" <<'PY'
import pathlib, sys
src, dst, pin = sys.argv[1:]
text = pathlib.Path(src).read_text()
old = None
for line in text.splitlines():
    if line.startswith('PIN_SHA="') and line.endswith('"'):
        old = line
        break
if old is None:
    raise SystemExit("PIN_SHA line missing")
pathlib.Path(dst).write_text(text.replace(old, f'PIN_SHA="{pin}"', 1))
PY
chmod +x "$WORKDIR/init-submodule.sh"

cat >"$WORKDIR/bin/git" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "\$*" >>"\$GIT_WRAP_LOG"
args=("\$@")
i=0
while [[ \$i -lt \${#args[@]} ]]; do
  a="\${args[\$i]}"
  if [[ "\$a" == "-C" ]]; then
    i=\$((i + 2))
    continue
  fi
  case "\$a" in
    fetch|clone)
      echo "blocked git \$a" >&2
      exit 99
      ;;
  esac
  break
done
exec "$REAL_GIT" "\$@"
EOF
chmod +x "$WORKDIR/bin/git"

run_init() {
  local dest="$1"
  GIT_WRAP_LOG="$WORKDIR/git.log" PATH="$WORKDIR/bin:$PATH" bash "$WORKDIR/init-submodule.sh" "$dest"
}

no_network() {
  local name="$1"
  if grep -E -q '(^| )(fetch|clone)( |$)' "$WORKDIR/git.log"; then
    echo "not ok - $name"
    FAIL=$((FAIL + 1))
  else
    echo "ok - $name"
    PASS=$((PASS + 1))
  fi
}

: >"$WORKDIR/git.log"
assert_ok "already at the pin" run_init "$WORKDIR/repo"
no_network "pin path did not fetch or clone"

printf 'tampered\n' >"$WORKDIR/repo/src/test/data/script_tests.json"
: >"$WORKDIR/git.log"
assert_ok "dirty fixture still returns" run_init "$WORKDIR/repo"
assert_ok "dirty fixture restored" grep -q '^{}$' "$WORKDIR/repo/src/test/data/script_tests.json"
no_network "repair did not fetch"

rm -rf "$WORKDIR/missing"
mkdir -p "$WORKDIR/missing"
git -C "$WORKDIR/missing" init -q
git -C "$WORKDIR/missing" -c user.email=t@example.com -c user.name=t commit -q --allow-empty -m other
: >"$WORKDIR/git.log"
assert_fail "unknown pin fetches" run_init "$WORKDIR/missing"
assert_ok "unknown pin tried fetch" grep -q fetch "$WORKDIR/git.log"

rm -rf "$WORKDIR/empty"
: >"$WORKDIR/git.log"
assert_fail "missing tree clones" run_init "$WORKDIR/empty"
assert_ok "missing tree tried clone" grep -q clone "$WORKDIR/git.log"

assert_fail "two args" bash "$SCRIPT" /tmp/a /tmp/b

if [[ -f "$ROOT/third_party/bitcoin/src/test/data/script_tests.json" ]]; then
  live="$(git -C "$ROOT/third_party/bitcoin" rev-parse HEAD)"
  want="$(sed -n 's/^PIN_SHA="\([0-9a-f]\{40\}\)".*/\1/p' "$SCRIPT")"
  if [[ "$live" == "$want" ]]; then
    before="$(git -C "$ROOT/third_party/bitcoin" status --porcelain)"
    : >"$WORKDIR/git.log"
    assert_ok "live pin returns" env GIT_WRAP_LOG="$WORKDIR/git.log" PATH="$WORKDIR/bin:$PATH" bash "$SCRIPT"
    after="$(git -C "$ROOT/third_party/bitcoin" status --porcelain)"
    assert_ok "live pin stays clean" test "$before" = "$after"
    no_network "live pin did not fetch"
  fi
fi

echo "1..$((PASS + FAIL))"
if [[ "$FAIL" -ne 0 ]]; then
  echo "FAILED $FAIL"
  exit 1
fi
