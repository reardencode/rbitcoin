#!/usr/bin/env bash
# Emit LLVM IR for the consensus proof crates with rustc 1.88.
# Does not run Alive2. The workspace pin stays 1.95.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -x "${HOME}/.cargo/bin/rustup" ]]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi

if ! rustup run 1.88.0 rustc --version >/dev/null 2>&1; then
  echo "rustc 1.88.0 is not installed" >&2
  exit 1
fi

rustup run 1.88.0 cargo rustc --release --ignore-rust-version \
  -p rbitcoin-primitives --lib -- \
  -C panic=abort -C lto=no --emit=llvm-ir
rustup run 1.88.0 cargo rustc --release --ignore-rust-version \
  -p rbitcoin-consensus --lib --features equiv -- \
  -C panic=abort -C lto=no --emit=llvm-ir

target_root="${CARGO_TARGET_DIR:-target}"
prim="$(find "$target_root" -name 'rbitcoin_primitives-*.ll' -print -quit)"
cons="$(find "$target_root" -name 'rbitcoin_consensus-*.ll' -print -quit)"
if [[ -z "$prim" || -z "$cons" ]]; then
  echo "llvm ir missing under $target_root" >&2
  exit 1
fi
echo "primitives $prim"
echo "consensus $cons"
