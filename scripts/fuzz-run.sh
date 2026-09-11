#!/usr/bin/env bash
# Nightly libFuzzer. rust-toolchain.toml pins 1.95; cargo-fuzz needs nightly.
# Callers inherit RUSTUP_TOOLCHAIN if already set; default is nightly.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fuzz_max_total_time() {
  if [[ -n "${FUZZ_MAX_TOTAL_TIME:-}" ]]; then
    printf '%s' "$FUZZ_MAX_TOTAL_TIME"
    return
  fi
  local weekday="${FUZZ_WEEKDAY:-$(date +%u)}"
  if [[ "$weekday" == "7" ]]; then
    printf '3600'
  else
    printf '600'
  fi
}

wire_dict_for_bin() {
  case "$1" in
    block_wire) printf 'fuzz/dict/block.dict' ;;
    v2_contents) printf 'fuzz/dict/v2.dict' ;;
    addrv2_wire) printf 'fuzz/dict/addrv2.dict' ;;
    inv_getdata_wire) printf 'fuzz/dict/inv.dict' ;;
    electrum_json) printf 'fuzz/dict/electrum.dict' ;;
    v2_session) printf 'fuzz/dict/p2p.dict' ;;
    p2p_sequence_differential) printf 'fuzz/dict/p2p.dict' ;;
    script_differential|script_verify_differential|script_kernel_differential) printf 'fuzz/dict/script.dict' ;;
    cmpct_differential) printf 'fuzz/dict/cmpct.dict' ;;
    *) printf '' ;;
  esac
}

fail_if_no_comparisons() {
  local log="$1"
  local min_rate="${2:-0.01}"
  if [[ ! -f "$log" ]]; then
    echo "fuzz-run: missing comparison log $log" >&2
    return 1
  fi
  local n
  n="$(grep -Eo '[A-Za-z0-9_-]+: comparisons=[0-9]+' "$log" | tail -1 | grep -Eo '[0-9]+$' || true)"
  if [[ -z "$n" || "$n" -lt 1 ]]; then
    echo "fuzz-run: no comparisons in $log (got ${n:-missing})" >&2
    return 1
  fi
  echo "fuzz-run: comparisons=$n"
  local runs
  runs="$(grep -Eo 'Done [0-9]+ runs' "$log" | tail -1 | grep -Eo '[0-9]+' | head -1 || true)"
  if [[ -n "$runs" && "$runs" -ge 1000 ]]; then
    if ! awk -v n="$n" -v runs="$runs" -v min="$min_rate" 'BEGIN {
      exit !((n / runs) >= min)
    }'; then
      echo "fuzz-run: mute skip-rate comparisons=$n runs=$runs min_rate=$min_rate" >&2
      return 1
    fi
  fi
}

# Copy seed into corpus only when the dest name is absent (grown inputs stay).
merge_seed() {
  local dest_dir="$1" src="$2" name="${3:-}"
  mkdir -p "$dest_dir"
  if [[ -z "$name" ]]; then
    name="$(basename "$src")"
  fi
  local dest="$dest_dir/$name"
  if [[ -e "$dest" ]]; then
    return 0
  fi
  cp "$src" "$dest"
}

copy_crashers() {
  local artifacts="$1" crashers="$2"
  mkdir -p "$crashers"
  if [[ ! -d "$artifacts" ]]; then
    return 0
  fi
  local f base
  while IFS= read -r -d '' f; do
    base="$(basename "$f")"
    if [[ ! -e "$crashers/$base" ]]; then
      cp "$f" "$crashers/$base"
    fi
  done < <(find "$artifacts" -type f -print0 2>/dev/null || true)
}

if [[ "${1:-}" == "--check-log" ]]; then
  fail_if_no_comparisons "${2:?log file}" "${3:-0.01}"
  exit 0
fi

if [[ "${1:-}" == "--merge-seed" ]]; then
  merge_seed "${2:?dest dir}" "${3:?src file}" "${4:-}"
  exit 0
fi

if [[ "${1:-}" == "--copy-crashers" ]]; then
  copy_crashers "${2:?artifacts dir}" "${3:?crashers dir}"
  exit 0
fi

if [[ "${1:-}" == "--default-time" ]]; then
  fuzz_max_total_time
  printf '\n'
  exit 0
fi

BIN="${1:-block_wire}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
SEED="${FUZZ_SEED:-$(date +%s)}"
CRASHERS="${FUZZ_CRASHERS:-fuzz/crashers}"

# Prebuilt cargo-fuzz (taiki-e/install-action musl binary) uses
# CURRENT_PLATFORM as cargo --target, so it builds
# x86_64-unknown-linux-musl. ASan cannot use statically linked musl
# (`sanitizer is incompatible with statically linked libc`). Pin the
# rustc host triple (gnu on GHA ubuntu-latest).
target="$(rustc "+${RUSTUP_TOOLCHAIN}" -vV 2>/dev/null | sed -n 's/^host: //p' || true)"
if [[ -z "$target" ]]; then
  target="$(rustc -vV | sed -n 's/^host: //p')"
fi
if [[ -z "$target" ]]; then
  echo "fuzz-run: could not read rustc host triple" >&2
  exit 1
fi

sanitizer="address"
timeout=10
if [[ "$BIN" == "block_differential" ]]; then
  sanitizer="none"
  timeout=90
elif [[ "$BIN" == "block_spend_differential" || "$BIN" == "block_fork_differential" || "$BIN" == "script_differential" || "$BIN" == "cmpct_reorg_differential" || "$BIN" == "block_reorg_n_differential" || "$BIN" == "block_csv_differential" || "$BIN" == "mempool_differential" || "$BIN" == "script_verify_differential" ]]; then
  sanitizer="none"
  timeout=180
elif [[ "$BIN" == "v2_session" || "$BIN" == "cmpct_differential" ]]; then
  sanitizer="address"
  timeout=90
elif [[ "$BIN" == "store_reorg" ]]; then
  sanitizer="address"
  timeout=30
elif [[ "$BIN" == "script_kernel_differential" ]]; then
  sanitizer="address"
  timeout=10
elif [[ "$BIN" == "p2p_sequence_differential" ]]; then
  sanitizer="none"
  timeout=180
fi

WRAP="$ROOT/scripts/fuzz-rustc-allow-warnings.sh"
export RUSTC_WRAPPER="$WRAP"

if [[ "${FUZZ_DRY_RUN:-}" == "1" ]]; then
  echo "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN"
  echo "CARGO_FUZZ_TARGET=$target"
  echo "FUZZ_BIN=$BIN"
  echo "FUZZ_SANITIZER=$sanitizer"
  echo "FUZZ_JOBS=in-process"
  echo "FUZZ_TIMEOUT=$timeout"
  echo "CARGO_TARGET_DIR_UNSET=1"
  echo "RUSTC_WRAPPER=$WRAP"
  echo "FUZZ_SEED=$SEED"
  echo "FUZZ_CORPUS_MERGE=1"
  echo "FUZZ_SKIP_RATE=1"
  echo "FUZZ_CRASHERS=$CRASHERS"
  echo "FUZZ_MAX_TOTAL_TIME=$(fuzz_max_total_time)"
  dict="$(wire_dict_for_bin "$BIN")"
  if [[ -n "$dict" ]]; then
    echo "FUZZ_DICT=$dict"
  fi
  if [[ "$BIN" == "script_differential" || "$BIN" == "script_verify_differential" ]]; then
    echo "FUZZ_MAX_LEN=2000"
  fi
  if [[ "$BIN" == "block_differential" || "$BIN" == "block_spend_differential" || "$BIN" == "block_fork_differential" || "$BIN" == "script_differential" || "$BIN" == "cmpct_reorg_differential" || "$BIN" == "block_reorg_n_differential" || "$BIN" == "block_csv_differential" || "$BIN" == "mempool_differential" || "$BIN" == "script_verify_differential" || "$BIN" == "v2_session" || "$BIN" == "cmpct_differential" || "$BIN" == "p2p_sequence_differential" ]]; then
    echo "RBITCOIN_CORE_BITCOIND=${RBITCOIN_CORE_BITCOIND:-}"
  fi
  if [[ "$BIN" == "store_reorg" ]]; then
    echo "FUZZ_NO_CORE=1"
  fi
  if [[ "$BIN" == "script_kernel_differential" ]]; then
    echo "FUZZ_NO_CORE=1"
    echo "FUZZ_MAX_LEN=2000"
  fi
  if [[ "$BIN" == "v2_session" || "$BIN" == "cmpct_differential" || "$BIN" == "p2p_sequence_differential" ]]; then
    echo "BITCOIND_LISTEN=1"
  fi
  exit 0
fi

finish_fuzz() {
  local st="$1"
  if [[ "$st" -ne 0 ]]; then
    copy_crashers fuzz/artifacts "$CRASHERS"
    exit "$st"
  fi
}

echo "fuzz-run: seed=$SEED" >&2

if [[ "$BIN" == "block_wire" ]]; then
  merge_seed fuzz/corpus/block_wire \
    crates/rbitcoin-consensus/tests/fixtures/signet_block_1.bin
  merge_seed fuzz/corpus/block_wire \
    crates/rbitcoin-consensus/tests/fixtures/mainnet_block_290329.bin
  merge_seed fuzz/corpus/block_wire \
    crates/rbitcoin-consensus/tests/fixtures/signet_block_90719.bin
  set +e
  env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" block_wire -- \
    -max_total_time="$(fuzz_max_total_time)" \
    -timeout="$timeout" \
    -max_len=1048576 \
    -dict=fuzz/dict/block.dict \
    -seed="$SEED"
  st=$?
  set -e
  finish_fuzz "$st"
  exit 0
fi

if [[ "$BIN" == "v2_contents" ]]; then
  merge_seed fuzz/corpus/v2_contents crates/rbitcoin-net/tests/fixtures/v2_ping.bin
  merge_seed fuzz/corpus/v2_contents crates/rbitcoin-net/tests/fixtures/v2_verack.bin
  merge_seed fuzz/corpus/v2_contents crates/rbitcoin-net/tests/fixtures/v2_sendaddrv2.bin
  merge_seed fuzz/corpus/v2_contents crates/rbitcoin-net/tests/fixtures/v2_sendcmpct.bin
  merge_seed fuzz/corpus/v2_contents crates/rbitcoin-net/tests/fixtures/v2_getheaders.bin
  set +e
  env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" v2_contents -- \
    -max_total_time="$(fuzz_max_total_time)" \
    -timeout="$timeout" \
    -max_len=65536 \
    -dict=fuzz/dict/v2.dict \
    -seed="$SEED"
  st=$?
  set -e
  finish_fuzz "$st"
  exit 0
fi

if [[ "$BIN" == "addrv2_wire" || "$BIN" == "inv_getdata_wire" || "$BIN" == "electrum_json" ]]; then
  mkdir -p "fuzz/corpus/$BIN"
  if [[ "$BIN" == "addrv2_wire" ]]; then
    merge_seed fuzz/corpus/addrv2_wire \
      crates/rbitcoin-net/tests/fixtures/addrv2_empty.bin
  elif [[ "$BIN" == "inv_getdata_wire" ]]; then
    merge_seed fuzz/corpus/inv_getdata_wire \
      crates/rbitcoin-net/tests/fixtures/inv_one.bin
  elif [[ "$BIN" == "electrum_json" ]]; then
    if [[ ! -e "fuzz/corpus/$BIN/ping.json" ]]; then
      printf '%s\n' '{"id":1,"method":"server.ping","params":[]}' >"fuzz/corpus/$BIN/ping.json"
    fi
    merge_seed fuzz/corpus/electrum_json \
      crates/rbitcoin-electrum/tests/fixtures/blockchain_scripthash_subscribe.json
  fi
  dict="$(wire_dict_for_bin "$BIN")"
  set +e
  env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" "$BIN" -- \
    -max_total_time="$(fuzz_max_total_time)" \
    -timeout="$timeout" \
    -max_len=65536 \
    -dict="$dict" \
    -seed="$SEED"
  st=$?
  set -e
  finish_fuzz "$st"
  exit 0
fi

if [[ "$BIN" == "v2_session" ]]; then
  export RBITCOIN_CORE_BITCOIND="$(./scripts/core-functional/fetch-bitcoind.sh)"
  merge_seed fuzz/corpus/v2_session crates/rbitcoin-net/tests/fixtures/v2_ping.bin
  merge_seed fuzz/corpus/v2_session crates/rbitcoin-net/tests/fixtures/v2_verack.bin
  log="${TMPDIR:-/tmp}/rbtc-fuzz-v2.$$.log"
  set +e
  env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" v2_session -- \
    -max_total_time="$(fuzz_max_total_time)" \
    -timeout="$timeout" \
    -max_len=65536 \
    -dict=fuzz/dict/p2p.dict \
    -seed="$SEED" \
    2>&1 | tee "$log"
  st=${PIPESTATUS[0]}
  set -e
  if [[ "$st" -ne 0 ]]; then
    copy_crashers fuzz/artifacts "$CRASHERS"
    exit "$st"
  fi
  fail_if_no_comparisons "$log" 0.005
  exit 0
fi

if [[ "$BIN" == "cmpct_differential" ]]; then
  export RBITCOIN_CORE_BITCOIND="$(./scripts/core-functional/fetch-bitcoind.sh)"
  merge_seed fuzz/corpus/cmpct_differential \
    fuzz/fixtures/cmpct_fuzz_two_tx.bin
  merge_seed fuzz/corpus/cmpct_differential \
    fuzz/fixtures/cmpct_fuzz_all_prefilled.bin
  merge_seed fuzz/corpus/cmpct_differential \
    fuzz/fixtures/cmpct_fuzz_fill.bin
  merge_seed fuzz/corpus/cmpct_differential \
    fuzz/fixtures/cmpct_fuzz_dup.bin
  merge_seed fuzz/corpus/cmpct_differential \
    fuzz/fixtures/cmpct_fuzz_raw.bin
  log="${TMPDIR:-/tmp}/rbtc-fuzz-cmpct.$$.log"
  set +e
  env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" cmpct_differential -- \
    -max_total_time="$(fuzz_max_total_time)" \
    -timeout="$timeout" \
    -max_len=65536 \
    -dict=fuzz/dict/cmpct.dict \
    -seed="$SEED" \
    2>&1 | tee "$log"
  st=${PIPESTATUS[0]}
  set -e
  if [[ "$st" -ne 0 ]]; then
    copy_crashers fuzz/artifacts "$CRASHERS"
    exit "$st"
  fi
  fail_if_no_comparisons "$log" 0.005
  exit 0
fi

if [[ "$BIN" == "store_reorg" ]]; then
  export RBITCOIN_IO="${RBITCOIN_IO:-fd}"
  merge_seed fuzz/corpus/store_reorg \
    crates/rbitcoin-net/tests/fixtures/store_reorg_ops.bin
  log="${TMPDIR:-/tmp}/rbtc-fuzz-store-reorg.$$.log"
  set +e
  env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" store_reorg -- \
    -max_total_time="$(fuzz_max_total_time)" \
    -timeout="$timeout" \
    -max_len=64 \
    -seed="$SEED" \
    2>&1 | tee "$log"
  st=${PIPESTATUS[0]}
  set -e
  if [[ "$st" -ne 0 ]]; then
    copy_crashers fuzz/artifacts "$CRASHERS"
    exit "$st"
  fi
  fail_if_no_comparisons "$log" 0.01
  exit 0
fi

if [[ "$BIN" == "script_kernel_differential" ]]; then
  merge_seed fuzz/corpus/script_kernel_differential \
    crates/rbitcoin-consensus/tests/fixtures/script_kernel_op_true.bin
  merge_seed fuzz/corpus/script_kernel_differential \
    crates/rbitcoin-consensus/tests/fixtures/script_kernel_op_return.bin
  for f in crates/rbitcoin-consensus/tests/fixtures/script_fuzz_*.bin; do
    merge_seed fuzz/corpus/script_kernel_differential "$f"
  done
  log="${TMPDIR:-/tmp}/rbtc-fuzz-script-kernel.$$.log"
  set +e
  env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" script_kernel_differential -- \
    -max_total_time="$(fuzz_max_total_time)" \
    -timeout="$timeout" \
    -max_len=2000 \
    -dict=fuzz/dict/script.dict \
    -seed="$SEED" \
    2>&1 | tee "$log"
  st=${PIPESTATUS[0]}
  set -e
  if [[ "$st" -ne 0 ]]; then
    copy_crashers fuzz/artifacts "$CRASHERS"
    exit "$st"
  fi
  fail_if_no_comparisons "$log" 0.01
  exit 0
fi

if [[ "$BIN" == "p2p_sequence_differential" ]]; then
  export RBITCOIN_IO="${RBITCOIN_IO:-fd}"
  export RBITCOIN_CORE_BITCOIND="$(./scripts/core-functional/fetch-bitcoind.sh)"
  merge_seed fuzz/corpus/p2p_sequence_differential \
    crates/rbitcoin-net/tests/fixtures/p2p_seq_two_ping.bin
  log="${TMPDIR:-/tmp}/rbtc-fuzz-p2p-seq.$$.log"
  set +e
  env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" --sanitizer none p2p_sequence_differential -- \
    -max_total_time="$(fuzz_max_total_time)" \
    -timeout="$timeout" \
    -max_len=256 \
    -dict=fuzz/dict/p2p.dict \
    -seed="$SEED" \
    2>&1 | tee "$log"
  st=${PIPESTATUS[0]}
  set -e
  if [[ "$st" -ne 0 ]]; then
    copy_crashers fuzz/artifacts "$CRASHERS"
    exit "$st"
  fi
  fail_if_no_comparisons "$log" 0.005
  exit 0
fi

if [[ "$BIN" != "block_differential" && "$BIN" != "block_spend_differential" && "$BIN" != "block_fork_differential" && "$BIN" != "script_differential" && "$BIN" != "cmpct_reorg_differential" && "$BIN" != "block_reorg_n_differential" && "$BIN" != "block_csv_differential" && "$BIN" != "mempool_differential" && "$BIN" != "script_verify_differential" ]]; then
  echo "fuzz-run: unknown target $BIN" >&2
  exit 1
fi

# Tiny heads via Query::open_or_create_tiny (not RBITCOIN_HEAD_SCALE).
# tx.head tiny is 16-bit (~64k). Compared candidates uniquify coinbase + extra
# txs so mix_txid values spread; do not override RBITCOIN_TX_HEAD_BITS
# (that was a BIP30-chain workaround).
export RBITCOIN_IO="${RBITCOIN_IO:-fd}"
export RBITCOIN_CORE_BITCOIND="$(./scripts/core-functional/fetch-bitcoind.sh)"

if [[ "$BIN" == "block_differential" ]]; then
  merge_seed fuzz/corpus/block_differential \
    crates/rbitcoin-consensus/tests/fixtures/regtest_height1.bin height1.bin
  merge_seed fuzz/corpus/block_differential \
    crates/rbitcoin-consensus/tests/fixtures/mainnet_block_290329.bin
  merge_seed fuzz/corpus/block_differential \
    crates/rbitcoin-consensus/tests/fixtures/signet_block_1.bin
elif [[ "$BIN" == "block_spend_differential" ]]; then
  merge_seed fuzz/corpus/block_spend_differential \
    crates/rbitcoin-consensus/tests/fixtures/regtest_height101_spend.bin spend.bin
elif [[ "$BIN" == "script_differential" ]]; then
  merge_seed fuzz/corpus/script_differential \
    crates/rbitcoin-consensus/tests/fixtures/script_op_true.bin op_true.bin
  for f in crates/rbitcoin-consensus/tests/fixtures/script_fuzz_*.bin; do
    merge_seed fuzz/corpus/script_differential "$f"
  done
elif [[ "$BIN" == "cmpct_reorg_differential" ]]; then
  merge_seed fuzz/corpus/cmpct_reorg_differential \
    crates/rbitcoin-consensus/tests/fixtures/regtest_fork_child.bin fork.bin
elif [[ "$BIN" == "block_reorg_n_differential" ]]; then
  merge_seed fuzz/corpus/block_reorg_n_differential \
    crates/rbitcoin-consensus/tests/fixtures/regtest_fork_child.bin fork.bin
elif [[ "$BIN" == "block_csv_differential" ]]; then
  merge_seed fuzz/corpus/block_csv_differential \
    crates/rbitcoin-consensus/tests/fixtures/csv_rel1.bin rel.bin
  merge_seed fuzz/corpus/block_csv_differential \
    crates/rbitcoin-consensus/tests/fixtures/csv_time.bin time.bin
  merge_seed fuzz/corpus/block_csv_differential \
    crates/rbitcoin-consensus/tests/fixtures/script_op_true.bin op_true.bin
elif [[ "$BIN" == "mempool_differential" ]]; then
  merge_seed fuzz/corpus/mempool_differential \
    crates/rbitcoin-consensus/tests/fixtures/regtest_height101_spend.bin spend.bin
elif [[ "$BIN" == "script_verify_differential" ]]; then
  merge_seed fuzz/corpus/script_verify_differential \
    crates/rbitcoin-consensus/tests/fixtures/script_op_true.bin op_true.bin
  for f in crates/rbitcoin-consensus/tests/fixtures/script_fuzz_*.bin; do
    merge_seed fuzz/corpus/script_verify_differential "$f"
  done
else
  merge_seed fuzz/corpus/block_fork_differential \
    crates/rbitcoin-consensus/tests/fixtures/regtest_fork_child.bin fork.bin
fi

log="${TMPDIR:-/tmp}/rbtc-fuzz-diff.$$.log"
max_len=262144
dict_args=()
if [[ "$BIN" == "script_differential" || "$BIN" == "script_verify_differential" ]]; then
  max_len=2000
  dict_args=(-dict=fuzz/dict/script.dict)
fi
set +e
env -u CARGO_TARGET_DIR cargo fuzz run --target "$target" --sanitizer none "$BIN" -- \
  -max_total_time="$(fuzz_max_total_time)" \
  -timeout="$timeout" \
  -max_len="$max_len" \
  "${dict_args[@]}" \
  -seed="$SEED" \
  2>&1 | tee "$log"
st=${PIPESTATUS[0]}
set -e
if [[ "$st" -ne 0 ]]; then
  copy_crashers fuzz/artifacts "$CRASHERS"
  exit "$st"
fi
rate=0.01
if [[ "$BIN" == "mempool_differential" || "$BIN" == "script_verify_differential" ]]; then
  rate=0.005
fi
fail_if_no_comparisons "$log" "$rate"
