#!/usr/bin/env bash
# Cargo sets RUSTC_WRAPPER and invokes: $WRAPPER $RUSTC <args>.
# Exec the given rustc (do not insert another rustc in front of $1).
# Append so this wins over Cargo's `-D warnings` (later rustc flags win).
exec "$@" -A warnings
