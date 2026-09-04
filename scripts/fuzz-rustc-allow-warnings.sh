#!/usr/bin/env bash
# Nightly cargo-fuzz inherits workspace `warnings = deny` on path members.
# Append so this wins over Cargo's `-D warnings` (later rustc flags win).
exec rustc "$@" -A warnings
