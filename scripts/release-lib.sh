# Shared helpers for scripts/release*.sh. ROOT must be set before sourcing.
# Not executed on its own.

release_die() { echo "error: $*" >&2; exit 1; }

release_cargo_workspace_version() {
  awk '
    /^\[workspace.package\]/ { p = 1; next }
    p && /^\[/ { exit }
    p && /^version = "/ {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' "$ROOT/Cargo.toml"
}

release_nix_package_version() {
  awk '
    /^[[:space:]]*version = "/ {
      gsub(/[";]/, "", $3)
      print $3
      exit
    }
  ' "$ROOT/nix/rbitcoin.nix"
}

release_changelog_has_heading() {
  local ver="$1"
  grep -qE "^## \\[${ver}\\]" "$ROOT/CHANGELOG.md"
}

release_changelog_notes() {
  local ver="$1"
  awk -v ver="$ver" '
    $0 ~ ("^## \\[" ver "\\]") { p = 1; next }
    p && /^## \[/ { exit }
    p { print }
  ' "$ROOT/CHANGELOG.md" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
}

# Body under ### Highlights for ## [ver], not including the heading.
release_changelog_highlights() {
  local ver="$1"
  awk -v ver="$ver" '
    $0 ~ ("^## \\[" ver "\\]") { p = 1; next }
    p && /^## \[/ { exit }
    p && /^### Highlights/ { h = 1; next }
    h && /^### / { exit }
    h && /^## / { exit }
    h { print }
  ' "$ROOT/CHANGELOG.md"
}

release_require_highlights() {
  local ver="$1"
  local body bullets n
  body="$(release_changelog_highlights "$ver")"
  [[ -n "$(printf '%s\n' "$body" | grep -v '^[[:space:]]*$')" ]] || \
    release_die "CHANGELOG.md ## [$ver] has no ### Highlights section"
  bullets="$(printf '%s\n' "$body" | grep -E '^- ' || true)"
  [[ -n "$bullets" ]] || \
    release_die "CHANGELOG.md ## [$ver] ### Highlights has no bullets"
  n="$(printf '%s\n' "$bullets" | grep -c .)"
  (( n <= 11 )) || \
    release_die "CHANGELOG.md ## [$ver] ### Highlights has $n bullets (max 11)"
}

release_parse_semver() {
  local ver="$1"
  [[ "$ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 1
  REL_MAJOR="${BASH_REMATCH[1]}"
  REL_MINOR="${BASH_REMATCH[2]}"
  REL_PATCH="${BASH_REMATCH[3]}"
}

release_is_ship() {
  [[ "${REL_PATCH:-}" != "99" ]]
}

release_is_maint_branch() {
  local branch="$1"
  [[ "$branch" =~ ^v[0-9]+\.[0-9]+\.x$ ]]
}

release_kind() {
  local ver
  ver="$(release_cargo_workspace_version)"
  release_parse_semver "$ver" || release_die "Cargo.toml workspace version is not X.Y.Z: ${ver:-empty}"
  if release_is_ship; then
    echo ship
  else
    echo dev
  fi
}

release_set_cargo_version() {
  local new="$1"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/rbitcoin-cargo-ver.XXXXXX")"
  awk -v new="$new" '
    /^\[workspace.package\]/ { p = 1 }
    p && /^\[/ && $0 != "[workspace.package]" { p = 0 }
    p && /^version = "/ { print "version = \"" new "\""; next }
    { print }
  ' "$ROOT/Cargo.toml" >"$tmp"
  mv "$tmp" "$ROOT/Cargo.toml"
}

release_set_nix_version() {
  local new="$1"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/rbitcoin-nix-ver.XXXXXX")"
  awk -v new="$new" '
    BEGIN { done = 0 }
    !done && /^[[:space:]]*version = "/ {
      sub(/version = "[^"]*"/, "version = \"" new "\"")
      done = 1
    }
    { print }
  ' "$ROOT/nix/rbitcoin.nix" >"$tmp"
  mv "$tmp" "$ROOT/nix/rbitcoin.nix"
}

# Fold changelog.d/*.md into ## [Unreleased], then delete those files.
# README.md is the pointer, not a note. thanks.md is the one-shot thanks
# paragraph for ### Highlights, not a category fragment. First non-empty
# line of a fragment is the Keep a Changelog category; the rest is the
# bullet text.
release_changelog_absorb_fragments() {
  local dir="$ROOT/changelog.d"
  [[ -d "$dir" ]] || return 0
  local files=() f base cat scratch categories
  shopt -s nullglob
  files=("$dir"/*.md)
  shopt -u nullglob
  local pending=()
  for f in "${files[@]}"; do
    base="$(basename "$f")"
    [[ "$base" == "README.md" || "$base" == "thanks.md" ]] && continue
    pending+=("$f")
  done
  ((${#pending[@]})) || return 0

  scratch="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-clfrag.XXXXXX")"
  categories=(Added Changed Deprecated Removed Fixed Security)
  for f in "${pending[@]}"; do
    cat="$(awk 'NF { print; exit }' "$f")"
    case "$cat" in
      Added | Changed | Deprecated | Removed | Fixed | Security) ;;
      *)
        release_die "changelog.d/$(basename "$f") category must be Added, Changed, Deprecated, Removed, Fixed, or Security (got: ${cat:-empty})"
        ;;
    esac
    awk 'BEGIN { skipped = 0 } !skipped && NF { skipped = 1; next } { print }' "$f" >>"$scratch/$cat.md"
    printf '\n' >>"$scratch/$cat.md"
  done

  local c
  for c in "${categories[@]}"; do
    [[ -f "$scratch/$c.md" ]] || continue
    release_changelog_insert_category "$c" "$scratch/$c.md"
  done
  rm -f "${pending[@]}"
  rm -rf "$scratch"
}

release_changelog_insert_category() {
  local cat="$1"
  local bodyfile="$2"
  local file="$ROOT/CHANGELOG.md"
  local start end catline next tmp
  start="$(grep -n '^## \[Unreleased\]' "$file" | head -1 | cut -d: -f1)"
  [[ -n "$start" ]] || release_die "CHANGELOG.md has no ## [Unreleased] heading"
  end="$(awk -v s="$start" 'NR > s && /^## / { print NR; exit }' "$file")"
  [[ -n "$end" ]] || end="$(($(wc -l <"$file") + 1))"
  catline="$(awk -v s="$start" -v e="$end" -v c="### $cat" \
    'NR > s && NR < e && $0 == c { print NR; exit }' "$file")"
  if [[ -n "$catline" ]]; then
    next="$(awk -v s="$catline" -v e="$end" \
      'NR > s && NR < e && (/^### / || /^## /) { print NR; exit }' "$file")"
    [[ -n "$next" ]] || next="$end"
  else
    next="$end"
  fi
  tmp="$(mktemp "${TMPDIR:-/tmp}/rbitcoin-clins.XXXXXX")"
  head -n "$((next - 1))" "$file" >"$tmp"
  if [[ -z "$catline" ]]; then
    printf '\n### %s\n\n' "$cat" >>"$tmp"
  fi
  cat "$bodyfile" >>"$tmp"
  tail -n "+$next" "$file" >>"$tmp"
  mv "$tmp" "$file"
}

# changelog.d/thanks.md is one release only. Print its paragraph and delete
# it. The cut places that paragraph under ### Highlights. It is not a
# bullet and there is no ### Thanks section. Later cuts have nothing to repeat.
release_changelog_take_thanks() {
  local f="$ROOT/changelog.d/thanks.md"
  [[ -f "$f" ]] || return 0
  local file="$ROOT/CHANGELOG.md"
  local start end
  start="$(grep -n '^## \[Unreleased\]' "$file" | head -1 | cut -d: -f1)"
  [[ -n "$start" ]] || release_die "CHANGELOG.md has no ## [Unreleased] heading"
  end="$(awk -v s="$start" 'NR > s && /^## / { print NR; exit }' "$file")"
  [[ -n "$end" ]] || end="$(($(wc -l <"$file") + 1))"
  if awk -v s="$start" -v e="$end" 'NR > s && NR < e && /^### Thanks$/ { found = 1 } END { exit !found }' "$file"; then
    release_die "CHANGELOG.md already has ### Thanks under Unreleased"
  fi
  cat "$f"
  rm -f "$f"
}

release_cut_changelog_ship() {
  local ver="$1"
  local date="$2"
  local tmp thanksf
  thanksf="$(mktemp "${TMPDIR:-/tmp}/rbitcoin-clthanks.XXXXXX")"
  release_changelog_take_thanks >"$thanksf"
  release_changelog_absorb_fragments
  tmp="$(mktemp "${TMPDIR:-/tmp}/rbitcoin-cl.XXXXXX")"
  awk -v ver="$ver" -v date="$date" -v tf="$thanksf" '
    function emit_thanks(   line, any) {
      any = 0
      while ((getline line < tf) > 0) {
        print line
        any = 1
      }
      close(tf)
      if (any) print ""
    }
    /^## \[Unreleased\]/ {
      print
      print ""
      print "## [" ver "] — " date
      print ""
      print "### Highlights"
      print ""
      emit_thanks()
      next
    }
    { print }
  ' "$ROOT/CHANGELOG.md" >"$tmp"
  mv "$tmp" "$ROOT/CHANGELOG.md"
  rm -f "$thanksf"
}

release_cut_changelog_dev_next() {
  local ver="$1"
  local toward="$2"
  local published="$3"
  local maint="$4"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/rbitcoin-cl-dev.XXXXXX")"
  awk -v ver="$ver" -v toward="$toward" -v published="$published" -v maint="$maint" '
    /^## \[Unreleased\]/ {
      print
      print ""
      print "### Changed"
      print ""
      print "- **Workspace version " ver ":** in-tree toward " toward "."
      print "  Published GitHub Releases remain " published "; `" maint "` is the patch branch."
      next
    }
    { print }
  ' "$ROOT/CHANGELOG.md" >"$tmp"
  mv "$tmp" "$ROOT/CHANGELOG.md"
}

release_latest_maint_branch() {
  local names name best_maj=-1 best_min=-1 best=""
  local maj min
  names="$(
    git -C "$ROOT" for-each-ref --format='%(refname:short)' \
      'refs/heads/v*.*.x' 'refs/remotes/*/v*.*.x' 2>/dev/null || true
  )"
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    name="${name##*/}"
    [[ "$name" =~ ^v([0-9]+)\.([0-9]+)\.x$ ]] || continue
    maj="${BASH_REMATCH[1]}"
    min="${BASH_REMATCH[2]}"
    if (( maj > best_maj || (maj == best_maj && min > best_min) )); then
      best_maj="$maj"
      best_min="$min"
      best="$name"
    fi
  done <<<"$names"
  [[ -n "$best" ]] || return 1
  printf '%s\n' "$best"
}

release_plan_minor() {
  local ver="$1"
  release_parse_semver "$ver" || return 1
  [[ "$REL_PATCH" == "99" ]] || return 1
  REL_SHIP="${REL_MAJOR}.$((REL_MINOR + 1)).0"
  REL_MAINT="v${REL_MAJOR}.$((REL_MINOR + 1)).x"
  REL_DEV_NEXT="${REL_MAJOR}.$((REL_MINOR + 1)).99"
}

release_plan_major() {
  local ver="$1"
  release_parse_semver "$ver" || return 1
  [[ "$REL_PATCH" == "99" ]] || return 1
  REL_SHIP="$((REL_MAJOR + 1)).0.0"
  REL_MAINT="v$((REL_MAJOR + 1)).0.x"
  REL_DEV_NEXT="$((REL_MAJOR + 1)).0.99"
}

release_plan_patch() {
  local ver="$1"
  release_parse_semver "$ver" || return 1
  [[ "$REL_PATCH" != "99" ]] || return 1
  local next=$((REL_PATCH + 1))
  (( next < 99 )) || return 1
  REL_SHIP="${REL_MAJOR}.${REL_MINOR}.${next}"
  REL_MAINT="v${REL_MAJOR}.${REL_MINOR}.x"
  REL_DEV_NEXT=""
}

release_plan_dev_next() {
  local ver="$1"
  release_parse_semver "$ver" || return 1
  [[ "$REL_PATCH" == "0" ]] || return 1
  REL_SHIP=""
  REL_MAINT="v${REL_MAJOR}.${REL_MINOR}.x"
  REL_DEV_NEXT="${REL_MAJOR}.${REL_MINOR}.99"
  REL_TOWARD="${REL_MAJOR}.$((REL_MINOR + 1)).0"
}
