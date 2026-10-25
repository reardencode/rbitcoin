Fixed

- **`ArrayTable` write-behind holds under every schedule the model checkers
  explored.** Four defects in the dirty-tracking protocol, found by the new
  suite: after a `truncate`, a flush that still shrank the file dropped
  every `set` below the old on-disk length that landed before it (no
  current caller reached it, since `disconnect_tip` flushes the shrink
  alone); a dirty mark landing right after a flush's clean step could read
  the stale low-water mark and lose an in-prefix write, which only aarch64
  can show; a rewriting flush whose length publish failed left a stale tail
  on disk once the writer truncated back to the on-disk length; and on the
  fd-only path a `get` racing a `truncate` returned a `Corrupt` error, or a
  value whose length was not yet published.
- **`ArrayTable` write-behind is model-checked.** Loom and shuttle drive
  `set` / `set_many` / `truncate` / `get` against `flush_dirty` over an
  in-memory file with faults, torn writes, and a reopen view, in
  `crates/rbitcoin-store/tests/model/main.rs` (`./scripts/model-check.sh
  loom|shuttle`, CI `model.yml`, nightly deep budget).
