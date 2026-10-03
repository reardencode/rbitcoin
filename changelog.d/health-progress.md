Added

- **`GET /progress` on the health listener.** JSON for the long stage
  running now (`tx.head` rebuild and tail backfill and input backfill
  while the store opens; the scripthash index build passes while
  indexing): `phase`, `stage`, `done`, `total`, `percent`,
  `elapsed_secs`, and a linear `eta_secs`, plus `finished` for the stage
  that ended last, at any `--log-level`. `--metrics` exports
  `rbitcoin_progress_done` / `_target` / `_start_time_seconds` with a
  `stage` label. `/readyz` is unchanged. The `tx.head` rebuild now counts
  each sealed range as it lands; its INFO line still prints only at the
  end.
