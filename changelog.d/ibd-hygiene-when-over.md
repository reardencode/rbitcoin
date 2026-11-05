Fixed

- **The header-chain walk runs only when it has rows to drop.** It is no
  longer on the once-a-second path. At most once a minute, it walks the
  header set when that set is more than 4,096 rows past the live queue,
  the in-flight blocks, and the height index, and it walks the work-path
  maps when those are more than 4,096 rows past the header set. A header
  sync does not trip it just because the chain is long. Rows a retired
  fork leaves behind are in the second check. A height that is still
  occupied keeps its row.
