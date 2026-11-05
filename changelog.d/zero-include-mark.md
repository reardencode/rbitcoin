Fixed

- **A scripthash index with no progress mark is rebuilt.** Restart used to
  treat a head with no include mark and no SEAL as caught up, so confirmed
  transactions in the gap never entered the index and later blocks were
  applied above it. Startup deletes that head and builds the index from
  the archive. A mark, or a SEAL when the mark file is missing, still
  resumes at the height it covers.
