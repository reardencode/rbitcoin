Fixed

- **A scripthash head with no include mark and no SEAL is rebuilt.**
  Restart used to treat that head as caught up, so confirmed
  transactions in the gap never entered the index and later blocks were
  applied above it. Replaying every height from the start is the append
  path over the whole chain. Startup deletes the head and
  bulk-materializes from Class A. A mark, or a SEAL when the mark file
  is missing, still resumes at the height it covers.
