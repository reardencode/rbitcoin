Fixed

- **A missing scripthash include mark is not indexed-through-tip.**
  Restart used to treat a durable head with no include mark as caught
  up, so confirmed transactions in the gap never entered the index and
  later blocks were applied above it. Recovery re-queues from the
  start. A head that already wrote the mark still resumes at that height.
