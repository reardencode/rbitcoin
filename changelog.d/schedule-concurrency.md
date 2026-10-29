Fixed

- **A push to `master` does not cancel a nightly Actions run.** Each scheduled workflow uses its own concurrency group. `mutants` still shares one group and queues, so two nights cannot both publish `mutants-state`.
