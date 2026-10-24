Fixed

- **`submitpackage` admits a 0-fee anchor parent with the child that spends it.**
  The parent fails alone as `dust`, before the min-relay check, so the package
  remainder now includes that failure and `accept_package` allows the output
  only when the fee is 0 and a later member spends it. A lone submit and a
  fee-paying 0-value output stay `dust`. A version-3 child of an unconfirmed
  version-2 parent stays `truc-ancestor`.
