Fixed

- **A spend reads the output it spends, not every output of its parent.**
  Resolving a prevout decoded the whole funding transaction and kept one
  output, so validation cost grew with the parent's output count: a block
  of 2,000 spends of one 20,000-output transaction took seconds. The store
  now reads one body span per parent and decodes only the spent outputs,
  on mempool accept, block proposals, the `submitblock` pre-check, and the
  fee stamp at connect, each reading a parent once per block. (#1349)
