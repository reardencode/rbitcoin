Fixed

- **A replacement may evict several mempool transactions that spend its unconfirmed inputs.** That is Core's cluster replacement. An unrelated unconfirmed input is still refused. Spending an output of a transaction the replacement evicts is `bad-txns-spends-conflicting-tx`. That spend used to enter the pool, so `getblocktemplate` could offer a block that fails `bad-txns-inputs-missingorspent`. A replacement that would exceed the cluster cap is `too-large-cluster`.
