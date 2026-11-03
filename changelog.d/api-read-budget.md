Added

- **RPC, REST, Electrum, Esplora, and BlindBit share one budget for store reads.** Each read takes a permit from one semaphore.
- **The default budget is 1 on rotating media, otherwise one less than the core count.** The minimum is 1. `--datadir-hdd` selects 1 only when `--store-read-budget` is omitted or `0`. `--store-read-budget N` (conf `store_read_budget=`) overrides that, including on rotating media.
- **The Esplora in-flight cap and the RPC work queue sit in front of this budget.** A full RPC work queue is still HTTP 503 before any call in that POST runs, and before a long-poll checks the tip. After a long-poll, the next call in that POST waits for a work-queue slot. A long-poll does not hold a disk permit while it waits.
- **A `getblocktemplate` without a `longpollid` keeps its work-queue slot.** It is not a long-poll. The build reads the template tip on a worker, with no disk permit, takes one permit, and reads the tip again without waiting on block connect. It builds only when both reads match. A long-poll's wait still samples the tip off the permit.
- **Esplora `GET /block-template` uses that same build read, before its 15-second cache lock.** The cache time is unchanged.
