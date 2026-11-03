Added

- **`--datadir-hdd` marks the main datadir as rotating media.** Default off. The node does not probe the block device. NixOS `services.rbitcoin.datadirHdd` passes the flag.
- **Confirm writes that body data as separate waves and holds the disk across them.** Each of `txout`, `seqsigwit`, and `spent` is its own write. The confirm thread holds the disk across those writes and across the spend-annotation sweep. The `tx.head` insert starts after annotation returns.
- **Lookup and load wait before each bulk read.** Script threads, RPC, scripthash extract, and the index builder do not.
- **Spend annotation is a 4 KiB page update on every device.** That sweep asks the kernel for random access. On every device, pin reads also join a hole of at most 64 KiB when the merged span stays at most 256 KiB.
