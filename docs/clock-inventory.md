# Clock inventory for #821 Step 1

HEAD: 886463ef master (2026-09-27) Merge #823 - latest, 100 sites
Command: rg -n "SystemTime::now()" crates/ --type rust -g '!*tests*' --no-heading | sort

Summary from your run:
- 10 crates/rbitcoin-store/src/bulk_io.rs -> log/perf LEAVE
- 6 crates/rbitcoin-node/src/run.rs -> mostly log/perf
- 5 crates/rbitcoin-store/src/bdz.rs -> log/perf LEAVE
- 4+4+4 peer.rs, spender_table, scripthash_head -> mix
- 3 peers.rs:1249 mock_now Acquire/Release + set_mock_now() bypasses hub.clock -> CRITICAL MIGRATE (split-brain), tx_relay.rs:625 mock_now Relaxed + note_mock_now() bypasses hub.clock -> CRITICAL MIGRATE, service.rs/seeds.rs -> node-time
- 2 tx_relay.rs -> 1x node-time (928 manual mock -> NodeClock), 1x log/perf (3753 tmp uniqueness) LEAVE

Legend per Rearden #688 item 2.1:
- log/perf: log stamps, metrics, perf timers - LEAVE as SystemTime::now()
- node-time: consensus / net / mempool / rpc - MIGRATE to NodeClock
- wall: explicitly wants wall even under mocktime (INV age gate)

| File | Line | Code | Class | Notes |
|------|------|------|-------|-------|
| crates/rbitcoin-cli/src/lib.rs | 328 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-consensus/src/clock.rs | 44 | `unix_secs(SystemTime::now())` | log/perf - LEAVE (root wall source - impl of NodeClock::now()) | |
| crates/rbitcoin-consensus/src/header.rs | 353 | `let n = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-consensus/src/lib.rs | 372 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-consensus/src/params.rs | 738 | `let n = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-consensus/src/regtest_pad.rs | 152 | `let n = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-consensus/src/script/core_fixture.rs | 130 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-electrum/src/tweaks.rs | 661 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-electrum/src/tweaks.rs | 767 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-electrum/src/tweaks.rs | 855 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-esplora/src/tx_json.rs | 584 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-esplora/src/tx_json.rs | 726 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-log/src/api_log.rs | 134 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-log/src/api_log.rs | 77 | `let ts = format_timestamp(SystemTime::now());` | log/perf - LEAVE | |
| crates/rbitcoin-log/src/lib.rs | 195 | `let ts = format_timestamp(SystemTime::now());` | log/perf - LEAVE | |
| crates/rbitcoin-mempool/src/accept.rs | 118 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-mempool/src/orphanage.rs | 415 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/asmap.rs | 500 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/i2p_sam.rs | 871 | `SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/peer_header_dos_journey.rs | 730 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/peer_header_dos_journey.rs | 903 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/peer.rs | 1116 | `let tick = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/peer.rs | 2785 | `let now_ms = std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/peer.rs | 835 | `let now = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/peer.rs | 925 | `let now = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/peers.rs | 1165 | `let tick = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/peers.rs | 1849 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/peers.rs | 920 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/seeds.rs | 1236 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/seeds.rs | 1487 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/seeds.rs | 1580 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/service.rs | 823 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/service.rs | 892 | `let n = std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/service.rs | 959 | `let n = std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-net/src/tx_relay.rs | 3753 | `let n = SystemTime::now()` | log/perf - LEAVE (tmp path uniqueness) | |
| crates/rbitcoin-net/src/tx_relay.rs | 928 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock (manual mock check -> use NodeClock) | |
| crates/rbitcoin-node/src/cli.rs | 533 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-node/src/config.rs | 1430 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-node/src/lock.rs | 101 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-node/src/regtest_rpc.rs | 53 | `let n = SystemTime::now()` | node-time - MIGRATE (setmocktime path) | |
| crates/rbitcoin-node/src/run.rs | 2117 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-node/src/run.rs | 2132 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-node/src/run.rs | 2154 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-node/src/run.rs | 2413 | `let nanos = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-node/src/run.rs | 2458 | `let nanos = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-node/src/run.rs | 2516 | `let nanos = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-query/src/run_builder_core.rs | 74 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-query/src/sh_builder.rs | 247 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-rpc/src/auth.rs | 114 | `let n = SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-rpc/src/methods/mine.rs | 609 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-rpc/src/methods/mine.rs | 751 | `std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-rpc/src/methods/net.rs | 13 | `let timemillis = std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-rpc/src/methods/net.rs | 290 | `let now = std::time::SystemTime::now()` | node-time - MIGRATE to NodeClock | |
| crates/rbitcoin-store/src/address_head.rs | 1833 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/array_table.rs | 345 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bdz.rs | 1293 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bdz.rs | 1514 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bdz.rs | 1575 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bdz.rs | 1656 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bdz.rs | 1723 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bulk_io.rs | 1005 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bulk_io.rs | 1070 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bulk_io.rs | 1147 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bulk_io.rs | 1230 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bulk_io.rs | 651 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bulk_io.rs | 720 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bulk_io.rs | 798 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bulk_io.rs | 850 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bulk_io.rs | 910 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/bulk_io.rs | 975 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/chain.rs | 594 | `std::time::SystemTime::now()` | node-time - MIGRATE (tip time) | |
| crates/rbitcoin-store/src/chain.rs | 847 | `std::time::SystemTime::now()` | node-time - MIGRATE (tip time) | |
| crates/rbitcoin-store/src/fuse8_filter.rs | 235 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/hashhead.rs | 984 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/header_table.rs | 504 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/integrity.rs | 471 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/io_session_iocp.rs | 254 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/point_table.rs | 152 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/readonly_map.rs | 203 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/scripthash_head.rs | 790 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/scripthash_head.rs | 819 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/scripthash_head.rs | 860 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/scripthash_head.rs | 921 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/scripthash_materialize.rs | 2386 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/scripthash_materialize.rs | 2416 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/scripthash_mphf.rs | 370 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/scripthash_sorted_head.rs | 330 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/segmented_head.rs | 1263 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/spend_durable.rs | 75 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/spender_table.rs | 129 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/spender_table.rs | 174 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/spender_table.rs | 203 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/spender_table.rs | 229 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/testutil.rs | 27 | `let nanos = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/tx_head_mphf.rs | 225 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/txid_body.rs | 391 | `let n = SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/uring_session.rs | 1834 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/var_table.rs | 631 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/var_table.rs | 676 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
| crates/rbitcoin-store/src/var_table.rs | 739 | `std::time::SystemTime::now()` | log/perf - LEAVE | |
