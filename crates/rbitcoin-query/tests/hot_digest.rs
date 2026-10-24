//! Logical digest of a store's confirmed chain (`Query::hot_digest`).
#![cfg(test)]
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use rbitcoin_consensus::{mine_empty_regtest, mine_regtest_paying, ChainParams, Milestone};
use rbitcoin_primitives::Height;
use rbitcoin_query::hot_digest::import_hot_store;
use rbitcoin_query::testutil::TempDir;
use rbitcoin_query::{accept_and_connect_block, confirm_wire_run, Query};
use rbitcoin_store::integrity::TipSeal;
use rbitcoin_store::spend_durable::SpendDurable;
use rbitcoin_store::StoreLayout;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn op_true() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

fn spend(prev: bitcoin::Txid, sats: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: op_true(),
        }],
    }
}

/// Regtest genesis plus 101 empty blocks: the height-1 coinbase is spendable
/// at 102. Mined once and batch-connected into each store.
fn mature_chain() -> (Block, Vec<(Height, Block)>) {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let (mut tip, mut time) = (genesis.block_hash(), genesis.header.time);
    let mut blocks = Vec::new();
    for h in 1..=101 {
        let b = mine_empty_regtest(tip, time + 600, h);
        (tip, time) = (b.block_hash(), b.header.time);
        blocks.push((Height(h), b));
    }
    (genesis, blocks)
}

fn mature_store(label: &str, chain: &(Block, Vec<(Height, Block)>)) -> (TempDir, Query) {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled(label);
    let params = ChainParams::regtest();
    accept_and_connect_block(&q, &params, Height::GENESIS, &chain.0, Milestone::NONE).unwrap();
    confirm_wire_run(&q, &params, Milestone::NONE, &chain.1).unwrap();
    (dir, q)
}

/// Block 102 on top of [`mature_chain`]: spends the height-1 coinbase.
fn block_102(chain: &(Block, Vec<(Height, Block)>)) -> Block {
    let tip = &chain.1.last().unwrap().1;
    let cb1 = chain.1[0].1.txdata[0].compute_txid();
    mine_regtest_paying(
        tip.block_hash(),
        tip.header.time + 600,
        102,
        op_true(),
        vec![spend(cb1, 49_0000_0000)],
    )
}

/// A store that first connects a sibling 102' spending the same coinbase,
/// then reorgs to `b102`. The sibling's creates and its spend annotation stay
/// behind as non-strong rows, so this store numbers `b102` differently from a
/// store that only ever saw `b102`.
fn reorged_store(
    label: &str,
    chain: &(Block, Vec<(Height, Block)>),
    b102: &Block,
) -> (TempDir, Query) {
    let params = ChainParams::regtest();
    let cb1 = chain.1[0].1.txdata[0].compute_txid();
    let (dir, q) = mature_store(label, chain);
    let sibling = mine_regtest_paying(
        b102.header.prev_blockhash,
        b102.header.time + 1,
        102,
        op_true(),
        vec![spend(cb1, 48_0000_0000)],
    );
    accept_and_connect_block(&q, &params, Height(102), &sibling, Milestone::NONE).unwrap();
    q.disconnect_tip().unwrap();
    accept_and_connect_block(&q, &params, Height(102), b102, Milestone::NONE).unwrap();
    (dir, q)
}

/// Same final chain, different secrets and reorg history: equal digests.
/// One extra strong spender annotation changes the digest.
#[test]
fn hot_digest_ignores_secret_and_reorg_history() {
    let params = ChainParams::regtest();
    let chain = mature_chain();
    let b102 = block_102(&chain);
    let (dir_a, a) = mature_store("hot-digest-a", &chain);
    accept_and_connect_block(&a, &params, Height(102), &b102, Milestone::NONE).unwrap();
    let (dir_b, b) = reorged_store("hot-digest-b", &chain, &b102);
    assert_ne!(
        a.block_tx_fks(Height(102)).unwrap(),
        b.block_tx_fks(Height(102)).unwrap(),
        "the pin needs B's fks to differ from A's"
    );
    assert_ne!(
        a.store().txs.store_secret().as_bytes(),
        b.store().txs.store_secret().as_bytes()
    );

    let da = a.hot_digest().unwrap().expect("non-empty store");
    let db = b.hot_digest().unwrap().expect("non-empty store");
    assert_eq!(
        (da.height, da.tip_hash),
        (102, b102.block_hash().to_byte_array())
    );
    assert_eq!(da, db);

    // Height 5's coinbase output is unspent. Annotate it as spent by the
    // strong spend at height 102.
    let cb5 = b.block_tx_fks(Height(5)).unwrap()[0];
    let spend_fk = b.block_tx_fks(Height(102)).unwrap()[1];
    b.store().put_spend_create(cb5, 0, spend_fk, 0).unwrap();
    assert_ne!(b.hot_digest().unwrap().unwrap().digest, da.digest);

    let (dir_e, empty) = rbitcoin_query::testutil::tiny_query_labeled("hot-digest-empty");
    assert!(empty.hot_digest().unwrap().is_none());
    for d in [dir_a, dir_b, dir_e] {
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// Import from the reorged store into an empty one: the digest matches, the
/// orphaned sibling's rows are not carried over, the secret is new, and the
/// chain reads back the same. A wrong digest and a non-empty destination are
/// refused.
#[test]
fn assumehot_import_rewrites_confirmed_chain() {
    let chain = mature_chain();
    let b102 = block_102(&chain);
    let (dir_src, src) = reorged_store("assumehot-src", &chain, &b102);
    let want = src.hot_digest().unwrap().expect("non-empty source");

    let (dir_bad, bad) = rbitcoin_query::testutil::tiny_query_labeled("assumehot-bad");
    let mut wrong = want.digest;
    wrong[0] ^= 1;
    let err = bad
        .import_hot(&src, &ChainParams::regtest(), wrong)
        .unwrap_err()
        .to_string();
    assert!(
        err.starts_with("assumehot: digest mismatch (expected "),
        "{err}"
    );

    let (dir_dst, dst) = rbitcoin_query::testutil::tiny_query_labeled("assumehot-dst");
    dst.import_hot(&src, &ChainParams::regtest(), want.digest)
        .unwrap();
    assert_eq!(dst.hot_digest().unwrap(), Some(want));
    assert_ne!(
        src.store().txs.store_secret().as_bytes(),
        dst.store().txs.store_secret().as_bytes()
    );
    let mut confirmed = 0u64;
    for h in 0..=102 {
        assert_eq!(
            dst.reconstruct_block_at_height(Height(h)).unwrap(),
            src.reconstruct_block_at_height(Height(h)).unwrap(),
            "height {h}"
        );
        confirmed += dst.block_tx_fks(Height(h)).unwrap().len() as u64;
    }
    assert!(
        src.store().txs.count() > confirmed,
        "the source must hold orphans"
    );
    assert_eq!(dst.store().txs.count(), confirmed);
    let cb1 = dst.block_tx_fks(Height(1)).unwrap()[0];
    let spend_fk = dst.block_tx_fks(Height(102)).unwrap()[1];
    assert_eq!(
        dst.store().spenders_create(cb1, 0).unwrap(),
        vec![(spend_fk, 0)]
    );

    let err = dst
        .import_hot(&src, &ChainParams::regtest(), want.digest)
        .unwrap_err()
        .to_string();
    assert_eq!(err, "assumehot: destination store is not empty");
    for d in [dir_src, dir_bad, dir_dst] {
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// What a node's shutdown leaves behind: one spend checkpoint
/// (`SpendSync::shutdown`), then a flush.
fn clean_shutdown(q: Query) {
    rbitcoin_query::spend_sync::checkpoint(&q).unwrap();
    q.store().flush().unwrap();
    drop(q);
}

/// Every file under `dir`, by relative path, with its bytes.
fn tree_bytes(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.insert(
                    p.strip_prefix(dir).unwrap().to_path_buf(),
                    std::fs::read(&p).unwrap(),
                );
            }
        }
    }
    out
}

fn copy_tree(from: &Path, to: &Path) {
    for (rel, bytes) in tree_bytes(from) {
        let p = to.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
}

/// The datadir-level import: it stages under `store.import`, renames only on
/// a match, leaves the source byte-identical, and seals the tip markers so the
/// first open does not walk from genesis. Unclean, old-schema and pruned
/// sources, an existing destination and a cold destination are refused before
/// anything is written.
#[test]
fn assumehot_import_store_stages_and_refuses_unclean_sources() {
    let chain = mature_chain();
    let b102 = block_102(&chain);
    let (dir_src, src) = reorged_store("assumehot-store-src", &chain, &b102);
    let want = src.hot_digest().unwrap().expect("non-empty source");
    clean_shutdown(src);
    let before = tree_bytes(dir_src.path());

    let scratch = TempDir::labeled("assumehot-store-dst").unwrap();
    let dst = scratch.path().join("store");
    let staging = scratch.path().join("store.import");
    let import = |src: &Path, dst: &Path, digest: [u8; 32]| {
        import_hot_store(
            StoreLayout::tiny(src),
            StoreLayout::tiny(dst),
            &ChainParams::regtest(),
            digest,
        )
        .map_err(|e| e.to_string())
    };

    let mut wrong = want.digest;
    wrong[0] ^= 1;
    let err = import(dir_src.path(), &dst, wrong).unwrap_err();
    assert!(
        err.starts_with("assumehot: digest mismatch (expected "),
        "{err}"
    );
    assert!(
        !dst.exists() && !staging.exists(),
        "a mismatch leaves nothing"
    );

    assert_eq!(import(dir_src.path(), &dst, want.digest).unwrap(), want);
    assert!(!staging.exists());
    assert!(
        tree_bytes(dir_src.path()) == before,
        "the import must not write to the source"
    );
    assert_eq!(
        TipSeal::load(&dst).unwrap().map(|s| s.tip_height),
        Some(102)
    );
    assert_eq!(
        SpendDurable::load(&dst).unwrap(),
        Some(SpendDurable::new(102, 102))
    );
    let reopened = Query::open_or_create_tiny(&dst).unwrap();
    assert_eq!(reopened.hot_digest().unwrap(), Some(want));
    drop(reopened);

    assert_eq!(
        import(dir_src.path(), &dst, want.digest).unwrap_err(),
        "assumehot: destination store is not empty"
    );
    let mut cold = StoreLayout::tiny(scratch.path().join("cold-store"));
    cold.cold_dir = Some(scratch.path().join("cold"));
    assert_eq!(
        import_hot_store(
            StoreLayout::tiny(dir_src.path()),
            cold,
            &ChainParams::regtest(),
            want.digest
        )
        .unwrap_err()
        .to_string(),
        "assumehot: a cold destination (--datadir-cold) is not supported"
    );

    let refused = |label: &str, edit: &dyn Fn(&Path)| -> String {
        let copy = TempDir::labeled(label).unwrap();
        copy_tree(dir_src.path(), copy.path());
        edit(copy.path());
        let out = scratch.path().join(label);
        let err = import(copy.path(), &out, want.digest).unwrap_err();
        assert!(!out.exists(), "{label}: a refusal leaves nothing");
        let _ = std::fs::remove_dir_all(copy.path());
        err
    };
    assert_eq!(
        refused("no-spend-marker", &|d| std::fs::remove_file(
            d.join("spend_durable")
        )
        .unwrap()),
        "assumehot: source did not shut down cleanly (spend_durable is missing)"
    );
    assert_eq!(
        refused("no-tip-seal", &|d| std::fs::remove_file(d.join("tip_seal"))
            .unwrap()),
        "assumehot: source did not shut down cleanly (tip_seal is missing)"
    );
    assert_eq!(
        refused("spend-marker-behind", &|d| SpendDurable::new(101, 101)
            .store(d)
            .unwrap()),
        "assumehot: source did not shut down cleanly (spend_durable is at 101, tip is 102)"
    );
    assert_eq!(
        refused("old-schema", &|d| {
            let mut meta = std::fs::read(d.join("meta")).unwrap();
            meta[4..6].copy_from_slice(&25u16.to_le_bytes());
            std::fs::write(d.join("meta"), meta).unwrap();
        }),
        format!(
            "assumehot: source schema 25 is not {}; open it once with this binary first",
            rbitcoin_primitives::SCHEMA_VERSION
        )
    );
    assert_eq!(
        refused("pruned", &|d| {
            let q = Query::open_or_create_tiny(d).unwrap();
            q.set_prune_seqsigwit(true).unwrap();
            q.apply_prune_seqsigwit_tip().unwrap();
            clean_shutdown(q);
        }),
        "assumehot: source is pruned"
    );
    // A split source keeps its append-only files elsewhere; the import names
    // only the hot store, so it refuses before opening anything.
    let split = TempDir::labeled("cold-source").unwrap();
    copy_tree(dir_src.path(), split.path());
    std::fs::write(
        rbitcoin_store::store::seqsigwit_reloc_path(split.path()),
        b"",
    )
    .unwrap();
    let split_before = tree_bytes(split.path());
    let out = scratch.path().join("cold-source");
    assert_eq!(
        import(split.path(), &out, want.digest).unwrap_err(),
        "assumehot: a cold source (--datadir-cold) is not supported"
    );
    assert!(!out.exists() && tree_bytes(split.path()) == split_before);
    let _ = std::fs::remove_dir_all(split.path());
    let _ = std::fs::remove_dir_all(dir_src.path());
    let _ = std::fs::remove_dir_all(scratch.path());
}

/// Flip one bit at `abs` in `file` of a closed store.
fn flip_byte(dir: &Path, file: &str, abs: u64) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join(file))
        .unwrap();
    let mut b = [0u8; 1];
    f.seek(SeekFrom::Start(abs)).unwrap();
    f.read_exact(&mut b).unwrap();
    b[0] ^= 1;
    f.seek(SeekFrom::Start(abs)).unwrap();
    f.write_all(&b).unwrap();
}

/// A source tampered below its tip window, with the expected digest taken
/// from the tampered store: the publisher's hash vouches for the bad data, so
/// only the block checks can refuse it.
fn tampered_source(label: &str, tamper: impl FnOnce(&Query, &Path)) -> (TempDir, Query) {
    let params = ChainParams::regtest();
    let chain = mature_chain();
    let (dir, q) = mature_store(label, &chain);
    accept_and_connect_block(
        &q,
        &params,
        Height(102),
        &block_102(&chain),
        Milestone::NONE,
    )
    .unwrap();
    q.store().flush().unwrap();
    tamper(&q, dir.path());
    drop(q);
    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    (dir, q)
}

/// Step 4: the import re-checks every block against its header and every
/// header against its parent, so a matching digest does not admit a changed
/// output or a chain the params do not accept.
#[test]
fn assumehot_import_checks_blocks_and_headers() {
    let params = ChainParams::regtest();
    let mut dirs = Vec::new();

    // Height 5's coinbase body is `99 92 05` then zero padding: meta, flags
    // (amount exponent 9, OP_TRUE template), mantissa 5. Flipping the last
    // non-zero byte pays 40 BTC instead of 50, so the txid changes.
    let (dir, src) = tampered_source("assumehot-bad-out", |q, d| {
        let cb5 = q.block_tx_fks(Height(5)).unwrap()[0];
        let (off, len) = q.store().tx_body_range(cb5).unwrap();
        let body = std::fs::read(d.join("txout.body")).unwrap();
        let rec = &body[off as usize..(off + len) as usize];
        let last = rec.iter().rposition(|&b| b != 0).unwrap();
        flip_byte(d, "txout.body", off + last as u64);
    });
    let want = src.hot_digest().unwrap().unwrap().digest;
    let (dst_dir, dst) = rbitcoin_query::testutil::tiny_query_labeled("assumehot-bad-out-dst");
    let err = dst.import_hot(&src, &params, want).unwrap_err().to_string();
    assert!(err.starts_with("assumehot: height 5 is invalid ("), "{err}");
    assert!(err.contains("merkle root mismatch"), "{err}");
    dirs.extend([dir, dst_dir]);

    // Header checks: an honest regtest source imported with testnet params
    // fails at genesis. The body checks pass there, so only the header check
    // can refuse it.
    let (dir, src) = tampered_source("assumehot-wrong-net", |_, _| {});
    let want = src.hot_digest().unwrap().unwrap().digest;
    let (dst_dir, dst) = rbitcoin_query::testutil::tiny_query_labeled("assumehot-wrong-net-dst");
    let err = dst
        .import_hot(&src, &ChainParams::testnet(), want)
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("assumehot: height 0 is invalid ("), "{err}");
    assert!(err.contains("genesis hash mismatch"), "{err}");
    dirs.extend([dir, dst_dir]);

    for d in dirs {
        let _ = std::fs::remove_dir_all(&d);
    }
}
