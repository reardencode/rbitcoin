use bitcoin::block::Version;
use bitcoin::{Amount, Block, CompactTarget, ScriptBuf, Target};
use rbitcoin_consensus::regtest_pad::*;
use rbitcoin_consensus::ChainParams;

#[test]
fn mine_regtest_paying_sets_coinbase_script() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let script = ScriptBuf::from_bytes(vec![0x00, 0x14].into_iter().chain([0x11u8; 20]).collect());
    let b = mine_regtest_paying(
        genesis.block_hash(),
        genesis.header.time + 1,
        1,
        script.clone(),
        vec![],
    );
    assert_eq!(b.txdata[0].output[0].script_pubkey, script);
    assert_eq!(b.header.prev_blockhash, genesis.block_hash());
    let target = Target::from_compact(b.header.bits);
    assert!(b.header.validate_pow(target).is_ok());
}

#[test]
fn op_true_signet_block_meets_pow_and_challenge() {
    use bitcoin::script::Script;
    let params = ChainParams::custom_signet(ScriptBuf::from_bytes(vec![0x51]), 10 * 60).unwrap();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Signet);
    let block = mine_op_true_signet_paying(
        &params,
        genesis.block_hash(),
        genesis.header.time.saturating_add(1),
        1,
        genesis.header.bits,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    );
    let target = Target::from_compact(block.header.bits);
    assert!(block.header.validate_pow(target).is_ok());
    rbitcoin_consensus::signet::validate_signet_block_solution(&block, Script::from_bytes(&[0x51]))
        .unwrap();
}

#[test]
fn mine_empty_regtest_uses_regtest_halving_subsidy() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let prev = genesis.block_hash();
    let t = genesis.header.time + 1;
    let b149 = mine_empty_regtest(prev, t, 149);
    let b150 = mine_empty_regtest(prev, t, 150);
    assert_eq!(
        b149.txdata[0].output[0].value,
        Amount::from_sat(50_0000_0000)
    );
    assert_eq!(
        b150.txdata[0].output[0].value,
        Amount::from_sat(25_0000_0000)
    );
}

/// `0x1b7fffff` is about 2^40 times the regtest pow limit, past one nonce span.
/// `generatetoaddress` must return that miss instead of scanning 2^32 nonces.
#[test]
fn regtest_grind_past_one_nonce_span_is_an_error() {
    let hard = CompactTarget::from_consensus(0x1b7f_ffff);
    let easy = CompactTarget::from_consensus(0x200f_ffff);
    let changelog = CompactTarget::from_consensus(0x1f7f_ffff);
    // Just over 2^31 times the regtest pow limit. Regtest generate refuses
    // it. A signet retarget at these bits is still under the signet pow
    // limit, and the shared search does not apply this cutoff.
    let signet_retarget = CompactTarget::from_consensus(0x1d00_ffff);
    assert!(!regtest_mine_fits_one_nonce_span(hard));
    assert!(regtest_mine_fits_one_nonce_span(easy));
    assert!(regtest_mine_fits_one_nonce_span(changelog));
    assert!(!regtest_mine_fits_one_nonce_span(signet_retarget));
    assert!(Target::from_compact(signet_retarget) <= ChainParams::signet().pow_limit);

    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let err = try_mine_regtest_paying_bits(
        genesis.block_hash(),
        genesis.header.time + 1,
        1,
        ScriptBuf::new(),
        vec![],
        hard,
    )
    .expect_err("one nonce span cannot meet 0x1b7fffff");
    assert_eq!(err, "regtest pow grind exhausted");

    let block = try_mine_regtest_paying_bits(
        genesis.block_hash(),
        genesis.header.time + 1,
        1,
        ScriptBuf::new(),
        vec![],
        easy,
    )
    .expect("0x200fffff fits one nonce span");
    assert_eq!(block.header.bits, easy);
    assert!(block
        .header
        .validate_pow(Target::from_compact(easy))
        .is_ok());
}

#[test]
fn grind_regtest_pow_changes_nonce_only() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut header = genesis.header;
    header.bits = CompactTarget::from_consensus(REGTEST_POW_BITS);
    header.nonce = 0;
    let version = header.version;
    let prev = header.prev_blockhash;
    let merkle = header.merkle_root;
    let time = header.time;
    let bits = header.bits;
    grind_regtest_pow(&mut header);
    assert_eq!(header.version, version);
    assert_eq!(header.prev_blockhash, prev);
    assert_eq!(header.merkle_root, merkle);
    assert_eq!(header.time, time);
    assert_eq!(header.bits, bits);
    let target = Target::from_compact(header.bits);
    assert!(header.validate_pow(target).is_ok());
}

#[test]
fn prepare_regtest_candidate_keeps_version_and_txids() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut block = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 1, 1);
    block.header.version = Version::from_consensus(5);
    let txids: Vec<_> = block.txdata.iter().map(|t| t.compute_txid()).collect();
    let version = block.header.version;
    prepare_regtest_candidate(
        &mut block,
        genesis.block_hash(),
        genesis.header.time + REGTEST_BLOCK_SPACING,
    );
    assert_eq!(block.header.version, version);
    let after: Vec<_> = block.txdata.iter().map(|t| t.compute_txid()).collect();
    assert_eq!(after, txids);
    assert_eq!(block.header.prev_blockhash, genesis.block_hash());
    assert_eq!(
        block.header.bits,
        CompactTarget::from_consensus(REGTEST_POW_BITS)
    );
    assert_eq!(
        block.header.merkle_root,
        block.compute_merkle_root().unwrap()
    );
    let target = Target::from_compact(block.header.bits);
    assert!(block.header.validate_pow(target).is_ok());
}

#[test]
fn regtest_height1_fixture_matches_mine_empty() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let b = mine_empty_regtest(
        genesis.block_hash(),
        genesis.header.time + REGTEST_BLOCK_SPACING,
        1,
    );
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/regtest_height1.bin");
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let got: Block = bitcoin::consensus::encode::deserialize(&raw).expect("fixture block");
    assert_eq!(got.header.prev_blockhash, genesis.block_hash());
    assert_eq!(
        got.header.bits,
        CompactTarget::from_consensus(REGTEST_POW_BITS)
    );
    let target = Target::from_compact(got.header.bits);
    assert!(got.header.validate_pow(target).is_ok());
    assert_eq!(
        bitcoin::consensus::encode::serialize(&b),
        raw,
        "regtest_height1.bin must match mine_empty_regtest(genesis, t+600, 1)"
    );
}
