use rbitcoin_consensus::error::*;
use rbitcoin_consensus::{is_warn_and_apply, reason_is_warn_and_apply};

#[test]
fn block_reject_reason_bip113_and_bip112_needles() {
    assert_eq!(
        block_reject_reason(&ConsensusError::BadTx("not final")),
        "bad-txns-nonfinal"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::BadTx("bad-txns-nonfinal")),
        "bad-txns-nonfinal"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::Script("CSV negative".into())),
        "block-script-verify-flag-failed (Negative locktime)"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::Script("CSV negative txid=ab vin=0".into())),
        "block-script-verify-flag-failed (Negative locktime)"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::Script("stack empty".into())),
        "block-script-verify-flag-failed (Operation not valid with the current stack size)"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::Script("CSV".into())),
        "block-script-verify-flag-failed (Locktime requirement not satisfied)"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::BadBlock("no transactions")),
        "bad-blk-length"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::BadBlock("block stripped size too large")),
        "bad-blk-length"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::BadBlock("first tx not coinbase")),
        "bad-cb-missing"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::BadBlock("coinbase excess value")),
        "bad-cb-amount"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::BadTx("no inputs")),
        "bad-txns-vin-empty"
    );
    for bip34 in ["bip34 height encoding", "bip34 coinbase script empty"] {
        assert_eq!(
            block_reject_reason(&ConsensusError::BadBlock(bip34)),
            "bad-cb-height"
        );
    }
    assert_eq!(
        block_reject_reason(&ConsensusError::BadHeader("incorrect proof of work bits")),
        "bad-diffbits"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::BadBlock("signet solution invalid")),
        "bad-signet-blksig"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::InvalidPow),
        "high-hash"
    );
    assert_eq!(
        block_reject_reason(&ConsensusError::Script("SIG_DER".into())),
        "block-script-verify-flag-failed (Non-canonical DER signature)"
    );
    // feature_cltv.py five BIP65 paren reasons (stack / negative / type /
    // locktime / SEQUENCE_FINAL).
    for (token, paren) in [
        (
            "stack empty",
            "Operation not valid with the current stack size",
        ),
        ("CLTV negative", "Negative locktime"),
        ("CLTV type", "Locktime requirement not satisfied"),
        ("CLTV", "Locktime requirement not satisfied"),
        ("CLTV final sequence", "Locktime requirement not satisfied"),
    ] {
        assert_eq!(
            block_reject_reason(&ConsensusError::Script(token.into())),
            format!("block-script-verify-flag-failed ({paren})")
        );
        assert_eq!(
            block_reject_log_line(
                "abcd",
                &format!("block-script-verify-flag-failed ({paren})")
            ),
            format!("Block validation error: block-script-verify-flag-failed ({paren})")
        );
    }
    assert_eq!(
        block_reject_reason(&ConsensusError::BadVersion(2)),
        "bad-version(0x00000002)"
    );
    assert_eq!(
        block_reject_log_line("abcd", "bad-version(0x00000002)"),
        "abcd, bad-version(0x00000002)"
    );
    assert_eq!(
        block_reject_log_line(
            "abcd",
            "block-script-verify-flag-failed (Non-canonical DER signature)"
        ),
        "Block validation error: block-script-verify-flag-failed (Non-canonical DER signature)"
    );
}

/// Every reject string this crate emits is either warn-and-apply or hard.
/// Proof-of-work and a body that does not match its header stay hard.
/// `reason_is_warn_and_apply` follows the same split, including Core's names.
#[test]
fn trust_reason_class() {
    let apply = [
        ConsensusError::Script("x".into()),
        ConsensusError::BadVersion(2),
        ConsensusError::BadHeader("timestamp <= median-time-past"),
        ConsensusError::BadHeader("timestamp too far in future"),
        ConsensusError::BadHeader("empty median time"),
        ConsensusError::BadHeader("time-too-old"),
        ConsensusError::BadHeader("time-too-new"),
        ConsensusError::BadHeader("time-timewarp-attack"),
        ConsensusError::BadBlock("bip34 height encoding"),
        ConsensusError::BadBlock("bip34 coinbase script empty"),
        ConsensusError::BadBlock("bad-blk-sigops"),
        ConsensusError::BadBlock("coinbase excess value"),
        ConsensusError::BadBlock("bad-cb-amount"),
        ConsensusError::BadBlock("signet solution invalid"),
        ConsensusError::BadBlock("signet: bad"),
        ConsensusError::BadTx("not final"),
        ConsensusError::BadTx("bad-txns-nonfinal"),
        ConsensusError::BadTx("coinbase immature"),
        ConsensusError::BadTx("bad-txns-BIP30"),
        ConsensusError::BadTx("bad-txns-premature-spend-of-coinbase"),
        ConsensusError::BadTx("non-BIP68-final"),
    ];
    let hard = [
        ConsensusError::InvalidPow,
        ConsensusError::BadHeader("incorrect proof of work bits"),
        ConsensusError::BadHeader("target above pow limit"),
        ConsensusError::BadHeader("bad-diffbits"),
        ConsensusError::BadBlock("unexpected witness before segwit"),
        ConsensusError::BadBlock("bad-witness-nonce-size"),
        ConsensusError::BadBlock("witness commitment mismatch"),
        ConsensusError::BadBlock("missing witness commitment"),
        ConsensusError::BadBlock("merkle root mismatch"),
        ConsensusError::BadPrev,
        ConsensusError::MissingPrevout,
        ConsensusError::PrevoutSpent,
        ConsensusError::Cancelled,
        ConsensusError::Internal("io"),
        ConsensusError::BadTx("in < out"),
        ConsensusError::BadBlock("duplicate txid"),
        ConsensusError::BadBlock("no transactions"),
        ConsensusError::BadBlock("signet encode"),
    ];
    for err in &apply {
        let reason = block_reject_reason(err);
        assert!(is_warn_and_apply(err), "apply {err:?} / {reason}");
        assert!(reason_is_warn_and_apply(&reason), "reason apply {reason}");
    }
    for err in &hard {
        let reason = block_reject_reason(err);
        assert!(!is_warn_and_apply(err), "hard {err:?} / {reason}");
        assert!(
            !reason_is_warn_and_apply(&reason),
            "reason hard {reason} from {err:?}"
        );
    }
    assert!(!reason_is_warn_and_apply("high-hash"));
    assert!(!reason_is_warn_and_apply("bad-txnmrklroot"));
    assert!(!reason_is_warn_and_apply("bad-diffbits"));
    let guard = rbitcoin_consensus::TrustCollect::enter();
    let encode = soften_signet_encode();
    drop(guard);
    assert!(
        matches!(encode, Err(ConsensusError::BadBlock("signet encode"))),
        "{encode:?}"
    );
}

fn soften_signet_encode() -> Result<(), ConsensusError> {
    rbitcoin_consensus::soften(ConsensusError::BadBlock("signet encode"))
}
