use rbitcoin_rpc::methods::mempool::*;

/// `btc_amounts_print_eight_decimals` reaches a warm estimate through the
/// handler. This pins the success shape across targets.
#[test]
fn an_estimate_is_feerate_and_blocks() {
    let r = smart_fee_json(2, Some(2_000));
    assert_eq!(r["feerate"], sat_btc_json(2_000), "{r}");
    assert_eq!(r["blocks"], 2, "{r}");
    assert_eq!(
        r.as_object().unwrap().len(),
        2,
        "only feerate and blocks: {r}"
    );
    let none = smart_fee_json(6, None);
    assert!(none.get("feerate").is_none(), "{none}");
    assert_eq!(none["blocks"], 6, "{none}");
    let off = smart_fee_json(12, Some(1_050));
    assert_eq!(off["blocks"], 12, "{off}");
    assert!(off.get("feerate").is_some(), "{off}");
    assert!(off.get("errors").is_none(), "{off}");
    let far = smart_fee_json(100, Some(800));
    assert_eq!(far["blocks"], 100, "{far}");
    assert!(far.get("feerate").is_some(), "{far}");
}
