//! Core `ScriptToAsmStr` and `decodescript` vectors, most lifted from
//! `test/functional/rpc_decodescript.py`.

use super::{ctx_empty, ctx_regtest_hub, p2wpkh_regtest};
use bitcoin::consensus::{deserialize, encode::serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::{ScriptBuf, Transaction};
use rbitcoin_rpc::methods::*;
use serde_json::{json, Value};

const SIG: &str = "304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c509001";
const KEY: &str = "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2";
const KEY_HASH: &str = "5dd1d3a048119c27b28293056724d9522f26d945";

const P2SH_INPUT_TX: &str = "0100000001696a20784a2c70143f634e95227dbdfdf0ecd51647052e70854512235f5986ca010000008a47304402207174775824bec6c2700023309a168231ec80b82c6069282f5133e6f11cbb04460220570edc55c7c5da2ca687ebd0372d3546ebc3f810516a002350cac72dfe192dfb014104d3f898e6487787910a690410b7a917ef198905c27fb9d3b0a42da12aceae0544fc7088d239d9a48f2828a15a09e84043001f27cc80d162cb95404e1210161536ffffffff0100e1f505000000001976a914eb6c6e0cdb2d256a32d97b8df1fc75d1920d9bca88ac00000000";
const MULTISIG_INPUT_TX: &str = "01000000018d1f5635abd06e2c7e2ddf58dc85b3de111e4ad6e0ab51bb0dcf5e84126d927300000000fdfe0000483045022100ae3b4e589dfc9d48cb82d41008dc5fa6a86f94d5c54f9935531924602730ab8002202f88cf464414c4ed9fa11b773c5ee944f66e9b05cc1e51d97abc22ce098937ea01483045022100b44883be035600e9328a01b66c7d8439b74db64187e76b99a68f7893b701d5380220225bf286493e4c4adcf928c40f785422572eb232f84a0b83b0dea823c3a19c75014c695221020743d44be989540d27b1b4bbbcfd17721c337cb6bc9af20eb8a32520b393532f2102c0120a1dda9e51a938d39ddd9fe0ebc45ea97e1d27a7cbd671d5431416d3dd87210213820eb3d5f509d7438c9eeecb4157b2f595105e7cd564b3cdbb9ead3da41eed53aeffffffff02611e0000000000001976a914dc863734a218bfe83ef770ee9d41a27f824a6e5688acee2a02000000000017a9142a5edea39971049a540474c6a99edf0aa4074c588700000000";
const DER_IMPOSTER_OUTPUT_TX: &str = "01000000015ded05872fdbda629c7d3d02b194763ce3b9b1535ea884e3c8e765d42e316724020000006b48304502204c10d4064885c42638cbff3585915b322de33762598321145ba033fc796971e2022100bb153ad3baa8b757e30a2175bd32852d2e1cb9080f84d7e32fcdfd667934ef1b012103163c0ff73511ea1743fb5b98384a2ff09dd06949488028fd819f4d83f56264efffffffff0200000000000000000b6a0930060201000201000180380100000000001976a9141cabd296e753837c086da7a45a6c2fe0d49d7b7b88ac00000000";

fn decode_script(ctx: &RpcContext, hex: &str) -> Value {
    dispatch(ctx, "decodescript", vec![json!(hex)]).unwrap()
}

fn decode_tx(ctx: &RpcContext, hex: &str) -> Value {
    dispatch(ctx, "decoderawtransaction", vec![json!(hex)]).unwrap()
}

fn with_script_sig(tx_hex: &str, script_sig_hex: &str) -> String {
    let mut tx: Transaction =
        deserialize(&rbitcoin_primitives::hex_decode(tx_hex).unwrap()).unwrap();
    tx.input[0].script_sig =
        ScriptBuf::from_bytes(rbitcoin_primitives::hex_decode(script_sig_hex).unwrap());
    serialize_hex(&tx)
}

#[test]
fn decodescript_asm_matches_core() {
    let push_sig = format!("48{SIG}");
    let push_key = format!("21{KEY}");
    let cltv = format!("63{push_key}ad670320a107b17568{push_key}ac");
    let rows: Vec<(String, String)> = vec![
        (push_sig.clone(), SIG.into()),
        (format!("{push_sig}{push_key}"), format!("{SIG} {KEY}")),
        (format!("00{push_sig}{push_sig}"), format!("0 {SIG} {SIG}")),
        ("5100".into(), "1 0".into()),
        (format!("{push_key}ac"), format!("{KEY} OP_CHECKSIG")),
        (
            format!("76a914{KEY_HASH}88ac"),
            format!("OP_DUP OP_HASH160 {KEY_HASH} OP_EQUALVERIFY OP_CHECKSIG"),
        ),
        (
            format!("52{push_key}{push_key}{push_key}53ae"),
            format!("2 {KEY} {KEY} {KEY} 3 OP_CHECKMULTISIG"),
        ),
        (
            format!("a914{KEY_HASH}87"),
            format!("OP_HASH160 {KEY_HASH} OP_EQUAL"),
        ),
        (format!("6a{push_sig}"), format!("OP_RETURN {SIG}")),
        (
            cltv,
            format!(
                "OP_IF {KEY} OP_CHECKSIGVERIFY OP_ELSE 500000 OP_CHECKLOCKTIMEVERIFY \
                 OP_DROP OP_ENDIF {KEY} OP_CHECKSIG"
            ),
        ),
        (format!("0014{KEY_HASH}"), format!("0 {KEY_HASH}")),
        ("51024e73".into(), "1 29518".into()),
        ("5102eeee".into(), "1 -28398".into()),
        ("6a00".into(), "OP_RETURN 0".into()),
        ("6aee".into(), "OP_RETURN OP_UNKNOWN".into()),
        ("6a02ee".into(), "OP_RETURN [error]".into()),
        ("02eeee".into(), "-28398".into()),
        ("ba".into(), "OP_CHECKSIGADD".into()),
        ("50".into(), "OP_RESERVED".into()),
        ("4f5160".into(), "-1 1 16".into()),
        ("4c00".into(), "0".into()),
        ("0180".into(), "0".into()),
        ("0181".into(), "-1".into()),
        ("04ffffff7f".into(), "2147483647".into()),
        ("04ffffffff".into(), "-2147483647".into()),
        ("05ffffffff00".into(), "ffffffff00".into()),
        (
            "b0b1b2b3b9".into(),
            "OP_NOP1 OP_CHECKLOCKTIMEVERIFY OP_CHECKSEQUENCEVERIFY OP_NOP4 OP_NOP10".into(),
        ),
        (
            "6162657e89bbfeff".into(),
            "OP_NOP OP_VER OP_VERIF OP_CAT OP_RESERVED1 OP_UNKNOWN OP_UNKNOWN OP_INVALIDOPCODE"
                .into(),
        ),
        ("76".into(), "OP_DUP".into()),
        ("7602ab".into(), "OP_DUP [error]".into()),
        ("4c".into(), "[error]".into()),
        ("".into(), "".into()),
    ];
    let (ctx, dir) = ctx_empty();
    for (hex, asm) in &rows {
        assert_eq!(decode_script(&ctx, hex)["asm"], json!(asm), "{hex}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn decoderawtransaction_script_sig_asm_decodes_sighash_like_core() {
    let (ctx, dir) = ctx_empty();
    let p2sh = decode_tx(&ctx, P2SH_INPUT_TX);
    assert_eq!(
        p2sh["vin"][0]["scriptSig"]["asm"],
        json!("304402207174775824bec6c2700023309a168231ec80b82c6069282f5133e6f11cbb04460220570edc55c7c5da2ca687ebd0372d3546ebc3f810516a002350cac72dfe192dfb[ALL] 04d3f898e6487787910a690410b7a917ef198905c27fb9d3b0a42da12aceae0544fc7088d239d9a48f2828a15a09e84043001f27cc80d162cb95404e1210161536")
    );

    let multisig = decode_tx(&ctx, MULTISIG_INPUT_TX);
    assert_eq!(
        multisig["txid"],
        json!("8e3730608c3b0bb5df54f09076e196bc292a8e39a78e73b44b6ba08c78f5cbb0")
    );
    assert_eq!(
        multisig["vin"][0]["scriptSig"]["asm"],
        json!("0 3045022100ae3b4e589dfc9d48cb82d41008dc5fa6a86f94d5c54f9935531924602730ab8002202f88cf464414c4ed9fa11b773c5ee944f66e9b05cc1e51d97abc22ce098937ea[ALL] 3045022100b44883be035600e9328a01b66c7d8439b74db64187e76b99a68f7893b701d5380220225bf286493e4c4adcf928c40f785422572eb232f84a0b83b0dea823c3a19c75[ALL] 5221020743d44be989540d27b1b4bbbcfd17721c337cb6bc9af20eb8a32520b393532f2102c0120a1dda9e51a938d39ddd9fe0ebc45ea97e1d27a7cbd671d5431416d3dd87210213820eb3d5f509d7438c9eeecb4157b2f595105e7cd564b3cdbb9ead3da41eed53ae")
    );
    assert_eq!(
        multisig["vout"][0]["scriptPubKey"]["asm"],
        json!(
            "OP_DUP OP_HASH160 dc863734a218bfe83ef770ee9d41a27f824a6e56 OP_EQUALVERIFY OP_CHECKSIG"
        )
    );
    assert_eq!(
        multisig["vout"][1]["scriptPubKey"]["asm"],
        json!("OP_HASH160 2a5edea39971049a540474c6a99edf0aa4074c58 OP_EQUAL")
    );

    let imposter = decode_tx(&ctx, DER_IMPOSTER_OUTPUT_TX);
    assert_eq!(
        imposter["vout"][0]["scriptPubKey"]["asm"],
        json!("OP_RETURN 300602010002010001")
    );

    let sig_all = "3045022100ae3b4e589dfc9d48cb82d41008dc5fa6a86f94d5c54f9935531924602730ab8002202f88cf464414c4ed9fa11b773c5ee944f66e9b05cc1e51d97abc22ce098937ea01";
    let der = &sig_all[..sig_all.len() - 2];
    let sig_none_acp = format!("{der}82");
    let script_sig_asm = |script_sig: &str| {
        decode_tx(&ctx, &with_script_sig(MULTISIG_INPUT_TX, script_sig))["vin"][0]["scriptSig"]
            ["asm"]
            .clone()
    };
    assert_eq!(
        script_sig_asm(&format!("48{sig_all}")),
        json!(format!("{der}[ALL]"))
    );
    assert_eq!(
        script_sig_asm(&format!("48{sig_none_acp}")),
        json!(format!("{der}[NONE|ANYONECANPAY]"))
    );
    assert_eq!(
        script_sig_asm(&format!("0048{sig_all}48{sig_none_acp}")),
        json!(format!("0 {der}[ALL] {der}[NONE|ANYONECANPAY]"))
    );
    assert_eq!(
        script_sig_asm("6a143011020701010101010101020601010101010101"),
        json!("OP_RETURN 3011020701010101010101020601010101010101")
    );
    assert_eq!(
        script_sig_asm(&format!("48{der}04")),
        json!(format!("{der}04")),
        "an undefined hashtype stays hex"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_rpcs_print_core_asm() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (addr, spk) = p2wpkh_regtest();
    let want = json!(format!("0 {}", "75".repeat(20)));
    dispatch(&ctx, "generatetoaddress", vec![json!(1), json!(addr)]).unwrap();
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let blk = dispatch(&ctx, "getblock", vec![tip.clone(), json!(2)]).unwrap();
    let cb = &blk["tx"][0];
    assert_eq!(
        cb["vout"][0]["scriptPubKey"]["hex"],
        json!(rbitcoin_primitives::hex_encode(spk.as_bytes()))
    );
    assert_eq!(cb["vout"][0]["scriptPubKey"]["asm"], want, "{cb}");
    let txid = cb["txid"].clone();
    let raw = dispatch(&ctx, "getrawtransaction", vec![txid.clone(), json!(true)]).unwrap();
    assert_eq!(raw["vout"][0]["scriptPubKey"]["asm"], want, "{raw}");
    let coin = dispatch(&ctx, "gettxout", vec![txid, json!(0)]).unwrap();
    assert_eq!(coin["scriptPubKey"]["asm"], want, "{coin}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `test/functional/data/rpc_decodescript.json`, plus P2PK, bare multisig,
/// and `OP_NOP10` objects built with Core's functional test framework.
const CORE_DECODESCRIPT: &str = r#"[
 ["5120eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", {
   "asm": "1 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
   "address": "bcrt1pamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhqz6nvlh",
   "desc": "rawtr(eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee)#jk7c6kys",
   "type": "witness_v1_taproot"}],
 ["5102eeee", {
   "asm": "1 -28398",
   "address": "bcrt1pamhqk96edn",
   "desc": "addr(bcrt1pamhqk96edn)#vkh8uj5a",
   "type": "witness_unknown"}],
 ["0020eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", {
   "asm": "0 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
   "address": "bcrt1qamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhqgdn98t",
   "desc": "addr(bcrt1qamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhqgdn98t)#afaecevx",
   "type": "witness_v0_scripthash",
   "p2sh": "2MwGk8mw1GBP6U9D5X8gTvgvXpuknmAK3fo"}],
 ["a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee87", {
   "asm": "OP_HASH160 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee OP_EQUAL",
   "address": "2NF2b3KS8xXb9XHvbRMXdZh8s5g92rUZHtp",
   "desc": "addr(2NF2b3KS8xXb9XHvbRMXdZh8s5g92rUZHtp)#ywfcpmh9",
   "type": "scripthash"}],
 ["6a00", {"asm": "OP_RETURN 0", "desc": "raw(6a00)#ncfmkl43", "type": "nulldata"}],
 ["6aee", {"asm": "OP_RETURN OP_UNKNOWN", "desc": "raw(6aee)#vsyzgqdt", "type": "nonstandard"}],
 ["6a02ee", {"asm": "OP_RETURN [error]", "desc": "raw(6a02ee)#gvdwnlzl", "type": "nonstandard"}],
 ["02eeee", {
   "asm": "-28398",
   "desc": "raw(02eeee)#5xzck7pr",
   "type": "nonstandard",
   "p2sh": "2N34iiGoUUkVSPiaaTFpJjB1FR9TXQu3PGM",
   "segwit": {
     "asm": "0 96c2368fc30514a438a8bd909f93c49a1549d77198ccbdb792043b666cb24f42",
     "desc": "addr(bcrt1qjmprdr7rq522gw9ghkgfly7yng25n4m3nrxtmdujqsakvm9jfapqk795l5)#5akkdska",
     "hex": "002096c2368fc30514a438a8bd909f93c49a1549d77198ccbdb792043b666cb24f42",
     "address": "bcrt1qjmprdr7rq522gw9ghkgfly7yng25n4m3nrxtmdujqsakvm9jfapqk795l5",
     "type": "witness_v0_scripthash",
     "p2sh-segwit": "2MtoejEictTQ6XtmHYzoYttt35Ec6krqFKN"}}],
 ["ba", {"asm": "OP_CHECKSIGADD", "desc": "raw(ba)#yy0eg44l", "type": "nonstandard"}],
 ["50", {"asm": "OP_RESERVED", "desc": "raw(50)#a7tu03xf", "type": "nonstandard"}],
 ["2103b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2ac", {
   "asm": "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2 OP_CHECKSIG",
   "desc": "pk(03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2)#h9zd5h4y",
   "type": "pubkey",
   "p2sh": "2NGPSb9XrNbqMS2rhEPezerzXVsnMk2e5oW",
   "segwit": {
     "asm": "0 5dd1d3a048119c27b28293056724d9522f26d945",
     "hex": "00145dd1d3a048119c27b28293056724d9522f26d945",
     "type": "witness_v0_keyhash",
     "address": "bcrt1qthga8gzgzxwz0v5zjvzkwfxe2ghjdk2997w9up",
     "desc": "addr(bcrt1qthga8gzgzxwz0v5zjvzkwfxe2ghjdk2997w9up)#4szxctnl",
     "p2sh-segwit": "2MszFsCB9jCc65ZyLXAXjXN3nq6yhKJEcqQ"}}],
 ["522103b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb22103b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb22103b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb253ae", {
   "asm": "2 03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2 03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2 03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2 3 OP_CHECKMULTISIG",
   "desc": "multi(2,03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2,03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2,03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2)#0urjxu43",
   "type": "multisig",
   "p2sh": "2MwtFW8ZnW2hgeEnW8pos6dNgqSHroF8v7R",
   "segwit": {
     "asm": "0 0f320decca000221b611117448134c78dd220cd22384ac80025b59e43c8698e8",
     "hex": "00200f320decca000221b611117448134c78dd220cd22384ac80025b59e43c8698e8",
     "type": "witness_v0_scripthash",
     "address": "bcrt1qpueqmmx2qqpzrds3z96ysy6v0rwjyrxjywz2eqqztdv7g0yxnr5q7ckd78",
     "desc": "wsh(multi(2,03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2,03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2,03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2))#lkvk0320",
     "p2sh-segwit": "2MyAJNJ4QTTwnM9TBPmKyD2XzwQGNhqBDCc"}}],
 ["b9", {
   "asm": "OP_NOP10",
   "desc": "raw(b9)#jlu6s349",
   "type": "nonstandard",
   "p2sh": "2MuCdHGuWznJtBSHpthmADdDJyQ63RRMr2s",
   "segwit": {
     "asm": "0 04d6c0c946716aac894fc1653383543a91faab601302cf011607c82f06304651",
     "hex": "002004d6c0c946716aac894fc1653383543a91faab601302cf011607c82f06304651",
     "type": "witness_v0_scripthash",
     "address": "bcrt1qqntvpj2xw942ez20c9jn8q6582gl42mqzvpv7qgkqlyz7p3sgegsu6atg4",
     "desc": "addr(bcrt1qqntvpj2xw942ez20c9jn8q6582gl42mqzvpv7qgkqlyz7p3sgegsu6atg4)#25ekxhmt",
     "p2sh-segwit": "2N8ZVEkbDkfzjdiqfmFu8o7rtMUr238CpKg"}}]
]"#;

#[test]
fn decodescript_objects_match_core() {
    let rows: Vec<(String, Value)> = serde_json::from_str(CORE_DECODESCRIPT).unwrap();
    let (ctx, dir) = ctx_empty();
    for (hex, want) in &rows {
        assert_eq!(&decode_script(&ctx, hex), want, "{hex}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn decodescript_wraps_only_where_core_does() {
    let push_key = format!("21{KEY}");
    let uncompressed = "04b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb25e01fc8fde47c96c98a4f3a8123e33a38a50cf9025cc8c4494a518f991792bb7";
    let rows: Vec<(String, bool, bool)> = vec![
        (format!("41{uncompressed}ac"), true, false),
        (format!("52{push_key}41{uncompressed}52ae"), true, false),
        (format!("0014{KEY_HASH}"), true, false),
        (format!("0020{}", "d8".repeat(32)), true, false),
        (format!("a914{KEY_HASH}87"), false, false),
        (format!("5120{}", "01".repeat(32)), false, false),
        ("51024e73".into(), false, false),
        ("7e".into(), false, false),
        ("bb".into(), false, false),
        (format!("4d0902{}", "ab".repeat(521)), false, false),
        (format!("4d0802{}75", "ab".repeat(520)), true, true),
    ];
    let (ctx, dir) = ctx_empty();
    for (hex, p2sh, segwit) in &rows {
        let got = decode_script(&ctx, hex);
        assert_eq!(got.get("p2sh").is_some(), *p2sh, "{hex} {got}");
        assert_eq!(got.get("segwit").is_some(), *segwit, "{hex} {got}");
        assert!(got.get("hex").is_none(), "{got}");
    }

    let p2pkh = decode_script(&ctx, &format!("76a914{KEY_HASH}88ac"));
    assert_eq!(
        p2pkh["segwit"]["type"],
        json!("witness_v0_keyhash"),
        "{p2pkh}"
    );
    assert_eq!(p2pkh["segwit"]["asm"], json!(format!("0 {KEY_HASH}")));

    let cltv = format!("63{push_key}ad670320a107b17568{push_key}ac");
    let cltv_hash =
        bitcoin::hashes::sha256::Hash::hash(&rbitcoin_primitives::hex_decode(&cltv).unwrap());
    let got = decode_script(&ctx, &cltv);
    assert_eq!(
        got["segwit"]["asm"],
        json!(format!("0 {cltv_hash:x}")),
        "{got}"
    );

    let anchor = decode_script(&ctx, "51024e73");
    assert_eq!(anchor["address"], json!("bcrt1pfeesnyr2tx"));

    let src = "5b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc401021031c41fdbcebe17bec8d49816e00ca1b5ac34766b91c9f2ac37d39c63e5e008afb2103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5fae736402c00fb269522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae68";
    let over_520 = decode_script(&ctx, src);
    assert_eq!(
        over_520["p2sh"],
        json!("2NEx4dVbLBLFmKHuyXhjbJpFxZm2dqTAPed"),
        "a redeem script over 520 bytes still gets Core's p2sh"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
