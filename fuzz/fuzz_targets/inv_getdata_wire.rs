#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rbitcoin_net::parse_v2_regtest_named("inv", data);
    let _ = rbitcoin_net::parse_v2_regtest_named("getdata", data);
});
