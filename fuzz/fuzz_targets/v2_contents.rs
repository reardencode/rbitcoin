#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rbitcoin_net::parse_v2_regtest(data);
});
