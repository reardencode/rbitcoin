//! Compile the vendored libsecp256k1 (with the batch module) in `depend/`.

fn main() {
    let root = "depend/secp256k1";
    println!("cargo:rerun-if-changed={root}");
    cc::Build::new()
        .include(root)
        .include(format!("{root}/include"))
        .include(format!("{root}/src"))
        .flag_if_supported("-Wno-unused-function")
        .define("SECP256K1_NO_API_VISIBILITY_ATTRIBUTES", None)
        .define("ENABLE_MODULE_EXTRAKEYS", Some("1"))
        .define("ENABLE_MODULE_SCHNORRSIG", Some("1"))
        .define("ENABLE_MODULE_BATCH", Some("1"))
        .define("ECMULT_WINDOW_SIZE", Some("15"))
        // Nothing here signs; keep the unused generator table small.
        .define("COMB_BLOCKS", Some("2"))
        .define("COMB_TEETH", Some("5"))
        .file(format!("{root}/src/precomputed_ecmult.c"))
        .file(format!("{root}/src/precomputed_ecmult_gen.c"))
        .file(format!("{root}/src/secp256k1.c"))
        .compile("rbtc_secp256k1");
}
