//! Taproot batch microbench over real blocks (ignored; run in release).

use super::block_866342::{
    fixture_dir, load_block, prevouts_from_json, prevouts_from_json_zst, script_jobs,
};
use super::ScriptCheckJob;
use bitcoin::consensus::deserialize;
use bitcoin::Block;
use std::path::Path;
use std::time::Instant;

/// Wall time of script checks for this block, input by input versus one
/// Taproot batch per steal chunk. One thread, so the ratio is CPU per block.
/// Run in release: `cargo test --release -p rbitcoin-consensus --lib
/// taproot_batch_bench -- --ignored --nocapture`.
#[test]
#[ignore = "microbench; agent VM numbers are not a perf result"]
fn block_866342_taproot_batch_bench() {
    let jobs = script_jobs(
        load_block(),
        prevouts_from_json_zst(&fixture_dir().join("spent_utxos.zst")),
    );
    taproot_batch_bench("866342", &jobs);
}

/// Same bench over `$RBTC_BENCH_BLOCKS/<name>.raw` (wire block) plus
/// `<name>.prevouts.json` (Floresta `spent_utxos` shape).
#[test]
#[ignore = "microbench over blocks outside the tree"]
fn extra_blocks_taproot_batch_bench() {
    let Ok(dir) = std::env::var("RBTC_BENCH_BLOCKS") else {
        eprintln!("RBTC_BENCH_BLOCKS unset");
        return;
    };
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("bench dir")
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            name.strip_suffix(".raw").map(str::to_string)
        })
        .collect();
    names.sort();
    for name in names {
        let dir = Path::new(&dir);
        let raw = std::fs::read(dir.join(format!("{name}.raw"))).expect("raw");
        let block: Block = deserialize(&raw).expect("block wire");
        let prevouts = std::fs::read(dir.join(format!("{name}.prevouts.json"))).expect("json");
        let jobs = script_jobs(block, prevouts_from_json(&prevouts));
        taproot_batch_bench(&name, &jobs);
    }
}

fn is_p2tr(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20
}

fn taproot_batch_bench(name: &str, jobs: &[ScriptCheckJob]) {
    use crate::script::batch::batched;
    use crate::script_pool::STEAL_CHUNK;

    let (mut key_path, mut script_path) = (0usize, 0usize);
    for job in jobs {
        for (i, vin) in job.tx.input.iter().enumerate() {
            if !is_p2tr(job.prevout_script(i).unwrap()) {
                continue;
            }
            let annex = vin.witness.len() >= 2
                && vin.witness.last().is_some_and(|l| l.first() == Some(&0x50));
            if vin.witness.len() - usize::from(annex) == 1 {
                key_path += 1;
            } else {
                script_path += 1;
            }
        }
    }
    let taproot: Vec<&ScriptCheckJob> = jobs
        .iter()
        .filter(|j| (0..j.prevouts.len()).any(|i| is_p2tr(j.prevout_script(i).unwrap())))
        .collect();
    let all: Vec<&ScriptCheckJob> = jobs.iter().collect();
    eprintln!(
        "{name}: txs={} taproot_txs={} p2tr key_path_inputs={key_path} script_path_inputs={script_path}",
        jobs.len(),
        taproot.len()
    );

    let each = |set: &[&ScriptCheckJob]| {
        for job in set {
            crate::block::verify_one_script_job(job).unwrap();
        }
    };
    let batch = |set: &[&ScriptCheckJob]| {
        for chunk in set.chunks(STEAL_CHUNK) {
            batched(|| {
                chunk
                    .iter()
                    .try_for_each(|j| crate::block::verify_one_script_job(j))
            })
            .unwrap();
        }
    };
    let rounds = 11;
    for (set_name, set) in [("all", &all), ("taproot", &taproot)] {
        each(set);
        batch(set);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for _ in 0..rounds {
            let t = Instant::now();
            each(set);
            a.push(t.elapsed().as_secs_f64() * 1e3);
            let t = Instant::now();
            batch(set);
            b.push(t.elapsed().as_secs_f64() * 1e3);
        }
        a.sort_by(f64::total_cmp);
        b.sort_by(f64::total_cmp);
        let (ma, mb) = (a[rounds / 2], b[rounds / 2]);
        eprintln!(
            "{name} {set_name}: each median={ma:.1}ms batched median={mb:.1}ms \
             speedup={:.3}x saved={:.1}%",
            ma / mb,
            (1.0 - mb / ma) * 100.0,
        );
    }
}
