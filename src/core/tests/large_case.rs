//! Size: a synthetic case with 200 000+ events through the full `build` pipeline, with a small in-memory sort
//! threshold so the external merge sort (spill to disk + k-way merge) does the ordering. Checks that the
//! sort spilled, that `timeline.jsonl` has every event in (utc_s, utc_ns, id) order, and that the process's
//! peak memory stays bounded; prints the run time and the peak.
//!
//! Ignored by default (a few seconds in release, slow in debug):
//!   cargo test --release --locked -p rv-timeline-core --test large_case -- --ignored --nocapture
//! `RV_LARGE_EVENTS` changes the event count (default 200 000).

use rv_timeline_core::RunConfig;
use rv_timeline_core::hash::HashAlgo;
use rv_timeline_core::model::{
    ItemRef, Precision, ReadError, RunRef, RunStatus, SourceRef, TimeEvent, TimelineOptions,
    ZoneInfo,
};
use rv_timeline_core::run::{RunSource, run_timeline_with};
use serde_json::Value;
use std::io::BufRead;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

const RUNS: u64 = 200;
const ITEMS: u64 = 21;
/// Events held in memory before the sorter spills a chunk.
const THRESHOLD: usize = 10_000;
/// Peak resident memory allowed for the whole test process. 200 000 events held at once would take several
/// hundred MiB with the reports' copies; the external sort keeps the peak far below.
const PEAK_LIMIT_MIB: u64 = 400;

/// Synthetic runs: `RUNS` rv-imgauth runs, each with `per_run` fs.modified events spread over the case's items,
/// at pseudo-random times before the evidence was registered (no signal fires). Generated on demand per run,
/// so the source itself never holds the whole case.
struct Synthetic {
    per_run: u64,
}

fn run_ref(i: u64) -> RunRef {
    let run_id = format!("20261110T{:02}{:02}00Z-{:06x}", i / 60 % 24, i % 60, i);
    RunRef {
        tool: "rv-imgauth".into(),
        tool_version: "0.3.0".into(),
        run_dir: format!("runs/rv-imgauth/{run_id}"),
        run_id,
        ..Default::default()
    }
}

impl RunSource for Synthetic {
    fn discover(&self, _: &Path) -> Result<Vec<RunRef>, ReadError> {
        Ok((0..RUNS).map(run_ref).collect())
    }
    fn verify(&self, _: &Path, run: RunRef) -> RunRef {
        RunRef {
            status: RunStatus::Verified,
            ..run
        }
    }
    fn read(&self, _: &Path, run: &RunRef) -> Result<Vec<TimeEvent>, ReadError> {
        let seed = run.run_id.bytes().fold(0x9E37_79B9_7F4A_7C15u64, |h, b| {
            (h ^ b as u64).wrapping_mul(0x0100_0000_01B3)
        });
        let mut x = seed | 1;
        Ok((0..self.per_run)
            .map(|n| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let item = n % ITEMS + 1;
                // 2020-01-01 .. 2025-12-31, with nanoseconds; ties on the second are frequent.
                let utc_s = 1_577_836_800 + (x % 189_302_400) as i64;
                let utc_ns = ((x >> 32) % 4) as u32 * 250_000_000;
                TimeEvent {
                    id: format!(
                        "{}:{}:E{:04}:fs.modified:{}",
                        run.tool,
                        run.run_id,
                        item,
                        n / ITEMS
                    ),
                    utc_s,
                    utc_ns,
                    zone: ZoneInfo::Explicit,
                    offset_min: Some(0),
                    precision: Precision::Millisecond,
                    original: format!("{utc_s}.{utc_ns:09}Z"),
                    kind: "fs.modified".into(),
                    item: ItemRef {
                        evidence_id: format!("E{item:04}"),
                        path: format!("R:\\evidence\\item-{item}.bin"),
                        ..Default::default()
                    },
                    source: SourceRef {
                        tool: run.tool.clone(),
                        tool_version: run.tool_version.clone(),
                        run_id: run.run_id.clone(),
                        run_dir: run.run_dir.clone(),
                        file: "logs/audit.jsonl".into(),
                        file_sha256: "0".repeat(64),
                        pointer: format!("line:{}/details/modified_utc", n + 1),
                    },
                    details: Default::default(),
                }
            })
            .collect())
    }
}

/// Peak resident set of this process in MiB (Linux: VmHWM; Windows: peak working set); None elsewhere.
fn peak_mib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        let kb: u64 = s
            .lines()
            .find(|l| l.starts_with("VmHWM:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kb / 1024)
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        #[derive(Default)]
        struct Counters {
            cb: u32,
            page_fault_count: u32,
            peak_working_set_size: usize,
            working_set_size: usize,
            quota_peak_paged_pool_usage: usize,
            quota_paged_pool_usage: usize,
            quota_peak_non_paged_pool_usage: usize,
            quota_non_paged_pool_usage: usize,
            pagefile_usage: usize,
            peak_pagefile_usage: usize,
        }
        unsafe extern "system" {
            fn GetCurrentProcess() -> isize;
            fn K32GetProcessMemoryInfo(process: isize, counters: *mut Counters, cb: u32) -> i32;
        }
        let mut c = Counters {
            cb: std::mem::size_of::<Counters>() as u32,
            ..Default::default()
        };
        // SAFETY: a pseudo-handle for this process and a correctly sized, writable struct.
        let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
        (ok != 0).then_some(c.peak_working_set_size as u64 / (1024 * 1024))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        if p.is_dir() {
            copy_dir(&p, &to.join(e.file_name()));
        } else {
            std::fs::copy(&p, to.join(e.file_name())).unwrap();
        }
    }
}

#[test]
#[ignore = "large case (200k events): run with --release -- --ignored"]
fn large_case_is_sorted_externally_with_bounded_memory() {
    let total: u64 = std::env::var("RV_LARGE_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let per_run = total.div_ceil(RUNS);
    let total = per_run * RUNS;
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("case");
    // The sample's case.json, case log and registry (E0001–E0021); its runs are replaced by the synthetic ones.
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/case");
    copy_dir(&sample, &case);
    std::fs::remove_dir_all(case.join("runs")).unwrap();

    let cfg = RunConfig {
        algorithms: vec![HashAlgo::Sha256],
        langs: vec!["en".into()],
        actor: "bench".into(),
        frontend: "test".into(),
        tool_version: "0.0.0".into(),
        ..Default::default()
    };
    let opts = TimelineOptions {
        case_dir: case.clone(),
        ..TimelineOptions::default()
    };
    let before = peak_mib();
    let t0 = Instant::now();
    let s = run_timeline_with(
        &cfg,
        &opts,
        &Synthetic { per_run },
        THRESHOLD,
        &mut |_| {},
        &AtomicBool::new(false),
    )
    .expect("build");
    let took = t0.elapsed();
    let peak = peak_mib();

    // The sort spilled to disk and cleaned up after itself.
    let audit = std::fs::read_to_string(s.log_dir.join("audit.jsonl")).unwrap();
    let ordered: Value = audit
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|e| e["action"] == "events_ordered")
        .expect("events_ordered entry");
    let d = &ordered["details"];
    assert_eq!(d["events"], total, "{d}");
    assert_eq!(d["sort"], "external", "{d}");
    let chunks = d["spilled_chunks"].as_u64().unwrap();
    assert!(chunks >= total / THRESHOLD as u64, "{d}");
    assert!(
        !s.log_dir.parent().unwrap().join("tmp").exists(),
        "spill folder removed"
    );

    // timeline.jsonl: every event once, in (utc_s, utc_ns, id) order.
    let f = std::fs::File::open(s.report_dir.join("timeline.jsonl")).unwrap();
    let mut prev: Option<(i64, String)> = None;
    let mut n = 0u64;
    for line in std::io::BufReader::new(f).lines() {
        let v: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let key = (
            v["timestamp"].as_i64().unwrap(),
            v["rakvor_event_id"].as_str().unwrap().to_string(),
        );
        if let Some(p) = &prev {
            assert!(*p <= key, "out of order at line {}: {p:?} > {key:?}", n + 1);
            assert!(p.1 != key.1, "duplicate event {}", key.1);
        }
        prev = Some(key);
        n += 1;
    }
    assert_eq!(n, total);

    eprintln!(
        "large case: {total} events from {RUNS} runs, threshold {THRESHOLD}, {chunks} spilled chunks, \
         build {:.1} s, peak memory {} MiB (before the build {} MiB)",
        took.as_secs_f64(),
        peak.map_or("n/a".into(), |p| p.to_string()),
        before.map_or("n/a".into(), |p| p.to_string()),
    );
    if let Some(p) = peak {
        assert!(
            p < PEAK_LIMIT_MIB,
            "peak memory {p} MiB is not bounded by the external sort (limit {PEAK_LIMIT_MIB} MiB)"
        );
    }
}
