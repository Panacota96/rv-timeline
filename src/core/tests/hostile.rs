//! Hostile inputs: a case folder an adversary could have edited. A deterministic mutation loop over the sample
//! case's tool outputs, audit logs, case log, case.json and registry (truncation, invalid UTF-8, huge strings,
//! deep nesting, wrong types, huge numbers, absurd times, paths escaping the case folder, symlinks).
//!
//! Most mutations are *re-sealed* the way an adversary with write access would: the changed output's digests
//! are rewritten in the run's audit log, the audit chain re-hashed, the case log's audit head and chain updated,
//! and case.json / registry digests re-recorded. That lets the mutated bytes reach the parsers instead of
//! stopping at the digest check.
//!
//! Invariants checked on every mutation: no panic, no hang (time budget), every run verified or excluded with
//! a known reason, no event cited from a file outside its run folder, unparseable times counted (never
//! invented); and, on a sample of mutations, the full `build` pipeline returns Ok or an error (never panics).
//!
//! `RV_FUZZ_ITERS` (default 200, enough for `cargo test` in debug) and `RV_FUZZ_SEED` change the loop. CI runs
//! 3000 mutations in an optimised build that keeps overflow checks and debug assertions:
//!   CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true RV_FUZZ_ITERS=3000 //!   cargo test --release --locked -p rv-timeline-core --test hostile

use rv_timeline_core::audit::{GENESIS, entry_hash};
use rv_timeline_core::hash::{HashAlgo, hash_bytes};
use rv_timeline_core::model::{RunRef, RunStatus, TimelineOptions};
use rv_timeline_core::{RunConfig, engine, readers};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

const REASONS: [&str; 6] = [
    "unreadable",
    "chain_broken",
    "not_finished",
    "unsupported_tool",
    "unsupported_version",
    "digest_mismatch",
];
/// Wall-clock budget of one mutation (discover + verify + read + engine), generous for slow CI runners.
const BUDGET: Duration = Duration::from_secs(20);
/// Budget of a full `build` (reports in every format, written to disk; slower on Windows with on-access scanning).
const PIPELINE_BUDGET: Duration = Duration::from_secs(120);

fn sample() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/case")
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

fn walk(d: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(d).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn rel(case: &Path, p: &Path) -> String {
    p.strip_prefix(case)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

/// xorshift64* — deterministic, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

const TIMES: [&str; 34] = [
    "99999-12-31T00:00:00Z",
    "+275760-09-13T00:00:00Z",
    "-000001-01-01T00:00:00Z",
    "0000-01-01T00:00:00+18:00",
    "9999-12-31T23:59:59.999999999-18:00",
    "2026-02-30T00:00:00Z",
    "2026-11-13T25:61:61Z",
    "2026-11-13T23:59:60Z",
    "2026-11-13T10:00:00.12345678901234567890123Z",
    "2026-11-13T10:00:00+99:99",
    "2026-11-13T10:00:00+2359",
    "2026",
    "2026-13",
    "D:99999999999999",
    "D:2026+99'99'",
    "D:20261113100000-",
    "991231235959Z",
    "99991231235959.99999999999Z",
    "Mon, 32 Foo 99999 99:99:99 +9999",
    "Wed, 11 Nov 2026 11:00:03 -0000 (comment",
    "Wed Nov 99 99:99:99 99999",
    "Nov 10 10:00:00 99999 GMT",
    "0000:00:00 00:00:00",
    "9999:12:31 23:59:60",
    "2026:11:13 10:00:00",
    "12:30:1e308",
    "99999999999999999999:00:00",
    "-1:-1:-1",
    "NaN:inf:-inf",
    "",
    "\u{0}",
    "2026-11-13T10:00:00Z\u{202e}",
    "１９９９-01-01T00:00:00Z",
    "2026-11-13 10:00:00",
];

const PATHS: [&str; 12] = [
    "../../../outside/statistics.json",
    "../../../../outside/statistics.json",
    "..\\..\\..\\outside\\statistics.json",
    "/etc/passwd",
    "C:/Windows/win.ini",
    "C:\\Windows\\win.ini",
    "\\\\server\\share\\x.json",
    "runs/../../outside/run",
    "runs/rv-imgauth/../../../outside",
    "/runs/rv-imgauth/x",
    "runs/rv-imgauth/..",
    "",
];

/// A hostile replacement value for one JSON node.
fn hostile(rng: &mut Rng, old: &Value) -> Value {
    match rng.below(14) {
        0 => Value::Null,
        1 => json!(true),
        2 => json!("x".repeat(1 + rng.below(1 << 20))),
        3 => {
            let depth = 1 + rng.below(200);
            let mut v = json!(0);
            for _ in 0..depth {
                v = if rng.chance(50) {
                    json!([v])
                } else {
                    json!({ "a": v })
                };
            }
            v
        }
        4 => json!(u64::MAX),
        5 => json!(i64::MIN),
        6 => json!(1e308),
        7 => json!(-0.0),
        8 => json!(*rng.pick(&TIMES)),
        9 => json!(*rng.pick(&PATHS)),
        10 => json!([old.clone(), old.clone()]),
        11 => json!({ "": old.clone() }),
        12 => match old {
            Value::String(s) => json!(s.len()),
            Value::Number(n) => json!(n.to_string()),
            _ => json!("ab\u{fffd}\u{0}"),
        },
        _ => json!(""),
    }
}

/// Paths of every node (object key / array index) in `v`, with whether the node is a time-looking string.
fn nodes(v: &Value, at: Vec<String>, out: &mut Vec<(Vec<String>, bool)>) {
    let timeish = v.as_str().is_some_and(|s| {
        s.len() >= 4
            && s.len() < 64
            && s.chars().filter(|c| c.is_ascii_digit()).count() >= 4
            && s.contains([':', '-', 'T'])
    });
    out.push((at.clone(), timeish));
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                let mut p = at.clone();
                p.push(k.clone());
                nodes(x, p, out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                let mut p = at.clone();
                p.push(i.to_string());
                nodes(x, p, out);
            }
        }
        _ => {}
    }
}

fn node_mut<'a>(v: &'a mut Value, at: &[String]) -> &'a mut Value {
    at.iter().fold(v, |v, k| match v {
        Value::Object(m) => m.get_mut(k).unwrap(),
        Value::Array(a) => &mut a[k.parse::<usize>().unwrap()],
        _ => unreachable!(),
    })
}

/// Replaces one node (time-looking strings preferred) or deletes an object key.
fn mutate_value(rng: &mut Rng, v: &mut Value) -> String {
    let mut all = Vec::new();
    nodes(v, vec![], &mut all);
    let times: Vec<_> = all.iter().filter(|(_, t)| *t).cloned().collect();
    let (at, _) = if !times.is_empty() && rng.chance(60) {
        rng.pick(&times).clone()
    } else {
        rng.pick(&all).clone()
    };
    if !at.is_empty() && rng.chance(10) {
        let (last, parent) = at.split_last().unwrap();
        if let Value::Object(m) = node_mut(v, parent) {
            m.remove(last);
            return format!("delete /{}", at.join("/"));
        }
    }
    let n = node_mut(v, &at);
    let new = hostile(rng, n);
    let shown: String = new.to_string().chars().take(60).collect();
    *n = new;
    format!("set /{} = {shown}", at.join("/"))
}

/// Byte-level damage: truncation, invalid UTF-8, random bytes, BOM, CRLF, an empty file.
fn mutate_bytes(rng: &mut Rng, b: &mut Vec<u8>) -> String {
    match rng.below(6) {
        0 => {
            let n = rng.below(b.len());
            b.truncate(n);
            format!("truncate at {n}")
        }
        1 => {
            let at = rng.below(b.len());
            b.insert(at, 0xFF);
            b.insert(at, 0xC3);
            format!("invalid UTF-8 at {at}")
        }
        2 => {
            for _ in 0..1 + rng.below(8) {
                let at = rng.below(b.len());
                if let Some(x) = b.get_mut(at) {
                    *x = rng.next() as u8;
                }
            }
            "random bytes".into()
        }
        3 => {
            b.splice(0..0, [0xEF, 0xBB, 0xBF]);
            "BOM".into()
        }
        4 => {
            let t = String::from_utf8_lossy(b).replace('\n', "\r\n");
            *b = t.into_bytes();
            "CRLF".into()
        }
        _ => {
            b.clear();
            "empty".into()
        }
    }
}

fn read_lines(p: &Path) -> Vec<Map<String, Value>> {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| match serde_json::from_str(l) {
            Ok(Value::Object(m)) => Some(m),
            _ => None,
        })
        .collect()
}

fn write_lines(p: &Path, entries: &[Map<String, Value>]) {
    let mut s = String::new();
    for e in entries {
        s.push_str(&serde_json::to_string(&Value::Object(e.clone())).unwrap());
        s.push('\n');
    }
    std::fs::write(p, s).unwrap();
}

/// Re-hashes a chain (seq kept as written, prev / entry hash recomputed).
fn rechain(entries: &mut [Map<String, Value>]) {
    let mut prev = GENESIS.to_string();
    for e in entries.iter_mut() {
        e.insert("prev_entry_hash".into(), json!(prev));
        let h = entry_hash(e);
        e.insert("entry_hash".into(), json!(h));
        prev = h;
    }
}

/// Rewrites every digest object in `v` (keys that are hash algorithms) with the digests of `bytes`.
fn redigest(v: &mut Value, bytes: &[u8]) {
    if let Value::Object(m) = v {
        let keys: Vec<String> = m.keys().cloned().collect();
        for k in keys {
            if let Some(a) = HashAlgo::parse(&k)
                && m[&k].is_string()
            {
                m.insert(k, json!(hash_bytes(bytes, a)));
            } else {
                redigest(m.get_mut(&k).unwrap(), bytes);
            }
        }
    }
}

/// The audit entry that records `out_rel` (relative to the run folder), as the readers interpret entries.
fn records(e: &Map<String, Value>, out_rel: &str) -> Option<Vec<String>> {
    let d = e.get("details")?;
    let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let action = e.get("action")?.as_str()?;
    let item = e.get("item").and_then(Value::as_str).unwrap_or_default();
    match action {
        "item_reports_written" => {
            let base = format!("reports/{}/", s(&d["folder"]));
            let name = out_rel.strip_prefix(&base)?;
            d["files"]
                .get(name)
                .map(|_| vec!["files".into(), name.into()])
        }
        "statistics_report_written" => {
            let name = out_rel.strip_prefix("reports/")?;
            d["files"]
                .get(name)
                .map(|_| vec!["files".into(), name.into()])
        }
        "output_written" if format!("reports/{}", s(&d["file"])) == out_rel => Some(vec![]),
        "environment_recorded" if out_rel == "logs/environment.json" => Some(vec![]),
        "hash_register_written" if out_rel == "logs/hashes.csv" => Some(vec![]),
        "trace_written" | "rsmf_written" if format!("rsmf/{item}") == out_rel => Some(vec![]),
        _ => None,
    }
}

/// Re-seals a run after one of its outputs (or its audit log) changed: digests, audit chain, case-log head.
fn reseal_run(case: &Path, run_dir: &str, changed_out: Option<&str>) {
    let dir = case.join(run_dir);
    let audit_p = dir.join("logs/audit.jsonl");
    let mut audit = read_lines(&audit_p);
    if let Some(out) = changed_out {
        let bytes = std::fs::read(dir.join(out)).unwrap_or_default();
        for e in audit.iter_mut() {
            if let Some(at) = records(e, out) {
                let d = e.get_mut("details").unwrap();
                let mut target = &mut *d;
                for k in &at {
                    target = target.get_mut(k.as_str()).unwrap();
                }
                redigest(target, &bytes);
            }
        }
    }
    rechain(&mut audit);
    write_lines(&audit_p, &audit);
    let head = audit
        .last()
        .and_then(|e| e["entry_hash"].as_str())
        .unwrap_or_default()
        .to_string();
    let log_p = case.join("case-log.jsonl");
    let mut log = read_lines(&log_p);
    for e in log.iter_mut() {
        if e.get("action").and_then(Value::as_str) == Some("run_finished")
            && e["details"]["run_dir"] == run_dir
        {
            let d = e.get_mut("details").unwrap();
            d["audit_head"] = json!(head);
            d["audit_entries"] = json!(audit.len());
        }
    }
    rechain(&mut log);
    write_lines(&log_p, &log);
}

/// Re-seals case.json / registry.json digests in the case log.
fn reseal_case(case: &Path) {
    let log_p = case.join("case-log.jsonl");
    let mut log = read_lines(&log_p);
    let cj = std::fs::read(case.join("case.json")).unwrap_or_default();
    let reg = std::fs::read(case.join("evidence/registry.json")).unwrap_or_default();
    for e in log.iter_mut() {
        let d = e.get_mut("details").unwrap();
        if d.get("case_json_sha256").is_some() {
            d["case_json_sha256"] = json!(hash_bytes(&cj, HashAlgo::Sha256));
        }
        if d.get("registry_sha256").is_some_and(Value::is_string) {
            d["registry_sha256"] = json!(hash_bytes(&reg, HashAlgo::Sha256));
        }
    }
    rechain(&mut log);
    write_lines(&log_p, &log);
}

/// A cited file stays inside its run folder: relative, forward slashes, no `..`, no prefix or root.
fn inside(file: &str) -> bool {
    !file.is_empty()
        && !file.contains('\\')
        && Path::new(file)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

/// Discover → verify → read → engine, as the pipeline does, checking the invariants. Err = invariant broken.
/// `only`: verify and read just that run folder (the one a mutation touched); None = every run.
fn check_case(case: &Path, only: Option<&str>) -> Result<(), String> {
    let runs = match readers::discover_runs(case) {
        Ok(r) => r,
        // Not a case folder any more (case.json unreadable): a clean error.
        Err(e) if e.reason == "unreadable" => return Ok(()),
        Err(e) => return Err(format!("discover: unexpected reason {e:?}")),
    };
    let mut out: Vec<RunRef> = Vec::new();
    let mut events = Vec::new();
    for run in runs {
        if only.is_some_and(|o| o != run.run_dir) {
            continue;
        }
        let mut run = readers::verify_run(case, run);
        if run.status == RunStatus::Verified {
            match readers::read_run_outcome(case, &run) {
                Ok(o) => {
                    if o.warnings.len() as u64 > o.skipped {
                        return Err("more warnings than skipped values".into());
                    }
                    for e in &o.events {
                        if e.source.run_dir != run.run_dir || !inside(&e.source.file) {
                            return Err(format!(
                                "event {} cites {:?} in {:?}",
                                e.id, e.source.file, e.source.run_dir
                            ));
                        }
                        if e.utc_ns >= 1_000_000_000 {
                            return Err(format!("event {} has utc_ns {}", e.id, e.utc_ns));
                        }
                    }
                    run.events = o.events.len() as u64;
                    events.extend(o.events);
                }
                Err(e) => {
                    run.status = RunStatus::Excluded;
                    run.exclusion = Some(rv_timeline_core::model::Exclusion {
                        reason: e.reason,
                        detail: e.detail,
                    });
                }
            }
        }
        if run.status == RunStatus::Excluded {
            let r = run.exclusion.as_ref().map(|x| x.reason.as_str());
            if !r.is_some_and(|r| REASONS.contains(&r)) {
                return Err(format!(
                    "{} excluded without a known reason: {r:?}",
                    run.run_dir
                ));
            }
        }
        out.push(run);
    }
    let opts = TimelineOptions {
        case_dir: case.to_path_buf(),
        ..TimelineOptions::default()
    };
    let t = engine::build("", out, events, &opts);
    if t.events
        .windows(2)
        .any(|w| engine::cmp_events(&w[0], &w[1]).is_gt())
    {
        return Err("timeline not ordered".into());
    }
    Ok(())
}

/// The full `build` pipeline: Ok, or a clean Err; outputs written when Ok.
fn check_pipeline(case: &Path) -> Result<(), String> {
    let cfg = RunConfig {
        algorithms: vec![HashAlgo::Sha256],
        langs: vec!["en".into()],
        actor: "fuzz".into(),
        frontend: "test".into(),
        tool_version: "0.0.0".into(),
        ..Default::default()
    };
    let opts = TimelineOptions {
        case_dir: case.to_path_buf(),
        ..TimelineOptions::default()
    };
    match rv_timeline_core::run::run_timeline(&cfg, &opts, &mut |_| {}, &AtomicBool::new(false)) {
        Ok(s) => {
            let stats = std::fs::read(s.report_dir.join("statistics.json"))
                .map_err(|e| format!("statistics.json: {e}"))?;
            serde_json::from_slice::<Value>(&stats).map_err(|e| format!("statistics.json: {e}"))?;
            Ok(())
        }
        Err(_) => Ok(()),
    }
}

fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "panic".into())
}

#[test]
fn hostile_case_folders_never_panic_hang_or_escape() {
    let iters: usize = std::env::var("RV_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let seed: u64 = std::env::var("RV_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x005E_ED71_11E1);
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("case");
    copy_dir(&sample(), &case);
    // A valid run folder outside the case: an escaping path that resolved would read it.
    let outside = tmp.path().join("outside");
    let img_run = std::fs::read_dir(case.join("runs/rv-imgauth"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    copy_dir(&img_run, &outside.join("run"));
    std::fs::copy(
        img_run.join("reports/statistics.json"),
        outside.join("statistics.json"),
    )
    .unwrap();

    let mut files = Vec::new();
    walk(&case, &mut files);
    let snapshot: BTreeMap<String, Vec<u8>> = files
        .iter()
        .map(|p| (rel(&case, p), std::fs::read(p).unwrap()))
        .collect();
    let targets: Vec<String> = snapshot
        .keys()
        .filter(|k| [".json", ".jsonl", ".csv"].iter().any(|x| k.ends_with(x)))
        .cloned()
        .collect();
    let outputs: Vec<&String> = targets
        .iter()
        .filter(|k| k.starts_with("runs/") && !k.ends_with("logs/audit.jsonl"))
        .collect();
    let audits: Vec<&String> = targets
        .iter()
        .filter(|k| k.ends_with("logs/audit.jsonl"))
        .collect();
    assert!(!outputs.is_empty() && !audits.is_empty());
    check_case(&case, None).expect("the unmodified sample passes");

    let mut rng = Rng(seed | 1);
    let mut failures: Vec<String> = Vec::new();
    let (mut slowest, mut slowest_build) = (Duration::ZERO, Duration::ZERO);
    for i in 0..iters {
        let what = rng.below(100);
        let pipeline = i % 100 == 0;
        // (file, mutation, run folder touched or None for the case files)
        let (file, desc, only) = if what < 55 {
            // A tool output, re-sealed (or not) in the run's audit log and the case log.
            let f = (*rng.pick(&outputs)).clone();
            let run_dir = f.splitn(4, '/').take(3).collect::<Vec<_>>().join("/");
            let out_rel = f[run_dir.len() + 1..].to_string();
            let p = case.join(&f);
            let mut d = String::new();
            if f.ends_with(".csv") || rng.chance(25) {
                let mut b = snapshot[&f].clone();
                d = mutate_bytes(&mut rng, &mut b);
                std::fs::write(&p, b).unwrap();
            } else if f.ends_with(".jsonl") {
                let mut lines = read_lines(&p);
                if !lines.is_empty() {
                    let n = rng.below(lines.len());
                    let mut v = Value::Object(lines[n].clone());
                    d = mutate_value(&mut rng, &mut v);
                    if let Value::Object(m) = v {
                        lines[n] = m;
                    }
                    write_lines(&p, &lines);
                }
            } else if let Ok(mut v) = serde_json::from_slice::<Value>(&snapshot[&f]) {
                d = mutate_value(&mut rng, &mut v);
                std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
            }
            if rng.chance(85) {
                reseal_run(&case, &run_dir, Some(&out_rel));
                d.push_str(" +resealed");
            }
            (f, d, Some(run_dir))
        } else if what < 80 {
            // A run's audit log: one entry changed (paths, versions, digests, times…), then re-chained.
            let f = (*rng.pick(&audits)).clone();
            let run_dir = f.trim_end_matches("/logs/audit.jsonl").to_string();
            let p = case.join(&f);
            let mut d;
            if rng.chance(15) {
                let mut b = snapshot[&f].clone();
                d = mutate_bytes(&mut rng, &mut b);
                std::fs::write(&p, b).unwrap();
            } else {
                let mut lines = read_lines(&p);
                let n = rng.below(lines.len());
                let mut v = Value::Object(lines[n].clone());
                // Aim at output paths half the time: they decide which files are read.
                let path_keys = ["folder", "file"];
                let aimed = v["details"].as_object().and_then(|m| {
                    path_keys
                        .iter()
                        .find(|k| m.contains_key(**k))
                        .map(|k| k.to_string())
                });
                d = match aimed {
                    Some(k) if rng.chance(50) => {
                        let bad = *rng.pick(&PATHS);
                        v["details"][&k] = json!(bad);
                        format!("details/{k} = {bad:?}")
                    }
                    _ if v.get("item").is_some() && rng.chance(20) => {
                        let bad = *rng.pick(&PATHS);
                        v["item"] = json!(bad);
                        format!("item = {bad:?}")
                    }
                    _ => mutate_value(&mut rng, &mut v),
                };
                if let Value::Object(m) = v {
                    lines[n] = m;
                }
                write_lines(&p, &lines);
                d = format!("line {}: {d}", n + 1);
            }
            if rng.chance(85) {
                reseal_run(&case, &run_dir, None);
                d.push_str(" +resealed");
            }
            (f, d, Some(run_dir))
        } else {
            // The case log, case.json or the registry (JSON or CSV), re-sealed in the case log.
            let f = rng
                .pick(&[
                    "case-log.jsonl",
                    "case.json",
                    "evidence/registry.json",
                    "evidence/registry.csv",
                ])
                .to_string();
            let p = case.join(&f);
            let mut d;
            if f.ends_with(".csv") || rng.chance(20) {
                let mut b = snapshot[&f].clone();
                d = mutate_bytes(&mut rng, &mut b);
                std::fs::write(&p, b).unwrap();
            } else if f == "case-log.jsonl" {
                let mut lines = read_lines(&p);
                let n = rng.below(lines.len());
                let mut v = Value::Object(lines[n].clone());
                d = if v["details"].get("run_dir").is_some() && rng.chance(50) {
                    let bad = *rng.pick(&PATHS);
                    v["details"]["run_dir"] = json!(bad);
                    format!("line {}: run_dir = {bad:?}", n + 1)
                } else {
                    mutate_value(&mut rng, &mut v)
                };
                if let Value::Object(m) = v {
                    lines[n] = m;
                }
                write_lines(&p, &lines);
            } else {
                let mut v: Value = serde_json::from_slice(&snapshot[&f]).unwrap();
                d = mutate_value(&mut rng, &mut v);
                std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
            }
            if rng.chance(85) {
                reseal_case(&case);
                d.push_str(" +resealed");
            }
            (f, d, None)
        };

        let mut took = Duration::ZERO;
        let mut took_build = Duration::ZERO;
        let r = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let t0 = Instant::now();
            check_case(&case, only.as_deref())?;
            took = t0.elapsed();
            if pipeline {
                let t1 = Instant::now();
                check_pipeline(&case)?;
                took_build = t1.elapsed();
            }
            Ok::<(), String>(())
        }));
        slowest = slowest.max(took);
        slowest_build = slowest_build.max(took_build);
        let problem = match r {
            Ok(Ok(())) if took > BUDGET => Some(format!("took {took:?}")),
            Ok(Ok(())) if took_build > PIPELINE_BUDGET => {
                Some(format!("build took {took_build:?}"))
            }
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(p) => Some(format!("PANIC {}", panic_text(p))),
        };
        if let Some(p) = problem {
            failures.push(format!("#{i} {file}: {desc} -> {p}"));
        }
        // Restore: every file back to the snapshot, nothing else left behind.
        let mut now = Vec::new();
        walk(&case, &mut now);
        for p in now {
            let k = rel(&case, &p);
            match snapshot.get(&k) {
                Some(b) => {
                    if std::fs::read(&p).ok().as_deref() != Some(b.as_slice()) {
                        std::fs::write(&p, b).unwrap();
                    }
                }
                None => std::fs::remove_file(&p).unwrap(),
            }
        }
        let _ = std::fs::remove_dir_all(case.join("runs/rv-timeline"));
    }
    eprintln!(
        "{iters} mutations, slowest {slowest:?} (full build: {slowest_build:?}), {} failures",
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} of {iters} mutations broke an invariant:\n{}",
        failures.len(),
        failures
            .iter()
            .take(30)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Creates a symlink (file or folder); false when the platform or the account does not allow it (Windows
/// without Developer Mode), in which case the symlink checks are skipped.
fn symlink(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        if target.is_dir() {
            std::os::windows::fs::symlink_dir(target, link).is_ok()
        } else {
            std::os::windows::fs::symlink_file(target, link).is_ok()
        }
    }
}

#[test]
fn symlinks_out_of_the_case_folder_are_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("case");
    copy_dir(&sample(), &case);
    let img = std::fs::read_dir(case.join("runs/rv-imgauth"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let run_dir = rel(&case, &img);
    // 1. An output replaced by a symlink to an identical file outside the case (the digest still matches).
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let stats = img.join("reports/statistics.json");
    std::fs::copy(&stats, outside.join("statistics.json")).unwrap();
    std::fs::remove_file(&stats).unwrap();
    if !symlink(&outside.join("statistics.json"), &stats) {
        eprintln!("symlinks not permitted here: skipped");
        return;
    }
    let r = readers::verify_run(&case, run_of(&case, &run_dir));
    assert_eq!(r.status, RunStatus::Excluded, "{r:?}");
    assert_eq!(r.exclusion.unwrap().reason, "unreadable");

    // 2. The whole run folder replaced by a symlink to an identical copy outside the case.
    std::fs::remove_file(&stats).unwrap();
    std::fs::copy(outside.join("statistics.json"), &stats).unwrap();
    let moved = outside.join("run");
    copy_dir(&img, &moved);
    std::fs::remove_dir_all(&img).unwrap();
    assert!(symlink(&moved, &img));
    let r = readers::verify_run(&case, run_of(&case, &run_dir));
    assert_eq!(r.status, RunStatus::Excluded, "{r:?}");
    assert_eq!(r.exclusion.unwrap().reason, "unreadable");
    // The other runs are still read.
    check_case(&case, None).unwrap();
}

fn run_of(case: &Path, run_dir: &str) -> RunRef {
    readers::discover_runs(case)
        .unwrap()
        .into_iter()
        .find(|r| r.run_dir == run_dir)
        .unwrap()
}

/// Recorded output paths that lead out of the run folder: `..` with either separator, absolute paths. The
/// rv-imgauth run's record of a metadata.json is pointed at an identical copy outside the case (so its digests
/// still match) and the run re-sealed: nothing may be read from there.
#[test]
fn recorded_paths_escaping_the_case_folder_are_not_read() {
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("case");
    copy_dir(&sample(), &case);
    let img = std::fs::read_dir(case.join("runs/rv-imgauth"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let run_dir = rel(&case, &img);
    let outside = tmp.path().join("outside");
    copy_dir(&img, &outside);
    let audit_p = img.join("logs/audit.jsonl");
    let original = std::fs::read(&audit_p).unwrap();
    let log_original = std::fs::read(case.join("case-log.jsonl")).unwrap();
    let entries = read_lines(&audit_p);
    let at = entries
        .iter()
        .position(|e| {
            e["action"] == "output_written"
                && e["details"]["file"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("/metadata.json"))
        })
        .expect("an output_written entry for a metadata.json");
    // e.g. items/00001-camera-original.jpg/metadata.json
    let file = entries[at]["details"]["file"].as_str().unwrap().to_string();
    let folder = file.trim_end_matches("/metadata.json").to_string();
    // The readers only take files below reports/items/<index>-…, so the escape starts inside an item folder
    // and climbs out: from <case>/runs/rv-imgauth/<run>/reports/<folder> up 7 levels to <tmp>.
    let tail = format!("{}outside/reports/{file}", "../".repeat(7));
    let abs = outside.join("reports").join(&file);
    for bad in [
        format!("{folder}/{tail}"),
        // Backslashes (separators on Windows), the name still ending in /metadata.json as the reader expects.
        format!(
            "{folder}/{}/metadata.json",
            tail.trim_end_matches("/metadata.json").replace('/', "\\")
        ),
        abs.to_string_lossy().into_owned(),
        abs.to_string_lossy().replace('\\', "/"),
        format!("{folder}/{}", abs.to_string_lossy()),
    ] {
        let mut e = entries.clone();
        e[at].get_mut("details").unwrap()["file"] = json!(bad);
        write_lines(&audit_p, &e);
        reseal_run(&case, &run_dir, None);
        let run = readers::verify_run(&case, run_of(&case, &run_dir));
        if run.status == RunStatus::Verified {
            let o = readers::read_run_outcome(&case, &run).unwrap();
            for ev in &o.events {
                assert!(
                    inside(&ev.source.file),
                    "{bad:?}: event {} read from {:?}",
                    ev.id,
                    ev.source.file
                );
            }
        }
        std::fs::write(&audit_p, &original).unwrap();
        std::fs::write(case.join("case-log.jsonl"), &log_original).unwrap();
    }
}

/// A time value no parser understands (resealed, so the run still verifies) is counted in the build's audit log
/// and statistics and named as a limitation; it is never placed on the timeline.
#[test]
fn an_unparseable_time_is_counted_never_placed() {
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("case");
    copy_dir(&sample(), &case);
    let img = std::fs::read_dir(case.join("runs/rv-imgauth"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let run_dir = rel(&case, &img);
    let out = "reports/items/00001-camera-original.jpg/metadata.json";
    let p = img.join(out);
    let mut v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    let tag = v["tags"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|t| t["name"] == "DateTimeOriginal")
        .expect("DateTimeOriginal");
    tag["value"] = json!("2026:13:45 99:99:99");
    std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    reseal_run(&case, &run_dir, Some(out));

    let cfg = RunConfig {
        algorithms: vec![HashAlgo::Sha256],
        langs: vec!["en".into()],
        actor: "tester".into(),
        frontend: "test".into(),
        tool_version: "0.0.0".into(),
        ..Default::default()
    };
    let opts = TimelineOptions {
        case_dir: case.clone(),
        ..TimelineOptions::default()
    };
    let s = rv_timeline_core::run::run_timeline(&cfg, &opts, &mut |_| {}, &AtomicBool::new(false))
        .unwrap();
    let audit: Vec<Value> = std::fs::read_to_string(s.log_dir.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let read = audit
        .iter()
        .find(|e| e["action"] == "run_read" && e["item"] == run_dir.as_str())
        .expect("run_read of the rv-imgauth run");
    assert_eq!(read["details"]["times_skipped"], 1, "{read}");
    let ex = read["details"]["times_skipped_examples"][0]
        .as_str()
        .unwrap();
    assert!(
        ex.contains("2026:13:45 99:99:99") && ex.contains(out),
        "{ex}"
    );
    let stats: Value =
        serde_json::from_slice(&std::fs::read(s.report_dir.join("statistics.json")).unwrap())
            .unwrap();
    assert_eq!(stats["timeline"]["times_skipped"], 1);
    assert_eq!(stats["limitations"][0], "TL_TIMES_SKIPPED");
    let jsonl = std::fs::read_to_string(s.report_dir.join("timeline.jsonl")).unwrap();
    assert!(!jsonl.contains("2026:13:45"));
}

/// Every key of every entry of every run's audit log deleted in turn, then re-sealed (the fuzz loop found a
/// panic on a missing `ts_utc`): the run is verified or excluded, never a panic.
#[test]
fn audit_entries_missing_any_key_never_panic() {
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("case");
    copy_dir(&sample(), &case);
    let log_original = std::fs::read(case.join("case-log.jsonl")).unwrap();
    for run in readers::discover_runs(&case).unwrap() {
        let audit_p = case.join(&run.run_dir).join("logs/audit.jsonl");
        let original = std::fs::read(&audit_p).unwrap();
        let entries = read_lines(&audit_p);
        // The first entries, the run's last ones and every distinct action once keep the loop short.
        let mut seen = std::collections::BTreeSet::new();
        let picked: Vec<usize> = (0..entries.len())
            .filter(|&i| {
                i < 3
                    || i + 3 >= entries.len()
                    || seen.insert(entries[i]["action"].as_str().unwrap_or("").to_string())
            })
            .collect();
        for i in picked {
            let keys: Vec<String> = entries[i]
                .keys()
                .chain(
                    entries[i]
                        .get("details")
                        .and_then(Value::as_object)
                        .into_iter()
                        .flat_map(|d| d.keys()),
                )
                .cloned()
                .collect();
            for k in keys {
                let mut e = entries.clone();
                if e[i].remove(&k).is_none()
                    && let Some(Value::Object(d)) = e[i].get_mut("details")
                {
                    d.remove(&k);
                }
                write_lines(&audit_p, &e);
                reseal_run(&case, &run.run_dir, None);
                let r = std::panic::catch_unwind(|| check_case(&case, Some(&run.run_dir)));
                assert!(
                    matches!(r, Ok(Ok(()))),
                    "{} line {}: without {k}: {:?}",
                    run.run_dir,
                    i + 1,
                    r.map_err(panic_text)
                );
                std::fs::write(&audit_p, &original).unwrap();
                std::fs::write(case.join("case-log.jsonl"), &log_original).unwrap();
            }
        }
    }
}
