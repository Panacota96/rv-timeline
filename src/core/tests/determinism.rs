//! Determinism: building the same case twice gives a byte-identical `timeline.jsonl` and the same reports JSON
//! once the run's own id, times and durations are blanked. The second build runs on the case restored to its
//! state before the first one (the first timeline run removed, the case log put back), so both builds see the
//! same inputs at the same path.

use rv_timeline_core::RunConfig;
use rv_timeline_core::hash::HashAlgo;
use rv_timeline_core::model::TimelineOptions;
use rv_timeline_core::run::run_timeline;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

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

/// Keys whose values belong to one build (when it ran, how long it took), blanked before comparing. The audit
/// head is the hash of the run's last audit entry, which records its own `ts_utc`: it differs on every build.
fn per_build(key: &str) -> bool {
    key.ends_with("_utc")
        || key.starts_with("elapsed")
        || key.starts_with("duration")
        || key == "head"
}

/// The JSON with the run id replaced and per-build values blanked.
fn normalize(v: &mut Value, run_id: &str) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if per_build(k) {
                    *x = Value::Null;
                } else {
                    normalize(x, run_id);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| normalize(x, run_id)),
        Value::String(s) if s.contains(run_id) => *s = s.replace(run_id, "<RUN>"),
        _ => {}
    }
}

/// One build; returns (timeline.jsonl bytes, every reports/**/*.json normalized, by path below reports/).
fn build(case: &Path) -> (Vec<u8>, BTreeMap<String, Value>) {
    let cfg = RunConfig {
        algorithms: vec![HashAlgo::Sha256, HashAlgo::Blake3],
        langs: vec!["en".into(), "es".into(), "fr".into()],
        actor: "tester".into(),
        frontend: "test".into(),
        tool_version: "0.0.0".into(),
        ..Default::default()
    };
    let opts = TimelineOptions {
        case_dir: case.to_path_buf(),
        display_zone: "America/Bogota".into(),
        ..TimelineOptions::default()
    };
    let s = run_timeline(&cfg, &opts, &mut |_| {}, &AtomicBool::new(false)).expect("build");
    let jsonl = std::fs::read(s.report_dir.join("timeline.jsonl")).unwrap();
    let mut files = Vec::new();
    walk(&s.report_dir, &mut files);
    let mut out = BTreeMap::new();
    for f in files
        .into_iter()
        .filter(|f| f.extension().is_some_and(|x| x == "json"))
    {
        let mut v: Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
        normalize(&mut v, &s.run_id);
        let rel = f
            .strip_prefix(&s.report_dir)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/")
            .replace(&s.run_id, "<RUN>");
        out.insert(rel, v);
    }
    (jsonl, out)
}

/// JSON pointers where `a` and `b` differ, with both values.
fn differences(at: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for k in x.keys().chain(y.keys().filter(|k| !x.contains_key(*k))) {
                differences(
                    &format!("{at}/{k}"),
                    x.get(k).unwrap_or(&Value::Null),
                    y.get(k).unwrap_or(&Value::Null),
                    out,
                );
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                differences(&format!("{at}/{i}"), p, q, out);
            }
        }
        _ if a != b => {
            let short = |v: &Value| v.to_string().chars().take(120).collect::<String>();
            out.push(format!("{at}: {} != {}", short(a), short(b)));
        }
        _ => {}
    }
}

#[test]
fn building_the_same_case_twice_gives_the_same_timeline_and_reports() {
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("case");
    copy_dir(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/case"),
        &case,
    );
    let log = std::fs::read(case.join("case-log.jsonl")).unwrap();
    let (jsonl_a, reports_a) = build(&case);
    // Back to the state before the first build.
    std::fs::remove_dir_all(case.join("runs/rv-timeline")).unwrap();
    std::fs::write(case.join("case-log.jsonl"), &log).unwrap();
    let (jsonl_b, reports_b) = build(&case);

    assert!(!jsonl_a.is_empty());
    assert!(
        jsonl_a == jsonl_b,
        "timeline.jsonl differs between two builds of the same case"
    );
    assert_eq!(
        reports_a.keys().collect::<Vec<_>>(),
        reports_b.keys().collect::<Vec<_>>(),
        "the two builds wrote different report files"
    );
    assert!(reports_a.contains_key("statistics.json"));
    let mut diffs = Vec::new();
    for (k, a) in &reports_a {
        differences(&format!("{k}#"), a, &reports_b[k], &mut diffs);
    }
    assert!(
        diffs.is_empty(),
        "{} values differ between two builds:\n{}",
        diffs.len(),
        diffs
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
