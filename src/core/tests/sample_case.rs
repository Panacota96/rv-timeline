//! End-to-end check of the readers and the engine against the sample case's ground truth
//! (`examples/sample/expected_timeline.json`, derived by `tests/make_sample_case.py` from the six tools' own
//! outputs, independently of this crate). Compares run verification, event ids/kinds/times and signals.

use rv_timeline_core::engine;
use rv_timeline_core::model::{RunRef, RunStatus, TimelineOptions};
use rv_timeline_core::readers;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn expected() -> Value {
    let p = root().join("examples/sample/expected_timeline.json");
    serde_json::from_slice(&std::fs::read(p).expect("expected_timeline.json")).expect("valid JSON")
}

/// Discovers, verifies and reads a case the way the pipeline does, then builds the timeline.
fn build(case_dir: &Path, exp: &Value) -> rv_timeline_core::model::Timeline {
    let opts = TimelineOptions {
        case_dir: case_dir.to_path_buf(),
        display_zone: exp["options"]["display_zone"]
            .as_str()
            .unwrap_or("UTC")
            .into(),
        clock_skew_s: exp["options"]["clock_skew_s"].as_u64().unwrap_or(300),
        ..TimelineOptions::default()
    };
    let all = readers::all();
    let mut runs: Vec<RunRef> = Vec::new();
    let mut events = Vec::new();
    for run in readers::discover_runs(case_dir).expect("discover") {
        let mut run = readers::verify_run(case_dir, run);
        if run.status == RunStatus::Verified {
            match readers::read_run(&all, case_dir, &run) {
                Ok(ev) => {
                    run.events = ev.len() as u64;
                    events.extend(ev);
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
        runs.push(run);
    }
    engine::build("", runs, events, &opts)
}

fn diff(label: &str, want: &BTreeSet<String>, got: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for m in want.difference(got) {
        out.push(format!("{label}: missing {m}"));
    }
    for x in got.difference(want) {
        out.push(format!("{label}: unexpected {x}"));
    }
    out
}

#[test]
fn clean_case_matches_ground_truth() {
    let exp = expected();
    let c = &exp["clean"];
    let t = build(&root().join("examples/sample/case"), &exp);
    let mut problems = Vec::new();

    let want_runs: BTreeSet<String> = c["runs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {} {}",
                r["run_dir"].as_str().unwrap(),
                r["status"].as_str().unwrap(),
                r["events"]
            )
        })
        .collect();
    let got_runs: BTreeSet<String> = t
        .runs
        .iter()
        .map(|r| {
            let s = if r.status == RunStatus::Verified {
                "verified"
            } else {
                "excluded"
            };
            format!("{} {} {}", r.run_dir, s, r.events)
        })
        .collect();
    problems.extend(diff("run", &want_runs, &got_runs));

    let want_ev: BTreeSet<String> = c["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            format!(
                "{} {}.{:09}",
                e["id"].as_str().unwrap(),
                e["utc_s"],
                e["utc_ns"].as_u64().unwrap_or(0)
            )
        })
        .collect();
    let got_ev: BTreeSet<String> = t
        .events
        .iter()
        .map(|e| format!("{} {}.{:09}", e.id, e.utc_s, e.utc_ns))
        .collect();
    problems.extend(diff("event", &want_ev, &got_ev));
    if c["zone_unknown"].as_u64() != Some(t.zone_unknown) {
        problems.push(format!(
            "zone_unknown: want {} got {}",
            c["zone_unknown"], t.zone_unknown
        ));
    }

    problems.extend(diff(
        "signal",
        &want_signals(&c["signals"]),
        &got_signals(&t),
    ));

    assert!(
        problems.is_empty(),
        "{} difference(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn tampered_copies_exclude_the_right_run() {
    let exp = expected();
    for (name, want) in exp["tampered"].as_object().unwrap() {
        let dir = root().join("examples/sample/tampered").join(name);
        let t = build(&dir, &exp);
        let run_dir = want["excluded_run"]["run_dir"].as_str().unwrap();
        let reason = want["excluded_run"]["reason"].as_str().unwrap();
        let r = t
            .runs
            .iter()
            .find(|r| r.run_dir == run_dir)
            .unwrap_or_else(|| panic!("{name}: run {run_dir} not found"));
        assert_eq!(
            r.status,
            RunStatus::Excluded,
            "{name}: {run_dir} should be excluded"
        );
        assert_eq!(
            r.exclusion.as_ref().map(|e| e.reason.as_str()),
            Some(reason),
            "{name}"
        );
        let others_excluded: Vec<&str> = t
            .runs
            .iter()
            .filter(|x| x.run_dir != run_dir && x.status == RunStatus::Excluded)
            .map(|x| x.run_dir.as_str())
            .collect();
        assert!(
            others_excluded.is_empty(),
            "{name}: other runs excluded too: {others_excluded:?}"
        );
        assert!(
            t.signals.iter().any(|s| s.code == "RUN_NOT_VERIFIED"),
            "{name}: RUN_NOT_VERIFIED"
        );
        // Every signal (RUN_NOT_VERIFIED included) with its item and severity.
        let problems = diff("signal", &want_signals(&want["signals"]), &got_signals(&t));
        assert!(problems.is_empty(), "{name}:\n{}", problems.join("\n"));
    }
}

/// Every signal of the clean case and the tampered copies renders in en/es/fr with each `%{placeholder}` of its
/// texts filled by a non-empty param (a missing one would print e.g. "In message , ...").
#[test]
fn every_signal_fills_its_placeholders() {
    let exp = expected();
    let mut dirs = vec![root().join("examples/sample/case")];
    for name in exp["tampered"].as_object().unwrap().keys() {
        dirs.push(root().join("examples/sample/tampered").join(name));
    }
    let mut problems = Vec::new();
    for dir in dirs {
        let t = build(&dir, &exp);
        for s in &t.signals {
            for lang in rv_timeline_core::i18n::LANGS {
                let c = rv_timeline_core::i18n::catalog(lang);
                let p = rv_timeline_core::report::localized_params(c, &s.params);
                let entry = c.signal_entry(&s.code, &p);
                for key in ["title", "shows", "does_not_prove"] {
                    let Some(text) = entry[key].as_str() else {
                        problems.push(format!("{lang} {}: no {key}", s.code));
                        continue;
                    };
                    for part in text.split("%{").skip(1) {
                        let name = part.split('}').next().unwrap_or_default();
                        if p.get(name).is_none_or(|v| v.trim().is_empty()) {
                            problems.push(format!("{lang} {} {key}: %{{{name}}} is empty", s.code));
                        }
                    }
                }
            }
        }
    }
    problems.sort();
    problems.dedup();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// `code item severity` of the signals in the ground truth.
fn want_signals(signals: &Value) -> BTreeSet<String> {
    signals
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let item = &s["item"];
            let it = if item.is_null() {
                String::new()
            } else {
                format!(
                    "{}{}",
                    item["evidence_id"].as_str().unwrap_or(""),
                    item["sub"].as_str().unwrap_or("")
                )
            };
            format!(
                "{} {} {}",
                s["code"].as_str().unwrap(),
                it,
                s["severity"].as_str().unwrap()
            )
        })
        .collect()
}

/// `code item severity` of the signals the engine produced.
fn got_signals(t: &rv_timeline_core::model::Timeline) -> BTreeSet<String> {
    t.signals
        .iter()
        .map(|s| {
            let it = s
                .item
                .as_ref()
                .map(|i| format!("{}{}", i.evidence_id, i.sub))
                .unwrap_or_default();
            let sev = serde_json::to_value(s.severity).unwrap();
            format!("{} {} {}", s.code, it, sev.as_str().unwrap())
        })
        .collect()
}
