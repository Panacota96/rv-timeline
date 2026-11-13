//! Review log (`review.jsonl`): what an examiner looked at AFTER a run finished (e.g. `ui_timeline_viewed` in the
//! GUI timeline viewer), kept next to the run's `audit.jsonl` in the same log folder.
//!
//! The run's audit chain is closed at `run_finished` (only `timestamp_obtained` may follow; `case::verify_case`
//! rejects anything else), so later viewing goes into this second chain, which vouches for the run it belongs
//! to:
//!
//! ```text
//! audit.jsonl:  … ── #N run_finished (entry_hash H) [── timestamp_obtained …]
//! review.jsonl: #1 {anchor_seq: N, anchor_hash: H, prev_entry_hash: H} ── #2 {prev: #1} ── …
//! ```
//!
//! Entry: `seq`, `at_utc`, `actor`, `action`, `run_id` (the audit's), `details` (any JSON object),
//! `prev_entry_hash`, `entry_hash` (same canonical rule as audit.jsonl: SHA-256 of the sorted-key compact JSON
//! without `entry_hash`). The first entry also holds `anchor_seq` / `anchor_hash`; its `prev_entry_hash` is the
//! anchor hash. `verify` checks the chain, that the anchor is the `run_finished` entry of the audit log in the
//! same folder and that every entry names that run. Ported unchanged from rv-mailauth (same rules).

use crate::audit::entry_hash;
use crate::time::utc_now;
use serde_json::{Map, Value, json};
use std::io::Write;
use std::path::Path;

pub const REVIEW_FILE: &str = "review.jsonl";
const AUDIT_FILE: &str = "audit.jsonl";

fn lines(path: &Path) -> Result<Vec<Value>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| {
            serde_json::from_str(l).map_err(|e| format!("line {}: not valid JSON ({})", i + 1, e))
        })
        .collect()
}

/// (run_id, seq, entry_hash) of the `run_finished` entry of an intact audit.jsonl.
fn anchor(log_dir: &Path) -> Result<(String, u64, String), String> {
    let audit = log_dir.join(AUDIT_FILE);
    crate::audit::verify(&audit).map_err(|p| {
        format!(
            "{} does not verify: {}",
            audit.display(),
            p.first().cloned().unwrap_or_default()
        )
    })?;
    let entries = lines(&audit)?;
    let fin = entries
        .iter()
        .rev()
        .find(|e| e["action"] == "run_finished")
        .ok_or_else(|| {
            format!(
                "{}: the run has not finished (no run_finished)",
                audit.display()
            )
        })?;
    Ok((
        fin["run_id"].as_str().unwrap_or_default().to_string(),
        fin["seq"].as_u64().unwrap_or(0),
        fin["entry_hash"].as_str().unwrap_or_default().to_string(),
    ))
}

/// Appends one review entry to `<log_dir>/review.jsonl` (created on first use, anchored to the run's
/// `run_finished` entry). Refuses when the audit log or the existing review log does not verify. Returns the
/// new entry's sequence number.
pub fn append(log_dir: &Path, actor: &str, action: &str, details: Value) -> Result<u64, String> {
    if !details.is_object() {
        return Err("review details must be a JSON object".into());
    }
    let (run_id, anchor_seq, anchor_hash) = anchor(log_dir)?;
    let path = log_dir.join(REVIEW_FILE);
    let (seq, prev) = if path.exists() {
        let n = verify(log_dir)
            .map_err(|p| format!("{} does not verify: {}", path.display(), p.join("; ")))?
            .unwrap_or(0);
        let last = lines(&path)?.pop();
        (
            n + 1,
            last.and_then(|l| l["entry_hash"].as_str().map(str::to_string))
                .unwrap_or_else(|| anchor_hash.clone()),
        )
    } else {
        (1, anchor_hash.clone())
    };
    let mut m = Map::new();
    m.insert("seq".into(), json!(seq));
    m.insert("at_utc".into(), json!(utc_now()));
    m.insert("run_id".into(), json!(run_id));
    m.insert("actor".into(), json!(actor));
    m.insert("action".into(), json!(action));
    m.insert("details".into(), details);
    if seq == 1 {
        m.insert("anchor_seq".into(), json!(anchor_seq));
        m.insert("anchor_hash".into(), json!(anchor_hash));
    }
    m.insert("prev_entry_hash".into(), json!(prev));
    let h = entry_hash(&m);
    m.insert("entry_hash".into(), json!(h));
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
    writeln!(f, "{}", Value::Object(m))
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
    Ok(seq)
}

/// Verifies `<log_dir>/review.jsonl`: Ok(None) when there is none, Ok(Some(entries)) when it is intact and
/// anchored to this run's `run_finished` entry, Err(problems) otherwise.
pub fn verify(log_dir: &Path) -> Result<Option<u64>, Vec<String>> {
    let path = log_dir.join(REVIEW_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let (run_id, anchor_seq, anchor_hash) = anchor(log_dir).map_err(|e| vec![e])?;
    let entries = lines(&path).map_err(|e| vec![e])?;
    let mut problems = vec![];
    let mut prev = anchor_hash.clone();
    for (i, e) in entries.iter().enumerate() {
        let n = i + 1;
        let Some(m) = e.as_object() else {
            problems.push(format!("review line {n}: not a JSON object"));
            continue;
        };
        if e["seq"].as_u64() != Some(n as u64) {
            problems.push(format!(
                "review line {n}: sequence {} where {n} was expected (deleted or re-ordered entry)",
                e["seq"]
            ));
        }
        if n == 1
            && (e["anchor_seq"].as_u64() != Some(anchor_seq)
                || e["anchor_hash"].as_str() != Some(anchor_hash.as_str()))
        {
            problems.push(format!(
                "review line 1: not anchored to run_finished (#{anchor_seq}) of this run's audit.jsonl"
            ));
        }
        if e["run_id"].as_str() != Some(run_id.as_str()) {
            problems.push(format!("review line {n}: names another run"));
        }
        if e["prev_entry_hash"].as_str() != Some(prev.as_str()) {
            problems.push(format!(
                "review line {n}: prev_entry_hash does not link to the previous entry"
            ));
        }
        let stored = e["entry_hash"].as_str().unwrap_or_default().to_string();
        if entry_hash(m) != stored {
            problems.push(format!(
                "review line {n}: entry_hash does not match its content (edited entry)"
            ));
        }
        prev = stored;
    }
    if problems.is_empty() {
        Ok(Some(entries.len() as u64))
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;

    fn finished_run(dir: &Path, run_id: &str) {
        let mut log = AuditLog::create(dir, run_id, "tester").unwrap();
        log.record("run_started", None, json!({})).unwrap();
        log.record("run_finished", None, json!({"items": 1}))
            .unwrap();
    }

    fn viewed(file: &str) -> Value {
        json!({"item": "E0001", "index": 1, "file": file, "digest_ok": true, "sha256": "ab",
               "run_id": "RUN-1", "at_utc": "2026-10-28T10:00:00Z"})
    }

    #[test]
    fn appended_entries_chain_from_run_finished() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(verify(d.path()), Ok(None));
        finished_run(d.path(), "RUN-1");
        assert_eq!(verify(d.path()), Ok(None));
        assert_eq!(
            append(
                d.path(),
                "Ana",
                "ui_timeline_viewed",
                viewed("reports/timeline-1.jsonl")
            ),
            Ok(1)
        );
        assert_eq!(
            append(
                d.path(),
                "Ana",
                "ui_timeline_viewed",
                viewed("reports/timeline-2.jsonl")
            ),
            Ok(2)
        );
        assert_eq!(verify(d.path()), Ok(Some(2)));
        let e = lines(&d.path().join(REVIEW_FILE)).unwrap();
        assert_eq!(e[0]["anchor_seq"], 2);
        assert_eq!(e[0]["details"]["file"], "reports/timeline-1.jsonl");
        assert_eq!(e[1]["prev_entry_hash"], e[0]["entry_hash"]);
        // The run's audit log itself is untouched (verify_case accepts nothing after run_finished).
        assert_eq!(crate::audit::verify(&d.path().join(AUDIT_FILE)), Ok(2));
        assert!(append(d.path(), "Ana", "x", json!("not an object")).is_err());
    }

    #[test]
    fn tampered_or_re_anchored_review_logs_are_detected() {
        let d = tempfile::tempdir().unwrap();
        finished_run(d.path(), "RUN-1");
        append(
            d.path(),
            "Ana",
            "ui_timeline_viewed",
            viewed("reports/timeline-1.jsonl"),
        )
        .unwrap();
        append(
            d.path(),
            "Ana",
            "ui_timeline_viewed",
            viewed("reports/timeline-2.jsonl"),
        )
        .unwrap();
        let path = d.path().join(REVIEW_FILE);
        let good = std::fs::read_to_string(&path).unwrap();

        // An edited entry.
        std::fs::write(
            &path,
            good.replace("reports/timeline-2.jsonl", "reports/timeline-3.jsonl"),
        )
        .unwrap();
        let p = verify(d.path()).unwrap_err();
        assert!(p.iter().any(|x| x.contains("edited entry")), "{p:?}");
        assert!(
            append(d.path(), "Ana", "ui_timeline_viewed", viewed("x")).is_err(),
            "no append to a broken log"
        );

        // A deleted entry.
        std::fs::write(&path, good.lines().nth(1).unwrap().to_string() + "\n").unwrap();
        assert!(verify(d.path()).is_err());

        // The same review log moved next to another run (re-anchored to the wrong audit chain).
        let other = tempfile::tempdir().unwrap();
        finished_run(other.path(), "RUN-2");
        std::fs::write(other.path().join(REVIEW_FILE), &good).unwrap();
        let p = verify(other.path()).unwrap_err();
        assert!(p.iter().any(|x| x.contains("not anchored")), "{p:?}");

        // A review log rebuilt with a consistent chain but a forged anchor.
        let mut first: Map<String, Value> =
            serde_json::from_str(good.lines().next().unwrap()).unwrap();
        first.insert("anchor_hash".into(), json!("00".repeat(32)));
        first.insert("prev_entry_hash".into(), json!("00".repeat(32)));
        let h = entry_hash(&first);
        first.insert("entry_hash".into(), json!(h));
        std::fs::write(&path, format!("{}\n", Value::Object(first))).unwrap();
        let p = verify(d.path()).unwrap_err();
        assert!(p.iter().any(|x| x.contains("not anchored")), "{p:?}");

        // A run that has not finished cannot be reviewed.
        let open = tempfile::tempdir().unwrap();
        let mut log = AuditLog::create(open.path(), "RUN-3", "tester").unwrap();
        log.record("run_started", None, json!({})).unwrap();
        assert!(append(open.path(), "Ana", "ui_timeline_viewed", viewed("x")).is_err());

        std::fs::write(&path, &good).unwrap();
        assert_eq!(verify(d.path()), Ok(Some(2)));
    }
}
