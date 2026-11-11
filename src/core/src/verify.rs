//! `verify-log`: the audit chain, its RFC 3161 timestamps and — because a hash chain alone cannot show that
//! entries were removed from its end — a truncation check against the records kept outside the log:
//!
//! * the timestamp: `timestamp-<seq>.json` names the entry it covers (`covers_seq`) and the token signs that
//!   entry's hash, so the log must still contain that entry with that hash;
//! * the case log: for a run inside a case folder (`<CASE>/runs/<tool>/<RUN-ID>/logs`), `run_finished` in
//!   `case-log.jsonl` records the run's final audit head and entry count (`audit_head`, `audit_entries`).
//!
//! Entries after the last anchored one cannot be proven complete; the report says how many there are.
//! Without a timestamp or a case record, truncation is not detectable and the report says so.
//! Same rules and wording as the Python profile (`core/verify.py`).

use crate::audit;
use crate::case::{CASE_FILE, CASE_LOG, normalize};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Printed when nothing outside the log records its length.
pub const NO_ANCHOR: &str = "truncation not detectable without a timestamp or case record";

/// What `verify-log` found.
#[derive(Clone, Debug, Default)]
pub struct LogVerification {
    pub path: PathBuf,
    /// Entries in the log (when the chain is intact).
    pub entries: u64,
    /// Anything here means exit 3 (broken chain, bad timestamp, truncation against a record).
    pub problems: Vec<String>,
    /// "timestamp <gen_time> by <tsa> covers entry #<seq>" for every timestamp.
    pub timestamps: Vec<String>,
    /// One line on truncation: what anchors the end of the log, or [`NO_ANCHOR`].
    pub truncation: String,
    pub warnings: Vec<String>,
}

fn read_entries(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// `<CASE>` and the run folder name when `log_dir` is `<CASE>/runs/<tool>/<RUN-ID>/logs`.
pub fn case_of_log_dir(log_dir: &Path) -> Option<PathBuf> {
    let abs = normalize(log_dir);
    if abs.file_name()? != "logs" {
        return None;
    }
    let runs = abs.parent()?.parent()?.parent()?;
    if runs.file_name()? != "runs" {
        return None;
    }
    let root = runs.parent()?;
    root.join(CASE_FILE).is_file().then(|| root.to_path_buf())
}

fn entries_count(n: u64) -> String {
    if n == 1 {
        "1 entry".into()
    } else {
        format!("{} entries", n)
    }
}

/// Verifies `path` (an audit.jsonl). Err only when the log cannot be opened. The TSA's CMS signature of
/// every timestamp token is checked; its certificate chain is not (see [`verify_log_with`]).
pub fn verify_log(path: &Path) -> Result<LogVerification, String> {
    verify_log_with(path, None)
}

/// Like [`verify_log`]; with `tsa_anchors` (a CA bundle, `--tsa-ca`) the TSA certificate chain of every
/// timestamp token is also validated up to one of them at the token's genTime (revocation is not checked).
pub fn verify_log_with(
    path: &Path,
    tsa_anchors: Option<&[x509_cert::Certificate]>,
) -> Result<LogVerification, String> {
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut v = LogVerification {
        path: path.to_path_buf(),
        ..Default::default()
    };
    match audit::verify(path) {
        Ok(n) => v.entries = n,
        Err(p) if p.len() == 1 && p[0].starts_with("cannot open") => return Err(p[0].clone()),
        Err(p) => {
            v.problems = p;
            return Ok(v);
        }
    }
    let entries = read_entries(path);
    let n = v.entries;
    let tokens = crate::trust::verify_timestamps_with(path, tsa_anchors);
    v.problems.extend(tokens.problems);

    // Anchors: (entry number, what vouches for it). The tokens are driven by the log's timestamp_obtained
    // entries (a recorded token whose .tsr or metadata is missing is a problem, never skipped); a covered entry
    // beyond the log's end is reported by verify_timestamps_with ("truncated: … which is not in the log").
    let mut anchors: Vec<(u64, String)> = tokens
        .covers
        .iter()
        .filter(|(seq, _)| *seq <= n)
        .map(|(seq, file)| {
            (
                *seq,
                format!("the RFC 3161 timestamp ({})", file.replace(".tsr", ".json")),
            )
        })
        .collect();
    // One line per token: with what its TSA signature and chain check established when every token verified.
    v.timestamps = if tokens.tokens.len() == tokens.listed.len() {
        tokens.tokens
    } else {
        tokens.listed
    };

    if let Some(case) = case_of_log_dir(&dir) {
        case_anchor(&case, &entries, n, &mut v, &mut anchors);
    }

    v.truncation = match anchors.iter().max_by_key(|(s, _)| *s) {
        None => NO_ANCHOR.to_string(),
        Some((s, by)) if *s == n => {
            format!("truncation: the final entry #{} is anchored by {}", n, by)
        }
        Some((s, by)) => {
            let later: Vec<&str> = entries
                .iter()
                .filter(|e| e["seq"].as_u64().unwrap_or(0) > *s)
                .map(|e| e["action"].as_str().unwrap_or("?"))
                .collect();
            format!(
                "truncation: entries up to #{} are anchored by {}; {} after it ({}) cannot be proven complete",
                s,
                by,
                entries_count(n - s),
                later.join(", ")
            )
        }
    };
    Ok(v)
}

/// Compares the end of the run's log with run_finished in the case log.
fn case_anchor(
    case: &Path,
    entries: &[Value],
    n: u64,
    v: &mut LogVerification,
    anchors: &mut Vec<(u64, String)>,
) {
    let case_log = case.join(CASE_LOG);
    if audit::verify(&case_log).is_err() {
        v.problems.push(format!(
            "{} is broken (run verify-case): it cannot vouch for this log's length",
            case_log.display()
        ));
        return;
    }
    let run_id = entries
        .first()
        .and_then(|e| e["run_id"].as_str())
        .unwrap_or_default()
        .to_string();
    let case_entries = read_entries(&case_log);
    let mine = |action: &str| {
        case_entries
            .iter()
            .find(|e| e["action"] == action && e["run_id"].as_str() == Some(run_id.as_str()))
    };
    let Some(fin) = mine("run_finished") else {
        v.warnings.push(if mine("run_started").is_some() {
            format!(
                "the case log has no run_finished for run {} (still running, or interrupted)",
                run_id
            )
        } else {
            format!("run {} is not announced in the case log", run_id)
        });
        return;
    };
    let recorded = fin["details"]["audit_entries"].as_u64().unwrap_or(0);
    if recorded == 0 {
        return;
    }
    if recorded > n {
        v.problems.push(format!(
            "truncated: the case log records {} entries at run_finished, but the log ends at entry #{}",
            recorded, n
        ));
        return;
    }
    let at = entries.iter().find(|e| e["seq"].as_u64() == Some(recorded));
    if at.and_then(|e| e["entry_hash"].as_str()) != fin["details"]["audit_head"].as_str() {
        v.problems.push(format!(
            "entry #{} is not the audit head recorded in the case log at run_finished",
            recorded
        ));
        return;
    }
    for later in entries
        .iter()
        .filter(|e| e["seq"].as_u64().unwrap_or(0) > recorded)
    {
        if later["action"] != "timestamp_obtained" {
            v.problems.push(format!(
                "entry #{} ({}) was appended after run_finished",
                later["seq"],
                later["action"].as_str().unwrap_or("?")
            ));
        }
    }
    anchors.push((recorded, "the case log (run_finished)".into()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn log(dir: &Path, n: usize) -> PathBuf {
        let mut l = audit::AuditLog::create(dir, "RUN-1", "t").unwrap();
        for i in 0..n {
            l.record("step", None, json!({"i": i})).unwrap();
        }
        dir.join("audit.jsonl")
    }

    fn drop_last(p: &Path) {
        let text = std::fs::read_to_string(p).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.pop();
        std::fs::write(p, format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn standalone_log_without_records_says_truncation_is_not_detectable() {
        let d = tempfile::tempdir().unwrap();
        let p = log(d.path(), 3);
        drop_last(&p);
        let v = verify_log(&p).unwrap();
        assert!(v.problems.is_empty());
        assert_eq!(v.entries, 2);
        assert_eq!(v.truncation, NO_ANCHOR);
        assert!(verify_log(&d.path().join("missing.jsonl")).is_err());
    }

    #[test]
    fn timestamp_covering_a_removed_entry_reports_truncation() {
        let d = tempfile::tempdir().unwrap();
        let p = log(d.path(), 4);
        let head = audit::heads(&p)[&3].clone();
        let meta = json!({"tsa": "test", "gen_time": "2026-01-01T00:00:00Z", "covers_seq": 3, "head": head,
                          "token_sha256": "", "file": "timestamp-00003.tsr"});
        std::fs::write(d.path().join("timestamp-00003.json"), meta.to_string()).unwrap();
        // The anchor itself (entry #3) is intact: only #4 is beyond it.
        let v = verify_log(&p).unwrap();
        assert!(
            v.truncation.contains("entries up to #3") && v.truncation.contains("1 entry after"),
            "{}",
            v.truncation
        );
        drop_last(&p);
        drop_last(&p);
        let v = verify_log(&p).unwrap();
        assert!(
            v.problems
                .iter()
                .any(|x| x.starts_with("truncated: timestamp-00003.tsr covers entry #3")),
            "{:?}",
            v.problems
        );
    }
}
