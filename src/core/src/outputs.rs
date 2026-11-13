//! Recorded outputs: re-hashes every file a run's audit log says the run wrote, so a report, register or
//! export edited, deleted or replaced after the run is caught by `verify-log` and `verify-case` (the audit
//! chain alone only proves the *recorded digests* are unchanged, not the files they describe).
//!
//! Shared by every Rakvor tool, byte-identical (like `trust.rs`); it depends only on `crate::hash` (itself
//! identical in every tool) and `serde_json`. Callers pass the entries of an audit log whose chain they have
//! already verified.
//!
//! ```text
//! audit.jsonl entries ──► recorded files (run-relative path → {algorithm: hex}; the latest entry wins)
//!   ──► safe path? (relative, `/`, no `..`, root, drive, `\` or `:`)           no ─► rejected, not read
//!   ──► area folder (logs | reports | rsmf) of this run's layout ──► canonical path inside the run?
//!                                                                             no ─► rejected, not read
//!   ──► exists? ─► regular file? ─► re-hash with every recorded algorithm ─► verified | mismatched
//! ```
//!
//! Run layouts (the log folder decides):
//!
//! * case run: `<CASE>/runs/<tool>/<RUN-ID>/{logs,reports,rsmf}`: every file must resolve inside `<RUN-ID>`;
//! * standalone run: `<OUT>/logs/<RUN-ID>`, `<OUT>/reports/<RUN-ID>`, `<OUT>/rsmf/<RUN-ID>`: every file must
//!   resolve inside its own area folder;
//! * any other log folder: only `logs/` files are checked; the others are skipped with the reason.
//!
//! Audit shapes understood (paths are written here run-relative, `<area>/<path>`):
//!
//! | action | where the path is | digests | tools |
//! | --- | --- | --- | --- |
//! | `environment_recorded` | `logs/<item>` (default `environment.json`) | `details` = {alg: hex} | all; rv-hub session logs |
//! | `hash_register_written` | `logs/<item>` (default `hashes.csv`) | `details` = {alg: hex} (+ `rows`, ignored) | all |
//! | `item_reports_written` | `reports/<details.folder>/<name>` for every `details.files` key | {alg: hex} per file | all |
//! | `statistics_report_written` | `reports/<name>` for every `details.files` key | {alg: hex} per file | all |
//! | `output_written` with `details.file` | `reports/<details.file>` | `details.hashes`, `details.digest` or `details.sha256` | rv-pdfauth, rv-imgauth, rv-mailauth, rv-certcheck |
//! | `timeline_written` | `<details.folder>/<name>` (folder is run-relative, e.g. `reports`) | {alg: hex} per file | rv-timeline |
//! | `report_written` | `reports/<item>` | `details` = {alg: hex} | rv-certcheck creation runs |
//! | `rsmf_written`, `trace_written` | `rsmf/<item>` | `details.hashes` (+ `details.sha256`) or `details` | rv-rsmf |
//!
//! Recorded but not re-hashed here (listed in [`OutputsCheck::skipped`] with the reason):
//!
//! * `timestamp_obtained`: the `.tsr` token is checked by the timestamp verification (`trust.rs`);
//! * `output_written` without `details.file` (rv-mailauth `keys import`) and `file_written` (rv-certcheck creation
//!   runs): the file was written outside the run folder, at a path the operator chose;
//! * the audit log itself (`audit.jsonl`, `audit.log`, `review.jsonl`): `audit.jsonl` and `review.jsonl` are
//!   verified by their hash chains; `audit.log` is a human-readable copy that nothing vouches for;
//! * a file recorded by an entry after `run_finished` (only `timestamp_obtained` may follow it);
//! * an entry of a known action that records no usable digest.
//!
//! Any other action whose name ends in `_written` is counted in [`OutputsCheck::unrecognised`] and ignored
//! (e.g. rv-certcheck `lab_set_written`, which names a folder outside the run). Entries that record no file
//! (`output_missing`, `item_hashed`, review-log entries, …) are not outputs and are not counted.
//! Algorithms: every name `crate::hash::HashAlgo::parse` knows (md5, sha1, sha256, sha512, sha3-256, blake3);
//! other keys are ignored.

use crate::hash::{HashAlgo, hash_reader};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

/// The folders of one run that audit entries name files in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunLayout {
    pub logs: PathBuf,
    pub reports: Option<PathBuf>,
    pub rsmf: Option<PathBuf>,
    /// The run folder (`<CASE>/runs/<tool>/<RUN-ID>`) when the run is in a case; `None` for a standalone run
    /// (each area folder is then its own containment root).
    pub run_dir: Option<PathBuf>,
}

impl RunLayout {
    /// The layout of the run whose audit log is in `log_dir` (see the module documentation).
    pub fn of_log_dir(log_dir: &Path) -> RunLayout {
        let logs = if log_dir.as_os_str().is_empty() {
            std::env::current_dir().unwrap_or_default()
        } else {
            std::path::absolute(log_dir).unwrap_or_else(|_| log_dir.to_path_buf())
        };
        let name = logs.file_name().map(|n| n.to_string_lossy().into_owned());
        let parent = logs.parent().map(Path::to_path_buf);
        if name.as_deref() == Some("logs")
            && let Some(run) = parent
        {
            return RunLayout {
                reports: Some(run.join("reports")),
                rsmf: Some(run.join("rsmf")),
                run_dir: Some(run),
                logs,
            };
        }
        if let (Some(id), Some(p)) = (name, parent)
            && p.file_name().is_some_and(|n| n == "logs")
            && let Some(out) = p.parent()
        {
            return RunLayout {
                reports: Some(out.join("reports").join(&id)),
                rsmf: Some(out.join("rsmf").join(&id)),
                run_dir: None,
                logs,
            };
        }
        RunLayout {
            logs,
            ..Default::default()
        }
    }

    fn area(&self, name: &str) -> Option<&Path> {
        match name {
            "logs" => Some(&self.logs),
            "reports" => self.reports.as_deref(),
            "rsmf" => self.rsmf.as_deref(),
            _ => None,
        }
    }
}

/// Why a recorded file is a problem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProblemKind {
    /// The file is gone.
    Missing,
    /// A digest differs from the one recorded.
    Mismatch,
    /// The recorded path is not a safe relative path, or it resolves outside the run (symlink, junction): not read.
    Rejected,
    /// The path exists but is not a readable regular file (e.g. replaced by a folder).
    Unreadable,
}

/// One recorded output that does not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputProblem {
    /// Run-relative path as recorded (`reports/items/00003-x/technical.json`).
    pub file: String,
    pub kind: ProblemKind,
    /// Audit entry that recorded the file last.
    pub seq: u64,
    /// For a mismatch: the algorithm, the recorded and the current digest.
    pub algorithm: String,
    pub expected: String,
    pub actual: String,
    pub detail: String,
}

impl std::fmt::Display for OutputProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ProblemKind::Mismatch => write!(
                f,
                "output {}: {} differs from audit entry #{} (recorded {}, now {}): edited or replaced after the run",
                self.file, self.algorithm, self.seq, self.expected, self.actual
            ),
            ProblemKind::Missing => write!(
                f,
                "output {}: missing (recorded by audit entry #{}): deleted or moved after the run",
                self.file, self.seq
            ),
            ProblemKind::Rejected => write!(
                f,
                "output {}: {} (audit entry #{}), not read",
                self.file, self.detail, self.seq
            ),
            ProblemKind::Unreadable => write!(
                f,
                "output {}: {} (audit entry #{})",
                self.file, self.detail, self.seq
            ),
        }
    }
}

/// A recorded file that was not re-hashed, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub file: String,
    pub seq: u64,
    pub reason: String,
}

/// What [`verify_recorded_outputs`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputsCheck {
    /// Distinct files the audit log records (the latest entry for a path wins), skipped ones included.
    pub recorded: usize,
    /// Re-hashed and equal to every recorded digest.
    pub verified: usize,
    pub missing: usize,
    pub mismatched: usize,
    /// Unsafe paths and paths resolving outside the run (never read) plus unreadable ones.
    pub rejected: usize,
    pub skipped: Vec<Skipped>,
    /// `#<seq> <action>` of `*_written` entries whose shape this module does not know (ignored).
    pub unrecognised: Vec<String>,
    /// Algorithms actually re-computed (names as in the audit log).
    pub algorithms: BTreeSet<String>,
    /// Anything here means the run's outputs no longer match its audit log (exit 3).
    pub problems: Vec<OutputProblem>,
}

impl OutputsCheck {
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty()
    }

    /// One line: `outputs: 37 verified of 37 recorded (sha256, md5)`, then what was skipped or not recognised.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "outputs: {} verified of {} recorded",
            self.verified, self.recorded
        );
        if !self.algorithms.is_empty() {
            s.push_str(&format!(
                " ({})",
                self.algorithms
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for (n, what) in [
            (self.missing, "missing"),
            (self.mismatched, "changed"),
            (self.rejected, "rejected"),
            (self.skipped.len(), "skipped"),
        ] {
            if n > 0 {
                s.push_str(&format!(", {} {}", n, what));
            }
        }
        if !self.unrecognised.is_empty() {
            s.push_str(&format!(
                ", {} unrecognised entr{} ignored",
                self.unrecognised.len(),
                if self.unrecognised.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            ));
        }
        s
    }

    /// `<file>: <reason>` for every skipped file.
    pub fn skipped_lines(&self) -> Vec<String> {
        self.skipped
            .iter()
            .map(|s| format!("not re-hashed: {} ({})", s.file, s.reason))
            .collect()
    }
}

/// A recorded file as one entry states it.
enum Rec {
    /// Run-relative path and digests {algorithm: lowercase hex}.
    Check(String, BTreeMap<String, String>),
    Skip(String, String),
}

/// Re-hashes every output recorded in `audit` (the entries of `<log_dir>/audit.jsonl`, chain already verified).
pub fn verify_recorded_outputs(log_dir: &Path, audit: &[Value]) -> OutputsCheck {
    verify_with_layout(&RunLayout::of_log_dir(log_dir), audit)
}

/// Like [`verify_recorded_outputs`], with the run's folders given explicitly.
pub fn verify_with_layout(layout: &RunLayout, audit: &[Value]) -> OutputsCheck {
    let mut c = OutputsCheck::default();
    // Path → (seq of the latest entry, what it records).
    let mut latest: BTreeMap<String, (u64, Rec)> = BTreeMap::new();
    let mut finished = false;
    for e in audit {
        let seq = e["seq"].as_u64().unwrap_or(0);
        let action = e["action"].as_str().unwrap_or_default();
        let Some(recs) = recorded_files(e) else {
            if action.ends_with("_written") {
                c.unrecognised.push(format!("#{} {}", seq, action));
            }
            if action == "run_finished" {
                finished = true;
            }
            continue;
        };
        for r in recs {
            let r = match r {
                Rec::Check(p, _) if finished => Rec::Skip(
                    p,
                    "recorded after run_finished, outside the run's anchored log".into(),
                ),
                r => r,
            };
            let path = match &r {
                Rec::Check(p, _) | Rec::Skip(p, _) => p.clone(),
            };
            latest.insert(path, (seq, r));
        }
    }
    c.recorded = latest.len();
    let mut roots: BTreeMap<String, Option<PathBuf>> = BTreeMap::new();
    for (file, (seq, rec)) in latest {
        let digests = match rec {
            Rec::Skip(_, reason) => {
                c.skipped.push(Skipped { file, seq, reason });
                continue;
            }
            Rec::Check(_, d) => d,
        };
        let problem = |kind, detail: String| OutputProblem {
            file: file.clone(),
            kind,
            seq,
            algorithm: String::new(),
            expected: String::new(),
            actual: String::new(),
            detail,
        };
        if !safe_rel(&file) {
            c.rejected += 1;
            c.problems.push(problem(
                ProblemKind::Rejected,
                "not a relative path inside the run folder".into(),
            ));
            continue;
        }
        let (area, rest) = file.split_once('/').unwrap_or((file.as_str(), ""));
        let Some(area_dir) = layout.area(area) else {
            c.skipped.push(Skipped {
                file: file.clone(),
                seq,
                reason: format!(
                    "the {}/ folder of this run is not known from its log folder",
                    area
                ),
            });
            continue;
        };
        if rest.is_empty() {
            c.rejected += 1;
            c.problems.push(problem(
                ProblemKind::Rejected,
                "names a run folder, not a file".into(),
            ));
            continue;
        }
        let root = roots
            .entry(area.to_string())
            .or_insert_with(|| {
                std::fs::canonicalize(layout.run_dir.as_deref().unwrap_or(area_dir)).ok()
            })
            .clone();
        let real = match std::fs::canonicalize(area_dir.join(rest)) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                c.missing += 1;
                c.problems
                    .push(problem(ProblemKind::Missing, String::new()));
                continue;
            }
            Err(e) => {
                c.rejected += 1;
                c.problems.push(problem(
                    ProblemKind::Unreadable,
                    format!("cannot open: {e}"),
                ));
                continue;
            }
        };
        if !root.as_ref().is_some_and(|r| real.starts_with(r)) {
            c.rejected += 1;
            c.problems.push(problem(
                ProblemKind::Rejected,
                "resolves outside the run folder (symlink or junction)".into(),
            ));
            continue;
        }
        if !real.is_file() {
            c.rejected += 1;
            c.problems.push(problem(
                ProblemKind::Unreadable,
                "is no longer a regular file (replaced after the run)".into(),
            ));
            continue;
        }
        let algos: Vec<(HashAlgo, &String)> = digests
            .iter()
            .filter_map(|(k, v)| HashAlgo::parse(k).map(|a| (a, v)))
            .collect();
        match rehash(&real, &algos) {
            Err(e) => {
                c.rejected += 1;
                c.problems.push(problem(
                    ProblemKind::Unreadable,
                    format!("cannot read: {e}"),
                ));
            }
            Ok(found) => {
                let bad = algos
                    .iter()
                    .zip(&found)
                    .find(|((_, want), got)| want != got);
                for (a, _) in &algos {
                    c.algorithms.insert(a.name().to_string());
                }
                match bad {
                    None => c.verified += 1,
                    Some(((a, want), got)) => {
                        c.mismatched += 1;
                        c.problems.push(OutputProblem {
                            algorithm: a.name().to_string(),
                            expected: want.to_string(),
                            actual: got.clone(),
                            ..problem(ProblemKind::Mismatch, String::new())
                        });
                    }
                }
            }
        }
    }
    c
}

/// Digests of `path` for `algos`, in order (at most two per read pass).
fn rehash(path: &Path, algos: &[(HashAlgo, &String)]) -> std::io::Result<Vec<String>> {
    let mut out = Vec::new();
    for pair in algos.chunks(2) {
        let sel: Vec<HashAlgo> = pair.iter().map(|(a, _)| *a).collect();
        let f = std::fs::File::open(path)?;
        let o =
            hash_reader(f, &sel, |_| true)?.ok_or_else(|| std::io::Error::other("cancelled"))?;
        out.extend(o.digests.into_iter().map(|(_, h)| h));
    }
    Ok(out)
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

/// {algorithm: lowercase hex} from `details.hashes`, `details.digest` or the object itself (unknown keys dropped).
fn digest_map(v: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for o in [v.get("hashes"), v.get("digest"), Some(v)]
        .into_iter()
        .flatten()
    {
        for (k, x) in o.as_object().into_iter().flatten() {
            if let Some(a) = HashAlgo::parse(k)
                && let Some(h) = x.as_str()
                && !h.is_empty()
            {
                out.entry(a.name().to_string())
                    .or_insert_with(|| h.to_ascii_lowercase());
            }
        }
    }
    out
}

/// The files one entry records, or None when its action records no output this module knows.
fn recorded_files(e: &Value) -> Option<Vec<Rec>> {
    let d = &e["details"];
    let item = text(&e["item"]);
    let or = |s: &str, default: &str| {
        if s.is_empty() {
            default.to_string()
        } else {
            s.to_string()
        }
    };
    let one = |path: String, v: &Value| {
        let h = digest_map(v);
        if h.is_empty() {
            Rec::Skip(path, "the entry records no usable digest".into())
        } else if matches!(
            path.as_str(),
            "logs/audit.jsonl" | "logs/audit.log" | "logs/review.jsonl"
        ) {
            Rec::Skip(path, "the audit log is verified by its hash chain".into())
        } else {
            Rec::Check(path, h)
        }
    };
    let files = |base: String, files: &Value| -> Vec<Rec> {
        files
            .as_object()
            .into_iter()
            .flatten()
            .map(|(name, h)| one(format!("{}/{}", base, name), h))
            .collect()
    };
    let outside = |what: &str| {
        Rec::Skip(
            or(what, "(unnamed file)"),
            "written outside the run folder, at a path the operator chose".into(),
        )
    };
    Some(match text(&e["action"]) {
        "environment_recorded" => vec![one(format!("logs/{}", or(item, "environment.json")), d)],
        "hash_register_written" => vec![one(format!("logs/{}", or(item, "hashes.csv")), d)],
        "item_reports_written" => files(format!("reports/{}", text(&d["folder"])), &d["files"]),
        "statistics_report_written" => files("reports".into(), &d["files"]),
        "timeline_written" => files(or(text(&d["folder"]), "reports"), &d["files"]),
        "output_written" if !text(&d["file"]).is_empty() => {
            vec![one(format!("reports/{}", text(&d["file"])), d)]
        }
        "output_written" => vec![outside(item)],
        "file_written" => vec![outside(&or(text(&d["path"]), item))],
        "report_written" if !item.is_empty() => vec![one(format!("reports/{}", item), d)],
        "rsmf_written" | "trace_written" if !item.is_empty() => {
            vec![one(format!("rsmf/{}", item), d)]
        }
        "timestamp_obtained" => vec![Rec::Skip(
            format!("logs/{}", or(item, text(&d["file"]))),
            "RFC 3161 token: checked by the timestamp verification".into(),
        )],
        _ => return None,
    })
}

/// A recorded path, accepted only when it is relative, uses forward slashes, has no `..`, `.`, root, drive or
/// empty component, and no `\` or `:` (drive letters, UNC paths, NTFS alternate streams).
pub fn safe_rel(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.contains(['\\', ':'])
        && rel
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
        && Path::new(rel)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_bytes;
    use serde_json::json;

    fn sha(b: &[u8]) -> String {
        hash_bytes(b, HashAlgo::Sha256)
    }

    /// A case-style run folder with one item report, statistics and a hash register.
    fn run() -> (tempfile::TempDir, PathBuf, Vec<Value>) {
        let d = tempfile::tempdir().unwrap();
        let run = d.path().join("RUN");
        for (p, b) in [
            ("logs/hashes.csv", "h"),
            ("reports/statistics.json", "s"),
            ("reports/items/00001-a/technical.json", "t"),
        ] {
            let f = run.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, b).unwrap();
        }
        let md5 = hash_bytes(b"t", HashAlgo::Md5);
        let audit = vec![
            json!({"seq": 1, "action": "run_started", "details": {}}),
            json!({"seq": 2, "action": "hash_register_written", "item": "hashes.csv",
                   "details": {"sha256": sha(b"h"), "rows": 1}}),
            json!({"seq": 3, "action": "item_reports_written", "item": "/ev/a",
                   "details": {"folder": "items/00001-a", "files": {"technical.json": {"sha256": sha(b"t"), "md5": md5}}}}),
            json!({"seq": 4, "action": "statistics_report_written",
                   "details": {"files": {"statistics.json": {"sha256": sha(b"s")}}}}),
            json!({"seq": 5, "action": "run_finished", "details": {}}),
        ];
        (d, run, audit)
    }

    #[test]
    fn a_clean_run_verifies_every_recorded_output() {
        let (_d, run, audit) = run();
        let c = verify_recorded_outputs(&run.join("logs"), &audit);
        assert!(c.is_clean(), "{:?}", c.problems);
        assert_eq!((c.recorded, c.verified), (3, 3));
        assert_eq!(
            c.algorithms.iter().cloned().collect::<Vec<_>>(),
            ["md5", "sha256"]
        );
        assert_eq!(
            c.summary(),
            "outputs: 3 verified of 3 recorded (md5, sha256)"
        );
    }

    #[test]
    fn edited_deleted_and_replaced_outputs_are_problems() {
        let (_d, run, audit) = run();
        std::fs::write(run.join("reports/items/00001-a/technical.json"), "T").unwrap();
        std::fs::remove_file(run.join("reports/statistics.json")).unwrap();
        std::fs::remove_file(run.join("logs/hashes.csv")).unwrap();
        std::fs::create_dir(run.join("logs/hashes.csv")).unwrap();
        let c = verify_recorded_outputs(&run.join("logs"), &audit);
        assert_eq!(
            (c.verified, c.mismatched, c.missing, c.rejected),
            (0, 1, 1, 1)
        );
        let lines: Vec<String> = c.problems.iter().map(|p| p.to_string()).collect();
        assert!(
            lines.iter().any(|l| l.starts_with(
                "output reports/items/00001-a/technical.json: md5 differs from audit entry #3"
            )),
            "{lines:?}"
        );
        assert!(lines.contains(&"output reports/statistics.json: missing (recorded by audit entry #4): deleted or moved after the run".to_string()));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("logs/hashes.csv: is no longer a regular file"))
        );
    }

    #[test]
    fn the_latest_entry_for_a_file_wins() {
        let (_d, run, mut audit) = run();
        std::fs::write(run.join("reports/statistics.json"), "s2").unwrap();
        audit.insert(
            4,
            json!({"seq": 5, "action": "statistics_report_written",
                   "details": {"files": {"statistics.json": {"sha256": sha(b"s2")}}}}),
        );
        let c = verify_recorded_outputs(&run.join("logs"), &audit);
        assert!(c.is_clean(), "{:?}", c.problems);
        assert_eq!(c.verified, 3);
    }

    #[test]
    fn path_escapes_are_rejected_and_not_read() {
        let (d, run, mut audit) = run();
        std::fs::write(d.path().join("outside.json"), "o").unwrap();
        for (i, bad) in ["../outside.json", "..\\outside.json", "C:/x.json", "a/./b"]
            .iter()
            .enumerate()
        {
            audit.insert(
                1,
                json!({"seq": 10 + i, "action": "output_written", "item": "/ev/a",
                       "details": {"file": bad, "hashes": {"sha256": sha(b"o")}}}),
            );
        }
        audit.insert(
            1,
            json!({"seq": 20, "action": "item_reports_written",
                   "details": {"folder": "../..", "files": {"outside.json": {"sha256": sha(b"o")}}}}),
        );
        let c = verify_recorded_outputs(&run.join("logs"), &audit);
        assert_eq!(c.rejected, 5, "{:?}", c.problems);
        assert_eq!(c.verified, 3);
        assert!(
            c.problems
                .iter()
                .all(|p| p.kind == ProblemKind::Rejected && p.to_string().ends_with(", not read"))
        );
        for bad in ["", "/etc/x", "reports//x", "reports/x:ads", "\\\\srv\\s"] {
            assert!(!safe_rel(bad), "{bad}");
        }
        assert!(safe_rel("reports/items/00001-a/technical.json"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_leading_out_of_the_run_is_rejected() {
        let (d, run, audit) = run();
        let p = run.join("reports/statistics.json");
        std::fs::remove_file(&p).unwrap();
        std::fs::write(d.path().join("s"), "s").unwrap();
        std::os::unix::fs::symlink(d.path().join("s"), &p).unwrap();
        let c = verify_recorded_outputs(&run.join("logs"), &audit);
        assert_eq!(c.rejected, 1);
        assert!(
            c.problems[0]
                .to_string()
                .contains("resolves outside the run folder")
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_leading_out_of_the_run_is_rejected() {
        let (d, run, audit) = run();
        let items = run.join("reports").join("items");
        let outside = d.path().join("elsewhere");
        std::fs::create_dir_all(outside.join("00001-a")).unwrap();
        std::fs::write(outside.join("00001-a/technical.json"), "t").unwrap();
        std::fs::remove_dir_all(&items).unwrap();
        let made = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&items)
            .arg(&outside)
            .output()
            .is_ok_and(|o| o.status.success());
        if !made {
            eprintln!("skipping: mklink /J is not available");
            return;
        }
        let c = verify_recorded_outputs(&run.join("logs"), &audit);
        assert_eq!((c.rejected, c.verified), (1, 2), "{:?}", c.problems);
        assert!(
            c.problems[0]
                .to_string()
                .contains("resolves outside the run folder")
        );
    }

    #[test]
    fn unknown_shapes_are_counted_and_known_exceptions_skipped_with_a_reason() {
        let (_d, run, mut audit) = run();
        audit.insert(
            1,
            json!({"seq": 30, "action": "lab_set_written", "item": "/x", "details": {"set": "a"}}),
        );
        audit.insert(
            1,
            json!({"seq": 31, "action": "output_written", "item": "C:/keys.txt",
                                "details": {"kind": "dkim_key_file", "sha256": "00"}}),
        );
        audit.insert(
            1,
            json!({"seq": 32, "action": "environment_recorded", "item": "environment.json",
                                "details": {"note": "no digest"}}),
        );
        audit.push(
            json!({"seq": 6, "action": "timestamp_obtained", "item": "timestamp-00005.tsr",
                          "details": {"token_sha256": "00"}}),
        );
        audit.push(
            json!({"seq": 7, "action": "hash_register_written", "item": "late.csv",
                          "details": {"sha256": "00"}}),
        );
        let c = verify_recorded_outputs(&run.join("logs"), &audit);
        assert!(c.is_clean(), "{:?}", c.problems);
        assert_eq!(c.unrecognised, ["#30 lab_set_written"]);
        assert_eq!(c.skipped.len(), 4, "{:?}", c.skipped);
        assert_eq!((c.recorded, c.verified), (7, 3));
        assert!(
            c.summary()
                .ends_with(", 4 skipped, 1 unrecognised entry ignored")
        );
        let reasons = c.skipped_lines().join("\n");
        for r in [
            "outside the run folder",
            "no usable digest",
            "timestamp verification",
            "after run_finished",
        ] {
            assert!(reasons.contains(r), "{r}: {reasons}");
        }
    }

    #[test]
    fn standalone_layout_and_other_tools_shapes() {
        let d = tempfile::tempdir().unwrap();
        let out = d.path();
        let id = "20260101T000000Z-abc";
        for (p, b) in [
            (format!("logs/{id}/environment.json"), "e"),
            (format!("reports/{id}/items/00001-a/x.json"), "x"),
            (format!("reports/{id}/timeline.jsonl"), "l"),
            (format!("reports/{id}/report.json"), "r"),
            (format!("rsmf/{id}/c/day.rsmf"), "z"),
        ] {
            let f = out.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, b).unwrap();
        }
        let audit = vec![
            json!({"seq": 1, "action": "environment_recorded", "item": "environment.json", "details": {"SHA256": sha(b"e").to_uppercase()}}),
            json!({"seq": 2, "action": "output_written", "details": {"file": "items/00001-a/x.json", "digest": {"sha256": sha(b"x")}}}),
            json!({"seq": 3, "action": "timeline_written", "details": {"folder": "reports", "files": {"timeline.jsonl": {"blake3": hash_bytes(b"l", HashAlgo::Blake3)}}}}),
            json!({"seq": 4, "action": "report_written", "item": "report.json", "details": {"sha256": sha(b"r")}}),
            json!({"seq": 5, "action": "rsmf_written", "item": "c/day.rsmf", "details": {"hashes": {"md5": hash_bytes(b"z", HashAlgo::Md5), "sha1": hash_bytes(b"z", HashAlgo::Sha1)}, "sha256": sha(b"z")}}),
        ];
        let layout = RunLayout::of_log_dir(&out.join("logs").join(id));
        assert_eq!(
            layout.reports.as_deref(),
            Some(out.join("reports").join(id).as_path())
        );
        let c = verify_with_layout(&layout, &audit);
        assert!(c.is_clean(), "{:?}", c.problems);
        assert_eq!(c.verified, 5);
        assert_eq!(c.algorithms.len(), 4, "{:?}", c.algorithms);
        // An unknown log-folder layout: only logs/ is checked.
        let c = verify_recorded_outputs(&out.join("logs").join(id).join("x"), &audit[1..2]);
        assert_eq!(c.skipped.len(), 1);
    }
}
