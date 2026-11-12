//! Source readers, one per Rakvor tool. Each turns a verified run's audited outputs into [`TimeEvent`]s.
//! Discovery and verification of runs live here too: [`discover_runs`] lists the case's runs and [`verify_run`]
//! checks the audit chain and marks excluded runs before any reader sees them.
//!
//! ```text
//! case.json + case-log.jsonl ──► discover_runs ──► RunRef × n (announced runs, then unannounced folders)
//! RunRef ──► verify_run:  run_dir safe & readable ─► audit chain (canonical JSON, prev/entry hash, seq)
//!                         ─► run_finished (audit, case log: completed) ─► case-log chain + audit head anchored
//!                         ─► reader exists / version supported ─► every recorded .json/.csv/.jsonl digest
//! verified RunRef ──► reader (only files the audit log lists, digest re-checked) ──► TimeEvent × n
//! ```
//!
//! Exclusion reasons: `unreadable`, `chain_broken`, `not_finished`, `unsupported_tool`, `unsupported_version`,
//! `digest_mismatch` (i18n `exclusion.<reason>`).

pub mod certcheck;
pub mod hashinv;
pub mod imgauth;
pub mod mailauth;
pub mod pdfauth;
pub mod rsmf;
pub mod timefmt;

use crate::audit::{GENESIS, entry_hash};
use crate::hash::{HashAlgo, hash_bytes};
use crate::model::{
    Exclusion, ItemRef, ReadError, RunRef, RunStatus, SourceReader, SourceRef, TimeEvent, ZoneInfo,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use timefmt::Parsed;

/// The case-folder schema this version reads.
pub const CASE_SCHEMA: &str = "rakvor.case/1";
/// Longest detail value kept in an event (characters).
pub const MAX_DETAIL: usize = 200;

/// What a reader got from one run: the events, and the times it could not parse (skipped, never invented).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadOutcome {
    pub events: Vec<TimeEvent>,
    /// Number of time values skipped because they did not parse.
    pub skipped: u64,
    /// One line per skipped value (`file pointer: "value"`), capped at [`MAX_WARNINGS`].
    pub warnings: Vec<String>,
}

pub const MAX_WARNINGS: usize = 100;

type ReadFn = fn(&Path, &RunRef) -> Result<ReadOutcome, ReadError>;

/// (tool, supported major.minor, reader function).
const TABLE: [(&str, (u64, u64), ReadFn); 6] = [
    ("rv-hashinv", (0, 4), hashinv::read),
    ("rv-pdfauth", (0, 4), pdfauth::read),
    ("rv-imgauth", (0, 3), imgauth::read),
    ("rv-rsmf", (0, 3), rsmf::read),
    ("rv-mailauth", (0, 2), mailauth::read),
    ("rv-certcheck", (0, 2), certcheck::read),
];

/// `major.minor` of a semver string (`0.4.1`, `0.4.1-rc.1`).
fn major_minor(v: &str) -> Option<(u64, u64)> {
    let mut it = v.trim().split(['.', '-', '+']);
    let ma = it.next()?.parse().ok()?;
    let mi = it.next()?.parse().ok()?;
    // A patch number is required: "0.4" alone is not a released version.
    it.next()?.parse::<u64>().ok()?;
    Some((ma, mi))
}

/// One reader of the built-in table.
pub struct TableReader {
    tool: &'static str,
    version: (u64, u64),
    read: ReadFn,
}

impl SourceReader for TableReader {
    fn tool(&self) -> &'static str {
        self.tool
    }
    fn supports(&self, tool_version: &str) -> bool {
        major_minor(tool_version) == Some(self.version)
    }
    fn read(&self, case_dir: &Path, run: &RunRef) -> Result<Vec<TimeEvent>, ReadError> {
        (self.read)(case_dir, run).map(|o| o.events)
    }
}

/// All readers built into this version.
pub fn all() -> Vec<Box<dyn SourceReader>> {
    TABLE
        .iter()
        .map(|(tool, version, read)| {
            Box::new(TableReader {
                tool,
                version: *version,
                read: *read,
            }) as Box<dyn SourceReader>
        })
        .collect()
}

/// `supports` ranges as text, for the reports (`rv-imgauth 0.3.x`).
pub fn supported_versions() -> Vec<(String, String)> {
    TABLE
        .iter()
        .map(|(t, (a, b), _)| (t.to_string(), format!("{a}.{b}.x")))
        .collect()
}

/// Like [`read_run`] with the skipped-time count and warnings (built-in readers only).
pub fn read_run_outcome(case_dir: &Path, run: &RunRef) -> Result<ReadOutcome, ReadError> {
    match TABLE.iter().find(|(t, _, _)| *t == run.tool) {
        Some((_, v, f)) if major_minor(&run.tool_version) == Some(*v) => f(case_dir, run),
        Some(_) => Err(err("unsupported_version", &run.tool_version)),
        None => Err(err("unsupported_tool", &run.tool)),
    }
}

pub(crate) fn err(reason: &str, detail: impl Into<String>) -> ReadError {
    ReadError {
        reason: reason.into(),
        detail: detail.into(),
    }
}

fn read_json_file(p: &Path) -> Result<Value, String> {
    let t = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    serde_json::from_str(&t).map_err(|e| format!("{}: not valid JSON ({e})", p.display()))
}

/// A run folder path from the case log, accepted only when it is relative, below `runs/` and free of `..`.
fn safe_run_dir(rel: &str) -> bool {
    let p = Path::new(rel);
    rel.starts_with("runs/")
        && !rel.contains('\\')
        && p.components().all(|c| matches!(c, Component::Normal(_)))
        && p.components().count() == 3
}

/// Entries of a JSON Lines file with their 1-based line numbers.
type Entries = Vec<(usize, Map<String, Value>)>;

/// JSON Lines with their 1-based line numbers. Blank lines are skipped; a line that is not a JSON object is an
/// error (the chain check would fail on it anyway).
fn read_jsonl(p: &Path) -> Result<(Entries, Vec<u8>), String> {
    let bytes = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| format!("{}: not UTF-8", p.display()))?;
    let mut out = Vec::new();
    for (i, l) in text.lines().enumerate() {
        if l.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(l) {
            Ok(Value::Object(m)) => out.push((i + 1, m)),
            _ => return Err(format!("line {} is not a JSON object", i + 1)),
        }
    }
    Ok((out, bytes))
}

/// Hash chain of an audit.jsonl or case-log.jsonl (the shared rule: `entry_hash` = SHA-256 of the canonical JSON
/// of the entry without `entry_hash`; `prev_entry_hash` = previous `entry_hash`, 64 zeros first; `seq` = 1, 2, …).
fn check_chain(entries: &[(usize, Map<String, Value>)]) -> Result<(), String> {
    let mut prev = GENESIS.to_string();
    for (n, (line, e)) in entries.iter().enumerate() {
        if e.get("seq").and_then(Value::as_u64) != Some(n as u64 + 1) {
            return Err(format!("line {line}: seq is not {}", n + 1));
        }
        if e.get("prev_entry_hash").and_then(Value::as_str) != Some(prev.as_str()) {
            return Err(format!(
                "line {line}: prev_entry_hash does not match the entry before"
            ));
        }
        let h = e
            .get("entry_hash")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if entry_hash(e) != h {
            return Err(format!(
                "line {line}: entry_hash does not match its content"
            ));
        }
        prev = h.to_string();
    }
    Ok(())
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

/// Lists every run recorded in the case folder: runs announced by `run_started` in case-log.jsonl (in log
/// order), then run folders under runs/<tool>/<run>/ the log does not announce. Status is still unchecked
/// (`Verified` until [`verify_run`] says otherwise). Err when the folder is not a `rakvor.case/1` case folder.
pub fn discover_runs(case_dir: &Path) -> Result<Vec<RunRef>, ReadError> {
    let case = read_json_file(&case_dir.join("case.json")).map_err(|e| err("unreadable", e))?;
    if case["schema"] != CASE_SCHEMA {
        return Err(err(
            "unreadable",
            format!("case.json: schema {} is not {CASE_SCHEMA}", case["schema"]),
        ));
    }
    let mut runs: Vec<RunRef> = Vec::new();
    if let Ok((log, _)) = read_jsonl(&case_dir.join("case-log.jsonl")) {
        for (_, e) in &log {
            if e.get("action").and_then(Value::as_str) != Some("run_started") {
                continue;
            }
            let d = &e["details"];
            let run_dir = s(&d["run_dir"]).to_string();
            if runs.iter().any(|r| r.run_dir == run_dir) {
                continue;
            }
            runs.push(RunRef {
                tool: s(&d["tool"]).to_string(),
                tool_version: s(&d["version"]).to_string(),
                run_id: e
                    .get("run_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                run_dir,
                ..Default::default()
            });
        }
    }
    let mut extra = Vec::new();
    for t in std::fs::read_dir(case_dir.join("runs"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if !t.path().is_dir() {
            continue;
        }
        let tool = t.file_name().to_string_lossy().into_owned();
        for r in std::fs::read_dir(t.path()).into_iter().flatten().flatten() {
            if !r.path().is_dir() {
                continue;
            }
            let run_id = r.file_name().to_string_lossy().into_owned();
            let run_dir = format!("runs/{tool}/{run_id}");
            if runs.iter().any(|x| x.run_dir == run_dir) {
                continue;
            }
            let version = read_jsonl(&r.path().join("logs/audit.jsonl"))
                .ok()
                .and_then(|(l, _)| {
                    l.into_iter()
                        .find(|(_, e)| {
                            e.get("action").and_then(Value::as_str) == Some("run_started")
                        })
                        .map(|(_, e)| s(&e["details"]["version"]).to_string())
                })
                .unwrap_or_default();
            extra.push(RunRef {
                tool: tool.clone(),
                tool_version: version,
                run_id,
                run_dir,
                ..Default::default()
            });
        }
    }
    extra.sort_by(|a, b| a.run_dir.cmp(&b.run_dir));
    runs.extend(extra);
    Ok(runs)
}

fn exclude(mut run: RunRef, e: ReadError) -> RunRef {
    run.status = RunStatus::Excluded;
    run.events = 0;
    run.exclusion = Some(Exclusion {
        reason: e.reason,
        detail: e.detail,
    });
    run
}

/// Verifies one run (finished, audit chain intact, outputs' digests as logged); excluded runs get their reason.
pub fn verify_run(case_dir: &Path, run: RunRef) -> RunRef {
    match check_run(case_dir, &run) {
        Ok(()) => RunRef {
            status: RunStatus::Verified,
            exclusion: None,
            ..run
        },
        Err(e) => exclude(run, e),
    }
}

fn check_run(case_dir: &Path, run: &RunRef) -> Result<(), ReadError> {
    let data = RunData::load(case_dir, run)?;
    // Finished, in the run's own audit log.
    let fin = data
        .audit
        .iter()
        .rev()
        .find(|(_, e)| e.get("action").and_then(Value::as_str) == Some("run_finished"))
        .ok_or_else(|| err("not_finished", "logs/audit.jsonl has no run_finished entry"))?;
    if fin.1["details"]["cancelled"] == Value::Bool(true) {
        return Err(err("not_finished", "the run was cancelled"));
    }
    // The case log: intact, announces the run as completed, and holds the run's final audit head.
    let (log, _) = read_jsonl(&case_dir.join("case-log.jsonl"))
        .map_err(|e| err("unreadable", format!("case-log.jsonl: {e}")))?;
    check_chain(&log).map_err(|e| err("chain_broken", format!("case-log.jsonl {e}")))?;
    let announced = log.iter().any(|(_, e)| {
        e.get("action").and_then(Value::as_str) == Some("run_started")
            && s(&e["details"]["run_dir"]) == run.run_dir
    });
    if !announced {
        return Err(err(
            "not_finished",
            "the case log does not announce this run folder (run_started missing)",
        ));
    }
    let finished = log
        .iter()
        .rev()
        .find(|(_, e)| {
            e.get("action").and_then(Value::as_str) == Some("run_finished")
                && s(&e["details"]["run_dir"]) == run.run_dir
        })
        .ok_or_else(|| {
            err(
                "not_finished",
                "the case log has no run_finished for this run",
            )
        })?;
    let d = &finished.1["details"];
    let exit_failed = d["exit_code"].as_i64().is_some_and(|c| c != 0);
    if s(&d["status"]) != "completed" || exit_failed {
        return Err(err(
            "not_finished",
            format!("case log status: {}", d["status"].as_str().unwrap_or("?")),
        ));
    }
    let n = d["audit_entries"].as_u64().unwrap_or(0) as usize;
    let head = s(&d["audit_head"]);
    match data.audit.get(n.wrapping_sub(1)) {
        Some((_, e)) if n > 0 && e.get("entry_hash").and_then(Value::as_str) == Some(head) => {}
        _ => {
            return Err(err(
                "chain_broken",
                format!(
                    "the audit head recorded in the case log is not entry #{n} of logs/audit.jsonl"
                ),
            ));
        }
    }
    if let Some((line, e)) = data.audit[n..].iter().find(|(_, e)| {
        !e.get("action")
            .and_then(Value::as_str)
            .is_some_and(|a| a.starts_with("timestamp_"))
    }) {
        return Err(err(
            "chain_broken",
            format!(
                "logs/audit.jsonl line {line}: {} after the recorded end of the run",
                s(&e["action"])
            ),
        ));
    }
    // A reader for this tool and version.
    match TABLE.iter().find(|(t, _, _)| *t == run.tool) {
        None => return Err(err("unsupported_tool", &run.tool)),
        Some((_, v, _)) if major_minor(&run.tool_version) != Some(*v) => {
            return Err(err("unsupported_version", &run.tool_version));
        }
        _ => {}
    }
    // The version announced in the case log is the one the run recorded.
    let started = data
        .audit
        .iter()
        .find(|(_, e)| e.get("action").and_then(Value::as_str) == Some("run_started"));
    if let Some((_, e)) = started
        && s(&e["details"]["version"]) != run.tool_version
    {
        return Err(err(
            "unsupported_version",
            format!(
                "case log says {}, the run's audit log says {}",
                run.tool_version,
                s(&e["details"]["version"])
            ),
        ));
    }
    // Every machine-readable output (the files readers read) still has its recorded digest.
    for rel in data.digests.keys() {
        if [".json", ".csv", ".jsonl"].iter().any(|x| rel.ends_with(x)) {
            data.check_file(rel)?;
        }
    }
    Ok(())
}

/// An evidence item of a run, from its audit log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunItem {
    pub index: u64,
    pub path: String,
    pub evidence_id: String,
    pub sha256: String,
    /// (line, value) of `item_started.details.modified_utc`.
    pub modified: Option<(usize, String)>,
    /// `evidence_verified_against_case.match == false`.
    pub case_mismatch: bool,
}

/// A run loaded for reading: its audit entries, the digests the audit log recorded per output file, its items.
pub struct RunData {
    pub run: RunRef,
    pub dir: PathBuf,
    pub audit: Vec<(usize, Map<String, Value>)>,
    pub audit_sha256: String,
    /// Output path relative to the run folder → {algorithm: hex}.
    pub digests: BTreeMap<String, BTreeMap<String, String>>,
    pub items: BTreeMap<u64, RunItem>,
    /// Output path → the `item` its `output_written` entry names (e.g. `<mbox>#2@1372` for a derived message).
    pub output_items: BTreeMap<String, String>,
}

fn digest_map(v: &Value) -> BTreeMap<String, String> {
    let o = v
        .get("hashes")
        .or_else(|| v.get("digest"))
        .filter(|x| x.is_object())
        .unwrap_or(v);
    o.as_object()
        .map(|m| {
            m.iter()
                .filter(|(k, _)| HashAlgo::parse(k).is_some())
                .filter_map(|(k, x)| x.as_str().map(|h| (k.clone(), h.to_ascii_lowercase())))
                .collect()
        })
        .unwrap_or_default()
}

/// The output files an audit entry records, with their digests (paths relative to the run folder).
fn recorded_outputs(e: &Map<String, Value>) -> Vec<(String, BTreeMap<String, String>)> {
    let d = e.get("details").cloned().unwrap_or(Value::Null);
    let item = e.get("item").and_then(Value::as_str).unwrap_or_default();
    let mut out = Vec::new();
    let mut files = |base: &str, files: &Value| {
        for (name, h) in files.as_object().into_iter().flatten() {
            out.push((format!("{base}{name}"), digest_map(h)));
        }
    };
    match e.get("action").and_then(Value::as_str).unwrap_or_default() {
        "item_reports_written" => files(&format!("reports/{}/", s(&d["folder"])), &d["files"]),
        "statistics_report_written" => files("reports/", &d["files"]),
        "output_written" if !s(&d["file"]).is_empty() => {
            out.push((format!("reports/{}", s(&d["file"])), digest_map(&d)))
        }
        "environment_recorded" => out.push(("logs/environment.json".into(), digest_map(&d))),
        "hash_register_written" => out.push(("logs/hashes.csv".into(), digest_map(&d))),
        "trace_written" | "rsmf_written" if !item.is_empty() => {
            out.push((format!("rsmf/{item}"), digest_map(&d)))
        }
        _ => {}
    }
    out.retain(|(p, h)| !h.is_empty() && !p.split('/').any(|c| c == ".." || c.is_empty()));
    out
}

impl RunData {
    /// Reads the run's audit log and checks its chain (`unreadable`, `chain_broken`).
    pub fn load(case_dir: &Path, run: &RunRef) -> Result<RunData, ReadError> {
        if !safe_run_dir(&run.run_dir) {
            return Err(err(
                "unreadable",
                format!("run folder {:?} is not runs/<tool>/<run>", run.run_dir),
            ));
        }
        let dir = case_dir.join(&run.run_dir);
        let (audit, bytes) = read_jsonl(&dir.join("logs/audit.jsonl")).map_err(|e| {
            if dir.join("logs/audit.jsonl").is_file() {
                err("chain_broken", format!("logs/audit.jsonl {e}"))
            } else {
                err("unreadable", e)
            }
        })?;
        if audit.is_empty() {
            return Err(err("unreadable", "logs/audit.jsonl is empty"));
        }
        check_chain(&audit).map_err(|e| err("chain_broken", format!("logs/audit.jsonl {e}")))?;
        let mut digests = BTreeMap::new();
        let mut items: BTreeMap<u64, RunItem> = BTreeMap::new();
        let mut output_items = BTreeMap::new();
        for (line, e) in &audit {
            for (p, h) in recorded_outputs(e) {
                if let Some(i) = e.get("item").and_then(Value::as_str)
                    && e.get("action").and_then(Value::as_str) == Some("output_written")
                {
                    output_items.insert(p.clone(), i.to_string());
                }
                digests.insert(p, h);
            }
            let d = &e["details"];
            let Some(index) = d["index"].as_u64() else {
                continue;
            };
            let item = e.get("item").and_then(Value::as_str).unwrap_or_default();
            match e.get("action").and_then(Value::as_str).unwrap_or_default() {
                "item_started" => {
                    let it = items.entry(index).or_default();
                    it.index = index;
                    it.path = item.to_string();
                    if let Some(m) = d["modified_utc"].as_str() {
                        it.modified = Some((*line, m.to_string()));
                    }
                }
                "item_hashed" => {
                    let it = items.entry(index).or_default();
                    it.index = index;
                    if it.path.is_empty() {
                        it.path = item.to_string();
                    }
                    it.sha256 = s(&d["hashes"]["sha256"]).to_string();
                }
                "evidence_registered" | "evidence_verified_against_case" => {
                    let it = items.entry(index).or_default();
                    it.evidence_id = s(&d["evidence_id"]).to_string();
                    if d["match"] == Value::Bool(false) {
                        it.case_mismatch = true;
                    }
                }
                _ => {}
            }
        }
        Ok(RunData {
            run: run.clone(),
            dir,
            audit,
            audit_sha256: hash_bytes(&bytes, HashAlgo::Sha256),
            digests,
            items,
            output_items,
        })
    }

    /// Checks one recorded output against the audit log; returns its bytes and SHA-256 (`unreadable` when it is
    /// missing or was never recorded, `digest_mismatch` when it changed).
    pub fn check_file(&self, rel: &str) -> Result<(Vec<u8>, String), ReadError> {
        let rec = self.digests.get(rel).ok_or_else(|| {
            err(
                "unreadable",
                format!("{rel}: not recorded in logs/audit.jsonl"),
            )
        })?;
        let bytes = std::fs::read(self.dir.join(rel))
            .map_err(|e| err("unreadable", format!("{rel}: {e}")))?;
        let mut checked = false;
        for (algo, want) in rec {
            if let Some(a) = HashAlgo::parse(algo) {
                if hash_bytes(&bytes, a) != *want {
                    return Err(err(
                        "digest_mismatch",
                        format!("{rel}: {algo} differs from logs/audit.jsonl"),
                    ));
                }
                checked = true;
            }
        }
        if !checked {
            return Err(err(
                "unreadable",
                format!("{rel}: no usable digest recorded"),
            ));
        }
        let sha = rec
            .get("sha256")
            .cloned()
            .unwrap_or_else(|| hash_bytes(&bytes, HashAlgo::Sha256));
        Ok((bytes, sha))
    }

    /// A recorded JSON output, digest checked. `Ok(None)` when the run did not record that file.
    pub fn json(&self, rel: &str) -> Result<Option<(Value, String)>, ReadError> {
        if !self.digests.contains_key(rel) {
            return Ok(None);
        }
        let (bytes, sha) = self.check_file(rel)?;
        let v = serde_json::from_slice(&bytes)
            .map_err(|e| err("unreadable", format!("{rel}: not valid JSON ({e})")))?;
        Ok(Some((v, sha)))
    }

    /// Recorded outputs whose path ends with `suffix`, in path order.
    pub fn outputs_ending(&self, suffix: &str) -> Vec<String> {
        self.digests
            .keys()
            .filter(|k| k.ends_with(suffix))
            .cloned()
            .collect()
    }

    /// The item an item folder (`reports/items/00003-x.jpg/…`) belongs to, by its 5-digit index prefix.
    pub fn item_of_folder(&self, rel: &str) -> Option<&RunItem> {
        let folder = rel.strip_prefix("reports/items/")?.split('/').next()?;
        let idx: u64 = folder.get(..5)?.parse().ok()?;
        self.items.get(&idx)
    }

    pub fn source(&self, file: &str, file_sha256: &str, pointer: String) -> SourceRef {
        SourceRef {
            tool: self.run.tool.clone(),
            tool_version: self.run.tool_version.clone(),
            run_id: self.run.run_id.clone(),
            run_dir: self.run.run_dir.clone(),
            file: file.to_string(),
            file_sha256: file_sha256.to_string(),
            pointer,
        }
    }
}

impl RunItem {
    pub fn item_ref(&self, sub: &str) -> ItemRef {
        ItemRef {
            evidence_id: self.evidence_id.clone(),
            path: self.path.clone(),
            sub: sub.to_string(),
            sha256: self.sha256.clone(),
        }
    }
}

/// Escapes one JSON-pointer token (RFC 6901).
pub fn ptr(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn cap(v: &str) -> String {
    if v.chars().count() <= MAX_DETAIL {
        v.to_string()
    } else {
        let mut s: String = v.chars().take(MAX_DETAIL - 1).collect();
        s.push('…');
        s
    }
}

/// Collects a run's events with stable ids (`<tool>:<run_id>:<item>:<kind>:<n>`; item = evidence id, else `i<index>`,
/// else `run`, followed by `#n` or `/<sub>` for a sub-item; n counted per item and kind in reading order) and
/// counts the values that did not parse.
pub struct Emitter<'a> {
    pub data: &'a RunData,
    counters: BTreeMap<(String, String), u32>,
    pub out: ReadOutcome,
}

/// One time value found in an output, before parsing.
pub struct Found<'a> {
    pub item: ItemRef,
    pub kind: &'a str,
    pub original: String,
    pub file: &'a str,
    pub file_sha256: &'a str,
    pub pointer: String,
    pub details: Vec<(&'a str, String)>,
}

impl<'a> Emitter<'a> {
    pub fn new(data: &'a RunData) -> Self {
        Emitter {
            data,
            counters: BTreeMap::new(),
            out: ReadOutcome::default(),
        }
    }

    /// Adds the event when `parsed` is Some; otherwise counts a skipped value with a warning.
    pub fn push(&mut self, f: Found<'_>, parsed: Option<Parsed>) {
        let Some(p) = parsed else {
            self.out.skipped += 1;
            if self.out.warnings.len() < MAX_WARNINGS {
                self.out.warnings.push(format!(
                    "{} {}: {:?} is not a time this reader understands ({})",
                    f.file,
                    f.pointer,
                    cap(&f.original),
                    f.kind
                ));
            }
            return;
        };
        let sub = match f.item.sub.as_str() {
            "" => String::new(),
            x if x.starts_with('#') => x.to_string(),
            x => format!("/{x}"),
        };
        let key = if !f.item.evidence_id.is_empty() {
            format!("{}{sub}", f.item.evidence_id)
        } else if f.item.path.is_empty() {
            "run".to_string()
        } else {
            let idx = self
                .data
                .items
                .values()
                .find(|i| i.path == f.item.path || f.item.path.starts_with(&format!("{}#", i.path)))
                .map(|i| i.index)
                .unwrap_or(0);
            format!("i{idx}{sub}")
        };
        let n = self
            .counters
            .entry((key.clone(), f.kind.to_string()))
            .or_insert(0);
        *n += 1;
        let id = format!(
            "{}:{}:{}:{}:{}",
            self.data.run.tool, self.data.run.run_id, key, f.kind, n
        );
        let mut details: BTreeMap<String, String> = f
            .details
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.to_string(), cap(&v)))
            .collect();
        if p.zone == ZoneInfo::Unknown {
            details.insert("zone".into(), "unknown".into());
        }
        self.out.events.push(TimeEvent {
            id,
            utc_s: p.utc_s,
            utc_ns: p.utc_ns,
            zone: p.zone,
            offset_min: p.offset_min,
            precision: p.precision,
            original: f.original,
            kind: f.kind.to_string(),
            item: f.item,
            source: self.data.source(f.file, f.file_sha256, f.pointer),
            details,
        });
    }

    /// `run.started` / `run.finished` from the audit log (entry `ts_utc`), `run.timestamped` for each RFC 3161
    /// token over the log (`genTime`), and `fs.modified` for each item (`item_started.modified_utc`).
    pub fn audit_events(&mut self) {
        let data = self.data;
        let file = "logs/audit.jsonl";
        for (line, e) in &data.audit {
            let action = e.get("action").and_then(Value::as_str).unwrap_or_default();
            let (kind, value, pointer) = match action {
                "run_started" => ("run.started", s(&e["ts_utc"]), "ts_utc"),
                "run_finished" => ("run.finished", s(&e["ts_utc"]), "ts_utc"),
                "timestamp_obtained" => (
                    "run.timestamped",
                    s(&e["details"]["gen_time"]),
                    "details/gen_time",
                ),
                _ => continue,
            };
            let mut details = vec![("actor", s(&e["actor"]).to_string())];
            if action == "timestamp_obtained" {
                details.push(("tsa", s(&e["details"]["tsa"]).to_string()));
                details.push(("covers_seq", e["details"]["covers_seq"].to_string()));
            }
            let f = Found {
                item: ItemRef::default(),
                kind,
                original: value.to_string(),
                file,
                file_sha256: &data.audit_sha256,
                pointer: format!("line:{line}/{pointer}"),
                details,
            };
            self.push(f, timefmt::rfc3339(value));
        }
        for it in data.items.values() {
            if let Some((line, m)) = &it.modified {
                let f = Found {
                    item: it.item_ref(""),
                    kind: "fs.modified",
                    original: m.clone(),
                    file,
                    file_sha256: &data.audit_sha256,
                    pointer: format!("line:{line}/details/modified_utc"),
                    details: vec![],
                };
                self.push(f, timefmt::rfc3339(m));
            }
        }
    }

    pub fn finish(mut self) -> ReadOutcome {
        self.out
            .events
            .sort_by(|a, b| (a.utc_s, a.utc_ns, &a.id).cmp(&(b.utc_s, b.utc_ns, &b.id)));
        self.out
    }
}

/// Convenience used by the engine: the reader for `tool`, if any.
pub fn reader_for<'a>(
    readers: &'a [Box<dyn SourceReader>],
    tool: &str,
) -> Option<&'a dyn SourceReader> {
    readers
        .iter()
        .find(|r| r.tool() == tool)
        .map(|r| r.as_ref())
}

/// Reads one verified run with the matching reader.
pub fn read_run(
    readers: &[Box<dyn SourceReader>],
    case_dir: &Path,
    run: &RunRef,
) -> Result<Vec<TimeEvent>, ReadError> {
    match reader_for(readers, &run.tool) {
        Some(r) if r.supports(&run.tool_version) => r.read(case_dir, run),
        Some(_) => Err(ReadError {
            reason: "unsupported_version".into(),
            detail: run.tool_version.clone(),
        }),
        None => Err(ReadError {
            reason: "unsupported_tool".into(),
            detail: run.tool.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        let r = all();
        let img = reader_for(&r, "rv-imgauth").unwrap();
        assert!(img.supports("0.3.0") && img.supports("0.3.1") && img.supports("0.3.12-rc.1"));
        assert!(
            !img.supports("0.4.0")
                && !img.supports("0.2.9")
                && !img.supports("0.3")
                && !img.supports("")
        );
        assert_eq!(r.len(), 6);
        assert!(reader_for(&r, "rv-timeline").is_none());
    }

    #[test]
    fn run_dirs_must_stay_in_runs() {
        assert!(safe_run_dir("runs/rv-imgauth/20261110T100000Z-ab12cd"));
        for bad in [
            "runs/../x/y",
            "/runs/a/b",
            "runs/a",
            "runs/a/b/c",
            "C:/runs/a/b",
            "runs\\a\\b",
            "logs/a/b",
        ] {
            assert!(!safe_run_dir(bad), "{bad}");
        }
    }
}
