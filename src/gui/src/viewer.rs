//! A finished timeline build as the window shows it, read back ONLY from the run's audited outputs:
//!
//! ```text
//! <run>/logs/audit.jsonl (chain verified, run_finished present)
//!   ├─ statistics_report_written → statistics.json digests ──► runs table, skipped runs, signals
//!   └─ timeline_written          → timeline.jsonl digests  ──► one streaming pass: digest check + line index
//! <run>/reports/statistics.json  ── digest == audit digest? ── no ──► refused (nothing shown)
//! <run>/reports/timeline.jsonl   ── digest == audit digest? ── no ──► refused (nothing shown)
//! index (offset, length, line hash, time, tool, item, kind, zone flag, signal severity) ──► filters
//! visible rows only ──► seek + read one line ──► line hash == indexed hash? ──► TimeEvent (small cache)
//! ```
//!
//! The index holds a few dozen bytes per event, so a timeline of millions of events is never parsed into memory
//! at once: the list asks for the rows it draws. No drawing code here: everything is unit-tested headless.

use rv_timeline_core::model::{
    ItemRef, Precision, RunRef, Severity, Signal, SourceRef, TimeEvent, ZoneInfo,
};
use rv_timeline_core::{HashAlgo, audit, hash};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

/// Rows kept parsed at most (the visible page and a little scroll-back).
pub const CACHE_ROWS: usize = 2_048;

/// A file the build wrote, as its audit log records it.
#[derive(Clone, Debug, PartialEq)]
pub struct AuditedFile {
    /// Relative to the run's report folder (`timeline.jsonl`, `statistics.json`).
    pub file: String,
    /// algorithm name -> hex digest
    pub hashes: BTreeMap<String, String>,
}

/// A run the build did not read (its own runs, the tools filter, the event limit).
#[derive(Clone, Debug, PartialEq)]
pub struct SkippedRow {
    pub tool: String,
    pub version: String,
    pub run_id: String,
    pub run_dir: String,
    /// `self` | `tool_filter` | `max_events`
    pub reason: String,
}

/// What the viewer keeps per event: where its line is, how to recognise it, and the filter keys.
#[derive(Clone, Debug, PartialEq)]
struct IndexEntry {
    offset: u64,
    len: u32,
    line_hash: u64,
    utc_s: i64,
    tool: u16,
    item: u32,
    kind: u16,
    /// Highest severity among the signals that name this event.
    severity: Option<Severity>,
}

/// Viewer filters; `None` = no filter on that key.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Filters {
    pub tool: Option<String>,
    /// Item key (`E0001`, or `path:<path>` for an item outside the registry).
    pub item: Option<String>,
    pub kind: Option<String>,
    /// Events named by a signal of at least this severity.
    pub severity: Option<Severity>,
    /// Inclusive UTC window, seconds since the epoch.
    pub from_s: Option<i64>,
    pub to_s: Option<i64>,
}

/// The timeline build read back from its audited outputs.
#[derive(Debug)]
pub struct TimelineView {
    pub run_id: String,
    pub run_dir: PathBuf,
    pub report_dir: PathBuf,
    pub log_dir: PathBuf,
    /// The build's display zone (`America/Bogota`, `UTC-05:00`…).
    pub display_zone: String,
    pub runs: Vec<RunRef>,
    pub skipped: Vec<SkippedRow>,
    pub signals: Vec<Signal>,
    /// For each signal, the rows (event indices) it names that are in timeline.jsonl.
    pub signal_rows: Vec<Vec<u32>>,
    /// Distinct tools, item keys (with a label) and kinds, sorted; the filter choices.
    pub tools: Vec<String>,
    pub items: Vec<(String, String)>,
    pub kinds: Vec<String>,
    pub max_events_reached: bool,
    /// Whether the build wrote timeline.jsonl (Timesketch output on).
    pub has_timeline_file: bool,
    /// (file, sha256) of the outputs shown, as checked against the audit log.
    pub files: Vec<(String, String)>,
    index: Vec<IndexEntry>,
    timeline_path: PathBuf,
    cache: HashMap<u32, TimeEvent>,
    /// Lines parsed after the index was built (for the "never everything at once" test).
    lines_parsed: u64,
}

fn read_audit(path: &Path) -> Result<Vec<Value>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| format!("{}: {}", path.display(), e)))
        .collect()
}

fn audited(file: &str, digests: &Value) -> AuditedFile {
    AuditedFile {
        file: file.to_string(),
        hashes: serde_json::from_value(digests.clone()).unwrap_or_default(),
    }
}

fn algorithms(f: &AuditedFile) -> Vec<(HashAlgo, String)> {
    f.hashes
        .iter()
        .filter_map(|(a, h)| HashAlgo::parse(a).map(|a| (a, h.to_ascii_lowercase())))
        .collect()
}

fn safe_join(dir: &Path, rel: &str) -> Result<PathBuf, String> {
    let p = Path::new(rel);
    if rel.is_empty() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(format!("{}: not a path inside the report folder", rel));
    }
    Ok(dir.join(p))
}

fn line_hash(bytes: &[u8]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// Rebuilds the event from its Timesketch line (`rakvor_*` fields; `timestamp` is in microseconds).
pub fn event_from_line(v: &Value) -> Result<TimeEvent, String> {
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    let ts = v["timestamp"]
        .as_i64()
        .ok_or_else(|| "line without a timestamp".to_string())?;
    let id = s("rakvor_event_id");
    if id.is_empty() {
        return Err("line without rakvor_event_id".into());
    }
    let precision: Precision =
        serde_json::from_value(v["rakvor_precision"].clone()).unwrap_or_default();
    let details = v
        .as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, x)| {
                    k.strip_prefix("rakvor_detail_")
                        .map(|d| (d.to_string(), x.as_str().unwrap_or_default().to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(TimeEvent {
        id,
        utc_s: ts.div_euclid(1_000_000),
        utc_ns: (ts.rem_euclid(1_000_000) * 1_000) as u32,
        zone: if v["rakvor_zone"] == "unknown" {
            ZoneInfo::Unknown
        } else {
            ZoneInfo::Explicit
        },
        offset_min: v["rakvor_offset_min"].as_i64().map(|m| m as i32),
        precision,
        original: s("rakvor_original"),
        kind: s("rakvor_kind"),
        item: ItemRef {
            evidence_id: s("rakvor_evidence_id"),
            path: s("rakvor_item_path"),
            sub: s("rakvor_item_sub"),
            sha256: s("rakvor_item_sha256"),
        },
        source: SourceRef {
            tool: s("rakvor_tool"),
            tool_version: s("rakvor_tool_version"),
            run_id: s("rakvor_run"),
            run_dir: s("rakvor_run_dir"),
            file: s("rakvor_file"),
            file_sha256: s("rakvor_file_sha256"),
            pointer: s("rakvor_pointer"),
        },
        details,
    })
}

/// `E0001 photo.jpg`, or the path for an item outside the registry.
fn item_label(evidence_id: &str, path: &str) -> String {
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());
    if evidence_id.is_empty() {
        name
    } else {
        format!("{} {}", evidence_id, name)
    }
}

fn item_key(evidence_id: &str, path: &str) -> String {
    if evidence_id.is_empty() {
        format!("path:{}", path)
    } else {
        evidence_id.to_string()
    }
}

/// Interns strings into small ids (tool, item, kind).
#[derive(Default)]
struct Interner {
    ids: HashMap<String, u32>,
    names: Vec<String>,
}

impl Interner {
    fn get(&mut self, s: &str) -> u32 {
        if let Some(i) = self.ids.get(s) {
            return *i;
        }
        let i = self.names.len() as u32;
        self.ids.insert(s.to_string(), i);
        self.names.push(s.to_string());
        i
    }
}

/// Builds the index while the digests are computed: every byte hashed is the byte indexed (one read).
struct Indexing<'a, R> {
    inner: R,
    offset: u64,
    line_start: u64,
    line: Vec<u8>,
    entries: Vec<IndexEntry>,
    tools: Interner,
    items: Interner,
    item_labels: HashMap<u32, String>,
    kinds: Interner,
    wanted: &'a HashSet<String>,
    found: HashMap<String, u32>,
    error: Option<String>,
}

impl<R: Read> Indexing<'_, R> {
    fn finish_line(&mut self) {
        let raw = std::mem::take(&mut self.line);
        let start = self.line_start;
        self.line_start = self.offset;
        let body: &[u8] = raw.strip_suffix(b"\n").unwrap_or(&raw);
        let body = body.strip_suffix(b"\r").unwrap_or(body);
        if body.iter().all(|b| b.is_ascii_whitespace()) || self.error.is_some() {
            return;
        }
        let n = self.entries.len() + 1;
        let v: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(format!("timeline.jsonl line {}: not valid JSON ({})", n, e));
                return;
            }
        };
        let (Some(ts), Some(id)) = (v["timestamp"].as_i64(), v["rakvor_event_id"].as_str()) else {
            self.error = Some(format!(
                "timeline.jsonl line {}: no timestamp or rakvor_event_id",
                n
            ));
            return;
        };
        let s = |k: &str| v[k].as_str().unwrap_or_default();
        let index = self.entries.len() as u32;
        if self.wanted.contains(id) {
            self.found.insert(id.to_string(), index);
        }
        let item = self
            .items
            .get(&item_key(s("rakvor_evidence_id"), s("rakvor_item_path")));
        self.item_labels
            .entry(item)
            .or_insert_with(|| item_label(s("rakvor_evidence_id"), s("rakvor_item_path")));
        self.entries.push(IndexEntry {
            offset: start,
            len: body.len() as u32,
            line_hash: line_hash(body),
            utc_s: ts.div_euclid(1_000_000),
            tool: self.tools.get(s("rakvor_tool")) as u16,
            item,
            kind: self.kinds.get(s("rakvor_kind")) as u16,
            severity: None,
        });
    }
}

impl<R: Read> Read for Indexing<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        let mut rest = &buf[..n];
        while let Some(p) = rest.iter().position(|&b| b == b'\n') {
            self.line.extend_from_slice(&rest[..=p]);
            self.offset += (p + 1) as u64;
            self.finish_line();
            rest = &rest[p + 1..];
        }
        self.line.extend_from_slice(rest);
        self.offset += rest.len() as u64;
        Ok(n)
    }
}

impl TimelineView {
    /// Reads the build in `run_dir` (`<CASE>/runs/rv-timeline/<RUN-ID>`). Refused when the audit chain does not
    /// verify, the run did not finish, or statistics.json / timeline.jsonl differ from their audited digests.
    pub fn load(run_dir: &Path) -> Result<TimelineView, String> {
        let log_dir = run_dir.join("logs");
        let report_dir = run_dir.join("reports");
        let audit_path = log_dir.join("audit.jsonl");
        audit::verify(&audit_path)
            .map_err(|p| format!("{} does not verify: {}", audit_path.display(), p.join("; ")))?;
        let entries = read_audit(&audit_path)?;
        let run_id = entries
            .first()
            .and_then(|e| e["run_id"].as_str())
            .unwrap_or_default()
            .to_string();
        let (mut stats, mut timeline, mut finished) = (None, None, false);
        for e in &entries {
            let d = &e["details"];
            match e["action"].as_str().unwrap_or_default() {
                "statistics_report_written" => {
                    stats = Some(audited("statistics.json", &d["files"]["statistics.json"]))
                }
                "timeline_written" => {
                    timeline = Some(audited("timeline.jsonl", &d["files"]["timeline.jsonl"]))
                }
                "run_finished" => finished = true,
                _ => {}
            }
        }
        if !finished {
            return Err(format!(
                "{}: the run has not finished (no run_finished)",
                audit_path.display()
            ));
        }
        let stats =
            stats.ok_or_else(|| "statistics.json is not recorded in the audit log".to_string())?;
        let stats_bytes = read_audited(&report_dir, &stats)?;
        let sv: Value =
            serde_json::from_slice(&stats_bytes).map_err(|e| format!("statistics.json: {}", e))?;
        let t = &sv["timeline"];
        if !t.is_object() {
            return Err("statistics.json: not a timeline build".into());
        }
        let runs: Vec<RunRef> = serde_json::from_value(t["runs"].clone())
            .map_err(|e| format!("statistics.json runs: {}", e))?;
        let signals: Vec<Signal> = serde_json::from_value(t["signals"].clone())
            .map_err(|e| format!("statistics.json signals: {}", e))?;
        let skipped = t["skipped"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|s| SkippedRow {
                        tool: s["tool"].as_str().unwrap_or_default().into(),
                        version: s["version"].as_str().unwrap_or_default().into(),
                        run_id: s["run_id"].as_str().unwrap_or_default().into(),
                        run_dir: s["run_dir"].as_str().unwrap_or_default().into(),
                        reason: s["reason"].as_str().unwrap_or_default().into(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut files = vec![(
            stats.file.clone(),
            hash::hash_bytes(&stats_bytes, HashAlgo::Sha256),
        )];
        let wanted: HashSet<String> = signals.iter().flat_map(|s| s.events.clone()).collect();
        let timeline_path = report_dir.join("timeline.jsonl");
        let mut view = TimelineView {
            run_id,
            run_dir: run_dir.to_path_buf(),
            report_dir: report_dir.clone(),
            log_dir,
            display_zone: t["display_zone"].as_str().unwrap_or("UTC").to_string(),
            runs,
            skipped,
            signal_rows: vec![Vec::new(); signals.len()],
            signals,
            tools: vec![],
            items: vec![],
            kinds: vec![],
            max_events_reached: t["max_events_reached"].as_bool().unwrap_or(false),
            has_timeline_file: timeline.is_some(),
            files: vec![],
            index: vec![],
            timeline_path: timeline_path.clone(),
            cache: HashMap::new(),
            lines_parsed: 0,
        };
        if let Some(tf) = timeline {
            let algos = algorithms(&tf);
            if algos.is_empty() {
                return Err("timeline.jsonl: no digest recorded in the audit log".into());
            }
            let path = safe_join(&report_dir, &tf.file)?;
            let f = std::fs::File::open(&path)
                .map_err(|e| format!("timeline.jsonl: cannot read ({})", e))?;
            let mut ix = Indexing {
                inner: std::io::BufReader::with_capacity(1 << 20, f),
                offset: 0,
                line_start: 0,
                line: Vec::new(),
                entries: Vec::new(),
                tools: Interner::default(),
                items: Interner::default(),
                item_labels: HashMap::new(),
                kinds: Interner::default(),
                wanted: &wanted,
                found: HashMap::new(),
                error: None,
            };
            let names: Vec<HashAlgo> = algos.iter().map(|(a, _)| *a).collect();
            let out = hash::hash_reader(&mut ix, &names, |_| true)
                .map_err(|e| format!("timeline.jsonl: cannot read ({})", e))?
                .ok_or_else(|| "timeline.jsonl: reading stopped".to_string())?;
            for (a, want) in &algos {
                let got = out
                    .digests
                    .iter()
                    .find(|(x, _)| x == a)
                    .map(|(_, h)| h.to_ascii_lowercase())
                    .unwrap_or_default();
                if &got != want {
                    return Err(format!(
                        "timeline.jsonl: {} does not match the digest recorded in the audit log (changed after the run)",
                        a.name()
                    ));
                }
            }
            if !ix.line.is_empty() {
                ix.finish_line();
            }
            if let Some(e) = ix.error {
                return Err(e);
            }
            let sha = out
                .digests
                .iter()
                .find(|(a, _)| *a == HashAlgo::Sha256)
                .map(|(_, h)| h.clone())
                .unwrap_or_else(|| {
                    format!(
                        "{}:{}",
                        out.digests[0].0.name(),
                        out.digests[0].1.to_ascii_lowercase()
                    )
                });
            files.push((tf.file.clone(), sha));
            // Highest signal severity per event, and each signal's rows.
            for (n, s) in view.signals.iter().enumerate() {
                for id in &s.events {
                    if let Some(&row) = ix.found.get(id) {
                        view.signal_rows[n].push(row);
                        let e = &mut ix.entries[row as usize];
                        e.severity = e.severity.max(Some(s.severity));
                    }
                }
                view.signal_rows[n].sort_unstable();
            }
            view.tools = ix.tools.names;
            view.kinds = ix.kinds.names;
            view.items = ix
                .items
                .names
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    (
                        k.clone(),
                        ix.item_labels.get(&(i as u32)).cloned().unwrap_or_default(),
                    )
                })
                .collect();
            view.index = ix.entries;
        }
        view.files = files;
        Ok(view)
    }

    /// Events in timeline.jsonl.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Events parsed for display since the view was loaded.
    pub fn lines_parsed(&self) -> u64 {
        self.lines_parsed
    }

    /// Parsed rows held in memory now.
    pub fn cached_rows(&self) -> usize {
        self.cache.len()
    }

    /// UTC seconds of row `i` (from the index, no read).
    pub fn utc_s(&self, i: u32) -> Option<i64> {
        self.index.get(i as usize).map(|e| e.utc_s)
    }

    /// Highest severity of the signals naming row `i`.
    pub fn severity(&self, i: u32) -> Option<Severity> {
        self.index.get(i as usize).and_then(|e| e.severity)
    }

    /// Rows matching the filters, in timeline order.
    pub fn filter(&self, f: &Filters) -> Vec<u32> {
        let find = |names: &[String], want: &Option<String>| -> Result<Option<usize>, ()> {
            match want {
                None => Ok(None),
                Some(w) => names.iter().position(|n| n == w).map(Some).ok_or(()),
            }
        };
        let item_names: Vec<String> = self.items.iter().map(|(k, _)| k.clone()).collect();
        let (Ok(tool), Ok(item), Ok(kind)) = (
            find(&self.tools, &f.tool),
            find(&item_names, &f.item),
            find(&self.kinds, &f.kind),
        ) else {
            return vec![];
        };
        self.index
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                tool.is_none_or(|t| e.tool as usize == t)
                    && item.is_none_or(|t| e.item as usize == t)
                    && kind.is_none_or(|t| e.kind as usize == t)
                    && f.severity
                        .is_none_or(|s| e.severity.is_some_and(|x| x >= s))
                    && f.from_s.is_none_or(|s| e.utc_s >= s)
                    && f.to_s.is_none_or(|s| e.utc_s <= s)
            })
            .map(|(i, _)| i as u32)
            .collect()
    }

    /// Row `i`, read from timeline.jsonl on demand. Refused when the line differs from the line checked at load
    /// (the file changed while the window was open).
    pub fn row(&mut self, i: u32) -> Result<TimeEvent, String> {
        if let Some(e) = self.cache.get(&i) {
            return Ok(e.clone());
        }
        let ix = self
            .index
            .get(i as usize)
            .ok_or_else(|| format!("no event at row {}", i))?
            .clone();
        let mut f = std::fs::File::open(&self.timeline_path)
            .map_err(|e| format!("timeline.jsonl: cannot read ({})", e))?;
        f.seek(SeekFrom::Start(ix.offset))
            .map_err(|e| format!("timeline.jsonl: {}", e))?;
        let mut buf = vec![0u8; ix.len as usize];
        f.read_exact(&mut buf)
            .map_err(|e| format!("timeline.jsonl: {}", e))?;
        if line_hash(&buf) != ix.line_hash {
            return Err(format!(
                "timeline.jsonl line {}: changed after it was checked against the audit log",
                i + 1
            ));
        }
        let v: Value = serde_json::from_slice(&buf)
            .map_err(|e| format!("timeline.jsonl line {}: {}", i + 1, e))?;
        let ev = event_from_line(&v)?;
        self.lines_parsed += 1;
        if self.cache.len() >= CACHE_ROWS {
            self.cache.clear();
        }
        self.cache.insert(i, ev.clone());
        Ok(ev)
    }
}

/// Reads one audited output and checks it against every digest the audit log recorded for it.
pub fn read_audited(report_dir: &Path, f: &AuditedFile) -> Result<Vec<u8>, String> {
    let path = safe_join(report_dir, &f.file)?;
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: cannot read ({})", f.file, e))?;
    let algos = algorithms(f);
    if algos.is_empty() {
        return Err(format!("{}: no digest recorded in the audit log", f.file));
    }
    for (a, want) in algos {
        if hash::hash_bytes(&bytes, a).to_ascii_lowercase() != want {
            return Err(format!(
                "{}: {} does not match the digest recorded in the audit log (changed after the run)",
                f.file,
                a.name()
            ));
        }
    }
    Ok(bytes)
}

/// The most recent finished timeline build of a case (`<CASE>/runs/rv-timeline/<RUN-ID>`), if any.
pub fn latest_timeline_run(case_dir: &Path) -> Option<PathBuf> {
    let dir = case_dir.join("runs").join(rv_timeline_core::TOOL_NAME);
    let mut runs: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("logs").join("audit.jsonl").is_file())
        .collect();
    runs.sort();
    runs.pop()
}

/// `2026-11-10`, `2026-11-10 10:00`, `2026-11-10T10:00:00Z` or `2026-11-10T11:00:00+01:00` to UTC seconds;
/// empty = no bound. A date alone is the start of that day, or its last second when `end_of_day`.
pub fn parse_utc(text: &str, end_of_day: bool) -> Result<Option<i64>, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let bad = || {
        format!(
            "'{}' is not a UTC time: use YYYY-MM-DD, YYYY-MM-DD HH:MM[:SS] or RFC 3339",
            t
        )
    };
    let norm = t.replacen(' ', "T", 1);
    let candidate = match norm.len() {
        10 => format!(
            "{}T{}Z",
            norm,
            if end_of_day { "23:59:59" } else { "00:00:00" }
        ),
        16 => format!("{}:00Z", norm),
        19 => format!("{}Z", norm),
        _ => norm.clone(),
    };
    rv_timeline_core::engine::parse_rfc3339(&candidate)
        .map(Some)
        .ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_window_texts() {
        assert_eq!(parse_utc("", false), Ok(None));
        assert_eq!(parse_utc("1970-01-02", false), Ok(Some(86_400)));
        assert_eq!(parse_utc("1970-01-01", true), Ok(Some(86_399)));
        assert_eq!(parse_utc("1970-01-01 01:00", false), Ok(Some(3_600)));
        assert_eq!(parse_utc("1970-01-01T00:00:10Z", false), Ok(Some(10)));
        assert_eq!(parse_utc("1970-01-01T01:00:00+01:00", false), Ok(Some(0)));
        assert!(parse_utc("yesterday", false).is_err());
    }

    #[test]
    fn a_timesketch_line_round_trips() {
        let e = TimeEvent {
            id: "rv-imgauth:R:E0001:exif.original:1".into(),
            utc_s: -5,
            utc_ns: 250_000_000,
            zone: ZoneInfo::Unknown,
            offset_min: None,
            precision: Precision::Millisecond,
            original: "1969:12:31 23:59:55.25".into(),
            kind: "exif.original".into(),
            item: ItemRef {
                evidence_id: "E0001".into(),
                path: "evidence/photo.jpg".into(),
                sub: String::new(),
                sha256: "ab".into(),
            },
            source: SourceRef {
                tool: "rv-imgauth".into(),
                tool_version: "0.3.0".into(),
                run_id: "R".into(),
                run_dir: "runs/rv-imgauth/R".into(),
                file: "reports/items/x/technical.json".into(),
                file_sha256: "cd".into(),
                pointer: "/metadata/exif/DateTimeOriginal".into(),
            },
            details: [("camera".to_string(), "X".to_string())].into(),
        };
        let line = rv_timeline_core::engine::timesketch_line(&e);
        let back = event_from_line(&serde_json::from_str(&line).unwrap()).unwrap();
        assert_eq!(back, e);
    }
}
