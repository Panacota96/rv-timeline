//! Reports: one statistics report per run, and two reports per item (technical + customer summary),
//! each in JSON (language-neutral, schema-versioned), HTML and PDF (one file per selected language).
//!
//! HTML and PDF are rendered from the same view model (`*_context`), so they never disagree.

pub mod pdf;

use crate::analyzer::{Finding, Severity};
use crate::engine::{self, DisplayZone};
use crate::hash::{HashAlgo, hash_bytes};
use crate::i18n::{Catalog, catalog};
use crate::model::{RunRef, RunStatus, Signal, TimeEvent};
use crate::time::human_duration;
use minijinja::Environment;
use pdf::Block;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const SCHEMA_STATISTICS: &str = "rakvor.statistics/1";
pub const SCHEMA_TECHNICAL: &str = "rakvor.item-technical/1";
pub const SCHEMA_SUMMARY: &str = "rakvor.item-summary/1";

/// Run-level limitations, always printed (what this tool cannot tell you).
pub const LIMITATIONS: [&str; 4] = [
    "SIGNATURE_TABLE_LIMITED",
    "TIMESTAMPS_FROM_FILESYSTEM",
    "CLEAN_RESULT_IS_NOT_AUTHENTICITY",
    "TIMESTAMP_PROVES_EXISTENCE_ONLY",
];
/// Limitations of a timeline run (rv-timeline's main verb), printed instead of [`LIMITATIONS`]; `TL_MAX_EVENTS`
/// is added when the event limit was reached.
pub const TIMELINE_LIMITATIONS: [&str; 6] = [
    "TL_ZONE_UNKNOWN",
    "TL_CLOCK_SKEW",
    "TL_TOOL_OUTPUTS_ONLY",
    "TL_READER_VERSIONS",
    "TL_CLEAN_IS_NOT_PROOF",
    "TIMESTAMP_PROVES_EXISTENCE_ONLY",
];
/// Rows of an item's events table in its reports; the complete list is in `timeline.jsonl`.
pub const ITEM_EVENT_ROWS: usize = 200;
pub const SCHEMA_CUSTODY: &str = "rakvor.item-custody/1";
const BLANK_TRANSFER_ROWS: usize = 6;

/// Custody form language per jurisdiction; an English copy is always added.
pub fn custody_langs(jurisdiction: &str) -> Vec<String> {
    let main = if jurisdiction == "fr" { "fr" } else { "es" };
    vec![main.to_string(), "en".to_string()]
}

#[derive(Clone)]
pub struct RunInfo {
    pub tool_name: String,
    pub tool_version: String,
    pub run_id: String,
    pub case_id: Option<String>,
    pub actor: String,
    pub frontend: String,
    pub algorithms: Vec<HashAlgo>,
    pub langs: Vec<String>,
    pub started_utc: String,
    pub finished_utc: String,
    pub elapsed_ms: u64,
    pub cancelled: bool,
    /// "co" (Colombia, Fiscalía) or "fr" (France, scellés)
    pub jurisdiction: String,
    pub signer: Option<std::sync::Arc<crate::trust::PdfSigner>>,
    /// {"status": "ok"|"pending"|"off", ...}
    pub timestamp: Value,
    /// Set when the run works in a shared case folder (`--case-dir`).
    pub case: Option<CaseInfo>,
    /// Set for a timeline build: what was read, the display zone, the signals.
    pub timeline: Option<TimelineInfo>,
}

/// A run found in the case folder but not used as a source (`self`, `tool_filter`, `max_events`).
#[derive(Clone, Debug)]
pub struct SkippedRun {
    pub run: RunRef,
    pub reason: String,
}

/// What a timeline build read and found, for the statistics report and the page headers.
#[derive(Clone, Debug)]
pub struct TimelineInfo {
    pub zone: DisplayZone,
    /// Every source run considered, verified or excluded (with its reason and event count).
    pub runs: Vec<RunRef>,
    pub skipped: Vec<SkippedRun>,
    pub events: u64,
    /// Events read but outside the window or the tool filter.
    pub filtered_out: u64,
    pub zone_unknown: u64,
    pub by_tool: BTreeMap<String, u64>,
    pub by_kind: BTreeMap<String, u64>,
    /// All signals (item, run and case level).
    pub signals: Vec<Signal>,
    pub clock_skew_s: u64,
    pub max_events: u64,
    pub cap_reached: bool,
    pub from_s: Option<i64>,
    pub to_s: Option<i64>,
    pub tools: Vec<String>,
    /// `timeline.jsonl` relative to the report folder, when written.
    pub timeline_file: Option<String>,
    pub spilled_chunks: usize,
}

impl TimelineInfo {
    pub fn limitations(&self) -> Vec<(&'static str, BTreeMap<String, String>)> {
        let mut out: Vec<(&'static str, BTreeMap<String, String>)> = TIMELINE_LIMITATIONS
            .iter()
            .map(|c| {
                let mut p = BTreeMap::new();
                p.insert("skew_s".to_string(), self.clock_skew_s.to_string());
                (*c, p)
            })
            .collect();
        if self.cap_reached {
            let mut p = BTreeMap::new();
            p.insert("max_events".to_string(), self.max_events.to_string());
            out.insert(0, ("TL_MAX_EVENTS", p));
        }
        out
    }

    pub fn verified(&self) -> usize {
        self.runs
            .iter()
            .filter(|r| r.status == RunStatus::Verified)
            .count()
    }

    pub fn excluded(&self) -> usize {
        self.runs.len() - self.verified()
    }
}

/// One evidence item's part of the timeline.
#[derive(Clone, Debug, Default)]
pub struct ItemTimeline {
    /// The first [`ITEM_EVENT_ROWS`] events in timeline order.
    pub events: Vec<TimeEvent>,
    pub total: u64,
    pub tools: Vec<String>,
    pub first_s: Option<i64>,
    pub last_s: Option<i64>,
    /// The item's signals (also in the item's findings, worded from the `signals` catalogue).
    pub signals: Vec<Signal>,
}

/// A timeline signal as a report finding (same code, severity and parameters).
pub fn signal_finding(s: &Signal) -> Finding {
    Finding {
        code: s.code.clone(),
        severity: sev(s.severity),
        params: s.params.clone(),
    }
}

fn sev(s: crate::model::Severity) -> Severity {
    match s {
        crate::model::Severity::Info => Severity::Info,
        crate::model::Severity::Low => Severity::Low,
        crate::model::Severity::Medium => Severity::Medium,
        crate::model::Severity::High => Severity::High,
    }
}

/// Signal parameters with the localised exclusion reason (`reason_text`).
fn localized_params(c: &Catalog, params: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut p = params.clone();
    if let Some(r) = params.get("reason") {
        p.insert(
            "reason_text".into(),
            c.text("exclusion", r).unwrap_or_else(|| r.clone()),
        );
    }
    p
}

fn limitation_texts(c: &Catalog, run: &RunInfo) -> Vec<String> {
    match &run.timeline {
        Some(t) => t
            .limitations()
            .iter()
            .map(|(code, p)| c.limitation_with(code, p))
            .collect(),
        None => LIMITATIONS.iter().map(|l| c.limitation(l)).collect(),
    }
}

fn limitation_codes(run: &RunInfo) -> Value {
    match &run.timeline {
        Some(t) => json!(
            t.limitations()
                .iter()
                .map(|(c, p)| json!({"code": c, "params": p}))
                .collect::<Vec<_>>()
        ),
        None => json!(LIMITATIONS),
    }
}

fn zone_time(run: &RunInfo, utc: &str) -> Option<String> {
    let t = run.timeline.as_ref()?;
    let s = engine::parse_rfc3339(utc)?;
    Some(t.zone.format(s, 0, crate::model::Precision::Second))
}

fn event_row(c: &Catalog, zone: &DisplayZone, e: &TimeEvent) -> Value {
    let unknown = e.zone == crate::model::ZoneInfo::Unknown;
    let utc = if unknown {
        format!("{} ({})", engine::utc_time(e), c.label("as_written"))
    } else {
        engine::utc_time(e)
    };
    json!({
        "id": e.id, "utc": utc, "unknown": unknown,
        "display": engine::display_time(e, zone).unwrap_or_else(|| c.label("zone_unknown_short")),
        "kind": e.kind, "kind_label": engine::kind_label(c.lang, &e.kind), "original": e.original,
        "sub": e.item.sub, "tool": e.source.tool, "run_id": e.source.run_id, "file": e.source.file,
        "pointer": e.source.pointer,
    })
}

fn signal_view(c: &Catalog, s: &Signal) -> Value {
    let p = localized_params(c, &s.params);
    let (title, shows, dnp) = c.signal(&s.code, &p);
    let key = sev(s.severity).key();
    json!({"code": s.code, "severity": key, "severity_label": c.severity(key), "title": title, "shows": shows,
           "does_not_prove": dnp, "events_text": capped_list(&s.events, 6),
           "evidence_id": s.item.as_ref().map(|i| i.evidence_id.clone()).unwrap_or_default()})
}

fn signal_json(s: &Signal, langs: &[String]) -> Value {
    let texts: BTreeMap<String, Value> = langs
        .iter()
        .map(|l| {
            let c = catalog(l);
            let (title, shows, dnp) = c.signal(&s.code, &localized_params(c, &s.params));
            (
                l.clone(),
                json!({"title": title, "shows": shows, "does_not_prove": dnp}),
            )
        })
        .collect();
    json!({"code": s.code, "severity": s.severity, "events": s.events, "item": s.item, "params": s.params, "text": texts})
}

fn severity_counts(signals: &[Signal]) -> BTreeMap<&'static str, u64> {
    let mut m: BTreeMap<&'static str, u64> = ["high", "medium", "low", "info"]
        .iter()
        .map(|k| (*k, 0))
        .collect();
    for s in signals {
        *m.entry(sev(s.severity).key()).or_default() += 1;
    }
    m
}

fn window_text(c: &Catalog, t: &TimelineInfo) -> String {
    let f = |v: Option<i64>| {
        v.map(|s| engine::fmt_utc(s, 0, crate::model::Precision::Second))
            .unwrap_or_else(|| "\u{2026}".into())
    };
    if t.from_s.is_none() && t.to_s.is_none() {
        c.label("none")
    } else {
        format!("{} \u{2013} {}", f(t.from_s), f(t.to_s))
    }
}

fn timeline_view(c: &Catalog, t: &TimelineInfo) -> Value {
    let runs: Vec<Value> = t.runs.iter().map(|r| {
        let status = if r.status == RunStatus::Verified { "verified" } else { "excluded" };
        let reason = r.exclusion.as_ref().map(|x| {
            let l = c.text("exclusion", &x.reason).unwrap_or_else(|| x.reason.clone());
            if x.detail.is_empty() { l } else { format!("{} ({})", l, x.detail) }
        }).unwrap_or_default();
        json!({"tool": r.tool, "version": r.tool_version, "run_id": r.run_id, "run_dir": r.run_dir, "status": status,
               "status_label": c.label(&format!("run_status_{}", status)), "reason": reason, "events": r.events})
    }).collect();
    let skipped: Vec<Value> = t
        .skipped
        .iter()
        .map(|s| {
            json!({"tool": s.run.tool, "run_id": s.run.run_id,
        "reason": c.label(&format!("skip_{}", s.reason))})
        })
        .collect();
    let by_tool: Vec<Value> = t
        .by_tool
        .iter()
        .map(|(k, n)| json!({"name": k, "count": n}))
        .collect();
    let by_kind: Vec<Value> = t
        .by_kind
        .iter()
        .map(|(k, n)| json!({"kind": k, "name": engine::kind_label(c.lang, k), "count": n}))
        .collect();
    let sev_rows: Vec<Value> = ["high", "medium", "low", "info"]
        .iter()
        .map(|k| json!({"key": k, "label": c.severity(k), "count": severity_counts(&t.signals)[k]}))
        .collect();
    let case_signals: Vec<Value> = t
        .signals
        .iter()
        .filter(|s| s.item.is_none())
        .map(|s| signal_view(c, s))
        .collect();
    let mut cap = BTreeMap::new();
    cap.insert("max".to_string(), t.max_events.to_string());
    json!({
        "zone": t.zone.name(), "runs": runs, "skipped": skipped, "by_tool": by_tool, "by_kind": by_kind,
        "severity_rows": sev_rows, "case_signals": case_signals, "events": t.events, "filtered_out": t.filtered_out,
        "zone_unknown": t.zone_unknown, "verified": t.verified(), "excluded": t.excluded(),
        "cap_note": if t.cap_reached { crate::i18n::fill(&c.label("events_cap_note"), &cap) } else { String::new() },
        "timeline_file": t.timeline_file, "window_text": window_text(c, t),
        "tools_text": if t.tools.is_empty() { c.label("all_tools") } else { t.tools.join(", ") },
        "clock_skew_text": format!("{} s", t.clock_skew_s), "signal_count": t.signals.len(),
    })
}

fn timeline_json(t: &TimelineInfo, langs: &[String]) -> Value {
    json!({
        "display_zone": t.zone.name(), "clock_skew_s": t.clock_skew_s, "max_events": t.max_events,
        "max_events_reached": t.cap_reached, "from_s": t.from_s, "to_s": t.to_s, "tools": t.tools,
        "runs": t.runs, "skipped": t.skipped.iter().map(|s| json!({"tool": s.run.tool, "version": s.run.tool_version,
            "run_id": s.run.run_id, "run_dir": s.run.run_dir, "reason": s.reason})).collect::<Vec<_>>(),
        "runs_verified": t.verified(), "runs_excluded": t.excluded(),
        "events": t.events, "events_filtered_out": t.filtered_out, "events_zone_unknown": t.zone_unknown,
        "events_by_tool": t.by_tool, "events_by_kind": t.by_kind,
        "signals_by_severity": severity_counts(&t.signals),
        "signals": t.signals.iter().map(|s| signal_json(s, langs)).collect::<Vec<_>>(),
        "timeline_file": t.timeline_file, "sort_spilled_chunks": t.spilled_chunks,
    })
}

fn item_timeline_text(c: &Catalog, tl: &ItemTimeline) -> String {
    match (tl.first_s, tl.last_s) {
        (Some(a), Some(b)) if tl.total > 0 => {
            let mut p = BTreeMap::new();
            p.insert("n".to_string(), tl.total.to_string());
            p.insert("tools".to_string(), tl.tools.join(", "));
            p.insert(
                "first".to_string(),
                engine::fmt_utc(a, 0, crate::model::Precision::Second),
            );
            p.insert(
                "last".to_string(),
                engine::fmt_utc(b, 0, crate::model::Precision::Second),
            );
            crate::i18n::fill(&c.label("tl_item_span"), &p)
        }
        _ => c.label("tl_item_none"),
    }
}

/// Counts of how the run's items relate to the case registry.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CaseTally {
    /// Items that carry an evidence id from intake (new or already registered).
    pub registered: u64,
    /// Of those, newly added to the registry by this run.
    pub added: u64,
    pub verified: u64,
    pub mismatched: u64,
    pub unregistered: u64,
}

#[derive(Clone, Debug)]
pub struct CaseInfo {
    pub case_id: String,
    /// "intake" | "analysis"
    pub role: String,
    pub dir: String,
    pub tally: CaseTally,
}

impl CaseInfo {
    pub fn to_json(&self) -> Value {
        let t = &self.tally;
        json!({"case_id": self.case_id, "role": self.role, "case_dir": self.dir,
               "counts": {"registered": t.registered, "added": t.added, "verified": t.verified,
                          "mismatched": t.mismatched, "unregistered": t.unregistered}})
    }
}

#[derive(Clone, Debug)]
pub struct ItemResult {
    pub index: u64,
    pub path: PathBuf,
    pub size: u64,
    pub modified_utc: Option<String>,
    pub hashes: Vec<(HashAlgo, String)>,
    pub detected_type: Option<String>,
    pub extension: Option<String>,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
    pub audit_first_seq: u64,
    pub audit_last_seq: u64,
    /// Case folder only: evidence id (E0001…), relation to the registry and intake date.
    pub evidence_id: Option<String>,
    /// registered | already_registered | verified | mismatch | not_in_registry
    pub case_status: Option<String>,
    pub intake_utc: Option<String>,
    /// Timeline build only: the item's events and signals.
    pub timeline: Option<ItemTimeline>,
}

impl ItemResult {
    pub fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.display().to_string())
    }

    /// ok = nothing above informational; attention = medium/low; problem = high.
    pub fn status(&self) -> &'static str {
        match self.findings.iter().map(|f| f.severity).max() {
            Some(Severity::High) => "problem",
            Some(Severity::Medium) | Some(Severity::Low) => "attention",
            _ => "ok",
        }
    }

    /// Folder name for this item's reports: "00007-invoice.pdf" (sanitised, max 60 chars).
    pub fn folder(&self) -> String {
        let clean: String = self
            .file_name()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .take(60)
            .collect();
        format!("{:05}-{}", self.index, clean)
    }
}

pub struct AuditRef {
    pub head: String,
    pub entries: u64,
    pub log_dir: String,
}

pub struct RunTotals {
    pub items: u64,
    pub bytes: u64,
    pub errors: u64,
}

fn env() -> &'static Environment<'static> {
    static E: OnceLock<Environment<'static>> = OnceLock::new();
    E.get_or_init(|| {
        let mut e = Environment::new();
        e.add_template(
            "statistics.html",
            include_str!("../../../../templates/statistics.html"),
        )
        .expect("template");
        e.add_template(
            "technical.html",
            include_str!("../../../../templates/technical.html"),
        )
        .expect("template");
        e.add_template(
            "summary.html",
            include_str!("../../../../templates/summary.html"),
        )
        .expect("template");
        e.add_template(
            "custody.html",
            include_str!("../../../../templates/custody.html"),
        )
        .expect("template");
        e
    })
}

const CSS: &str = include_str!("../../../../templates/report.css");
const LOGO_SVG: &str = include_str!("../../../../templates/rv-mark.svg");

pub fn render_html(template: &str, ctx: &Value) -> Result<String, String> {
    env()
        .get_template(template)
        .and_then(|t| t.render(minijinja::value::Serde(ctx)))
        .map_err(|e| format!("template {}: {}", template, e))
}

fn finding_view(c: &Catalog, f: &Finding) -> Value {
    let (title, shows, dnp) = c.finding(&f.code, &localized_params(c, &f.params));
    json!({"code": f.code, "severity": f.severity.key(), "severity_label": c.severity(f.severity.key()), "title": title, "shows": shows, "does_not_prove": dnp})
}

fn run_view(c: &Catalog, run: &RunInfo) -> Value {
    json!({
        "run_id": run.run_id, "case_id": run.case_id, "actor": run.actor, "frontend": run.frontend,
        "started_utc": run.started_utc, "finished_utc": run.finished_utc,
        "duration_text": human_duration(run.elapsed_ms),
        "algorithms_text": run.algorithms.iter().map(|a| a.name()).collect::<Vec<_>>().join(" + "),
        "cancelled": run.cancelled,
        "lang": c.lang,
        "started_display": zone_time(run, &run.started_utc),
        "finished_display": zone_time(run, &run.finished_utc),
    })
}

fn base(c: &Catalog, run: &RunInfo) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("lang".into(), json!(c.lang));
    let mut t = c.labels().clone();
    if run.timeline.is_some() {
        t["method_text"] = json!(c.label("tl_method_text"));
    }
    m.insert("t".into(), t);
    m.insert(
        "zone".into(),
        json!(run.timeline.as_ref().map(|t| t.zone.name())),
    );
    m.insert("css".into(), json!(CSS));
    m.insert(
        "tool".into(),
        json!({"name": run.tool_name, "version": run.tool_version}),
    );
    m.insert("run".into(), run_view(c, run));
    m.insert("limitations".into(), json!(limitation_texts(c, run)));
    m.insert("brand".into(), c.brand().clone());
    m.insert("logo_svg".into(), json!(LOGO_SVG));
    m.insert(
        "signature".into(),
        json!({"signed": run.signer.is_some(), "by": run.signer.as_ref().map(|s| s.subject.clone()).unwrap_or_default(),
               "certificate_sha256": run.signer.as_ref().map(|s| s.fingerprint_sha256.clone()).unwrap_or_default()}),
    );
    let mut ts = run.timestamp.clone();
    if !ts.is_object() {
        ts = json!({"status": "off"});
    }
    let label = c.label(&format!(
        "timestamp_{}",
        ts["status"].as_str().unwrap_or("off")
    ));
    ts["status_label"] = json!(label);
    m.insert("timestamp".into(), ts);
    m
}

fn throughput(bytes: u64, ms: u64) -> String {
    if ms == 0 {
        return "-".into();
    }
    let per_s = bytes as f64 * 1000.0 / ms as f64;
    if per_s >= 1048576.0 {
        format!("{:.1} MiB/s", per_s / 1048576.0)
    } else {
        format!("{:.1} KiB/s", per_s / 1024.0)
    }
}

/// Keeps reports readable at scale (50,000 files): the first `max` names, then "… (+N)".
/// The complete lists stay in hashes.csv, statistics.json and the audit log.
pub fn capped_list(names: &[String], max: usize) -> String {
    if names.len() <= max {
        names.join(", ")
    } else {
        format!(
            "{}, \u{2026} (+{})",
            names[..max].join(", "),
            names.len() - max
        )
    }
}

fn capped_paths(items: &[ItemResult], idx: &[usize]) -> Vec<String> {
    let mut p: Vec<String> = idx
        .iter()
        .take(20)
        .map(|&i| items[i].path.display().to_string())
        .collect();
    if idx.len() > 20 {
        p.push(format!("\u{2026} (+{})", idx.len() - 20));
    }
    p
}

/// Groups of identical content by primary hash (only items that were hashed and are not empty).
pub fn duplicate_groups(items: &[ItemResult]) -> Vec<(String, Vec<usize>)> {
    let mut by: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, it) in items.iter().enumerate() {
        if let (Some((_, h)), true) = (it.hashes.first(), it.size > 0) {
            by.entry(h.clone()).or_default().push(i);
        }
    }
    by.into_iter().filter(|(_, v)| v.len() > 1).collect()
}

pub fn statistics_context(
    lang: &str,
    run: &RunInfo,
    items: &[ItemResult],
    totals: &RunTotals,
    audit: &AuditRef,
) -> Value {
    let c = catalog(lang);
    let mut m = base(c, run);
    let mut sev: BTreeMap<Severity, u64> = BTreeMap::new();
    let mut codes: BTreeMap<String, u64> = BTreeMap::new();
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    for it in items {
        for f in &it.findings {
            *sev.entry(f.severity).or_default() += 1;
            *codes.entry(f.code.clone()).or_default() += 1;
        }
        *types
            .entry(
                it.detected_type
                    .clone()
                    .unwrap_or_else(|| c.label("unknown")),
            )
            .or_default() += 1;
    }
    let severity_rows: Vec<Value> = [Severity::High, Severity::Medium, Severity::Low, Severity::Info]
        .iter()
        .map(|s| json!({"key": s.key(), "label": c.severity(s.key()), "count": sev.get(s).copied().unwrap_or(0)}))
        .collect();
    let code_rows: Vec<Value> = codes.iter().map(|(code, n)| json!({"code": code, "title": c.finding(code, &BTreeMap::new()).0, "count": n})).collect();
    let type_rows: Vec<Value> = types
        .iter()
        .map(|(name, n)| json!({"name": name, "count": n}))
        .collect();
    let duplicate_rows: Vec<Value> = duplicate_groups(items)
        .into_iter()
        .map(|(h, idx)| json!({"hash": h, "paths": capped_paths(items, &idx)}))
        .collect();
    let item_rows: Vec<Value> = items
        .iter()
        .map(|it| {
            json!({"index": it.index, "file_name": it.file_name(), "size": it.size, "finding_count": it.findings.len(),
                   "evidence_id": it.evidence_id,
                   "status": it.status(), "status_label": c.label(&format!("status_{}", it.status())),
                   "link": format!("items/{}/technical.{}.html", it.folder(), lang)})
        })
        .collect();
    m.insert("totals".into(), json!({"items": totals.items, "bytes": totals.bytes, "errors": totals.errors, "throughput_text": throughput(totals.bytes, run.elapsed_ms)}));
    m.insert("severity_rows".into(), json!(severity_rows));
    m.insert("code_rows".into(), json!(code_rows));
    m.insert("type_rows".into(), json!(type_rows));
    m.insert("duplicate_rows".into(), json!(duplicate_rows));
    m.insert("item_rows".into(), json!(item_rows));
    m.insert("case".into(), case_view(run));
    m.insert(
        "timeline".into(),
        run.timeline
            .as_ref()
            .map(|t| timeline_view(c, t))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "audit".into(),
        json!({"head": audit.head, "entries": audit.entries, "log_dir": audit.log_dir}),
    );
    Value::Object(m)
}

fn case_view(run: &RunInfo) -> Value {
    run.case.as_ref().map(|c| {
        let t = &c.tally;
        json!({"case_id": c.case_id, "role": c.role, "dir": c.dir, "registered": t.registered, "added": t.added,
               "verified": t.verified, "mismatched": t.mismatched, "unregistered": t.unregistered})
    }).unwrap_or(Value::Null)
}

fn item_view(c: &Catalog, it: &ItemResult) -> Value {
    let status = it.status();
    let pre = if it.timeline.is_some() { "tl_" } else { "" };
    let (alg, hash) = it
        .hashes
        .first()
        .map(|(a, h)| (a.name().to_string(), h.clone()))
        .unwrap_or_else(|| ("-".into(), c.label("none")));
    json!({
        "index": it.index, "file_name": it.file_name(), "path": it.path.display().to_string(), "size": it.size,
        "modified_utc": it.modified_utc.clone().unwrap_or_else(|| c.label("unknown")),
        "extension_text": it.extension.clone().map(|e| format!(".{}", e)).unwrap_or_else(|| c.label("none")),
        "detected_text": it.detected_type.clone().unwrap_or_else(|| c.label("unknown")),
        "status": status, "status_label": c.label(&format!("status_{}", status)),
        "summary_text": c.label(&format!("{}summary_{}", pre, status)), "next_text": c.label(&format!("{}next_{}", pre, status)),
        "timeline": it.timeline.is_some(),
        "timeline_text": it.timeline.as_ref().map(|t| item_timeline_text(c, t)),
        "primary_algorithm": alg, "primary_hash": hash,
        "audit_first_seq": it.audit_first_seq, "audit_last_seq": it.audit_last_seq,
        "evidence_id": it.evidence_id, "intake_utc": it.intake_utc, "case_status": it.case_status,
        "case_status_label": it.case_status.as_ref().map(|s| c.label(&format!("case_status_{}", s))),
    })
}

pub fn item_context(lang: &str, run: &RunInfo, it: &ItemResult, audit: &AuditRef) -> Value {
    let c = catalog(lang);
    let mut m = base(c, run);
    m.insert("item".into(), item_view(c, it));
    m.insert("case".into(), case_view(run));
    m.insert(
        "hash_rows".into(),
        json!(
            it.hashes
                .iter()
                .map(|(a, h)| json!({"algorithm": a.name(), "value": h}))
                .collect::<Vec<_>>()
        ),
    );
    m.insert(
        "findings".into(),
        json!(
            it.findings
                .iter()
                .map(|f| finding_view(c, f))
                .collect::<Vec<_>>()
        ),
    );
    if let (Some(tl), Some(t)) = (&it.timeline, &run.timeline) {
        let rows: Vec<Value> = tl
            .events
            .iter()
            .take(ITEM_EVENT_ROWS)
            .map(|e| event_row(c, &t.zone, e))
            .collect();
        let more = tl.total.saturating_sub(rows.len() as u64);
        let mut p = BTreeMap::new();
        p.insert("n".to_string(), more.to_string());
        m.insert("events".into(), json!(rows));
        m.insert("events_total".into(), json!(tl.total));
        m.insert(
            "events_more".into(),
            json!(if more > 0 {
                crate::i18n::fill(&c.label("events_more"), &p)
            } else {
                String::new()
            }),
        );
    }
    m.insert(
        "audit".into(),
        json!({"head": audit.head, "entries": audit.entries, "log_dir": audit.log_dir}),
    );
    Value::Object(m)
}

// ---------- JSON (language-neutral; texts included for each selected language) ----------

fn findings_json(it: &ItemResult, langs: &[String]) -> Value {
    json!(
        it.findings
            .iter()
            .map(|f| {
                let texts: BTreeMap<String, Value> = langs
                    .iter()
                    .map(|l| {
                        let c = catalog(l);
                        let (title, shows, dnp) =
                            c.finding(&f.code, &localized_params(c, &f.params));
                        (
                            l.clone(),
                            json!({"title": title, "shows": shows, "does_not_prove": dnp}),
                        )
                    })
                    .collect();
                json!({"code": f.code, "severity": f.severity, "params": f.params, "text": texts})
            })
            .collect::<Vec<_>>()
    )
}

fn run_json(run: &RunInfo) -> Value {
    json!({"run_id": run.run_id, "case_id": run.case_id, "actor": run.actor, "frontend": run.frontend,
           "algorithms": run.algorithms, "langs": run.langs, "started_utc": run.started_utc,
           "finished_utc": run.finished_utc, "elapsed_ms": run.elapsed_ms, "cancelled": run.cancelled,
           "jurisdiction": run.jurisdiction, "pdf_signed_by": run.signer.as_ref().map(|s| s.subject.clone()),
           "pdf_signer_certificate_sha256": run.signer.as_ref().map(|s| s.fingerprint_sha256.clone())})
}

pub fn statistics_json(
    run: &RunInfo,
    items: &[ItemResult],
    totals: &RunTotals,
    audit: &AuditRef,
) -> Value {
    let mut sev: BTreeMap<&str, u64> = ["high", "medium", "low", "info"]
        .iter()
        .map(|k| (*k, 0))
        .collect();
    let mut codes: BTreeMap<String, u64> = BTreeMap::new();
    let mut status: BTreeMap<&str, u64> = BTreeMap::new();
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    for it in items {
        for f in &it.findings {
            *sev.entry(f.severity.key()).or_default() += 1;
            *codes.entry(f.code.clone()).or_default() += 1;
        }
        *status.entry(it.status()).or_default() += 1;
        *types
            .entry(it.detected_type.clone().unwrap_or_else(|| "unknown".into()))
            .or_default() += 1;
    }
    json!({
        "schema": SCHEMA_STATISTICS,
        "tool": {"name": run.tool_name, "version": run.tool_version},
        "run": run_json(run),
        "totals": {"items": totals.items, "bytes": totals.bytes, "errors": totals.errors},
        "findings_by_severity": sev, "findings_by_code": codes, "items_by_status": status, "items_by_type": types,
        "duplicate_groups": duplicate_groups(items).into_iter().map(|(h, idx)| json!({"hash": h, "items": idx.iter().map(|&i| items[i].index).collect::<Vec<_>>()})).collect::<Vec<_>>(),
        "case": run.case.as_ref().map(|c| c.to_json()),
        "items": items.iter().map(|it| json!({"index": it.index, "evidence_id": it.evidence_id, "path": it.path.display().to_string(), "size": it.size, "status": it.status(),
              "findings": it.findings.iter().map(|f| f.code.clone()).collect::<Vec<_>>(), "report_folder": format!("items/{}", it.folder())})).collect::<Vec<_>>(),
        "limitations": limitation_codes(run),
        "timeline": run.timeline.as_ref().map(|t| timeline_json(t, &run.langs)),
        "audit": {"head": audit.head, "entries": audit.entries, "log_dir": audit.log_dir},
        "timestamp": if run.timestamp.is_object() { run.timestamp.clone() } else { json!({"status": "off"}) },
    })
}

pub fn technical_json(run: &RunInfo, it: &ItemResult) -> Value {
    json!({
        "schema": SCHEMA_TECHNICAL,
        "tool": {"name": run.tool_name, "version": run.tool_version},
        "run": run_json(run),
        "item": {"index": it.index, "evidence_id": it.evidence_id, "path": it.path.display().to_string(), "file_name": it.file_name(), "size": it.size,
                 "modified_utc": it.modified_utc, "extension": it.extension, "detected_type": it.detected_type,
                 "status": it.status(), "error": it.error},
        "case": run.case.as_ref().map(|c| json!({"case_id": c.case_id, "role": c.role, "case_dir": c.dir,
                 "status": it.case_status, "intake_utc": it.intake_utc})),
        "hashes": it.hashes.iter().map(|(a, h)| (a.name().to_string(), json!(h))).collect::<serde_json::Map<_, _>>(),
        "findings": findings_json(it, &run.langs),
        "timeline": it.timeline.as_ref().map(|tl| json!({
            "display_zone": run.timeline.as_ref().map(|t| t.zone.name()),
            "events_total": tl.total, "events_listed": tl.events.len().min(ITEM_EVENT_ROWS),
            "first_utc": tl.first_s.map(|s| engine::fmt_utc(s, 0, crate::model::Precision::Second)),
            "last_utc": tl.last_s.map(|s| engine::fmt_utc(s, 0, crate::model::Precision::Second)),
            "tools": tl.tools, "events": tl.events.iter().take(ITEM_EVENT_ROWS).collect::<Vec<_>>(),
            "signals": tl.signals.iter().map(|s| signal_json(s, &run.langs)).collect::<Vec<_>>(),
        })),
        "limitations": limitation_codes(run),
        "audit": {"first_seq": it.audit_first_seq, "last_seq": it.audit_last_seq},
    })
}

pub fn summary_json(run: &RunInfo, it: &ItemResult) -> Value {
    let texts: BTreeMap<String, Value> = run
        .langs
        .iter()
        .map(|l| {
            let c = catalog(l);
            let pre = if it.timeline.is_some() { "tl_" } else { "" };
            (l.clone(), json!({"status": c.label(&format!("status_{}", it.status())), "summary": c.label(&format!("{}summary_{}", pre, it.status())), "next_step": c.label(&format!("{}next_{}", pre, it.status())),
                               "timeline": it.timeline.as_ref().map(|t| item_timeline_text(c, t))}))
        })
        .collect();
    json!({
        "schema": SCHEMA_SUMMARY,
        "run_id": run.run_id, "case_id": run.case_id,
        "item": {"index": it.index, "evidence_id": it.evidence_id, "file_name": it.file_name()},
        "status": it.status(),
        "fingerprint": it.hashes.first().map(|(a, h)| json!({"algorithm": a.name(), "value": h})),
        "findings": findings_json(it, &run.langs),
        "text": texts,
    })
}

// ---------- PDF (built from the same view model as HTML) ----------

fn s(v: &Value, path: &str) -> String {
    let mut cur = v;
    for p in path.split('.') {
        cur = &cur[p];
    }
    match cur {
        Value::String(x) => x.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v[key].as_array().map(|a| a.as_slice()).unwrap_or(&[])
}

fn header(ctx: &Value, title_key: &str, subtitle: String) -> Vec<Block> {
    vec![
        Block::Title(s(ctx, &format!("t.{}", title_key))),
        Block::Subtitle(subtitle),
    ]
}

fn signature_row(ctx: &Value) -> (String, String) {
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let v = if ctx["signature"]["signed"].as_bool() == Some(true) {
        format!(
            "{} {} ({} {})",
            t("signed_by"),
            s(ctx, "signature.by"),
            t("certificate_sha256"),
            s(ctx, "signature.certificate_sha256")
        )
    } else {
        t("not_signed")
    };
    (t("signature"), v)
}

/// Renders blocks with the Rakvor band, footer and tagline; signs when the run has a certificate.
fn finish(ctx: &Value, title: &str, blocks: &[Block], run: &RunInfo) -> Result<Vec<u8>, String> {
    let mut footer = format!(
        "{} {} {} \u{00B7} {}",
        s(ctx, "t.generated_by"),
        s(ctx, "tool.name"),
        s(ctx, "tool.version"),
        s(ctx, "run.run_id")
    );
    if ctx["zone"].is_string() {
        footer = format!(
            "{} \u{00B7} {}: {}",
            footer,
            s(ctx, "t.display_zone"),
            s(ctx, "zone")
        );
    }
    let producer = format!("{} {}", s(ctx, "tool.name"), s(ctx, "tool.version"));
    let (page, of, descriptor, tagline) = (
        s(ctx, "t.page"),
        s(ctx, "t.of"),
        s(ctx, "brand.descriptor"),
        s(ctx, "brand.tagline"),
    );
    let meta = pdf::Meta {
        title,
        footer: &footer,
        page_word: &page,
        of_word: &of,
        producer: &producer,
        descriptor: &descriptor,
        tagline: &tagline,
    };
    match &run.signer {
        Some(signer) => {
            let f = |data: &[u8]| signer.sign_detached(data);
            pdf::render(blocks, &meta, Some(&f))
        }
        None => pdf::render(blocks, &meta, None),
    }
}

pub fn statistics_pdf(ctx: &Value, run: &RunInfo) -> Result<Vec<u8>, String> {
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let mut b = header(
        ctx,
        "title_statistics",
        format!("{}: {}", t("run_id"), s(ctx, "run.run_id")),
    );
    if ctx["run"]["cancelled"].as_bool() == Some(true) {
        b.push(Block::Note(t("cancelled_note")));
    }
    if ctx["timeline"].is_object() {
        return statistics_pdf_timeline(ctx, run, b);
    }
    let mut kv = vec![(
        t("tool"),
        format!("{} {}", s(ctx, "tool.name"), s(ctx, "tool.version")),
    )];
    if !s(ctx, "run.case_id").is_empty() {
        kv.push((t("case"), s(ctx, "run.case_id")));
    }
    for (k, p) in [
        ("actor", "run.actor"),
        ("started", "run.started_utc"),
        ("finished", "run.finished_utc"),
        ("duration", "run.duration_text"),
        ("frontend", "run.frontend"),
        ("algorithms", "run.algorithms_text"),
        ("items", "totals.items"),
        ("bytes", "totals.bytes"),
        ("errors", "totals.errors"),
        ("throughput", "totals.throughput_text"),
    ] {
        kv.push((t(k), s(ctx, p)));
    }
    b.push(Block::Kv(kv));
    b.push(Block::Heading(t("findings_by_severity")));
    b.push(Block::Kv(
        arr(ctx, "severity_rows")
            .iter()
            .map(|r| (s(r, "label"), s(r, "count")))
            .collect(),
    ));
    b.push(Block::Heading(t("findings_by_code")));
    let codes = arr(ctx, "code_rows");
    if codes.is_empty() {
        b.push(Block::Para(t("none")))
    } else {
        b.push(Block::Kv(
            codes
                .iter()
                .map(|r| (s(r, "title"), s(r, "count")))
                .collect(),
        ))
    }
    b.push(Block::Heading(t("by_type")));
    b.push(Block::Kv(
        arr(ctx, "type_rows")
            .iter()
            .map(|r| (s(r, "name"), s(r, "count")))
            .collect(),
    ));
    b.push(Block::Heading(t("duplicates")));
    let dups = arr(ctx, "duplicate_rows");
    if dups.is_empty() {
        b.push(Block::Para(t("none")));
    }
    for d in dups {
        b.push(Block::Mono(s(d, "hash")));
        for p in arr(d, "paths") {
            b.push(Block::Bullet(p.as_str().unwrap_or_default().to_string()));
        }
        b.push(Block::Space(4.0));
    }
    if ctx["case"].is_object() {
        b.push(Block::Heading(t("case_verification")));
        let mut rows = vec![(t("case"), s(ctx, "case.case_id"))];
        for k in [
            "registered",
            "added",
            "verified",
            "mismatched",
            "unregistered",
        ] {
            rows.push((t(k), s(ctx, &format!("case.{}", k))));
        }
        rows.push((t("case_dir"), s(ctx, "case.dir")));
        b.push(Block::Kv(rows));
    }
    b.push(Block::Heading(t("items")));
    b.push(Block::Kv(
        arr(ctx, "item_rows")
            .iter()
            .map(|r| {
                let eid = s(r, "evidence_id");
                (
                    if eid.is_empty() {
                        format!("#{}  {}", s(r, "index"), s(r, "file_name"))
                    } else {
                        format!("#{}  {}  {}", s(r, "index"), eid, s(r, "file_name"))
                    },
                    format!(
                        "{} \u{00B7} {} {} \u{00B7} {} {}",
                        s(r, "status_label"),
                        s(r, "size"),
                        t("bytes").to_lowercase(),
                        s(r, "finding_count"),
                        t("findings").to_lowercase()
                    ),
                )
            })
            .collect(),
    ));
    b.push(Block::Heading(t("limitations")));
    for l in arr(ctx, "limitations") {
        b.push(Block::Bullet(l.as_str().unwrap_or_default().into()));
    }
    b.push(Block::Heading(t("timestamp")));
    let mut ts_rows = vec![(t("status"), s(ctx, "timestamp.status_label"))];
    if !s(ctx, "timestamp.tsa").is_empty() {
        ts_rows.push((t("tsa"), s(ctx, "timestamp.tsa")));
    }
    if !s(ctx, "timestamp.gen_time").is_empty() {
        ts_rows.push((t("gen_time"), s(ctx, "timestamp.gen_time")));
        ts_rows.push((t("covers"), format!("#{}", s(ctx, "timestamp.covers_seq"))));
        ts_rows.push((t("audit_head"), s(ctx, "timestamp.head")));
    }
    ts_rows.push(signature_row(ctx));
    b.push(Block::Kv(ts_rows));
    b.push(Block::Heading(t("audit")));
    b.push(Block::Kv(vec![
        (t("audit_head"), s(ctx, "audit.head")),
        (t("audit_entries"), s(ctx, "audit.entries")),
        (t("log_dir"), s(ctx, "audit.log_dir")),
    ]));
    finish(ctx, &t("title_statistics"), &b, run)
}

fn with_display(ctx: &Value, utc: &str, display: &str) -> String {
    let d = s(ctx, display);
    if d.is_empty() {
        s(ctx, utc)
    } else {
        format!("{} \u{00B7} {}", s(ctx, utc), d)
    }
}

fn signal_blocks(b: &mut Vec<Block>, ctx: &Value, list: &[Value]) {
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    if list.is_empty() {
        b.push(Block::Para(t("none")));
    }
    for x in list {
        b.push(Block::Finding {
            badge: s(x, "severity_label"),
            title: format!("{}  ({})", s(x, "title"), s(x, "code")),
            rows: vec![
                (t("shows"), s(x, "shows")),
                (t("does_not_prove"), s(x, "does_not_prove")),
            ],
        });
    }
}

fn statistics_pdf_timeline(
    ctx: &Value,
    run: &RunInfo,
    mut b: Vec<Block>,
) -> Result<Vec<u8>, String> {
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let mut kv = vec![(
        t("tool"),
        format!("{} {}", s(ctx, "tool.name"), s(ctx, "tool.version")),
    )];
    if !s(ctx, "run.case_id").is_empty() {
        kv.push((t("case"), s(ctx, "run.case_id")));
    }
    kv.push((t("display_zone"), s(ctx, "zone")));
    kv.push((t("actor"), s(ctx, "run.actor")));
    kv.push((
        t("started"),
        with_display(ctx, "run.started_utc", "run.started_display"),
    ));
    kv.push((
        t("finished"),
        with_display(ctx, "run.finished_utc", "run.finished_display"),
    ));
    for (k, p) in [
        ("duration", "run.duration_text"),
        ("frontend", "run.frontend"),
        ("algorithms", "run.algorithms_text"),
        ("runs_verified", "timeline.verified"),
        ("runs_excluded", "timeline.excluded"),
        ("events_total", "timeline.events"),
        ("events_filtered", "timeline.filtered_out"),
        ("events_zone_unknown", "timeline.zone_unknown"),
        ("signals", "timeline.signal_count"),
        ("items", "totals.items"),
        ("window", "timeline.window_text"),
        ("tools_filter", "timeline.tools_text"),
        ("clock_skew", "timeline.clock_skew_text"),
        ("timeline_file", "timeline.timeline_file"),
    ] {
        kv.push((t(k), s(ctx, p)));
    }
    b.push(Block::Kv(kv));
    if !s(ctx, "timeline.cap_note").is_empty() {
        b.push(Block::Note(s(ctx, "timeline.cap_note")));
    }
    let tl = &ctx["timeline"];
    b.push(Block::Heading(t("runs")));
    b.push(Block::Kv(
        arr(tl, "runs")
            .iter()
            .map(|r| {
                let mut v = format!(
                    "{} \u{00B7} {} {}",
                    s(r, "status_label"),
                    s(r, "events"),
                    t("events").to_lowercase()
                );
                if !s(r, "reason").is_empty() {
                    v = format!("{} \u{00B7} {}", v, s(r, "reason"));
                }
                (
                    format!("{} {}  {}", s(r, "tool"), s(r, "version"), s(r, "run_id")),
                    v,
                )
            })
            .collect(),
    ));
    let skipped = arr(tl, "skipped");
    if !skipped.is_empty() {
        b.push(Block::Heading(t("runs_skipped")));
        b.push(Block::Kv(
            skipped
                .iter()
                .map(|r| {
                    (
                        format!("{}  {}", s(r, "tool"), s(r, "run_id")),
                        s(r, "reason"),
                    )
                })
                .collect(),
        ));
    }
    for (head, key) in [("events_by_tool", "by_tool"), ("events_by_kind", "by_kind")] {
        b.push(Block::Heading(t(head)));
        let rows = arr(tl, key);
        if rows.is_empty() {
            b.push(Block::Para(t("none")));
        } else {
            b.push(Block::Kv(
                rows.iter().map(|r| (s(r, "name"), s(r, "count"))).collect(),
            ));
        }
    }
    b.push(Block::Heading(t("signals_by_severity")));
    b.push(Block::Kv(
        arr(tl, "severity_rows")
            .iter()
            .map(|r| (s(r, "label"), s(r, "count")))
            .collect(),
    ));
    b.push(Block::Heading(t("case_signals")));
    signal_blocks(&mut b, ctx, arr(tl, "case_signals"));
    b.push(Block::Heading(t("items")));
    b.push(Block::Kv(
        arr(ctx, "item_rows")
            .iter()
            .map(|r| {
                (
                    format!(
                        "#{}  {}  {}",
                        s(r, "index"),
                        s(r, "evidence_id"),
                        s(r, "file_name")
                    ),
                    format!(
                        "{} \u{00B7} {} {}",
                        s(r, "status_label"),
                        s(r, "finding_count"),
                        t("signals").to_lowercase()
                    ),
                )
            })
            .collect(),
    ));
    b.push(Block::Heading(t("limitations")));
    for l in arr(ctx, "limitations") {
        b.push(Block::Bullet(l.as_str().unwrap_or_default().into()));
    }
    b.push(Block::Heading(t("timestamp")));
    let mut ts_rows = vec![(t("status"), s(ctx, "timestamp.status_label"))];
    if !s(ctx, "timestamp.tsa").is_empty() {
        ts_rows.push((t("tsa"), s(ctx, "timestamp.tsa")));
    }
    if !s(ctx, "timestamp.gen_time").is_empty() {
        ts_rows.push((t("gen_time"), s(ctx, "timestamp.gen_time")));
        ts_rows.push((t("covers"), format!("#{}", s(ctx, "timestamp.covers_seq"))));
        ts_rows.push((t("audit_head"), s(ctx, "timestamp.head")));
    }
    ts_rows.push(signature_row(ctx));
    b.push(Block::Kv(ts_rows));
    b.push(Block::Heading(t("audit")));
    b.push(Block::Kv(vec![
        (t("audit_head"), s(ctx, "audit.head")),
        (t("audit_entries"), s(ctx, "audit.entries")),
        (t("log_dir"), s(ctx, "audit.log_dir")),
    ]));
    finish(ctx, &t("title_statistics"), &b, run)
}

pub fn technical_pdf(ctx: &Value, run: &RunInfo) -> Result<Vec<u8>, String> {
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let mut b = header(
        ctx,
        "title_technical",
        format!(
            "{} #{} \u{00B7} {} \u{00B7} {}: {}",
            t("item"),
            s(ctx, "item.index"),
            s(ctx, "item.file_name"),
            t("run_id"),
            s(ctx, "run.run_id")
        ),
    );
    let timeline = ctx["item"]["timeline"].as_bool() == Some(true);
    let mut rows = if timeline {
        vec![
            (t("path"), s(ctx, "item.path")),
            (t("size"), s(ctx, "item.size")),
            (t("status"), s(ctx, "item.status_label")),
            (t("display_zone"), s(ctx, "zone")),
            (t("events"), s(ctx, "item.timeline_text")),
        ]
    } else {
        vec![
            (t("path"), s(ctx, "item.path")),
            (t("size"), s(ctx, "item.size")),
            (t("modified"), s(ctx, "item.modified_utc")),
            (t("extension"), s(ctx, "item.extension_text")),
            (t("detected_type"), s(ctx, "item.detected_text")),
            (t("status"), s(ctx, "item.status_label")),
        ]
    };
    if ctx["case"].is_object() {
        rows.push((t("case"), s(ctx, "case.case_id")));
        rows.push((
            t("evidence_id"),
            if s(ctx, "item.evidence_id").is_empty() {
                t("none")
            } else {
                s(ctx, "item.evidence_id")
            },
        ));
        rows.push((t("case_registry"), s(ctx, "item.case_status_label")));
        if !s(ctx, "item.intake_utc").is_empty() {
            rows.push((t("intake_date"), s(ctx, "item.intake_utc")));
        }
    }
    b.push(Block::Kv(rows));
    b.push(Block::Heading(t("hashes")));
    b.push(Block::Kv(
        arr(ctx, "hash_rows")
            .iter()
            .map(|h| (s(h, "algorithm"), s(h, "value")))
            .collect(),
    ));
    b.push(Block::Heading(t("findings")));
    let f = arr(ctx, "findings");
    if f.is_empty() {
        b.push(Block::Para(t("none")));
    }
    for x in f {
        b.push(Block::Finding {
            badge: s(x, "severity_label"),
            title: format!("{}  ({})", s(x, "title"), s(x, "code")),
            rows: vec![
                (t("shows"), s(x, "shows")),
                (t("does_not_prove"), s(x, "does_not_prove")),
            ],
        });
    }
    if timeline {
        b.push(Block::Heading(t("events")));
        let ev = arr(ctx, "events");
        if ev.is_empty() {
            b.push(Block::Para(t("none")));
        } else {
            b.push(Block::Kv(
                ev.iter()
                    .map(|e| {
                        let mut v = format!(
                            "{} \u{00B7} {}: {} ({}, {}",
                            s(e, "display"),
                            s(e, "kind_label"),
                            s(e, "original"),
                            s(e, "tool"),
                            s(e, "file")
                        );
                        if !s(e, "pointer").is_empty() {
                            v = format!("{} {}", v, s(e, "pointer"));
                        }
                        v.push(')');
                        (s(e, "utc"), v)
                    })
                    .collect(),
            ));
        }
        if !s(ctx, "events_more").is_empty() {
            b.push(Block::Note(s(ctx, "events_more")));
        }
    }
    b.push(Block::Heading(t("method")));
    b.push(Block::Para(t("method_text")));
    b.push(Block::Heading(t("audit")));
    b.push(Block::Kv(vec![
        (
            t("audit_entries"),
            format!(
                "#{} \u{2013} #{}",
                s(ctx, "item.audit_first_seq"),
                s(ctx, "item.audit_last_seq")
            ),
        ),
        (t("log_dir"), s(ctx, "audit.log_dir")),
        signature_row(ctx),
    ]));
    b.push(Block::Heading(t("limitations")));
    for l in arr(ctx, "limitations") {
        b.push(Block::Bullet(l.as_str().unwrap_or_default().into()));
    }
    finish(ctx, &t("title_technical"), &b, run)
}

pub fn summary_pdf(ctx: &Value, run: &RunInfo) -> Result<Vec<u8>, String> {
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let mut sub = s(ctx, "item.file_name");
    if !s(ctx, "item.evidence_id").is_empty() {
        sub = format!(
            "{} \u{00B7} {}: {}",
            sub,
            t("evidence_id"),
            s(ctx, "item.evidence_id")
        );
    }
    if !s(ctx, "run.case_id").is_empty() {
        sub = format!("{} \u{00B7} {}: {}", sub, t("case"), s(ctx, "run.case_id"));
    }
    let mut b = header(ctx, "title_summary", sub);
    b.push(Block::Status(s(ctx, "item.status_label")));
    b.push(Block::Para(s(ctx, "item.summary_text")));
    if !s(ctx, "item.timeline_text").is_empty() {
        b.push(Block::Para(s(ctx, "item.timeline_text")));
    }
    b.push(Block::Heading(t("what_we_did")));
    b.push(Block::Para(t("method_text")));
    b.push(Block::Heading(t("what_we_found")));
    let f = arr(ctx, "findings");
    if f.is_empty() {
        b.push(Block::Para(t("none")));
    }
    for x in f {
        b.push(Block::Bullet(format!(
            "{}. {}",
            s(x, "title"),
            s(x, "shows")
        )));
    }
    b.push(Block::Heading(t("fingerprint")));
    b.push(Block::Para(t("fingerprint_text")));
    b.push(Block::Kv(vec![(
        s(ctx, "item.primary_algorithm"),
        s(ctx, "item.primary_hash"),
    )]));
    b.push(Block::Heading(t("next_steps")));
    b.push(Block::Para(s(ctx, "item.next_text")));
    finish(ctx, &t("title_summary"), &b, run)
}

// ---------- Chain-of-custody form (one per item; jurisdiction language + English) ----------

pub fn custody_context(lang: &str, run: &RunInfo, it: &ItemResult, audit: &AuditRef) -> Value {
    let mut ctx = item_context(lang, run, it, audit);
    let c = catalog(lang);
    let j = if run.jurisdiction == "fr" { "fr" } else { "co" };
    let mut cu = c.custody().clone();
    let get = |k: &str| c.custody()[k].as_str().unwrap_or(k).to_string();
    let mut params = BTreeMap::new();
    for (k, v) in [
        ("tool", run.tool_name.clone()),
        ("version", run.tool_version.clone()),
        ("run_id", run.run_id.clone()),
        ("start", run.started_utc.clone()),
        ("end", run.finished_utc.clone()),
        ("first", it.audit_first_seq.to_string()),
        ("last", it.audit_last_seq.to_string()),
    ] {
        params.insert(k.to_string(), v);
    }
    cu["title"] = json!(get(&format!("title_{}", j)));
    cu["basis"] = json!(get(&format!("basis_{}", j)));
    cu["case_label"] = json!(get(&format!("case_{}", j)));
    cu["evidence_id_label"] = json!(get(&format!("evidence_id_{}", j)));
    cu["evidence_id"] = json!(custody_evidence_id(run, it));
    cu["intake_utc"] = json!(it.intake_utc);
    cu["jurisdiction_label"] = json!(c.ui(&format!("jur_{}", j)));
    cu["operation_text"] = json!(crate::i18n::fill(&get("operation_text"), &params));
    cu["blank_rows"] = json!((0..BLANK_TRANSFER_ROWS).collect::<Vec<_>>());
    ctx["custody"] = cu;
    ctx
}

/// The case registry id (E0001…) when the run is linked to a case, else "<RUN-ID>-<NNNNN>".
fn custody_evidence_id(run: &RunInfo, it: &ItemResult) -> String {
    it.evidence_id
        .clone()
        .unwrap_or_else(|| format!("{}-{:05}", run.run_id, it.index))
}

pub fn custody_json(run: &RunInfo, it: &ItemResult) -> Value {
    json!({
        "schema": SCHEMA_CUSTODY,
        "jurisdiction": run.jurisdiction,
        "run_id": run.run_id, "case_id": run.case_id,
        "evidence_id": custody_evidence_id(run, it),
        "intake_utc": it.intake_utc,
        "item": {"index": it.index, "path": it.path.display().to_string(), "file_name": it.file_name(), "size": it.size},
        "hashes": it.hashes.iter().map(|(a, h)| (a.name().to_string(), json!(h))).collect::<serde_json::Map<_, _>>(),
        "examiner": run.actor,
        "operations": [{"tool": run.tool_name, "version": run.tool_version, "start_utc": run.started_utc, "end_utc": run.finished_utc,
                        "audit_first_seq": it.audit_first_seq, "audit_last_seq": it.audit_last_seq}],
        "transfers": [],
    })
}

pub fn custody_pdf(ctx: &Value, run: &RunInfo) -> Result<Vec<u8>, String> {
    let c = |k: &str| s(ctx, &format!("custody.{}", k));
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let mut b = vec![
        Block::Title(c("title")),
        Block::Subtitle(format!(
            "{}: {} \u{00B7} {}: {}",
            t("jurisdiction"),
            c("jurisdiction_label"),
            t("run_id"),
            s(ctx, "run.run_id")
        )),
        Block::Note(c("basis")),
        Block::Kv(vec![
            (c("case_label"), s(ctx, "run.case_id")),
            (c("evidence_id_label"), c("evidence_id")),
            (
                c("description"),
                format!(
                    "{} \u{00B7} {} bytes \u{00B7} {}",
                    s(ctx, "item.file_name"),
                    s(ctx, "item.size"),
                    s(ctx, "item.detected_text")
                ),
            ),
            (c("location"), s(ctx, "item.path")),
        ]),
        Block::Heading(c("integrity")),
        Block::Kv(
            arr(ctx, "hash_rows")
                .iter()
                .map(|h| (s(h, "algorithm"), s(h, "value")))
                .collect(),
        ),
        Block::Heading(c("operations")),
        Block::Para(c("operation_text")),
        Block::Kv(vec![(c("examiner"), s(ctx, "run.actor"))]),
        Block::Heading(c("transfers")),
        Block::Grid {
            header: vec![
                c("date_time"),
                c("delivered_by"),
                c("received_by"),
                c("purpose"),
                c("condition"),
            ],
            widths: vec![80.0, 120.0, 120.0, 80.0, 95.0],
            rows: BLANK_TRANSFER_ROWS,
            row_h: 30.0,
        },
        Block::Heading(c("observations")),
        Block::Grid {
            header: vec![String::new()],
            widths: vec![495.0],
            rows: 2,
            row_h: 30.0,
        },
        Block::SignLines(vec![
            format!(
                "{}: {} \u{2014} {}",
                c("examiner"),
                s(ctx, "run.actor"),
                c("signature_line")
            ),
            format!("{} \u{2014} {}", c("received_by"), c("signature_line")),
        ]),
    ];
    if let Some(Block::Kv(rows)) = b.get_mut(3) {
        if s(ctx, "run.case_id").is_empty() {
            rows[0].1 = String::new();
        }
        if !c("intake_utc").is_empty() {
            rows.insert(2, (c("intake_date"), c("intake_utc")));
        }
    }
    finish(ctx, &c("title"), &b, run)
}

// ---------- Writing ----------

/// Writes bytes and returns (file name, digests) for the audit log.
pub fn write_hashed(
    dir: &Path,
    name: &str,
    data: &[u8],
    algos: &[HashAlgo],
) -> Result<(String, Value), String> {
    let p = dir.join(name);
    std::fs::write(&p, data).map_err(|e| format!("cannot write {}: {}", p.display(), e))?;
    let digests: serde_json::Map<String, Value> = algos
        .iter()
        .map(|a| (a.name().to_string(), json!(hash_bytes(data, *a))))
        .collect();
    Ok((name.to_string(), Value::Object(digests)))
}

pub fn pretty(v: &Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(v).expect("serializable");
    s.push('\n');
    s.into_bytes()
}

/// Writes the six (or more, with several languages) report files of one item. Returns {file: digests}.
pub fn write_item_reports(
    dir: &Path,
    run: &RunInfo,
    it: &ItemResult,
    audit: &AuditRef,
) -> Result<serde_json::Map<String, Value>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
    let algos = &run.algorithms;
    let mut files = serde_json::Map::new();
    let mut put = |r: Result<(String, Value), String>| -> Result<(), String> {
        let (n, d) = r?;
        files.insert(n, d);
        Ok(())
    };
    put(write_hashed(
        dir,
        "technical.json",
        &pretty(&technical_json(run, it)),
        algos,
    ))?;
    put(write_hashed(
        dir,
        "summary.json",
        &pretty(&summary_json(run, it)),
        algos,
    ))?;
    for lang in &run.langs {
        let ctx = item_context(lang, run, it, audit);
        put(write_hashed(
            dir,
            &format!("technical.{}.html", lang),
            render_html("technical.html", &ctx)?.as_bytes(),
            algos,
        ))?;
        put(write_hashed(
            dir,
            &format!("summary.{}.html", lang),
            render_html("summary.html", &ctx)?.as_bytes(),
            algos,
        ))?;
        put(write_hashed(
            dir,
            &format!("technical.{}.pdf", lang),
            &technical_pdf(&ctx, run)?,
            algos,
        ))?;
        put(write_hashed(
            dir,
            &format!("summary.{}.pdf", lang),
            &summary_pdf(&ctx, run)?,
            algos,
        ))?;
    }
    put(write_hashed(
        dir,
        "custody.json",
        &pretty(&custody_json(run, it)),
        algos,
    ))?;
    for lang in custody_langs(&run.jurisdiction) {
        let ctx = custody_context(&lang, run, it, audit);
        put(write_hashed(
            dir,
            &format!("custody.{}.html", lang),
            render_html("custody.html", &ctx)?.as_bytes(),
            algos,
        ))?;
        put(write_hashed(
            dir,
            &format!("custody.{}.pdf", lang),
            &custody_pdf(&ctx, run)?,
            algos,
        ))?;
    }
    Ok(files)
}

pub fn write_statistics(
    dir: &Path,
    run: &RunInfo,
    items: &[ItemResult],
    totals: &RunTotals,
    audit: &AuditRef,
) -> Result<serde_json::Map<String, Value>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
    let algos = &run.algorithms;
    let mut files = serde_json::Map::new();
    let (n, d) = write_hashed(
        dir,
        "statistics.json",
        &pretty(&statistics_json(run, items, totals, audit)),
        algos,
    )?;
    files.insert(n, d);
    for lang in &run.langs {
        let ctx = statistics_context(lang, run, items, totals, audit);
        let (n, d) = write_hashed(
            dir,
            &format!("statistics.{}.html", lang),
            render_html("statistics.html", &ctx)?.as_bytes(),
            algos,
        )?;
        files.insert(n, d);
        let (n, d) = write_hashed(
            dir,
            &format!("statistics.{}.pdf", lang),
            &statistics_pdf(&ctx, run)?,
            algos,
        )?;
        files.insert(n, d);
    }
    Ok(files)
}
