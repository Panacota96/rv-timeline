//! Everything the window shows and every rule it enforces, without any drawing code.
//! Kept separate from `app.rs` so it can be unit-tested headless (CI has no display).
//!
//! ```text
//! settings (each change = ui_* entry with at_utc) ──► to_config ──► RunConfig + TimelineOptions ──► run_timeline
//! finished build ──► TimelineView::load (audited outputs only) ──► runs, signals, timeline list
//!                     every view, refusal, selection ──► review.jsonl (chained to the build's run_finished)
//! ```

use crate::viewer::{Filters, TimelineView, latest_timeline_run, parse_utc};
use rv_timeline_core::model::{Severity, TimelineOptions};
use rv_timeline_core::{
    CaseRole, Event, HashAlgo, RunConfig, TOOL_NAME, TOOL_VERSION, engine::DisplayZone, i18n,
    time::human_duration,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub enum Phase {
    Idle,
    Running,
    Finished,
    Cancelled,
    Failed(String),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
    pub elapsed_ms: u64,
    pub eta_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Outcome {
    pub items: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    pub report: PathBuf,
    pub log_dir: PathBuf,
    /// `<CASE>/runs/rv-timeline/<RUN-ID>`
    pub run_dir: PathBuf,
}

/// What the case folder holds, read (and verified) when it is chosen.
#[derive(Clone, Debug, PartialEq)]
pub struct CaseSummary {
    pub case_id: String,
    pub items: usize,
    pub jurisdiction: String,
}

/// Display zones offered in the list (any fixed offset can also be typed).
pub const ZONE_CHOICES: [&str; 3] = ["UTC", "America/Bogota", "Europe/Paris"];

/// Tools this version reads (the tools filter).
pub fn supported_tools() -> Vec<String> {
    let mut t: Vec<String> = rv_timeline_core::readers::supported_versions()
        .into_iter()
        .map(|(tool, _)| tool)
        .collect();
    t.dedup();
    t
}

#[derive(Debug)]
pub struct GuiState {
    pub case_dir: String,
    pub case_summary: Option<CaseSummary>,
    pub case_error: Option<String>,
    /// Canonical display zone name (`UTC`, `UTC-05:00`, `America/Bogota`, `Europe/Paris`).
    pub display_zone: String,
    /// Tools to read; empty = every supported tool.
    pub tools: Vec<String>,
    /// UTC window as typed, and as parsed.
    pub from_text: String,
    pub to_text: String,
    pub from_s: Option<i64>,
    pub to_s: Option<i64>,
    pub clock_skew_s: u64,
    pub max_events: u64,
    pub timesketch: bool,
    /// Report language(s).
    pub lang: String,
    pub actor: String,
    pub phase: Phase,
    pub progress: Progress,
    pub current_item: String,
    pub warnings: Vec<String>,
    pub outcome: Option<Outcome>,
    /// User actions recorded before the run; handed to the core as audit preamble entries.
    pub ui_actions: Vec<(String, Value)>,
    /// Interface language (en/es/fr), independent from the report language.
    pub ui_lang: String,
    pub timestamp: bool,
    pub tsa_url: String,
    pub sign_cert: String,
    /// Kept in memory only; never logged.
    pub sign_password: String,
    // ---- results / timeline viewer ----
    pub view: Option<TimelineView>,
    pub view_error: Option<String>,
    /// The full-window timeline page is shown.
    pub view_page: bool,
    pub filters: Filters,
    pub filter_from_text: String,
    pub filter_to_text: String,
    /// Rows (event indices) passing the filters, in timeline order.
    pub filtered: Vec<u32>,
    /// Times shown first in the build's display zone (else UTC first).
    pub zone_first: bool,
    pub selected_signal: Option<usize>,
    pub selected_event: Option<u32>,
    /// Position in `filtered` the list should scroll to (consumed by the window).
    pub scroll_to: Option<usize>,
    /// Last failure to write the review log (the entry then goes to the next build's audit preamble).
    pub review_error: Option<String>,
}

impl Default for GuiState {
    fn default() -> Self {
        let o = TimelineOptions::default();
        GuiState {
            case_dir: String::new(),
            case_summary: None,
            case_error: None,
            display_zone: o.display_zone,
            tools: o.tools,
            from_text: String::new(),
            to_text: String::new(),
            from_s: o.from_s,
            to_s: o.to_s,
            clock_skew_s: o.clock_skew_s,
            max_events: o.max_events,
            timesketch: o.timesketch,
            lang: "en".into(),
            actor: rv_timeline_core::env::os_user(),
            phase: Phase::Idle,
            progress: Progress::default(),
            current_item: String::new(),
            warnings: vec![],
            outcome: None,
            ui_actions: vec![],
            ui_lang: "en".into(),
            timestamp: true,
            tsa_url: rv_timeline_core::trust::DEFAULT_TSA.into(),
            sign_cert: String::new(),
            sign_password: String::new(),
            view: None,
            view_error: None,
            view_page: false,
            filters: Filters::default(),
            filter_from_text: String::new(),
            filter_to_text: String::new(),
            filtered: vec![],
            zone_first: false,
            selected_signal: None,
            selected_event: None,
            scroll_to: None,
            review_error: None,
        }
    }
}

fn sev_name(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

impl GuiState {
    /// Records a user action with the time it happened (written to the audit log when the build starts).
    fn note(&mut self, action: &str, mut details: Value) {
        if let Some(o) = details.as_object_mut() {
            o.insert("at_utc".into(), json!(rv_timeline_core::time::utc_now()));
        }
        self.ui_actions.push((action.to_string(), details));
    }

    pub fn is_running(&self) -> bool {
        self.phase == Phase::Running
    }

    /// GUI text in the interface language.
    pub fn tr(&self, key: &str) -> String {
        i18n::catalog(&self.ui_lang).ui(key)
    }

    // ---------------------------------------------------------------- settings

    /// The case folder to build the timeline of; it is opened (and verified) at once to show its id.
    pub fn set_case_dir(&mut self, path: &str) {
        let path = path.trim().trim_matches('"').to_string();
        if self.case_dir == path {
            return;
        }
        self.case_dir = path.clone();
        self.note(
            "ui_case_dir_changed",
            json!({"path": if path.is_empty() { Value::Null } else { json!(path) }, "role": CaseRole::Analysis.name()}),
        );
        self.refresh_case();
    }

    /// Re-reads the case folder's id and registry size (after a build, or when the folder is chosen).
    pub fn refresh_case(&mut self) {
        self.case_summary = None;
        self.case_error = None;
        if self.case_dir.is_empty() {
            return;
        }
        match rv_timeline_core::case::Case::open(Path::new(&self.case_dir)) {
            Ok(c) => {
                self.case_summary = Some(CaseSummary {
                    case_id: c.case_id,
                    items: c.items.len(),
                    jurisdiction: c.jurisdiction,
                })
            }
            Err(e) => self.case_error = Some(e.message),
        }
    }

    /// The case folder given by RV Hub (`--case-dir`): preset like a chosen folder (`ui_case_dir_changed`) and
    /// recorded as `ui_case_dir_from_launcher`, so the audit log shows the folder was not chosen in the GUI.
    pub fn set_case_dir_from_launcher(&mut self, path: &Path) {
        let shown = path.display().to_string();
        self.note("ui_case_dir_from_launcher", json!({"path": shown}));
        self.set_case_dir(&shown);
    }

    /// A launch argument that was ignored (e.g. `--case-dir` without a folder), recorded in the audit log.
    pub fn note_launch_problem(&mut self, problem: &str) {
        self.note("ui_launch_argument_ignored", json!({"problem": problem}));
    }

    /// `UTC`, a fixed offset (`-05:00`), `America/Bogota` or `Europe/Paris`; stored under its canonical name.
    pub fn set_display_zone(&mut self, zone: &str) -> Result<(), String> {
        let z = DisplayZone::parse(zone)?.name();
        if self.display_zone != z {
            self.display_zone = z.clone();
            self.note("ui_display_zone_changed", json!({"display_zone": z}));
        }
        Ok(())
    }

    /// Whether `tool` is read (every tool is, while the filter is empty).
    pub fn tool_selected(&self, tool: &str) -> bool {
        self.tools.is_empty() || self.tools.iter().any(|t| t == tool)
    }

    /// Ticks or unticks one tool. Ticking every tool clears the filter (= all tools); at least one stays.
    pub fn set_tool(&mut self, tool: &str, on: bool) -> Result<(), String> {
        let all = supported_tools();
        if !all.iter().any(|t| t == tool) {
            return Err(format!("{} is not a supported tool", tool));
        }
        let mut chosen: Vec<String> = all
            .iter()
            .filter(|t| self.tool_selected(t))
            .cloned()
            .collect();
        if on && !chosen.iter().any(|t| t == tool) {
            chosen.push(tool.to_string());
        } else if !on {
            chosen.retain(|t| t != tool);
        }
        if chosen.is_empty() {
            return Err(self.tr("tools_one"));
        }
        let new: Vec<String> = if chosen.len() == all.len() {
            vec![]
        } else {
            all.into_iter().filter(|t| chosen.contains(t)).collect()
        };
        if new != self.tools {
            self.tools = new;
            self.note(
                "ui_tools_filter_changed",
                json!({"tools": self.tools, "all": self.tools.is_empty()}),
            );
        }
        Ok(())
    }

    /// The UTC window (`from`, `to`, inclusive). Empty texts = no bound; a date alone covers the whole day.
    pub fn set_window(&mut self, from: &str, to: &str) -> Result<(), String> {
        let f = parse_utc(from, false)?;
        let t = parse_utc(to, true)?;
        if let (Some(a), Some(b)) = (f, t)
            && a > b
        {
            return Err(self.tr("window_order"));
        }
        self.from_text = from.trim().to_string();
        self.to_text = to.trim().to_string();
        if (f, t) != (self.from_s, self.to_s) {
            self.from_s = f;
            self.to_s = t;
            self.note(
                "ui_window_changed",
                json!({"from_s": f, "to_s": t, "from": self.from_text, "to": self.to_text}),
            );
        }
        Ok(())
    }

    /// Tolerated clock difference between sources, seconds (0 to 7 days).
    pub fn set_clock_skew(&mut self, text: &str) -> Result<(), String> {
        let s: u64 = text
            .trim()
            .parse()
            .ok()
            .filter(|s| *s <= 7 * 86_400)
            .ok_or_else(|| self.tr("skew_invalid"))?;
        if s != self.clock_skew_s {
            self.clock_skew_s = s;
            self.note("ui_clock_skew_changed", json!({"clock_skew_s": s}));
        }
        Ok(())
    }

    /// Events read at most (at least 1); reaching it is reported as a limitation, never silently.
    pub fn set_max_events(&mut self, text: &str) -> Result<(), String> {
        let n: u64 = text
            .trim()
            .replace(['_', ' ', ','], "")
            .parse()
            .ok()
            .filter(|n| *n >= 1)
            .ok_or_else(|| self.tr("max_events_invalid"))?;
        if n != self.max_events {
            self.max_events = n;
            self.note("ui_max_events_changed", json!({"max_events": n}));
        }
        Ok(())
    }

    /// Whether timeline.jsonl (Timesketch import) is written.
    pub fn set_timesketch(&mut self, on: bool) {
        if self.timesketch != on {
            self.timesketch = on;
            self.note("ui_timesketch_changed", json!({"timesketch": on}));
        }
    }

    pub fn set_lang(&mut self, l: &str) {
        if self.lang != l {
            self.lang = l.to_string();
            self.note("ui_language_changed", json!({"lang": l}));
        }
    }

    pub fn set_ui_lang(&mut self, l: &str) {
        if self.ui_lang != l && ["en", "es", "fr"].contains(&l) {
            self.ui_lang = l.to_string();
            self.note("ui_interface_language_changed", json!({"ui_lang": l}));
        }
    }

    pub fn set_timestamp(&mut self, on: bool, url: &str) {
        let url = url.trim().to_string();
        if self.timestamp != on || self.tsa_url != url {
            self.timestamp = on;
            self.tsa_url = url.clone();
            self.note(
                "ui_timestamp_changed",
                json!({"enabled": on, "tsa_url": url}),
            );
        }
    }

    pub fn set_sign_cert(&mut self, path: &str) {
        let path = path.trim().trim_matches('"').to_string();
        if self.sign_cert != path {
            self.sign_cert = path.clone();
            self.note(
                "ui_signing_certificate_changed",
                json!({"path": if path.is_empty() { Value::Null } else { json!(path) }}),
            );
        }
    }

    /// What the output field shows: the build is written inside the case folder.
    pub fn out_dir_display(&self) -> String {
        PathBuf::from(self.case_dir.trim())
            .join("runs")
            .join(TOOL_NAME)
            .join("<RUN-ID>")
            .display()
            .to_string()
    }

    pub fn can_start(&self) -> bool {
        !self.is_running() && !self.case_dir.trim().is_empty() && self.case_error.is_none()
    }

    /// The build's options exactly as the CLI flags would give them.
    pub fn timeline_options(&self) -> TimelineOptions {
        TimelineOptions {
            case_dir: PathBuf::from(self.case_dir.trim()),
            display_zone: self.display_zone.clone(),
            tools: self.tools.clone(),
            from_s: self.from_s,
            to_s: self.to_s,
            clock_skew_s: self.clock_skew_s,
            max_events: self.max_events,
            timesketch: self.timesketch,
        }
    }

    /// Builds the run configuration; the recorded UI actions become audit preamble entries.
    pub fn to_config(&self) -> Result<(RunConfig, TimelineOptions), String> {
        if self.case_dir.trim().is_empty() {
            return Err(self.tr("need_case"));
        }
        if let Some(e) = &self.case_error {
            return Err(e.clone());
        }
        let langs = i18n::parse_langs(&self.lang)?;
        if !self.sign_cert.is_empty() && !Path::new(&self.sign_cert).is_file() {
            return Err(format!("Signing certificate not found: {}", self.sign_cert));
        }
        let opts = self.timeline_options();
        let mut preamble = self.ui_actions.clone();
        preamble.push((
            "ui_start_clicked".into(),
            json!({"case_dir": self.case_dir.trim(), "display_zone": opts.display_zone, "tools": opts.tools,
                   "from_s": opts.from_s, "to_s": opts.to_s, "clock_skew_s": opts.clock_skew_s,
                   "max_events": opts.max_events, "timesketch": opts.timesketch, "lang": self.lang,
                   "timestamp": self.timestamp, "pdf_signing": !self.sign_cert.is_empty(),
                   "at_utc": rv_timeline_core::time::utc_now()}),
        ));
        let opt = |v: Option<i64>| v.map_or("none".to_string(), |s| s.to_string());
        let settings = vec![
            format!("{} (gui)", TOOL_NAME),
            format!("case_dir={}", self.case_dir.trim()),
            format!("display_zone={}", opts.display_zone),
            format!(
                "tools={}",
                if opts.tools.is_empty() {
                    "all".to_string()
                } else {
                    opts.tools.join(",")
                }
            ),
            format!("from_s={}", opt(opts.from_s)),
            format!("to_s={}", opt(opts.to_s)),
            format!("clock_skew_s={}", opts.clock_skew_s),
            format!("max_events={}", opts.max_events),
            format!("timesketch={}", opts.timesketch),
            format!("lang={}", self.lang),
            format!(
                "tsa={}",
                if self.timestamp {
                    self.tsa_url.as_str()
                } else {
                    "off"
                }
            ),
            format!(
                "sign_cert={}",
                if self.sign_cert.is_empty() {
                    "none"
                } else {
                    self.sign_cert.as_str()
                }
            ),
        ];
        let cfg = RunConfig {
            algorithms: vec![HashAlgo::Sha256],
            langs,
            actor: self.actor_name(),
            case_id: None,
            frontend: "gui".into(),
            preamble,
            command_line: settings,
            tool_name: TOOL_NAME.into(),
            tool_version: TOOL_VERSION.into(),
            tsa_url: self.timestamp.then(|| self.tsa_url.clone()),
            sign_cert: (!self.sign_cert.is_empty()).then(|| PathBuf::from(&self.sign_cert)),
            sign_password: (!self.sign_password.is_empty()).then(|| self.sign_password.clone()),
            case_dir: Some(PathBuf::from(self.case_dir.trim())),
            case_role: CaseRole::Analysis,
            ..Default::default()
        };
        Ok((cfg, opts))
    }

    fn actor_name(&self) -> String {
        if self.actor.trim().is_empty() {
            rv_timeline_core::env::os_user()
        } else {
            self.actor.trim().to_string()
        }
    }

    // ---------------------------------------------------------------- the build

    pub fn start(&mut self) {
        self.phase = Phase::Running;
        self.progress = Progress::default();
        self.current_item.clear();
        self.warnings.clear();
        self.outcome = None;
        self.close_view();
        self.view = None;
        self.view_error = None;
        // Recorded actions now belong to this build's audit log.
        self.ui_actions.clear();
    }

    pub fn apply(&mut self, e: &Event) {
        match e {
            Event::RunStarted { total_items, .. } => self.progress.total = *total_items,
            Event::ItemStarted { path, .. } => self.current_item = path.clone(),
            Event::ItemFinished {
                path,
                status,
                findings,
                ..
            } if status == "excluded" => self.warnings.push(format!(
                "{}: {} ({})",
                path,
                self.tr("excluded"),
                findings.join(", ")
            )),
            Event::Progress {
                done,
                total,
                elapsed_ms,
                eta_ms,
                ..
            } => {
                self.progress = Progress {
                    done: *done,
                    total: *total,
                    elapsed_ms: *elapsed_ms,
                    eta_ms: *eta_ms,
                };
            }
            Event::Error { path, message } => {
                self.warnings
                    .push(format!("{}: {}", path.as_deref().unwrap_or("-"), message))
            }
            Event::RunFinished {
                items,
                high,
                medium,
                low,
                info,
                report_dir,
                log_dir,
                cancelled,
                elapsed_ms,
                ..
            } => {
                self.progress.elapsed_ms = *elapsed_ms;
                self.progress.eta_ms = None;
                let lang = if self.lang == "all" {
                    "en".to_string()
                } else {
                    self.lang.clone()
                };
                let report_dir = PathBuf::from(report_dir);
                self.outcome = Some(Outcome {
                    items: *items,
                    high: *high,
                    medium: *medium,
                    low: *low,
                    info: *info,
                    report: report_dir.join(format!("statistics.{}.html", lang)),
                    log_dir: PathBuf::from(log_dir),
                    run_dir: report_dir
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_default(),
                });
                self.phase = if *cancelled {
                    Phase::Cancelled
                } else {
                    Phase::Finished
                };
                self.current_item.clear();
            }
            _ => {}
        }
    }

    pub fn fail(&mut self, msg: String) {
        self.phase = Phase::Failed(msg);
    }

    /// 0.0..=1.0, by runs examined.
    pub fn fraction(&self) -> f32 {
        let p = &self.progress;
        // Skipped runs (own runs, tools filter) send no progress: a finished build is complete.
        if matches!(self.phase, Phase::Finished) {
            1.0
        } else if p.total > 0 {
            (p.done as f64 / p.total as f64).clamp(0.0, 1.0) as f32
        } else {
            0.0
        }
    }

    /// Remaining time: the core's estimate, else the average time per run so far.
    pub fn eta_ms(&self) -> Option<u64> {
        let p = &self.progress;
        p.eta_ms.or_else(|| {
            (p.done > 0 && p.total > p.done && p.elapsed_ms >= 500)
                .then(|| p.elapsed_ms * (p.total - p.done) / p.done)
        })
    }

    /// `live_elapsed_ms` is measured by the window clock so the timer keeps moving between events.
    pub fn timing_text(&self, live_elapsed_ms: Option<u64>) -> String {
        let elapsed = live_elapsed_ms
            .unwrap_or(self.progress.elapsed_ms)
            .max(self.progress.elapsed_ms);
        let eta = match self.eta_ms() {
            Some(ms) if self.is_running() => human_duration(ms),
            _ => "\u{2014}".into(),
        };
        format!(
            "{}: {}   \u{00B7}   {}: {}",
            self.tr("elapsed"),
            human_duration(elapsed),
            self.tr("remaining"),
            eta
        )
    }

    pub fn progress_text(&self) -> String {
        format!(
            "{} / {} {}  \u{00B7}  {:.0}%",
            self.progress.done,
            self.progress.total,
            self.tr("runs_word"),
            self.fraction() * 100.0
        )
    }

    // ---------------------------------------------------------------- results and viewer

    /// Reads the finished build back from its audited outputs (results + timeline view).
    pub fn load_results(&mut self) -> bool {
        let Some(dir) = self.outcome.as_ref().map(|o| o.run_dir.clone()) else {
            return false;
        };
        self.refresh_case();
        self.open_run(&dir)
    }

    /// The latest timeline build of the chosen case folder, if any.
    pub fn latest_run(&self) -> Option<PathBuf> {
        if self.case_dir.trim().is_empty() {
            return None;
        }
        latest_timeline_run(Path::new(self.case_dir.trim()))
    }

    /// Opens a finished build. Shown only when statistics.json and timeline.jsonl match the digests in its audit
    /// log; both outcomes go to that build's review log (`ui_timeline_viewed` / `ui_timeline_refused`).
    pub fn open_run(&mut self, run_dir: &Path) -> bool {
        self.close_view();
        let mut details = json!({"run_dir": run_dir.display().to_string(),
                                 "at_utc": rv_timeline_core::time::utc_now()});
        match TimelineView::load(run_dir) {
            Ok(v) => {
                details["run_id"] = json!(v.run_id);
                details["files"] = json!(
                    v.files
                        .iter()
                        .map(|(f, h)| json!({"file": f, "sha256": h}))
                        .collect::<Vec<_>>()
                );
                details["digest_ok"] = json!(true);
                details["events"] = json!(v.len());
                details["signals"] = json!(v.signals.len());
                let log_dir = v.log_dir.clone();
                self.view = Some(v);
                self.view_error = None;
                self.filters = Filters::default();
                self.filter_from_text.clear();
                self.filter_to_text.clear();
                self.refilter();
                self.record_review(&log_dir, "ui_timeline_viewed", details);
                true
            }
            Err(e) => {
                details["digest_ok"] = json!(false);
                details["reason"] = json!(e);
                self.view = None;
                self.view_error = Some(e);
                self.filtered.clear();
                self.record_review(&run_dir.join("logs"), "ui_timeline_refused", details);
                false
            }
        }
    }

    pub fn open_view_page(&mut self) {
        if self.view.is_some() {
            self.view_page = true;
        }
    }

    pub fn close_view(&mut self) {
        self.view_page = false;
        self.selected_signal = None;
        self.selected_event = None;
        self.scroll_to = None;
    }

    fn refilter(&mut self) {
        self.filtered = self
            .view
            .as_ref()
            .map(|v| v.filter(&self.filters))
            .unwrap_or_default();
    }

    fn view_log(&self) -> Option<(PathBuf, String)> {
        self.view
            .as_ref()
            .map(|v| (v.log_dir.clone(), v.run_id.clone()))
    }

    /// Applies new viewer filters (recorded in the review log as `ui_timeline_filter_changed`).
    pub fn set_filters(&mut self, f: Filters) {
        if f == self.filters {
            return;
        }
        self.filters = f;
        self.refilter();
        if let Some((log, run_id)) = self.view_log() {
            let f = &self.filters;
            let details = json!({"run_id": run_id, "tool": f.tool, "item": f.item, "kind": f.kind,
                                 "severity": f.severity.map(sev_name), "from_s": f.from_s, "to_s": f.to_s,
                                 "rows": self.filtered.len(), "at_utc": rv_timeline_core::time::utc_now()});
            self.record_review(&log, "ui_timeline_filter_changed", details);
        }
    }

    /// The viewer's UTC window from typed texts.
    pub fn set_filter_window(&mut self, from: &str, to: &str) -> Result<(), String> {
        let a = parse_utc(from, false)?;
        let b = parse_utc(to, true)?;
        if let (Some(x), Some(y)) = (a, b)
            && x > y
        {
            return Err(self.tr("window_order"));
        }
        self.filter_from_text = from.trim().to_string();
        self.filter_to_text = to.trim().to_string();
        let mut f = self.filters.clone();
        f.from_s = a;
        f.to_s = b;
        self.set_filters(f);
        Ok(())
    }

    /// Shows times first in the build's display zone (`true`) or in UTC (`false`).
    pub fn set_zone_first(&mut self, on: bool) {
        if self.zone_first == on {
            return;
        }
        self.zone_first = on;
        if let Some((log, run_id)) = self.view_log() {
            let zone = self.view.as_ref().map(|v| v.display_zone.clone());
            self.record_review(
                &log,
                "ui_timeline_zone_toggled",
                json!({"run_id": run_id, "first": if on { zone } else { Some("UTC".into()) },
                       "at_utc": rv_timeline_core::time::utc_now()}),
            );
        }
    }

    /// Selects a signal: its events are highlighted and the list scrolls to the first one shown.
    pub fn select_signal(&mut self, n: Option<usize>) {
        if n == self.selected_signal {
            return;
        }
        let Some(v) = &self.view else { return };
        if n.is_some_and(|n| n >= v.signals.len()) {
            return;
        }
        self.selected_signal = n;
        let Some(n) = n else { return };
        let s = &v.signals[n];
        let rows = v.signal_rows[n].clone();
        let details = json!({"run_id": v.run_id, "code": s.code, "severity": sev_name(s.severity),
                             "events": s.events, "item": s.item.as_ref().map(|i| i.evidence_id.clone()),
                             "at_utc": rv_timeline_core::time::utc_now()});
        let log = v.log_dir.clone();
        self.scroll_to = rows
            .first()
            .and_then(|r| self.filtered.binary_search(r).ok());
        self.record_review(&log, "ui_signal_selected", details);
    }

    /// Whether row `i` belongs to the selected signal.
    pub fn highlighted(&self, i: u32) -> bool {
        match (self.selected_signal, &self.view) {
            (Some(n), Some(v)) => v.signal_rows[n].binary_search(&i).is_ok(),
            _ => false,
        }
    }

    /// Opens one event's details (recorded with its citation as `ui_event_viewed`).
    pub fn select_event(&mut self, i: Option<u32>) {
        if i == self.selected_event {
            return;
        }
        self.selected_event = i;
        let Some(i) = i else { return };
        let Some(v) = self.view.as_mut() else { return };
        let (log, run_id) = (v.log_dir.clone(), v.run_id.clone());
        let details = match v.row(i) {
            Ok(e) => json!({"run_id": run_id, "event_id": e.id, "row": i, "line_ok": true,
                            "source": {"run_dir": e.source.run_dir, "file": e.source.file,
                                       "file_sha256": e.source.file_sha256, "pointer": e.source.pointer},
                            "at_utc": rv_timeline_core::time::utc_now()}),
            Err(err) => json!({"run_id": run_id, "row": i, "line_ok": false, "reason": err,
                               "at_utc": rv_timeline_core::time::utc_now()}),
        };
        self.record_review(&log, "ui_event_viewed", details);
    }

    /// Writes one entry to the viewed build's hash-chained review log (`review.jsonl`, anchored to its
    /// `run_finished`). If that fails, the entry falls back to the next build's audit preamble and the error is
    /// kept for the status line.
    fn record_review(&mut self, log_dir: &Path, action: &str, details: Value) {
        match rv_timeline_core::review::append(log_dir, &self.actor_name(), action, details.clone())
        {
            Ok(_) => self.review_error = None,
            Err(e) => {
                self.review_error = Some(e);
                self.note(action, details);
            }
        }
    }

    /// Exclusion reason of a run in the interface language.
    pub fn exclusion_text(&self, reason: &str) -> String {
        i18n::catalog(&self.ui_lang)
            .text("exclusion", reason)
            .unwrap_or_else(|| reason.to_string())
    }

    /// (title, shows, does not prove) of signal `n` in the interface language.
    pub fn signal_texts(&self, n: usize) -> Option<(String, String, String)> {
        let s = self.view.as_ref()?.signals.get(n)?;
        let c = i18n::catalog(&self.ui_lang);
        let mut p = s.params.clone();
        if let Some(r) = s.params.get("reason") {
            p.insert(
                "reason_text".into(),
                c.text("exclusion", r).unwrap_or_else(|| r.clone()),
            );
        }
        Some(c.signal(&s.code, &p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actions(s: &GuiState) -> Vec<&str> {
        s.ui_actions.iter().map(|(a, _)| a.as_str()).collect()
    }

    fn last(s: &GuiState) -> &Value {
        &s.ui_actions.last().unwrap().1
    }

    fn stamped(d: &Value) -> bool {
        d["at_utc"].as_str().is_some_and(|t| t.ends_with('Z'))
    }

    pub(crate) fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            let t = to.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                copy_dir(&e.path(), &t);
            } else {
                std::fs::copy(e.path(), &t).unwrap();
            }
        }
    }

    pub(crate) fn sample_case(tag: &str) -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let dir = std::env::temp_dir().join(format!("rv-tl-gui-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        copy_dir(&root.join("examples/sample/case"), &dir);
        dir
    }

    #[test]
    fn defaults_match_the_core_options() {
        let s = GuiState::default();
        let o = TimelineOptions::default();
        let mine = s.timeline_options();
        assert_eq!(
            (
                mine.display_zone,
                mine.tools,
                mine.clock_skew_s,
                mine.max_events,
                mine.timesketch
            ),
            (
                o.display_zone,
                o.tools,
                o.clock_skew_s,
                o.max_events,
                o.timesketch
            )
        );
        assert!(!s.can_start(), "no case folder yet");
        assert!(s.to_config().is_err());
    }

    #[test]
    fn display_zone_is_validated_canonical_and_audited() {
        let mut s = GuiState::default();
        s.set_display_zone("america/bogota").unwrap();
        assert_eq!(s.display_zone, "America/Bogota");
        assert_eq!(actions(&s), ["ui_display_zone_changed"]);
        assert_eq!(last(&s)["display_zone"], "America/Bogota");
        assert!(stamped(last(&s)));
        s.set_display_zone("-05:00").unwrap();
        assert_eq!(s.display_zone, "UTC-05:00");
        s.set_display_zone("UTC-0500").unwrap();
        assert_eq!(s.ui_actions.len(), 2, "same zone: no new entry");
        assert!(s.set_display_zone("Mars/Olympus").is_err());
        assert_eq!(s.display_zone, "UTC-05:00", "a bad zone changes nothing");
        assert_eq!(s.ui_actions.len(), 2);
    }

    #[test]
    fn tools_filter_keeps_at_least_one_and_all_means_empty() {
        let mut s = GuiState::default();
        let all = supported_tools();
        assert!(all.len() >= 2 && all.iter().all(|t| s.tool_selected(t)));
        s.set_tool(&all[0], false).unwrap();
        assert!(!s.tool_selected(&all[0]));
        assert_eq!(s.tools.len(), all.len() - 1);
        assert_eq!(actions(&s), ["ui_tools_filter_changed"]);
        assert_eq!(last(&s)["all"], false);
        assert!(stamped(last(&s)));
        s.set_tool(&all[0], true).unwrap();
        assert!(s.tools.is_empty(), "every tool ticked = no filter");
        assert_eq!(last(&s)["all"], true);
        for t in &all[1..] {
            s.set_tool(t, false).unwrap();
        }
        assert_eq!(s.tools, vec![all[0].clone()]);
        assert!(s.set_tool(&all[0], false).is_err(), "the last tool stays");
        assert!(s.set_tool("rv-unknown", true).is_err());
        assert_eq!(s.timeline_options().tools, vec![all[0].clone()]);
    }

    #[test]
    fn window_is_parsed_ordered_and_audited() {
        let mut s = GuiState::default();
        s.set_window("2026-11-10", "2026-11-10").unwrap();
        assert_eq!(s.from_s, Some(1_794_268_800));
        assert_eq!(
            s.to_s,
            Some(1_794_268_800 + 86_399),
            "a date covers the day"
        );
        assert_eq!(actions(&s), ["ui_window_changed"]);
        assert_eq!(last(&s)["from_s"], 1_794_268_800i64);
        assert!(stamped(last(&s)));
        assert!(s.set_window("2026-11-11", "2026-11-10").is_err());
        assert!(s.set_window("soon", "").is_err());
        assert_eq!(s.ui_actions.len(), 1, "refused windows change nothing");
        s.set_window("", "").unwrap();
        assert_eq!((s.from_s, s.to_s), (None, None));
        assert_eq!(s.ui_actions.len(), 2);
    }

    #[test]
    fn skew_max_events_and_timesketch_are_audited() {
        let mut s = GuiState::default();
        s.set_clock_skew("120").unwrap();
        assert_eq!(s.clock_skew_s, 120);
        assert!(s.set_clock_skew("-1").is_err() && s.set_clock_skew("999999999").is_err());
        s.set_max_events("100_000").unwrap();
        assert_eq!(s.max_events, 100_000);
        assert!(s.set_max_events("0").is_err() && s.set_max_events("many").is_err());
        s.set_timesketch(false);
        s.set_timesketch(false);
        assert_eq!(
            actions(&s),
            [
                "ui_clock_skew_changed",
                "ui_max_events_changed",
                "ui_timesketch_changed"
            ]
        );
        assert_eq!(s.ui_actions[0].1["clock_skew_s"], 120);
        assert_eq!(s.ui_actions[1].1["max_events"], 100_000);
        assert_eq!(s.ui_actions[2].1["timesketch"], false);
        assert!(s.ui_actions.iter().all(|(_, d)| stamped(d)));
        let o = s.timeline_options();
        assert_eq!(
            (o.clock_skew_s, o.max_events, o.timesketch),
            (120, 100_000, false)
        );
    }

    #[test]
    fn languages_and_trust_settings_are_audited() {
        let mut s = GuiState::default();
        s.set_ui_lang("fr");
        assert_eq!(s.tr("start"), "Construire la chronologie");
        s.set_ui_lang("de");
        assert_eq!(s.ui_lang, "fr");
        s.set_lang("es");
        s.set_timestamp(false, "http://tsa.example");
        s.set_sign_cert("missing.p12");
        assert_eq!(
            actions(&s),
            [
                "ui_interface_language_changed",
                "ui_language_changed",
                "ui_timestamp_changed",
                "ui_signing_certificate_changed"
            ]
        );
        assert!(s.ui_actions.iter().all(|(_, d)| stamped(d)));
        s.sign_password = "secret-value".into();
        assert!(
            s.ui_actions
                .iter()
                .all(|(_, d)| !d.to_string().contains("secret-value"))
        );
    }

    #[test]
    fn case_folder_is_verified_and_feeds_the_config() {
        let mut s = GuiState {
            timestamp: false,
            ..Default::default()
        };
        let missing = std::env::temp_dir().join("rv-tl-gui-no-such-case");
        s.set_case_dir(&missing.display().to_string());
        assert!(s.case_error.is_some() && !s.can_start());
        assert!(s.to_config().is_err());
        let case = sample_case("cfg");
        s.set_case_dir(&format!("\"{}\"", case.display()));
        assert!(s.case_error.is_none(), "{:?}", s.case_error);
        assert_eq!(s.case_summary.as_ref().unwrap().case_id, "RV-SAMPLE-001");
        assert!(s.can_start());
        assert!(s.out_dir_display().contains("rv-timeline"));
        s.set_display_zone("Europe/Paris").unwrap();
        let (cfg, opts) = s.to_config().unwrap();
        assert_eq!(cfg.case_dir.as_deref(), Some(case.as_path()));
        assert_eq!(opts.case_dir, case);
        assert_eq!(opts.display_zone, "Europe/Paris");
        assert_eq!(cfg.frontend, "gui");
        let a: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(
            a,
            [
                "ui_case_dir_changed",
                "ui_case_dir_changed",
                "ui_display_zone_changed",
                "ui_start_clicked"
            ]
        );
        assert!(cfg.preamble.iter().all(|(_, d)| stamped(d)));
        let _ = std::fs::remove_dir_all(&case);
    }

    #[test]
    fn a_real_build_from_gui_settings_is_audited_and_viewed() {
        let case = sample_case("run");
        let mut s = GuiState {
            timestamp: false, // tests stay offline
            actor: "Examiner".into(),
            ..Default::default()
        };
        s.set_case_dir(&case.display().to_string());
        s.set_display_zone("America/Bogota").unwrap();
        s.set_clock_skew("300").unwrap();
        s.set_max_events("1000000").unwrap();
        let (cfg, opts) = s.to_config().unwrap();
        s.start();
        assert!(s.ui_actions.is_empty());
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let summary =
            rv_timeline_core::run::run_timeline(&cfg, &opts, &mut |e| s.apply(e), &cancel).unwrap();
        assert_eq!(s.phase, Phase::Finished);
        assert!((s.fraction() - 1.0).abs() < 1e-6);
        let log = std::fs::read_to_string(summary.log_dir.join("audit.jsonl")).unwrap();
        for a in [
            "\"ui_case_dir_changed\"",
            "\"ui_display_zone_changed\"",
            "\"ui_max_events_changed\"",
            "\"ui_start_clicked\"",
            "\"frontend\":\"gui\"",
        ] {
            assert!(log.contains(a), "{}", a);
        }
        assert!(s.load_results(), "{:?}", s.view_error);
        let v = s.view.as_ref().unwrap();
        assert_eq!(v.display_zone, "America/Bogota");
        assert!(v.runs.len() >= 6 && !v.is_empty());
        assert_eq!(s.filtered.len(), v.len());
        // The view is recorded in the build's review log, chained to its run_finished.
        assert_eq!(
            rv_timeline_core::review::verify(&summary.log_dir),
            Ok(Some(1))
        );
        if !v.signals.is_empty() {
            s.select_signal(Some(0));
            assert_eq!(
                rv_timeline_core::review::verify(&summary.log_dir),
                Ok(Some(2))
            );
        }
        let review = std::fs::read_to_string(summary.log_dir.join("review.jsonl")).unwrap();
        assert!(review.contains("\"ui_timeline_viewed\"") && review.contains("timeline.jsonl"));
        assert!(s.review_error.is_none());
        let _ = std::fs::remove_dir_all(&case);
    }

    #[test]
    fn eta_from_runs_done() {
        let mut s = GuiState::default();
        s.start();
        s.apply(&Event::Progress {
            done: 1,
            total: 4,
            bytes_done: 0,
            bytes_total: 0,
            elapsed_ms: 2_000,
            eta_ms: None,
        });
        assert_eq!(s.eta_ms(), Some(6_000));
        assert!(s.timing_text(Some(2_500)).contains("6.0 s"));
        assert!(s.progress_text().starts_with("1 / 4"));
        assert!((s.fraction() - 0.25).abs() < 1e-6);
    }
}
