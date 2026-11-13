//! The window. Drawing only: rules live in `state.rs` and `viewer.rs`, work lives in the core (worker thread).
//! Rakvor dark theme; interface language EN/ES/FR switchable at any time (texts from i18n "ui").

use crate::state::{GuiState, Phase, ZONE_CHOICES, supported_tools};
use crate::viewer::Filters;
use eframe::egui;
use rv_timeline_core::engine::{self, DisplayZone};
use rv_timeline_core::model::{RunStatus, Severity, TimeEvent, ZoneInfo};
use rv_timeline_core::{Event, RunSummary, TOOL_VERSION, i18n};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

// Rakvor palette
const NIGHT: egui::Color32 = egui::Color32::from_rgb(0x0D, 0x11, 0x17);
const NIGHT2: egui::Color32 = egui::Color32::from_rgb(0x1A, 0x1F, 0x26);
const BLUE: egui::Color32 = egui::Color32::from_rgb(0x2A, 0x5C, 0xFF);
const VIOLET: egui::Color32 = egui::Color32::from_rgb(0x6B, 0x00, 0xFF);
const CYAN: egui::Color32 = egui::Color32::from_rgb(0x00, 0xE5, 0xFF);
const MIST: egui::Color32 = egui::Color32::from_rgb(0xE6, 0xE6, 0xE6);
const GREY: egui::Color32 = egui::Color32::from_rgb(0x9A, 0xA4, 0xB2);
const AMBER: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xB0, 0x40);
const RED: egui::Color32 = egui::Color32::from_rgb(0xFF, 0x6B, 0x6B);
const GREEN: egui::Color32 = egui::Color32::from_rgb(0x4C, 0xD9, 0x7B);
const UI_LANGS: [(&str, &str); 3] = [("en", "English"), ("es", "Español"), ("fr", "Français")];
/// Height of one timeline row (two text lines); every row has it, so only visible rows are drawn.
const ROW_H: f32 = 40.0;

enum Msg {
    Event(Event),
    Done(Result<RunSummary, String>),
}

pub struct HashInvApp {
    state: GuiState,
    rx: Option<Receiver<Msg>>,
    cancel: Arc<AtomicBool>,
    started: Option<Instant>,
    notice: Option<String>,
    themed: bool,
    /// Texts being typed; applied (and audited) when the field loses focus.
    case_entry: String,
    zone_entry: String,
    from_entry: String,
    to_entry: String,
    skew_entry: String,
    max_entry: String,
}

/// Applies the Rakvor dark theme.
pub fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = NIGHT;
    v.window_fill = NIGHT2;
    v.extreme_bg_color = NIGHT2; // text fields
    v.widgets.inactive.bg_stroke =
        egui::Stroke::new(1.0, egui::Color32::from_rgb(0x2B, 0x32, 0x40));
    v.widgets.noninteractive.bg_stroke =
        egui::Stroke::new(1.0, egui::Color32::from_rgb(0x2B, 0x32, 0x40));
    v.faint_bg_color = NIGHT2;
    v.override_text_color = Some(MIST);
    v.selection.bg_fill = BLUE;
    v.hyperlink_color = CYAN;
    v.widgets.inactive.bg_fill = NIGHT2;
    v.widgets.inactive.weak_bg_fill = NIGHT2;
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, CYAN);
    v.widgets.active.bg_fill = BLUE;
    ctx.set_visuals(v);
}

/// Interface texts in `lang`, without borrowing the state (drawing code mutates it meanwhile).
fn translator(lang: &str) -> impl Fn(&str) -> String + use<> {
    let c = i18n::catalog(lang);
    move |k: &str| c.ui(k)
}

fn sev_color(s: Severity) -> egui::Color32 {
    match s {
        Severity::High => RED,
        Severity::Medium => AMBER,
        Severity::Low => CYAN,
        Severity::Info => GREY,
    }
}

fn sev_key(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

impl HashInvApp {
    pub fn new() -> Self {
        Self::from_state(GuiState::default())
    }

    /// A window over an existing state (tests, documentation screenshots).
    pub fn from_state(state: GuiState) -> Self {
        HashInvApp {
            case_entry: state.case_dir.clone(),
            zone_entry: if ZONE_CHOICES.contains(&state.display_zone.as_str()) {
                String::new()
            } else {
                state.display_zone.clone()
            },
            from_entry: state.from_text.clone(),
            to_entry: state.to_text.clone(),
            skew_entry: state.clock_skew_s.to_string(),
            max_entry: state.max_events.to_string(),
            state,
            rx: None,
            cancel: Arc::new(AtomicBool::new(false)),
            started: None,
            notice: None,
            themed: false,
        }
    }

    pub fn state(&self) -> &GuiState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut GuiState {
        &mut self.state
    }

    /// Starts from the executable's arguments: `--case-dir DIR` (RV Hub), or a case folder dropped on the .exe.
    pub fn from_launch(args: crate::launch::LaunchArgs) -> Self {
        let mut s = GuiState::default();
        let mut notes = args.notes.clone();
        let mut inputs = args.inputs.into_iter();
        if let Some(dir) = args.case_dir {
            s.set_case_dir_from_launcher(&dir);
        } else if let Some(first) = inputs.next() {
            s.set_case_dir(&first.display().to_string());
        }
        for extra in inputs {
            notes.push(format!(
                "{}: ignored (one case folder per timeline)",
                extra.display()
            ));
        }
        for n in &notes {
            s.note_launch_problem(n);
        }
        let mut app = Self::from_state(s);
        if !notes.is_empty() {
            app.notice = Some(notes.join("\n"));
        }
        app
    }

    fn start(&mut self, ctx: &egui::Context) {
        let (cfg, opts) = match self.state.to_config() {
            Ok(c) => c,
            Err(e) => {
                self.notice = Some(e);
                return;
            }
        };
        self.notice = None;
        self.state.start();
        self.cancel.store(false, Ordering::SeqCst);
        self.started = Some(Instant::now());
        let (tx, rx) = channel();
        self.rx = Some(rx);
        let cancel = self.cancel.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let tx2 = tx.clone();
            let r2 = repaint.clone();
            let mut sink = move |e: &Event| {
                let _ = tx2.send(Msg::Event(e.clone()));
                r2.request_repaint();
            };
            let result = rv_timeline_core::run::run_timeline(&cfg, &opts, &mut sink, &cancel);
            let _ = tx.send(Msg::Done(result));
            repaint.request_repaint();
        });
    }

    fn drain(&mut self) {
        let Some(rx) = &self.rx else { return };
        let mut done = None;
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Event(e) => {
                    if let Event::Timestamp { status, reason, .. } = &e
                        && status != "ok"
                    {
                        self.state
                            .warnings
                            .push(format!("timestamp: {}", reason.as_deref().unwrap_or("-")));
                    }
                    self.state.apply(&e)
                }
                Msg::Done(r) => done = Some(r),
            }
        }
        if let Some(r) = done {
            self.rx = None;
            self.started = None;
            match r {
                Ok(_) => {
                    self.state.load_results();
                }
                Err(e) => self.state.fail(e),
            }
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(38.0, 38.0), egui::Sense::hover());
            ui.painter().rect(
                rect,
                8.0,
                NIGHT2,
                egui::Stroke::new(2.0, BLUE),
                egui::StrokeKind::Inside,
            );
            ui.painter().text(
                rect.center() - egui::vec2(0.0, 3.0),
                egui::Align2::CENTER_CENTER,
                "RV",
                egui::FontId::proportional(16.0),
                MIST,
            );
            ui.painter().line_segment(
                [
                    rect.center() + egui::vec2(-8.0, 10.0),
                    rect.center() + egui::vec2(8.0, 10.0),
                ],
                egui::Stroke::new(2.0, CYAN),
            );
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("R A K V O R").strong().size(16.0));
                let desc = i18n::catalog(&self.state.ui_lang).brand()["descriptor"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                ui.label(egui::RichText::new(desc).color(CYAN).size(10.0));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let current = UI_LANGS
                    .iter()
                    .find(|(k, _)| *k == self.state.ui_lang)
                    .map(|(_, v)| *v)
                    .unwrap_or("English");
                let mut chosen = None;
                egui::ComboBox::from_id_salt("ui-lang")
                    .selected_text(current)
                    .show_ui(ui, |ui| {
                        for (k, v) in UI_LANGS {
                            if ui.selectable_label(self.state.ui_lang == k, v).clicked() {
                                chosen = Some(k);
                            }
                        }
                    });
                if let Some(k) = chosen {
                    self.state.set_ui_lang(k);
                }
                ui.label(self.state.tr("ui_lang"));
                ui.weak(format!("RV Timeline v{}", TOOL_VERSION));
            });
        });
        ui.weak(self.state.tr("audit_note"));
        let (r, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 3.0), egui::Sense::hover());
        let third = r.width() / 3.0;
        for (i, c) in [BLUE, VIOLET, CYAN].iter().enumerate() {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(
                    r.min + egui::vec2(third * i as f32, 0.0),
                    egui::vec2(third, 3.0),
                ),
                0.0,
                *c,
            );
        }
    }

    fn section_title(ui: &mut egui::Ui, text: String) {
        ui.add_space(4.0);
        ui.label(egui::RichText::new(text).color(CYAN).strong().size(15.0));
    }

    fn case_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("case_section"));
        ui.label(self.state.tr("case_help"));
        ui.add_enabled_ui(enabled, |ui| {
            ui.horizontal(|ui| {
                ui.label(self.state.tr("case_dir"));
                let hint = self.state.tr("case_dir_hint");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.case_entry)
                        .hint_text(hint)
                        .desired_width(420.0),
                );
                if r.lost_focus() {
                    let entry = self.case_entry.clone();
                    self.state.set_case_dir(&entry);
                }
                #[cfg(windows)]
                if ui.button(self.state.tr("browse")).clicked()
                    && let Some(d) = rfd::FileDialog::new().pick_folder()
                {
                    self.case_entry = d.display().to_string();
                    let entry = self.case_entry.clone();
                    self.state.set_case_dir(&entry);
                }
            });
            let dropped: Option<PathBuf> = ui.ctx().input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .map(|f| f.path().to_path_buf())
                    .find(|p| p.is_dir())
            });
            if let Some(p) = dropped {
                self.case_entry = p.display().to_string();
                self.state.set_case_dir(&self.case_entry.clone());
            }
            if let Some(c) = &self.state.case_summary {
                ui.label(
                    egui::RichText::new(format!(
                        "{}: {}  \u{00B7}  {} {}  \u{00B7}  {}: {}",
                        self.state.tr("case"),
                        c.case_id,
                        c.items,
                        self.state.tr("registry_items"),
                        self.state.tr("out_dir"),
                        self.state.out_dir_display()
                    ))
                    .color(GREEN),
                );
            }
            if let Some(e) = &self.state.case_error {
                ui.colored_label(RED, e);
            }
            if let Some(dir) = self.state.latest_run()
                && ui.button(self.state.tr("open_latest")).clicked()
            {
                self.state.open_run(&dir);
            }
        });
    }

    fn settings_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("settings"));
        let tr = translator(&self.state.ui_lang);
        let (l_zone, l_zone_hint, l_tools, l_from, l_to, l_hint, l_skew, l_max, l_ts) = (
            tr("display_zone"),
            tr("zone_offset_hint"),
            tr("tools"),
            tr("window_from"),
            tr("window_to"),
            tr("window_hint"),
            tr("clock_skew"),
            tr("max_events"),
            tr("timesketch"),
        );
        let mut problem: Option<String> = None;
        ui.add_enabled_ui(enabled, |ui| {
            egui::Grid::new("settings-grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(l_zone);
                    ui.horizontal(|ui| {
                        let mut chosen = None;
                        egui::ComboBox::from_id_salt("zone")
                            .selected_text(self.state.display_zone.clone())
                            .show_ui(ui, |ui| {
                                for z in ZONE_CHOICES {
                                    if ui
                                        .selectable_label(self.state.display_zone == z, z)
                                        .clicked()
                                    {
                                        chosen = Some(z);
                                    }
                                }
                            });
                        if let Some(z) = chosen {
                            self.zone_entry.clear();
                            if let Err(e) = self.state.set_display_zone(z) {
                                problem = Some(e);
                            }
                        }
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut self.zone_entry)
                                .hint_text(l_zone_hint)
                                .desired_width(170.0),
                        );
                        if r.lost_focus()
                            && !self.zone_entry.trim().is_empty()
                            && let Err(e) = self.state.set_display_zone(&self.zone_entry.clone())
                        {
                            problem = Some(e);
                        }
                    });
                    ui.end_row();
                    ui.label(l_tools);
                    ui.horizontal_wrapped(|ui| {
                        for t in supported_tools() {
                            let mut on = self.state.tool_selected(&t);
                            if ui.checkbox(&mut on, &t).changed()
                                && let Err(e) = self.state.set_tool(&t, on)
                            {
                                problem = Some(e);
                            }
                        }
                    });
                    ui.end_row();
                    ui.label(format!("{} / {}", l_from, l_to));
                    ui.horizontal(|ui| {
                        let a = ui.add(
                            egui::TextEdit::singleline(&mut self.from_entry)
                                .hint_text(l_hint.clone())
                                .desired_width(170.0),
                        );
                        ui.label("\u{2013}");
                        let b = ui.add(
                            egui::TextEdit::singleline(&mut self.to_entry)
                                .hint_text(l_hint)
                                .desired_width(170.0),
                        );
                        if (a.lost_focus() || b.lost_focus())
                            && let Err(e) = self
                                .state
                                .set_window(&self.from_entry.clone(), &self.to_entry.clone())
                        {
                            problem = Some(e);
                        }
                    });
                    ui.end_row();
                    ui.label(l_skew);
                    let r = ui
                        .add(egui::TextEdit::singleline(&mut self.skew_entry).desired_width(100.0));
                    if r.lost_focus() {
                        match self.state.set_clock_skew(&self.skew_entry.clone()) {
                            Ok(()) => self.skew_entry = self.state.clock_skew_s.to_string(),
                            Err(e) => problem = Some(e),
                        }
                    }
                    ui.end_row();
                    ui.label(l_max);
                    let r = ui
                        .add(egui::TextEdit::singleline(&mut self.max_entry).desired_width(100.0));
                    if r.lost_focus() {
                        match self.state.set_max_events(&self.max_entry.clone()) {
                            Ok(()) => self.max_entry = self.state.max_events.to_string(),
                            Err(e) => problem = Some(e),
                        }
                    }
                    ui.end_row();
                    ui.label("Timesketch");
                    let mut on = self.state.timesketch;
                    if ui.checkbox(&mut on, l_ts).changed() {
                        self.state.set_timesketch(on);
                    }
                    ui.end_row();
                });
        });
        if problem.is_some() {
            self.notice = problem;
        }
    }

    fn report_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("reports"));
        let (l_lang, l_exam, l_all) = (
            self.state.tr("report_lang"),
            self.state.tr("examiner"),
            self.state.tr("lang_all"),
        );
        ui.add_enabled_ui(enabled, |ui| {
            egui::Grid::new("report-grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(l_lang);
                    let choices = [
                        ("en", "English".to_string()),
                        ("es", "Español".to_string()),
                        ("fr", "Français".to_string()),
                        ("all", l_all),
                    ];
                    let current = choices
                        .iter()
                        .find(|(k, _)| *k == self.state.lang)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    let mut chosen = None;
                    egui::ComboBox::from_id_salt("lang")
                        .selected_text(current)
                        .show_ui(ui, |ui| {
                            for (k, v) in &choices {
                                if ui.selectable_label(self.state.lang == *k, v).clicked() {
                                    chosen = Some(*k);
                                }
                            }
                        });
                    if let Some(k) = chosen {
                        self.state.set_lang(k);
                    }
                    ui.end_row();
                    ui.label(l_exam);
                    ui.add(egui::TextEdit::singleline(&mut self.state.actor).desired_width(300.0));
                    ui.end_row();
                });
        });
    }

    fn trust_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("trust"));
        let tr = translator(&self.state.ui_lang);
        let (l_jur, l_tsa, l_cert, l_pass, l_browse) = (
            tr("jurisdiction"),
            tr("tsa"),
            tr("sign_cert"),
            tr("sign_pass"),
            tr("browse"),
        );
        let jur = match self
            .state
            .case_summary
            .as_ref()
            .map(|c| c.jurisdiction.as_str())
        {
            Some("fr") => tr("jur_fr"),
            Some(_) => tr("jur_co"),
            None => "\u{2014}".to_string(),
        };
        let l_from_case = tr("jur_from_case");
        ui.add_enabled_ui(enabled, |ui| {
            egui::Grid::new("trust-grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(l_jur);
                    ui.label(format!("{}  ({})", jur, l_from_case));
                    ui.end_row();
                    ui.label(l_tsa);
                    ui.horizontal(|ui| {
                        let mut on = self.state.timestamp;
                        let mut url = self.state.tsa_url.clone();
                        let c = ui.checkbox(&mut on, "");
                        let t = ui.add_enabled(
                            on,
                            egui::TextEdit::singleline(&mut url).desired_width(280.0),
                        );
                        if c.changed() || t.lost_focus() {
                            self.state.set_timestamp(on, &url);
                        } else {
                            self.state.tsa_url = url;
                        }
                    });
                    ui.end_row();
                    ui.label(l_cert);
                    ui.horizontal(|ui| {
                        let mut path = self.state.sign_cert.clone();
                        let r = ui.add(egui::TextEdit::singleline(&mut path).desired_width(280.0));
                        if r.lost_focus() || r.changed() {
                            self.state.set_sign_cert(&path);
                        }
                        #[cfg(windows)]
                        if ui.button(&l_browse).clicked()
                            && let Some(f) = rfd::FileDialog::new()
                                .add_filter("PKCS#12", &["p12", "pfx"])
                                .pick_file()
                        {
                            self.state.set_sign_cert(&f.display().to_string());
                        }
                        let _ = &l_browse;
                    });
                    ui.end_row();
                    ui.label(l_pass);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.state.sign_password)
                            .password(true)
                            .desired_width(280.0),
                    );
                    ui.end_row();
                });
        });
    }

    fn run_section(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if self.state.is_running() {
                if ui.button(self.state.tr("cancel")).clicked() {
                    self.cancel.store(true, Ordering::SeqCst);
                    self.notice = Some(self.state.tr("cancelling"));
                }
            } else {
                let start = egui::Button::new(
                    egui::RichText::new(self.state.tr("start"))
                        .strong()
                        .color(egui::Color32::WHITE),
                )
                .fill(BLUE);
                if ui.add_enabled(self.state.can_start(), start).clicked() {
                    let ctx = ui.ctx().clone();
                    self.start(&ctx);
                }
            }
            if let Some(n) = &self.notice {
                ui.colored_label(AMBER, n);
            }
        });
        ui.add_space(6.0);
        ui.add(
            egui::ProgressBar::new(self.state.fraction())
                .text(self.state.progress_text())
                .fill(BLUE)
                .animate(self.state.is_running()),
        );
        let live = self.started.map(|s| s.elapsed().as_millis() as u64);
        ui.label(self.state.timing_text(live));
        if !self.state.current_item.is_empty() {
            ui.weak(format!(
                "{}: {}",
                self.state.tr("now"),
                self.state.current_item
            ));
        }
        match &self.state.phase {
            Phase::Failed(e) => {
                ui.colored_label(RED, format!("{}: {}", self.state.tr("failed"), e));
            }
            Phase::Finished | Phase::Cancelled => {
                if let Some(o) = self.state.outcome.clone() {
                    ui.separator();
                    let title = if self.state.phase == Phase::Cancelled {
                        self.state.tr("cancelled")
                    } else {
                        self.state.tr("done")
                    };
                    ui.label(egui::RichText::new(title).color(CYAN).strong());
                    ui.label(format!(
                        "{} {} \u{00B7} {}: {} / {} / {} / {}",
                        o.items,
                        self.state.tr("items_word"),
                        self.state.tr("signals"),
                        o.high,
                        o.medium,
                        o.low,
                        o.info
                    ));
                    ui.horizontal(|ui| {
                        if ui.button(self.state.tr("open_report")).clicked() {
                            open_path(&o.report);
                        }
                        if ui.button(self.state.tr("open_logs")).clicked() {
                            open_path(&o.log_dir);
                        }
                    });
                }
            }
            _ => {}
        }
        if !self.state.warnings.is_empty() {
            egui::CollapsingHeader::new(format!(
                "{} ({})",
                self.state.tr("warnings"),
                self.state.warnings.len()
            ))
            .show(ui, |ui| {
                for w in &self.state.warnings {
                    ui.label(w);
                }
            });
        }
    }

    /// Runs table, skipped runs and signals of the loaded build (digest-checked statistics.json).
    fn results_section(&mut self, ui: &mut egui::Ui) {
        if let Some(e) = &self.state.view_error {
            ui.colored_label(RED, format!("{} {}", self.state.tr("view_refused"), e));
        }
        self.review_status(ui);
        let Some(v) = &self.state.view else { return };
        let tr = translator(&self.state.ui_lang);
        let c = i18n::catalog(&self.state.ui_lang);
        Self::section_title(ui, format!("{} \u{2014} {}", tr("results"), v.run_id));
        ui.label(egui::RichText::new(tr("runs_table")).strong());
        egui::Grid::new("runs-grid")
            .num_columns(6)
            .striped(true)
            .spacing([14.0, 4.0])
            .show(ui, |ui| {
                for h in [
                    "col_tool",
                    "col_version",
                    "col_run",
                    "col_status",
                    "col_events",
                    "col_reason",
                ] {
                    ui.label(egui::RichText::new(tr(h)).color(GREY));
                }
                ui.end_row();
                for r in &v.runs {
                    ui.monospace(&r.tool);
                    ui.monospace(&r.tool_version);
                    ui.monospace(&r.run_id);
                    if r.status == RunStatus::Verified {
                        ui.colored_label(GREEN, c.label("run_status_verified"));
                    } else {
                        ui.colored_label(RED, c.label("run_status_excluded"));
                    }
                    ui.label(r.events.to_string());
                    match &r.exclusion {
                        Some(x) => ui.label(format!(
                            "{}{}",
                            self.state.exclusion_text(&x.reason),
                            if x.detail.is_empty() {
                                String::new()
                            } else {
                                format!(" ({})", x.detail)
                            }
                        )),
                        None => ui.weak("\u{2014}"),
                    };
                    ui.end_row();
                }
                for s in &v.skipped {
                    ui.monospace(&s.tool);
                    ui.monospace(&s.version);
                    ui.monospace(&s.run_id);
                    ui.colored_label(GREY, tr("not_read"));
                    ui.label("0");
                    ui.label(c.label(&format!("skip_{}", s.reason)));
                    ui.end_row();
                }
            });
        if v.max_events_reached {
            ui.colored_label(AMBER, tr("cap_reached"));
        }
        if !v.has_timeline_file {
            ui.colored_label(AMBER, tr("no_timeline_file"));
        }
        ui.add_space(6.0);
        ui.label(egui::RichText::new(format!("{} ({})", tr("signals"), v.signals.len())).strong());
        if v.signals.is_empty() {
            ui.weak(tr("no_signals"));
        }
        let n_signals = v.signals.len();
        let events_word = tr("events_word");
        for n in 0..n_signals {
            let Some(v) = &self.state.view else { return };
            let s = &v.signals[n];
            let (title, shows, dnp) = self.state.signal_texts(n).unwrap_or_default();
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    sev_color(s.severity),
                    egui::RichText::new(c.severity(sev_key(s.severity)).to_uppercase()).strong(),
                );
                ui.label(egui::RichText::new(format!("{}  {}", s.code, title)).strong());
                if !s.events.is_empty() {
                    ui.weak(format!("\u{00B7} {} {}", s.events.len(), events_word));
                }
            });
            ui.indent(("sig", n), |ui| {
                ui.label(format!("{}: {}", c.label("shows"), shows));
                ui.weak(format!("{}: {}", c.label("does_not_prove"), dnp));
            });
        }
        ui.add_space(6.0);
        let open = egui::Button::new(
            egui::RichText::new(tr("open_timeline"))
                .strong()
                .color(egui::Color32::WHITE),
        )
        .fill(VIOLET);
        if ui.add(open).clicked() {
            self.state.open_view_page();
        }
    }

    fn review_status(&self, ui: &mut egui::Ui) {
        match &self.state.review_error {
            Some(e) => {
                ui.colored_label(
                    AMBER,
                    format!("{} {}", self.state.tr("review_log_failed"), e),
                );
            }
            None if self.state.view.is_some() => {
                ui.weak(self.state.tr("review_logged"));
            }
            None => {}
        }
    }

    // ------------------------------------------------------------------ timeline page

    fn timeline_page(&mut self, ui: &mut egui::Ui) {
        let tr = translator(&self.state.ui_lang);
        let Some(v) = &self.state.view else {
            self.state.close_view();
            return;
        };
        let (run_id, zone_name, total) = (v.run_id.clone(), v.display_zone.clone(), v.len());
        ui.horizontal(|ui| {
            if ui.button(tr("back")).clicked() {
                self.state.close_view();
            }
            ui.label(
                egui::RichText::new(format!("{} \u{2014} {}", tr("timeline_title"), run_id))
                    .color(CYAN)
                    .strong()
                    .size(15.0),
            );
            ui.label(format!(
                "{} / {} {}",
                self.state.filtered.len(),
                total,
                tr("events_word")
            ));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mut first = self.state.zone_first;
                ui.selectable_value(&mut first, true, &zone_name);
                ui.selectable_value(&mut first, false, "UTC");
                ui.label(tr("zone_toggle"));
                self.state.set_zone_first(first);
            });
        });
        self.filter_bar(ui);
        self.review_status(ui);
        ui.separator();
        egui::Panel::left("signals-panel")
            .default_size(330.0)
            .resizable(true)
            .show(ui, |ui| self.signals_panel(ui));
        if self.state.selected_event.is_some() {
            egui::Panel::bottom("event-panel")
                .resizable(true)
                .default_size(170.0)
                .show(ui, |ui| self.event_panel(ui));
        }
        self.event_list(ui);
    }

    fn filter_bar(&mut self, ui: &mut egui::Ui) {
        let tr = translator(&self.state.ui_lang);
        let Some(v) = &self.state.view else { return };
        let c = i18n::catalog(&self.state.ui_lang);
        let any = tr("any");
        let mut f: Filters = self.state.filters.clone();
        let tools = v.tools.clone();
        let items = v.items.clone();
        let kinds = v.kinds.clone();
        let (mut apply_window, mut clear) = (false, false);
        ui.horizontal_wrapped(|ui| {
            ui.label(tr("filter_tool"));
            egui::ComboBox::from_id_salt("f-tool")
                .selected_text(f.tool.clone().unwrap_or_else(|| any.clone()))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut f.tool, None, &any);
                    for t in &tools {
                        ui.selectable_value(&mut f.tool, Some(t.clone()), t);
                    }
                });
            ui.label(tr("filter_item"));
            let item_text = f
                .item
                .as_ref()
                .and_then(|k| items.iter().find(|(x, _)| x == k).map(|(_, l)| l.clone()))
                .unwrap_or_else(|| any.clone());
            egui::ComboBox::from_id_salt("f-item")
                .selected_text(item_text)
                .width(170.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut f.item, None, &any);
                    for (k, l) in &items {
                        ui.selectable_value(&mut f.item, Some(k.clone()), l);
                    }
                });
            ui.label(tr("filter_kind"));
            egui::ComboBox::from_id_salt("f-kind")
                .selected_text(
                    f.kind
                        .as_ref()
                        .map(|k| c.kind(k))
                        .unwrap_or_else(|| any.clone()),
                )
                .width(190.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut f.kind, None, &any);
                    for k in &kinds {
                        ui.selectable_value(&mut f.kind, Some(k.clone()), c.kind(k));
                    }
                });
            ui.label(tr("filter_severity"));
            egui::ComboBox::from_id_salt("f-sev")
                .selected_text(
                    f.severity
                        .map(|s| format!("\u{2265} {}", c.severity(sev_key(s))))
                        .unwrap_or_else(|| any.clone()),
                )
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut f.severity, None, &any);
                    for s in [
                        Severity::High,
                        Severity::Medium,
                        Severity::Low,
                        Severity::Info,
                    ] {
                        ui.selectable_value(
                            &mut f.severity,
                            Some(s),
                            format!("\u{2265} {}", c.severity(sev_key(s))),
                        );
                    }
                });
        });
        ui.horizontal(|ui| {
            ui.label(format!("{} / {}", tr("window_from"), tr("window_to")));
            let a = ui.add(
                egui::TextEdit::singleline(&mut self.state.filter_from_text)
                    .hint_text(tr("window_hint"))
                    .desired_width(160.0),
            );
            ui.label("\u{2013}");
            let b = ui.add(
                egui::TextEdit::singleline(&mut self.state.filter_to_text)
                    .hint_text(tr("window_hint"))
                    .desired_width(160.0),
            );
            let enter =
                (a.lost_focus() || b.lost_focus()) && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.button(tr("apply")).clicked() || enter {
                apply_window = true;
            }
            if ui.button(tr("clear_filters")).clicked() {
                clear = true;
            }
        });
        if clear {
            self.state.filter_from_text.clear();
            self.state.filter_to_text.clear();
            self.state.set_filters(Filters::default());
            return;
        }
        // Combo changes keep the window already applied.
        f.from_s = self.state.filters.from_s;
        f.to_s = self.state.filters.to_s;
        self.state.set_filters(f);
        if apply_window {
            let (a, b) = (
                self.state.filter_from_text.clone(),
                self.state.filter_to_text.clone(),
            );
            if let Err(e) = self.state.set_filter_window(&a, &b) {
                self.notice = Some(e);
            } else {
                self.notice = None;
            }
        }
        if let Some(n) = &self.notice {
            ui.colored_label(AMBER, n);
        }
    }

    fn signals_panel(&mut self, ui: &mut egui::Ui) {
        let tr = translator(&self.state.ui_lang);
        let Some(v) = &self.state.view else { return };
        let c = i18n::catalog(&self.state.ui_lang);
        ui.label(egui::RichText::new(format!("{} ({})", tr("signals"), v.signals.len())).strong());
        ui.weak(tr("signal_help"));
        let sigs: Vec<_> = v
            .signals
            .iter()
            .enumerate()
            .map(|(n, s)| (n, s.code.clone(), s.severity, v.signal_rows[n].len()))
            .collect();
        let mut chosen = None;
        egui::ScrollArea::vertical()
            .id_salt("signals-scroll")
            .show(ui, |ui| {
                if sigs.is_empty() {
                    ui.weak(tr("no_signals"));
                }
                for (n, code, sev, rows) in sigs {
                    let (title, shows, dnp) = self.state.signal_texts(n).unwrap_or_default();
                    let selected = self.state.selected_signal == Some(n);
                    let text = egui::RichText::new(format!(
                        "{}  {}{}",
                        c.severity(sev_key(sev)).to_uppercase(),
                        title,
                        if rows > 0 {
                            format!("  ({})", rows)
                        } else {
                            String::new()
                        }
                    ))
                    .color(sev_color(sev));
                    if ui
                        .selectable_label(selected, text)
                        .on_hover_text(&code)
                        .clicked()
                    {
                        chosen = Some(if selected { None } else { Some(n) });
                    }
                    if selected {
                        ui.indent(("sel", n), |ui| {
                            ui.label(format!("{}: {}", c.label("shows"), shows));
                            ui.weak(format!("{}: {}", c.label("does_not_prove"), dnp));
                        });
                    }
                    ui.add_space(2.0);
                }
            });
        if let Some(n) = chosen {
            self.state.select_signal(n);
        }
    }

    /// Time texts of an event: (UTC, display zone); a zone-unknown event is never converted.
    fn times(&self, e: &TimeEvent, zone: &DisplayZone) -> (String, String) {
        let unknown = self.state.tr("zone_unknown");
        match e.zone {
            ZoneInfo::Unknown => (format!("{}  ({})", engine::utc_time(e), unknown), unknown),
            ZoneInfo::Explicit => (
                engine::utc_time(e),
                engine::display_time(e, zone).unwrap_or_default(),
            ),
        }
    }

    /// The virtualised list: only the rows in view are read from timeline.jsonl and drawn.
    fn event_list(&mut self, ui: &mut egui::Ui) {
        let Some(v) = &self.state.view else { return };
        if !v.has_timeline_file {
            ui.colored_label(AMBER, self.state.tr("no_timeline_file"));
            return;
        }
        let zone = DisplayZone::parse(&v.display_zone).unwrap_or(DisplayZone::Utc);
        let lang = self.state.ui_lang.clone();
        let n = self.state.filtered.len();
        let mut area = egui::ScrollArea::both()
            .id_salt("event-list")
            .auto_shrink([false, false]);
        if let Some(pos) = self.state.scroll_to.take() {
            let step = ROW_H + ui.spacing().item_spacing.y;
            area = area.vertical_scroll_offset((pos as f32 * step - 2.0 * step).max(0.0));
        }
        let mut clicked = None;
        area.show_rows(ui, ROW_H, n, |ui, range| {
            let width = ui.available_width().max(900.0);
            for pos in range {
                let i = self.state.filtered[pos];
                let (rect, resp) =
                    ui.allocate_exact_size(egui::vec2(width, ROW_H), egui::Sense::click());
                if resp.clicked() {
                    clicked = Some(i);
                }
                if !ui.is_rect_visible(rect) {
                    continue;
                }
                let highlighted = self.state.highlighted(i);
                let selected = self.state.selected_event == Some(i);
                let sev = self.state.view.as_ref().and_then(|v| v.severity(i));
                let row = self.state.view.as_mut().map(|v| v.row(i));
                let p = ui.painter_at(rect);
                let bg = if selected {
                    BLUE.gamma_multiply(0.45)
                } else if highlighted {
                    VIOLET.gamma_multiply(0.35)
                } else if pos % 2 == 0 {
                    NIGHT2
                } else {
                    NIGHT
                };
                p.rect_filled(rect, 2.0, bg);
                if let Some(s) = sev {
                    p.rect_filled(
                        egui::Rect::from_min_size(rect.min, egui::vec2(4.0, ROW_H)),
                        0.0,
                        sev_color(s),
                    );
                }
                if highlighted {
                    p.rect_stroke(
                        rect,
                        2.0,
                        egui::Stroke::new(1.0, CYAN),
                        egui::StrokeKind::Inside,
                    );
                }
                let e = match row {
                    Some(Ok(e)) => e,
                    Some(Err(err)) => {
                        p.text(
                            rect.left_center() + egui::vec2(10.0, 0.0),
                            egui::Align2::LEFT_CENTER,
                            err,
                            egui::FontId::proportional(12.0),
                            RED,
                        );
                        continue;
                    }
                    None => continue,
                };
                let (utc, local) = self.times(&e, &zone);
                let (first, second) = if self.state.zone_first {
                    (local, utc)
                } else {
                    (utc, local)
                };
                let item = {
                    let mut s = if e.item.evidence_id.is_empty() {
                        e.item.path.clone()
                    } else {
                        format!("{}  {}", e.item.evidence_id, e.item.path)
                    };
                    if !e.item.sub.is_empty() {
                        s = format!("{} [{}]", s, e.item.sub);
                    }
                    s
                };
                let cite = format!(
                    "{} \u{00B7} {} \u{00B7} {} \u{00B7} {}",
                    e.source.tool, e.source.run_id, e.source.file, e.source.pointer
                );
                let mono = egui::FontId::monospace(12.0);
                let prop = egui::FontId::proportional(12.5);
                let small = egui::FontId::proportional(11.5);
                let cols = [10.0, 300.0, 560.0];
                let y1 = rect.top() + 4.0;
                let y2 = rect.top() + 21.0;
                let cell = |x0: f32, x1: f32, y: f32, text: String, font: egui::FontId, col| {
                    let clip = egui::Rect::from_min_max(
                        egui::pos2(rect.left() + x0, rect.top()),
                        egui::pos2((rect.left() + x1 - 8.0).min(rect.right()), rect.bottom()),
                    );
                    p.with_clip_rect(clip).text(
                        egui::pos2(rect.left() + x0, y),
                        egui::Align2::LEFT_TOP,
                        text,
                        font,
                        col,
                    );
                };
                let right = rect.width();
                cell(cols[0], cols[1], y1, first, mono.clone(), MIST);
                cell(cols[0], cols[1], y2, second, mono, GREY);
                cell(
                    cols[1],
                    cols[2],
                    y1,
                    engine::kind_label(&lang, &e.kind),
                    prop.clone(),
                    CYAN,
                );
                cell(cols[1], cols[2], y2, item, small.clone(), MIST);
                cell(
                    cols[2],
                    right,
                    y1,
                    format!("\u{201C}{}\u{201D}", e.original),
                    prop,
                    MIST,
                );
                cell(cols[2], right, y2, cite, small, GREY);
            }
        });
        if let Some(i) = clicked {
            let next = if self.state.selected_event == Some(i) {
                None
            } else {
                Some(i)
            };
            self.state.select_event(next);
        }
    }

    fn event_panel(&mut self, ui: &mut egui::Ui) {
        let Some(i) = self.state.selected_event else {
            return;
        };
        let tr = translator(&self.state.ui_lang);
        let Some(v) = self.state.view.as_mut() else {
            return;
        };
        let zone = DisplayZone::parse(&v.display_zone).unwrap_or(DisplayZone::Utc);
        let zone_name = v.display_zone.clone();
        let row = v.row(i);
        let c = i18n::catalog(&self.state.ui_lang);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(tr("event_details"))
                    .color(CYAN)
                    .strong(),
            );
            if ui.small_button("x").clicked() {
                self.state.selected_event = None;
            }
        });
        let e = match row {
            Ok(e) => e,
            Err(err) => {
                ui.colored_label(RED, err);
                return;
            }
        };
        let (utc, local) = self.times(&e, &zone);
        egui::ScrollArea::vertical()
            .id_salt("event-details")
            .show(ui, |ui| {
                egui::Grid::new("event-grid")
                    .num_columns(2)
                    .spacing([12.0, 3.0])
                    .show(ui, |ui| {
                        let mut row = |k: String, val: String| {
                            ui.label(egui::RichText::new(k).color(GREY));
                            ui.add(egui::Label::new(egui::RichText::new(val).monospace()).wrap());
                            ui.end_row();
                        };
                        row(c.label("time_utc"), utc);
                        row(
                            format!("{} ({})", c.label("time_display"), zone_name),
                            local,
                        );
                        row(c.label("original"), e.original.clone());
                        row(
                            c.label("kind"),
                            format!("{}  [{}]", c.kind(&e.kind), e.kind),
                        );
                        row(
                            c.label("item"),
                            format!(
                                "{} {}{}  SHA-256 {}",
                                e.item.evidence_id,
                                e.item.path,
                                if e.item.sub.is_empty() {
                                    String::new()
                                } else {
                                    format!(" [{}]", e.item.sub)
                                },
                                if e.item.sha256.is_empty() {
                                    "\u{2014}"
                                } else {
                                    &e.item.sha256
                                }
                            ),
                        );
                        row(
                            c.label("tool_run"),
                            format!(
                                "{} {} \u{00B7} {} \u{00B7} {}",
                                e.source.tool,
                                e.source.tool_version,
                                e.source.run_id,
                                e.source.run_dir
                            ),
                        );
                        row(
                            tr("citation"),
                            format!(
                                "{}  {}  (SHA-256 {})",
                                e.source.file, e.source.pointer, e.source.file_sha256
                            ),
                        );
                        if !e.details.is_empty() {
                            row(
                                tr("details"),
                                e.details
                                    .iter()
                                    .map(|(k, v)| format!("{}={}", k, v))
                                    .collect::<Vec<_>>()
                                    .join("  \u{00B7}  "),
                            );
                        }
                        row("id".into(), e.id.clone());
                    });
            });
    }

    /// Draws one frame into the root `ui` (what eframe calls every frame).
    pub fn draw(&mut self, ui: &mut egui::Ui) {
        if !self.themed {
            apply_theme(ui.ctx());
            self.themed = true;
        }
        self.drain();
        if self.state.is_running() {
            // Keep the elapsed timer moving even when no event arrives.
            ui.ctx().request_repaint_after(Duration::from_millis(200));
        }
        egui::CentralPanel::default().show(ui, |ui| {
            if self.state.view_page && self.state.view.is_some() {
                self.header(ui);
                self.timeline_page(ui);
                return;
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.header(ui);
                let enabled = !self.state.is_running();
                self.case_section(ui, enabled);
                self.settings_section(ui, enabled);
                self.report_section(ui, enabled);
                self.trust_section(ui, enabled);
                self.run_section(ui);
                if !self.state.is_running() {
                    self.results_section(ui);
                }
            });
        });
    }
}

impl Default for HashInvApp {
    fn default() -> Self {
        Self::new()
    }
}

fn open_path(p: &Path) {
    #[cfg(windows)]
    let _ = std::process::Command::new("explorer").arg(p).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(p).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(p).spawn();
}

impl eframe::App for HashInvApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launch::parse_launch_args;
    use rv_timeline_core::audit::AuditLog;
    use rv_timeline_core::model::{ItemRef, Precision, SourceRef};
    use serde_json::json;

    fn launch(args: &[&str]) -> HashInvApp {
        HashInvApp::from_launch(parse_launch_args(args.iter().map(std::ffi::OsString::from)))
    }

    fn actions(app: &HashInvApp) -> Vec<&str> {
        app.state
            .ui_actions
            .iter()
            .map(|(a, _)| a.as_str())
            .collect()
    }

    #[test]
    fn launcher_case_dir_is_preset_and_audited() {
        let app = launch(&["--case-dir", "X"]);
        assert_eq!(app.state.case_dir, "X");
        assert_eq!(app.case_entry, "X");
        assert!(app.state.case_error.is_some(), "X is not a case folder");
        assert_eq!(
            actions(&app),
            ["ui_case_dir_from_launcher", "ui_case_dir_changed"]
        );
        let d = &app.state.ui_actions[0].1;
        assert_eq!(d["path"], "X");
        assert!(d["at_utc"].as_str().is_some_and(|t| t.ends_with('Z')));
        assert!(app.notice.is_none());
    }

    #[test]
    fn a_dropped_folder_is_the_case_and_extras_are_noted() {
        let app = launch(&["C:\\CASE", "b.pdf"]);
        assert_eq!(app.state.case_dir, "C:\\CASE");
        assert_eq!(
            actions(&app),
            ["ui_case_dir_changed", "ui_launch_argument_ignored"]
        );
        assert!(app.notice.as_deref().is_some_and(|n| n.contains("b.pdf")));
        let app = launch(&["--case-dir"]);
        assert!(app.state.case_dir.is_empty());
        assert_eq!(actions(&app), ["ui_launch_argument_ignored"]);
    }

    fn event(n: u64) -> TimeEvent {
        TimeEvent {
            id: format!("rv-hashinv:R1:E{:04}:fs.modified:{}", n % 50 + 1, n),
            utc_s: 1_794_268_800 + n as i64,
            utc_ns: 0,
            zone: if n.is_multiple_of(7) {
                ZoneInfo::Unknown
            } else {
                ZoneInfo::Explicit
            },
            offset_min: if n.is_multiple_of(7) { None } else { Some(0) },
            precision: Precision::Second,
            original: format!("2026-11-10 00:00:{:02}", n % 60),
            kind: if n.is_multiple_of(2) {
                "fs.modified".into()
            } else {
                "exif.original".into()
            },
            item: ItemRef {
                evidence_id: format!("E{:04}", n % 50 + 1),
                path: format!("evidence/file-{}.jpg", n % 50 + 1),
                sub: String::new(),
                sha256: String::new(),
            },
            source: SourceRef {
                tool: if n.is_multiple_of(3) {
                    "rv-imgauth"
                } else {
                    "rv-hashinv"
                }
                .into(),
                tool_version: "0.4.1".into(),
                run_id: "R1".into(),
                run_dir: "runs/rv-hashinv/R1".into(),
                file: "logs/hashes.csv".into(),
                file_sha256: "00".repeat(32),
                pointer: format!("line:{}", n + 2),
            },
            details: Default::default(),
        }
    }

    /// A finished timeline build written the way the pipeline writes one (audit chain, digests), with `n` events
    /// and one signal naming two of them.
    fn synthetic_build(tag: &str, n: u64) -> PathBuf {
        let run = std::env::temp_dir()
            .join(format!("rv-tl-gui-{}-{}", tag, std::process::id()))
            .join("runs/rv-timeline/20261113T100000Z-abcdef");
        let _ = std::fs::remove_dir_all(&run);
        let (logs, reports) = (run.join("logs"), run.join("reports"));
        std::fs::create_dir_all(&reports).unwrap();
        let mut text = String::with_capacity(n as usize * 700);
        for i in 0..n {
            text.push_str(&engine::timesketch_line(&event(i)));
            text.push('\n');
        }
        std::fs::write(reports.join("timeline.jsonl"), &text).unwrap();
        let (a, b) = (event(3).id, event(n - 2).id);
        let stats = json!({"timeline": {
            "display_zone": "Europe/Paris", "max_events_reached": false,
            "runs": [{"tool": "rv-hashinv", "tool_version": "0.4.1", "run_id": "R1", "run_dir": "runs/rv-hashinv/R1",
                      "status": "verified", "events": n},
                     {"tool": "rv-pdfauth", "tool_version": "0.2.0", "run_id": "R2", "run_dir": "runs/rv-pdfauth/R2",
                      "status": "excluded", "exclusion": {"reason": "digest_mismatch", "detail": "x.json"}, "events": 0}],
            "skipped": [],
            "signals": [{"code": "EXIF_AFTER_INTAKE", "severity": "medium", "events": [a, b],
                         "item": null, "params": {"delta_s": "60"}},
                        {"code": "RUN_NOT_VERIFIED", "severity": "high", "events": [],
                         "params": {"tool": "rv-pdfauth", "run_id": "R2", "reason": "digest_mismatch"}}]
        }});
        let stats = serde_json::to_vec_pretty(&stats).unwrap();
        std::fs::write(reports.join("statistics.json"), &stats).unwrap();
        let sha =
            |b: &[u8]| rv_timeline_core::hash::hash_bytes(b, rv_timeline_core::HashAlgo::Sha256);
        let mut log = AuditLog::create(&logs, "20261113T100000Z-abcdef", "tester").unwrap();
        log.record("run_started", None, json!({"purpose": "timeline"}))
            .unwrap();
        log.record(
            "timeline_written",
            Some("timeline.jsonl"),
            json!({"folder": "reports", "files": {"timeline.jsonl": {"sha256": sha(text.as_bytes())}}, "lines": n}),
        )
        .unwrap();
        log.record(
            "statistics_report_written",
            None,
            json!({"files": {"statistics.json": {"sha256": sha(&stats)}}}),
        )
        .unwrap();
        log.record("run_finished", None, json!({"events": n}))
            .unwrap();
        run
    }

    fn frame(app: &mut HashInvApp, ctx: &egui::Context) {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1400.0, 900.0),
            )),
            ..Default::default()
        };
        let mut out = ctx.run_ui(raw, |ui| app.draw(ui));
        out.textures_delta.clear();
    }

    #[test]
    fn a_tampered_timeline_is_refused_and_the_refusal_is_reviewed() {
        let run = synthetic_build("tamper", 40);
        let mut app = HashInvApp::new();
        assert!(app.state.open_run(&run), "{:?}", app.state.view_error);
        assert_eq!(app.state.view.as_ref().unwrap().len(), 40);
        // One changed byte in timeline.jsonl after the build.
        let path = run.join("reports/timeline.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            text.replacen("2026-11-10 00:00:05", "2026-11-10 00:00:06", 1),
        )
        .unwrap();
        assert!(!app.state.open_run(&run), "tampered timeline refused");
        assert!(app.state.view.is_none() && app.state.filtered.is_empty());
        let err = app.state.view_error.clone().unwrap();
        assert!(
            err.contains("timeline.jsonl") && err.contains("digest"),
            "{}",
            err
        );
        // Nothing of it is drawn: the timeline page cannot open and the main page shows the refusal.
        app.state.open_view_page();
        assert!(!app.state.view_page);
        let ctx = egui::Context::default();
        frame(&mut app, &ctx);
        // Both the view and the refusal are in the build's review log, chained to run_finished.
        let logs = run.join("logs");
        assert_eq!(rv_timeline_core::review::verify(&logs), Ok(Some(2)));
        let review = std::fs::read_to_string(logs.join("review.jsonl")).unwrap();
        assert!(
            review.contains("\"ui_timeline_viewed\"") && review.contains("\"ui_timeline_refused\"")
        );
        // A tampered statistics.json is refused the same way.
        std::fs::write(&path, text).unwrap();
        assert!(app.state.open_run(&run));
        let stats = run.join("reports/statistics.json");
        let s = std::fs::read_to_string(&stats).unwrap();
        std::fs::write(&stats, s.replace("\"high\"", "\"low\"")).unwrap();
        assert!(!app.state.open_run(&run));
        assert!(
            app.state
                .view_error
                .as_deref()
                .unwrap()
                .contains("statistics.json")
        );
        let _ = std::fs::remove_dir_all(run.ancestors().nth(3).unwrap());
    }

    #[test]
    fn a_line_changed_while_open_is_not_shown() {
        let run = synthetic_build("live", 20);
        let mut app = HashInvApp::new();
        assert!(app.state.open_run(&run));
        let path = run.join("reports/timeline.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replacen("00:00:01\"", "00:00:09\"", 1)).unwrap();
        let v = app.state.view.as_mut().unwrap();
        assert!(v.row(0).is_ok());
        let err = v.row(1).unwrap_err();
        assert!(err.contains("changed"), "{}", err);
        let _ = std::fs::remove_dir_all(run.ancestors().nth(3).unwrap());
    }

    #[test]
    fn a_large_timeline_renders_only_the_visible_rows() {
        const N: u64 = 120_000;
        let run = synthetic_build("large", N);
        let mut app = HashInvApp::new();
        assert!(app.state.open_run(&run), "{:?}", app.state.view_error);
        let v = app.state.view.as_ref().unwrap();
        assert_eq!(v.len(), N as usize);
        assert_eq!(v.lines_parsed(), 0, "the index parses no event for display");
        assert_eq!(v.signal_rows[0], vec![3, (N - 2) as u32]);
        app.state.open_view_page();
        let ctx = egui::Context::default();
        for _ in 0..3 {
            frame(&mut app, &ctx);
        }
        let parsed = app.state.view.as_ref().unwrap().lines_parsed();
        assert!(
            parsed > 0 && parsed < 200,
            "only the visible rows are read: {}",
            parsed
        );
        // Selecting the signal scrolls to its last event (row N-2) and reads only that page.
        app.state.select_signal(Some(0));
        assert_eq!(app.state.scroll_to, Some(3));
        app.state.scroll_to = Some((N - 2) as usize);
        for _ in 0..3 {
            frame(&mut app, &ctx);
        }
        let v = app.state.view.as_ref().unwrap();
        assert!(v.cached_rows() < 400, "{}", v.cached_rows());
        assert!(v.lines_parsed() < 400, "{}", v.lines_parsed());
        assert!(app.state.highlighted((N - 2) as u32) && !app.state.highlighted(4));
        // Filters work on the index, without reading events.
        let before = app.state.view.as_ref().unwrap().lines_parsed();
        app.state.set_filters(Filters {
            tool: Some("rv-imgauth".into()),
            ..Default::default()
        });
        assert_eq!(app.state.filtered.len(), N.div_ceil(3) as usize);
        app.state.set_filters(Filters {
            severity: Some(Severity::Medium),
            ..Default::default()
        });
        assert_eq!(app.state.filtered, vec![3, (N - 2) as u32]);
        app.state
            .set_filter_window("2026-11-10 00:00:10", "2026-11-10 00:00:19")
            .unwrap();
        assert!(app.state.filtered.is_empty(), "severity and window combine");
        app.state.set_filters(Filters {
            from_s: app.state.filters.from_s,
            to_s: app.state.filters.to_s,
            ..Default::default()
        });
        assert_eq!(app.state.filtered.len(), 10);
        assert_eq!(app.state.view.as_ref().unwrap().lines_parsed(), before);
        let _ = std::fs::remove_dir_all(run.ancestors().nth(3).unwrap());
    }
}
