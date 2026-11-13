//! docs/reports.md lists every signal code with its severity and the exact English wording of i18n/en.json
//! (title, what it shows, what it does not prove), every event kind with its label, and every limitation a
//! timeline report prints. This test regenerates the three tables and fails when the page differs;
//! `RV_UPDATE_DOCS=1 cargo test -p rv-timeline-core --test docs_catalogue` rewrites them.

use rv_timeline_core::engine::SIGNAL_CODES;
use rv_timeline_core::report::TIMELINE_LIMITATIONS;
use serde_json::Value;
use std::path::{Path, PathBuf};

const SIG_START: &str = "<!-- signals-catalogue:start (generated from i18n/en.json by src/core/tests/docs_catalogue.rs; do not edit by hand) -->";
const SIG_END: &str = "<!-- signals-catalogue:end -->";
const KIND_START: &str = "<!-- kinds:start (generated from i18n/en.json by src/core/tests/docs_catalogue.rs; do not edit by hand) -->";
const KIND_END: &str = "<!-- kinds:end -->";
const LIM_START: &str = "<!-- limitations:start (generated from i18n/en.json by src/core/tests/docs_catalogue.rs; do not edit by hand) -->";
const LIM_END: &str = "<!-- limitations:end -->";

/// The i18n key of the Received-hops variant of CLOCK_SKEW_SUSPECTED (param `basis` = `received_hops`).
const HOPS_VARIANT: &str = "CLOCK_SKEW_SUSPECTED.received_hops";

/// Severities the engine can give each catalogue entry (`engine.rs`, `SignalEngine::finish`; its unit tests pin
/// them). Several values: the rule picks one per signal, the reason is in docs/theory.md B8.
const SEVERITIES: [(&str, &str); 9] = [
    (
        "EXIF_AFTER_INTAKE",
        "High (Medium when every late value is zone unknown and within tolerance + 14 h)",
    ),
    ("MAIL_DATE_AFTER_FIRST_HOP", "Medium"),
    ("PDF_REVISION_BEFORE_PREVIOUS", "Medium"),
    ("FILE_MODIFIED_AFTER_INTAKE", "Medium"),
    ("EVENT_IN_FUTURE", "Medium"),
    ("CLOCK_SKEW_SUSPECTED", "Low"),
    (HOPS_VARIANT, "Low"),
    (
        "RUN_NOT_VERIFIED",
        "Medium (chain_broken, digest_mismatch); Low (other reasons)",
    ),
    ("ZONE_UNKNOWN_EVENTS", "Informational"),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn en() -> Value {
    serde_json::from_str(&std::fs::read_to_string(root().join("i18n/en.json")).unwrap()).unwrap()
}

fn signals_table() -> String {
    let en = en();
    let mut out = format!(
        "{SIG_START}\n\n| Code | Severity | Title | What it shows | What it does not prove |\n| --- | --- | --- | --- | --- |\n"
    );
    for (code, sev) in SEVERITIES {
        let s = &en["signals"][code];
        let shown = if code == HOPS_VARIANT {
            "`CLOCK_SKEW_SUSPECTED` (basis `received_hops`)".to_string()
        } else if code == "CLOCK_SKEW_SUSPECTED" {
            "`CLOCK_SKEW_SUSPECTED` (basis `tools`)".to_string()
        } else {
            format!("`{code}`")
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            shown,
            sev,
            cell(s["title"].as_str().unwrap_or_default()),
            cell(s["shows"].as_str().unwrap_or_default()),
            cell(s["does_not_prove"].as_str().unwrap_or_default()),
        ));
    }
    out.push_str(&format!("\n{SIG_END}"));
    out
}

fn kinds_table() -> String {
    let en = en();
    let mut out = format!("{KIND_START}\n\n| Kind | Label (en.json) |\n| --- | --- |\n");
    for (kind, label) in en["kind"].as_object().unwrap() {
        out.push_str(&format!(
            "| `{}` | {} |\n",
            kind,
            cell(label.as_str().unwrap_or_default())
        ));
    }
    out.push_str(&format!("\n{KIND_END}"));
    out
}

fn limitations_table() -> String {
    let en = en();
    let mut out = format!("{LIM_START}\n\n| Code | Text (en.json) |\n| --- | --- |\n");
    for code in ["TL_TIMES_SKIPPED", "TL_MAX_EVENTS"]
        .iter()
        .chain(TIMELINE_LIMITATIONS.iter())
    {
        let text = cell(en["limitations"][*code].as_str().unwrap_or_default());
        out.push_str(&format!("| `{code}` | {text} |\n"));
    }
    out.push_str(&format!("\n{LIM_END}"));
    out
}

#[test]
fn catalogue_codes_are_the_engine_codes_and_the_hops_variant() {
    let en = en();
    let mut catalogue: Vec<&str> = en["signals"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut known: Vec<&str> = SIGNAL_CODES.iter().copied().chain([HOPS_VARIANT]).collect();
    let mut documented: Vec<&str> = SEVERITIES.iter().map(|(c, _)| *c).collect();
    catalogue.sort();
    known.sort();
    documented.sort();
    assert_eq!(
        catalogue, known,
        "i18n/en.json signals vs engine::SIGNAL_CODES"
    );
    assert_eq!(
        documented, known,
        "SEVERITIES in this test vs engine::SIGNAL_CODES"
    );
}

#[test]
fn every_printed_limitation_is_worded() {
    let en = en();
    for code in ["TL_TIMES_SKIPPED", "TL_MAX_EVENTS"]
        .iter()
        .chain(TIMELINE_LIMITATIONS.iter())
    {
        assert!(
            en["limitations"][*code]
                .as_str()
                .is_some_and(|t| !t.is_empty()),
            "{code} has no English wording"
        );
    }
}

/// Replaces the block between `start` and `end` with `fresh` (RV_UPDATE_DOCS=1) or fails when it differs.
fn check_block(start: &str, end: &str, fresh: &str) {
    // All blocks live in one file: one test at a time reads and (with RV_UPDATE_DOCS=1) rewrites it.
    static PAGE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = PAGE.lock().unwrap_or_else(|e| e.into_inner());
    let page_path = root().join("docs/reports.md");
    let page = std::fs::read_to_string(&page_path)
        .unwrap()
        .replace("\r\n", "\n");
    let (Some(a), Some(b)) = (page.find(start), page.find(end)) else {
        panic!("docs/reports.md has no generated block {start}");
    };
    let current = &page[a..b + end.len()];
    if current != fresh {
        if std::env::var("RV_UPDATE_DOCS").as_deref() == Ok("1") {
            let updated = format!("{}{}{}", &page[..a], fresh, &page[b + end.len()..]);
            std::fs::write(&page_path, updated).unwrap();
        } else {
            panic!(
                "docs/reports.md differs from i18n/en.json ({start}): run \
                 RV_UPDATE_DOCS=1 cargo test -p rv-timeline-core --test docs_catalogue"
            );
        }
    }
}

#[test]
fn reports_page_lists_the_signals_exactly() {
    check_block(SIG_START, SIG_END, &signals_table());
}

#[test]
fn reports_page_lists_the_event_kinds_exactly() {
    check_block(KIND_START, KIND_END, &kinds_table());
}

#[test]
fn reports_page_lists_the_limitations_exactly() {
    check_block(LIM_START, LIM_END, &limitations_table());
}
