//! Data model of the case timeline — FROZEN for v0.1.
//!
//! Field names here are the contract between the source readers (one per Rakvor tool), the timeline engine,
//! the outputs (`timeline.jsonl` for Timesketch, the reports) and the CLI/GUI. Later work may add fields
//! (with `#[serde(default)]`), never rename or remove one.
//!
//! ```text
//! case folder ──► RunRef × n (case.json + runs/<tool>/<run>/)
//!   each run ──► verified first (audit chain + digests of the files read) ──► excluded runs: RUN_NOT_VERIFIED
//!   verified run ──► SourceReader for its tool ──► TimeEvent × n (each cites run, output file, digest, pointer)
//! all events ──► engine: sort by UTC (zone-unknown events kept, flagged), cross-source Signals ──► outputs
//! ```
//!
//! Times are integers only (seconds + nanoseconds since the Unix epoch, offsets in minutes): the audit chain is
//! canonical JSON with integers and strings, never floats.
//!
//! # Conventions (readers, engine and the sample case's ground truth all follow these)
//!
//! **Event id** — `<tool>:<run_id>:<item>[/<sub>]:<kind>:<n>`.
//! - `<item>` is the evidence id (`E0004`); `i<index>` (the run's item index) when the run did not link the item to
//!   the registry; `run` for run-level events.
//! - `/<sub>` is present only when [`ItemRef::sub`] is not empty, always with a `/` (`E0016/#3`, `E0018/r2`).
//! - `n` counts **from 0** per (run, item/sub, kind), in the order the values appear in the source file (the same
//!   base as the JSON pointer indices).
//!
//! **What counts as an event**: one time value written in a tool's audited output, once per run that wrote it. A
//! value derived from other events (first/last of a conversation, a duration) is not an event; two different source
//! values with the same instant are two events (e.g. a PDF signature's `/M` and its CMS signingTime).
//!
//! **Run-level events** (every tool, item `run`, from the run's `logs/audit.jsonl`, the hash-chained record):
//! `run.started` = `ts_utc` of the `run_started` entry, `run.finished` = `ts_utc` of the `run_finished` entry,
//! `run.timestamped` = `details.gen_time` of each `timestamp_obtained` entry. `reports/statistics.json` holds close
//! but different times (written before the final audit entry) and is not used.
//!
//! **Kinds and sources per tool** (`fs.modified` comes from every tool: `item_started.details.modified_utc` in the
//! audit log, once per item and run — the messages of an mbox share their container's):
//!
//! | Tool | Kinds (source) | Sub-item |
//! | --- | --- | --- |
//! | rv-hashinv | `intake.registered` (`technical.json` `/case/intake_utc`, only items this run registered) | none |
//! | rv-imgauth | `exif.original`, `exif.digitized`, `exif.modify` (EXIF DateTimeOriginal / DateTimeDigitized / IFD0 DateTime + OffsetTime* + SubSecTime*), `gps.time`, `xmp.create`, `xmp.modify`, `xmp.metadata`, `xmp.photoshop_created`, `xmp.exif_original`, `xmp.history`, `png.time`, `png.creation_time` (`metadata.json`) | none |
//! | rv-pdfauth | `pdf.info.created`, `pdf.info.modified` (Info dictionary of each revision, `objects.json`); `pdf.signature.claimed` (a signature dictionary's `/M`); `pdf.revision.signed` (CMS signingTime, `technical.json`); `pdf.xmp.saved`; `pdf.info.saved` (only without `objects.json`) | `r<n>`, revision n from 1 |
//! | rv-rsmf | `chat.message`, `chat.join`, `chat.leave`, `chat.history`, `chat.disclaimer`, `chat.unknown` (one per `rsmf/trace.json` row, by its RSMF kind) | `<conversation id>/<day>`: the row's `conversation` and the stem of its `rsmf_file` (`c-554810aa3173/2026-03-02`) |
//! | rv-mailauth | `mail.date`, `mail.hop` (`headers.json`), `mail.attachment.created`, `mail.attachment.modified`, `mail.msg.submitted`, `mail.msg.delivered`, `mail.mbox_from` (`mbox_index.json`, the mbox `From ` line) | `#<n>` for message n of an mbox, else none |
//! | rv-certcheck | `cert.not_before`, `cert.not_after`, `cert.revoked`, `tsa.gen_time` (`chain.json`) | `c<n>` (n-th certificate of the file, from 1) when the file holds several certificates; none when it holds one (and for `tsa.gen_time`) |
//!
//! **Zone**: [`ZoneInfo::Explicit`] when the value or the tool's output states it (an RFC 5322 date, ISO 8601 with
//! an offset or `Z`, EXIF with its OffsetTime*, PNG tIME — UTC by the PNG specification and labelled UTC by
//! rv-imgauth —, a chat time converted by rv-rsmf with the examiner's `--timezone`); [`ZoneInfo::Unknown`] when it
//! does not (EXIF without OffsetTime*, an mbox `From ` line, a chat time without `--timezone`, `-0000`).
//! [`Timeline::zone_unknown`] counts them and the engine emits **one** case-level `ZONE_UNKNOWN_EVENTS` (info,
//! no item) with that count.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// How precise the source's time is. A date-only EXIF value is `Day`; RFC 5322 dates are `Second`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Precision {
    Day,
    Minute,
    #[default]
    Second,
    Millisecond,
    Microsecond,
    Nanosecond,
}

/// What the source said about the time zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ZoneInfo {
    /// The source states an offset (`+0100`, `Z`): `offset_min` holds it.
    #[default]
    Explicit,
    /// The source has no zone (EXIF without OffsetTime, a "local time" field). The event is placed as if it were
    /// UTC and flagged; it is never converted with a guessed zone.
    Unknown,
}

/// One point in time from one source. `utc_s`/`utc_ns` is the instant (for `ZoneInfo::Unknown`, the wall-clock
/// time read as UTC); `original` keeps the source's own wording, unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TimeEvent {
    /// Stable id: `<tool>:<run_id>:<item>[/<sub>]:<kind>:<n>`, n from 0 (see the module's conventions) — unique in
    /// a timeline, the same on every rebuild.
    pub id: String,
    pub utc_s: i64,
    #[serde(default)]
    pub utc_ns: u32,
    pub zone: ZoneInfo,
    /// Offset of the original time from UTC, in minutes (None when `zone` is Unknown).
    pub offset_min: Option<i32>,
    pub precision: Precision,
    /// The time exactly as the source wrote it (e.g. `Tue, 10 Nov 2026 11:00:00 +0100`, `2026:11:10 10:00:00`).
    pub original: String,
    /// What kind of time this is, a dotted key also used for i18n: `intake.registered`, `fs.modified`,
    /// `fs.created`, `fs.accessed`, `exif.original`, `exif.digitized`, `xmp.modify`, `pdf.info.created`,
    /// `pdf.info.modified`, `pdf.revision.signed`, `chat.message`, `mail.date`, `mail.hop`, `cert.not_before`,
    /// `cert.not_after`, `cert.revoked`, `tsa.gen_time`, `run.started`, `run.finished`, … (readers may add keys;
    /// each needs an i18n label).
    pub kind: String,
    pub item: ItemRef,
    pub source: SourceRef,
    /// Short, language-neutral details for the reports (sender, revision number, camera model, hop host…).
    /// Strings only; long values are capped by the reader.
    #[serde(default)]
    pub details: BTreeMap<String, String>,
}

/// The evidence the event is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ItemRef {
    /// Evidence id from the case registry (`E0001`), empty when the run was not linked to the registry.
    pub evidence_id: String,
    /// Path as the tool recorded it (registry path, or `<mbox>#<n>@<offset>` for a derived item).
    pub path: String,
    /// Sub-item inside the evidence: PDF revision `r2`, mbox message `#3`, chat `<conversation id>/<day>`,
    /// certificate `c2` of a file holding several; empty if none (formats per tool: the module's conventions).
    #[serde(default)]
    pub sub: String,
    /// SHA-256 of the evidence as registered (from the registry or the run), empty if unknown.
    #[serde(default)]
    pub sha256: String,
}

/// Where the event was read: which tool run, which output file, which place in it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SourceRef {
    pub tool: String,
    pub tool_version: String,
    pub run_id: String,
    /// Run folder relative to the case folder (`runs/rv-imgauth/20261110T100000Z-ab12cd`).
    pub run_dir: String,
    /// Output file relative to the run folder (`reports/items/00003-photo.jpg/technical.json`).
    pub file: String,
    /// SHA-256 of that output file as recorded in the run's audit log (checked before reading).
    pub file_sha256: String,
    /// JSON pointer (`/metadata/exif/DateTimeOriginal`) or `line:<n>` inside the file.
    pub pointer: String,
}

/// One tool run found in the case folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RunRef {
    pub tool: String,
    pub tool_version: String,
    pub run_id: String,
    /// Relative to the case folder.
    pub run_dir: String,
    pub status: RunStatus,
    /// Why the run was excluded (i18n key `exclusion.<reason>`) and short details.
    #[serde(default)]
    pub exclusion: Option<Exclusion>,
    /// Events read from this run (0 when excluded).
    #[serde(default)]
    pub events: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    #[default]
    Verified,
    /// Audit chain broken, an output's digest differs from the audit log, the run did not finish, or no reader
    /// supports this tool/version. Its events are not in the timeline.
    Excluded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Exclusion {
    /// `chain_broken`, `digest_mismatch`, `not_finished`, `unsupported_tool`, `unsupported_version`, `unreadable`
    pub reason: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

/// A cross-source signal about time: what the events show together. Never a verdict; i18n gives
/// `title`, `shows` and `does_not_prove` for each code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// `EXIF_AFTER_INTAKE`, `MAIL_DATE_AFTER_FIRST_HOP`, `PDF_REVISION_BEFORE_PREVIOUS`, `FILE_MODIFIED_AFTER_INTAKE`,
    /// `EVENT_IN_FUTURE`, `CLOCK_SKEW_SUSPECTED`, `RUN_NOT_VERIFIED`, `ZONE_UNKNOWN_EVENTS`.
    /// `CLOCK_SKEW_SUSPECTED` has two bases (param `basis`): `tools`, two tools reading the same facts a constant offset
    /// apart, or `received_hops`: a message's Received hop stamped more than the tolerance before the hop before
    /// it. `ZONE_UNKNOWN_EVENTS` is one case-level signal (no item) with the count.
    pub code: String,
    pub severity: Severity,
    /// Ids of the events involved (empty for run-level signals).
    #[serde(default)]
    pub events: Vec<String>,
    /// The evidence item concerned, when there is one.
    #[serde(default)]
    pub item: Option<ItemRef>,
    /// Integers and strings for the i18n templates (e.g. `delta_s`, `skew_s`, `tool`).
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

/// The built timeline: runs considered, events sorted by (utc_s, utc_ns, id), signals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Timeline {
    pub case_id: String,
    pub runs: Vec<RunRef>,
    pub events: Vec<TimeEvent>,
    pub signals: Vec<Signal>,
    /// Events whose zone is unknown (also in `events`).
    #[serde(default)]
    pub zone_unknown: u64,
}

/// Options of a timeline build; the CLI flags and GUI settings map 1:1 onto these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineOptions {
    /// `--case-dir`: the case folder to read (required).
    pub case_dir: PathBuf,
    /// `--display-zone`: zone the reports show times in besides UTC: `UTC`, a fixed offset `-05:00`, or one of the
    /// named zones `America/Bogota`, `Europe/Paris` (CET/CEST rules built in, no tz database needed).
    pub display_zone: String,
    /// `--tool`: only these tools' runs (empty = all supported tools).
    #[serde(default)]
    pub tools: Vec<String>,
    /// `--from` / `--to`: only events in this UTC window (seconds since the epoch), inclusive.
    #[serde(default)]
    pub from_s: Option<i64>,
    #[serde(default)]
    pub to_s: Option<i64>,
    /// `--clock-skew`: tolerated difference between sources, seconds, before a cross-source order is a signal.
    pub clock_skew_s: u64,
    /// `--max-events`: stop reading after this many events (recorded as a limitation, never silent).
    pub max_events: u64,
    /// `--timesketch`: also write `timeline.jsonl` (Timesketch import format). On by default.
    pub timesketch: bool,
}

impl Default for TimelineOptions {
    fn default() -> Self {
        TimelineOptions {
            case_dir: PathBuf::new(),
            display_zone: "UTC".into(),
            tools: Vec::new(),
            from_s: None,
            to_s: None,
            clock_skew_s: 300,
            max_events: 5_000_000,
            timesketch: true,
        }
    }
}

/// Errors a reader returns for a run it cannot read: the run is then excluded with this reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadError {
    pub reason: String,
    pub detail: String,
}

/// One source reader per Rakvor tool. Readers only read files the run's audit log lists with a digest, and check
/// that digest first (`verify_output`); they never write.
pub trait SourceReader: Send + Sync {
    /// Tool name as in `describe --json` (`rv-imgauth`).
    fn tool(&self) -> &'static str;
    /// Whether this reader understands outputs of that tool version (semver string); unsupported versions exclude
    /// the run with `unsupported_version` instead of guessing.
    fn supports(&self, tool_version: &str) -> bool;
    /// Reads the events of one verified run.
    fn read(&self, case_dir: &std::path::Path, run: &RunRef) -> Result<Vec<TimeEvent>, ReadError>;
}
