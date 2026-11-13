//! Timeline engine: merge and sort events (stable order: utc_s, utc_ns, id), apply the options' window and tool
//! filter, compute cross-source [`Signal`]s, convert to the display zone, and write `timeline.jsonl` (Timesketch).
//! Streams and sorts on disk past an in-memory threshold ([`EventSorter`]).
//!
//! ```text
//! verified run ──► events (one batch per run) ──► keep()? ──► SignalEngine::observe_batch ──► EventSorter::push
//!                                                                                               │ (spills sorted
//!                                                                                               ▼  chunks past N)
//! SignalEngine::finish(runs) ──► signals            EventSorter::finish ──► k-way merge ──► timeline.jsonl, reports
//! ```
//!
//! Times are never guessed: an event whose zone is unknown keeps its wall-clock time read as UTC, is counted
//! (`ZONE_UNKNOWN_EVENTS`) and is shown "as written" in the reports, never converted to the display zone. Any
//! comparison that involves such an event widens its tolerance by [`ZONE_MARGIN_S`] (the largest UTC offset).

use crate::model::{
    ItemRef, Precision, RunRef, RunStatus, Severity, Signal, TimeEvent, Timeline, TimelineOptions,
    ZoneInfo,
};
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime};
use serde_json::{Map, Value, json};
use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Lines, Write};
use std::path::{Path, PathBuf};

/// Largest distance between a wall-clock time and UTC (UTC+14 / UTC-12): the margin added to the tolerance when a
/// comparison involves an event whose zone is unknown.
pub const ZONE_MARGIN_S: i64 = 14 * 3600;

/// Events kept in memory before [`EventSorter`] spills a sorted chunk to disk.
pub const DEFAULT_SORT_THRESHOLD: usize = 250_000;

/// Signal codes, in the order the reports list them.
pub const SIGNAL_CODES: [&str; 8] = [
    "EXIF_AFTER_INTAKE",
    "MAIL_DATE_AFTER_FIRST_HOP",
    "PDF_REVISION_BEFORE_PREVIOUS",
    "FILE_MODIFIED_AFTER_INTAKE",
    "EVENT_IN_FUTURE",
    "CLOCK_SKEW_SUSPECTED",
    "RUN_NOT_VERIFIED",
    "ZONE_UNKNOWN_EVENTS",
];

// ---------------------------------------------------------------------------------------------------------------
// Display zone
// ---------------------------------------------------------------------------------------------------------------

/// The zone the reports show times in besides UTC. Named zones carry their rules (no tz database).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayZone {
    Utc,
    /// Fixed offset from UTC, minutes (never 0: that is `Utc`).
    Fixed(i32),
    /// America/Bogota: UTC-05:00 all year (Colombia has no daylight saving time since 1993).
    Bogota,
    /// Europe/Paris: CET (UTC+01:00), CEST (UTC+02:00) from the last Sunday of March 01:00 UTC to the last Sunday
    /// of October 01:00 UTC (EU rules, in force since 1996).
    Paris,
}

fn parse_offset(s: &str) -> Option<i32> {
    let (sign, rest) = match s.as_bytes().first()? {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    let digits: String = rest.chars().filter(|c| *c != ':').collect();
    if !digits.chars().all(|c| c.is_ascii_digit()) || rest.matches(':').count() > 1 {
        return None;
    }
    let (h, m) = match digits.len() {
        1 | 2 => (digits.parse::<i32>().ok()?, 0),
        3 | 4 => {
            let (h, m) = digits.split_at(digits.len() - 2);
            (h.parse::<i32>().ok()?, m.parse::<i32>().ok()?)
        }
        _ => return None,
    };
    if m >= 60 || h * 60 + m > 14 * 60 {
        return None;
    }
    Some(sign * (h * 60 + m))
}

/// `+HH:MM` / `-HH:MM`.
pub fn offset_text(min: i32) -> String {
    let sign = if min < 0 { '-' } else { '+' };
    let a = min.unsigned_abs();
    format!("{}{:02}:{:02}", sign, a / 60, a % 60)
}

/// Last Sunday of `month` (31-day months only: March, October) at 01:00 UTC, seconds since the epoch.
fn last_sunday_0100_utc(year: i32, month: u32) -> Option<i64> {
    let d = NaiveDate::from_ymd_opt(year, month, 31)?;
    let back = d.weekday().num_days_from_sunday() as u64;
    let sunday = d.checked_sub_days(chrono::Days::new(back))?;
    Some(sunday.and_hms_opt(1, 0, 0)?.and_utc().timestamp())
}

/// Whether Paris is on summer time (CEST) at this instant.
pub fn paris_summer_time(utc_s: i64) -> bool {
    let Some(dt) = DateTime::from_timestamp(utc_s, 0) else {
        return false;
    };
    let y = dt.year();
    match (last_sunday_0100_utc(y, 3), last_sunday_0100_utc(y, 10)) {
        (Some(start), Some(end)) => utc_s >= start && utc_s < end,
        _ => false,
    }
}

impl DisplayZone {
    /// `UTC`, `Z`, a fixed offset (`-05:00`, `+0100`, `UTC+02:00`), `America/Bogota` or `Europe/Paris`
    /// (case-insensitive).
    pub fn parse(s: &str) -> Result<DisplayZone, String> {
        let t = s.trim();
        let lower = t.to_ascii_lowercase();
        let named = match lower.as_str() {
            "utc" | "z" | "gmt" | "etc/utc" => Some(DisplayZone::Utc),
            "america/bogota" => Some(DisplayZone::Bogota),
            "europe/paris" => Some(DisplayZone::Paris),
            _ => None,
        };
        if let Some(z) = named {
            return Ok(z);
        }
        let body = lower
            .strip_prefix("utc")
            .or_else(|| lower.strip_prefix("gmt"))
            .unwrap_or(&lower);
        match parse_offset(body) {
            Some(0) => Ok(DisplayZone::Utc),
            Some(m) => Ok(DisplayZone::Fixed(m)),
            None => Err(format!(
                "unknown display zone '{}': use UTC, a fixed offset such as -05:00, America/Bogota or Europe/Paris",
                s
            )),
        }
    }

    /// Canonical name, as recorded in the audit log and printed on every report page.
    pub fn name(&self) -> String {
        match self {
            DisplayZone::Utc => "UTC".into(),
            DisplayZone::Fixed(m) => format!("UTC{}", offset_text(*m)),
            DisplayZone::Bogota => "America/Bogota".into(),
            DisplayZone::Paris => "Europe/Paris".into(),
        }
    }

    /// Offset from UTC at this instant, minutes.
    pub fn offset_at(&self, utc_s: i64) -> i32 {
        match self {
            DisplayZone::Utc => 0,
            DisplayZone::Fixed(m) => *m,
            DisplayZone::Bogota => -300,
            DisplayZone::Paris => {
                if paris_summer_time(utc_s) {
                    120
                } else {
                    60
                }
            }
        }
    }

    /// Short label of the zone at this instant: `UTC`, `UTC-05:00`, `COT`, `CET`, `CEST`.
    pub fn abbrev_at(&self, utc_s: i64) -> String {
        match self {
            DisplayZone::Utc => "UTC".into(),
            DisplayZone::Fixed(m) => format!("UTC{}", offset_text(*m)),
            DisplayZone::Bogota => "COT".into(),
            DisplayZone::Paris => {
                if paris_summer_time(utc_s) {
                    "CEST".into()
                } else {
                    "CET".into()
                }
            }
        }
    }

    /// `2026-11-10 11:00:00 CET (+01:00)`; for UTC `2026-11-10 10:00:00 UTC`. Day-precision times show the date.
    pub fn format(&self, utc_s: i64, utc_ns: u32, precision: Precision) -> String {
        let off = self.offset_at(utc_s);
        let wall = wall_clock(utc_s.saturating_add(off as i64 * 60), utc_ns, precision);
        match self {
            DisplayZone::Utc => format!("{} UTC", wall),
            _ => format!("{} {} ({})", wall, self.abbrev_at(utc_s), offset_text(off)),
        }
    }
}

fn fraction(ns: u32, precision: Precision) -> String {
    match precision {
        Precision::Millisecond => format!(".{:03}", ns / 1_000_000),
        Precision::Microsecond => format!(".{:06}", ns / 1_000),
        Precision::Nanosecond => format!(".{:09}", ns),
        _ => String::new(),
    }
}

/// `YYYY-MM-DD HH:MM:SS[.fff]` of a wall-clock instant (no zone); `@<seconds>` when out of range.
pub fn wall_clock(s: i64, ns: u32, precision: Precision) -> String {
    let Some(dt) = DateTime::from_timestamp(s, 0) else {
        return format!("@{}", s);
    };
    match precision {
        Precision::Day => dt.format("%Y-%m-%d").to_string(),
        Precision::Minute => dt.format("%Y-%m-%d %H:%M").to_string(),
        p => format!("{}{}", dt.format("%Y-%m-%d %H:%M:%S"), fraction(ns, p)),
    }
}

/// ISO 8601 UTC with the event's precision: `2026-11-10T10:00:00Z`, `2026-11-10T10:00:00.123Z`, `2026-11-10`.
pub fn fmt_utc(s: i64, ns: u32, precision: Precision) -> String {
    let Some(dt) = DateTime::from_timestamp(s, 0) else {
        return format!("@{}", s);
    };
    match precision {
        Precision::Day => dt.format("%Y-%m-%d").to_string(),
        Precision::Minute => dt.format("%Y-%m-%dT%H:%MZ").to_string(),
        p => format!("{}{}Z", dt.format("%Y-%m-%dT%H:%M:%S"), fraction(ns, p)),
    }
}

/// How an event's time reads in the display zone: `None` when the event's zone is unknown (never converted).
pub fn display_time(e: &TimeEvent, zone: &DisplayZone) -> Option<String> {
    match e.zone {
        ZoneInfo::Unknown => None,
        ZoneInfo::Explicit => Some(zone.format(e.utc_s, e.utc_ns, e.precision)),
    }
}

/// UTC column of an event: ISO UTC, or for a zone-unknown event the wall clock as written (no `Z`).
pub fn utc_time(e: &TimeEvent) -> String {
    match e.zone {
        ZoneInfo::Explicit => fmt_utc(e.utc_s, e.utc_ns, e.precision),
        ZoneInfo::Unknown => wall_clock(e.utc_s, e.utc_ns, e.precision),
    }
}

/// "3 d 04 h 05 min", "2 h 05 min", "4 min 05 s", "12 s" (absolute value).
pub fn human_delta(secs: i64) -> String {
    let s = secs.unsigned_abs();
    match s {
        0..=59 => format!("{} s", s),
        60..=3599 => format!("{} min {:02} s", s / 60, s % 60),
        3600..=86_399 => format!("{} h {:02} min", s / 3600, (s % 3600) / 60),
        _ => format!(
            "{} d {:02} h {:02} min",
            s / 86_400,
            (s % 86_400) / 3600,
            (s % 3600) / 60
        ),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Ordering and filters
// ---------------------------------------------------------------------------------------------------------------

/// The timeline order: (utc_s, utc_ns, id). Ids are unique, so the order is total and the same on every rebuild.
pub fn cmp_events(a: &TimeEvent, b: &TimeEvent) -> Ordering {
    (a.utc_s, a.utc_ns, &a.id).cmp(&(b.utc_s, b.utc_ns, &b.id))
}

/// Whether the options keep this event: tool filter (empty = all) and the inclusive UTC window.
pub fn keep(e: &TimeEvent, opts: &TimelineOptions) -> bool {
    if !opts.tools.is_empty() && !opts.tools.iter().any(|t| t == &e.source.tool) {
        return false;
    }
    if opts.from_s.is_some_and(|f| e.utc_s < f) {
        return false;
    }
    if opts.to_s.is_some_and(|t| e.utc_s > t) {
        return false;
    }
    true
}

/// Sorts events into the timeline order and applies the window/tool filters (in memory).
pub fn order(events: Vec<TimeEvent>, opts: &TimelineOptions) -> Vec<TimeEvent> {
    let mut events: Vec<TimeEvent> = events.into_iter().filter(|e| keep(e, opts)).collect();
    events.sort_by(cmp_events);
    events
}

// ---------------------------------------------------------------------------------------------------------------
// External merge sort
// ---------------------------------------------------------------------------------------------------------------

/// Sorts any number of events with bounded memory: past `threshold` events in memory, the buffer is sorted and
/// written to a chunk file (JSON lines) in a private folder under `spill_parent`; [`EventSorter::finish`] merges the
/// chunks. The folder is removed when the sorted stream is dropped.
pub struct EventSorter {
    threshold: usize,
    buf: Vec<TimeEvent>,
    spill_parent: PathBuf,
    dir: Option<PathBuf>,
    chunks: Vec<PathBuf>,
    total: u64,
}

impl EventSorter {
    pub fn new(spill_parent: &Path, threshold: usize) -> EventSorter {
        EventSorter {
            threshold: threshold.max(1),
            buf: Vec::new(),
            spill_parent: spill_parent.to_path_buf(),
            dir: None,
            chunks: Vec::new(),
            total: 0,
        }
    }

    pub fn push(&mut self, e: TimeEvent) -> io::Result<()> {
        self.buf.push(e);
        self.total += 1;
        if self.buf.len() >= self.threshold {
            self.spill()?;
        }
        Ok(())
    }

    /// Events pushed so far.
    pub fn len(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Chunk files written so far (0 = everything sorted in memory).
    pub fn spilled_chunks(&self) -> usize {
        self.chunks.len()
    }

    fn spill(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let dir = match &self.dir {
            Some(d) => d.clone(),
            None => {
                let d = self.spill_parent.join(format!(
                    "sort-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                ));
                std::fs::create_dir_all(&d)?;
                self.dir = Some(d.clone());
                d
            }
        };
        self.buf.sort_by(cmp_events);
        let p = dir.join(format!("chunk-{:05}.jsonl", self.chunks.len()));
        let mut w = BufWriter::new(File::create(&p)?);
        for e in self.buf.drain(..) {
            serde_json::to_writer(&mut w, &e)?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
        self.chunks.push(p);
        Ok(())
    }

    /// The events in timeline order.
    pub fn finish(mut self) -> io::Result<SortedEvents> {
        if self.chunks.is_empty() {
            let mut buf = std::mem::take(&mut self.buf);
            buf.sort_by(cmp_events);
            return Ok(SortedEvents {
                inner: Inner::Memory(buf.into_iter()),
                dir: None,
            });
        }
        self.spill()?;
        let mut readers = Vec::with_capacity(self.chunks.len());
        let mut heap = BinaryHeap::new();
        for (i, p) in self.chunks.iter().enumerate() {
            let mut lines = BufReader::new(File::open(p)?).lines();
            if let Some(e) = next_event(&mut lines)? {
                heap.push(Reverse(HeapItem { e, src: i }));
            }
            readers.push(lines);
        }
        Ok(SortedEvents {
            inner: Inner::Merge { readers, heap },
            dir: self.dir.take(),
        })
    }
}

impl Drop for EventSorter {
    fn drop(&mut self) {
        if let Some(d) = self.dir.take() {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

fn next_event(lines: &mut Lines<BufReader<File>>) -> io::Result<Option<TimeEvent>> {
    match lines.next() {
        None => Ok(None),
        Some(l) => {
            let l = l?;
            serde_json::from_str(&l)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        }
    }
}

struct HeapItem {
    e: TimeEvent,
    src: usize,
}

impl PartialEq for HeapItem {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}
impl Eq for HeapItem {}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for HeapItem {
    fn cmp(&self, o: &Self) -> Ordering {
        cmp_events(&self.e, &o.e).then(self.src.cmp(&o.src))
    }
}

enum Inner {
    Memory(std::vec::IntoIter<TimeEvent>),
    Merge {
        readers: Vec<Lines<BufReader<File>>>,
        heap: BinaryHeap<Reverse<HeapItem>>,
    },
}

/// Sorted event stream from [`EventSorter::finish`]; removes its chunk folder when dropped.
pub struct SortedEvents {
    inner: Inner,
    dir: Option<PathBuf>,
}

impl Iterator for SortedEvents {
    type Item = io::Result<TimeEvent>;
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            Inner::Memory(it) => it.next().map(Ok),
            Inner::Merge { readers, heap } => {
                let Reverse(HeapItem { e, src }) = heap.pop()?;
                match next_event(&mut readers[src]) {
                    Ok(Some(n)) => heap.push(Reverse(HeapItem { e: n, src })),
                    Ok(None) => {}
                    Err(err) => return Some(Err(err)),
                }
                Some(Ok(e))
            }
        }
    }
}

impl Drop for SortedEvents {
    fn drop(&mut self) {
        if let Some(d) = self.dir.take() {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------------------------------------------

/// Kinds that legitimately lie after the run that recorded them (validity ends, next updates): never
/// `EVENT_IN_FUTURE`.
const FORWARD_KINDS: [&str; 3] = ["cert.not_after", "crl.next_update", "ocsp.next_update"];

/// Kinds compared across tools for `CLOCK_SKEW_SUSPECTED` (the same fact read by several tools). High-volume kinds
/// (chat messages, mail hops) are left out to keep memory bounded.
const SKEW_PREFIXES: [&str; 7] = [
    "fs.",
    "exif.",
    "xmp.",
    "pdf.info.",
    "mail.date",
    "cert.",
    "tsa.",
];

/// Kind that gives a PDF revision its time, by priority.
const PDF_REVISION_KINDS: [&str; 3] = ["pdf.revision.signed", "pdf.info.modified", "xmp.modify"];

#[derive(Clone, Debug)]
struct Mini {
    id: String,
    s: i64,
    /// Seconds covered by the event's precision (Day = 86 400).
    span: i64,
    unknown: bool,
    original: String,
    kind: String,
}

impl Mini {
    fn of(e: &TimeEvent) -> Mini {
        Mini {
            id: e.id.clone(),
            s: e.utc_s,
            span: match e.precision {
                Precision::Day => 86_400,
                Precision::Minute => 60,
                _ => 1,
            },
            unknown: e.zone == ZoneInfo::Unknown,
            original: e.original.clone(),
            kind: e.kind.clone(),
        }
    }
    /// Last second covered.
    fn end(&self) -> i64 {
        self.s.saturating_add(self.span - 1)
    }
}

/// The intake time an item is compared with.
#[derive(Clone, Debug)]
struct Anchor {
    s: i64,
    /// Event id when the intake came from an `intake.registered` event (else the registry).
    event: Option<String>,
    /// Run that registered the item (with `event`): its `fs.modified` is the time seen at intake.
    run_id: Option<String>,
    text: String,
}

/// One `mail.hop` of a message: the run that read it, its `Received` position (1 = first relay), relay host.
#[derive(Clone, Debug)]
struct Hop {
    run_id: String,
    position: Option<u32>,
    by: String,
    m: Mini,
}

#[derive(Default)]
struct MailGroup {
    date: Vec<Mini>,
    hops: Vec<Hop>,
}

/// `<evidence_id>` or `path:<path>` for items not linked to the registry.
pub fn item_key(i: &ItemRef) -> String {
    if i.evidence_id.is_empty() {
        format!("path:{}", i.path)
    } else {
        i.evidence_id.clone()
    }
}

fn revision_number(e: &TimeEvent) -> Option<u32> {
    let parse = |s: &str| {
        let t = s.trim().trim_start_matches(['r', 'R']);
        let t = t.strip_prefix("ev").unwrap_or(t);
        t.parse::<u32>().ok()
    };
    parse(&e.item.sub).or_else(|| e.details.get("revision").and_then(|r| parse(r)))
}

/// Start time encoded in a Rakvor run id (`20261110T100000Z-ab12cd`).
pub fn run_id_start(run_id: &str) -> Option<i64> {
    let stamp = run_id.get(..16)?;
    NaiveDateTime::parse_from_str(stamp, "%Y%m%dT%H%M%SZ")
        .ok()
        .map(|d| d.and_utc().timestamp())
}

/// Parses an RFC 3339 / ISO 8601 UTC time (`2026-11-10T10:00:00.123Z`) to seconds.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|d| d.timestamp())
}

fn p(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

/// How a signal names a message: its sub-item (`#3` in an mbox), else the file name of the item.
fn message_name(sub: &str, item: Option<&ItemRef>) -> String {
    if !sub.is_empty() {
        return sub.to_string();
    }
    item.map(|i| {
        i.path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_string()
    })
    .filter(|n| !n.is_empty())
    .or_else(|| item.map(|i| i.evidence_id.clone()))
    .unwrap_or_default()
}

fn item_only(i: &ItemRef) -> ItemRef {
    ItemRef {
        sub: String::new(),
        ..i.clone()
    }
}

type SkewFacts = BTreeMap<(String, String), BTreeMap<String, Mini>>;
type FutureHits = Vec<(Mini, i64, String)>;
type PairDeltas = Vec<(i64, String, String)>;

/// Computes the cross-source signals incrementally: events are observed one run batch at a time (memory holds only
/// the few kinds the signals compare), then [`SignalEngine::finish`] returns the signals in a stable order.
pub struct SignalEngine {
    tol: i64,
    intake: BTreeMap<String, Anchor>,
    items: BTreeMap<String, ItemRef>,
    exif: BTreeMap<String, Vec<Mini>>,
    /// item key → (run id, fs.modified)
    fs_mod: BTreeMap<String, Vec<(String, Mini)>>,
    mail: BTreeMap<(String, String), MailGroup>,
    pdf: BTreeMap<String, BTreeMap<u32, Vec<Mini>>>,
    /// item key → (kind, sub) → tool → first explicit-zone value
    skew: BTreeMap<String, SkewFacts>,
    /// (item key, run id) → (event, delta, reference text)
    future: BTreeMap<(String, String), FutureHits>,
    zone_unknown: u64,
    zone_unknown_tools: BTreeSet<String>,
}

impl SignalEngine {
    pub fn new(opts: &TimelineOptions) -> SignalEngine {
        SignalEngine {
            tol: opts.clock_skew_s.min(i64::MAX as u64) as i64,
            intake: BTreeMap::new(),
            items: BTreeMap::new(),
            exif: BTreeMap::new(),
            fs_mod: BTreeMap::new(),
            mail: BTreeMap::new(),
            pdf: BTreeMap::new(),
            skew: BTreeMap::new(),
            future: BTreeMap::new(),
            zone_unknown: 0,
            zone_unknown_tools: BTreeSet::new(),
        }
    }

    /// Intake time of an evidence item from the audited case registry (`registered_utc`). The earliest of the
    /// registry and any `intake.registered` event is used.
    pub fn add_registry_intake(&mut self, evidence_id: &str, registered_utc: &str) {
        if let Some(s) = parse_rfc3339(registered_utc) {
            self.anchor(
                evidence_id,
                Anchor {
                    s,
                    event: None,
                    run_id: None,
                    text: registered_utc.to_string(),
                },
            );
        }
    }

    fn anchor(&mut self, evidence_id: &str, a: Anchor) {
        match self.intake.get(evidence_id) {
            Some(cur) if cur.s < a.s || (cur.s == a.s && cur.event.is_some()) => {}
            _ => {
                self.intake.insert(evidence_id.to_string(), a);
            }
        }
    }

    /// Events with no zone so far.
    pub fn zone_unknown(&self) -> u64 {
        self.zone_unknown
    }

    /// Observes the events of one or more runs (each run's events should come in one batch: its `run.finished`
    /// time is the reference for `EVENT_IN_FUTURE`; without one the start encoded in the run id is used).
    pub fn observe_batch(&mut self, events: &[TimeEvent]) {
        let mut run_ref: BTreeMap<&str, (i64, &'static str)> = BTreeMap::new();
        for e in events {
            let r = &e.source.run_id;
            match e.kind.as_str() {
                "run.finished" => {
                    let cur = run_ref.entry(r).or_insert((e.utc_s, "run_finished"));
                    if cur.1 != "run_finished" || cur.0 < e.utc_s {
                        *cur = (e.utc_s, "run_finished");
                    }
                }
                "run.started" => {
                    let cur = run_ref.entry(r).or_insert((e.utc_s, "run_started"));
                    if cur.1 == "run_started" && cur.0 < e.utc_s {
                        cur.0 = e.utc_s;
                    }
                }
                _ => {}
            }
        }
        for e in events {
            if !run_ref.contains_key(e.source.run_id.as_str())
                && let Some(s) = run_id_start(&e.source.run_id)
            {
                run_ref.insert(&e.source.run_id, (s, "run_id"));
            }
        }
        for e in events {
            let reference = run_ref.get(e.source.run_id.as_str()).copied();
            self.observe(e, reference);
        }
    }

    fn observe(&mut self, e: &TimeEvent, run_ref: Option<(i64, &'static str)>) {
        let key = item_key(&e.item);
        self.items
            .entry(key.clone())
            .or_insert_with(|| item_only(&e.item));
        let m = Mini::of(e);
        if m.unknown {
            self.zone_unknown += 1;
            self.zone_unknown_tools.insert(e.source.tool.clone());
        }
        match e.kind.as_str() {
            "intake.registered" if !e.item.evidence_id.is_empty() && !m.unknown => {
                let a = Anchor {
                    s: e.utc_s,
                    event: Some(e.id.clone()),
                    run_id: Some(e.source.run_id.clone()),
                    text: e.original.clone(),
                };
                self.anchor(&e.item.evidence_id.clone(), a);
            }
            "exif.original" => self.exif.entry(key.clone()).or_default().push(m.clone()),
            "fs.modified" => self
                .fs_mod
                .entry(key.clone())
                .or_default()
                .push((e.source.run_id.clone(), m.clone())),
            "mail.date" => self
                .mail
                .entry((key.clone(), e.item.sub.clone()))
                .or_default()
                .date
                .push(m.clone()),
            "mail.hop" => self
                .mail
                .entry((key.clone(), e.item.sub.clone()))
                .or_default()
                .hops
                .push(Hop {
                    run_id: e.source.run_id.clone(),
                    position: e
                        .details
                        .get("position")
                        .and_then(|p| p.trim().parse().ok()),
                    by: e.details.get("by").cloned().unwrap_or_default(),
                    m: m.clone(),
                }),
            _ => {}
        }
        if PDF_REVISION_KINDS.contains(&e.kind.as_str())
            && let Some(r) = revision_number(e)
        {
            self.pdf
                .entry(key.clone())
                .or_default()
                .entry(r)
                .or_default()
                .push(m.clone());
        }
        if !m.unknown && SKEW_PREFIXES.iter().any(|p| e.kind.starts_with(p)) {
            self.skew
                .entry(key.clone())
                .or_default()
                .entry((e.kind.clone(), e.item.sub.clone()))
                .or_default()
                .entry(e.source.tool.clone())
                .or_insert(m.clone());
        }
        // EVENT_IN_FUTURE: later than the run that recorded it.
        if let Some((ref_s, ref_kind)) = run_ref
            && !e.kind.starts_with("run.")
            && !FORWARD_KINDS.contains(&e.kind.as_str())
        {
            let margin = self.tol + if m.unknown { ZONE_MARGIN_S } else { 0 };
            if m.s > ref_s.saturating_add(margin) {
                self.future
                    .entry((key, e.source.run_id.clone()))
                    .or_default()
                    .push((m, e.utc_s - ref_s, ref_kind.to_string()));
            }
        }
    }

    /// The signals, sorted by (item, code, first event); run-level and case-level signals last.
    pub fn finish(self, runs: &[RunRef]) -> Vec<Signal> {
        let tol = self.tol;
        let item = |k: &str| self.items.get(k).cloned();
        let mut out: Vec<Signal> = Vec::new();

        // EXIF_AFTER_INTAKE. High: a capture time after the audited intake contradicts the registry (the content
        // was hashed before it was, per its own metadata, taken). With no zone in EXIF, only a gap beyond the
        // largest UTC offset is High; a smaller one is Medium (the zone alone could explain it).
        for (k, list) in &self.exif {
            let Some(ev_id) = self.items.get(k).map(|i| i.evidence_id.clone()) else {
                continue;
            };
            let Some(a) = self.intake.get(&ev_id) else {
                continue;
            };
            let late: Vec<&Mini> = list.iter().filter(|m| m.s > a.s + tol).collect();
            if late.is_empty() {
                continue;
            }
            let high = late
                .iter()
                .any(|m| !m.unknown || m.s > a.s + tol + ZONE_MARGIN_S);
            let worst = late.iter().map(|m| m.s - a.s).max().unwrap_or(0);
            let first = late[0];
            let mut events: Vec<String> = a.event.iter().cloned().collect();
            events.extend(late.iter().map(|m| m.id.clone()));
            out.push(Signal {
                code: "EXIF_AFTER_INTAKE".into(),
                severity: if high {
                    Severity::High
                } else {
                    Severity::Medium
                },
                events,
                item: item(k),
                params: p(&[
                    ("exif", first.original.clone()),
                    ("intake", a.text.clone()),
                    ("delta_s", worst.to_string()),
                    ("delta", human_delta(worst)),
                    ("count", late.len().to_string()),
                    (
                        "zone",
                        if first.unknown { "unknown" } else { "explicit" }.into(),
                    ),
                    ("tolerance_s", tol.to_string()),
                ]),
            });
        }

        // FILE_MODIFIED_AFTER_INTAKE. Medium: the file-system time moved after intake. The content can still match
        // the registry (copy, touch, restore) — the analysis tools verify the hash separately; this does not by
        // itself contradict the intake. A modification time counts when it is later than the intake beyond the
        // tolerance, or later than the intake and different from the one the intake run itself recorded: the file
        // was then touched after it was registered, whatever the clocks (no tolerance needed).
        for (k, list) in &self.fs_mod {
            let Some(ev_id) = self.items.get(k).map(|i| i.evidence_id.clone()) else {
                continue;
            };
            let Some(a) = self.intake.get(&ev_id) else {
                continue;
            };
            let at_intake: Vec<i64> = list
                .iter()
                .filter(|(r, _)| Some(r) == a.run_id.as_ref())
                .map(|(_, m)| m.s)
                .collect();
            let late: Vec<&Mini> = list
                .iter()
                .filter(|(r, m)| {
                    let beyond = m.s > a.s + tol + if m.unknown { ZONE_MARGIN_S } else { 0 };
                    let changed = !m.unknown
                        && m.s > a.s
                        && Some(r) != a.run_id.as_ref()
                        && !at_intake.is_empty()
                        && !at_intake.contains(&m.s);
                    beyond || changed
                })
                .map(|(_, m)| m)
                .collect();
            if late.is_empty() {
                continue;
            }
            let worst = late.iter().map(|m| m.s - a.s).max().unwrap_or(0);
            let mut events: Vec<String> = a.event.iter().cloned().collect();
            events.extend(late.iter().map(|m| m.id.clone()));
            out.push(Signal {
                code: "FILE_MODIFIED_AFTER_INTAKE".into(),
                severity: Severity::Medium,
                events,
                item: item(k),
                params: p(&[
                    ("modified", late[0].original.clone()),
                    ("intake", a.text.clone()),
                    ("delta_s", worst.to_string()),
                    ("delta", human_delta(worst)),
                    ("count", late.len().to_string()),
                    ("tolerance_s", tol.to_string()),
                ]),
            });
        }

        // MAIL_DATE_AFTER_FIRST_HOP. Medium: the Date header (set by the sender's client) is later than the first
        // relay's Received time, possibly read by different tools; clocks and relays disagree.
        for ((k, sub), g) in &self.mail {
            // The first relay: position 1 when the hops carry their position, else the earliest hop.
            let first = if g.hops.iter().any(|h| h.position.is_some()) {
                g.hops
                    .iter()
                    .filter(|h| h.position.is_some())
                    .min_by_key(|h| (h.position, h.m.s))
            } else {
                g.hops.iter().min_by_key(|h| h.m.s)
            };
            let Some(first) = first.map(|h| &h.m) else {
                continue;
            };
            for d in &g.date {
                let margin = tol
                    + if d.unknown || first.unknown {
                        ZONE_MARGIN_S
                    } else {
                        0
                    };
                if d.s > first.end() + margin {
                    let delta = d.s - first.s;
                    let mut it = item(k);
                    if let Some(i) = it.as_mut() {
                        i.sub = sub.clone();
                    }
                    let message = message_name(sub, it.as_ref());
                    out.push(Signal {
                        code: "MAIL_DATE_AFTER_FIRST_HOP".into(),
                        severity: Severity::Medium,
                        events: vec![d.id.clone(), first.id.clone()],
                        item: it,
                        params: p(&[
                            ("date", d.original.clone()),
                            ("hop", first.original.clone()),
                            ("message", message.clone()),
                            ("delta_s", delta.to_string()),
                            ("delta", human_delta(delta)),
                            ("tolerance_s", tol.to_string()),
                        ]),
                    });
                }
            }
        }

        // CLOCK_SKEW_SUSPECTED (Received hops). Low: in one message, as one run read it, a relay stamped its
        // Received time more than the tolerance *before* the relay that handed the message to it. A message only
        // moves forward, so the relays' clocks (or zones) disagree.
        for ((k, sub), g) in &self.mail {
            let mut by_run: BTreeMap<&str, Vec<&Hop>> = BTreeMap::new();
            for h in g.hops.iter().filter(|h| h.position.is_some()) {
                by_run.entry(h.run_id.as_str()).or_default().push(h);
            }
            for hops in by_run.values_mut() {
                hops.sort_by_key(|h| (h.position, h.m.s));
                for w in hops.windows(2) {
                    let (a, b) = (w[0], w[1]);
                    let margin = tol
                        + if a.m.unknown || b.m.unknown {
                            ZONE_MARGIN_S
                        } else {
                            0
                        };
                    if a.position == b.position || a.m.s <= b.m.end() + margin {
                        continue;
                    }
                    let skew = a.m.s - b.m.s;
                    let mut it = item(k);
                    if let Some(i) = it.as_mut() {
                        i.sub = sub.clone();
                    }
                    let message = message_name(sub, it.as_ref());
                    let pos = |h: &Hop| h.position.map(|p| p.to_string()).unwrap_or_default();
                    out.push(Signal {
                        code: "CLOCK_SKEW_SUSPECTED".into(),
                        severity: Severity::Low,
                        events: vec![a.m.id.clone(), b.m.id.clone()],
                        item: it,
                        params: p(&[
                            // Relay host names (the tool_a/tool_b params of the cross-source variant name tools,
                            // so they are not set here).
                            ("basis", "received_hops".into()),
                            ("previous_host", a.by.clone()),
                            ("host", b.by.clone()),
                            ("previous_hop", pos(a)),
                            ("hop", pos(b)),
                            ("message", message.clone()),
                            ("skew_s", skew.to_string()),
                            ("skew", human_delta(skew)),
                            ("pairs", "1".into()),
                            ("tolerance_s", tol.to_string()),
                        ]),
                    });
                }
            }
        }

        // PDF_REVISION_BEFORE_PREVIOUS. Medium: an incremental update dated before the revision it builds on.
        for (k, revs) in &self.pdf {
            let pick = |list: &Vec<Mini>| -> Option<Mini> {
                PDF_REVISION_KINDS
                    .iter()
                    .find_map(|kind| list.iter().find(|m| &m.kind == kind).cloned())
            };
            let timed: Vec<(u32, Mini)> = revs
                .iter()
                .filter_map(|(r, l)| pick(l).map(|m| (*r, m)))
                .collect();
            for w in timed.windows(2) {
                let ((r0, a), (r1, b)) = (&w[0], &w[1]);
                let margin = tol
                    + if a.unknown || b.unknown {
                        ZONE_MARGIN_S
                    } else {
                        0
                    };
                if b.end() + margin < a.s {
                    let delta = a.s - b.s;
                    out.push(Signal {
                        code: "PDF_REVISION_BEFORE_PREVIOUS".into(),
                        severity: Severity::Medium,
                        events: vec![a.id.clone(), b.id.clone()],
                        item: item(k),
                        params: p(&[
                            ("revision", r1.to_string()),
                            ("previous", r0.to_string()),
                            ("time", b.original.clone()),
                            ("previous_time", a.original.clone()),
                            ("delta_s", delta.to_string()),
                            ("delta", human_delta(delta)),
                            ("tolerance_s", tol.to_string()),
                        ]),
                    });
                }
            }
        }

        // EVENT_IN_FUTURE. Medium: a time later than the end of the run that read it cannot be an observed past
        // event (wrong device clock, wrong zone, or an edited value); it contradicts the tool run, not the intake.
        for ((k, run_id), list) in &self.future {
            let worst = list.iter().map(|(_, d, _)| *d).max().unwrap_or(0);
            let (first, _, reference) = &list[0];
            out.push(Signal {
                code: "EVENT_IN_FUTURE".into(),
                severity: Severity::Medium,
                events: list.iter().map(|(m, _, _)| m.id.clone()).collect(),
                item: item(k),
                params: p(&[
                    ("run_id", run_id.clone()),
                    ("time", first.original.clone()),
                    ("kind", first.kind.clone()),
                    ("reference", reference.clone()),
                    ("count", list.len().to_string()),
                    ("delta_s", worst.to_string()),
                    ("delta", human_delta(worst)),
                    ("tolerance_s", tol.to_string()),
                ]),
            });
        }

        // CLOCK_SKEW_SUSPECTED (across tools). Low: two tools read the same facts of one item at least twice, always apart by
        // more than the tolerance and by about the same amount — a clock or zone offset of one source, which also
        // explains other signals. Zone-unknown values are not compared.
        for (k, facts) in &self.skew {
            let mut pairs: BTreeMap<(String, String), PairDeltas> = BTreeMap::new();
            for by_tool in facts.values() {
                let tools: Vec<(&String, &Mini)> = by_tool.iter().collect();
                for i in 0..tools.len() {
                    for j in i + 1..tools.len() {
                        let (ta, a) = tools[i];
                        let (tb, b) = tools[j];
                        pairs.entry((ta.clone(), tb.clone())).or_default().push((
                            b.s - a.s,
                            a.id.clone(),
                            b.id.clone(),
                        ));
                    }
                }
            }
            for ((ta, tb), mut ds) in pairs {
                if ds.len() < 2 || ds.iter().any(|(d, _, _)| d.abs() <= tol) {
                    continue;
                }
                ds.sort();
                let (min, max) = (ds[0].0, ds[ds.len() - 1].0);
                if max - min > tol || (min < 0) != (max < 0) {
                    continue;
                }
                let median = ds[ds.len() / 2].0;
                out.push(Signal {
                    code: "CLOCK_SKEW_SUSPECTED".into(),
                    severity: Severity::Low,
                    events: ds
                        .iter()
                        .flat_map(|(_, a, b)| [a.clone(), b.clone()])
                        .collect(),
                    item: item(k),
                    params: p(&[
                        ("basis", "tools".into()),
                        ("tool_a", ta),
                        ("tool_b", tb),
                        ("skew_s", median.to_string()),
                        ("skew", human_delta(median)),
                        ("pairs", ds.len().to_string()),
                        ("tolerance_s", tol.to_string()),
                    ]),
                });
            }
        }

        let key_of = |s: &Signal| s.item.as_ref().map(item_key).unwrap_or_default();
        out.sort_by(|a, b| {
            (key_of(a), &a.code, &a.events, &a.params).cmp(&(
                key_of(b),
                &b.code,
                &b.events,
                &b.params,
            ))
        });

        // RUN_NOT_VERIFIED, one per excluded run. Medium when the run's own record is inconsistent (audit chain
        // broken, an output differs from its logged digest): its outputs cannot be relied on. Low for runs that
        // did not finish or that this version cannot read (nothing suggests a change, the events are just missing).
        let mut excluded: Vec<&RunRef> = runs
            .iter()
            .filter(|r| r.status == RunStatus::Excluded)
            .collect();
        excluded.sort_by(|a, b| (&a.tool, &a.run_id).cmp(&(&b.tool, &b.run_id)));
        for r in excluded {
            let (reason, detail) = r
                .exclusion
                .as_ref()
                .map(|x| (x.reason.clone(), x.detail.clone()))
                .unwrap_or_else(|| ("unreadable".into(), String::new()));
            let severity = match reason.as_str() {
                "chain_broken" | "digest_mismatch" => Severity::Medium,
                _ => Severity::Low,
            };
            out.push(Signal {
                code: "RUN_NOT_VERIFIED".into(),
                severity,
                events: vec![],
                item: None,
                params: p(&[
                    ("tool", r.tool.clone()),
                    ("version", r.tool_version.clone()),
                    ("run_id", r.run_id.clone()),
                    ("run_dir", r.run_dir.clone()),
                    ("reason", reason),
                    ("detail", detail),
                ]),
            });
        }

        // ZONE_UNKNOWN_EVENTS. Info: a count, so the reader knows how many times are wall-clock values.
        if self.zone_unknown > 0 {
            out.push(Signal {
                code: "ZONE_UNKNOWN_EVENTS".into(),
                severity: Severity::Info,
                events: vec![],
                item: None,
                params: p(&[
                    ("count", self.zone_unknown.to_string()),
                    (
                        "tools",
                        self.zone_unknown_tools
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                ]),
            });
        }
        out
    }
}

/// Cross-source signals over an ordered timeline (in memory; the pipeline uses [`SignalEngine`] directly).
pub fn signals(timeline: &Timeline, opts: &TimelineOptions) -> Vec<Signal> {
    let mut eng = SignalEngine::new(opts);
    let mut by_run: BTreeMap<&str, Vec<TimeEvent>> = BTreeMap::new();
    for e in &timeline.events {
        by_run
            .entry(e.source.run_id.as_str())
            .or_default()
            .push(e.clone());
    }
    for batch in by_run.values() {
        eng.observe_batch(batch);
    }
    eng.finish(&timeline.runs)
}

/// Builds a whole timeline in memory: filters, order, zone-unknown count, signals.
pub fn build(
    case_id: &str,
    runs: Vec<RunRef>,
    events: Vec<TimeEvent>,
    opts: &TimelineOptions,
) -> Timeline {
    let events = order(events, opts);
    let zone_unknown = events
        .iter()
        .filter(|e| e.zone == ZoneInfo::Unknown)
        .count() as u64;
    let mut t = Timeline {
        case_id: case_id.to_string(),
        runs,
        events,
        signals: vec![],
        zone_unknown,
    };
    t.signals = signals(&t, opts);
    t
}

// ---------------------------------------------------------------------------------------------------------------
// Timesketch
// ---------------------------------------------------------------------------------------------------------------

/// English label of an event kind (i18n `kind` section), else the key itself.
pub fn kind_label(lang: &str, kind: &str) -> String {
    crate::i18n::catalog(lang)
        .text("kind", kind)
        .unwrap_or_else(|| kind.to_string())
}

/// `2026-11-10T10:00:00+00:00` (with microseconds when the event has them): the `datetime` Timesketch reads.
pub fn timesketch_datetime(e: &TimeEvent) -> String {
    match DateTime::from_timestamp(e.utc_s, e.utc_ns) {
        Some(dt) if e.utc_ns / 1000 != 0 => dt.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string(),
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
        None => format!("@{}", e.utc_s),
    }
}

/// One Timesketch JSONL line for an event (`message`, `datetime`, `timestamp_desc`, plus Rakvor fields). Keys are
/// sorted, so a line is the same on every rebuild. No trailing newline.
pub fn timesketch_line(e: &TimeEvent) -> String {
    let label = kind_label("en", &e.kind);
    let mut subject = if e.item.evidence_id.is_empty() {
        e.item.path.clone()
    } else {
        format!("{} {}", e.item.evidence_id, e.item.path)
    };
    if !e.item.sub.is_empty() {
        subject = format!("{} [{}]", subject, e.item.sub);
    }
    let zone = match e.zone {
        ZoneInfo::Explicit => "explicit",
        ZoneInfo::Unknown => "unknown",
    };
    let mut m = Map::new();
    m.insert(
        "message".into(),
        json!(format!(
            "{}: {} \u{2014} {} ({})",
            label, e.original, subject, e.source.tool
        )),
    );
    m.insert("datetime".into(), json!(timesketch_datetime(e)));
    m.insert(
        "timestamp".into(),
        json!(
            e.utc_s
                .saturating_mul(1_000_000)
                .saturating_add((e.utc_ns / 1000) as i64)
        ),
    );
    m.insert("timestamp_desc".into(), json!(label));
    for (k, v) in [
        ("rakvor_event_id", json!(e.id)),
        ("rakvor_kind", json!(e.kind)),
        ("rakvor_evidence_id", json!(e.item.evidence_id)),
        ("rakvor_item_path", json!(e.item.path)),
        ("rakvor_item_sub", json!(e.item.sub)),
        ("rakvor_item_sha256", json!(e.item.sha256)),
        ("rakvor_tool", json!(e.source.tool)),
        ("rakvor_tool_version", json!(e.source.tool_version)),
        ("rakvor_run", json!(e.source.run_id)),
        ("rakvor_run_dir", json!(e.source.run_dir)),
        ("rakvor_file", json!(e.source.file)),
        ("rakvor_file_sha256", json!(e.source.file_sha256)),
        ("rakvor_pointer", json!(e.source.pointer)),
        ("rakvor_zone", json!(zone)),
        ("rakvor_offset_min", json!(e.offset_min)),
        ("rakvor_precision", json!(e.precision)),
        ("rakvor_original", json!(e.original)),
    ] {
        m.insert(k.into(), v);
    }
    for (k, v) in &e.details {
        m.insert(format!("rakvor_detail_{}", k), json!(v));
    }
    Value::Object(m).to_string()
}

// ---------------------------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{Exclusion, SourceRef};

    pub(crate) fn ts(s: &str) -> i64 {
        parse_rfc3339(s).unwrap()
    }

    /// Hand-built event: `tool`, evidence, kind, RFC 3339 UTC time.
    pub(crate) fn ev(tool: &str, evidence: &str, kind: &str, utc: &str, n: u32) -> TimeEvent {
        let run_id = "20261112T090000Z-aaaaaa".to_string();
        TimeEvent {
            id: format!("{}:{}:{}:{}:{}", tool, run_id, evidence, kind, n),
            utc_s: ts(utc),
            utc_ns: 0,
            zone: ZoneInfo::Explicit,
            offset_min: Some(0),
            precision: Precision::Second,
            original: utc.to_string(),
            kind: kind.into(),
            item: ItemRef {
                evidence_id: evidence.into(),
                path: format!("evidence/{}.bin", evidence),
                sub: String::new(),
                sha256: "ab".repeat(32),
            },
            source: SourceRef {
                tool: tool.into(),
                tool_version: "1.0.0".into(),
                run_id: run_id.clone(),
                run_dir: format!("runs/{}/{}", tool, run_id),
                file: "reports/statistics.json".into(),
                file_sha256: "cd".repeat(32),
                pointer: "/x".into(),
            },
            details: BTreeMap::new(),
        }
    }

    fn opts() -> TimelineOptions {
        TimelineOptions::default()
    }

    fn codes(events: Vec<TimeEvent>, runs: Vec<RunRef>) -> Vec<(String, Severity)> {
        build("C", runs, events, &opts())
            .signals
            .into_iter()
            .map(|s| (s.code, s.severity))
            .collect()
    }

    fn intake(e: &str) -> TimeEvent {
        ev(
            "rv-hashinv",
            e,
            "intake.registered",
            "2026-11-10T10:00:00Z",
            0,
        )
    }

    #[test]
    fn zones_parse_and_name() {
        assert_eq!(DisplayZone::parse("utc").unwrap(), DisplayZone::Utc);
        assert_eq!(DisplayZone::parse("+00:00").unwrap(), DisplayZone::Utc);
        assert_eq!(
            DisplayZone::parse("-05:00").unwrap(),
            DisplayZone::Fixed(-300)
        );
        assert_eq!(
            DisplayZone::parse("UTC+0530").unwrap(),
            DisplayZone::Fixed(330)
        );
        assert_eq!(DisplayZone::parse("+01").unwrap(), DisplayZone::Fixed(60));
        assert_eq!(
            DisplayZone::parse("america/BOGOTA").unwrap(),
            DisplayZone::Bogota
        );
        assert_eq!(
            DisplayZone::parse("Europe/Paris").unwrap(),
            DisplayZone::Paris
        );
        for bad in ["Mars/Base", "+15:00", "+01:60", "0100", "", "+1:2:3"] {
            assert!(DisplayZone::parse(bad).is_err(), "{}", bad);
        }
        assert_eq!(DisplayZone::Fixed(-300).name(), "UTC-05:00");
        assert_eq!(DisplayZone::Paris.name(), "Europe/Paris");
    }

    #[test]
    fn bogota_is_minus_five_all_year() {
        let z = DisplayZone::Bogota;
        for t in [
            "2026-01-15T12:00:00Z",
            "2026-07-15T12:00:00Z",
            "2026-03-29T00:59:59Z",
        ] {
            assert_eq!(z.offset_at(ts(t)), -300, "{}", t);
        }
        assert_eq!(
            z.format(ts("2026-11-10T10:00:00Z"), 0, Precision::Second),
            "2026-11-10 05:00:00 COT (-05:00)"
        );
        assert_eq!(
            DisplayZone::Fixed(90).format(ts("2026-11-10T10:00:00Z"), 0, Precision::Minute),
            "2026-11-10 11:30 UTC+01:30 (+01:30)"
        );
    }

    #[test]
    fn paris_dst_edges() {
        let z = DisplayZone::Paris;
        // 2026: last Sunday of March = 29th, of October = 25th; switch at 01:00 UTC.
        assert_eq!(z.offset_at(ts("2026-03-29T00:59:59Z")), 60);
        assert_eq!(z.offset_at(ts("2026-03-29T01:00:00Z")), 120);
        assert_eq!(z.offset_at(ts("2026-10-25T00:59:59Z")), 120);
        assert_eq!(z.offset_at(ts("2026-10-25T01:00:00Z")), 60);
        // 2024: March 31st, October 27th (a 31st that is itself a Sunday).
        assert_eq!(z.offset_at(ts("2024-03-31T00:59:59Z")), 60);
        assert_eq!(z.offset_at(ts("2024-03-31T01:00:00Z")), 120);
        assert_eq!(z.offset_at(ts("2024-10-27T01:00:00Z")), 60);
        assert_eq!(z.offset_at(ts("2024-01-01T00:00:00Z")), 60);
        assert_eq!(
            z.format(ts("2026-03-29T00:59:59Z"), 0, Precision::Second),
            "2026-03-29 01:59:59 CET (+01:00)"
        );
        assert_eq!(
            z.format(ts("2026-03-29T01:00:00Z"), 0, Precision::Second),
            "2026-03-29 03:00:00 CEST (+02:00)"
        );
        assert_eq!(
            z.format(ts("2026-10-25T00:30:00Z"), 0, Precision::Second),
            "2026-10-25 02:30:00 CEST (+02:00)"
        );
        assert_eq!(
            z.format(ts("2026-10-25T01:30:00Z"), 0, Precision::Second),
            "2026-10-25 02:30:00 CET (+01:00)"
        );
        assert_eq!(
            DisplayZone::Utc.format(
                ts("2026-10-25T01:30:00Z"),
                5_000_000,
                Precision::Millisecond
            ),
            "2026-10-25 01:30:00.005 UTC"
        );
    }

    #[test]
    fn utc_formats_and_unknown_zone_is_never_converted() {
        assert_eq!(
            fmt_utc(ts("2026-11-10T10:00:00Z"), 0, Precision::Second),
            "2026-11-10T10:00:00Z"
        );
        assert_eq!(
            fmt_utc(ts("2026-11-10T10:00:00Z"), 0, Precision::Day),
            "2026-11-10"
        );
        assert_eq!(
            fmt_utc(
                ts("2026-11-10T10:00:00Z"),
                123_456_789,
                Precision::Microsecond
            ),
            "2026-11-10T10:00:00.123456Z"
        );
        let mut e = ev(
            "rv-imgauth",
            "E0001",
            "exif.original",
            "2026-11-10T10:00:00Z",
            0,
        );
        e.zone = ZoneInfo::Unknown;
        e.offset_min = None;
        assert_eq!(display_time(&e, &DisplayZone::Paris), None);
        assert_eq!(utc_time(&e), "2026-11-10 10:00:00");
        e.zone = ZoneInfo::Explicit;
        assert_eq!(
            display_time(&e, &DisplayZone::Paris).unwrap(),
            "2026-11-10 11:00:00 CET (+01:00)"
        );
        assert_eq!(human_delta(-3725), "1 h 02 min");
        assert_eq!(human_delta(90_061), "1 d 01 h 01 min");
        assert_eq!(
            run_id_start("20261112T090000Z-aaaaaa"),
            Some(ts("2026-11-12T09:00:00Z"))
        );
    }

    #[test]
    fn order_and_filters() {
        let a = ev(
            "rv-imgauth",
            "E1",
            "exif.original",
            "2026-11-10T10:00:00Z",
            2,
        );
        let b = ev(
            "rv-pdfauth",
            "E1",
            "pdf.info.created",
            "2026-11-10T10:00:00Z",
            1,
        );
        let mut c = ev("rv-imgauth", "E1", "fs.modified", "2026-11-10T09:00:00Z", 3);
        c.utc_ns = 5;
        let d = ev("rv-imgauth", "E1", "fs.created", "2026-11-10T09:00:00Z", 4);
        let out = order(vec![a.clone(), b.clone(), c.clone(), d.clone()], &opts());
        let ids: Vec<&str> = out.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids,
            [d.id.as_str(), c.id.as_str(), a.id.as_str(), b.id.as_str()]
        );
        let mut o = opts();
        o.tools = vec!["rv-pdfauth".into()];
        assert_eq!(order(out.clone(), &o).len(), 1);
        let mut o = opts();
        o.from_s = Some(ts("2026-11-10T09:30:00Z"));
        o.to_s = Some(ts("2026-11-10T10:00:00Z"));
        assert_eq!(order(out, &o).len(), 2, "window is inclusive");
    }

    #[test]
    fn external_sort_equals_in_memory_sort() {
        let tmp = tempfile::tempdir().unwrap();
        let mut events = Vec::new();
        for i in 0..1000u32 {
            // Pseudo-random times with many ties, so the id tie-break matters.
            let s = ts("2026-01-01T00:00:00Z") + ((i as i64 * 7919) % 97) * 60;
            let mut e = ev(
                "rv-imgauth",
                &format!("E{:04}", i % 13),
                "fs.modified",
                "2026-01-01T00:00:00Z",
                i,
            );
            e.utc_s = s;
            e.utc_ns = (i % 3) * 1000;
            events.push(e);
        }
        let mut expected = events.clone();
        expected.sort_by(cmp_events);
        let mut sorter = EventSorter::new(tmp.path(), 64);
        for e in events.iter().rev().cloned() {
            sorter.push(e).unwrap();
        }
        assert_eq!(sorter.len(), 1000);
        assert!(sorter.spilled_chunks() >= 15);
        let got: Vec<TimeEvent> = sorter.finish().unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(got, expected);
        assert_eq!(
            std::fs::read_dir(tmp.path()).unwrap().count(),
            0,
            "chunk folder removed"
        );
        // Below the threshold nothing touches the disk.
        let mut small = EventSorter::new(tmp.path(), 10_000);
        for e in events.iter().take(50).cloned() {
            small.push(e).unwrap();
        }
        assert_eq!(small.spilled_chunks(), 0);
        assert_eq!(small.finish().unwrap().count(), 50);
    }

    #[test]
    fn clean_case_has_no_signal() {
        let mut events = vec![
            intake("E0001"),
            ev(
                "rv-imgauth",
                "E0001",
                "exif.original",
                "2026-11-01T08:00:00Z",
                1,
            ),
            ev(
                "rv-imgauth",
                "E0001",
                "fs.modified",
                "2026-11-01T08:05:00Z",
                2,
            ),
            ev(
                "rv-imgauth",
                "E0001",
                "run.finished",
                "2026-11-12T09:10:00Z",
                3,
            ),
            // The same mtime read by a second tool: no skew.
            ev(
                "rv-hashinv",
                "E0001",
                "fs.modified",
                "2026-11-01T08:05:00Z",
                4,
            ),
            ev(
                "rv-mailauth",
                "E0002",
                "mail.hop",
                "2026-11-02T10:00:00Z",
                1,
            ),
            ev(
                "rv-mailauth",
                "E0002",
                "mail.hop",
                "2026-11-02T10:00:05Z",
                2,
            ),
            ev(
                "rv-mailauth",
                "E0002",
                "mail.date",
                "2026-11-02T09:59:58Z",
                3,
            ),
            // Certificates may expire after the run.
            ev(
                "rv-certcheck",
                "E0003",
                "cert.not_after",
                "2030-01-01T00:00:00Z",
                1,
            ),
        ];
        for (n, t) in ["2026-11-01T10:00:00Z", "2026-11-03T10:00:00Z"]
            .iter()
            .enumerate()
        {
            let mut e = ev("rv-pdfauth", "E0004", "pdf.info.modified", t, n as u32);
            e.item.sub = format!("r{}", n + 1);
            events.push(e);
        }
        let runs = vec![RunRef {
            tool: "rv-imgauth".into(),
            run_id: "x".into(),
            ..Default::default()
        }];
        assert_eq!(codes(events, runs), vec![]);
    }

    #[test]
    fn exif_after_intake_fires_high_or_medium_with_unknown_zone() {
        let late = ev(
            "rv-imgauth",
            "E0001",
            "exif.original",
            "2026-11-10T12:00:00Z",
            1,
        );
        assert_eq!(
            codes(vec![intake("E0001"), late.clone()], vec![]),
            [("EXIF_AFTER_INTAKE".into(), Severity::High)]
        );
        // Within the tolerance: nothing.
        let near = ev(
            "rv-imgauth",
            "E0001",
            "exif.original",
            "2026-11-10T10:04:00Z",
            1,
        );
        assert!(codes(vec![intake("E0001"), near], vec![]).is_empty());
        // Unknown zone, 2 h later: the zone alone could explain it → Medium (+ the zone count).
        let mut u = late.clone();
        u.zone = ZoneInfo::Unknown;
        u.offset_min = None;
        assert_eq!(
            codes(vec![intake("E0001"), u.clone()], vec![]),
            [
                ("EXIF_AFTER_INTAKE".into(), Severity::Medium),
                ("ZONE_UNKNOWN_EVENTS".into(), Severity::Info)
            ]
        );
        // Unknown zone, 2 days later: High.
        u.utc_s += 2 * 86_400;
        assert_eq!(codes(vec![intake("E0001"), u], vec![])[0].1, Severity::High);
        // Intake taken from the audited registry when no intake event was read.
        let mut eng = SignalEngine::new(&opts());
        eng.add_registry_intake("E0001", "2026-11-10T10:00:00.000Z");
        eng.observe_batch(&[late]);
        let s = eng.finish(&[]);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].params["delta_s"], "7200");
        assert_eq!(s[0].item.as_ref().unwrap().evidence_id, "E0001");
    }

    #[test]
    fn file_modified_after_intake() {
        let m = ev(
            "rv-imgauth",
            "E0001",
            "fs.modified",
            "2026-11-11T10:00:00Z",
            1,
        );
        assert_eq!(
            codes(vec![intake("E0001"), m], vec![]),
            [("FILE_MODIFIED_AFTER_INTAKE".into(), Severity::Medium)]
        );
        // Another item's intake is irrelevant.
        let m = ev(
            "rv-imgauth",
            "E0002",
            "fs.modified",
            "2026-11-11T10:00:00Z",
            1,
        );
        assert!(codes(vec![intake("E0001"), m], vec![]).is_empty());
    }

    /// The same event read by another run (`run_id`).
    fn in_run(mut e: TimeEvent, run_id: &str) -> TimeEvent {
        e.id = e.id.replace("20261112T090000Z-aaaaaa", run_id);
        e.source.run_id = run_id.into();
        e
    }

    #[test]
    fn file_touched_seconds_after_intake_is_seen_by_a_later_run() {
        // The sample case: the intake run recorded the file's old mtime; a later run saw a new one 3 s after the
        // intake — within the clock tolerance, yet the mtime changed after the item was registered.
        let at_intake = ev(
            "rv-hashinv",
            "E0001",
            "fs.modified",
            "2026-11-09T06:00:00Z",
            0,
        );
        let later = in_run(
            ev(
                "rv-imgauth",
                "E0001",
                "fs.modified",
                "2026-11-10T10:00:03Z",
                0,
            ),
            "20261112T100000Z-bbbbbb",
        );
        let t = build(
            "C",
            vec![],
            vec![intake("E0001"), at_intake.clone(), later.clone()],
            &opts(),
        );
        assert_eq!(
            t.signals
                .iter()
                .map(|s| (s.code.as_str(), s.severity))
                .collect::<Vec<_>>(),
            [("FILE_MODIFIED_AFTER_INTAKE", Severity::Medium)]
        );
        assert_eq!(t.signals[0].events[1], later.id);
        // Without the intake run's own reading, 3 s is within the tolerance: nothing.
        assert!(codes(vec![intake("E0001"), later.clone()], vec![]).is_empty());
        // The value the intake run recorded, read again later: unchanged, nothing.
        let mut same = later;
        same.utc_s = at_intake.utc_s;
        assert!(codes(vec![intake("E0001"), at_intake, same], vec![]).is_empty());
    }

    #[test]
    fn received_hops_out_of_order_are_a_clock_skew() {
        // The sample's mbox message #3: hop 2 (mx.acme.example) is stamped 20 min before hop 1.
        let hop = |pos: u32, by: &str, t: &str| {
            let mut e = ev("rv-mailauth", "E0016", "mail.hop", t, pos - 1);
            e.item.sub = "#3".into();
            e.details.insert("position".into(), pos.to_string());
            e.details.insert("by".into(), by.into());
            e
        };
        let h1 = hop(1, "smtp.example.org", "2026-11-11T10:00:00Z");
        let h2 = hop(2, "mx.acme.example", "2026-11-11T09:40:00Z");
        let t = build("C", vec![], vec![h2.clone(), h1.clone()], &opts());
        assert_eq!(t.signals.len(), 1, "{:?}", t.signals);
        let s = &t.signals[0];
        assert_eq!(
            (s.code.as_str(), s.severity),
            ("CLOCK_SKEW_SUSPECTED", Severity::Low)
        );
        assert_eq!(s.events, vec![h1.id.clone(), h2.id.clone()]);
        assert_eq!(s.item.as_ref().unwrap().sub, "#3");
        assert_eq!(s.params["skew_s"], "1200");
        assert_eq!(
            (
                s.params["host"].as_str(),
                s.params["previous_host"].as_str()
            ),
            ("mx.acme.example", "smtp.example.org")
        );
        assert!(!s.params.contains_key("tool_a") && !s.params.contains_key("tool_b"));
        assert_eq!(s.params["message"], "#3");
        // In order, or out of order within the tolerance: nothing.
        let ok = hop(2, "mx.acme.example", "2026-11-11T10:00:03Z");
        assert!(codes(vec![h1.clone(), ok], vec![]).is_empty());
        let near = hop(2, "mx.acme.example", "2026-11-11T09:57:00Z");
        assert!(codes(vec![h1.clone(), near], vec![]).is_empty());
        // Hops read by two different runs are not compared with each other.
        let other = in_run(h2, "20261112T100000Z-bbbbbb");
        assert!(codes(vec![h1, other], vec![]).is_empty());
    }

    #[test]
    fn first_hop_is_position_one_when_known() {
        let mut d = ev(
            "rv-mailauth",
            "E0002",
            "mail.date",
            "2026-11-02T10:30:00Z",
            0,
        );
        let mut h1 = ev(
            "rv-mailauth",
            "E0002",
            "mail.hop",
            "2026-11-02T10:00:00Z",
            0,
        );
        let mut h2 = ev(
            "rv-mailauth",
            "E0002",
            "mail.hop",
            "2026-11-02T09:00:00Z",
            1,
        );
        for (e, pos) in [(&mut h1, "1"), (&mut h2, "2")] {
            e.details.insert("position".into(), pos.into());
        }
        d.item.sub = String::new();
        let t = build("C", vec![], vec![d.clone(), h1.clone(), h2], &opts());
        let m = t
            .signals
            .iter()
            .find(|s| s.code == "MAIL_DATE_AFTER_FIRST_HOP")
            .unwrap();
        assert_eq!(m.events, vec![d.id, h1.id]);
        assert_eq!(m.params["delta_s"], "1800");
        // A message that is a file of its own is named by its file name.
        assert_eq!(m.params["message"], "E0002.bin");
    }

    #[test]
    fn mail_date_after_first_hop_across_tools() {
        let mut d = ev(
            "rv-mailauth",
            "E0002",
            "mail.date",
            "2026-11-02T12:00:00Z",
            1,
        );
        let mut h1 = ev("rv-hashinv", "E0002", "mail.hop", "2026-11-02T10:00:00Z", 2);
        let mut h2 = ev(
            "rv-mailauth",
            "E0002",
            "mail.hop",
            "2026-11-02T13:00:00Z",
            3,
        );
        for e in [&mut d, &mut h1, &mut h2] {
            e.item.sub = "#3".into();
        }
        let t = build("C", vec![], vec![d.clone(), h1.clone(), h2], &opts());
        assert_eq!(t.signals.len(), 1);
        let s = &t.signals[0];
        assert_eq!(s.code, "MAIL_DATE_AFTER_FIRST_HOP");
        assert_eq!(s.events, vec![d.id.clone(), h1.id.clone()]);
        assert_eq!(s.item.as_ref().unwrap().sub, "#3");
        // A hop of another message does not count.
        h1.item.sub = "#4".into();
        assert!(codes(vec![d, h1], vec![]).is_empty());
    }

    #[test]
    fn pdf_revision_before_previous() {
        let mk = |r: u32, t: &str| {
            let mut e = ev("rv-pdfauth", "E0004", "pdf.revision.signed", t, r);
            e.item.sub = format!("r{}", r);
            e
        };
        let evs = vec![mk(1, "2026-11-05T10:00:00Z"), mk(2, "2026-11-03T10:00:00Z")];
        let t = build("C", vec![], evs, &opts());
        assert_eq!(t.signals.len(), 1);
        assert_eq!(t.signals[0].code, "PDF_REVISION_BEFORE_PREVIOUS");
        assert_eq!(t.signals[0].params["revision"], "2");
        assert!(
            codes(
                vec![mk(1, "2026-11-03T10:00:00Z"), mk(2, "2026-11-05T10:00:00Z")],
                vec![]
            )
            .is_empty()
        );
    }

    #[test]
    fn event_in_future_against_the_run() {
        let fin = ev(
            "rv-imgauth",
            "E0001",
            "run.finished",
            "2026-11-12T09:10:00Z",
            9,
        );
        let fut = ev(
            "rv-imgauth",
            "E0001",
            "exif.digitized",
            "2026-12-01T00:00:00Z",
            1,
        );
        assert_eq!(
            codes(vec![fin.clone(), fut.clone()], vec![]),
            [("EVENT_IN_FUTURE".into(), Severity::Medium)]
        );
        let t = build("C", vec![], vec![fin.clone(), fut.clone()], &opts());
        assert_eq!(t.signals[0].params["reference"], "run_finished");
        // Without run.finished the run id's start is the reference.
        let t = build("C", vec![], vec![fut], &opts());
        assert_eq!(t.signals[0].params["reference"], "run_id");
        let ok = ev(
            "rv-imgauth",
            "E0001",
            "exif.digitized",
            "2026-11-12T09:12:00Z",
            1,
        );
        assert!(codes(vec![fin, ok], vec![]).is_empty());
    }

    #[test]
    fn clock_skew_suspected() {
        let a1 = ev(
            "rv-hashinv",
            "E0001",
            "fs.modified",
            "2026-11-01T08:00:00Z",
            1,
        );
        let a2 = ev(
            "rv-hashinv",
            "E0001",
            "fs.created",
            "2026-10-01T08:00:00Z",
            2,
        );
        let b1 = ev(
            "rv-imgauth",
            "E0001",
            "fs.modified",
            "2026-11-01T09:00:00Z",
            1,
        );
        let b2 = ev(
            "rv-imgauth",
            "E0001",
            "fs.created",
            "2026-10-01T09:00:10Z",
            2,
        );
        let t = build(
            "C",
            vec![],
            vec![a1.clone(), a2.clone(), b1.clone(), b2],
            &opts(),
        );
        assert_eq!(t.signals.len(), 1);
        let s = &t.signals[0];
        assert_eq!(
            (s.code.as_str(), s.severity),
            ("CLOCK_SKEW_SUSPECTED", Severity::Low)
        );
        assert_eq!(
            (s.params["tool_a"].as_str(), s.params["tool_b"].as_str()),
            ("rv-hashinv", "rv-imgauth")
        );
        // Inconsistent offsets (1 h and 3 h): not a skew.
        let b2 = ev(
            "rv-imgauth",
            "E0001",
            "fs.created",
            "2026-10-01T11:00:00Z",
            2,
        );
        assert!(codes(vec![a1.clone(), a2, b1.clone(), b2], vec![]).is_empty());
        // A single shared fact is not "consistently" offset.
        assert!(codes(vec![a1, b1], vec![]).is_empty());
    }

    #[test]
    fn run_not_verified_one_per_run_and_zone_unknown_count() {
        let run = |id: &str, reason: &str| RunRef {
            tool: "rv-pdfauth".into(),
            tool_version: "0.3.0".into(),
            run_id: id.into(),
            run_dir: format!("runs/rv-pdfauth/{}", id),
            status: RunStatus::Excluded,
            exclusion: Some(Exclusion {
                reason: reason.into(),
                detail: String::new(),
            }),
            events: 0,
        };
        let verified = RunRef {
            tool: "rv-imgauth".into(),
            run_id: "ok".into(),
            ..Default::default()
        };
        let got = codes(
            vec![],
            vec![
                run("b", "unsupported_version"),
                verified,
                run("a", "chain_broken"),
            ],
        );
        assert_eq!(
            got,
            [
                ("RUN_NOT_VERIFIED".into(), Severity::Medium),
                ("RUN_NOT_VERIFIED".into(), Severity::Low)
            ]
        );
        let mut u = ev(
            "rv-imgauth",
            "E0001",
            "exif.original",
            "2026-11-01T08:00:00Z",
            1,
        );
        u.zone = ZoneInfo::Unknown;
        let t = build("C", vec![], vec![u.clone(), u], &opts());
        assert_eq!(t.zone_unknown, 2);
        assert_eq!(t.signals[0].code, "ZONE_UNKNOWN_EVENTS");
        assert_eq!(t.signals[0].params["count"], "2");
    }

    #[test]
    fn timesketch_line_format() {
        let mut e = ev(
            "rv-imgauth",
            "E0001",
            "exif.original",
            "2026-11-10T10:00:00Z",
            1,
        );
        e.original = "2026:11:10 11:00:00".into();
        e.offset_min = Some(60);
        e.details.insert("camera".into(), "X100".into());
        let line = timesketch_line(&e);
        assert!(!line.contains('\n'));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["datetime"], "2026-11-10T10:00:00+00:00");
        assert_eq!(v["timestamp"], ts("2026-11-10T10:00:00Z") * 1_000_000);
        assert_eq!(v["timestamp_desc"], kind_label("en", "exif.original"));
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("2026:11:10 11:00:00")
        );
        for (k, want) in [
            ("rakvor_event_id", e.id.as_str()),
            ("rakvor_evidence_id", "E0001"),
            ("rakvor_tool", "rv-imgauth"),
            ("rakvor_run", "20261112T090000Z-aaaaaa"),
            ("rakvor_file", "reports/statistics.json"),
            ("rakvor_pointer", "/x"),
            ("rakvor_zone", "explicit"),
            ("rakvor_original", "2026:11:10 11:00:00"),
            ("rakvor_detail_camera", "X100"),
        ] {
            assert_eq!(v[k], want, "{}", k);
        }
        assert_eq!(v["rakvor_file_sha256"], "cd".repeat(32));
        assert_eq!(v["rakvor_offset_min"], 60);
        e.utc_ns = 250_000_000;
        let v: Value = serde_json::from_str(&timesketch_line(&e)).unwrap();
        assert_eq!(v["datetime"], "2026-11-10T10:00:00.250000+00:00");
        // Same input, same bytes.
        assert_eq!(timesketch_line(&e), timesketch_line(&e.clone()));
    }

    #[test]
    fn rebuild_is_deterministic() {
        let mut events = vec![
            intake("E0001"),
            ev(
                "rv-imgauth",
                "E0001",
                "exif.original",
                "2026-11-10T12:00:00Z",
                1,
            ),
            ev(
                "rv-imgauth",
                "E0001",
                "fs.modified",
                "2026-11-11T12:00:00Z",
                2,
            ),
            ev(
                "rv-imgauth",
                "E0002",
                "exif.digitized",
                "2027-01-01T00:00:00Z",
                3,
            ),
        ];
        let a = build("C", vec![], events.clone(), &opts());
        events.reverse();
        let b = build("C", vec![], events, &opts());
        assert_eq!(a, b);
        let lines = |t: &Timeline| t.events.iter().map(timesketch_line).collect::<Vec<_>>();
        assert_eq!(lines(&a), lines(&b));
    }
}
