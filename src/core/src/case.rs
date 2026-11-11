//! Shared case folder (`rakvor.case/1`): the link between Rakvor tools.
//!
//! ```text
//! <CASE>/case.json               created once, never changed
//! <CASE>/case-log.jsonl          hash-chained (same rule as audit.jsonl), append-only, written under case-log.lock
//! <CASE>/evidence/registry.json  written only by the intake tool; its SHA-256 is recorded in the case log
//! <CASE>/evidence/registry.csv
//! <CASE>/runs/<tool>/<RUN-ID>/{logs,reports}/
//! ```
//!
//! The intake tool registers evidence (E0001…); analysis tools re-hash and compare against the registry.
//! Every append re-verifies the case log first: a broken case is never extended.
//! The contract (shared with the Python profile, byte-compatible) is `references/case-folder.md` of the forge.

use crate::audit::{self, GENESIS, build_entry};
use crate::hash::{HashAlgo, hash_bytes};
use crate::time::utc_now;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

pub const SCHEMA_CASE: &str = "rakvor.case/1";
pub const SCHEMA_REGISTRY: &str = "rakvor.registry/1";
pub const CASE_FILE: &str = "case.json";
pub const CASE_LOG: &str = "case-log.jsonl";
pub const LOCK_FILE: &str = "case-log.lock";
pub const REGISTRY_JSON: &str = "evidence/registry.json";
pub const REGISTRY_CSV: &str = "evidence/registry.csv";
/// A lock older than this is reported as stale. It is never deleted automatically.
pub const STALE_LOCK: Duration = Duration::from_secs(600);
/// How long a tool waits for another tool's lock before giving up.
pub const LOCK_WAIT: Duration = Duration::from_secs(30);

/// What a tool does with the case registry. The reference (rv-timeline) is the intake tool; tools scaffolded
/// from it are analysis tools (`CASE_ROLE` in lib.rs and `case_role` in .forge.json).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaseRole {
    /// Registers every successfully hashed item (writes evidence/registry.json).
    Intake,
    /// Re-hashes every item and compares it with the registry (never writes the registry).
    Analysis,
}

impl CaseRole {
    pub fn name(&self) -> &'static str {
        match self {
            CaseRole::Intake => "intake",
            CaseRole::Analysis => "analysis",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseErrorKind {
    /// Wrong schema, case id mismatch, missing --case on creation, unknown evidence id → exit 2.
    Usage,
    /// Case log chain or registry digest broken → exit 3.
    Broken,
    /// Another tool holds the lock (or a stale lock is left) → exit 1.
    Locked,
    /// File system error → exit 1.
    Io,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CaseError {
    pub kind: CaseErrorKind,
    pub message: String,
}

impl CaseError {
    fn new(kind: CaseErrorKind, message: impl Into<String>) -> CaseError {
        CaseError {
            kind,
            message: message.into(),
        }
    }
    fn io(what: &str, path: &Path, e: impl fmt::Display) -> CaseError {
        CaseError::new(
            CaseErrorKind::Io,
            format!("{} {}: {}", what, path.display(), e),
        )
    }
    /// CLI exit code for this error (contract: 2 usage, 3 broken case, 1 otherwise).
    pub fn exit_code(&self) -> u8 {
        match self.kind {
            CaseErrorKind::Usage => 2,
            CaseErrorKind::Broken => 3,
            CaseErrorKind::Locked | CaseErrorKind::Io => 1,
        }
    }
}

impl fmt::Display for CaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<CaseError> for String {
    fn from(e: CaseError) -> String {
        e.message
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegisteredBy {
    pub tool: String,
    pub version: String,
    pub run_id: String,
    /// Audit entry (`item_hashed`) in that run's audit.jsonl that holds the hashes.
    pub audit_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegistryItem {
    pub evidence_id: String,
    pub path: String,
    pub size: u64,
    pub hashes: BTreeMap<String, String>,
    pub registered_by: RegisteredBy,
    pub registered_utc: String,
}

impl RegistryItem {
    fn number(&self) -> u64 {
        self.evidence_id
            .trim_start_matches('E')
            .parse()
            .unwrap_or(0)
    }
}

/// Result of comparing an item's fresh hashes with a registry entry.
#[derive(Clone, Debug, PartialEq)]
pub enum Comparison {
    /// Every algorithm present in both agrees (names of the compared algorithms).
    Match(Vec<String>),
    /// First algorithm that disagrees.
    Mismatch {
        algorithm: String,
        expected: String,
        actual: String,
    },
    /// No algorithm in common: cannot compare.
    NoCommonAlgorithm,
}

pub fn compare(expected: &BTreeMap<String, String>, actual: &[(HashAlgo, String)]) -> Comparison {
    let mut common = Vec::new();
    for (a, h) in actual {
        if let Some(e) = expected.get(a.name()) {
            if !e.eq_ignore_ascii_case(h) {
                return Comparison::Mismatch {
                    algorithm: a.name().into(),
                    expected: e.clone(),
                    actual: h.clone(),
                };
            }
            common.push(a.name().to_string());
        }
    }
    if common.is_empty() {
        Comparison::NoCommonAlgorithm
    } else {
        Comparison::Match(common)
    }
}

/// Absolute, lexically normalised path (no `.`/`..`), the form stored in the registry.
pub fn normalize_path(p: &Path) -> String {
    normalize(p).display().to_string()
}

/// [`normalize_path`] as a `PathBuf` (opens files whose names are not valid UTF-8 too).
pub fn normalize(p: &Path) -> PathBuf {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// "E0001", "E0002", … (more digits after E9999).
pub fn evidence_id(n: u64) -> String {
    format!("E{:04}", n)
}

/// Parses "E0001,e7" → ["E0001", "E0007"]. Usage error on anything else.
pub fn parse_evidence_ids(raw: &[String]) -> Result<Vec<String>, CaseError> {
    let mut out: Vec<String> = Vec::new();
    for part in raw
        .iter()
        .flat_map(|r| r.split(','))
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
    {
        let digits = part
            .strip_prefix('E')
            .or_else(|| part.strip_prefix('e'))
            .filter(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()));
        match digits.and_then(|d| d.parse::<u64>().ok()) {
            Some(n) if n > 0 => {
                let id = evidence_id(n);
                if !out.contains(&id) {
                    out.push(id);
                }
            }
            _ => {
                return Err(CaseError::new(
                    CaseErrorKind::Usage,
                    format!("invalid evidence id '{}': use E0001, E0002, …", part),
                ));
            }
        }
    }
    Ok(out)
}

/// The case algorithms rule: a run always includes at least one algorithm present in the registry.
/// Returns the effective selection and, when changed, (added, replaced).
pub fn ensure_case_algorithm(
    selected: &[HashAlgo],
    registry: &[HashAlgo],
) -> (Vec<HashAlgo>, Option<(HashAlgo, Option<HashAlgo>)>) {
    if registry.is_empty() || selected.iter().any(|a| registry.contains(a)) {
        return (selected.to_vec(), None);
    }
    let pick = if registry.contains(&HashAlgo::Sha256) {
        HashAlgo::Sha256
    } else {
        registry[0]
    };
    let mut out = selected.to_vec();
    if out.len() < HashAlgo::MAX_SELECTED {
        out.push(pick);
        (out, Some((pick, None)))
    } else {
        let replaced = out[HashAlgo::MAX_SELECTED - 1];
        out[HashAlgo::MAX_SELECTED - 1] = pick;
        (out, Some((pick, Some(replaced))))
    }
}

fn sha256_file(p: &Path) -> Option<String> {
    std::fs::read(p)
        .ok()
        .map(|b| hash_bytes(&b, HashAlgo::Sha256))
}

/// SHA-256 of evidence/registry.json (None when the case has no registry yet).
pub fn registry_digest(dir: &Path) -> Option<String> {
    sha256_file(&dir.join(REGISTRY_JSON))
}

fn read_json(p: &Path) -> Result<Value, String> {
    let text =
        std::fs::read_to_string(p).map_err(|e| format!("cannot read {}: {}", p.display(), e))?;
    serde_json::from_str(&text).map_err(|e| format!("{} is not valid JSON: {}", p.display(), e))
}

fn read_entries(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// State of an intact case log.
#[derive(Clone, Debug)]
pub struct LogState {
    pub entries: u64,
    pub head: String,
    /// Last `registry_sha256` recorded (None = no registry yet).
    pub registry_sha256: Option<String>,
}

/// Verifies case.json, the case-log chain and the registry digest. Ok(state) or Err(problems).
pub fn verify_log_and_registry(dir: &Path) -> Result<LogState, Vec<String>> {
    let mut problems = Vec::new();
    let log_path = dir.join(CASE_LOG);
    let entries = match audit::verify(&log_path) {
        Ok(n) => n,
        Err(p) => {
            return Err(p
                .into_iter()
                .map(|x| format!("{}: {}", CASE_LOG, x))
                .collect());
        }
    };
    let all = read_entries(&log_path);
    let head = all
        .last()
        .and_then(|e| e["entry_hash"].as_str())
        .unwrap_or(GENESIS)
        .to_string();
    match all.first() {
        Some(first) if first["action"] == "case_created" => {
            let case = read_json(&dir.join(CASE_FILE)).unwrap_or(Value::Null);
            if first["details"]["case_id"] != case["case_id"] {
                problems.push(format!(
                    "{}: case_id differs from the case_created entry",
                    CASE_FILE
                ));
            }
            if let Some(d) = first["details"]["case_json_sha256"].as_str()
                && sha256_file(&dir.join(CASE_FILE)).as_deref() != Some(d)
            {
                problems.push(format!(
                    "{}: content differs from the digest recorded at creation (edited)",
                    CASE_FILE
                ));
            }
        }
        _ => problems.push(format!("{}: the first entry is not case_created", CASE_LOG)),
    }
    let recorded = all
        .iter()
        .rev()
        .find_map(|e| e["details"]["registry_sha256"].as_str().map(String::from));
    let reg_path = dir.join(REGISTRY_JSON);
    match (&recorded, reg_path.is_file()) {
        (Some(d), true) => {
            if sha256_file(&reg_path).as_deref() != Some(d.as_str()) {
                problems.push(format!(
                    "{}: SHA-256 differs from the digest recorded in the case log (edited registry)",
                    REGISTRY_JSON
                ));
            }
        }
        (Some(_), false) => problems.push(format!(
            "{}: missing, but the case log records a registry digest",
            REGISTRY_JSON
        )),
        (None, true) => problems.push(format!(
            "{}: present, but no registry digest is recorded in the case log",
            REGISTRY_JSON
        )),
        (None, false) => {}
    }
    if problems.is_empty() {
        Ok(LogState {
            entries,
            head,
            registry_sha256: recorded,
        })
    } else {
        Err(problems)
    }
}

/// Exclusive lock on the case log; removed when dropped.
pub struct CaseLock {
    path: PathBuf,
}

impl Drop for CaseLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Who is writing (stored in the lock file and in case-log entries).
#[derive(Clone, Debug)]
pub struct Writer {
    pub tool: String,
    pub version: String,
    pub run_id: String,
    pub actor: String,
}

pub fn lock(dir: &Path, w: &Writer, wait: Duration) -> Result<CaseLock, CaseError> {
    let path = dir.join(LOCK_FILE);
    let started = Instant::now();
    loop {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                let info = json!({"tool": w.tool, "version": w.version, "run_id": w.run_id, "pid": std::process::id(),
                                  "host": crate::env::hostname(), "created_utc": utc_now()});
                let _ = writeln!(f, "{}", info);
                return Ok(CaseLock { path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let holder = std::fs::read_to_string(&path).unwrap_or_default();
                let holder: Value = serde_json::from_str(holder.trim()).unwrap_or(Value::Null);
                let who = format!(
                    "{} run {} (since {})",
                    holder["tool"].as_str().unwrap_or("?"),
                    holder["run_id"].as_str().unwrap_or("?"),
                    holder["created_utc"].as_str().unwrap_or("?")
                );
                let age = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| SystemTime::now().duration_since(t).ok())
                    .unwrap_or_default();
                if age > STALE_LOCK {
                    return Err(CaseError::new(
                        CaseErrorKind::Locked,
                        format!(
                            "stale case lock {} held by {} for more than {} minutes. If no Rakvor tool is working on this case, \
                             delete the lock file by hand and run again (it is never removed automatically).",
                            path.display(),
                            who,
                            STALE_LOCK.as_secs() / 60
                        ),
                    ));
                }
                if started.elapsed() >= wait {
                    return Err(CaseError::new(
                        CaseErrorKind::Locked,
                        format!(
                            "the case log is locked by {} ({}); try again when it has finished",
                            who,
                            path.display()
                        ),
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(CaseError::io("cannot create lock", &path, e)),
        }
    }
}

/// An open, verified case folder.
#[derive(Clone, Debug)]
pub struct Case {
    pub dir: PathBuf,
    pub case_id: String,
    pub jurisdiction: String,
    pub created_utc: String,
    /// Registry snapshot (sorted by evidence id).
    pub items: Vec<RegistryItem>,
    pub lock_wait: Duration,
}

fn load_case_json(dir: &Path) -> Result<Value, CaseError> {
    let p = dir.join(CASE_FILE);
    let v = read_json(&p).map_err(|e| CaseError::new(CaseErrorKind::Usage, e))?;
    if v["schema"] != SCHEMA_CASE {
        return Err(CaseError::new(
            CaseErrorKind::Usage,
            format!(
                "{} has schema {} ; this tool reads {} only",
                p.display(),
                v["schema"],
                SCHEMA_CASE
            ),
        ));
    }
    Ok(v)
}

fn load_registry(dir: &Path) -> Result<Vec<RegistryItem>, CaseError> {
    let p = dir.join(REGISTRY_JSON);
    if !p.is_file() {
        return Ok(vec![]);
    }
    let v = read_json(&p).map_err(|e| CaseError::new(CaseErrorKind::Broken, e))?;
    if v["schema"] != SCHEMA_REGISTRY {
        return Err(CaseError::new(
            CaseErrorKind::Usage,
            format!("{} is not a {} file", p.display(), SCHEMA_REGISTRY),
        ));
    }
    let mut items: Vec<RegistryItem> = serde_json::from_value(v["items"].clone())
        .map_err(|e| CaseError::new(CaseErrorKind::Broken, format!("{}: {}", p.display(), e)))?;
    items.sort_by_key(|i| i.number());
    Ok(items)
}

impl Case {
    /// Opens an existing case and verifies it (exit-3 class error if broken).
    pub fn open(dir: &Path) -> Result<Case, CaseError> {
        let v = load_case_json(dir)?;
        verify_log_and_registry(dir).map_err(|p| {
            CaseError::new(
                CaseErrorKind::Broken,
                format!(
                    "the case folder {} fails verification; a broken case is never extended: {}",
                    dir.display(),
                    p.join("; ")
                ),
            )
        })?;
        Ok(Case {
            dir: dir.to_path_buf(),
            case_id: v["case_id"].as_str().unwrap_or_default().to_string(),
            jurisdiction: v["jurisdiction"].as_str().unwrap_or("co").to_string(),
            created_utc: v["created_utc"].as_str().unwrap_or_default().to_string(),
            items: load_registry(dir)?,
            lock_wait: LOCK_WAIT,
        })
    }

    /// Opens the case, or creates it (case.json + case_created) when the folder has no case.json.
    /// Returns (case, created).
    pub fn open_or_create(
        dir: &Path,
        case_id: Option<&str>,
        jurisdiction: &str,
        w: &Writer,
    ) -> Result<(Case, bool), CaseError> {
        if dir.join(CASE_FILE).exists() {
            let c = Case::open(dir)?;
            c.check_case_id(case_id)?;
            return Ok((c, false));
        }
        let Some(id) = case_id.map(str::trim).filter(|s| !s.is_empty()) else {
            return Err(CaseError::new(
                CaseErrorKind::Usage,
                format!(
                    "{} is not a case folder yet: give --case ID (and --jurisdiction) to create it",
                    dir.display()
                ),
            ));
        };
        if jurisdiction != "co" && jurisdiction != "fr" {
            return Err(CaseError::new(
                CaseErrorKind::Usage,
                format!("unknown jurisdiction '{}': use co or fr", jurisdiction),
            ));
        }
        std::fs::create_dir_all(dir.join("evidence"))
            .map_err(|e| CaseError::io("cannot create", dir, e))?;
        let guard = lock(dir, w, LOCK_WAIT)?;
        let body = json!({
            "schema": SCHEMA_CASE, "case_id": id, "jurisdiction": jurisdiction, "created_utc": utc_now(),
            "created_by": {"tool": w.tool, "version": w.version, "run_id": w.run_id, "actor": w.actor},
        });
        let bytes = crate::report::pretty(&body);
        let p = dir.join(CASE_FILE);
        match OpenOptions::new().write(true).create_new(true).open(&p) {
            Ok(mut f) => f
                .write_all(&bytes)
                .map_err(|e| CaseError::io("cannot write", &p, e))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                drop(guard);
                let c = Case::open(dir)?;
                c.check_case_id(case_id)?;
                return Ok((c, false));
            }
            Err(e) => return Err(CaseError::io("cannot create", &p, e)),
        }
        let c = Case {
            dir: dir.to_path_buf(),
            case_id: id.to_string(),
            jurisdiction: jurisdiction.to_string(),
            created_utc: body["created_utc"].as_str().unwrap_or_default().to_string(),
            items: vec![],
            lock_wait: LOCK_WAIT,
        };
        c.append_unlocked(
            w,
            "case_created",
            json!({"case_id": id, "jurisdiction": jurisdiction, "schema": SCHEMA_CASE,
                   "case_json_sha256": hash_bytes(&bytes, HashAlgo::Sha256), "registry_sha256": null,
                   "tool": w.tool, "version": w.version}),
        )?;
        drop(guard);
        Ok((c, true))
    }

    fn check_case_id(&self, case_id: Option<&str>) -> Result<(), CaseError> {
        match case_id.map(str::trim).filter(|s| !s.is_empty()) {
            Some(id) if id != self.case_id => Err(CaseError::new(
                CaseErrorKind::Usage,
                format!(
                    "the case folder {} belongs to case {}, not {}",
                    self.dir.display(),
                    self.case_id,
                    id
                ),
            )),
            _ => Ok(()),
        }
    }

    pub fn get(&self, id: &str) -> Option<&RegistryItem> {
        self.items.iter().find(|i| i.evidence_id == id)
    }

    pub fn find_by_path(&self, normalized: &str) -> Option<&RegistryItem> {
        // Latest registration of that path wins (an earlier one may have been superseded by changed content).
        self.items
            .iter()
            .rev()
            .find(|i| same_path(&i.path, normalized))
    }

    pub fn find_by_content(&self, hashes: &[(HashAlgo, String)]) -> Option<&RegistryItem> {
        self.items
            .iter()
            .find(|i| matches!(compare(&i.hashes, hashes), Comparison::Match(_)))
    }

    /// Algorithms present in every registered item, in the standard order.
    pub fn registry_algorithms(&self) -> Vec<HashAlgo> {
        HashAlgo::ALL
            .into_iter()
            .filter(|a| {
                !self.items.is_empty() && self.items.iter().all(|i| i.hashes.contains_key(a.name()))
            })
            .collect()
    }

    /// Verifies the log and appends one entry (caller holds the lock). Returns (seq, entry_hash).
    fn append_unlocked(
        &self,
        w: &Writer,
        action: &str,
        details: Value,
    ) -> Result<(u64, String), CaseError> {
        let path = self.dir.join(CASE_LOG);
        let (seq, prev) = if path.exists() {
            let n = audit::verify(&path).map_err(|p| {
                CaseError::new(
                    CaseErrorKind::Broken,
                    format!(
                        "refusing to extend a broken case log ({}): {}",
                        path.display(),
                        p[0]
                    ),
                )
            })?;
            let last = read_entries(&path)
                .last()
                .and_then(|e| e["entry_hash"].as_str().map(String::from))
                .unwrap_or_else(|| GENESIS.to_string());
            (n + 1, last)
        } else {
            (1, GENESIS.to_string())
        };
        let entry = build_entry(seq, &w.run_id, &w.actor, action, None, details, &prev);
        let line = serde_json::to_string(&Value::Object(entry.clone())).expect("serializable");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| CaseError::io("cannot open", &path, e))?;
        writeln!(f, "{}", line)
            .and_then(|_| f.sync_all())
            .map_err(|e| CaseError::io("cannot write", &path, e))?;
        Ok((
            seq,
            entry["entry_hash"].as_str().unwrap_or_default().to_string(),
        ))
    }

    /// Appends one event under the lock, after re-verifying the case log and registry digest.
    pub fn append(
        &self,
        w: &Writer,
        action: &str,
        details: Value,
    ) -> Result<(u64, String), CaseError> {
        let _guard = lock(&self.dir, w, self.lock_wait)?;
        self.reverify()?;
        self.append_unlocked(w, action, details)
    }

    fn reverify(&self) -> Result<LogState, CaseError> {
        verify_log_and_registry(&self.dir).map_err(|p| {
            CaseError::new(
                CaseErrorKind::Broken,
                format!(
                    "refusing to extend a broken case ({}): {}",
                    self.dir.display(),
                    p.join("; ")
                ),
            )
        })
    }

    /// Intake: registers items under the lock (reloading the registry first), writes registry.json/.csv and
    /// appends `evidence_registered` with the new registry digest.
    /// Same path + same content → the existing id; anything else → a new id.
    /// Returns, per input, the id it got, and the case-log seq of `evidence_registered`.
    pub fn register(
        &mut self,
        w: &Writer,
        regs: &[Registration],
    ) -> Result<(Vec<Assigned>, u64), CaseError> {
        let _guard = lock(&self.dir, w, self.lock_wait)?;
        self.reverify()?;
        let mut items = load_registry(&self.dir)?;
        let mut next = items.iter().map(|i| i.number()).max().unwrap_or(0);
        let now = utc_now();
        let mut out = Vec::with_capacity(regs.len());
        for r in regs {
            let existing = items.iter().rev().find(|i| {
                same_path(&i.path, &r.path)
                    && matches!(compare(&i.hashes, &r.hashes), Comparison::Match(_))
            });
            if let Some(e) = existing {
                out.push(Assigned {
                    evidence_id: e.evidence_id.clone(),
                    added: false,
                    registered_utc: e.registered_utc.clone(),
                });
                continue;
            }
            next += 1;
            let id = evidence_id(next);
            items.push(RegistryItem {
                evidence_id: id.clone(),
                path: r.path.clone(),
                size: r.size,
                hashes: r
                    .hashes
                    .iter()
                    .map(|(a, h)| (a.name().to_string(), h.clone()))
                    .collect(),
                registered_by: RegisteredBy {
                    tool: w.tool.clone(),
                    version: w.version.clone(),
                    run_id: w.run_id.clone(),
                    audit_seq: r.audit_seq,
                },
                registered_utc: now.clone(),
            });
            out.push(Assigned {
                evidence_id: id,
                added: true,
                registered_utc: now.clone(),
            });
        }
        items.sort_by_key(|i| i.number());
        let added: Vec<&String> = out
            .iter()
            .filter(|o| o.added)
            .map(|o| &o.evidence_id)
            .collect();
        let reg_json = crate::report::pretty(&json!({"schema": SCHEMA_REGISTRY, "items": items}));
        let reg_path = self.dir.join(REGISTRY_JSON);
        if !added.is_empty() || !reg_path.exists() {
            std::fs::create_dir_all(self.dir.join("evidence"))
                .map_err(|e| CaseError::io("cannot create", &self.dir, e))?;
            std::fs::write(&reg_path, &reg_json)
                .map_err(|e| CaseError::io("cannot write", &reg_path, e))?;
            let csv_path = self.dir.join(REGISTRY_CSV);
            std::fs::write(&csv_path, registry_csv(&items))
                .map_err(|e| CaseError::io("cannot write", &csv_path, e))?;
        }
        let digest = sha256_file(&reg_path).unwrap_or_default();
        let (seq, _) = self.append_unlocked(
            w,
            "evidence_registered",
            json!({"tool": w.tool, "version": w.version,
                   "evidence_ids": out.iter().map(|o| o.evidence_id.clone()).collect::<Vec<_>>(),
                   "added": added, "registry_items": items.len(), "registry_sha256": digest}),
        )?;
        self.items = items;
        Ok((out, seq))
    }
}

/// The evidence id an item got at registration.
#[derive(Clone, Debug, PartialEq)]
pub struct Assigned {
    pub evidence_id: String,
    /// false = same path and content were already registered under this id
    pub added: bool,
    pub registered_utc: String,
}

/// One item to register (intake role).
#[derive(Clone, Debug)]
pub struct Registration {
    /// normalize_path() of the evidence file
    pub path: String,
    pub size: u64,
    pub hashes: Vec<(HashAlgo, String)>,
    pub audit_seq: u64,
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// evidence_id,path,size,<algorithms present, standard order>,run_id
pub fn registry_csv(items: &[RegistryItem]) -> String {
    let algos: Vec<&str> = HashAlgo::ALL
        .iter()
        .map(|a| a.name())
        .filter(|a| items.iter().any(|i| i.hashes.contains_key(*a)))
        .collect();
    let mut out = format!("evidence_id,path,size,{},run_id\n", algos.join(","));
    for i in items {
        let h: Vec<String> = algos
            .iter()
            .map(|a| i.hashes.get(*a).cloned().unwrap_or_default())
            .collect();
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            i.evidence_id,
            csv_field(&i.path),
            i.size,
            h.join(","),
            i.registered_by.run_id
        ));
    }
    out
}

/// What `verify-case` found.
#[derive(Clone, Debug, Default)]
pub struct CaseVerification {
    pub case_id: String,
    pub entries: u64,
    pub registry_items: usize,
    pub runs: usize,
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
}

/// Full check of a case folder: case log chain, registry digest, each run's audit chain (and timestamps), the
/// cross-links (case_linked ↔ run_started) and that the audit head recorded at run_finished is the run's
/// final entry (later entries may only be `timestamp_obtained`).
pub fn verify_case(dir: &Path) -> CaseVerification {
    let mut v = CaseVerification::default();
    match load_case_json(dir) {
        Ok(c) => v.case_id = c["case_id"].as_str().unwrap_or_default().to_string(),
        Err(e) => {
            v.problems.push(e.message);
            return v;
        }
    }
    match verify_log_and_registry(dir) {
        Ok(s) => v.entries = s.entries,
        Err(p) => {
            v.problems.extend(p);
            if !dir.join(CASE_LOG).is_file() {
                return v;
            }
        }
    }
    v.registry_items = load_registry(dir).map(|i| i.len()).unwrap_or(0);
    let all = read_entries(&dir.join(CASE_LOG));
    let mut started: BTreeMap<String, (String, String)> = BTreeMap::new(); // run_id -> (run_dir, entry hash)
    let mut finished: BTreeMap<String, Value> = BTreeMap::new();
    for e in &all {
        let rid = e["run_id"].as_str().unwrap_or_default().to_string();
        match e["action"].as_str() {
            Some("run_started") => {
                started.insert(
                    rid,
                    (
                        e["details"]["run_dir"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string(),
                        e["entry_hash"].as_str().unwrap_or_default().to_string(),
                    ),
                );
            }
            Some("run_finished") => {
                if !started.contains_key(&rid) {
                    v.problems.push(format!(
                        "case log: run_finished for {} without run_started",
                        rid
                    ));
                }
                finished.insert(rid, e["details"].clone());
            }
            _ => {}
        }
    }
    v.runs = started.len();
    for (rid, (run_dir, started_hash)) in &started {
        let log_dir = dir.join(run_dir).join("logs");
        let audit_path = log_dir.join("audit.jsonl");
        let fin = finished.get(rid);
        let recorded_entries = fin.and_then(|f| f["audit_entries"].as_u64()).unwrap_or(0);
        if !audit_path.is_file() {
            if fin.is_none() || recorded_entries > 0 {
                v.problems
                    .push(format!("run {}: {} is missing", rid, audit_path.display()));
            }
            continue;
        }
        if let Err(p) = audit::verify(&audit_path) {
            for x in p {
                v.problems.push(format!("run {}: audit.jsonl {}", rid, x));
            }
            continue;
        }
        let entries = read_entries(&audit_path);
        match entries.iter().find(|e| e["action"] == "case_linked") {
            Some(l) => {
                if l["details"]["case_id"].as_str() != Some(v.case_id.as_str()) {
                    v.problems
                        .push(format!("run {}: case_linked names another case", rid));
                }
                if l["details"]["case_log_head_at_start"].as_str() != Some(started_hash.as_str()) {
                    v.problems.push(format!(
                        "run {}: case_linked does not point to its run_started entry in the case log",
                        rid
                    ));
                }
            }
            None => v
                .problems
                .push(format!("run {}: audit.jsonl has no case_linked entry", rid)),
        }
        for p in crate::trust::verify_timestamps(&audit_path) {
            v.problems.push(format!("run {}: {}", rid, p));
        }
        let Some(fin) = fin else {
            v.warnings.push(format!(
                "run {}: no run_finished in the case log (still running, or interrupted)",
                rid
            ));
            continue;
        };
        if recorded_entries == 0 {
            continue;
        }
        let at = entries
            .iter()
            .find(|e| e["seq"].as_u64() == Some(recorded_entries));
        if at.and_then(|e| e["entry_hash"].as_str()) != fin["audit_head"].as_str() {
            v.problems.push(format!(
                "run {}: the audit head recorded in the case log is not entry #{} of the run's audit.jsonl",
                rid, recorded_entries
            ));
        }
        for later in entries
            .iter()
            .filter(|e| e["seq"].as_u64().unwrap_or(0) > recorded_entries)
        {
            if later["action"] != "timestamp_obtained" {
                v.problems.push(format!(
                    "run {}: audit entry #{} ({}) was appended after run_finished",
                    rid,
                    later["seq"],
                    later["action"].as_str().unwrap_or("?")
                ));
            }
        }
    }
    // Run folders that the case log never announced.
    if let Ok(tools) = std::fs::read_dir(dir.join("runs")) {
        for t in tools.flatten() {
            for r in std::fs::read_dir(t.path()).into_iter().flatten().flatten() {
                let name = r.file_name().to_string_lossy().into_owned();
                if !started.contains_key(&name) {
                    v.warnings.push(format!(
                        "runs/{}/{} is not announced in the case log",
                        t.file_name().to_string_lossy(),
                        name
                    ));
                }
            }
        }
    }
    v
}

/// What `verify-case --rehash` found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Rehash {
    /// Registered items re-hashed (the latest registration of each reachable path).
    pub checked: usize,
    /// Of those, items whose digests all equal the registry's.
    pub matched: usize,
    /// Items in the registry.
    pub registered: usize,
}

/// Re-hashes every registered item that is still reachable and compares it with the registry (`verify-case
/// --rehash`). A path registered several times (its content changed between intakes) is compared with its
/// latest registration; earlier ones are reported as superseded. Differences go to `v.problems` (exit 3),
/// unreachable or unreadable files to `v.warnings`.
pub fn rehash_registry(dir: &Path, v: &mut CaseVerification) -> Rehash {
    let items = match load_registry(dir) {
        Ok(i) => i,
        Err(e) => {
            v.problems
                .push(format!("{}: cannot re-hash: {}", REGISTRY_JSON, e.message));
            return Rehash::default();
        }
    };
    let mut r = Rehash {
        registered: items.len(),
        ..Default::default()
    };
    for (i, item) in items.iter().enumerate() {
        if let Some(later) = items[i + 1..]
            .iter()
            .find(|o| same_path(&o.path, &item.path))
        {
            v.warnings.push(format!(
                "{} {}: superseded by {} (same path registered again): not re-hashed",
                item.evidence_id, item.path, later.evidence_id
            ));
            continue;
        }
        let path = PathBuf::from(&item.path);
        if !path.is_file() {
            v.warnings.push(format!(
                "{} {}: not reachable from this workstation: not re-hashed",
                item.evidence_id, item.path
            ));
            continue;
        }
        let mut algos: Vec<HashAlgo> = HashAlgo::ALL
            .into_iter()
            .filter(|a| item.hashes.contains_key(a.name()))
            .collect();
        algos.truncate(HashAlgo::MAX_SELECTED);
        if algos.is_empty() {
            v.warnings.push(format!(
                "{} {}: no supported algorithm in the registry: not re-hashed",
                item.evidence_id, item.path
            ));
            continue;
        }
        let outcome =
            std::fs::File::open(&path).and_then(|f| crate::hash::hash_reader(f, &algos, |_| true));
        let digests = match outcome {
            Ok(Some(o)) => o.digests,
            Ok(None) => continue,
            Err(e) => {
                v.warnings.push(format!(
                    "{} {}: cannot be read ({}): not re-hashed",
                    item.evidence_id, item.path, e
                ));
                continue;
            }
        };
        r.checked += 1;
        match compare(&item.hashes, &digests) {
            Comparison::Match(_) => r.matched += 1,
            Comparison::Mismatch {
                algorithm,
                expected,
                actual,
            } => v.problems.push(format!(
                "{} {}: {} differs from the registry (registered {}, now {})",
                item.evidence_id, item.path, algorithm, expected, actual
            )),
            Comparison::NoCommonAlgorithm => {}
        }
    }
    r
}

/// Checks done by front-ends before a run, to map case problems to exit codes (2 usage, 3 broken):
/// schema, broken log/registry, case id, missing --case on creation, unknown evidence ids.
pub fn preflight(
    dir: &Path,
    case_id: Option<&str>,
    evidence_ids: &[String],
) -> Result<(), CaseError> {
    if !dir.join(CASE_FILE).exists() {
        if case_id.map(str::trim).filter(|s| !s.is_empty()).is_none() {
            return Err(CaseError::new(
                CaseErrorKind::Usage,
                format!(
                    "{} is not a case folder yet: give --case ID (and --jurisdiction) to create it",
                    dir.display()
                ),
            ));
        }
        if !evidence_ids.is_empty() {
            return Err(CaseError::new(
                CaseErrorKind::Usage,
                "--evidence needs an existing case folder with a registry",
            ));
        }
        return Ok(());
    }
    let c = Case::open(dir)?;
    c.check_case_id(case_id)?;
    c.check_ids(evidence_ids)
}

impl Case {
    pub fn check_ids(&self, ids: &[String]) -> Result<(), CaseError> {
        let unknown: Vec<&String> = ids.iter().filter(|i| self.get(i).is_none()).collect();
        if unknown.is_empty() {
            Ok(())
        } else {
            Err(CaseError::new(
                CaseErrorKind::Usage,
                format!(
                    "evidence id(s) not in the case registry: {}",
                    unknown
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ))
        }
    }
}

/// Paths are compared as text after normalisation; Windows file systems are case-insensitive, so the
/// comparison is too (D:\Evidence\a.pdf and d:\evidence\A.PDF are the same file there).
pub fn same_path(a: &str, b: &str) -> bool {
    #[cfg(windows)]
    {
        a.to_lowercase() == b.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(run: &str) -> Writer {
        Writer {
            tool: "rv-test".into(),
            version: "0".into(),
            run_id: run.into(),
            actor: "tester".into(),
        }
    }

    fn reg(path: &str, sha: &str) -> Registration {
        Registration {
            path: path.into(),
            size: 1,
            hashes: vec![(HashAlgo::Sha256, sha.into())],
            audit_seq: 3,
        }
    }

    #[test]
    fn create_register_and_verify() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("case");
        assert_eq!(
            Case::open_or_create(&dir, None, "co", &w("R1"))
                .unwrap_err()
                .kind,
            CaseErrorKind::Usage
        );
        let (mut c, created) = Case::open_or_create(&dir, Some("C-1"), "fr", &w("R1")).unwrap();
        assert!(created);
        let (ids, _) = c
            .register(&w("R1"), &[reg("/a", "aa"), reg("/b", "bb")])
            .unwrap();
        assert_eq!(ids[0].evidence_id, "E0001");
        assert_eq!(ids[1].evidence_id, "E0002");
        // Same path + same content → same id; same path, other content → new id.
        let (ids, _) = c
            .register(&w("R2"), &[reg("/a", "aa"), reg("/b", "cc")])
            .unwrap();
        assert_eq!(
            (
                ids[0].evidence_id.as_str(),
                ids[0].added,
                ids[1].evidence_id.as_str(),
                ids[1].added
            ),
            ("E0001", false, "E0003", true)
        );
        let again = Case::open(&dir).unwrap();
        assert_eq!(again.items.len(), 3);
        assert_eq!(again.jurisdiction, "fr");
        assert_eq!(again.find_by_path("/b").unwrap().evidence_id, "E0003");
        let csv = std::fs::read_to_string(dir.join(REGISTRY_CSV)).unwrap();
        assert!(csv.starts_with("evidence_id,path,size,sha256,run_id\nE0001,/a,1,aa,R1\n"));
        assert!(verify_case(&dir).problems.is_empty());
        // Wrong case id is a usage error.
        assert_eq!(
            preflight(&dir, Some("OTHER"), &[]).unwrap_err().kind,
            CaseErrorKind::Usage
        );
        assert_eq!(
            preflight(&dir, None, &["E0009".into()]).unwrap_err().kind,
            CaseErrorKind::Usage
        );
        assert!(preflight(&dir, Some("C-1"), &["E0002".into()]).is_ok());
    }

    #[test]
    fn edited_registry_or_log_is_detected_and_never_extended() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("case");
        let (mut c, _) = Case::open_or_create(&dir, Some("C-1"), "co", &w("R1")).unwrap();
        c.register(&w("R1"), &[reg("/a", "aa")]).unwrap();
        let rp = dir.join(REGISTRY_JSON);
        let original = std::fs::read_to_string(&rp).unwrap();
        std::fs::write(&rp, original.replace("\"aa\"", "\"ab\"")).unwrap();
        let e = Case::open(&dir).unwrap_err();
        assert_eq!(e.kind, CaseErrorKind::Broken);
        assert!(e.message.contains("registry"), "{}", e.message);
        assert!(c.append(&w("R2"), "run_started", json!({})).is_err());
        std::fs::write(&rp, original).unwrap();
        assert!(Case::open(&dir).is_ok());
        let lp = dir.join(CASE_LOG);
        let log = std::fs::read_to_string(&lp).unwrap();
        std::fs::write(&lp, log.replacen("tester", "mallory", 1)).unwrap();
        assert_eq!(Case::open(&dir).unwrap_err().exit_code(), 3);
        assert!(!verify_case(&dir).problems.is_empty());
    }

    #[test]
    fn lock_contention_and_stale_lock() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("case");
        let (mut c, _) = Case::open_or_create(&dir, Some("C-1"), "co", &w("R1")).unwrap();
        c.lock_wait = Duration::from_millis(0);
        let held = lock(&dir, &w("OTHER"), Duration::ZERO).unwrap();
        let e = c.append(&w("R2"), "run_started", json!({})).unwrap_err();
        assert_eq!(e.kind, CaseErrorKind::Locked);
        assert!(
            e.message.contains("locked by rv-test run OTHER"),
            "{}",
            e.message
        );
        drop(held);
        assert!(c.append(&w("R2"), "run_started", json!({})).is_ok());
        // A lock older than 10 minutes is reported as stale and left in place.
        let lp = dir.join(LOCK_FILE);
        std::fs::write(&lp, "{}").unwrap();
        let old = SystemTime::now() - Duration::from_secs(11 * 60);
        std::fs::File::options()
            .write(true)
            .open(&lp)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let e = c.append(&w("R3"), "run_started", json!({})).unwrap_err();
        assert!(e.message.contains("stale"), "{}", e.message);
        assert!(lp.exists(), "a stale lock is never removed automatically");
    }

    #[test]
    fn algorithms_ids_and_paths() {
        use HashAlgo::*;
        assert_eq!(
            ensure_case_algorithm(&[Md5], &[Sha256]).0,
            vec![Md5, Sha256]
        );
        assert_eq!(
            ensure_case_algorithm(&[Md5, Sha1], &[Blake3]),
            (vec![Md5, Blake3], Some((Blake3, Some(Sha1))))
        );
        assert_eq!(ensure_case_algorithm(&[Sha256], &[Sha256]).1, None);
        assert_eq!(
            parse_evidence_ids(&["e1, E0007".into(), "E0001".into()]).unwrap(),
            vec!["E0001", "E0007"]
        );
        assert!(parse_evidence_ids(&["7".into()]).is_err());
        assert_eq!(evidence_id(12345), "E12345");
        let p = normalize_path(Path::new("/x/y/../z/./f.txt"));
        // Separator is "\\" on Windows: compare path components, not text.
        assert!(
            Path::new(&p).ends_with(Path::new("z").join("f.txt")) && !p.contains(".."),
            "{}",
            p
        );
        let mut exp = BTreeMap::new();
        exp.insert("sha256".to_string(), "AA".to_string());
        assert!(matches!(
            compare(&exp, &[(Sha256, "aa".into())]),
            Comparison::Match(_)
        ));
        assert!(matches!(
            compare(&exp, &[(Md5, "aa".into())]),
            Comparison::NoCommonAlgorithm
        ));
    }

    #[test]
    fn rehash_compares_reachable_items_with_the_registry() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("case");
        let ev = d.path().join("ev");
        std::fs::create_dir_all(&ev).unwrap();
        let (a, b) = (ev.join("a.txt"), ev.join("b.txt"));
        std::fs::write(&a, "a").unwrap();
        std::fs::write(&b, "b").unwrap();
        let sha = |p: &Path| hash_bytes(&std::fs::read(p).unwrap(), HashAlgo::Sha256);
        let (mut c, _) = Case::open_or_create(&dir, Some("C-1"), "co", &w("R1")).unwrap();
        let gone = ev.join("gone.txt").display().to_string();
        c.register(
            &w("R1"),
            &[
                reg(&normalize_path(&a), &sha(&a)),
                reg(&normalize_path(&b), &sha(&b)),
                reg(&gone, "00"),
            ],
        )
        .unwrap();
        let mut v = CaseVerification::default();
        let r = rehash_registry(&dir, &mut v);
        assert_eq!((r.registered, r.checked, r.matched), (3, 2, 2));
        assert!(v.problems.is_empty(), "{:?}", v.problems);
        assert!(
            v.warnings
                .iter()
                .any(|w| w.contains("E0003") && w.contains("not reachable"))
        );
        // Evidence changed after intake: reported as a problem.
        std::fs::write(&b, "B").unwrap();
        let mut v = CaseVerification::default();
        let r = rehash_registry(&dir, &mut v);
        assert_eq!((r.checked, r.matched), (2, 1));
        assert!(v.problems[0].starts_with("E0002 ") && v.problems[0].contains("sha256 differs"));
        // Re-registered with the new content: the old entry is superseded, the new one matches.
        c.register(&w("R2"), &[reg(&normalize_path(&b), &sha(&b))])
            .unwrap();
        let mut v = CaseVerification::default();
        let r = rehash_registry(&dir, &mut v);
        assert_eq!((r.registered, r.checked, r.matched), (4, 2, 2));
        assert!(
            v.problems.is_empty() && v.warnings.iter().any(|w| w.contains("superseded by E0004"))
        );
    }
}
