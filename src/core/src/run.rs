//! The pipeline both front-ends call: intake → hash + analyze each item → duplicates →
//! hashes.csv → per-item reports → statistics report. Every step is written to the audit log.
//!
//! With `case_dir` the run works inside a shared case folder (see `case.rs`): outputs go to
//! `<CASE>/runs/<tool>/<RUN-ID>/`, the case log records run_started / run_finished, and depending on
//! [`CaseRole`] every item is registered (intake) or verified against the registry (analysis).

use crate::analyzer::{Finding, Severity, analyze};
use crate::audit::AuditLog;
use crate::case::{self, Case, CaseRole, Comparison, Registration, Writer};
use crate::events::{Event, eta_ms};
use crate::hash::{HashAlgo, hash_bytes, hash_reader, validate_selection};
use crate::input::collect;
use crate::report::{self, AuditRef, CaseInfo, CaseTally, ItemResult, RunInfo, RunTotals};
use crate::time::{utc_compact, utc_from, utc_now};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct RunConfig {
    pub inputs: Vec<PathBuf>,
    pub input_list: Option<PathBuf>,
    pub recursive: bool,
    pub algorithms: Vec<HashAlgo>,
    pub out_dir: PathBuf,
    pub langs: Vec<String>,
    pub actor: String,
    pub case_id: Option<String>,
    /// "cli" or "gui"
    pub frontend: String,
    /// Front-end actions to audit before the run starts (e.g. GUI setting changes): (action, details).
    pub preamble: Vec<(String, Value)>,
    /// Command line (CLI) or equivalent settings (GUI), stored in environment.json.
    pub command_line: Vec<String>,
    pub tool_name: String,
    pub tool_version: String,
    /// Custody form: "co" (Colombia, Fiscalía) or "fr" (France, scellés).
    pub jurisdiction: String,
    /// RFC 3161 time-stamping authority; None = no timestamp.
    pub tsa_url: Option<String>,
    /// Examiner's .p12/.pfx used to sign every PDF.
    pub sign_cert: Option<PathBuf>,
    /// Never logged.
    pub sign_password: Option<String>,
    /// Shared case folder (`--case-dir`). None = standalone run in `out_dir`.
    pub case_dir: Option<PathBuf>,
    /// Case folder only: evidence ids to examine (E0001…). With no input and no ids, every registered item.
    pub evidence_ids: Vec<String>,
    /// Intake (registers evidence) or analysis (verifies against the registry). Default: [`crate::CASE_ROLE`].
    pub case_role: CaseRole,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig {
            inputs: vec![],
            input_list: None,
            recursive: false,
            algorithms: vec![HashAlgo::Sha256],
            out_dir: PathBuf::from("rakvor-out"),
            langs: vec!["en".into()],
            actor: "unknown".into(),
            case_id: None,
            frontend: "cli".into(),
            preamble: vec![],
            command_line: vec![],
            tool_name: crate::TOOL_NAME.into(),
            tool_version: crate::TOOL_VERSION.into(),
            jurisdiction: "co".into(),
            tsa_url: None,
            sign_cert: None,
            sign_password: None,
            case_dir: None,
            evidence_ids: vec![],
            case_role: crate::CASE_ROLE,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RunSummary {
    pub run_id: String,
    pub items: u64,
    pub bytes: u64,
    pub errors: u64,
    pub elapsed_ms: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    pub cancelled: bool,
    pub report_dir: PathBuf,
    pub log_dir: PathBuf,
    pub audit_head: String,
    /// {"status": "ok"|"pending"|"off", ...}
    pub timestamp: Value,
    /// Case folder runs: case id, role and how the items relate to the registry.
    pub case: Option<CaseInfo>,
}

/// A run linked to a case folder.
struct CaseLink {
    case: Case,
    writer: Writer,
    /// "runs/<tool>/<RUN-ID>" (relative to the case folder, forward slashes)
    run_rel: String,
    run_dir: PathBuf,
    started_seq: u64,
    started_head: String,
    created: bool,
    requested_algorithms: Vec<HashAlgo>,
    algo_change: Option<(HashAlgo, Option<HashAlgo>)>,
    requested_jurisdiction: String,
    registry_sha256: Option<String>,
    /// normalised path → evidence id, for items selected with --evidence
    by_evidence: BTreeMap<String, String>,
    tally: CaseTally,
}

impl CaseLink {
    fn info(&self, role: CaseRole) -> CaseInfo {
        CaseInfo {
            case_id: self.case.case_id.clone(),
            role: role.name().into(),
            dir: self.case.dir.display().to_string(),
            tally: self.tally.clone(),
        }
    }
}

/// Opens (or creates) the case, resolves --evidence, applies the case rules to the configuration and appends
/// run_started to the case log. Nothing is written into a case that fails verification.
fn open_case(cfg: &RunConfig, dir: &Path, run_id: &str) -> Result<(RunConfig, CaseLink), String> {
    let writer = Writer {
        tool: cfg.tool_name.clone(),
        version: cfg.tool_version.clone(),
        run_id: run_id.to_string(),
        actor: cfg.actor.clone(),
    };
    let ids = case::parse_evidence_ids(&cfg.evidence_ids)?;
    let (case, created) =
        Case::open_or_create(dir, cfg.case_id.as_deref(), &cfg.jurisdiction, &writer)?;
    case.check_ids(&ids)?;
    let mut c = cfg.clone();
    c.case_id = Some(case.case_id.clone());
    c.jurisdiction = case.jurisdiction.clone();
    let (algos, algo_change) =
        case::ensure_case_algorithm(&cfg.algorithms, &case.registry_algorithms());
    c.algorithms = algos;
    c.evidence_ids = ids.clone();
    let mut by_evidence = BTreeMap::new();
    for id in &ids {
        if let Some(it) = case.get(id) {
            c.inputs.push(PathBuf::from(&it.path));
            by_evidence.insert(it.path.clone(), id.clone());
        }
    }
    if c.inputs.is_empty() && c.input_list.is_none() {
        c.inputs = case.items.iter().map(|i| PathBuf::from(&i.path)).collect();
    }
    let run_rel = format!("runs/{}/{}", cfg.tool_name, run_id);
    let run_dir = dir.join("runs").join(&cfg.tool_name).join(run_id);
    let (started_seq, started_head) = case.append(
        &writer,
        "run_started",
        json!({"tool": cfg.tool_name, "version": cfg.tool_version, "run_dir": run_rel, "frontend": cfg.frontend,
               "role": cfg.case_role.name(), "evidence_ids": ids}),
    )?;
    let registry_sha256 = case::registry_digest(dir);
    Ok((
        c,
        CaseLink {
            case,
            writer,
            run_rel,
            run_dir,
            started_seq,
            started_head,
            created,
            requested_algorithms: cfg.algorithms.clone(),
            algo_change,
            requested_jurisdiction: cfg.jurisdiction.clone(),
            registry_sha256,
            by_evidence,
            tally: CaseTally::default(),
        },
    ))
}

/// Appends run_finished to the case log (also after a cancel or a failure). The audit head recorded here is the
/// run's final audit entry, read back from disk.
fn finish_case(
    link: &CaseLink,
    cfg: &RunConfig,
    log_dir: &Path,
    result: &Result<RunSummary, String>,
    sink: &mut dyn FnMut(&Event),
) {
    let heads = crate::audit::heads(&log_dir.join("audit.jsonl"));
    let (entries, head) = heads
        .iter()
        .next_back()
        .map(|(s, h)| (*s, json!(h)))
        .unwrap_or((0, Value::Null));
    let t = &link.tally;
    let verification = json!({"registered": t.registered, "added": t.added, "verified": t.verified,
                              "mismatched": t.mismatched, "unregistered": t.unregistered});
    let details = match result {
        Ok(s) => json!({
            "tool": cfg.tool_name, "version": cfg.tool_version, "run_dir": link.run_rel,
            "status": if s.cancelled { "cancelled" } else { "completed" },
            "audit_head": head, "audit_entries": entries,
            "timestamp_status": s.timestamp["status"].as_str().unwrap_or("off"),
            "totals": {"items": s.items, "bytes": s.bytes, "errors": s.errors, "high": s.high, "medium": s.medium,
                       "low": s.low, "info": s.info},
            "verification": verification,
        }),
        Err(e) => json!({
            "tool": cfg.tool_name, "version": cfg.tool_version, "run_dir": link.run_rel, "status": "failed",
            "reason": e, "audit_head": head, "audit_entries": entries, "timestamp_status": "off",
            "totals": null, "verification": verification,
        }),
    };
    if let Err(e) = link.case.append(&link.writer, "run_finished", details) {
        sink(&Event::Error {
            path: None,
            message: format!("case log: run_finished not recorded: {}", e),
        });
    }
}

const PROGRESS_EVERY: Duration = Duration::from_millis(150);

fn new_run_id() -> String {
    let seed = format!(
        "{:?}-{}-{}",
        std::time::SystemTime::now(),
        std::process::id(),
        crate::env::hostname()
    );
    format!(
        "{}-{}",
        utc_compact(),
        &hash_bytes(seed.as_bytes(), HashAlgo::Sha256)[..6]
    )
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Runs the whole pipeline. Events go to `sink`; set `cancel` to stop after the current chunk
/// (partial reports are still written and the cancellation is audited).
pub fn run(
    cfg: &RunConfig,
    sink: &mut dyn FnMut(&Event),
    cancel: &AtomicBool,
) -> Result<RunSummary, String> {
    validate_selection(&cfg.algorithms)?;
    if cfg.langs.is_empty() {
        return Err("select at least one report language".into());
    }
    if cfg.jurisdiction != "co" && cfg.jurisdiction != "fr" {
        return Err(format!(
            "unknown jurisdiction '{}': use co or fr",
            cfg.jurisdiction
        ));
    }
    let run_id = new_run_id();
    let Some(case_dir) = &cfg.case_dir else {
        let log_dir = cfg.out_dir.join("logs").join(&run_id);
        let report_dir = cfg.out_dir.join("reports").join(&run_id);
        return pipeline(cfg, sink, cancel, &run_id, &log_dir, &report_dir, None);
    };
    let (cfg, mut link) = open_case(cfg, case_dir, &run_id)?;
    let log_dir = link.run_dir.join("logs");
    let report_dir = link.run_dir.join("reports");
    let result = pipeline(
        &cfg,
        sink,
        cancel,
        &run_id,
        &log_dir,
        &report_dir,
        Some(&mut link),
    );
    finish_case(&link, &cfg, &log_dir, &result, sink);
    result
}

fn pipeline(
    cfg: &RunConfig,
    sink: &mut dyn FnMut(&Event),
    cancel: &AtomicBool,
    run_id: &str,
    log_dir: &Path,
    report_dir: &Path,
    mut link: Option<&mut CaseLink>,
) -> Result<RunSummary, String> {
    let started = Instant::now();
    let started_utc = utc_now();
    let run_id = run_id.to_string();
    let (log_dir, report_dir) = (log_dir.to_path_buf(), report_dir.to_path_buf());
    let mut log = AuditLog::create(&log_dir, &run_id, &cfg.actor)
        .map_err(|e| format!("cannot create audit log in {}: {}", log_dir.display(), e))?;
    let io = |e: std::io::Error| format!("audit log write failed: {}", e);

    log.record(
        "run_started",
        None,
        json!({
            "tool": cfg.tool_name, "version": cfg.tool_version, "frontend": cfg.frontend,
            "algorithms": cfg.algorithms, "langs": cfg.langs, "case_id": cfg.case_id,
            "inputs": cfg.inputs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "input_list": cfg.input_list.as_ref().map(|p| p.display().to_string()),
            "recursive": cfg.recursive, "out_dir": cfg.out_dir.display().to_string(),
            "jurisdiction": cfg.jurisdiction, "tsa_url": cfg.tsa_url,
            "sign_cert": cfg.sign_cert.as_ref().map(|p| p.display().to_string()),
            "case_dir": cfg.case_dir.as_ref().map(|p| p.display().to_string()),
            "evidence_ids": cfg.evidence_ids,
        }),
    )
    .map_err(io)?;
    if let Some(l) = link.as_deref() {
        log.record(
            "case_linked",
            None,
            json!({"case_id": l.case.case_id, "case_dir": l.case.dir.display().to_string(), "role": cfg.case_role.name(),
                   "run_dir": l.run_rel, "case_created": l.created, "case_log_seq_at_start": l.started_seq,
                   "case_log_head_at_start": l.started_head, "registry_sha256": l.registry_sha256,
                   "registry_items": l.case.items.len(), "jurisdiction": l.case.jurisdiction,
                   "requested_jurisdiction": l.requested_jurisdiction}),
        )
        .map_err(io)?;
        if let Some((added, replaced)) = l.algo_change {
            log.record(
                "case_algorithm_added",
                None,
                json!({"requested": l.requested_algorithms, "added": added, "replaced": replaced,
                       "algorithms": cfg.algorithms, "registry_algorithms": l.case.registry_algorithms()}),
            )
            .map_err(io)?;
        }
    }
    for (action, details) in &cfg.preamble {
        log.record(action, None, details.clone()).map_err(io)?;
    }

    let env_json = report::pretty(&crate::env::describe(
        &cfg.tool_name,
        &cfg.tool_version,
        &cfg.frontend,
        &cfg.command_line,
    ));
    let (_, env_digest) =
        report::write_hashed(&log_dir, "environment.json", &env_json, &cfg.algorithms)?;
    log.record("environment_recorded", Some("environment.json"), env_digest)
        .map_err(io)?;
    let signer = match &cfg.sign_cert {
        None => None,
        Some(p) => {
            match crate::trust::PdfSigner::load(p, cfg.sign_password.as_deref().unwrap_or("")) {
                Ok(s) => {
                    log.record(
                        "signing_certificate_loaded",
                        Some(&p.display().to_string()),
                        json!({"subject": s.subject, "certificate_sha256": s.fingerprint_sha256}),
                    )
                    .map_err(io)?;
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    log.record("run_failed", None, json!({"reason": e}))
                        .map_err(io)?;
                    return Err(e);
                }
            }
        }
    };

    let items = match collect(&cfg.inputs, cfg.input_list.as_deref(), cfg.recursive) {
        Ok(i) => i,
        Err(e) => {
            log.record("error", None, json!({"stage": "input", "message": e}))
                .map_err(io)?;
            log.record("run_failed", None, json!({"reason": e}))
                .map_err(io)?;
            return Err(e);
        }
    };
    let total_items = items.len() as u64;
    let total_bytes: u64 = items.iter().map(|i| i.size).sum();
    log.record(
        "inputs_resolved",
        None,
        json!({"items": total_items, "bytes": total_bytes}),
    )
    .map_err(io)?;
    sink(&Event::RunStarted {
        run_id: run_id.clone(),
        tool: cfg.tool_name.clone(),
        version: cfg.tool_version.clone(),
        frontend: cfg.frontend.clone(),
        algorithms: cfg.algorithms.clone(),
        langs: cfg.langs.clone(),
        total_items,
        total_bytes,
    });

    let mut results: Vec<ItemResult> = Vec::with_capacity(items.len());
    let mut hashed_seq: BTreeMap<u64, u64> = BTreeMap::new();
    let mut bytes_before = 0u64;
    let mut errors = 0u64;
    let mut cancelled = false;
    let mut last_progress = Instant::now() - PROGRESS_EVERY;

    for item in &items {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        let path_s = item.path.display().to_string();
        let modified = std::fs::metadata(&item.path)
            .and_then(|m| m.modified())
            .ok();
        let modified_utc = modified.map(utc_from);
        sink(&Event::ItemStarted {
            index: item.index,
            path: path_s.clone(),
            size: item.size,
        });
        let first_seq = log
            .record(
                "item_started",
                Some(&path_s),
                json!({"index": item.index, "size": item.size, "modified_utc": modified_utc}),
            )
            .map_err(io)?;

        let mut on_chunk = |n: u64| {
            if last_progress.elapsed() >= PROGRESS_EVERY {
                last_progress = Instant::now();
                let elapsed = started.elapsed().as_millis() as u64;
                let done_bytes = bytes_before + n;
                sink(&Event::Progress {
                    done: item.index - 1,
                    total: total_items,
                    bytes_done: done_bytes,
                    bytes_total: total_bytes,
                    elapsed_ms: elapsed,
                    eta_ms: eta_ms(elapsed, done_bytes, total_bytes),
                });
            }
            !cancel.load(Ordering::Relaxed)
        };
        // File::open is read-only: the evidence is never opened for writing.
        let outcome = std::fs::File::open(&item.path)
            .and_then(|f| hash_reader(f, &cfg.algorithms, &mut on_chunk));
        let mut result = ItemResult {
            index: item.index,
            path: item.path.clone(),
            size: item.size,
            modified_utc,
            hashes: vec![],
            detected_type: None,
            extension: None,
            findings: vec![],
            error: None,
            audit_first_seq: first_seq,
            audit_last_seq: first_seq,
            evidence_id: None,
            case_status: None,
            intake_utc: None,
        };
        match outcome {
            Ok(None) => {
                log.record(
                    "item_cancelled",
                    Some(&path_s),
                    json!({"index": item.index}),
                )
                .map_err(io)?;
                cancelled = true;
                break;
            }
            Ok(Some(out)) => {
                let after = std::fs::metadata(&item.path)
                    .and_then(|m| m.modified())
                    .ok();
                let hashes: BTreeMap<String, String> = out
                    .digests
                    .iter()
                    .map(|(a, h)| (a.name().to_string(), h.clone()))
                    .collect();
                let seq = log.record("item_hashed", Some(&path_s), json!({"index": item.index, "bytes_read": out.bytes, "hashes": hashes, "mtime_unchanged": modified == after})).map_err(io)?;
                hashed_seq.insert(item.index, seq);
                sink(&Event::ItemHashed {
                    index: item.index,
                    path: path_s.clone(),
                    hashes,
                });
                let a = analyze(&result.file_name(), out.bytes, &out.head);
                result.size = out.bytes;
                result.hashes = out.digests;
                result.detected_type = a.detected_type;
                result.extension = a.extension;
                result.findings = a.findings;
                if let Some(l) = link.as_deref_mut() {
                    case_check_item(l, cfg.case_role, &mut result, &mut log, sink)?;
                }
            }
            Err(e) => {
                errors += 1;
                result.error = Some(e.to_string());
                result
                    .findings
                    .push(Finding::new("UNREADABLE", Severity::High).with("error", e.to_string()));
                sink(&Event::Error {
                    path: Some(path_s.clone()),
                    message: e.to_string(),
                });
                log.record(
                    "item_error",
                    Some(&path_s),
                    json!({"index": item.index, "message": e.to_string()}),
                )
                .map_err(io)?;
            }
        }
        let codes: Vec<String> = result.findings.iter().map(|f| f.code.clone()).collect();
        result.audit_last_seq = log.record("item_analyzed", Some(&path_s), json!({"index": item.index, "detected_type": result.detected_type, "extension": result.extension, "findings": result.findings, "status": result.status()})).map_err(io)?;
        sink(&Event::ItemFinished {
            index: item.index,
            path: path_s,
            status: result.status().into(),
            findings: codes,
        });
        bytes_before += item.size;
        let elapsed = started.elapsed().as_millis() as u64;
        sink(&Event::Progress {
            done: item.index,
            total: total_items,
            bytes_done: bytes_before,
            bytes_total: total_bytes,
            elapsed_ms: elapsed,
            eta_ms: eta_ms(elapsed, bytes_before, total_bytes),
        });
        results.push(result);
    }
    if cancelled {
        log.record(
            "run_cancelled",
            None,
            json!({"processed": results.len(), "of": total_items}),
        )
        .map_err(io)?;
        sink(&Event::Cancelled {
            done: results.len() as u64,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    }

    // Intake: register every successfully hashed item in the case registry (under the case lock).
    if let (Some(l), CaseRole::Intake) = (link.as_deref_mut(), cfg.case_role) {
        register_items(l, &mut results, &hashed_seq, &mut log, sink)?;
    }

    // Duplicates (cross-item finding).
    let primary = cfg.algorithms[0];
    for (hash, idx) in report::duplicate_groups(&results) {
        let names: Vec<String> = idx.iter().map(|&i| results[i].file_name()).collect();
        log.record("duplicate_group", None, json!({"algorithm": primary, "hash": hash, "items": idx.iter().map(|&i| results[i].index).collect::<Vec<_>>()})).map_err(io)?;
        for &i in &idx {
            let others: Vec<String> = names
                .iter()
                .enumerate()
                .filter(|(j, _)| idx[*j] != i)
                .map(|(_, n)| n.clone())
                .collect();
            results[i].findings.push(
                Finding::new("DUPLICATE", Severity::Info)
                    .with("algorithm", primary.name())
                    .with("count", idx.len().to_string())
                    .with("others", crate::report::capped_list(&others, 10)),
            );
        }
    }

    // hashes.csv: the hash register of every reviewed file.
    let mut csv = format!(
        "index,path,size,{},status,error\n",
        cfg.algorithms
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>()
            .join(",")
    );
    for r in &results {
        let hashes: Vec<String> = cfg
            .algorithms
            .iter()
            .map(|a| {
                r.hashes
                    .iter()
                    .find(|(x, _)| x == a)
                    .map(|(_, h)| h.clone())
                    .unwrap_or_default()
            })
            .collect();
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            r.index,
            csv_field(&r.path.display().to_string()),
            r.size,
            hashes.join(","),
            r.status(),
            csv_field(r.error.as_deref().unwrap_or(""))
        ));
    }
    let (_, csv_digest) =
        report::write_hashed(&log_dir, "hashes.csv", csv.as_bytes(), &cfg.algorithms)?;
    log.record("hash_register_written", Some("hashes.csv"), csv_digest)
        .map_err(io)?;

    // Reports.
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let info = RunInfo {
        tool_name: cfg.tool_name.clone(),
        tool_version: cfg.tool_version.clone(),
        run_id: run_id.clone(),
        case_id: cfg.case_id.clone(),
        actor: cfg.actor.clone(),
        frontend: cfg.frontend.clone(),
        algorithms: cfg.algorithms.clone(),
        langs: cfg.langs.clone(),
        started_utc,
        finished_utc: utc_now(),
        elapsed_ms,
        cancelled,
        jurisdiction: cfg.jurisdiction.clone(),
        signer,
        timestamp: json!({"status": "off"}),
        case: link.as_deref().map(|l| l.info(cfg.case_role)),
    };
    let log_dir_s = log_dir.display().to_string();
    for r in &results {
        let audit = AuditRef {
            head: log.head().to_string(),
            entries: log.entries(),
            log_dir: log_dir_s.clone(),
        };
        let dir = report_dir.join("items").join(r.folder());
        let files = report::write_item_reports(&dir, &info, r, &audit)?;
        log.record(
            "item_reports_written",
            Some(&r.path.display().to_string()),
            json!({"folder": format!("items/{}", r.folder()), "files": files}),
        )
        .map_err(io)?;
    }
    if !results.is_empty() {
        sink(&Event::ReportWritten {
            kind: "items".into(),
            path: report_dir.join("items").display().to_string(),
        });
    }
    let totals = RunTotals {
        items: results.len() as u64,
        bytes: results.iter().map(|r| r.size).sum(),
        errors,
    };
    // Trusted timestamp of the chain head: covers every evidence hash, finding and per-item report digest.
    let mut info = info;
    if let Some(url) = &cfg.tsa_url {
        match crate::trust::timestamp_head(&log_dir, log.entries(), log.head(), url) {
            Ok(ts) => {
                log.record("timestamp_obtained", Some(&ts.file), ts.to_json())
                    .map_err(io)?;
                let mut v = ts.to_json();
                v["status"] = json!("ok");
                info.timestamp = v;
            }
            Err(e) => {
                log.record("timestamp_pending", None, json!({"tsa": url, "reason": e, "covers_seq": log.entries(), "head": log.head()})).map_err(io)?;
                info.timestamp = json!({"status": "pending", "tsa": url, "reason": e});
            }
        }
        sink(&Event::Timestamp {
            status: info.timestamp["status"].as_str().unwrap_or_default().into(),
            tsa: url.clone(),
            gen_time: info.timestamp["gen_time"].as_str().map(String::from),
            reason: info.timestamp["reason"].as_str().map(String::from),
        });
    }
    let audit = AuditRef {
        head: log.head().to_string(),
        entries: log.entries(),
        log_dir: log_dir_s,
    };
    let files = report::write_statistics(&report_dir, &info, &results, &totals, &audit)?;
    log.record("statistics_report_written", None, json!({"files": files}))
        .map_err(io)?;
    let main_report = report_dir.join(format!("statistics.{}.html", cfg.langs[0]));
    sink(&Event::ReportWritten {
        kind: "statistics".into(),
        path: main_report.display().to_string(),
    });

    let mut sev: BTreeMap<Severity, u64> = BTreeMap::new();
    for f in results.iter().flat_map(|r| &r.findings) {
        *sev.entry(f.severity).or_default() += 1;
    }
    let summary = RunSummary {
        run_id,
        items: totals.items,
        bytes: totals.bytes,
        errors,
        elapsed_ms: started.elapsed().as_millis() as u64,
        high: sev.get(&Severity::High).copied().unwrap_or(0),
        medium: sev.get(&Severity::Medium).copied().unwrap_or(0),
        low: sev.get(&Severity::Low).copied().unwrap_or(0),
        info: sev.get(&Severity::Info).copied().unwrap_or(0),
        cancelled,
        report_dir: report_dir.clone(),
        log_dir: log_dir.clone(),
        audit_head: String::new(),
        timestamp: info.timestamp.clone(),
        case: info.case.clone(),
    };
    log.record("run_finished", None, json!({"items": summary.items, "bytes": summary.bytes, "errors": errors, "elapsed_ms": summary.elapsed_ms, "high": summary.high, "medium": summary.medium, "low": summary.low, "info": summary.info, "cancelled": cancelled})).map_err(io)?;
    sink(&Event::RunFinished {
        items: summary.items,
        bytes: summary.bytes,
        errors,
        elapsed_ms: summary.elapsed_ms,
        high: summary.high,
        medium: summary.medium,
        low: summary.low,
        info: summary.info,
        report_dir: report_dir.display().to_string(),
        log_dir: log_dir.display().to_string(),
        cancelled,
    });
    Ok(RunSummary {
        audit_head: log.head().to_string(),
        ..summary
    })
}

/// Analysis: compares the fresh hashes with the registry (by --evidence id, else by path, else by content).
/// Intake: notes a registered path whose content changed. Findings are added to the item.
fn case_check_item(
    l: &mut CaseLink,
    role: CaseRole,
    result: &mut ItemResult,
    log: &mut AuditLog,
    sink: &mut dyn FnMut(&Event),
) -> Result<(), String> {
    let io = |e: std::io::Error| format!("audit log write failed: {}", e);
    let norm = case::normalize_path(&result.path);
    let path_s = result.path.display().to_string();
    if role == CaseRole::Intake {
        if let Some(prev) = l.case.find_by_path(&norm)
            && matches!(
                case::compare(&prev.hashes, &result.hashes),
                Comparison::Mismatch { .. }
            )
        {
            result.findings.push(
                Finding::new("REGISTRY_PATH_CONTENT_CHANGED", Severity::Medium)
                    .with("previous_id", prev.evidence_id.clone()),
            );
        }
        return Ok(());
    }
    let expected = l
        .by_evidence
        .get(&norm)
        .and_then(|id| l.case.get(id))
        .map(|e| (e.clone(), "evidence_id"))
        .or_else(|| l.case.find_by_path(&norm).map(|e| (e.clone(), "path")))
        .or_else(|| {
            l.case
                .find_by_content(&result.hashes)
                .map(|e| (e.clone(), "content"))
        });
    let status = match expected {
        None => {
            log.record(
                "evidence_not_in_case_registry",
                Some(&path_s),
                json!({"index": result.index, "case_id": l.case.case_id}),
            )
            .map_err(io)?;
            result.findings.push(
                Finding::new("EVIDENCE_NOT_IN_CASE_REGISTRY", Severity::Medium)
                    .with("case_id", l.case.case_id.clone()),
            );
            l.tally.unregistered += 1;
            "not_in_registry"
        }
        Some((e, by)) => {
            result.evidence_id = Some(e.evidence_id.clone());
            result.intake_utc = Some(e.registered_utc.clone());
            match case::compare(&e.hashes, &result.hashes) {
                Comparison::Match(algos) => {
                    log.record("evidence_verified_against_case", Some(&path_s),
                        json!({"index": result.index, "evidence_id": e.evidence_id, "algorithm": algos.join("+"),
                               "match": true, "matched_by": by})).map_err(io)?;
                    l.tally.verified += 1;
                    "verified"
                }
                other => {
                    let (algorithm, expected, actual) = match other {
                        Comparison::Mismatch {
                            algorithm,
                            expected,
                            actual,
                        } => (algorithm, expected, actual),
                        _ => ("none".to_string(), "-".to_string(), "-".to_string()),
                    };
                    log.record("evidence_verified_against_case", Some(&path_s),
                        json!({"index": result.index, "evidence_id": e.evidence_id, "algorithm": algorithm,
                               "match": false, "matched_by": by, "expected": expected, "actual": actual})).map_err(io)?;
                    result.findings.push(
                        Finding::new("EVIDENCE_HASH_MISMATCH_WITH_CASE", Severity::High)
                            .with("evidence_id", e.evidence_id.clone())
                            .with("algorithm", algorithm)
                            .with("expected", expected)
                            .with("actual", actual),
                    );
                    l.tally.mismatched += 1;
                    "mismatch"
                }
            }
        }
    };
    result.case_status = Some(status.into());
    sink(&Event::EvidenceLinked {
        index: result.index,
        path: path_s,
        evidence_id: result.evidence_id.clone(),
        status: status.into(),
    });
    Ok(())
}

/// Intake: registers every hashed item (same path + same content keeps its id) and audits each id.
fn register_items(
    l: &mut CaseLink,
    results: &mut [ItemResult],
    hashed_seq: &BTreeMap<u64, u64>,
    log: &mut AuditLog,
    sink: &mut dyn FnMut(&Event),
) -> Result<(), String> {
    let io = |e: std::io::Error| format!("audit log write failed: {}", e);
    let idx: Vec<usize> = (0..results.len())
        .filter(|&i| !results[i].hashes.is_empty())
        .collect();
    if idx.is_empty() {
        return Ok(());
    }
    let regs: Vec<Registration> = idx
        .iter()
        .map(|&i| Registration {
            path: case::normalize_path(&results[i].path),
            size: results[i].size,
            hashes: results[i].hashes.clone(),
            audit_seq: hashed_seq.get(&results[i].index).copied().unwrap_or(0),
        })
        .collect();
    let (ids, case_seq) = match l.case.register(&l.writer, &regs) {
        Ok(x) => x,
        Err(e) => {
            log.record(
                "error",
                None,
                json!({"stage": "case_registry", "message": e.message}),
            )
            .map_err(io)?;
            log.record("run_failed", None, json!({"reason": e.message}))
                .map_err(io)?;
            return Err(e.message);
        }
    };
    let digest = case::registry_digest(&l.case.dir);
    for (&i, a) in idx.iter().zip(ids) {
        let (id, added, utc) = (a.evidence_id, a.added, a.registered_utc);
        let r = &mut results[i];
        let status = if added {
            "registered"
        } else {
            "already_registered"
        };
        log.record(
            "evidence_registered",
            Some(&r.path.display().to_string()),
            json!({"index": r.index, "evidence_id": id, "new": added, "case_log_seq": case_seq,
                   "registry_sha256": digest}),
        )
        .map_err(io)?;
        l.tally.registered += 1;
        if added {
            l.tally.added += 1;
        }
        r.evidence_id = Some(id);
        r.case_status = Some(status.into());
        r.intake_utc = Some(utc);
        sink(&Event::EvidenceLinked {
            index: r.index,
            path: r.path.display().to_string(),
            evidence_id: r.evidence_id.clone(),
            status: status.into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(input: PathBuf, out: PathBuf) -> RunConfig {
        RunConfig {
            inputs: vec![input],
            input_list: None,
            recursive: true,
            algorithms: vec![HashAlgo::Sha256, HashAlgo::Md5],
            out_dir: out,
            langs: vec!["es".into(), "en".into()],
            actor: "tester".into(),
            case_id: Some("CASE-1".into()),
            frontend: "test".into(),
            preamble: vec![("ui_setting_changed".into(), json!({"lang": "es"}))],
            command_line: vec![],
            tool_name: "rv-timeline".into(),
            tool_version: "0.0.0".into(),
            ..Default::default()
        }
    }

    #[test]
    fn full_run_writes_logs_and_reports() {
        let ev = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(ev.path().join("a.txt"), "same").unwrap();
        std::fs::write(ev.path().join("b.txt"), "same").unwrap();
        std::fs::write(ev.path().join("photo.jpg"), b"%PDF-1.7\n...").unwrap();
        let mut events = Vec::new();
        let s = run(
            &cfg(ev.path().into(), out.path().into()),
            &mut |e| events.push(e.clone()),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(s.items, 3);
        assert_eq!(s.medium, 1); // extension mismatch
        assert_eq!(s.info, 2); // duplicate pair
        assert!(crate::audit::verify(&s.log_dir.join("audit.jsonl")).is_ok());
        for f in ["audit.log", "hashes.csv", "environment.json"] {
            assert!(s.log_dir.join(f).exists(), "{}", f);
        }
        for f in ["statistics.json", "statistics.es.html", "statistics.en.pdf"] {
            assert!(s.report_dir.join(f).exists(), "{}", f);
        }
        let item = s.report_dir.join("items/00003-photo.jpg");
        for f in [
            "custody.json",
            "custody.es.pdf",
            "custody.en.html",
            "technical.json",
            "summary.json",
            "technical.es.html",
            "summary.en.pdf",
            "technical.en.pdf",
            "summary.es.html",
        ] {
            assert!(item.join(f).exists(), "{}", f);
        }
        let es = std::fs::read_to_string(s.report_dir.join("statistics.es.html")).unwrap();
        let en = std::fs::read_to_string(s.report_dir.join("statistics.en.html")).unwrap();
        assert_ne!(es, en);
        assert!(matches!(events.first(), Some(Event::RunStarted { .. })));
        assert!(matches!(events.last(), Some(Event::RunFinished { .. })));
        let csv = std::fs::read_to_string(s.log_dir.join("hashes.csv")).unwrap();
        assert!(csv.starts_with("index,path,size,sha256,md5,"));
    }

    #[test]
    fn cancel_before_start_writes_partial_reports() {
        let ev = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(ev.path().join("a.txt"), "x").unwrap();
        let s = run(
            &cfg(ev.path().into(), out.path().into()),
            &mut |_| {},
            &AtomicBool::new(true),
        )
        .unwrap();
        assert!(s.cancelled);
        assert_eq!(s.items, 0);
        let log = std::fs::read_to_string(s.log_dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("\"run_cancelled\""));
    }

    fn sample_copy(dir: &Path) -> PathBuf {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/evidence");
        let ev = dir.join("evidence");
        std::fs::create_dir_all(&ev).unwrap();
        for e in std::fs::read_dir(src).unwrap() {
            let p = e.unwrap().path();
            std::fs::copy(&p, ev.join(p.file_name().unwrap())).unwrap();
        }
        ev
    }

    fn case_cfg(case: &Path, role: CaseRole, inputs: Vec<PathBuf>) -> RunConfig {
        RunConfig {
            inputs,
            algorithms: vec![HashAlgo::Sha256, HashAlgo::Md5],
            langs: vec!["en".into()],
            actor: "tester".into(),
            case_id: Some("CASE-T".into()),
            frontend: "test".into(),
            tool_version: "0.0.0".into(),
            case_dir: Some(case.to_path_buf()),
            case_role: role,
            ..Default::default()
        }
    }

    fn case_log(case: &Path) -> Vec<Value> {
        std::fs::read_to_string(case.join(case::CASE_LOG))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn run_dirs(case: &Path) -> usize {
        std::fs::read_dir(case.join("runs/rv-timeline"))
            .map(|d| d.count())
            .unwrap_or(0)
    }

    #[test]
    fn case_intake_then_analysis_detects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let ev = sample_copy(tmp.path());
        let case = tmp.path().join("case");
        let go = |c: &RunConfig| run(c, &mut |_| {}, &AtomicBool::new(false));

        // 1. Intake registers the three sample items.
        let s = go(&case_cfg(&case, CaseRole::Intake, vec![ev.clone()])).unwrap();
        let t = s.case.as_ref().unwrap().tally.clone();
        assert_eq!((t.registered, t.added), (3, 3));
        assert!(s.log_dir.starts_with(case.join("runs/rv-timeline")));
        assert!(s.log_dir.ends_with("logs") && s.report_dir.ends_with("reports"));
        let reg = Case::open(&case).unwrap();
        let ids: Vec<&str> = reg.items.iter().map(|i| i.evidence_id.as_str()).collect();
        assert_eq!(ids, ["E0001", "E0002", "E0003"]);
        let audit = std::fs::read_to_string(s.log_dir.join("audit.jsonl")).unwrap();
        let actions: Vec<String> = audit
            .lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["action"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(&actions[..2], ["run_started", "case_linked"]);
        assert_eq!(
            actions
                .iter()
                .filter(|a| *a == "evidence_registered")
                .count(),
            3
        );
        let tech: Value = serde_json::from_str(
            &std::fs::read_to_string(
                s.report_dir
                    .join("items/00001-acta-copia.txt/technical.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(tech["item"]["evidence_id"], "E0001");
        let custody: Value = serde_json::from_str(
            &std::fs::read_to_string(s.report_dir.join("items/00001-acta-copia.txt/custody.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (custody["evidence_id"].as_str(), custody["case_id"].as_str()),
            (Some("E0001"), Some("CASE-T"))
        );
        assert!(custody["intake_utc"].is_string());
        let v = case::verify_case(&case);
        assert!(v.problems.is_empty(), "{:?}", v.problems);
        assert_eq!((v.runs, v.registry_items), (1, 3));

        // 2. Re-running intake keeps the ids.
        let s = go(&case_cfg(&case, CaseRole::Intake, vec![ev.clone()])).unwrap();
        let t = s.case.unwrap().tally;
        assert_eq!((t.registered, t.added), (3, 0));

        // 3. Analysis role, all registered items by default, disjoint algorithm → sha256 added.
        let mut a = case_cfg(&case, CaseRole::Analysis, vec![]);
        a.case_id = None;
        a.algorithms = vec![HashAlgo::Blake3];
        let mut events = vec![];
        let s = run(&a, &mut |e| events.push(e.clone()), &AtomicBool::new(false)).unwrap();
        let t = s.case.clone().unwrap().tally;
        assert_eq!((t.verified, t.mismatched, t.unregistered), (3, 0, 0));
        assert_eq!(s.high, 0);
        let audit = std::fs::read_to_string(s.log_dir.join("audit.jsonl")).unwrap();
        assert!(
            audit.contains("\"case_algorithm_added\"")
                && audit.contains("\"evidence_verified_against_case\"")
        );
        assert_eq!(
            events
                .iter()
                .filter(
                    |e| matches!(e, Event::EvidenceLinked { status, .. } if status == "verified")
                )
                .count(),
            3
        );

        // 4. Tampered evidence copy → high mismatch finding, analysis still runs; unregistered file → medium.
        std::fs::write(ev.join("acta.txt"), "tampered").unwrap();
        std::fs::write(ev.join("extra.txt"), "not registered").unwrap();
        let mut a = case_cfg(&case, CaseRole::Analysis, vec![ev.clone()]);
        a.case_id = None;
        let s = go(&a).unwrap();
        let t = s.case.clone().unwrap().tally;
        assert_eq!((t.verified, t.mismatched, t.unregistered), (2, 1, 1));
        assert!(s.high >= 1);
        let stats = std::fs::read_to_string(s.report_dir.join("statistics.json")).unwrap();
        assert!(
            stats.contains("EVIDENCE_HASH_MISMATCH_WITH_CASE")
                && stats.contains("EVIDENCE_NOT_IN_CASE_REGISTRY")
        );
        let html = std::fs::read_to_string(s.report_dir.join("statistics.en.html")).unwrap();
        assert!(html.contains("E0003") && html.contains("Case folder"));
        let fin = case_log(&case).into_iter().last().unwrap();
        assert_eq!(fin["action"], "run_finished");
        assert_eq!(fin["details"]["verification"]["mismatched"], 1);
        assert_eq!(
            fin["details"]["audit_head"].as_str(),
            Some(s.audit_head.as_str())
        );
        // Intake of the changed file: new id + note.
        let s = go(&case_cfg(
            &case,
            CaseRole::Intake,
            vec![ev.join("acta.txt")],
        ))
        .unwrap();
        assert_eq!(s.medium, 1);
        assert_eq!(Case::open(&case).unwrap().items.len(), 4);
        let v = case::verify_case(&case);
        assert!(v.problems.is_empty(), "{:?}", v.problems);

        // 5. Cancelled and failed runs still close their entry in the case log.
        let mut a = case_cfg(&case, CaseRole::Analysis, vec![]);
        a.case_id = None;
        let s = run(&a, &mut |_| {}, &AtomicBool::new(true)).unwrap();
        assert!(s.cancelled);
        assert_eq!(
            case_log(&case).last().unwrap()["details"]["status"],
            "cancelled"
        );
        a.inputs = vec![tmp.path().join("missing")];
        assert!(go(&a).is_err());
        let last = case_log(&case).pop().unwrap();
        assert_eq!(
            (last["action"].as_str(), last["details"]["status"].as_str()),
            (Some("run_finished"), Some("failed"))
        );
        assert!(case::verify_case(&case).problems.is_empty());

        // 6. A tampered case log is detected and never extended.
        let lp = case.join(case::CASE_LOG);
        let original = std::fs::read_to_string(&lp).unwrap();
        std::fs::write(&lp, original.replacen("\"tester\"", "\"mallory\"", 1)).unwrap();
        assert!(!case::verify_case(&case).problems.is_empty());
        let before = run_dirs(&case);
        let mut a = case_cfg(&case, CaseRole::Analysis, vec![]);
        a.case_id = None;
        let e = go(&a).unwrap_err();
        assert!(e.contains("never extended"), "{}", e);
        assert_eq!(run_dirs(&case), before, "no run folder in a broken case");
        assert_eq!(
            std::fs::read_to_string(&lp).unwrap(),
            original.replacen("\"tester\"", "\"mallory\"", 1)
        );
        std::fs::write(&lp, &original).unwrap();

        // 7. An edited registry is detected through the digest recorded in the case log.
        let rp = case.join(case::REGISTRY_JSON);
        let reg = std::fs::read_to_string(&rp).unwrap();
        std::fs::write(&rp, reg.replacen("E0002", "E0009", 1)).unwrap();
        let v = case::verify_case(&case);
        assert!(
            v.problems.iter().any(|p| p.contains("registry")),
            "{:?}",
            v.problems
        );
        assert!(go(&a).is_err());
        std::fs::write(&rp, reg).unwrap();

        // 8. An edited run audit log is detected by verify-case.
        let first_run = case
            .join("runs/rv-timeline")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let ap = first_run.join("logs/audit.jsonl");
        let audit = std::fs::read_to_string(&ap).unwrap();
        std::fs::write(&ap, audit.replacen("\"tester\"", "\"mallory\"", 1)).unwrap();
        assert!(!case::verify_case(&case).problems.is_empty());
    }

    #[test]
    fn evidence_ids_select_items_and_unknown_ids_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let ev = sample_copy(tmp.path());
        let case = tmp.path().join("case");
        run(
            &case_cfg(&case, CaseRole::Intake, vec![ev]),
            &mut |_| {},
            &AtomicBool::new(false),
        )
        .unwrap();
        let mut a = case_cfg(&case, CaseRole::Analysis, vec![]);
        a.evidence_ids = vec!["e2".into()];
        let s = run(&a, &mut |_| {}, &AtomicBool::new(false)).unwrap();
        assert_eq!(s.items, 1);
        assert_eq!(s.case.unwrap().tally.verified, 1);
        a.evidence_ids = vec!["E0042".into()];
        let e = run(&a, &mut |_| {}, &AtomicBool::new(false)).unwrap_err();
        assert!(e.contains("E0042"), "{}", e);
        a.case_id = Some("OTHER".into());
        a.evidence_ids = vec![];
        assert!(run(&a, &mut |_| {}, &AtomicBool::new(false)).is_err());
    }

    #[test]
    fn three_algorithms_are_refused() {
        let mut c = cfg(PathBuf::from("."), PathBuf::from("."));
        c.algorithms = vec![HashAlgo::Md5, HashAlgo::Sha1, HashAlgo::Sha256];
        assert!(run(&c, &mut |_| {}, &AtomicBool::new(false)).is_err());
    }
}
