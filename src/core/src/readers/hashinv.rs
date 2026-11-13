//! rv-hashinv 0.4.x (intake). Events: `intake.registered` per newly registered item (the registry's
//! `registered_utc`, as `technical.json` → `/case/intake_utc` reports it; the audit entry `evidence_registered`
//! when the item has no technical report), `fs.modified` (the file-system modification time the run recorded),
//! `run.started`, `run.finished`, `run.timestamped`.
//!
//! ```text
//! logs/audit.jsonl ── item_started.modified_utc ──► fs.modified
//!                  └─ evidence_registered (new) ─┐
//! reports/items/NNNNN-name/technical.json ── /case/intake_utc (status registered) ──► intake.registered
//! ```
//!
//! Not mapped: creation/access times (rv-hashinv records only the modification time); items already
//! registered by an earlier run (their intake event comes from that run).

use super::{Emitter, Found, ReadOutcome, RunData, at, s, timefmt};
use crate::model::{ReadError, RunRef};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

pub fn read(case_dir: &Path, run: &RunRef) -> Result<ReadOutcome, ReadError> {
    let data = RunData::load(case_dir, run)?;
    let mut em = Emitter::new(&data);
    em.audit_events();
    let mut done = BTreeSet::new();
    for rel in data.outputs_ending("/technical.json") {
        let Some(item) = data.item_of_folder(&rel) else {
            continue;
        };
        let Some((v, sha)) = data.json(&rel)? else {
            continue;
        };
        done.insert(item.index);
        if s(&v["case"]["status"]) != "registered" {
            continue;
        }
        let Some(t) = v["case"]["intake_utc"].as_str() else {
            continue;
        };
        let mut it = item.item_ref("");
        if it.evidence_id.is_empty() {
            it.evidence_id = s(&v["item"]["evidence_id"]).to_string();
        }
        em.push(
            Found {
                item: it,
                kind: "intake.registered",
                original: t.to_string(),
                file: &rel,
                file_sha256: &sha,
                pointer: "/case/intake_utc".into(),
                details: vec![("tool", run.tool.clone())],
            },
            timefmt::rfc3339(t),
        );
    }
    for (line, e) in &data.audit {
        let d = &at(e, "details");
        if e.get("action").and_then(Value::as_str) != Some("evidence_registered")
            || d["new"] != Value::Bool(true)
        {
            continue;
        }
        let Some(item) = d["index"].as_u64().and_then(|i| data.items.get(&i)) else {
            continue;
        };
        if done.contains(&item.index) {
            continue;
        }
        let t = s(at(e, "ts_utc"));
        em.push(
            Found {
                item: item.item_ref(""),
                kind: "intake.registered",
                original: t.to_string(),
                file: "logs/audit.jsonl",
                file_sha256: &data.audit_sha256,
                pointer: format!("line:{line}/ts_utc"),
                details: vec![("tool", run.tool.clone())],
            },
            timefmt::rfc3339(t),
        );
    }
    Ok(em.finish())
}
