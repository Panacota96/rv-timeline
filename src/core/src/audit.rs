//! Append-only, hash-chained audit log (`audit.jsonl`) plus a human-readable twin (`audit.log`).
//!
//! Chain rule (shared with every Rakvor tool, any language):
//!   entry_hash = SHA-256( canonical JSON of the entry without `entry_hash` )
//!   canonical  = keys sorted, no whitespace, UTF-8 (Python: json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False))
//!   the first entry's prev_entry_hash is 64 zeros.
//! Editing, deleting or re-ordering any line breaks verification from that line on.

use crate::hash::{HashAlgo, hash_bytes};
use crate::time::utc_now;
use serde_json::{Map, Value, json};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One chained entry (shared by audit.jsonl and the case log `case-log.jsonl`), with its `entry_hash` set.
pub fn build_entry(
    seq: u64,
    run_id: &str,
    actor: &str,
    action: &str,
    item: Option<&str>,
    details: Value,
    prev: &str,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("seq".into(), json!(seq));
    m.insert("ts_utc".into(), json!(utc_now()));
    m.insert("run_id".into(), json!(run_id));
    m.insert("actor".into(), json!(actor));
    m.insert("action".into(), json!(action));
    if let Some(i) = item {
        m.insert("item".into(), json!(i));
    }
    m.insert("details".into(), details);
    m.insert("prev_entry_hash".into(), json!(prev));
    let h = entry_hash(&m);
    m.insert("entry_hash".into(), json!(h));
    m
}

pub struct AuditLog {
    jsonl: File,
    text: File,
    seq: u64,
    head: String,
    run_id: String,
    actor: String,
    pub dir: PathBuf,
}

/// SHA-256 of the canonical form of `entry` (with `entry_hash` removed).
pub fn entry_hash(entry: &Map<String, Value>) -> String {
    let mut m = entry.clone();
    m.remove("entry_hash");
    // serde_json's Map is a BTreeMap (no `preserve_order` feature): keys come out sorted at every level.
    let canonical = serde_json::to_string(&Value::Object(m)).expect("serializable");
    hash_bytes(canonical.as_bytes(), HashAlgo::Sha256)
}

impl AuditLog {
    pub fn create(dir: &Path, run_id: &str, actor: &str) -> io::Result<AuditLog> {
        std::fs::create_dir_all(dir)?;
        let open = |name: &str| {
            OpenOptions::new()
                .create_new(true)
                .append(true)
                .open(dir.join(name))
        };
        Ok(AuditLog {
            jsonl: open("audit.jsonl")?,
            text: open("audit.log")?,
            seq: 0,
            head: GENESIS.into(),
            run_id: run_id.into(),
            actor: actor.into(),
            dir: dir.to_path_buf(),
        })
    }

    /// Re-opens an intact log to append later actions (e.g. a delayed timestamp).
    pub fn resume(dir: &Path, actor: &str) -> Result<AuditLog, String> {
        let path = dir.join("audit.jsonl");
        let n = verify(&path)
            .map_err(|p| format!("refusing to append to a broken audit log: {}", p[0]))?;
        let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let last: Value =
            serde_json::from_str(text.lines().last().unwrap_or("{}")).map_err(|e| e.to_string())?;
        let open = |name: &str| {
            OpenOptions::new()
                .append(true)
                .open(dir.join(name))
                .map_err(|e| e.to_string())
        };
        Ok(AuditLog {
            jsonl: open("audit.jsonl")?,
            text: open("audit.log")?,
            seq: n,
            head: last["entry_hash"].as_str().unwrap_or_default().to_string(),
            run_id: last["run_id"].as_str().unwrap_or_default().to_string(),
            actor: actor.to_string(),
            dir: dir.to_path_buf(),
        })
    }

    pub fn head(&self) -> &str {
        &self.head
    }

    pub fn entries(&self) -> u64 {
        self.seq
    }

    /// Appends one action. Returns its sequence number.
    pub fn record(&mut self, action: &str, item: Option<&str>, details: Value) -> io::Result<u64> {
        self.seq += 1;
        let m = build_entry(
            self.seq,
            &self.run_id,
            &self.actor,
            action,
            item,
            details,
            &self.head,
        );
        let ts = m["ts_utc"].as_str().unwrap_or_default().to_string();
        let h = m["entry_hash"].as_str().unwrap_or_default().to_string();
        writeln!(
            self.jsonl,
            "{}",
            serde_json::to_string(&Value::Object(m.clone())).expect("serializable")
        )?;
        let detail_text = summarize(m.get("details").unwrap());
        writeln!(
            self.text,
            "{}  #{:05}  {:<20} {}{}",
            ts,
            self.seq,
            action,
            item.map(|i| format!("{}  ", i)).unwrap_or_default(),
            detail_text
        )?;
        self.jsonl.flush()?;
        self.text.flush()?;
        self.head = h;
        Ok(self.seq)
    }
}

fn summarize(v: &Value) -> String {
    match v {
        Value::Object(o) => o
            .iter()
            .filter(|(_, v)| !v.is_object())
            .map(|(k, v)| {
                let text = match v {
                    Value::String(s) => s.clone(),
                    Value::Array(a) => a
                        .iter()
                        .map(|x| {
                            x.as_str()
                                .map(String::from)
                                .unwrap_or_else(|| x.to_string())
                        })
                        .collect::<Vec<_>>()
                        .join("+"),
                    other => other.to_string(),
                };
                format!("{}={}", k, text)
            })
            .collect::<Vec<_>>()
            .join(" "),
        other => other.to_string(),
    }
}

/// seq -> entry_hash, to check what a timestamp covers.
pub fn heads(path: &Path) -> std::collections::BTreeMap<u64, String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|e| {
            (
                e["seq"].as_u64().unwrap_or(0),
                e["entry_hash"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// Verifies a log. Ok(entry count) when intact, Err(list of problems) otherwise.
pub fn verify(path: &Path) -> Result<u64, Vec<String>> {
    let f = File::open(path).map_err(|e| vec![format!("cannot open {}: {}", path.display(), e)])?;
    let mut problems = Vec::new();
    let mut prev = GENESIS.to_string();
    let mut expected_seq = 1u64;
    for (lineno, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| vec![format!("read error: {}", e)])?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                problems.push(format!("line {}: not valid JSON ({})", lineno + 1, e));
                continue;
            }
        };
        let Some(m) = v.as_object() else {
            problems.push(format!("line {}: not a JSON object", lineno + 1));
            continue;
        };
        let seq = m.get("seq").and_then(|s| s.as_u64()).unwrap_or(0);
        if seq != expected_seq {
            problems.push(format!(
                "line {}: sequence {} where {} was expected (deleted or re-ordered entry)",
                lineno + 1,
                seq,
                expected_seq
            ));
        }
        if m.get("prev_entry_hash").and_then(|s| s.as_str()) != Some(prev.as_str()) {
            problems.push(format!(
                "line {}: prev_entry_hash does not link to the previous entry",
                lineno + 1
            ));
        }
        let stored = m
            .get("entry_hash")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        if entry_hash(m) != stored {
            problems.push(format!(
                "line {}: entry_hash does not match its content (edited entry)",
                lineno + 1
            ));
        }
        prev = stored;
        expected_seq = seq + 1;
    }
    if problems.is_empty() {
        Ok(expected_seq - 1)
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(dir: &Path) -> PathBuf {
        let mut log = AuditLog::create(dir, "RUN-1", "tester").unwrap();
        log.record(
            "run_started",
            None,
            json!({"algorithms": ["sha256"], "note": "café ñ"}),
        )
        .unwrap();
        log.record("item_hashed", Some("a.txt"), json!({"sha256": "00"}))
            .unwrap();
        log.record("run_finished", None, json!({"items": 1}))
            .unwrap();
        dir.join("audit.jsonl")
    }

    #[test]
    fn intact_log_verifies() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(verify(&sample(d.path())), Ok(3));
    }

    #[test]
    fn edit_delete_and_reorder_are_detected() {
        let d = tempfile::tempdir().unwrap();
        let p = sample(d.path());
        let original = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = original.lines().collect();

        std::fs::write(&p, original.replace("tester", "mallory")).unwrap();
        assert!(verify(&p).is_err(), "edit");

        std::fs::write(&p, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(verify(&p).is_err(), "delete");

        std::fs::write(&p, format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2])).unwrap();
        assert!(verify(&p).is_err(), "reorder");
    }
}
