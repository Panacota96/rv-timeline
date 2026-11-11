//! The event stream: the only way the core talks to a front-end.
//! The CLI renders events as a progress bar or JSON Lines; the GUI renders them as widgets.
//! The core never prints.

use crate::hash::HashAlgo;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    RunStarted {
        run_id: String,
        tool: String,
        version: String,
        frontend: String,
        algorithms: Vec<HashAlgo>,
        langs: Vec<String>,
        total_items: u64,
        total_bytes: u64,
    },
    ItemStarted {
        index: u64,
        path: String,
        size: u64,
    },
    ItemHashed {
        index: u64,
        path: String,
        hashes: BTreeMap<String, String>,
    },
    ItemFinished {
        index: u64,
        path: String,
        status: String,
        findings: Vec<String>,
    },
    /// Case folder only: the item's evidence id and how it relates to the case registry
    /// (registered | already_registered | verified | mismatch | not_in_registry).
    EvidenceLinked {
        index: u64,
        path: String,
        evidence_id: Option<String>,
        status: String,
    },
    Progress {
        done: u64,
        total: u64,
        bytes_done: u64,
        bytes_total: u64,
        elapsed_ms: u64,
        eta_ms: Option<u64>,
    },
    ReportWritten {
        kind: String,
        path: String,
    },
    Error {
        path: Option<String>,
        message: String,
    },
    Timestamp {
        status: String,
        tsa: String,
        gen_time: Option<String>,
        reason: Option<String>,
    },
    Cancelled {
        done: u64,
        elapsed_ms: u64,
    },
    RunFinished {
        items: u64,
        bytes: u64,
        errors: u64,
        elapsed_ms: u64,
        high: u64,
        medium: u64,
        low: u64,
        info: u64,
        report_dir: String,
        log_dir: String,
        cancelled: bool,
    },
}

/// Estimated time remaining from bytes processed so far.
pub fn eta_ms(elapsed_ms: u64, bytes_done: u64, bytes_total: u64) -> Option<u64> {
    if bytes_done == 0 || elapsed_ms < 500 || bytes_total < bytes_done {
        return None;
    }
    Some(((bytes_total - bytes_done) as u128 * elapsed_ms as u128 / bytes_done as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eta_and_json_shape() {
        assert_eq!(eta_ms(1000, 50, 100), Some(1000));
        assert_eq!(eta_ms(100, 50, 100), None);
        let e = Event::Progress {
            done: 1,
            total: 2,
            bytes_done: 3,
            bytes_total: 4,
            elapsed_ms: 5,
            eta_ms: None,
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.starts_with("{\"event\":\"progress\""));
    }
}
