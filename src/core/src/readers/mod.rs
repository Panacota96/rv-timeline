//! Source readers, one per Rakvor tool (round 2, agent A). Each turns a verified run's audited outputs into
//! [`TimeEvent`]s. Discovery and verification of runs live here too: [`discover_runs`] lists the case's runs and
//! [`verify_run`] checks the audit chain and marks excluded runs before any reader sees them.

use crate::model::{ReadError, RunRef, SourceReader, TimeEvent};
use std::path::Path;

/// All readers built into this version. Agent A fills this list.
pub fn all() -> Vec<Box<dyn SourceReader>> {
    Vec::new()
}

/// Lists every run recorded in the case folder (case.json + runs/<tool>/<run>/), status still unchecked.
pub fn discover_runs(_case_dir: &Path) -> Result<Vec<RunRef>, ReadError> {
    Ok(Vec::new())
}

/// Verifies one run (finished, audit chain intact, outputs' digests as logged); excluded runs get their reason.
pub fn verify_run(_case_dir: &Path, run: RunRef) -> RunRef {
    run
}

/// Convenience used by the engine: the reader for `tool`, if any.
pub fn reader_for<'a>(
    readers: &'a [Box<dyn SourceReader>],
    tool: &str,
) -> Option<&'a dyn SourceReader> {
    readers
        .iter()
        .find(|r| r.tool() == tool)
        .map(|r| r.as_ref())
}

/// Reads one verified run with the matching reader.
pub fn read_run(
    readers: &[Box<dyn SourceReader>],
    case_dir: &Path,
    run: &RunRef,
) -> Result<Vec<TimeEvent>, ReadError> {
    match reader_for(readers, &run.tool) {
        Some(r) if r.supports(&run.tool_version) => r.read(case_dir, run),
        Some(_) => Err(ReadError {
            reason: "unsupported_version".into(),
            detail: run.tool_version.clone(),
        }),
        None => Err(ReadError {
            reason: "unsupported_tool".into(),
            detail: run.tool.clone(),
        }),
    }
}
