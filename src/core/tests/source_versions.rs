//! Coverage of the source tools' latest releases (run by the `source-versions` workflow, which fetches them).
//!
//! `RV_SOURCE_RELEASES` holds one `tool version` pair per line (`rv-hashinv 0.5.1`, a leading `v` is allowed).
//! Each pair must be read by a built-in reader, and every built-in reader must be in the list, so a source tool
//! missing from the fetch is caught too. Ignored by default: it needs the network data.

use rv_timeline_core::readers;
use std::collections::BTreeSet;

#[test]
#[ignore = "needs RV_SOURCE_RELEASES (the source-versions workflow sets it)"]
fn latest_source_releases_are_read() {
    let list = std::env::var("RV_SOURCE_RELEASES").expect("RV_SOURCE_RELEASES is not set");
    let all = readers::all();
    let mut seen = BTreeSet::new();
    let mut missing = Vec::new();
    for line in list.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (tool, version) = line
            .split_once(char::is_whitespace)
            .unwrap_or_else(|| panic!("not `tool version`: {line:?}"));
        let version = version.trim().trim_start_matches('v');
        seen.insert(tool.to_string());
        match all.iter().find(|r| r.tool() == tool) {
            Some(r) if r.supports(version) => println!("ok       {tool} {version}"),
            Some(_) => missing.push(format!("{tool} {version} (unsupported_version)")),
            None => missing.push(format!("{tool} {version} (no reader)")),
        }
    }
    let unlisted: Vec<_> = all
        .iter()
        .map(|r| r.tool())
        .filter(|t| !seen.contains(*t))
        .collect();
    assert!(
        unlisted.is_empty(),
        "readers without a release in RV_SOURCE_RELEASES: {unlisted:?}"
    );
    assert!(
        missing.is_empty(),
        "latest source releases this version would exclude: {missing:?} (supported: {:?})",
        readers::supported_versions()
    );
}
