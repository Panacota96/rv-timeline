//! Reader tests on the synthetic case folder `tests/fixtures/readers/case` (built by `make_case.py` next to it):
//! discovery, verification (including tampered copies) and the events each reader produces.

use rv_timeline_core::model::{Precision, RunRef, RunStatus, TimeEvent, ZoneInfo};
use rv_timeline_core::readers::{self, discover_runs, read_run, read_run_outcome, verify_run};
use std::path::{Path, PathBuf};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/readers/case")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let p = e.path();
        let t = to.join(e.file_name());
        if p.is_dir() {
            copy_dir(&p, &t);
        } else {
            std::fs::copy(&p, &t).unwrap();
        }
    }
}

fn tmp_case() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let c = d.path().join("case");
    copy_dir(&fixture(), &c);
    (d, c)
}

fn run(case: &Path, run_dir: &str) -> RunRef {
    discover_runs(case)
        .unwrap()
        .into_iter()
        .find(|r| r.run_dir == run_dir)
        .unwrap_or_else(|| panic!("{run_dir} not discovered"))
}

fn utc(s: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(s).unwrap().timestamp()
}

fn events(run_dir: &str) -> Vec<TimeEvent> {
    let case = fixture();
    let r = verify_run(&case, run(&case, run_dir));
    assert_eq!(
        r.status,
        RunStatus::Verified,
        "{run_dir}: {:?}",
        r.exclusion
    );
    let ev = read_run(&readers::all(), &case, &r).unwrap();
    // Stable: the same ids on every read, all distinct, every citation complete.
    let again = read_run(&readers::all(), &case, &r).unwrap();
    assert_eq!(ev, again);
    let mut ids: Vec<&str> = ev.iter().map(|e| e.id.as_str()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), ev.len(), "duplicate ids in {run_dir}");
    for e in &ev {
        assert_eq!(e.source.run_dir, run_dir);
        assert_eq!(e.source.file_sha256.len(), 64, "{}", e.id);
        assert!(
            !e.source.pointer.is_empty() && !e.original.is_empty(),
            "{}",
            e.id
        );
        assert!(
            case.join(run_dir).join(&e.source.file).is_file(),
            "{}",
            e.id
        );
        if e.zone == ZoneInfo::Unknown {
            assert_eq!(e.offset_min, None, "{}", e.id);
        }
    }
    ev
}

fn find<'a>(ev: &'a [TimeEvent], id: &str) -> &'a TimeEvent {
    ev.iter().find(|e| e.id == id).unwrap_or_else(|| {
        panic!(
            "{id} missing; have {:#?}",
            ev.iter().map(|e| &e.id).collect::<Vec<_>>()
        )
    })
}

/// (id, kind, utc, zone)
fn expect(ev: &[TimeEvent], rows: &[(&str, &str, &str, ZoneInfo)]) {
    for (id, kind, t, zone) in rows {
        let e = find(ev, id);
        assert_eq!(
            (e.kind.as_str(), e.utc_s, e.zone),
            (*kind, utc(t), *zone),
            "{id}"
        );
    }
}

#[test]
fn discovery_lists_announced_runs_in_log_order() {
    let runs = discover_runs(&fixture()).unwrap();
    let dirs: Vec<&str> = runs.iter().map(|r| r.run_dir.as_str()).collect();
    assert_eq!(
        dirs,
        [
            "runs/rv-hashinv/20261110T090000Z-aaaaaa",
            "runs/rv-imgauth/20261111T100000Z-bbbbbb",
            "runs/rv-pdfauth/20261111T110000Z-cccccc",
            "runs/rv-mailauth/20261111T120000Z-dddddd",
            "runs/rv-rsmf/20261111T130000Z-eeeeee",
            "runs/rv-certcheck/20261111T140000Z-ffffff",
            "runs/rv-imgauth/20261112T090000Z-111111",
            "runs/rv-triage/20261112T100000Z-222222",
            "runs/rv-hashinv/20261112T110000Z-333333",
        ]
    );
    assert_eq!(runs[1].tool, "rv-imgauth");
    assert_eq!(runs[1].tool_version, "0.3.1");
    assert_eq!(runs[1].run_id, "20261111T100000Z-bbbbbb");
}

#[test]
fn discovery_needs_a_case_folder() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(discover_runs(d.path()).unwrap_err().reason, "unreadable");
    std::fs::write(d.path().join("case.json"), r#"{"schema":"rakvor.case/9"}"#).unwrap();
    assert!(
        discover_runs(d.path())
            .unwrap_err()
            .detail
            .contains("schema")
    );
}

#[test]
fn verification_reasons() {
    let case = fixture();
    let reasons: Vec<(String, Option<String>)> = discover_runs(&case)
        .unwrap()
        .into_iter()
        .map(|r| verify_run(&case, r))
        .map(|r| (r.run_dir, r.exclusion.map(|e| e.reason)))
        .collect();
    let want = |d: &str| reasons.iter().find(|(x, _)| x == d).unwrap().1.clone();
    for ok in ["aaaaaa", "bbbbbb", "cccccc", "dddddd", "eeeeee", "ffffff"] {
        let d = reasons.iter().find(|(x, _)| x.ends_with(ok)).unwrap();
        assert_eq!(d.1, None, "{}", d.0);
    }
    assert_eq!(
        want("runs/rv-imgauth/20261112T090000Z-111111").as_deref(),
        Some("not_finished")
    );
    assert_eq!(
        want("runs/rv-triage/20261112T100000Z-222222").as_deref(),
        Some("unsupported_tool")
    );
    assert_eq!(
        want("runs/rv-hashinv/20261112T110000Z-333333").as_deref(),
        Some("unsupported_version")
    );
}

#[test]
fn edited_output_is_a_digest_mismatch() {
    let (_d, case) = tmp_case();
    let dir = "runs/rv-imgauth/20261111T100000Z-bbbbbb";
    let f = case
        .join(dir)
        .join("reports/items/00001-photo.jpg/metadata.json");
    let t = std::fs::read_to_string(&f)
        .unwrap()
        .replace("18:00:00", "17:00:00");
    std::fs::write(&f, t).unwrap();
    let r = verify_run(&case, run(&case, dir));
    assert_eq!(r.status, RunStatus::Excluded);
    let e = r.exclusion.unwrap();
    assert_eq!(e.reason, "digest_mismatch");
    assert!(e.detail.contains("metadata.json"), "{}", e.detail);
    // The reader refuses it too, even when called without verify_run.
    assert_eq!(
        read_run(&readers::all(), &case, &run(&case, dir))
            .unwrap_err()
            .reason,
        "digest_mismatch"
    );
}

#[test]
fn edited_audit_line_breaks_the_chain() {
    let (_d, case) = tmp_case();
    let dir = "runs/rv-mailauth/20261111T120000Z-dddddd";
    let f = case.join(dir).join("logs/audit.jsonl");
    let t = std::fs::read_to_string(&f).unwrap().replacen(
        "2026-11-03T08:00:00Z",
        "2026-11-03T07:00:00Z",
        1,
    );
    std::fs::write(&f, t).unwrap();
    let r = verify_run(&case, run(&case, dir));
    assert_eq!(r.exclusion.unwrap().reason, "chain_broken");
}

#[test]
fn truncated_audit_log_is_caught_by_the_case_log() {
    let (_d, case) = tmp_case();
    let dir = "runs/rv-pdfauth/20261111T110000Z-cccccc";
    let f = case.join(dir).join("logs/audit.jsonl");
    let t = std::fs::read_to_string(&f).unwrap();
    let lines: Vec<&str> = t.lines().collect();
    // Drop run_finished and the timestamp after it: the chain itself still verifies.
    std::fs::write(&f, lines[..lines.len() - 2].join("\n") + "\n").unwrap();
    let r = verify_run(&case, run(&case, dir));
    assert_eq!(r.exclusion.unwrap().reason, "not_finished");
    // Dropping only the trailing timestamp entry is fine (it may be added later).
    let (_d2, case2) = tmp_case();
    let f2 = case2.join(dir).join("logs/audit.jsonl");
    std::fs::write(&f2, lines[..lines.len() - 1].join("\n") + "\n").unwrap();
    assert_eq!(
        verify_run(&case2, run(&case2, dir)).status,
        RunStatus::Verified
    );
}

#[test]
fn edited_case_log_excludes_every_run() {
    let (_d, case) = tmp_case();
    let f = case.join("case-log.jsonl");
    let t = std::fs::read_to_string(&f)
        .unwrap()
        .replacen("\"cli\"", "\"gui\"", 1);
    std::fs::write(&f, t).unwrap();
    let r = verify_run(&case, run(&case, "runs/rv-hashinv/20261110T090000Z-aaaaaa"));
    let e = r.exclusion.unwrap();
    assert_eq!(e.reason, "chain_broken");
    assert!(e.detail.contains("case-log.jsonl"));
}

#[test]
fn unannounced_or_escaping_run_folders_are_excluded() {
    let (_d, case) = tmp_case();
    copy_dir(
        &case.join("runs/rv-imgauth/20261111T100000Z-bbbbbb"),
        &case.join("runs/rv-imgauth/20261113T000000Z-999999"),
    );
    let r = run(&case, "runs/rv-imgauth/20261113T000000Z-999999");
    assert_eq!(r.tool_version, "0.3.1");
    assert_eq!(
        verify_run(&case, r).exclusion.unwrap().reason,
        "not_finished"
    );
    let evil = RunRef {
        tool: "rv-imgauth".into(),
        tool_version: "0.3.1".into(),
        run_dir: "runs/../../etc".into(),
        ..Default::default()
    };
    assert_eq!(
        verify_run(&case, evil).exclusion.unwrap().reason,
        "unreadable"
    );
}

#[test]
fn hashinv_events() {
    let ev = events("runs/rv-hashinv/20261110T090000Z-aaaaaa");
    let p = "rv-hashinv:20261110T090000Z-aaaaaa";
    expect(
        &ev,
        &[
            (
                &format!("{p}:run:run.started:0"),
                "run.started",
                "2026-11-10T09:00:00.100Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:run:run.finished:0"),
                "run.finished",
                "2026-11-10T09:00:09Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:run:run.timestamped:0"),
                "run.timestamped",
                "2026-11-10T09:00:09Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:E0001:intake.registered:0"),
                "intake.registered",
                "2026-11-10T09:00:01Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:E0007:intake.registered:0"),
                "intake.registered",
                "2026-11-10T09:00:07Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:E0003:fs.modified:0"),
                "fs.modified",
                "2026-11-03T08:00:00Z",
                ZoneInfo::Explicit,
            ),
        ],
    );
    assert_eq!(ev.len(), 3 + 7 + 7);
    let e = find(&ev, &format!("{p}:E0002:intake.registered:0"));
    assert_eq!(e.item.path, "D:\\evidence\\contract.pdf");
    assert_eq!(e.item.sha256, "a2".repeat(32));
    assert_eq!(
        e.source.file,
        "reports/items/00002-contract.pdf/technical.json"
    );
    assert_eq!(e.source.pointer, "/case/intake_utc");
    assert_eq!(e.precision, Precision::Millisecond);
    let started = find(&ev, &format!("{p}:run:run.started:0"));
    assert_eq!(started.utc_ns, 100_000_000);
    assert_eq!(started.source.file, "logs/audit.jsonl");
    assert_eq!(started.source.pointer, "line:1/ts_utc");
}

#[test]
fn imgauth_events() {
    let ev = events("runs/rv-imgauth/20261111T100000Z-bbbbbb");
    let p = "rv-imgauth:20261111T100000Z-bbbbbb:E0001";
    expect(
        &ev,
        &[
            (
                &format!("{p}:exif.original:0"),
                "exif.original",
                "2026-11-09T23:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:exif.digitized:0"),
                "exif.digitized",
                "2026-11-09T18:00:00Z",
                ZoneInfo::Unknown,
            ),
            (
                &format!("{p}:exif.modify:0"),
                "exif.modify",
                "2026-11-09T18:30:00Z",
                ZoneInfo::Unknown,
            ),
            (
                &format!("{p}:gps.time:0"),
                "gps.time",
                "2026-11-09T23:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:xmp.create:0"),
                "xmp.create",
                "2026-11-09T18:00:00Z",
                ZoneInfo::Unknown,
            ),
            (
                &format!("{p}:xmp.modify:0"),
                "xmp.modify",
                "2026-11-12T09:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:xmp.history:0"),
                "xmp.history",
                "2026-11-12T09:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                "rv-imgauth:20261111T100000Z-bbbbbb:E0007:png.time:0",
                "png.time",
                "2026-11-08T12:00:00Z",
                ZoneInfo::Explicit,
            ),
        ],
    );
    let o = find(&ev, &format!("{p}:exif.original:0"));
    assert_eq!(o.original, "2026:11:09 18:00:00 -05:00");
    assert_eq!(
        (o.offset_min, o.utc_ns, o.precision),
        (Some(-300), 250_000_000, Precision::Millisecond)
    );
    assert_eq!(o.source.pointer, "/tags/3/value");
    assert_eq!(o.details["model"], "EC-1");
    assert_eq!(
        find(&ev, &format!("{p}:exif.digitized:0")).details["zone"],
        "unknown"
    );
    // "not a date" is skipped and counted, never invented.
    assert!(!ev.iter().any(|e| e.kind == "xmp.metadata"));
    let case = fixture();
    let out = read_run_outcome(
        &case,
        &run(&case, "runs/rv-imgauth/20261111T100000Z-bbbbbb"),
    )
    .unwrap();
    assert_eq!(out.skipped, 1);
    assert!(out.warnings[0].contains("not a date"), "{:?}", out.warnings);
}

#[test]
fn pdfauth_events() {
    let ev = events("runs/rv-pdfauth/20261111T110000Z-cccccc");
    let p = "rv-pdfauth:20261111T110000Z-cccccc:E0002";
    expect(
        &ev,
        &[
            (
                &format!("{p}/r1:pdf.info.created:0"),
                "pdf.info.created",
                "2026-11-01T14:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}/r1:pdf.info.modified:0"),
                "pdf.info.modified",
                "2026-11-01T14:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}/r2:pdf.info.modified:0"),
                "pdf.info.modified",
                "2026-11-05T12:00:00Z",
                ZoneInfo::Unknown,
            ),
            (
                &format!("{p}/r1:pdf.signature.claimed:0"),
                "pdf.signature.claimed",
                "2026-11-01T14:30:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}/r1:pdf.revision.signed:0"),
                "pdf.revision.signed",
                "2026-11-01T14:30:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}/r1:pdf.xmp.saved:0"),
                "pdf.xmp.saved",
                "2026-11-01T14:00:00Z",
                ZoneInfo::Explicit,
            ),
        ],
    );
    // With objects.json, Info dates come from the raw D: strings, not from the normalised technical.json value.
    assert!(!ev.iter().any(|e| e.kind == "pdf.info.saved"));
    let c = find(&ev, &format!("{p}/r1:pdf.info.created:0"));
    assert_eq!(c.original, "D:20261101090000-05'00'");
    assert_eq!(c.item.sub, "r1");
    assert_eq!(
        c.source.file,
        "reports/items/00002-contract.pdf/objects.json"
    );
    assert_eq!(c.source.pointer, "/revisions/0/objects/1/dict/CreationDate");
    assert_eq!(c.details["object"], "7 0");
}

#[test]
fn mailauth_events() {
    let ev = events("runs/rv-mailauth/20261111T120000Z-dddddd");
    let p = "rv-mailauth:20261111T120000Z-dddddd";
    expect(
        &ev,
        &[
            (
                &format!("{p}:E0003:mail.date:0"),
                "mail.date",
                "2026-11-10T08:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:E0003:mail.hop:0"),
                "mail.hop",
                "2026-11-10T08:00:04Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:E0003:mail.hop:1"),
                "mail.hop",
                "2026-11-10T08:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:E0003:mail.attachment.modified:0"),
                "mail.attachment.modified",
                "2026-11-13T09:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:E0004/#1:mail.date:0"),
                "mail.date",
                "2026-11-11T11:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:E0004/#2:mail.date:0"),
                "mail.date",
                "2026-11-11T12:30:00Z",
                ZoneInfo::Unknown,
            ),
            (
                &format!("{p}:E0004/#1:mail.mbox_from:0"),
                "mail.mbox_from",
                "2026-11-11T11:00:03Z",
                ZoneInfo::Unknown,
            ),
            (
                &format!("{p}:E0004/#2:mail.mbox_from:0"),
                "mail.mbox_from",
                "2026-11-11T11:30:02Z",
                ZoneInfo::Unknown,
            ),
        ],
    );
    let m = find(&ev, &format!("{p}:E0004/#2:mail.date:0"));
    assert_eq!(m.item.path, "D:\\evidence\\box.mbox#2@900");
    assert_eq!(
        (m.item.sub.as_str(), m.item.evidence_id.as_str()),
        ("#2", "E0004")
    );
    assert_eq!(m.item.sha256, "a4".repeat(32));
    assert_eq!(m.original, "Wed, 11 Nov 2026 12:30:00 -0000");
    let hop = find(&ev, &format!("{p}:E0003:mail.hop:0"));
    assert_eq!(hop.details["position"], "2");
    assert_eq!(hop.source.pointer, "/headers/hops/0/date_raw");
}

#[test]
fn rsmf_events() {
    let ev = events("runs/rv-rsmf/20261111T130000Z-eeeeee");
    let p = "rv-rsmf:20261111T130000Z-eeeeee:E0005/c1/2026-11-09";
    expect(
        &ev,
        &[
            (
                &format!("{p}:chat.message:0"),
                "chat.message",
                "2026-11-09T23:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:chat.message:1"),
                "chat.message",
                "2026-11-09T23:05:00Z",
                ZoneInfo::Explicit,
            ),
        ],
    );
    let m = find(&ev, &format!("{p}:chat.message:0"));
    assert_eq!(m.original, "9/11/26, 18:00");
    assert_eq!(m.precision, Precision::Minute);
    assert_eq!(m.offset_min, None);
    assert!(m.details["zone_applied"].starts_with("America/Bogota"));
    assert_eq!(m.source.file, "rsmf/trace.json");
    assert_eq!(m.item.sub, "c1/2026-11-09");
    assert!(
        !ev.iter().any(|e| e.kind.starts_with("chat.conversation.")),
        "no derived first/last events"
    );
    let case = fixture();
    let out = read_run_outcome(&case, &run(&case, "runs/rv-rsmf/20261111T130000Z-eeeeee")).unwrap();
    assert_eq!(out.skipped, 1, "the garbled row is counted, not placed");
}

#[test]
fn certcheck_events() {
    let ev = events("runs/rv-certcheck/20261111T140000Z-ffffff");
    let p = "rv-certcheck:20261111T140000Z-ffffff:E0006";
    expect(
        &ev,
        &[
            (
                &format!("{p}:cert.not_before:0"),
                "cert.not_before",
                "2026-01-01T00:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:cert.not_after:0"),
                "cert.not_after",
                "2027-01-01T00:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:cert.revoked:0"),
                "cert.revoked",
                "2026-06-01T12:00:00Z",
                ZoneInfo::Explicit,
            ),
            (
                &format!("{p}:tsa.gen_time:0"),
                "tsa.gen_time",
                "2026-11-02T10:00:00Z",
                ZoneInfo::Explicit,
            ),
        ],
    );
    let r = find(&ev, &format!("{p}:cert.revoked:0"));
    assert_eq!(r.details["reason"], "keyCompromise");
    assert_eq!(
        r.source.pointer,
        "/verdicts/0/nodes/0/revocation/revoked_at"
    );
}

#[test]
fn read_run_refuses_unsupported_versions() {
    let case = fixture();
    let r = run(&case, "runs/rv-hashinv/20261112T110000Z-333333");
    assert_eq!(
        read_run(&readers::all(), &case, &r).unwrap_err().reason,
        "unsupported_version"
    );
    let r = run(&case, "runs/rv-triage/20261112T100000Z-222222");
    assert_eq!(
        read_run(&readers::all(), &case, &r).unwrap_err().reason,
        "unsupported_tool"
    );
    assert_eq!(
        read_run_outcome(&case, &r).unwrap_err().reason,
        "unsupported_tool"
    );
}

#[test]
fn every_kind_has_a_label_in_every_language() {
    let case = fixture();
    let mut kinds = std::collections::BTreeSet::new();
    for r in discover_runs(&case).unwrap() {
        let r = verify_run(&case, r);
        if r.status == RunStatus::Verified {
            kinds.extend(
                read_run(&readers::all(), &case, &r)
                    .unwrap()
                    .into_iter()
                    .map(|e| e.kind),
            );
        }
    }
    assert!(kinds.len() >= 27, "{kinds:?}");
    for l in rv_timeline_core::i18n::LANGS {
        let c = rv_timeline_core::i18n::catalog(l);
        for k in &kinds {
            assert!(c.has_kind(k), "{l}: no label for {k}");
        }
    }
}
