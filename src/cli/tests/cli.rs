//! End-to-end tests of the rv-timeline binary: the contract every Rakvor CLI must meet, on the sample case
//! (examples/sample/case) and its tampered copies.

use assert_cmd::Command;
use predicates::prelude::*;
use rv_timeline_core::HashAlgo;
use std::path::{Path, PathBuf};

const TOOL: &str = rv_timeline_core::TOOL_NAME;

fn bin() -> Command {
    let mut c = Command::cargo_bin("rv-timeline").unwrap();
    c.env("RV_NO_TIMESTAMP", "1"); // offline by default; trust_* tests use a local test TSA
    c
}

/// The fake TSA process, killed when dropped, so a failing assertion cannot leave it running. An orphaned
/// server keeps the test's inherited stderr open: under `cargo test | tee` (CI) the step then never ends.
struct TsaServer(std::process::Child);

impl Drop for TsaServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts tests/fake_tsa.py (needs Python with pyhanko). Returns None to skip when unavailable.
fn test_pki(dir: &Path) -> Option<(TsaServer, String)> {
    let py = std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fake_tsa.py");
    let ok = std::process::Command::new(&py)
        .args(["-c", "import pyhanko"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!(
            "skipping trust test: {} has no pyhanko (pip install pyhanko)",
            py
        );
        return None;
    }
    let mut server = TsaServer(
        std::process::Command::new(&py)
            .arg(&script)
            .arg("serve")
            .arg(dir)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .ok()?,
    );
    let mut line = String::new();
    use std::io::BufRead;
    std::io::BufReader::new(server.0.stdout.take()?)
        .read_line(&mut line)
        .ok()?;
    Some((server, line.trim().to_string()))
}

fn only_dir(p: &Path) -> PathBuf {
    std::fs::read_dir(p)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

fn sample_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        if p.is_dir() {
            copy_dir(&p, &to.join(e.file_name()));
        } else {
            std::fs::copy(&p, to.join(e.file_name())).unwrap();
        }
    }
}

/// A fresh copy of examples/sample/case (or of a tampered copy: `tampered/<name>`), so tests never write into
/// the repository.
fn case_copy(rel: &str, dest: &Path) -> PathBuf {
    let case = dest.join("CASE");
    copy_dir(&sample_dir().join(rel), &case);
    case
}

fn build(case: &Path) -> Command {
    let mut c = bin();
    c.args(["build", "--progress", "none", "--case-dir"])
        .arg(case);
    c
}

/// The run folder printed on the "logs:" line of the summary.
fn run_folder(stdout: &[u8]) -> PathBuf {
    let text = String::from_utf8_lossy(stdout);
    let logs = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("logs:"))
        .expect("logs line")
        .trim();
    PathBuf::from(logs).parent().unwrap().to_path_buf()
}

fn audit(run: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(run.join("logs/audit.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Every file of the case outside rv-timeline's own run folders, with its content (the case log aside).
fn case_files(case: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let mut all = Vec::new();
    walk(case, &mut all);
    let own = case.join("runs").join(TOOL);
    all.into_iter()
        .filter(|p| !p.starts_with(&own) && !p.ends_with("case-log.jsonl"))
        .map(|p| {
            (
                p.strip_prefix(case).unwrap().to_path_buf(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect()
}

#[test]
fn help_has_every_required_section() {
    let out = bin().args(["build", "--help"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for section in [
        "DESCRIPTION:",
        "Options:",
        "EXAMPLES:",
        "EXIT CODES:",
        "FILES WRITTEN:",
        "FORENSIC NOTES:",
        "timeline.jsonl",
    ] {
        assert!(text.contains(section), "missing {}", section);
    }
    let flags = [
        "--case-dir",
        "--display-zone",
        "--tool",
        "--from",
        "--to",
        "--clock-skew",
        "--max-events",
        "--no-timesketch",
        "--hash",
        "--out",
        "--lang",
        "--actor",
        "--case",
        "--progress",
        "--jurisdiction",
        "--tsa-url",
        "--no-timestamp",
        "--sign-cert",
        "--sign-pass-env",
    ];
    for flag in flags {
        assert!(text.contains(flag), "missing {}", flag);
    }
    // Every option documents a default and an example.
    assert!(text.matches("Default:").count() >= flags.len());
    assert!(text.matches("Example:").count() >= flags.len());
    // The evidence-input options of the template are gone: the input is a case folder.
    for gone in ["--input", "--recursive", "--evidence"] {
        assert!(!text.contains(gone), "{} still documented", gone);
    }
    // `scan` is not a command of this tool.
    bin().args(["scan", "--help"]).assert().code(2);
}

#[test]
fn bad_options_are_usage_errors_and_write_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let case = case_copy("case", tmp.path());
    for (args, msg) in [
        (&["--hash", "md5,sha1,sha256"][..], "at most 2"),
        (&["--hash", "crc32"], "unknown hash algorithm"),
        (&["--lang", "de"], "unsupported language"),
        (&["--display-zone", "Mars/Olympus"], "unknown display zone"),
        (&["--from", "yesterday"], "not an RFC 3339 time"),
        (&["--to", "2026-13-01T00:00:00Z"], "not an RFC 3339 time"),
        (
            &[
                "--from",
                "2026-11-02T00:00:00Z",
                "--to",
                "2026-11-01T00:00:00Z",
            ],
            "--from is later than --to",
        ),
        (&["--tool", "rv-unknown"], "unknown tool 'rv-unknown'"),
        (&["--max-events", "0"], "--max-events"),
        (&["--clock-skew", "abc"], "--clock-skew"),
        (&["--case", "OTHER-CASE"], "RV-SAMPLE-001"),
    ] {
        build(&case)
            .args(args)
            .assert()
            .code(2)
            .stderr(predicate::str::contains(msg));
    }
    assert!(!case.join("runs").join(TOOL).exists());
    // A folder that is not a case folder: never created, exit 2.
    let empty = tmp.path().join("not-a-case");
    std::fs::create_dir_all(&empty).unwrap();
    build(&empty)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("is not a case folder"));
    assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0);
    bin()
        .args(["build", "--progress", "none"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--case-dir"));
}

#[test]
fn sample_case_builds_a_verified_cited_timeline() {
    let tmp = tempfile::tempdir().unwrap();
    let case = case_copy("case", tmp.path());
    let before = case_files(&case);
    let out = bin()
        .args([
            "build",
            "--progress",
            "jsonl",
            "--hash",
            "sha256,md5",
            "--lang",
            "all",
        ])
        .args([
            "--display-zone",
            "America/Bogota",
            "--actor",
            "Tester",
            "--case-dir",
        ])
        .arg(&case)
        .output()
        .unwrap();
    // The sample has medium- and high-severity signals by design (examples/sample/README.md): exit 3.
    assert_eq!(out.status.code(), Some(3), "{:?}", out);
    let events: Vec<serde_json::Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("stdout is only JSON Lines"))
        .collect();
    assert_eq!(events.first().unwrap()["event"], "run_started");
    assert_eq!(events.last().unwrap()["event"], "run_finished");
    let elapsed: Vec<u64> = events
        .iter()
        .filter(|e| e["event"] == "progress")
        .map(|e| e["elapsed_ms"].as_u64().unwrap())
        .collect();
    assert!(!elapsed.is_empty() && elapsed.windows(2).all(|w| w[0] <= w[1]));
    let report_dir = PathBuf::from(events.last().unwrap()["report_dir"].as_str().unwrap());
    let run = report_dir.parent().unwrap().to_path_buf();
    assert!(run.starts_with(case.join("runs").join(TOOL)));

    // timeline.jsonl: present, one JSON object per line in Timesketch form, its digests in the audit log.
    let jsonl = std::fs::read(report_dir.join("timeline.jsonl")).unwrap();
    let lines: Vec<serde_json::Value> = String::from_utf8(jsonl.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!lines.is_empty());
    for l in &lines {
        for k in [
            "message",
            "datetime",
            "timestamp",
            "timestamp_desc",
            "rakvor_event_id",
        ] {
            assert!(l.get(k).is_some(), "{} missing in {}", k, l);
        }
    }
    let entries = audit(&run);
    let written = entries
        .iter()
        .find(|e| e["action"] == "timeline_written")
        .expect("timeline_written");
    assert_eq!(written["item"], "timeline.jsonl");
    let digests = &written["details"]["files"]["timeline.jsonl"];
    assert_eq!(
        digests["sha256"],
        rv_timeline_core::hash::hash_bytes(&jsonl, HashAlgo::Sha256)
    );
    assert_eq!(
        digests["md5"],
        rv_timeline_core::hash::hash_bytes(&jsonl, HashAlgo::Md5)
    );
    assert_eq!(written["details"]["lines"], lines.len() as u64);
    let actions: Vec<&str> = entries
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions[..2], ["run_started", "case_linked"]);
    assert_eq!(actions.last(), Some(&"run_finished"));
    assert!(actions.contains(&"run_verified") && !actions.contains(&"run_excluded"));
    assert_eq!(
        entries[0]["details"]["timeline"]["display_zone"],
        "America/Bogota"
    );
    for f in ["statistics.json", "statistics.es.html", "statistics.fr.pdf"] {
        assert!(report_dir.join(f).is_file(), "{}", f);
    }
    assert!(report_dir.join("items").read_dir().unwrap().count() >= 21);

    // Only the run's own folder and the case log changed; the case and the run verify.
    assert_eq!(before, case_files(&case));
    bin()
        .arg("verify-log")
        .arg(run.join("logs"))
        .assert()
        .code(0)
        .stdout(predicate::str::contains("review log: none"));
    bin()
        .arg("verify-case")
        .arg(&case)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("OK  case RV-SAMPLE-001"))
        .stdout(predicate::str::contains("review logs: 0 entries"));
    // Viewing after the run (review.jsonl): both commands print the entries they verified.
    for f in ["timeline.jsonl", "statistics.json"] {
        rv_timeline_core::review::append(
            &run.join("logs"),
            "tester",
            "ui_timeline_viewed",
            serde_json::json!({ "file": f }),
        )
        .unwrap();
    }
    bin()
        .arg("verify-log")
        .arg(run.join("logs"))
        .assert()
        .code(0)
        .stdout(predicate::str::contains(
            "review log: 2 entries, chain intact",
        ));
    bin()
        .arg("verify-case")
        .arg(&case)
        .assert()
        .code(0)
        .stdout(predicate::str::contains(
            "review logs: 2 entries across the runs, all verified",
        ));
    let review = run.join("logs").join(rv_timeline_core::review::REVIEW_FILE);
    std::fs::remove_file(&review).unwrap();

    // A second build skips the first timeline run (never reads itself).
    let o = build(&case).output().unwrap();
    assert_eq!(o.status.code(), Some(3));
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("skipped 1"), "{}", text);
    assert!(text.contains("excluded 0"), "{}", text);
}

#[test]
fn no_timesketch_and_filters_are_honoured() {
    let tmp = tempfile::tempdir().unwrap();
    let case = case_copy("case", tmp.path());
    let o = build(&case)
        .args([
            "--no-timesketch",
            "--tool",
            "rv-rsmf",
            "--examiner",
            "Tester",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(
        text.contains("timeline: not written (--no-timesketch)"),
        "{}",
        text
    );
    let run = run_folder(&o.stdout);
    assert!(!run.join("reports/timeline.jsonl").exists());
    let entries = audit(&run);
    assert!(!entries.iter().any(|e| e["action"] == "timeline_written"));
    assert!(entries.iter().all(|e| e["actor"] == "Tester"));
    // Every run of another tool is skipped and logged as such.
    let skipped: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|e| e["action"] == "run_skipped" && e["details"]["reason"] == "tool_filter")
        .collect();
    assert!(!skipped.is_empty());
    assert!(
        entries
            .iter()
            .filter(|e| e["action"] == "run_verified")
            .all(|e| e["details"]["tool"] == "rv-rsmf")
    );
    assert_eq!(
        entries[0]["details"]["timeline"]["tools"],
        serde_json::json!(["rv-rsmf"])
    );
    // A window with no event still builds (empty timeline), within the window rules.
    let o = build(&case)
        .args([
            "--from",
            "1990-01-01T00:00:00Z",
            "--to",
            "1990-01-02T00:00:00+01:00",
        ])
        .output()
        .unwrap();
    assert!(matches!(o.status.code(), Some(0) | Some(3)), "{:?}", o);
    let text = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(text.contains("events:   0"), "{}", text);
}

#[test]
fn tampered_runs_are_excluded_with_exit_3_and_a_reason() {
    for (copy, tool, reason) in [
        ("digest-mismatch", "rv-imgauth", "digest_mismatch"),
        ("chain-broken", "rv-mailauth", "chain_broken"),
        ("not-finished", "rv-certcheck", "not_finished"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let case = case_copy(&format!("tampered/{}", copy), tmp.path());
        let o = build(&case).output().unwrap();
        assert_eq!(o.status.code(), Some(3), "{}: {:?}", copy, o);
        let text = String::from_utf8_lossy(&o.stdout).to_string();
        assert!(
            text.contains(&format!("excluded: runs/{}/", tool)) && text.contains(reason),
            "{}: {}",
            copy,
            text
        );
        assert!(text.contains("excluded 1"), "{}: {}", copy, text);
        let run = run_folder(&o.stdout);
        let excluded: Vec<serde_json::Value> = audit(&run)
            .into_iter()
            .filter(|e| e["action"] == "run_excluded")
            .collect();
        assert_eq!(excluded.len(), 1, "{}", copy);
        assert_eq!(excluded[0]["details"]["tool"], tool);
        assert_eq!(excluded[0]["details"]["reason"], reason);
        assert!(run.join("reports/timeline.jsonl").is_file());
        // The exclusion is also on stderr in jsonl mode (stdout stays JSON only).
        let tmp2 = tempfile::tempdir().unwrap();
        let case2 = case_copy(&format!("tampered/{}", copy), tmp2.path());
        let o = bin()
            .args(["build", "--progress", "jsonl", "--case-dir"])
            .arg(&case2)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(3));
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("run excluded (not verified)"),
            "{:?}",
            o
        );
    }
}

#[test]
fn a_broken_case_is_never_extended() {
    let tmp = tempfile::tempdir().unwrap();
    let case = case_copy("case", tmp.path());
    let log = case.join("case-log.jsonl");
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::write(&log, text.replacen("\"seq\":2", "\"seq\":7", 1)).unwrap();
    let runs_before = std::fs::read_dir(case.join("runs")).unwrap().count();
    build(&case).assert().code(3);
    assert_eq!(
        std::fs::read_dir(case.join("runs")).unwrap().count(),
        runs_before
    );
    assert!(!case.join("runs").join(TOOL).exists());
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        text.replacen("\"seq\":2", "\"seq\":7", 1)
    );
}

/// examples/sample/run.sh builds the timeline on a copy of the sample case and checks the exit code and that
/// timeline.jsonl is written and listed in the audit log.
#[test]
#[cfg(unix)]
fn sample_script_builds_the_timeline() {
    let script = sample_dir().join("run.sh");
    let exe = env!("CARGO_BIN_EXE_rv-timeline");
    let out = tempfile::tempdir().unwrap();
    let o = std::process::Command::new("sh")
        .arg(&script)
        .arg(exe)
        .env("RV_NO_TIMESTAMP", "1")
        .env("RV_SAMPLE_OUT", out.path())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{}", text);
    assert!(
        text.contains("timeline.jsonl is listed in the audit log"),
        "{}",
        text
    );
}

#[test]
fn timestamp_of_a_missing_log_exits_3() {
    let d = tempfile::tempdir().unwrap();
    bin()
        .arg("timestamp")
        .arg(d.path())
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no audit log at"));
}

#[test]
fn self_test_passes() {
    bin()
        .arg("self-test")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("FAIL").not());
}

#[test]
fn usage_doc_matches_help() {
    let generated = bin().arg("docs-cli").output().unwrap().stdout;
    let doc = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/usage-cli.md");
    let committed = std::fs::read(&doc).unwrap_or_default();
    assert!(
        committed == generated,
        "docs/usage-cli.md is out of date: run `cargo run -p rv-timeline-cli -- docs-cli > docs/usage-cli.md`"
    );
}

/// Review (sidecar bypass): a copy of `logs` without its timestamp-*.json files. The audit log's
/// timestamp_obtained entries still name the tokens, so the missing metadata is a problem and the tokens are
/// still checked: with another CA bundle the chain is still refused.
fn sidecar_deletion_is_detected(logs: &Path, good_ca: &Path, other_ca: &Path) {
    let copy = tempfile::tempdir().unwrap();
    for e in std::fs::read_dir(logs).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.is_file() && !(name.starts_with("timestamp-") && name.ends_with(".json")) {
            std::fs::copy(&p, copy.path().join(&name)).unwrap();
        }
    }
    for ca in [good_ca, other_ca] {
        bin()
            .arg("verify-log")
            .arg(copy.path())
            .arg("--tsa-ca")
            .arg(ca)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("metadata"));
    }
    bin()
        .arg("verify-log")
        .arg(copy.path())
        .arg("--tsa-ca")
        .arg(other_ca)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("chain not validated"));
    bin().arg("verify-log").arg(copy.path()).assert().code(3);
}

/// The token checked from its metadata alone (log cut just before its timestamp_obtained entry, metadata digest
/// updated to the altered token): the TSA signature check catches the alteration.
fn altered_token_without_its_entry_fails_the_signature(
    logs: &Path,
    tsr: &Path,
    meta: &serde_json::Value,
) {
    let cut = tempfile::tempdir().unwrap();
    let covers = meta["covers_seq"].as_u64().unwrap();
    let kept: String = std::fs::read_to_string(logs.join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"].as_u64() <= Some(covers)
        })
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(cut.path().join("audit.jsonl"), kept).unwrap();
    std::fs::copy(tsr, cut.path().join(tsr.file_name().unwrap())).unwrap();
    std::fs::write(
        cut.path()
            .join(tsr.with_extension("json").file_name().unwrap()),
        meta.to_string(),
    )
    .unwrap();
    bin()
        .arg("verify-log")
        .arg(cut.path())
        .assert()
        .code(3)
        .stdout(predicate::str::contains("signature value does not verify"));
}

#[test]
fn trust_timestamp_signature_and_custody_with_test_pki() {
    let pki = tempfile::tempdir().unwrap();
    let Some((tsa, url)) = test_pki(pki.path()) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let case = case_copy("case", tmp.path());
    let o = bin()
        .env_remove("RV_NO_TIMESTAMP")
        .env("NO_PROXY", "127.0.0.1")
        .env("RV_SIGN_PASSWORD", "test")
        .args(["build", "--case-dir"])
        .arg(&case)
        .args([
            "--jurisdiction",
            "fr",
            "--tsa-url",
            &url,
            "--progress",
            "none",
            "--sign-cert",
        ])
        .arg(pki.path().join("examiner.p12"))
        .output()
        .unwrap();
    // The sample has medium/high signals by design: exit 3.
    assert_eq!(o.status.code(), Some(3), "{:?}", o);
    assert!(String::from_utf8_lossy(&o.stdout).contains("timestamp: ok"));
    let run = run_folder(&o.stdout);
    let logs = run.join("logs");
    // The TSA's CMS signature is checked; the chain only with --tsa-ca.
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("TSA signature valid"))
        .stdout(predicate::str::contains("chain not checked"))
        .stdout(
            predicate::str::contains("covers entry")
                .and(predicate::str::contains("truncation: the final entry")),
        );
    bin()
        .arg("verify-log")
        .arg(&logs)
        .arg("--tsa-ca")
        .arg(pki.path().join("ca.pem"))
        .assert()
        .code(0)
        .stdout(predicate::str::contains(
            "chain validated to O=Rakvor TEST,CN=Rakvor TEST CA",
        ))
        .stdout(predicate::str::contains("chain not checked").not());
    // Another CA does not vouch for this TSA.
    let other = tempfile::tempdir().unwrap();
    let made = std::process::Command::new(
        std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into()),
    )
    .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fake_tsa.py"))
    .arg("certs")
    .arg(other.path())
    .status()
    .unwrap();
    assert!(made.success());
    bin()
        .arg("verify-log")
        .arg(&logs)
        .arg("--tsa-ca")
        .arg(other.path().join("ca.pem"))
        .assert()
        .code(3)
        .stdout(predicate::str::contains("chain not validated"));
    bin()
        .arg("verify-log")
        .arg(&logs)
        .arg("--tsa-ca")
        .arg(other.path().join("missing.pem"))
        .assert()
        .code(1);
    sidecar_deletion_is_detected(
        &logs,
        &pki.path().join("ca.pem"),
        &other.path().join("ca.pem"),
    );
    // The case's own jurisdiction (co) applies, whatever --jurisdiction says.
    let item = only_dir(&run.join("reports/items"));
    for f in [
        "custody.json",
        "custody.es.pdf",
        "custody.es.html",
        "custody.en.pdf",
    ] {
        assert!(item.join(f).is_file(), "{}", f);
    }
    let pdf = std::fs::read(item.join("technical.en.pdf")).unwrap();
    assert!(String::from_utf8_lossy(&pdf).contains("/adbe.pkcs7.detached"));
    // Independent check: pyHanko validates every signed PDF (intact + cryptographically valid; the test CA
    // is not a trusted root, so an untrusted chain is expected).
    let py = std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/validate_pdf_signature.py");
    let v = std::process::Command::new(&py)
        .arg(&script)
        .arg(run.join("reports"))
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&v.stdout);
    assert!(v.status.success(), "pyHanko validation failed:\n{}", report);
    let lines: Vec<serde_json::Value> = report
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(lines.len() >= 8, "every PDF validated: {}", report);
    for l in &lines {
        assert_eq!(
            (&l["intact"], &l["valid"]),
            (&true.into(), &true.into()),
            "{}",
            l
        );
        assert!(l["signer"].as_str().unwrap().contains("Ana Ruiz"), "{}", l);
    }
    // The reports print the signer's certificate fingerprint, as logged at signing_certificate_loaded.
    let audit = std::fs::read_to_string(logs.join("audit.jsonl")).unwrap();
    let loaded: serde_json::Value = audit
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|e| e["action"] == "signing_certificate_loaded")
        .unwrap();
    let fp = loaded["details"]["certificate_sha256"].as_str().unwrap();
    assert_eq!(fp.len(), 64);
    assert!(
        std::fs::read_to_string(item.join("technical.en.html"))
            .unwrap()
            .contains(fp)
    );
    // Removing entries back to (and including) the timestamped one is detected through covers_seq.
    let audit_path = logs.join("audit.jsonl");
    let full = std::fs::read_to_string(&audit_path).unwrap();
    let kept: Vec<&str> = full.lines().collect();
    std::fs::write(
        &audit_path,
        format!("{}\n", kept[..kept.len() - 4].join("\n")),
    )
    .unwrap();
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("truncated"));
    std::fs::write(&audit_path, &full).unwrap();
    // Tampering with the token is detected.
    let tsr = std::fs::read_dir(&logs)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "tsr"))
        .unwrap();
    let mut b = std::fs::read(&tsr).unwrap();
    // The last byte of a token is the last byte of the TSA's RSA signature value.
    let last = b.len() - 1;
    b[last] ^= 0xff;
    std::fs::write(&tsr, &b).unwrap();
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("missing or altered"));
    // Updating the digest in the metadata file does not help: the audit log's timestamp_obtained entry is what
    // the token is checked against, and the metadata now disagrees with it.
    let meta_path = tsr.with_extension("json");
    let mut meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    meta["token_sha256"] = rv_timeline_core::hash::hash_bytes(&b, HashAlgo::Sha256).into();
    std::fs::write(&meta_path, meta.to_string()).unwrap();
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("missing or altered"));
    altered_token_without_its_entry_fails_the_signature(&logs, &tsr, &meta);
    // Offline run: pending, then added later with `timestamp`.
    let tmp2 = tempfile::tempdir().unwrap();
    let case2 = case_copy("case", tmp2.path());
    let o = bin()
        .env_remove("RV_NO_TIMESTAMP")
        .args(["build", "--case-dir"])
        .arg(&case2)
        .args(["--tsa-url", "http://127.0.0.1:9/tsr", "--progress", "none"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(3), "{:?}", o);
    assert!(String::from_utf8_lossy(&o.stdout).contains("timestamp: pending"));
    let logs2 = run_folder(&o.stdout).join("logs");
    bin()
        .env("NO_PROXY", "127.0.0.1")
        .args(["timestamp"])
        .arg(&logs2)
        .args(["--tsa-url", &url])
        .assert()
        .code(0);
    bin()
        .arg("verify-log")
        .arg(&logs2)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("covers entry"));
    drop(tsa);
}

/// Cross-profile check without the other repository: a case folder written by the other profile
/// (tests/golden/case-by-<profile>.zip.b64, made by tests/golden/regenerate.py) verifies here, and tampering with it is
/// still detected. Unpacked with tests/golden/unpack.py (RV_TEST_PYTHON), like the other Python-based oracles.
#[test]
fn golden_case_from_the_other_profile_verifies() {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden");
    let mut archives: Vec<PathBuf> = std::fs::read_dir(&golden)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    archives.retain(|p| p.to_string_lossy().ends_with(".zip.b64"));
    archives.sort();
    let py = std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    for archive in archives {
        let tmp = tempfile::tempdir().unwrap();
        let unzip = std::process::Command::new(&py)
            .arg(golden.join("unpack.py"))
            .arg(&archive)
            .arg(tmp.path())
            .status();
        if !unzip.is_ok_and(|s| s.success()) {
            eprintln!(
                "skipping golden case test: {} cannot unpack {}",
                py,
                archive.display()
            );
            return;
        }
        let case = tmp.path().join("CASE-GOLDEN");
        bin()
            .arg("verify-case")
            .arg(&case)
            .assert()
            .code(0)
            .stdout(predicate::str::contains(
                "3 registered items, 1 runs verified",
            ));
        let logs = only_dir(&only_dir(&case.join("runs"))).join("logs");
        bin()
            .arg("verify-log")
            .arg(&logs)
            .assert()
            .code(0)
            .stdout(
                predicate::str::contains("covers entry #").and(
                    predicate::str::is_match(
                        r"truncation: the final entry #\d+ is anchored by the case log \(run_finished\)",
                    )
                    .unwrap(),
                ),
            );
        let audit = logs.join("audit.jsonl");
        let full = std::fs::read(&audit).unwrap();
        let cut = full[..full.len() - 1]
            .iter()
            .rposition(|&b| b == b'\n')
            .unwrap()
            + 1;
        std::fs::write(&audit, &full[..cut]).unwrap();
        bin()
            .arg("verify-log")
            .arg(&logs)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("truncated: the case log records"));
        bin().arg("verify-case").arg(&case).assert().code(3);
        std::fs::write(&audit, &full).unwrap();
        // verify-case checks each token against its timestamp_obtained entry: an altered signature value, even
        // with the digest in the metadata file updated to match, makes the case fail (the entry's digest differs).
        let tsr = std::fs::read_dir(&logs)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "tsr"))
            .unwrap();
        let meta_path = tsr.with_extension("json");
        let (token, meta_text) = (
            std::fs::read(&tsr).unwrap(),
            std::fs::read_to_string(&meta_path).unwrap(),
        );
        let mut b = token.clone();
        let last = b.len() - 1;
        b[last] ^= 0xff;
        std::fs::write(&tsr, &b).unwrap();
        let mut meta: serde_json::Value = serde_json::from_str(&meta_text).unwrap();
        meta["token_sha256"] = rv_timeline_core::hash::hash_bytes(&b, HashAlgo::Sha256).into();
        std::fs::write(&meta_path, meta.to_string()).unwrap();
        bin()
            .arg("verify-case")
            .arg(&case)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("missing or altered"));
        std::fs::write(&tsr, &token).unwrap();
        // Review (sidecar bypass): deleting the metadata file does not skip the token's checks.
        std::fs::remove_file(&meta_path).unwrap();
        bin()
            .arg("verify-case")
            .arg(&case)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("metadata"));
        std::fs::write(&meta_path, &meta_text).unwrap();
        bin().arg("verify-case").arg(&case).assert().code(0);
        let reg = case.join("evidence/registry.json");
        let text = std::fs::read_to_string(&reg).unwrap();
        std::fs::write(&reg, text.replacen("\"size\": ", "\"size\": 1", 1)).unwrap();
        bin()
            .arg("verify-case")
            .arg(&case)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("registry.json"));
    }
}

/// CI and release build with the toolchain pinned in rust-toolchain.toml (never a floating `stable`).
#[test]
fn workflows_use_the_pinned_toolchain() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pin = std::fs::read_to_string(root.join("rust-toolchain.toml")).unwrap();
    let channel = pin
        .lines()
        .find_map(|l| l.trim().strip_prefix("channel = "))
        .unwrap()
        .trim_matches('"');
    assert!(
        channel.split('.').count() == 3 && channel.split('.').all(|p| p.parse::<u32>().is_ok()),
        "rust-toolchain.toml must pin an exact x.y.z version, not {}",
        channel
    );
    for wf in ["ci.yml", "release.yml"] {
        let text = std::fs::read_to_string(root.join(".github/workflows").join(wf)).unwrap();
        assert!(!text.contains("rust-toolchain@stable"), "{}", wf);
        assert!(text.contains("rustup toolchain install"), "{}", wf);
    }
}
