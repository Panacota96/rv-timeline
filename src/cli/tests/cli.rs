//! End-to-end tests of the rv-timeline binary: the contract every Rakvor CLI must meet.

use assert_cmd::Command;
use predicates::prelude::*;
use rv_timeline_core::{CASE_ROLE, CaseRole, HashAlgo, RunConfig, run};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

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

fn sample() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/evidence")
}

fn only_dir(p: &Path) -> PathBuf {
    std::fs::read_dir(p)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

#[test]
fn help_has_every_required_section() {
    let out = bin().args(["scan", "--help"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for section in [
        "DESCRIPTION:",
        "Options:",
        "EXAMPLES:",
        "EXIT CODES:",
        "FILES WRITTEN:",
        "FORENSIC NOTES:",
    ] {
        assert!(text.contains(section), "missing {}", section);
    }
    for flag in [
        "--input",
        "--input-list",
        "--recursive",
        "--hash",
        "--out",
        "--lang",
        "--actor",
        "--case",
        "--progress",
        "--case-dir",
        "--evidence",
    ] {
        assert!(text.contains(flag), "missing {}", flag);
    }
    // every option documents a default and an example
    assert!(
        text.matches("Default:").count() >= 9,
        "each option needs a Default: line"
    );
    assert!(
        text.matches("Example:").count() >= 9,
        "each option needs an Example: line"
    );
}

#[test]
fn three_hash_algorithms_are_a_usage_error() {
    bin()
        .args(["scan", "-i", "."])
        .args(["--hash", "md5,sha1,sha256"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("at most 2"));
}

#[test]
fn unknown_language_and_algorithm_are_usage_errors() {
    bin()
        .args(["scan", "-i", ".", "--lang", "de"])
        .assert()
        .code(2);
    bin()
        .args(["scan", "-i", ".", "--hash", "crc32"])
        .assert()
        .code(2);
}

#[test]
fn missing_input_is_a_runtime_error_and_is_audited() {
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["scan", "-i", "does-not-exist", "-o"])
        .arg(out.path())
        .args(["--progress", "none"])
        .assert()
        .code(1);
    let log = only_dir(&out.path().join("logs")).join("audit.jsonl");
    let text = std::fs::read_to_string(log).unwrap();
    assert!(text.contains("\"run_failed\""));
}

#[test]
fn bulk_scan_writes_reports_logs_and_verifiable_chain() {
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["scan", "-i"])
        .arg(sample())
        .args([
            "--hash",
            "sha256,blake3",
            "--lang",
            "all",
            "--case",
            "T-1",
            "--actor",
            "ci",
            "--progress",
            "none",
            "-o",
        ])
        .arg(out.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("items: 3"));
    let logs = only_dir(&out.path().join("logs"));
    let reports = only_dir(&out.path().join("reports"));
    for f in ["audit.jsonl", "audit.log", "hashes.csv", "environment.json"] {
        assert!(logs.join(f).is_file(), "{}", f);
    }
    for l in ["en", "es", "fr"] {
        for ext in ["html", "pdf"] {
            assert!(reports.join(format!("statistics.{}.{}", l, ext)).is_file());
        }
    }
    let items: Vec<_> = std::fs::read_dir(reports.join("items")).unwrap().collect();
    assert_eq!(items.len(), 3, "one folder per item");
    for item in items {
        let d = item.unwrap().path();
        for f in [
            "technical.json",
            "summary.json",
            "technical.es.pdf",
            "summary.fr.html",
        ] {
            assert!(d.join(f).is_file(), "{} in {}", f, d.display());
        }
        let pdf = std::fs::read(d.join("technical.en.pdf")).unwrap();
        assert!(pdf.starts_with(b"%PDF-") && pdf.ends_with(b"%%EOF\n"));
    }
    bin().arg("verify-log").arg(&logs).assert().code(0).stdout(
        predicate::str::contains("chain intact").and(predicate::str::contains(
            "truncation not detectable without a timestamp or case record",
        )),
    );

    // The standalone Python verifier: intact run, then a run folder without hashes.csv (reported as missing,
    // the chain is still checked).
    let py = std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    let oracle = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/verify_chain.py");
    if let Ok(o) = std::process::Command::new(&py)
        .arg(&oracle)
        .arg(&logs)
        .output()
    {
        let blake3 = std::process::Command::new(&py)
            .args(["-c", "import blake3"])
            .status()
            .is_ok_and(|s| s.success());
        if blake3 {
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
        }
        let csv = logs.join("hashes.csv");
        let saved = std::fs::read(&csv).unwrap();
        std::fs::remove_file(&csv).unwrap();
        let o = std::process::Command::new(&py)
            .arg(&oracle)
            .arg(&logs)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&o.stdout);
        assert_eq!(o.status.code(), Some(3), "{}", text);
        assert!(
            text.contains("chain: intact | register: MISSING"),
            "{}",
            text
        );
        std::fs::write(&csv, saved).unwrap();
    }

    // Tampering with one entry is detected.
    let p = logs.join("audit.jsonl");
    let text = std::fs::read_to_string(&p).unwrap();
    std::fs::write(
        &p,
        text.replacen("\"actor\":\"ci\"", "\"actor\":\"mallory\"", 1),
    )
    .unwrap();
    bin()
        .arg("verify-log")
        .arg(&p)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("BROKEN"));
}

#[test]
fn jsonl_progress_is_one_event_per_line_with_elapsed_time() {
    let out = tempfile::tempdir().unwrap();
    let o = bin()
        .args(["scan", "-i"])
        .arg(sample())
        .args(["--progress", "jsonl", "-o"])
        .arg(out.path())
        .output()
        .unwrap();
    let text = String::from_utf8(o.stdout).unwrap();
    let events: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSON line"))
        .collect();
    assert_eq!(events.first().unwrap()["event"], "run_started");
    assert_eq!(events.last().unwrap()["event"], "run_finished");
    let elapsed: Vec<u64> = events
        .iter()
        .filter(|e| e["event"] == "progress")
        .map(|e| e["elapsed_ms"].as_u64().unwrap())
        .collect();
    assert!(
        !elapsed.is_empty() && elapsed.windows(2).all(|w| w[0] <= w[1]),
        "elapsed_ms must be monotonic"
    );
}

#[test]
fn evidence_is_not_modified() {
    let ev = tempfile::tempdir().unwrap();
    let f = ev.path().join("a.bin");
    std::fs::write(&f, b"evidence").unwrap();
    let before = std::fs::metadata(&f).unwrap().modified().unwrap();
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["scan", "-i"])
        .arg(&f)
        .args(["--progress", "none", "-o"])
        .arg(out.path())
        .assert()
        .code(0);
    assert_eq!(std::fs::read(&f).unwrap(), b"evidence");
    assert_eq!(std::fs::metadata(&f).unwrap().modified().unwrap(), before);
}

#[test]
fn executable_under_another_name_exits_3() {
    let ev = tempfile::tempdir().unwrap();
    std::fs::write(ev.path().join("invoice.pdf"), b"MZ\x90\x00\x03\x00\x00\x00").unwrap();
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["scan", "-i"])
        .arg(ev.path())
        .args(["--progress", "none", "-o"])
        .arg(out.path())
        .assert()
        .code(3);
}

/// examples/sample/run.sh compares the tool's hashes.csv with expected_hashes.csv and fails on a difference.
#[test]
#[cfg(unix)]
fn sample_script_compares_the_hash_register() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/run.sh");
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
        text.contains("hashes.csv matches expected_hashes.csv (3 files"),
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
    let out = tempfile::tempdir().unwrap();
    bin()
        .env_remove("RV_NO_TIMESTAMP")
        .env("NO_PROXY", "127.0.0.1")
        .env("RV_SIGN_PASSWORD", "test")
        .args(["scan", "-i"])
        .arg(sample())
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
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("timestamp: ok"));
    let logs = only_dir(&out.path().join("logs"));
    // The TSA's CMS signature is checked; the chain only with --tsa-ca.
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("TSA signature valid"))
        .stdout(predicate::str::contains("chain not checked"))
        .stdout(
            predicate::str::contains("covers entry").and(predicate::str::is_match(
                r"truncation: entries up to #\d+ are anchored by the RFC 3161 timestamp \(timestamp-\d{5}\.json\); 3 entries after it \(timestamp_obtained, statistics_report_written, run_finished\) cannot be proven complete",
            ).unwrap()),
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
    let item = only_dir(&only_dir(&out.path().join("reports")).join("items"));
    for f in [
        "custody.json",
        "custody.fr.pdf",
        "custody.fr.html",
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
        .arg(only_dir(&out.path().join("reports")))
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
        .stdout(predicate::str::contains("truncated: timestamp-"));
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
    let out2 = tempfile::tempdir().unwrap();
    bin()
        .env_remove("RV_NO_TIMESTAMP")
        .args(["scan", "-i"])
        .arg(sample())
        .args([
            "--tsa-url",
            "http://127.0.0.1:9/tsr",
            "--progress",
            "none",
            "-o",
        ])
        .arg(out2.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("timestamp: pending"));
    let logs2 = only_dir(&out2.path().join("logs"));
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

fn case_scan(case: &Path) -> Command {
    let mut c = bin();
    c.args(["scan", "--progress", "none", "--case-dir"])
        .arg(case);
    c
}

/// Analysis-role tools (CASE_ROLE flipped by the scaffold) need registered evidence first: an intake run made
/// through the core with the role set explicitly. Intake tools register through their own CLI.
fn seed_registry(case: &Path, case_id: &str) {
    let cfg = RunConfig {
        inputs: vec![sample()],
        algorithms: vec![HashAlgo::Sha256, HashAlgo::Md5],
        actor: "seed".into(),
        case_id: Some(case_id.into()),
        jurisdiction: "fr".into(),
        case_dir: Some(case.to_path_buf()),
        case_role: CaseRole::Intake,
        ..Default::default()
    };
    run(&cfg, &mut |_| {}, &AtomicBool::new(false)).unwrap();
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

#[test]
fn case_folder_intake_verify_case_and_tampering() {
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("CASE-1");
    let intake = CASE_ROLE == CaseRole::Intake;
    if !intake {
        seed_registry(&case, "CASE-1");
    }
    let out = case_scan(&case)
        .args(["-i"])
        .arg(sample())
        .args([
            "--case",
            "CASE-1",
            "--hash",
            "sha256,md5",
            "--jurisdiction",
            "fr",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains(if intake {
            "case:   CASE-1 (intake) registered 3 (new 3)"
        } else {
            "case:   CASE-1 (analysis) registered 0 (new 0), verified 3, mismatched 0"
        }))
        .get_output()
        .stdout
        .clone();
    for f in [
        "case.json",
        "case-log.jsonl",
        "evidence/registry.json",
        "evidence/registry.csv",
    ] {
        assert!(case.join(f).is_file(), "{}", f);
    }
    assert!(!case.join("case-log.lock").exists(), "lock released");
    let run_dir = run_folder(&out);
    assert!(run_dir.starts_with(case.join("runs")));
    assert!(
        run_dir.join("logs/audit.jsonl").is_file()
            && run_dir.join("reports/statistics.en.html").is_file()
    );
    // verify-log of a run in a case: its end is anchored by run_finished in the case log.
    let run_logs = run_dir.join("logs");
    bin()
        .arg("verify-log")
        .arg(&run_logs)
        .assert()
        .code(0)
        .stdout(
            predicate::str::is_match(
                r"truncation: the final entry #\d+ is anchored by the case log \(run_finished\)",
            )
            .unwrap(),
        );
    let audit_path = run_logs.join("audit.jsonl");
    let full = std::fs::read_to_string(&audit_path).unwrap();
    let kept: Vec<&str> = full.lines().collect();
    std::fs::write(
        &audit_path,
        format!("{}\n", kept[..kept.len() - 1].join("\n")),
    )
    .unwrap();
    bin()
        .arg("verify-log")
        .arg(&run_logs)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("truncated: the case log records"));
    std::fs::write(&audit_path, &full).unwrap();
    // Directory listing order differs between filesystems: look at every item's custody form.
    let custody_ids: Vec<String> = std::fs::read_dir(run_dir.join("reports/items"))
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path().join("custody.fr.html")).unwrap())
        .collect();
    assert!(custody_ids.iter().any(|c| c.contains("E0001")));
    let runs_before = if intake { 1 } else { 2 };
    bin()
        .arg("verify-case")
        .arg(&case)
        .assert()
        .code(0)
        .stdout(predicate::str::contains(format!(
            "3 registered items, {} runs verified",
            runs_before
        )));
    // The case id may be left out once the case exists; --evidence selects registered items.
    case_scan(&case)
        .args(["--evidence", "E0002"])
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains("items: 1").and(predicate::str::contains(if intake {
                "registered 1 (new 0)"
            } else {
                "verified 1"
            })),
        );
    bin().arg("verify-case").arg(&case).assert().code(0);
    bin()
        .args(["verify-case", "--rehash"])
        .arg(&case)
        .assert()
        .code(0)
        .stdout(predicate::str::contains(
            "re-hashed 3 of 3 registered items: 3 match the registry",
        ));

    // Usage errors: another case's folder, unknown id, --evidence without --case-dir, creation without --case.
    case_scan(&case).args(["--case", "OTHER"]).assert().code(2);
    case_scan(&case)
        .args(["--evidence", "E0099"])
        .assert()
        .code(2);
    bin().args(["scan", "--evidence", "E0001"]).assert().code(2);
    case_scan(&tmp.path().join("NEW"))
        .arg("-i")
        .arg(sample())
        .assert()
        .code(2);
    let odd = tmp.path().join("ODD");
    std::fs::create_dir_all(&odd).unwrap();
    std::fs::write(odd.join("case.json"), r#"{"schema":"other/9"}"#).unwrap();
    case_scan(&odd).arg("-i").arg(sample()).assert().code(2);
    bin().arg("verify-case").arg(tmp.path()).assert().code(1);

    // A tampered case log: verify-case exit 3, and no tool extends the case.
    let log = case.join("case-log.jsonl");
    let original = std::fs::read_to_string(&log).unwrap();
    std::fs::write(&log, original.replacen("CASE-1", "CASE-X", 1)).unwrap();
    bin()
        .arg("verify-case")
        .arg(&case)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("BROKEN"));
    let runs = |c: &Path| {
        std::fs::read_dir(c.join("runs").join(TOOL))
            .unwrap()
            .count()
    };
    let before = runs(&case);
    case_scan(&case).arg("-i").arg(sample()).assert().code(3);
    assert_eq!(runs(&case), before, "no run folder in a broken case");
    std::fs::write(&log, &original).unwrap();
    // A tampered registry: detected through the digest recorded in the case log.
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

/// The other profile of this tool (RV_CROSS_PROJECT = its project folder, with .forge.json): (command, cwd).
fn other_profile() -> Option<(Vec<String>, PathBuf)> {
    let dir = PathBuf::from(std::env::var("RV_CROSS_PROJECT").ok()?);
    let forge: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(".forge.json")).ok()?).ok()?;
    if forge["profile"] == "python" {
        let py = [".venv/bin/python", ".venv/Scripts/python.exe"]
            .iter()
            .map(|p| dir.join(p))
            .find(|p| p.is_file())?;
        let module = forge["module"].as_str()?.to_string();
        Some((vec![py.display().to_string(), "-m".into(), module], dir))
    } else {
        let cmd = forge["cli_command"].as_array()?;
        Some((
            cmd.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            dir,
        ))
    }
}

fn other(cmd: &(Vec<String>, PathBuf), args: &[&std::ffi::OsStr]) -> std::process::Output {
    std::process::Command::new(&cmd.0[0])
        .args(&cmd.0[1..])
        .args(args)
        .current_dir(&cmd.1)
        .env("RV_NO_TIMESTAMP", "1")
        .output()
        .unwrap()
}

/// A case written by the other profile verifies here and the reverse (set RV_CROSS_PROJECT to run it).
#[test]
fn cross_language_case_verification() {
    if CASE_ROLE != CaseRole::Intake {
        eprintln!("skipping cross-language case test: it compares two intake reference profiles");
        return;
    }
    let Some(cmd) = other_profile() else {
        eprintln!(
            "skipping cross-language case test: set RV_CROSS_PROJECT to the other profile's project"
        );
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("CASE-X");
    let s = sample();
    let o = other(
        &cmd,
        &[
            "scan".as_ref(),
            "-i".as_ref(),
            s.as_os_str(),
            "--progress".as_ref(),
            "none".as_ref(),
            "--case-dir".as_ref(),
            case.as_os_str(),
            "--case".as_ref(),
            "CASE-X".as_ref(),
        ],
    );
    assert!(
        o.status.success(),
        "other profile intake: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    bin().arg("verify-case").arg(&case).assert().code(0);
    // This profile extends the case written by the other one (same ids), and the other verifies it.
    case_scan(&case)
        .arg("-i")
        .arg(sample())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("registered 3 (new 0)"));
    let o = other(&cmd, &["verify-case".as_ref(), case.as_os_str()]);
    assert!(
        o.status.success(),
        "other profile verify-case: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    let log = case.join("case-log.jsonl");
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::write(&log, text.replacen("\"seq\":2", "\"seq\":7", 1)).unwrap();
    let o = other(&cmd, &["verify-case".as_ref(), case.as_os_str()]);
    assert_eq!(o.status.code(), Some(3));

    // Both profiles number the same folder identically (bytewise order of the normalised path).
    let ev = tmp.path().join("order");
    for f in [
        "a/x.txt",
        "a-b/x.txt",
        "B.txt",
        "a.txt",
        "é.txt",
        "z/w.txt",
        "a b.txt",
        "a_b.txt",
    ] {
        let p = ev.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, f).unwrap();
    }
    let numbering = |out: &Path| -> Vec<(String, String)> {
        let csv = std::fs::read_to_string(only_dir(&out.join("logs")).join("hashes.csv")).unwrap();
        csv.lines()
            .skip(1)
            .map(|l| {
                let mut f = l.splitn(3, ',');
                (f.next().unwrap().to_string(), f.next().unwrap().to_string())
            })
            .collect()
    };
    let (mine, theirs) = (tmp.path().join("mine"), tmp.path().join("theirs"));
    bin()
        .args(["scan", "-r", "--progress", "none", "-i"])
        .arg(&ev)
        .arg("-o")
        .arg(&mine)
        .assert()
        .code(0);
    let o = other(
        &cmd,
        &[
            "scan".as_ref(),
            "-r".as_ref(),
            "--progress".as_ref(),
            "none".as_ref(),
            "-i".as_ref(),
            ev.as_os_str(),
            "-o".as_ref(),
            theirs.as_os_str(),
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(numbering(&mine), numbering(&theirs));
    assert_eq!(numbering(&mine).len(), 8);
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
