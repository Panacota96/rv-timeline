//! rv-timeline command-line interface. All work happens in `rv_timeline_core`; this file only
//! parses arguments, renders events (progress bar or JSON Lines) and maps results to exit codes.

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rv_timeline_core::engine::{self, DisplayZone};
use rv_timeline_core::model::TimelineOptions;
use rv_timeline_core::trust::{self, DEFAULT_TSA};
use rv_timeline_core::{
    CASE_ROLE, Event, HashAlgo, RunConfig, TOOL_NAME, TOOL_VERSION, audit, case, hash, i18n,
    readers, run, verify,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_FINDINGS: u8 = 3;
const EXIT_CANCELLED: u8 = 130;

const ABOUT: &str = "Build one cited timeline of a Rakvor case folder from the runs of the other Rakvor tools: every run verified first, every time in UTC with its original wording, cross-source signals, a Timesketch file and court-ready reports with a tamper-evident audit log.";

const LONG_ABOUT: &str = "\
DESCRIPTION:
  rv-timeline reads a Rakvor case folder (the folder that holds case.json) and builds one timeline
  of everything the other Rakvor tools recorded about the evidence: rv-hashinv (intake, file
  times), rv-pdfauth (PDF dates and revisions), rv-imgauth (EXIF, XMP, PNG times), rv-rsmf (chat
  messages), rv-mailauth (Date and Received hops) and rv-certcheck (validity, revocation, RFC 3161
  times). It never opens the evidence itself. For the case it:
    1. verifies the case log and the evidence registry (a broken case is refused, exit 3);
    2. verifies every tool run before reading it: audit chain intact, run finished, and the
       SHA-256 of every output it reads equal to the one in the run's audit log. A run that fails
       is excluded (no event from it) and reported with the reason;
    3. reads the time values of each verified run, in UTC, keeping the original wording and a
       citation (run, output file, its SHA-256, JSON pointer) for each event;
    4. orders all events, computes cross-source signals and writes reports/timeline.jsonl
       (Timesketch), one report per evidence item and a statistics report.
  The run is written inside the case, under <CASE>/runs/rv-timeline/<RUN-ID>/, and recorded in
  the case log. Every action is appended to a hash-chained log that `rv-timeline verify-log` can
  check later; `rv-timeline verify-case <CASE>` checks the whole case.";

const BUILD_AFTER_HELP: &str = "\
EXAMPLES:
  Build the timeline of a case (UTC, English reports):
    rv-timeline build --case-dir E:\\CASE-014
  Show local times for Colombia as well, Spanish reports, check the case id:
    rv-timeline build --case-dir E:\\CASE-014 --case CASE-014 --display-zone America/Bogota --lang es
  Only mail and images, one week, French and English reports, machine-readable progress:
    rv-timeline build --case-dir E:\\CASE-014 --tool rv-mailauth,rv-imgauth \\
      --from 2026-11-01T00:00:00Z --to 2026-11-08T00:00:00Z --lang fr,en --progress jsonl
  Then verify the run's audit log and the whole case:
    rv-timeline verify-log E:\\CASE-014\\runs\\rv-timeline\\<RUN-ID>\\logs
    rv-timeline verify-case E:\\CASE-014
  Import into Timesketch: upload <CASE>/runs/rv-timeline/<RUN-ID>/reports/timeline.jsonl.

EXIT CODES:
  0    Timeline built; every run verified and no medium- or high-severity signal.
  1    Runtime error (case log locked by another tool, output not writable, signing
       certificate unreadable, ...). See the audit log.
  2    Usage error (unknown option, more than two hash algorithms, unsupported language,
       unknown display zone or tool, --from/--to not RFC 3339 or in the wrong order,
       --max-events 0, a folder that is not a case folder, --case of another case).
  3    Timeline built with at least one run excluded (not verified: chain broken, digest
       mismatch, not finished, unsupported tool version, unreadable) or at least one medium- or
       high-severity signal to review; or the case folder fails verification (nothing is written
       to it).
  130  Cancelled with Ctrl+C. Partial reports and the cancellation are written to the audit log.

FILES WRITTEN:
  Inside the case folder, <RUN> = <CASE>/runs/rv-timeline/<RUN-ID>:
  <RUN>/logs/audit.jsonl              Hash-chained log of every action (one JSON object per line):
                                      runs discovered, verified, read, excluded or skipped, events
                                      ordered, timeline written (with its digests), signals.
  <RUN>/logs/audit.log                The same actions, human-readable.
  <RUN>/logs/environment.json         Tool and dependency versions, OS, host, user, command line.
  <RUN>/logs/timestamp-<SEQ>.tsr|.json  RFC 3161 token for the audit chain head.
  <RUN>/reports/timeline.jsonl        Every event, one JSON object per line, Timesketch import
                                      format (message, datetime, timestamp_desc + the citation).
                                      Its digests are in the audit log (timeline_written).
                                      Not written with --no-timesketch.
  <RUN>/reports/statistics.json       Runs (verified, excluded with reason, skipped), events per
                                      tool and kind, signals (+ statistics.<LANG>.html and .pdf).
  <RUN>/reports/items/<NNNNN>-<NAME>/technical.json|.<LANG>.html|.<LANG>.pdf  Item timeline.
  <RUN>/reports/items/<NNNNN>-<NAME>/summary.json|.<LANG>.html|.<LANG>.pdf    Customer summary.
  <RUN>/reports/items/<NNNNN>-<NAME>/custody.json|.<es|fr>.html|.pdf|.en.html|.pdf  Custody form.
  <CASE>/case-log.jsonl               run_started and run_finished of this run are appended.
  Nothing else in the case folder changes: the other tools' runs and the evidence are only read.

FORENSIC NOTES:
  - Verification comes before reading: a run whose audit chain is broken, that did not finish,
    or whose output differs from the digest in its own audit log is excluded, never read. The
    exclusion and its reason are in the audit log, the statistics report and a RUN_NOT_VERIFIED
    signal.
  - In this version the only sources are the outputs of Rakvor tool runs in the case folder; the
    evidence files are not opened. A time no tool recorded is not in the timeline.
  - Times are kept as the source wrote them (original) and placed in UTC. A source without a
    time zone (e.g. EXIF without OffsetTime) is never converted with a guessed zone: the event
    is placed as if it were UTC, marked zone unknown and counted (ZONE_UNKNOWN_EVENTS).
    --display-zone only adds a local-time column; ordering is always by UTC.
  - A signal shows that events from different sources disagree in time (e.g. an EXIF date after
    the intake, a mail Date after its first hop). It does not show who changed what, or that a
    file was tampered with: clocks can be wrong or skewed (--clock-skew), and every signal says
    what it does not prove. An empty signal list does not prove the evidence is authentic.
  - --tool, --from/--to and --max-events narrow the timeline; what was left out is recorded in
    the audit log and printed in the reports, never silent.
  - Each audit entry stores the SHA-256 of the previous one; the run's audit head is recorded in
    the case log, so the two chains vouch for each other. The chain head is timestamped by an
    RFC 3161 authority; offline, the run finishes with `timestamp_pending`: run
    `rv-timeline timestamp <LOG>` later.
  - With --sign-cert every PDF is signed with the examiner's certificate; the password is never
    logged.";

#[derive(Parser)]
#[command(name = TOOL_NAME, version = TOOL_VERSION, about = ABOUT, long_about = LONG_ABOUT, max_term_width = 100,
          after_long_help = "Run `rv-timeline <COMMAND> --help` for the options, examples and exit codes of each command.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build the timeline of a case folder from the verified runs of the other Rakvor tools.
    #[command(long_about = LONG_ABOUT, after_long_help = BUILD_AFTER_HELP)]
    Build(Box<BuildArgs>),
    /// Verify an audit log (audit.jsonl): edited, deleted or re-ordered entries, and truncation.
    #[command(after_long_help = "\
CHECKS:
  - every entry links to the previous one (hash chain): an edited, deleted or re-ordered entry
    breaks it;
  - every timestamp token the log records (timestamp_obtained) is still next to it with its
    metadata (timestamp-<SEQ>.tsr with the recorded SHA-256, timestamp-<SEQ>.json agreeing): a
    missing file is a problem, never a skipped check; a token file no entry records is checked
    too. Every token covers the hash of the entry it names;
  - the TSA's CMS signature of every token: signer certificate in the token, ESS
    signing-certificate binding, message digest over TSTInfo, RSA signature, and an extended key
    usage that is critical and only timeStamping (RFC 3161). With --tsa-ca, also the TSA
    certificate path up to that CA bundle at the token's genTime (every candidate issuer tried;
    CA flag, keyCertSign, pathLenConstraint, directoryName name constraints, no unsupported
    critical extension); without it the output says \"chain not checked\". Revocation is
    never checked: establish it from CRL/OCSP evidence covering genTime;
  - truncation: a chain alone cannot show that entries were removed from its end. The log must
    still contain the entry covered by its RFC 3161 timestamp (covers_seq) and, for a run inside
    a case folder (<CASE>/runs/<TOOL>/<RUN-ID>/logs), end with the audit head that the case log
    recorded at run_finished (only timestamp_obtained may follow). Entries after the last
    anchored one are listed as not provable; with neither record the output says
    \"truncation not detectable without a timestamp or case record\".
  - the review log (review.jsonl next to audit.jsonl, written when the timeline is viewed after
    the run): its chain, its anchor to this run's run_finished entry and the run id of every
    entry. The output prints its entry count (\"review log: none\" when there is none); an
    edited or misplaced review log is a problem.

EXAMPLES:
  rv-timeline verify-log rakvor-out/logs/20261019T101500Z-a1b2c3/audit.jsonl
  rv-timeline verify-log rakvor-out/logs/20261019T101500Z-a1b2c3
  rv-timeline verify-log E:\\CASE-014\\runs\\rv-timeline\\20261019T101500Z-a1b2c3\\logs
  rv-timeline verify-log rakvor-out/logs/20261019T101500Z-a1b2c3 --tsa-ca digicert-tsa-roots.pem

EXIT CODES:
  0  The chain is intact and agrees with its timestamps and case record (if any).
  1  The log or the --tsa-ca file cannot be read.
  3  The chain is broken (an entry was edited, deleted or re-ordered), a timestamp does not
     match or does not verify (altered token, invalid TSA signature, chain not trusted by
     --tsa-ca), or the log is shorter than its timestamp or case record says (truncated).")]
    VerifyLog {
        /// Path to audit.jsonl, or to the run's log folder that contains it.
        ///
        /// Example: rakvor-out/logs/20261019T101500Z-a1b2c3
        log: PathBuf,
        /// CA bundle (PEM with one or more certificates, or one DER certificate) that the TSA
        /// certificate of every timestamp token must chain to, at the token's genTime.
        ///
        /// Default: none (the TSA signature is checked, the chain is not).
        /// Example: --tsa-ca C:\certs\tsa-roots.pem
        #[arg(long, value_name = "PEM", verbatim_doc_comment)]
        tsa_ca: Option<PathBuf>,
    },
    /// Check every hash algorithm against known-answer test vectors.
    #[command(after_long_help = "\
EXAMPLES:
  rv-timeline self-test

EXIT CODES:
  0  All algorithms give the published answer for the input \"abc\".
  1  At least one algorithm failed: do not use this build for evidence.")]
    SelfTest,
    /// Add an RFC 3161 timestamp to a finished run (e.g. after working offline).
    #[command(after_long_help = "\
EXAMPLES:
  rv-timeline timestamp rakvor-out/logs/20261019T101500Z-a1b2c3
  rv-timeline timestamp rakvor-out/logs/20261019T101500Z-a1b2c3 --tsa-url https://freetsa.org/tsr

EXIT CODES:
  0  Timestamp obtained and logged.
  1  The TSA could not be reached (nothing changed; try again).
  3  The log is missing or broken: no timestamp is added.")]
    Timestamp {
        /// The run's log folder (or its audit.jsonl).
        ///
        /// Example: rakvor-out/logs/20261019T101500Z-a1b2c3
        log: PathBuf,
        /// RFC 3161 time-stamping authority.
        /// Default: http://timestamp.digicert.com
        /// Example: --tsa-url https://freetsa.org/tsr
        #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
        tsa_url: String,
        /// Name written in the new audit entry.
        /// Default: the operating-system user name
        /// Example: --actor "Ana Ruiz"
        #[arg(short, long, value_name = "NAME", verbatim_doc_comment)]
        actor: Option<String>,
    },
    /// Verify a whole case folder: case log, evidence registry and every run's audit log.
    #[command(after_long_help = "\
CHECKS:
  - case-log.jsonl is an intact hash chain starting with case_created; case.json is unchanged;
  - evidence/registry.json has the SHA-256 recorded at the last registry change;
  - every run announced in the case log has an intact audit.jsonl (and valid timestamp
    tokens: imprint and TSA signature; the TSA chain is not checked, use verify-log
    --tsa-ca), its case_linked entry points to its run_started entry, and the audit head
    recorded at run_finished is its final entry (only timestamp_obtained may follow);
  - every run's review log (review.jsonl, viewing after the run), when present: its chain and its
    anchor to that run; the output prints the review entries counted across the runs;
  - with --rehash: every registered item still reachable at its registered path is read again
    and its digests are compared with the registry (the latest registration of a path).

EXAMPLES:
  rv-timeline verify-case E:\\CASE-014
  rv-timeline verify-case E:\\CASE-014 --rehash

EXIT CODES:
  0  The case folder is intact (warnings, e.g. a run still in progress or an item not
     reachable for --rehash, are printed).
  1  The folder is not a case folder (no case.json).
  3  At least one check failed: the case was edited, truncated or re-ordered, or (--rehash)
     an evidence file differs from the registry.")]
    VerifyCase {
        /// The case folder (the one that holds case.json).
        ///
        /// Example: E:\CASE-014
        case: PathBuf,
        /// Also re-hash every registered item still reachable and compare it with the registry.
        /// Default: off (only the registry's digest is checked)
        /// Example: --rehash
        #[arg(long, verbatim_doc_comment)]
        rehash: bool,
    },
    /// Print the full help of every command as Markdown (used to generate docs/usage-cli.md).
    #[command(hide = true)]
    DocsCli,
    /// Describe this tool as JSON (schema rakvor.describe/1) for RV Hub and scripts.
    #[command(hide = true, after_long_help = DESCRIBE_AFTER_HELP)]
    Describe {
        /// Print JSON: one pretty-printed object with sorted keys.
        /// Default: on (JSON is the only format)
        /// Example: --json
        #[arg(long, verbatim_doc_comment)]
        json: bool,
    },
}

const DESCRIBE_AFTER_HELP: &str = "\
DESCRIPTION:
  Prints what this tool is, what it accepts and how to launch it, validated by
  schemas/describe.schema.json. RV Hub reads it to list the tool and start its GUI on a case
  folder (rv-timeline-gui.exe --case-dir <CASE>). rv-timeline's input is a case folder, not
  evidence files: the files it reads are the case's JSON documents and JSON Lines logs and the
  other tools' JSON outputs, so it is never suggested for an evidence file.
  Fields: schema, tool, title, version, role (analysis), main_verb (build), accepts (json,
  jsonl; no signature), case_formats, log_formats, cli_exe, gui_exe, exit_codes. Nothing is
  read or written; no audit log is created.

EXAMPLES:
  rv-timeline describe --json

EXIT CODES:
  0  The description was printed.";

#[derive(Clone, Copy, ValueEnum)]
enum ProgressMode {
    /// Progress bar with elapsed time and the runs done on stderr.
    Bar,
    /// One JSON event per line on stdout (for scripts and other tools).
    Jsonl,
    /// No progress output; only the final summary.
    None,
}

#[derive(Args)]
struct BuildArgs {
    /// The case folder to read (the one that holds case.json), written by the other Rakvor tools.
    /// The timeline run is written inside it, under <DIR>/runs/rv-timeline/<RUN-ID>/.
    /// Default: none (required)
    /// Example: --case-dir E:\CASE-014
    #[arg(long, value_name = "DIR", verbatim_doc_comment)]
    case_dir: PathBuf,

    /// Zone the reports show times in, next to UTC: UTC, a fixed offset (-05:00, +01:00), or
    /// America/Bogota or Europe/Paris (summer time built in). Events are always ordered by UTC;
    /// an event whose source has no zone is never converted.
    /// Default: UTC
    /// Example: --display-zone America/Bogota
    #[arg(
        long,
        value_name = "ZONE",
        default_value = "UTC",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    display_zone: String,

    /// Only the runs of these tools, comma-separated or repeated: rv-hashinv, rv-pdfauth,
    /// rv-imgauth, rv-rsmf, rv-mailauth, rv-certcheck. Other runs are skipped and logged.
    /// Default: every supported tool
    /// Example: --tool rv-mailauth,rv-imgauth
    #[arg(
        long = "tool",
        value_name = "TOOL",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    tools: Vec<String>,

    /// Only events at or after this instant (RFC 3339, e.g. 2026-11-01T00:00:00Z or with an
    /// offset, 2026-11-01T00:00:00-05:00).
    /// Default: no lower bound
    /// Example: --from 2026-11-01T00:00:00Z
    #[arg(long, value_name = "TIME", verbatim_doc_comment)]
    from: Option<String>,

    /// Only events at or before this instant (RFC 3339).
    /// Default: no upper bound
    /// Example: --to 2026-11-30T23:59:59Z
    #[arg(long, value_name = "TIME", verbatim_doc_comment)]
    to: Option<String>,

    /// Difference in seconds tolerated between two sources' clocks before their order becomes a
    /// signal (smaller differences are within clock skew).
    /// Default: 300
    /// Example: --clock-skew 120
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 300,
        verbatim_doc_comment,
        hide_default_value = true
    )]
    clock_skew: u64,

    /// Stop reading after this many events (the earliest of the last run read are kept). Reaching
    /// it is recorded in the audit log and the reports, never silent.
    /// Default: 5000000
    /// Example: --max-events 100000
    #[arg(
        long,
        value_name = "N",
        default_value_t = 5_000_000,
        value_parser = clap::value_parser!(u64).range(1..),
        verbatim_doc_comment,
        hide_default_value = true
    )]
    max_events: u64,

    /// Do not write reports/timeline.jsonl (the Timesketch import file).
    /// Default: off (timeline.jsonl is written and its digests logged)
    /// Example: --no-timesketch
    #[arg(long, verbatim_doc_comment)]
    no_timesketch: bool,

    /// Hash algorithm(s) for the files this run writes (timeline.jsonl, reports, logs): one or
    /// two of md5, sha1, sha256, sha512, sha3-256, blake3. More than two is refused (exit code 2).
    /// Default: sha256
    /// Example: --hash sha256,md5
    #[arg(
        short = 'H',
        long = "hash",
        value_name = "ALGO",
        value_delimiter = ',',
        default_value = "sha256",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    hashes: Vec<String>,

    /// Not used by build: every output goes inside the case folder (<CASE>/runs/rv-timeline/).
    /// Accepted so that scripts shared with the other Rakvor tools keep working.
    /// Default: ./rakvor-out (ignored)
    /// Example: --out E:\case-014\rv-timeline
    #[arg(
        short,
        long,
        value_name = "DIR",
        default_value = "rakvor-out",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    out: PathBuf,

    /// Report language(s): en, es, fr (comma-separated), or all. JSON is language-neutral.
    /// Default: en
    /// Example: --lang es   or   --lang all
    #[arg(
        short,
        long,
        value_name = "LANG",
        default_value = "en",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    lang: String,

    /// Name of the examiner, written in every audit entry and report (alias: --examiner).
    /// Default: the operating-system user name
    /// Example: --actor "Ana Ruiz"
    #[arg(
        short,
        long,
        alias = "examiner",
        value_name = "NAME",
        verbatim_doc_comment
    )]
    actor: Option<String>,

    /// Case identifier: when given, it must match the case folder's case.json (exit 2 otherwise).
    /// Default: none (the case id is read from case.json)
    /// Example: --case CASE-2026-014
    #[arg(short, long = "case", value_name = "ID", verbatim_doc_comment)]
    case_id: Option<String>,

    /// How progress is shown: bar, jsonl or none.
    /// Default: bar (hidden automatically when stderr is not a terminal)
    /// Example: --progress jsonl
    #[arg(
        short,
        long,
        value_enum,
        value_name = "MODE",
        default_value = "bar",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    progress: ProgressMode,

    /// Chain-of-custody form per item: co (Colombia, Fiscalía style, Spanish) or fr (France,
    /// scellés, French); an English copy is always added. The case's own jurisdiction
    /// (case.json) applies; the value given here is recorded as requested.
    /// Default: co
    /// Example: --jurisdiction fr
    #[arg(short, long, value_name = "CC", default_value = "co", value_parser = ["co", "fr"], verbatim_doc_comment, hide_default_value = true, hide_possible_values = true)]
    jurisdiction: String,

    /// RFC 3161 time-stamping authority for the audit chain head.
    /// Default: http://timestamp.digicert.com
    /// Example: --tsa-url https://freetsa.org/tsr
    #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
    tsa_url: String,

    /// Do not request a trusted timestamp (offline labs). Also set by RV_NO_TIMESTAMP=1.
    /// Default: off (a timestamp is requested)
    /// Example: --no-timestamp
    #[arg(long, env = "RV_NO_TIMESTAMP", value_parser = clap::builder::FalseyValueParser::new(), verbatim_doc_comment, hide_env = true)]
    no_timestamp: bool,

    /// Examiner's certificate (.p12/.pfx, RSA) used to sign every PDF report. The password is read
    /// from the environment variable named by --sign-pass-env, or asked for interactively.
    /// Default: none (PDFs are not signed)
    /// Example: --sign-cert C:\certs\ana-ruiz.p12
    #[arg(long, value_name = "P12", verbatim_doc_comment)]
    sign_cert: Option<PathBuf>,

    /// Environment variable holding the certificate password.
    /// Default: RV_SIGN_PASSWORD
    /// Example: --sign-pass-env CERT_PASS
    #[arg(
        long,
        value_name = "VAR",
        default_value = "RV_SIGN_PASSWORD",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    sign_pass_env: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    ExitCode::from(match cli.command {
        Command::Build(a) => build(*a),
        Command::VerifyLog { log, tsa_ca } => verify_log(log, tsa_ca),
        Command::VerifyCase { case, rehash } => verify_case(case, rehash),
        Command::SelfTest => self_test(),
        Command::Timestamp {
            log,
            tsa_url,
            actor,
        } => timestamp(log, tsa_url, actor),
        Command::DocsCli => {
            print!("{}", docs_cli());
            EXIT_OK
        }
        Command::Describe { json: _ } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&describe()).expect("describe is valid JSON")
            );
            EXIT_OK
        }
    })
}

fn usage_error(msg: &str) -> u8 {
    eprintln!(
        "error: {}\n\nFor more information, try 'rv-timeline build --help'.",
        msg
    );
    EXIT_USAGE
}

/// Tools the built-in readers understand (the values --tool accepts).
fn supported_tools() -> Vec<String> {
    readers::all()
        .iter()
        .map(|r| r.tool().to_string())
        .collect()
}

/// Checks every option and the case folder before anything is written: usage problems give exit 2,
/// a case that fails verification exit 3.
fn options(a: &BuildArgs) -> Result<(Vec<HashAlgo>, Vec<String>, TimelineOptions), u8> {
    let mut algos = Vec::new();
    for h in &a.hashes {
        match HashAlgo::parse(h) {
            Some(x) => algos.push(x),
            None => {
                return Err(usage_error(&format!(
                    "unknown hash algorithm '{}': use md5, sha1, sha256, sha512, sha3-256 or blake3",
                    h
                )));
            }
        }
    }
    hash::validate_selection(&algos).map_err(|e| usage_error(&e))?;
    let langs = i18n::parse_langs(&a.lang).map_err(|e| usage_error(&e))?;
    let zone = DisplayZone::parse(&a.display_zone).map_err(|e| usage_error(&e))?;
    let known = supported_tools();
    let mut tools: Vec<String> = Vec::new();
    for t in a.tools.iter().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        if !known.iter().any(|k| k == t) {
            return Err(usage_error(&format!(
                "unknown tool '{}': use {}",
                t,
                known.join(", ")
            )));
        }
        if !tools.iter().any(|x| x == t) {
            tools.push(t.to_string());
        }
    }
    let time = |name: &str, v: &Option<String>| -> Result<Option<i64>, u8> {
        match v {
            None => Ok(None),
            Some(s) => engine::parse_rfc3339(s).map(Some).ok_or_else(|| {
                usage_error(&format!(
                    "{} '{}' is not an RFC 3339 time: use e.g. 2026-11-01T00:00:00Z",
                    name, s
                ))
            }),
        }
    };
    let from_s = time("--from", &a.from)?;
    let to_s = time("--to", &a.to)?;
    if let (Some(f), Some(t)) = (from_s, to_s)
        && f > t
    {
        return Err(usage_error("--from is later than --to"));
    }
    let dir = &a.case_dir;
    if !dir.join(case::CASE_FILE).is_file() {
        return Err(usage_error(&format!(
            "{} is not a case folder (no {}): rv-timeline reads a case written by the other Rakvor tools and never creates one",
            dir.display(),
            case::CASE_FILE
        )));
    }
    // Case problems found before the run map to their own exit codes (2 another case, 3 broken case).
    if let Err(e) = case::preflight(dir, a.case_id.as_deref(), &[]) {
        return Err(match e.exit_code() {
            EXIT_USAGE => usage_error(&e.message),
            code => {
                eprintln!("error: {}", e.message);
                code
            }
        });
    }
    let opts = TimelineOptions {
        case_dir: dir.clone(),
        display_zone: zone.name(),
        tools,
        from_s,
        to_s,
        clock_skew_s: a.clock_skew,
        max_events: a.max_events,
        timesketch: !a.no_timesketch,
    };
    Ok((algos, langs, opts))
}

/// What the run's own audit log says about it (read back for the summary, so the summary never
/// says more than the log).
#[derive(Default)]
struct AuditFacts {
    events: u64,
    runs_verified: u64,
    zone_unknown: u64,
    skipped: u64,
    excluded: Vec<String>,
    timeline_written: bool,
}

fn audit_facts(log_dir: &Path, own_run_id: &str) -> AuditFacts {
    let mut f = AuditFacts::default();
    let text = std::fs::read_to_string(log_dir.join("audit.jsonl")).unwrap_or_default();
    for line in text.lines() {
        let Ok(e) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let d = &e["details"];
        match e["action"].as_str().unwrap_or_default() {
            "run_excluded" => f.excluded.push(format!(
                "{} ({}{}{})",
                d["run_dir"].as_str().unwrap_or("-"),
                d["reason"].as_str().unwrap_or("-"),
                if d["detail"].as_str().unwrap_or("").is_empty() {
                    ""
                } else {
                    ": "
                },
                d["detail"].as_str().unwrap_or("")
            )),
            // This run is in the case log too and is skipped as "self": not counted.
            "run_skipped" if d["run_id"].as_str() != Some(own_run_id) => f.skipped += 1,
            "timeline_written" => f.timeline_written = true,
            "signals_computed" => f.zone_unknown = d["zone_unknown_events"].as_u64().unwrap_or(0),
            "run_finished" => {
                f.events = d["events"].as_u64().unwrap_or(0);
                f.runs_verified = d["runs_verified"].as_u64().unwrap_or(0);
            }
            _ => {}
        }
    }
    f
}

fn build(a: BuildArgs) -> u8 {
    let (algos, langs, opts) = match options(&a) {
        Ok(x) => x,
        Err(code) => return code,
    };

    let cancel = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    let _ = ctrlc::set_handler(move || c.store(true, Ordering::SeqCst));

    let cfg = RunConfig {
        inputs: vec![],
        input_list: None,
        recursive: false,
        algorithms: algos,
        out_dir: a.out.clone(),
        langs,
        actor: a
            .actor
            .clone()
            .unwrap_or_else(rv_timeline_core::env::os_user),
        case_id: a.case_id.clone(),
        frontend: "cli".into(),
        preamble: vec![],
        command_line: std::env::args().collect(),
        tool_name: TOOL_NAME.into(),
        tool_version: TOOL_VERSION.into(),
        jurisdiction: a.jurisdiction.clone(),
        tsa_url: if a.no_timestamp {
            None
        } else {
            Some(a.tsa_url.clone())
        },
        sign_password: a
            .sign_cert
            .as_ref()
            .and_then(|_| password(&a.sign_pass_env)),
        sign_cert: a.sign_cert.clone(),
        case_dir: Some(a.case_dir.clone()),
        evidence_ids: vec![],
        case_role: CASE_ROLE,
    };

    let bar = match a.progress {
        ProgressMode::Bar => {
            let b = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::stderr_with_hz(8));
            b.set_style(
                ProgressStyle::with_template(
                    "{spinner} [{elapsed_precise}] {wide_bar} {pos}/{len} runs {msg}",
                )
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
            );
            Some(b)
        }
        _ => None,
    };
    let jsonl = matches!(a.progress, ProgressMode::Jsonl);
    let mut excluded_runs = 0u64;
    // A closed stdout (e.g. `| head`) must never abort a forensic run half-way: stop printing, keep working.
    let mut stdout_open = true;
    let mut sink = |e: &Event| {
        if let Event::ItemFinished { status, .. } = e
            && status == "excluded"
        {
            excluded_runs += 1;
        }
        if jsonl && stdout_open {
            let mut out = std::io::stdout().lock();
            stdout_open = writeln!(out, "{}", serde_json::to_string(e).unwrap_or_default())
                .and_then(|_| out.flush())
                .is_ok();
        }
        if let Some(b) = &bar {
            match e {
                Event::RunStarted { total_items, .. } => b.set_length(*total_items),
                Event::Progress { done, .. } => b.set_position(*done),
                Event::ItemFinished {
                    path,
                    status,
                    findings,
                    ..
                } if status == "excluded" => b.println(format!(
                    "warning: run excluded (not verified): {} ({})",
                    path,
                    findings.join(", ")
                )),
                Event::Error { path, message } => b.println(format!(
                    "warning: {}: {}",
                    path.as_deref().unwrap_or("-"),
                    message
                )),
                Event::Cancelled { .. } => b.println("cancelled: writing partial reports..."),
                Event::Timestamp { status, reason, .. } if status != "ok" => b.println(format!(
                    "warning: timestamp pending ({}); run `rv-timeline timestamp` later",
                    reason.as_deref().unwrap_or("-")
                )),
                _ => {}
            }
        }
    };
    let result = run::run_timeline(&cfg, &opts, &mut sink, &cancel);
    if let Some(b) = &bar {
        b.finish_and_clear();
    }
    let s = match result {
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
        Ok(s) => s,
    };
    let facts = audit_facts(&s.log_dir, &s.run_id);
    let excluded = excluded_runs.max(facts.excluded.len() as u64);
    let to_review = excluded > 0 || s.high > 0 || s.medium > 0;
    if jsonl {
        // stdout carries only JSON events; exclusions are repeated on stderr for the operator.
        for x in &facts.excluded {
            eprintln!("warning: run excluded (not verified): {}", x);
        }
    } else {
        let timeline = if facts.timeline_written {
            s.report_dir.join("timeline.jsonl").display().to_string()
        } else {
            "not written (--no-timesketch)".into()
        };
        let mut out = format!(
            "{status}  run {id}\n  case:     {case}\n  runs:     verified {verified}, excluded {excluded}, skipped {skipped}\n  events:   {events} (zone unknown: {zu})  items: {items}  elapsed: {elapsed}\n  signals:  high {h}, medium {m}, low {l}, info {i}\n  timeline: {timeline}\n  timestamp: {ts}\n  report:   {report}\n  logs:     {logs}",
            status = if s.cancelled {
                "CANCELLED"
            } else if to_review {
                "DONE (to review: excluded runs or medium/high signals)"
            } else {
                "DONE"
            },
            id = s.run_id,
            case = s
                .case
                .as_ref()
                .map(|c| c.case_id.clone())
                .unwrap_or_default(),
            verified = facts.runs_verified,
            skipped = facts.skipped,
            events = facts.events,
            zu = facts.zone_unknown,
            items = s.items,
            elapsed = rv_timeline_core::time::human_duration(s.elapsed_ms),
            h = s.high,
            m = s.medium,
            l = s.low,
            i = s.info,
            ts = format!(
                "{} {}",
                s.timestamp["status"].as_str().unwrap_or("off"),
                s.timestamp["gen_time"].as_str().unwrap_or("")
            )
            .trim(),
            report = s
                .report_dir
                .join(format!("statistics.{}.html", cfg.langs[0]))
                .display(),
            logs = s.log_dir.display()
        );
        for x in &facts.excluded {
            out.push_str(&format!("\n  excluded: {}", x));
        }
        let _ = writeln!(std::io::stdout(), "{}", out);
    }
    if s.cancelled {
        EXIT_CANCELLED
    } else if to_review {
        EXIT_FINDINGS
    } else {
        EXIT_OK
    }
}

fn password(env: &str) -> Option<String> {
    if let Ok(p) = std::env::var(env) {
        return Some(p);
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        // No echo: the password never appears on screen or in a terminal recording.
        return rpassword::prompt_password("Certificate password: ").ok();
    }
    None
}

fn timestamp(log: PathBuf, tsa_url: String, actor: Option<String>) -> u8 {
    let dir = if log.is_file() {
        log.parent().map(|p| p.to_path_buf()).unwrap_or_default()
    } else {
        log
    };
    if !dir.join("audit.jsonl").is_file() {
        eprintln!(
            "error: no audit log at {}: nothing to timestamp",
            dir.join("audit.jsonl").display()
        );
        return EXIT_FINDINGS;
    }
    let mut audit_log = match audit::AuditLog::resume(
        &dir,
        &actor.unwrap_or_else(rv_timeline_core::env::os_user),
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_FINDINGS;
        }
    };
    match trust::timestamp_head(&dir, audit_log.entries(), audit_log.head(), &tsa_url) {
        Ok(ts) => {
            if let Err(e) = audit_log.record("timestamp_obtained", Some(&ts.file), ts.to_json()) {
                eprintln!("error: {}", e);
                return EXIT_ERROR;
            }
            println!(
                "OK  timestamp {} by {} covers entry #{}",
                ts.gen_time, ts.tsa, ts.covers_seq
            );
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {}", e);
            EXIT_ERROR
        }
    }
}

fn verify_log(log: PathBuf, tsa_ca: Option<PathBuf>) -> u8 {
    let path = if log.is_dir() {
        log.join("audit.jsonl")
    } else {
        log
    };
    let anchors = match tsa_ca.as_deref().map(trust::load_ca_bundle).transpose() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
    };
    let v = match verify::verify_log_with(&path, anchors.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
    };
    if v.problems.is_empty() {
        println!(
            "OK  {} entries, chain intact: {}",
            v.entries,
            path.display()
        );
        for t in &v.timestamps {
            println!("    {}", t);
        }
        println!("    {}", v.truncation);
        match v.review_entries {
            Some(n) => println!("    review log: {} entries, chain intact", n),
            None => println!("    review log: none"),
        }
    } else {
        println!("BROKEN  {}", path.display());
        for p in &v.problems {
            println!("  - {}", p);
        }
    }
    for w in &v.warnings {
        println!("  warning: {}", w);
    }
    if v.problems.is_empty() {
        EXIT_OK
    } else {
        EXIT_FINDINGS
    }
}

fn verify_case(dir: PathBuf, rehash: bool) -> u8 {
    if !dir.join(case::CASE_FILE).is_file() {
        eprintln!(
            "error: {} is not a case folder (no {})",
            dir.display(),
            case::CASE_FILE
        );
        return EXIT_ERROR;
    }
    let mut v = case::verify_case(&dir);
    let rehashed = rehash.then(|| case::rehash_registry(&dir, &mut v));
    if v.problems.is_empty() {
        println!(
            "OK  case {}: {} case-log entries, {} registered items, {} runs verified: {}",
            v.case_id,
            v.entries,
            v.registry_items,
            v.runs,
            dir.display()
        );
        println!(
            "    review logs: {} entries across the runs, all verified",
            v.review_entries
        );
        if let Some(r) = &rehashed {
            println!(
                "    re-hashed {} of {} registered items: {} match the registry",
                r.checked, r.registered, r.matched
            );
        }
        for w in &v.warnings {
            println!("  warning: {}", w);
        }
        EXIT_OK
    } else {
        println!("BROKEN  case {}: {}", v.case_id, dir.display());
        for p in &v.problems {
            println!("  - {}", p);
        }
        if let Some(r) = &rehashed {
            println!(
                "    re-hashed {} of {} registered items: {} match the registry",
                r.checked, r.registered, r.matched
            );
        }
        for w in &v.warnings {
            println!("  warning: {}", w);
        }
        EXIT_FINDINGS
    }
}

fn self_test() -> u8 {
    let failed = hash::self_test();
    for (algo, _) in hash::KNOWN_ANSWERS {
        println!(
            "{:<9} {}",
            algo.name(),
            if failed.contains(&algo) {
                "FAIL"
            } else {
                "PASS"
            }
        );
    }
    if failed.is_empty() {
        EXIT_OK
    } else {
        EXIT_ERROR
    }
}

/// The tool's self-description (`describe --json`, schema rakvor.describe/1; see schemas/describe.schema.json).
/// serde_json sorts the keys (no preserve_order feature), so the output is stable.
fn describe() -> serde_json::Value {
    serde_json::json!({
        "schema": "rakvor.describe/1",
        "tool": TOOL_NAME,
        "title": "RV Timeline",
        "version": TOOL_VERSION,
        "role": CASE_ROLE.name(),
        "main_verb": "build",
        // The input is a case folder: the files read directly are the case's JSON documents and JSON Lines
        // logs and the other tools' JSON outputs. No evidence signature: never suggested for an evidence file.
        "accepts": {"extensions": ["json", "jsonl"], "signatures": []},
        "case_formats": [case::SCHEMA_CASE],
        "log_formats": ["rakvor.audit/1"],
        "cli_exe": format!("{}.exe", TOOL_NAME),
        "gui_exe": format!("{}-gui.exe", TOOL_NAME),
        "exit_codes": {
            "0": "Timeline built; every run verified and no medium- or high-severity signal.",
            "1": "Runtime error (case log locked, output not writable, ...).",
            "2": "Usage error (unknown option, bad value, not a case folder, case folder of another case).",
            "3": "Timeline built with an excluded run or a medium/high-severity signal to review, or the case folder fails verification.",
            "130": "Cancelled with Ctrl+C; partial reports and the cancellation are in the audit log."
        }
    })
}

/// Markdown of every command's long help, so docs/usage-cli.md can never drift from the binary.
fn docs_cli() -> String {
    let mut root = Cli::command().term_width(100);
    root.build();
    let mut out = String::from(
        "# Command-line reference\n\n<!-- Generated by `rv-timeline docs-cli`. Do not edit by hand: CI fails if this file differs. -->\n\n",
    );
    out.push_str("```mermaid\nflowchart LR\n  A[rv-timeline] --> B[build]\n  A --> C[verify-log]\n  A --> D[self-test]\n  A --> T[timestamp]\n  A --> V[verify-case]\n  K[(CASE folder<br/>runs of the other tools)] -- verified, read --> B\n  B --> E[(runs/rv-timeline/RUN-ID/logs)]\n  B --> F[(runs/rv-timeline/RUN-ID/reports<br/>timeline.jsonl)]\n  V --> K\n  T --> E\n  C --> E\n```\n\n");
    out.push_str(&format!(
        "## rv-timeline\n\n```text\n{}\n```\n\n",
        root.render_long_help().to_string().trim_end()
    ));
    let names: Vec<String> = root
        .get_subcommands()
        // `describe` is hidden from the command list but documented (RV Hub reads it).
        .filter(|c| (!c.is_hide_set() || c.get_name() == "describe") && c.get_name() != "help")
        .map(|c| c.get_name().to_string())
        .collect();
    for name in names {
        let sub = root.find_subcommand_mut(&name).expect("subcommand");
        let mut sub = sub.clone().bin_name(format!("rv-timeline {}", name));
        out.push_str(&format!(
            "## rv-timeline {}\n\n```text\n{}\n```\n\n",
            name,
            sub.render_long_help().to_string().trim_end()
        ));
    }
    out
}
