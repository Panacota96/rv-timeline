# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [Unreleased]

### Added
- Project scaffolded with rakvor-tool-forge (rust profile) on 2026-11-11.
- `rv-timeline build`: one cited timeline of a Rakvor case folder from the audited outputs of rv-hashinv,
  rv-pdfauth, rv-imgauth, rv-rsmf, rv-mailauth and rv-certcheck; every run verified before it is read (audit
  chain, case-log anchor, output digests), excluded runs reported as `RUN_NOT_VERIFIED`.
- Events in UTC with the original wording, offset and precision; zone-unknown events placed as written, flagged and
  counted, never converted; display zones UTC, fixed offsets, `America/Bogota`, `Europe/Paris`.
- Cross-source signals: `EXIF_AFTER_INTAKE`, `FILE_MODIFIED_AFTER_INTAKE`, `MAIL_DATE_AFTER_FIRST_HOP`,
  `PDF_REVISION_BEFORE_PREVIOUS`, `EVENT_IN_FUTURE`, `CLOCK_SKEW_SUSPECTED` (tools and Received-hops bases),
  `RUN_NOT_VERIFIED`, `ZONE_UNKNOWN_EVENTS`.
- `reports/timeline.jsonl` for Timesketch, per-item timeline reports, statistics report, `hashes.csv` of the case
  files read; external merge sort past 250 000 events.
- Desktop app with a virtualised timeline viewer (filters, display-zone toggle, signal highlighting, event
  citation) and a hash-chained review log checked by `verify-log` and `verify-case`.
- Sample case written by the six released tools, three tampered copies and `expected_timeline.json`.
- Documentation written from the code: theory (plain-language and expert parts), signals catalogue generated from
  `i18n/en.json` and checked by a test, admissibility (draft), usage, GUI, installation, development, architecture,
  case folder, handover and ADRs 0002–0004.
