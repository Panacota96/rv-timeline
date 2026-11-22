# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [0.4.1](https://github.com/Panacota96/rv-timeline/compare/v0.4.0...v0.4.1) (2026-11-22)


### Bug Fixes

* **readers:** read the release-check minors (they were excluded as unsupported_version) ([#19](https://github.com/Panacota96/rv-timeline/issues/19)) ([b5143cf](https://github.com/Panacota96/rv-timeline/commit/b5143cf52393fe3308383628b39bcc65acf8c7b6))

## [0.4.0](https://github.com/Panacota96/rv-timeline/compare/v0.3.0...v0.4.0) (2026-11-21)


### Features

* **update:** check for a newer release (update-check, start-up banner) ([#17](https://github.com/Panacota96/rv-timeline/issues/17)) ([db74529](https://github.com/Panacota96/rv-timeline/commit/db74529982197ea445625e6c49813ad5580cc32d))

## [0.3.0](https://github.com/Panacota96/rv-timeline/compare/v0.2.3...v0.3.0) (2026-11-20)


### Features

* **readers:** read rv-avauth runs and skip rv-report runs (they made every build exit 3) ([#15](https://github.com/Panacota96/rv-timeline/issues/15)) ([2b8692f](https://github.com/Panacota96/rv-timeline/commit/2b8692fa94fff72058cdae14d8e50e6a5ede8fbd))

## [0.2.3](https://github.com/Panacota96/rv-timeline/compare/v0.2.2...v0.2.3) (2026-11-19)


### Bug Fixes

* **readers:** read rv-hashinv 0.5 runs (they were excluded as unsupported_version) ([#12](https://github.com/Panacota96/rv-timeline/issues/12)) ([22be488](https://github.com/Panacota96/rv-timeline/commit/22be488e61c95088dc98f251e5560096382dd05c))

## [0.2.2](https://github.com/Panacota96/rv-timeline/compare/v0.2.1...v0.2.2) (2026-11-19)


### Bug Fixes

* **deps:** drop the unmaintained chrono dependency (RUSTSEC-2026-0543); every date written or read is golden-tested byte-identical ([3681e5c](https://github.com/Panacota96/rv-timeline/commit/3681e5cab62e59c679f81ebb8115c2454c3d66a6))

## [0.2.1](https://github.com/Panacota96/rv-timeline/compare/v0.2.0...v0.2.1) (2026-11-17)


### Bug Fixes

* **core:** skip RV Hub verification runs instead of excluding them ([#7](https://github.com/Panacota96/rv-timeline/issues/7)) ([00b3b94](https://github.com/Panacota96/rv-timeline/commit/00b3b94b23a284d18968ece0646a8e0e18202ea2))

## [0.2.0](https://github.com/Panacota96/rv-timeline/compare/v0.1.0...v0.2.0) (2026-11-14)


### Features

* RV Timeline v0.1 — cited case timeline from the Rakvor tools' outputs ([#3](https://github.com/Panacota96/rv-timeline/issues/3)) ([76bf02d](https://github.com/Panacota96/rv-timeline/commit/76bf02d4f257757a130ecd651451e0136e268bca))


### Bug Fixes

* **cli:** list the review log in describe --json log_formats ([14b9186](https://github.com/Panacota96/rv-timeline/commit/14b9186ae6734da5e4bab9e3bf063c35b3ebcd43))
* **core:** late audit entries and redirected run folders cannot hide an edited output ([e7850ab](https://github.com/Panacota96/rv-timeline/commit/e7850ab69933690b8fe0faa018ad803bb201a4fe))
* **core:** re-hash the outputs a run's audit log records in verify-log and verify-case ([cf4515c](https://github.com/Panacota96/rv-timeline/commit/cf4515cf82949423c72409f6b8f0380e198dd668))
* verify-log and verify-case re-hash the outputs the audit log records ([accace9](https://github.com/Panacota96/rv-timeline/commit/accace9ff3edc24679c59240540b3ce6aeb172dd))

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
