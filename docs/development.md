# Development, CI/CD and releases

## Build and test locally

```bash
cargo build --workspace                 # debug build of core, CLI and GUI
cargo test  --workspace                 # unit + integration tests (GUI tests are headless)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo run -p rv-timeline-cli -- scan -i examples/sample/evidence --lang all
cargo run -p rv-timeline-gui
```

Linux needs no system packages to build. On Windows use the MSVC toolchain (`rustup default stable-msvc`);
binaries are linked with the static C runtime (`.cargo/config.toml`), so they run on a clean Windows 10/11.

## Test pyramid

```mermaid
flowchart BT
    U["Unit tests (core)<br/>known-answer hashes · chain tamper · i18n keys · PDF · wrapping"] --> I
    I["Integration tests (CLI binary)<br/>help sections · exit codes · bulk run · verify-log · evidence untouched · docs drift"] --> X
    X["Cross-language check<br/>tests/verify_chain.py re-verifies the chain and the hashes with Python"] --> M
    M["Manual release check<br/>Windows 10 VM + Windows 11: install, GUI run, open report"]
```

## Continuous integration

```mermaid
flowchart LR
    PR["Push / PR"] --> L["lint<br/>fmt · clippy · actionlint"]
    L --> T1["test ubuntu-latest"]
    L --> T2["test windows-latest"]
    T1 --> D["docs drift<br/>docs-cli = docs/usage-cli.md"]
    T1 --> X["cross-check<br/>verify_chain.py on sample run"]
    T2 --> B["build Windows exe<br/>(artifact)"]
```

`ci.yml` runs on every push and pull request with read-only permissions.

## Releasing

```mermaid
sequenceDiagram
    participant Dev
    participant RP as release-please
    participant GH as GitHub
    participant W as release.yml (windows-latest)
    Dev->>GH: merge Conventional Commits to main
    RP->>GH: opens "chore(main): release x.y.z" PR (CHANGELOG + version)
    Dev->>GH: review & merge release PR
    RP->>GH: tag vX.Y.Z + GitHub Release
    GH->>W: tag push triggers release.yml
    W->>W: build --release, self-test, sample run
    W->>W: portable zip + Inno Setup installer
    W->>W: SHA256SUMS + CycloneDX SBOM
    W->>GH: build-provenance attestation, upload assets
```

| Artifact | Built by |
| --- | --- |
| `rv-timeline-X.Y.Z-windows-x64.zip` | portable: both exes + README + LICENSE + NOTICE + examples |
| `rv-timeline-X.Y.Z-windows-x64-setup.exe` | Inno Setup (`packaging/windows/installer.iss`), per-user install, adds CLI to PATH |
| `SHA256SUMS` | `sha256sum` over the assets |
| `sbom.cdx.json` | `cargo cyclonedx` |
| Attestation | `actions/attest-build-provenance` |

### Code signing

Unsigned executables trigger SmartScreen warnings. Options (decide per legal entity):

| Option | Notes |
| --- | --- |
| Azure Artifact Signing (Trusted Signing) | Low cost, integrates with GitHub Actions; available to organisations in eligible countries (the French entity qualifies, the Colombian one currently does not). |
| OV code-signing certificate (HSM/cloud key) | Works for either entity; slower reputation build-up. |

Signing is a step in `release.yml` guarded by `if: secrets…` so unsigned builds still work for testing.

Full procedure (secrets, signing certificate, test packages, rebuilding a release, manual packaging): [release-process.md](release-process.md).

### Release checklist (manual)

- [ ] `rv-timeline self-test` on the released exe passes on Windows 10 **and** Windows 11
- [ ] GUI opens, runs the sample, *Open report* works
- [ ] `SHA256SUMS` matches the downloaded files; `gh attestation verify` passes
- [ ] CHANGELOG entry reviewed by a human
