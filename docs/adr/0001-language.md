# ADR 0001 — Implementation language: Rust (Profile A)

- Status: accepted
- Date: 2026-11-11
- Deciders: the project owner, without a per-tool advocate council (see Context)

## Context

Turns the separate tool reports of a case into one cited timeline a judge can follow (rv-hub#7). The owner chose Rust for the five planned tools without a per-tool advocate council (2026-11-11), for consistency with the six released Rust tools; the overrides below are the known domain risks, written by the session, not by advocates.

Weight preset: **client**. Score overrides (domain risks noted by the session, not argued by advocates):

- none

## Options scored (1–5, weighted)

| Criterion | Weight | Rust | Python | C (+asm) |
| --- | :-: | :-: | :-: | :-: |
| Speed (throughput, startup) | 3 | 5 | 3 | 5 |
| Transferability (Win10/11 x64 + ARM64, Linux) | 3 | 5 | 4 | 3 |
| Storage (executable / installer size) | 2 | 4 | 2 | 5 |
| Hardware / RAM (8 GB laptops, VMs without GPU) | 2 | 5 | 3 | 5 |
| Windows GUI maturity | 2 | 4 | 4 | 2 |
| CLI --help quality | 2 | 5 | 5 | 2 |
| Packaging, signing, antivirus false positives | 2 | 4 | 2 | 4 |
| Memory safety / court auditability | 3 | 5 | 3 | 2 |
| Team velocity | 2 | 3 | 5 | 3 |
| CI/CD complexity (5 = simple) | 1 | 5 | 3 | 3 |
| **Weighted total** (max 110) | | **100** | 75 | 75 |

```mermaid
pie showData
    title Weighted score (client preset)
    "Rust" : 100
    "Python" : 75
    "C (+asm)" : 75
```

## Decision

Profile A (Rust workspace: core + clap CLI + egui GUI). 

## Consequences

- Two static executables (CLI + GUI), no runtime to install; one core library powers both.
- Contributors need Rust; Windows binaries are built on GitHub's `windows-latest` runners.
- No hand-written assembly: hash and parsing crates already use SIMD/CPU intrinsics.
