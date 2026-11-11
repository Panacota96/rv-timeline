# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please report vulnerabilities privately to **security@rakvor.example** (replace with the real address)
or through GitHub's *Report a vulnerability* button. Do not open a public issue.

Include the version (`rv-timeline --version`), the operating system and the steps to reproduce.
We acknowledge reports within 3 working days and aim to publish a fix within 30 days.

## Scope that matters most for a forensic tool

- Anything that lets a run **modify evidence**, or write outside the chosen output folder.
- Anything that lets an altered `audit.jsonl` **pass** `verify-log`.
- Wrong hash values for any input (please include the file or its size and expected digest).
- Malicious input files that crash the tool or make it hang.

## Verifying a release

Every release publishes `SHA256SUMS`, a CycloneDX SBOM and a GitHub build-provenance attestation:

```powershell
Get-FileHash .\rv-timeline-0.1.0-windows-x64.zip -Algorithm SHA256
gh attestation verify .\rv-timeline-0.1.0-windows-x64.zip --repo Panacota96/rv-timeline
```
