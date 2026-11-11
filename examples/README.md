# Examples

## `sample/` — three files that exercise every report section

| File | What it demonstrates | Expected finding |
| --- | --- | --- |
| `evidence/acta.txt` | Plain text | DUPLICATE (info) |
| `evidence/acta-copia.txt` | Same content as `acta.txt` | DUPLICATE (info) |
| `evidence/foto-vacaciones.jpg` | A PDF renamed as a photo | EXTENSION_MISMATCH (medium) |

`expected_hashes.csv` holds the digests of the three files in all six algorithms, computed independently with
Python's `hashlib` and `blake3`, so you can check the tool's output.

```mermaid
flowchart LR
    E["evidence/ (3 files)"] --> S["rv-timeline scan --hash sha256,md5 --lang all"]
    S --> O["out/logs/RUN-ID · out/reports/RUN-ID"]
    O --> V["rv-timeline verify-log → OK"]
    O --> C["compare with expected_hashes.csv"]
```

Run it:

```bash
examples/sample/run.sh target/release/rv-timeline          # Linux / macOS
```

```powershell
.\examples\sample\run.ps1 -Bin .\rv-timeline.exe          # Windows
```

Expected summary: 3 items, 0 errors, findings `high 0, medium 1, low 0, info 2`, exit code 0.
