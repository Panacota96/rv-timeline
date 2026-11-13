# Builds the timeline of the sample case on Windows and checks the result.
# Works on a copy of examples\sample\case in examples\sample\out (or $env:RV_SAMPLE_OUT), so the committed case is
# never changed. Fails (non-zero exit) if the self-test fails, if `build` does not end with the expected exit code,
# if reports\timeline.jsonl is missing or not listed with its SHA-256 in the run's audit log, or if verify-log or
# verify-case fails.
# Usage: .\examples\sample\run.ps1 [-Bin C:\path\to\rv-timeline.exe]
param([string]$Bin = "rv-timeline")
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = if ($env:RV_SAMPLE_OUT) { $env:RV_SAMPLE_OUT } else { Join-Path $here "out" }
$case = Join-Path $out "case"
if (Test-Path $case) { Remove-Item -Recurse -Force $case }
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item -Recurse (Join-Path $here "case") $case
& $Bin self-test; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Expected exit code 3: every run verifies, but the sample plants medium- and high-severity signals
# (EXIF_AFTER_INTAKE, MAIL_DATE_AFTER_FIRST_HOP, ...; see README.md).
& $Bin build --case-dir $case --hash sha256,md5 --lang all --display-zone America/Bogota --actor "Sample" --progress none
if ($LASTEXITCODE -ne 3) { Write-Host "FAIL: build exited with $LASTEXITCODE, expected 3"; exit 1 }
$run = Get-ChildItem (Join-Path $case "runs\rv-timeline") | Sort-Object Name | Select-Object -Last 1
$timeline = Join-Path $run.FullName "reports\timeline.jsonl"
if (-not (Test-Path $timeline) -or (Get-Item $timeline).Length -eq 0) {
  Write-Host "FAIL: $timeline is missing or empty"; exit 1
}
$want = (Get-FileHash -Algorithm SHA256 $timeline).Hash.ToLowerInvariant()
$listed = Select-String -Path (Join-Path $run.FullName "logs\audit.jsonl") -SimpleMatch '"action":"timeline_written"' |
  Where-Object { $_.Line.Contains("""sha256"":""$want""") }
if (-not $listed) { Write-Host "FAIL: timeline.jsonl (SHA-256 $want) is not listed in the audit log"; exit 1 }
$lines = (Get-Content $timeline | Measure-Object -Line).Lines
Write-Host "timeline.jsonl is listed in the audit log (SHA-256 $want, $lines events)"
& $Bin verify-log (Join-Path $run.FullName "logs"); if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Bin verify-case $case; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Reports: $($run.FullName)\reports\statistics.en.html"
