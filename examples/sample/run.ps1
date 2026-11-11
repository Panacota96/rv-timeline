# Runs the sample review on Windows and checks the result.
# Fails (non-zero exit) if the self-test, the scan or verify-log fails, or if the tool's hash register
# (logs\<RUN-ID>\hashes.csv) differs from the independently computed expected_hashes.csv.
# Usage: .\examples\sample\run.ps1 [-Bin C:\path\to\rv-timeline.exe]
param([string]$Bin = "rv-timeline")
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $here "out"
& $Bin self-test; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Expected exit code 0: one medium finding (extension mismatch) and one duplicate pair, no high finding.
& $Bin scan --input (Join-Path $here "evidence") --hash sha256,md5 --lang all --case DEMO-001 --actor "Sample" --out $out --progress none
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$run = Get-ChildItem (Join-Path $out "logs") | Sort-Object Name | Select-Object -Last 1
& $Bin verify-log $run.FullName; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Compare the tool's hash register (logs\<RUN-ID>\hashes.csv) with the independently computed
# expected_hashes.csv: same files, sizes, SHA-256 and MD5. Any difference fails the script (exit 3).
$expected = Import-Csv (Join-Path $here "expected_hashes.csv")
$register = Import-Csv (Join-Path $run.FullName "hashes.csv")
$bad = 0
if ($register.Count -ne $expected.Count) {
  Write-Host "MISMATCH: the tool hashed $($register.Count) files, expected_hashes.csv lists $($expected.Count)"
  $bad = 1
}
foreach ($row in $expected) {
  $got = $register | Where-Object { (Split-Path -Leaf $_.path) -eq $row.file }
  if ($null -eq $got -or @($got).Count -ne 1) { Write-Host "MISMATCH: $($row.file) not in hashes.csv"; $bad = 1; continue }
  if ($got.size -ne $row.size -or $got.sha256 -ne $row.sha256 -or $got.md5 -ne $row.md5) {
    Write-Host "MISMATCH $($row.file): tool $($got.size),$($got.sha256),$($got.md5), expected $($row.size),$($row.sha256),$($row.md5)"
    $bad = 1
  }
}
if ($bad) { exit 3 }
Write-Host "hashes.csv matches expected_hashes.csv ($($expected.Count) files: size, SHA-256, MD5)"
Write-Host "Reports: $out\reports\$($run.Name)\statistics.en.html"
