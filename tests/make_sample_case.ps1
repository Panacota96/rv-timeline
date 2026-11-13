# Builds examples/sample/case and examples/sample/expected_timeline.json on Windows (the tests write the tampered
# copies).
# The work is done by tests/make_sample_case.sh (one implementation, so both give the same case); this wrapper runs
# it with Git for Windows' bash. Usage: .\tests\make_sample_case.ps1 [-RakvorRoot C:\path\to\Rakvor]
param([string]$RakvorRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
$ErrorActionPreference = "Stop"
# Git for Windows' bash (not WSL's bash.exe in System32, which would not see the Windows paths).
$git = Get-Command git -ErrorAction Stop
$bash = Join-Path (Split-Path -Parent (Split-Path -Parent $git.Source)) "bin\bash.exe"
if (-not (Test-Path $bash)) { throw "Git for Windows bash not found next to $($git.Source)" }
$script = Join-Path $PSScriptRoot "make_sample_case.sh"
& $bash $script $RakvorRoot
exit $LASTEXITCODE
