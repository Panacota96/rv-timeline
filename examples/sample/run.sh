#!/usr/bin/env sh
# Builds the timeline of the sample case and checks the result. Usage: examples/sample/run.sh [path-to-rv-timeline]
# Works on a copy of examples/sample/case in examples/sample/out (or $RV_SAMPLE_OUT), so the committed case is
# never changed. Fails (non-zero exit) if the self-test fails, if `build` does not end with the expected exit code,
# if reports/timeline.jsonl is missing or not listed with its SHA-256 in the run's audit log, or if verify-log or
# verify-case fails.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bin=${1:-rv-timeline}
out=${RV_SAMPLE_OUT:-"$here/out"}
rm -rf "$out/case"
mkdir -p "$out"
cp -R "$here/case" "$out/case"
"$bin" self-test
# Expected exit code 3: every run verifies, but the sample plants medium- and high-severity signals
# (EXIF_AFTER_INTAKE, MAIL_DATE_AFTER_FIRST_HOP, ...; see README.md).
code=0
"$bin" build --case-dir "$out/case" --hash sha256,md5 --lang all --display-zone America/Bogota \
  --actor "Sample" --progress none || code=$?
if [ "$code" -ne 3 ]; then
  echo "FAIL: build exited with $code, expected 3"
  exit 1
fi
run=$(ls "$out/case/runs/rv-timeline" | tail -n 1)
dir="$out/case/runs/rv-timeline/$run"
if [ ! -s "$dir/reports/timeline.jsonl" ]; then
  echo "FAIL: $dir/reports/timeline.jsonl is missing or empty"
  exit 1
fi
want=$(sha256sum "$dir/reports/timeline.jsonl" | cut -d' ' -f1)
if ! grep '"action":"timeline_written"' "$dir/logs/audit.jsonl" | grep -q "\"sha256\":\"$want\""; then
  echo "FAIL: timeline.jsonl (SHA-256 $want) is not listed in the audit log"
  exit 1
fi
echo "timeline.jsonl is listed in the audit log (SHA-256 $want, $(wc -l < "$dir/reports/timeline.jsonl" | tr -d ' ') events)"
"$bin" verify-log "$dir/logs"
"$bin" verify-case "$out/case"
echo "Reports: $dir/reports/statistics.en.html"
