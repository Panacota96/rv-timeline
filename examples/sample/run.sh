#!/usr/bin/env sh
# Runs the sample review and checks the result. Usage: examples/sample/run.sh [path-to-rv-timeline]
# Output folder: examples/sample/out (or $RV_SAMPLE_OUT).
# Fails (non-zero exit) if the self-test, the scan or verify-log fails, or if the tool's hash register
# (logs/<RUN-ID>/hashes.csv) differs from the independently computed expected_hashes.csv.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bin=${1:-rv-timeline}
out=${RV_SAMPLE_OUT:-"$here/out"}
"$bin" self-test
# Expected exit code 0: one medium finding (extension mismatch) and one duplicate pair, no high finding.
"$bin" scan --input "$here/evidence" --hash sha256,md5 --lang all --case DEMO-001 --actor "Sample" --out "$out" --progress none
run=$(ls "$out/logs" | tail -n 1)
"$bin" verify-log "$out/logs/$run"
# Compare the tool's hash register with expected_hashes.csv: same files, sizes, SHA-256 and MD5.
# hashes.csv: index,path,size,<algorithms>,status,error (path may be quoted); fields are read from the right.
awk -F, '
  FNR == 1 { if (FILENAME ~ /expected_hashes\.csv$/) { for (i = 1; i <= NF; i++) e[$i] = i } else { for (i = 1; i <= NF; i++) h[$i] = i; hn = NF }; next }
  FILENAME ~ /expected_hashes\.csv$/ { want[$e["file"]] = $e["size"] "," $e["sha256"] "," $e["md5"]; n++; next }
  {
    path = $0; sub(/^[0-9]+,/, "", path); sub(/,[0-9]+,[^,]*,[^,]*,[^,]*,[^,]*$/, "", path)
    gsub(/"/, "", path); sub(/.*[\/\\]/, "", path)
    got[path] = $(NF - hn + h["size"]) "," $(NF - hn + h["sha256"]) "," $(NF - hn + h["md5"])
    m++
  }
  END {
    for (f in want) if (got[f] != want[f]) { print "MISMATCH " f ": tool " got[f] ", expected " want[f]; bad = 1 }
    if (m != n) { print "MISMATCH: the tool hashed " m " files, expected_hashes.csv lists " n; bad = 1 }
    if (bad) exit 3
    print "hashes.csv matches expected_hashes.csv (" n " files: size, SHA-256, MD5)"
  }' "$here/expected_hashes.csv" "$out/logs/$run/hashes.csv"
echo "Reports: $out/reports/$run/statistics.en.html"
