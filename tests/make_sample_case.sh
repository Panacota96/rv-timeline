#!/usr/bin/env bash
# Builds examples/sample/case/ (a Rakvor case folder with one completed run of each of the six tools, every output
# kept) and examples/sample/expected_timeline.json. Its expectations for the three tampered copies come from copies
# written to a temporary folder; the tests write them again with `make_sample_case.py tamper` (not committed).
# See examples/sample/README.md.
#
# Usage: tests/make_sample_case.sh [RAKVOR_ROOT]
#   RAKVOR_ROOT  folder holding the six tool repositories (rv-hashinv, rv-pdfauth, rv-imgauth, rv-rsmf,
#                rv-mailauth, rv-certcheck), each built with `cargo build --release --locked -p <tool>-cli`.
#                Default: the parent of this repository. The curated evidence is copied from their
#                examples/sample/ folders; the executables are taken from <repo>/target/release/.
#                Use the tools' main branches at their released versions.
# Environment:
#   RV_TEST_PYTHON     Python 3 (standard library only is needed). Default: python3.
#   RV_PDFIUM_PATH     pdfium library for rv-pdfauth's visual comparison (optional; without it the run notes it).
#   RV_SAMPLE_DRIVE    Windows only: free drive letter mapped with `subst` onto the work folder, so the paths the
#                      tools record are neutral (R:\evidence\...) instead of the user's profile. Default: R:
#   RV_SAMPLE_ROOT     Linux/macOS: work folder (its absolute path is recorded by the tools). Default: /tmp/rv-sample
#   RV_TIMELINE_EXE    rv-timeline executable whose verify-case must accept the clean case too (it re-hashes every
#                      recorded output). Default: target/release/rv-timeline of this repository.
#
# Deterministic: the evidence bytes and modification times, the tool options, the order of the runs, the evidence
# ids and every time read from the evidence. Not deterministic (they are the clock of the run): run ids, the
# run/intake times and the time of the planted modification. expected_timeline.json is therefore regenerated from
# the new outputs on every build, never edited by hand.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
rakvor=$(cd "${1:-$here/..}" && pwd)
py=${RV_TEST_PYTHON:-python3}
sample="$here/examples/sample"
helper="$here/tests/make_sample_case.py"
tools="rv-hashinv rv-pdfauth rv-imgauth rv-rsmf rv-mailauth rv-certcheck"

case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) windows=1; exe=.exe ;; *) windows=0; exe= ;; esac
timeline=${RV_TIMELINE_EXE:-$here/target/release/rv-timeline$exe}
[ -x "$timeline" ] || { echo "missing $timeline (cargo build --release --locked -p rv-timeline-cli)" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------- work folder
work=$(mktemp -d "${TMPDIR:-/tmp}/rv-sample-work.XXXXXX")
if [ "$windows" = 1 ]; then
  drive=${RV_SAMPLE_DRIVE:-R:}
  if [ -e "$drive/" ]; then echo "drive $drive is in use; set RV_SAMPLE_DRIVE to a free letter" >&2; exit 1; fi
  subst "$drive" "$(cygpath -w "$work")"
  trap 'cd /; MSYS_NO_PATHCONV=1 subst "$drive" /d >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
  root="$drive"                       # what the shell uses (R:)
  wroot="$drive"                      # what the tools record (R:\...)
  w() { printf '%s\\%s' "$wroot" "$(printf '%s' "$1" | tr '/' '\\')"; }
else
  root=${RV_SAMPLE_ROOT:-/tmp/rv-sample}
  rm -rf "$root"; mkdir -p "$root"
  trap 'rm -rf "$work" "$root"' EXIT
  wroot="$root"
  w() { printf '%s/%s' "$wroot" "$1"; }
fi
mkdir -p "$root/bin" "$root/inputs"

# Executables run from the neutral folder (environment.json records the command line).
# Each executable must report its repository's released version (version.txt): a stale build would record an old
# version in the case and the timeline would exclude the run as unsupported_version.
for t in $tools; do
  src="$rakvor/$t/target/release/$t$exe"
  [ -x "$src" ] || { echo "missing $src (cargo build --release --locked -p $t-cli in $rakvor/$t)" >&2; exit 1; }
  got=$("$src" --version | tr -d '\r'); got=${got#"$t "}
  if [ -f "$rakvor/$t/version.txt" ]; then
    want=$(tr -d '\r\n ' < "$rakvor/$t/version.txt")
    [ "$got" = "$want" ] || { echo "$src reports $got but $t/version.txt says $want: rebuild it" >&2; exit 1; }
  fi
  cp "$src" "$root/bin/"
done
pdfium=
if [ -n "${RV_PDFIUM_PATH:-}" ] && [ -f "$RV_PDFIUM_PATH" ]; then
  cp "$RV_PDFIUM_PATH" "$root/bin/"; pdfium=$(w "bin/$(basename "$RV_PDFIUM_PATH")")
fi
bin() { printf '%s/bin/%s%s' "$root" "$1" "$exe"; }

# ---------------------------------------------------------------------------------------------- evidence
"$py" -I "$helper" evidence "$rakvor" "$root/evidence"
cp "$rakvor/rv-mailauth/examples/sample/dkim-keys.txt" "$root/inputs/dkim-keys.txt"

# Neutral host and user in environment.json / case-log (the tools read these variables).
export COMPUTERNAME=RV-SAMPLE-HOST HOSTNAME=RV-SAMPLE-HOST USERNAME=sample-examiner USER=sample-examiner
export RV_NO_TIMESTAMP=1
# Empty per-user folders on the neutral drive: the tools then use only their built-in fingerprint databases (no
# local state of the machine that builds the case) and record no profile path.
mkdir -p "$root/profile/local" "$root/profile/roaming" "$root/profile/tmp"
export LOCALAPPDATA="$(w profile/local)" APPDATA="$(w profile/roaming)" USERPROFILE="$(w profile)" \
  XDG_DATA_HOME="$(w profile/local)" XDG_CONFIG_HOME="$(w profile/roaming)"
tmp_tools="$(w profile/tmp)"
[ -n "$pdfium" ] && export RV_PDFIUM_PATH="$pdfium"
cd "$root/"
case_dir=$(w case)
common=(--case-dir "$case_dir" --hash sha256,md5 --lang en --actor "Sample Examiner" --no-timestamp --progress none)

# run TOOL EXPECTED-EXIT-CODES ARGS...: runs one tool and fails unless it exits with one of the codes.
run() {
  local t=$1 ok=$2 rc=0; shift 2
  echo "== $t $1"
  TEMP="$tmp_tools" TMP="$tmp_tools" "$(bin "$t")" "$@" || rc=$?
  case " $ok " in *" $rc "*) ;; *) echo "$t exited $rc (expected one of: $ok)" >&2; exit 1 ;; esac
}

# 1. Intake: registers the 21 evidence files (E0001..E0021, sorted by path).
run rv-hashinv "0" scan -i "$(w evidence)" -r --case RV-SAMPLE-001 --jurisdiction co "${common[@]}"
# 2. Planted FILE_MODIFIED_AFTER_INTAKE: camera-original.jpg's modification time is moved past the intake (same
#    bytes, so the hash still matches the registry), then rv-hashinv re-examines that one item.
sleep 2
touch "$root/evidence/images/camera-original.jpg"
cam=$("$py" -I -c 'import json,sys; print(next(i["evidence_id"] for i in json.load(open(sys.argv[1]))["items"] if i["path"].replace("\\","/").endswith("images/camera-original.jpg")))' "$root/case/evidence/registry.json")
run rv-hashinv "0" scan --evidence "$cam" "${common[@]}"
# 3. Analysis tools, each on its own part of the evidence. Exit 3 = completed with high findings (by design).
run rv-pdfauth "0 3" analyze -i "$(w evidence/pdf)" "${common[@]}"
run rv-imgauth "0 3" analyze -i "$(w evidence/images)" --maps none "${common[@]}"
run rv-rsmf "0 3" convert -i "$(w evidence/chat)" -r --timezone Europe/Paris "${common[@]}"
run rv-mailauth "0 3" analyze -i "$(w evidence/mail)" --dkim-keys "$(w inputs/dkim-keys.txt)" \
  --own-domain acme.example "${common[@]}"
run rv-certcheck "0 3" analyze -i "$(w evidence/certs)" --anchor "$(w anchors/rakvor-lab-root.crt)" \
  --at 2026-06-01T00:00:00Z "${common[@]}"

# ---------------------------------------------------------------------------------------------- versions
{
  printf '{\n  "description": "Executables that wrote examples/sample/case (rakvor-root/<tool>/target/release, built from the commit shown).",\n  "tools": {\n'
  first=1
  for t in $tools; do
    v=$("$(bin "$t")" --version | tr -d '\r'); v=${v#"$t "}
    c=$(git -C "$rakvor/$t" rev-parse HEAD 2>/dev/null || echo unknown)
    s=$(sha256sum "$(bin "$t")" | cut -d' ' -f1)
    [ $first = 1 ] || printf ',\n'; first=0
    printf '    "%s": {"version": "%s", "commit": "%s", "exe_sha256": "%s"}' "$t" "$v" "$c" "$s"
  done
  printf '\n  }\n}\n'
} > "$work/tool-versions.json"

# ---------------------------------------------------------------------------------------------- verify + copy
# Nothing is deleted after the runs: every output a run's audit log records stays, so verify-case (which re-hashes
# them, src/core/src/outputs.rs) accepts the case with every tool and with rv-timeline.
for t in $tools; do "$(bin "$t")" verify-case "$case_dir" > "$work/verify-$t.txt" || { cat "$work/verify-$t.txt"; echo "$t verify-case failed on the clean case" >&2; exit 1; }; done
"$timeline" verify-case "$root/case" > "$work/verify-rv-timeline.txt" || { cat "$work/verify-rv-timeline.txt"; echo "rv-timeline verify-case failed on the clean case" >&2; exit 1; }
echo "verify-case: clean case OK with all six tools and rv-timeline"
rm -rf "$sample/case" "$sample/tampered"
cp -R "$root/case" "$sample/case"
cp "$work/tool-versions.json" "$sample/tool-versions.json"
cp "$root/derived.json" "$sample/derived-evidence.json"

"$py" -I "$helper" tamper "$sample/case" "$work/tampered"
"$py" -I "$helper" expected "$sample/case" "$work/tampered" "$sample/tool-versions.json" "$sample/expected_timeline.json"

# The clean case and the tampered copies through every tool's verify-case (expected exit codes: expected_timeline.json).
"$py" -I "$helper" check-verify "$sample/expected_timeline.json" "$sample/case" "$work/tampered" \
  $(for t in $tools; do bin "$t"; printf ' '; done) "$timeline"
echo "sample case written to $sample/case ($(du -sh "$sample/case" | cut -f1)); the tests write the tampered copies"
