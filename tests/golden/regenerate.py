#!/usr/bin/env python3
"""Regenerates the golden case folder written by the OTHER profile of this tool (cross-profile check in CI).

  python tests/golden/regenerate.py <other-profile-project>     (or set RV_CROSS_PROJECT)

The other profile (Rust <-> Python, found through its .forge.json) runs one intake scan of
examples/sample/evidence into a new case folder, with a timestamp from the local test TSA
(tests/fake_tsa.py, so the run carries a real RFC 3161 token). The case folder is stored as
tests/golden/case-by-<other-profile>.zip.b64 (base64 text, see unpack.py), and case-by-<other-profile>.json records what produced it.
This profile's test suite and CI unpack it and run `verify-case` and `verify-log` on it: each profile
must keep reading what the other writes, byte for byte, without the other repository being present.

A zip, not a folder: its bytes never change (no line-ending conversion by git, no renaming by the
forge's scaffold), and the case log records SHA-256 digests of the files inside it.
Run this script with a Python that has pyhanko (the test TSA needs it), then commit both files.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import base64
import io
import textwrap
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CASE_ID = "CASE-GOLDEN"


def other_profile(project: Path) -> tuple[str, list[str]]:
    forge = json.loads((project / ".forge.json").read_text("utf-8"))
    if forge.get("profile") == "python":
        py = next((p for p in (project / ".venv/bin/python", project / ".venv/Scripts/python.exe") if p.is_file()), None)
        if py is None:
            sys.exit(f"{project}: no .venv (run `uv sync` there first)")
        return "python", [str(py), "-m", forge["module"]]
    return forge["profile"], list(forge["cli_command"])


def git_head(project: Path) -> str:
    r = subprocess.run(["git", "-C", str(project), "rev-parse", "HEAD"], capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(project), "status", "--porcelain"], capture_output=True, text=True).stdout.strip()
    return (r.stdout.strip() or "unknown") + ("+uncommitted" if dirty else "")


def main() -> int:
    arg = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("RV_CROSS_PROJECT")
    if not arg:
        print(__doc__)
        return 2
    project = Path(arg).resolve()
    profile, cmd = other_profile(project)
    sys.path.insert(0, str(ROOT / "tests"))
    import fake_tsa  # needs pyhanko; imported only when regenerating

    with tempfile.TemporaryDirectory(prefix="rv-golden-") as tmp:
        tmp = Path(tmp)
        evidence = tmp / "evidence"
        shutil.copytree(ROOT / "examples" / "sample" / "evidence", evidence)
        fake_tsa.make_certs(tmp / "pki")
        srv, url = fake_tsa.serve(tmp / "pki")
        case = tmp / CASE_ID
        env = {k: v for k, v in os.environ.items() if k != "RV_NO_TIMESTAMP"}
        env["NO_PROXY"] = "127.0.0.1"
        args = ["scan", "-i", str(evidence), "--case-dir", str(case), "--case", CASE_ID, "--jurisdiction", "fr"]
        args += ["--hash", "sha256,md5", "--lang", "en", "--actor", "golden", "--tsa-url", url, "--progress", "none"]
        try:
            r = subprocess.run([*cmd, *args], cwd=project, env=env, capture_output=True, text=True, encoding="utf-8")
        finally:
            srv.shutdown()
        print(r.stdout, r.stderr, sep="\n")
        if r.returncode != 0 or "timestamp: ok" not in r.stdout:
            print(f"the {profile} profile did not complete a timestamped intake (exit {r.returncode})")
            return 1
        version = subprocess.run([*cmd, "--version"], cwd=project, capture_output=True, text=True).stdout.strip()
        buf = io.BytesIO()
        archive = HERE / f"case-by-{profile}.zip.b64"
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(p for p in case.rglob("*") if p.is_file()):
                info = zipfile.ZipInfo(f.relative_to(tmp).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, f.read_bytes())
        source = {
            "written_by": {"profile": profile, "version": version, "commit": git_head(project)},
            "generated_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "command": [a.replace(str(tmp), "<tmp>").replace(url, "<test TSA>") for a in args],
            "note": "Evidence paths in the registry point to a deleted temporary folder: verify-case checks the case "
            "without --rehash. The timestamp comes from the test TSA of tests/fake_tsa.py (not a trusted authority).",
        }
        archive.write_text("\n".join(textwrap.wrap(base64.b64encode(buf.getvalue()).decode(), 76)) + "\n", encoding="ascii")
        (HERE / f"case-by-{profile}.json").write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {archive}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
