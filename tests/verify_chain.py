#!/usr/bin/env python3
"""Independent re-implementation of the Rakvor audit-chain check, hash register check and recorded-outputs check.

Usage: python tests/verify_chain.py <OUT>/logs/<RUN-ID>
       python tests/verify_chain.py <CASE>/runs/<tool>/<RUN-ID>/logs
       (the path of audit.jsonl itself is accepted too)

Three checks, written from the audit-log contract and not from the Rust code (a second implementation):

* chain: every audit.jsonl entry links to the previous one and its entry_hash is the SHA-256 of its canonical JSON;
* register: every file in hashes.csv still has the recorded digests (an mbox message `<mbox>#<n>@<offset>` is
  re-hashed from its byte range; an append-only case-log.jsonl may have grown after the run read it);
* outputs: every file the audit log says the run wrote (registers, environment, reports, RSMF, timelines) still has
  the digests the log records. Only when the chain is intact (else nothing it records is trusted). Rules: the
  latest entry for a path wins; an entry after run_finished never replaces an earlier record; RFC 3161 tokens and
  files written outside the run are not re-hashed; a path must be a plain relative path (`/`, no `..`, `.`, root,
  drive, `\\` or `:`) that resolves inside the run folder (case run) or its own area folder (standalone run), and
  a redirected run or area folder (symlink, junction) is rejected.

Exit 0 when all three are clean, 3 otherwise (a missing audit.jsonl or hashes.csv is reported as missing; the
other checks still run), 2 on a usage error or when a run used blake3 and the `blake3` module is not installed.
Uses only the Python standard library (plus `blake3` if a run used it).
"""
import csv
import hashlib
import json
import os
import re
import sys

GENESIS = "0" * 64
ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "sha3-256", "blake3")
AUDIT_LOGS = ("logs/audit.jsonl", "logs/audit.log", "logs/review.jsonl")
LATE = "recorded after run_finished, outside the run's anchored log"
OUTSIDE = "written outside the run folder, at a path the operator chose"
# A message inside an mbox is registered as "<mbox path>#<n>@<offset>": <offset> is where its "From " separator
# line starts, and the recorded digests cover the `size` raw bytes that follow that line (no un-escaping).
MBOX_ITEM = re.compile(r"^(?P<mbox>.+)#(?P<n>\d+)@(?P<offset>\d+)$")


class NeedBlake3(Exception):
    pass


# ---------------------------------------------------------------------------------------------------------- chain


def canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_chain(path: str) -> tuple[list[str], list]:
    """(problems, entries without their entry_hash)."""
    problems, entries, prev, expected = [], [], GENESIS, 1
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                problems.append(f"line {n}: not valid JSON ({e})")
                continue
            if not isinstance(entry, dict):
                problems.append(f"line {n}: not a JSON object")
                continue
            stored = entry.pop("entry_hash", "")
            if entry.get("seq") != expected:
                problems.append(f"line {n}: seq {entry.get('seq')} (expected {expected})")
            if entry.get("prev_entry_hash") != prev:
                problems.append(f"line {n}: prev_entry_hash does not link")
            if hashlib.sha256(canonical(entry)).hexdigest() != stored:
                problems.append(f"line {n}: entry_hash mismatch")
            seq = entry.get("seq")
            prev, expected = stored, (seq if isinstance(seq, int) and not isinstance(seq, bool) else expected) + 1
            entries.append(entry)
    return problems, entries


# --------------------------------------------------------------------------------------------------------- digests


def hasher(algo: str):
    if algo == "blake3":
        try:
            import blake3  # pip install blake3
        except ImportError:
            raise NeedBlake3() from None
        return blake3.blake3()
    return hashlib.new({"sha3-256": "sha3_256"}.get(algo, algo))


def digest(path: str, algo: str, limit: int | None = None) -> str:
    """Digest of the file, or of its first `limit` bytes."""
    h, left = hasher(algo), limit
    with open(path, "rb") as fh:
        while left is None or left > 0:
            chunk = fh.read(1 << 20 if left is None else min(1 << 20, left))
            if not chunk:
                break
            h.update(chunk)
            if left is not None:
                left -= len(chunk)
    return h.hexdigest()


def mbox_digest(path: str, algo: str, size: int | None) -> str:
    m = MBOX_ITEM.match(path)
    if size is None:
        raise OSError(f"{path}: mbox message without a recorded size")
    h = hasher(algo)
    with open(m["mbox"], "rb") as fh:
        fh.seek(int(m["offset"]))
        if not fh.readline().startswith(b"From "):
            raise OSError(f"{path}: no mbox 'From ' line at offset {m['offset']}")
        data = fh.read(size)
    if len(data) != size:
        raise OSError(f"{path}: mbox ends before {size} bytes")
    h.update(data)
    return h.hexdigest()


# -------------------------------------------------------------------------------------------------------- register


def verify_register(path: str) -> list[str]:
    problems = []
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        algos = [c for c in reader.fieldnames or [] if c not in ("index", "path", "size", "status", "error")]
        for row in reader:
            if row.get("error"):
                continue
            p = row["path"]
            size = int(row["size"]) if (row.get("size") or "").isdigit() else None
            for a in algos:
                try:
                    if MBOX_ITEM.match(p) and not os.path.exists(p):
                        got = mbox_digest(p, a, size)
                    else:
                        got = digest(p, a)
                        # The case log is append-only and is read before the hub appends its own entries: the
                        # register's size says how many bytes were read, and that prefix must keep the digest.
                        if got != row[a] and os.path.basename(p) == "case-log.jsonl" and size is not None \
                                and size < os.path.getsize(p) and digest(p, a, size) == row[a]:
                            continue
                except OSError as e:
                    problems.append(f"{p}: {e}")
                    break
                if got != row[a]:
                    problems.append(f"{p}: {a} {got} != recorded {row[a]}")
    return problems


# --------------------------------------------------------------------------------------------------------- outputs


def ascii_lower(s: str) -> str:
    return s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))


def algorithm(name) -> str | None:
    """Canonical algorithm name for an audit key (`SHA256`, `sha3_256`, `sha3` …), or None."""
    if not isinstance(name, str):
        return None
    s = ascii_lower(name.strip()).replace("_", "-")
    if s == "sha3":
        return "sha3-256"
    return s if s in ALGORITHMS else None


def field(v, key):
    return v.get(key) if isinstance(v, dict) else None


def text(v) -> str:
    return v if isinstance(v, str) else ""


def digests_of(v) -> dict:
    """{algorithm: lowercase hex} from v["hashes"], v["digest"], then v itself; the first value per algorithm wins."""
    out = {}
    for obj in (field(v, "hashes"), field(v, "digest"), v):
        if not isinstance(obj, dict):
            continue
        for k in sorted(obj):  # the audit object's keys in sorted order
            a, h = algorithm(k), obj[k]
            if a and isinstance(h, str) and h and a not in out:
                out[a] = ascii_lower(h)
    return out


def records_of(entry: dict):
    """[(run-relative path, digests or None, skip reason or None)] for one entry; None if it records no output."""
    d, item, action = entry.get("details"), text(entry.get("item")), text(entry.get("action"))

    def one(path, v):
        h = digests_of(v)
        if not h:
            return (path, None, "the entry records no usable digest")
        if path in AUDIT_LOGS:
            return (path, None, "the audit log is verified by its hash chain")
        return (path, h, None)

    def many(base, files):
        return [one(f"{base}/{name}", files[name]) for name in sorted(files)] if isinstance(files, dict) else []

    if action == "environment_recorded":
        return [one(f"logs/{item or 'environment.json'}", d)]
    if action == "hash_register_written":
        return [one(f"logs/{item or 'hashes.csv'}", d)]
    if action == "item_reports_written":
        return many(f"reports/{text(field(d, 'folder'))}", field(d, "files"))
    if action == "statistics_report_written":
        return many("reports", field(d, "files"))
    if action == "timeline_written":
        return many(text(field(d, "folder")) or "reports", field(d, "files"))
    if action == "output_written":
        f = text(field(d, "file"))
        return [one(f"reports/{f}", d)] if f else [(item or "(unnamed file)", None, OUTSIDE)]
    if action == "file_written":
        return [(text(field(d, "path")) or item or "(unnamed file)", None, OUTSIDE)]
    if action == "report_written" and item:
        return [one(f"reports/{item}", d)]
    if action in ("rsmf_written", "trace_written") and item:
        return [one(f"rsmf/{item}", d)]
    if action == "timestamp_obtained":
        return [(f"logs/{item or text(field(d, 'file'))}", None,
                 "RFC 3161 token: checked by the timestamp verification")]
    return None


def plain_relative(rel: str) -> bool:
    return bool(rel) and "\\" not in rel and ":" not in rel and all(c not in ("", ".", "..") for c in rel.split("/"))


def real(path: str) -> str:
    """Canonical path; raises FileNotFoundError / OSError like a strict resolve."""
    os.stat(path)  # FileNotFoundError when it is not there
    return os.path.realpath(path, strict=True)


def layout_of(log_dir: str) -> tuple[dict, str | None]:
    """({area: folder}, run folder or None) for the run whose audit log is in log_dir."""
    logs = os.path.abspath(log_dir)
    parent = os.path.dirname(logs)
    if os.path.basename(logs) == "logs" and parent != logs:
        return {"logs": logs, "reports": os.path.join(parent, "reports"), "rsmf": os.path.join(parent, "rsmf")}, parent
    out, run_id = os.path.dirname(parent), os.path.basename(logs)
    if os.path.basename(parent) == "logs" and out != parent:
        return {"logs": logs, "reports": os.path.join(out, "reports", run_id),
                "rsmf": os.path.join(out, "rsmf", run_id)}, None
    return {"logs": logs}, None


def trusted(folder: str, levels: int) -> str | None:
    """Canonical folder, only if its last `levels` components are not redirected (symlink or junction)."""
    names, base = [], folder
    for _ in range(levels):
        name = os.path.basename(base)
        if not name:
            return None
        names.append(name)
        base = os.path.dirname(base)
    try:
        expected = os.path.join(real(base), *reversed(names))
        got = real(folder)
    except OSError:
        return None
    return got if got == expected else None


def inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def verify_outputs(log_dir: str, entries: list) -> dict:
    r = {"recorded": 0, "verified": 0, "missing": 0, "changed": 0, "rejected": 0,
         "skipped": [], "unrecognised": [], "algorithms": set(), "problems": []}
    latest, finished = {}, False  # path -> (seq, digests or None, skip reason or None)
    for e in entries:
        seq = e.get("seq")
        seq = seq if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0 else 0
        action = text(e.get("action"))
        recs = records_of(e)
        if recs is None:
            if action.endswith("_written"):
                r["unrecognised"].append(f"#{seq} {action}")
            if action == "run_finished":
                finished = True
            continue
        for path, h, why in recs:
            if not finished:
                latest[path] = (seq, h, why)
            elif path in latest:
                r["skipped"].append((path, seq, f"{LATE}: the earlier record is the one checked"))
            else:
                latest[path] = (seq, None, why if h is None else LATE)
    r["recorded"] = len(latest)
    areas, run_dir = layout_of(log_dir)
    roots = {}
    for path in sorted(latest):
        seq, want, why = latest[path]
        if want is None:
            r["skipped"].append((path, seq, why))
            continue

        def problem(kind, detail):
            if kind == "missing":
                r["missing"] += 1
                msg = f"output {path}: missing (recorded by audit entry #{seq}): deleted or moved after the run"
            elif kind == "rejected":
                r["rejected"] += 1
                msg = f"output {path}: {detail} (audit entry #{seq}), not read"
            else:  # unreadable
                r["rejected"] += 1
                msg = f"output {path}: {detail} (audit entry #{seq})"
            r["problems"].append(msg)

        if not plain_relative(path):
            problem("rejected", "not a relative path inside the run folder")
            continue
        area, _, rest = path.partition("/")
        if area not in areas:
            r["skipped"].append((path, seq, f"the {area}/ folder of this run is not known from its log folder"))
            continue
        if not rest:
            problem("rejected", "names a run folder, not a file")
            continue
        if area not in roots:
            roots[area] = trusted(run_dir, 1) if run_dir else trusted(areas[area], 2)
        root = roots[area]
        if root is None:
            problem("rejected", "the run's folder resolves elsewhere (symlink or junction): not read")
            continue
        try:
            target = real(os.path.join(areas[area], *rest.split("/")))
        except FileNotFoundError:
            problem("missing", "")
            continue
        except OSError as e:
            problem("unreadable", f"cannot open: {e}")
            continue
        if not inside(target, root):
            problem("rejected", "resolves outside the run folder (symlink or junction)")
            continue
        if not os.path.isfile(target):
            problem("unreadable", "is no longer a regular file (replaced after the run)")
            continue
        try:
            got = {a: digest(target, a) for a in sorted(want)}
        except OSError as e:
            problem("unreadable", f"cannot read: {e}")
            continue
        r["algorithms"].update(want)
        bad = next((a for a in sorted(want) if want[a] != got[a]), None)
        if bad is None:
            r["verified"] += 1
        else:
            r["changed"] += 1
            r["problems"].append(f"output {path}: {bad} differs from audit entry #{seq} "
                                 f"(recorded {want[bad]}, now {got[bad]}): edited or replaced after the run")
    return r


def outputs_summary(r: dict) -> str:
    s = f"outputs: {r['verified']} verified of {r['recorded']} recorded"
    if r["algorithms"]:
        s += f" ({', '.join(sorted(r['algorithms']))})"
    for n, what in ((r["missing"], "missing"), (r["changed"], "changed"), (r["rejected"], "rejected"),
                    (len(r["skipped"]), "skipped")):
        if n:
            s += f", {n} {what}"
    if r["unrecognised"]:
        n = len(r["unrecognised"])
        s += f", {n} unrecognised entr{'y' if n == 1 else 'ies'} ignored"
    return s


# ------------------------------------------------------------------------------------------------------------ main


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    d = sys.argv[1]
    if os.path.isfile(d):
        d = os.path.dirname(os.path.abspath(d))
    log, csv_path = os.path.join(d, "audit.jsonl"), os.path.join(d, "hashes.csv")
    try:
        chain, entries = verify_chain(log) if os.path.isfile(log) else ([f"{log}: missing"], [])
        register = verify_register(csv_path) if os.path.isfile(csv_path) else [f"{csv_path}: missing"]
        outputs = None if chain else verify_outputs(d, entries)
    except NeedBlake3:
        print("error: this run used blake3: install the `blake3` module (pip install blake3)")
        return 2
    for p in chain + register + (outputs["problems"] if outputs else []):
        print("  -", p)
    if outputs:
        print("   ", outputs_summary(outputs))
        for path, _, why in outputs["skipped"]:
            print(f"    not re-hashed: {path} ({why})")
        for u in outputs["unrecognised"]:
            print(f"    not recognised (ignored): {u}")

    def status(problems: list[str], good: str, bad: str) -> str:
        return good if not problems else "MISSING" if problems[0].endswith(": missing") else bad

    out = "NOT CHECKED (chain not intact)" if outputs is None else "match" if not outputs["problems"] else "MISMATCH"
    print("chain:", status(chain, "intact", "BROKEN"), "| register:", status(register, "matches", "MISMATCH"),
          "| outputs:", out)
    return 0 if not (chain or register or (outputs or {}).get("problems")) else 3


if __name__ == "__main__":
    sys.exit(main())
