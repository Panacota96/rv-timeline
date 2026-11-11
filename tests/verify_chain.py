#!/usr/bin/env python3
"""Independent re-implementation of the Rakvor audit-chain check and hash register check.

Usage: python tests/verify_chain.py <OUT>/logs/<RUN-ID>

Exit 0 when the chain is intact and every file in hashes.csv still has the recorded digests,
3 otherwise (a missing audit.jsonl or hashes.csv is reported as missing; the other file is still
checked). Uses only the Python standard library (plus `blake3` if a run used it).
"""
import csv
import hashlib
import json
import os
import sys

GENESIS = "0" * 64


def canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_chain(path: str) -> list[str]:
    problems, prev, expected = [], GENESIS, 1
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                problems.append(f"line {n}: not valid JSON ({e})")
                continue
            stored = entry.pop("entry_hash", "")
            if entry.get("seq") != expected:
                problems.append(f"line {n}: seq {entry.get('seq')} (expected {expected})")
            if entry.get("prev_entry_hash") != prev:
                problems.append(f"line {n}: prev_entry_hash does not link")
            if hashlib.sha256(canonical(entry)).hexdigest() != stored:
                problems.append(f"line {n}: entry_hash mismatch")
            seq = entry.get("seq")
            prev, expected = stored, (seq if isinstance(seq, int) else expected) + 1
    return problems


def digest(path: str, algo: str) -> str:
    if algo == "blake3":
        import blake3  # pip install blake3

        h = blake3.blake3()
    else:
        h = hashlib.new({"sha3-256": "sha3_256"}.get(algo, algo))
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_register(path: str) -> list[str]:
    problems = []
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        algos = [c for c in reader.fieldnames if c not in ("index", "path", "size", "status", "error")]
        for row in reader:
            if row["error"]:
                continue
            for a in algos:
                try:
                    got = digest(row["path"], a)
                except OSError as e:
                    problems.append(f"{row['path']}: {e}")
                    break
                if got != row[a]:
                    problems.append(f"{row['path']}: {a} {got} != recorded {row[a]}")
    return problems


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    d = sys.argv[1]
    log, csv_path = os.path.join(d, "audit.jsonl"), os.path.join(d, "hashes.csv")
    chain = verify_chain(log) if os.path.isfile(log) else [f"{log}: missing"]
    register = verify_register(csv_path) if os.path.isfile(csv_path) else [f"{csv_path}: missing"]
    for p in chain + register:
        print("  -", p)

    def status(problems: list[str], good: str, bad: str) -> str:
        return good if not problems else "MISSING" if problems[0].endswith(": missing") else bad

    print("chain:", status(chain, "intact", "BROKEN"), "| register:", status(register, "matches", "MISMATCH"))
    return 0 if not (chain or register) else 3


if __name__ == "__main__":
    sys.exit(main())
