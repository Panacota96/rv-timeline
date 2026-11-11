#!/usr/bin/env python3
"""Validates every JSON report of a run against schemas/.

Usage: python tests/validate_reports.py <OUT>/reports/<RUN-ID>
       python tests/validate_reports.py <CASE>     (a whole case folder: case.json, registry.json and every run's reports)
"""
import json
import pathlib
import sys

import jsonschema  # pip install jsonschema

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMAS = {
    "statistics.json": "statistics.schema.json",
    "technical.json": "item-technical.schema.json",
    "summary.json": "item-summary.schema.json",
    "custody.json": "item-custody.schema.json",
    "case.json": "case.schema.json",
    "registry.json": "registry.schema.json",
}


def main() -> int:
    report_dir = pathlib.Path(sys.argv[1])
    count, failures = 0, 0
    for path in sorted(report_dir.rglob("*.json")):
        if path.name not in SCHEMAS:
            continue  # domain outputs (object dumps, extracted files) are not reports; their digests are audited
        schema = json.loads((ROOT / "schemas" / SCHEMAS[path.name]).read_text(encoding="utf-8"))
        try:
            jsonschema.validate(json.loads(path.read_text(encoding="utf-8")), schema)
            count += 1
        except jsonschema.ValidationError as e:
            failures += 1
            print(f"{path}: {e.message}")
    print(f"{count} report(s) valid, {failures} invalid")
    return 1 if failures or count == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
