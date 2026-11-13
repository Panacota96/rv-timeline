"""Builds the synthetic case folder `case/` used by the reader tests (tests/readers.rs).

The outputs are trimmed copies of what each tool writes (same file names, same JSON shapes, only the fields the
readers read plus a few neighbours); the audit logs and the case log follow the shared chain rule, so the folder
verifies like a real one. Every name, address and value is invented (example.org / example.com domains).

Run from this folder:  python make_case.py      (rewrites case/ from scratch; deterministic)
"""

import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "case"
GENESIS = "0" * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def md5(b):
    return hashlib.md5(b).hexdigest()


def pretty(obj):
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


class Chain:
    def __init__(self, path, run_id="", actor="Examiner"):
        self.path, self.run_id, self.actor = path, run_id, actor
        self.entries, self.head = [], GENESIS

    def add(self, action, ts, details, item=None, run_id=None):
        e = {"seq": len(self.entries) + 1, "ts_utc": ts, "run_id": run_id or self.run_id, "actor": self.actor,
             "action": action, "details": details, "prev_entry_hash": self.head}
        if item is not None:
            e["item"] = item
        e["entry_hash"] = sha256(canonical(e).encode("utf-8"))
        self.head = e["entry_hash"]
        self.entries.append(e)
        return e

    def write(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8", newline="\n") as f:
            for e in self.entries:
                f.write(canonical(e) + "\n")


CASE_LOG = Chain(ROOT / "case-log.jsonl", actor="Examiner")
EVIDENCE = {
    1: ("E0001", "D:\\evidence\\photo.jpg", "a1" * 32),
    2: ("E0002", "D:\\evidence\\contract.pdf", "a2" * 32),
    3: ("E0003", "D:\\evidence\\mail.eml", "a3" * 32),
    4: ("E0004", "D:\\evidence\\box.mbox", "a4" * 32),
    5: ("E0005", "D:\\evidence\\chat.zip", "a5" * 32),
    6: ("E0006", "D:\\evidence\\cert.pem", "a6" * 32),
    7: ("E0007", "D:\\evidence\\screen.png", "a7" * 32),
}


def name_of(path):
    return path.rsplit("\\", 1)[-1]


class Run:
    def __init__(self, tool, version, run_id, start, role="analysis"):
        self.tool, self.version, self.run_id, self.start = tool, version, run_id, start
        self.run_dir = f"runs/{tool}/{run_id}"
        self.dir = ROOT / self.run_dir
        self.audit = Chain(self.dir / "logs" / "audit.jsonl", run_id)
        self.role = role
        cl = CASE_LOG.add("run_started", start, {"evidence_ids": [], "frontend": "cli", "role": role,
                                                  "run_dir": self.run_dir, "tool": tool, "version": version},
                          run_id=run_id)
        self.audit.add("run_started", start, {"tool": tool, "version": version, "frontend": "cli",
                                              "algorithms": ["sha256", "md5"]})
        self.audit.add("case_linked", start, {"case_id": "CASE-TL-1", "role": role, "run_dir": self.run_dir,
                                              "case_log_head_at_start": cl["entry_hash"]})
        env = pretty({"tool": {"name": tool, "version": version}, "os": "Windows 11"})
        self.file("logs/environment.json", env)
        self.audit.add("environment_recorded", start, {"sha256": sha256(env), "md5": md5(env)},
                       item="environment.json")

    def file(self, rel, data):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return {"sha256": sha256(data), "md5": md5(data)}

    def item(self, index, ts, modified, case_action):
        eid, path, digest = EVIDENCE[index]
        self.audit.add("item_started", ts, {"index": index, "size": 1000 + index, "modified_utc": modified},
                       item=path)
        self.audit.add("item_hashed", ts, {"index": index, "bytes_read": 1000 + index,
                                           "hashes": {"sha256": digest, "md5": digest[:32]}, "mtime_unchanged": True},
                       item=path)
        if case_action == "registered":
            self.audit.add("evidence_registered", ts, {"index": index, "evidence_id": eid, "new": True,
                                                       "case_log_seq": 0, "registry_sha256": "b0" * 32}, item=path)
        else:
            self.audit.add("evidence_verified_against_case", ts, {"index": index, "evidence_id": eid,
                                                                  "algorithm": "sha256", "match": True,
                                                                  "matched_by": "evidence_id"}, item=path)
        return f"{index:05d}-{name_of(path)}"

    def output(self, index, folder, name, kind, obj, ts, item=None):
        data = pretty(obj)
        h = self.file(f"reports/items/{folder}/{name}", data)
        self.audit.add("output_written", ts, {"index": index, "kind": kind, "file": f"items/{folder}/{name}",
                                              "bytes": len(data), "hashes": h}, item=item or EVIDENCE[index][1])

    def reports(self, index, folder, technical, ts):
        data = pretty(technical)
        h = self.file(f"reports/items/{folder}/technical.json", data)
        self.audit.add("item_reports_written", ts, {"folder": f"items/{folder}", "files": {"technical.json": h}},
                       item=EVIDENCE[index][1])

    def finish(self, ts, status="completed", case_log=True):
        self.audit.add("run_finished", ts, {"cancelled": status == "cancelled", "items": 1, "errors": 0})
        n, head = len(self.audit.entries), self.audit.head
        self.audit.add("timestamp_obtained", ts, {"covers_seq": n, "file": f"timestamp-{n:05d}.tsr",
                                                  "gen_time": ts[:19] + "Z", "head": head,
                                                  "token_sha256": "c0" * 32, "tsa": "http://tsa.example.org"},
                       item=f"timestamp-{n:05d}.tsr")
        self.audit.write()
        if case_log:
            CASE_LOG.add("run_finished", ts, {"audit_entries": n, "audit_head": head, "run_dir": self.run_dir,
                                              "status": status, "timestamp_status": "ok", "tool": self.tool,
                                              "version": self.version, "totals": {"items": 1}},
                         run_id=self.run_id)


def technical(run, index, extra):
    eid, path, digest = EVIDENCE[index]
    t = {"schema": "rakvor.item-technical/1", "tool": {"name": run.tool, "version": run.version},
         "item": {"index": index, "evidence_id": eid, "path": path, "file_name": name_of(path)},
         "hashes": {"sha256": digest}}
    t.update(extra)
    return t


def main():
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)
    case = pretty({"case_id": "CASE-TL-1", "created_by": {"actor": "Examiner", "run_id": "20261110T090000Z-aaaaaa",
                                                          "tool": "rv-hashinv", "version": "0.4.1"},
                   "created_utc": "2026-11-10T09:00:00.000Z", "jurisdiction": "co", "schema": "rakvor.case/1"})
    (ROOT / "case.json").write_bytes(case)
    CASE_LOG.add("case_created", "2026-11-10T09:00:00.000Z",
                 {"case_id": "CASE-TL-1", "case_json_sha256": sha256(case), "jurisdiction": "co",
                  "registry_sha256": None, "schema": "rakvor.case/1", "tool": "rv-hashinv", "version": "0.4.1"},
                 run_id="20261110T090000Z-aaaaaa")

    # rv-hashinv: intake of the seven items.
    r = Run("rv-hashinv", "0.4.1", "20261110T090000Z-aaaaaa", "2026-11-10T09:00:00.100Z", role="intake")
    for i in EVIDENCE:
        ts = f"2026-11-10T09:00:0{i}.000Z"
        folder = r.item(i, ts, f"2026-11-0{i}T08:00:00Z", "registered")
        r.reports(i, folder, technical(r, i, {"case": {"case_id": "CASE-TL-1", "role": "intake",
                                                       "status": "registered", "intake_utc": ts}}), ts)
    r.finish("2026-11-10T09:00:09.000Z")

    # rv-imgauth: EXIF with and without offsets, GPS, XMP, history, PNG tIME, one unparseable date.
    r = Run("rv-imgauth", "0.3.1", "20261111T100000Z-bbbbbb", "2026-11-11T10:00:00.000Z")
    folder = r.item(1, "2026-11-11T10:00:01.000Z", "2026-11-01T08:00:00Z", "verified")
    tags = [("IFD0", "Make", "ExampleCam"), ("IFD0", "Model", "EC-1"),
            ("IFD0", "DateTime", "2026:11:09 18:30:00"),
            ("Exif", "DateTimeOriginal", "2026:11:09 18:00:00"), ("Exif", "OffsetTimeOriginal", "-05:00"),
            ("Exif", "SubSecTimeOriginal", "25"), ("Exif", "DateTimeDigitized", "2026:11:09 18:00:00"),
            ("GPS", "GPSDateStamp", "2026:11:09"), ("GPS", "GPSTimeStamp", "23:00:00"),
            ("XMP", "xmp:CreateDate", "2026-11-09T18:00:00"), ("XMP", "xmp:ModifyDate", "2026-11-12T10:00:00+01:00"),
            ("XMP", "xmp:MetadataDate", "not a date"), ("XMP", "xmp:CreatorTool", "ExampleEditor 2.0")]
    meta = {"tags": [{"group": g, "id": 0, "name": n, "value": v} for g, n, v in tags],
            "xmp": "<x:xmpmeta/>", "xmp_history": [{"action": "saved", "when": "2026-11-12T10:00:00+01:00",
                                                     "software_agent": "ExampleEditor 2.0", "changed": "/",
                                                     "instance_id": "xmp.iid:1"}],
            "icc_sha256": None, "makernote_present": False, "problems": []}
    r.output(1, folder, "metadata.json", "metadata", meta, "2026-11-11T10:00:01.500Z")
    r.output(1, folder, "structure.json", "structure", {"format": "jpeg", "width": 4, "height": 4},
             "2026-11-11T10:00:01.500Z")
    folder = r.item(7, "2026-11-11T10:00:02.000Z", "2026-11-07T08:00:00Z", "verified")
    r.output(7, folder, "metadata.json", "metadata",
             {"tags": [{"group": "PNG-tIME", "id": 0, "name": "tIME", "value": "2026-11-08 12:00:00"}],
              "xmp": None, "xmp_history": [], "icc_sha256": None, "makernote_present": False, "problems": []},
             "2026-11-11T10:00:02.500Z")
    r.finish("2026-11-11T10:00:03.000Z")

    # rv-pdfauth: two revisions, a signature, Info dates with and without an offset.
    r = Run("rv-pdfauth", "0.4.1", "20261111T110000Z-cccccc", "2026-11-11T11:00:00.000Z")
    folder = r.item(2, "2026-11-11T11:00:01.000Z", "2026-11-02T08:00:00Z", "verified")
    objects = {"revisions": [
        {"objects": [
            {"id": "1 0", "offset": 15, "type": "/Catalog", "dict": {"Type": "/Catalog", "Pages": "2 0 R"}},
            {"id": "7 0", "offset": 400, "type": "dict",
             "dict": {"Producer": "ExampleWriter 1.0", "CreationDate": "D:20261101090000-05'00'",
                      "ModDate": "D:20261101090000-05'00'"}},
            {"id": "9 0", "offset": 600, "type": "/Sig",
             "dict": {"Type": "/Sig", "Filter": "/Adobe.PPKLite", "ByteRange": [0, 10, 20, 30],
                      "M": "D:20261101093000-05'00'", "Name": "Signer Example"}}]},
        {"objects": [
            {"id": "7 0", "offset": 1200, "type": "dict",
             "dict": {"Producer": "ExampleEditor 2.0", "CreationDate": "D:20261101090000-05'00'",
                      "ModDate": "D:20261105120000"}}]}]}
    r.output(2, folder, "objects.json", "objects_dump", objects, "2026-11-11T11:00:01.500Z")
    r.reports(2, folder, technical(r, 2, {"pdf": {
        "revisions": [
            {"index": 1, "saved_at_info": "2026-11-01T14:00:00Z", "saved_at_xmp": "2026-11-01T14:00:00Z",
             "producer": "ExampleWriter 1.0"},
            {"index": 2, "saved_at_info": "2026-11-05T12:00:00Z", "saved_at_xmp": None,
             "producer": "ExampleEditor 2.0"}],
        "signatures": [{"field": "Signature1", "signer_subject": "CN=Signer Example", "revision": 1,
                        "signing_time": "2026-11-01T14:30:00Z"}]}}), "2026-11-11T11:00:02.000Z")
    r.finish("2026-11-11T11:00:03.000Z")

    # rv-mailauth: one .eml (Date, two hops, attachment date) and an mbox with two messages.
    r = Run("rv-mailauth", "0.2.0", "20261111T120000Z-dddddd", "2026-11-11T12:00:00.000Z")
    folder = r.item(3, "2026-11-11T12:00:01.000Z", "2026-11-03T08:00:00Z", "verified")
    hop = lambda pos, by, frm, raw: {"by": by, "from": frm, "position": pos, "date_raw": raw, "header_index": 2 - pos}
    r.output(3, folder, "headers.json", "headers", {
        "attachments": [{"file_name": "invoice.csv", "index": 1, "creation_date_raw": None,
                         "modification_date_raw": "Fri, 13 Nov 2026 09:00:00 +0000", "sha256": "d1" * 32}],
        "headers": {"date_raw": "Tue, 10 Nov 2026 09:00:00 +0100", "message_id": "1@example.org",
                    "from": [{"address": "sender@example.org", "domain": "example.org", "name": "Sender"}],
                    "hops": [hop(2, "mx.example.com", "smtp.example.org", "Tue, 10 Nov 2026 08:00:04 +0000"),
                             hop(1, "smtp.example.org", "[192.0.2.10]", "Tue, 10 Nov 2026 09:00:00 +0100")],
                    "msg": None}}, "2026-11-11T12:00:01.500Z")
    folder = r.item(4, "2026-11-11T12:00:02.000Z", "2026-11-04T08:00:00Z", "verified")
    mbox = EVIDENCE[4][1]
    r.output(4, folder, "mbox_index.json", "mbox_index", {"bytes": 2000, "count": 2, "mbox": mbox, "messages": [
        {"from_line": "From sender@example.org Wed Nov 11 11:00:03 2026", "id": f"{mbox}#1@0", "n": 1, "offset": 0},
        {"from_line": "From sender@example.org Wed Nov 11 11:30:02 2026", "id": f"{mbox}#2@900", "n": 2,
         "offset": 900}]}, "2026-11-11T12:00:02.500Z")
    for n, off, date in [(1, 0, "Wed, 11 Nov 2026 12:00:00 +0100"), (2, 900, "Wed, 11 Nov 2026 12:30:00 -0000")]:
        r.output(4, f"{folder}_{n}_{off}", "headers.json", "headers", {
            "attachments": [], "headers": {"date_raw": date, "message_id": f"m{n}@example.org", "from": [],
                                           "hops": [], "msg": None}}, "2026-11-11T12:00:03.000Z",
                 item=f"{mbox}#{n}@{off}")
    r.finish("2026-11-11T12:00:04.000Z")

    # rv-rsmf: a WhatsApp export converted with --timezone America/Bogota.
    r = Run("rv-rsmf", "0.3.1", "20261111T130000Z-eeeeee", "2026-11-11T13:00:00.000Z")
    r.item(5, "2026-11-11T13:00:01.000Z", "2026-11-05T08:00:00Z", "verified")
    r.audit.add("conversion_started", "2026-11-11T13:00:01.100Z",
                {"options": {"source": None, "timezone": "America/Bogota", "slice": "day"},
                 "rsmf_dir": "rsmf"})
    rows = [
        {"export": "chat.zip", "source_file": "_chat.txt", "line": 1, "line_end": 1, "native_id": None,
         "source_time": "9/11/26, 18:00", "utc": "2026-11-09T23:00:00Z", "rsmf_file": "c1/2026-11-09.rsmf",
         "event_id": "e-000001", "conversation": "c1", "kind": "message", "attachments": 0},
        {"export": "chat.zip", "source_file": "_chat.txt", "line": 2, "line_end": 2, "native_id": None,
         "source_time": "9/11/26, 18:05", "utc": "2026-11-09T23:05:00Z", "rsmf_file": "c1/2026-11-09.rsmf",
         "event_id": "e-000002", "conversation": "c1", "kind": "message", "attachments": 1},
        {"export": "chat.zip", "source_file": "_chat.txt", "line": 3, "line_end": 3, "native_id": None,
         "source_time": "garbled", "utc": None, "rsmf_file": "c1/2026-11-09.rsmf",
         "event_id": "e-000003", "conversation": "c1", "kind": "message", "attachments": 0}]
    for name, obj in [("trace.json", rows), ("conversions.json", {"exports": [
            {"export": "chat.zip", "source": "whatsapp", "item_index": 5, "conversations": 1, "events": 3}]})]:
        h = r.file(f"rsmf/{name}", pretty(obj))
        r.audit.add("trace_written", "2026-11-11T13:00:02.000Z", h, item=name)
    r.finish("2026-11-11T13:00:03.000Z")

    # rv-certcheck: a certificate (validity, revoked by a CRL) and a timestamp token.
    r = Run("rv-certcheck", "0.2.2", "20261111T140000Z-ffffff", "2026-11-11T14:00:00.000Z")
    folder = r.item(6, "2026-11-11T14:00:01.000Z", "2026-11-06T08:00:00Z", "verified")
    cert = {"subject": "CN=Lab Leaf Example", "issuer": "CN=Lab CA Example", "serial_hex": "01",
            "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "sha256": "e1" * 32}
    chain = {"schema": "rakvor.cert-chain/1", "item": 6, "kind": "certificate", "certificates": [cert],
             "verdicts": [{"status": "invalid", "at": "2026-11-11T14:00:00Z", "nodes": [
                 {"depth": 0, "cert": cert, "status": "error",
                  "revocation": {"status": "revoked", "reason": "keyCompromise",
                                 "revoked_at": "2026-06-01T12:00:00Z",
                                 "source": {"kind": "crl", "origin": "evidence #7", "sha256": "f1" * 32}}}]}],
             "timestamp": {"info": {"gen_time": "2026-11-02T10:00:00Z", "tsa_name": "CN=TSA Example",
                                    "serial_hex": "0a", "accuracy": "1s"}, "imprint_file": "contract.pdf"}}
    r.output(6, folder, "chain.json", "chain", chain, "2026-11-11T14:00:02.000Z")
    r.finish("2026-11-11T14:00:03.000Z")

    # Excluded runs: not finished, unsupported tool, unsupported version.
    r = Run("rv-imgauth", "0.3.1", "20261112T090000Z-111111", "2026-11-12T09:00:00.000Z")
    r.item(1, "2026-11-12T09:00:01.000Z", "2026-11-01T08:00:00Z", "verified")
    r.audit.write()
    r = Run("rv-triage", "0.1.0", "20261112T100000Z-222222", "2026-11-12T10:00:00.000Z")
    r.finish("2026-11-12T10:00:01.000Z")
    r = Run("rv-hashinv", "0.3.1", "20261112T110000Z-333333", "2026-11-12T11:00:00.000Z", role="intake")
    r.finish("2026-11-12T11:00:01.000Z")

    CASE_LOG.write()


if __name__ == "__main__":
    main()
