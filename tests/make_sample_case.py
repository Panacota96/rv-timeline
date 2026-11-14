#!/usr/bin/env python3
"""Helper of tests/make_sample_case.sh (and .ps1): builds the curated evidence set, the tampered copies and
examples/sample/expected_timeline.json for the rv-timeline sample case.

    make_sample_case.py evidence <rakvor-root> <dst>     copy + derive the synthetic evidence set
    make_sample_case.py tamper   <clean-case> <dst-root>  write the three tampered copies of the clean case
    make_sample_case.py expected <clean-case> <tampered-root> <versions.json> <out.json>
    make_sample_case.py check-verify <expected.json> <clean-case> <tampered-root> <exe>...  verify-case on the clean
                                                          case and on the tampered copies

The tampered copies are not committed: the tests write them from examples/sample/case into a temporary folder with
`tamper` (the same edits every time); their expectations stay in expected_timeline.json.

Standard library only. Every value written to expected_timeline.json is read from the tools' own outputs (case.json,
case-log.jsonl, registry.json, the runs' audit.jsonl and JSON reports); the only things this script decides are
which of those values are time events and which signals they plant (see examples/sample/README.md).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

# ------------------------------------------------------------------------------------------------ evidence

# (tool repo, path below examples/sample/, destination below evidence/)
COPIES = [
    ("rv-pdfauth", "evidence/original.pdf", "pdf/original.pdf"),
    ("rv-pdfauth", "evidence/edited-incremental.pdf", "pdf/edited-incremental.pdf"),
    ("rv-pdfauth", "evidence/signed-then-modified.pdf", "pdf/signed-then-modified.pdf"),
    ("rv-imgauth", "evidence/camera-original.jpg", "images/camera-original.jpg"),
    ("rv-imgauth", "evidence/screenshot.png", "images/screenshot.png"),
    ("rv-imgauth", "evidence/edited-gimp.jpg", "images/edited-gimp.jpg"),
    ("rv-rsmf", "evidence/whatsapp-android-en/WhatsApp Chat with Ana Ruiz.txt",
     "chat/whatsapp-android-en/WhatsApp Chat with Ana Ruiz.txt"),
    ("rv-rsmf", "evidence/whatsapp-android-en/IMG-20260302-WA0001.jpg",
     "chat/whatsapp-android-en/IMG-20260302-WA0001.jpg"),
    ("rv-mailauth", "evidence/01-clean-rsa.eml", "mail/01-clean-rsa.eml"),
    ("rv-mailauth", "evidence/12-mailbox.mbox", "mail/12-mailbox.mbox"),
    ("rv-certcheck", "evidence/leaf.crt", "certs/leaf.crt"),
    ("rv-certcheck", "evidence/leaf-expired.crt", "certs/leaf-expired.crt"),
    ("rv-certcheck", "evidence/leaf-revoked.crt", "certs/leaf-revoked.crt"),
    ("rv-certcheck", "evidence/intermediate.crt", "certs/intermediate.crt"),
    ("rv-certcheck", "evidence/intermediate.crl", "certs/intermediate.crl"),
    ("rv-certcheck", "evidence/tsa.crt", "certs/tsa.crt"),
    ("rv-certcheck", "evidence/data.txt", "certs/data.txt"),
    ("rv-certcheck", "evidence/data.tsr", "certs/data.tsr"),
    # Not evidence: the lab root the certificates are judged against (--anchor), never registered.
    ("rv-certcheck", "anchors/rakvor-lab-root.crt", "../anchors/rakvor-lab-root.crt"),
]

# Derived files: a copy of a tool sample with same-length byte replacements (offsets inside the file are kept, so
# the structure the tools parse is unchanged). (repo, source, destination, [(old, new, expected count)], why)
DERIVED = [
    ("rv-pdfauth", "evidence/edited-incremental.pdf", "pdf/backdated-revision.pdf",
     [(b"/ModDate (D:20260311091500-05'00')", b"/ModDate (D:20260303091500-05'00')", 1)],
     "revision 3 ModDate moved before revision 2 (2026-03-04 12:15 -05:00) -> PDF_REVISION_BEFORE_PREVIOUS"),
    ("rv-imgauth", "evidence/reference/ref-1.jpg", "images/future-exif.jpg",
     [(b"2026:05:14 10:25:02", b"2031:05:14 10:25:02", 3)],
     "EXIF dates (with OffsetTime +02:00) moved to 2031 -> EXIF_AFTER_INTAKE and EVENT_IN_FUTURE"),
    ("rv-mailauth", "evidence/01-clean-rsa.eml", "mail/20-date-after-first-hop.eml",
     [(b"Date: Tue, 10 Nov 2026 09:00:00 +0100", b"Date: Tue, 10 Nov 2026 09:47:00 +0100", 1)],
     "Date header 47 min after both Received hops -> MAIL_DATE_AFTER_FIRST_HOP (and the DKIM signature breaks)"),
]


def cmd_evidence(root: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    for repo, src, rel in COPIES:
        out = (dst / rel).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / repo / "examples/sample" / src, out)
    notes = []
    for repo, src, rel, edits, why in DERIVED:
        data = (root / repo / "examples/sample" / src).read_bytes()
        for old, new, count in edits:
            assert len(old) == len(new), (old, new)
            found = data.count(old)
            if found != count:
                sys.exit(f"{repo}/{src}: expected {count} x {old!r}, found {found}")
            data = data.replace(old, new)
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        notes.append({"file": rel, "from": f"{repo}/examples/sample/{src}", "change": why,
                      "sha256": hashlib.sha256(data).hexdigest()})
    (dst.parent / "derived.json").write_text(json.dumps(notes, indent=2) + "\n", encoding="utf-8", newline="\n")
    # Fixed modification time for every file (the copy would otherwise carry the time of the build).
    for p in list(dst.rglob("*")) + list((dst.parent / "anchors").rglob("*")):
        if p.is_file():
            os.utime(p, (EVIDENCE_MTIME, EVIDENCE_MTIME))


# 2026-11-12T06:00:00Z: the evidence files' modification time (before the intake, after every event inside them
# except the planted future EXIF date).
EVIDENCE_MTIME = int(dt.datetime(2026, 11, 12, 6, 0, 0, tzinfo=dt.timezone.utc).timestamp())


# ------------------------------------------------------------------------------------------------ case helpers


def jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runs_of(case: Path) -> list[dict]:
    """Runs in case-log order: {tool, version, run_id, run_dir, finished}."""
    out, by_id = [], {}
    for e in jsonl(case / "case-log.jsonl"):
        d = e.get("details", {})
        if e["action"] == "run_started":
            r = {"tool": d["tool"], "version": d["version"], "run_id": e["run_id"], "run_dir": d["run_dir"],
                 "started_ts": e["ts_utc"], "finished": None}
            out.append(r)
            by_id[e["run_id"]] = r
        elif e["action"] == "run_finished" and e["run_id"] in by_id:
            by_id[e["run_id"]]["finished"] = e
    return out


def run_of(case: Path, tool: str, nth: int = 0) -> dict:
    return [r for r in runs_of(case) if r["tool"] == tool][nth]


# ------------------------------------------------------------------------------------------------ tamper

TAMPERED = {
    "digest-mismatch": {
        "tool": "rv-imgauth",
        "reason": "digest_mismatch",
        "what": "reports/items/<n>-future-exif.jpg/metadata.json: the EXIF year 2031 replaced by 2026 (backdating "
                "the dates the timeline reads; the audit log still records the original SHA-256 of that file)",
    },
    "chain-broken": {
        "tool": "rv-mailauth",
        "reason": "chain_broken",
        "what": "logs/audit.jsonl: the item_analyzed entry of 20-date-after-first-hop.eml edited (finding "
                "DATE_AFTER_FIRST_HOP removed) without recomputing entry_hash",
    },
    "not-finished": {
        "tool": "rv-certcheck",
        "reason": "not_finished",
        "what": "the run's run_finished entry removed from case-log.jsonl (the last case-log entry) and the run's "
                "audit.jsonl/audit.log cut before its own run_finished entry: a run interrupted before it ended",
    },
}


def cmd_tamper(clean: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    for name, t in TAMPERED.items():
        case = dst / name
        shutil.copytree(clean, case)
        run = run_of(case, t["tool"])
        rd = case / run["run_dir"]
        if name == "digest-mismatch":
            [f] = list(rd.glob("reports/items/*-future-exif.jpg/metadata.json"))
            data = f.read_bytes()
            n = data.count(b"2031:05:14")
            assert n >= 1, f
            f.write_bytes(data.replace(b"2031:05:14", b"2026:05:14"))
            t["file"] = f.relative_to(rd).as_posix()
        elif name == "chain-broken":
            p = rd / "logs/audit.jsonl"
            lines = p.read_text(encoding="utf-8").split("\n")
            hits = [i for i, x in enumerate(lines)
                    if '"action":"item_analyzed"' in x and "20-date-after-first-hop.eml" in x
                    and '"DATE_AFTER_FIRST_HOP"' in x]
            assert len(hits) == 1, hits
            i = hits[0]
            before = lines[i]
            # The line is canonical JSON (sorted keys, no spaces): re-serialising an untouched entry gives the same
            # bytes, so the only change is the removed finding.
            entry = json.loads(before)
            assert json.dumps(entry, separators=(",", ":"), sort_keys=True, ensure_ascii=False) == before
            entry["details"]["findings"] = [f for f in entry["details"]["findings"]
                                            if f.get("code") != "DATE_AFTER_FIRST_HOP"]
            after = json.dumps(entry, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
            assert after != before
            lines[i] = after
            p.write_text("\n".join(lines), encoding="utf-8", newline="")
            t["seq"] = json.loads(after)["seq"]
        elif name == "not-finished":
            cl = case / "case-log.jsonl"
            lines = cl.read_text(encoding="utf-8").splitlines(keepends=True)
            last = json.loads(lines[-1])
            assert last["action"] == "run_finished" and last["run_id"] == run["run_id"], last["action"]
            cl.write_text("".join(lines[:-1]), encoding="utf-8", newline="")
            p = rd / "logs/audit.jsonl"
            al = p.read_text(encoding="utf-8").splitlines(keepends=True)
            cut = next(i for i, x in enumerate(al) if json.loads(x)["action"] == "run_finished")
            p.write_text("".join(al[:cut]), encoding="utf-8", newline="")
            t["audit_entries_kept"] = cut
            log = rd / "logs/audit.log"
            if log.exists():
                ll = log.read_text(encoding="utf-8").splitlines(keepends=True)
                k = next((i for i, x in enumerate(ll) if re.search(r"  #\d+  run_finished", x)), None)
                if k is not None:
                    log.write_text("".join(ll[:k]), encoding="utf-8", newline="")
        t["run_id"] = run["run_id"]
        t["run_dir"] = run["run_dir"]


# ------------------------------------------------------------------------------------------------ time parsing
# Each parser returns (utc_s, utc_ns, zone, offset_min, precision) for one source string, read exactly as the
# source states it: no zone is ever guessed (zone "unknown" = the wall-clock time read as UTC).

EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def _pack(naive: dt.datetime, offset_min: int | None, frac_digits: int, ns: int = 0, precision: str | None = None):
    off = offset_min or 0
    utc = naive.replace(tzinfo=dt.timezone.utc) - dt.timedelta(minutes=off)
    s = int((utc - EPOCH).total_seconds())
    prec = precision or {0: "second", 3: "millisecond", 6: "microsecond", 9: "nanosecond"}[frac_digits]
    return s, ns, ("explicit" if offset_min is not None else "unknown"), offset_min, prec


def parse_offset(s: str) -> int:
    s = s.strip().replace("'", "").replace(":", "")
    if s in ("Z", "z", ""):
        return 0
    sign = -1 if s[0] == "-" else 1
    return sign * (int(s[1:3]) * 60 + int(s[3:5] or 0))


def t_iso(s: str):
    """2026-11-12T23:07:12.276Z, 2026-05-16T18:02:10+02:00"""
    import re
    m = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?(Z|[+-]\d\d:?\d\d)?", s)
    assert m, s
    frac = m.group(7) or ""
    ns = int((frac + "000000000")[:9]) if frac else 0
    naive = dt.datetime(*map(int, m.groups()[:6]))
    off = parse_offset(m.group(8)) if m.group(8) else None
    return _pack(naive, off, len(frac), ns)


def t_exif(s: str, offset: str | None, subsec: str | None = None):
    """EXIF 2026:05:14 10:21:33 (+ OffsetTime* and SubSecTime* when present)."""
    naive = dt.datetime.strptime(s, "%Y:%m:%d %H:%M:%S")
    digits = (subsec or "").strip()
    assert digits.isdigit() or not digits, subsec
    ns = int((digits + "000000000")[:9]) if digits else 0
    frac = {0: 0, 1: 3, 2: 3, 3: 3, 4: 6, 5: 6, 6: 6}.get(len(digits), 9)
    return _pack(naive, parse_offset(offset) if offset else None, frac, ns)


def t_asctime(s: str):
    """Wed Nov 11 11:00:03 2026 (mbox From_ line): no zone."""
    naive = dt.datetime.strptime(" ".join(s.split()), "%a %b %d %H:%M:%S %Y")
    return _pack(naive, None, 0)


def t_rfc5322(s: str):
    """Tue, 10 Nov 2026 09:00:00 +0100"""
    import email.utils
    tup = email.utils.parsedate_tz(s)
    assert tup and tup[9] is not None, s
    naive = dt.datetime(*tup[:6])
    return _pack(naive, tup[9] // 60, 0)


def t_pdf(s: str):
    """D:20260302091500-05'00'"""
    import re
    m = re.fullmatch(r"D:(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(Z|[+-]\d\d'?\d\d'?)?", s)
    assert m, s
    naive = dt.datetime(*map(int, m.groups()[:6]))
    off = parse_offset(m.group(7)) if m.group(7) else None
    return _pack(naive, off, 0)


def iso_utc(s: int, ns: int) -> str:
    t = EPOCH + dt.timedelta(seconds=s)
    base = t.strftime("%Y-%m-%dT%H:%M:%S")
    return base + (f".{ns:09d}".rstrip("0") if ns else "") + "Z"


# ------------------------------------------------------------------------------------------------ readers
# One function per tool: (case, run, ctx) -> list of raw events. A raw event names the output file it was read from
# (relative to the run folder) and the JSON pointer of the value inside it.


def load(rd: Path, rel: str):
    return json.loads((rd / rel).read_text(encoding="utf-8"))


def ev(kind, parsed, original, item, file, pointer, sub="", **details):
    s, ns, zone, off, prec = parsed
    return {"kind": kind, "utc_s": s, "utc_ns": ns, "zone": zone, "offset_min": off, "precision": prec,
            "original": original, "item": item, "sub": sub, "file": file, "pointer": pointer,
            "details": {k: str(v) for k, v in details.items() if v is not None}}


def items_of(rd: Path) -> list[tuple[str, dict]]:
    """(technical.json path relative to the run, parsed) for every item report of the run, in index order."""
    out = []
    for f in sorted(rd.glob("reports/items/*/technical.json")):
        out.append((f.relative_to(rd).as_posix(), json.loads(f.read_text(encoding="utf-8"))))
    return out


def common_item_events(run: dict, rel: str, d: dict, registry: dict) -> list[dict]:
    """fs.modified from every run's item report; intake.registered from the run that registered the item."""
    out = []
    it = d["item"]
    eid = it.get("evidence_id") or ""
    if it.get("modified_utc"):
        out.append(ev("fs.modified", t_iso(it["modified_utc"]), it["modified_utc"], eid, rel, "/item/modified_utc"))
    reg = registry.get(eid)
    case = d.get("case") or {}
    if reg and reg["registered_by"]["run_id"] == run["run_id"] and case.get("intake_utc"):
        out.append(ev("intake.registered", t_iso(case["intake_utc"]), case["intake_utc"], eid, rel,
                      "/case/intake_utc"))
    return out


def read_hashinv(case: Path, run: dict, registry: dict) -> list[dict]:
    rd = case / run["run_dir"]
    out = []
    for rel, d in items_of(rd):
        out += common_item_events(run, rel, d, registry)
    return out


# (EXIF tag, its group, kind, the OffsetTime* tag that states its zone, the SubSecTime* tag)
EXIF_KINDS = [
    ("DateTimeOriginal", "Exif", "exif.original", "OffsetTimeOriginal", "SubSecTimeOriginal"),
    ("DateTimeDigitized", "Exif", "exif.digitized", "OffsetTimeDigitized", "SubSecTimeDigitized"),
    ("DateTime", "IFD0", "exif.modify", "OffsetTime", "SubSecTime"),
]
XMP_KINDS = {"xmp:CreateDate": "xmp.create", "xmp:ModifyDate": "xmp.modify", "xmp:MetadataDate": "xmp.metadata",
             "photoshop:DateCreated": "xmp.photoshop_created", "exif:DateTimeOriginal": "xmp.exif_original"}


def read_imgauth(case: Path, run: dict, registry: dict) -> list[dict]:
    rd = case / run["run_dir"]
    out = []
    for rel, d in items_of(rd):
        out += common_item_events(run, rel, d, registry)
        eid = d["item"].get("evidence_id") or ""
        # metadata.json holds every tag (technical.json's summary leaves OffsetTimeDigitized out).
        mrel = rel.replace("technical.json", "metadata.json")
        meta = load(rd, mrel)
        tags = meta["tags"]
        byname = {}
        for i, t in enumerate(tags):
            byname.setdefault((t["group"], t["name"]), (i, t["value"]))
        for name, group, kind, offtag, subtag in EXIF_KINDS:
            for i, t in enumerate(tags):
                if (t["group"], t["name"]) != (group, name):
                    continue
                off = byname.get(("Exif", offtag))
                sub = byname.get(("Exif", subtag))
                out.append(ev(kind, t_exif(t["value"], off[1] if off else None, sub[1] if sub else None),
                              t["value"] + (f" {off[1]}" if off else ""), eid, mrel, f"/tags/{i}/value",
                              offset_pointer=(f"/tags/{off[0]}/value" if off else None)))
        if ("GPS", "GPSDateStamp") in byname:
            sys.exit(f"{mrel}: GPS time not in the sample: extend make_sample_case.py (rv-timeline reads gps.time)")
        for i, t in enumerate(tags):
            if t["group"] == "PNG-tIME" and t["name"] == "tIME":
                # PNG tIME is UTC by the PNG specification (11.3.6.1); rv-imgauth labels it UTC.
                naive = dt.datetime.strptime(t["value"], "%Y-%m-%d %H:%M:%S")
                out.append(ev("png.time", _pack(naive, 0, 0), t["value"], eid, mrel, f"/tags/{i}/value"))
            elif t["group"].startswith("PNG") and t["name"] == "Creation Time":
                sys.exit(f"{mrel}: PNG Creation Time not in the sample: extend make_sample_case.py")
            elif t["group"] == "XMP" and t["name"] in XMP_KINDS:
                out.append(ev(XMP_KINDS[t["name"]], t_iso(t["value"].strip()), t["value"], eid, mrel,
                              f"/tags/{i}/value"))
        for i, h in enumerate(meta.get("xmp_history") or []):
            if h.get("when"):
                out.append(ev("xmp.history", t_iso(h["when"].strip()), h["when"], eid, mrel,
                              f"/xmp_history/{i}/when", action=h.get("action"), software=h.get("software_agent")))
    return out


CHAT_KINDS = {"": "chat.message", "message": "chat.message", "disclaimer": "chat.disclaimer", "join": "chat.join",
              "leave": "chat.leave", "history": "chat.history"}


def read_rsmf(case: Path, run: dict, registry: dict) -> list[dict]:
    rd = case / run["run_dir"]
    out = []
    by_export = {}
    for rel, d in items_of(rd):
        out += common_item_events(run, rel, d, registry)
        conv = d.get("conversion") or {}
        if conv.get("export"):
            by_export[conv["export"]] = (d["item"].get("evidence_id") or "", conv)
    trace = load(rd, "rsmf/trace.json")
    for i, t in enumerate(trace):
        eid, conv = by_export[t["export"]]
        tz = conv["facts"].get("timezone")
        assert tz, "the sample's chat is converted with --timezone (else its times are zone-unknown)"
        s, ns, _, _, _ = t_iso(t["utc"])
        # The export has no offset; rv-rsmf applied the examiner's --timezone. The offset is the one that zone gives
        # at that instant (utc - local wall clock), recorded as explicit with its basis in the details.
        local = dt.datetime.strptime(t["source_time"], "%d/%m/%Y, %H:%M")
        off = int((local.replace(tzinfo=dt.timezone.utc) - (EPOCH + dt.timedelta(seconds=s))).total_seconds() // 60)
        # Sub-item: <conversation id>/<day>, the day being the stem of the RSMF file the row went into.
        day = Path(t["rsmf_file"].replace("\\", "/")).stem
        out.append(ev(CHAT_KINDS.get(t["kind"] or "", "chat.unknown"), (s, ns, "explicit", off, "minute"),
                      t["source_time"], eid, "rsmf/trace.json", f"/{i}/source_time",
                      sub=f"{t['conversation']}/{day}", chat_kind=t["kind"], line=t["line"],
                      timezone_basis=f"--timezone {tz}", event_id=t["event_id"]))
    return out


def read_mailauth(case: Path, run: dict, registry: dict) -> list[dict]:
    rd = case / run["run_dir"]
    out = []
    for rel, d in items_of(rd):
        it = d["item"]
        eid = it.get("evidence_id") or ""
        derived = d.get("derived_from")
        if not derived:  # a message inside an mbox carries its container's file times: read them once
            out += common_item_events(run, rel, d, registry)
        sub = f"#{derived['n']}" if derived else ""
        irel = rel.replace("technical.json", "mbox_index.json")
        if (rd / irel).exists():
            # The mbox "From " separator line: the time the message was written to the mailbox (asctime, no zone).
            for i, m in enumerate(load(rd, irel).get("messages") or []):
                if m.get("from_line"):
                    out.append(ev("mail.mbox_from", t_asctime(" ".join(m["from_line"].split()[-5:])),
                                  m["from_line"], eid, irel, f"/messages/{i}/from_line", sub=f"#{m['n']}",
                                  offset=m.get("offset")))
        hrel = rel.replace("technical.json", "headers.json")
        if not (rd / hrel).exists():
            continue  # the mbox container itself: its messages are items of their own
        doc = load(rd, hrel)
        h = doc["headers"]
        if h.get("date_raw"):
            out.append(ev("mail.date", t_rfc5322(h["date_raw"]), h["date_raw"], eid, hrel, "/headers/date_raw",
                          sub=sub, message_id=h.get("message_id")))
        for i, hop in enumerate(h.get("hops") or []):
            if hop.get("date_raw"):
                out.append(ev("mail.hop", t_rfc5322(hop["date_raw"]), hop["date_raw"], eid, hrel,
                              f"/headers/hops/{i}/date_raw", sub=sub, position=hop["position"], by=hop.get("by"),
                              host=hop.get("from")))
        for i, a in enumerate(doc.get("attachments") or []):
            for key, kind in (("creation_date_raw", "mail.attachment.created"),
                              ("modification_date_raw", "mail.attachment.modified")):
                if a.get(key):
                    out.append(ev(kind, t_rfc5322(a[key]), a[key], eid, hrel, f"/attachments/{i}/{key}", sub=sub,
                                  file_name=a.get("file_name")))
        if isinstance(h.get("msg"), dict):
            for key, kind in (("client_submit_time", "mail.msg.submitted"), ("delivery_time", "mail.msg.delivered")):
                if h["msg"].get(key):
                    out.append(ev(kind, t_iso(h["msg"][key]), h["msg"][key], eid, hrel, f"/headers/msg/{key}",
                                  sub=sub))
    return out


def read_pdfauth(case: Path, run: dict, registry: dict) -> list[dict]:
    """objects.json: the Info dictionary (CreationDate, ModDate) written in each revision and each signature
    dictionary's /M, with the PDF date strings as the file states them; technical.json: CMS signing times and the
    XMP saved time per revision. sub = r<n> (revision n, from 1)."""
    rd = case / run["run_dir"]
    out = []
    for rel, d in items_of(rd):
        out += common_item_events(run, rel, d, registry)
        eid = d["item"].get("evidence_id") or ""
        orel = rel.replace("technical.json", "objects.json")
        has_objects = (rd / orel).exists()
        pdf = d.get("pdf") or {}
        for ri, rev in enumerate(pdf.get("revisions") or []):
            n = rev.get("index") or ri + 1
            for key, kind, wanted in (("saved_at_info", "pdf.info.saved", not has_objects),
                                      ("saved_at_xmp", "pdf.xmp.saved", True)):
                if wanted and rev.get(key):
                    out.append(ev(kind, t_iso(rev[key]), rev[key], eid, rel, f"/pdf/revisions/{ri}/{key}",
                                  sub=f"r{n}", revision=n))
        for si, sig in enumerate(pdf.get("signatures") or []):
            if sig.get("signing_time"):
                out.append(ev("pdf.revision.signed", t_iso(sig["signing_time"]), sig["signing_time"], eid, rel,
                              f"/pdf/signatures/{si}/signing_time",
                              sub=f"r{sig['revision']}" if sig.get("revision") else "", revision=sig.get("revision")))
        if not has_objects:
            continue
        for ri, rev in enumerate(load(rd, orel).get("revisions") or []):
            n = ri + 1
            for oi, obj in enumerate(rev.get("objects") or []):
                dd = obj.get("dict") if isinstance(obj.get("dict"), dict) else None
                if dd is None:
                    continue
                base = f"/revisions/{ri}/objects/{oi}/dict"
                if dd.get("Type") == "/Sig" or "ByteRange" in dd:
                    if isinstance(dd.get("M"), str):
                        out.append(ev("pdf.signature.claimed", t_pdf(dd["M"]), dd["M"], eid, orel, f"{base}/M",
                                      sub=f"r{n}", revision=n, object=obj.get("id")))
                elif "Type" not in dd:  # the Info dictionary has no /Type
                    for key, kind in (("CreationDate", "pdf.info.created"), ("ModDate", "pdf.info.modified")):
                        if isinstance(dd.get(key), str):
                            out.append(ev(kind, t_pdf(dd[key]), dd[key], eid, orel, f"{base}/{key}", sub=f"r{n}",
                                          revision=n, object=obj.get("id")))
    return out


def read_certcheck(case: Path, run: dict, registry: dict) -> list[dict]:
    """chain.json: the item's own certificates (validity), a revocation time, an RFC 3161 token's genTime.
    rv-certcheck 0.2.x writes these as normalised UTC strings (Z); that string is the original kept here. A CRL
    item's own thisUpdate/nextUpdate are not in its outputs, so a CRL has file times only. Sub-item c<n> (n-th
    certificate of the file) only when the file holds several certificates."""
    rd = case / run["run_dir"]
    out = []
    for rel, d in items_of(rd):
        out += common_item_events(run, rel, d, registry)
        eid = d["item"].get("evidence_id") or ""
        crel = rel.replace("technical.json", "chain.json")
        if not (rd / crel).exists():
            continue
        c = load(rd, crel)
        certs = c.get("certificates") or []

        def csub(i: int) -> str:
            return f"c{i + 1}" if len(certs) > 1 else ""

        for i, cert in enumerate(certs):
            for kind, key in (("cert.not_before", "not_before"), ("cert.not_after", "not_after")):
                if cert.get(key):
                    out.append(ev(kind, t_iso(cert[key]), cert[key], eid, crel, f"/certificates/{i}/{key}",
                                  sub=csub(i), subject=cert.get("subject"), serial=cert.get("serial_hex")))
        for v, verdict in enumerate(c.get("verdicts") or []):
            for ni, node in enumerate(verdict.get("nodes") or []):
                rev = node.get("revocation") or {}
                if rev.get("status") != "revoked" or not rev.get("revoked_at"):
                    continue
                sha = (node.get("cert") or {}).get("sha256")
                pos = next((i for i, x in enumerate(certs) if sha and x.get("sha256") == sha), None)
                out.append(ev("cert.revoked", t_iso(rev["revoked_at"]), rev["revoked_at"], eid, crel,
                              f"/verdicts/{v}/nodes/{ni}/revocation/revoked_at",
                              sub=csub(pos) if pos is not None else "", subject=node["cert"].get("subject")))
        ts = (c.get("timestamp") or {}).get("info") or {}
        if ts.get("gen_time"):
            out.append(ev("tsa.gen_time", t_iso(ts["gen_time"]), ts["gen_time"], eid, crel,
                          "/timestamp/info/gen_time", accuracy=ts.get("accuracy"), serial=ts.get("serial_hex")))
    return out


def run_level_events(case: Path, run: dict) -> list[dict]:
    """run.started / run.finished: ts_utc of the run's own run_started / run_finished audit entries (the chained
    record; reports/statistics.json is written before the final entry and holds slightly different times);
    run.timestamped: genTime of each RFC 3161 token over the audit log."""
    rd = case / run["run_dir"]
    out = []
    for line, e in enumerate(jsonl_lines(rd / AUDIT), start=1):
        if e is None:
            continue
        a = e["action"]
        if a in ("run_started", "run_finished"):
            out.append(ev(a.replace("_", "."), t_iso(e["ts_utc"]), e["ts_utc"], "", AUDIT, f"line:{line}/ts_utc",
                          actor=e.get("actor")))
        elif a == "timestamp_obtained" and (e.get("details") or {}).get("gen_time"):
            g = e["details"]["gen_time"]
            out.append(ev("run.timestamped", t_iso(g), g, "", AUDIT, f"line:{line}/details/gen_time",
                          tsa=e["details"].get("tsa")))
    return out


AUDIT = "logs/audit.jsonl"


def jsonl_lines(path: Path) -> list[dict | None]:
    """Each line of a JSON Lines file (None for a blank line), so that line numbers stay 1-based file lines."""
    return [json.loads(x) if x.strip() else None for x in path.read_text(encoding="utf-8").splitlines()]


# ------------------------------------------------------------------------------------------------ digests


def audit_digests(rd: Path) -> dict[str, str]:
    """Output file (relative to the run folder) -> SHA-256 as the run's audit log records it."""
    out = {}
    for e in jsonl(rd / "logs/audit.jsonl"):
        d = e.get("details") or {}
        a = e["action"]
        if a in ("item_reports_written", "statistics_report_written") and isinstance(d.get("files"), dict):
            base = "reports/" + (d["folder"] + "/" if d.get("folder") else "")
            for name, h in d["files"].items():
                out[base + name] = h["sha256"]
        elif a == "output_written" and d.get("file"):
            out["reports/" + d["file"]] = (d.get("hashes") or d.get("digest"))["sha256"]
        elif a in ("trace_written", "rsmf_written") and e.get("item"):
            out["rsmf/" + e["item"]] = d.get("sha256") or d["hashes"]["sha256"]
    return out


# ------------------------------------------------------------------------------------------------ expected

READERS = {
    "rv-hashinv": lambda c, r, g: read_hashinv(c, r, g),
    "rv-imgauth": lambda c, r, g: read_imgauth(c, r, g),
    "rv-rsmf": lambda c, r, g: read_rsmf(c, r, g),
    "rv-mailauth": lambda c, r, g: read_mailauth(c, r, g),
    "rv-pdfauth": lambda c, r, g: read_pdfauth(c, r, g),
    "rv-certcheck": lambda c, r, g: read_certcheck(c, r, g),
}

CLOCK_SKEW_S = 300  # TimelineOptions::default().clock_skew_s
# Kinds that state a validity bound or a schedule, not something that happened: never EVENT_IN_FUTURE.
NOT_OCCURRENCES = {"cert.not_before", "cert.not_after", "crl.next_update", "crl.this_update"}
EXIF_EVENT_KINDS = {"exif.original", "exif.digitized", "exif.modify"}
SEVERITY = {  # proposed severities (the engine owns them; the codes, events and items are the ground truth)
    "EXIF_AFTER_INTAKE": "high", "FILE_MODIFIED_AFTER_INTAKE": "medium", "PDF_REVISION_BEFORE_PREVIOUS": "medium",
    "MAIL_DATE_AFTER_FIRST_HOP": "medium", "EVENT_IN_FUTURE": "medium", "CLOCK_SKEW_SUSPECTED": "low",
    "ZONE_UNKNOWN_EVENTS": "info",
}


def item_key(e: dict) -> str:
    if not e["item"]:
        return "run"
    return e["item"] + (f"/{e['sub']}" if e["sub"] else "")


def build_events(case: Path, runs: list[dict], registry: dict) -> list[dict]:
    events = []
    for run in runs:
        rd = case / run["run_dir"]
        digests = audit_digests(rd)
        raw = READERS[run["tool"]](case, run, registry) + run_level_events(case, run)
        counters: dict[tuple, int] = {}
        for e in raw:
            k = (item_key(e), e["kind"])
            n = counters.get(k, 0)
            counters[k] = n + 1
            # The audit log is checked by its hash chain (and the case log's record of its head), not by a digest.
            digest = sha256(rd / AUDIT) if e["file"] == AUDIT else digests.get(e["file"])
            if digest is None:
                sys.exit(f"{run['run_dir']}/{e['file']}: no digest in the audit log")
            if digest != sha256(rd / e["file"]):
                sys.exit(f"{run['run_dir']}/{e['file']}: digest differs from the audit log in the clean case")
            reg = registry.get(e["item"])
            events.append({
                "id": f"{run['tool']}:{run['run_id']}:{k[0]}:{e['kind']}:{n}",
                "utc": iso_utc(e["utc_s"], e["utc_ns"]),
                "utc_s": e["utc_s"], "utc_ns": e["utc_ns"], "zone": e["zone"], "offset_min": e["offset_min"],
                "precision": e["precision"], "original": e["original"], "kind": e["kind"],
                "item": {"evidence_id": e["item"], "path": reg["path"] if reg else "", "sub": e["sub"],
                         "sha256": reg["hashes"].get("sha256", "") if reg else ""},
                "source": {"tool": run["tool"], "tool_version": run["version"], "run_id": run["run_id"],
                           "run_dir": run["run_dir"], "file": e["file"], "file_sha256": digest,
                           "pointer": e["pointer"]},
                "details": e["details"],
            })
    events.sort(key=lambda x: (x["utc_s"], x["utc_ns"], x["id"]))
    return events


def ref(e: dict) -> str:
    return e["id"]


def build_signals(events: list[dict], runs: list[dict], registry: dict, excluded: list[dict]) -> list[dict]:
    sig = []

    def add(code, evs, eid, sub="", **params):
        item = None
        if eid:
            r = registry[eid]
            item = {"evidence_id": eid, "path": r["path"], "sub": sub, "sha256": r["hashes"].get("sha256", "")}
        sig.append({"code": code, "severity": SEVERITY[code], "events": [ref(e) for e in evs], "item": item,
                    "params": {k: str(v) for k, v in params.items()}})

    by_item: dict[str, list[dict]] = {}
    for e in events:
        if e["item"]["evidence_id"]:
            by_item.setdefault(e["item"]["evidence_id"], []).append(e)
    last_finished = max(e["utc_s"] for e in events if e["kind"] == "run.finished")

    for eid in sorted(by_item):
        evs = by_item[eid]
        intake = [e for e in evs if e["kind"] == "intake.registered"]
        it = intake[0] if intake else None
        if it:
            t0 = (it["utc_s"], it["utc_ns"])
            # EXIF_AFTER_INTAKE: an EXIF date (zone stated) later than the item's registration.
            late = [e for e in evs if e["kind"] in EXIF_EVENT_KINDS and e["zone"] == "explicit"
                    and (e["utc_s"], e["utc_ns"]) > t0]
            if late:
                add("EXIF_AFTER_INTAKE", late + [it], eid, delta_s=min(e["utc_s"] for e in late) - it["utc_s"])
            # FILE_MODIFIED_AFTER_INTAKE: a modification time later than the registration, either beyond the
            # tolerated skew or (any amount) differing from the one the intake run itself recorded.
            seen = {(e["utc_s"], e["utc_ns"]) for e in evs
                    if e["kind"] == "fs.modified" and e["source"]["run_id"] == it["source"]["run_id"]}
            mod = [e for e in evs if e["kind"] == "fs.modified" and (e["utc_s"], e["utc_ns"]) > t0
                   and (e["utc_s"] - it["utc_s"] > CLOCK_SKEW_S
                        or (seen and e["source"]["run_id"] != it["source"]["run_id"]
                            and (e["utc_s"], e["utc_ns"]) not in seen))]
            if mod:
                add("FILE_MODIFIED_AFTER_INTAKE", mod + [it], eid,
                    delta_s=min(e["utc_s"] for e in mod) - it["utc_s"], runs=len({e["source"]["run_id"] for e in mod}))
        # PDF_REVISION_BEFORE_PREVIOUS: revision n's ModDate earlier than revision n-1's (one run's reading).
        by_run: dict[str, list[dict]] = {}
        for e in evs:
            if e["kind"] == "pdf.info.modified":
                by_run.setdefault(e["source"]["run_id"], []).append(e)
        for rid, revs in by_run.items():
            revs = sorted(revs, key=lambda e: int(e["details"]["revision"]))
            for a, b in zip(revs, revs[1:]):
                if (b["utc_s"], b["utc_ns"]) < (a["utc_s"], a["utc_ns"]):
                    add("PDF_REVISION_BEFORE_PREVIOUS", [a, b], eid, revision=b["details"]["revision"],
                        previous=a["details"]["revision"], delta_s=a["utc_s"] - b["utc_s"])
        # Mail: per message (sub), Date after the first hop; hops going back in time beyond the tolerated skew.
        msgs: dict[tuple, list[dict]] = {}
        for e in evs:
            if e["kind"] in ("mail.date", "mail.hop"):
                msgs.setdefault((e["source"]["run_id"], e["item"]["sub"]), []).append(e)
        for (rid, sub), m in sorted(msgs.items()):
            hops = sorted([e for e in m if e["kind"] == "mail.hop"], key=lambda e: int(e["details"]["position"]))
            date = [e for e in m if e["kind"] == "mail.date"]
            if date and hops and date[0]["utc_s"] - hops[0]["utc_s"] > CLOCK_SKEW_S:
                add("MAIL_DATE_AFTER_FIRST_HOP", [date[0], hops[0]], eid, sub=sub,
                    delta_s=date[0]["utc_s"] - hops[0]["utc_s"])
            for a, b in zip(hops, hops[1:]):
                if a["utc_s"] - b["utc_s"] > CLOCK_SKEW_S:
                    add("CLOCK_SKEW_SUSPECTED", [a, b], eid, sub=sub, basis="received_hops",
                        skew_s=a["utc_s"] - b["utc_s"], hosts=f"{a['details'].get('by')} -> {b['details'].get('by')}")
        # EVENT_IN_FUTURE: something that happened after the last run of the case finished.
        fut = [e for e in evs if e["kind"] not in NOT_OCCURRENCES and e["utc_s"] > last_finished]
        if fut:
            add("EVENT_IN_FUTURE", fut, eid, reference="last run.finished",
                delta_s=min(e["utc_s"] for e in fut) - last_finished)
    # ZONE_UNKNOWN_EVENTS: one case-level count (no item, no event list), as the engine's spec says.
    unk = [e for e in events if e["zone"] == "unknown"]
    if unk:
        add("ZONE_UNKNOWN_EVENTS", [], "", count=len(unk),
            tools=", ".join(sorted({e["source"]["tool"] for e in unk})))
    for x in excluded:
        # The engine's severity: medium when the run's own record is inconsistent, low when it is just missing.
        sev = "medium" if x["reason"] in ("chain_broken", "digest_mismatch") else "low"
        sig.append({"code": "RUN_NOT_VERIFIED", "severity": sev, "events": [],
                    "item": None, "params": {"tool": x["tool"], "run_id": x["run_id"], "reason": x["reason"]}})
    return sig


def registry_of(case: Path) -> dict:
    return {i["evidence_id"]: i for i in load(case, "evidence/registry.json")["items"]}


def summarize(case: Path, rel_case: str, excluded: list[dict] | None = None) -> dict:
    excluded = excluded or []
    ex_ids = {x["run_id"] for x in excluded}
    registry = registry_of(case)
    runs = runs_of(case)
    ok = [r for r in runs if r["run_id"] not in ex_ids]
    events = build_events(case, ok, registry)
    signals = build_signals(events, ok, registry, excluded)
    count: dict[str, int] = {}
    for e in events:
        count[e["source"]["run_id"]] = count.get(e["source"]["run_id"], 0) + 1
    run_refs = []
    for r in runs:
        x = next((x for x in excluded if x["run_id"] == r["run_id"]), None)
        run_refs.append({"tool": r["tool"], "tool_version": r["version"], "run_id": r["run_id"],
                         "run_dir": r["run_dir"], "status": "excluded" if x else "verified",
                         "exclusion": {"reason": x["reason"], "detail": x["what"]} if x else None,
                         "events": 0 if x else count.get(r["run_id"], 0)})
    items = []
    for eid, reg in sorted(registry.items()):
        evs = [e for e in events if e["item"]["evidence_id"] == eid]
        kinds: dict[str, int] = {}
        for e in evs:
            kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        items.append({"evidence_id": eid, "path": reg["path"], "sha256": reg["hashes"].get("sha256", ""),
                      "event_counts": dict(sorted(kinds.items())), "events": [e["id"] for e in evs]})
    return {"case_dir": rel_case, "case_id": load(case, "case.json")["case_id"], "runs": run_refs,
            "events_total": len(events), "zone_unknown": sum(e["zone"] == "unknown" for e in events),
            "items": items, "events": events, "signals": signals}


def cmd_expected(clean: Path, tampered: Path, versions: Path, out: Path) -> None:
    doc = {
        "schema": "rv-timeline.sample-expected/1",
        "description": "Ground truth for `rv-timeline build --case-dir examples/sample/case` and the tampered copies, "
                       "derived by tests/make_sample_case.py from the tools' own outputs. See "
                       "examples/sample/README.md for where each field comes from.",
        "options": {"display_zone": "UTC", "clock_skew_s": CLOCK_SKEW_S},
        "tool_versions": load(versions.parent, versions.name)["tools"],
        "event_id": "<tool>:<run_id>:<evidence_id>[/<sub>]:<kind>:<n> (run-level events: <evidence_id> = 'run'); "
                    "n counts from 0 per (run, item/sub, kind) in the order of the values in the source file",
        "clean": summarize(clean, "examples/sample/case"),
        "clean_verify_case_exit": 0,
        "tampered": {},
    }
    for name, t in TAMPERED.items():
        case = tampered / name
        run = run_of(case, t["tool"])
        x = {"tool": t["tool"], "run_id": run["run_id"], "reason": t["reason"], "what": t["what"]}
        s = summarize(case, f"tampered/{name} (written by make_sample_case.py tamper)", [x])
        doc["tampered"][name] = {
            "excluded_run": {"tool": t["tool"], "run_id": run["run_id"], "run_dir": run["run_dir"],
                             "reason": t["reason"], "what": t["what"]},
            "verify_case_exit": TAMPERED_VERIFY[name],
            "verify_case_exit_without_output_rehash": TAMPERED_VERIFY_NO_REHASH[name],
            "runs": s["runs"], "events_total": s["events_total"],
            "signals": s["signals"],
            "signals_total": len(s["signals"]),
            "signal_codes": sorted({g["code"] for g in s["signals"]}),
        }
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


# Exit code `verify-case` gives on each copy (0 intact, 3 broken). verify-case checks the case log, the registry and
# every run's audit chain and its anchoring, and (src/core/src/outputs.rs: rv-timeline and every tool that has it)
# re-hashes every output a run's audit log records, so the edited metadata.json of digest-mismatch is exit 3. A tool
# whose verify-case does not re-hash outputs yet (it prints no "outputs:" line) gives the second value. An interrupted
# run (no run_finished) is a warning only; rv-timeline's own checks exclude it.
TAMPERED_VERIFY = {"digest-mismatch": 3, "chain-broken": 3, "not-finished": 0}
TAMPERED_VERIFY_NO_REHASH = {"digest-mismatch": 0, "chain-broken": 3, "not-finished": 0}


def cmd_check_verify(expected: Path, clean: Path, tampered: Path, exes: list[str]) -> None:
    import subprocess
    doc = json.loads(expected.read_text(encoding="utf-8"))
    bad = 0
    rehash = {}
    for exe in exes:
        p = subprocess.run([exe, "verify-case", str(clean)], capture_output=True, text=True)
        rehash[exe] = any(x.strip().startswith("outputs:") for x in p.stdout.splitlines())
        print(f"{'clean':16} {Path(exe).stem:13} exit {p.returncode} (re-hashes outputs: {rehash[exe]})")
        if p.returncode != doc["clean_verify_case_exit"]:
            print(f"  expected exit {doc['clean_verify_case_exit']}:\n{p.stdout}{p.stderr}")
            bad = 1
    for name, t in doc["tampered"].items():
        case = tampered / name
        for exe in exes:
            p = subprocess.run([exe, "verify-case", str(case)], capture_output=True, text=True)
            first = (p.stdout.strip().splitlines() or [""])[0]
            warn = "warning" in (p.stdout + p.stderr).lower() or "no run_finished" in (p.stdout + p.stderr)
            print(f"{name:16} {Path(exe).stem:13} exit {p.returncode} {first[:100]}")
            want = t["verify_case_exit"] if rehash[exe] else t["verify_case_exit_without_output_rehash"]
            if p.returncode != want:
                print(f"  expected exit {want}:\n{p.stdout}{p.stderr}")
                bad = 1
            if name == "not-finished" and not warn:
                print("  expected a 'no run_finished' warning"); bad = 1
    if bad:
        sys.exit(3)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["evidence"] and len(a) == 3:
        cmd_evidence(Path(a[1]), Path(a[2]))
    elif a[:1] == ["tamper"] and len(a) == 3:
        cmd_tamper(Path(a[1]), Path(a[2]))
    elif a[:1] == ["expected"] and len(a) == 5:
        cmd_expected(Path(a[1]), Path(a[2]), Path(a[3]), Path(a[4]))
    elif a[:1] == ["check-verify"] and len(a) >= 5:
        cmd_check_verify(Path(a[1]), Path(a[2]), Path(a[3]), a[4:])
    else:
        sys.exit(__doc__)
