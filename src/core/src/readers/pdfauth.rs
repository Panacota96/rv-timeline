//! rv-pdfauth 0.4.x (PDF). Sub-items are revisions (`r1`, `r2`, …). Events:
//!
//! | Kind | Source |
//! | --- | --- |
//! | `pdf.info.created`, `pdf.info.modified` | `objects.json` → the Info dictionary of each revision (`/CreationDate`, `/ModDate`, raw `D:` strings with their own offset) |
//! | `pdf.info.saved` | `technical.json` → `/pdf/revisions/<i>/saved_at_info`, only when the run wrote no `objects.json` (rv-pdfauth's UTC form: a zone-less PDF date was already read as UTC there) |
//! | `pdf.xmp.saved` | `technical.json` → `/pdf/revisions/<i>/saved_at_xmp` (XMP ModifyDate, else CreateDate, as rv-pdfauth normalised it) |
//! | `pdf.revision.signed` | `technical.json` → `/pdf/signatures/<i>/signing_time` (CMS signingTime, UTC) |
//! | `pdf.signature.claimed` | `objects.json` → `/M` of each signature dictionary (the time the signer's software wrote) |
//!
//! Not mapped: RFC 3161 document timestamps inside the PDF (rv-pdfauth 0.4 does not decode their genTime), the
//! raw XMP packet dates (only the normalised value is in the outputs), annotation `/M` dates.
//!
//! ```text
//! reports/items/NNNNN-name/objects.json   ──► Info /CreationDate /ModDate per revision, /Sig /M
//! reports/items/NNNNN-name/technical.json ──► XMP saved time per revision, CMS signing times
//! ```

use super::{Emitter, Found, ReadOutcome, RunData, s, timefmt};
use crate::model::{ReadError, RunRef};
use std::path::Path;

pub fn read(case_dir: &Path, run: &RunRef) -> Result<ReadOutcome, ReadError> {
    let data = RunData::load(case_dir, run)?;
    let mut em = Emitter::new(&data);
    em.audit_events();
    for rel in data.outputs_ending("/technical.json") {
        let Some(item) = data.item_of_folder(&rel) else {
            continue;
        };
        let folder = rel.trim_end_matches("technical.json");
        let objects_rel = format!("{folder}objects.json");
        let objects = data.json(&objects_rel)?;
        let Some((v, sha)) = data.json(&rel)? else {
            continue;
        };
        let pdf = &v["pdf"];
        for (i, r) in pdf["revisions"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let sub = format!("r{}", r["index"].as_u64().unwrap_or(i as u64 + 1));
            let producer = s(&r["producer"]).to_string();
            for (key, kind, wanted) in [
                ("saved_at_info", "pdf.info.saved", objects.is_none()),
                ("saved_at_xmp", "pdf.xmp.saved", true),
            ] {
                let t = s(&r[key]);
                if !wanted || t.is_empty() {
                    continue;
                }
                em.push(
                    Found {
                        item: item.item_ref(&sub),
                        kind,
                        original: t.to_string(),
                        file: &rel,
                        file_sha256: &sha,
                        pointer: format!("/pdf/revisions/{i}/{key}"),
                        details: vec![
                            ("producer", producer.clone()),
                            ("normalised_by", "rv-pdfauth".into()),
                        ],
                    },
                    timefmt::any(t).map(|p| p.0),
                );
            }
        }
        for (i, sig) in pdf["signatures"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let t = s(&sig["signing_time"]);
            if t.is_empty() {
                continue;
            }
            let sub = sig["revision"]
                .as_u64()
                .map(|r| format!("r{r}"))
                .unwrap_or_default();
            em.push(
                Found {
                    item: item.item_ref(&sub),
                    kind: "pdf.revision.signed",
                    original: t.to_string(),
                    file: &rel,
                    file_sha256: &sha,
                    pointer: format!("/pdf/signatures/{i}/signing_time"),
                    details: vec![
                        ("field", s(&sig["field"]).to_string()),
                        ("signer", s(&sig["signer_subject"]).to_string()),
                    ],
                },
                timefmt::rfc3339(t),
            );
        }
        let Some((o, osha)) = objects else {
            continue;
        };
        for (k, rev) in o["revisions"].as_array().into_iter().flatten().enumerate() {
            let sub = format!("r{}", k + 1);
            for (j, obj) in rev["objects"].as_array().into_iter().flatten().enumerate() {
                let d = &obj["dict"];
                let Some(dict) = d.as_object() else {
                    continue;
                };
                let is_sig = s(&d["Type"]) == "/Sig" || dict.contains_key("ByteRange");
                let mut fields: Vec<(&str, &str)> = Vec::new();
                if is_sig {
                    fields.push(("M", "pdf.signature.claimed"));
                } else if !dict.contains_key("Type") {
                    fields.push(("CreationDate", "pdf.info.created"));
                    fields.push(("ModDate", "pdf.info.modified"));
                }
                for (key, kind) in fields {
                    let Some(t) = d[key].as_str() else {
                        continue;
                    };
                    let mut details = vec![("object", s(&obj["id"]).to_string())];
                    if !is_sig {
                        details.push(("producer", s(&d["Producer"]).to_string()));
                    } else {
                        details.push(("signer_name", s(&d["Name"]).to_string()));
                    }
                    em.push(
                        Found {
                            item: item.item_ref(&sub),
                            kind,
                            original: t.to_string(),
                            file: &objects_rel,
                            file_sha256: &osha,
                            pointer: format!("/revisions/{k}/objects/{j}/dict/{key}"),
                            details,
                        },
                        timefmt::pdf(t),
                    );
                }
            }
        }
    }
    Ok(em.finish())
}
