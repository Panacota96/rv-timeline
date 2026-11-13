//! rv-imgauth 0.3.x (images). Reads each item's `metadata.json` (every tag the tool read: `/tags/<i>` =
//! {group, name, value}, plus `/xmp_history`). Events:
//!
//! | Kind | Source tags |
//! | --- | --- |
//! | `exif.original` | Exif DateTimeOriginal + OffsetTimeOriginal + SubSecTimeOriginal |
//! | `exif.digitized` | Exif DateTimeDigitized + OffsetTimeDigitized + SubSecTimeDigitized |
//! | `exif.modify` | IFD0 DateTime + Exif OffsetTime + SubSecTime |
//! | `gps.time` | GPS GPSDateStamp + GPSTimeStamp (UTC by definition) |
//! | `xmp.create`, `xmp.modify`, `xmp.metadata`, `xmp.photoshop_created`, `xmp.exif_original` | XMP tags |
//! | `xmp.history` | xmpMM:History `when` (action and software agent in details) |
//! | `png.time` | PNG tIME (UTC by the PNG specification) |
//! | `png.creation_time` | PNG text "Creation Time" when it is a self-describing format (RFC 3339/5322…) |
//!
//! EXIF times without OffsetTime* are zone-unknown. Not mapped: IPTC DateCreated/TimeCreated (no documented
//! rendering), MakerNote times, IFD1 (thumbnail) DateTime.
//!
//! ```text
//! reports/items/NNNNN-name/metadata.json ──► tags (EXIF/GPS/XMP/PNG) + xmp_history ──► exif.* gps.* xmp.* png.*
//! ```

use super::{Emitter, Found, ReadOutcome, RunData, s, timefmt};
use crate::model::{ReadError, RunRef};
use std::path::Path;

const XMP_KINDS: [(&str, &str); 5] = [
    ("xmp:CreateDate", "xmp.create"),
    ("xmp:ModifyDate", "xmp.modify"),
    ("xmp:MetadataDate", "xmp.metadata"),
    ("photoshop:DateCreated", "xmp.photoshop_created"),
    ("exif:DateTimeOriginal", "xmp.exif_original"),
];

/// (EXIF date tag, its group, offset tag, sub-second tag, kind).
const EXIF_KINDS: [(&str, &str, &str, &str, &str); 3] = [
    (
        "DateTimeOriginal",
        "Exif",
        "OffsetTimeOriginal",
        "SubSecTimeOriginal",
        "exif.original",
    ),
    (
        "DateTimeDigitized",
        "Exif",
        "OffsetTimeDigitized",
        "SubSecTimeDigitized",
        "exif.digitized",
    ),
    (
        "DateTime",
        "IFD0",
        "OffsetTime",
        "SubSecTime",
        "exif.modify",
    ),
];

pub fn read(case_dir: &Path, run: &RunRef) -> Result<ReadOutcome, ReadError> {
    let data = RunData::load(case_dir, run)?;
    let mut em = Emitter::new(&data);
    em.audit_events();
    for rel in data.outputs_ending("/metadata.json") {
        let Some(item) = data.item_of_folder(&rel) else {
            continue;
        };
        let Some((v, sha)) = data.json(&rel)? else {
            continue;
        };
        let tags: Vec<(usize, &str, &str, &str)> = v["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
            .map(|(i, t)| (i, s(&t["group"]), s(&t["name"]), s(&t["value"])))
            .collect();
        let find = |group: &str, name: &str| {
            tags.iter()
                .find(|(_, g, n, _)| *g == group && *n == name)
                .map(|(i, _, _, v)| (*i, *v))
        };
        let model = find("IFD0", "Model")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        let found = |kind: &'static str,
                     original: String,
                     pointer: String,
                     details: Vec<(&'static str, String)>| Found {
            item: item.item_ref(""),
            kind,
            original,
            file: &rel,
            file_sha256: &sha,
            pointer,
            details,
        };
        for (tag, group, off_tag, sub_tag, kind) in EXIF_KINDS {
            for (i, g, n, value) in &tags {
                if *g != group || *n != tag {
                    continue;
                }
                let off = find("Exif", off_tag);
                let sub = find("Exif", sub_tag);
                let mut original = value.to_string();
                let mut details = vec![("model", model.clone())];
                if let Some((oi, o)) = off {
                    original = format!("{value} {o}");
                    details.push(("offset_pointer", format!("/tags/{oi}/value")));
                }
                if let Some((si, _)) = sub {
                    details.push(("subsec_pointer", format!("/tags/{si}/value")));
                }
                let p = timefmt::exif(value, off.map(|o| o.1), sub.map(|x| x.1));
                em.push(
                    found(kind, original, format!("/tags/{i}/value"), details),
                    p,
                );
            }
        }
        if let (Some((di, d)), Some((ti, t))) =
            (find("GPS", "GPSDateStamp"), find("GPS", "GPSTimeStamp"))
        {
            em.push(
                found(
                    "gps.time",
                    format!("{d} {t}"),
                    format!("/tags/{di}/value"),
                    vec![("time_pointer", format!("/tags/{ti}/value"))],
                ),
                timefmt::gps(d, t),
            );
        }
        for (i, g, n, value) in &tags {
            let pointer = format!("/tags/{i}/value");
            if *g == "XMP" {
                if let Some((_, kind)) = XMP_KINDS.iter().find(|(name, _)| name == n) {
                    let p = timefmt::iso8601(value.trim());
                    em.push(found(kind, value.to_string(), pointer, vec![]), p);
                }
            } else if *g == "PNG-tIME" && *n == "tIME" {
                em.push(
                    found("png.time", value.to_string(), pointer, vec![]),
                    timefmt::utc_wallclock(value),
                );
            } else if g.starts_with("PNG") && *n == "Creation Time" {
                let p = timefmt::any(value).map(|x| x.0);
                em.push(
                    found("png.creation_time", value.to_string(), pointer, vec![]),
                    p,
                );
            }
        }
        for (i, h) in v["xmp_history"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let when = s(&h["when"]);
            if when.is_empty() {
                continue;
            }
            em.push(
                found(
                    "xmp.history",
                    when.to_string(),
                    format!("/xmp_history/{i}/when"),
                    vec![
                        ("action", s(&h["action"]).to_string()),
                        ("software_agent", s(&h["software_agent"]).to_string()),
                    ],
                ),
                timefmt::iso8601(when.trim()),
            );
        }
    }
    Ok(em.finish())
}
