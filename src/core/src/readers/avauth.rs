//! rv-avauth 0.2.x and 0.3.x (audio and video). Reads each item's `metadata.json`: `/times/<i>` = {source, origin, raw,
//! unix, utc}, every time value the tool read from the file (`origin` `header` for container boxes, `tag` for a
//! tag with a zone, `tag_local` for a tag without one). Events:
//!
//! | Kind | Source (`/times/<i>/source`) |
//! | --- | --- |
//! | `media.header.created` | MP4 / MOV / M4A `mvhd.creation`, `tkhd[n].creation`, `mdhd[n].creation` (UTC by definition) |
//! | `media.header.modified` | the same boxes, `.modification` |
//! | `media.tag.created` | QuickTime `com.apple.quicktime.creationdate`, `©day`, `date`; Vorbis `DATE`, `CREATION_TIME`; RIFF `INFO ICRD`; BWF `bext OriginationDate`; ID3 `TDRC`, `TYER`, `TYE` |
//! | `media.tag.encoded` | ID3 `TDEN` |
//! | `media.tag.tagged` | ID3 `TDTG` |
//! | `media.tag.released` | ID3 `TDOR` (original release) |
//! | `media.tag.date` | any other date tag rv-avauth reports |
//!
//! The reader parses `raw` itself ([`timefmt::mp4_seconds`], [`timefmt::media_tag`]) and does not use rv-avauth's
//! `utc`: for a `tag_local` value that field reads the wall clock as UTC, while here the time stays zone-unknown.
//! A header value of 0 means the field is not set: no event, and not counted as a skipped time. A year alone (ID3
//! `TYER` `2026`) places no instant and is counted as skipped.
//!
//! ```text
//! reports/items/NNNNN-name/metadata.json ──► /times/<i> (header) ──► media.header.created / .modified
//!                                        └─► /times/<i> (tag, tag_local) ──► media.tag.*
//! ```

use super::{Emitter, Found, ReadOutcome, RunData, s, timefmt};
use crate::model::{ReadError, RunRef};
use std::path::Path;

/// Kind of a date tag, from the tag name (the last word of `source`).
fn tag_kind(name: &str) -> &'static str {
    match name {
        "com.apple.quicktime.creationdate"
        | "©day"
        | "date"
        | "DATE"
        | "CREATION_TIME"
        | "ICRD"
        | "OriginationDate"
        | "TDRC"
        | "TYER"
        | "TYE" => "media.tag.created",
        "TDEN" => "media.tag.encoded",
        "TDTG" => "media.tag.tagged",
        "TDOR" => "media.tag.released",
        _ => "media.tag.date",
    }
}

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
        // The device the file claims to come from (QuickTime keys, ©mod, Vorbis MODEL), as a detail.
        let model = v["device_claims"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| {
                let k = s(&c["key"]);
                k.ends_with(".model") || k == "©mod" || k.eq_ignore_ascii_case("model")
            })
            .map(|c| s(&c["value"]).to_string())
            .unwrap_or_default();
        for (i, t) in v["times"].as_array().into_iter().flatten().enumerate() {
            let (source, origin, raw) = (s(&t["source"]), s(&t["origin"]), s(&t["raw"]));
            let (kind, parsed, mut details) = if origin == "header" {
                if raw == "0" {
                    continue;
                }
                // `mvhd.creation`, `tkhd[1].modification`: the box, then which of its two times.
                let (bx, field) = source.rsplit_once('.').unwrap_or((source, ""));
                let kind = if field == "modification" {
                    "media.header.modified"
                } else {
                    "media.header.created"
                };
                (
                    kind,
                    timefmt::mp4_seconds(raw),
                    vec![("box", bx.to_string())],
                )
            } else {
                let name = source.rsplit(' ').next().unwrap_or(source);
                (tag_kind(name), timefmt::media_tag(raw), vec![])
            };
            details.push(("source", source.to_string()));
            details.push(("origin", origin.to_string()));
            details.push(("model", model.clone()));
            em.push(
                Found {
                    item: item.item_ref(""),
                    kind,
                    original: raw.to_string(),
                    file: &rel,
                    file_sha256: &sha,
                    pointer: format!("/times/{i}/raw"),
                    details,
                },
                parsed,
            );
        }
    }
    Ok(em.out)
}

#[cfg(test)]
mod tests {
    use super::tag_kind;

    #[test]
    fn tag_kinds() {
        for n in [
            "com.apple.quicktime.creationdate",
            "©day",
            "date",
            "DATE",
            "CREATION_TIME",
            "ICRD",
            "OriginationDate",
            "TDRC",
            "TYER",
            "TYE",
        ] {
            assert_eq!(tag_kind(n), "media.tag.created", "{n}");
        }
        assert_eq!(tag_kind("TDEN"), "media.tag.encoded");
        assert_eq!(tag_kind("TDTG"), "media.tag.tagged");
        assert_eq!(tag_kind("TDOR"), "media.tag.released");
        assert_eq!(tag_kind("TXXX"), "media.tag.date");
    }
}
