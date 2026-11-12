//! rv-rsmf 0.3.x (chat exports → RSMF). Reads `rsmf/trace.json` (one row per converted event: export,
//! source_file, line, source_time as written in the export, utc as rv-rsmf computed it, conversation, kind) and
//! `rsmf/conversions.json` (export → item index, source kind). Sub-item: the conversation id. Events:
//!
//! | Kind | Source |
//! | --- | --- |
//! | `chat.message`, `chat.join`, `chat.leave`, `chat.history`, `chat.disclaimer`, `chat.unknown` | each trace row (RSMF event type) |
//! | `chat.conversation.first`, `chat.conversation.last` | earliest / latest row of each conversation |
//!
//! Zone rule (never guessed here): a `source_time` with its own offset is used as written. A zone-less
//! `source_time` with an rv-rsmf `utc` takes the offset between the two when the wall clock is ISO 8601 (Telegram);
//! a locale format (WhatsApp, CSV) uses rv-rsmf's `utc`, as *explicit* when the examiner gave `--timezone` (named in
//! `zone_applied`, offset not restated) and as *zone unknown* otherwise (rv-rsmf then read it as UTC). A
//! `source_time` with one `:` (no seconds) is minute precision.
//!
//! Not mapped: edit and reaction times inside the RSMF files (the trace lists events only).
//!
//! ```text
//! rsmf/conversions.json ── exports[] (export → item_index, source) ─┐
//! rsmf/trace.json ── rows (source_time, utc, conversation, kind) ───┴─► chat.* events per conversation
//! ```

use super::{Emitter, Found, ReadOutcome, RunData, s, timefmt};
use crate::model::{Precision, ReadError, RunRef, ZoneInfo};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// The examiner's `--timezone` recorded in the run's audit log (`conversion_started` → options.timezone).
fn timezone_option(data: &RunData) -> Option<String> {
    data.audit.iter().find_map(|(_, e)| {
        if e.get("action").and_then(Value::as_str) != Some("conversion_started") {
            return None;
        }
        e["details"]["options"]["timezone"]
            .as_str()
            .map(String::from)
    })
}

fn row_time(
    source_time: &str,
    utc: &str,
    tz: Option<&str>,
) -> Option<(timefmt::Parsed, Option<String>)> {
    let st = source_time.trim();
    if let Some((p, _)) = timefmt::any(st)
        && p.zone == ZoneInfo::Explicit
    {
        return Some((p, None));
    }
    let u = timefmt::rfc3339(utc)?;
    if let Some(local) = timefmt::iso8601(st)
        && local.zone == ZoneInfo::Unknown
    {
        let diff = local.utc_s - u.utc_s;
        if diff % 60 == 0 && diff.abs() <= 18 * 3600 {
            return Some((
                timefmt::Parsed {
                    zone: ZoneInfo::Explicit,
                    offset_min: Some((diff / 60) as i32),
                    precision: local.precision,
                    ..u
                },
                None,
            ));
        }
        return None;
    }
    let precision = if st.matches(':').count() == 1 {
        Precision::Minute
    } else {
        u.precision
    };
    Some(match tz {
        Some(z) => (
            timefmt::Parsed {
                zone: ZoneInfo::Explicit,
                offset_min: None,
                precision,
                ..u
            },
            Some(z.to_string()),
        ),
        None => (
            timefmt::Parsed {
                zone: ZoneInfo::Unknown,
                offset_min: None,
                precision,
                ..u
            },
            None,
        ),
    })
}

pub fn read(case_dir: &Path, run: &RunRef) -> Result<ReadOutcome, ReadError> {
    let data = RunData::load(case_dir, run)?;
    let mut em = Emitter::new(&data);
    em.audit_events();
    let tz = timezone_option(&data);
    let mut exports: BTreeMap<String, (u64, String)> = BTreeMap::new();
    if let Some((c, _)) = data.json("rsmf/conversions.json")? {
        for x in c["exports"].as_array().into_iter().flatten() {
            if let Some(i) = x["item_index"].as_u64() {
                exports.insert(
                    s(&x["export"]).to_string(),
                    (i, s(&x["source"]).to_string()),
                );
            }
        }
    }
    let rel = "rsmf/trace.json";
    let Some((trace, sha)) = data.json(rel)? else {
        return Ok(em.finish());
    };
    // (item index, conversation) → (first, last): (utc_s, utc_ns, row index, parsed, zone_applied).
    type Edge = (i64, u32, usize, timefmt::Parsed, Option<String>);
    let mut edges: BTreeMap<(u64, String), (Edge, Edge)> = BTreeMap::new();
    let rows = trace.as_array().cloned().unwrap_or_default();
    for (i, r) in rows.iter().enumerate() {
        let export = s(&r["export"]);
        let Some((index, source)) = exports.get(export) else {
            continue;
        };
        let Some(item) = data.items.get(index) else {
            continue;
        };
        let conv = s(&r["conversation"]).to_string();
        let kind = match s(&r["kind"]) {
            "" | "message" => "chat.message",
            "disclaimer" => "chat.disclaimer",
            "join" => "chat.join",
            "leave" => "chat.leave",
            "history" => "chat.history",
            _ => "chat.unknown",
        };
        let st = s(&r["source_time"]);
        let parsed = row_time(st, s(&r["utc"]), tz.as_deref());
        let mut details = vec![
            ("source", source.clone()),
            ("source_file", s(&r["source_file"]).to_string()),
            ("line", r["line"].to_string()),
            ("event_id", s(&r["event_id"]).to_string()),
            ("rsmf_utc", s(&r["utc"]).to_string()),
        ];
        if let Some((_, Some(z))) = &parsed {
            details.push(("zone_applied", format!("{z} (rv-rsmf --timezone)")));
        }
        if let Some((p, z)) = &parsed {
            let e: Edge = (p.utc_s, p.utc_ns, i, *p, z.clone());
            let slot = edges
                .entry((*index, conv.clone()))
                .or_insert((e.clone(), e.clone()));
            if (e.0, e.1) < (slot.0.0, slot.0.1) {
                slot.0 = e.clone();
            }
            if (e.0, e.1) >= (slot.1.0, slot.1.1) {
                slot.1 = e;
            }
        }
        em.push(
            Found {
                item: item.item_ref(&conv),
                kind,
                original: st.to_string(),
                file: rel,
                file_sha256: &sha,
                pointer: format!("/{i}/source_time"),
                details,
            },
            parsed.map(|p| p.0),
        );
    }
    for ((index, conv), (first, last)) in edges {
        let Some(item) = data.items.get(&index) else {
            continue;
        };
        for (kind, e) in [
            ("chat.conversation.first", first),
            ("chat.conversation.last", last),
        ] {
            let (_, _, i, p, z) = e;
            let mut details = vec![("event_id", s(&rows[i]["event_id"]).to_string())];
            if let Some(z) = z {
                details.push(("zone_applied", format!("{z} (rv-rsmf --timezone)")));
            }
            em.push(
                Found {
                    item: item.item_ref(&conv),
                    kind,
                    original: s(&rows[i]["source_time"]).to_string(),
                    file: rel,
                    file_sha256: &sha,
                    pointer: format!("/{i}/source_time"),
                    details,
                },
                Some(p),
            );
        }
    }
    Ok(em.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_rules() {
        // Own offset wins.
        let (p, z) = row_time("2026-11-10T10:00:00Z", "2026-11-10T10:00:00Z", None).unwrap();
        assert_eq!(
            (p.zone, p.offset_min, z),
            (ZoneInfo::Explicit, Some(0), None)
        );
        // Telegram: local wall clock + rv-rsmf UTC → the offset between them.
        let (p, _) = row_time("2026-11-10T05:00:00", "2026-11-10T10:00:00Z", None).unwrap();
        assert_eq!((p.zone, p.offset_min), (ZoneInfo::Explicit, Some(-300)));
        // WhatsApp with --timezone: explicit, zone named.
        let (p, z) = row_time(
            "10/11/26, 5:00",
            "2026-11-10T10:00:00Z",
            Some("America/Bogota"),
        )
        .unwrap();
        assert_eq!(
            (p.zone, p.precision, z.as_deref()),
            (
                ZoneInfo::Explicit,
                Precision::Minute,
                Some("America/Bogota")
            )
        );
        // Without --timezone: unknown.
        let (p, _) = row_time("10/11/26, 10:00:00", "2026-11-10T10:00:00Z", None).unwrap();
        assert_eq!(
            (p.zone, p.offset_min, p.precision),
            (ZoneInfo::Unknown, None, Precision::Second)
        );
        // No UTC from rv-rsmf and no own zone: skipped.
        assert!(row_time("10/11/26, 10:00", "", None).is_none());
    }
}
