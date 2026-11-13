//! rv-mailauth 0.2.x (email). Reads each message's `headers.json` (an `.eml`, an `.msg`, or one message of an
//! mbox: sub-item `#n`, path `<mbox>#n@offset`) and each mbox's `mbox_index.json`. Events:
//!
//! | Kind | Source |
//! | --- | --- |
//! | `mail.date` | `/headers/date_raw` (the Date header, RFC 5322; `-0000` = zone unknown) |
//! | `mail.hop` | `/headers/hops/<i>/date_raw` (each Received header's date; `position` 1 = first hop) |
//! | `mail.attachment.created`, `mail.attachment.modified` | `/attachments/<i>/creation_date_raw`, `modification_date_raw` (MIME Content-Disposition dates) |
//! | `mail.msg.submitted`, `mail.msg.delivered` | `/headers/msg/client_submit_time`, `delivery_time` (Outlook .msg properties, UTC) |
//! | `mail.mbox_from` | `mbox_index.json` → `/messages/<i>/from_line` (the mbox `From ` line, asctime, zone unknown) |
//!
//! Not mapped: dates inside DKIM/ARC signatures (`t=`, `x=`) — rv-mailauth 0.2 does not write them out.
//!
//! ```text
//! reports/items/NNNNN-name[_n_off]/headers.json ──► mail.date, mail.hop × n, mail.attachment.*, mail.msg.*
//! reports/items/NNNNN-name.mbox/mbox_index.json ──► mail.mbox_from × messages
//! ```

use super::{Emitter, Found, ReadOutcome, RunData, s, timefmt};
use crate::model::{ItemRef, ReadError, RunRef};
use std::path::Path;

/// `#n` of a derived message path `<mbox>#n@offset` (empty for a file item).
fn sub_of(path: &str) -> String {
    match path.rsplit_once('#') {
        Some((_, rest)) => match rest.split_once('@') {
            Some((n, _)) if !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) => {
                format!("#{n}")
            }
            _ => String::new(),
        },
        None => String::new(),
    }
}

fn mail_time(raw: &str) -> Option<timefmt::Parsed> {
    timefmt::rfc5322(raw).or_else(|| timefmt::any(raw).map(|p| p.0))
}

pub fn read(case_dir: &Path, run: &RunRef) -> Result<ReadOutcome, ReadError> {
    let data = RunData::load(case_dir, run)?;
    let mut em = Emitter::new(&data);
    em.audit_events();
    for rel in data.outputs_ending("/headers.json") {
        let Some(container) = data.item_of_folder(&rel) else {
            continue;
        };
        let Some((v, sha)) = data.json(&rel)? else {
            continue;
        };
        let path = data
            .output_items
            .get(&rel)
            .cloned()
            .unwrap_or_else(|| container.path.clone());
        let sub = sub_of(&path);
        let item = ItemRef {
            path,
            ..container.item_ref(&sub)
        };
        let h = &v["headers"];
        let message_id = s(&h["message_id"]).to_string();
        let from = h["from"]
            .as_array()
            .and_then(|a| a.first())
            .map(|f| s(&f["address"]).to_string())
            .unwrap_or_default();
        let found = |kind: &'static str,
                     original: &str,
                     pointer: String,
                     details: Vec<(&'static str, String)>| Found {
            item: item.clone(),
            kind,
            original: original.to_string(),
            file: &rel,
            file_sha256: &sha,
            pointer,
            details,
        };
        if let Some(t) = h["date_raw"].as_str() {
            em.push(
                found(
                    "mail.date",
                    t,
                    "/headers/date_raw".into(),
                    vec![("message_id", message_id.clone()), ("from", from.clone())],
                ),
                mail_time(t),
            );
        }
        for (i, hop) in h["hops"].as_array().into_iter().flatten().enumerate() {
            let Some(t) = hop["date_raw"].as_str() else {
                continue;
            };
            em.push(
                found(
                    "mail.hop",
                    t,
                    format!("/headers/hops/{i}/date_raw"),
                    vec![
                        ("position", hop["position"].to_string()),
                        ("by", s(&hop["by"]).to_string()),
                        ("from", s(&hop["from"]).to_string()),
                        ("message_id", message_id.clone()),
                    ],
                ),
                mail_time(t),
            );
        }
        for (i, a) in v["attachments"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            for (key, kind) in [
                ("creation_date_raw", "mail.attachment.created"),
                ("modification_date_raw", "mail.attachment.modified"),
            ] {
                let Some(t) = a[key].as_str() else {
                    continue;
                };
                em.push(
                    found(
                        kind,
                        t,
                        format!("/attachments/{i}/{key}"),
                        vec![
                            ("file_name", s(&a["file_name"]).to_string()),
                            ("attachment_sha256", s(&a["sha256"]).to_string()),
                        ],
                    ),
                    mail_time(t),
                );
            }
        }
        if h["msg"].is_object() {
            for (key, kind) in [
                ("client_submit_time", "mail.msg.submitted"),
                ("delivery_time", "mail.msg.delivered"),
            ] {
                let Some(t) = h["msg"][key].as_str() else {
                    continue;
                };
                em.push(
                    found(
                        kind,
                        t,
                        format!("/headers/msg/{key}"),
                        vec![("message_id", message_id.clone())],
                    ),
                    timefmt::rfc3339(t),
                );
            }
        }
    }
    for rel in data.outputs_ending("/mbox_index.json") {
        let Some(container) = data.item_of_folder(&rel) else {
            continue;
        };
        let Some((v, sha)) = data.json(&rel)? else {
            continue;
        };
        for (i, m) in v["messages"].as_array().into_iter().flatten().enumerate() {
            let Some(line) = m["from_line"].as_str() else {
                continue;
            };
            let path = m["id"].as_str().map(String::from).unwrap_or_default();
            let sub = m["n"]
                .as_u64()
                .map(|n| format!("#{n}"))
                .unwrap_or_else(|| sub_of(&path));
            let item = ItemRef {
                path: if path.is_empty() {
                    container.path.clone()
                } else {
                    path
                },
                ..container.item_ref(&sub)
            };
            // "From <sender> <asctime>": the date is the last five words.
            let words: Vec<&str> = line.split_ascii_whitespace().collect();
            let date = if words.len() >= 7 {
                words[words.len() - 5..].join(" ")
            } else {
                String::new()
            };
            em.push(
                Found {
                    item,
                    kind: "mail.mbox_from",
                    original: line.to_string(),
                    file: &rel,
                    file_sha256: &sha,
                    pointer: format!("/messages/{i}/from_line"),
                    details: vec![("offset", m["offset"].to_string())],
                },
                timefmt::asctime(&date),
            );
        }
    }
    Ok(em.finish())
}

#[cfg(test)]
mod tests {
    #[test]
    fn sub_items() {
        assert_eq!(super::sub_of("C:\\e\\12-mailbox.mbox#2@1372"), "#2");
        assert_eq!(super::sub_of("C:\\e\\a#b.eml"), "");
        assert_eq!(super::sub_of("C:\\e\\01.eml"), "");
    }
}
