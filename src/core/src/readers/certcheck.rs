//! rv-certcheck 0.2.x (certificates, CRLs, OCSP, RFC 3161 tokens). Reads each item's `chain.json`. Sub-item:
//! `c<n>`, the n-th certificate of the item (file order, from 1) when the file holds several certificates; none
//! when it holds one. Events:
//!
//! | Kind | Source |
//! | --- | --- |
//! | `cert.not_before`, `cert.not_after` | `/certificates/<i>/not_before`, `not_after` (RFC 3339 UTC as rv-certcheck renders the X.509 time) |
//! | `cert.revoked` | `/verdicts/<v>/nodes/<n>/revocation/revoked_at` when the status is `revoked` (CRL or OCSP) |
//! | `tsa.gen_time` | `/timestamp/info/gen_time` (the token's TSTInfo genTime) |
//!
//! Not mapped: CMS signing times (rv-certcheck 0.2 does not check CMS/PAdES signatures), CRL thisUpdate /
//! nextUpdate and OCSP producedAt of CRL/OCSP items (not in its outputs), the validity of chain certificates
//! other than the item's own (they come from other items or anchors).
//!
//! ```text
//! reports/items/NNNNN-name/chain.json ── certificates[] ─► cert.not_before / cert.not_after
//!                                     ├─ verdicts[].nodes[].revocation ─► cert.revoked
//!                                     └─ timestamp.info.gen_time ─► tsa.gen_time
//! ```

use super::{Emitter, Found, ReadOutcome, RunData, s, timefmt};
use crate::model::{ReadError, RunRef};
use std::path::Path;

/// Sub-item of the i-th certificate (0-based) of a file holding `count`: `c<i+1>`, or none for a single one.
fn cert_sub(count: usize, i: usize) -> String {
    if count > 1 {
        format!("c{}", i + 1)
    } else {
        String::new()
    }
}

pub fn read(case_dir: &Path, run: &RunRef) -> Result<ReadOutcome, ReadError> {
    let data = RunData::load(case_dir, run)?;
    let mut em = Emitter::new(&data);
    em.audit_events();
    for rel in data.outputs_ending("/chain.json") {
        let Some(item) = data.item_of_folder(&rel) else {
            continue;
        };
        let Some((v, sha)) = data.json(&rel)? else {
            continue;
        };
        let certs = v["certificates"].as_array().cloned().unwrap_or_default();
        let sub_of = |i: usize| cert_sub(certs.len(), i);
        for (i, c) in certs.iter().enumerate() {
            let sub = sub_of(i);
            for (key, kind) in [
                ("not_before", "cert.not_before"),
                ("not_after", "cert.not_after"),
            ] {
                let Some(t) = c[key].as_str() else {
                    continue;
                };
                em.push(
                    Found {
                        item: item.item_ref(&sub),
                        kind,
                        original: t.to_string(),
                        file: &rel,
                        file_sha256: &sha,
                        pointer: format!("/certificates/{i}/{key}"),
                        details: vec![
                            ("subject", s(&c["subject"]).to_string()),
                            ("issuer", s(&c["issuer"]).to_string()),
                            ("serial", s(&c["serial_hex"]).to_string()),
                            ("cert_sha256", s(&c["sha256"]).to_string()),
                        ],
                    },
                    timefmt::rfc3339(t).or_else(|| timefmt::x509(t)),
                );
            }
        }
        for (vi, verdict) in v["verdicts"].as_array().into_iter().flatten().enumerate() {
            for (ni, node) in verdict["nodes"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                let r = &node["revocation"];
                if s(&r["status"]) != "revoked" {
                    continue;
                }
                let Some(t) = r["revoked_at"].as_str() else {
                    continue;
                };
                let cert_sha = s(&node["cert"]["sha256"]);
                let sub = certs
                    .iter()
                    .position(|c| s(&c["sha256"]) == cert_sha && !cert_sha.is_empty())
                    .map(sub_of)
                    .unwrap_or_default();
                em.push(
                    Found {
                        item: item.item_ref(&sub),
                        kind: "cert.revoked",
                        original: t.to_string(),
                        file: &rel,
                        file_sha256: &sha,
                        pointer: format!("/verdicts/{vi}/nodes/{ni}/revocation/revoked_at"),
                        details: vec![
                            ("subject", s(&node["cert"]["subject"]).to_string()),
                            ("reason", s(&r["reason"]).to_string()),
                            ("revocation_source", s(&r["source"]["kind"]).to_string()),
                            ("depth", node["depth"].to_string()),
                        ],
                    },
                    timefmt::rfc3339(t).or_else(|| timefmt::x509(t)),
                );
            }
        }
        let ts = &v["timestamp"]["info"];
        if let Some(t) = ts["gen_time"].as_str() {
            em.push(
                Found {
                    item: item.item_ref(""),
                    kind: "tsa.gen_time",
                    original: t.to_string(),
                    file: &rel,
                    file_sha256: &sha,
                    pointer: "/timestamp/info/gen_time".into(),
                    details: vec![
                        ("tsa", s(&ts["tsa_name"]).to_string()),
                        ("serial", s(&ts["serial_hex"]).to_string()),
                        (
                            "imprint_file",
                            s(&v["timestamp"]["imprint_file"]).to_string(),
                        ),
                        ("accuracy", s(&ts["accuracy"]).to_string()),
                    ],
                },
                timefmt::rfc3339(t).or_else(|| timefmt::x509(t)),
            );
        }
    }
    Ok(em.finish())
}

#[cfg(test)]
mod tests {
    #[test]
    fn certificate_sub_items_only_for_several() {
        assert_eq!(super::cert_sub(1, 0), "");
        assert_eq!(super::cert_sub(3, 0), "c1");
        assert_eq!(super::cert_sub(3, 2), "c3");
    }
}
