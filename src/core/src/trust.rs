//! Trust features: RFC 3161 timestamps of the audit chain and digital signatures on PDF reports.
//!
//! Timestamp: the head of the audit chain (the last entry_hash, itself a SHA-256) is sent to a
//! time-stamping authority. The token proves the log — and every evidence hash, finding and report
//! digest recorded before it — existed at that time. Stored next to the log:
//!   timestamp-<seq>.tsr   DER response (verify: openssl ts -verify -digest <head> -in … -CAfile …)
//!   timestamp-<seq>.json  tsa, gen_time, covers_seq, head, token_sha256
//! Offline: the run completes, `timestamp_pending` is logged, `<tool> timestamp <log-dir>` adds it later.
//!
//! `verify-log` re-checks every token the audit log records (`timestamp_obtained`; a missing `.tsr` or `.json` is a
//! problem, never a skipped check) and any token file next to it that no entry records: imprint, status, and the
//! CMS signature of the TSA (signer certificate in the token, ESS signing-certificate binding, message digest over
//! TSTInfo, RSA signature, critical timeStamping-only EKU); with a CA bundle (`--tsa-ca`) also the certificate path
//! at genTime (an RFC 5280 subset: see `check_path`). Revocation is never checked.
//!
//! PDF signature: CMS detached signature (adbe.pkcs7.detached) with the examiner's .p12/.pfx (RSA keys).
//! The password is never logged.

use crate::hash::{HashAlgo, hash_bytes};
use cms::builder::{SignedDataBuilder, SignerInfoBuilder, create_signing_time_attribute};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};
use der::asn1::{Int, OctetString};
use der::{Any, Decode, Encode};
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::DecodePrivateKey;
use serde_json::{Value, json};
use sha2_legacy::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use std::path::Path;
use x509_cert::Certificate;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion};

pub const DEFAULT_TSA: &str = "http://timestamp.digicert.com";

#[derive(Clone, Debug, PartialEq)]
pub struct Timestamp {
    pub tsa: String,
    pub gen_time: String,
    pub covers_seq: u64,
    pub head: String,
    pub token_sha256: String,
    pub file: String,
}

impl Timestamp {
    pub fn to_json(&self) -> Value {
        json!({"tsa": self.tsa, "gen_time": self.gen_time, "covers_seq": self.covers_seq, "head": self.head,
               "token_sha256": self.token_sha256, "file": self.file})
    }
}

fn sha256_alg() -> spki::AlgorithmIdentifier<Any> {
    spki::AlgorithmIdentifier {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: Some(Any::null()),
    }
}

fn nonce() -> Vec<u8> {
    let seed = format!("{:?}-{}", std::time::SystemTime::now(), std::process::id());
    let mut n = crate::hash::hex_decode(&hash_bytes(seed.as_bytes(), HashAlgo::Sha256)[..16])
        .unwrap_or_default();
    n[0] &= 0x7f; // positive INTEGER
    n
}

pub fn build_request(digest: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let req = TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: sha256_alg(),
            hashed_message: OctetString::new(digest).map_err(|e| e.to_string())?,
        },
        req_policy: None,
        nonce: Some(Int::new(nonce).map_err(|e| e.to_string())?),
        cert_req: true,
        extensions: None,
    };
    req.to_der().map_err(|e| e.to_string())
}

/// Checks a TSA response; returns gen_time (UTC, ISO 8601).
pub fn parse_response(der: &[u8], digest: &[u8], nonce: Option<&[u8]>) -> Result<String, String> {
    let resp =
        TimeStampResp::from_der(der).map_err(|e| format!("not a time-stamp response: {}", e))?;
    let status = format!("{:?}", resp.status.status);
    if !(status == "Accepted" || status == "GrantedWithMods") {
        return Err(format!("TSA refused the request: {}", status));
    }
    let token = resp.time_stamp_token.ok_or("TSA response has no token")?;
    let sd: SignedData = token
        .content
        .decode_as()
        .map_err(|e| format!("bad token: {}", e))?;
    let econtent = sd
        .encap_content_info
        .econtent
        .ok_or("token without TSTInfo")?;
    let octets: OctetString = econtent
        .decode_as()
        .map_err(|e| format!("bad TSTInfo: {}", e))?;
    let info = parse_tst_info(octets.as_bytes())?;
    if info.imprint != digest {
        return Err("the token does not cover the requested digest".into());
    }
    if let (Some(want), Some(got)) = (nonce, info.nonce.as_ref()) {
        let want = Int::new(want).map_err(|e| e.to_string())?;
        if got.as_slice() != want.as_bytes() {
            return Err("nonce mismatch (possible replay)".into());
        }
    }
    Ok(info.gen_time)
}

struct TstFields {
    imprint: Vec<u8>,
    gen_time: String,
    nonce: Option<Vec<u8>>,
}

/// Minimal DER walk over TSTInfo. Done by hand on purpose: many TSAs put fractional seconds in
/// genTime ("20261020182422.123Z"), which strict GeneralizedTime decoders reject.
/// One DER TLV at `pos` (definite length, at most 4 length bytes): (tag, content start, content end).
fn der_tlv(b: &[u8], pos: usize) -> Result<(u8, usize, usize), String> {
    let bad = || "bad DER encoding".to_string();
    let tag = *b.get(pos).ok_or_else(bad)?;
    let first = *b.get(pos + 1).ok_or_else(bad)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return Err(bad());
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *b.get(pos + 2 + i).ok_or_else(bad)? as usize;
        }
        (l, 2 + n)
    };
    let start = pos + hdr;
    if start.checked_add(len).is_none_or(|e| e > b.len()) {
        return Err(bad());
    }
    Ok((tag, start, start + len))
}

fn parse_tst_info(der: &[u8]) -> Result<TstFields, String> {
    let tlv = der_tlv;
    let (tag, start, end) = tlv(der, 0)?;
    if tag != 0x30 {
        return Err("TSTInfo is not a SEQUENCE".into());
    }
    let mut fields = Vec::new();
    let mut pos = start;
    while pos < end {
        let (t, s, e) = tlv(der, pos)?;
        fields.push((t, s, e));
        pos = e;
    }
    let (t, s, e) = *fields.get(2).ok_or("TSTInfo too short")?;
    if t != 0x30 {
        return Err("bad messageImprint".into());
    }
    let (_, _, alg_end) = tlv(der, s)?;
    let (ot, os, oe) = tlv(der, alg_end)?;
    if ot != 0x04 || oe > e {
        return Err("bad messageImprint".into());
    }
    let imprint = der[os..oe].to_vec();
    let (gt, gs, ge) = *fields.get(4).ok_or("TSTInfo without genTime")?;
    if gt != 0x18 {
        return Err("bad genTime".into());
    }
    let raw = std::str::from_utf8(&der[gs..ge]).map_err(|_| "bad genTime")?;
    if raw.len() < 14 || !raw[..14].chars().all(|c| c.is_ascii_digit()) {
        return Err("bad genTime".into());
    }
    let gen_time = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &raw[0..4],
        &raw[4..6],
        &raw[6..8],
        &raw[8..10],
        &raw[10..12],
        &raw[12..14]
    );
    let nonce = fields
        .iter()
        .skip(5)
        .find(|(t, _, _)| *t == 0x02)
        .map(|(_, s, e)| der[*s..*e].to_vec());
    Ok(TstFields {
        imprint,
        gen_time,
        nonce,
    })
}

pub fn request_timestamp(digest: &[u8], url: &str) -> Result<(String, Vec<u8>), String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("unsupported TSA URL scheme: {}", url));
    }
    let n = nonce();
    let body = build_request(digest, &n)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .build()
        .into();
    let mut resp = agent
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .send(&body[..])
        .map_err(|e| format!("cannot reach {}: {}", url, e))?;
    let der = resp
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_vec()
        .map_err(|e| format!("cannot read TSA response: {}", e))?;
    let gen_time = parse_response(&der, digest, Some(&n))?;
    Ok((gen_time, der))
}

pub fn timestamp_head(
    log_dir: &Path,
    seq: u64,
    head: &str,
    url: &str,
) -> Result<Timestamp, String> {
    let digest = crate::hash::hex_decode(head).ok_or("bad chain head")?;
    let (gen_time, der) = request_timestamp(&digest, url)?;
    let file = format!("timestamp-{:05}.tsr", seq);
    std::fs::write(log_dir.join(&file), &der).map_err(|e| e.to_string())?;
    let ts = Timestamp {
        tsa: url.into(),
        gen_time,
        covers_seq: seq,
        head: head.into(),
        token_sha256: hash_bytes(&der, HashAlgo::Sha256),
        file,
    };
    let mut text = serde_json::to_string_pretty(&ts.to_json()).expect("json");
    text.push('\n');
    std::fs::write(log_dir.join(format!("timestamp-{:05}.json", seq)), text)
        .map_err(|e| e.to_string())?;
    Ok(ts)
}

/// Checks the RFC 3161 tokens of the audit log at `audit_path` (see [`verify_timestamps_with`]) without trust
/// anchors (the TSA certificate chain is not validated). Returns the problems only.
pub fn verify_timestamps(audit_path: &Path) -> Vec<String> {
    verify_timestamps_with(audit_path, None).problems
}

/// Outcome of `verify_timestamps_with`: problems (any → the log does not verify) and one line per token.
#[derive(Debug, Default)]
pub struct TimestampVerification {
    pub problems: Vec<String>,
    /// One line per token whose TSA signature (and, with anchors, chain) verified.
    pub tokens: Vec<String>,
    /// One line per token known (recorded in the log or found next to it):
    /// "timestamp <gen_time> by <tsa> covers entry #<seq>".
    pub listed: Vec<String>,
    /// (covered entry, token file) for every token whose covered entry is in the log: the truncation anchors.
    pub covers: Vec<(u64, String)>,
}

/// A token file name as the tools write it (`timestamp-<seq>.tsr`): a plain name in the log folder.
fn is_token_name(name: &str) -> bool {
    name.starts_with("timestamp-")
        && name.ends_with(".tsr")
        && name.len() <= 64
        && !name.contains(['/', '\\', ':'])
        && !name.contains("..")
}

fn read_json(path: &Path) -> Option<Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

/// Checks the RFC 3161 tokens of the audit log at `audit_path`, driven by the log itself so that deleting a
/// file cannot skip a check (fail closed):
///
/// 1. every `timestamp_obtained` entry names a token: its `.tsr` must be next to the log with the recorded
///    SHA-256, its `timestamp-<seq>.json` metadata must be there and agree with the entry, the entry it covers
///    must still be in the log with that hash, and the token's TSA signature (and, with `anchors` — a CA bundle,
///    `--tsa-ca` — its certificate chain at genTime) must verify;
/// 2. a `timestamp-*.json` next to the log that no entry records (the run could not record it) is checked the
///    same way from its own fields;
/// 3. a `timestamp-*.tsr` that neither an entry nor a metadata file names cannot be checked and is a problem.
///
/// Revocation of the TSA certificate is never checked.
pub fn verify_timestamps_with(
    audit_path: &Path,
    anchors: Option<&[Certificate]>,
) -> TimestampVerification {
    let log_dir = audit_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let heads = crate::audit::heads(audit_path);
    let entries: Vec<Value> = std::fs::read_to_string(audit_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let mut out = TimestampVerification::default();
    let mut named: Vec<String> = Vec::new();
    // What a token claims: listed, and (when its covered entry is in the log) a truncation anchor. Returns the
    // covered entry's hash, None (a problem) when the entry is not recorded or not in the log.
    let claim = |out: &mut TimestampVerification,
                 file: &str,
                 covers: Option<u64>,
                 tsa: &str,
                 gen_time: &str|
     -> Option<(u64, Vec<u8>)> {
        let Some(seq) = covers else {
            out.problems
                .push(format!("{}: the entry it covers is not recorded", file));
            return None;
        };
        out.listed.push(format!(
            "timestamp {} by {} covers entry #{}",
            gen_time, tsa, seq
        ));
        let Some(head) = heads.get(&seq).and_then(|h| crate::hash::hex_decode(h)) else {
            out.problems.push(format!(
                "truncated: {} covers entry #{}, which is not in the log (entries removed from the end)",
                file, seq
            ));
            return None;
        };
        if seq > 0 {
            out.covers.push((seq, file.to_string()));
        }
        Some((seq, head))
    };
    let check = |out: &mut TimestampVerification,
                 file: &str,
                 seq: u64,
                 head: &[u8],
                 tsa: &str,
                 der: &[u8]| {
        match verify_token(der, head, anchors) {
            Ok(c) => out.tokens.push(format!(
                "timestamp {} by {} covers entry #{}: {}",
                c.gen_time,
                tsa,
                seq,
                c.describe()
            )),
            Err(e) => out
                .problems
                .push(format!("{}: {} (entry #{})", file, e, seq)),
        }
    };

    // 1. Tokens the audit log records.
    for e in entries
        .iter()
        .filter(|e| e["action"] == "timestamp_obtained")
    {
        let d = &e["details"];
        let file = d["file"].as_str().unwrap_or_default();
        let at = e["seq"].as_u64().unwrap_or(0);
        if !is_token_name(file) {
            out.problems.push(format!(
                "entry #{} records timestamp token {}, which is missing or altered (not a token file name)",
                at,
                if file.is_empty() { "?" } else { file }
            ));
            continue;
        }
        if named.iter().any(|n| n == file) {
            continue;
        }
        named.push(file.to_string());
        let want = d["token_sha256"].as_str().unwrap_or_default();
        let covers = d["covers_seq"].as_u64();
        let (tsa, gen_time) = (
            d["tsa"].as_str().unwrap_or("?"),
            d["gen_time"].as_str().unwrap_or("?"),
        );
        if covers.is_some_and(|c| c >= at) {
            out.problems.push(format!(
                "entry #{} records timestamp token {} covering a later entry",
                at, file
            ));
            continue;
        }
        let claimed = claim(&mut out, file, covers, tsa, gen_time);
        let der = std::fs::read(log_dir.join(file)).unwrap_or_default();
        if der.is_empty() || hash_bytes(&der, HashAlgo::Sha256) != want {
            out.problems.push(format!(
                "entry #{} records timestamp token {}, which is missing or altered",
                at, file
            ));
            continue;
        }
        let meta_name = format!("{}.json", &file[..file.len() - 4]);
        match read_json(&log_dir.join(&meta_name)) {
            None => out.problems.push(format!(
                "{}: its metadata {} is missing or unreadable (entry #{} records the token)",
                file, meta_name, at
            )),
            Some(m) => {
                if m["file"].as_str() != Some(file)
                    || m["token_sha256"].as_str() != Some(want)
                    || m["covers_seq"].as_u64() != covers
                {
                    out.problems.push(format!(
                        "{}: its metadata {} does not match entry #{} of the audit log",
                        file, meta_name, at
                    ));
                }
            }
        }
        if let Some((seq, head)) = claimed {
            check(&mut out, file, seq, &head, tsa, &der);
        }
    }

    // 2. and 3. Token files next to the log that no entry records.
    let mut on_disk: Vec<String> = std::fs::read_dir(&log_dir)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("timestamp-"))
                .collect()
        })
        .unwrap_or_default();
    on_disk.sort();
    for m in on_disk.iter().filter(|n| n.ends_with(".json")) {
        let stem = &m[..m.len() - 5];
        if named.iter().any(|n| n.strip_suffix(".tsr") == Some(stem)) {
            continue;
        }
        let Some(meta) = read_json(&log_dir.join(m)) else {
            out.problems
                .push(format!("{}: unreadable", log_dir.join(m).display()));
            continue;
        };
        let file = meta["file"].as_str().unwrap_or_default();
        if !is_token_name(file) {
            out.problems
                .push(format!("{}: names no token file ({:?})", m, file));
            continue;
        }
        named.push(file.to_string());
        let tsa = meta["tsa"].as_str().unwrap_or("?");
        let gen_time = meta["gen_time"].as_str().unwrap_or("?");
        let Some((seq, head)) = claim(&mut out, file, meta["covers_seq"].as_u64(), tsa, gen_time)
        else {
            continue;
        };
        let der = std::fs::read(log_dir.join(file)).unwrap_or_default();
        if hash_bytes(&der, HashAlgo::Sha256) != meta["token_sha256"].as_str().unwrap_or_default() {
            out.problems
                .push(format!("{}: token file missing or altered", file));
            continue;
        }
        check(&mut out, file, seq, &head, tsa, &der);
    }
    for t in on_disk.iter().filter(|n| n.ends_with(".tsr")) {
        if !named.iter().any(|n| n == t) {
            out.problems.push(format!(
                "{}: a timestamp token that neither the audit log nor a metadata file records (cannot be checked)",
                t
            ));
        }
    }
    out
}

// ---------------------------------------------------------------- TSA token signature (RFC 3161 / RFC 5652)

const OID_CT_TSTINFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_ATTR_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_ATTR_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_ATTR_SIGNING_CERT: &str = "1.2.840.113549.1.9.16.2.12";
const OID_ATTR_SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";
const OID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const OID_EXT_EKU: &str = "2.5.29.37";
const OID_EXT_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_EXT_SKI: &str = "2.5.29.14";
const OID_SHA1: &str = "1.3.14.3.2.26";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const OID_RSA_SHA512: &str = "1.2.840.113549.1.1.13";

fn oid(s: &str) -> const_oid::ObjectIdentifier {
    const_oid::ObjectIdentifier::new_unwrap(s)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Md {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

fn md_of(o: &const_oid::ObjectIdentifier) -> Option<Md> {
    match o.to_string().as_str() {
        OID_SHA1 => Some(Md::Sha1),
        OID_SHA256 => Some(Md::Sha256),
        OID_SHA384 => Some(Md::Sha384),
        OID_SHA512 => Some(Md::Sha512),
        _ => None,
    }
}

fn md_digest(md: Md, data: &[u8]) -> Vec<u8> {
    use sha2_legacy::{Sha384, Sha512};
    match md {
        Md::Sha1 => crate::hash::hex_decode(&hash_bytes(data, HashAlgo::Sha1)).unwrap_or_default(),
        Md::Sha256 => Sha256::digest(data).to_vec(),
        Md::Sha384 => Sha384::digest(data).to_vec(),
        Md::Sha512 => Sha512::digest(data).to_vec(),
    }
}

/// RSA PKCS#1 v1.5 verification of `sig` over `data` hashed with `md`.
fn rsa_verify(
    spki: &spki::SubjectPublicKeyInfoOwned,
    md: Md,
    data: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    use rsa::pkcs8::DecodePublicKey;
    let spki_der = spki.to_der().map_err(|e| e.to_string())?;
    let key = rsa::RsaPublicKey::from_public_key_der(&spki_der).map_err(|_| {
        "the signer key is not RSA (not supported: signature not checked)".to_string()
    })?;
    let scheme = match md {
        Md::Sha256 => rsa::Pkcs1v15Sign::new::<Sha256>(),
        Md::Sha384 => rsa::Pkcs1v15Sign::new::<sha2_legacy::Sha384>(),
        Md::Sha512 => rsa::Pkcs1v15Sign::new::<sha2_legacy::Sha512>(),
        Md::Sha1 => return Err("SHA-1 signatures are not supported (signature not checked)".into()),
    };
    key.verify(scheme, &md_digest(md, data), sig)
        .map_err(|_| "signature value does not verify".to_string())
}

/// Hash used by a signature algorithm: `rsaEncryption` takes the SignerInfo digest algorithm.
fn sig_md(alg: &const_oid::ObjectIdentifier, digest_md: Option<Md>) -> Result<Md, String> {
    match alg.to_string().as_str() {
        OID_RSA => digest_md.ok_or_else(|| "unsupported digest algorithm".to_string()),
        OID_RSA_SHA256 => Ok(Md::Sha256),
        OID_RSA_SHA384 => Ok(Md::Sha384),
        OID_RSA_SHA512 => Ok(Md::Sha512),
        other => Err(format!(
            "signature algorithm {} not supported (signature not checked)",
            other
        )),
    }
}

/// Children of a DER constructed value: (tag, content).
fn der_children(mut b: &[u8]) -> Result<Vec<(u8, &[u8])>, String> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (tag, s, e) = der_tlv(b, 0)?;
        out.push((tag, &b[s..e]));
        b = &b[e..];
    }
    Ok(out)
}

fn ext<'c>(cert: &'c Certificate, id: &str) -> Option<&'c x509_cert::ext::Extension> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid(id))
}

fn subject(cert: &Certificate) -> String {
    cert.tbs_certificate.subject.to_string()
}

/// What `verify_token` established about one token.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenCheck {
    pub gen_time: String,
    pub tsa_subject: String,
    /// Subject of the trust anchor the TSA certificate chains to; None = chain not validated.
    pub anchor: Option<String>,
}

impl TokenCheck {
    pub fn describe(&self) -> String {
        match &self.anchor {
            Some(a) => format!(
                "TSA signature valid (signer: {}); chain validated to {} (revocation not checked)",
                self.tsa_subject, a
            ),
            None => format!(
                "TSA signature valid (signer: {}); chain not checked (pass --tsa-ca <CA bundle> to validate it)",
                self.tsa_subject
            ),
        }
    }
}

/// Full check of a stored TSA response: status, message imprint = `digest`, then the CMS SignedData of the
/// token — eContentType id-ct-TSTInfo, one SignerInfo whose certificate is in the token, signed attributes
/// with content-type, message-digest over the TSTInfo, ESS signing-certificate (v1 or v2) binding that
/// certificate, the signature value (RSA PKCS#1 v1.5) and the timeStamping extended key usage. With
/// `anchors`, the certificate chain is also validated at genTime (signatures, validity, CA flag); revocation
/// is never checked.
pub fn verify_token(
    der: &[u8],
    digest: &[u8],
    anchors: Option<&[Certificate]>,
) -> Result<TokenCheck, String> {
    let gen_time = parse_response(der, digest, None)?;
    let resp =
        TimeStampResp::from_der(der).map_err(|e| format!("not a time-stamp response: {}", e))?;
    let token = resp.time_stamp_token.ok_or("TSA response has no token")?;
    let sd: SignedData = token
        .content
        .decode_as()
        .map_err(|e| format!("bad token: {}", e))?;
    if sd.encap_content_info.econtent_type != oid(OID_CT_TSTINFO) {
        return Err("token content is not a TSTInfo".into());
    }
    let tst: OctetString = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or("token without TSTInfo")?
        .decode_as()
        .map_err(|e| format!("bad TSTInfo: {}", e))?;
    let tst = tst.as_bytes();
    let si = match sd.signer_infos.0.as_slice() {
        [one] => one,
        [] => return Err("token has no SignerInfo".into()),
        _ => return Err("token has more than one SignerInfo".into()),
    };
    let certs: Vec<Certificate> = sd
        .certificates
        .as_ref()
        .map(|cs| {
            cs.0.iter()
                .filter_map(|c| match c {
                    CertificateChoices::Certificate(c) => Some(c.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let signer = certs
        .iter()
        .find(|c| match &si.sid {
            SignerIdentifier::IssuerAndSerialNumber(ias) => {
                c.tbs_certificate.issuer == ias.issuer
                    && c.tbs_certificate.serial_number == ias.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => ext(c, OID_EXT_SKI)
                .and_then(|e| OctetString::from_der(e.extn_value.as_bytes()).ok())
                .is_some_and(|v| v.as_bytes() == ski.0.as_bytes()),
        })
        .ok_or("the TSA certificate is not in the token (signature not checked)")?;
    let tsa_subject = subject(signer);
    let digest_md = md_of(&si.digest_alg.oid);
    let attrs = si
        .signed_attrs
        .as_ref()
        .ok_or("token SignerInfo has no signed attributes")?;
    let attr = |id: &str| {
        attrs
            .iter()
            .find(|a| a.oid == oid(id))
            .and_then(|a| a.values.iter().next())
    };
    // content-type
    let ct = attr(OID_ATTR_CONTENT_TYPE).ok_or("signed attributes lack content-type")?;
    let ct: const_oid::ObjectIdentifier = ct
        .decode_as()
        .map_err(|e| format!("bad content-type: {}", e))?;
    if ct != oid(OID_CT_TSTINFO) {
        return Err("signed content-type is not id-ct-TSTInfo".into());
    }
    // message-digest over the TSTInfo
    let md =
        digest_md.ok_or_else(|| format!("digest algorithm {} not supported", si.digest_alg.oid))?;
    let want: OctetString = attr(OID_ATTR_MESSAGE_DIGEST)
        .ok_or("signed attributes lack message-digest")?
        .decode_as()
        .map_err(|e| format!("bad message-digest: {}", e))?;
    if want.as_bytes() != md_digest(md, tst).as_slice() {
        return Err("message-digest does not match the TSTInfo (token altered)".into());
    }
    // ESS signing-certificate (v2 preferred, else v1) binds the TSA certificate.
    let cert_der = signer.to_der().map_err(|e| e.to_string())?;
    let (ess, v2) = match (attr(OID_ATTR_SIGNING_CERT_V2), attr(OID_ATTR_SIGNING_CERT)) {
        (Some(a), _) => (a, true),
        (None, Some(a)) => (a, false),
        (None, None) => {
            return Err(
                "signed attributes lack the ESS signing-certificate (RFC 5816/2634)".into(),
            );
        }
    };
    let ess = ess.to_der().map_err(|e| e.to_string())?;
    let (_, s, e) = der_tlv(&ess, 0)?;
    let seq = der_children(&ess[s..e])?;
    let (_, ids) = seq.first().ok_or("empty ESS signing-certificate")?;
    let (_, first) = *der_children(ids)?
        .first()
        .ok_or("ESS signing-certificate lists no certificate")?;
    let fields = der_children(first)?;
    let (hash_md, hash) = if v2 {
        match fields.as_slice() {
            [(0x30, alg), (0x04, h), ..] => {
                let (_, os, oe) = der_tlv(alg, 0)?;
                let o = const_oid::ObjectIdentifier::from_bytes(&alg[os..oe])
                    .map_err(|e| format!("bad ESSCertIDv2 algorithm: {}", e))?;
                (
                    md_of(&o).ok_or("ESSCertIDv2 hash algorithm not supported")?,
                    *h,
                )
            }
            [(0x04, h), ..] => (Md::Sha256, *h),
            _ => return Err("bad ESSCertIDv2".into()),
        }
    } else {
        match fields.as_slice() {
            [(0x04, h), ..] => (Md::Sha1, *h),
            _ => return Err("bad ESSCertID".into()),
        }
    };
    if hash != md_digest(hash_md, &cert_der).as_slice() {
        return Err(
            "ESS signing-certificate does not match the TSA certificate in the token".into(),
        );
    }
    // Signature over the DER of the signed attributes (SET OF).
    let signed = attrs.to_der().map_err(|e| e.to_string())?;
    let smd = sig_md(&si.signature_algorithm.oid, digest_md)?;
    rsa_verify(
        &signer.tbs_certificate.subject_public_key_info,
        smd,
        &signed,
        si.signature.as_bytes(),
    )
    .map_err(|e| format!("TSA {}", e))?;
    // RFC 3161 §2.3: the TSA certificate's extendedKeyUsage is critical and contains only id-kp-timeStamping.
    check_tsa_eku(signer)?;
    let anchor = match anchors {
        None => None,
        Some(a) => Some(validate_chain(signer, &certs, a, &gen_time)?),
    };
    Ok(TokenCheck {
        gen_time,
        tsa_subject,
        anchor,
    })
}

/// RFC 3161 §2.3: "The corresponding certificate MUST contain only one instance of the extended key usage field
/// extension … with KeyPurposeID having value id-kp-timeStamping. This extension MUST be critical." Same rule as
/// rv-certcheck's token analysis and OpenSSL's `timestampsign` purpose.
fn check_tsa_eku(signer: &Certificate) -> Result<(), String> {
    let e = ext(signer, OID_EXT_EKU)
        .ok_or("the TSA certificate lacks the timeStamping extended key usage")?;
    let eku = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(e.extn_value.as_bytes())
        .map_err(|_| "the TSA certificate's extended key usage is malformed".to_string())?;
    if !eku.0.contains(&oid(OID_KP_TIME_STAMPING)) {
        return Err("the TSA certificate lacks the timeStamping extended key usage".into());
    }
    if eku.0.len() != 1 {
        return Err(
            "the TSA certificate's extended key usage must contain only id-kp-timeStamping (RFC 3161 §2.3)"
                .into(),
        );
    }
    if !e.critical {
        return Err(
            "the TSA certificate's extended key usage must be critical (RFC 3161 §2.3)".into(),
        );
    }
    Ok(())
}

fn unix_of(gen_time: &str) -> Result<u64, String> {
    chrono::DateTime::parse_from_rfc3339(gen_time)
        .map(|d| d.timestamp().max(0) as u64)
        .map_err(|e| format!("bad genTime {}: {}", gen_time, e))
}

fn check_validity(c: &Certificate, at: u64) -> Result<(), String> {
    let v = &c.tbs_certificate.validity;
    let (nb, na) = (
        v.not_before.to_unix_duration().as_secs(),
        v.not_after.to_unix_duration().as_secs(),
    );
    if at < nb || at > na {
        return Err(format!(
            "certificate {} was not valid at the token's genTime",
            subject(c)
        ));
    }
    Ok(())
}

/// Verifies that `issuer` signed `cert`.
fn signed_by(cert: &Certificate, issuer: &Certificate) -> bool {
    let Ok(tbs) = cert.tbs_certificate.to_der() else {
        return false;
    };
    let Ok(md) = sig_md(&cert.signature_algorithm.oid, None) else {
        return false;
    };
    let Some(sig) = cert.signature.as_bytes() else {
        return false;
    };
    rsa_verify(
        &issuer.tbs_certificate.subject_public_key_info,
        md,
        &tbs,
        sig,
    )
    .is_ok()
}

// ---------------------------------------------------------------- TSA certificate path (RFC 5280 subset)
//
// What is checked on the path TSA certificate → intermediates (from the token) → anchor (from --tsa-ca):
// * every signature (RSA PKCS#1 v1.5) and every certificate's validity at genTime;
// * basicConstraints cA=TRUE on every intermediate; an anchor is a CA when it has cA=TRUE, or (no
//   basicConstraints) when it is an X.509 v1 certificate or its keyUsage has keyCertSign (as OpenSSL);
// * keyCertSign when an issuer (intermediate or anchor) has a keyUsage extension;
// * pathLenConstraint of every issuer, anchor included: non-self-issued intermediates below it (RFC 5280
//   §6.1.4(l)-(m)); self-issued key-rollover certificates do not count;
// * nameConstraints of every issuer: directoryName subtrees are evaluated against the subject (and
//   directoryName subjectAltNames) of every certificate below it, except self-issued intermediates (§6.1.3(b));
//   names compared per §7.1 (attribute values of string types case-folded with whitespace collapsed). Other
//   name forms (dNSName, rfc822Name, iPAddress, URI, …) are not evaluated: a subtree of such a form while a
//   certificate below carries a name of that form (subjectAltName, or emailAddress in the subject for
//   rfc822Name) rejects the path, fail closed; subtrees with minimum/maximum are rejected too;
// * critical extensions: only those in [`HANDLED_CRITICAL`] are accepted, on every certificate of the path
//   including the anchor; any other critical extension (policyConstraints, policyMappings, inhibitAnyPolicy
//   among them: certificate-policy processing is not implemented) rejects it. A critical certificatePolicies
//   is accepted: with no policy required by the verifier and policyConstraints rejected, §6.1.5(g) succeeds
//   whatever the policies are. A critical extendedKeyUsage on a CA must allow timeStamping (or anyEKU);
// * path building tries every candidate issuer in the token and every candidate anchor in the bundle
//   (cross-signed intermediates, expired-then-renewed anchors), depth-first, at most [`MAX_PATH`] certificates
//   below the anchor, never the same certificate twice on one path, at most [`MAX_CANDIDATES`] signature checks.
// Not checked: revocation (CRL/OCSP) — never; certificate policies (see above); the extended key usage of CAs
// when not critical; algorithms other than RSA.

const OID_EXT_KEY_USAGE: &str = "2.5.29.15";
const OID_EXT_SAN: &str = "2.5.29.17";
const OID_EXT_NAME_CONSTRAINTS: &str = "2.5.29.30";
const OID_EXT_CERT_POLICIES: &str = "2.5.29.32";
const OID_EXT_AKI: &str = "2.5.29.35";
const OID_ANY_EKU: &str = "2.5.29.37.0";
const OID_EMAIL_ADDRESS: &str = "1.2.840.113549.1.9.1";

/// Critical extensions the path validation processes (any other critical extension rejects the path).
const HANDLED_CRITICAL: [&str; 8] = [
    OID_EXT_BASIC_CONSTRAINTS,
    OID_EXT_KEY_USAGE,
    OID_EXT_EKU,
    OID_EXT_NAME_CONSTRAINTS,
    OID_EXT_CERT_POLICIES,
    OID_EXT_SAN,
    OID_EXT_SKI,
    OID_EXT_AKI,
];

/// At most this many certificates below the trust anchor (the TSA certificate and its intermediates).
const MAX_PATH: usize = 8;
/// At most this many candidate issuers tried (signature checks) while building one path.
const MAX_CANDIDATES: usize = 512;

fn decode_ext<T: for<'a> Decode<'a>>(
    c: &Certificate,
    id: &str,
    what: &str,
) -> Result<Option<(T, bool)>, String> {
    match ext(c, id) {
        None => Ok(None),
        Some(e) => T::from_der(e.extn_value.as_bytes())
            .map(|v| Some((v, e.critical)))
            .map_err(|_| format!("certificate {} has a malformed {}", subject(c), what)),
    }
}

fn self_issued(c: &Certificate) -> bool {
    c.tbs_certificate.subject == c.tbs_certificate.issuer
}

/// Extensions every certificate of the path must pass: no duplicates, no unhandled critical extension, and the
/// handled ones decodable.
fn check_extensions(c: &Certificate) -> Result<(), String> {
    let exts = c.tbs_certificate.extensions.as_deref().unwrap_or_default();
    for (i, e) in exts.iter().enumerate() {
        if exts[..i].iter().any(|p| p.extn_id == e.extn_id) {
            return Err(format!(
                "certificate {} has the extension {} twice",
                subject(c),
                e.extn_id
            ));
        }
        if e.critical && !HANDLED_CRITICAL.iter().any(|h| e.extn_id == oid(h)) {
            return Err(format!(
                "certificate {} has an unsupported critical extension {} (not evaluated: rejected)",
                subject(c),
                e.extn_id
            ));
        }
    }
    use x509_cert::ext::pkix::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName, constraints::NameConstraints,
    };
    decode_ext::<BasicConstraints>(c, OID_EXT_BASIC_CONSTRAINTS, "basicConstraints")?;
    decode_ext::<KeyUsage>(c, OID_EXT_KEY_USAGE, "keyUsage")?;
    decode_ext::<ExtendedKeyUsage>(c, OID_EXT_EKU, "extendedKeyUsage")?;
    decode_ext::<NameConstraints>(c, OID_EXT_NAME_CONSTRAINTS, "nameConstraints")?;
    decode_ext::<SubjectAltName>(c, OID_EXT_SAN, "subjectAltName")?;
    Ok(())
}

/// RFC 5280 §7.1 comparison of one attribute value: string types case-folded, whitespace trimmed and
/// collapsed; other types byte for byte.
fn attr_value_key(v: &Any) -> Vec<u8> {
    let raw = v.value();
    let text = match u8::from(der::Tagged::tag(v)) {
        0x0c | 0x13 | 0x16 | 0x14 => String::from_utf8(raw.to_vec()).ok(),
        0x1e if raw.len() & 1 == 0 => String::from_utf16(
            &raw.chunks(2)
                .map(|p| u16::from_be_bytes([p[0], p[1]]))
                .collect::<Vec<_>>(),
        )
        .ok(),
        _ => None,
    };
    match text {
        Some(t) => {
            let mut k = vec![b's'];
            k.extend(
                t.split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase()
                    .into_bytes(),
            );
            k
        }
        None => {
            let mut k = vec![b'b'];
            k.extend(v.to_der().unwrap_or_default());
            k
        }
    }
}

fn rdn_key(rdn: &x509_cert::name::RelativeDistinguishedName) -> Vec<(String, Vec<u8>)> {
    let mut k: Vec<_> = rdn
        .0
        .iter()
        .map(|a| (a.oid.to_string(), attr_value_key(&a.value)))
        .collect();
    k.sort();
    k
}

/// `name` is within the directoryName subtree `base`: base's RDNs are a prefix of name's.
fn dn_within(name: &x509_cert::name::Name, base: &x509_cert::name::Name) -> bool {
    base.0.len() <= name.0.len()
        && base
            .0
            .iter()
            .zip(name.0.iter())
            .all(|(b, n)| rdn_key(b) == rdn_key(n))
}

fn general_name_kind(g: &x509_cert::ext::pkix::name::GeneralName) -> &'static str {
    use x509_cert::ext::pkix::name::GeneralName as G;
    match g {
        G::OtherName(_) => "otherName",
        G::Rfc822Name(_) => "rfc822Name",
        G::DnsName(_) => "dNSName",
        G::DirectoryName(_) => "directoryName",
        G::EdiPartyName(_) => "ediPartyName",
        G::UniformResourceIdentifier(_) => "uniformResourceIdentifier",
        G::IpAddress(_) => "iPAddress",
        G::RegisteredId(_) => "registeredID",
    }
}

/// Checks the names of `c` against the nameConstraints `nc` of `issuer`.
fn check_names(
    c: &Certificate,
    issuer: &Certificate,
    nc: &x509_cert::ext::pkix::constraints::NameConstraints,
) -> Result<(), String> {
    use x509_cert::ext::pkix::SubjectAltName;
    use x509_cert::ext::pkix::name::GeneralName as G;
    let sans: Vec<G> = decode_ext::<SubjectAltName>(c, OID_EXT_SAN, "subjectAltName")?
        .map(|(s, _)| s.0)
        .unwrap_or_default();
    let mut dns: Vec<&x509_cert::name::Name> = Vec::new();
    if !c.tbs_certificate.subject.0.is_empty() {
        dns.push(&c.tbs_certificate.subject);
    }
    for s in &sans {
        if let G::DirectoryName(n) = s {
            dns.push(n);
        }
    }
    let has_email_attr = c
        .tbs_certificate
        .subject
        .0
        .iter()
        .any(|r| r.0.iter().any(|a| a.oid == oid(OID_EMAIL_ADDRESS)));
    let permitted = nc.permitted_subtrees.as_deref().unwrap_or_default();
    let excluded = nc.excluded_subtrees.as_deref().unwrap_or_default();
    let violation = |how: &str| {
        Err(format!(
            "certificate {} violates the name constraints of {} ({})",
            subject(c),
            subject(issuer),
            how
        ))
    };
    for st in permitted.iter().chain(excluded) {
        if st.minimum != 0 || st.maximum.is_some() {
            return Err(format!(
                "the name constraints of {} use minimum/maximum, which cannot be evaluated (rejected)",
                subject(issuer)
            ));
        }
        let kind = general_name_kind(&st.base);
        if kind == "directoryName" {
            continue;
        }
        let carries = sans.iter().any(|s| general_name_kind(s) == kind)
            || (kind == "rfc822Name" && has_email_attr);
        if carries {
            return Err(format!(
                "the {} name constraints of {} cannot be evaluated for {}, which has {} names (rejected)",
                kind,
                subject(issuer),
                subject(c),
                kind
            ));
        }
    }
    let permitted_dn: Vec<&x509_cert::name::Name> = permitted
        .iter()
        .filter_map(|s| match &s.base {
            G::DirectoryName(n) => Some(n),
            _ => None,
        })
        .collect();
    for name in &dns {
        if !permitted_dn.is_empty() && !permitted_dn.iter().any(|b| dn_within(name, b)) {
            return violation(&format!("{} is outside the permitted subtrees", name));
        }
        let excluded_dn = excluded.iter().filter_map(|s| match &s.base {
            G::DirectoryName(n) => Some(n),
            _ => None,
        });
        for b in excluded_dn {
            if dn_within(name, b) {
                return violation(&format!("{} is inside the excluded subtree {}", name, b));
            }
        }
    }
    Ok(())
}

/// Path constraints of a complete candidate path: `path[0]` is the TSA certificate, the last one the anchor.
fn check_path(path: &[&Certificate]) -> Result<(), String> {
    use x509_cert::ext::pkix::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, constraints::NameConstraints,
    };
    let n = path.len();
    for (j, c) in path.iter().enumerate().skip(1) {
        let is_anchor = j == n - 1;
        let bc = decode_ext::<BasicConstraints>(c, OID_EXT_BASIC_CONSTRAINTS, "basicConstraints")?;
        let ku = decode_ext::<KeyUsage>(c, OID_EXT_KEY_USAGE, "keyUsage")?;
        match &bc {
            Some((b, _)) if b.ca => {}
            Some(_) => {
                return Err(format!(
                    "certificate {} is not a CA (basicConstraints cA is false) but issued {}",
                    subject(c),
                    subject(path[j - 1])
                ));
            }
            None => {
                let v1 = c.tbs_certificate.version == x509_cert::certificate::Version::V1
                    && c.tbs_certificate.extensions.is_none();
                let cert_sign = ku.as_ref().is_some_and(|(k, _)| k.key_cert_sign());
                if !(is_anchor && (v1 || cert_sign)) {
                    return Err(format!(
                        "certificate {} is not a CA (no basicConstraints) but issued {}",
                        subject(c),
                        subject(path[j - 1])
                    ));
                }
            }
        }
        if ku.as_ref().is_some_and(|(k, _)| !k.key_cert_sign()) {
            return Err(format!(
                "certificate {} may not sign certificates (its keyUsage lacks keyCertSign)",
                subject(c)
            ));
        }
        if let Some(max) = bc.as_ref().and_then(|(b, _)| b.path_len_constraint) {
            let below = path[1..j].iter().filter(|x| !self_issued(x)).count();
            if below > max as usize {
                return Err(format!(
                    "certificate {} allows {} intermediate CA certificate(s) below it (pathLenConstraint), the path has {}",
                    subject(c),
                    max,
                    below
                ));
            }
        }
        let ca_eku = decode_ext::<ExtendedKeyUsage>(c, OID_EXT_EKU, "extendedKeyUsage")?;
        if ca_eku.is_some_and(|(eku, critical)| {
            critical
                && !eku
                    .0
                    .iter()
                    .any(|p| *p == oid(OID_KP_TIME_STAMPING) || *p == oid(OID_ANY_EKU))
        }) {
            return Err(format!(
                "certificate {} has a critical extended key usage without timeStamping",
                subject(c)
            ));
        }
        if let Some((nc, _)) =
            decode_ext::<NameConstraints>(c, OID_EXT_NAME_CONSTRAINTS, "nameConstraints")?
        {
            for (k, below) in path[..j].iter().enumerate() {
                if k > 0 && self_issued(below) {
                    continue;
                }
                check_names(below, c, &nc)?;
            }
        }
    }
    Ok(())
}

/// Depth-first search for a valid path (see the section comment above).
struct PathSearch<'a> {
    token: &'a [Certificate],
    anchors: &'a [Certificate],
    anchor_ders: Vec<Vec<u8>>,
    at: u64,
    tried: usize,
    first_problem: Option<String>,
    deepest: String,
}

impl<'a> PathSearch<'a> {
    fn note(&mut self, problem: String) {
        self.first_problem.get_or_insert(problem);
    }

    fn budget(&mut self) -> bool {
        self.tried += 1;
        if self.tried > MAX_CANDIDATES {
            self.note(format!(
                "more than {MAX_CANDIDATES} candidate issuers (search stopped)"
            ));
            return false;
        }
        true
    }

    fn extend(
        &mut self,
        path: &mut Vec<&'a Certificate>,
        ders: &mut Vec<Vec<u8>>,
    ) -> Option<String> {
        let cur = *path.last()?;
        if let Err(e) = check_validity(cur, self.at).and_then(|_| check_extensions(cur)) {
            self.note(e);
            return None;
        }
        self.deepest = subject(cur);
        if self.anchor_ders.contains(ders.last()?) {
            // The certificate itself is in the bundle: the path ends here.
            return match check_path(path) {
                Ok(()) => Some(subject(cur)),
                Err(e) => {
                    self.note(e);
                    None
                }
            };
        }
        for a in self.anchors {
            if a.tbs_certificate.subject != cur.tbs_certificate.issuer {
                continue;
            }
            let Ok(a_der) = a.to_der() else { continue };
            if ders.contains(&a_der) {
                continue;
            }
            if !self.budget() {
                return None;
            }
            if !signed_by(cur, a) {
                continue;
            }
            if let Err(e) = check_validity(a, self.at).and_then(|_| check_extensions(a)) {
                self.note(e);
                continue;
            }
            path.push(a);
            let r = check_path(path);
            path.pop();
            match r {
                Ok(()) => return Some(subject(a)),
                Err(e) => self.note(e),
            }
        }
        let has_issuer_in_token = self
            .token
            .iter()
            .any(|c| c.tbs_certificate.subject == cur.tbs_certificate.issuer);
        if path.len() >= MAX_PATH {
            if has_issuer_in_token {
                self.note(format!(
                    "TSA certificate chain too long (more than {MAX_PATH} certificates below the trust anchor)"
                ));
            }
            return None;
        }
        for c in self.token {
            if c.tbs_certificate.subject != cur.tbs_certificate.issuer {
                continue;
            }
            let Ok(c_der) = c.to_der() else { continue };
            if ders.contains(&c_der) {
                continue;
            }
            if !self.budget() {
                return None;
            }
            if !signed_by(cur, c) {
                continue;
            }
            path.push(c);
            ders.push(c_der);
            if let Some(anchor) = self.extend(path, ders) {
                return Some(anchor);
            }
            path.pop();
            ders.pop();
        }
        None
    }
}

/// Builds and checks a path from the TSA certificate to one of `anchors` at genTime (see the section comment
/// above for what is and is not checked). Returns the anchor's subject.
fn validate_chain(
    leaf: &Certificate,
    token_certs: &[Certificate],
    anchors: &[Certificate],
    gen_time: &str,
) -> Result<String, String> {
    let mut search = PathSearch {
        token: token_certs,
        anchors,
        anchor_ders: anchors.iter().filter_map(|a| a.to_der().ok()).collect(),
        at: unix_of(gen_time)?,
        tried: 0,
        first_problem: None,
        deepest: subject(leaf),
    };
    let leaf_der = leaf.to_der().map_err(|e| e.to_string())?;
    if let Some(anchor) = search.extend(&mut vec![leaf], &mut vec![leaf_der]) {
        return Ok(anchor);
    }
    Err(match search.first_problem {
        Some(p) => format!("TSA certificate chain not validated: {p}"),
        None => format!(
            "TSA certificate chain not validated: no trusted issuer for {} in the CA bundle",
            search.deepest
        ),
    })
}

/// Reads a CA bundle for `--tsa-ca`: PEM (one or more certificates) or a single DER certificate.
pub fn load_ca_bundle(path: &Path) -> Result<Vec<Certificate>, String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let certs = if data.starts_with(b"-----") || data.windows(11).any(|w| w == b"-----BEGIN ") {
        Certificate::load_pem_chain(&data)
            .map_err(|e| format!("{}: bad PEM: {}", path.display(), e))?
    } else {
        vec![
            Certificate::from_der(&data)
                .map_err(|e| format!("{}: bad DER certificate: {}", path.display(), e))?,
        ]
    };
    if certs.is_empty() {
        return Err(format!("{}: no certificate", path.display()));
    }
    Ok(certs)
}

// ---------------------------------------------------------------- PDF signatures

/// RSA PKCS#1 v1.5 signing key that always signs with blinding (fresh OS randomness per signature).
///
/// The cms builder signs through the plain `Signer` trait, which rsa 0.9 implements without blinding.
/// Blinding is the standard countermeasure to timing side channels on the private-key operation
/// (RUSTSEC-2023-0071, "Marvin"), so the examiner's key is only ever used through this wrapper. PKCS#1 v1.5
/// signatures are deterministic: blinding changes the timing, not the signature bytes.
struct BlindedSigningKey(SigningKey<Sha256>);

impl rsa::signature::Keypair for BlindedSigningKey {
    type VerifyingKey = rsa::pkcs1v15::VerifyingKey<Sha256>;
    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}

impl spki::SignatureAlgorithmIdentifier for BlindedSigningKey {
    type Params = der::AnyRef<'static>;
    const SIGNATURE_ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> =
        <SigningKey<Sha256> as spki::SignatureAlgorithmIdentifier>::SIGNATURE_ALGORITHM_IDENTIFIER;
}

impl rsa::signature::Signer<Signature> for BlindedSigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, rsa::signature::Error> {
        use rsa::signature::RandomizedSigner;
        self.0.try_sign_with_rng(&mut rsa::rand_core::OsRng, msg)
    }
}

pub struct PdfSigner {
    key: BlindedSigningKey,
    certs: Vec<Certificate>,
    pub subject: String,
    pub fingerprint_sha256: String,
}

impl PdfSigner {
    pub fn load(path: &Path, password: &str) -> Result<PdfSigner, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("cannot read signing certificate {}: {}", path.display(), e))?;
        let ks = p12_keystore::KeyStore::from_pkcs12(
            &data,
            password,
            p12_keystore::Pkcs12ImportPolicy::Relaxed,
        )
        .map_err(|e| {
            format!(
                "cannot load signing certificate {}: wrong password or unsupported file ({})",
                path.display(),
                e
            )
        })?;
        let (_, chain) = ks
            .private_key_chain()
            .ok_or("the certificate file contains no private key")?;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(chain.key().as_der())
            .map_err(|_| "only RSA signing certificates are supported".to_string())?;
        let certs = chain
            .certs()
            .iter()
            .map(|c| Certificate::from_der(c.as_der()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let first = chain.certs().first().ok_or("no certificate in the file")?;
        Ok(PdfSigner {
            key: BlindedSigningKey(SigningKey::<Sha256>::new(key)),
            certs,
            subject: first.subject().to_string(),
            fingerprint_sha256: hash_bytes(first.as_der(), HashAlgo::Sha256),
        })
    }

    /// CMS SignedData (detached) over `content`, DER-encoded.
    pub fn sign_detached(&self, content: &[u8]) -> Result<Vec<u8>, String> {
        let digest = Sha256::digest(content);
        let cert = &self.certs[0];
        let eci = EncapsulatedContentInfo {
            econtent_type: const_oid::db::rfc5911::ID_DATA,
            econtent: None,
        };
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        });
        let dalg = AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };
        fn err<E: std::fmt::Debug>(e: E) -> String {
            format!("{:?}", e)
        }
        let mut sib = SignerInfoBuilder::new(&self.key, sid, dalg.clone(), &eci, Some(&digest))
            .map_err(err)?;
        sib.add_signed_attribute(create_signing_time_attribute().map_err(err)?)
            .map_err(err)?;
        let mut b = SignedDataBuilder::new(&eci);
        b.add_digest_algorithm(dalg).map_err(err)?;
        for c in &self.certs {
            b.add_certificate(CertificateChoices::Certificate(c.clone()))
                .map_err(err)?;
        }
        b.add_signer_info::<_, Signature>(sib).map_err(err)?;
        b.build().map_err(err)?.to_der().map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_valid_der_and_bad_responses_are_rejected() {
        let req = build_request(&[7u8; 32], &[1, 2, 3]).unwrap();
        assert_eq!(req[0], 0x30);
        assert!(TimeStampReq::from_der(&req).is_ok());
        assert!(parse_response(b"garbage", &[0u8; 32], None).is_err());
        assert!(request_timestamp(&[0u8; 32], "file:///etc/passwd").is_err());
        assert!(request_timestamp(&[0u8; 32], "http://127.0.0.1:9/tsr").is_err());
    }

    #[test]
    fn token_and_ca_bundle_inputs_are_checked() {
        assert!(verify_token(b"garbage", &[0u8; 32], None).is_err());
        // Truncated or oversized DER lengths are rejected, not read past the end.
        assert!(der_tlv(&[0x30, 0x05, 0x01], 0).is_err());
        assert!(der_tlv(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff], 0).is_err());
        assert_eq!(der_tlv(&[0x04, 0x01, 0xaa], 0), Ok((0x04, 2, 3)));
        let dir = tempfile::tempdir().unwrap();
        assert!(load_ca_bundle(&dir.path().join("missing.pem")).is_err());
        std::fs::write(dir.path().join("empty.pem"), b"-----BEGIN NOTHING-----\n").unwrap();
        assert!(load_ca_bundle(&dir.path().join("empty.pem")).is_err());
        assert_eq!(md_of(&oid(OID_SHA256)), Some(Md::Sha256));
        assert!(sig_md(&oid("1.2.840.10045.4.3.2"), Some(Md::Sha256)).is_err());
    }

    /// Review (sidecar bypass): the tokens are driven by the audit log's timestamp_obtained entries, so deleting
    /// a metadata file, pointing an entry outside the log folder or leaving an unexplained token is a problem.
    #[test]
    fn recorded_tokens_fail_closed_without_their_files() {
        let d = tempfile::tempdir().unwrap();
        let mut log = crate::audit::AuditLog::create(d.path(), "RUN-1", "t").unwrap();
        log.record("step", None, json!({})).unwrap();
        let tsr = b"not a real token";
        let sha = hash_bytes(tsr, HashAlgo::Sha256);
        log.record(
            "timestamp_obtained",
            Some("timestamp-00001.tsr"),
            json!({"file": "timestamp-00001.tsr", "token_sha256": sha, "covers_seq": 1,
                   "tsa": "t", "gen_time": "2026-01-01T00:00:00Z"}),
        )
        .unwrap();
        log.record(
            "timestamp_obtained",
            None,
            json!({"file": "../outside.tsr", "token_sha256": sha, "covers_seq": 1}),
        )
        .unwrap();
        let audit = d.path().join("audit.jsonl");
        // .tsr and metadata both missing.
        let p = verify_timestamps(&audit);
        assert!(
            p.iter().any(|x| x.contains(
                "entry #2 records timestamp token timestamp-00001.tsr, which is missing or altered"
            )),
            "{p:?}"
        );
        assert!(
            p.iter()
                .any(|x| x.contains("entry #3") && x.contains("not a token file name")),
            "{p:?}"
        );
        // .tsr back, metadata still missing: a problem, and the token is still checked.
        std::fs::write(d.path().join("timestamp-00001.tsr"), tsr).unwrap();
        let v = verify_timestamps_with(&audit, None);
        assert!(
            v.problems
                .iter()
                .any(|x| x.contains("metadata timestamp-00001.json is missing")),
            "{:?}",
            v.problems
        );
        assert!(
            v.problems
                .iter()
                .any(|x| x.starts_with("timestamp-00001.tsr: not a time-stamp response")),
            "{:?}",
            v.problems
        );
        assert_eq!(v.covers, vec![(1, "timestamp-00001.tsr".to_string())]);
        // Metadata that disagrees with the entry.
        let meta = json!({"file": "timestamp-00001.tsr", "token_sha256": sha, "covers_seq": 2});
        std::fs::write(d.path().join("timestamp-00001.json"), meta.to_string()).unwrap();
        assert!(
            verify_timestamps(&audit)
                .iter()
                .any(|x| x.contains("does not match entry #2"))
        );
        // A token nothing records.
        std::fs::write(d.path().join("timestamp-00009.tsr"), tsr).unwrap();
        assert!(
            verify_timestamps(&audit)
                .iter()
                .any(|x| x.starts_with("timestamp-00009.tsr: a timestamp token that neither"))
        );
        assert!(is_token_name("timestamp-0003.tsr"));
        for bad in [
            "../timestamp-1.tsr",
            "timestamp-1.json",
            "timestamp-a/b.tsr",
            "x.tsr",
            "timestamp-..tsr",
        ] {
            assert!(!is_token_name(bad), "{bad}");
        }
    }

    /// tests/fixtures/tsa-chains (made by make_chains.py, cross-checked with `openssl verify -purpose
    /// timestampsign`): every case reaches its expected verdict, and agrees with OpenSSL's unless the case
    /// documents why the tool is deliberately stricter (or, for path building, more thorough).
    #[test]
    fn chain_fixtures_match_expected_and_openssl() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/tsa-chains");
        let expected: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).unwrap())
                .unwrap();
        let gen_time = expected["gen_time"].as_str().unwrap();
        let cases = expected["cases"].as_object().unwrap();
        assert!(cases.len() >= 30, "{}", cases.len());
        let mut wrong = Vec::new();
        for (name, case) in cases {
            let d = dir.join("cases").join(name);
            let leaf = load_ca_bundle(&d.join("leaf.pem")).unwrap().remove(0);
            let chain = if d.join("chain.pem").exists() {
                load_ca_bundle(&d.join("chain.pem")).unwrap()
            } else {
                Vec::new()
            };
            let anchors = load_ca_bundle(&d.join("anchors.pem")).unwrap();
            let got = check_tsa_eku(&leaf)
                .and_then(|_| validate_chain(&leaf, &chain, &anchors, gen_time));
            let want = case["expect"].as_str().unwrap();
            let ok = match &got {
                Ok(_) => want == "ok",
                Err(e) => want != "ok" && e.contains(want),
            };
            if !ok {
                wrong.push(format!("{name}: want {want:?}, got {got:?}"));
            }
            let openssl_ok = case["openssl"] == "ok";
            if (want == "ok") != openssl_ok && case.get("deliberate_difference").is_none() {
                wrong.push(format!(
                    "{name}: disagrees with OpenSSL ({})",
                    case["openssl"]
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn blinded_signing_matches_unblinded_and_verifies() {
        use rsa::signature::{Keypair, Signer, Verifier};
        // Fresh test key; 1024 bits keeps the debug-build test fast (production keys come from the .p12).
        let mut rng = rsa::rand_core::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let plain = SigningKey::<Sha256>::new(key);
        let blinded = BlindedSigningKey(plain.clone());
        let msg = b"Rakvor report bytes";
        let a = blinded.try_sign(msg).unwrap();
        let b = plain.try_sign(msg).unwrap();
        assert_eq!(
            a, b,
            "PKCS#1 v1.5 is deterministic: blinding must not change the signature"
        );
        assert!(blinded.verifying_key().verify(msg, &a).is_ok());
    }
}
