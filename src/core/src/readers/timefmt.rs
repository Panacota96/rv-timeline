//! Strict time parsers for the formats the Rakvor tools write. Each parser accepts exactly its format and
//! returns `None` otherwise: a reader then skips the value and counts a warning, it never guesses.
//!
//! ```text
//! RFC 3339 / ISO 8601 (XMP subsets)  2026-11-10T10:00:00.5+01:00 · 2026-11-10T10:00 · 2026-11-10
//! RFC 5322                           Tue, 10 Nov 2026 11:00:00 +0100  (-0000 = zone unknown)
//! EXIF                               2026:11:10 10:00:00  (+ OffsetTime* "+01:00", SubSecTime* "123")
//! PDF                                D:20261110100000+01'00'  (D:2026 … any prefix; no zone = unknown)
//! X.509                              UTCTime 261110100000Z · GeneralizedTime 20261110100000.5Z
//! OpenSSL text                       Nov 10 10:00:00 2026 GMT
//! ```
//!
//! Every value keeps its precision (`Day` for a date, `Second` for `HH:MM:SS`, `Millisecond`… for fractions) and
//! its zone: an explicit offset gives `ZoneInfo::Explicit`; no zone gives `ZoneInfo::Unknown` and the wall-clock
//! time read as UTC.

use crate::model::{Precision, ZoneInfo};
use chrono::{NaiveDate, NaiveDateTime, NaiveTime};

/// A parsed instant (seconds + nanoseconds since the Unix epoch, UTC).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub utc_s: i64,
    pub utc_ns: u32,
    pub zone: ZoneInfo,
    /// Offset of the original from UTC, minutes (None when the zone is unknown).
    pub offset_min: Option<i32>,
    pub precision: Precision,
}

/// Largest offset accepted (RFC 3339 allows ±23:59; real zones stay within ±14:00, we accept up to ±18:00).
const MAX_OFFSET_MIN: i32 = 18 * 60;

fn digits(s: &[u8], at: usize, n: usize) -> Option<u32> {
    let b = s.get(at..at + n)?;
    if !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(b.iter().fold(0u32, |a, d| a * 10 + u32::from(d - b'0')))
}

/// Fraction digits → (nanoseconds, precision). 1–9 digits.
fn fraction(f: &[u8]) -> Option<(u32, Precision)> {
    if f.is_empty() || f.len() > 9 || !f.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut ns = 0u32;
    for i in 0..9 {
        ns = ns * 10 + f.get(i).map_or(0, |d| u32::from(d - b'0'));
    }
    let p = match f.len() {
        1..=3 => Precision::Millisecond,
        4..=6 => Precision::Microsecond,
        _ => Precision::Nanosecond,
    };
    Some((ns, p))
}

#[allow(clippy::too_many_arguments)]
fn build(
    y: i32,
    mo: u32,
    d: u32,
    h: u32,
    mi: u32,
    s: u32,
    ns: u32,
    offset_min: Option<i32>,
    precision: Precision,
) -> Option<Parsed> {
    // Leap seconds (:60) are rejected: chrono would fold them and the instant would be invented.
    let date = NaiveDate::from_ymd_opt(y, mo, d)?;
    let time = NaiveTime::from_hms_nano_opt(h, mi, s, ns)?;
    if s > 59 || ns > 999_999_999 {
        return None;
    }
    let naive = NaiveDateTime::new(date, time);
    let local_s = naive.and_utc().timestamp();
    let (zone, utc_s) = match offset_min {
        Some(o) if o.abs() <= MAX_OFFSET_MIN => {
            (ZoneInfo::Explicit, local_s.checked_sub(i64::from(o) * 60)?)
        }
        Some(_) => return None,
        None => (ZoneInfo::Unknown, local_s),
    };
    Some(Parsed {
        utc_s,
        utc_ns: ns,
        zone,
        offset_min,
        precision,
    })
}

/// `Z`, `z`, `+HH:MM`, `-HH:MM` (also `+HHMM` and `+HH` when `loose`). Returns the offset in minutes.
fn offset(s: &[u8], loose: bool) -> Option<i32> {
    match s {
        b"Z" | b"z" => return Some(0),
        [] => return None,
        _ => {}
    }
    let sign = match s[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (h, m) = match s.len() {
        6 if s[3] == b':' => (digits(s, 1, 2)?, digits(s, 4, 2)?),
        5 if loose => (digits(s, 1, 2)?, digits(s, 3, 2)?),
        3 if loose => (digits(s, 1, 2)?, 0),
        _ => return None,
    };
    if m > 59 {
        return None;
    }
    Some(sign * (h as i32 * 60 + m as i32))
}

/// RFC 3339 date-time: `YYYY-MM-DDTHH:MM:SS[.f]` followed by `Z` or `±HH:MM` (required). `T` may be `t` or a space.
pub fn rfc3339(raw: &str) -> Option<Parsed> {
    match iso8601(raw)? {
        p if p.zone == ZoneInfo::Explicit && p.precision >= Precision::Second => Some(p),
        _ => None,
    }
}

/// ISO 8601 as XMP writes it: `YYYY`, `YYYY-MM`, `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM[:SS[.f]][TZD]`. Without a TZD the
/// zone is unknown. Date-only values are `Day` precision (a year or month alone is placed on its first day).
pub fn iso8601(raw: &str) -> Option<Parsed> {
    let s = raw.as_bytes();
    let y = digits(s, 0, 4)? as i32;
    if s.len() == 4 {
        return build(y, 1, 1, 0, 0, 0, 0, None, Precision::Day);
    }
    if s.get(4) != Some(&b'-') {
        return None;
    }
    let mo = digits(s, 5, 2)?;
    if s.len() == 7 {
        return build(y, mo, 1, 0, 0, 0, 0, None, Precision::Day);
    }
    if s.get(7) != Some(&b'-') {
        return None;
    }
    let d = digits(s, 8, 2)?;
    if s.len() == 10 {
        return build(y, mo, d, 0, 0, 0, 0, None, Precision::Day);
    }
    if !matches!(s.get(10), Some(b'T' | b't' | b' ')) {
        return None;
    }
    let h = digits(s, 11, 2)?;
    if s.get(13) != Some(&b':') {
        return None;
    }
    let mi = digits(s, 14, 2)?;
    let mut pos = 16;
    let (mut sec, mut ns, mut prec) = (0, 0, Precision::Minute);
    if s.get(16) == Some(&b':') {
        sec = digits(s, 17, 2)?;
        prec = Precision::Second;
        pos = 19;
        if matches!(s.get(19), Some(b'.' | b',')) {
            let end = s[20..]
                .iter()
                .position(|c| !c.is_ascii_digit())
                .map_or(s.len(), |p| 20 + p);
            (ns, prec) = fraction(&s[20..end])?;
            pos = end;
        }
    }
    let off = if pos == s.len() {
        None
    } else {
        Some(offset(&s[pos..], false)?)
    };
    build(y, mo, d, h, mi, sec, ns, off, prec)
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn month(s: &str) -> Option<u32> {
    MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(s))
        .map(|i| i as u32 + 1)
}

/// RFC 5322 date-time (section 3.3, with the obsolete zones of 4.3): `[Day, ] D Mon YYYY HH:MM[:SS] zone
/// [(comment)]`. `-0000` means the zone is unknown (RFC 5322 3.3) and gives `ZoneInfo::Unknown`.
pub fn rfc5322(raw: &str) -> Option<Parsed> {
    let mut s = raw.trim();
    // Trailing comment such as "(CET)" or "(UTC)".
    if s.ends_with(')') {
        let open = s.rfind('(')?;
        s = s[..open].trim_end();
    }
    if let Some(i) = s.find(',') {
        let day = s[..i].trim();
        if !["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            .iter()
            .any(|d| d.eq_ignore_ascii_case(day))
        {
            return None;
        }
        s = s[i + 1..].trim_start();
    }
    let parts: Vec<&str> = s.split_ascii_whitespace().collect();
    let [d, mon, y, t, zone] = parts.as_slice() else {
        return None;
    };
    if d.is_empty() || d.len() > 2 || !d.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let d: u32 = d.parse().ok()?;
    let mo = month(mon)?;
    if !y.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let y: i32 = match y.len() {
        4 => y.parse().ok()?,
        // Obsolete 2/3-digit years (RFC 5322 4.3).
        2 => {
            let v: i32 = y.parse().ok()?;
            if v < 50 { 2000 + v } else { 1900 + v }
        }
        3 => 1900 + y.parse::<i32>().ok()?,
        _ => return None,
    };
    let tb = t.as_bytes();
    let h = digits(tb, 0, 2)?;
    if tb.get(2) != Some(&b':') {
        return None;
    }
    let mi = digits(tb, 3, 2)?;
    let (sec, prec) = match tb.len() {
        5 => (0, Precision::Minute),
        8 if tb[5] == b':' => (digits(tb, 6, 2)?, Precision::Second),
        _ => return None,
    };
    let off = match *zone {
        "-0000" => None,
        "UT" | "GMT" | "Z" | "z" => Some(0),
        "EST" => Some(-300),
        "EDT" => Some(-240),
        "CST" => Some(-360),
        "CDT" => Some(-300),
        "MST" => Some(-420),
        "MDT" => Some(-360),
        "PST" => Some(-480),
        "PDT" => Some(-420),
        z if z.len() == 5 => {
            let zb = z.as_bytes();
            let sign = match zb[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (oh, om) = (digits(zb, 1, 2)?, digits(zb, 3, 2)?);
            if om > 59 {
                return None;
            }
            Some(sign * (oh as i32 * 60 + om as i32))
        }
        _ => return None,
    };
    build(y, mo, d, h, mi, sec, 0, off, prec)
}

/// EXIF `YYYY:MM:DD HH:MM:SS` (or the date alone, `YYYY:MM:DD`, as in GPSDateStamp) with the optional
/// `OffsetTime*` value (`+01:00`, `Z` is not EXIF but tolerated) and `SubSecTime*` digits. Blank or all-zero dates
/// (the EXIF "unknown" filler) are rejected.
pub fn exif(raw: &str, offset_time: Option<&str>, subsec: Option<&str>) -> Option<Parsed> {
    let s = raw.trim_end_matches('\0').as_bytes();
    let y = digits(s, 0, 4)? as i32;
    if s.get(4) != Some(&b':') || s.get(7) != Some(&b':') {
        return None;
    }
    let (mo, d) = (digits(s, 5, 2)?, digits(s, 8, 2)?);
    let off = match offset_time.map(str::trim).filter(|o| !o.is_empty()) {
        Some(o) => Some(offset(o.as_bytes(), false)?),
        None => None,
    };
    if s.len() == 10 {
        return build(y, mo, d, 0, 0, 0, 0, off, Precision::Day);
    }
    if s.len() != 19 || s[10] != b' ' || s[13] != b':' || s[16] != b':' {
        return None;
    }
    let (h, mi, sec) = (digits(s, 11, 2)?, digits(s, 14, 2)?, digits(s, 17, 2)?);
    let (ns, prec) = match subsec.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => fraction(v.as_bytes())?,
        None => (0, Precision::Second),
    };
    build(y, mo, d, h, mi, sec, ns, off, prec)
}

/// EXIF GPS time: GPSDateStamp `YYYY:MM:DD` plus GPSTimeStamp as the tools render it (`HH:MM:SS`, each part
/// possibly decimal, e.g. `09:30:05.5`). GPS time is UTC by definition.
pub fn gps(date: &str, time: &str) -> Option<Parsed> {
    let d = exif(date.trim(), None, None)?;
    if d.precision != Precision::Day || d.zone != ZoneInfo::Unknown {
        return None;
    }
    let parts: Vec<&str> = time.trim().split(':').collect();
    let [h, m, s] = parts.as_slice() else {
        return None;
    };
    let whole = |v: &str| -> Option<u32> {
        if v.is_empty() || v.len() > 2 || !v.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        v.parse().ok()
    };
    let (h, m) = (whole(h)?, whole(m)?);
    let (sec, ns, prec) = match s.split_once('.') {
        Some((a, f)) => {
            let (ns, p) = fraction(f.as_bytes())?;
            (whole(a)?, ns, p)
        }
        None => (whole(s)?, 0, Precision::Second),
    };
    if h > 23 || m > 59 || sec > 59 {
        return None;
    }
    let utc_s = d.utc_s + i64::from(h * 3600 + m * 60 + sec);
    Some(Parsed {
        utc_s,
        utc_ns: ns,
        zone: ZoneInfo::Explicit,
        offset_min: Some(0),
        precision: prec,
    })
}

/// PDF date (ISO 32000-1 7.9.4): `D:YYYY[MM[DD[HH[mm[SS]]]]][O[HH['mm[']]]]` with O = `Z`, `+`, `-`. Without O
/// the zone is unknown. `D:` is optional (many producers omit it). Precision follows the digits present.
pub fn pdf(raw: &str) -> Option<Parsed> {
    let r = raw.trim();
    let s = r.strip_prefix("D:").unwrap_or(r).as_bytes();
    let n = s
        .iter()
        .position(|c| !c.is_ascii_digit())
        .unwrap_or(s.len());
    if !matches!(n, 4 | 6 | 8 | 10 | 12 | 14) {
        return None;
    }
    let y = digits(s, 0, 4)? as i32;
    let get = |at: usize, def: u32| if n > at { digits(s, at, 2) } else { Some(def) };
    let (mo, d, h, mi, sec) = (get(4, 1)?, get(6, 1)?, get(8, 0)?, get(10, 0)?, get(12, 0)?);
    let prec = match n {
        4..=8 => Precision::Day,
        10 | 12 => Precision::Minute,
        _ => Precision::Second,
    };
    let rest = &s[n..];
    let off = match rest.first() {
        None => None,
        Some(b'Z') => {
            // "Z", "Z00'00'" and "Z00'00" are all written in the wild.
            let tail = &rest[1..];
            if !(tail.is_empty() || tail == b"00'00'" || tail == b"00'00" || tail == b"00") {
                return None;
            }
            Some(0)
        }
        Some(&c @ (b'+' | b'-')) => {
            let sign = if c == b'+' { 1 } else { -1 };
            let oh = digits(rest, 1, 2)?;
            let tail = &rest[3..];
            let om = match tail {
                b"" | b"'" => 0,
                _ if tail.first() == Some(&b'\'') => {
                    let m = digits(tail, 1, 2)?;
                    if !(tail.len() == 3 || (tail.len() == 4 && tail[3] == b'\'')) {
                        return None;
                    }
                    m
                }
                _ => return None,
            };
            if oh > 23 || om > 59 {
                return None;
            }
            Some(sign * (oh as i32 * 60 + om as i32))
        }
        _ => return None,
    };
    build(y, mo, d, h, mi, sec, 0, off, prec)
}

/// X.509 / ASN.1 time in its DER text form: UTCTime `YYMMDDHHMMSSZ` (YY ≥ 50 → 19YY, RFC 5280 4.1.2.5.1) or
/// GeneralizedTime `YYYYMMDDHHMMSS[.f]Z`. DER requires `Z`; offsets are rejected.
pub fn x509(raw: &str) -> Option<Parsed> {
    let s = raw.as_bytes();
    let body = s.strip_suffix(b"Z")?;
    let (y, rest) = match body.len() {
        12 => {
            let yy = digits(body, 0, 2)? as i32;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &body[2..])
        }
        n if n >= 14 => (digits(body, 0, 4)? as i32, &body[4..]),
        _ => return None,
    };
    let f = |a| digits(rest, a, 2);
    let (mo, d, h, mi, sec) = (f(0)?, f(2)?, f(4)?, f(6)?, f(8)?);
    let (ns, prec) = match &rest[10..] {
        [] => (0, Precision::Second),
        [b'.', frac @ ..] if body.len() >= 14 => fraction(frac)?,
        _ => return None,
    };
    build(y, mo, d, h, mi, sec, ns, Some(0), prec)
}

/// OpenSSL's text form of an ASN.1 time: `Nov 10 10:00:00 2026 GMT` (day padded with a space or not).
pub fn openssl_text(raw: &str) -> Option<Parsed> {
    let parts: Vec<&str> = raw.split_ascii_whitespace().collect();
    let [mon, d, t, y, "GMT"] = parts.as_slice() else {
        return None;
    };
    let mo = month(mon)?;
    if d.is_empty() || d.len() > 2 || !d.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if y.len() != 4 {
        return None;
    }
    let tb = t.as_bytes();
    if tb.len() != 8 || tb[2] != b':' || tb[5] != b':' {
        return None;
    }
    build(
        digits(y.as_bytes(), 0, 4)? as i32,
        mo,
        d.parse().ok()?,
        digits(tb, 0, 2)?,
        digits(tb, 3, 2)?,
        digits(tb, 6, 2)?,
        0,
        Some(0),
        Precision::Second,
    )
}

/// C `asctime` form as in an mbox `From ` line: `Wed Nov 11 11:00:03 2026` (day padded with a space or not). It
/// carries no zone: the result is zone-unknown.
pub fn asctime(raw: &str) -> Option<Parsed> {
    let parts: Vec<&str> = raw.split_ascii_whitespace().collect();
    let [wd, mon, d, t, y] = parts.as_slice() else {
        return None;
    };
    if !["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].contains(wd) {
        return None;
    }
    let mo = month(mon)?;
    if d.is_empty() || d.len() > 2 || !d.bytes().all(|c| c.is_ascii_digit()) || y.len() != 4 {
        return None;
    }
    let tb = t.as_bytes();
    if tb.len() != 8 || tb[2] != b':' || tb[5] != b':' {
        return None;
    }
    build(
        digits(y.as_bytes(), 0, 4)? as i32,
        mo,
        d.parse().ok()?,
        digits(tb, 0, 2)?,
        digits(tb, 3, 2)?,
        digits(tb, 6, 2)?,
        0,
        None,
        Precision::Second,
    )
}

/// `YYYY-MM-DD HH:MM:SS` stated to be UTC by its format (PNG tIME as rv-imgauth renders it).
pub fn utc_wallclock(raw: &str) -> Option<Parsed> {
    let p = iso8601(raw)?;
    if p.zone != ZoneInfo::Unknown || p.precision != Precision::Second || raw.len() != 19 {
        return None;
    }
    Some(Parsed {
        zone: ZoneInfo::Explicit,
        offset_min: Some(0),
        ..p
    })
}

/// Any of the self-describing formats, in a fixed order (RFC 3339 / ISO 8601, RFC 5322, PDF, X.509): for values
/// whose writer is not documented (chat exports, attachment headers). Returns the parser's name too.
pub fn any(raw: &str) -> Option<(Parsed, &'static str)> {
    let r = raw.trim();
    if r.is_empty() {
        return None;
    }
    if let Some(p) = iso8601(r) {
        return Some((p, "iso8601"));
    }
    if let Some(p) = rfc5322(r) {
        return Some((p, "rfc5322"));
    }
    if r.starts_with("D:")
        && let Some(p) = pdf(r)
    {
        return Some((p, "pdf"));
    }
    if let Some(p) = x509(r) {
        return Some((p, "x509"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use Precision::*;
    use ZoneInfo::*;

    fn at(s: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().timestamp()
    }

    #[test]
    fn table() {
        type P = fn(&str) -> Option<Parsed>;
        /// (parser, input, utc, ns, zone, offset, precision)
        type Row = (
            P,
            &'static str,
            &'static str,
            u32,
            ZoneInfo,
            Option<i32>,
            Precision,
        );
        let exif0: P = |s| exif(s, None, None);
        let ok: Vec<Row> = vec![
            (
                rfc3339,
                "2026-11-10T10:00:00Z",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                rfc3339,
                "2026-11-10T11:00:00+01:00",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(60),
                Second,
            ),
            (
                rfc3339,
                "2026-11-10T05:00:00.123-05:00",
                "2026-11-10T10:00:00Z",
                123_000_000,
                Explicit,
                Some(-300),
                Millisecond,
            ),
            (
                rfc3339,
                "2026-11-10 10:00:00.123456Z",
                "2026-11-10T10:00:00Z",
                123_456_000,
                Explicit,
                Some(0),
                Microsecond,
            ),
            (
                rfc3339,
                "2026-11-10t10:00:00.000000001z",
                "2026-11-10T10:00:00Z",
                1,
                Explicit,
                Some(0),
                Nanosecond,
            ),
            (
                iso8601,
                "2026-11-10T10:00",
                "2026-11-10T10:00:00Z",
                0,
                Unknown,
                None,
                Minute,
            ),
            (
                iso8601,
                "2026-11-10T10:00+02:00",
                "2026-11-10T08:00:00Z",
                0,
                Explicit,
                Some(120),
                Minute,
            ),
            (
                iso8601,
                "2026-11-10",
                "2026-11-10T00:00:00Z",
                0,
                Unknown,
                None,
                Day,
            ),
            (
                iso8601,
                "2026-11",
                "2026-11-01T00:00:00Z",
                0,
                Unknown,
                None,
                Day,
            ),
            (
                iso8601,
                "2026",
                "2026-01-01T00:00:00Z",
                0,
                Unknown,
                None,
                Day,
            ),
            (
                iso8601,
                "2026-11-10T10:00:00",
                "2026-11-10T10:00:00Z",
                0,
                Unknown,
                None,
                Second,
            ),
            (
                rfc5322,
                "Tue, 10 Nov 2026 11:00:00 +0100",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(60),
                Second,
            ),
            (
                rfc5322,
                "10 Nov 2026 05:00:00 -0500 (EST)",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(-300),
                Second,
            ),
            (
                rfc5322,
                "Tue, 10 Nov 2026 10:00 GMT",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(0),
                Minute,
            ),
            (
                rfc5322,
                "Tue, 10 Nov 2026 10:00:00 -0000",
                "2026-11-10T10:00:00Z",
                0,
                Unknown,
                None,
                Second,
            ),
            (
                rfc5322,
                "Tue, 10 Nov 26 02:00:00 PST",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(-480),
                Second,
            ),
            (
                rfc5322,
                "Wed,  1 Jan 2025 00:00:00 +0000",
                "2025-01-01T00:00:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                exif0,
                "2026:11:10 10:00:00",
                "2026-11-10T10:00:00Z",
                0,
                Unknown,
                None,
                Second,
            ),
            (
                |s| exif(s, Some("+01:00"), None),
                "2026:11:10 11:00:00",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(60),
                Second,
            ),
            (
                |s| exif(s, Some("-05:00"), Some("25")),
                "2026:11:10 05:00:00",
                "2026-11-10T10:00:00Z",
                250_000_000,
                Explicit,
                Some(-300),
                Millisecond,
            ),
            (
                exif0,
                "2026:11:10",
                "2026-11-10T00:00:00Z",
                0,
                Unknown,
                None,
                Day,
            ),
            (
                |s| gps("2026:11:10", s),
                "10:00:05.5",
                "2026-11-10T10:00:05Z",
                500_000_000,
                Explicit,
                Some(0),
                Millisecond,
            ),
            (
                |s| gps("2026:11:10", s),
                "09:30:00",
                "2026-11-10T09:30:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                pdf,
                "D:20261110110000+01'00'",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(60),
                Second,
            ),
            (
                pdf,
                "D:20261110050000-05'00",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(-300),
                Second,
            ),
            (
                pdf,
                "D:20261110100000Z",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                pdf,
                "D:20261110100000Z00'00'",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                pdf,
                "D:20261110100000",
                "2026-11-10T10:00:00Z",
                0,
                Unknown,
                None,
                Second,
            ),
            (
                pdf,
                "D:202611101000+01",
                "2026-11-10T09:00:00Z",
                0,
                Explicit,
                Some(60),
                Minute,
            ),
            (pdf, "D:2026", "2026-01-01T00:00:00Z", 0, Unknown, None, Day),
            (
                pdf,
                "20261110100000Z",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                x509,
                "261110100000Z",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                x509,
                "991231235959Z",
                "1999-12-31T23:59:59Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                x509,
                "20261110100000Z",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                x509,
                "20261110100000.25Z",
                "2026-11-10T10:00:00Z",
                250_000_000,
                Explicit,
                Some(0),
                Millisecond,
            ),
            (
                openssl_text,
                "Nov 10 10:00:00 2026 GMT",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                openssl_text,
                "Feb  1 10:00:00 2026 GMT",
                "2026-02-01T10:00:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                utc_wallclock,
                "2026-11-10 10:00:00",
                "2026-11-10T10:00:00Z",
                0,
                Explicit,
                Some(0),
                Second,
            ),
            (
                asctime,
                "Wed Nov 11 11:00:03 2026",
                "2026-11-11T11:00:03Z",
                0,
                Unknown,
                None,
                Second,
            ),
            (
                asctime,
                "Sun Nov  1 09:00:00 2026",
                "2026-11-01T09:00:00Z",
                0,
                Unknown,
                None,
                Second,
            ),
        ];
        for (f, input, utc, ns, zone, off, prec) in ok {
            let p = f(input).unwrap_or_else(|| panic!("{input} should parse"));
            assert_eq!(
                (p.utc_s, p.utc_ns, p.zone, p.offset_min, p.precision),
                (at(utc), ns, zone, off, prec),
                "{input}"
            );
        }
        let bad: Vec<(P, &str)> = vec![
            (rfc3339, "2026-11-10T10:00:00"),
            (rfc3339, "2026-11-10"),
            (rfc3339, "2026-02-30T10:00:00Z"),
            (rfc3339, "2026-11-10T24:00:00Z"),
            (rfc3339, "2026-11-10T23:59:60Z"),
            (rfc3339, "2026-11-10T10:00:00+25:00"),
            (rfc3339, "2026-11-10T10:00:00+01"),
            (rfc3339, "2026-11-10T10:00:00.Z"),
            (rfc3339, "2026-11-10T10:00:00.1234567890Z"),
            (rfc3339, " 2026-11-10T10:00:00Z"),
            (iso8601, "2026-1-10"),
            (iso8601, "26-11-10"),
            (rfc5322, "Tue, 10 Nov 2026 11:00:00"),
            (rfc5322, "Tux, 10 Nov 2026 11:00:00 +0100"),
            (rfc5322, "Tue, 31 Nov 2026 11:00:00 +0100"),
            (rfc5322, "Tue, 10 Nox 2026 11:00:00 +0100"),
            (rfc5322, "Tue, 10 Nov 2026 11:00:00 +01:00"),
            (rfc5322, "Tue, 10 Nov 2026 11:00:00 CET"),
            (exif0, "0000:00:00 00:00:00"),
            (exif0, "    :  :     :  :  "),
            (exif0, "2026-11-10 10:00:00"),
            (exif0, "2026:11:10 10:00"),
            (|s| exif(s, Some("bogus"), None), "2026:11:10 10:00:00"),
            (|s| exif(s, None, Some("x1")), "2026:11:10 10:00:00"),
            (|s| gps("2026:11:10", s), "25:00:00"),
            (|s| gps("2026:11:10", s), "10:00"),
            (pdf, "D:2026111"),
            (pdf, "D:20261310"),
            (pdf, "D:20261110100000+01'00'x"),
            (pdf, "D:20261110100000Y"),
            (pdf, "garbage"),
            (x509, "261110100000"),
            (x509, "261110100000+0100"),
            (x509, "2611101000Z"),
            (x509, "261110100000.5Z"),
            (openssl_text, "Nov 10 10:00:00 2026 CET"),
            (utc_wallclock, "2026-11-10T10:00:00Z"),
            (asctime, "Wed Nov 11 11:00:03"),
            (asctime, "Xyz Nov 11 11:00:03 2026"),
        ];
        for (f, input) in bad {
            assert_eq!(f(input), None, "{input} must not parse");
        }
    }

    #[test]
    fn any_picks_the_right_parser() {
        assert_eq!(any("2026-11-10T10:00:00Z").unwrap().1, "iso8601");
        assert_eq!(any("Tue, 10 Nov 2026 11:00:00 +0100").unwrap().1, "rfc5322");
        assert_eq!(any("D:20261110100000Z").unwrap().1, "pdf");
        assert_eq!(any("20261110100000Z").unwrap().1, "x509");
        assert!(any("10/11/26, 9:00 a. m.").is_none());
        assert!(any("").is_none());
    }

    /// Deterministic mutation fuzzing: thousands of byte-level mutations of valid inputs never panic, and whatever
    /// parses keeps its invariants (nanoseconds < 1e9, offset only with an explicit zone, within ±18 h).
    #[test]
    fn fuzz_parsers_never_panic() {
        let seeds = [
            "2026-11-10T10:00:00.123+01:00",
            "Tue, 10 Nov 2026 11:00:00 +0100 (CET)",
            "2026:11:10 10:00:00",
            "D:20261110110000+01'00'",
            "20261110100000.25Z",
            "261110100000Z",
            "Nov 10 10:00:00 2026 GMT",
            "10:00:05.5",
            "Wed Nov 11 11:00:03 2026",
        ];
        let alphabet = b"0123456789:-+.,'TZDz ()GMTNovTue\0\xff9";
        let mut state: u64 = 0x5EED_1234_ABCD_0001;
        let mut next = || {
            // xorshift64*
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut parsed = 0u32;
        for i in 0..6000u32 {
            let mut b = seeds[i as usize % seeds.len()].as_bytes().to_vec();
            for _ in 0..(1 + next() % 4) {
                let r = next();
                let pos = (r >> 8) as usize % (b.len() + 1);
                let c = alphabet[(r >> 32) as usize % alphabet.len()];
                match r % 4 {
                    0 if pos < b.len() => b[pos] = c,
                    1 => b.insert(pos, c),
                    2 if pos < b.len() => {
                        b.remove(pos);
                    }
                    _ => b.truncate(pos),
                }
            }
            let s = String::from_utf8_lossy(&b).into_owned();
            let results = [
                rfc3339(&s),
                iso8601(&s),
                rfc5322(&s),
                exif(&s, Some(&s), Some(&s)),
                exif(&s, None, None),
                gps("2026:11:10", &s),
                gps(&s, "10:00:00"),
                pdf(&s),
                x509(&s),
                openssl_text(&s),
                utc_wallclock(&s),
                asctime(&s),
                any(&s).map(|p| p.0),
            ];
            for p in results.into_iter().flatten() {
                parsed += 1;
                assert!(p.utc_ns < 1_000_000_000, "{s}");
                match p.zone {
                    Explicit => assert!(
                        p.offset_min.is_some_and(|o| o.abs() <= MAX_OFFSET_MIN),
                        "{s}"
                    ),
                    Unknown => assert_eq!(p.offset_min, None, "{s}"),
                }
            }
        }
        assert!(parsed > 0, "the mutations should leave some valid inputs");
    }
}
