//! UTC timestamps and durations in one place, so every output uses the same format.

use std::time::{SystemTime, UNIX_EPOCH};

/// Whole seconds since the Unix epoch (floored, like a calendar) and the nanoseconds past them.
fn unix_parts(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            match d.subsec_nanos() {
                0 => (-(d.as_secs() as i64), 0),
                n => (-(d.as_secs() as i64) - 1, 1_000_000_000 - n),
            }
        }
    }
}

/// Proleptic Gregorian (year, month, day) of a day count since 1970-01-01 (H. Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// The year as RFC 3339 / ISO 8601 writes it: 4 digits, with a sign outside 0000–9999 (`+30828`, `-0001`).
fn year(y: i64) -> String {
    if (0..=9999).contains(&y) {
        format!("{y:04}")
    } else if y > 9999 {
        format!("+{y}")
    } else {
        format!("-{:04}", -y)
    }
}

/// (year text, month, day, hour, minute, second, nanosecond) of `t` in UTC. Exact for every `SystemTime`.
fn fields(t: SystemTime) -> (String, u32, u32, u32, u32, u32, u32) {
    let (secs, nanos) = unix_parts(t);
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400) as u32);
    let (y, m, d) = civil(days);
    (year(y), m, d, sod / 3600, sod % 3600 / 60, sod % 60, nanos)
}

/// "2026-10-19T20:15:03.123Z"
pub fn utc_now() -> String {
    utc_millis(SystemTime::now())
}

/// RFC 3339 UTC with milliseconds (truncated): "2026-10-19T20:15:03.123Z".
pub fn utc_millis(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s, n) = fields(t);
    format!(
        "{y}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{:03}Z",
        n / 1_000_000
    )
}

/// RFC 3339 UTC to the second (truncated): "2026-10-19T20:15:03Z".
pub fn utc_from(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s, _) = fields(t);
    format!("{y}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Compact UTC stamp for run identifiers: "20261019T201503Z".
pub fn utc_compact() -> String {
    compact_of(SystemTime::now())
}

pub fn compact_of(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s, _) = fields(t);
    format!("{y}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// PDF date string (ISO 32000 §7.9.4) in UTC: "D:20261019201503Z".
pub fn pdf_date(t: SystemTime) -> String {
    format!("D:{}", compact_of(t).replace('T', ""))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    let leap = y.rem_euclid(4) == 0 && (y.rem_euclid(100) != 0 || y.rem_euclid(400) == 0);
    match m {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Seconds since the Unix epoch of an RFC 3339 date-time (e.g. an RFC 3161 genTime as written in the audit log),
/// with exactly the grammar of chrono's `parse_from_rfc3339`, which this replaces: `YYYY-MM-DD`, `T`/`t`/space,
/// `hh:mm:ss`, an optional fraction (ignored: the result is floored seconds), `Z`/`z` or `±hh:mm` (`-` or U+2212,
/// hours ≤ 23). A leap second (`:60`) counts as `:59`.
pub fn rfc3339_unix(s: &str) -> Result<i64, String> {
    let bad = || format!("not an RFC 3339 date-time: {s:?}");
    let b = s.as_bytes();
    let num = |at: usize, n: usize| -> Option<i64> {
        let d = b.get(at..at + n)?;
        d.iter()
            .all(u8::is_ascii_digit)
            .then(|| d.iter().fold(0, |a, c| a * 10 + i64::from(c - b'0')))
    };
    let field = |at, n| num(at, n).ok_or_else(bad);
    let (y, mo, d) = (field(0, 4)?, field(5, 2)?, field(8, 2)?);
    let (h, mi, sec) = (field(11, 2)?, field(14, 2)?, field(17, 2)?);
    if b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(bad());
    }
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || sec > 60
    {
        return Err(bad());
    }
    let mut rest = &s[19..];
    if let Some(f) = rest.strip_prefix('.') {
        let n = f.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return Err(bad());
        }
        rest = &f[n..];
    }
    let offset = if let Some(r) = rest.strip_prefix(['Z', 'z']) {
        rest = r;
        0
    } else {
        let (sign, r) = match rest.strip_prefix('+') {
            Some(r) => (1, r),
            None => (-1, rest.strip_prefix(['-', '\u{2212}']).ok_or_else(bad)?),
        };
        let o = r.as_bytes();
        if o.len() != 5
            || !o[..2].iter().all(u8::is_ascii_digit)
            || o[2] != b':'
            || !(b'0'..=b'5').contains(&o[3])
            || !o[4].is_ascii_digit()
        {
            return Err(bad());
        }
        let oh = i64::from(o[0] - b'0') * 10 + i64::from(o[1] - b'0');
        let om = i64::from(o[3] - b'0') * 10 + i64::from(o[4] - b'0');
        if oh > 23 {
            return Err(bad());
        }
        rest = "";
        sign * (oh * 3600 + om * 60)
    };
    if !rest.is_empty() {
        return Err(bad());
    }
    Ok(
        days_from_civil(y, mo as u32, d as u32) * 86_400 + h * 3600 + mi * 60 + sec.min(59)
            - offset,
    )
}

/// "1 h 02 min 03 s", "4 min 05 s", "12.3 s"
pub fn human_duration(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..=59 => format!("{:.1} s", ms as f64 / 1000.0),
        60..=3599 => format!("{} min {:02} s", s / 60, s % 60),
        _ => format!("{} h {:02} min {:02} s", s / 3600, (s % 3600) / 60, s % 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn durations() {
        assert_eq!(human_duration(12_300), "12.3 s");
        assert_eq!(human_duration(245_000), "4 min 05 s");
        assert_eq!(human_duration(3_723_000), "1 h 02 min 03 s");
        assert!(utc_now().ends_with('Z'));
        assert_eq!(utc_compact().len(), 16);
    }

    fn instants() -> Vec<SystemTime> {
        vec![
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::new(1_763_200_000, 123_456_789),
            UNIX_EPOCH + Duration::new(1_763_200_000, 999_999_999),
            UNIX_EPOCH - Duration::from_millis(1500),
            UNIX_EPOCH + Duration::new(2_147_483_648, 1_000_000),
            UNIX_EPOCH + Duration::new(253_402_300_799, 999_000_000),
            UNIX_EPOCH + Duration::new(910_692_730_085, 477_580_700),
            UNIX_EPOCH + Duration::new(253_402_300_800, 0),
            UNIX_EPOCH - Duration::new(11_644_473_600, 0),
            UNIX_EPOCH - Duration::new(1_000_000_000, 250_000_000),
        ]
    }

    const PARSE_INPUTS: [&str; 28] = [
        "2026-11-15T10:00:00Z",
        "2026-11-15T10:00:00.123456789Z",
        "2026-11-15T10:00:00+01:00",
        "2026-11-15T10:00:00-05:30",
        "2026-11-15t10:00:00z",
        "2026-11-15 10:00:00Z",
        "2026-11-15T10:00:00",
        "2026-11-15T10:00Z",
        "2016-12-31T23:59:60Z",
        "2026-02-30T10:00:00Z",
        "2026-11-15T24:00:00Z",
        "2026-11-15T10:00:00+0100",
        "20261115T100000Z",
        " 2026-11-15T10:00:00Z",
        "1969-12-31T23:59:59.5Z",
        "",
        "2026-11-15T10:00:00\u{2212}05:00",
        "2026-11-15T10:00:00+24:00",
        "2026-11-15T10:00:00+25:59",
        "2026-11-15T10:00:00+23:59",
        "9999-12-31T23:59:59-23:59",
        "2026-11-15T10:00:00+01:60",
        "2026-11-15T10:00:60Z",
        "2026-11-15T10:00:00.1234567890123Z",
        "0000-01-01T00:00:00Z",
        "2026-11-15T10:00:00+00:00",
        "2026-11-15T10:00:00-00:00",
        "2026-11-15T10:00:00Z ",
    ];

    /// Frozen from chrono 0.4 (before the move to jiff): every format must stay byte-identical, every parse
    /// must accept and reject exactly the same inputs.
    #[test]
    fn golden_formats() {
        let want = [
            (
                "1970-01-01T00:00:00.000Z",
                "1970-01-01T00:00:00Z",
                "19700101T000000Z",
                "D:19700101000000Z",
            ),
            (
                "2025-11-15T09:46:40.123Z",
                "2025-11-15T09:46:40Z",
                "20251115T094640Z",
                "D:20251115094640Z",
            ),
            (
                "2025-11-15T09:46:40.999Z",
                "2025-11-15T09:46:40Z",
                "20251115T094640Z",
                "D:20251115094640Z",
            ),
            (
                "1969-12-31T23:59:58.500Z",
                "1969-12-31T23:59:58Z",
                "19691231T235958Z",
                "D:19691231235958Z",
            ),
            (
                "2038-01-19T03:14:08.001Z",
                "2038-01-19T03:14:08Z",
                "20380119T031408Z",
                "D:20380119031408Z",
            ),
            (
                "9999-12-31T23:59:59.999Z",
                "9999-12-31T23:59:59Z",
                "99991231T235959Z",
                "D:99991231235959Z",
            ),
            (
                "+30828-09-14T02:48:05.477Z",
                "+30828-09-14T02:48:05Z",
                "+308280914T024805Z",
                "D:+308280914024805Z",
            ),
            (
                "+10000-01-01T00:00:00.000Z",
                "+10000-01-01T00:00:00Z",
                "+100000101T000000Z",
                "D:+100000101000000Z",
            ),
            (
                "1601-01-01T00:00:00.000Z",
                "1601-01-01T00:00:00Z",
                "16010101T000000Z",
                "D:16010101000000Z",
            ),
            (
                "1938-04-24T22:13:19.750Z",
                "1938-04-24T22:13:19Z",
                "19380424T221319Z",
                "D:19380424221319Z",
            ),
        ];
        for (t, w) in instants().into_iter().zip(want) {
            assert_eq!(
                (
                    utc_millis(t).as_str(),
                    utc_from(t).as_str(),
                    compact_of(t).as_str(),
                    pdf_date(t).as_str()
                ),
                w
            );
        }
    }

    #[test]
    fn golden_parse() {
        let want: [Option<i64>; 28] = [
            Some(1794736800),
            Some(1794736800),
            Some(1794733200),
            Some(1794756600),
            Some(1794736800),
            Some(1794736800),
            None,
            None,
            Some(1483228799),
            None,
            None,
            None,
            None,
            None,
            Some(-1),
            None,
            Some(1794754800),
            None,
            None,
            Some(1794650460),
            Some(253402387139),
            None,
            Some(1794736859),
            Some(1794736800),
            Some(-62167219200),
            Some(1794736800),
            Some(1794736800),
            None,
        ];
        for (s, w) in PARSE_INPUTS.into_iter().zip(want) {
            assert_eq!(rfc3339_unix(s).ok(), w, "{s:?}");
        }
    }

    /// Prints the golden values (run with `--ignored --nocapture` to regenerate them).
    #[test]
    #[ignore]
    fn print_golden() {
        for t in instants() {
            println!(
                "{:?} | {} | {} | {} | {}",
                t,
                utc_millis(t),
                utc_from(t),
                compact_of(t),
                pdf_date(t)
            );
        }
        for s in PARSE_INPUTS {
            println!("{:?} => {:?}", s, rfc3339_unix(s).ok());
        }
    }
}
