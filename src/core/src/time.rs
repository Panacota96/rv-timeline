//! UTC timestamps and durations in one place, so every output uses the same format.

use jiff::Timestamp;
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

/// True for the RFC 3339 `date-time` shape: `YYYY-MM-DD`, `T`/`t`/space, `hh:mm:ss`, optional fraction,
/// `Z`/`z` or `±hh:mm`. Stricter than jiff's ISO 8601 parser (which also takes basic formats, `+hhmm` and a
/// missing seconds field): only what RFC 3339 allows is accepted, exactly as before.
fn rfc3339_shape(s: &str) -> bool {
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|x| x.iter().all(u8::is_ascii_digit));
    if b.len() < 20
        || !digits(0..4)
        || b[4] != b'-'
        || !digits(5..7)
        || b[7] != b'-'
        || !digits(8..10)
        || !matches!(b[10], b'T' | b't' | b' ')
        || !digits(11..13)
        || b[13] != b':'
        || !digits(14..16)
        || b[16] != b':'
        || !digits(17..19)
    {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        let n = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return false;
        }
        i += 1 + n;
    }
    match &b[i..] {
        [b'Z' | b'z'] => true,
        [b'+' | b'-', h1, h2, b':', m1, m2] => [h1, h2, m1, m2].iter().all(|c| c.is_ascii_digit()),
        _ => false,
    }
}

/// Seconds since the Unix epoch of an RFC 3339 date-time (e.g. an RFC 3161 genTime as written in the audit log).
/// A leap second (`:60`) counts as `:59`.
pub fn rfc3339_unix(s: &str) -> Result<i64, String> {
    if !rfc3339_shape(s) {
        return Err(format!("not an RFC 3339 date-time: {s:?}"));
    }
    let mut norm = s.to_string();
    if &s[17..19] == "60" {
        norm.replace_range(17..19, "59");
    }
    norm.parse::<Timestamp>()
        // floored, like the formatting (-0.5 s is second -1)
        .map(|t| t.as_second() - i64::from(t.subsec_nanosecond() < 0))
        .map_err(|e| e.to_string())
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

    const PARSE_INPUTS: [&str; 16] = [
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
        let want: [Option<i64>; 16] = [
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
