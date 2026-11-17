//! Golden vectors for every date/time code path of the timeline (formatting in UTC and in the display zone,
//! Timesketch `datetime`, RFC 3339 and run-id parsing, the readers' strict parsers). Frozen from the chrono 0.4
//! implementation before the move to jiff: every output must stay byte-identical, every parse must accept and
//! reject exactly the same inputs.
//!
//! Regenerate (only when a change of behaviour is intended):
//! `cargo test -p rv-timeline-core --test golden_time -- --ignored --nocapture print_golden`

use rv_timeline_core::engine::{
    DisplayZone, display_time, fmt_utc, paris_summer_time, parse_rfc3339, run_id_start,
    timesketch_datetime, utc_time, wall_clock,
};
use rv_timeline_core::model::{Precision, TimeEvent, ZoneInfo};
use rv_timeline_core::readers::timefmt;

const PRECISIONS: [Precision; 6] = [
    Precision::Day,
    Precision::Minute,
    Precision::Second,
    Precision::Millisecond,
    Precision::Microsecond,
    Precision::Nanosecond,
];

/// First and last second the former `DateTime<Utc>` could hold (-262143-01-01T00:00:00 / 262142-12-31T23:59:59).
const RANGE_MIN: i64 = -8_334_601_228_800;
const RANGE_MAX: i64 = 8_210_266_876_799;

/// (seconds, nanoseconds) instants: epoch, fractions, pre-1970, year 0 / -1, 9999 / +10000, range edges, extremes.
fn instants() -> Vec<(i64, u32)> {
    vec![
        (0, 0),
        (1_794_736_800, 0),
        (1_794_736_800, 999),
        (1_794_736_800, 1_000),
        (1_794_736_800, 123_000_000),
        (1_794_736_800, 123_456_000),
        (1_794_736_800, 123_456_789),
        (1_794_736_800, 999_999_999),
        (1_794_736_859, 1_500_000_000),
        (1_794_736_859, 1_000_000_000),
        (1_794_736_859, 1_000_000_999),
        (1_794_736_800, 1_000_000_000),
        (1_794_736_859, 2_000_000_000),
        (1_794_736_800, u32::MAX),
        (-1, 0),
        (-1, 500_000_000),
        (-86_400, 0),
        (-11_644_473_600, 0),
        (-62_135_596_800, 0),
        (-62_167_219_200, 0),
        (-62_167_219_201, 0),
        (951_782_400, 0),
        (2_147_483_648, 1_000_000),
        (253_402_214_400, 0),
        (253_402_300_799, 999_999_999),
        (253_402_300_800, 0),
        (910_692_730_085, 477_580_700),
        (RANGE_MIN, 0),
        (RANGE_MIN - 1, 0),
        (RANGE_MAX, 999_000_000),
        (RANGE_MAX + 1, 0),
        (i64::MIN, 0),
        (i64::MAX, 0),
    ]
}

/// Paris DST edges (2026 gap and overlap, March/October 31 on a Sunday, before 1996, far past/future).
fn zone_instants() -> Vec<i64> {
    vec![
        1_774_745_999, // 2026-03-29T00:59:59Z: last CET second
        1_774_746_000, // 2026-03-29T01:00:00Z: first CEST second (wall 02:00 skipped)
        1_792_889_999, // 2026-10-25T00:59:59Z: last CEST second (wall 02:59:59 first time)
        1_792_890_000, // 2026-10-25T01:00:00Z: first CET second (wall 02:00 again)
        1_792_891_800, // 2026-10-25T01:30:00Z: overlap, second time
        1_711_846_799, // 2024-03-31T00:59:59Z: March 31 is a Sunday
        1_711_846_800,
        1_635_642_000, // 2021-10-31T01:00:00Z: October 31 is a Sunday
        1_635_641_999,
        644_000_000, // 1990-05-29: summer before the 1996 rules
        951_782_400, // 2000-02-29
        0,
        -1,
        -62_167_219_200, // 0000-01-01
        -62_150_000_000, // year 0, summer
        253_402_214_400, // 9999-12-31
        253_388_000_000, // 9999, summer
        253_402_300_800, // +10000-01-01
        RANGE_MIN,
        RANGE_MIN - 1,
        RANGE_MAX,
        RANGE_MAX + 1,
        i64::MIN,
        i64::MAX,
    ]
}

const ZONE_NAMES: [&str; 20] = [
    "UTC",
    "z",
    "GMT",
    "Etc/UTC",
    "Europe/Paris",
    "europe/PARIS",
    " America/Bogota ",
    "+01:00",
    "-05:00",
    "UTC+02:00",
    "gmt-0530",
    "+0545",
    "+14:00",
    "+14:01",
    "-12",
    "+00:00",
    "Europe/Berlin",
    "Mars/Olympus",
    "",
    "+1:2:3",
];

const RFC3339: [&str; 62] = [
    "2026-11-10T10:00:00Z",
    "2026-11-10t10:00:00z",
    "2026-11-10 10:00:00Z",
    "2026-11-10X10:00:00Z",
    "  2026-11-10T10:00:00Z\n",
    "\u{3000}2026-11-10T10:00:00Z",
    "2026-11-10T10:00:00.5Z",
    "2026-11-10T10:00:00.123456789Z",
    "2026-11-10T10:00:00.1234567891234Z",
    "2026-11-10T10:00:00.Z",
    "2026-11-10T10:00:00,5Z",
    "2026-11-10T10:00:00.5+01:00",
    "2026-11-10T10:00:00+01:00",
    "2026-11-10T10:00:00-05:30",
    "2026-11-10T10:00:00\u{2212}05:00",
    "2026-11-10T10:00:00+23:59",
    "2026-11-10T10:00:00-23:59",
    "2026-11-10T10:00:00+24:00",
    "2026-11-10T10:00:00+25:00",
    "2026-11-10T10:00:00+99:00",
    "2026-11-10T10:00:00+01:60",
    "2026-11-10T10:00:00+0100",
    "2026-11-10T10:00:00+01",
    "2026-11-10T10:00:00+01:00:00",
    "2026-11-10T10:00:00Z ",
    "2026-11-10T10:00:00ZZ",
    "2026-11-10T10:00:00",
    "2026-11-10T10:00Z",
    "2026-11-10",
    "2016-12-31T23:59:60Z",
    "2026-11-10T10:00:60Z",
    "2026-11-10T10:00:60.5Z",
    "2026-11-10T10:00:61Z",
    "2026-11-10T24:00:00Z",
    "2026-11-10T23:60:00Z",
    "2026-02-29T10:00:00Z",
    "2024-02-29T10:00:00Z",
    "1900-02-29T10:00:00Z",
    "2000-02-29T10:00:00Z",
    "2026-04-31T10:00:00Z",
    "2026-00-10T10:00:00Z",
    "2026-13-10T10:00:00Z",
    "2026-11-00T10:00:00Z",
    "0000-01-01T00:00:00Z",
    "0000-01-01T00:00:00+01:00",
    "9999-12-31T23:59:59Z",
    "9999-12-31T23:59:59-23:59",
    "9999-12-30T22:00:00Z",
    "1969-12-31T23:59:59.999Z",
    "1969-12-31T23:59:59.5Z",
    "1601-01-01T00:00:00Z",
    "+2026-11-10T10:00:00Z",
    "2026-1-10T10:00:00Z",
    "20261110T100000Z",
    "\u{ff12}026-11-10T10:00:00Z",
    "2026-11-10T10:00:00.\u{e9}Z",
    "2026-11-10T10:00:00+01:0\u{e9}",
    "",
    "2026",
    "2026-11-10T10:00:00Z\u{0}",
    "2026-11-10T10:00:00+00:00",
    "2026-11-10T10:00:00-00:00",
];

const RUN_IDS: [&str; 33] = [
    "20261110T100000Z-ab12cd",
    "20261110T100000Z",
    "20261110T100000z-ab12cd",
    "20261110t100000Z-ab12cd",
    "20261110T100000",
    "20261110T240000Z-x",
    "20261110T236000Z-x",
    "20261110T235960Z-x",
    "20261110T100060Z-x",
    "20261110T100061Z-x",
    "20260230T100000Z-x",
    "20240229T100000Z-x",
    "20261310T100000Z-x",
    "20261100T100000Z-x",
    "00000101T000000Z-x",
    "99991231T235959Z-x",
    "19691231T235959Z-x",
    " 2026111T100000Z",
    "999 1110T100000Z",
    "-001 0101T10000Z",
    "+2026 1110T1000Z",
    "+20261110T100000Z",
    "2026 1 1T1 0 00Z",
    "20261110T10 0 0Z",
    "2026111\u{e9}T10000Z",
    "２０２６1110T100000Z",
    "+999999 11T1000Z",
    "+262142 1231T10Z",
    "+262143 0101T10Z",
    "+2026 1 1T1 0 0Z",
    "+1234 1 1T1 0 0Z",
    "-1234 1 1T1 0 0Z",
    "",
];

const ISO8601: [&str; 30] = [
    "2026",
    "2026-11",
    "2026-11-10",
    "2026-11-10T10:00",
    "2026-11-10T10:00:00",
    "2026-11-10T10:00:00.5",
    "2026-11-10T10:00:00,123456",
    "2026-11-10T10:00:00.123456789+01:00",
    "2026-11-10T10:00:00Z",
    "2026-11-10T10:00+02:00",
    "0000",
    "0000-01-01T00:00:00+18:00",
    "0000-01-01T00:00:00-18:00",
    "9999-12-31T23:59:59-18:00",
    "9999-12-31T23:59:59+18:00",
    "9999-12-31T23:59:59.999999999Z",
    "2026-11-10T10:00:00+18:01",
    "2026-11-10T10:00:00-18:00",
    "2026-02-29",
    "2024-02-29",
    "1900-02-29",
    "2000-02-29",
    "2026-04-31",
    "2026-00",
    "2026-13",
    "2026-11-00",
    "2026-11-10T24:00",
    "2026-11-10T23:60",
    "2026-11-10T23:59:60Z",
    "1969-12-31T23:59:59.999Z",
];

const RFC5322: [&str; 16] = [
    "Tue, 10 Nov 2026 11:00:00 +0100",
    "10 Nov 2026 11:00 +0100",
    "Tue, 10 Nov 2026 11:00:00 -0000",
    "Tue, 10 Nov 2026 11:00:00 GMT (UTC)",
    "Tue, 10 Nov 26 11:00:00 EST",
    "Tue, 10 Nov 49 11:00:00 PDT",
    "Tue, 10 Nov 50 11:00:00 +0000",
    "Tue, 10 Nov 126 11:00:00 +0000",
    "29 Feb 2026 11:00:00 +0000",
    "29 Feb 2024 11:00:00 +0000",
    "31 Apr 2026 11:00:00 +0000",
    "10 Nov 2026 24:00:00 +0000",
    "10 Nov 2026 11:00:60 +0000",
    "1 Jan 0000 00:00:00 +2359",
    "31 Dec 9999 23:59:59 -2359",
    "10 Nov 2026 11:00:00 +0160",
];

const EXIF: [(&str, Option<&str>, Option<&str>); 14] = [
    ("2026:11:10 10:00:00", None, None),
    ("2026:11:10 10:00:00", Some("+01:00"), Some("123")),
    ("2026:11:10 10:00:00", Some("Z"), Some("1234567")),
    ("2026:11:10 10:00:00\0", Some(" "), Some("")),
    ("2026:11:10", None, None),
    ("0000:00:00 00:00:00", None, None),
    ("    :  :     :  :  ", None, None),
    ("2026:02:29 10:00:00", None, None),
    ("2024:02:29 10:00:00", Some("-05:00"), None),
    ("2026:11:10 24:00:00", None, None),
    ("2026:11:10 10:00:60", None, None),
    ("2026:11:10 10:00:00", Some("+19:00"), None),
    ("9999:12:31 23:59:59", Some("-18:00"), Some("999999999")),
    ("1969:12:31 23:59:59", None, Some("5")),
];

const GPS: [(&str, &str); 6] = [
    ("2026:11:10", "09:30:05"),
    ("2026:11:10", "09:30:05.5"),
    ("2026:02:29", "09:30:05"),
    ("2026:11:10", "24:00:00"),
    ("0000:01:01", "00:00:00"),
    ("9999:12:31", "23:59:59.999"),
];

const PDF: [&str; 16] = [
    "D:20261110100000+01'00'",
    "D:20261110100000Z",
    "D:20261110100000Z00'00'",
    "D:20261110100000",
    "D:2026",
    "D:202611",
    "D:2026111010",
    "D:202611101000-05'30",
    "20261110100000+01'",
    "D:20260229100000Z",
    "D:20261110240000Z",
    "D:20261110106000Z",
    "D:00000101000000+23'59'",
    "D:99991231235959-23'59'",
    "D:20261100",
    "D:20261310",
];

const X509: [&str; 10] = [
    "261110100000Z",
    "491231235959Z",
    "500101000000Z",
    "20261110100000Z",
    "20261110100000.5Z",
    "261110100000.5Z",
    "20260229100000Z",
    "20261110240000Z",
    "99991231235959Z",
    "00000101000000Z",
];

const OTHERS: [&str; 10] = [
    "Nov 10 10:00:00 2026 GMT",
    "Nov  1 10:00:00 2026 GMT",
    "Feb 29 10:00:00 2026 GMT",
    "Wed Nov 11 11:00:03 2026",
    "Sun Feb 29 11:00:03 2026",
    "2026-11-10 10:00:00",
    "2026-11-10 24:00:00",
    "2026-11-10T10:00:00",
    "0000-01-01 00:00:00",
    "9999-12-31 23:59:59",
];

fn event(s: i64, ns: u32, zone: ZoneInfo, precision: Precision) -> TimeEvent {
    TimeEvent {
        utc_s: s,
        utc_ns: ns,
        zone,
        precision,
        ..Default::default()
    }
}

fn zones() -> Vec<DisplayZone> {
    vec![
        DisplayZone::Utc,
        DisplayZone::Paris,
        DisplayZone::Bogota,
        DisplayZone::Fixed(-300),
        DisplayZone::Fixed(345),
        DisplayZone::Fixed(-720),
        DisplayZone::Fixed(840),
    ]
}

/// Every golden line: `<function>(<input>) => <output>`.
fn lines() -> Vec<String> {
    let mut out = Vec::new();
    for (s, ns) in instants() {
        for p in PRECISIONS {
            out.push(format!(
                "wall_clock({s}, {ns}, {p:?}) => {:?}",
                wall_clock(s, ns, p)
            ));
            out.push(format!(
                "fmt_utc({s}, {ns}, {p:?}) => {:?}",
                fmt_utc(s, ns, p)
            ));
            for zone in [ZoneInfo::Explicit, ZoneInfo::Unknown] {
                let e = event(s, ns, zone, p);
                out.push(format!(
                    "utc_time({s}, {ns}, {zone:?}, {p:?}) => {:?}",
                    utc_time(&e)
                ));
                out.push(format!(
                    "display_time({s}, {ns}, {zone:?}, {p:?}, Paris) => {:?}",
                    display_time(&e, &DisplayZone::Paris)
                ));
            }
        }
        let e = event(s, ns, ZoneInfo::Explicit, Precision::Nanosecond);
        out.push(format!(
            "timesketch_datetime({s}, {ns}) => {:?}",
            timesketch_datetime(&e)
        ));
    }
    for s in zone_instants() {
        out.push(format!(
            "paris_summer_time({s}) => {}",
            paris_summer_time(s)
        ));
        for z in zones() {
            out.push(format!(
                "{z:?}.offset_at({s}) => {} / {:?}",
                z.offset_at(s),
                z.abbrev_at(s)
            ));
            for p in [Precision::Day, Precision::Minute, Precision::Millisecond] {
                out.push(format!(
                    "{z:?}.format({s}, 250000000, {p:?}) => {:?}",
                    z.format(s, 250_000_000, p)
                ));
            }
        }
    }
    for n in ZONE_NAMES {
        let r = DisplayZone::parse(n).map(|z| (z, z.name()));
        out.push(format!("DisplayZone::parse({n:?}) => {r:?}"));
    }
    for s in RFC3339 {
        out.push(format!("parse_rfc3339({s:?}) => {:?}", parse_rfc3339(s)));
    }
    for s in RUN_IDS {
        out.push(format!("run_id_start({s:?}) => {:?}", run_id_start(s)));
    }
    for s in ISO8601 {
        out.push(format!("iso8601({s:?}) => {:?}", timefmt::iso8601(s)));
        out.push(format!("rfc3339({s:?}) => {:?}", timefmt::rfc3339(s)));
        out.push(format!("any({s:?}) => {:?}", timefmt::any(s)));
    }
    for s in RFC3339 {
        out.push(format!(
            "timefmt::rfc3339({s:?}) => {:?}",
            timefmt::rfc3339(s)
        ));
    }
    for s in RFC5322 {
        out.push(format!("rfc5322({s:?}) => {:?}", timefmt::rfc5322(s)));
        out.push(format!("any({s:?}) => {:?}", timefmt::any(s)));
    }
    for (s, o, f) in EXIF {
        out.push(format!(
            "exif({s:?}, {o:?}, {f:?}) => {:?}",
            timefmt::exif(s, o, f)
        ));
    }
    for (d, t) in GPS {
        out.push(format!("gps({d:?}, {t:?}) => {:?}", timefmt::gps(d, t)));
    }
    for s in PDF {
        out.push(format!("pdf({s:?}) => {:?}", timefmt::pdf(s)));
        out.push(format!("any({s:?}) => {:?}", timefmt::any(s)));
    }
    for s in X509 {
        out.push(format!("x509({s:?}) => {:?}", timefmt::x509(s)));
    }
    for s in OTHERS {
        out.push(format!(
            "openssl_text({s:?}) => {:?}",
            timefmt::openssl_text(s)
        ));
        out.push(format!("asctime({s:?}) => {:?}", timefmt::asctime(s)));
        out.push(format!(
            "utc_wallclock({s:?}) => {:?}",
            timefmt::utc_wallclock(s)
        ));
    }
    out
}

/// Prints the golden table (run with `--ignored --nocapture` to regenerate `GOLDEN`).
#[test]
#[ignore]
fn print_golden() {
    for l in lines() {
        println!("    {l:?},");
    }
}

#[test]
fn golden_dates() {
    let got = lines();
    assert_eq!(got.len(), GOLDEN.len(), "number of golden vectors");
    for (g, w) in got.iter().zip(GOLDEN) {
        assert_eq!(g, w);
    }
}

include!("golden_time/vectors.rs");
