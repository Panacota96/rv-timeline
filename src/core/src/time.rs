//! UTC timestamps and durations in one place, so every output uses the same format.

use chrono::{DateTime, SecondsFormat, Utc};
use std::time::SystemTime;

/// "2026-10-19T20:15:03.123Z"
pub fn utc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn utc_from(t: SystemTime) -> String {
    DateTime::<Utc>::from(t).to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Compact UTC stamp for run identifiers: "20261019T201503Z".
pub fn utc_compact() -> String {
    Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
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
    #[test]
    fn durations() {
        assert_eq!(human_duration(12_300), "12.3 s");
        assert_eq!(human_duration(245_000), "4 min 05 s");
        assert_eq!(human_duration(3_723_000), "1 h 02 min 03 s");
        assert!(utc_now().ends_with('Z'));
        assert_eq!(utc_compact().len(), 16);
    }
}
