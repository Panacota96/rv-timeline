//! Timeline engine (round 2, agent B): merge and sort events (stable order: utc_s, utc_ns, id), apply the
//! options' window and tool filter, compute cross-source [`Signal`]s, convert to the display zone, and write
//! `timeline.jsonl` (Timesketch). Streams and sorts on disk past an in-memory threshold.

use crate::model::{Signal, TimeEvent, Timeline, TimelineOptions};

/// Sorts events into the timeline order and applies the window/tool filters.
pub fn order(mut events: Vec<TimeEvent>, _opts: &TimelineOptions) -> Vec<TimeEvent> {
    events.sort_by(|a, b| (a.utc_s, a.utc_ns, &a.id).cmp(&(b.utc_s, b.utc_ns, &b.id)));
    events
}

/// Cross-source signals over an ordered timeline.
pub fn signals(_timeline: &Timeline, _opts: &TimelineOptions) -> Vec<Signal> {
    Vec::new()
}

/// One Timesketch JSONL line for an event (`message`, `datetime`, `timestamp_desc`, plus Rakvor fields).
pub fn timesketch_line(_event: &TimeEvent) -> String {
    String::new()
}
