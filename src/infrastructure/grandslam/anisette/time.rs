//! Time formatting helpers for Anisette payloads.

use std::time::SystemTime;

/// Format the current system time as ISO 8601 (RFC 3339).
pub(super) fn iso8601_now() -> String {
    let now = SystemTime::now();
    let dur = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let nanos = dur.subsec_nanos();

    let (year, month, day, hour, min, sec) = unix_to_utc(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year,
        month,
        day,
        hour,
        min,
        sec,
        nanos / 1_000_000
    )
}

/// Convert Unix seconds to UTC date/time components.
fn unix_to_utc(seconds: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = seconds / 86400;
    let rem = seconds % 86400;
    let hour = (rem / 3600) as u32;
    let min = ((rem % 3600) / 60) as u32;
    let sec = (rem % 60) as u32;

    let mut year = 1970u32;
    let mut days_left = i64::try_from(days).unwrap_or(i64::MAX);

    loop {
        let year_days = if is_leap_year(year) { 366 } else { 365 };
        if days_left < year_days {
            break;
        }
        days_left -= year_days;
        year += 1;
    }

    let month_days = [
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut month = 1u32;
    for &md in &month_days {
        if days_left < md {
            break;
        }
        days_left -= md;
        month += 1;
    }

    let day = u32::try_from(days_left + 1).unwrap_or(1);
    (year, month, day, hour, min, sec)
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}
