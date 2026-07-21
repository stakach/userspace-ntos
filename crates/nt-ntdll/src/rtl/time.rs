//! `Rtl*` time conversions.
//!
//! NT time is 100-ns ticks since 1601-01-01 (`FILETIME`/`LARGE_INTEGER`). `RtlTimeToTimeFields`
//! decomposes it into a `TIME_FIELDS` (year/month/day/hour/minute/second/ms/weekday);
//! `RtlTimeFieldsToTime` recomposes. `RtlTimeToSecondsSince1970` rebases to the Unix epoch.
//!
//! Category A. Pure calendar arithmetic (proleptic Gregorian), host-tested against known values.

/// `TIME_FIELDS` — a decomposed NT time (`ntdef.h`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct TimeFields {
    /// Year (e.g. 1601..=30827).
    pub year: i16,
    /// Month 1..=12.
    pub month: i16,
    /// Day 1..=31.
    pub day: i16,
    /// Hour 0..=23.
    pub hour: i16,
    /// Minute 0..=59.
    pub minute: i16,
    /// Second 0..=59.
    pub second: i16,
    /// Millisecond 0..=999.
    pub milliseconds: i16,
    /// Weekday 0=Sunday..=6=Saturday.
    pub weekday: i16,
}

/// 100-ns ticks per second.
const TICKS_PER_SEC: i64 = 10_000_000;
/// 100-ns ticks per millisecond.
const TICKS_PER_MS: i64 = 10_000;
/// Seconds per day.
const SECS_PER_DAY: i64 = 86_400;
/// Days from 1601-01-01 to 1970-01-01 (the Unix epoch), proleptic Gregorian.
const DAYS_1601_TO_1970: i64 = 134_774;
/// NT ticks from 1601-01-01 to 1980-01-01 (the DOS epoch).
const TICKS_TO_1980: i64 = 0x01A8_E79F_E1D5_8000;

#[inline]
fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[inline]
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from 1601-01-01 (exclusive of `year`/`month`/`day` themselves) — i.e. the day index with
/// 1601-01-01 == 0.
fn days_since_1601(year: i64, month: i64, day: i64) -> i64 {
    let mut days = 0i64;
    let mut y = 1601;
    while y < year {
        days += if is_leap(y) { 366 } else { 365 };
        y += 1;
    }
    let mut m = 1;
    while m < month {
        days += days_in_month(year, m);
        m += 1;
    }
    days + (day - 1)
}

/// `RtlTimeToTimeFields`: decompose a 100-ns NT tick count into calendar fields.
pub fn time_to_time_fields(nt_time: i64) -> TimeFields {
    let total_secs = nt_time / TICKS_PER_SEC;
    let sub_sec_ticks = nt_time % TICKS_PER_SEC;
    let ms = (sub_sec_ticks / TICKS_PER_MS) as i16;

    let mut days = total_secs / SECS_PER_DAY;
    let mut rem = total_secs % SECS_PER_DAY;
    if rem < 0 {
        rem += SECS_PER_DAY;
        days -= 1;
    }
    let hour = (rem / 3600) as i16;
    let minute = ((rem % 3600) / 60) as i16;
    let second = (rem % 60) as i16;

    // Weekday: 1601-01-01 was a Monday (== 1). NT/Windows uses 0=Sunday.
    let weekday = (((days % 7) + 1 + 7) % 7) as i16;

    // Walk the calendar forward from 1601 to place `days`.
    let mut year = 1601i64;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let mut month = 1i64;
    loop {
        let dm = days_in_month(year, month);
        if days < dm {
            break;
        }
        days -= dm;
        month += 1;
    }
    TimeFields {
        year: year as i16,
        month: month as i16,
        day: (days + 1) as i16,
        hour,
        minute,
        second,
        milliseconds: ms,
        weekday,
    }
}

/// `RtlTimeFieldsToTime`: recompose calendar fields into a 100-ns NT tick count. Returns `None` for
/// out-of-range fields.
pub fn time_fields_to_time(tf: &TimeFields) -> Option<i64> {
    if tf.year < 1601
        || tf.month < 1
        || tf.month > 12
        || tf.day < 1
        || tf.milliseconds < 0
        || tf.milliseconds > 999
    {
        return None;
    }
    let (year, month, day) = (tf.year as i64, tf.month as i64, tf.day as i64);
    if day > days_in_month(year, month) {
        return None;
    }
    if tf.hour < 0
        || tf.hour > 23
        || tf.minute < 0
        || tf.minute > 59
        || tf.second < 0
        || tf.second > 59
    {
        return None;
    }
    let days = days_since_1601(year, month, day);
    let secs =
        days * SECS_PER_DAY + tf.hour as i64 * 3600 + tf.minute as i64 * 60 + tf.second as i64;
    Some(secs * TICKS_PER_SEC + tf.milliseconds as i64 * TICKS_PER_MS)
}

/// `RtlTimeToElapsedTimeFields`: decompose an elapsed NT tick count into days and time-of-day.
pub fn time_to_elapsed_time_fields(nt_time: i64) -> TimeFields {
    let elapsed_seconds = (nt_time as u64) / TICKS_PER_SEC as u64;
    let seconds_in_day = elapsed_seconds % SECS_PER_DAY as u64;
    let seconds_in_minute = seconds_in_day % 3600;

    TimeFields {
        year: 0,
        month: 0,
        day: (elapsed_seconds / SECS_PER_DAY as u64) as i16,
        hour: (seconds_in_day / 3600) as i16,
        minute: (seconds_in_minute / 60) as i16,
        second: (seconds_in_minute % 60) as i16,
        milliseconds: ((nt_time % TICKS_PER_SEC) / TICKS_PER_MS) as i16,
        weekday: 0,
    }
}

/// `RtlCutoverTimeToSystemTime`: resolve a fixed or recurring cutover time to an absolute NT time.
pub fn cutover_time_to_system_time(
    cutover: &TimeFields,
    current_time: i64,
    this_years_cutover_only: bool,
) -> Option<i64> {
    if cutover.year != 0 {
        let system_time = time_fields_to_time(cutover)?;
        return (system_time >= current_time).then_some(system_time);
    }

    if cutover.day == 0 || cutover.day > 5 {
        return None;
    }

    let current = time_to_time_fields(current_time);
    let mut next_years_cutover = false;
    loop {
        let mut adjusted = TimeFields {
            year: current.year + i16::from(next_years_cutover),
            month: cutover.month,
            day: 1,
            hour: cutover.hour,
            minute: cutover.minute,
            second: cutover.second,
            milliseconds: cutover.milliseconds,
            weekday: 0,
        };

        let first_of_month = time_fields_to_time(&adjusted)?;
        let first_fields = time_to_time_fields(first_of_month);

        if first_fields.weekday != cutover.weekday {
            let days = if first_fields.weekday < cutover.weekday {
                cutover.weekday - first_fields.weekday
            } else {
                7 - (first_fields.weekday - cutover.weekday)
            };
            adjusted.day += days;
        }

        if cutover.day > 1 {
            let mut days = 7 * (cutover.day - 1);
            let month_length = days_in_month(adjusted.year as i64, adjusted.month as i64) as i16;
            if adjusted.day + days > month_length {
                days -= 7;
            }
            adjusted.day += days;
        }

        let system_time = time_fields_to_time(&adjusted)?;
        if this_years_cutover_only || next_years_cutover || system_time >= current_time {
            return Some(system_time);
        }

        next_years_cutover = true;
    }
}

/// `RtlTimeToSecondsSince1970`: convert an NT tick count to Unix epoch seconds. Returns `None` if
/// the time precedes 1970 or overflows `u32` (matches the Windows `ULONG` contract).
pub fn time_to_seconds_since_1970(nt_time: i64) -> Option<u32> {
    let secs = nt_time / TICKS_PER_SEC - DAYS_1601_TO_1970 * SECS_PER_DAY;
    if secs < 0 || secs > u32::MAX as i64 {
        return None;
    }
    Some(secs as u32)
}

/// `RtlSecondsSince1970ToTime`: the inverse — Unix seconds → NT tick count.
pub fn seconds_since_1970_to_time(seconds: u32) -> i64 {
    (seconds as i64 + DAYS_1601_TO_1970 * SECS_PER_DAY) * TICKS_PER_SEC
}

/// `RtlTimeToSecondsSince1980`: convert an NT tick count to DOS epoch seconds. Returns `None` if the
/// time overflows the `ULONG` seconds output.
pub fn time_to_seconds_since_1980(nt_time: i64) -> Option<u32> {
    let secs = (nt_time as i128 - TICKS_TO_1980 as i128) / TICKS_PER_SEC as i128;
    if secs < 0 || secs > u32::MAX as i128 {
        return None;
    }
    Some(secs as u32)
}

/// `RtlSecondsSince1980ToTime`: DOS epoch seconds → NT tick count.
pub fn seconds_since_1980_to_time(seconds: u32) -> i64 {
    seconds as i64 * TICKS_PER_SEC + TICKS_TO_1980
}

/// `RtlLocalTimeToSystemTime`: apply the system timezone bias.
pub fn local_time_to_system_time(local_time: i64, timezone_bias: i64) -> i64 {
    local_time.wrapping_add(timezone_bias)
}

/// `RtlSystemTimeToLocalTime`: remove the system timezone bias.
pub fn system_time_to_local_time(system_time: i64, timezone_bias: i64) -> i64 {
    system_time.wrapping_sub(timezone_bias)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_1601_is_zero() {
        let tf = time_to_time_fields(0);
        assert_eq!(tf.year, 1601);
        assert_eq!(tf.month, 1);
        assert_eq!(tf.day, 1);
        assert_eq!(tf.weekday, 1); // Monday
        assert_eq!(time_fields_to_time(&tf), Some(0));
    }

    #[test]
    fn unix_epoch_roundtrip() {
        let nt = seconds_since_1970_to_time(0);
        let tf = time_to_time_fields(nt);
        assert_eq!((tf.year, tf.month, tf.day), (1970, 1, 1));
        assert_eq!(tf.weekday, 4); // 1970-01-01 was a Thursday
        assert_eq!(time_to_seconds_since_1970(nt), Some(0));
    }

    #[test]
    fn known_datetime_roundtrip() {
        // 2021-03-14 15:09:26.535
        let tf = TimeFields {
            year: 2021,
            month: 3,
            day: 14,
            hour: 15,
            minute: 9,
            second: 26,
            milliseconds: 535,
            weekday: 0, // filled by decode; ignored by encode
        };
        let nt = time_fields_to_time(&tf).unwrap();
        let back = time_to_time_fields(nt);
        assert_eq!((back.year, back.month, back.day), (2021, 3, 14));
        assert_eq!((back.hour, back.minute, back.second), (15, 9, 26));
        assert_eq!(back.milliseconds, 535);
        assert_eq!(back.weekday, 0); // 2021-03-14 was a Sunday
    }

    #[test]
    fn leap_day_valid_and_invalid() {
        let feb29_2020 = TimeFields {
            year: 2020,
            month: 2,
            day: 29,
            ..Default::default()
        };
        assert!(time_fields_to_time(&feb29_2020).is_some());
        let feb29_2021 = TimeFields {
            year: 2021,
            month: 2,
            day: 29,
            ..Default::default()
        };
        assert!(time_fields_to_time(&feb29_2021).is_none());
    }

    #[test]
    fn invalid_time_fields_are_rejected() {
        assert!(time_fields_to_time(&TimeFields {
            year: 1600,
            month: 1,
            day: 1,
            ..Default::default()
        })
        .is_none());
        assert!(time_fields_to_time(&TimeFields {
            year: 2020,
            month: 1,
            day: 1,
            milliseconds: 1000,
            ..Default::default()
        })
        .is_none());
    }

    #[test]
    fn elapsed_time_fields_are_duration_fields() {
        let elapsed = 2 * SECS_PER_DAY * TICKS_PER_SEC
            + 3 * 3600 * TICKS_PER_SEC
            + 4 * 60 * TICKS_PER_SEC
            + 5 * TICKS_PER_SEC
            + 6 * TICKS_PER_MS;
        let tf = time_to_elapsed_time_fields(elapsed);
        assert_eq!((tf.year, tf.month, tf.day), (0, 0, 2));
        assert_eq!(
            (tf.hour, tf.minute, tf.second, tf.milliseconds),
            (3, 4, 5, 6)
        );
    }

    #[test]
    fn cutover_time_to_system_time_handles_fixed_and_recurring_rules() {
        let current = time_fields_to_time(&TimeFields {
            year: 2024,
            month: 3,
            day: 1,
            ..Default::default()
        })
        .unwrap();
        let fixed = TimeFields {
            year: 2024,
            month: 4,
            day: 15,
            hour: 2,
            ..Default::default()
        };
        assert_eq!(
            time_to_time_fields(cutover_time_to_system_time(&fixed, current, false).unwrap()).day,
            15
        );

        let second_sunday_in_march = TimeFields {
            year: 0,
            month: 3,
            day: 2,
            hour: 2,
            weekday: 0,
            ..Default::default()
        };
        let resolved = time_to_time_fields(
            cutover_time_to_system_time(&second_sunday_in_march, current, false).unwrap(),
        );
        assert_eq!(
            (resolved.year, resolved.month, resolved.day, resolved.hour),
            (2024, 3, 10, 2)
        );
    }

    #[test]
    fn pre_1970_rejected_for_unix() {
        assert_eq!(time_to_seconds_since_1970(0), None); // 1601 predates 1970
    }

    #[test]
    fn dos_epoch_roundtrip() {
        let nt = seconds_since_1980_to_time(0);
        let tf = time_to_time_fields(nt);
        assert_eq!((tf.year, tf.month, tf.day), (1980, 1, 1));
        assert_eq!(tf.weekday, 2); // 1980-01-01 was a Tuesday
        assert_eq!(time_to_seconds_since_1980(nt), Some(0));

        let max = seconds_since_1980_to_time(u32::MAX);
        assert_eq!(time_to_seconds_since_1980(max), Some(u32::MAX));
        assert_eq!(time_to_seconds_since_1980(max + TICKS_PER_SEC), None);
    }

    #[test]
    fn local_system_bias_roundtrip() {
        let system = seconds_since_1970_to_time(12345);
        let bias = 10 * 60 * TICKS_PER_SEC;
        let local = system_time_to_local_time(system, bias);
        assert_eq!(local_time_to_system_time(local, bias), system);
    }
}
