//! 日期辅助:日粒度取整与区间判断。
//!
//! 全部基于 UTC。

use chrono::{DateTime, TimeZone, Utc};

/// 取当天 00:00:00(UTC)。
pub fn floor<Tz: TimeZone>(t: DateTime<Tz>) -> DateTime<Utc> {
    let utc = t.with_timezone(&Utc);
    let secs = utc.timestamp();
    Utc.timestamp_opt(secs - secs.rem_euclid(86_400), 0)
        .single()
        .unwrap_or(utc)
}

/// 取当天 23:59:59(UTC)。
pub fn ceil<Tz: TimeZone>(t: DateTime<Tz>) -> DateTime<Utc> {
    floor(t) + chrono::Duration::days(1) - chrono::Duration::seconds(1)
}

/// `date <= milestone`。
pub fn before_or_equal<Tz: TimeZone, Tz2: TimeZone>(
    milestone: DateTime<Tz>,
    date: DateTime<Tz2>,
) -> bool {
    date.with_timezone(&Utc) <= milestone.with_timezone(&Utc)
}

/// `date >= milestone`。
pub fn after_or_equal<Tz: TimeZone, Tz2: TimeZone>(
    milestone: DateTime<Tz>,
    date: DateTime<Tz2>,
) -> bool {
    date.with_timezone(&Utc) >= milestone.with_timezone(&Utc)
}

/// 两个日期区间是否相交。
pub fn overlap<Tz: TimeZone, Tz2: TimeZone>(
    start1: DateTime<Tz>,
    end1: DateTime<Tz>,
    start2: DateTime<Tz2>,
    end2: DateTime<Tz2>,
) -> bool {
    let s1 = start1.with_timezone(&Utc);
    let e1 = end1.with_timezone(&Utc);
    let s2 = start2.with_timezone(&Utc);
    let e2 = end2.with_timezone(&Utc);
    // 区间相交当且仅当"任一区间的端点落在另一区间内":
    (s1 >= s2 && s1 <= e2)
        || (e1 >= s2 && e1 <= e2)
        || (s2 >= s1 && s2 <= e1)
        || (e2 >= s1 && e2 <= e1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 12, 30, 45).unwrap()
    }

    #[test]
    fn test_floor_ceil() {
        let t = utc(2023, 5, 23);
        assert_eq!(floor(t).format("%H:%M:%S").to_string(), "00:00:00");
        assert_eq!(ceil(t).format("%H:%M:%S").to_string(), "23:59:59");
        assert_eq!(floor(t).format("%Y-%m-%d").to_string(), "2023-05-23");
    }

    #[test]
    fn test_before_after_or_equal() {
        let milestone = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let before = Utc.with_ymd_and_hms(2022, 12, 31, 0, 0, 0).unwrap();
        let equal = milestone;
        let after = Utc.with_ymd_and_hms(2023, 1, 31, 0, 0, 0).unwrap();

        assert!(before_or_equal(milestone, before));
        assert!(before_or_equal(milestone, equal));
        assert!(!before_or_equal(milestone, after));

        assert!(!after_or_equal(milestone, before));
        assert!(after_or_equal(milestone, equal));
        assert!(after_or_equal(milestone, after));
    }

    #[test]
    fn test_overlap() {
        let s1 = Utc.with_ymd_and_hms(2022, 12, 28, 0, 0, 0).unwrap();
        let e1 = Utc.with_ymd_and_hms(2022, 12, 31, 0, 0, 0).unwrap();
        let s2 = Utc.with_ymd_and_hms(2022, 12, 30, 0, 0, 0).unwrap();
        let e2 = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let s3 = Utc.with_ymd_and_hms(2023, 1, 2, 0, 0, 0).unwrap();
        let e3 = Utc.with_ymd_and_hms(2023, 1, 4, 0, 0, 0).unwrap();

        assert!(overlap(s1, e1, s2, e2));
        assert!(!overlap(s1, e1, s3, e3));

        let s4 = Utc.with_ymd_and_hms(2023, 7, 13, 0, 0, 0).unwrap();
        let e4 = Utc.with_ymd_and_hms(2023, 7, 14, 0, 0, 0).unwrap();
        let s5 = Utc.with_ymd_and_hms(2023, 7, 10, 0, 0, 0).unwrap();
        let e5 = Utc.with_ymd_and_hms(2023, 7, 17, 0, 0, 0).unwrap();

        assert!(overlap(s4, e4, s5, e5));
        assert!(overlap(s5, e5, s4, e4));
    }
}
