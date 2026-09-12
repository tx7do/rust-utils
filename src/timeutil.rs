//! 时间工具箱(移植自 go-utils/timeutil 的核心部分):
//! 常用区间(今天/昨天/本月/上月/今年/去年)、时间差计算、时长格式化
//! 与格式转换。全部基于本地时区(`chrono::Local`)。
//!
//! Go 版中大量的 `*Ptr` 指针转换与 protobuf Timestamp 转换未移植
//! ——在 Rust 里前者是 `Option`,后者属于 prost 的领域。
//!
//! ```
//! use rust_utils::timeutil;
//!
//! let (start, end) = timeutil::get_today_range_time();
//! assert!(start <= end);
//! assert_eq!(
//!     timeutil::string_difference_days("2023-05-20", "2023-05-23"),
//!     3
//! );
//! ```

use chrono::{DateTime, Datelike, Duration, Local, NaiveDate, NaiveDateTime, TimeZone};
use std::time::Duration as StdDuration;

/// 日期布局:`2023-05-23`。
pub const DATE_LAYOUT: &str = "%Y-%m-%d";
/// 时间布局:`2023-05-23 15:04:05`。
pub const DATETIME_LAYOUT: &str = "%Y-%m-%d %H:%M:%S";

fn day_range(now: DateTime<Local>) -> (DateTime<Local>, DateTime<Local>) {
    let start = Local
        .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
        .single()
        .unwrap_or(now);
    let end = Local
        .with_ymd_and_hms(now.year(), now.month(), now.day(), 23, 59, 59)
        .single()
        .unwrap_or(now);
    (start, end)
}

/// 获取区间时间 —— 今天。
pub fn get_today_range_time() -> (DateTime<Local>, DateTime<Local>) {
    day_range(Local::now())
}

/// 获取区间时间 —— 昨天。
pub fn get_yesterday_range_time() -> (DateTime<Local>, DateTime<Local>) {
    day_range(Local::now() - Duration::days(1))
}

fn month_range(now: DateTime<Local>) -> (DateTime<Local>, DateTime<Local>) {
    let first = Local
        .with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
        .single()
        .unwrap_or(now);
    let last_day = days_in_month(now.year(), now.month());
    let end = Local
        .with_ymd_and_hms(now.year(), now.month(), last_day, 23, 59, 59)
        .single()
        .unwrap_or(now);
    (first, end)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    NaiveDate::from_ymd_opt(year, month, 1)
        .and_then(|d| d.checked_add_months(chrono::Months::new(1)))
        .map(|next| (next - Duration::days(1)).day())
        .unwrap_or(30)
}

/// 获取区间时间 —— 本月。
pub fn get_current_month_range_time() -> (DateTime<Local>, DateTime<Local>) {
    month_range(Local::now())
}

/// 获取区间时间 —— 上个月。
pub fn get_last_month_range_time() -> (DateTime<Local>, DateTime<Local>) {
    let now = Local::now();
    let prev = NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .and_then(|d| d.checked_sub_months(chrono::Months::new(1)))
        .and_then(|d| d.and_hms_opt(12, 0, 0))
        .and_then(|t| Local.from_local_datetime(&t).single())
        .unwrap_or(now);
    month_range(prev)
}

fn year_range(year: i32) -> (DateTime<Local>, DateTime<Local>) {
    let first = Local
        .with_ymd_and_hms(year, 1, 1, 0, 0, 0)
        .single()
        .unwrap_or_else(Local::now);
    let end = Local
        .with_ymd_and_hms(year, 12, 31, 23, 59, 59)
        .single()
        .unwrap_or_else(Local::now);
    (first, end)
}

/// 获取区间时间 —— 今年。
pub fn get_current_year_range_time() -> (DateTime<Local>, DateTime<Local>) {
    year_range(Local::now().year())
}

/// 获取区间时间 —— 去年。
pub fn get_last_year_range_time() -> (DateTime<Local>, DateTime<Local>) {
    year_range(Local::now().year() - 1)
}

macro_rules! range_string {
    ($fn_name:ident, $time_fn:ident, $layout:expr) => {
        /// 对应区间时间的字符串形式。
        pub fn $fn_name() -> (String, String) {
            let (start, end) = $time_fn();
            (
                start.format($layout).to_string(),
                end.format($layout).to_string(),
            )
        }
    };
}

range_string!(
    get_today_range_date_string,
    get_today_range_time,
    DATE_LAYOUT
);
range_string!(
    get_yesterday_range_date_string,
    get_yesterday_range_time,
    DATE_LAYOUT
);
range_string!(
    get_current_month_range_date_string,
    get_current_month_range_time,
    DATE_LAYOUT
);
range_string!(
    get_last_month_range_date_string,
    get_last_month_range_time,
    DATE_LAYOUT
);
range_string!(
    get_current_year_range_date_string,
    get_current_year_range_time,
    DATE_LAYOUT
);
range_string!(
    get_last_year_range_date_string,
    get_last_year_range_time,
    DATE_LAYOUT
);
range_string!(
    get_today_range_time_string,
    get_today_range_time,
    DATETIME_LAYOUT
);
range_string!(
    get_yesterday_range_time_string,
    get_yesterday_range_time,
    DATETIME_LAYOUT
);
range_string!(
    get_current_month_range_time_string,
    get_current_month_range_time,
    DATETIME_LAYOUT
);
range_string!(
    get_last_month_range_time_string,
    get_last_month_range_time,
    DATETIME_LAYOUT
);
range_string!(
    get_current_year_range_time_string,
    get_current_year_range_time,
    DATETIME_LAYOUT
);
range_string!(
    get_last_year_range_time_string,
    get_last_year_range_time,
    DATETIME_LAYOUT
);

// ---------------------------------------------------------------------------
// 时间差
// ---------------------------------------------------------------------------

/// 两个日期字符串(按 [`DATE_LAYOUT`])之间相差的小时数。
pub fn day_difference_hours(start_date: &str, end_date: &str) -> f64 {
    match (
        NaiveDate::parse_from_str(start_date, DATE_LAYOUT),
        NaiveDate::parse_from_str(end_date, DATE_LAYOUT),
    ) {
        (Ok(s), Ok(e)) => (e - s).num_hours() as f64,
        _ => 0.0,
    }
}

/// 两个日期字符串之间相差的天数(向上取整,相等为 0)。
pub fn string_difference_days(start_date: &str, end_date: &str) -> i64 {
    let hours = day_difference_hours(start_date, end_date);
    if hours == 0.0 {
        return 0;
    }
    (hours / 24.0).ceil() as i64
}

/// 两个时间按日取整(本地时区 00:00)后相差的小时数。
pub fn day_time_difference_hours(start_date: DateTime<Local>, end_date: DateTime<Local>) -> f64 {
    let floor = |t: DateTime<Local>| {
        Local
            .with_ymd_and_hms(t.year(), t.month(), t.day(), 0, 0, 0)
            .single()
            .unwrap_or(t)
    };
    (floor(end_date) - floor(start_date)).num_hours() as f64
}

/// 两个时间相差的天数(按日取整后向上取整)。
pub fn time_difference_days(start_date: DateTime<Local>, end_date: DateTime<Local>) -> i64 {
    let hours = day_time_difference_hours(start_date, end_date);
    if hours == 0.0 {
        return 0;
    }
    (hours / 24.0).ceil() as i64
}

/// 两个 Unix 秒之间相差的小时数。
pub fn day_seconds_difference_hours(start_second: i64, end_second: i64) -> f64 {
    (end_second - start_second) as f64 / 3600.0
}

/// 两个 Unix 秒之间相差的天数(向上取整)。
pub fn seconds_difference_days(start_second: i64, end_second: i64) -> i64 {
    let hours = day_seconds_difference_hours(start_second, end_second);
    if hours == 0.0 {
        return 0;
    }
    (hours / 24.0).ceil() as i64
}

// ---------------------------------------------------------------------------
// 时长与格式
// ---------------------------------------------------------------------------

/// 把时长拆成 (小时, 分钟, 秒)。
pub fn duration_hms(d: StdDuration) -> (u64, u64, u64) {
    let total = d.as_secs();
    (total / 3600, (total % 3600) / 60, total % 60)
}

/// 把时长格式化为紧凑形式(如 `1h2m3s`、`5m`、`30s`)。
pub fn format_timer(d: StdDuration) -> String {
    let (h, m, s) = duration_hms(d);
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

/// 按指定布局把时间字符串从一种格式转换为另一种格式。
///
/// ```
/// use rust_utils::timeutil;
///
/// assert_eq!(
///     timeutil::from_to("2023/05/23 14:30:00", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d"),
///     Ok("2023-05-23".to_string())
/// );
/// ```
pub fn from_to(value: &str, from_layout: &str, to_layout: &str) -> Result<String, String> {
    let parsed = NaiveDateTime::parse_from_str(value, from_layout)
        .or_else(|_| {
            NaiveDate::parse_from_str(value, from_layout).map(|d| d.and_hms_opt(0, 0, 0).unwrap())
        })
        .map_err(|e| e.to_string())?;
    Ok(parsed.format(to_layout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_today_range() {
        let (start, end) = get_today_range_time();
        assert!(start <= end);
        assert_eq!(start.hour(), 0);
        assert_eq!(start.minute(), 0);
        assert_eq!(end.hour(), 23);
        assert_eq!(end.minute(), 59);
        assert_eq!(end.second(), 59);

        let (ds, de) = get_today_range_date_string();
        assert_eq!(ds, de);
        let (ts, te) = get_today_range_time_string();
        assert!(ts.ends_with("00:00:00"));
        assert!(te.ends_with("23:59:59"));
        let _ = ds;
        let _ = de;
    }

    #[test]
    fn test_month_and_year_ranges() {
        let (start, end) = get_current_month_range_time();
        assert_eq!(start.day(), 1);
        assert!(end.day() >= 28);

        let (last_start, last_end) = get_last_month_range_time();
        assert_eq!(last_start.day(), 1);
        assert!(last_end <= start);
        assert!(last_end.day() >= 28);

        let (ys, ye) = get_current_year_range_time();
        assert_eq!((ys.month(), ys.day()), (1, 1));
        assert_eq!((ye.month(), ye.day()), (12, 31));

        let (lys, lye) = get_last_year_range_time();
        assert_eq!(lys.year() + 1, ye.year());
        assert_eq!((lye.month(), lye.day()), (12, 31));
    }

    #[test]
    fn test_differences() {
        assert_eq!(string_difference_days("2023-05-20", "2023-05-23"), 3);
        assert_eq!(string_difference_days("2023-05-23", "2023-05-23"), 0);
        assert_eq!(string_difference_days("2023-05-23", "2023-05-20"), -3);
        assert!((day_difference_hours("2023-05-20", "2023-05-23") - 72.0).abs() < 1e-9);

        assert_eq!(seconds_difference_days(0, 86_400), 1);
        assert_eq!(seconds_difference_days(0, 0), 0);
        assert!((day_seconds_difference_hours(0, 7_200) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_day_time_difference() {
        let start = Local.with_ymd_and_hms(2023, 5, 20, 15, 30, 0).unwrap();
        let end = Local.with_ymd_and_hms(2023, 5, 23, 8, 0, 0).unwrap();
        // 双方都先取整到当日 00:00:20日 → 23日 = 72 小时
        assert!((day_time_difference_hours(start, end) - 72.0).abs() < 1e-9);
        assert_eq!(time_difference_days(start, end), 3);
        assert_eq!(time_difference_days(start, start), 0);
        // 同一天内不论时刻,取整后都是 0
        let same_day = Local.with_ymd_and_hms(2023, 5, 20, 23, 59, 0).unwrap();
        assert_eq!(time_difference_days(start, same_day), 0);
    }

    #[test]
    fn test_duration_format() {
        assert_eq!(format_timer(std::time::Duration::new(3_723, 0)), "1h2m3s");
        assert_eq!(format_timer(std::time::Duration::new(125, 0)), "2m5s");
        assert_eq!(format_timer(std::time::Duration::new(30, 0)), "30s");
        assert_eq!(duration_hms(std::time::Duration::new(3_723, 0)), (1, 2, 3));
    }

    #[test]
    fn test_from_to() {
        assert_eq!(
            from_to("2023/05/23 14:30:00", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d").unwrap(),
            "2023-05-23"
        );
        assert_eq!(
            from_to("2023-05-23", DATE_LAYOUT, "%Y/%m/%d").unwrap(),
            "2023/05/23"
        );
        assert!(from_to("bad", DATE_LAYOUT, "%Y").is_err());
    }
}
