//! 时间区间:今天/昨天/本月/上月/年区间与格式化。
//!
//! 运行:`cargo run --features chrono --example timeutil`

use rust_utils::timeutil;

fn main() {
    let (today_start, today_end) = timeutil::get_today_range_time();
    println!(
        "today:    {} ~ {}",
        today_start.format("%F %T"),
        today_end.format("%F %T")
    );

    let (yest_start, yest_end) = timeutil::get_yesterday_range_time();
    println!("yesterday:{yest_start} ~ {yest_end}");

    let (m_start, m_end) = timeutil::get_current_month_range_time();
    println!(
        "month:    {} ~ {}",
        m_start.format("%F"),
        m_end.format("%F")
    );

    let (lm_start, lm_end) = timeutil::get_last_month_range_time();
    println!(
        "lastmonth:{} ~ {}",
        lm_start.format("%F"),
        lm_end.format("%F")
    );

    let (year_start, year_end) = timeutil::get_current_year_range_time();
    println!(
        "year:     {} ~ {}",
        year_start.format("%F"),
        year_end.format("%F")
    );

    // 相对时间格式化(计时器样式)
    println!(
        "timer:    {}",
        timeutil::format_timer(std::time::Duration::from_secs(3725))
    );

    assert!(today_end > today_start);
    assert!(yest_end < today_start, "昨天区间整体早于今天起点");
    assert!(lm_end < m_start);
    println!("OK");
}
