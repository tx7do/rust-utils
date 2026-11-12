//! protobuf 时间转换(feature `prost-time`):`chrono` 的 DateTime 与
//! `prost_types::Timestamp/Duration` 的互转。
//!
//! 对位上游 `copierutil` 的 time↔protobuf 转换器:gRPC 服务里
//! `google.protobuf.Timestamp`/`Duration` 是心跳字段,这一对纯函数
//! 就是它们与 `chrono`/`std::time` 的桥。全部 fail-fast:越界
//! (秒数超 `i64`/chrono 表域)或负时长一律报错,不做截断。
//!
//! 与 auditutil 的关系:审计签名内容中的 Timestamp 形态必须与上游
//! Go 逐位兼容(nanos 恒为 0 的占位结构),不经过本模块 —— 本模块
//! 服务的是真实 protobuf 序列化场景。
//!
//! ```
//! use chrono::{DateTime, Utc};
//! use rust_utils::prost_time;
//!
//! let ts = prost_time::timestamp_from_datetime(
//!     "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
//! ).unwrap();
//! assert_eq!(ts.seconds, 1767225600);
//! assert_eq!(ts.nanos, 0);
//! let back = prost_time::datetime_from_timestamp(ts).unwrap();
//! assert_eq!(back.to_rfc3339(), "2026-01-01T00:00:00+00:00");
//! ```

use chrono::{DateTime, Local, TimeZone, Utc};
use prost_types::Timestamp;

/// `DateTime<Utc>` → `Timestamp`(纳秒取自亚秒部分,恒为规范域
/// `0..=999_999_999`;秒数超 `i64` 报错——chrono 在 i64 域内,实际不可达)。
pub fn timestamp_from_datetime(dt: DateTime<Utc>) -> Result<Timestamp, String> {
    let seconds = dt.timestamp();
    let nanos = dt.timestamp_subsec_nanos() as i32;
    Ok(Timestamp { seconds, nanos })
}

/// `DateTime<Local>` → `Timestamp`(先归一为 UTC 再转换)。
pub fn timestamp_from_local(dt: DateTime<Local>) -> Result<Timestamp, String> {
    timestamp_from_datetime(dt.with_timezone(&Utc))
}

/// `Timestamp` → `DateTime<Utc>`(秒数超出 chrono 表域或纳秒非规范域
/// (`nanos < 0` 或 `> 999_999_999`)报错)。
pub fn datetime_from_timestamp(ts: Timestamp) -> Result<DateTime<Utc>, String> {
    if !(0..=999_999_999).contains(&ts.nanos) {
        return Err(format!(
            "prosttime: nanos {} out of canonical range",
            ts.nanos
        ));
    }
    Utc.timestamp_opt(ts.seconds, ts.nanos as u32)
        .single()
        .ok_or_else(|| format!("prosttime: seconds {} out of range", ts.seconds))
}

/// `std::time::Duration` → `prost_types::Duration`(秒数超 `i64` 报错;
/// 纳秒恒为规范域)。
pub fn duration_from_std(d: std::time::Duration) -> Result<prost_types::Duration, String> {
    let seconds = i64::try_from(d.as_secs())
        .map_err(|_| format!("prosttime: duration {}s out of i64 range", d.as_secs()))?;
    Ok(prost_types::Duration {
        seconds,
        nanos: d.subsec_nanos() as i32,
    })
}

/// `prost_types::Duration` → `std::time::Duration`(protobuf 允许负时长,
/// std 不支持 —— 负值报错;秒数超 u64 报错)。
pub fn std_duration_from_prost(d: prost_types::Duration) -> Result<std::time::Duration, String> {
    if d.seconds < 0 || d.nanos < 0 {
        return Err(format!(
            "prosttime: negative duration {}s {}ns not supported",
            d.seconds, d.nanos
        ));
    }
    let seconds = u64::try_from(d.seconds)
        .map_err(|_| format!("prosttime: duration {}s out of u64 range", d.seconds))?;
    let nanos =
        u32::try_from(d.nanos).map_err(|_| format!("prosttime: nanos {} out of range", d.nanos))?;
    Ok(std::time::Duration::new(seconds, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDateTime;

    fn utc_ymd(year: i32, month: u32, day: u32, h: u32, m: u32, s: u32) -> DateTime<Utc> {
        Utc.from_utc_datetime(
            &NaiveDateTime::parse_from_str(
                &format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}"),
                "%Y-%m-%dT%H:%M:%S",
            )
            .unwrap(),
        )
    }

    #[test]
    fn timestamp_known_values() {
        // 纪元起点
        let ts = timestamp_from_datetime(utc_ymd(1970, 1, 1, 0, 0, 0)).unwrap();
        assert_eq!(ts.seconds, 0);
        assert_eq!(ts.nanos, 0);
        // 2026-01-01(模块文档向量)
        let ts = timestamp_from_datetime(utc_ymd(2026, 1, 1, 0, 0, 0)).unwrap();
        assert_eq!(ts.seconds, 1767225600);
        // 亚秒精度保留
        let dt = utc_ymd(2026, 6, 15, 12, 30, 45) + chrono::Duration::nanoseconds(123_456_789);
        let ts = timestamp_from_datetime(dt).unwrap();
        assert_eq!(ts.nanos, 123_456_789);
    }

    #[test]
    fn timestamp_roundtrip() {
        // 逐秒采样回环(含闰秒临近日期的常规秒)
        for day in [1u32, 15, 28] {
            let dt = utc_ymd(2025, 2, day, 8, 9, 10);
            let ts = timestamp_from_datetime(dt).unwrap();
            let back = datetime_from_timestamp(ts).unwrap();
            assert_eq!(back, dt, "day={day}");
        }
        // 极值:i64 秒域内 chrono 可表达的最大时间
        let ts = Timestamp {
            seconds: 253_402_300_799,
            nanos: 999_999_999,
        }; // 9999-12-31T23:59:59.999999999
        let back = datetime_from_timestamp(ts).unwrap();
        let re = timestamp_from_datetime(back).unwrap();
        assert_eq!(re.seconds, ts.seconds);
        assert_eq!(re.nanos, ts.nanos);
    }

    #[test]
    fn timestamp_errors() {
        // 纳秒非规范域拒绝
        assert!(datetime_from_timestamp(Timestamp {
            seconds: 0,
            nanos: -1
        })
        .is_err());
        assert!(datetime_from_timestamp(Timestamp {
            seconds: 0,
            nanos: 1_000_000_000
        })
        .is_err());
        // 秒数超出 chrono 表域拒绝
        assert!(datetime_from_timestamp(Timestamp {
            seconds: i64::MAX,
            nanos: 0
        })
        .is_err());
        assert!(datetime_from_timestamp(Timestamp {
            seconds: i64::MIN,
            nanos: 0
        })
        .is_err());
    }

    #[test]
    fn local_variant_uses_timezone() {
        // Local 转换:以 UTC 时间戳对照(不依赖运行地时区的具体偏移,
        // 只验证与 with_timezone(&Utc) 一致)
        let local = Local::now();
        let ts = timestamp_from_local(local).unwrap();
        let expect = timestamp_from_datetime(local.with_timezone(&Utc)).unwrap();
        assert_eq!(ts, expect);
    }

    #[test]
    fn duration_conversions() {
        // 常规往返
        let d = std::time::Duration::new(125, 500_000_000);
        let pb = duration_from_std(d).unwrap();
        assert_eq!(pb.seconds, 125);
        assert_eq!(pb.nanos, 500_000_000);
        assert_eq!(std_duration_from_prost(pb).unwrap(), d);
        // 零
        let pb = duration_from_std(std::time::Duration::ZERO).unwrap();
        assert_eq!(
            std_duration_from_prost(pb).unwrap(),
            std::time::Duration::ZERO
        );
        // 亚秒纳秒级
        let d = std::time::Duration::from_nanos(1);
        let pb = duration_from_std(d).unwrap();
        assert_eq!(pb.seconds, 0);
        assert_eq!(pb.nanos, 1);
    }

    #[test]
    fn duration_errors() {
        // 负时长(std 不支持)报错
        assert!(std_duration_from_prost(prost_types::Duration {
            seconds: -1,
            nanos: 0
        })
        .is_err());
        assert!(std_duration_from_prost(prost_types::Duration {
            seconds: 0,
            nanos: -1
        })
        .is_err());
        // 秒数超 u64 报错
        let d = prost_types::Duration {
            seconds: i64::MIN,
            nanos: 0,
        };
        assert!(std_duration_from_prost(d).is_err());
        // std 超大时长报错(u64 秒 > i64 域)
        let big = std::time::Duration::new(u64::MAX, 0);
        assert!(duration_from_std(big).is_err());
    }
}
