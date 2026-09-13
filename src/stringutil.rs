//! 字符串辅助工具(移植自 go-utils/stringutil 的常用部分)。
//!
//! Go 版 60 余个 `IntToString` / `StringToInt...OrDefault` 逐类型转换
//! 函数,在 Rust 里对应 `to_string()` 与 [`parse_or`] 一个泛型函数;
//! commons-lang 风格的随机串生成器已合并进 `random` 模块
//! (feature `rand`)。这里保留:
//!
//! - [`parse_or`] / [`parse_bool`]:带默认值的容错解析;
//! - [`replace_json_field`]:原始 JSON 字符串的字段值重写(正则语义移植)。
//!
//! ```
//! use rust_utils::stringutil;
//!
//! assert_eq!(stringutil::parse_or("42", 0), 42);
//! assert_eq!(stringutil::parse_or("oops", 0), 0);
//! assert_eq!(stringutil::parse_bool("true"), Some(true));
//!
//! let json = r#"{"tenantId":"old","name":"n"}"#;
//! let rewritten = stringutil::replace_json_field("tenantId|tenant_id", "new", json);
//! assert!(rewritten.contains(r#""tenantId": "new""#));
//! ```

use std::str::FromStr;

/// 解析失败时返回默认值(等价 Go 版 `StringTo...OrDefault` 函数族)。
///
/// ```
/// use rust_utils::stringutil::parse_or;
/// assert_eq!(parse_or("3.14", 0.0_f64), 3.14);
/// assert_eq!(parse_or("x", 7_i64), 7);
/// ```
pub fn parse_or<T: FromStr>(s: &str, default: T) -> T {
    s.trim().parse().unwrap_or(default)
}

/// 宽松布尔解析(等价 Go `strconv.ParseBool`):
/// `1/t/T/true/TRUE/True` 为真,`0/f/F/false/FALSE/False` 为假,其余 `None`。
pub fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

/// 在原始 JSON 字符串中把指定字符串字段的值替换为 `new_value`
/// (移植自 Go 版 `ReplaceJSONField`)。
///
/// - `field_names`:多个字段名用竖线分隔(如 `"tenantId|tenant_id"`),
///   大小写不敏感;
/// - 只匹配值为**字符串**的字段(与 Go 版正则 `"([^"]*)"` 语义一致,
///   不处理转义引号);
/// - 替换后冒号后统一为一个空格(Go 版 `${1}: "new"` 语义)。
///
/// ```
/// use rust_utils::stringutil::replace_json_field;
///
/// let json = r#"{"TenantId": "a", "x": 1}"#;
/// assert_eq!(
///     replace_json_field("tenantId", "b", json),
///     r#"{"TenantId": "b", "x": 1}"#
/// );
/// ```
pub fn replace_json_field(field_names: &str, new_value: &str, json_str: &str) -> String {
    let fields: Vec<&str> = field_names
        .split('|')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .collect();
    if fields.is_empty() || json_str.is_empty() {
        return json_str.to_string();
    }

    let bytes = json_str.as_bytes();
    let mut out = String::with_capacity(json_str.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'"' {
            out.push(json_str[i..].chars().next().unwrap());
            i += json_str[i..].chars().next().unwrap().len_utf8();
            continue;
        }
        // 找字段名的结束引号
        let Some(close) = json_str[i + 1..].find('"') else {
            out.push_str(&json_str[i..]);
            break;
        };
        let close = i + 1 + close;
        let name = &json_str[i + 1..close];
        // 是否命中目标字段:向后找 `:` 与字符串值
        let mut j = close + 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b':' {
            let mut k = j + 1;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b'"' {
                if let Some(value_end_rel) = json_str[k + 1..].find('"') {
                    let value_end = k + 1 + value_end_rel;
                    if fields.iter().any(|f| f.eq_ignore_ascii_case(name)) {
                        // 命中:保留原始带引号字段名,冒号后规范为一个空格
                        out.push_str(&json_str[i..=close]);
                        out.push_str(": \"");
                        out.push_str(new_value);
                        out.push('"');
                        i = value_end + 1;
                        continue;
                    }
                }
            }
        }
        // 未命中:原样推进
        out.push_str(&json_str[i..=close]);
        i = close + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_or() {
        assert_eq!(parse_or("42", 0_i32), 42);
        assert_eq!(parse_or(" 42 ", 0_i32), 42); // 去空白
        assert_eq!(parse_or("abc", 0_i32), 0);
        assert_eq!(parse_or("", 9_i64), 9);
        assert_eq!(parse_or("3.5", 1.0_f64), 3.5);
        assert!(parse_or("true", false));
    }

    #[test]
    fn test_parse_bool() {
        for s in ["1", "t", "T", "true", "TRUE", "True"] {
            assert_eq!(parse_bool(s), Some(true), "s: {s}");
        }
        for s in ["0", "f", "F", "false", "FALSE", "False"] {
            assert_eq!(parse_bool(s), Some(false), "s: {s}");
        }
        assert_eq!(parse_bool("yes"), None);
        assert_eq!(parse_bool(""), None);
        assert_eq!(parse_bool("2"), None);
    }

    #[test]
    fn test_replace_json_field() {
        // 单字段
        let json = r#"{"name":"tom","age":18}"#;
        assert_eq!(
            replace_json_field("name", "jerry", json),
            r#"{"name": "jerry","age":18}"#
        );
        // 多字段别名,大小写不敏感
        let json2 = r#"{"TenantId":"a","tenant_id":"b"}"#;
        let out = replace_json_field("tenantId|tenant_id", "X", json2);
        assert!(out.contains(r#""TenantId": "X""#));
        assert!(out.contains(r#""tenant_id": "X""#));
        // 非字符串值 / 未命中字段不动
        let json3 = r#"{"n": 5, "other":"v"}"#;
        assert_eq!(replace_json_field("n", "z", json3), json3);
        assert_eq!(replace_json_field("missing", "z", json3), json3);
        // 空输入
        assert_eq!(replace_json_field("", "v", json3), json3);
        assert_eq!(replace_json_field("name", "v", ""), "");
        // 冒号带空格的输入
        let json4 = r#"{"a" :   "old"}"#;
        assert_eq!(replace_json_field("a", "new", json4), r#"{"a": "new"}"#);
    }
}
