//! Django 风格的过滤/排序查询语法解析。
//!
//! 支持两种过滤形式,通过回调逐条产出 `(field, operator, value)`:
//!
//! - JSON 形式:`{"field__op": value}`(字段名与操作符用 `__` 连接),
//!   需要 `json` feature;
//! - 查询字符串形式:`field:op:value1|value2,field2:op:value`;
//! - 排序形式:`-field` 降序、`+field`/`field` 升序,逗号分隔。
//!
//! ```
//! use rust_utils::query_parser;
//!
//! let mut got = Vec::new();
//! query_parser::parse_filter_query_string(
//!     "name__icontains:%E5%BC%A0,age__gte:18",
//!     |field, op, value| got.push((field.to_string(), op.to_string(), value.to_string())),
//! ).unwrap();
//! assert_eq!(got[0].0, "name");
//! assert_eq!(got[0].1, query_parser::FILTER_ICONTAINS);
//! assert_eq!(got[1].2, "18");
//! ```

/// 不等于。
pub const FILTER_NOT: &str = "not";
/// 检查值是否在列表中。
pub const FILTER_IN: &str = "in";
/// 不在列表中。
pub const FILTER_NOT_IN: &str = "not_in";
/// 大于或等于传递的值。
pub const FILTER_GTE: &str = "gte";
/// 大于传递值。
pub const FILTER_GT: &str = "gt";
/// 小于或等于传递的值。
pub const FILTER_LTE: &str = "lte";
/// 小于传递值。
pub const FILTER_LT: &str = "lt";
/// 是否介于给定的两个值之间。
pub const FILTER_RANGE: &str = "range";
/// 是否为空。
pub const FILTER_IS_NULL: &str = "isnull";
/// 是否不为空。
pub const FILTER_NOT_IS_NULL: &str = "not_isnull";
/// 是否包含指定的子字符串。
pub const FILTER_CONTAINS: &str = "contains";
/// 不区分大小写,是否包含指定的子字符串。
pub const FILTER_ICONTAINS: &str = "icontains";
/// 以值开头。
pub const FILTER_STARTS_WITH: &str = "startswith";
/// 不区分大小写,以值开头。
pub const FILTER_ISTARTSWITH: &str = "istartswith";
/// 以值结尾。
pub const FILTER_ENDS_WITH: &str = "endswith";
/// 不区分大小写,以值结尾。
pub const FILTER_IENDSWITH: &str = "iendswith";
/// 精确匹配。
pub const FILTER_EXACT: &str = "exact";
/// 不区分大小写,精确匹配。
pub const FILTER_IEXACT: &str = "iexact";
/// 正则表达式。
pub const FILTER_REGEX: &str = "regex";
/// 不区分大小写,正则表达式。
pub const FILTER_IREGEX: &str = "iregex";
/// 全文搜索。
pub const FILTER_SEARCH: &str = "search";

/// 日期部分:日期。
pub const DATE_PART_DATE: &str = "date";
/// 日期部分:年。
pub const DATE_PART_YEAR: &str = "year";
/// 日期部分:ISO8601 年。
pub const DATE_PART_ISO_YEAR: &str = "iso_year";
/// 日期部分:季度。
pub const DATE_PART_QUARTER: &str = "quarter";
/// 日期部分:月。
pub const DATE_PART_MONTH: &str = "month";
/// 日期部分:ISO8601 周编号。
pub const DATE_PART_WEEK: &str = "week";
/// 日期部分:星期几。
pub const DATE_PART_WEEK_DAY: &str = "week_day";
/// 日期部分:ISO8601 星期几。
pub const DATE_PART_ISO_WEEK_DAY: &str = "iso_week_day";
/// 日期部分:日。
pub const DATE_PART_DAY: &str = "day";
/// 日期部分:时:分:秒。
pub const DATE_PART_TIME: &str = "time";
/// 日期部分:小时。
pub const DATE_PART_HOUR: &str = "hour";
/// 日期部分:分钟。
pub const DATE_PART_MINUTE: &str = "minute";
/// 日期部分:秒。
pub const DATE_PART_SECOND: &str = "second";
/// 日期部分:微秒。
pub const DATE_PART_MICROSECOND: &str = "microsecond";

/// JSON 过滤器 —— 字段名和操作符的分隔符。
pub const JSON_FILTER_FIELD_OPERATOR_DELIMITER: &str = "__";

/// 查询字符串过滤器 —— 字段名和操作符的分隔符。
pub const QUERY_FILTER_FIELD_OPERATOR_DELIMITER: &str = ":";
/// 查询字符串过滤器 —— 多个键值对的分隔符。
pub const QUERY_FILTER_QUERIES_DELIMITER: &str = ",";
/// 查询字符串过滤器 —— 多个值的分隔符。
pub const QUERY_FILTER_VALUES_DELIMITER: &str = "|";

/// JSON 字段分隔符(JSONB 嵌套字段)。
pub const JSON_FIELD_DELIMITER: &str = ".";

/// 解析过滤条件的 JSON 字符串,先尝试对象 `{"f__op": "v"}`,
/// 失败后再尝试对象数组 `[{"f__op": "v"}, ...]`,逐条调用 `handler`。
#[cfg(feature = "json")]
pub fn parse_filter_json_string<F>(query: &str, mut handler: F) -> Result<(), serde_json::Error>
where
    F: FnMut(&str, &str, &str),
{
    use std::collections::HashMap;

    if query.is_empty() {
        return Ok(());
    }

    match serde_json::from_str::<HashMap<String, String>>(query) {
        Ok(map) => {
            // 对键排序,保证输出顺序确定。
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                parse_filter_field(k, &map[k], &mut handler);
            }
            Ok(())
        }
        Err(_first_err) => {
            let arr = serde_json::from_str::<Vec<HashMap<String, String>>>(query)?;
            for item in &arr {
                let mut keys: Vec<&String> = item.keys().collect();
                keys.sort();
                for k in keys {
                    parse_filter_field(k, &item[k], &mut handler);
                }
            }
            Ok(())
        }
    }
}

/// 解析过滤条件的查询字符串(`field:op:value,field2:op2:value2`),
/// 逐条调用 `handler`。解析失败的单项被跳过,整体不会报错。
pub fn parse_filter_query_string<F>(query: &str, mut handler: F) -> Result<(), String>
where
    F: FnMut(&str, &str, &str),
{
    if query.is_empty() {
        return Ok(());
    }
    for pair in split_query_queries(query) {
        let parts = split_query_field_and_operator(pair);
        if parts.len() != 2 {
            continue;
        }
        let Ok(key) = decode_special_characters(parts[0].trim()) else {
            continue;
        };
        let Ok(value) = decode_special_characters(parts[1].trim()) else {
            continue;
        };
        parse_filter_field(&key, &value, &mut handler);
    }
    Ok(())
}

/// 解析单个过滤条件的字段(可含 `__` 操作符后缀),调用 `handler`。
/// 字段名会被转换为 snake_case。
pub fn parse_filter_field<F>(key: &str, value: &str, mut handler: F)
where
    F: FnMut(&str, &str, &str),
{
    if key.is_empty() || value.is_empty() {
        return;
    }
    let parts = split_json_field_and_operator(key);
    if parts.is_empty() {
        return;
    }
    if parts[0].trim().is_empty() {
        return;
    }
    let field = crate::stringcase::to_snake_case(parts[0]);
    let op = if parts.len() > 1 { parts[1] } else { "" };
    handler(field.as_str(), op, value);
}

/// 解析排序字符串(`-field` 降序、`+field`/`field` 升序,逗号分隔)。
pub fn parse_order_by_string<F>(order_by: &str, mut handler: F) -> Result<(), String>
where
    F: FnMut(&str, bool),
{
    if order_by.is_empty() {
        return Ok(());
    }
    for part in order_by.split(',') {
        parse_order_by_field(part.trim(), &mut handler);
    }
    Ok(())
}

/// 解析多个排序字符串。
pub fn parse_order_by_strings<F>(order_bys: &[&str], mut handler: F) -> Result<(), String>
where
    F: FnMut(&str, bool),
{
    for v in order_bys {
        if v.is_empty() {
            continue;
        }
        parse_order_by_field(v, &mut handler);
    }
    Ok(())
}

/// 解析单个排序字段并调用 `handler(field, desc)`。
pub fn parse_order_by_field<F>(order_by: &str, mut handler: F)
where
    F: FnMut(&str, bool),
{
    let order_by = order_by.trim();
    if order_by.is_empty() {
        return;
    }
    if let Some(rest) = order_by.strip_prefix('-') {
        handler(rest, true);
    } else if let Some(rest) = order_by.strip_prefix('+') {
        handler(rest, false);
    } else {
        handler(order_by, false);
    }
}

/// JSON 过滤器 —— 分割"字段名"和"操作符"。
pub fn split_json_field_and_operator(field: &str) -> Vec<&str> {
    field.split(JSON_FILTER_FIELD_OPERATOR_DELIMITER).collect()
}

/// 查询字符串过滤器 —— 分割"字段名"和"操作符"。
pub fn split_query_field_and_operator(field: &str) -> Vec<&str> {
    field.split(QUERY_FILTER_FIELD_OPERATOR_DELIMITER).collect()
}

/// 查询字符串过滤器 —— 分割多个键值对。
pub fn split_query_queries(field: &str) -> Vec<&str> {
    field.split(QUERY_FILTER_QUERIES_DELIMITER).collect()
}

/// 查询字符串过滤器 —— 分割多个值。
pub fn split_query_values(field: &str) -> Vec<&str> {
    field.split(QUERY_FILTER_VALUES_DELIMITER).collect()
}

/// 将 JSONB 字段字符串按分隔符分割成多个字段。
pub fn split_json_field(field: &str) -> Vec<&str> {
    field.split(JSON_FIELD_DELIMITER).collect()
}

/// 对字符串做查询串百分号编码(空格编码为 `+`)。
pub fn encode_special_characters(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 解码查询串百分号编码(`+` 解码为空格),非法 `%` 序列返回错误。
pub fn decode_special_characters(input: &str) -> Result<String, String> {
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(format!(
                        "invalid URL escape \"{:.3}\"",
                        &input[i..(i + 3).min(input.len())]
                    ));
                }
                let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) else {
                    return Err(format!(
                        "invalid URL escape \"{:.3}\"",
                        &input[i..(i + 3).min(input.len())]
                    ));
                };
                out.push(h * 16 + l);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| format!("invalid UTF-8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_query_string(query: &str) -> Vec<(String, String, String)> {
        let mut got = Vec::new();
        parse_filter_query_string(query, |f, o, v| {
            got.push((f.to_string(), o.to_string(), v.to_string()))
        })
        .unwrap();
        got
    }

    #[test]
    fn test_parse_filter_query_string() {
        let got = collect_query_string("name__icontains:abc,age__gte:18");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], ("name".into(), "icontains".into(), "abc".into()));
        assert_eq!(got[1], ("age".into(), "gte".into(), "18".into()));
    }

    #[test]
    fn test_parse_filter_query_string_percent_decoding() {
        let got = collect_query_string("name__exact:%E5%BC%A0%E4%B8%89,a+b__exact:x%2Cy");
        assert_eq!(got[0].2, "张三");
        // 逗号需要被编码,否则会被当作键值对分隔符
        assert_eq!(got[1].0, "a_b"); // 字段名会再做一次 snake_case
        assert_eq!(got[1].2, "x,y");
    }

    #[test]
    fn test_parse_filter_query_string_invalid_items_skipped() {
        // 三段式(多一个冒号)、解码失败、无冒号的项都会被跳过
        let got = collect_query_string("no-delimiter,age__gte:18,bad%zz:exact:x,a:b:c");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "age");
    }

    #[test]
    fn test_parse_filter_query_string_empty() {
        assert!(collect_query_string("").is_empty());
    }

    #[test]
    fn test_parse_filter_field_snake_case() {
        let mut got = Vec::new();
        parse_filter_field("userName__icontains", "abc", |f, o, v| {
            got.push((f.to_string(), o.to_string(), v.to_string()))
        });
        assert_eq!(
            got,
            vec![("user_name".into(), "icontains".into(), "abc".into())]
        );

        let mut got2 = Vec::new();
        parse_filter_field("id", "5", |f, o, v| {
            got2.push((f.to_string(), o.to_string(), v.to_string()))
        });
        assert_eq!(got2, vec![("id".into(), "".into(), "5".into())]);

        // 空字段/空值直接忽略
        let mut n = 0;
        parse_filter_field("", "x", |_, _, _| n += 1);
        parse_filter_field("a", "", |_, _, _| n += 1);
        assert_eq!(n, 0);
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_parse_filter_json_string() {
        let mut got = Vec::new();
        parse_filter_json_string(
            r#"{"userName__icontains":"abc","age__gte":"18"}"#,
            |f, o, v| got.push((f.to_string(), o.to_string(), v.to_string())),
        )
        .unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("age".into(), "gte".into(), "18".into()),
                ("user_name".into(), "icontains".into(), "abc".into()),
            ]
        );
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_parse_filter_json_string_array() {
        let mut got = Vec::new();
        parse_filter_json_string(
            r#"[{"id__in":"1|2"},{"userName__exact":"tom"}]"#,
            |f, o, v| got.push((f.to_string(), o.to_string(), v.to_string())),
        )
        .unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("id".into(), "in".into(), "1|2".into()),
                ("user_name".into(), "exact".into(), "tom".into()),
            ]
        );
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_parse_filter_json_string_invalid() {
        assert!(parse_filter_json_string("not-json", |_, _, _| {}).is_err());
        // 数字值无法反序列化为字符串映射,回退数组也失败 → 报错
        assert!(parse_filter_json_string(r#"{"age":18}"#, |_, _, _| {}).is_err());
    }

    #[test]
    fn test_parse_order_by() {
        let mut got = Vec::new();
        parse_order_by_string("-createdAt, +id, name", |f, desc| {
            got.push((f.to_string(), desc))
        })
        .unwrap();
        assert_eq!(
            got,
            vec![
                ("createdAt".into(), true),
                ("id".into(), false),
                ("name".into(), false),
            ]
        );

        let mut got2: Vec<(String, bool)> = Vec::new();
        parse_order_by_strings(&["-a", "", "b"], |f, desc| got2.push((f.to_string(), desc)))
            .unwrap();
        assert_eq!(
            got2,
            vec![("a".to_string(), true), ("b".to_string(), false)]
        );
    }

    #[test]
    fn test_split_helpers() {
        assert_eq!(
            split_json_field_and_operator("name__in"),
            vec!["name", "in"]
        );
        assert_eq!(split_json_field_and_operator("name"), vec!["name"]);
        assert_eq!(
            split_query_field_and_operator("name:icontains"),
            vec!["name", "icontains"]
        );
        assert_eq!(
            split_query_queries("a:exact:1,b:exact:2"),
            vec!["a:exact:1", "b:exact:2"]
        );
        assert_eq!(split_query_values("1|2|3"), vec!["1", "2", "3"]);
        assert_eq!(split_json_field("a.b.c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let src = "张三 abc-1.2~ x";
        let enc = encode_special_characters(src);
        assert_eq!(enc, "%E5%BC%A0%E4%B8%89+abc-1.2~+x");
        assert_eq!(decode_special_characters(&enc).unwrap(), src);
        assert!(decode_special_characters("bad%zz").is_err());
        assert!(decode_special_characters("bad%2").is_err());
    }
}
