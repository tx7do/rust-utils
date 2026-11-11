//! Django 风格 `field__op` 查询解析(过滤/排序表达式)。
//!
//! 运行:`cargo run --features json --example query_parser`

use rust_utils::query_parser;

fn main() {
    // 过滤(JSON 形态):键 `field__op`,值为字符串;
    // 多值操作符(__in/__nin)用 `|` 分隔
    let query = r#"{"name__contains":"张","age__gte":"18","status__in":"1|2"}"#;
    query_parser::parse_filter_json_string(query, |key, op, value| {
        println!("filter: {key} {op} {value}");
    })
    .unwrap();

    // 过滤(URL query 形态):name__contains=张&deleted=false
    query_parser::parse_filter_query_string(
        "name__contains=张&deleted=false",
        |key, op, value| {
            println!("query : {key} {op} {value}");
        },
    )
    .unwrap();

    // 排序:-created_at,id(前缀 - 为降序)
    query_parser::parse_order_by_string("-created_at,id", |field, desc| {
        println!("order : {field} {}", if desc { "DESC" } else { "ASC" });
    })
    .unwrap();

    // 字段与操作符拆分(JSONB 嵌套字段以 . 分隔)
    let parts = query_parser::split_json_field_and_operator("profile.name__eq");
    println!("split : {parts:?}");

    assert_eq!(parts.last().copied(), Some("eq"));
    println!("OK");
}
