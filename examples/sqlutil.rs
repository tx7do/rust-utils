//! PostgreSQL 词法级 SQL 脱敏与表提取(纯 std;审计日志配套)。
//!
//! 运行:`cargo run --example sqlutil`

use rust_utils::sqlutil;

fn main() {
    let sql = r#"
        INSERT INTO users (name, id_card, note)
        VALUES ('张三', '110101199003078675', '电话 13812345678')
        RETURNING id; -- 归档
    "#;

    println!("masked:\n{}", sqlutil::mask_sql(sql));
    println!("tables: {:?}", sqlutil::extract_tables(sql));

    let masked = sqlutil::mask_sql(sql);
    assert!(!masked.contains("张三"), "字符串字面量已脱敏");
    assert!(!masked.contains("110101199003078675"));
    assert!(masked.contains("INSERT INTO"), "结构与关键字保留");
    assert!(sqlutil::extract_tables(sql)
        .iter()
        .any(|t| t.contains("users")));
    println!("OK");
}
