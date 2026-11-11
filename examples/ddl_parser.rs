//! MySQL `CREATE TABLE` DDL 解析(手写词法,零依赖)。
//!
//! 运行:`cargo run --example ddl_parser`

use rust_utils::ddl_parser;

fn main() {
    let ddl = r#"
        CREATE TABLE `sys_user` (
            `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
            `user_name` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '登录名',
            `status` TINYINT NOT NULL DEFAULT 1,
            `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`),
            UNIQUE KEY `uk_user_name` (`user_name`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统用户';
    "#;

    let table = ddl_parser::parse_create_table(ddl).unwrap();
    println!(
        "table: {} (engine={}, charset={})",
        table.name, table.engine, table.charset
    );
    for col in &table.columns {
        println!(
            "  {:<14} {:<18} nullable={:<5} default={:?}",
            col.name,
            col.column_type,
            col.nullable,
            if col.default.is_empty() {
                "-"
            } else {
                &col.default
            }
        );
    }
    assert_eq!(table.name, "sys_user");
    assert!(table
        .columns
        .iter()
        .any(|c| c.name == "user_name" && !c.primary_key));
    assert!(table
        .columns
        .iter()
        .any(|c| c.name == "id" && c.primary_key));
    println!("OK");
}
