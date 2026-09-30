//! 解析器模块基准:ddl_parser / query_parser。
//!
//! 运行:`cargo bench --bench parsers`

use criterion::{criterion_group, criterion_main, Criterion};
use rust_utils::{ddl_parser, query_parser};
use std::hint::black_box;

const CREATE_TABLE_SQL: &str = "CREATE TABLE `t_user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_name` varchar(64) NOT NULL DEFAULT '' COMMENT '登录名',
  `email` varchar(128) DEFAULT NULL,
  `age` int(11) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_name` (`user_name`),
  KEY `idx_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';";

const MULTI_TABLE_SQL: &str = "CREATE TABLE `t_order` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) NOT NULL,
  `amount` decimal(10,2) DEFAULT '0.00',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

CREATE TABLE `t_item` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `order_id` bigint(20) NOT NULL,
  `sku` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;";

const FILTER_QUERY: &str =
    "name__icontains:%E5%BC%A0,age__gte:18,city__in:beijing%7Cshanghai,deleted:eq:0";
const ORDER_BY: &str = "-created_at,+user_name,email";

fn bench_ddl_parser(c: &mut Criterion) {
    let mut group = c.benchmark_group("ddl_parser");

    group.bench_function("parse_create_table", |bm| {
        bm.iter(|| black_box(ddl_parser::parse_create_table(black_box(CREATE_TABLE_SQL))))
    });
    group.bench_function("parse_create_tables_multi", |bm| {
        bm.iter(|| black_box(ddl_parser::parse_create_tables(black_box(MULTI_TABLE_SQL))))
    });

    group.finish();
}

fn bench_query_parser(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_parser");

    group.bench_function("parse_filter_query_string", |bm| {
        bm.iter(|| {
            black_box(query_parser::parse_filter_query_string(
                black_box(FILTER_QUERY),
                |field, op, value| {
                    black_box((field, op, value));
                },
            ))
        })
    });
    group.bench_function("parse_order_by_string", |bm| {
        bm.iter(|| {
            black_box(query_parser::parse_order_by_string(
                black_box(ORDER_BY),
                |field, desc| {
                    black_box((field, desc));
                },
            ))
        })
    });

    group.finish();
}

criterion_group!(benches, bench_ddl_parser, bench_query_parser);
criterion_main!(benches);
