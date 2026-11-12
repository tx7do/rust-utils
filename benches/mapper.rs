//! 字段映射基准:rename/枚举/缺省/白名单的 apply 全链路。
//!
//! 运行:`cargo bench --features mapper -- bench_mapper`

use criterion::{criterion_group, criterion_main, Criterion};
use rust_utils::mapper::Mapper;
use serde_json::json;
use std::hint::black_box;

fn bench_mapper(c: &mut Criterion) {
    let mapper = Mapper::new()
        .rename("user_name", "userName")
        .rename("profile.email", "email")
        .map_enum("status", |t| {
            t.entry(1, "active").entry(2, "frozen").entry(3, "disabled");
        })
        .default_field("role", json!("viewer"))
        .exclude("password_hash");

    let entity = json!({
        "id": 1001,
        "user_name": "alice",
        "profile": { "email": "a@x.com", "phone": "13800000000" },
        "status": 1,
        "password_hash": "…",
    });

    c.bench_function("mapper/apply", |b| {
        b.iter(|| mapper.apply(black_box(&entity)).unwrap())
    });
}

criterion_group!(benches, bench_mapper);
criterion_main!(benches);
