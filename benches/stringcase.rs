//! stringcase 模块基准:大小写转换与拆分。
//!
//! 运行:`cargo bench --bench stringcase`

use criterion::{criterion_group, criterion_main, Criterion};
use rust_utils::stringcase;
use std::hint::black_box;

/// 覆盖常见形态:蛇形、小驼峰、大驼峰、烤肉串、含缩写词与数字段。
const INPUTS: &[&str] = &[
    "user_id",
    "userName",
    "HTTPStatusCode",
    "foo-bar-baz",
    "parseJSONResponseV2",
    "rust_utils_toolbox",
    "get_user_by_id_and_name",
    "XMLHttpRequest",
];

fn bench_stringcase(c: &mut Criterion) {
    let mut group = c.benchmark_group("stringcase");

    group.bench_function("snake_case", |b| {
        b.iter(|| {
            for s in INPUTS {
                black_box(stringcase::snake_case(black_box(s)));
            }
        })
    });
    group.bench_function("upper_snake_case", |b| {
        b.iter(|| {
            for s in INPUTS {
                black_box(stringcase::upper_snake_case(black_box(s)));
            }
        })
    });
    group.bench_function("lower_camel_case", |b| {
        b.iter(|| {
            for s in INPUTS {
                black_box(stringcase::lower_camel_case(black_box(s)));
            }
        })
    });
    group.bench_function("upper_camel_case", |b| {
        b.iter(|| {
            for s in INPUTS {
                black_box(stringcase::upper_camel_case(black_box(s)));
            }
        })
    });
    group.bench_function("kebab_case", |b| {
        b.iter(|| {
            for s in INPUTS {
                black_box(stringcase::kebab_case(black_box(s)));
            }
        })
    });

    group.bench_function("split", |b| {
        b.iter(|| {
            for s in INPUTS {
                black_box(stringcase::split(black_box(s)));
            }
        })
    });
    group.bench_function("replace_non_alphanumeric", |b| {
        b.iter(|| {
            for s in INPUTS {
                black_box(stringcase::replace_non_alphanumeric(black_box(s), "_"));
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_stringcase);
criterion_main!(benches);
