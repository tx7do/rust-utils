//! 集合与数值模块基准:sliceutil / maputil / mathutil / id。
//!
//! 运行:`cargo bench --bench collections`

use criterion::{criterion_group, criterion_main, Criterion};
use rust_utils::{id, maputil, mathutil, sliceutil};
use std::hint::black_box;

/// 两个有部分重叠的 i64 切片(各 1000 个元素,重叠约 1/3)。
fn overlap_slices() -> (Vec<i64>, Vec<i64>) {
    let a: Vec<i64> = (0..1000).map(|i| i * 3).collect();
    let b: Vec<i64> = (500..1500).map(|i| i * 2).collect();
    (a, b)
}

fn bench_sliceutil(c: &mut Criterion) {
    let (a, b) = overlap_slices();

    let mut group = c.benchmark_group("sliceutil");

    group.bench_function("unique_1000", |bm| {
        bm.iter(|| black_box(sliceutil::unique(black_box(&a))))
    });
    group.bench_function("intersection_1000", |bm| {
        bm.iter(|| black_box(sliceutil::intersection(black_box(&[&a, &b]))))
    });
    group.bench_function("union_1000", |bm| {
        bm.iter(|| black_box(sliceutil::union(black_box(&[&a, &b]))))
    });
    group.bench_function("difference_1000", |bm| {
        bm.iter(|| black_box(sliceutil::difference(black_box(&[&a, &b]))))
    });
    group.bench_function("chunk_1000_by_16", |bm| {
        bm.iter(|| black_box(sliceutil::chunk(black_box(&a), 16)))
    });
    group.bench_function("find_indexes_of_1000", |bm| {
        bm.iter(|| black_box(sliceutil::find_indexes_of(black_box(&a), black_box(&999))))
    });

    group.finish();
}

fn bench_maputil(c: &mut Criterion) {
    let mut m1 = std::collections::HashMap::new();
    let mut m2 = std::collections::HashMap::new();
    for i in 0..100 {
        m1.insert(format!("key-{i}"), i);
        m2.insert(format!("key-{}", i + 50), i);
    }

    let mut group = c.benchmark_group("maputil");

    group.bench_function("keys_100", |bm| {
        bm.iter(|| black_box(maputil::keys(black_box(&m1))))
    });
    group.bench_function("values_100", |bm| {
        bm.iter(|| black_box(maputil::values(black_box(&m1))))
    });
    group.bench_function("merge_100", |bm| {
        bm.iter(|| black_box(maputil::merge(black_box(vec![m1.clone(), m2.clone()]))))
    });

    group.finish();
}

fn bench_mathutil(c: &mut Criterion) {
    // 确定性伪随机数据(避免引入 rand feature)
    let nums: Vec<f64> = (0..10_000)
        .map(|i| ((i as f64 * 0.6180339887).fract() - 0.5) * 10.0)
        .collect();
    let gauss = mathutil::Gaussian::new(2.0, 9.0);

    let mut group = c.benchmark_group("mathutil");

    group.bench_function("mean_10k", |bm| {
        bm.iter(|| black_box(mathutil::mean(black_box(&nums))))
    });
    group.bench_function("standard_deviation_10k", |bm| {
        bm.iter(|| black_box(mathutil::standard_deviation(black_box(&nums))))
    });
    group.bench_function("erfc", |bm| {
        bm.iter(|| {
            for i in 0..100 {
                black_box(mathutil::erfc(black_box(i as f64 * 0.03)));
            }
        })
    });
    group.bench_function("gaussian_pdf_100", |bm| {
        bm.iter(|| {
            for i in 0..100 {
                black_box(gauss.pdf(black_box(i as f64 * 0.1)));
            }
        })
    });
    group.bench_function("gaussian_cdf_100", |bm| {
        bm.iter(|| {
            for i in 0..100 {
                black_box(gauss.cdf(black_box(i as f64 * 0.1)));
            }
        })
    });

    group.finish();
}

fn bench_id(c: &mut Criterion) {
    let mut group = c.benchmark_group("id");

    group.bench_function("snowflake_generate", |bm| {
        bm.iter(|| black_box(id::new_snowflake_id(black_box(1)).unwrap()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sliceutil,
    bench_maputil,
    bench_mathutil,
    bench_id
);
criterion_main!(benches);
