//! 敏感词过滤基准:词典构建一次,度量命中检测与打码。
//!
//! 运行:`cargo bench --features sensitive -- bench_sensitive`

use criterion::{criterion_group, criterion_main, Criterion};
use rust_utils::sensitive::SensitiveFilter;
use std::hint::black_box;

fn bench_sensitive(c: &mut Criterion) {
    // 千词词典 + 混合文本(含中文命中与英文命中)
    let words: Vec<String> = (0..1000).map(|i| format!("词{i}")).collect();
    let text =
        "这是一段正常的文本,其中偶尔出现词42与词777这类敏感词,穿插大量无关内容以模拟真实篇幅。"
            .repeat(50);

    let filter = SensitiveFilter::new(&words);
    assert!(filter.is_hit(&text));

    c.bench_function("sensitive/find_all", |b| {
        b.iter(|| filter.find_all(black_box(&text)))
    });
    c.bench_function("sensitive/mask", |b| {
        b.iter(|| filter.mask(black_box(&text), '*'))
    });
    c.bench_function("sensitive/is_hit", |b| {
        b.iter(|| filter.is_hit(black_box(&text)))
    });
}

criterion_group!(benches, bench_sensitive);
criterion_main!(benches);
