//! QR 码基准:编码矩阵、SVG 序列化与终端块字符。
//!
//! 运行:`cargo bench --features qrcode -- bench_qrcode`

use criterion::{criterion_group, criterion_main, Criterion};
use rust_utils::qrcode::{self, EcLevel};
use std::hint::black_box;

fn bench_qrcode(c: &mut Criterion) {
    let text = "https://example.com/join?code=RUST42&ts=2026";

    c.bench_function("qrcode/encode", |b| {
        b.iter(|| qrcode::encode(black_box(text), black_box(EcLevel::M)).unwrap())
    });

    let qr = qrcode::encode(text, EcLevel::M).unwrap();
    c.bench_function("qrcode/to_svg", |b| b.iter(|| qr.to_svg(black_box(4))));
    c.bench_function("qrcode/to_unicode", |b| {
        b.iter(|| qr.to_unicode(black_box(2)))
    });
}

criterion_group!(benches, bench_qrcode);
criterion_main!(benches);
