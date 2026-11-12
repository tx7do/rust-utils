//! JWT 基准:HS256 签发/校验与 RS256 签发/校验(密钥预生成)。
//!
//! 运行:`cargo bench --features jwt -- bench_jwt`

use criterion::{criterion_group, criterion_main, Criterion};
use rust_utils::jwt::{self, Algorithm};
use serde_json::json;
use std::hint::black_box;

const SECRET: &str = "bench-secret";

fn bench_jwt(c: &mut Criterion) {
    let claims = json!({ "sub": "bench-user", "role": "admin", "exp": 4102444800i64 });

    let hs_token = jwt::generate_jwt(claims.clone(), SECRET, Algorithm::HS256).unwrap();
    c.bench_function("jwt/hs256_generate", |b| {
        b.iter(|| jwt::generate_jwt(black_box(claims.clone()), SECRET, Algorithm::HS256).unwrap())
    });
    c.bench_function("jwt/hs256_verify", |b| {
        b.iter(|| jwt::verify_jwt(black_box(&hs_token), SECRET))
    });

    // RSA:密钥生成一次(数百毫秒),不计入迭代
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/jwt");
    let private_pem = std::fs::read_to_string(format!("{dir}/rsa_private.pem")).unwrap();
    let public_pem = std::fs::read_to_string(format!("{dir}/rsa_public.pem")).unwrap();
    let rs_token = jwt::generate_jwt_with_key(claims, &private_pem, Algorithm::RS256).unwrap();
    c.bench_function("jwt/rs256_generate", |b| {
        b.iter(|| {
            jwt::generate_jwt_with_key(
                black_box(json!({ "sub": "bench", "exp": 4102444800i64 })),
                &private_pem,
                Algorithm::RS256,
            )
            .unwrap()
        })
    });
    c.bench_function("jwt/rs256_verify", |b| {
        b.iter(|| jwt::verify_jwt_with_key(black_box(&rs_token), &public_pem, Algorithm::RS256))
    });
}

criterion_group!(benches, bench_jwt);
criterion_main!(benches);
