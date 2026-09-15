<div align="center">

# rust-utils

**English** | [中文](./README.md) | [日本語](./README_ja.md)

</div>

---

A Rust toolbox: case-style conversion, slice/map helpers, Snowflake IDs, order IDs, query-condition parsing, MySQL DDL parsing, a priority event loop, relation backfill, password hashing, AES/HMAC, JWT, random nickname generation, bank-card BIN lookup, image CAPTCHA, IP geolocation, machine translation, distributed locks, Chinese national crypto (SM), and more.

Design principles:

- **Core modules are zero-dependency** (`std` only); capability areas with heavier dependencies (time, randomness, crypto, JWT, …) are enabled per-feature;
- The whole crate carries `#![forbid(unsafe_code)]`;
- Boundary reads (geoip, ddl_parser, …) return errors or empty results on out-of-range or malformed input — never panic.

## Usage

```toml
[dependencies]
rust-utils = "0.1"

# Enable features as needed, e.g.:
# rust-utils = { version = "0.1", features = ["chrono", "rand", "password"] }
# or everything: features = ["full"]
```

## Modules

| Module | Feature | Description |
|---|---|---|
| [`byteutil`] | default | Integer/byte conversions, ASCII case flips |
| [`stringcase`] | default | camel/snake/kebab conversion, acronym- and digit-segment aware |
| [`stringutil`] | default | Lenient numeric/boolean parsing, JSON field-value rewriting |
| [`sliceutil`] | default | Find family, intersection/difference/union, dedup, chunking |
| [`maputil`] | default | keys/values/merge/drop/filter |
| [`mathutil`] | default | Statistics, hand-written Gaussian, Erfc/Ierfc |
| [`pagination`] | default | Pagination offsets |
| [`cryptocurrency`] | default | Crypto wallet address format validation |
| [`query_parser`] | `json` (for the JSON form) | Django-style `field__op` filter/sort parsing |
| [`ddl_parser`] | default | MySQL `CREATE TABLE` parsing (hand-written lexer, zero deps) |
| [`eventloop`] | default | Single-threaded priority event loop, with a frame-driven mode |
| [`aggregator`] | default | Relation backfill (lists/trees) + parallel executor + cached batch loader |
| [`id`] | default (`uuid` optional) | Snowflake IDs, order IDs, machine codes (built-in SHA-256), UUID v4/v7 |
| [`fsutil`] | default (`glob` optional) | File/path helpers |
| [`dateutil`] | `chrono` | Day-granularity truncation, range checks |
| [`timeutil`] | `chrono` | Today/yesterday/this-month/last-month ranges, time differences, format conversion |
| [`random`] | `rand` | Random toolkit: weighted choice/alias table/dice/jitter/gaussian/phone numbers, etc. |
| [`name_generator`] | `name-generator` | Random nicknames and Chinese/English/Japanese names (embedded 2.5 MB dictionaries) |
| [`slug`] | `slug` | URL slugs (unicode transliteration) |
| [`password`] | `password` | PBKDF2/bcrypt/argon2/HMAC/SHA hashing strategies |
| [`crypto`] | `crypto` | AES-CBC/AES-GCM/HMAC/SHA-2, PKCS#7 padding |
| [`jwt`] | `jwt` | JWT generate/parse/verify/refresh (HS256) |
| [`bank_card`] | `bank-card` | Luhn validation + BIN lookup (2,013 embedded records) |
| [`captcha`] | `captcha` | Image CAPTCHA: digit/alphanumeric/arithmetic/Chinese text drivers + slide/click/rotate, self-drawn rendering, JSON output compatible with the base64Captcha front-end component, pluggable storage (`captcha-redis` adds a Redis store) |
| [`fieldmask`] | `fieldmask` | Field masks: nested mask-tree building + filter/prune/overwrite/validate/path normalization, over `serde_json::Value` |
| [`tls`] | `tls` | TLS certificate loading: rustls server/client configs assembled from PEM files/bytes (one-way/mutual) |
| [`geoip`] | `geoip` | IP geolocation with three backends: qqwry (GB18030, province/city splitting), ip2region xdb v2 (vector index + segment bisection, searcher pool), MaxMind mmdb reader; data files are loaded by the caller |
| [`translator`] | `translator` | Translators for four backends: Baidu (MD5 signature) / Alibaba (RPC signature) / Google (bare v1 endpoint, v2/v3 REST) / Volc (HMAC-SHA256 derivation chain); one request per call, no automatic retry; request construction and signatures are offline-verifiable |
| [`distlock`] | `distlock` | Distributed locks: Locker/Lock abstractions with acquire options (Redis store via `distlock-redis`, wire-compatible with the bsm/redislock protocol; no etcd backend yet) |
| [`sm`] | `sm` | Chinese national crypto SM2 (C1C3C2/ASN.1 encryption & signatures) / SM3 / SM4-CBC |

[`byteutil`]: src/byteutil.rs
[`stringcase`]: src/stringcase.rs
[`stringutil`]: src/stringutil.rs
[`sm`]: src/sm.rs
[`sliceutil`]: src/sliceutil.rs
[`maputil`]: src/maputil.rs
[`mathutil`]: src/mathutil.rs
[`pagination`]: src/pagination.rs
[`cryptocurrency`]: src/cryptocurrency.rs
[`query_parser`]: src/query_parser.rs
[`ddl_parser`]: src/ddl_parser.rs
[`eventloop`]: src/eventloop.rs
[`aggregator`]: src/aggregator.rs
[`id`]: src/id.rs
[`fsutil`]: src/fsutil.rs
[`dateutil`]: src/dateutil.rs
[`timeutil`]: src/timeutil.rs
[`random`]: src/random.rs
[`name_generator`]: src/name_generator.rs
[`slug`]: src/slug.rs
[`password`]: src/password.rs
[`crypto`]: src/crypto.rs
[`jwt`]: src/jwt.rs
[`bank_card`]: src/bank_card.rs
[`captcha`]: src/captcha.rs
[`fieldmask`]: src/fieldmask.rs
[`tls`]: src/tls.rs
[`geoip`]: src/geoip.rs
[`translator`]: src/translator.rs
[`distlock`]: src/distlock.rs

## Examples

### Case conversion (acronym- and digit-segment aware)

```rust
use rust_utils::stringcase;

assert_eq!(stringcase::snake_case("HTTPStatusCode"), "http_status_code");
assert_eq!(stringcase::snake_case("Numbers123Test"), "numbers123_test");
assert_eq!(stringcase::upper_camel_case("parse_url.do_parse"), "ParseUrlDoParse");
assert_eq!(stringcase::kebab_case("Hello World!"), "hello-world");
```

### Snowflake IDs and order IDs

```rust
use rust_utils::id;

let node = id::SnowflakeNode::new(1).unwrap();
let a = node.generate();
let b = node.generate();
assert!(b > a); // monotonically increasing

let order = id::generate_order_id_with_random("ORD", None);         // ORD + 14-digit timestamp + random digits
let order = id::generate_order_id_with_increase_index("ORD", None); // ORD + 14-digit timestamp + incrementing index
```

### Query condition parsing

```rust
use rust_utils::query_parser;

let mut got = Vec::new();
query_parser::parse_filter_query_string(
    "name__icontains:%E5%BC%A0,age__gte:18",
    |field, op, value| got.push((field.to_string(), op.to_string(), value.to_string())),
).unwrap();
// got: [("name", "icontains", "张"), ("age", "gte", "18")]
```

### MySQL DDL parsing

```rust
use rust_utils::ddl_parser;

let table = ddl_parser::parse_create_table(
    "CREATE TABLE `users` (\
        `id` BIGINT AUTO_INCREMENT PRIMARY KEY, \
        `userName` VARCHAR(100) NOT NULL COMMENT '用户名'\
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表'",
).unwrap();

assert_eq!(table.name, "users");
assert!(table.columns[0].auto_increment);
assert_eq!(table.columns[1].comment, "用户名");
assert_eq!(table.engine, "innodb");
```

### Priority event loop

```rust
use rust_utils::eventloop::{new_request_event, EventLoop, EventProcessor, EventResult};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Collector(Arc<Mutex<Vec<String>>>);

impl EventProcessor<String> for Collector {
    fn process(&mut self, event: Event<String>) -> EventResult<String> {
        self.0.lock().unwrap().push(event.event_type.clone());
        EventResult::ok(event.data)
    }
}

let seen = Arc::new(Mutex::new(Vec::new()));
let loop_ = EventLoop::new(16, Collector(seen.clone()), false);
loop_.start();

// request events carry a receipt, handy for waiting on completion
let (ev, rx) = new_request_event("ping", Some("hello".to_string()));
loop_.submit(ev).unwrap();
let reply = rx.recv_timeout(Duration::from_secs(5)).unwrap();
loop_.stop();

assert_eq!(reply.data.as_deref(), Some("hello"));
```

### Relation backfill (avoids N+1)

```rust
use rust_utils::aggregator::populate;
use std::collections::HashMap;

struct Order { id: u32, user_name: Option<String> }

let mut orders = vec![Order { id: 1, user_name: None }];
let users: HashMap<u32, String> = [(1, "张三".to_string())].into();

populate(&mut orders, &users, |o| o.id, |o, name| o.user_name = Some(name));
assert_eq!(orders[0].user_name.as_deref(), Some("张三"));
```

### Password hashing

```rust
use rust_utils::password::{Argon2Crypto, Crypto};

let algo = Argon2Crypto;
let hash = algo.encrypt("s3cret!").unwrap();       // standard PHC format
assert!(algo.verify("s3cret!", &hash).unwrap());
```

### CAPTCHA service

Seven drivers: four text drivers (digit/alphanumeric/arithmetic/Chinese) plus three interactive ones (slide/click/rotate); rendering is fully programmatic, with no external image assets (see `assets/captcha/README.md` for glyph asset notes). Text drivers return PNG data URIs; interactive drivers return JSON compatible with the base64Captcha front-end component.

```rust
use rust_utils::captcha::{Captcha, Config, DriverKind};

let cap = Captcha::with_config(Config::with_driver(DriverKind::Digit));
let (id, b64, answer) = cap.generate().unwrap();
// text drivers return a PNG data URI; slide/click/rotate drivers return
// JSON (with embedded JPEG master / PNG thumbnail images)
assert!(b64.starts_with("data:image/png;base64,"));
assert!(cap.verify(&id, &answer).unwrap()); // one-shot verification
```

With the `captcha-redis` feature enabled, swap `Captcha::with_store(MemoryStore::new(), cfg)` for `RedisStore::new("redis://127.0.0.1/")?` — the service-level API stays exactly the same.

### Cached batch loading

```rust
use rust_utils::aggregator::Loader;
use std::sync::atomic::{AtomicUsize, Ordering};

let calls = std::sync::Arc::new(AtomicUsize::new(0));
let calls2 = calls.clone();
let loader = Loader::new(move |keys: &[u32]| {
    calls2.fetch_add(1, Ordering::Relaxed);
    keys.iter().map(|k| (*k, k * 10)).collect()
});

let got = loader.load_many(&[1, 2, 3]);
assert_eq!(got[&2].as_ref(), &20);
loader.load_many(&[2, 3]); // all cache hits, no refetch
assert_eq!(calls.load(Ordering::Relaxed), 1);
```

## Development

```bash
cargo test                 # core-module tests (zero-dependency)
cargo test --all-features  # all-module tests (297 unit + 28 doc tests, 1 marked ignore)
cargo clippy --all-features --all-targets
cargo fmt
```

## License

MIT
