<div align="center">

# rust-utils

[English](./README_en.md) | **中文** | [日本語](./README_ja.md)

</div>

---

Rust 工具箱:命名风格转换、切片/映射辅助、雪花 ID、订单号、查询条件解析、MySQL DDL 解析、优先级事件循环、数据回填、密码哈希、AES/HMAC、JWT、随机昵称生成、银行卡 BIN 查询、图形验证码、IP 归属地、机器翻译、分布式锁、国密等。

设计原则:

- **核心模块零依赖**(只依赖 `std`),重依赖的能力(时间、随机、加密、JWT 等)通过 feature 按需启用;
- 全 crate `#![forbid(unsafe_code)]`;
- 边界读取(geoip、ddl_parser 等)对越界与畸形输入一律返回错误或空结果,不做 panic。

## 使用

```toml
[dependencies]
rust-utils = "0.1"

# 按需启用 feature,例如:
# rust-utils = { version = "0.1", features = ["chrono", "rand", "password"] }
# 或全量:features = ["full"]
```

## 模块一览

| 模块 | feature | 说明 |
|---|---|---|
| [`byteutil`] | 默认 | 整数/字节互转、ASCII 大小写 |
| [`stringcase`] | 默认 | 驼峰/蛇形/烤肉串转换,识别缩写词与数字段 |
| [`stringutil`] | 默认 | 宽松数值/布尔解析、JSON 字段值重写 |
| [`sliceutil`] | 默认 | 查找族、交集/差集/并集、去重、分块 |
| [`maputil`] | 默认 | keys/values/merge/drop/filter |
| [`mathutil`] | 默认 | 统计量、手写正态分布(Gaussian)、Erfc/Ierfc |
| [`pagination`] | 默认 | 分页偏移量 |
| [`cryptocurrency`] | 默认 | 加密货币钱包地址格式校验 |
| [`query_parser`] | `json`(JSON 形式需要) | Django 风格 `field__op` 过滤/排序解析 |
| [`ddl_parser`] | 默认 | MySQL `CREATE TABLE` 解析(手写词法,零依赖) |
| [`eventloop`] | 默认 | 单线程优先级事件循环,支持帧驱动模式 |
| [`aggregator`] | 默认 | 关联数据回填(列表/树)+ 并行执行器 + 缓存式批量加载 |
| [`id`] | 默认(`uuid` 可选) | 雪花 ID、订单号、机器码(内置 SHA-256)、UUID v4/v7 |
| [`fsutil`] | 默认(`glob` 可选) | 文件/路径辅助 |
| [`dateutil`] | `chrono` | 日粒度取整、区间判断 |
| [`timeutil`] | `chrono` | 今天/昨天/本月/上月区间、时间差、格式转换 |
| [`random`] | `rand` | 随机工具:加权/别名表/骰子/抖动/正态/手机号等 |
| [`name_generator`] | `name-generator` | 随机昵称与中英日姓名(内嵌 2.5 MB 词库) |
| [`slug`] | `slug` | URL slug(unicode 转写) |
| [`password`] | `password` | PBKDF2/bcrypt/argon2/HMAC/SHA 哈希策略 |
| [`crypto`] | `crypto` | AES-CBC/AES-GCM/HMAC/SHA-2、PKCS#7 填充 |
| [`jwt`] | `jwt` | JWT 生成/解析/校验/刷新(HS256) |
| [`bank_card`] | `bank-card` | Luhn 校验 + BIN 查询(内嵌 2013 条记录) |
| [`captcha`] | `captcha` | 图形验证码:数字/字母/算术/中文四类文本驱动 + 滑块/点选/旋转,自绘渲染,输出 JSON 与 base64Captcha 前端组件兼容,存储层可插拔(`captcha-redis` 提供 Redis 落地) |
| [`fieldmask`] | `fieldmask` | 字段掩码:嵌套掩码树构建 + filter/prune/overwrite/validate/路径归一化,作用于 `serde_json::Value` |
| [`tls`] | `tls` | TLS 证书加载:从 PEM 文件/字节组装 rustls 服务端/客户端配置(单向/双向) |
| [`geoip`] | `geoip` | IP 归属地查询三后端:qqwry(GB18030、省/市切分)、ip2region xdb v2(向量索引+段索引二分、查询器池)、MaxMind mmdb 读取器;数据文件由调用方加载 |
| [`translator`] | `translator` | 翻译器四后端:百度(MD5 签名)/阿里(RPC 签名)/谷歌(v1 裸端点、v2/v3 REST)/火山(HMAC-SHA256 派生链);单次请求不自动重试,请求构造与签名可离线验证 |
| [`distlock`] | `distlock` | 分布式锁:Locker/Lock 抽象与获取选项(Redis 落地用 `distlock-redis`,兼容 bsm/redislock 线上协议;暂未提供 etcd 后端) |
| [`sm`] | `sm` | 国密 SM2(C1C3C2/ASN.1 加解密、签名验签)/SM3/SM4-CBC |

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

## 示例

### 命名风格转换(能识别缩写词和数字段)

```rust
use rust_utils::stringcase;

assert_eq!(stringcase::snake_case("HTTPStatusCode"), "http_status_code");
assert_eq!(stringcase::snake_case("Numbers123Test"), "numbers123_test");
assert_eq!(stringcase::upper_camel_case("parse_url.do_parse"), "ParseUrlDoParse");
assert_eq!(stringcase::kebab_case("Hello World!"), "hello-world");
```

### 雪花 ID 与订单号

```rust
use rust_utils::id;

let node = id::SnowflakeNode::new(1).unwrap();
let a = node.generate();
let b = node.generate();
assert!(b > a); // 趋势递增

let order = id::generate_order_id_with_random("ORD", None);      // ORD + 14位时间戳 + 随机数
let order = id::generate_order_id_with_increase_index("ORD", None); // ORD + 14位时间戳 + 自增索引
```

### 查询条件解析

```rust
use rust_utils::query_parser;

let mut got = Vec::new();
query_parser::parse_filter_query_string(
    "name__icontains:%E5%BC%A0,age__gte:18",
    |field, op, value| got.push((field.to_string(), op.to_string(), value.to_string())),
).unwrap();
// got: [("name", "icontains", "张"), ("age", "gte", "18")]
```

### MySQL DDL 解析

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

### 优先级事件循环

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

// 请求事件带回执,便于等待处理完成
let (ev, rx) = new_request_event("ping", Some("hello".to_string()));
loop_.submit(ev).unwrap();
let reply = rx.recv_timeout(Duration::from_secs(5)).unwrap();
loop_.stop();

assert_eq!(reply.data.as_deref(), Some("hello"));
```

### 关联数据回填(避免 N+1)

```rust
use rust_utils::aggregator::populate;
use std::collections::HashMap;

struct Order { id: u32, user_name: Option<String> }

let mut orders = vec![Order { id: 1, user_name: None }];
let users: HashMap<u32, String> = [(1, "张三".to_string())].into();

populate(&mut orders, &users, |o| o.id, |o, name| o.user_name = Some(name));
assert_eq!(orders[0].user_name.as_deref(), Some("张三"));
```

### 密码哈希

```rust
use rust_utils::password::{Argon2Crypto, Crypto};

let algo = Argon2Crypto;
let hash = algo.encrypt("s3cret!").unwrap();       // 标准 PHC 格式
assert!(algo.verify("s3cret!", &hash).unwrap());
```

### 验证码服务

七种驱动:数字/字母/算术/中文四类文本驱动,加滑块/点选/旋转三类
交互驱动;渲染为程序自绘,不依赖外部图片素材(字形资产说明见
`assets/captcha/README.md`)。文本驱动返回 PNG 数据 URI,交互驱动
返回 JSON,结构与 base64Captcha 前端组件一致。

```rust
use rust_utils::captcha::{Captcha, Config, DriverKind};

let cap = Captcha::with_config(Config::with_driver(DriverKind::Digit));
let (id, b64, answer) = cap.generate().unwrap();
// 文本驱动返回 PNG 数据 URI;滑块/点选/旋转驱动返回 JSON
// (内嵌 JPEG 主图 / PNG 缩略图)
assert!(b64.starts_with("data:image/png;base64,"));
assert!(cap.verify(&id, &answer).unwrap()); // 一次性校验
```

Redis 存储启用 `captcha-redis` feature 后,把 `Captcha::with_store(MemoryStore::new(), cfg)`
换成 `RedisStore::new("redis://127.0.0.1/")?` 即可,服务层 API 完全一致。

### 缓存式批量加载

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
loader.load_many(&[2, 3]); // 全部命中缓存,不再取数
assert_eq!(calls.load(Ordering::Relaxed), 1);
```

## 开发

```bash
cargo test              # 核心模块测试(零依赖)
cargo test --all-features  # 全部模块测试(297 单测 + 28 文档测试,其中 1 例标记 ignore 不执行)
cargo clippy --all-features --all-targets
cargo fmt
```

## License

MIT
