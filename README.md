# rust-utils

从 [tx7do/go-utils](https://github.com/tx7do/go-utils) 移植而来的 Rust 工具箱:命名风格转换、切片/映射辅助、雪花 ID、订单号、查询条件解析、MySQL DDL 解析、优先级事件循环、数据回填、密码哈希、AES/HMAC、JWT、随机昵称生成、银行卡 BIN 查询等。

设计原则:**核心模块零依赖**(只依赖 `std`),重依赖的能力(时间、随机、加密、JWT 等)通过 feature 按需启用;全 crate `#![forbid(unsafe_code)]`。

## 使用

```toml
[dependencies]
rust-utils = "0.1"

# 按需启用 feature,例如:
# rust-utils = { version = "0.1", features = ["chrono", "rand", "password"] }
# 或全量:features = ["full"]
```

## 模块一览

| Rust 模块 | 对应 Go 包 | feature | 说明 |
|---|---|---|---|
| [`byteutil`] | byteutil | 默认 | 整数/字节互转、ASCII 大小写 |
| [`stringcase`] | stringcase | 默认 | 驼峰/蛇形/烤肉串转换,识别缩写词与数字段 |
| [`sliceutil`] | sliceutil | 默认 | 查找族、交集/差集/并集、去重、分块 |
| [`maputil`] | maputils | 默认 | keys/values/merge/drop/filter |
| [`mathutil`] | math | 默认 | 统计量、手写正态分布(Gaussian)、Erfc/Ierfc |
| [`pagination`] | pagination | 默认 | 分页偏移量 |
| [`cryptocurrency`] | cryptocurrency | 默认 | 加密货币钱包地址格式校验 |
| [`query_parser`] | query_parser | `json`(JSON 形式需要) | Django 风格 `field__op` 过滤/排序解析 |
| [`ddl_parser`] | ddl_parser | 默认 | MySQL `CREATE TABLE` 解析(手写词法,零依赖) |
| [`eventloop`] | eventloop | 默认 | 单线程优先级事件循环,支持帧驱动模式 |
| [`aggregator`] | aggregator | 默认 | 关联数据回填(列表/树)+ 并行执行器 |
| [`id`] | id | 默认(`uuid` 可选) | 雪花 ID、订单号、机器码(内置 SHA-256)、UUID v4/v7 |
| [`fsutil`] | ioutil | 默认(`glob` 可选) | 文件/路径辅助 |
| [`dateutil`] | dateutil | `chrono` | 日粒度取整、区间判断 |
| [`timeutil`] | timeutil | `chrono` | 今天/昨天/本月/上月区间、时间差、格式转换 |
| [`random`] | rand | `rand` | 随机工具:加权/别名表/骰子/抖动/正态/手机号等 |
| [`name_generator`] | name_generator | `name-generator` | 随机昵称与中英日姓名(内嵌 2.5 MB 词库) |
| [`slug`] | slug | `slug` | URL slug(unicode 转写) |
| [`password`] | password | `password` | PBKDF2/bcrypt/argon2/HMAC/SHA 哈希策略 |
| [`crypto`] | crypto | `crypto` | AES-CBC/AES-GCM/HMAC/SHA-2、PKCS#7 填充 |
| [`jwt`] | jwtutil | `jwt` | JWT 生成/解析/校验/刷新(HS256) |
| [`bank_card`] | bank_card | `bank-card` | Luhn 校验 + BIN 查询(内嵌 2013 条记录) |
| [`captcha`] | captcha | `captcha` | 图形验证码:数字/字母/算术/中文四类文本驱动 + 滑块/点选/旋转,自绘渲染,输出 JSON 与上游同构,存储层可插拔(`captcha-redis` 提供 Redis 落地) |
| [`fieldmask`] | fieldmaskutil | `fieldmask` | 字段掩码:嵌套掩码树构建 + filter/prune/overwrite/validate/路径归一化(语义移植到 `serde_json::Value` 上) |
| [`tls`] | tls | `tls` | TLS 证书加载:从 PEM 文件/字节组装 rustls 服务端/客户端配置(单向/双向) |
| [`sm`] | crypto(SM 部分) | `sm` | 国密 SM2(C1C3C2/ASN.1 加解密、签名验签)/SM3/SM4-CBC |

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

七种驱动(数字/字母/算术/中文四类文本 + 滑块/点选/旋转)与 Go 版
一一对应,配置面、输出 JSON 结构、验证容差对齐;渲染为程序自绘
(字形资产说明见 `assets/captcha/README.md`)。

```rust
use rust_utils::captcha::{Captcha, Config, DriverKind};

let cap = Captcha::with_config(Config::with_driver(DriverKind::Digit));
let (id, b64, answer) = cap.generate().unwrap();
// 文本驱动返回 PNG 数据 URI;滑块/点选/旋转驱动返回
// 与上游同构的 JSON(内嵌 JPEG 主图 / PNG 缩略图)
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

## 与 Go 版的差异

未移植的 Go 包及原因:

| Go 包 | 原因 |
|---|---|
| `trans`(指针助手) | Rust 的 `Option<T>` 天然覆盖 |
| `copierutil` / `mapper` / `structutil` | 基于 Go 反射,在 Rust 中应改用 serde/prost 方案 |
| `distlock` / `translator` / `geoip` | 依赖 Redis/etcd、外部 HTTP 服务或大体积数据文件,建议单独封装 |
| `code_generator` | Go `text/template` 生态专属 |

行为修正(相对 Go 版的 bug):

- `sliceutil` 的 `FindLastIndex`/`FindLastIndexOf` 在 Go 里永远检查不到下标 0,已修正;
- `ddl_parser` 的 `--` 行注释在 Go 里只会删掉最后一行(正则未开多行模式),已改为标准的"删到行尾";
- `cryptocurrency` 的 XMR 正则多了一个前导 `/`(导致永远匹配不上)、TRC 正则未加锚点,均已修正;
- `aggregator` 的并行执行器重试语义在 Rust 中要求任务可重复调用(`Fn`);
- `id::protected_id` / `new_xid` / `new_sonyflake_id` 中机器标识来源由 Go 版的内网 IP 改为进程内随机/进程 ID(std 无对应 API);
- `crypto::EcdsaCipher::public_key_bytes` 由 Go 版的非标准 ASN.1 结构体改为标准 SEC1 非压缩编码;
- 上游 gmsm 的 `CipherUnmarshal` 对 X/Y 不做 32 字节前导补零(概率性产生短 C1 导致解密错位),Rust 版补齐。

`captcha` 的固有差异(上游因素材缺失不可用的部分,本库以程序生成素材
实现同构管线):

- 滑块/点选的背景为 wrapper 同款渐变公式,点选字形为内嵌 GNU Unifont
  位图子集、干扰图元逐式移植自上游,旋转驱动的圆盘为径向图案替身
  (字形素材及其许可见 `assets/captcha/README.md`);数字驱动内置的
  11×18 点阵与 dchest/base64Captcha 逐字节一致(Apache-2.0);
- 上游 `rotate` builder 不读 wrapper 的 `RotateConfig`(恒用上游默认
  常量 220×220、缩略 {140,150,160,170}、角度 [30,330]),Rust 版
  保持同一行为,该配置字段惰性;
- 上游点选验证把期望答案序列化为 JSON 对象、而其自身按数组解析,
  恒为失败;Rust 版将同数据存为数组,使逐点 ±10px 的原验证语义可用。

`tls` 与 `fieldmask` 的固有差异:

- `tls` 返回 rustls 的 `ServerConfig`/`ClientConfig` 而非 Go 的
  `*tls.Config`;`insecure_skip_verify` 参数保留但为空操作(上游
  把它设在服务端配置上,该字段本就只对客户端验证生效);系统根
  信任由 `rustls-native-certs` 加载;
- `fieldmask` 把上游基于 proto 反射的掩码语义移植到
  `serde_json::Value` 上:JSON 对象同时对应 proto 的普通字段与
  map 字段,统一采用上游普通字段分支的保守语义(上游 map 分支
  对掩码内标量更激进,见模块文档);`Validate` 以模板 JSON 对象
 充当消息描述符;`fieldmaskpb.FieldMask` 包装与字段号→路径
  转换为 proto 专属,未移植。

## 开发

```bash
cargo test              # 核心模块测试(零依赖)
cargo test --all-features  # 全部模块测试(244 单测 + 28 文档测试,其中 1 例标记 ignore 不执行)
cargo clippy --all-features --all-targets
cargo fmt
```

## License

MIT
