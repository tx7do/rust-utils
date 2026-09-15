<div align="center">

# rust-utils

[English](./README_en.md) | [中文](./README.md) | **日本語**

</div>

---

Rust 製ツールボックス:命名スタイル変換、スライス/マップ補助、Snowflake ID、注文番号、検索条件パース、MySQL DDL パース、優先度付きイベントループ、関連データ紐付け、パスワードハッシュ、AES/HMAC、JWT、ランダムニックネーム生成、銀行カード BIN 検索、画像 CAPTCHA、IP ジオロケーション、機械翻訳、分散ロック、中国国家暗号(SM)など。

設計原則:

- **コアモジュールはゼロ依存**(`std` のみ)。依存の重い機能(時刻、乱数、暗号、JWT など)は feature で必要に応じて有効化;
- クレート全体で `#![forbid(unsafe_code)]`;
- 境界の読み取り(geoip、ddl_parser など)は、範囲外や不正な入力に対してエラーまたは空の結果を返し、決して panic しない。

## 使い方

```toml
[dependencies]
rust-utils = "0.1"

# 必要な feature を有効化、例:
# rust-utils = { version = "0.1", features = ["chrono", "rand", "password"] }
# または全量: features = ["full"]
```

## モジュール一覧

| モジュール | feature | 説明 |
|---|---|---|
| [`byteutil`] | デフォルト | 整数/バイト変換、ASCII 大文字小文字 |
| [`stringcase`] | デフォルト | キャメル/スネーク/ケバブ変換、略語と数字セグメントを認識 |
| [`stringutil`] | デフォルト | 寛容な数値/ブール解析、JSON フィールド値の書き換え |
| [`sliceutil`] | デフォルト | 検索系、積/差/和集合、重複排除、チャンク分割 |
| [`maputil`] | デフォルト | keys/values/merge/drop/filter |
| [`mathutil`] | デフォルト | 統計量、手書き正規分布(Gaussian)、Erfc/Ierfc |
| [`pagination`] | デフォルト | ページング オフセット |
| [`cryptocurrency`] | デフォルト | 暗号資産ウォレットアドレスの形式検証 |
| [`query_parser`] | `json`(JSON 形式に必要) | Django 風 `field__op` フィルタ/ソート解析 |
| [`ddl_parser`] | デフォルト | MySQL `CREATE TABLE` 解析(手書きレキサ、ゼロ依存) |
| [`eventloop`] | デフォルト | シングルスレッド優先度付きイベントループ、フレーム駆動モード対応 |
| [`aggregator`] | デフォルト | 関連データ紐付け(リスト/ツリー)+ 並列エグゼキュータ + キャッシュ式バッチローダ |
| [`id`] | デフォルト(`uuid` 任意) | Snowflake ID、注文番号、マシンコード(内蔵 SHA-256)、UUID v4/v7 |
| [`fsutil`] | デフォルト(`glob` 任意) | ファイル/パス補助 |
| [`dateutil`] | `chrono` | 日粒度の丸め、期間判定 |
| [`timeutil`] | `chrono` | 今日/昨日/今月/先月の期間、時間差、形式変換 |
| [`random`] | `rand` | 乱数ツール:重み付き選択/エイリアステーブル/サイコロ/ジッタ/正規分布/電話番号など |
| [`name_generator`] | `name-generator` | ランダムニックネームと中英日の氏名(内蔵 2.5 MB 辞書) |
| [`slug`] | `slug` | URL slug(Unicode 音訳) |
| [`password`] | `password` | PBKDF2/bcrypt/argon2/HMAC/SHA ハッシュ戦略 |
| [`crypto`] | `crypto` | AES-CBC/AES-GCM/HMAC/SHA-2、PKCS#7 パディング |
| [`jwt`] | `jwt` | JWT 生成/パース/検証/リフレッシュ(HS256) |
| [`bank_card`] | `bank-card` | Luhn 検証 + BIN 検索(内蔵 2,013 件) |
| [`captcha`] | `captcha` | 画像 CAPTCHA:数字/英数字/算術/中国語の 4 テキストドライバ + スライド/クリック/回転、自前描画、base64Captcha フロントエンド コンポーネント互換の JSON 出力、ストレージ差し替え可(Redis は `captcha-redis`) |
| [`fieldmask`] | `fieldmask` | フィールドマスク:ネストしたマスクツリー構築 + filter/prune/overwrite/validate/パス正規化、`serde_json::Value` 上で動作 |
| [`tls`] | `tls` | TLS 証明書ロード:PEM ファイル/バイトから rustls のサーバー/クライアント設定を組立(一方向/相互) |
| [`geoip`] | `geoip` | IP ジオロケーション 3 バックエンド:qqwry(GB18030、省/市分割)、ip2region xdb v2(ベクトルインデックス+セグメント二分探索、検索器プール)、MaxMind mmdb リーダー。データファイルは呼び出し側でロード |
| [`translator`] | `translator` | 翻訳 4 バックエンド:百度(MD5 署名)/阿里(RPC 署名)/Google(v1 素のエンドポイント、v2/v3 REST)/火山(HMAC-SHA256 派生チェーン)。1 回のリクエストで自動リトライなし、リクエスト構築と署名はオフライン検証可能 |
| [`distlock`] | `distlock` | 分散ロック:Locker/Lock 抽象と取得オプション(Redis 実装は `distlock-redis`、bsm/redislock プロトコルとワイヤ互換。etcd バックエンドは未提供) |
| [`sm`] | `sm` | 中国国家暗号 SM2(C1C3C2/ASN.1 の暗号化・署名検証)/SM3/SM4-CBC |

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

## 例

### 命名スタイル変換(略語と数字セグメントを認識)

```rust
use rust_utils::stringcase;

assert_eq!(stringcase::snake_case("HTTPStatusCode"), "http_status_code");
assert_eq!(stringcase::snake_case("Numbers123Test"), "numbers123_test");
assert_eq!(stringcase::upper_camel_case("parse_url.do_parse"), "ParseUrlDoParse");
assert_eq!(stringcase::kebab_case("Hello World!"), "hello-world");
```

### Snowflake ID と注文番号

```rust
use rust_utils::id;

let node = id::SnowflakeNode::new(1).unwrap();
let a = node.generate();
let b = node.generate();
assert!(b > a); // 単調増加

let order = id::generate_order_id_with_random("ORD", None);         // ORD + 14桁タイムスタンプ + 乱数
let order = id::generate_order_id_with_increase_index("ORD", None); // ORD + 14桁タイムスタンプ + 増分インデックス
```

### 検索条件パース

```rust
use rust_utils::query_parser;

let mut got = Vec::new();
query_parser::parse_filter_query_string(
    "name__icontains:%E5%BC%A0,age__gte:18",
    |field, op, value| got.push((field.to_string(), op.to_string(), value.to_string())),
).unwrap();
// got: [("name", "icontains", "张"), ("age", "gte", "18")]
```

### MySQL DDL パース

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

### 優先度付きイベントループ

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

// リクエストイベントは受信証を持ち、処理完了の待ち合わせに便利
let (ev, rx) = new_request_event("ping", Some("hello".to_string()));
loop_.submit(ev).unwrap();
let reply = rx.recv_timeout(Duration::from_secs(5)).unwrap();
loop_.stop();

assert_eq!(reply.data.as_deref(), Some("hello"));
```

### 関連データ紐付け(N+1 の回避)

```rust
use rust_utils::aggregator::populate;
use std::collections::HashMap;

struct Order { id: u32, user_name: Option<String> }

let mut orders = vec![Order { id: 1, user_name: None }];
let users: HashMap<u32, String> = [(1, "张三".to_string())].into();

populate(&mut orders, &users, |o| o.id, |o, name| o.user_name = Some(name));
assert_eq!(orders[0].user_name.as_deref(), Some("张三"));
```

### パスワードハッシュ

```rust
use rust_utils::password::{Argon2Crypto, Crypto};

let algo = Argon2Crypto;
let hash = algo.encrypt("s3cret!").unwrap();       // 標準 PHC 形式
assert!(algo.verify("s3cret!", &hash).unwrap());
```

### CAPTCHA サービス

7 種類のドライバ:数字/英数字/算術/中国語の 4 テキスト系と、スライド/クリック/回転の 3 インタラクティブ系。描画は完全にプログラム生成で、外部画像素材に依存しない(字形素材の詳細は `assets/captcha/README.md`)。テキスト系は PNG data URI を、インタラクティブ系は base64Captcha フロントエンド コンポーネント互換の JSON を返します。

```rust
use rust_utils::captcha::{Captcha, Config, DriverKind};

let cap = Captcha::with_config(Config::with_driver(DriverKind::Digit));
let (id, b64, answer) = cap.generate().unwrap();
// テキスト系は PNG data URI を返す。スライド/クリック/回転は
// JSON(JPEG 本体/PNG サムネイルを埋め込み)を返す
assert!(b64.starts_with("data:image/png;base64,"));
assert!(cap.verify(&id, &answer).unwrap()); // ワンタイム検証
```

`captcha-redis` feature を有効にすると、`Captcha::with_store(MemoryStore::new(), cfg)` を `RedisStore::new("redis://127.0.0.1/")?` に替えるだけで、サービス層 API はそのまま使えます。

### キャッシュ式バッチロード

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
loader.load_many(&[2, 3]); // すべてキャッシュ ヒット、再取得なし
assert_eq!(calls.load(Ordering::Relaxed), 1);
```

## 開発

```bash
cargo test                 # コアモジュールのテスト(ゼロ依存)
cargo test --all-features  # 全モジュールのテスト(297 ユニット + 28 ドキュメントテスト、1 例は ignore)
cargo clippy --all-features --all-targets
cargo fmt
```

## License

MIT
