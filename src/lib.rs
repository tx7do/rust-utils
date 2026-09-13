//! rust-utils —— 从 [tx7do/go-utils](https://github.com/tx7do/go-utils) 移植的 Rust 工具箱。
//!
//! 核心模块零依赖;重依赖的能力(时间、随机、密码哈希、加密、JWT 等)通过
//! feature 按需启用,见 README。
//!
//! 各模块与 Go 包的对应关系:
//!
//! | Rust 模块        | Go 包           | feature          |
//! |------------------|-----------------|------------------|
//! | [`byteutil`]     | byteutil        | 默认             |
//! | [`stringcase`]   | stringcase      | 默认             |
//! | [`stringutil`]   | stringutil      | 默认             |
//! | [`sliceutil`]    | sliceutil       | 默认             |
//! | [`maputil`]      | maputils        | 默认             |
//! | [`mathutil`]     | math            | 默认             |
//! | [`pagination`]   | pagination      | 默认             |
//! | [`cryptocurrency`] | cryptocurrency | 默认            |
//! | [`bank_card`]    | bank_card       | `bank-card`      |
//! | [`query_parser`] | query_parser    | `json`           |
//! | [`ddl_parser`]   | ddl_parser      | 默认             |
//! | [`eventloop`]    | eventloop       | 默认             |
//! | [`aggregator`]   | aggregator      | 默认             |
//! | [`id`]           | id              | 默认(`uuid` 可选) |
//! | [`fsutil`]       | ioutil          | 默认(`glob` 可选) |
//! | [`dateutil`]     | dateutil        | `chrono`         |
//! | [`timeutil`]     | timeutil        | `chrono`         |
//! | [`random`]       | rand            | `rand`           |
//! | [`name_generator`] | name_generator | `name-generator` |
//! | [`slug`]         | slug            | `slug`           |
//! | [`password`]     | password        | `password`       |
//! | [`crypto`]       | crypto          | `crypto`         |
//! | [`sm`]           | crypto(SM 部分) | `sm`            |
//! | [`captcha`]      | captcha         | `captcha`(Redis 落地用 `captcha-redis`) |
//! | [`geoip`]        | geoip           | `geoip`           |
//! | [`translator`]   | translator      | `translator`      | 翻译器四后端:百度(MD5 签名)/阿里(RPC 签名)/谷歌(v1 裸端点、v2/v3 REST 等价)/火山(HMAC-SHA256 派生链);请求构造与签名可离线验证 |
//! | [`distlock`]     | distlock        | `distlock`        | 分布式锁:Locker/Lock 抽象与获取选项(Redis 落地用 `distlock-redis`,按 bsm/redislock 协议逐式复刻;etcd 后端未移植) |
//! | [`jwt`]          | jwtutil         | `jwt`            |

#![allow(clippy::module_inception)]

pub mod aggregator;
pub mod byteutil;
pub mod cryptocurrency;
pub mod ddl_parser;
pub mod eventloop;
pub mod fsutil;
pub mod id;
pub mod maputil;
pub mod mathutil;
pub mod pagination;
pub mod query_parser;
pub mod sliceutil;
pub mod stringcase;
pub mod stringutil;

#[cfg(feature = "bank-card")]
pub mod bank_card;

// 标准 base64(带填充),供 captcha/crypto/sm/translator 模块共用。
#[cfg(any(
    feature = "captcha",
    feature = "crypto",
    feature = "sm",
    feature = "translator"
))]
pub(crate) mod base64util {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
            out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6 & 0x3F) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(n & 0x3F) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        let mut vals = Vec::with_capacity(s.len());
        for c in s.bytes() {
            match c {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                    vals.push(ALPHABET.iter().position(|a| *a == c).unwrap() as u32)
                }
                b'=' | b'\n' | b'\r' => {}
                _ => return Err(format!("invalid base64 character: {}", c as char)),
            }
        }
        let mut out = Vec::with_capacity(vals.len() * 3 / 4);
        for chunk in vals.chunks(4) {
            let n = match chunk.len() {
                4 => (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6) | chunk[3],
                3 => (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6),
                2 => (chunk[0] << 18) | (chunk[1] << 12),
                _ => return Err("invalid base64 length".to_string()),
            };
            out.push((n >> 16 & 0xFF) as u8);
            if chunk.len() >= 3 {
                out.push((n >> 8 & 0xFF) as u8);
            }
            if chunk.len() == 4 {
                out.push((n & 0xFF) as u8);
            }
        }
        Ok(out)
    }
}

#[cfg(feature = "captcha")]
pub mod captcha;
#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "chrono")]
pub mod dateutil;
#[cfg(feature = "distlock")]
pub mod distlock;
#[cfg(feature = "fieldmask")]
pub mod fieldmask;
#[cfg(feature = "geoip")]
pub mod geoip;
#[cfg(feature = "jwt")]
pub mod jwt;
#[cfg(feature = "name-generator")]
pub mod name_generator;
#[cfg(feature = "rand")]
pub mod random;
#[cfg(feature = "slug")]
pub mod slug;
#[cfg(feature = "sm")]
pub mod sm;
#[cfg(feature = "chrono")]
pub mod timeutil;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "translator")]
pub mod translator;
