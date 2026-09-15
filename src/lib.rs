//! rust-utils —— 通用 Rust 工具箱。
//!
//! 设计原则:**核心模块零依赖**(只依赖 `std`),重依赖的能力(时间、随机、
//! 密码哈希、加密、JWT 等)通过 feature 按需启用;全 crate
//! `#![forbid(unsafe_code)]`;边界读取(geoip、ddl_parser 等)对越界与
//! 畸形输入一律返回错误或空结果,不做 panic。
//!
//! 各模块与 feature 的对应关系:
//!
//! | 模块 | feature | 说明 |
//! |------|---------|------|
//! | [`byteutil`] | 默认 | 整数/字节互转、ASCII 大小写 |
//! | [`stringcase`] | 默认 | 驼峰/蛇形/烤肉串转换,识别缩写词与数字段 |
//! | [`stringutil`] | 默认 | 宽松数值/布尔解析、JSON 字段值重写 |
//! | [`sliceutil`] | 默认 | 查找族、交集/差集/并集、去重、分块 |
//! | [`maputil`] | 默认 | keys/values/merge/drop/filter |
//! | [`mathutil`] | 默认 | 统计量、手写正态分布(Gaussian)、Erfc/Ierfc |
//! | [`pagination`] | 默认 | 分页偏移量 |
//! | [`cryptocurrency`] | 默认 | 加密货币钱包地址格式校验 |
//! | [`query_parser`] | `json` | Django 风格 `field__op` 过滤/排序解析 |
//! | [`ddl_parser`] | 默认 | MySQL `CREATE TABLE` 解析(手写词法,零依赖) |
//! | [`eventloop`] | 默认 | 单线程优先级事件循环,支持帧驱动模式 |
//! | [`aggregator`] | 默认 | 关联数据回填(列表/树)+ 并行执行器 + 缓存式批量加载 |
//! | [`id`] | 默认(`uuid` 可选) | 雪花 ID、订单号、机器码(内置 SHA-256)、UUID v4/v7 |
//! | [`fsutil`] | 默认(`glob` 可选) | 文件/路径辅助 |
//! | [`dateutil`] | `chrono` | 日粒度取整、区间判断 |
//! | [`timeutil`] | `chrono` | 今天/昨天/本月/上月区间、时间差、格式转换 |
//! | [`random`] | `rand` | 随机工具:加权/别名表/骰子/抖动/正态/手机号等 |
//! | [`name_generator`] | `name-generator` | 随机昵称与中英日姓名(内嵌词库) |
//! | [`slug`] | `slug` | URL slug(unicode 转写) |
//! | [`password`] | `password` | PBKDF2/bcrypt/argon2/HMAC/SHA 哈希策略 |
//! | [`crypto`] | `crypto` | AES-CBC/AES-GCM/HMAC/SHA-2、PKCS#7 填充 |
//! | [`jwt`] | `jwt` | JWT 生成/解析/校验/刷新(HS256) |
//! | [`bank_card`] | `bank-card` | Luhn 校验 + BIN 查询(内嵌记录) |
//! | [`captcha`] | `captcha`(Redis 落地用 `captcha-redis`) | 图形验证码:四类文本驱动 + 滑块/点选/旋转,自绘渲染 |
//! | [`geoip`] | `geoip` | IP 归属地三后端:qqwry、ip2region xdb v2、MaxMind mmdb,数据由调用方加载 |
//! | [`translator`] | `translator` | 翻译器四后端:百度/阿里/谷歌/火山,请求构造与签名可离线验证 |
//! | [`distlock`] | `distlock`(Redis 落地用 `distlock-redis`) | 分布式锁 Locker/Lock 抽象与获取选项 |
//! | [`tls`] | `tls` | 从 PEM 文件/字节组装 rustls 服务端/客户端配置(单向/双向) |
//! | [`fieldmask`] | `fieldmask` | 字段掩码:嵌套掩码树 + filter/prune/overwrite/validate |
//! | [`sm`] | `sm` | 国密 SM2(C1C3C2/ASN.1)/SM3/SM4-CBC |

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
