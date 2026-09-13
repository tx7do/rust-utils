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
#[cfg(feature = "captcha")]
pub mod captcha;
#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "chrono")]
pub mod dateutil;
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
