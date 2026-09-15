//! IP 归属地查询(feature `geoip`)。
//!
//! 提供三个后端:
//!
//! - [`qqwry`]:纯真 qqwry.dat 读取器(索引二分、重定向链、
//!   GB18030 解码、地址省/市切分);
//! - [`ip2region`]:xdb v2 查询器(向量索引 + 段索引二分,
//!   IPv4/IPv6、查询器池与缓存策略);
//! - [`geolite`]:MaxMind GeoLite2 mmdb 读取器(`maxminddb`)。
//!
//! 实现要点:
//!
//! - 数据文件不由库内嵌,各构造函数接收字节序列,由调用方自行
//!   加载;
//! - 越界/畸形输入返回错误、零偏移或空串,不 panic;
//!   qqwry 索引二分对单条目与未对齐索引区间的未命中输入按
//!   未找到返回,不死循环;
//! - `geolite` 查询失败返回错误,不终止进程。

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub mod geolite;
pub mod ip2region;
pub mod qqwry;

/// 归属地查询结果(json 字段名为小写的 `ip`/`country`/`province`/`city`/`isp`)。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoResult {
    pub ip: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
}

/// 解析 IP 字符串为字节序列:IPv4 与 IPv4 映射形态
/// (`::ffff:a.b.c.d`)的 IPv6 折叠为 4 字节网络序,其余 IPv6 为
/// 16 字节网络序;不可解析返回 `None`(由各调用方映射为自身的
/// 错误文案)。
pub(crate) fn parse_ip_bytes(s: &str) -> Option<Vec<u8>> {
    let ip: IpAddr = s.parse().ok()?;
    Some(match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.octets().to_vec(),
            None => v6.octets().to_vec(),
        },
    })
}

/// 点分前缀匹配(IP 是否落在 `net/bits` 网段内)。
pub(crate) fn net_matches_prefix(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(v4), IpAddr::V4(n4)) => {
            if bits == 0 {
                return true;
            }
            if bits > 32 {
                return false;
            }
            let mask = if bits == 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - bits)
            };
            (u32::from(v4) & mask) == (u32::from(n4) & mask)
        }
        (IpAddr::V6(v6), IpAddr::V6(n6)) => {
            if bits == 0 {
                return true;
            }
            if bits > 128 {
                return false;
            }
            let a = u128::from(v6);
            let b = u128::from(n6);
            let mask = if bits == 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - bits)
            };
            (a & mask) == (b & mask)
        }
        _ => false,
    }
}
