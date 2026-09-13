//! IP 归属地查询(对应 Go 版 `geoip` 包,feature `geoip`)。
//!
//! 三个后端与 Go 版一一对应:
//!
//! - [`qqwry`]:纯真 qqwry.dat 读取器(索引二分、重定向链、
//!   GB18030 解码、地址省/市切分);
//! - [`ip2region`]:xdb v2 查询器(向量索引 + 段索引二分,
//!   IPv4/IPv6、查询器池与缓存策略);
//! - [`geolite`]:MaxMind GeoLite2 mmdb 读取器(`maxminddb`)。
//!
//! 与 Go 版的固有差异:
//!
//! - 数据文件不由库内嵌(Go 版 go:embed 了 62 MB mmdb、51 MB xdb、
//!   10 MB qqwry.dat),各构造函数改为接收字节序列,由调用方自行
//!   加载;
//! - 各读取器的越界访问由 Go 的 panic 改为返回错误/空结果;
//!   qqwry 索引二分在低于首条目起始 IP 的输入上会死循环,
//!   改为按未找到返回;
//! - `geolite` 查询失败时 Go 版 `log.Fatal` 直接杀进程,
//!   改为返回错误。

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub mod geolite;
pub mod ip2region;
pub mod qqwry;

/// 归属地查询结果(字段名与上游 `geoip.Result` 的 json tag 一致)。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoResult {
    pub ip: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
}

/// 解析 IP 字符串为字节序列,对应上游 `net.ParseIP` + `To4`/`To16`
/// 的组合语义:IPv4 与 IPv4 映射形态(`::ffff:a.b.c.d`)的 IPv6
/// 折叠为 4 字节网络序,其余 IPv6 为 16 字节网络序;不可解析返回
/// `None`(由各调用方映射为自身的错误文案)。
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
