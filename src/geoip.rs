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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_ip_bytes() {
        // IPv4 → 4 字节网络序
        assert_eq!(
            parse_ip_bytes("1.2.3.4").as_deref(),
            Some(&[1, 2, 3, 4][..])
        );
        // IPv4 映射形态的 IPv6 折叠为 4 字节
        assert_eq!(
            parse_ip_bytes("::ffff:1.2.3.4").as_deref(),
            Some(&[1, 2, 3, 4][..])
        );
        // 普通 IPv6 → 16 字节
        let mut loopback = vec![0u8; 15];
        loopback.push(1);
        assert_eq!(parse_ip_bytes("::1"), Some(loopback));
        assert_eq!(parse_ip_bytes("::").as_deref(), Some(&[0u8; 16][..]));
        // 不可解析
        assert_eq!(parse_ip_bytes("abc"), None);
        assert_eq!(parse_ip_bytes("1.2.3"), None);
        assert_eq!(parse_ip_bytes(""), None);
    }

    #[test]
    fn test_net_matches_prefix_v4() {
        let net = IpAddr::from(Ipv4Addr::new(192, 168, 0, 0));
        let ip_in = IpAddr::from(Ipv4Addr::new(192, 168, 10, 20));
        let ip_out = IpAddr::from(Ipv4Addr::new(192, 169, 0, 1));
        assert!(net_matches_prefix(ip_in, net, 16));
        assert!(!net_matches_prefix(ip_out, net, 16));
        // /32 精确匹配
        assert!(net_matches_prefix(
            IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)),
            32
        ));
        assert!(!net_matches_prefix(
            IpAddr::from(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)),
            32
        ));
        // /0 匹配一切,/33 与 /255 越界不匹配
        assert!(net_matches_prefix(ip_out, net, 0));
        assert!(!net_matches_prefix(ip_in, net, 33));
        assert!(!net_matches_prefix(ip_in, net, 255));
    }

    #[test]
    fn test_net_matches_prefix_v6_and_mixed() {
        let net: IpAddr = "2001:db8::".parse().unwrap();
        let ip_in: IpAddr = "2001:db8::dead:beef".parse().unwrap();
        let ip_out: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(net_matches_prefix(ip_in, net, 32));
        assert!(!net_matches_prefix(ip_out, net, 32));
        assert!(net_matches_prefix(ip_out, net, 0));
        assert!(!net_matches_prefix(ip_in, net, 129));
        // v4 与 v6 混用恒不匹配
        let v4: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!net_matches_prefix(v4, net, 0));
        assert!(!net_matches_prefix(ip_in, v4, 0));
    }
}
