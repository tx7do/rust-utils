//! MaxMind GeoLite2 mmdb 读取器(对应 Go 版 `geoip/geolite`,
//! feature `geoip`)。
//!
//! 与上游的差异:
//!
//! - 数据文件不由库内嵌(Go 版 `go:embed` 了 62 MB 的
//!   GeoLite2-City.mmdb),改为构造函数接收字节序列;
//! - 查询失败时 Go 版 `log.Fatal` 直接杀进程,改为返回错误;
//! - 命名表按语言代码取值缺失时返回空串,对应上游 Go map
//!   索引的零值语义;
//! - 结果的 `ip` 字段上游从不赋值,保持为空串。

use crate::geoip::{net_matches_prefix, GeoResult};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const DEFAULT_OUTPUT_LANGUAGE: &str = "zh-CN";

/// GeoLite2 客户端(上游 `geolite.Client`)。
pub struct Client {
    db: maxminddb::Reader<Vec<u8>>,
    output_language: String,
}

impl Client {
    /// 从 mmdb 字节序列创建(上游 `NewClient` + 内嵌数据)。
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, String> {
        let db = maxminddb::Reader::from_source(data).map_err(|e| e.to_string())?;
        Ok(Self {
            db,
            output_language: DEFAULT_OUTPUT_LANGUAGE.to_string(),
        })
    }

    /// 设置输出的语言,默认为 `zh-CN`(上游 `SetLanguage`)。
    pub fn set_language(&mut self, code: &str) {
        self.output_language = code.to_string();
    }

    /// 通过 IP 获取地区(上游 `Client.Query`)。
    pub fn query(&self, raw_ip: &str) -> Result<GeoResult, String> {
        let mut ret = GeoResult::default();
        let Ok(ip) = raw_ip.parse::<IpAddr>() else {
            return Err("invalid ip address".to_string());
        };

        if is_private_ip(ip) {
            ret.country = "局域网".to_string();
            ret.province = "局域网".to_string();
            ret.city = "局域网".to_string();
            return Ok(ret);
        }

        let record = self
            .db
            .lookup::<maxminddb::geoip2::City>(ip)
            .map_err(|e| e.to_string())?;

        // 上游 `Names[lang]` 的 map 零值语义:缺失语言一律取空串
        let country_names = record.country.as_ref().and_then(|c| c.names.as_ref());
        ret.country = take_name(country_names, &self.output_language);
        if let Some(subdivisions) = &record.subdivisions {
            if !subdivisions.is_empty() {
                let names = subdivisions[0].names.as_ref();
                ret.province = take_name(names, &self.output_language);
            }
        }
        let city_names = record.city.as_ref().and_then(|c| c.names.as_ref());
        ret.city = take_name(city_names, &self.output_language);

        Ok(ret)
    }
}

/// 从命名表按语言取值,缺失返回空串。
fn take_name(names: Option<&BTreeMap<&str, &str>>, lang: &str) -> String {
    names
        .and_then(|m| m.get(lang))
        .copied()
        .unwrap_or("")
        .to_string()
}

/// 内网判定(上游 `geolite.IsPrivateIP`:IPv4 与 IPv6 网段表)。
/// 上游 `net.IPNet.Contains` 会先对 IPv4 映射形态做 `To4` 折叠,
/// 此处保持同一语义。
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    let folded = match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
    };
    match folded {
        IpAddr::V4(_) => V4_PRIVATE_NETS
            .iter()
            .any(|(net, bits)| net_matches_prefix(folded, IpAddr::V4(Ipv4Addr::from(*net)), *bits)),
        IpAddr::V6(_) => V6_PRIVATE_NETS
            .iter()
            .any(|(net, bits)| net_matches_prefix(folded, IpAddr::V6(Ipv6Addr::from(*net)), *bits)),
    }
}

/// IPv4 内网网段(上游列表,依次为私网/回环/链路本地)。
const V4_PRIVATE_NETS: [([u8; 4], u8); 5] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
];

/// IPv6 内网网段(上游列表,依次为 ULA/链路本地/回环/已废弃的站点本地)。
const V6_PRIVATE_NETS: [([u8; 16], u8); 4] = [
    ([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
    ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128),
    ([0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geolite_invalid_data() {
        assert!(Client::from_bytes(vec![1, 2, 3, 4]).is_err());
        assert!(Client::from_bytes(Vec::new()).is_err());
        assert!(Client::from_bytes(vec![b' '; 1024]).is_err());
    }

    #[test]
    fn geolite_is_private_table() {
        let yes = [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "fec0::1",
            // IPv4 映射形态按上游 Contains 的 To4 折叠语义
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
        ];
        for ip in yes {
            assert!(is_private_ip(ip.parse().unwrap()), "{ip}");
        }
        let no = [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "0.0.0.0",
            "2001:db8::1",
            "::ffff:8.8.8.8",
        ];
        for ip in no {
            assert!(!is_private_ip(ip.parse().unwrap()), "{ip}");
        }
    }
}
