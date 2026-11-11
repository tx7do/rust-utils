//! MaxMind GeoLite2 mmdb 读取器(feature `geoip`)。
//!
//! 行为说明:
//!
//! - 数据文件不由库内嵌,构造函数接收字节序列,由调用方自行加载;
//! - 查询失败返回错误,不终止进程;
//! - 命名表按语言代码取值,缺失时返回空串;
//! - 结果的 `ip` 字段不赋值,保持为空串。

use crate::geoip::{net_matches_prefix, GeoResult};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const DEFAULT_OUTPUT_LANGUAGE: &str = "zh-CN";

/// GeoLite2 客户端。
pub struct Client {
    db: maxminddb::Reader<Vec<u8>>,
    output_language: String,
}

impl Client {
    /// 从 mmdb 字节序列创建。
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, String> {
        let db = maxminddb::Reader::from_source(data).map_err(|e| e.to_string())?;
        Ok(Self {
            db,
            output_language: DEFAULT_OUTPUT_LANGUAGE.to_string(),
        })
    }

    /// 设置输出的语言,默认为 `zh-CN`。
    pub fn set_language(&mut self, code: &str) {
        self.output_language = code.to_string();
    }

    /// 通过 IP 获取地区。
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

        // 命名表缺失语言时一律取空串
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

/// 内网判定(IPv4 与 IPv6 网段表)。
/// IPv4 映射形态先折叠为 4 字节再匹配。
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

/// IPv4 内网网段(依次为私网/回环/链路本地)。
const V4_PRIVATE_NETS: [([u8; 4], u8); 5] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
];

/// IPv6 内网网段(依次为 ULA/链路本地/回环/已废弃的站点本地)。
const V6_PRIVATE_NETS: [([u8; 16], u8); 4] = [
    ([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
    ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128),
    ([0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// 加载 assets/geoip 下的测试库(与上游 go-utils 内嵌的是同一份文件)。
    /// 数据文件不随 crates.io 包分发,缺失时返回 None 让用例跳过。
    fn test_client() -> Option<Client> {
        let path = format!(
            "{}/assets/geoip/GeoLite2-City.mmdb",
            env!("CARGO_MANIFEST_DIR")
        );
        match std::fs::read(&path) {
            Ok(bytes) => Client::from_bytes(bytes)
                .map_err(|e| panic!("内置测试库加载失败({path}): {e}"))
                .ok(),
            Err(_) => {
                eprintln!("跳过:未找到测试数据 {path}");
                None
            }
        }
    }

    #[test]
    fn geolite_invalid_data() {
        assert!(Client::from_bytes(vec![1, 2, 3, 4]).is_err());
        assert!(Client::from_bytes(Vec::new()).is_err());
        assert!(Client::from_bytes(vec![b' '; 1024]).is_err());
    }

    #[test]
    fn geolite_query_chengdu_pin() {
        let Some(g) = test_client() else { return };
        // 同一 IP 上游 go-utils 断言中国/四川省/成都;但 MaxMind 更新数据后
        // zh-CN 省名变为"四川",上游测试未复核、当前在其仓库内已挂
        // (go test 实测库返回"四川")。此处钉死现库实际值。
        let ret = g.query("47.108.149.89").unwrap();
        assert_eq!(ret.country, "中国");
        assert_eq!(ret.province, "四川");
        assert_eq!(ret.city, "成都");
    }

    #[test]
    fn geolite_private_ip_short_circuits() {
        let Some(g) = test_client() else { return };
        for ip in [
            "127.0.0.1",
            "::1",
            "192.168.1.1",
            "10.0.0.7",
            "::ffff:172.16.3.4",
        ] {
            let ret = g.query(ip).unwrap();
            assert_eq!(ret.country, "局域网", "{ip}");
            assert_eq!(ret.province, "局域网", "{ip}");
            assert_eq!(ret.city, "局域网", "{ip}");
        }
    }

    #[test]
    fn geolite_invalid_ip_errors() {
        let Some(g) = test_client() else { return };
        assert_eq!(g.query("not-an-ip").unwrap_err(), "invalid ip address");
        assert_eq!(g.query("").unwrap_err(), "invalid ip address");
    }

    #[test]
    fn geolite_set_language_switches_output() {
        let Some(mut g) = test_client() else { return };
        // 默认 zh-CN
        let ret = g.query("47.108.149.89").unwrap();
        assert_eq!(ret.country, "中国");
        // 切 en 后同 IP 输出英文命名表
        g.set_language("en");
        let ret = g.query("47.108.149.89").unwrap();
        assert_eq!(ret.country, "China");
        assert_eq!(ret.province, "Sichuan");
        assert_eq!(ret.city, "Chengdu");
        // 不存在的语言 → 命名表缺失取空串
        g.set_language("xx-YY");
        let ret = g.query("47.108.149.89").unwrap();
        assert_eq!(ret.country, "");
    }

    #[test]
    fn geolite_query_result_ip_field_stays_empty() {
        let Some(g) = test_client() else { return };
        // 模块行为说明:结果的 ip 字段不赋值,保持为空串
        let ret = g.query("8.8.8.8").unwrap();
        assert_eq!(ret.ip, "");
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
            // IPv4 映射形态折叠为 4 字节后判定
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
