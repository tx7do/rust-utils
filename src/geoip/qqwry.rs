//! 纯真 qqwry.dat 读取器(feature `geoip`)。
//!
//! 数据格式:文件头两个 LE u32 给出索引区起止偏移(止偏移指向
//! 最后一条索引条目);索引条目 7 字节(LE u32 起始 IP + LE u24
//! 记录偏移);记录为 [LE u32 结束 IP][国家字段][运营商字段],
//! 两个字段或为 GB18030 内联 NUL 结尾串,或为
//! [0x01|0x02][LE u24] 重定向标记(记录级国家字段另有 0x01 双重
//! 重定向形态)。
//!
//! 行为说明:
//!
//! - 数据文件不由库内嵌,构造函数接收字节序列,由调用方自行加载;
//! - 越界读取返回零偏移/空串,不 panic;
//! - 运营商字段的位置按读出的国家串长度推进;
//! - 索引二分对单条目(startPos==endPos)与区间未按 7 字节对齐的
//!   文件,未命中条目起始 IP 时按未找到返回,不死循环;命中条目
//!   起始 IP 时返回其记录,低于首条目起始 IP 的查询按二分收敛
//!   返回首条记录;
//! - 地址省/市切分基于终止符字面匹配实现,见 [`spilt_address`]。

use crate::geoip::{net_matches_prefix, parse_ip_bytes, GeoResult};
use std::net::{IpAddr, Ipv4Addr};

/// 索引条目长度。
const IP_RECORD_LENGTH: u32 = 7;

/// 重定向标记。
const REDIRECT_MODE1: u8 = 0x01;
const REDIRECT_MODE2: u8 = 0x02;

/// qqwry 客户端。
pub struct Client {
    data: Vec<u8>,
    start_pos: u32,
    end_pos: u32,
    /// 索引条目数(区间倒挂时按无符号回绕)。
    pub ip_num: i64,
}

impl Client {
    /// 从 qqwry.dat 字节序列创建。
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, String> {
        if data.len() < 8 {
            return Err("qqwry: invalid data file".to_string());
        }
        let start_pos = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end_pos = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let ip_num = i64::from(end_pos.wrapping_sub(start_pos)) / i64::from(IP_RECORD_LENGTH) + 1;
        Ok(Self {
            data,
            start_pos,
            end_pos,
            ip_num,
        })
    }

    /// 归属地查询。
    pub fn query(&self, query_ip: &str) -> Result<GeoResult, String> {
        // IP 与国家字段无条件先行赋值
        let mut res = GeoResult {
            ip: query_ip.to_string(),
            country: "中国".to_string(),
            ..Default::default()
        };

        let ip32 = parse_ip(query_ip)?;
        if is_private_ip(query_ip) {
            // 内网 IP 的省/市置"局域网"并提前返回
            res.province = "局域网".to_string();
            res.city = "局域网".to_string();
            return Ok(res);
        }

        let offset = self.locate_ip(ip32);
        if offset == 0 {
            return Err("ip not found".to_string());
        }

        let offset = offset.wrapping_add(4); // 跳过记录的结束 IP 字段
        let (country_bytes, isp_pos) = self.read_country_field(offset);

        if !country_bytes.is_empty() {
            let area = gb18030_decode(&country_bytes).trim().to_string();
            let areas = spilt_address(&area);
            match areas.len() {
                2 => {
                    res.province = areas[0].clone();
                    res.city = areas[1].clone();
                }
                1 => {
                    res.city = areas[0].clone();
                }
                _ => {
                    res.city = area;
                }
            }
        }

        if let Some(isp_bytes) = self.isp_field(isp_pos) {
            let isp = gb18030_decode(&isp_bytes).trim().to_string();
            if !isp.is_empty() {
                // CZ88.NET 占位串清空
                res.isp = if isp.contains("CZ88.NET") {
                    String::new()
                } else {
                    isp
                };
            }
        }

        Ok(res)
    }

    /// 读一条索引条目(起始 IP LE u32 +
    /// 记录偏移 LE u24;越界返回零)。
    fn locate_read(&self, offset: u32) -> (u32, u32) {
        let end = offset.wrapping_add(IP_RECORD_LENGTH) as usize;
        let Some(b) = self.data.get(offset as usize..end) else {
            return (0, 0);
        };
        let ip = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let rec = u32::from(b[4]) | (u32::from(b[5]) << 8) | (u32::from(b[6]) << 16);
        (ip, rec)
    }

    /// 索引二分定位。返回记录偏移,0 表示未找到。
    /// 退化与未对齐区间的行为见模块文档。
    fn locate_ip(&self, ip: u32) -> u32 {
        let mut i = self.start_pos;
        let mut j = self.end_pos;
        let mut offset = 0u32;
        loop {
            if j <= i {
                // 退化区间(单条目或区间倒挂):
                // 仅命中该条目起始 IP 时返回其记录
                let (start_ip, rec) = self.locate_read(i);
                if start_ip == ip {
                    offset = rec;
                }
                break;
            }
            if j.wrapping_sub(i) == IP_RECORD_LENGTH {
                // 二分收敛到相邻条对:候选为 i 条记录,
                // 以 j 条目的起始 IP 为上界
                let mid = i;
                let (_, rec) = self.locate_read(mid);
                offset = rec;
                let (next_ip, _) = self.locate_read(mid.wrapping_add(IP_RECORD_LENGTH));
                if ip < next_ip {
                    break;
                }
                offset = 0;
                break;
            }
            let mid =
                i.wrapping_add(((j.wrapping_sub(i) / IP_RECORD_LENGTH) >> 1) * IP_RECORD_LENGTH);
            if mid <= i || mid >= j {
                // 区间未按条目对齐:同上,仅等值命中时返回
                let (start_ip, rec) = self.locate_read(i);
                if start_ip == ip {
                    offset = rec;
                }
                break;
            }
            let (start_ip, rec) = self.locate_read(mid);
            if start_ip > ip {
                j = mid;
            } else if start_ip < ip {
                i = mid;
            } else {
                offset = rec;
                break;
            }
        }
        offset
    }

    /// 读 NUL 结尾串(无 NUL 或越界返回空)。
    fn read_string(&self, offset: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = offset as usize;
        while i < self.data.len() {
            if self.data[i] == 0 {
                out.extend_from_slice(&self.data[offset as usize..i]);
                break;
            }
            i += 1;
        }
        out
    }

    /// 读 LE u24(越界返回 0)。
    fn read_u24(&self, offset: u32) -> u32 {
        let end = offset.wrapping_add(3) as usize;
        let Some(b) = self.data.get(offset as usize..end) else {
            return 0;
        };
        u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16)
    }

    /// 国家字段:返回
    /// (国家串字节, 运营商字段位置)。0x01/0x02 为重定向标记,
    /// 其余为首字节即串首字符的内联形态。内联形态的推进长度按
    /// 读出的国家串长度(见模块文档)。
    fn read_country_field(&self, offset: u32) -> (Vec<u8>, u32) {
        let mode = self.data.get(offset as usize).copied().unwrap_or(0);
        match mode {
            REDIRECT_MODE1 => {
                let mut pos = self.read_u24(offset.wrapping_add(1));
                let inner = self.data.get(pos as usize).copied().unwrap_or(0);
                let mut pos_ca = pos;
                if inner == REDIRECT_MODE2 {
                    pos_ca = self.read_u24(pos.wrapping_add(1));
                    pos = pos.wrapping_add(4);
                }
                let country = self.read_string(pos_ca);
                if inner != REDIRECT_MODE2 {
                    pos = pos.wrapping_add(country.len() as u32).wrapping_add(1);
                }
                (country, pos)
            }
            REDIRECT_MODE2 => {
                let country = self.read_string(self.read_u24(offset.wrapping_add(1)));
                (country, offset.wrapping_add(4))
            }
            _ => {
                let country = self.read_string(offset);
                let isp_pos = offset.wrapping_add(country.len() as u32).wrapping_add(1);
                (country, isp_pos)
            }
        }
    }

    /// 运营商字段:重定向标记后跟 LE u24,
    /// 否则内联;重定向解析为 0 时不读取。
    fn isp_field(&self, mut isp_pos: u32) -> Option<Vec<u8>> {
        let mode = self.data.get(isp_pos as usize).copied().unwrap_or(0);
        if mode == REDIRECT_MODE1 || mode == REDIRECT_MODE2 {
            isp_pos = self.read_u24(isp_pos.wrapping_add(1));
        }
        if isp_pos == 0 {
            return None;
        }
        Some(self.read_string(isp_pos))
    }
}

/// 解析 IPv4 为大端 u32(IPv4 映射形态折叠为 4 字节,
/// 其余一律按非 IPv4 拒绝)。
fn parse_ip(query_ip: &str) -> Result<u32, String> {
    let bytes = parse_ip_bytes(query_ip).ok_or("ip is not ipv4")?;
    if bytes.len() != 4 {
        return Err("ip is not ipv4".to_string());
    }
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// 内网判定(解析失败或含 `:` 视为
/// 内网,随后检查 IPv4 内网段)。
fn is_private_ip(ip_str: &str) -> bool {
    if ip_str.contains(':') {
        return true;
    }
    let Ok(IpAddr::V4(v4)) = ip_str.parse::<IpAddr>() else {
        return true;
    };
    for (net, bits) in [
        ([10, 0, 0, 0], 8u8),
        ([172, 16, 0, 0], 12),
        ([192, 168, 0, 0], 16),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
    ] {
        if net_matches_prefix(IpAddr::V4(v4), IpAddr::V4(Ipv4Addr::from(net)), bits) {
            return true;
        }
    }
    false
}

/// GB18030 解码(非法字节按替换字符处理)。
fn gb18030_decode(src: &[u8]) -> String {
    let (cow, _, _) = encoding_rs::GB18030.decode(src);
    cow.into_owned()
}

/// 地址省/市切分:自每个起点先消耗一个以上非换行字符,再按各
/// 终止符(省/市/自治区/自治州/盟/县/区/管委会/街道/镇/乡)的
/// 最左出现截取;换行阻断其所在起点的匹配,命中后从匹配末尾
/// 继续扫描。
fn spilt_address(addr: &str) -> Vec<String> {
    const TERMINATORS: [&str; 11] = [
        "省",
        "市",
        "自治区",
        "自治州",
        "盟",
        "县",
        "区",
        "管委会",
        "街道",
        "镇",
        "乡",
    ];
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < addr.len() {
        let mut hit: Option<(usize, usize)> = None;
        for (i, ch) in addr[pos..].char_indices() {
            if ch == '\n' {
                // `.` 不匹配换行,该起点无匹配
                break;
            }
            if i == 0 {
                continue; // `.+?` 的下界:先消耗一个字符
            }
            if let Some(term) = TERMINATORS
                .iter()
                .find(|term| addr[pos + i..].starts_with(*term))
            {
                hit = Some((pos + i, term.len()));
                break;
            }
        }
        match hit {
            Some((term_pos, term_len)) => {
                out.push(addr[pos..term_pos + term_len].to_string());
                pos = term_pos + term_len;
            }
            None => {
                let Some(ch) = addr[pos..].chars().next() else {
                    break;
                };
                pos += ch.len_utf8();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gbk(s: &str) -> Vec<u8> {
        let (cow, _, _) = encoding_rs::GB18030.encode(s);
        cow.into_owned()
    }

    /// 追加一个内联形态的记录体:[4B 结束 IP 哨兵][国家 GB18030]
    /// [0x00][运营商][0x00],返回国家串的绝对偏移。
    fn put_inline_record(buf: &mut Vec<u8>, country: &[u8], isp: &[u8]) -> usize {
        buf.extend_from_slice(&[0u8; 4]);
        let country_offset = buf.len();
        buf.extend_from_slice(country);
        buf.push(0);
        buf.extend_from_slice(isp);
        buf.push(0);
        country_offset
    }

    /// 追加一个国家重定向形态的记录体:[4B 哨兵][0x02][LE u24
    /// 目标][运营商][0x00]。
    fn put_redirect_record(buf: &mut Vec<u8>, target: usize, isp: &[u8]) {
        buf.extend_from_slice(&[0u8; 4]);
        buf.push(REDIRECT_MODE2);
        buf.extend_from_slice(&(target as u32).to_le_bytes()[..3]);
        buf.extend_from_slice(isp);
        buf.push(0);
    }

    /// 追加一个 mode1 重定向形态的记录体:[4B 哨兵][0x01][LE u24
    /// 目标][填充 0x00]。
    fn put_mode1_record(buf: &mut Vec<u8>, target: usize) {
        buf.extend_from_slice(&[0u8; 4]);
        buf.push(REDIRECT_MODE1);
        buf.extend_from_slice(&(target as u32).to_le_bytes()[..3]);
        buf.push(0);
    }

    /// 追加一个内联形态的内层 blob(mode1 重定向的目标布局,
    /// 无记录体的结束 IP 哨兵):[国家 GB18030][0x00][运营商][0x00]。
    fn put_inline_blob(buf: &mut Vec<u8>, country: &[u8], isp: &[u8]) {
        buf.extend_from_slice(country);
        buf.push(0);
        buf.extend_from_slice(isp);
        buf.push(0);
    }

    /// 追加一个 mode2 形态的内层 blob:[0x02][LE u24 目标]
    /// [运营商][0x00]。
    fn put_redirect_blob(buf: &mut Vec<u8>, target: usize, isp: &[u8]) {
        buf.push(REDIRECT_MODE2);
        buf.extend_from_slice(&(target as u32).to_le_bytes()[..3]);
        buf.extend_from_slice(isp);
        buf.push(0);
    }

    /// 主夹具:7 条索引。A/X/Y 为内联国家串(切分两段/一段/零段,
    /// X/Y 兼带空白裁剪与 CZ88.NET 清空),B 为国家重定向(指向
    /// A 的国家串),Z/W 为 mode1 重定向(分别指向内联内层与
    /// mode2 内层 blob),末条为不可达的哑条目。
    fn build_fixture() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 8 + 7 * 7];
        let rec_a = buf.len();
        let country_a = put_inline_record(&mut buf, &gbk("浙江省杭州市"), b"ISP-A");
        let rec_x = buf.len();
        put_inline_record(&mut buf, &gbk("  某某盟  "), b"  ISP-X  ");
        let rec_y = buf.len();
        put_inline_record(&mut buf, &gbk("某某某"), b"CZ88.NET");
        let rec_b = buf.len();
        put_redirect_record(&mut buf, country_a, b"ISP-B");
        let inner_inline = buf.len();
        put_inline_blob(&mut buf, &gbk("丙丙省丁丁市"), b"ISP-M1");
        let inner_mode2 = buf.len();
        put_redirect_blob(&mut buf, country_a, b"ISP-M2");
        let rec_z = buf.len();
        put_mode1_record(&mut buf, inner_inline);
        let rec_w = buf.len();
        put_mode1_record(&mut buf, inner_mode2);
        let rec_dummy = buf.len();
        put_inline_record(&mut buf, &gbk("无"), b"ISP-D");

        // 头:索引区起止(止偏移指向最后一条条目)
        let start: u32 = 8;
        let end: u32 = 8 + 6 * 7;
        buf[0..4].copy_from_slice(&start.to_le_bytes());
        buf[4..8].copy_from_slice(&end.to_le_bytes());

        // 索引区:起始 IP(LE u32)+ 记录偏移(LE u24)
        let ips = [
            0x0100_0001u32,
            0x6400_0001,
            0x9600_0001,
            0xC800_0001,
            0xD200_0001,
            0xDC00_0001,
            0xFB00_0001,
        ];
        let recs = [rec_a, rec_x, rec_y, rec_b, rec_z, rec_w, rec_dummy];
        for (i, (ip, rec)) in ips.into_iter().zip(recs).enumerate() {
            let slot = 8 + i * 7;
            buf[slot..slot + 4].copy_from_slice(&ip.to_le_bytes());
            buf[slot + 4..slot + 7].copy_from_slice(&rec.to_le_bytes()[..3]);
        }
        buf
    }

    /// 单条目夹具:startPos==endPos(仅命中条目起始 IP 的查询
    /// 返回记录)。
    fn build_single_entry_fixture() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 8 + 7];
        put_inline_record(&mut buf, &gbk("浙江省杭州市"), b"ISP-A");
        buf[0..4].copy_from_slice(&8u32.to_le_bytes());
        buf[4..8].copy_from_slice(&8u32.to_le_bytes());
        buf[8..12].copy_from_slice(&0x0505_0505u32.to_le_bytes());
        buf[12..15].copy_from_slice(&15u32.to_le_bytes()[..3]);
        buf
    }

    /// 未对齐夹具:索引区差值(10 字节)非 7 的倍数(未命中一律
    /// 按未找到返回)。
    fn build_misaligned_fixture() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 8 + 7 * 2];
        put_inline_record(&mut buf, &gbk("浙江省杭州市"), b"ISP-A");
        buf[0..4].copy_from_slice(&8u32.to_le_bytes());
        buf[4..8].copy_from_slice(&18u32.to_le_bytes());
        buf[8..12].copy_from_slice(&0x0100_0001u32.to_le_bytes());
        buf[12..15].copy_from_slice(&22u32.to_le_bytes()[..3]);
        buf
    }

    #[test]
    fn qqwry_fixture_queries() {
        let client = Client::from_bytes(build_fixture()).unwrap();
        assert_eq!(client.ip_num, 7);

        // A:内联国家,切分两段;1.0.0.1 为段首含端
        for ip in ["1.0.0.5", "1.0.0.1"] {
            let r = client.query(ip).unwrap();
            assert_eq!(r.ip, ip, "{ip}");
            assert_eq!(r.country, "中国", "{ip}");
            assert_eq!(r.province, "浙江省", "{ip}");
            assert_eq!(r.city, "杭州市", "{ip}");
            assert_eq!(r.isp, "ISP-A", "{ip}");
        }
        // 低于首条目起始 IP:二分收敛后返回首条记录
        let r = client.query("0.9.9.9").unwrap();
        assert_eq!(r.province, "浙江省");
        assert_eq!(r.city, "杭州市");
        assert_eq!(r.isp, "ISP-A");
        // X:国家串/运营商带首尾空白(验证 TrimSpace),切分一段 → 仅市
        let r = client.query("100.0.0.5").unwrap();
        assert_eq!(r.province, "");
        assert_eq!(r.city, "某某盟");
        assert_eq!(r.isp, "ISP-X");
        // Y:国家串无切分后缀 → 整串作市;运营商为 CZ88.NET 占位 → 清空
        let r = client.query("150.0.0.5").unwrap();
        assert_eq!(r.province, "");
        assert_eq!(r.city, "某某某");
        assert_eq!(r.isp, "");
        // B:国家重定向 → A 的国家串,运营商内联
        let r = client.query("200.0.0.5").unwrap();
        assert_eq!(r.province, "浙江省");
        assert_eq!(r.city, "杭州市");
        assert_eq!(r.isp, "ISP-B");
        // Z:mode1 → 内联内层;运营商位置按国家串长度推进
        let r = client.query("210.0.0.5").unwrap();
        assert_eq!(r.province, "丙丙省");
        assert_eq!(r.city, "丁丁市");
        assert_eq!(r.isp, "ISP-M1");
        // W:mode1 → mode2 内层(链式重定向)
        let r = client.query("220.0.0.5").unwrap();
        assert_eq!(r.province, "浙江省");
        assert_eq!(r.city, "杭州市");
        assert_eq!(r.isp, "ISP-M2");
    }

    #[test]
    fn qqwry_out_of_range() {
        let client = Client::from_bytes(build_fixture()).unwrap();
        // 末条索引为不可达的哑条目:不低于其起始 IP 一律未找到
        for ip in ["251.0.0.5", "252.0.0.1", "255.255.255.255"] {
            assert_eq!(client.query(ip).unwrap_err(), "ip not found", "{ip}");
        }
        // 非法/非 IPv4 输入(映射形态之外的 IPv6 一律拒绝)
        for ip in ["abc", "1.2.3", "1.2.3.4.5", "::1", "fe80::1", "2001:db8::1"] {
            assert_eq!(client.query(ip).unwrap_err(), "ip is not ipv4", "{ip}");
        }
    }

    #[test]
    fn qqwry_private_short_circuit() {
        let client = Client::from_bytes(build_fixture()).unwrap();
        // 内网段命中,或含 ":"(映射形态折叠为 4 字节后仍短路)
        for ip in [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.9.9",
            "127.0.0.1",
            "169.254.1.1",
            "::ffff:8.8.8.8",
            "::ffff:192.168.1.1",
        ] {
            let r = client.query(ip).unwrap();
            assert_eq!(r.province, "局域网", "{ip}");
            assert_eq!(r.city, "局域网", "{ip}");
            assert_eq!(r.isp, "", "{ip}");
        }
    }

    #[test]
    fn qqwry_is_private_unit() {
        let yes = [
            "192.168.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "127.0.0.1",
            "169.254.0.1",
            "::1",
            "fe80::1",
            "::ffff:1.2.3.4",
            "1.2.3",
            "abc",
        ];
        for ip in yes {
            assert!(is_private_ip(ip), "{ip}");
        }
        let no = ["8.8.8.8", "1.1.1.1", "172.32.0.1", "0.0.0.0"];
        for ip in no {
            assert!(!is_private_ip(ip), "{ip}");
        }
    }

    #[test]
    fn qqwry_invalid_data() {
        assert!(Client::from_bytes(vec![1, 2, 3]).is_err());
        // 全零头:零距区间,条目数为 1,任何查询未找到
        let client = Client::from_bytes(vec![0u8; 16]).unwrap();
        assert_eq!(client.ip_num, 1);
        assert_eq!(client.query("1.2.3.4").unwrap_err(), "ip not found");
        assert_eq!(client.query("0.0.0.0").unwrap_err(), "ip not found");
    }

    #[test]
    fn qqwry_single_entry_fixture() {
        let client = Client::from_bytes(build_single_entry_fixture()).unwrap();
        assert_eq!(client.ip_num, 1);
        // 命中唯一条目的起始 IP:等值命中返回其记录
        let r = client.query("5.5.5.5").unwrap();
        assert_eq!(r.province, "浙江省");
        assert_eq!(r.city, "杭州市");
        assert_eq!(r.isp, "ISP-A");
        // 其余查询:按未找到返回
        for ip in ["5.5.5.6", "9.9.9.9", "1.2.3.4", "0.0.0.0"] {
            assert_eq!(client.query(ip).unwrap_err(), "ip not found", "{ip}");
        }
    }

    #[test]
    fn qqwry_misaligned_fixture() {
        let client = Client::from_bytes(build_misaligned_fixture()).unwrap();
        // 首条目起始 IP 的等值命中:返回其记录
        let r = client.query("1.0.0.1").unwrap();
        assert_eq!(r.province, "浙江省");
        assert_eq!(r.city, "杭州市");
        // 未命中的查询:按未找到返回
        assert_eq!(client.query("1.0.0.5").unwrap_err(), "ip not found");
    }

    #[test]
    fn spilt_address_unit() {
        // 懒惰前缀 + 首个终止符,换行阻断所在起点的匹配
        assert_eq!(
            spilt_address("浙江省杭州市西湖区"),
            vec!["浙江省", "杭州市", "西湖区"]
        );
        assert_eq!(spilt_address("广西壮族自治区"), vec!["广西壮族自治区"]);
        assert_eq!(spilt_address("某某市"), vec!["某某市"]);
        // 无终止符、或终止符前无消耗字符 → 无匹配
        assert!(spilt_address("abc").is_empty());
        assert!(spilt_address("某某某某").is_empty());
        assert!(spilt_address("省").is_empty());
        assert_eq!(spilt_address("某某省市"), vec!["某某省"]);
        // 换行阻断其所在起点的匹配,其后文本另起匹配
        assert_eq!(spilt_address("浙江省\n杭州市"), vec!["浙江省", "杭州市"]);
        assert_eq!(spilt_address("\n浙江省"), vec!["浙江省"]);
        assert_eq!(spilt_address("某\n某市"), vec!["某市"]);
    }
}
