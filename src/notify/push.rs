//! 移动端厂商推送渠道:APNs / FCM / 华为 / 荣耀 / 小米 / OPPO / vivo。
//! 对齐上游 `push` 包(`push.go` + 各厂商文件)。
//!
//! 全部裸 HTTP(零厂商 SDK)。每个渠道发送**单台设备**
//! ([`Message::target`](crate::notify::Message) = 设备令牌/regId),多设备的遍历、
//! 失效令牌清理与结果聚合是调用方编排层的事。
//!
//! 错误语义沿 [`NotifyError`] 惯例分三类:
//! - 配置类([`NotifyError::NotConfigured`]):凭据缺失、目标为空等,拨号之前拦下;
//! - 令牌失效([`NotifyError::InvalidToken`]):厂商明确说这个 regId/token 已经作废
//!   (应用卸载/实例删除)——调用方应删设备行自清理,不算投递失败重试;
//! - 其余([`NotifyError::Delivery`]):拨过号被拒或链路故障,按投递失败处理。
//!
//! # APNs 的 HTTP/2 限制
//!
//! APNs 强制 HTTP/2,而本 crate 的出站客户端(ureq)只支持 HTTP/1.1。因此
//! [`apns::Apns`] 的签名(ES256 provider token)与请求构造完整实现且全部离线
//! 可测,但 `Apns` 的 `Service::send`(trait 实现)一律返回 [`NotifyError::NotConfigured`]——
//! 需要真发 APNs 的部署请外接 HTTP/2 客户端,用本模块导出的纯函数自行组装请求。
//!
//! 各厂商一览:
//!
//! | 渠道 | 类型 | 鉴权 | 令牌失效判定 |
//! |------|------|------|--------------|
//! | Apple APNs | [`apns::Apns`] | ES256 JWT(受限,见上) | 410 或 reason=Unregistered/BadDeviceToken |
//! | Firebase | [`fcm::Fcm`] | 服务账号 OAuth2(RS256 JWT) | HTTP 404/410 |
//! | 华为/荣耀 | [`huawei::Huawei`] / [`huawei::Honor`] | client_credentials OAuth2 | code 0x80200xxx 段 |
//! | 小米 | [`xiaomi::Xiaomi`] | `Authorization: Key=` | code 20201/20202 |
//! | OPPO | [`oppo::Oppo`] | 两段式 auth token | code 2008 |
//! | vivo | [`vivo::Vivo`] | MD5 签名四元组 | code 10080 |

pub mod apns;
pub mod fcm;
pub mod huawei;
pub mod oppo;
pub mod vivo;
pub mod xiaomi;

pub use apns::{Apns, ApnsConfig};
pub use fcm::{Fcm, FcmConfig};
pub use huawei::{Honor, Huawei, HuaweiConfig};
pub use oppo::{Oppo, OppoConfig};
pub use vivo::{Vivo, VivoConfig};
pub use xiaomi::{Xiaomi, XiaomiConfig};

use std::io::Read;

use crate::notify::{check_target, map_ureq_error, NotifyError};

/// 读对端应答的上限:结论都是几百字节的小 JSON/文本。
pub(super) const ANSWER_LIMIT: u64 = 8 << 10;

/// POST 一次出站请求:先过 SSRF 预检,发送 `body`,返回 `(状态码, 限长响应体)`。
///
/// 传输错误经 [`map_ureq_error`] 归类;4xx/5xx 不算传输错误——响应体照常读出,
/// 交由各渠道的解析函数按厂商语义归类。
pub(super) fn post(
    agent: &ureq::Agent,
    url: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<(u16, String), NotifyError> {
    check_target(url)?;
    let mut req = agent.post(url);
    for (name, value) in headers {
        req = req.set(name, value);
    }
    let resp = match req.send_string(body) {
        Ok(resp) => resp,
        // 4xx/5xx 在 ureq 里走 Err 分支:响应体还带着,照常读出归类。
        Err(ureq::Error::Status(_, resp)) => resp,
        Err(e) => return Err(map_ureq_error(e)),
    };
    let status = resp.status();
    let mut buf = Vec::new();
    let mut reader = resp.into_reader().take(ANSWER_LIMIT);
    let _ = reader.read_to_end(&mut buf);
    Ok((status, String::from_utf8_lossy(&buf).into_owned()))
}

/// 进错误文案的响应片段截断:对端可能回一整页 HTML。
pub(super) fn err_snippet(body: &str) -> String {
    const LIMIT: usize = 256;
    if body.len() <= LIMIT {
        return body.to_string();
    }
    let mut end = LIMIT;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &body[..end])
}

/// rune 安全截断(厂商标题有字符数上限,超了直接 400)。
pub(super) fn truncate_runes(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// URL 查询/表单成分编码(Go `url.QueryEscape` 语义):字母数字与 `-_.~` 直通,
/// 空格作 `+`,其余 `%XX` 大写十六进制。
pub(super) fn query_escape(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// 参数对的有序表单编码(Go `url.Values.Encode()` 语义):按键名排序。
pub(super) fn form_encode(pairs: &[(String, String)]) -> String {
    let mut pairs = pairs.to_vec();
    pairs.sort();
    let mut out = String::new();
    for (k, v) in &pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&query_escape(k));
        out.push('=');
        out.push_str(&query_escape(v));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 对齐上游 oppo_test.go 的 TestOppoTitleTruncatedTo28Runes:按 rune 不按
    /// 字节截断,中文标题不会腰斩出半个字。
    #[test]
    fn test_truncate_runes() {
        let long = "重".repeat(40);
        let truncated = truncate_runes(&long, 28);
        assert_eq!(truncated.chars().count(), 28);
        assert_eq!(truncated, "重".repeat(28));
        // ASCII 混排同样安全
        assert_eq!(truncate_runes("hello", 3), "hel");
    }

    /// err_snippet:256 字节上限,字符边界安全。
    #[test]
    fn test_err_snippet() {
        assert_eq!(err_snippet("short"), "short");
        let long = "长".repeat(200); // 400 字节
        let snippet = err_snippet(&long);
        assert!(snippet.len() < 300, "{}", snippet.len());
        assert!(snippet.ends_with('…'));
    }

    /// 表单编码:排序 + QueryEscape 语义(空格为 +,~ 不转义)。
    #[test]
    fn test_form_encode() {
        let pairs = vec![
            ("b".to_string(), "2".to_string()),
            ("a".to_string(), "x y".to_string()),
        ];
        assert_eq!(form_encode(&pairs), "a=x+y&b=2");
        assert_eq!(query_escape("a~b*c"), "a~b%2Ac");
    }
}
