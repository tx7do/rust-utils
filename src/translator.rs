//! 翻译器,feature `translator`。
//!
//! 四个后端:
//!
//! - [`baidu`]:百度翻译开放平台(表单 POST,MD5 签名);
//! - [`alibaba`]:阿里云机器翻译(按官方 API 的 RPC 签名算法
//!   构造请求,签名随 URL 查询串提交,正文为表单 POST);
//! - [`google`]:谷歌翻译(v1 为裸 HTTP 端点拼接调用,v2/v3 为
//!   REST 调用);
//! - [`volc`]:火山引擎翻译(HMAC-SHA256 四级密钥派生链签名 +
//!   JSON POST;另有批量入口)。
//!
//! 各后端的细节见各自模块文档;整体行为要点:
//!
//! - 请求行为:四后端均为单次请求,不自动重试;错误一律为字符串;
//! - 签名与编码:URL 编码对 ASCII 字母数字与 `-_.~` 直通,空格
//!   作 `+`,其余按 `%XX` 大写十六进制;有序表单/查询串按键名
//!   排序;语言标签原样透传,不做 BCP47 校验;
//! - 响应解析:对越界/畸形数据一律返回错误,不 panic;
//! - `alibaba` 的 `SignatureNonce` 取 UUID v4 的 32 位十六进制;
//! - `volc` 提供 `Display` 实现,输出脱敏的调试字符串;
//! - 各后端支持的语言代码表见对应云厂商的官方文档。

pub mod alibaba;
pub mod baidu;
pub mod google;
pub mod volc;

/// 翻译器接口。
pub trait Translator {
    /// 翻译。
    fn translate(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, String>;
}

/// URL 查询/表单成分编码(按字节处理:ASCII 字母数字与
/// `-_.~` 直通,空格作 `+`,其余 `%XX` 大写十六进制)。
pub(crate) fn query_escape(s: &str) -> String {
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

/// 参数对的有序表单/查询串编码(按键名排序,键与值均经
/// `query_escape` 编码)。
pub(crate) fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut pairs: Vec<_> = pairs.to_vec();
    pairs.sort();
    let mut out = String::new();
    for (key, value) in &pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&query_escape(key));
        out.push('=');
        out.push_str(&query_escape(value));
    }
    out
}

/// 小写十六进制编码。
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
