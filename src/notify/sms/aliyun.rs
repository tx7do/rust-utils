//! 阿里云短信(Dysmsapi SendSms),feature `notify`。对齐上游 `sms/aliyun.go`。
//!
//! 协议是阿里云 RPC 风格:全部参数排序拼接做 HMAC-SHA1 签名,请求本身是一张
//! 普通表单——签名只管"请求没被篡改",与 GET/POST 形态无关。
//!
//! 阿里云把业务结论放在 HTTP 200 的 body 里(`Code=="OK"` 才是发出去了),
//! 只看状态码会把"对方没收"记成发送成功。

use std::collections::HashMap;
use std::io::Read;

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::notify::NotifyError;

type HmacSha1 = Hmac<Sha1>;

/// SendSms 端点(RPC 风格,POST 表单)。
pub const ALIYUN_SMS_ENDPOINT: &str = "https://dysmsapi.aliyuncs.com/";
/// API 版本。
pub const ALIYUN_SMS_VERSION: &str = "2017-05-26";
/// 地域缺省值。
pub const ALIYUN_SMS_DEFAULT_REGION: &str = "cn-hangzhou";

/// 读对端应答的上限:结论是一个几百字节的小 JSON。
const ANSWER_BYTES: u64 = 4 * 1024;

/// 阿里云规范的百分号编码(RFC3986):空格用 `%20`(不是 `+`)、星号要转义、
/// 波浪号不转义——Go 的 QueryEscape 三处都与规范不同,逐条修回来。
pub fn percent_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// 表单成分编码(Go `url.QueryEscape` 语义):字母数字与 `-_.~` 直通,
/// 空格作 `+`,其余 `%XX` 大写十六进制。
fn query_escape(s: &str) -> String {
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

/// 标准(base64,带填充)编码——签名与摘要进 HTTP 头/表单用。
pub(super) fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6 & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 0x3F) as usize] as char } else { '=' });
    }
    out
}

/// 阿里云 RPC 风格签名(HMAC-SHA1),可独立测试的纯函数。
///
/// stringToSign = `"POST&%2F&"` + percent_encode(按参数名排序的 canonical query),
/// 签名密钥是 `AccessKeySecret + "&"`——那个悬空的 `&` 是协议的一部分,不是笔误。
pub fn sign_rpc(params: &[(String, String)], access_secret: &str) -> String {
    let mut keys: Vec<&str> = params.iter().map(|(k, _)| k.as_str()).collect();
    keys.sort_unstable();
    let value_of = |k: &str| {
        params
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };

    let mut canonical = String::new();
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            canonical.push('&');
        }
        canonical.push_str(&percent_encode(k));
        canonical.push('=');
        canonical.push_str(&percent_encode(value_of(k)));
    }

    let string_to_sign =
        format!("POST&{}&{}", percent_encode("/"), percent_encode(&canonical));
    let key = format!("{access_secret}&");
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key.as_bytes()).expect("hmac 接受任意长度密钥");
    mac.update(string_to_sign.as_bytes());
    base64_encode(&mac.finalize().into_bytes())
}

/// 构造 SendSms 的完整表单体(含 `Signature`),可独立测试的纯函数。
///
/// - `template_param_json`:模板参数整表序列化的 JSON(模板里写 `${name}`);
/// - `nonce` / `timestamp`:随机串与 UTC 时间戳(`YYYY-MM-DDTHH:MM:SSZ`),
///   由调用方注入以便离线测试。
// 参数面对齐上游 Go SendSms 的调用面(凭据/模板/目标/时间源各一),不再归并。
#[allow(clippy::too_many_arguments)]
pub fn build_form(
    access_key_id: &str,
    access_secret: &str,
    sign_name: &str,
    template_code: &str,
    region: &str,
    phone: &str,
    template_param_json: &str,
    nonce: &str,
    timestamp: &str,
) -> String {
    let params = vec![
        ("AccessKeyId".to_string(), access_key_id.to_string()),
        ("Action".to_string(), "SendSms".to_string()),
        ("Format".to_string(), "JSON".to_string()),
        ("PhoneNumbers".to_string(), phone.to_string()),
        ("RegionId".to_string(), region.to_string()),
        ("SignName".to_string(), sign_name.to_string()),
        ("SignatureMethod".to_string(), "HMAC-SHA1".to_string()),
        ("SignatureNonce".to_string(), nonce.to_string()),
        ("SignatureVersion".to_string(), "1.0".to_string()),
        ("TemplateCode".to_string(), template_code.to_string()),
        ("TemplateParam".to_string(), template_param_json.to_string()),
        ("Timestamp".to_string(), timestamp.to_string()),
        ("Version".to_string(), ALIYUN_SMS_VERSION.to_string()),
    ];
    let signature = sign_rpc(&params, access_secret);
    let mut params = params;
    params.push(("Signature".to_string(), signature));
    form_encode(&params)
}

/// 解析阿里云应答,可独立测试的纯函数。
///
/// 阿里云把业务结论放在 body 的 `Code` 里(HTTP 恒 200):`Code=="OK"` 才是
/// 发出去了,回执带 `BizId`;其余一律投递失败。
pub fn parse_answer(status: u16, body: &str) -> Result<String, NotifyError> {
    if !(200..300).contains(&status) {
        return Err(NotifyError::Delivery(format!(
            "peer answered {}: {}",
            status,
            truncate_answer(body)
        )));
    }
    #[derive(serde::Deserialize)]
    #[allow(non_snake_case)]
    struct Answer<'a> {
        #[serde(rename = "Code", default, borrow)]
        code: &'a str,
        #[serde(rename = "Message", default)]
        message: &'a str,
        #[serde(rename = "BizId", default)]
        biz_id: &'a str,
    }
    let answer: Answer<'_> = serde_json::from_str(body)
        .map_err(|_| NotifyError::Delivery(format!("peer answer is not JSON: {body}")))?;
    if answer.code != "OK" {
        let message = if answer.message.is_empty() { "no message" } else { answer.message };
        return Err(NotifyError::Delivery(format!(
            "provider answered Code={}: {message}",
            answer.code
        )));
    }
    Ok(answer.biz_id.to_string())
}

/// 给单个手机号下发一条短信(由 [`super::SmsService`] 分派)。
///
/// `phone` 收国内裸号(无 `+86` 前缀,由 [`super::normalize_phone_number`] 归一);
/// `template_params` 按参数名整表序列化为 `TemplateParam` JSON(模板里写 `${name}`)。
/// 成功返回厂商侧 `BizId`。
pub(super) fn send(
    agent: &ureq::Agent,
    cfg: &super::SmsConfig,
    phone: &str,
    template_params: &HashMap<String, String>,
) -> Result<String, NotifyError> {
    let region = if cfg.region.is_empty() { ALIYUN_SMS_DEFAULT_REGION } else { &cfg.region };
    let template_param = serde_json::to_string(template_params)
        .map_err(|e| NotifyError::NotConfigured(format!("encode template param failed: {e}")))?;
    let body = build_form(
        &cfg.access_key_id,
        &cfg.access_secret,
        &cfg.sign_name,
        &cfg.template_code,
        region,
        phone,
        &template_param,
        &random_nonce(),
        &utc_timestamp(),
    );

    crate::notify::check_target(ALIYUN_SMS_ENDPOINT)?;
    let resp = match agent
        .post(ALIYUN_SMS_ENDPOINT)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body)
    {
        Ok(resp) => resp,
        // 4xx/5xx 在 ureq 里走 Err 分支:响应体还带着,照常读出归类。
        Err(ureq::Error::Status(_, resp)) => resp,
        Err(e) => return Err(crate::notify::map_ureq_error(e)),
    };
    let status = resp.status();
    let answer = read_answer(resp);
    parse_answer(status, &answer)
}

/// 读对端应答(限长),对端可能回一整页 HTML。
fn read_answer(resp: ureq::Response) -> String {
    let mut buf = Vec::new();
    let mut reader = resp.into_reader().take(ANSWER_BYTES);
    let _ = reader.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// 进错误文案的响应片段截断:按字符边界安全截到 512 字节。
fn truncate_answer(body: &str) -> String {
    const LIMIT: usize = 512;
    if body.len() <= LIMIT {
        return body.to_string();
    }
    let mut end = LIMIT;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &body[..end])
}

/// `SignatureNonce`:16 随机字节的十六进制串。
fn random_nonce() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("系统随机源不可用时短信无从谈起");
    let mut out = String::with_capacity(32);
    for b in buf {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `Timestamp`:UTC 的 `YYYY-MM-DDTHH:MM:SSZ`(阿里云要的就是秒级 GMT 形态)。
fn utc_timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 对齐上游 `sms_test.go` 的 TestSignAliyunRPC:钉值锁的是"参数排序 +
    /// 百分号编码 + HMAC-SHA1(secret&)"这一整条链,任何一环被改签名就全量漂移。
    #[test]
    fn test_sign_rpc_pinned_vector() {
        let params: Vec<(String, String)> = [
            ("AccessKeyId", "testkey"),
            ("Action", "SendSms"),
            ("Format", "JSON"),
            ("PhoneNumbers", "13800138000"),
            ("RegionId", "cn-hangzhou"),
            ("SignName", "签名测试"),
            ("SignatureMethod", "HMAC-SHA1"),
            ("SignatureNonce", "nonce-1"),
            ("SignatureVersion", "1.0"),
            ("TemplateCode", "SMS_1234567"),
            ("TemplateParam", r#"{"code":"123456"}"#),
            ("Timestamp", "2026-10-15T06:00:00Z"),
            ("Version", "2017-05-26"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        const WANT: &str = "gS9g6UDJP7wPmNOLjjv07DkaWNk=";
        assert_eq!(sign_rpc(&params, "testsecret"), WANT);

        // 拼装顺序无关性:canonical query 按参数名排序,调用方先放谁不影响结果。
        let mut shuffled = params.clone();
        shuffled.reverse();
        assert_eq!(sign_rpc(&shuffled, "testsecret"), WANT);
    }

    /// 对齐上游 TestAliyunPercentEncode:RFC3986 与 QueryEscape 的三处分歧各钉一条。
    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("a b"), "a%20b"); // 空格:%20,不是 +
        assert_eq!(percent_encode("a*b"), "a%2Ab"); // 星号必须转义
        assert_eq!(percent_encode("a~b"), "a~b"); // 波浪号不转义
        assert_eq!(percent_encode("签名"), "%E7%AD%BE%E5%90%8D");
        assert_eq!(percent_encode(r#"{"x"}"#), "%7B%22x%22%7D");
    }

    /// 表单体:键排序、值经 QueryEscape、Signature 收尾在册。
    #[test]
    fn test_build_form_shape() {
        let body = build_form(
            "testkey",
            "testsecret",
            "签名测试",
            "SMS_1234567",
            "cn-hangzhou",
            "13800138000",
            r#"{"code":"123456"}"#,
            "nonce-1",
            "2026-10-15T06:00:00Z",
        );
        // 键按字母序出站(Go url.Values.Encode 语义)
        let keys: Vec<&str> = body.split('&').map(|kv| kv.split('=').next().unwrap()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "表单键必须有序");
        assert!(body.starts_with("AccessKeyId=testkey&Action=SendSms"));
        assert!(body.contains("PhoneNumbers=13800138000"));
        assert!(body.contains(&format!("Version={ALIYUN_SMS_VERSION}")));
        // 签名本身进表单:用同一批参数复算,值必须能在 body 里找到
        let sig = body
            .split('&')
            .find(|kv| kv.starts_with("Signature="))
            .map(|kv| kv.trim_start_matches("Signature=").to_string())
            .expect("Signature 必须在表单里");
        assert!(!sig.is_empty());
    }

    /// 应答解析:Code==OK 才是成功;业务结论在 200 的 body 里。
    #[test]
    fn test_parse_answer() {
        // 成功:BizId 进回执
        let biz = parse_answer(
            200,
            r#"{"Code":"OK","Message":"OK","RequestId":"req-1","BizId":"biz-9"}"#,
        )
        .unwrap();
        assert_eq!(biz, "biz-9");
        // 业务失败:200 但 Code != OK
        let err = parse_answer(200, r#"{"Code":"isv.BUSINESS_LIMIT_CONTROL","Message":"触发分钟级流控"}"#)
            .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("isv.BUSINESS_LIMIT_CONTROL"));
        // 空 Message 兜底
        let err = parse_answer(200, r#"{"Code":"isv.TEMPLATE_MISSING_PARAMETERS"}"#).unwrap_err();
        assert!(err.to_string().contains("no message"), "{err}");
        // HTTP 层失败
        let err = parse_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)));
        // 非 JSON 应答
        let err = parse_answer(200, "<html>gateway</html>").unwrap_err();
        assert!(err.to_string().contains("not JSON"));
    }

    /// 官方 Endpoint 与缺省 Region 钉死(尾部斜杠是上游口径,签名只串 path 不含 host)。
    #[test]
    fn test_aliyun_sms_endpoint_constants() {
        assert_eq!(ALIYUN_SMS_ENDPOINT, "https://dysmsapi.aliyuncs.com/");
        assert_eq!(ALIYUN_SMS_DEFAULT_REGION, "cn-hangzhou");
    }
}
