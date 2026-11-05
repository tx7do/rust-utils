//! 腾讯云短信(sms SendSms,TC3-HMAC-SHA256 签名),feature `notify`。
//! 对齐上游 `sms/tencent.go`。
//!
//! 与阿里云最大的协议差异:签名不只盖参数,还盖**整个 JSON 请求体**;
//! 手机号只认 E.164(`+86` 前缀由 [`super::normalize_phone_number`] 补齐)。
//!
//! 两级结论都要看:API 级错误在 `Response.Error`;API 成功后每条号码各有一个
//! `Code`,`Code=="Ok"`(这个 Ok 的大小写与阿里云不同)才是发出去了。

use std::io::Read;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::notify::NotifyError;

type HmacSha256 = Hmac<Sha256>;

/// API 主机。
pub const TENCENT_SMS_HOST: &str = "sms.tencentcloudapi.com";
/// 服务名(进签名 scope)。
pub const TENCENT_SMS_SERVICE: &str = "sms";
/// API 版本。
pub const TENCENT_SMS_VERSION: &str = "2021-01-11";
/// 地域缺省值。
pub const TENCENT_SMS_DEFAULT_REGION: &str = "ap-guangzhou";

/// 读对端应答的上限:结论是一个几百字节的小 JSON。
const ANSWER_BYTES: u64 = 4 * 1024;

/// 小写十六进制编码。
fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac 接受任意长度密钥");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// TC3-HMAC-SHA256 请求签名,可独立测试的纯函数。
///
/// 签名链四段派生(date → service → tc3_request → stringToSign),每段都是
/// HMAC-SHA256;Credential 里必须带 AccessKeyId,它参与"这份签名是谁的"的判定。
///
/// - `now_unix`:秒级 Unix 时间戳(注入以便离线测试);
/// - `payload`:完整的 JSON 请求体字节——签名盖住它。
pub fn sign_tc3(access_key_id: &str, access_secret: &str, now_unix: i64, payload: &[u8]) -> String {
    let date = chrono::DateTime::from_timestamp(now_unix, 0)
        .unwrap_or_default()
        .format("%Y-%m-%d")
        .to_string();
    let timestamp = now_unix.to_string();

    let hashed_payload = sha256_hex(payload);
    let canonical_request = format!(
        "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:{TENCENT_SMS_HOST}\n\ncontent-type;host\n{hashed_payload}"
    );
    let string_to_sign = format!(
        "TC3-HMAC-SHA256\n{timestamp}\n{date}/{TENCENT_SMS_SERVICE}/tc3_request\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(format!("TC3{access_secret}").as_bytes(), date.as_bytes());
    let k_service = hmac_sha256(&k_date, TENCENT_SMS_SERVICE.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"tc3_request");
    let signature = hex_encode(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!(
        "TC3-HMAC-SHA256 Credential={access_key_id}/{date}/{TENCENT_SMS_SERVICE}/tc3_request, SignedHeaders=content-type;host, Signature={signature}"
    )
}

/// 构造 SendSms 的 JSON 请求体,可独立测试的纯函数。
///
/// `phone` 收 E.164;`template_params` 为位置参数(按参数名排序取值,见
/// [`super::template_params_ordered`])。
pub fn build_payload(
    phone: &str,
    sdk_app_id: &str,
    sign_name: &str,
    template_id: &str,
    template_params: &[String],
) -> String {
    serde_json::json!({
        "PhoneNumberSet": [phone],
        "SmsSdkAppId": sdk_app_id,
        "SignName": sign_name,
        "TemplateId": template_id,
        "TemplateParamSet": template_params,
    })
    .to_string()
}

/// 构造请求头(键值对,顺序即发送顺序),可独立测试的纯函数。
///
/// `Authorization` 由 [`sign_tc3`] 派生;`X-TC-Region` 不参与签名
/// (TC3 在本实现里只签 content-type 与 host)。
pub fn build_headers(
    access_key_id: &str,
    access_secret: &str,
    region: &str,
    now_unix: i64,
    payload: &[u8],
) -> Vec<(String, String)> {
    vec![
        (
            "Content-Type".to_string(),
            "application/json; charset=utf-8".to_string(),
        ),
        ("X-TC-Action".to_string(), "SendSms".to_string()),
        ("X-TC-Version".to_string(), TENCENT_SMS_VERSION.to_string()),
        ("X-TC-Timestamp".to_string(), now_unix.to_string()),
        ("X-TC-Region".to_string(), region.to_string()),
        (
            "Authorization".to_string(),
            sign_tc3(access_key_id, access_secret, now_unix, payload),
        ),
    ]
}

/// 解析腾讯云应答,可独立测试的纯函数。成功返回 `SerialNo`。
pub fn parse_answer(status: u16, body: &str) -> Result<String, NotifyError> {
    #[derive(serde::Deserialize)]
    struct Answer {
        #[serde(rename = "Response")]
        response: ResponseBody,
    }
    #[derive(serde::Deserialize)]
    #[allow(non_snake_case)]
    struct ResponseBody {
        #[serde(rename = "Error")]
        error: Option<ApiError>,
        #[serde(rename = "SendStatusSet", default)]
        send_status_set: Vec<SendStatus>,
    }
    #[derive(serde::Deserialize)]
    #[allow(non_snake_case)]
    struct ApiError {
        #[serde(rename = "Code")]
        code: String,
        #[serde(rename = "Message")]
        message: String,
    }
    #[derive(serde::Deserialize)]
    #[allow(non_snake_case)]
    struct SendStatus {
        #[serde(rename = "Code")]
        code: String,
        #[serde(rename = "Message")]
        message: String,
        #[serde(rename = "SerialNo")]
        serial_no: String,
    }

    if !(200..300).contains(&status) {
        return Err(NotifyError::Delivery(format!(
            "peer answered {}: {}",
            status,
            truncate_answer(body)
        )));
    }
    let answer: Answer = serde_json::from_str(body)
        .map_err(|_| NotifyError::Delivery(format!("peer answer is not JSON: {body}")))?;
    if let Some(e) = answer.response.error {
        return Err(NotifyError::Delivery(format!(
            "provider answered Error={}: {}",
            e.code, e.message
        )));
    }
    if answer.response.send_status_set.is_empty() {
        return Err(NotifyError::Delivery(format!(
            "peer answered without SendStatusSet: {body}"
        )));
    }
    let st = &answer.response.send_status_set[0];
    if st.code != "Ok" {
        let message = if st.message.is_empty() { "no message" } else { &st.message };
        return Err(NotifyError::Delivery(format!(
            "provider answered Code={}: {message}",
            st.code
        )));
    }
    Ok(st.serial_no.clone())
}

/// 给单个手机号下发一条短信(由 [`super::SmsService`] 分派)。
///
/// `phone` 收 E.164(带 `+86` 前缀);`template_params` 为位置参数。
/// 成功返回厂商侧 `SerialNo`。
pub(super) fn send(
    agent: &ureq::Agent,
    cfg: &super::SmsConfig,
    phone: &str,
    template_params: &[String],
) -> Result<String, NotifyError> {
    let region = if cfg.region.is_empty() {
        TENCENT_SMS_DEFAULT_REGION.to_string()
    } else {
        cfg.region.clone()
    };
    let payload = build_payload(phone, &cfg.app_id, &cfg.sign_name, &cfg.template_code, template_params);
    let now = chrono::Utc::now().timestamp();
    let headers = build_headers(&cfg.access_key_id, &cfg.access_secret, &region, now, payload.as_bytes());

    let url = format!("https://{TENCENT_SMS_HOST}/");
    crate::notify::check_target(&url)?;
    let mut req = agent.post(&url);
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let resp = match req.send_string(&payload) {
        Ok(resp) => resp,
        Err(ureq::Error::Status(_, resp)) => resp,
        Err(e) => return Err(crate::notify::map_ureq_error(e)),
    };
    let status = resp.status();
    let answer = read_answer(resp);
    parse_answer(status, &answer)
}

/// 读对端应答(限长)。
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 对齐上游 `sms_test.go` 的 TestSignTencentTC3:钉值含 Credential 段的日期
    /// 派生(从时间戳取 UTC 日期)与整条四段 HMAC 链。
    #[test]
    fn test_sign_tc3_pinned_vector() {
        let now: i64 = 1_760_508_000; // 2025-10-15 UTC
        let payload = br#"{"PhoneNumberSet":["+8613800138000"]}"#;

        const WANT: &str = "TC3-HMAC-SHA256 Credential=AKIDtest/2025-10-15/sms/tc3_request, SignedHeaders=content-type;host, Signature=87a2b3a99f4de4ff56c14d845602b819bab7e2dc4e3413e5edc030c144e5195e";
        assert_eq!(sign_tc3("AKIDtest", "testsecret", now, payload), WANT);

        // 签名盖住请求体:body 变一个字节,Signature 段必须变(Credential 段不变)。
        let other = sign_tc3("AKIDtest", "testsecret", now, br#"{"PhoneNumberSet":["+8613800138001"]}"#);
        assert_ne!(other, WANT, "不同 payload 的签名必须不同");
        assert!(
            other.starts_with("TC3-HMAC-SHA256 Credential=AKIDtest/2025-10-15/sms/tc3_request"),
            "credential/date 前缀漂移: {other}"
        );

        // 密钥错了签名必须不同:这是"配错 Secret 会对端拒签"排障路径的根基。
        assert_ne!(sign_tc3("AKIDtest", "othersecret", now, payload), WANT);
    }

    /// 请求体与请求头:字段名对齐腾讯云 API,Authorization 由签名派生。
    #[test]
    fn test_build_payload_and_headers() {
        let payload = build_payload("+8613800138000", "140000", "签名", "SMS_1", &["123456".to_string()]);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["PhoneNumberSet"][0], "+8613800138000");
        assert_eq!(v["SmsSdkAppId"], "140000");
        assert_eq!(v["TemplateParamSet"][0], "123456");

        let now: i64 = 1_760_508_000;
        let headers = build_headers("AKIDtest", "testsecret", "ap-guangzhou", now, payload.as_bytes());
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
                .unwrap()
        };
        assert_eq!(get("Content-Type"), "application/json; charset=utf-8");
        assert_eq!(get("X-TC-Action"), "SendSms");
        assert_eq!(get("X-TC-Version"), TENCENT_SMS_VERSION);
        assert_eq!(get("X-TC-Timestamp"), "1760508000");
        assert_eq!(get("X-TC-Region"), "ap-guangzhou");
        assert!(get("Authorization").starts_with("TC3-HMAC-SHA256 Credential=AKIDtest/2025-10-15/sms/tc3_request"));
    }

    /// 应答解析:API 级 Error、号码级 Code(ok 大小写敏感)、SerialNo 进回执。
    #[test]
    fn test_parse_answer() {
        // 成功:SerialNo 进回执
        let serial = parse_answer(
            200,
            r#"{"Response":{"RequestId":"req-1","SendStatusSet":[{"Code":"Ok","Message":"send success","SerialNo":"sn-1"}]}}"#,
        )
        .unwrap();
        assert_eq!(serial, "sn-1");
        // API 级错误
        let err = parse_answer(
            200,
            r#"{"Response":{"Error":{"Code":"AuthFailure.SignatureFailure","Message":"签名错误"}}}"#,
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("AuthFailure.SignatureFailure"));
        // 号码级失败:Code 大小写敏感,非 "Ok" 即失败
        let err = parse_answer(
            200,
            r#"{"Response":{"SendStatusSet":[{"Code":"Failed.SignatureIncorrectOrUnapproved","Message":"签名不正确","SerialNo":""}]}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("签名不正确"));
        // 缺 SendStatusSet
        let err = parse_answer(200, r#"{"Response":{"RequestId":"r"}}"#).unwrap_err();
        assert!(err.to_string().contains("without SendStatusSet"));
        // HTTP 层失败 / 非 JSON
        assert!(matches!(parse_answer(502, "bad gateway").unwrap_err(), NotifyError::Delivery(_)));
        assert!(parse_answer(200, "<html/>").unwrap_err().to_string().contains("not JSON"));
    }

    /// Host/Service/缺省 Region 钉死:TC3 签名串里含 Host 与 Service,漂移会全量签名失败。
    #[test]
    fn test_tencent_sms_constants() {
        assert_eq!(TENCENT_SMS_HOST, "sms.tencentcloudapi.com");
        assert_eq!(TENCENT_SMS_SERVICE, "sms");
        assert_eq!(TENCENT_SMS_DEFAULT_REGION, "ap-guangzhou");
    }
}
