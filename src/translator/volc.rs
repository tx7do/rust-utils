//! 火山引擎翻译后端(对应 Go 版 `translator/volc`,feature
//! `translator`)。
//!
//! 上游语义:JSON POST 至 `translate.volcengineapi.com`,附
//! `X-Date`(UTC 时间戳)、`X-Content-Sha256`(请求体 SHA-256
//! 的 base64)、`Authorization`(规范请求经 HMAC-SHA256 四级
//! 密钥派生链签名)。单条与批量两个入口,批量校验条数一致。
//!
//! 与上游的差异:上游的请求调试打印(含凭据与签名头)未移植;
//! `Host` 头由 HTTP 客户端按 URL 自动设置(上游显式设置,值
//! 相同);`VerifySignature` 调试辅助由签名测试覆盖。

use crate::base64util;
use crate::translator::hex_encode;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::time::Duration;

const VOLC_SERVICE: &str = "translate";
const VOLC_HOST: &str = "translate.volcengineapi.com";

type HmacSha256 = Hmac<Sha256>;

/// 火山引擎翻译器(上游 `volc.Translator`:区域默认
/// `cn-north-1`,上游 `WithRegion`/`WithHTTPClient` 语义;密钥
/// 去除末尾换行)。
pub struct Translator {
    access_key: String,
    secret_key: String,
    region: String,
    client: ureq::Agent,
}

impl Translator {
    /// 创建(上游 `NewTranslator`:空密钥报错,密钥依序去除末尾
    /// `\n` 与 `\r\n`;上游客户端 30 秒超时)。
    pub fn new(access_key: &str, secret_key: &str) -> Result<Self, String> {
        if access_key.is_empty() || secret_key.is_empty() {
            return Err("accessKey和secretKey不能为空".to_string());
        }
        // 上游:两处 TrimSuffix 依序执行(单次各至多去除一个后缀)
        let mut secret_key = secret_key.to_string();
        for suffix in ["\n", "\r\n"] {
            if let Some(stripped) = secret_key.strip_suffix(suffix) {
                secret_key = stripped.to_string();
            }
        }
        Ok(Self {
            access_key: access_key.to_string(),
            secret_key,
            region: "cn-north-1".to_string(),
            client: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        })
    }

    /// 设置区域(上游 `WithRegion`)。
    pub fn with_region(mut self, region: &str) -> Self {
        self.region = region.to_string();
        self
    }

    /// 设置 HTTP 客户端(上游 `WithHTTPClient`)。
    pub fn with_http_client(mut self, client: ureq::Agent) -> Self {
        self.client = client;
        self
    }

    /// HMAC-SHA256(上游 `hmacSHA256`)。
    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// 生成签名(上游 `generateSignature` 的逐式复刻)。
    fn generate_signature(&self, body: &[u8], timestamp: &str, date: &str) -> String {
        let body_hash_b64 = {
            let hash: [u8; 32] = Sha256::digest(body).into();
            base64util::encode(&hash)
        };
        let canonical_headers = format!(
            "content-type:application/json\nhost:{VOLC_HOST}\nx-content-sha256:{body_hash_b64}\nx-date:{timestamp}\n"
        );
        let signed_headers = "content-type;host;x-content-sha256;x-date";
        let canonical_request = format!(
            "POST\n/\nAction=TranslateText&Version=2020-06-01\n{canonical_headers}{signed_headers}\n{body_hash_b64}"
        );
        let credential_scope = format!("{date}/{}/{VOLC_SERVICE}/request", self.region);
        let canonical_request_hash = {
            let hash: [u8; 32] = Sha256::digest(canonical_request.as_bytes()).into();
            hex_encode(&hash)
        };
        let string_to_sign =
            format!("HMAC-SHA256\n{timestamp}\n{credential_scope}\n{canonical_request_hash}");
        // 四级密钥派生链(密钥尾接单个换行)
        let k_date =
            Self::hmac_sha256(format!("{}\n", self.secret_key).as_bytes(), date.as_bytes());
        let k_region = Self::hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = Self::hmac_sha256(&k_region, VOLC_SERVICE.as_bytes());
        let k_signing = Self::hmac_sha256(&k_service, b"request");
        let signature = Self::hmac_sha256(&k_signing, string_to_sign.as_bytes());
        hex_encode(&signature)
    }

    /// 构建并签名请求(上游 `buildAndSignRequest`:URL 为常量,
    /// 头含时间戳/体哈希/签权;时间为上游取当下 UTC,此处注入
    /// 以便测试)。
    fn build_and_sign_request(
        &self,
        body: &[u8],
        now: DateTime<Utc>,
    ) -> (String, [(&'static str, String); 4]) {
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let body_hash_b64 = {
            let hash: [u8; 32] = Sha256::digest(body).into();
            base64util::encode(&hash)
        };
        let signature = self.generate_signature(body, &timestamp, &date);
        let authorization = format!(
            "HMAC-SHA256 Credential={}/{}/{}/{VOLC_SERVICE}/request, SignedHeaders=content-type;host;x-content-sha256;x-date, Signature={signature}",
            self.access_key, date, self.region
        );
        let url = format!("https://{VOLC_HOST}/?Action=TranslateText&Version=2020-06-01");
        (
            url,
            [
                ("Content-Type", "application/json".to_string()),
                ("X-Date", timestamp),
                ("X-Content-Sha256", body_hash_b64),
                ("Authorization", authorization),
            ],
        )
    }

    /// 调用 API(上游 `callAPI`:请求体 JSON 序列化、签名请求、
    /// POST、响应解析)。
    fn call_api(&self, body: &str) -> Result<VolcTranslationResponse, String> {
        let (url, headers) = self.build_and_sign_request(body.as_bytes(), Utc::now());
        let mut request = self.client.post(&url);
        for (name, value) in headers {
            request = request.set(name, &value);
        }
        let response = match request.send_string(body) {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(format!("发送请求失败: {e}")),
        };
        let status = response.status();
        let resp_body = response
            .into_string()
            .map_err(|e| format!("读取响应失败: {e}"))?;
        if status != 200 {
            return Err(format!("HTTP错误: {status}, 响应: {resp_body}"));
        }
        Self::parse_response(&resp_body)
    }

    /// 响应解析(上游 `callAPI` 的响应处理:元数据错误报错,
    /// 否则取翻译响应)。
    fn parse_response(body: &str) -> Result<VolcTranslationResponse, String> {
        let resp: VolcResponse =
            serde_json::from_str(body).map_err(|e| format!("解析响应失败: {e}, 响应: {body}"))?;
        if let Some(error) = resp.response_metadata.error {
            return Err(format!("API错误: {} - {}", error.code, error.message));
        }
        Ok(resp.translation_response)
    }
}

impl crate::translator::Translator for Translator {
    /// 单文本翻译(上游 `Translate`)。
    fn translate(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, String> {
        if source.is_empty() {
            return Err("待翻译文本不能为空".to_string());
        }
        let text_list = [source.to_string()];
        let body = serde_json::to_string(&TranslateTextRequest {
            source_language: source_lang,
            target_language: target_lang,
            text_list: &text_list,
            scene: "general",
        })
        .map_err(|e| format!("翻译失败: 序列化请求体失败: {e}"))?;
        let response = self.call_api(&body).map_err(|e| format!("翻译失败: {e}"))?;
        let Some(first) = response.translation_list.first() else {
            return Err("翻译结果为空".to_string());
        };
        Ok(first.text.clone())
    }
}

impl Translator {
    /// 批量翻译(上游 `TranslateBatch`)。
    pub fn translate_batch(
        &self,
        sources: &[&str],
        source_lang: &str,
        target_lang: &str,
    ) -> Result<Vec<String>, String> {
        if sources.is_empty() {
            return Ok(Vec::new());
        }
        let text_list: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
        let body = serde_json::to_string(&TranslateTextRequest {
            source_language: source_lang,
            target_language: target_lang,
            text_list: &text_list,
            scene: "general",
        })
        .map_err(|e| format!("批量翻译失败: 序列化请求体失败: {e}"))?;
        let response = self
            .call_api(&body)
            .map_err(|e| format!("批量翻译失败: {e}"))?;
        if response.translation_list.len() != sources.len() {
            return Err(format!(
                "结果数量不匹配：输入{}条，返回{}条",
                sources.len(),
                response.translation_list.len()
            ));
        }
        Ok(response
            .translation_list
            .into_iter()
            .map(|item| item.text)
            .collect())
    }
}

// 上游 String():脱敏的调试字符串
impl fmt::Display for Translator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Translator{{region: {}, accessKey: {}****{}}}",
            self.region,
            &self.access_key[..6],
            &self.access_key[self.access_key.len() - 4..]
        )
    }
}

/// 上游 `translateTextRequest` 的 JSON 形态。
#[derive(Serialize)]
struct TranslateTextRequest<'a> {
    #[serde(rename = "SourceLanguage")]
    source_language: &'a str,
    #[serde(rename = "TargetLanguage")]
    target_language: &'a str,
    #[serde(rename = "TextList")]
    text_list: &'a [String],
    #[serde(rename = "Scene")]
    scene: &'a str,
}

/// 上游 `translateTextResponse` 的 JSON 形态(`TranslationList`
/// 缺失时为空表,对应上游零值)。
#[derive(Deserialize, Default)]
struct VolcTranslationResponse {
    #[serde(default, rename = "TranslationList")]
    translation_list: Vec<VolcTranslationItem>,
}

/// 上游 `translateTextResponse` 内层条目(`Text` 缺失时为空串)。
#[derive(Deserialize)]
struct VolcTranslationItem {
    #[serde(default, rename = "Text")]
    text: String,
}

/// 上游 `volcResponse` 的 JSON 形态。
#[derive(Deserialize, Default)]
struct VolcResponse {
    #[serde(default, rename = "ResponseMetadata")]
    response_metadata: VolcResponseMetadata,
    #[serde(default, rename = "TranslationResponse")]
    translation_response: VolcTranslationResponse,
}

/// 上游 `ResponseMetadata`(仅错误字段被读取)。
#[derive(Deserialize, Default)]
struct VolcResponseMetadata {
    #[serde(default, rename = "Error")]
    error: Option<VolcResponseError>,
}

/// 上游错误对象。
#[derive(Deserialize)]
struct VolcResponseError {
    #[serde(default, rename = "Code")]
    code: String,
    #[serde(default, rename = "Message")]
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn volc_constructor() {
        assert_eq!(
            Translator::new("", "s").err().unwrap(),
            "accessKey和secretKey不能为空"
        );
        assert_eq!(
            Translator::new("a", "").err().unwrap(),
            "accessKey和secretKey不能为空"
        );
        let t = Translator::new("test_access_key", "test_secret_key\n").unwrap();
        assert_eq!(t.region, "cn-north-1"); // 上游默认区域
        assert_eq!(t.secret_key, "test_secret_key"); // 末尾换行去除
        let t = t.with_region("cn-shanghai");
        assert_eq!(t.region, "cn-shanghai");
    }

    #[test]
    fn volc_build_and_sign_request() {
        let t = Translator::new("test_access_key", "test_secret_key").unwrap();
        // 请求体经结构体序列化(上游 json.Marshal 的字段序)
        let text_list = ["你好，世界！".to_string()];
        let body = serde_json::to_string(&TranslateTextRequest {
            source_language: "zh",
            target_language: "en",
            text_list: &text_list,
            scene: "general",
        })
        .unwrap();
        assert_eq!(
            body,
            r#"{"SourceLanguage":"zh","TargetLanguage":"en","TextList":["你好，世界！"],"Scene":"general"}"#
        );
        // 固定时间下的签名链输出(基于 Go 源码字面转录的独立预计算;
        // X-Content-Sha256 与上游测试日志一致)
        let now = Utc.with_ymd_and_hms(2026, 3, 2, 12, 46, 26).unwrap();
        let (url, headers) = t.build_and_sign_request(body.as_bytes(), now);
        assert_eq!(
            url,
            "https://translate.volcengineapi.com/?Action=TranslateText&Version=2020-06-01"
        );
        let mut map = std::collections::HashMap::new();
        for (name, value) in headers {
            map.insert(name, value);
        }
        assert_eq!(map["Content-Type"], "application/json");
        assert_eq!(map["X-Date"], "20260302T124626Z");
        assert_eq!(
            map["X-Content-Sha256"],
            "GJhRzIaMG00WvKXo6+ZpVqHnnAnV0T+hBSOmxfEfOuQ="
        );
        assert_eq!(
            map["Authorization"],
            "HMAC-SHA256 Credential=test_access_key/20260302/cn-north-1/translate/request, SignedHeaders=content-type;host;x-content-sha256;x-date, Signature=3800c84dcba85487c6f5140417f032cb5813e0095d8d224485a9845aa50d79e4"
        );
    }

    #[test]
    fn volc_response_parsing() {
        let resp = Translator::parse_response(
            r#"{"TranslationResponse":{"TranslationList":[{"Text":"a"},{"Text":"b"}]}}"#,
        )
        .unwrap();
        assert_eq!(resp.translation_list.len(), 2);
        assert_eq!(
            Translator::parse_response(
                r#"{"ResponseMetadata":{"Error":{"Code":"X","Message":"m"}}}"#
            )
            .err()
            .unwrap(),
            "API错误: X - m"
        );
        let err = Translator::parse_response("not json").err().unwrap();
        assert!(err.starts_with("解析响应失败"), "{err}");
        // 翻译列表缺失 → 上游零值(空表)
        let resp = Translator::parse_response("{}").unwrap();
        assert!(resp.translation_list.is_empty());
    }

    #[test]
    fn volc_rejects_empty_source() {
        use crate::translator::Translator as _;
        let t = Translator::new("k", "s").unwrap();
        assert_eq!(
            t.translate("", "zh", "en").err().unwrap(),
            "待翻译文本不能为空"
        );
    }

    #[test]
    fn volc_display_masks_key() {
        let t = Translator::new("test_access_key", "test_secret_key").unwrap();
        assert_eq!(
            t.to_string(),
            "Translator{region: cn-north-1, accessKey: test_a****_key}"
        );
    }
}
