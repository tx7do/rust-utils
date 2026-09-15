//! 阿里云机器翻译后端,feature `translator`。
//!
//! - 请求行为:POST 调用 `mt.<region>.aliyuncs.com` 的 RPC 接口,
//!   签名随 URL 查询串提交,业务参数同时作为表单体发送;单次
//!   请求,不自动重试,错误一律为字符串;客户端无显式超时。
//! - 签名与编码:URL 查询串与表单体各自按键名排序、经
//!   [`query_escape`](crate::translator) 编码;签名为排序编码串
//!   经三处固定替换(`+`→`%20`、`*`→`%2A`、`%7E`→`~`)后整串
//!   二次转义,前缀 `POST&%2F&`,HMAC-SHA1(密钥尾接 `&`)的
//!   base64;`SignatureNonce` 取 UUID v4 的 32 位十六进制,
//!   `Timestamp` 为 GMT ISO8601 形态。
//! - 测试:签名金标为官方 SDK 自带测试向量。

use crate::base64util;
use crate::translator::{form_encode, query_escape};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha1::Sha1;
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

/// 阿里云翻译器(区域默认 `cn-hangzhou`,经 `with_region_id`
/// 设置)。
pub struct Translator {
    access_key_id: String,
    access_key_secret: String,
    region_id: String,
    client: ureq::Agent,
}

impl Translator {
    /// 创建(端点由区域构造,无错误路径)。
    pub fn new(access_key_id: &str, access_key_secret: &str) -> Self {
        Self {
            access_key_id: access_key_id.to_string(),
            access_key_secret: access_key_secret.to_string(),
            region_id: "cn-hangzhou".to_string(),
            client: ureq::AgentBuilder::new().build(),
        }
    }

    /// 设置区域 ID。
    pub fn with_region_id(mut self, region_id: &str) -> Self {
        self.region_id = region_id.to_string();
        self
    }

    /// 端点(`mt.<region>.aliyuncs.com`)。
    fn endpoint(&self) -> String {
        format!("mt.{}.aliyuncs.com", self.region_id)
    }

    /// RPC 签名(按官方 API 的 RPC 签名算法,见模块文档)。
    fn sign_rpc(params: &[(&str, &str)], method: &str, secret: &str) -> String {
        // 参数按键名排序并经转义
        let formed = form_encode(params);
        // 三处固定替换(经 query_escape 的输出仅 "+" 分支有效)
        let replaced = formed
            .replace('+', "%20")
            .replace('*', "%2A")
            .replace("%7E", "~");
        // 整串二次转义后拼前缀
        let string_to_sign = format!("{method}&%2F&{}", query_escape(&replaced));
        let key = format!("{secret}&");
        let mut mac = <HmacSha1 as Mac>::new_from_slice(key.as_bytes()).expect("hmac key");
        mac.update(string_to_sign.as_bytes());
        base64util::encode(&mac.finalize().into_bytes())
    }

    /// 构造请求(参数组装与签名;时间戳与 nonce 由调用方注入
    /// 以便测试)。
    fn build_request(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
        timestamp: &str,
        nonce: &str,
    ) -> (String, String) {
        let body_params = [
            ("FormatType", "text"),
            ("Scene", "general"),
            ("SourceLanguage", source_lang),
            ("SourceText", source),
            ("TargetLanguage", target_lang),
        ];
        // 鉴权与固定参数(业务参数并入其中共同参与签名)
        let mut signed_params = [
            ("AccessKeyId", self.access_key_id.as_str()),
            ("Action", "TranslateGeneral"),
            ("Format", "json"),
            ("SignatureMethod", "HMAC-SHA1"),
            ("SignatureNonce", nonce),
            ("SignatureVersion", "1.0"),
            ("Timestamp", timestamp),
            ("Version", "2019-01-01"),
        ]
        .to_vec();
        signed_params.extend(body_params);
        let signature = Self::sign_rpc(&signed_params, "POST", &self.access_key_secret);
        let mut url_params = signed_params;
        url_params.push(("Signature", signature.as_str()));
        let url = format!("https://{}/?{}", self.endpoint(), form_encode(&url_params));
        let body = form_encode(&body_params);
        (url, body)
    }

    /// 响应解析。
    fn parse_response(body: &str) -> Result<String, String> {
        let resp: AliResponse =
            serde_json::from_str(body).map_err(|e| format!("alibaba translate error: {e}"))?;
        if let Some(code) = resp.code {
            if code != 200 {
                return Err(format!(
                    "alibaba translate error: code={code}, message={}",
                    resp.message.unwrap_or_default()
                ));
            }
        }
        let Some(data) = resp.data else {
            return Err("alibaba translate: empty response".to_string());
        };
        let Some(translated) = data.translated else {
            return Err("alibaba translate: translation result is nil".to_string());
        };
        Ok(translated)
    }
}

impl crate::translator::Translator for Translator {
    /// 翻译。
    fn translate(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, String> {
        // 时间戳(GMT ISO8601)与 nonce(UUID v4)
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = Uuid::new_v4().simple().to_string();
        let (url, body) = self.build_request(source, source_lang, target_lang, &timestamp, &nonce);
        let response = match self
            .client
            .post(&url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&body)
        {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(format!("alibaba translate error: {e}")),
        };
        let status = response.status();
        let resp_body = response.into_string().map_err(|e| e.to_string())?;
        if status != 200 {
            return Err(format!(
                "alibaba translate error: status {status}, body: {resp_body}"
            ));
        }
        Self::parse_response(&resp_body)
    }
}

/// 响应体的 JSON 形态。
#[derive(Deserialize)]
struct AliResponse {
    #[serde(default, rename = "Code")]
    code: Option<i32>,
    #[serde(default, rename = "Message")]
    message: Option<String>,
    #[serde(default, rename = "Data")]
    data: Option<AliData>,
}

/// 响应体 `Data` 内层的 JSON 形态。
#[derive(Deserialize)]
struct AliData {
    #[serde(default, rename = "Translated")]
    translated: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alibaba_constructor_and_region() {
        let t = Translator::new("test_access_key_id", "test_access_key_secret");
        assert_eq!(t.region_id, "cn-hangzhou"); // 默认区域
        assert_eq!(t.endpoint(), "mt.cn-hangzhou.aliyuncs.com");
        let t = t.with_region_id("cn-shanghai");
        assert_eq!(t.region_id, "cn-shanghai");
        assert_eq!(t.endpoint(), "mt.cn-shanghai.aliyuncs.com");
    }

    #[test]
    fn alibaba_rpc_signature_golden() {
        // 官方 SDK 自带测试向量:
        // GetRPCSignature({"test":"ok"}, method="", secret="accessKeySecret")
        assert_eq!(
            Translator::sign_rpc(&[("test", "ok")], "", "accessKeySecret"),
            "jHx/oHoHNrbVfhncHEvPdHXZwHU="
        );
    }

    #[test]
    fn alibaba_build_request() {
        let t = Translator::new("test_access_key_id", "test_access_key_secret");
        let (url, body) = t.build_request(
            "Hello, World!",
            "auto",
            "zh-TW",
            "2026-03-02T12:46:26Z",
            "0123456789abcdef0123456789abcdef",
        );
        assert_eq!(
            url,
            "https://mt.cn-hangzhou.aliyuncs.com/?AccessKeyId=test_access_key_id&Action=TranslateGeneral&Format=json&FormatType=text&Scene=general&Signature=V5URx4CwhR39Q9nJpMxXJkroxYs%3D&SignatureMethod=HMAC-SHA1&SignatureNonce=0123456789abcdef0123456789abcdef&SignatureVersion=1.0&SourceLanguage=auto&SourceText=Hello%2C+World%21&TargetLanguage=zh-TW&Timestamp=2026-03-02T12%3A46%3A26Z&Version=2019-01-01"
        );
        assert_eq!(
            body,
            "FormatType=text&Scene=general&SourceLanguage=auto&SourceText=Hello%2C+World%21&TargetLanguage=zh-TW"
        );
    }

    #[test]
    fn alibaba_response_parsing() {
        assert_eq!(
            Translator::parse_response(r#"{"Code":200,"Data":{"Translated":"ok"}}"#).unwrap(),
            "ok"
        );
        assert_eq!(
            Translator::parse_response(r#"{"Code":400,"Message":"bad"}"#).unwrap_err(),
            "alibaba translate error: code=400, message=bad"
        );
        assert_eq!(
            Translator::parse_response(r#"{"Code":200}"#).unwrap_err(),
            "alibaba translate: empty response"
        );
        assert_eq!(
            Translator::parse_response(r#"{"Data":{}}"#).unwrap_err(),
            "alibaba translate: translation result is nil"
        );
        assert!(Translator::parse_response("not json").is_err());
    }
}
