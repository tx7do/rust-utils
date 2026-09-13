//! 阿里云机器翻译后端(对应 Go 版 `translator/alibaba`,feature
//! `translator`)。
//!
//! 上游经官方 SDK(alimt + darabonba-openapi)调用
//! `mt.<region>.aliyuncs.com` 的 RPC 接口;此处按该 SDK 的线上
//! 形态逐式复刻:URL 查询串与表单体各自按键排序、经
//! [`query_escape`](crate::translator) 编码(SDK 的
//! `url.Values.Encode`);签名为排序编码串经三处历史替换
//! (`+`→`%20`、`*`→`%2A`、`%7E`→`~`)后整串二次转义,前缀
//! `POST&%2F&`,HMAC-SHA1(密钥尾接 `&`)的 base64。
//!
//! 与上游的差异:SDK 的重试/退避与内部错误对象未移植(单次
//! 请求,错误以字符串代替;上游客户端无显式超时,此处同样保持
//! 默认);`SignatureNonce` 见包级文档;`Timestamp` 为上游
//! `GetTimestamp` 的 GMT ISO8601 形态。

use crate::base64util;
use crate::translator::{form_encode, query_escape};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha1::Sha1;
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

/// 阿里云翻译器(上游 `alibaba.Translator`:区域默认
/// `cn-hangzhou`,上游 `WithRegionID` 语义)。
pub struct Translator {
    access_key_id: String,
    access_key_secret: String,
    region_id: String,
    client: ureq::Agent,
}

impl Translator {
    /// 创建(上游 `NewTranslator`:上游端点构造恒有区域,无错误
    /// 路径,此处直接返回 `Self`)。
    pub fn new(access_key_id: &str, access_key_secret: &str) -> Self {
        Self {
            access_key_id: access_key_id.to_string(),
            access_key_secret: access_key_secret.to_string(),
            region_id: "cn-hangzhou".to_string(),
            client: ureq::AgentBuilder::new().build(),
        }
    }

    /// 设置区域 ID(上游 `WithRegionID`)。
    pub fn with_region_id(mut self, region_id: &str) -> Self {
        self.region_id = region_id.to_string();
        self
    }

    /// 端点(上游:`mt.<region>.aliyuncs.com`)。
    fn endpoint(&self) -> String {
        format!("mt.{}.aliyuncs.com", self.region_id)
    }

    /// RPC 签名(上游 `buildRpcStringToSign` + `sign` 的逐式
    /// 复刻,见模块文档)。
    fn sign_rpc(params: &[(&str, &str)], method: &str, secret: &str) -> String {
        // 上游 getUrlFormedMap:url.Values.Encode() 的排序+转义
        let formed = form_encode(params);
        // 上游的三处历史替换(对 Encode 的输出仅 "+" 分支有效)
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

    /// 构造请求(上游 `DoRPCRequest` 的参数组装与签名;时间戳与
    /// nonce 由上游取当下时间与随机杂凑,此处注入以便测试)。
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
        // 上游 Query 初始集与鉴权参数(body 参数经 Merge 并入)
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

    /// 响应解析(上游 `TranslateGeneral` 的响应处理)。
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
    /// 翻译(上游 `Translate` 的完整调用链)。
    fn translate(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, String> {
        // 上游 GetTimestamp/GetNonce
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

/// 上游 `TranslateGeneralResponseBody` 的 JSON 形态。
#[derive(Deserialize)]
struct AliResponse {
    #[serde(default, rename = "Code")]
    code: Option<i32>,
    #[serde(default, rename = "Message")]
    message: Option<String>,
    #[serde(default, rename = "Data")]
    data: Option<AliData>,
}

/// 上游 `TranslateGeneralResponseBodyData` 的 JSON 形态。
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
        assert_eq!(t.region_id, "cn-hangzhou"); // 上游默认区域
        assert_eq!(t.endpoint(), "mt.cn-hangzhou.aliyuncs.com");
        let t = t.with_region_id("cn-shanghai");
        assert_eq!(t.region_id, "cn-shanghai");
        assert_eq!(t.endpoint(), "mt.cn-shanghai.aliyuncs.com");
    }

    #[test]
    fn alibaba_rpc_signature_golden() {
        // 上游 SDK 自带测试向量:
        // GetRPCSignature({"test":"ok"}, method="", secret="accessKeySecret")
        // (与独立实现的预计算一致)
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
