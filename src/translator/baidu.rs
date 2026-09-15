//! 百度翻译开放平台后端,feature `translator`。
//!
//! 表单 POST(`q`/`from`/`to`/`appid`/`salt`/`sign`),`sign` 为
//! MD5(appid + q + salt + 密钥)的小写十六进制;响应
//! `trans_result[0].dst` 为译文,`error_code`/`error_msg` 为错误。

use crate::translator::{form_encode, hex_encode};
use md5::{Digest as _, Md5};
use serde::Deserialize;
use std::time::Duration;

const BAIDU_ENDPOINT: &str = "https://fanyi-api.baidu.com/api/trans/vip/translate";

/// 百度翻译器(客户端 30 秒超时)。
pub struct Translator {
    app_id: String,
    secret_key: String,
    client: ureq::Agent,
}

impl Translator {
    /// 创建。
    pub fn new(app_id: &str, secret_key: &str) -> Self {
        Self {
            app_id: app_id.to_string(),
            secret_key: secret_key.to_string(),
            client: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }

    /// 签名。
    fn generate_sign(&self, query: &str, salt: i64) -> String {
        let str_ = format!("{}{}{}{}", self.app_id, query, salt, self.secret_key);
        let digest: [u8; 16] = Md5::digest(str_.as_bytes()).into();
        hex_encode(&digest)
    }

    /// 构造请求(参数组装与签名;`salt` 由调用方注入以便测试)。
    fn build_request(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
        salt: i64,
    ) -> (String, String) {
        let salt_str = salt.to_string();
        let sign = self.generate_sign(source, salt);
        let params = [
            ("appid", self.app_id.as_str()),
            ("from", source_lang),
            ("q", source),
            ("salt", salt_str.as_str()),
            ("sign", sign.as_str()),
            ("to", target_lang),
        ];
        (BAIDU_ENDPOINT.to_string(), form_encode(&params))
    }

    /// 响应解析。
    fn parse_response(body: &str) -> Result<String, String> {
        let resp: BaiduResponse = serde_json::from_str(body).map_err(|e| e.to_string())?;
        if !resp.error_code.is_empty() {
            return Err(format!(
                "baidu translate error: {} - {}",
                resp.error_code, resp.error_msg
            ));
        }
        if let Some(first) = resp.trans_result.first() {
            return Ok(first.dst.clone());
        }
        Err("baidu translate: invalid response format".to_string())
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
        let salt = rand::random::<i64>();
        let (_, body) = self.build_request(source, source_lang, target_lang, salt);
        let response = match self
            .client
            .post(BAIDU_ENDPOINT)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&body)
        {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(e.to_string()),
        };
        let status = response.status();
        let resp_body = response.into_string().map_err(|e| e.to_string())?;
        if status != 200 {
            return Err(format!(
                "baidu translate error: status {status}, body: {resp_body}"
            ));
        }
        Self::parse_response(&resp_body)
    }
}

/// 响应的 JSON 形态。
#[derive(Deserialize)]
struct BaiduResponse {
    #[serde(default)]
    trans_result: Vec<BaiduTransItem>,
    #[serde(default)]
    error_code: String,
    #[serde(default)]
    error_msg: String,
}

/// 响应内层条目。
#[derive(Deserialize)]
struct BaiduTransItem {
    #[serde(default)]
    dst: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baidu_constructor() {
        let t = Translator::new("test_app_id", "test_secret_key");
        assert_eq!(t.app_id, "test_app_id");
        assert_eq!(t.secret_key, "test_secret_key");
    }

    #[test]
    fn baidu_generate_sign() {
        let t = Translator::new("20230101000001234", "test_secret_key");
        // 独立预计算的 MD5 向量
        assert_eq!(
            t.generate_sign("apple", 1234567890),
            "79c8d3557d1e04376e00011acc0c1490"
        );
        assert_eq!(
            t.generate_sign("hello world", 9876543210),
            "2def0a70a997368c5e550aca5abe3ed9"
        );
    }

    #[test]
    fn baidu_build_request() {
        let t = Translator::new("20230101000001234", "test_secret_key");
        let (url, body) = t.build_request("apple", "en", "zh", 1234567890);
        assert_eq!(url, "https://fanyi-api.baidu.com/api/trans/vip/translate");
        // 表单编码的排序与转义(含空格作 "+")
        assert_eq!(
            body,
            "appid=20230101000001234&from=en&q=apple&salt=1234567890&sign=79c8d3557d1e04376e00011acc0c1490&to=zh"
        );
        let (_, body) = t.build_request("hello world", "en", "zh", 9876543210);
        assert_eq!(
            body,
            "appid=20230101000001234&from=en&q=hello+world&salt=9876543210&sign=2def0a70a997368c5e550aca5abe3ed9&to=zh"
        );
    }

    #[test]
    fn baidu_response_parsing() {
        assert_eq!(
            Translator::parse_response(r#"{"trans_result":[{"src":"x","dst":" translated"}]}"#)
                .unwrap(),
            " translated"
        );
        assert_eq!(
            Translator::parse_response(r#"{"error_code":"54001","error_msg":"Invalid Sign"}"#)
                .unwrap_err(),
            "baidu translate error: 54001 - Invalid Sign"
        );
        assert_eq!(
            Translator::parse_response("{}").unwrap_err(),
            "baidu translate: invalid response format"
        );
        assert!(Translator::parse_response("not json").is_err());
    }
}
