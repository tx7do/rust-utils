//! 百度翻译开放平台后端,feature `translator`。
//!
//! 移植自 go-utils 的 `translator/baidu` 包。表单 POST
//! (`q`/`from`/`to`/`appid`/`salt`/`sign`),`sign` 为
//! MD5(appid + q + salt + 密钥)的小写十六进制;响应 `trans_result`
//! 逐段 `dst` 按换行合并为译文,`error_code`/`error_msg` 为错误。
//!
//! 语言标签走 BCP47(`zh-CN`/`en-US`/`ar`),由 [`normalize_lang`]
//! 归一为百度语种码(`zh`/`en`/`ara`);未收录的语种去掉地区后缀后
//! 小写透传。端点与 HTTP 客户端可覆盖(测试注入 mock、代理策略自定义)。

use crate::translator::{form_encode, hex_encode};
use md5::{Digest as _, Md5};
use serde::Deserialize;
use std::time::Duration;

/// 百度通用翻译 API 的缺省端点。
pub const DEFAULT_ENDPOINT: &str = "https://fanyi-api.baidu.com/api/trans/vip/translate";

/// BCP47 语言标签 → 百度语种码(与上游 `bcp47ToBaidu` 同表)。
fn bcp47_to_baidu(lang: &str) -> Option<&'static str> {
    match lang {
        "auto" => Some("auto"),
        "zh" => Some("zh"),
        "zh-cn" => Some("zh"),
        "zh-tw" => Some("cht"),
        "zh-hk" => Some("cht"),
        "en" => Some("en"),
        "en-us" => Some("en"),
        "en-gb" => Some("en"),
        "ar" => Some("ara"),
        "ja" => Some("jp"),
        "ja-jp" => Some("jp"),
        "ko" => Some("kor"),
        "ko-kr" => Some("kor"),
        "fr" => Some("fra"),
        "fr-fr" => Some("fra"),
        "es" => Some("spa"),
        "es-es" => Some("spa"),
        "de" => Some("de"),
        "de-de" => Some("de"),
        "ru" => Some("ru"),
        "ru-ru" => Some("ru"),
        "pt" => Some("pt"),
        "pt-br" => Some("pt"),
        "it" => Some("it"),
        "it-it" => Some("it"),
        "th" => Some("th"),
        "th-th" => Some("th"),
        "vi" => Some("vie"),
        "vi-vn" => Some("vie"),
        _ => None,
    }
}

/// 将 BCP47 语言标签归一为百度语种码。
///
/// 未收录的语种去掉地区后缀后小写透传(`xxx-YY` → `xxx`)。
pub fn normalize_lang(lang: &str) -> String {
    let l = lang.trim().to_lowercase();
    if let Some(v) = bcp47_to_baidu(&l) {
        return v.to_string();
    }
    if let Some(i) = l.find('-') {
        if i > 0 {
            if let Some(v) = bcp47_to_baidu(&l[..i]) {
                return v.to_string();
            }
            return l[..i].to_string();
        }
    }
    l
}

/// 百度翻译器(客户端 30 秒超时;端点与 HTTP 客户端可覆盖)。
pub struct Translator {
    app_id: String,
    secret_key: String,
    endpoint: String,
    agent: ureq::Agent,
}

impl Translator {
    /// 创建。
    pub fn new(app_id: &str, secret_key: &str) -> Self {
        Self {
            app_id: app_id.to_string(),
            secret_key: secret_key.to_string(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }

    /// 覆盖请求端点(测试注入 mock 服务用)。
    pub fn with_endpoint(mut self, endpoint: &str) -> Self {
        self.endpoint = endpoint.to_string();
        self
    }

    /// 覆盖 HTTP 客户端(代理/超时策略自定义用)。
    pub fn with_agent(mut self, agent: ureq::Agent) -> Self {
        self.agent = agent;
        self
    }

    /// 签名:MD5(appid + q + salt + 密钥)。
    ///
    /// MD5 是百度通用翻译 API 协议强制的签名算法(服务端只认这一种,
    /// 无法升级为 SHA-256 等更强哈希);此处用途是请求鉴权 MAC,并非
    /// 口令/敏感数据的存储哈希。
    fn generate_sign(&self, query: &str, salt: u64) -> String {
        let str_ = format!("{}{}{}{}", self.app_id, query, salt, self.secret_key);
        let digest: [u8; 16] = Md5::digest(str_.as_bytes()).into();
        hex_encode(&digest)
    }

    /// 构造请求(参数组装与签名;语种码已归一、`salt` 由调用方注入以便测试)。
    fn build_request(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
        salt: u64,
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
        (self.endpoint.clone(), form_encode(&params))
    }

    /// 响应解析:错误码优先;否则把多段 `trans_result` 的 `dst` 按换行
    /// 合并(换行分隔的输入对应多段结果;空结果返回空串)。
    fn parse_response(body: &str) -> Result<String, String> {
        let resp: BaiduResponse = serde_json::from_str(body)
            .map_err(|e| format!("baidu translator: decode response: {e}"))?;
        if !resp.error_code.is_empty() {
            return Err(format!(
                "baidu translator: api error {}: {}",
                resp.error_code, resp.error_msg
            ));
        }
        Ok(resp
            .trans_result
            .iter()
            .map(|r| r.dst.as_str())
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

impl crate::translator::Translator for Translator {
    /// 翻译文本。`source_lang` 传 `"auto"`、空串或未配凭据前先做守卫:
    /// 凭据缺失直接报错;空白输入直接返回空译文(不打 API)。
    fn translate(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, String> {
        if self.app_id.is_empty() || self.secret_key.is_empty() {
            return Err("baidu translator: appid/secret is not configured".to_owned());
        }
        if source.trim().is_empty() {
            return Ok(String::new());
        }

        let from = normalize_lang(source_lang);
        let from = if from.is_empty() {
            "auto"
        } else {
            from.as_str()
        };
        let to = normalize_lang(target_lang);

        let salt = rand::random::<u64>();
        let (endpoint, body) = self.build_request(source, from, &to, salt);
        let response = match self
            .agent
            .post(&endpoint)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&body)
        {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(format!("baidu translator: request: {e}")),
        };
        let status = response.status();
        // into_string 自带 10MB 上限(对位上游 io.LimitReader(10<<20) 的
        // 体积防护);超限直接报错,不会把巨包读进内存。
        let resp_body = response
            .into_string()
            .map_err(|e| format!("baidu translator: read response: {e}"))?;
        if status != 200 {
            return Err(format!(
                "baidu translator: unexpected status {status}: {resp_body}"
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
    // trait 与结构体同名,匿名导入仅供 translate() 方法解析
    use crate::translator::Translator as _;

    #[test]
    fn baidu_constructor() {
        let t = Translator::new("test_app_id", "test_secret_key");
        assert_eq!(t.app_id, "test_app_id");
        assert_eq!(t.secret_key, "test_secret_key");
        assert_eq!(t.endpoint, DEFAULT_ENDPOINT);
        // 端点/客户端可覆盖
        let t = Translator::new("a", "b")
            .with_endpoint("http://127.0.0.1:1/mock")
            .with_agent(ureq::AgentBuilder::new().build());
        assert_eq!(t.endpoint, "http://127.0.0.1:1/mock");
    }

    #[test]
    fn baidu_normalize_lang() {
        // 表内直配:主流语种与地区变体归到百度语种码
        assert_eq!(normalize_lang("auto"), "auto");
        assert_eq!(normalize_lang("zh"), "zh");
        assert_eq!(normalize_lang("zh-CN"), "zh");
        assert_eq!(normalize_lang("zh-TW"), "cht");
        assert_eq!(normalize_lang("zh-HK"), "cht");
        assert_eq!(normalize_lang("en-US"), "en");
        assert_eq!(normalize_lang("en-GB"), "en");
        assert_eq!(normalize_lang("ar"), "ara");
        assert_eq!(normalize_lang("ja-JP"), "jp");
        assert_eq!(normalize_lang("ko-KR"), "kor");
        assert_eq!(normalize_lang("pt-BR"), "pt");
        assert_eq!(normalize_lang("vi-VN"), "vie");
        // 大小写与空白不敏感
        assert_eq!(normalize_lang("  ZH-cn "), "zh");
        // 未收录语种:去掉地区后缀后小写透传
        assert_eq!(normalize_lang("xxx-YY"), "xxx");
        assert_eq!(normalize_lang("yue"), "yue");
        // 空串透传(translate 侧把空源语种落回 auto)
        assert_eq!(normalize_lang(""), "");
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
        assert_eq!(url, DEFAULT_ENDPOINT);
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
        // 多段结果按换行合并(换行分隔的输入 → 多段译文)
        assert_eq!(
            Translator::parse_response(
                r#"{"trans_result":[{"src":"a","dst":"甲"},{"src":"b","dst":"乙"}]}"#
            )
            .unwrap(),
            "甲\n乙"
        );
        assert_eq!(
            Translator::parse_response(r#"{"trans_result":[{"src":"x","dst":" translated"}]}"#)
                .unwrap(),
            " translated"
        );
        // 空结果返回空串(上游已去掉 invalid response format 分支)
        assert_eq!(Translator::parse_response("{}").unwrap(), "");
        assert_eq!(
            Translator::parse_response(r#"{"error_code":"54001","error_msg":"Invalid Sign"}"#)
                .unwrap_err(),
            "baidu translator: api error 54001: Invalid Sign"
        );
        assert!(Translator::parse_response("not json").is_err());
    }

    #[test]
    fn baidu_translate_guards() {
        // 凭据守卫:appid/secret 缺失直接报错,不打 API
        let t = Translator::new("", "");
        assert_eq!(
            t.translate("hi", "en", "zh"),
            Err("baidu translator: appid/secret is not configured".to_owned())
        );
        let t = Translator::new("id", "");
        assert_eq!(
            t.translate("hi", "en", "zh"),
            Err("baidu translator: appid/secret is not configured".to_owned())
        );

        // 空白输入守卫:直接返回空译文,不打 API
        let t = Translator::new("id", "secret");
        assert_eq!(t.translate("", "en", "zh").unwrap(), "");
        assert_eq!(t.translate("   \r\n", "en", "zh").unwrap(), "");
    }

    #[test]
    fn baidu_translate_normalizes_and_reaches_endpoint() {
        // 端点指向本地不可达地址:请求必然失败,但足以验证请求前
        // 的语种归一与守卫已生效、错误语与上游一致
        let t = Translator::new("id", "secret").with_endpoint("http://127.0.0.1:1/translate");
        let err = t.translate("hello", "EN-US", "zh-CN").unwrap_err();
        assert!(
            err.starts_with("baidu translator: request: "),
            "unexpected: {err}"
        );
    }
}
