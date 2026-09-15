//! 谷歌翻译后端,feature `translator`。
//!
//! v1 为裸 HTTP 端点(`translate.googleapis.com/translate_a`,
//! 拼接 URL,嵌套数组响应取各段首元素拼接);v2 为 REST 调用
//! (`language/translate/v2`,`key` 查询参数 + JSON 体,源语言
//! 参数被丢弃);v3 为 REST 调用(`/v3/:translateText`,不设置
//! parent,空父路径下由服务端报错,密钥经 `x-goog-api-key` 头)。
//!
//! 请求行为:单次请求,不自动重试,错误一律为字符串;语言标签
//! 原样透传,不做 BCP47 校验;文本经 `query_escape` 编码,语言
//! 参数原样拼接。响应解析对越界/畸形数据一律返回错误,不 panic;
//! v2 响应键名按谷歌公开 API 文档(`translatedText`)。v2/v3
//! 响应中的源语言标签未被使用,未建模。

use crate::translator::query_escape;
use serde::{Deserialize, Serialize};

/// 谷歌翻译器(默认版本为 v1,经 `with_version`/`with_api_key`
/// 设置版本与密钥;客户端无显式超时)。
pub struct Translator {
    version: String,
    api_key: String,
    client: ureq::Agent,
}

impl Default for Translator {
    fn default() -> Self {
        Self::new()
    }
}

impl Translator {
    /// 创建。
    pub fn new() -> Self {
        Self {
            version: String::new(),
            api_key: String::new(),
            client: ureq::AgentBuilder::new().build(),
        }
    }

    /// 设置 API 版本。
    pub fn with_version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }

    /// 设置 API 密钥。
    pub fn with_api_key(mut self, key: &str) -> Self {
        self.api_key = key.to_string();
        self
    }

    /// v1 的 URL 构造(语言参数原样拼接,文本经 `query_escape`
    /// 编码)。
    fn build_v1_uri(source: &str, source_lang: &str, target_lang: &str) -> String {
        format!(
            "https://translate.googleapis.com/translate_a/single?client=gtx&sl={source_lang}&tl={target_lang}&dt=t&q={}",
            query_escape(source)
        )
    }

    /// v2 的请求构造(`key` 查询参数 + JSON 体,源语言参数被
    /// 丢弃)。
    fn build_v2_request(&self, source: &str, target_lang: &str) -> (String, String) {
        let url = format!(
            "https://translation.googleapis.com/language/translate/v2?key={}",
            query_escape(&self.api_key)
        );
        let body = serde_json::json!({"q": [source], "target": target_lang}).to_string();
        (url, body)
    }

    /// v3 的请求构造(不设置 parent,密钥经 `x-goog-api-key` 头)。
    fn build_v3_request(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> (String, String, String) {
        let contents = [source.to_string()];
        let body = serde_json::to_string(&V3Request {
            source_language_code: source_lang,
            target_language_code: target_lang,
            mime_type: "text/plain",
            contents: &contents,
        })
        .unwrap_or_default();
        (
            "https://translate.googleapis.com/v3/:translateText".to_string(),
            body,
            self.api_key.clone(),
        )
    }

    /// v1 响应解析。
    fn parse_v1_response(body: &str) -> Result<String, String> {
        if body.contains("<title>Error 400 (Bad Request") {
            return Err("error 400 (Bad Request)".to_string());
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
            return Err("error unmarshalling data".to_string());
        };
        // 要求顶层数组为 JSON 数组
        let Some(outer) = value.as_array() else {
            return Err("error unmarshalling data".to_string());
        };
        if outer.is_empty() {
            return Err("no translated data in response".to_string());
        }
        let Some(inner) = outer[0].as_array() else {
            return Err("error unmarshalling data".to_string());
        };
        let mut text = String::new();
        for segment in inner {
            let Some(segment_array) = segment.as_array() else {
                // 非数组的内层元素按解析错误处理
                return Err("error unmarshalling data".to_string());
            };
            // 取各段首元素;非字符串元素跳过
            if let Some(serde_json::Value::String(s)) = segment_array.first() {
                text.push_str(s);
            }
        }
        Ok(text)
    }

    /// v2 响应解析(翻译列表为空或缺失时返回错误)。
    fn parse_v2_response(body: &str) -> Result<String, String> {
        let resp: V2Response = serde_json::from_str(body).map_err(|e| e.to_string())?;
        let Some(translation) = resp
            .data
            .and_then(|d| d.translations)
            .and_then(|t| t.into_iter().next())
        else {
            return Err("google translate v2: no translations in response".to_string());
        };
        Ok(translation.translated_text.unwrap_or_default())
    }

    /// v3 响应解析(数量非一时返回固定错误文本)。
    fn parse_v3_response(body: &str) -> Result<String, String> {
        let resp: V3Response = serde_json::from_str(body).map_err(|e| e.to_string())?;
        let translations = resp.translations.unwrap_or_default();
        if translations.len() != 1 {
            return Err("TranslateText: expected exactly one translation".to_string());
        }
        Ok(translations[0].translated_text.clone().unwrap_or_default())
    }
}

impl crate::translator::Translator for Translator {
    /// 翻译(按版本分派:默认与未知版本走 v1)。
    fn translate(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, String> {
        match self.version.as_str() {
            "v2" => self.translate_v2(source, source_lang, target_lang),
            "v3" => self.translate_v3(source, source_lang, target_lang),
            _ => self.translate_v1(source, source_lang, target_lang),
        }
    }
}

impl Translator {
    /// v1 路径。
    pub fn translate_v1(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, String> {
        let uri = Self::build_v1_uri(source, source_lang, target_lang);
        let body = match self.client.get(&uri).call() {
            Ok(r) => r
                .into_string()
                .map_err(|_| "error reading response body".to_string())?,
            Err(ureq::Error::Status(_, r)) => r
                .into_string()
                .map_err(|_| "error reading response body".to_string())?,
            Err(_) => return Err("error getting translate.googleapis.com".to_string()),
        };
        Self::parse_v1_response(&body)
    }

    /// v2 路径(非 2xx 直接报错,源语言被丢弃)。
    pub fn translate_v2(
        &self,
        source: &str,
        _source_lang: &str,
        target_lang: &str,
    ) -> Result<String, String> {
        let (url, body) = self.build_v2_request(source, target_lang);
        let response = match self
            .client
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body)
        {
            Ok(r) => r,
            Err(e) => return Err(e.to_string()),
        };
        let resp_body = response.into_string().map_err(|e| e.to_string())?;
        Self::parse_v2_response(&resp_body)
    }

    /// v3 路径(错误经 `TranslateText: ` 前缀包装,含不设置
    /// parent 时服务端返回的错误)。
    pub fn translate_v3(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, String> {
        let (url, body, api_key) = self.build_v3_request(source, source_lang, target_lang);
        let response = match self
            .client
            .post(&url)
            .set("Content-Type", "application/json")
            .set("x-goog-api-key", &api_key)
            .send_string(&body)
        {
            Ok(r) => r,
            Err(e) => return Err(format!("TranslateText: {e}")),
        };
        let resp_body = response
            .into_string()
            .map_err(|e| format!("TranslateText: {e}"))?;
        Self::parse_v3_response(&resp_body)
    }
}

/// v2 响应。
#[derive(Deserialize)]
struct V2Response {
    #[serde(default, rename = "data")]
    data: Option<V2Data>,
}

/// v2 响应内层。
#[derive(Deserialize)]
struct V2Data {
    #[serde(default, rename = "translations")]
    translations: Option<Vec<V2Translation>>,
}

/// v2 翻译条目。
#[derive(Deserialize)]
struct V2Translation {
    #[serde(default, rename = "translatedText")]
    translated_text: Option<String>,
}

/// v3 响应。
#[derive(Deserialize)]
struct V3Response {
    #[serde(default, rename = "translations")]
    translations: Option<Vec<V3Translation>>,
}

/// v3 翻译条目。
#[derive(Deserialize)]
struct V3Translation {
    #[serde(default, rename = "translatedText")]
    translated_text: Option<String>,
}

/// v3 请求体。
#[derive(Serialize)]
struct V3Request<'a> {
    #[serde(rename = "sourceLanguageCode")]
    source_language_code: &'a str,
    #[serde(rename = "targetLanguageCode")]
    target_language_code: &'a str,
    #[serde(rename = "mimeType")]
    mime_type: &'a str,
    #[serde(rename = "contents")]
    contents: &'a [String],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_builder_and_dispatch() {
        let t = Translator::new();
        assert_eq!(t.version, ""); // 默认版本(分派走 v1)
        assert_eq!(t.api_key, "");
        let t = t.with_version("v2").with_api_key("KEY");
        assert_eq!(t.version, "v2");
        assert_eq!(t.api_key, "KEY");
    }

    #[test]
    fn google_v1_uri() {
        assert_eq!(
            Translator::build_v1_uri("你好", "en", "zh-CN"),
            "https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=zh-CN&dt=t&q=%E4%BD%A0%E5%A5%BD"
        );
        // 语言参数不经转义,文本经 query_escape 编码
        assert_eq!(
            Translator::build_v1_uri("a b", "e n", "zh"),
            "https://translate.googleapis.com/translate_a/single?client=gtx&sl=e n&tl=zh&dt=t&q=a+b"
        );
    }

    #[test]
    fn google_v2_request() {
        let t = Translator::new().with_api_key("TESTKEY");
        let (url, body) = t.build_v2_request("hello", "de");
        assert_eq!(
            url,
            "https://translation.googleapis.com/language/translate/v2?key=TESTKEY"
        );
        assert_eq!(body, r#"{"q":["hello"],"target":"de"}"#);
    }

    #[test]
    fn google_v3_request() {
        let t = Translator::new().with_api_key("TESTKEY");
        let (url, body, key) = t.build_v3_request("x", "en", "zh");
        assert_eq!(url, "https://translate.googleapis.com/v3/:translateText");
        assert_eq!(key, "TESTKEY");
        assert_eq!(
            body,
            r#"{"sourceLanguageCode":"en","targetLanguageCode":"zh","mimeType":"text/plain","contents":["x"]}"#
        );
    }

    #[test]
    fn google_v1_response_parsing() {
        assert_eq!(
            Translator::parse_v1_response(r#"[[["Hello","x"],["world","y"]]]"#).unwrap(),
            "Helloworld"
        );
        // 空内层表 → 空串
        assert_eq!(Translator::parse_v1_response("[[[]]]").unwrap(), "");
        assert_eq!(
            Translator::parse_v1_response("[]").unwrap_err(),
            "no translated data in response"
        );
        // 非数组顶层数据/内层段、非 JSON
        assert_eq!(
            Translator::parse_v1_response("{}").unwrap_err(),
            "error unmarshalling data"
        );
        assert_eq!(
            Translator::parse_v1_response("[5]").unwrap_err(),
            "error unmarshalling data"
        );
        assert_eq!(
            Translator::parse_v1_response("[[5]]").unwrap_err(),
            "error unmarshalling data"
        );
        assert_eq!(
            Translator::parse_v1_response("not json").unwrap_err(),
            "error unmarshalling data"
        );
        // 含 400 错误标题的 HTML
        assert_eq!(
            Translator::parse_v1_response("<html><title>Error 400 (Bad Request)</title></html>")
                .unwrap_err(),
            "error 400 (Bad Request)"
        );
    }

    #[test]
    fn google_v2_response_parsing() {
        assert_eq!(
            Translator::parse_v2_response(r#"{"data":{"translations":[{"translatedText":"hi"}]}}"#)
                .unwrap(),
            "hi"
        );
        // 空列表/缺失:报错
        assert!(Translator::parse_v2_response(r#"{"data":{"translations":[]}}"#).is_err());
        assert!(Translator::parse_v2_response("{}").is_err());
        assert!(Translator::parse_v2_response("not json").is_err());
    }

    #[test]
    fn google_v3_response_parsing() {
        assert_eq!(
            Translator::parse_v3_response(r#"{"translations":[{"translatedText":"hi"}]}"#).unwrap(),
            "hi"
        );
        // 数量非一/缺失:固定错误文本
        assert_eq!(
            Translator::parse_v3_response(r#"{"translations":[]}"#).unwrap_err(),
            "TranslateText: expected exactly one translation"
        );
        assert_eq!(
            Translator::parse_v3_response("{}").unwrap_err(),
            "TranslateText: expected exactly one translation"
        );
        assert!(Translator::parse_v3_response("not json").is_err());
    }
}
