//! 华为云短信(MSGSMS):WSSE 鉴权 + 模板短信,裸 HTTP 调批量发送路径,
//! feature `notify`。对齐上游 `notify/huaweisms/huaweisms.go`。
//!
//! 发送端点即"批量发送"路径(官方单发也走它,一人一条只是 `result` 数组只有
//! 一项)。[`Config::sender`] 是签名通道号(`csms` 开头),不是签名名称。
//!
//! WSSE 鉴权:X-WSSE 头携带 UsernameToken,`PasswordDigest =
//! base64(sha256(nonce + created + appSecret))`,三段原始串直接相连(不加分隔符);
//! created 为 UTC 的 RFC3339 秒级。Authorization 头是协议钉死的常量串。
//!
//! 厂商把业务结论放在 HTTP 200 的 body 里(`code == "000000"` 才是发出去了),
//! 只看状态码会把"对方没收"记成发送成功。
//!
//! 与上游 Go 版的差异:`Config.Ref`(展示标识,只进错误文案)未移植;
//! `context.Context` 取消传播在本 crate 的阻塞式 API 里不存在。
//!
//! 测试离线进行:请求构造、WSSE 签名与回执解析拆成纯函数断言,不真实连网。

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::notify::sms::normalize_phone_number;
use crate::notify::{Message, NotifyError, Receipt, check_target, map_ureq_error, new_client};

/// APP 接入地址(按申请的短信应用所在区域,控制台可查)。
pub const DEFAULT_API_BASE: &str = "https://smsapi.cn-north-4.myhuaweicloud.com";

/// WSSE 固定的 Authorization 头(协议钉死,无参数)。
pub const WSSE_AUTHORIZATION: &str = r#"WSSE realm="SDP",profile="UsernameToken",type="Appkey""#;

/// 批量发送端点路径(官方单发也走它)。
const SEND_PATH: &str = "/sms/batchSendSms/v1";

/// 厂商侧"成功"业务码。
const CODE_OK: &str = "000000";

/// 进错误文案的响应片段上限:对端可能回一整页 HTML。
const SNIPPET_LIMIT: usize = 256;

/// 华为云短信配置。手机号按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// APP 凭据(WSSE UsernameToken)。
    pub app_key: String,
    /// APP 凭据。
    pub app_secret: String,
    /// 签名通道号(`csms` 开头,即 from 参数)。
    pub sender: String,
    /// 已报备的模板 ID。
    pub template_id: String,
    /// 可选的状态报告回调地址。
    pub status_callback: String,
    /// APP 接入地址,留空用默认区域;按应用所在区域覆盖。
    pub api_base: String,
}

/// 华为云短信渠道。无状态,可并发使用。
pub struct Service {
    agent: ureq::Agent,
    cfg: Config,
}

/// 构造好的出站请求:纯数据,供离线测试断言。
struct Prepared {
    url: String,
    body: String,
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
}

impl Service {
    /// 构造华为云短信渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
    pub fn new(cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.api_base.is_empty() {
            cfg.api_base = DEFAULT_API_BASE.to_string();
        }
        Service {
            agent: new_client(crate::notify::allow_private_target()),
            cfg,
        }
    }

    /// 构造请求(纯函数):手机号归一为 E.164 进表单,模板变量按参数名排序
    /// 序列化为 `templateParas` 数组,WSSE 两头(Authorization + X-WSSE)进请求头。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "huaweisms destination is empty".into(),
            ));
        }
        if self.cfg.app_key.is_empty()
            || self.cfg.app_secret.is_empty()
            || self.cfg.sender.is_empty()
            || self.cfg.template_id.is_empty()
        {
            return Err(NotifyError::NotConfigured(
                "huaweisms config incomplete: app_key/app_secret/sender/template_id required"
                    .into(),
            ));
        }
        // 目标归一在出站前裁决:E.164 形态(+86 可选,带着最稳)。
        let (_, e164) = normalize_phone_number(&msg.target).map_err(NotifyError::NotConfigured)?;

        let mut pairs = vec![
            ("from".to_string(), self.cfg.sender.clone()),
            ("to".to_string(), e164),
            ("templateId".to_string(), self.cfg.template_id.clone()),
        ];
        if !msg.params.is_empty() {
            pairs.push(("templateParas".to_string(), template_paras_json(&msg.params)));
        }
        if !self.cfg.status_callback.is_empty() {
            pairs.push(("statusCallback".to_string(), self.cfg.status_callback.clone()));
        }
        Ok(Prepared {
            url: format!("{}{SEND_PATH}", self.cfg.api_base),
            body: form_encode(&pairs),
            content_type: "application/x-www-form-urlencoded",
            headers: vec![
                ("Authorization", WSSE_AUTHORIZATION.to_string()),
                (
                    "X-WSSE",
                    build_wsse(
                        &self.cfg.app_key,
                        &self.cfg.app_secret,
                        &random_nonce(),
                        &utc_created(),
                    ),
                ),
            ],
        })
    }

    /// 解析回执(纯函数):业务结论在 body 的 code(`"000000"` 为成功),
    /// HTTP 恒 200;成功时首条结果的 `smsMsgId` 进回执。
    fn parse_answer(status: u16, body: &str) -> Result<String, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        #[derive(serde::Deserialize, Default)]
        struct Answer {
            #[serde(default)]
            code: String,
            #[serde(default)]
            description: String,
            #[serde(default)]
            result: Vec<AnswerItem>,
        }
        #[derive(serde::Deserialize, Default)]
        struct AnswerItem {
            #[serde(rename = "smsMsgId", default)]
            sms_msg_id: String,
        }
        let answer: Answer = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
        })?;
        if answer.code != CODE_OK {
            let description = if answer.description.is_empty() {
                "no description"
            } else {
                &answer.description
            };
            return Err(NotifyError::Delivery(format!(
                "peer answered code={}: {description}",
                answer.code
            )));
        }
        Ok(answer
            .result
            .first()
            .map(|item| item.sms_msg_id.clone())
            .unwrap_or_default())
    }

    /// POST 已构造好的请求,返回 (状态码, 应答文本)。
    /// 非 2xx 也返回应答文本,由 [`Self::parse_answer`] 统一归类——对端的
    /// 错误说明在 body 里,丢了对账就没依据了。
    fn post(&self, req: &Prepared) -> Result<(u16, String), NotifyError> {
        let mut request = self
            .agent
            .post(&req.url)
            .set("Content-Type", req.content_type);
        for (name, value) in &req.headers {
            request = request.set(name, value);
        }
        match request.send_string(&req.body) {
            Ok(resp) => Ok((resp.status(), read_answer(resp)?)),
            Err(ureq::Error::Status(status, resp)) => Ok((status, read_answer(resp)?)),
            Err(err) => Err(map_ureq_error(err)),
        }
    }
}

impl crate::notify::Service for Service {
    fn name(&self) -> &str {
        "huaweisms"
    }

    /// 给 Target(手机号,CN 裸号或 E.164)发一条模板短信:
    /// `Message::params` 为模板变量,按参数名排序取值序列化成 `templateParas`
    /// 数组(单参数无感,多参数时模板 `${1}${2}` 的对应关系由排序决定,
    /// 多参数请核对模板占位顺序)。
    /// [`Receipt::provider_id`] 带回 `smsMsgId`。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let req = self.build_request(msg)?;
        check_target(&req.url)?;
        let (status, body) = self.post(&req)?;
        let provider_id = Self::parse_answer(status, &body)?;
        Ok(Receipt { provider_id })
    }
}

// ---------------------------------------------------------------------------
// 可独立测试的纯函数
// ---------------------------------------------------------------------------

/// X-WSSE 头:`PasswordDigest = base64(sha256(nonce + created + appSecret))`,
/// 三段原始串直接相连(不加分隔符);`nonce` 为随机串,`created` 为 UTC 的
/// RFC3339 秒级。拆出参数以便离线钉值复算。
pub fn build_wsse(app_key: &str, app_secret: &str, nonce: &str, created: &str) -> String {
    let digest = base64_encode(&sha256(format!("{nonce}{created}{app_secret}").as_bytes()));
    format!(
        r#"UsernameToken Username="{app_key}", PasswordDigest="{digest}", Nonce="{nonce}", Created="{created}""#
    )
}

/// 模板变量:按参数名排序取值,序列化为 JSON 数组字符串。
/// 单参数(验证码 code)无感;多参数时模板 `${1}${2}` 的对应关系由这个排序决定。
pub fn template_paras_json(params: &HashMap<String, String>) -> String {
    let mut keys: Vec<&String> = params.keys().collect();
    keys.sort();
    let values: Vec<&str> = keys.into_iter().map(|k| params[k].as_str()).collect();
    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// SHA-256 摘要(32 字节)。
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// 标准 base64(带填充)。PasswordDigest 进 HTTP 头用;crate 的 base64 工具
/// 在 notify feature 下不可用(被 captcha/crypto 等门控),这份实现就地兜住。
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// application/x-www-form-urlencoded 组件编码:保留字符(A-Z a-z 0-9 - _ . ~)
/// 原样,空格转 +,其余字节按 %XX(大写十六进制)。对齐 Go 的 url.QueryEscape。
fn form_urlencode(s: &str) -> String {
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
fn form_encode(pairs: &[(String, String)]) -> String {
    let mut pairs = pairs.to_vec();
    pairs.sort();
    let mut out = String::new();
    for (k, v) in &pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&form_urlencode(k));
        out.push('=');
        out.push_str(&form_urlencode(v));
    }
    out
}

/// Nonce:16 随机字节的十六进制串(32 字符)。
fn random_nonce() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("系统随机源不可用时短信无从谈起");
    let mut out = String::with_capacity(32);
    for b in buf {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Created:UTC 的 RFC3339 秒级(`YYYY-MM-DDTHH:MM:SSZ`)。
fn utc_created() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// 读对端应答文本。
fn read_answer(resp: ureq::Response) -> Result<String, NotifyError> {
    resp.into_string()
        .map_err(|e| NotifyError::Delivery(format!("read peer answer: {e}")))
}

/// 进错误文案的响应片段截断(按字节上限回退到字符边界)。
fn snippet(body: &str) -> String {
    if body.len() <= SNIPPET_LIMIT {
        return body.to_string();
    }
    let mut end = SNIPPET_LIMIT;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", &body[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::Service as _;

    fn full_cfg() -> Config {
        Config {
            app_key: "app-key-1".into(),
            app_secret: "secret-1".into(),
            sender: "csms100000001".into(),
            template_id: "tpl-1".into(),
            ..Config::default()
        }
    }

    #[test]
    fn test_name() {
        assert_eq!(Service::new(full_cfg()).name(), "huaweisms");
    }

    // 对齐上游 TestSendConfigAndTargetIssues:缺 template_id / 空目标 / 号码不合法,
    // 全部在拨号之前拦下,归 NotConfigured。
    #[test]
    fn test_config_and_target_issues() {
        let svc = Service::new(Config {
            app_key: "k".into(),
            app_secret: "s".into(),
            sender: "csms1".into(),
            ..Config::default()
        });
        let err = svc
            .send(&Message::new("13800138000", "").with_param("code", "1"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(
            err.to_string().contains("app_key/app_secret/sender/template_id"),
            "{err}"
        );

        let err = Service::new(full_cfg())
            .send(&Message::new("", ""))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("destination is empty"));

        let err = Service::new(full_cfg())
            .send(&Message::new("not-a-phone", "").with_param("code", "1"))
            .unwrap_err();
        assert!(err.is_not_configured(), "号码不合法一次都不碰对端: {err}");
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let mut cfg = full_cfg();
        cfg.api_base = "http://127.0.0.1:9".into();
        let err = Service::new(cfg)
            .send(&Message::new("13800138000", "").with_param("code", "1"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 对齐上游 TestSendDeliversWSSEAndTemplateForm 的离线部分:请求路径、鉴权两头、
    // 表单关键字段(from 是签名通道号、手机号 E.164、模板变量是 JSON 数组串)。
    #[test]
    fn test_build_request() {
        let svc = Service::new(full_cfg());
        let req = svc
            .build_request(&Message::new("13800138000", "").with_param("code", "123456"))
            .unwrap();
        assert_eq!(
            req.url,
            "https://smsapi.cn-north-4.myhuaweicloud.com/sms/batchSendSms/v1",
            "官方单发也走批量路径"
        );
        assert_eq!(req.content_type, "application/x-www-form-urlencoded");
        assert_eq!(
            req.headers[0],
            ("Authorization", WSSE_AUTHORIZATION.to_string()),
            "Authorization 是协议钉死的常量串"
        );

        // X-WSSE 结构钉住,并用 PasswordDigest 的算法独立复算一遍。
        let (username, digest, nonce, created) =
            parse_wsse(&req.headers[1].1).expect("X-WSSE 形态不符");
        assert_eq!(username, "app-key-1");
        let want = base64_encode(&sha256(format!("{nonce}{created}secret-1").as_bytes()));
        assert_eq!(
            digest, want,
            "PasswordDigest 必须等于 base64(sha256(nonce+created+secret)),三段原始串直连"
        );
        assert_eq!(nonce.len(), 32, "nonce 是 16 随机字节的 hex");
        assert_eq!(created.len(), 20, "created 是 UTC 秒级 RFC3339: {created}");
        assert!(created.ends_with('Z'), "created 以 Z 收尾: {created}");
        assert!(
            created[..created.len() - 1]
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-' || b == b'T' || b == b':'),
            "created 主体是数字与 -/T/: {created}"
        );

        // 表单关键字段。
        assert!(req.body.contains("from=csms100000001"), "{}", req.body);
        assert!(req.body.contains("to=%2B8613800138000"), "手机号 E.164 出站: {}", req.body);
        assert!(req.body.contains("templateId=tpl-1"), "{}", req.body);
        assert!(
            req.body.contains("templateParas=%5B%22123456%22%5D"),
            "模板变量是 JSON 数组串: {}",
            req.body
        );
    }

    // 从 X-WSSE 头里拆出四段(测试专用,不用正则)。
    fn parse_wsse(wsse: &str) -> Option<(String, String, String, String)> {
        let rest = wsse.strip_prefix("UsernameToken ")?;
        let mut username = None;
        let mut digest = None;
        let mut nonce = None;
        let mut created = None;
        for part in rest.split(", ") {
            let (k, v) = part.split_once('=')?;
            let v = v.trim_matches('"').to_string();
            match k {
                "Username" => username = Some(v),
                "PasswordDigest" => digest = Some(v),
                "Nonce" => nonce = Some(v),
                "Created" => created = Some(v),
                _ => return None,
            }
        }
        Some((username?, digest?, nonce?, created?))
    }

    // build_wsse 钉值:nonce/created 注入后整串可复现。
    #[test]
    fn test_build_wsse_pinned() {
        let wsse = build_wsse(
            "app-key-1",
            "secret-1",
            "0102030405060708090a0b0c0d0e0f10",
            "2026-10-15T06:00:00Z",
        );
        let want = format!(
            r#"UsernameToken Username="app-key-1", PasswordDigest="{}", Nonce="0102030405060708090a0b0c0d0e0f10", Created="2026-10-15T06:00:00Z""#,
            base64_encode(&sha256(
                b"0102030405060708090a0b0c0d0e0f102026-10-15T06:00:00Zsecret-1"
            ))
        );
        assert_eq!(wsse, want);
    }

    // 模板变量:按参数名排序取值;空表出空数组。
    #[test]
    fn test_template_paras_json() {
        let mut params = HashMap::new();
        params.insert("code".to_string(), "123456".to_string());
        assert_eq!(template_paras_json(&params), r#"["123456"]"#);

        params.insert("b".to_string(), "2".to_string());
        params.insert("a".to_string(), "1".to_string());
        params.remove("code");
        assert_eq!(
            template_paras_json(&params),
            r#"["1","2"]"#,
            "多参数按参数名排序取值,对应模板占位顺序"
        );
        assert_eq!(template_paras_json(&HashMap::new()), "[]");
    }

    // 状态报告回调配了就进表单。
    #[test]
    fn test_status_callback() {
        let mut cfg = full_cfg();
        cfg.status_callback = "https://cb.example.com/sms".into();
        let svc = Service::new(cfg);
        let req = svc
            .build_request(&Message::new("13800138000", "").with_param("code", "1"))
            .unwrap();
        assert!(
            req.body.contains("statusCallback=https%3A%2F%2Fcb.example.com%2Fsms"),
            "{}",
            req.body
        );
    }

    // 回执解析:smsMsgId 进回执;业务结论在 200 的 body 里,E200028 之类是失败。
    #[test]
    fn test_parse_answer() {
        let sms_id = Service::parse_answer(
            200,
            r#"{"code":"000000","description":"Success","result":[{"smsMsgId":"d6e3cdd0","status":"000000","originTo":"+8613800138000"}]}"#,
        )
        .unwrap();
        assert_eq!(sms_id, "d6e3cdd0", "smsMsgId 要进回执");

        // 成功但无 result:回执留空。
        let sms_id = Service::parse_answer(200, r#"{"code":"000000","description":"Success"}"#).unwrap();
        assert_eq!(sms_id, "");

        let err = Service::parse_answer(
            200,
            r#"{"code":"E200028","description":"Template variable count is inconsistent"}"#,
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("code=E200028"), "{err}");

        let err = Service::parse_answer(200, r#"{"code":"E000102"}"#).unwrap_err();
        assert!(err.to_string().contains("no description"), "{err}");

        let err = Service::parse_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");

        let err = Service::parse_answer(200, "<html>gateway</html>").unwrap_err();
        assert!(err.to_string().contains("not JSON"), "{err}");
    }

    // 随机源与时间戳形态。
    #[test]
    fn test_random_nonce_and_utc_created() {
        let nonce = random_nonce();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.bytes().all(|b| b.is_ascii_hexdigit()), "{nonce}");
        assert_ne!(random_nonce(), nonce, "随机源不可复现");

        let created = utc_created();
        assert_eq!(created.len(), 20, "{created}");
        assert!(created.ends_with('Z'), "{created}");
    }

    // 表单编码细节:保留字符原样、空格转 +、非 ASCII 按 UTF-8 %XX。
    #[test]
    fn test_form_urlencode() {
        assert_eq!(form_urlencode("aBc-_.~123"), "aBc-_.~123");
        assert_eq!(form_urlencode("a b"), "a+b");
        assert_eq!(form_urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(form_urlencode("+86"), "%2B86");
        assert_eq!(form_urlencode("验证"), "%E9%AA%8C%E8%AF%81");
    }
}
