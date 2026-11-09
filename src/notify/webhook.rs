//! HTTP 回调渠道(webhook):把通知正文 POST 到对端地址。
//!
//! 发成什么形状由 [`Config`] 决定,其中 `sign_style` 是本渠道的核心约定——
//! 它决定"签名怎么算、签名放哪、用什么判对端收下了没有":
//!
//! - `CUSTOM`(空串按它,历史行为):HMAC 自有方案。签名 = `sha256=<hex(hmac_sha256(secret, "<秒>.<body>"))>`,
//!   放 `X-Gw-Timestamp`(秒)/ `X-Gw-Signature` 两个请求头;判成败只看 HTTP 状态码。
//!   把时间戳折进签名是为了让"同一份 body 重放"必须同时重放时间戳。
//! - `NONE`:什么都不带(配了 Secret 也不签);正文仍用默认形状。
//! - `DINGTALK`:钉钉群机器人。签名 = `base64(hmac_sha256(key=secret, data="<毫秒>\n<secret>"))`,
//!   与毫秒时间戳一起拼进 URL query 的 `timestamp`/`sign`;判应答 body 的 `errcode`。
//! - `FEISHU`:飞书群机器人。签名 = `base64(hmac_sha256(key="<秒>\n<secret>", data=空))`,
//!   在模板渲染之后并进正文顶层的 `timestamp`/`sign` 字段;判应答 body 的 `code`。
//! - `WECOM`:企微群机器人。凭据在 URL 的 key 上,不带签名;判应答 body 的 `errcode`。
//!
//! 为什么非得看 body:三家都会在 HTTP 200 里返回失败(钉钉被关键词/安全策略拦下时
//! 给的就是 200 + errcode 310000),只看状态码会把"对方没收"记成投递成功。
//!
//! 正文形状是另一件事(`payload_template`):占位符 `{{name}}` 单趟替换,变量值按
//! JSON 字符串内容转义、不加引号(引号归模板作者)。空模板时,CUSTOM/NONE 用默认的
//! `{"title","content","delivered_at"}` 三字段形状(或 `default_payload` 钩子接管),
//! 三家机器人各用内置 text 模板。
//!
//! 出站地址取自 `Message.target`——"这条到底发去了哪里"由调用方的投递记录回答。

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt,
    Service as NotifyService,
};

/// CUSTOM 风格的签名头:对端用 Secret 按 `sha256=<hex(hmac("<timestamp>.", body))>` 复算比对。
pub const HEADER_SIGNATURE: &str = "X-Gw-Signature";
/// CUSTOM 风格的时间戳头:与签名成对出现,签名覆盖 `<timestamp>.<body>`。
pub const HEADER_TIMESTAMP: &str = "X-Gw-Timestamp";

/// 读对端应答的上限:判"200 但其实没收"要看 body,
/// 而各家机器人的结论都是一个几百字节的小 JSON。
const ANSWER_BYTES: usize = 4 * 1024;
/// 失败时截入错误文案的对端响应体上限。只用于排障,刻意小:对端可能回一整页 HTML。
const MAX_RESPONSE_BYTES: usize = 512;

/// 出站请求头的默认 User-Agent。
pub const DEFAULT_USER_AGENT: &str = "rust-utils-notify/1.0";

/// CUSTOM/NONE 且未配模板时的正文钩子:返回值经 serde 原样出站(字段类型归调用方)。
/// `None` 用库内置默认 `{"title","content","delivered_at"}`。
pub type DefaultPayloadHook = Arc<dyn Fn(&Message) -> Result<Value, String> + Send + Sync>;

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// 一条 WEBHOOK 渠道的配置。
#[derive(Clone, Default)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案——库里可能配了好几条,
    /// 报错要能定位"是哪条"。
    pub ref_: String,
    /// 签名密钥。各风格对它的用法见模块文档;空串即不签名。
    pub secret: String,
    /// 签名风格:`CUSTOM / NONE / DINGTALK / FEISHU / WECOM`。
    /// 空串按 CUSTOM(历史行为),认不出的值报错而不是静默兜底。
    pub sign_style: String,
    /// 载荷模板,占位符 `{{name}}` 单趟替换;空串表示用默认正文。
    pub payload_template: String,
    /// CUSTOM/NONE 且未配模板时的正文钩子;`None` 用库内置默认三字段形状。
    pub default_payload: Option<DefaultPayloadHook>,
    /// 出站请求头,空串用库默认。
    pub user_agent: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("ref_", &self.ref_)
            .field("secret", &"<redacted>")
            .field("sign_style", &self.sign_style)
            .field("payload_template", &self.payload_template)
            .field("default_payload", &self.default_payload.is_some())
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 风格
// ---------------------------------------------------------------------------

/// 一条 WEBHOOK 渠道的"出站风格":签名怎么算、签名放哪、用什么判对端收下了没有。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookStyle {
    /// HMAC 自有方案(签名头 + 只看状态码)。
    Custom,
    /// 不签名,只发默认正文。
    None,
    /// 钉钉群机器人(签名进 URL query,毫秒时间戳)。
    Dingtalk,
    /// 飞书群机器人(签名进正文顶层,秒时间戳)。
    Feishu,
    /// 企微群机器人(凭据在 URL,不带签名)。
    Wecom,
}

/// 风格串 → 风格。
///
/// 空串按 CUSTOM:存储里这一列可空,NULL 的语义就是"加列之前只有 CUSTOM 一种行为"。
/// 认不出的值报错而不是兜成 CUSTOM:把 DINGTALK 拼成 DINGTAKL 后静默按自有方案发出去,
/// 对端只表现为"签名不对",排查方向整个是反的。大小写敏感。
pub fn resolve_style(raw: &str) -> Result<WebhookStyle, String> {
    match raw {
        "" => Ok(WebhookStyle::Custom),
        "CUSTOM" => Ok(WebhookStyle::Custom),
        "NONE" => Ok(WebhookStyle::None),
        "DINGTALK" => Ok(WebhookStyle::Dingtalk),
        "FEISHU" => Ok(WebhookStyle::Feishu),
        "WECOM" => Ok(WebhookStyle::Wecom),
        other => Err(format!(
            "unknown webhook sign style {other:?} (expected CUSTOM / NONE / DINGTALK / FEISHU / WECOM)"
        )),
    }
}

/// 该风格用哪个 body 字段判"对端真的收下了"。
fn verdict_field_of(style: WebhookStyle) -> &'static str {
    match style {
        WebhookStyle::Dingtalk | WebhookStyle::Wecom => "errcode",
        WebhookStyle::Feishu => "code",
        WebhookStyle::Custom | WebhookStyle::None => "",
    }
}

/// 该风格的时间戳精度:钉钉要毫秒,其余按秒。
fn webhook_timestamp(style: WebhookStyle) -> String {
    let now = chrono::Utc::now();
    if style == WebhookStyle::Dingtalk {
        now.timestamp_millis().to_string()
    } else {
        now.timestamp().to_string()
    }
}

/// 当前时刻的 RFC3339(UTC,秒精度,`Z` 后缀)。
fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// 签名
// ---------------------------------------------------------------------------

/// HMAC-SHA256("<timestamp>.", body) 的十六进制(CUSTOM 风格)。
fn sign_webhook_body(secret: &str, timestamp: &str, body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac 接受任意长度密钥");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

/// 钉钉:base64(hmac_sha256(key=secret, data="<ms>\n<secret>"))。
///
/// 密钥与消息的分工容易记反——它和飞书恰好相反(钉钉 key=secret,飞书 key=待签串、数据为空),
/// 而两种写法的错误表现都是对端回 "sign not match",所以测试各钉一条向量。
fn sign_dingtalk(secret: &str, timestamp: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac 接受任意长度密钥");
    mac.update(format!("{timestamp}\n{secret}").as_bytes());
    base64_standard(&mac.finalize().into_bytes())
}

/// 飞书:base64(hmac_sha256(key="<s>\n<secret>", data=空))。
fn sign_feishu(secret: &str, timestamp: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(format!("{timestamp}\n{secret}").as_bytes())
        .expect("hmac 接受任意长度密钥");
    mac.update(b"");
    base64_standard(&mac.finalize().into_bytes())
}

/// 小写十六进制编码。
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 标准 base64(带 `=` 填充),用于签名向量与 Basic 认证。
fn base64_standard(data: &[u8]) -> String {
    base64_with(
        data,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        true,
    )
}

/// URL 安全 base64(不带填充),用于随机 nonce(对齐 Go crand.Text 的形状)。
fn base64_url_nopad(data: &[u8]) -> String {
    base64_with(
        data,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        false,
    )
}

fn base64_with(data: &[u8], table: &[u8; 64], padded: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(table[(n >> 18) as usize & 63] as char);
        out.push(table[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(table[(n >> 6) as usize & 63] as char);
        } else if padded {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(table[n as usize & 63] as char);
        } else if padded {
            out.push('=');
        }
    }
    out
}

/// 会话内唯一的随机串(16 随机字节的 URL 安全 base64)。
fn nonce_text() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("getrandom 生成随机字节失败");
    base64_url_nopad(&buf)
}

// ---------------------------------------------------------------------------
// 模板
// ---------------------------------------------------------------------------

/// 各风格的内置默认正文(调用方没配 PayloadTemplate 时用)。
///
/// 只有 text 一种消息形状:markdown 与卡片的结构三家各不同,且都要额外的排版决策;
/// text 足够让一条通知进群被人看见。企微 text 正文上限 2048 字节、钉钉 20000——
/// 这里不截断:按字节数腰斩一条通知,不如让对端的报错说清楚"太长了"。
const BUILTIN_DINGTALK: &str = r#"{"msgtype":"text","text":{"content":"{{title}}\n{{content}}"}}"#;
const BUILTIN_FEISHU: &str = r#"{"msg_type":"text","content":{"text":"{{title}}\n{{content}}"}}"#;
const BUILTIN_WECOM: &str = r#"{"msgtype":"text","text":{"content":"{{title}}\n{{content}}"}}"#;

/// 转义成 JSON 字符串内容(不含首尾引号)。
///
/// serde_json 不做 HTML 转义:中文正文里出现 `< > &` 时不该被写成 `\u003c`,
/// 那会让群里的 `<at>` 标签变成一串字面量。
fn json_escape_string(s: &str) -> String {
    let encoded = Value::String(s.to_string()).to_string();
    encoded[1..encoded.len() - 1].to_string()
}

/// 占位符表。值一律按 JSON 字符串内容转义、不加引号:
/// 于是放在引号里的 `{{title}}` 与不放在引号里的 `{{recipient_user_id}}` 都能用,引号归模板作者。
///
/// 基础变量之外,`Message.params` 的每个键都成为同名占位符(可覆盖基础变量):
/// 渠道想暴露业务侧的事件类型、关联 ID 之类,从 params 传入即可。
fn webhook_vars(msg: &Message, timestamp: &str, sign: &str) -> HashMap<String, String> {
    let mut vars: HashMap<String, String> = HashMap::new();
    vars.insert("title".into(), json_escape_string(&msg.title));
    vars.insert("content".into(), json_escape_string(&msg.content));
    vars.insert("delivered_at".into(), json_escape_string(&rfc3339_now()));
    vars.insert("timestamp".into(), json_escape_string(timestamp));
    vars.insert("nonce".into(), nonce_text());

    // 没有签名可暴露时把键删掉,而不是留一个空串:空串会让对端收到 "sign":"",
    // 看上去像"签了个空签名",而真实情况是这条渠道压根没配密钥。
    if !sign.is_empty() {
        vars.insert("sign".into(), json_escape_string(sign));
    }

    for (key, value) in &msg.params {
        vars.insert(key.clone(), json_escape_string(value));
    }

    vars
}

/// 单趟替换 `{{name}}`。
///
/// 不用逐变量替换:那样 `{{content}}` 的值里若含 `{{title}}`,后一轮替换会把正文文本
/// 当模板再渲染一次。单趟扫描让每个值只出现一次,天然不递归。
/// 未识别的占位符报错——拼错的 `{{contnet}}` 原样留在正文里,对端只会收到一串花括号。
fn render_template(template: &str, vars: &HashMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());

    let mut rest = template;
    while !rest.is_empty() {
        let Some(open) = rest.find("{{") else {
            out.push_str(rest);
            break;
        };
        let after_open = &rest[open + 2..];
        let Some(closing) = after_open.find("}}") else {
            // 没有闭合:当正文尾巴原样发出("{{" 在 JSON 字符串里是合法内容,不值得为它失败)。
            out.push_str(rest);
            break;
        };
        let name = &after_open[..closing];
        let Some(value) = vars.get(name) else {
            return Err(format!(
                "payload template uses unsupported placeholder {{{{{}}}}}",
                name
            ));
        };
        out.push_str(&rest[..open]);
        out.push_str(value);
        rest = &after_open[closing + 2..];
    }

    Ok(out)
}

/// 把 timestamp / sign 并进正文顶层对象(飞书要求的签名落点)。
///
/// 只并顶层:飞书看的是 body 顶层那两个字段。模板作者把文字渲染进 content.text 里,
/// 不该为此负责信封字段——所以渲染结果必须是 JSON 对象,否则这里报错。
fn merge_envelope(body: &str, timestamp: &str, sign: &str) -> Result<String, String> {
    let mut envelope: Map<String, Value> = serde_json::from_str(body).map_err(|_| {
        format!(
            "feishu signature goes into the body, so the payload template must render a JSON object; got: {}",
            truncate_for_error(body)
        )
    })?;
    envelope.insert("timestamp".into(), Value::String(timestamp.to_string()));
    envelope.insert("sign".into(), Value::String(sign.to_string()));
    serde_json::to_string(&envelope).map_err(|e| format!("merge envelope fields failed: {e}"))
}

/// 进错误文案的响应片段截断:对端可能回一整页 HTML。
fn truncate_for_error(body: &str) -> String {
    if body.len() <= MAX_RESPONSE_BYTES {
        return body.to_string();
    }
    format!("{}…", body_floor_boundary(MAX_RESPONSE_BYTES, body))
}

/// 按字节截断但不劈开 UTF-8 字符(Go 按字节硬切会产生乱码,Rust 退到字符边界)。
fn body_floor_boundary(limit: usize, body: &str) -> &str {
    let mut end = limit.min(body.len());
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    &body[..end]
}

// ---------------------------------------------------------------------------
// 出站请求
// ---------------------------------------------------------------------------

/// build_outbound 的渲染结果:发什么、签名放哪、用什么判成败。
#[derive(Debug)]
struct Rendered {
    body: String,
    /// 放进请求头的签名(CUSTOM)。空则不带。
    timestamp_header: String,
    signature_header: String,
    /// 钉钉要拼进 URL 的签名参数;None 表示不改地址。
    dingtalk_query: Option<(String, String)>,
}

/// build_request 的最终产物:一切就绪、只待发送的出站请求。
struct Outbound {
    method: &'static str,
    url: String,
    body: String,
    timestamp_header: String,
    signature_header: String,
}

/// WEBHOOK 渠道。
pub struct Service {
    client: ureq::Agent,
    allow_private: bool,
    cfg: Config,
}

impl Service {
    /// 构造 WEBHOOK 渠道。
    ///
    /// `allow_private = true`(本机联调)时整条 SSRF 防线关闭(连环回都能发);
    /// 生产部署必须传 `false`(出站既过 [`check_target`] 预检,也过客户端守卫解析器)。
    pub fn new(allow_private: bool, cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.user_agent.is_empty() {
            cfg.user_agent = DEFAULT_USER_AGENT.to_string();
        }
        Service {
            client: new_client(allow_private),
            allow_private,
            cfg,
        }
    }

    /// 渠道名。
    pub fn name(&self) -> &str {
        "webhook"
    }

    /// 配置自检:风格认得出来、模板渲染得出合法 JSON。只渲染不拨号。
    ///
    /// 用一份假正文渲染:模板能引用的变量与内容无关,"能不能渲染成合法 JSON"也与之无关——
    /// 调用方在入队一次性消息(如验证码)之前先跑它,别等消息躺在队列里失败四次。
    pub fn precheck(&self) -> Result<(), NotifyError> {
        let style = self.style()?;
        let probe =
            Message::new("https://precheck.invalid/hook", "precheck").with_content("precheck");
        self.build_outbound(style, &probe).map(|_| ())
    }

    /// 给错误垫上"是哪条配置"的前缀;配了 Ref 才带渠道段。
    /// 前缀只垫一次:内层消息不再写 "webhook:",否则错误文案念成结巴。
    fn prefix(&self, msg: &str) -> String {
        if self.cfg.ref_.is_empty() {
            format!("webhook: {msg}")
        } else {
            format!("webhook: channel [{}] {}", self.cfg.ref_, msg)
        }
    }

    fn style(&self) -> Result<WebhookStyle, NotifyError> {
        resolve_style(&self.cfg.sign_style).map_err(|e| NotifyError::NotConfigured(self.prefix(&e)))
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        let endpoint = normalize_url(&msg.target)?;
        let style = self.style()?;
        let rendered = self.build_outbound(style, msg)?;

        let mut url = endpoint;
        if let Some((timestamp, sign)) = rendered.dingtalk_query {
            // 钉钉把签名拼在 URL query 上:保留对端原本要看的 access_token 等参数,只追加两个键。
            url = merge_query(&url, &[("timestamp", &timestamp), ("sign", &sign)]);
        }

        Ok(Outbound {
            method: "POST",
            url,
            body: rendered.body,
            timestamp_header: rendered.timestamp_header,
            signature_header: rendered.signature_header,
        })
    }

    /// 按风格算出正文与签名(纯函数,离线可测)。
    ///
    /// 渲染顺序就是这件事的难点:钉钉/飞书的签名只盖时间戳与密钥、不盖正文,所以签名能先算出来、
    /// 再当占位符用;CUSTOM 的签名盖住正文,于是正文里不可能出现 `{{sign}}` —— 引用它就在这儿报错,
    /// 而不是渲染出一个空串让对端验签失败。
    fn build_outbound(&self, style: WebhookStyle, msg: &Message) -> Result<Rendered, NotifyError> {
        let timestamp = webhook_timestamp(style);

        // body_sign 只在"签名不依赖正文"的风格里有值;有值才作为 {{sign}} 暴露。
        let mut body_sign = String::new();
        let mut rendered = Rendered {
            body: String::new(),
            timestamp_header: String::new(),
            signature_header: String::new(),
            dingtalk_query: None,
        };

        match style {
            WebhookStyle::Dingtalk => {
                if !self.cfg.secret.is_empty() {
                    body_sign = sign_dingtalk(&self.cfg.secret, &timestamp);
                    rendered.dingtalk_query = Some((timestamp.clone(), body_sign.clone()));
                }
            }
            WebhookStyle::Feishu => {
                if !self.cfg.secret.is_empty() {
                    body_sign = sign_feishu(&self.cfg.secret, &timestamp);
                }
            }
            WebhookStyle::Custom => {
                // 头里的时间戳先定下来:它不进正文,也就不可能形成循环。
                rendered.timestamp_header = timestamp.clone();
            }
            WebhookStyle::None | WebhookStyle::Wecom => {
                // 无签名:企微的凭据在 URL 的 key 上,NONE 是什么都不带。
            }
        }

        rendered.body = self.render_body(style, msg, &timestamp, &body_sign)?;

        // 飞书把签名当正文字段,所以它必须在模板渲染之后并进顶层对象。
        if style == WebhookStyle::Feishu && !self.cfg.secret.is_empty() {
            rendered.body = merge_envelope(&rendered.body, &timestamp, &body_sign)
                .map_err(|e| NotifyError::NotConfigured(self.prefix(&e)))?;
        }

        if style == WebhookStyle::Custom && !self.cfg.secret.is_empty() {
            rendered.signature_header = format!(
                "sha256={}",
                sign_webhook_body(&self.cfg.secret, &timestamp, &rendered.body)
            );
        }

        Ok(rendered)
    }

    /// 渲染出站正文(纯函数,离线可测)。
    ///
    /// 风格只管"签名怎么算、放哪、用什么判成败",正文形状是另一件事:
    /// CUSTOM 与 NONE 的默认正文来自 default_payload 钩子(没配钩子用库内置的三字段形状),
    /// 三家群机器人各用内置 text 模板。
    fn render_body(
        &self,
        style: WebhookStyle,
        msg: &Message,
        timestamp: &str,
        sign: &str,
    ) -> Result<String, NotifyError> {
        let template = if !self.cfg.payload_template.is_empty() {
            self.cfg.payload_template.clone()
        } else if matches!(style, WebhookStyle::Custom | WebhookStyle::None) {
            let payload = match &self.cfg.default_payload {
                Some(hook) => hook(msg).map_err(|e| {
                    NotifyError::NotConfigured(self.prefix(&format!("default payload: {e}")))
                })?,
                None => json!({
                    "title": msg.title,
                    "content": msg.content,
                    "delivered_at": rfc3339_now(),
                }),
            };
            return serde_json::to_string(&payload).map_err(|e| {
                NotifyError::NotConfigured(self.prefix(&format!("encode payload failed: {e}")))
            });
        } else {
            match style {
                WebhookStyle::Dingtalk => BUILTIN_DINGTALK,
                WebhookStyle::Feishu => BUILTIN_FEISHU,
                WebhookStyle::Wecom => BUILTIN_WECOM,
                _ => unreachable!("CUSTOM/NONE 的默认正文已在上方处理"),
            }
            .to_string()
        };

        let vars = webhook_vars(msg, timestamp, sign);
        let rendered = render_template(&template, &vars)
            .map_err(|e| NotifyError::NotConfigured(self.prefix(&e)))?;
        if serde_json::from_str::<Value>(&rendered).is_err() {
            return Err(NotifyError::NotConfigured(self.prefix(&format!(
                "payload template rendered invalid JSON: {}",
                truncate_for_error(&rendered)
            ))));
        }
        Ok(rendered)
    }

    /// 解析 2xx 应答:该风格下对端 body 是否报失败。
    fn parse_response(&self, style: WebhookStyle, body: &str) -> Result<Receipt, NotifyError> {
        check_provider_response(style, body)?;
        Ok(Receipt::default())
    }

    /// 处理一个已拿到的响应:状态码判门,2xx 之后才轮到 body 说话。
    fn finish(&self, style: WebhookStyle, resp: ureq::Response) -> Result<Receipt, NotifyError> {
        let status = resp.status();
        let body = read_body_limited(resp, ANSWER_BYTES);
        if !(200..=299).contains(&status) {
            return Err(status_error(status, &body));
        }
        self.parse_response(style, &body)
    }

    /// 真正发一次出站。
    fn deliver(&self, out: &Outbound, style: WebhookStyle) -> Result<Receipt, NotifyError> {
        let mut req = self.client.request(out.method, &out.url);
        req = req
            .set("Content-Type", "application/json; charset=utf-8")
            .set("User-Agent", &self.cfg.user_agent);
        if !out.timestamp_header.is_empty() {
            req = req.set(HEADER_TIMESTAMP, &out.timestamp_header);
        }
        if !out.signature_header.is_empty() {
            req = req.set(HEADER_SIGNATURE, &out.signature_header);
        }

        match req.send_string(&out.body) {
            Ok(resp) => self.finish(style, resp),
            Err(ureq::Error::Status(status, resp)) => {
                let body = read_body_limited(resp, ANSWER_BYTES);
                Err(status_error(status, &body))
            }
            Err(err) => Err(map_ureq_error(err)),
        }
    }
}

impl NotifyService for Service {
    fn name(&self) -> &str {
        Service::name(self)
    }

    /// 投递一次回调。返回 [`NotifyError`] 一律是"投递失败";配置类失败(含 SSRF 拦网)
    /// 归 `NotifyError::NotConfigured` / `NotifyError::BlockedTarget`(都没联系到对端),
    /// 调用方据此与"拨过号被拒"的 [`NotifyError::Delivery`] 区分开。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "webhook target url is empty".into(),
            ));
        }

        let out = self.build_request(msg)?;

        if !self.allow_private {
            check_target(&out.url)?;
        }

        let style = self.style()?;
        self.deliver(&out, style)
    }
}

/// 只放行绝对 http(s) 地址。
///
/// 相对地址(`//10.0.0.5/x`、`/y`)在这一步被挡掉:它们到了 HTTP 客户端那里
/// 会报一个不含原址的错,排障时看不出"配在库里的值本来就不是绝对地址"。
pub fn normalize_url(raw: &str) -> Result<String, NotifyError> {
    let (scheme, rest) = match raw.split_once("://") {
        Some(pair) => pair,
        None => {
            return Err(NotifyError::NotConfigured(format!(
                "webhook url {raw:?} is invalid: not an absolute url"
            )))
        }
    };
    if scheme != "http" && scheme != "https" {
        return Err(NotifyError::NotConfigured(format!(
            "webhook url {raw:?} must be http(s)"
        )));
    }
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    if host.is_empty() {
        return Err(NotifyError::NotConfigured(format!(
            "webhook url {raw:?} has no host"
        )));
    }
    Ok(raw.to_string())
}

// ---------------------------------------------------------------------------
// 出站辅助(本地小工具;translator 模块被 feature 门控,notify 不依赖它)
// ---------------------------------------------------------------------------

/// 把对端应答读进来并限长。
fn read_body_limited(resp: ureq::Response, limit: usize) -> String {
    let mut buf = Vec::new();
    let _ = resp.into_reader().take(limit as u64).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// 非 2xx 状态的错误:带状态码与响应片段。
fn status_error(status: u16, body: &str) -> NotifyError {
    NotifyError::Delivery(format!(
        "peer answered {status}: {}",
        truncate_snippet(body)
    ))
}

/// 应答片段截断:进错误文案就够排障了,别把一整页 HTML 塞进去。
fn truncate_snippet(body: &str) -> String {
    const SNIPPET_LIMIT: usize = 256;
    if body.len() <= SNIPPET_LIMIT {
        return body.to_string();
    }
    format!("{}…", body_floor_boundary(SNIPPET_LIMIT, body))
}

/// URL 查询成分编码(按字节:ASCII 字母数字与 `-_.~` 直通,空格作 `+`,其余 `%XX`)。
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

/// URL 查询成分解码(`+` 还原成空格,`%XX` 还原成字节)。
fn query_unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push(((hi << 4) | lo) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 往 endpoint 的 query 上合并参数(同名键覆盖),按键名排序重编(对齐 Go url.Values.Encode)。
fn merge_query(endpoint: &str, adds: &[(&str, &str)]) -> String {
    let (base, raw_query) = match endpoint.split_once('?') {
        Some((base, q)) => (base, q),
        None => (endpoint, ""),
    };

    let mut pairs: Vec<(String, String)> = raw_query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (query_unescape(k), query_unescape(v)),
            None => (query_unescape(p), String::new()),
        })
        .collect();
    for (k, v) in adds {
        pairs.retain(|(ek, _)| ek != k);
        pairs.push(((*k).to_string(), (*v).to_string()));
    }
    pairs.sort();

    let encoded: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect();
    let joined = encoded.join("&");
    if joined.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{joined}")
    }
}

/// 该风格下对端 body 是否报失败。
///
/// 只在 2xx 之后调用:非 2xx 由 send 的失败分支带状态码与响应片段报出去。
/// body 不是 JSON 时放行——对端已经用 2xx 表了态,猜它的意思比承认"看不出"更糟。
fn check_provider_response(style: WebhookStyle, body: &str) -> Result<(), NotifyError> {
    let verdict = verdict_field_of(style);
    if verdict.is_empty() {
        return Ok(());
    }

    let Ok(answer) = serde_json::from_str::<Value>(body) else {
        return Ok(());
    };
    let Some(obj) = answer.as_object() else {
        return Ok(());
    };

    let err_code = obj.get("errcode").and_then(Value::as_i64);
    let code = obj.get("code").and_then(Value::as_i64);
    let code = if verdict == "code" { code } else { err_code };
    let Some(code) = code.filter(|c| *c != 0) else {
        return Ok(());
    };

    let mut reason = obj.get("errmsg").and_then(Value::as_str).unwrap_or("");
    if reason.is_empty() {
        reason = obj.get("msg").and_then(Value::as_str).unwrap_or("");
    }
    if reason.is_empty() {
        reason = "no message";
    }
    Err(NotifyError::Delivery(format!(
        "peer answered 200 but {verdict}={code}: {reason}"
    )))
}

// ---------------------------------------------------------------------------
// 测试(纯离线:构造、签名、模板、判据;不发 HTTP)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 两家机器人官方文档示例里用的密钥,向量是照它算的。
    const SECRET: &str = "xxx";
    /// 官方示例时间戳(2022-08-30)。
    const TS: &str = "1661860880";
    /// 飞书 sign("xxx", 1661860880) 的期望值:
    /// base64(hmac_sha256(key="1661860880\nxxx", data=空)),取自飞书开放平台文档。
    const WANT_FEISHU_SIGN: &str = "QnWVTSBe6FmQDE0bG6X0mURbI+DnvVyu1h+j5dHOjrU=";
    /// 钉钉同输入下的期望值:
    /// base64(hmac_sha256(key="xxx", data="1661860880\nxxx"))(按官方公式独立算出)。
    const WANT_DINGTALK_SIGN: &str = "dIUMcehSFkPlWOGqwoP5EFcartyN67QSY9wbVW+hTbE=";

    fn style_service(style: &str, template: &str, secret: &str) -> Service {
        Service::new(
            true,
            Config {
                ref_: "7".into(),
                secret: secret.into(),
                sign_style: style.into(),
                payload_template: template.into(),
                ..Config::default()
            },
        )
    }

    fn style_msg() -> Message {
        Message::new("https://example.com/hook", "重置验证码").with_content("您的验证码是 123456")
    }

    fn json_eq(actual: &str, expected: &str) {
        let a: Value = serde_json::from_str(actual).expect("actual 是合法 JSON");
        let b: Value = serde_json::from_str(expected).expect("expected 是合法 JSON");
        assert_eq!(a, b, "JSON 不等\nactual:   {a}\nexpected: {b}");
    }

    /// 解析出 URL 的 query 对(解码回原值)。
    fn query_pairs(url: &str) -> Vec<(String, String)> {
        let raw = url.split_once('?').map(|(_, q)| q).unwrap_or("");
        raw.split('&')
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (query_unescape(k), query_unescape(v)),
                None => (query_unescape(p), String::new()),
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // 签名向量
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_vectors() {
        // 两条一起看才看得出这条测试的意义:钉钉是 key=secret / data="<ts>\n<secret>",
        // 飞书是 key="<ts>\n<secret>" / data=空 —— 分工记反时对端只回一句 "sign not match"。
        assert_eq!(sign_dingtalk(SECRET, TS), WANT_DINGTALK_SIGN);
        assert_eq!(sign_feishu(SECRET, TS), WANT_FEISHU_SIGN);
        assert_ne!(
            sign_dingtalk(SECRET, TS),
            sign_feishu(SECRET, TS),
            "两个算法在同样输入下必须产出不同值"
        );
    }

    #[test]
    fn test_custom_sign_covers_timestamp_dot_body() {
        // CUSTOM 的签名覆盖 "<时间戳>.<正文>" 这整个串。
        let body = r#"{"content":"c","delivered_at":"x","title":"t"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(TS.as_bytes());
        mac.update(b".");
        mac.update(body.as_bytes());
        let want = hex_encode(&mac.finalize().into_bytes());
        assert_eq!(sign_webhook_body(SECRET, TS, body), want);
    }

    // -----------------------------------------------------------------------
    // 风格解析与判据
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_style() {
        // 空串按 CUSTOM:这一列可空,空的语义就是"当时只有 CUSTOM 一种行为"。
        assert_eq!(resolve_style("").unwrap(), WebhookStyle::Custom);
        for (raw, want) in [
            ("CUSTOM", WebhookStyle::Custom),
            ("NONE", WebhookStyle::None),
            ("DINGTALK", WebhookStyle::Dingtalk),
            ("FEISHU", WebhookStyle::Feishu),
            ("WECOM", WebhookStyle::Wecom),
        ] {
            assert_eq!(resolve_style(raw).unwrap(), want, "{raw}");
        }

        // 大小写敏感:钉钉拼成小写也不能认,那会让"配置里写的是什么"与"发出去的是什么"分家。
        for raw in [
            "custom", "DINGTAKL", "DingTalk", "dingtalk", "  FEISHU", "SMS",
        ] {
            let err = resolve_style(raw).unwrap_err();
            assert!(err.contains(raw), "{err} 要带上原值 {raw}");
            assert!(err.contains("CUSTOM / NONE"), "{err} 要说出可取值清单");
        }
    }

    #[test]
    fn test_verdict_field_of() {
        assert_eq!(verdict_field_of(WebhookStyle::Dingtalk), "errcode");
        assert_eq!(verdict_field_of(WebhookStyle::Wecom), "errcode");
        // 飞书的结论字段是 code/msg,不是 errcode。
        assert_eq!(verdict_field_of(WebhookStyle::Feishu), "code");
        assert_eq!(
            verdict_field_of(WebhookStyle::Custom),
            "",
            "自有方案没有约定字段:只看状态码"
        );
        assert_eq!(verdict_field_of(WebhookStyle::None), "");
    }

    // -----------------------------------------------------------------------
    // 各风格的出站构造
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_outbound_dingtalk() {
        let svc = style_service("DINGTALK", "", SECRET);
        let out = svc
            .build_outbound(WebhookStyle::Dingtalk, &style_msg())
            .unwrap();

        assert!(out.timestamp_header.is_empty());
        assert!(
            out.signature_header.is_empty(),
            "钉钉不签 body(签名只盖时间戳与密钥),所以没有签名头"
        );
        assert_eq!(verdict_field_of(WebhookStyle::Dingtalk), "errcode");

        let (ts, sign) = out.dingtalk_query.as_ref().expect("钉钉要有 query 签名");
        // 毫秒:钉钉服务端按 ±1 小时窗口判过期,用秒会直接报"timestamp outside validity period"。
        let ms: i64 = ts.parse().expect("timestamp 是数字");
        assert!(
            ms > 1_000_000_000_000,
            "必须是 13 位毫秒,10 位秒会被当成 1970 年"
        );
        assert!(ms < 10_000_000_000_000);
        assert_eq!(
            sign_dingtalk(SECRET, ts),
            *sign,
            "query 里的 timestamp 与 sign 必须成对"
        );

        // 内置正文是 text 形状,标题与正文之间是 JSON 转义过的 \n。
        let body: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(body["msgtype"], "text");
        assert_eq!(body["text"]["content"], "重置验证码\n您的验证码是 123456");
        assert!(!out.body.contains("sign"), "钉钉的签名不该出现在正文里");
    }

    #[test]
    fn test_build_outbound_dingtalk_unsigned() {
        let svc = style_service("DINGTALK", "", "");
        let out = svc
            .build_outbound(WebhookStyle::Dingtalk, &style_msg())
            .unwrap();

        assert!(
            out.dingtalk_query.is_none(),
            "签名一栏留空时不该往 URL 上拼 timestamp=&sign="
        );
        json_eq(
            &out.body,
            r#"{"msgtype":"text","text":{"content":"重置验证码\n您的验证码是 123456"}}"#,
        );
        assert_eq!(
            verdict_field_of(WebhookStyle::Dingtalk),
            "errcode",
            "判据是风格带的,跟签不签名无关"
        );
    }

    #[test]
    fn test_build_outbound_dingtalk_query_merge_preserves_token() {
        let svc = style_service("DINGTALK", "", SECRET);
        let msg =
            Message::new("https://example.com/hook/?access_token=abc123", "t").with_content("c");
        let out = svc.build_request(&msg).unwrap();

        let pairs = query_pairs(&out.url);
        let get = |k: &str| pairs.iter().find(|(pk, _)| pk == k).map(|(_, v)| v.clone());
        assert_eq!(
            get("access_token").as_deref(),
            Some("abc123"),
            "拼签名必须保留地址原有的参数"
        );
        let ts = get("timestamp").expect("timestamp");
        assert_eq!(ts.chars().count(), 13, "钉钉要 13 位毫秒");
        assert_eq!(
            get("sign").as_deref(),
            Some(sign_dingtalk(SECRET, &ts).as_str()),
            "签名与时间戳成对"
        );
        assert!(out.timestamp_header.is_empty());
        assert!(out.signature_header.is_empty(), "钉丁只认 query,不发签名头");
    }

    #[test]
    fn test_build_outbound_feishu_envelope() {
        let svc = style_service("FEISHU", "", SECRET);
        let out = svc
            .build_outbound(WebhookStyle::Feishu, &style_msg())
            .unwrap();

        assert!(out.dingtalk_query.is_none());
        assert!(out.signature_header.is_empty());
        assert_eq!(verdict_field_of(WebhookStyle::Feishu), "code");

        let envelope: Value = serde_json::from_str(&out.body).unwrap();
        let obj = envelope.as_object().unwrap();
        assert!(obj.contains_key("timestamp"));
        assert!(
            obj.contains_key("sign"),
            "飞书把签名放正文顶层两个字段,不是请求头"
        );

        let ts = envelope["timestamp"].as_str().unwrap();
        assert_eq!(ts.chars().count(), 10, "飞书要 10 位秒时间戳");
        assert_eq!(envelope["sign"], sign_feishu(SECRET, ts).as_str());

        // 并信封不许丢掉模板渲染出来的正文。
        assert_eq!(envelope["msg_type"], "text");
        assert_eq!(
            envelope["content"]["text"],
            "重置验证码\n您的验证码是 123456"
        );
    }

    #[test]
    fn test_build_outbound_feishu_no_html_escape() {
        // 并信封不得把 < > & 转义成 \u003c:飞书/钉钉的 @ 人语法就是 <at> 标签。
        let svc = style_service("FEISHU", "", SECRET);
        let msg = Message::new("https://example.com/hook", "<尖括号> & 与号").with_content("a > b");
        let out = svc.build_outbound(WebhookStyle::Feishu, &msg).unwrap();
        let raw = out.body.clone();
        assert!(!raw.contains("\\u003c"), "并完信封不许再 HTML 转义一次");
        assert!(raw.contains("<尖括号> & 与号\\na > b"), "raw: {raw}");
    }

    #[test]
    fn test_build_outbound_wecom_unsigned() {
        let svc = style_service("WECOM", "", SECRET);
        let out = svc
            .build_outbound(WebhookStyle::Wecom, &style_msg())
            .unwrap();

        assert!(out.dingtalk_query.is_none());
        assert!(out.signature_header.is_empty());
        assert_eq!(verdict_field_of(WebhookStyle::Wecom), "errcode");
        json_eq(
            &out.body,
            r#"{"msgtype":"text","text":{"content":"重置验证码\n您的验证码是 123456"}}"#,
        );
    }

    #[test]
    fn test_build_outbound_custom_default_body() {
        let svc = style_service("CUSTOM", "", SECRET);
        let out = svc
            .build_outbound(WebhookStyle::Custom, &style_msg())
            .unwrap();

        assert_eq!(
            verdict_field_of(WebhookStyle::Custom),
            "",
            "自有方案没约定判据字段:只看状态码"
        );

        let parsed: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(parsed["title"], "重置验证码");
        assert_eq!(parsed["content"], "您的验证码是 123456");
        assert!(parsed.get("delivered_at").is_some());
        assert_eq!(
            parsed.as_object().unwrap().len(),
            3,
            "默认正文就三个字段:业务扩展字段归钩子"
        );
        assert!(
            parsed["delivered_at"].is_string(),
            "delivered_at 是 RFC3339 字符串"
        );

        // 时间戳进头、签名覆盖"时间戳.正文":头里的 ts 必须就是签名里那个。
        assert_eq!(
            out.timestamp_header.chars().count(),
            10,
            "CUSTOM 用秒时间戳"
        );
        assert!(!out.signature_header.is_empty());
        let recomputed = sign_webhook_body(SECRET, &out.timestamp_header, &out.body);
        assert_eq!(
            out.signature_header,
            format!("sha256={recomputed}"),
            "签名必须在正文定型之后算:先签再渲染会让对端复算永远对不上"
        );
    }

    #[test]
    fn test_build_outbound_custom_unsigned() {
        let svc = style_service("CUSTOM", "", "");
        let out = svc
            .build_outbound(WebhookStyle::Custom, &style_msg())
            .unwrap();
        assert!(
            out.signature_header.is_empty(),
            "没有密钥却发一个空签名头,对端会拿它和自己的 HMAC 比"
        );
    }

    #[test]
    fn test_build_outbound_none_uses_default_body() {
        // NONE 只管"不签名",正文仍要有默认形状——内置模板表只登记了三家机器人,
        // NONE 不填模板若渲染出空正文,报出来的是"不是合法 JSON",看不出真正原因。
        let svc = style_service("NONE", "", SECRET);
        let out = svc
            .build_outbound(WebhookStyle::None, &style_msg())
            .unwrap();

        let parsed: Value = serde_json::from_str(&out.body).expect("NONE 不填模板也要出合法 JSON");
        assert_eq!(parsed["title"], "重置验证码");

        assert!(out.dingtalk_query.is_none());
        assert!(
            out.signature_header.is_empty(),
            "NONE 配了密钥也不签:这一列的语义就是\"什么都不带\""
        );
        assert_eq!(verdict_field_of(WebhookStyle::None), "");
    }

    #[test]
    fn test_default_payload_hook() {
        let svc = Service::new(
            true,
            Config {
                ref_: "7".into(),
                sign_style: "CUSTOM".into(),
                default_payload: Some(Arc::new(|msg: &Message| {
                    Ok(json!({
                        "event_type": "PASSWORD_RESET_CODE",
                        "title": msg.title,
                        "recipient_user_id": 1024_i64,
                    }))
                })),
                ..Config::default()
            },
        );

        let out = svc
            .build_outbound(WebhookStyle::Custom, &style_msg())
            .unwrap();
        // 钩子经 serde 原样出站:字段类型归调用方(数字就是数字)。
        json_eq(
            &out.body,
            r#"{"event_type":"PASSWORD_RESET_CODE","title":"重置验证码","recipient_user_id":1024}"#,
        );
    }

    #[test]
    fn test_default_payload_hook_error_is_not_configured() {
        let svc = Service::new(
            true,
            Config {
                ref_: "7".into(),
                sign_style: "CUSTOM".into(),
                default_payload: Some(Arc::new(|_msg: &Message| Err("hook 炸了".into()))),
                ..Config::default()
            },
        );
        let err = svc
            .build_outbound(WebhookStyle::Custom, &style_msg())
            .unwrap_err();
        assert!(err.is_not_configured());
        assert!(err.to_string().contains("default payload: hook 炸了"));
        assert!(err.to_string().contains("channel [7]"));
    }

    // -----------------------------------------------------------------------
    // 模板
    // -----------------------------------------------------------------------

    #[test]
    fn test_template_renders_each_value_as_json_string_content() {
        let mut msg = Message::new("https://example.com/hook", "标题占位");
        msg.title = r#"带"引号"、反斜杠 \ 、换行"#.to_string() + "\n" + "与 <尖括号> & 和 中文";
        msg.content = "正文里有 \t 制表符".to_string() + "\"结束\"";
        msg.params.insert("uid".into(), "1024".into());
        msg.params.insert("rid".into(), "7".into());
        msg.params
            .insert("event_type".into(), "PASSWORD_RESET_CODE".into());

        let template = r#"{"t":"{{title}}","c":"{{content}}","uid":{{uid}},"rid":{{rid}},"e":"{{event_type}}","n":"{{nonce}}"}"#;
        let svc = style_service("NONE", template, "");
        let out = svc.build_outbound(WebhookStyle::None, &msg).unwrap();

        let raw = out.body.clone();
        assert!(
            raw.contains("<尖括号>"),
            "中文正文里的 < > & 不该变成 \\u003c"
        );
        assert!(raw.contains('&'), "同上");
        assert!(
            raw.contains("\"uid\":1024"),
            "Params 值按 JSON 字符串内容转义:纯数字可以裸放"
        );
        assert!(raw.contains("\"rid\":7"));

        let parsed: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(parsed["t"], msg.title);
        assert_eq!(parsed["c"], msg.content);
        assert_eq!(parsed["e"], "PASSWORD_RESET_CODE");
        assert_eq!(parsed["uid"], 1024);

        // 每次投递换一个 nonce:对端据此判"同一时间戳同正文"的重放。
        let out2 = svc.build_outbound(WebhookStyle::None, &msg).unwrap();
        assert_ne!(raw, out2.body);
    }

    #[test]
    fn test_template_is_not_recursive() {
        let mut msg = style_msg();
        msg.title = "{{content}}".into();
        msg.content = "真正文".into();

        let svc = style_service("NONE", r#"{"t":"{{title}}"}"#, "");
        let out = svc.build_outbound(WebhookStyle::None, &msg).unwrap();

        let parsed: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(
            parsed["t"], "{{content}}",
            "逐变量替换会让 {{title}} 的值里的 {{content}} 被后一轮替换掉:单趟扫描每个值只出现一次"
        );
    }

    #[test]
    fn test_template_rejections() {
        struct Case {
            style: &'static str,
            template: &'static str,
            want_cause: &'static str,
        }
        let cases = [
            Case {
                style: "CUSTOM",
                template: r#"{"t":"{{contnet}}"}"#,
                want_cause: "unsupported placeholder {{contnet}}",
            },
            // CUSTOM 的签名盖住正文,正文里引用 {{sign}} 是循环,必须报错。
            Case {
                style: "CUSTOM",
                template: r#"{"t":"{{title}}","s":"{{sign}}"}"#,
                want_cause: "unsupported placeholder {{sign}}",
            },
            Case {
                style: "FEISHU",
                template: "通知:{{title}}",
                want_cause: "rendered invalid JSON",
            },
            Case {
                style: "WECOM",
                template: r#"{"t":"{{title}}}"#,
                want_cause: "rendered invalid JSON",
            },
        ];

        for c in &cases {
            let svc = style_service(c.style, c.template, "");
            let err = svc
                .build_outbound(resolve_style(c.style).unwrap(), &style_msg())
                .unwrap_err();
            assert!(
                err.is_not_configured(),
                "{}: 配置错重试也不会变好",
                c.want_cause
            );
            assert!(
                err.to_string().contains(c.want_cause),
                "{}: {err}",
                c.want_cause
            );
            assert!(
                err.to_string().contains("channel [7]"),
                "{}: 报错要带配置标识",
                c.want_cause
            );
            assert_eq!(
                err.to_string().matches("webhook: ").count(),
                1,
                "{}: 前缀只垫一次,两处都写就把错误文案念成结巴",
                c.want_cause
            );
        }
    }

    #[test]
    fn test_render_template_unclosed_is_literal() {
        // "{{{" 这类值出现在通知正文里不该让整条投递失败:它在 JSON 字符串里是合法内容。
        let mut vars = HashMap::new();
        vars.insert("title".to_string(), "v".to_string());
        let got = render_template(r#"{"t":"{{title}}","x":"{{unclosed"}"#, &vars).unwrap();
        assert_eq!(got, r#"{"t":"v","x":"{{unclosed"}"#);
    }

    // -----------------------------------------------------------------------
    // 预检与目标
    // -----------------------------------------------------------------------

    #[test]
    fn test_precheck() {
        for (style, template, secret) in [
            ("", "", ""),
            ("CUSTOM", "", "k"),
            ("NONE", "", ""),
            ("DINGTALK", "", "k"),
            ("DINGTALK", "", ""),
            (
                "FEISHU",
                r#"{"msg_type":"text","content":{"text":"{{title}}"},"s":"{{sign}}"}"#,
                "k",
            ),
            (
                "WECOM",
                r#"{"msgtype":"text","text":{"content":"{{content}}"}}"#,
                "",
            ),
        ] {
            let svc = style_service(style, template, secret);
            assert!(
                svc.precheck().is_ok(),
                "style={style:?} template={template:?}"
            );
        }

        let broken = [
            ("DINGTAKL", "", ""),
            ("CUSTOM", r#"{"t":{{title}}}"#, ""),
            ("CUSTOM", r#"{"s":"{{sign}}"}"#, "k"),
            ("FEISHU", "plain {{title}}", "k"),
            // 飞书要往顶层并签名字段,模板渲染出数组就并不进去。
            ("FEISHU", r#"["{{title}}"]"#, "k"),
        ];
        for (style, template, secret) in broken {
            let svc = style_service(style, template, secret);
            let err = svc.precheck().unwrap_err();
            assert!(
                err.is_not_configured(),
                "style={style:?}: 配置错属\"没发出去且重试无用\""
            );
            assert!(err.to_string().contains("channel [7]"));
        }
    }

    #[test]
    fn test_normalize_url() {
        for bad in [
            "",
            "/hooks/1",
            "//127.0.0.1/x",
            "ftp://example.com/x",
            "not a url",
        ] {
            let err = normalize_url(bad).unwrap_err();
            assert!(err.is_not_configured(), "{bad:?} 不该放行");
        }
        for ok in ["https://example.com/hook", "http://example.com:8080/h?a=1"] {
            assert_eq!(normalize_url(ok).unwrap(), ok, "{ok:?} 应放行");
        }
    }

    #[test]
    fn test_send_empty_target() {
        // 目标为空是调用方的问题:一次都没联系对端,按"没尝试"归类。
        let svc = Service::new(false, Config::default());
        let err = svc.send(&Message::new("", "t")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_send_blocked_target() {
        // SSRF 防线:生产默认下 127.0.0.1 一次都拨不出去,归 BlockedTarget
        // (Go 的 configErr 双包 ErrNotConfigured+ErrBlockedTarget;Rust 单枚举里 BlockedTarget 即"没联系对端")。
        let svc = Service::new(
            false,
            Config {
                ref_: "7".into(),
                ..Config::default()
            },
        );
        let err = svc
            .send(&Message::new("http://127.0.0.1:1/hook", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
        assert!(err.to_string().contains("127.0.0.1"));
    }

    #[test]
    fn test_send_broken_template_never_dials() {
        // 模板渲染不出合法 JSON:错在出站之前。
        let svc = Service::new(
            true,
            Config {
                ref_: "7".into(),
                sign_style: "CUSTOM".into(),
                payload_template: "通知:{{title}}".into(),
                ..Config::default()
            },
        );
        let err = svc
            .send(&Message::new("https://example.invalid/hook", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "配置错重试也不会变好");
        assert!(err.to_string().contains("channel [7]"));
        assert!(svc.precheck().is_err(), "预检要提前撞出同一个错");
    }

    // -----------------------------------------------------------------------
    // 对端判据
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_provider_response() {
        struct Case {
            name: &'static str,
            style: WebhookStyle,
            body: &'static str,
            want_error: &'static str,
        }
        let cases = [
            Case {
                name: "dingtalk rejected",
                style: WebhookStyle::Dingtalk,
                body: r#"{"errcode":310000,"errmsg":"keywords not in content"}"#,
                want_error: "errcode=310000",
            },
            Case {
                name: "dingtalk ok",
                style: WebhookStyle::Dingtalk,
                body: r#"{"errcode":0,"errmsg":"ok"}"#,
                want_error: "",
            },
            Case {
                name: "dingtalk ignores feishu field",
                style: WebhookStyle::Dingtalk,
                body: r#"{"code":19021}"#,
                want_error: "",
            },
            Case {
                name: "wecom rejected",
                style: WebhookStyle::Wecom,
                body: r#"{"errcode":93000,"errmsg":"invalid webhook k"}"#,
                want_error: "invalid webhook k",
            },
            Case {
                name: "feishu rejected",
                style: WebhookStyle::Feishu,
                body: r#"{"code":19021,"msg":"sign match fail"}"#,
                want_error: "code=19021",
            },
            Case {
                name: "feishu ok",
                style: WebhookStyle::Feishu,
                body: r#"{"code":0,"msg":"success"}"#,
                want_error: "",
            },
            Case {
                name: "custom looks nowhere but status",
                style: WebhookStyle::Custom,
                body: r#"{"errcode":310000}"#,
                want_error: "",
            },
            Case {
                name: "none same",
                style: WebhookStyle::None,
                body: r#"{"errcode":310000}"#,
                want_error: "",
            },
            Case {
                name: "html answer is not guessed",
                style: WebhookStyle::Dingtalk,
                body: "<html>502 Bad Gateway</html>",
                want_error: "",
            },
            Case {
                name: "empty body",
                style: WebhookStyle::Dingtalk,
                body: "",
                want_error: "",
            },
            Case {
                name: "json array",
                style: WebhookStyle::Dingtalk,
                body: "[]",
                want_error: "",
            },
            Case {
                name: "missing verdict field",
                style: WebhookStyle::Feishu,
                body: r#"{"msg":"failed"}"#,
                want_error: "",
            },
        ];

        for c in &cases {
            match check_provider_response(c.style, c.body) {
                Ok(()) => assert!(c.want_error.is_empty(), "{}: 不该报错", c.name),
                Err(err) => {
                    assert!(!c.want_error.is_empty(), "{}: 该报错", c.name);
                    assert!(
                        err.to_string().contains("peer answered 200"),
                        "{}: {err}",
                        c.name
                    );
                    assert!(err.to_string().contains(c.want_error), "{}: {err}", c.name);
                    assert!(
                        !err.is_not_configured(),
                        "{}: 拨过号被拒 = 投递失败,不该按配置失败记账",
                        c.name
                    );
                }
            }
        }
    }

    #[test]
    fn test_truncate_for_error() {
        assert_eq!(truncate_for_error("short"), "short");

        let long = "a".repeat(MAX_RESPONSE_BYTES + 100);
        let got = truncate_for_error(&long);
        assert_eq!(
            got.chars().count(),
            MAX_RESPONSE_BYTES + "…".chars().count()
        );
        assert!(got.ends_with('…'));
    }

    #[test]
    fn test_json_escape_string() {
        assert_eq!(json_escape_string(r#"a"b"#), r#"a\"b"#);
        assert_eq!(json_escape_string(r"a\b"), r"a\\b");
        // 真换行要写成 \n 两字符,否则模板里的 JSON 断成两行。
        assert_eq!(json_escape_string("a\nb"), r"a\nb");
        assert_eq!(json_escape_string("a\tb"), r"a\tb");
        // 不转义 HTML:否则中文正文里的尖括号在群里变成 \u003c。
        assert_eq!(json_escape_string(r"a<b>&c"), r"a<b>&c");
        assert_eq!(json_escape_string(""), "");
        assert_eq!(json_escape_string("中文"), "中文");

        // 转义结果必须能原样嵌进引号里再解回来——这是"引号归模板作者"这一设计的成立前提。
        for raw in [
            r#"带"引号""#,
            "换行\n与\t制表",
            r"反斜杠\",
            r#"<a href="x">&"#,
            "中文",
        ] {
            let want = json!({ "v": raw }).to_string();
            let built = format!(r#"{{"v":"{}"}}"#, json_escape_string(raw));
            json_eq(&built, &want);
        }
    }

    #[test]
    fn test_merge_query() {
        assert_eq!(
            merge_query(
                "https://qyapi.example.com/cgi?access_token=abc&b=2",
                &[("timestamp", "1"), ("sign", "a+b")]
            ),
            "https://qyapi.example.com/cgi?access_token=abc&b=2&sign=a%2Bb&timestamp=1",
            "原有参数保留、新键追加、按键名排序重编"
        );
        assert_eq!(
            merge_query("https://e.com/x", &[("k", "v")]),
            "https://e.com/x?k=v"
        );
        // 同名键覆盖
        assert_eq!(
            merge_query("https://e.com/x?k=old", &[("k", "new")]),
            "https://e.com/x?k=new"
        );
    }

    #[test]
    fn test_query_escape_unescape_roundtrip() {
        for raw in ["a b", "a&b=c", "中文+加号", "a/b?c", ""] {
            assert_eq!(query_unescape(&query_escape(raw)), raw, "{raw:?}");
        }
        assert_eq!(query_escape("a b"), "a+b");
    }

    #[test]
    fn test_signature_header_and_user_agent_constants() {
        // CUSTOM 风格签名头名对端要照收;UA 是本 crate 品牌串(Go 上游为 go-utils-notify/1.0)。
        assert_eq!(HEADER_SIGNATURE, "X-Gw-Signature");
        assert_eq!(HEADER_TIMESTAMP, "X-Gw-Timestamp");
        assert_eq!(DEFAULT_USER_AGENT, "rust-utils-notify/1.0");
    }
}
