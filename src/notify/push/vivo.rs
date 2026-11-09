//! vivo 推送(appId/appKey/appSecret 鉴权三元组 + MD5 签名),feature `notify`。
//! 对齐上游 `push/vivo.go`。
//!
//! vivo 通知栏消息不支持数据面——`Message::params` 被忽略,业务数据请自行并进
//! `content`。vivo 有每小时推送量窗等厂商硬限制:失败如实上报,不做静默整形。
//! 响应码 10080 归 [`NotifyError::InvalidToken`]。
//!
//! 说明:MD5 属于「notify」feature 未携带的依赖,这里内嵌一份纯 std 的 RFC 1321
//! 实现(全 crate 禁 unsafe,不动 Cargo.toml),仅用于本签名。

use crate::notify::{Message, NotifyError, Receipt, Service};

/// vivo Push 单播通知端点。
pub const VIVO_SEND_URL: &str = "https://push-api.vivo.com.cn/message/notify/unicast";

/// "regId 无效"响应码(厂商码漂移只改这里)。
const VIVO_INVALID_CODE: i64 = 10080;

/// vivo 推送配置(鉴权三元组)。
#[derive(Debug, Clone, Default)]
pub struct VivoConfig {
    /// 应用 ID。
    pub app_id: String,
    /// 应用 Key。
    pub app_key: String,
    /// 应用 Secret。
    pub app_secret: String,
    /// 端点,留空用官方;测试可覆盖。
    pub send_url: String,
}

/// vivo 推送渠道。无状态,可并发使用。
pub struct Vivo {
    agent: ureq::Agent,
    send_url: String,
    cfg: VivoConfig,
}

impl Vivo {
    /// 构造 vivo 推送渠道;`allow_private` 仅供本机联调时关闭 SSRF 防线。
    pub fn new(allow_private: bool, cfg: VivoConfig) -> Self {
        let send_url = if cfg.send_url.is_empty() {
            VIVO_SEND_URL.to_string()
        } else {
            cfg.send_url.clone()
        };
        Vivo {
            agent: crate::notify::new_client(allow_private),
            send_url,
            cfg,
        }
    }
}

impl Service for Vivo {
    fn name(&self) -> &str {
        "vivo"
    }

    /// 给 Target(vivo regId)推一条通知栏消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("vivo regId is empty".into()));
        }
        if self.cfg.app_id.is_empty()
            || self.cfg.app_key.is_empty()
            || self.cfg.app_secret.is_empty()
        {
            return Err(NotifyError::NotConfigured(
                "vivo config incomplete: app_id/app_key/app_secret required".into(),
            ));
        }

        // 四元组(appId/appKey/timestamp/sign)不成对对端直接拒;
        // 表单里的 sign 必须能用表单里的 timestamp 复算出来。
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let form = super::form_encode(&[
            ("appId".to_string(), self.cfg.app_id.clone()),
            ("appKey".to_string(), self.cfg.app_key.clone()),
            ("content".to_string(), msg.content.clone()),
            ("regId".to_string(), msg.target.clone()),
            (
                "sign".to_string(),
                vivo_sign(&self.cfg.app_key, &timestamp, &self.cfg.app_secret),
            ),
            ("timestamp".to_string(), timestamp),
            ("title".to_string(), msg.title.clone()),
        ]);
        let (status, body) = super::post(
            &self.agent,
            &self.send_url,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &form,
        )?;
        parse_answer(status, &body)?;
        Ok(Receipt::default())
    }
}

/// vivo 请求签名:`MD5(appKey + timestamp + appSecret)` 小写 hex。
/// 签名细节漂移只改这里。
pub fn vivo_sign(app_key: &str, timestamp: &str, app_secret: &str) -> String {
    hex_lower(&md5(format!("{app_key}{timestamp}{app_secret}").as_bytes()))
}

/// 应答归类,可独立测试的纯函数。
///
/// 2xx 且 `code == 0` 才是发出去了;10080 归令牌失效;其余投递失败。
pub fn parse_answer(status: u16, body: &str) -> Result<(), NotifyError> {
    #[derive(serde::Deserialize, Default)]
    struct Answer {
        #[serde(default)]
        code: i64,
    }
    let answer: Answer = serde_json::from_str(body).unwrap_or_default();
    if (200..300).contains(&status) && answer.code == 0 {
        return Ok(());
    }
    if answer.code == VIVO_INVALID_CODE {
        return Err(NotifyError::InvalidToken(
            "invalid regId (code 10080)".into(),
        ));
    }
    Err(NotifyError::Delivery(format!(
        "vivo push failed: http {status} code {}: {}",
        answer.code,
        super::err_snippet(body)
    )))
}

// ---------------------------------------------------------------------------
// 内嵌 MD5(RFC 1321,纯 std,无 unsafe)
// ---------------------------------------------------------------------------

/// MD5 摘要(16 字节)。
fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    // 消息填充:补 0x80、补零至 ≡56 (mod 64)、追加 64 位小端比特长度。
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) = (
        0x6745_2301u32,
        0xefcd_ab89u32,
        0x98ba_dcfeu32,
        0x1032_5476u32,
    );

    for chunk in msg.chunks_exact(64) {
        let m: [u32; 16] = std::array::from_fn(|i| {
            u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().expect("64 字节块内切片"))
        });
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(tmp.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// 小写十六进制编码。
fn hex_lower(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 对齐上游 TestVivoSign:签名 = MD5(appKey+timestamp+appSecret) 小写 hex。
    #[test]
    fn test_vivo_sign() {
        // 独立复算值:md5hex("key-11760000000secret-1")
        assert_eq!(
            vivo_sign("key-1", "1760000000", "secret-1"),
            hex_lower(&md5(b"key-11760000000secret-1"))
        );
        // 不同 appKey 的签名必须不同:签名错对端只会回 sign fail
        assert_ne!(
            vivo_sign("key-1", "1760000000", "secret-1"),
            vivo_sign("key-2", "1760000000", "secret-1")
        );
    }

    /// 内嵌 MD5 对 RFC 1321 标准测试向量。
    #[test]
    fn test_md5_standard_vectors() {
        assert_eq!(hex_lower(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex_lower(&md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex_lower(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex_lower(&md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex_lower(&md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        // 跨块输入(80 字节,RFC 1321 测试组第 7 向量)
        assert_eq!(
            hex_lower(&md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
        // 块边界(56 字节:填充恰跨块)与相邻长度区分度
        assert_ne!(hex_lower(&md5(&[b'a'; 55])), hex_lower(&md5(&[b'a'; 56])));
        assert_ne!(hex_lower(&md5(&[b'a'; 56])), hex_lower(&md5(&[b'a'; 57])));
    }

    /// 对齐上游 TestVivoInvalidRegID:10080 = regId 失效,调用方删行自清理。
    #[test]
    fn test_invalid_reg_id() {
        let err = parse_answer(200, r#"{"code":10080,"msg":"regId invalid"}"#).unwrap_err();
        assert!(err.is_invalid_token(), "10080 = regId 失效,得到 {err}");
    }

    /// 非 0 厂商码 / HTTP 层失败归投递失败。
    #[test]
    fn test_peer_error() {
        let err = parse_answer(200, r#"{"code":30,"msg":"quota"}"#).unwrap_err();
        assert!(!err.is_invalid_token());
        assert!(matches!(err, NotifyError::Delivery(_)));
        assert!(parse_answer(503, "unavailable").is_err());
    }

    /// 成功路径。
    #[test]
    fn test_success() {
        assert!(parse_answer(200, r#"{"code":0,"msg":"ok","taskId":"task-1"}"#).is_ok());
    }

    /// 拨号前自检:缺 app_secret 在拨号之前就该拦下;空 regId 同样。
    #[test]
    fn test_pre_dial_checks() {
        let svc = Vivo::new(
            false,
            VivoConfig {
                app_id: "100".into(),
                app_key: "k".into(),
                ..Default::default()
            },
        );
        let err = svc.send(&Message::new("reg", "t")).unwrap_err();
        assert!(err.is_not_configured());
        assert!(
            err.to_string().contains("app_id/app_key/app_secret"),
            "{err}"
        );

        let svc = Vivo::new(
            false,
            VivoConfig {
                app_id: "100".into(),
                app_key: "k".into(),
                app_secret: "s".into(),
                ..Default::default()
            },
        );
        let err = svc.send(&Message::new("", "t")).unwrap_err();
        assert!(err.to_string().contains("regId is empty"), "{err}");
        assert_eq!(Service::name(&svc), "vivo");
    }

    /// 官方单播端点钉死(对齐上游 VivoSendURL)。
    #[test]
    fn test_vivo_send_url_constant() {
        assert_eq!(
            VIVO_SEND_URL,
            "https://push-api.vivo.com.cn/message/notify/unicast"
        );
    }
}
