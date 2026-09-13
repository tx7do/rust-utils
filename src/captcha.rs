//! 验证码服务(移植自 go-utils/captcha 的文本验证码部分),feature
//! `captcha`。
//!
//! 分两层:
//! - **生成层**:数字 / 字母 / 算术 / 中文四类图形验证码
//!   (基于 `captcha` crate 渲染 PNG,输出 base64);
//! - **存储层**:[`Store`] trait(带过期的存取校验),默认
//!   [`MemoryStore`] 零依赖,Redis 落地见 [`RedisStore`]
//!   (feature `captcha-redis`)。
//!
//! Go 版的滑块 / 点选 / 旋转验证码依赖 go-captcha 的素材管线,未移植。
//!
//! ```
//! use rust_utils::captcha::{Captcha, DriverKind};
//!
//! let cap = Captcha::with_config(DriverKind::Digit.into());
//! let (id, b64, answer) = cap.generate().unwrap();
//! assert!(b64.starts_with("data:image/png;base64,"));
//! assert!(answer.chars().all(|c| c.is_ascii_digit()));
//!
//! // 一次性校验:成功后即失效
//! assert!(cap.verify(&id, &answer).unwrap());
//! assert!(!cap.verify(&id, &answer).unwrap());
//! ```

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// 验证码类型(对应 Go 版 Driver 常量;滑块/点选/旋转未移植)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverKind {
    /// 纯数字。
    Digit,
    /// 字母数字混合。
    String,
    /// 算术题(如 `3+5=?`,答案为数值)。
    Math,
    /// 常用汉字。
    Chinese,
}

/// 验证码配置。
#[derive(Debug, Clone)]
pub struct CaptchaConfig {
    /// 驱动类型(默认 [`DriverKind::Digit`],与 Go 版默认一致)。
    pub driver: DriverKind,
    /// 字符数(默认 4)。
    pub length: usize,
    /// 图片宽度(默认 120)。
    pub width: u32,
    /// 图片高度(默认 48)。
    pub height: u32,
    /// 验证码有效期(默认 10 分钟)。
    pub ttl: Duration,
    /// 噪点概率 0.0 ~ 1.0(默认 0.1)。
    pub noise: f32,
    /// 干扰点数量(默认 5)。
    pub dots: u32,
    /// 中文词库(`DriverKind::Chinese` 使用;默认内置常用汉字)。
    pub chinese_dict: String,
}

impl Default for CaptchaConfig {
    fn default() -> Self {
        CaptchaConfig {
            driver: DriverKind::Digit,
            length: 4,
            width: 120,
            height: 48,
            ttl: Duration::from_secs(600),
            noise: 0.1,
            dots: 5,
            chinese_dict: COMMON_CHINESE_CHARS.to_string(),
        }
    }
}

impl From<DriverKind> for CaptchaConfig {
    fn from(driver: DriverKind) -> Self {
        CaptchaConfig {
            driver,
            ..CaptchaConfig::default()
        }
    }
}

/// 内置常用汉字表(`DriverKind::Chinese` 的默认词库)。
pub const COMMON_CHINESE_CHARS: &str = "的一是了我不人在他有这个上们来到时大地为子中你说生国年着就那和要她出也得里后自以会家可下而过天去能对小多然于心学么之都好看起发当没成只如事把还用第样道想作种开美总从无情己面最女但现前些所同日手又行意动方期它头经长儿回位分爱老因很给名法间斯知世什两次使身者被高已亲其进此话常与活正感";

// ---------------------------------------------------------------------------
// 存储层
// ---------------------------------------------------------------------------

/// 验证码存储:带过期的存取(对应 Go 版 store 接口)。
pub trait Store: Send + Sync {
    /// 保存答案,`ttl` 后过期(覆盖同 ID 旧值)。
    fn save(&self, id: &str, answer: &str, ttl: Duration) -> Result<(), String>;
    /// 读取答案。
    fn get(&self, id: &str) -> Result<Option<String>, String>;
    /// 删除。
    fn delete(&self, id: &str) -> Result<(), String>;
    /// 是否存在。
    fn exists(&self, id: &str) -> Result<bool, String>;
    /// 剩余有效期;不存在返回 `None`。
    fn remaining_ttl(&self, id: &str) -> Result<Option<Duration>, String>;
}

/// 进程内内存存储(默认实现,重启即失效)。
///
/// 过期为惰性清除:读到过期项时删除。
#[derive(Default)]
pub struct MemoryStore {
    entries: std::sync::Mutex<HashMap<String, (String, Instant)>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn fresh(entry: Option<&(String, Instant)>) -> Option<String> {
        match entry {
            Some((answer, expires)) if *expires > Instant::now() => Some(answer.clone()),
            _ => None,
        }
    }
}

impl Store for MemoryStore {
    fn save(&self, id: &str, answer: &str, ttl: Duration) -> Result<(), String> {
        self.entries
            .lock()
            .unwrap()
            .insert(id.to_string(), (answer.to_string(), Instant::now() + ttl));
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<String>, String> {
        let mut entries = self.entries.lock().unwrap();
        match Self::fresh(entries.get(id)) {
            Some(answer) => Ok(Some(answer)),
            None => {
                entries.remove(id); // 惰性清除过期项
                Ok(None)
            }
        }
    }

    fn delete(&self, id: &str) -> Result<(), String> {
        self.entries.lock().unwrap().remove(id);
        Ok(())
    }

    fn exists(&self, id: &str) -> Result<bool, String> {
        let mut entries = self.entries.lock().unwrap();
        if Self::fresh(entries.get(id)).is_some() {
            Ok(true)
        } else {
            entries.remove(id);
            Ok(false)
        }
    }

    fn remaining_ttl(&self, id: &str) -> Result<Option<Duration>, String> {
        let entries = self.entries.lock().unwrap();
        Ok(entries
            .get(id)
            .and_then(|(_, expires)| expires.checked_duration_since(Instant::now())))
    }
}

/// Redis 存储(feature `captcha-redis`),键有 `captcha:` 前缀。
#[cfg(feature = "captcha-redis")]
pub struct RedisStore {
    client: redis::Client,
    prefix: String,
}

#[cfg(feature = "captcha-redis")]
impl RedisStore {
    /// 用 Redis 连接串创建存储(如 `redis://127.0.0.1/`),创建时即测试连通。
    pub fn new(url: impl Into<String>) -> Result<Self, String> {
        let client = redis::Client::open(url.into()).map_err(|e| format!("redis open: {e}"))?;
        let mut con = client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        redis::cmd("PING")
            .query::<String>(&mut con)
            .map_err(|e| format!("redis ping: {e}"))?;
        Ok(RedisStore {
            client,
            prefix: "captcha:".to_string(),
        })
    }

    fn key(&self, id: &str) -> String {
        format!("{}{}", self.prefix, id)
    }
}

#[cfg(feature = "captcha-redis")]
impl Store for RedisStore {
    fn save(&self, id: &str, answer: &str, ttl: Duration) -> Result<(), String> {
        let mut con = self
            .client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        redis::cmd("SET")
            .arg(self.key(id))
            .arg(answer)
            .arg("EX")
            .arg(ttl.as_secs().max(1))
            .query::<()>(&mut con)
            .map_err(|e| format!("redis set: {e}"))
    }

    fn get(&self, id: &str) -> Result<Option<String>, String> {
        let mut con = self
            .client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        redis::cmd("GET")
            .arg(self.key(id))
            .query::<Option<String>>(&mut con)
            .map_err(|e| format!("redis get: {e}"))
    }

    fn delete(&self, id: &str) -> Result<(), String> {
        let mut con = self
            .client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        redis::cmd("DEL")
            .arg(self.key(id))
            .query::<()>(&mut con)
            .map_err(|e| format!("redis del: {e}"))
    }

    fn exists(&self, id: &str) -> Result<bool, String> {
        let mut con = self
            .client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        redis::cmd("EXISTS")
            .arg(self.key(id))
            .query::<i64>(&mut con)
            .map(|n| n > 0)
            .map_err(|e| format!("redis exists: {e}"))
    }

    fn remaining_ttl(&self, id: &str) -> Result<Option<Duration>, String> {
        let mut con = self
            .client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        let ttl: i64 = redis::cmd("TTL")
            .arg(self.key(id))
            .query(&mut con)
            .map_err(|e| format!("redis ttl: {e}"))?;
        Ok(match ttl {
            n if n > 0 => Some(Duration::from_secs(n as u64)),
            _ => None, // -2 不存在,-1 无过期
        })
    }
}

// ---------------------------------------------------------------------------
// 服务层
// ---------------------------------------------------------------------------

/// 验证码服务。
pub struct Captcha<S: Store> {
    store: S,
    config: RwLock<CaptchaConfig>,
}

impl Captcha<MemoryStore> {
    /// 内存存储 + 默认配置。
    pub fn new() -> Self {
        Self::with_config(CaptchaConfig::default())
    }

    /// 内存存储 + 自定义配置。
    pub fn with_config(config: CaptchaConfig) -> Self {
        Self::with_store(MemoryStore::new(), config)
    }
}

impl<S: Store + Default> Default for Captcha<S> {
    fn default() -> Self {
        Self::with_store(S::default(), CaptchaConfig::default())
    }
}

impl<S: Store> Captcha<S> {
    /// 自定义存储 + 配置。
    pub fn with_store(store: S, config: CaptchaConfig) -> Self {
        Captcha {
            store,
            config: RwLock::new(config),
        }
    }

    /// 生成验证码,返回 `(id, base64 图片, 明文答案)`。
    /// 答案同时已存入存储;`base64` 带 `data:image/png;base64,` 前缀。
    pub fn generate(&self) -> Result<(String, String, String), String> {
        let cfg = self.config.read().unwrap().clone();
        let id = new_captcha_id();
        let (answer, b64) = render(&cfg)?;
        self.store.save(&id, &answer, cfg.ttl)?;
        Ok((id, b64, answer))
    }

    /// 手动保存答案(对应 Go 版 Save)。
    pub fn save(&self, id: &str, answer: &str) -> Result<(), String> {
        let ttl = self.config.read().unwrap().ttl;
        self.store.save(id, answer, ttl)
    }

    /// 校验并删除(默认语义):答案匹配即删除并返回 true,不匹配返回 false。
    pub fn verify(&self, id: &str, input: &str) -> Result<bool, String> {
        self.verify_impl(id, input, true)
    }

    /// 只校验不删除(对应 Go 版 VerifyWithoutDelete)。
    pub fn verify_keep(&self, id: &str, input: &str) -> Result<bool, String> {
        self.verify_impl(id, input, false)
    }

    fn verify_impl(&self, id: &str, input: &str, clear: bool) -> Result<bool, String> {
        let Some(stored) = self.store.get(id)? else {
            return Ok(false);
        };
        if stored == input.trim() {
            if clear {
                self.store.delete(id)?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 删除验证码。
    pub fn delete(&self, id: &str) -> Result<(), String> {
        self.store.delete(id)
    }

    /// 是否存在。
    pub fn exists(&self, id: &str) -> Result<bool, String> {
        self.store.exists(id)
    }

    /// 剩余有效期。
    pub fn get_remaining_time(&self, id: &str) -> Result<Option<Duration>, String> {
        self.store.remaining_ttl(id)
    }

    /// 更新配置(对应 Go 版 SetConfig)。
    pub fn set_config(&self, config: CaptchaConfig) {
        *self.config.write().unwrap() = config;
    }

    /// 当前配置(对应 Go 版 GetConfig)。
    pub fn get_config(&self) -> CaptchaConfig {
        self.config.read().unwrap().clone()
    }
}

fn new_captcha_id() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 按驱动类型生成答案与渲染图。
fn render(cfg: &CaptchaConfig) -> Result<(String, String), String> {
    use rand::Rng;
    let length = cfg.length.max(1);
    let mut rng = rand::rng();

    let (chars, answer): (Vec<char>, String) = match cfg.driver {
        DriverKind::Digit => {
            let chars: Vec<char> = (0..length)
                .map(|_| (b'0' + rng.random_range(0..10)) as char)
                .collect();
            let answer = chars.iter().collect();
            (chars, answer)
        }
        DriverKind::String => {
            const CHARSET: &[u8] = b"23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
            let chars: Vec<char> = (0..length)
                .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
                .collect();
            let answer = chars.iter().collect();
            (chars, answer)
        }
        DriverKind::Math => {
            let a = rng.random_range(1..=20);
            let b = rng.random_range(1..=20);
            let (question, answer) = match rng.random_range(0..3) {
                0 => (format!("{a}+{b}=?"), (a + b).to_string()),
                1 => {
                    let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
                    (format!("{hi}-{lo}=?"), (hi - lo).to_string())
                }
                _ => (format!("{a}*{b}=?"), (a * b).to_string()),
            };
            (question.chars().collect(), answer)
        }
        DriverKind::Chinese => {
            let dict: Vec<char> = cfg.chinese_dict.chars().collect();
            if dict.len() < 10 {
                return Err("chinese_dict too small".to_string());
            }
            let chars: Vec<char> = (0..length)
                .map(|_| dict[rng.random_range(0..dict.len())])
                .collect();
            let answer = chars.iter().collect();
            (chars, answer)
        }
    };

    let mut cap = captcha_crate::Captcha::new();
    cap.set_chars(&chars)
        .apply_filter(captcha_crate::filters::Noise::new(cfg.noise))
        .apply_filter(captcha_crate::filters::Dots::new(cfg.dots))
        .view(cfg.width, cfg.height);
    let png_b64 = cap.as_base64().ok_or("render captcha failed")?;
    Ok((answer, format!("data:image/png;base64,{png_b64}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_store_ttl() {
        let store = MemoryStore::new();
        store.save("k1", "v1", Duration::from_millis(60)).unwrap();
        assert_eq!(store.get("k1").unwrap().as_deref(), Some("v1"));
        assert!(store.exists("k1").unwrap());
        assert!(store.remaining_ttl("k1").unwrap().is_some());

        store.delete("k1").unwrap();
        assert!(!store.exists("k1").unwrap());
        assert_eq!(store.get("k1").unwrap(), None);
        assert_eq!(store.remaining_ttl("k1").unwrap(), None);

        // 过期
        store.save("k2", "v2", Duration::from_millis(30)).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        assert!(!store.exists("k2").unwrap());
        assert_eq!(store.get("k2").unwrap(), None);
    }

    #[test]
    fn test_generate_and_verify_roundtrip() {
        let cap = Captcha::with_config(DriverKind::Digit.into());
        let (id, b64, answer) = cap.generate().unwrap();
        assert!(!id.is_empty());
        assert!(b64.starts_with("data:image/png;base64,"));
        assert_eq!(answer.len(), 4);
        assert!(answer.chars().all(|c| c.is_ascii_digit()));
        assert!(cap.exists(&id).unwrap());
        assert!(cap.get_remaining_time(&id).unwrap().is_some());

        // 一次性校验
        assert!(cap.verify(&id, &answer).unwrap());
        assert!(!cap.exists(&id).unwrap());
        assert!(!cap.verify(&id, &answer).unwrap()); // 已删除
    }

    #[test]
    fn test_verify_semantics() {
        let cap = Captcha::with_config(DriverKind::String.into());
        let (id, _, answer) = cap.generate().unwrap();
        // 错误答案不删除
        assert!(!cap.verify(&id, "zzzz").unwrap());
        assert!(cap.exists(&id).unwrap());
        // 去除首尾空白仍可命中
        assert!(cap.verify(&id, &format!("  {answer} ")).unwrap());

        // verify_keep 不删除
        let (id2, _, answer2) = cap.generate().unwrap();
        assert!(cap.verify_keep(&id2, &answer2).unwrap());
        assert!(cap.exists(&id2).unwrap());
        assert!(cap.verify(&id2, &answer2).unwrap()); // 显式删除后失效
    }

    #[test]
    fn test_math_driver() {
        let cap = Captcha::with_config(DriverKind::Math.into());
        let (_, _, answer) = cap.generate().unwrap();
        assert!(answer.parse::<i64>().is_ok(), "math answer: {answer}");
    }

    #[test]
    fn test_chinese_driver() {
        let cap = Captcha::with_config(DriverKind::Chinese.into());
        let (_, b64, answer) = cap.generate().unwrap();
        assert_eq!(answer.chars().count(), 4);
        let dict = COMMON_CHINESE_CHARS;
        assert!(answer.chars().all(|c| dict.contains(c)));
        assert!(b64.starts_with("data:image/png;base64,"));
    }

    #[test]
    fn test_config_get_set() {
        let cap = Captcha::new();
        cap.set_config(CaptchaConfig {
            driver: DriverKind::Chinese,
            length: 5,
            ttl: Duration::from_secs(30),
            ..CaptchaConfig::default()
        });
        let got = cap.get_config();
        assert_eq!(got.driver, DriverKind::Chinese);
        assert_eq!(got.length, 5);
        assert_eq!(got.ttl, Duration::from_secs(30));

        // 新配置生效:5 个汉字
        let (_, _, answer) = cap.generate().unwrap();
        assert_eq!(answer.chars().count(), 5);
    }

    #[test]
    fn test_manual_save_and_remaining() {
        let cap = Captcha::new();
        cap.save("manual-id", "answer").unwrap();
        assert!(cap.exists("manual-id").unwrap());
        let ttl = cap.get_remaining_time("manual-id").unwrap().unwrap();
        assert!(ttl <= Duration::from_secs(600) && ttl > Duration::ZERO);
        assert!(cap.verify("manual-id", "answer").unwrap());
    }

    // Redis 存储:设置 REDIS_TEST_URL 环境变量后启用
    #[test]
    fn test_redis_store_live() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            return;
        };
        let store = RedisStore::new(url).expect("redis connect");
        store.save("rk1", "v1", Duration::from_secs(60)).unwrap();
        assert_eq!(store.get("rk1").unwrap().as_deref(), Some("v1"));
        assert!(store.exists("rk1").unwrap());
        assert!(store.remaining_ttl("rk1").unwrap().is_some());
        store.delete("rk1").unwrap();
        assert!(!store.exists("rk1").unwrap());
    }
}
