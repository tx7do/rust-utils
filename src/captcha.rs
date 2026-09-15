//! 验证码服务,feature `captcha`。
//!
//! 七种驱动([`Captcha::generate`] 按配置分发):
//! - 文本四类(`Digit` / `String` / `Math` / `Chinese`):输出与
//!   base64Captcha 前端组件兼容。数字驱动为点阵圆填充渲染
//!   (内置 11×18 数字位图,与 base64Captcha 的 digitFontData
//!   逐字节一致,Apache-2.0;外加剪切漂移、穿透线、正弦扭曲、
//!   干扰圆);其余三类为列布局 + 逐字随机字号与深浅色 + 噪声字符。
//!   运行期背景恒为随机浅色、字形恒为随机深色,配置中的颜色字段
//!   为惰性字段。`Chinese` 驱动的字符池取 `language` 字段(默认
//!   `"zh"`;按逗号切分的三分支语义见 `chinese_text`)。
//! - 图形三类:`Slide`(滑块)/ `Click`(点选)/ `Rotate`(旋转):
//!   输出 JSON 的结构、字段名、ID 格式与 base64Captcha 前端组件
//!   兼容;主图 JPEG、其余图片 PNG。
//!
//! 存储层为 [`Store`] trait(带过期的存取),默认 [`MemoryStore`]
//! 零依赖,Redis 落地见 [`RedisStore`](feature `captcha-redis`);
//! 键名为 `{key_prefix}:{id}`。
//!
//! 实现说明:
//! - 全部图像素材由程序自绘:滑块与点选背景为渐变公式
//!   (见 `paste_gradient`),点选字形为内嵌 GNU Unifont 位图子集
//!   (见 `assets/captcha/README.md`),干扰图元(填充圆、折线、
//!   正弦扭曲)自行实现;旋转驱动的圆盘为程序生成的径向图案。
//! - 旋转驱动恒取内置常量(主图 220×220、缩略边长
//!   {140,150,160,170}、角度 [30,330] 闭区间),`RotateConfig`
//!   字段为惰性。
//! - 点选期望答案按数组存储,逐点 ±10px 的验证语义因此可用。
//!
//! ```
//! use rust_utils::captcha::{Captcha, Config, DriverKind};
//!
//! let cap = Captcha::with_config(Config::with_driver(DriverKind::Digit));
//! let (id, b64, answer) = cap.generate().unwrap();
//! assert!(b64.starts_with("data:image/png;base64,"));
//!
//! // 一次性校验:成功后即失效
//! assert!(cap.verify(&id, &answer).unwrap());
//! assert!(!cap.verify(&id, &answer).unwrap());
//! ```

use std::collections::HashMap;
use std::f64::consts::PI;
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::{ExtendedColorType, ImageEncoder, Rgb, RgbImage, Rgba, RgbaImage};
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::base64util;

/// 内嵌 Unifont 位图字形集(见 `assets/captcha/README.md`)。
const UNIFONT_BIN: &[u8] = include_bytes!("../assets/captcha/unifont_cjk.bin");

// ---------------------------------------------------------------------------
// 驱动类型与配置
// ---------------------------------------------------------------------------

/// 验证码驱动类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverKind {
    Digit,
    String,
    Math,
    Chinese,
    Slide,
    Click,
    Rotate,
}

/// 数字验证码配置。
#[derive(Debug, Clone)]
pub struct DigitConfig {
    pub height: u32,
    pub width: u32,
    pub captcha_count: usize,
    pub max_skew: f64,
    pub dot_count: usize,
    pub bg_color: [u8; 3],
    pub font_color: [u8; 3],
}

impl Default for DigitConfig {
    fn default() -> Self {
        DigitConfig {
            height: 80,
            width: 240,
            captcha_count: 4,
            max_skew: 0.7,
            dot_count: 80,
            bg_color: [255, 255, 255],
            font_color: [0, 0, 0],
        }
    }
}

/// 字符串验证码配置。
#[derive(Debug, Clone)]
pub struct StringConfig {
    pub height: u32,
    pub width: u32,
    pub captcha_count: usize,
    pub max_skew: f64,
    pub dot_count: usize,
    pub bg_color: [u8; 3],
    pub font_color: [u8; 3],
    pub source: String,
}

impl Default for StringConfig {
    fn default() -> Self {
        StringConfig {
            height: 80,
            width: 240,
            captcha_count: 4,
            max_skew: 0.7,
            dot_count: 80,
            bg_color: [255, 255, 255],
            font_color: [0, 0, 0],
            source: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string(),
        }
    }
}

/// 算术验证码配置。
#[derive(Debug, Clone)]
pub struct MathConfig {
    pub height: u32,
    pub width: u32,
    pub dot_count: usize,
    pub max_skew: f64,
    pub bg_color: [u8; 3],
    pub font_color: [u8; 3],
}

impl Default for MathConfig {
    fn default() -> Self {
        MathConfig {
            height: 80,
            width: 240,
            dot_count: 80,
            max_skew: 0.7,
            bg_color: [255, 255, 255],
            font_color: [0, 0, 0],
        }
    }
}

/// 中文验证码配置。
#[derive(Debug, Clone)]
pub struct ChineseConfig {
    pub height: u32,
    pub width: u32,
    pub captcha_count: usize,
    pub dot_count: usize,
    pub max_skew: f64,
    pub bg_color: [u8; 3],
    pub font_color: [u8; 3],
    pub language: String,
}

impl Default for ChineseConfig {
    fn default() -> Self {
        ChineseConfig {
            height: 80,
            width: 240,
            captcha_count: 4,
            dot_count: 80,
            max_skew: 0.7,
            bg_color: [255, 255, 255],
            font_color: [0, 0, 0],
            language: "zh".to_string(),
        }
    }
}

/// 滑块拼图配置。
#[derive(Debug, Clone)]
pub struct SlideConfig {
    pub master_width: u32,
    pub master_height: u32,
    pub tile_width: u32,
    pub tile_height: u32,
    pub tile_radius: u32,
    pub jigsaw_radius: u32,
    pub shadow_offset_x: i32,
    pub shadow_offset_y: i32,
    pub shadow_blur: u32,
}

impl Default for SlideConfig {
    fn default() -> Self {
        SlideConfig {
            master_width: 300,
            master_height: 220,
            tile_width: 60,
            tile_height: 60,
            tile_radius: 5,
            jigsaw_radius: 10,
            shadow_offset_x: 5,
            shadow_offset_y: 5,
            shadow_blur: 10,
        }
    }
}

/// 点选文字配置。
#[derive(Debug, Clone)]
pub struct ClickConfig {
    pub master_width: u32,
    pub master_height: u32,
    pub thumb_width: u32,
    pub thumb_height: u32,
    pub captcha_count: usize,
    pub verify_count: usize,
    pub display_shadow: bool,
    pub shadow_color: String,
    pub shadow_offset_x: i32,
    pub shadow_offset_y: i32,
    pub chars: String,
    pub language: String,
}

impl Default for ClickConfig {
    fn default() -> Self {
        ClickConfig {
            master_width: 300,
            master_height: 220,
            thumb_width: 150,
            thumb_height: 40,
            captcha_count: 6,
            verify_count: 3,
            display_shadow: true,
            shadow_color: "#000000".to_string(),
            shadow_offset_x: 2,
            shadow_offset_y: 2,
            chars: "这的是随了机文我你他字在有不么中".to_string(),
            language: "zh".to_string(),
        }
    }
}

/// 旋转验证码配置。
#[derive(Debug, Clone)]
pub struct RotateConfig {
    pub master_width: u32,
    pub master_height: u32,
    pub thumb_width: u32,
    pub thumb_height: u32,
}

impl Default for RotateConfig {
    fn default() -> Self {
        RotateConfig {
            master_width: 300,
            master_height: 300,
            thumb_width: 150,
            thumb_height: 150,
        }
    }
}

/// 总配置(驱动选择与各驱动子配置)。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 驱动类型(默认 `Digit`)。
    pub driver: Option<DriverKind>,
    /// 过期时间(默认 5 分钟)。
    pub expire: Option<Duration>,
    /// 存储键前缀(默认 `captcha`)。
    pub key_prefix: String,
    pub digit_config: Option<DigitConfig>,
    pub string_config: Option<StringConfig>,
    pub math_config: Option<MathConfig>,
    pub chinese_config: Option<ChineseConfig>,
    pub slide_config: Option<SlideConfig>,
    pub click_config: Option<ClickConfig>,
    pub rotate_config: Option<RotateConfig>,
}

impl Config {
    /// 以指定驱动类型构造配置(其余字段取默认值)。
    pub fn with_driver(driver: DriverKind) -> Self {
        Config {
            driver: Some(driver),
            expire: Some(Duration::from_secs(300)),
            key_prefix: "captcha".to_string(),
            digit_config: Some(DigitConfig::default()),
            string_config: Some(StringConfig::default()),
            math_config: Some(MathConfig::default()),
            chinese_config: Some(ChineseConfig::default()),
            slide_config: Some(SlideConfig::default()),
            click_config: Some(ClickConfig::default()),
            rotate_config: Some(RotateConfig::default()),
        }
    }

    fn driver(&self) -> DriverKind {
        self.driver.unwrap_or(DriverKind::Digit)
    }

    fn expire(&self) -> Duration {
        self.expire.unwrap_or(Duration::from_secs(300))
    }

    fn key_prefix(&self) -> &str {
        if self.key_prefix.is_empty() {
            "captcha"
        } else {
            &self.key_prefix
        }
    }
}

// ---------------------------------------------------------------------------
// 输出数据结构
// ---------------------------------------------------------------------------

/// 滑块拼图输出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlideCaptchaData {
    pub id: String,
    pub master_image: String,
    pub tile_image: String,
    pub x_position: i32,
}

/// 点选输出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickCaptchaData {
    pub id: String,
    pub master_image: String,
    pub thumb_image: String,
    pub dots: HashMap<i32, ClickDot>,
}

/// 点选点位(`char` 恒为空串)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickDot {
    pub x: i32,
    pub y: i32,
    pub char: String,
    pub width: i32,
    pub height: i32,
    pub angle: i32,
}

/// 旋转输出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateCaptchaData {
    pub id: String,
    pub master_image: String,
    pub thumb_image: String,
    pub angle: i32,
}

// ---------------------------------------------------------------------------
// 存储层
// ---------------------------------------------------------------------------

/// 验证码存储:带过期的存取。
pub trait Store: Send + Sync {
    fn save(&self, key: &str, answer: &str, ttl: Duration) -> Result<(), String>;
    fn get(&self, key: &str) -> Result<Option<String>, String>;
    fn delete(&self, key: &str) -> Result<(), String>;
    fn exists(&self, key: &str) -> Result<bool, String>;
    fn remaining_ttl(&self, key: &str) -> Result<Option<Duration>, String>;
}

/// 进程内内存存储(默认实现;过期项在访问时惰性清除)。
#[derive(Default)]
pub struct MemoryStore {
    entries: Mutex<HashMap<String, (String, Instant)>>,
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
    fn save(&self, key: &str, answer: &str, ttl: Duration) -> Result<(), String> {
        self.entries
            .lock()
            .unwrap()
            .insert(key.to_string(), (answer.to_string(), Instant::now() + ttl));
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<String>, String> {
        let mut entries = self.entries.lock().unwrap();
        match Self::fresh(entries.get(key)) {
            Some(answer) => Ok(Some(answer)),
            None => {
                entries.remove(key);
                Ok(None)
            }
        }
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        self.entries.lock().unwrap().remove(key);
        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool, String> {
        let mut entries = self.entries.lock().unwrap();
        if Self::fresh(entries.get(key)).is_some() {
            Ok(true)
        } else {
            entries.remove(key);
            Ok(false)
        }
    }

    fn remaining_ttl(&self, key: &str) -> Result<Option<Duration>, String> {
        let entries = self.entries.lock().unwrap();
        Ok(entries
            .get(key)
            .and_then(|(_, expires)| expires.checked_duration_since(Instant::now())))
    }
}

/// Redis 存储(feature `captcha-redis`);键需调用方自行加前缀。
#[cfg(feature = "captcha-redis")]
pub struct RedisStore {
    client: redis::Client,
}

#[cfg(feature = "captcha-redis")]
impl RedisStore {
    pub fn new(url: impl Into<String>) -> Result<Self, String> {
        let client = redis::Client::open(url.into()).map_err(|e| format!("redis open: {e}"))?;
        let mut con = client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        redis::cmd("PING")
            .query::<String>(&mut con)
            .map_err(|e| format!("redis ping: {e}"))?;
        Ok(RedisStore { client })
    }
}

#[cfg(feature = "captcha-redis")]
impl Store for RedisStore {
    fn save(&self, key: &str, answer: &str, ttl: Duration) -> Result<(), String> {
        let mut con = self
            .client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        redis::cmd("SET")
            .arg(key)
            .arg(answer)
            .arg("EX")
            .arg(ttl.as_secs().max(1))
            .query::<()>(&mut con)
            .map_err(|e| format!("redis set: {e}"))
    }

    fn get(&self, key: &str) -> Result<Option<String>, String> {
        let mut con = self
            .client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        redis::cmd("GET")
            .arg(key)
            .query::<Option<String>>(&mut con)
            .map_err(|e| format!("redis get: {e}"))
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        let mut con = self
            .client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        redis::cmd("DEL")
            .arg(key)
            .query::<()>(&mut con)
            .map_err(|e| format!("redis del: {e}"))
    }

    fn exists(&self, key: &str) -> Result<bool, String> {
        let mut con = self
            .client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        redis::cmd("EXISTS")
            .arg(key)
            .query::<i64>(&mut con)
            .map(|n| n > 0)
            .map_err(|e| format!("redis exists: {e}"))
    }

    fn remaining_ttl(&self, key: &str) -> Result<Option<Duration>, String> {
        let mut con = self
            .client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        let ttl: i64 = redis::cmd("TTL")
            .arg(key)
            .query(&mut con)
            .map_err(|e| format!("redis ttl: {e}"))?;
        Ok(match ttl {
            n if n > 0 => Some(Duration::from_secs(n as u64)),
            _ => None,
        })
    }
}

// ---------------------------------------------------------------------------
// 服务层
// ---------------------------------------------------------------------------

/// 验证码服务:生成后答案自动入库,
/// 键为 `{key_prefix}:{id}`、TTL 为 `expire`。
pub struct Captcha<S: Store> {
    store: S,
    config: RwLock<Config>,
}

impl Captcha<MemoryStore> {
    /// 内存存储 + 默认配置。
    pub fn new() -> Self {
        Self::with_config(Config::default())
    }

    /// 内存存储 + 自定义配置。
    pub fn with_config(config: Config) -> Self {
        Self::with_store(MemoryStore::new(), config)
    }
}

impl<S: Store + Default> Default for Captcha<S> {
    fn default() -> Self {
        Self::with_store(S::default(), Config::default())
    }
}

impl<S: Store> Captcha<S> {
    /// 自定义存储 + 配置。
    pub fn with_store(store: S, config: Config) -> Self {
        Captcha {
            store,
            config: RwLock::new(config),
        }
    }

    /// 生成验证码,返回 `(id, 图片或 JSON, 明文答案)`。
    ///
    /// 文本驱动返回 PNG 数据 URI;图形驱动返回对应数据结构的
    /// JSON(结构内嵌图片数据 URI)。
    pub fn generate(&self) -> Result<(String, String, String), String> {
        let cfg = self.config.read().unwrap().clone();
        let mut rng = rand::rng();
        let (id, b64, answer) = match cfg.driver() {
            DriverKind::Slide => gen_slide(&cfg.slide(), &mut rng)?,
            DriverKind::Click => gen_click(&cfg.click(), &mut rng)?,
            DriverKind::Rotate => gen_rotate(&mut rng)?,
            DriverKind::Math => {
                let mc = cfg.math();
                let (question, answer) = math_question(&mut rng);
                gen_text(
                    mc.width as i32,
                    mc.height as i32,
                    mc.dot_count,
                    TXT_NUMBERS,
                    &question,
                    &answer,
                    &mut rng,
                )?
            }
            DriverKind::String => {
                let sc = cfg.string();
                let content = rand_text(sc.captcha_count, &sc.source, &mut rng)
                    .ok_or("draw captcha: text must not be empty")?;
                gen_text(
                    sc.width as i32,
                    sc.height as i32,
                    sc.dot_count,
                    NOISE_CHARS,
                    &content,
                    &content,
                    &mut rng,
                )?
            }
            DriverKind::Chinese => {
                let cc = cfg.chinese();
                let content = chinese_text(&cc.language, cc.captcha_count, &mut rng)
                    .ok_or("draw captcha: text must not be empty")?;
                gen_text(
                    cc.width as i32,
                    cc.height as i32,
                    cc.dot_count,
                    NOISE_CHARS,
                    &content,
                    &content,
                    &mut rng,
                )?
            }
            DriverKind::Digit => {
                let dc = cfg.digit();
                let content: String = (0..dc.captcha_count)
                    .map(|_| char::from(b'0' + ri_n(&mut rng, 10) as u8))
                    .collect();
                let (id, b64) = render_digit(&dc, &content, &mut rng)?;
                (id, b64, content)
            }
        };
        self.store.save(&self.key(&id), &answer, cfg.expire())?;
        Ok((id, b64, answer))
    }

    /// 手动保存答案(键与 TTL 同 [`generate`])。
    pub fn save(&self, id: &str, answer: &str) -> Result<(), String> {
        let ttl = self.config.read().unwrap().expire();
        self.store.save(&self.key(id), answer, ttl)
    }

    /// 校验并删除:答案匹配即删除。
    pub fn verify(&self, id: &str, input: &str) -> Result<bool, String> {
        self.verify_impl(id, input, true)
    }

    /// 只校验不删除。
    pub fn verify_keep(&self, id: &str, input: &str) -> Result<bool, String> {
        self.verify_impl(id, input, false)
    }

    fn verify_impl(&self, id: &str, input: &str, clear: bool) -> Result<bool, String> {
        let key = self.key(id);
        let Some(stored) = self.store.get(&key)? else {
            return Ok(false);
        };
        let driver = self.config.read().unwrap().driver();
        let matched = match driver {
            DriverKind::Slide => verify_slide(&stored, input),
            DriverKind::Click => verify_click(&stored, input),
            DriverKind::Rotate => verify_rotate(&stored, input),
            _ => stored == input,
        };
        if matched && clear {
            self.store.delete(&key)?;
        }
        Ok(matched)
    }

    /// 删除验证码。
    pub fn delete(&self, id: &str) -> Result<(), String> {
        self.store.delete(&self.key(id))
    }

    /// 是否存在。
    pub fn exists(&self, id: &str) -> Result<bool, String> {
        self.store.exists(&self.key(id))
    }

    /// 剩余有效期。
    pub fn get_remaining_time(&self, id: &str) -> Result<Option<Duration>, String> {
        self.store.remaining_ttl(&self.key(id))
    }

    /// 更新配置。
    pub fn set_config(&self, config: Config) {
        *self.config.write().unwrap() = config;
    }

    /// 当前配置。
    pub fn get_config(&self) -> Config {
        self.config.read().unwrap().clone()
    }

    fn key(&self, id: &str) -> String {
        let cfg = self.config.read().unwrap();
        store_key(cfg.key_prefix(), id)
    }
}

/// 存储键:`{key_prefix}:{id}`。
fn store_key(prefix: &str, id: &str) -> String {
    format!("{prefix}:{id}")
}

// 未设置的子配置在生成时取对应默认值。
impl Config {
    fn digit(&self) -> DigitConfig {
        self.digit_config.clone().unwrap_or_default()
    }

    fn string(&self) -> StringConfig {
        self.string_config.clone().unwrap_or_default()
    }

    fn math(&self) -> MathConfig {
        self.math_config.clone().unwrap_or_default()
    }

    fn chinese(&self) -> ChineseConfig {
        self.chinese_config.clone().unwrap_or_default()
    }

    fn slide(&self) -> SlideConfig {
        self.slide_config.clone().unwrap_or_default()
    }

    fn click(&self) -> ClickConfig {
        self.click_config.clone().unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// 验证
// ---------------------------------------------------------------------------

/// 期望答案点位(点选答案在存储层的序列化结构)。
#[derive(Serialize, Deserialize)]
struct ExpectedClickDot {
    index: i32,
    x: i32,
    y: i32,
    size: i32,
    width: i32,
    height: i32,
    text: String,
    shape: String,
    angle: i32,
    color: String,
    color2: String,
}

/// 用户输入点位(仅需 `x` / `y` 两个字段)。
#[derive(Serialize, Deserialize)]
struct UserClickDot {
    x: f64,
    y: f64,
}

/// 滑块验证(仅比较 X、容差 ±5px)。
fn verify_slide(expected: &str, actual: &str) -> bool {
    let (Some(e), Some(a)) = (parse_int_prefix(expected), parse_int_prefix(actual)) else {
        return false;
    };
    e.abs_diff(a) <= 5
}

/// 点选验证(数量相等且逐点 ±10px)。
fn verify_click(expected: &str, actual: &str) -> bool {
    let (Ok(exp), Ok(act)) = (
        serde_json::from_str::<Vec<ExpectedClickDot>>(expected),
        serde_json::from_str::<Vec<UserClickDot>>(actual),
    ) else {
        return false;
    };
    if exp.len() != act.len() {
        return false;
    }
    for (e, a) in exp.iter().zip(act.iter()) {
        let dx = (f64::from(e.x) - a.x).abs();
        let dy = (f64::from(e.y) - a.y).abs();
        if dx > 10.0 || dy > 10.0 {
            return false;
        }
    }
    true
}

/// 旋转验证(环形角度差、容差 ±5°)。
fn verify_rotate(expected: &str, actual: &str) -> bool {
    let (Some(e), Some(a)) = (parse_int_prefix(expected), parse_int_prefix(actual)) else {
        return false;
    };
    let mut diff = e.abs_diff(a);
    if diff > 180 {
        diff = 360 - diff;
    }
    diff <= 5
}

/// 前导十进制整数(跳过前导空白、允许符号、取最长数字前缀;
/// 溢出或无数字视为失败)。
fn parse_int_prefix(s: &str) -> Option<i32> {
    let t = s.trim_start();
    let (sign, digits) = if let Some(r) = t.strip_prefix('-') {
        (-1i64, r)
    } else if let Some(r) = t.strip_prefix('+') {
        (1, r)
    } else {
        (1, t)
    };
    let mut val: i64 = 0;
    let mut n = 0u32;
    for b in digits.bytes() {
        if !b.is_ascii_digit() {
            break;
        }
        val = val * 10 + i64::from(b - b'0');
        n += 1;
        if val > i32::MAX as i64 {
            return None;
        }
    }
    if n == 0 {
        return None;
    }
    i32::try_from(sign * val).ok()
}

// ---------------------------------------------------------------------------
// 采样与颜色
// ---------------------------------------------------------------------------

/// [min, max] 闭区间(含大小交换)。
fn ri_fast(rng: &mut impl Rng, min: i32, max: i32) -> i32 {
    let (lo, hi) = if min > max { (max, min) } else { (min, max) };
    rng.random_range(lo..=hi)
}

/// [0, n) 半开区间。
fn ri_n(rng: &mut impl Rng, n: i32) -> i32 {
    rng.random_range(0..n)
}

/// [from, to) 半开区间(`to - from <= 0` 时返回 `from`)。
fn ri_range(rng: &mut impl Rng, from: i32, to: i32) -> i32 {
    if to - from <= 0 {
        from
    } else {
        rng.random_range(from..to)
    }
}

/// [0,1) 均匀。
fn rf(rng: &mut impl Rng) -> f64 {
    rng.random::<f64>()
}

/// 均匀取表项(索引采样)。
fn pick<T: Copy>(rng: &mut impl Rng, list: &[T]) -> T {
    list[rng.random_range(0..list.len())]
}

/// 随机浅色(各通道 [200,254])。
fn rand_light_color(rng: &mut impl Rng) -> [u8; 4] {
    let mut c = [0u8; 4];
    for v in c.iter_mut().take(3) {
        *v = (ri_n(rng, 55) + 200) as u8;
    }
    c[3] = 255;
    c
}

/// 随机深色(基色加亮偏移,通道按 `u8` 截断回绕)。
fn rand_deep_color(rng: &mut impl Rng) -> [u8; 4] {
    let red = ri_n(rng, 255);
    let green = ri_n(rng, 255);
    let mut blue = if red + green > 400 {
        0
    } else {
        400 - red - green
    };
    if blue > 255 {
        blue = 255;
    }
    let base = [red as u8, green as u8, blue as u8];
    let increase = 30.0 + f64::from(ri_n(rng, 255));
    let mut rgb = [0u8; 3];
    for (o, v) in rgb.iter_mut().zip(base.iter()) {
        let x = (f64::from(*v) - increase).min(255.0).abs();
        *o = ((x.trunc() as i64) & 0xff) as u8;
    }
    [rgb[0], rgb[1], rgb[2], 255]
}

/// 颜色亮度扰动(通道按 `u8` 回绕;`maxc > 255` 分支对
/// `u8` 恒假,略)。
fn random_brightness(rng: &mut impl Rng, c: [u8; 4]) -> [u8; 4] {
    let minc = c[0].min(c[1]).min(c[2]);
    let maxc = c[0].max(c[1]).max(c[2]);
    let n = ri_n(rng, 255 - i32::from(maxc)) - i32::from(minc);
    let mut out = c;
    for (o, v) in out.iter_mut().zip(c.iter()).take(3) {
        *o = ((i32::from(*v) + n) & 0xff) as u8;
    }
    out
}

/// `#RRGGBB` / `#RGB` 解析(解析失败返回黑色)。
fn parse_hex_color(s: &str) -> [u8; 4] {
    let invalid = [0, 0, 0, 255];
    let Some(rest) = s.strip_prefix('#') else {
        return invalid;
    };
    let nibbles: Option<Vec<u8>> = match rest.len() {
        6 => rest
            .as_bytes()
            .chunks_exact(2)
            .map(|p| Some((hex_val(p[0])? << 4) | hex_val(p[1])?))
            .collect(),
        3 => rest
            .as_bytes()
            .iter()
            .map(|&b| hex_val(b).map(|h| h * 17))
            .collect(),
        _ => None,
    };
    let Some(rgb) = nibbles else {
        return invalid;
    };
    [rgb[0], rgb[1], rgb[2], 255]
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 题面与答案
// ---------------------------------------------------------------------------

/// 均匀取 `size` 个字符(池空或 size 为 0 返回 `None`)。
fn rand_text(size: usize, pool: &str, rng: &mut impl Rng) -> Option<String> {
    let chars: Vec<char> = pool.chars().collect();
    if chars.is_empty() || size == 0 {
        return None;
    }
    Some(
        (0..size)
            .map(|_| chars[rng.random_range(0..chars.len())])
            .collect(),
    )
}

/// 中文字符池生成:`language` 按 `,` 切分——单段即字符池;
/// 段数不大于长度时回退数字字母表;否则逐字随机取段拼接。
fn chinese_text(language: &str, count: usize, rng: &mut impl Rng) -> Option<String> {
    let parts: Vec<&str> = language.split(',').collect();
    if parts.len() == 1 {
        rand_text(count, parts[0], rng)
    } else if parts.len() <= count {
        rand_text(count, ID_CHARS, rng)
    } else {
        Some((0..count).map(|_| pick(rng, &parts)).collect::<String>())
    }
}

/// 算术题生成(乘号记作 `x`)。
fn math_question(rng: &mut impl Rng) -> (String, String) {
    match ri_n(rng, 3) {
        0 => {
            let (a, b) = (ri_n(rng, 20), ri_n(rng, 20));
            (format!("{a}+{b}=?"), (a + b).to_string())
        }
        1 => {
            let (a, b) = (ri_n(rng, 10), ri_n(rng, 10));
            (format!("{a}x{b}=?"), (a * b).to_string())
        }
        _ => {
            let (a, b) = (ri_n(rng, 80) + ri_n(rng, 20), ri_n(rng, 80));
            (format!("{a}-{b}=?"), (a - b).to_string())
        }
    }
}

/// 随机 ID(20 字符取自数字+字母表)。
fn random_id(rng: &mut impl Rng) -> String {
    (0..20)
        .map(|_| ID_CHARS.as_bytes()[rng.random_range(0..ID_CHARS.len())] as char)
        .collect()
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 位图字体与图元
// ---------------------------------------------------------------------------

fn read_u32(buf: &[u8], off: &mut usize) -> Option<u32> {
    if *off + 4 > buf.len() {
        return None;
    }
    let v = u32::from_le_bytes(buf[*off..*off + 4].try_into().ok()?);
    *off += 4;
    Some(v)
}

/// 解析内嵌 Unifont 位图(LE u32 计数 + 每字形 u32 码点 + 32 字节)。
fn font_table() -> &'static HashMap<u32, [u8; 32]> {
    static TABLE: OnceLock<HashMap<u32, [u8; 32]>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut map = HashMap::new();
        let mut off = 0usize;
        let Some(count) = read_u32(UNIFONT_BIN, &mut off) else {
            return map;
        };
        for _ in 0..count {
            let Some(cp) = read_u32(UNIFONT_BIN, &mut off) else {
                break;
            };
            if off + 32 > UNIFONT_BIN.len() {
                break;
            }
            let mut bitmap = [0u8; 32];
            bitmap.copy_from_slice(&UNIFONT_BIN[off..off + 32]);
            off += 32;
            map.insert(cp, bitmap);
        }
        map
    })
}

/// 汉字判定(BMP 范围近似;仅影响摆放偏移)。
fn is_han(c: char) -> bool {
    matches!(c, '\u{4E00}'..='\u{9FFF}' | '\u{3400}'..='\u{4DBF}')
}

/// 字形目标尺寸:汉字全宽、其余半宽,高度同字号。
fn glyph_dims(c: char, size: i32) -> (i32, i32) {
    if is_han(c) {
        (size, size)
    } else {
        (size / 2, size)
    }
}

/// 写像素(越界静默跳过)。
fn set_px(img: &mut RgbaImage, x: i32, y: i32, color: [u8; 4]) {
    if x < 0 || y < 0 || x >= img.width() as i32 || y >= img.height() as i32 {
        return;
    }
    img.put_pixel(x as u32, y as u32, Rgba(color));
}

/// 将缩放后的位图字形写入画布(最近邻采样,仅字形位为 1 的像素;
/// 越界跳过)。
fn draw_scaled_glyph(
    dst: &mut RgbaImage,
    ch: char,
    ox: i32,
    oy: i32,
    gw: i32,
    gh: i32,
    color: [u8; 4],
) {
    let cp = u32::from(ch);
    let Some(bitmap) = font_table().get(&cp) else {
        return;
    };
    let src_w: u32 = if cp < 0x80 { 8 } else { 16 };
    if gw <= 0 || gh <= 0 {
        return;
    }
    let (dw, dh) = (gw as u32, gh as u32);
    for ty in 0..dh {
        for tx in 0..dw {
            let sx = (u64::from(tx) * u64::from(src_w) / u64::from(dw)) as u32;
            let sy = (u64::from(ty) * 16 / u64::from(dh)) as u32;
            if sy > 15 || sx >= src_w {
                continue;
            }
            let byte = bitmap[sy as usize * 2 + (sx / 8) as usize];
            if (byte >> (7 - (sx & 7))) & 1 == 1 {
                set_px(dst, ox + tx as i32, oy + ty as i32, color);
            }
        }
    }
}

/// 中点圆填充。
fn draw_filled_circle(img: &mut RgbaImage, cx: i32, cy: i32, radius: i32, color: [u8; 4]) {
    let mut f = 1 - radius;
    let mut dfx = 1;
    let mut dfy = -2 * radius;
    let (mut xo, mut yo) = (0, radius);
    set_px(img, cx, cy + radius, color);
    set_px(img, cx, cy - radius, color);
    draw_horiz_line(img, cx - radius, cx + radius, cy, color);
    while xo < yo {
        if f >= 0 {
            yo -= 1;
            dfy += 2;
            f += dfy;
        }
        xo += 1;
        dfx += 2;
        f += dfx;
        draw_horiz_line(img, cx - xo, cx + xo, cy + yo, color);
        draw_horiz_line(img, cx - xo, cx + xo, cy - yo, color);
        draw_horiz_line(img, cx - yo, cx + yo, cy + xo, color);
        draw_horiz_line(img, cx - yo, cx + yo, cy - xo, color);
    }
}

fn draw_horiz_line(img: &mut RgbaImage, from_x: i32, to_x: i32, y: i32, color: [u8; 4]) {
    for x in from_x..=to_x {
        set_px(img, x, y, color);
    }
}

/// 五像素宽 Bresenham 折线。
fn draw_beeline(img: &mut RgbaImage, mut p1: (i32, i32), p2: (i32, i32), color: [u8; 4]) {
    let dx = f64::from(p1.0 - p2.0).abs();
    let dy = f64::from(p2.1 - p1.1).abs();
    let mut sx = 1;
    let mut sy = 1;
    if p1.0 >= p2.0 {
        sx = -1;
    }
    if p1.1 >= p2.1 {
        sy = -1;
    }
    let mut err = dx - dy;
    loop {
        for o in -2i32..=2 {
            set_px(img, p1.0 + o, p1.1, color);
        }
        if p1 == p2 {
            return;
        }
        let e2 = err * 2.0;
        if e2 > -dy {
            err -= dy;
            p1.0 += sx;
        }
        if e2 < dx {
            err += dx;
            p1.1 += sy;
        }
    }
}

/// 源覆盖合成(Porter-Duff over、非预乘;源图仅取 `[region]` 区域,
/// 两侧越界截断)。
fn composite_over(
    dst: &mut RgbaImage,
    src: &RgbaImage,
    region: (i32, i32, i32, i32),
    dx: i32,
    dy: i32,
) {
    let (bx, by, bw, bh) = region;
    if bw <= 0 || bh <= 0 {
        return;
    }
    for py in 0..bh {
        for px in 0..bw {
            let (sx, sy) = (bx + px, by + py);
            if sx < 0 || sy < 0 || sx >= src.width() as i32 || sy >= src.height() as i32 {
                continue;
            }
            let s = src.get_pixel(sx as u32, sy as u32);
            let sa = u32::from(s.0[3]);
            if sa == 0 {
                continue;
            }
            let tx = dx + px;
            let ty = dy + py;
            if tx < 0 || ty < 0 || tx >= dst.width() as i32 || ty >= dst.height() as i32 {
                continue;
            }
            let d = dst.get_pixel(tx as u32, ty as u32);
            let ia = 255 - sa;
            let oa = (sa + (u32::from(d.0[3]) * ia) / 255).min(255);
            let src3 = [s.0[0], s.0[1], s.0[2]];
            let dst3 = [d.0[0], d.0[1], d.0[2]];
            let mut rgb = [0u8; 3];
            for (o, (sv, dv)) in rgb.iter_mut().zip(src3.iter().zip(dst3.iter())) {
                *o = ((u32::from(*sv) * sa + u32::from(*dv) * ia) / 255).min(255) as u8;
            }
            dst.put_pixel(
                tx as u32,
                ty as u32,
                Rgba([rgb[0], rgb[1], rgb[2], oa as u8]),
            );
        }
    }
}

/// 正弦扭曲(越界源取画布初始色)。
fn distort_warp(img: &mut RgbaImage, amp: f64, period: f64, oob: [u8; 4]) {
    let (w, h) = (img.width() as i32, img.height() as i32);
    let dx = 2.0 * PI / period;
    let old = img.clone();
    for y in 0..h {
        for x in 0..w {
            let xo = amp * (f64::from(y) * dx).sin();
            let yo = amp * (f64::from(x) * dx).cos();
            let sx = x + xo as i32;
            let sy = y + yo as i32;
            let c = if sx < 0 || sy < 0 || sx >= w || sy >= h {
                oob
            } else {
                old.get_pixel(sx as u32, sy as u32).0
            };
            img.put_pixel(x as u32, y as u32, Rgba(c));
        }
    }
}

/// 旋转外接尺寸(含 0.1 舍入分支)。
fn rotated_size(w: i32, h: i32, angle_deg: i32) -> (i32, i32) {
    if w <= 0 || h <= 0 {
        return (0, 0);
    }
    let rad = f64::from(angle_deg) * PI / 180.0;
    let (sin, cos) = rad.sin_cos();
    let mut min_x = 0.0f64;
    let mut max_x = 0.0f64;
    let mut min_y = 0.0f64;
    let mut max_y = 0.0f64;
    for (px, py) in [
        (f64::from(w - 1), 0.0),
        (f64::from(w - 1), f64::from(h - 1)),
        (0.0, f64::from(h - 1)),
    ] {
        let rx = px * cos - py * sin;
        let ry = px * sin + py * cos;
        min_x = min_x.min(rx);
        max_x = max_x.max(rx);
        min_y = min_y.min(ry);
        max_y = max_y.max(ry);
    }
    let mut width = max_x - min_x + 1.0;
    if width - width.floor() > 0.1 {
        width += 1.0;
    }
    let mut height = max_y - min_y + 1.0;
    if height - height.floor() > 0.1 {
        height += 1.0;
    }
    (width as i32, height as i32)
}

/// 扩幅旋转(绕中心旋转进外接画布,最近邻采样)。
fn rotate_expand(img: &RgbaImage, angle_deg: i32) -> RgbaImage {
    if angle_deg == 0 {
        return img.clone();
    }
    let (sw, sh) = (img.width() as i32, img.height() as i32);
    let (w, h) = rotated_size(sw, sh, angle_deg);
    if w <= 0 || h <= 0 {
        return img.clone();
    }
    let mut out = RgbaImage::new(w as u32, h as u32);
    let rad = f64::from(angle_deg) * PI / 180.0;
    let (sin, cos) = rad.sin_cos();
    let (scx, scy) = (f64::from(sw) / 2.0, f64::from(sh) / 2.0);
    let (dcx, dcy) = (f64::from(w) / 2.0, f64::from(h) / 2.0);
    for y in 0..h {
        for x in 0..w {
            let ux = f64::from(x) - dcx;
            let uy = f64::from(y) - dcy;
            let sx = cos * ux + sin * uy + scx;
            let sy = -sin * ux + cos * uy + scy;
            if sx >= 0.0 && sy >= 0.0 && sx < f64::from(sw) && sy < f64::from(sh) {
                out.put_pixel(x as u32, y as u32, *img.get_pixel(sx as u32, sy as u32));
            }
        }
    }
    out
}

/// 原幅旋转(绕中心逆映射,画布尺寸不变)。
fn rotate_inplace(img: &mut RgbaImage, angle_deg: i32) {
    if angle_deg == 0 {
        return;
    }
    let (w, h) = (img.width() as i32, img.height() as i32);
    let rad = f64::from(angle_deg) * PI / 180.0;
    let (sin, cos) = rad.sin_cos();
    let (cx, cy) = (f64::from(w) / 2.0, f64::from(h) / 2.0);
    let old = img.clone();
    for y in 0..h {
        for x in 0..w {
            let ux = f64::from(x) - cx;
            let uy = f64::from(y) - cy;
            let sx = cos * ux + sin * uy + cx;
            let sy = -sin * ux + cos * uy + cy;
            let px = if sx >= 0.0 && sy >= 0.0 && sx < f64::from(w) && sy < f64::from(h) {
                *old.get_pixel(sx as u32, sy as u32)
            } else {
                Rgba([0, 0, 0, 0])
            };
            img.put_pixel(x as u32, y as u32, px);
        }
    }
}

/// 非透明包围盒 ±2,越界截断。
fn calc_margin_blank(img: &RgbaImage) -> (i32, i32, i32, i32) {
    let (w, h) = (img.width() as i32, img.height() as i32);
    let mut min_x = w;
    let mut max_x = 0;
    let mut min_y = h;
    let mut max_y = 0;
    for y in 0..h {
        for x in 0..w {
            if img.get_pixel(x as u32, y as u32).0[3] > 0 {
                if x < min_x {
                    min_x = x;
                }
                if x > max_x {
                    max_x = x;
                }
                if y < min_y {
                    min_y = y;
                }
                if y > max_y {
                    max_y = y;
                }
            }
        }
    }
    min_x = (min_x - 2).max(0);
    max_x = (max_x + 2).min(w);
    min_y = (min_y - 2).max(0);
    max_y = (max_y + 2).min(h);
    (min_x, min_y, max_x - min_x, max_y - min_y)
}

/// 数字字形位图(11×18),与 base64Captcha 的 digitFontData 逐字节一致(Apache-2.0)。
const DIGIT_FONT: [[u8; 198]; 10] = [
    [
        0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1,
        1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0,
        0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
        0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1,
        1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1,
        1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0,
    ],
    [
        0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,
        0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    ],
    [
        0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1,
        1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0,
        0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    ],
    [
        0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1,
        1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1,
        1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1,
        0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1,
        1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0,
    ],
    [
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0,
    ],
    [
        0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0,
        0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1,
        1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1,
        1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1,
        1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0,
    ],
    [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    ],
    [
        0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0,
        1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0,
        0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0,
        0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1,
        0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0,
    ],
    [
        0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1,
        1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0,
        0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,
        1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1,
        1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    ],
];

// 内置常量:ID/字符/噪声表与点选色表。
const TXT_NUMBERS: &str = "012346789";
const ID_CHARS: &str = "012346789ABCDEFGHJKMNOQRSTUVXYZabcdefghjkmnoqrstuvxyz";
const NOISE_CHARS: &str = "012346789ABCDEFGHJKMNOQRSTUVXYZabcdefghjkmnoqrstuvxyz,.[]<>";
const CLICK_COLORS: [&str; 7] = [
    "#fde98e", "#60c1ff", "#fcb08e", "#fb88ff", "#b4fed4", "#cbfaa9", "#78d6f8",
];
const CLICK_THUMB_COLORS: [&str; 7] = [
    "#1f55c4", "#780592", "#2f6b00", "#910000", "#864401", "#675901", "#016e5c",
];

// ---------------------------------------------------------------------------
// 渲染:文本(列布局 + 噪声字符)
// ---------------------------------------------------------------------------

/// 文本渲染:先铺随机噪声字符、再写题面字符。
/// 背景恒随机浅色、字形恒随机深色(配置中的颜色字段为惰性)。
#[allow(clippy::too_many_arguments)]
fn gen_text(
    width: i32,
    height: i32,
    noise_count: usize,
    noise_pool: &str,
    question: &str,
    answer: &str,
    rng: &mut impl Rng,
) -> Result<(String, String, String), String> {
    if question.is_empty() {
        return Err("draw captcha: text must not be empty".into());
    }
    if width <= 0 || height <= 0 {
        return Err("draw captcha: invalid size".into());
    }
    let mut img = RgbaImage::from_pixel(width as u32, height as u32, Rgba(rand_light_color(rng)));
    if noise_count > 0 {
        let raw_font_size = f64::from(height) / (1.0 + f64::from(ri_n(rng, 7)) / 10.0);
        if let Some(noise) = rand_text(noise_count, noise_pool, rng) {
            for ch in noise.chars() {
                let rw = ri_n(rng, width);
                let rh = ri_n(rng, height);
                let size = (raw_font_size / 2.0 + f64::from(ri_n(rng, 5))) as i32;
                let (gw, gh) = glyph_dims(ch, size);
                draw_scaled_glyph(&mut img, ch, rw, rh - gh, gw, gh, rand_light_color(rng));
            }
        }
    }
    let font_width = width / question.len() as i32;
    for (byte_off, ch) in question.char_indices() {
        let font_size = height * (ri_n(rng, 7) + 7) / 16;
        let color = rand_deep_color(rng);
        let x = font_width * byte_off as i32 + font_width / font_size;
        let y = height / 2 + font_size / 2 - ri_n(rng, height / 16 * 3);
        let (gw, gh) = glyph_dims(ch, font_size);
        draw_scaled_glyph(&mut img, ch, x, y - gh, gw, gh, color);
    }
    let id = random_id(rng);
    let b64 = png_data_uri(&img)?;
    Ok((id, b64, answer.to_string()))
}

// ---------------------------------------------------------------------------
// 渲染:数字点阵
// ---------------------------------------------------------------------------

/// 数字渲染:圆填充字形与逐行剪切、穿透线、正弦扭曲、
/// 干扰圆填充;调色板色映射到 RGBA。
fn render_digit(
    cfg: &DigitConfig,
    question: &str,
    rng: &mut impl Rng,
) -> Result<(String, String), String> {
    if cfg.width == 0 || cfg.height == 0 {
        return Err("draw captcha: invalid size".into());
    }
    let (w, h) = (cfg.width as i32, cfg.height as i32);
    let count = question.chars().count() as i32;
    let mut prim = [0u8; 4];
    for v in prim.iter_mut().take(3) {
        *v = rng.random_range(0..129) as u8;
    }
    prim[3] = 255;
    let mut palette: Vec<[u8; 4]> = Vec::new();
    if cfg.dot_count == 0 {
        palette.push(prim);
    } else {
        palette.push([255, 255, 255, 0]);
        palette.push(prim);
        for _ in 2..=cfg.dot_count {
            palette.push(random_brightness(rng, prim));
        }
    }
    let (m_width, m_height, dot_size) = calc_digit_sizes(w, h, count);
    let maxx = w - (m_width + dot_size) * count - dot_size;
    let maxy = h - m_height - dot_size * 2;
    let border = if w > h { h / 5 } else { w / 5 };
    let mut x = ri_n(rng, maxx - border * 2) + border;
    let y = ri_n(rng, maxy - border * 2) + border;
    let mut img = RgbaImage::from_pixel(w as u32, h as u32, Rgba(palette[0]));
    let glyph_color = *palette.get(1).unwrap_or(&[255, 255, 255, 0]);
    for ch in question.chars() {
        let idx = (ch as u8).wrapping_sub(b'0') as usize;
        if let Some(digit) = DIGIT_FONT.get(idx) {
            draw_digit(
                &mut img,
                digit,
                x,
                y,
                dot_size,
                cfg.max_skew,
                glyph_color,
                rng,
            );
        }
        x += m_width + dot_size;
    }
    strike_through(&mut img, dot_size, glyph_color, rng);
    distort_warp(
        &mut img,
        rf(rng) * 5.0 + 5.0,
        rf(rng) * 100.0 + 100.0,
        palette[0],
    );
    fill_with_circles(&mut img, cfg.dot_count as i32, dot_size, &palette, rng);
    let id = random_id(rng);
    let b64 = png_data_uri(&img)?;
    Ok((id, b64))
}

/// 计算摆位:边距内的单字宽高与点阵点径。
fn calc_digit_sizes(w: i32, h: i32, count: i32) -> (i32, i32, i32) {
    let border = if w > h { h / 4 } else { w / 4 };
    let wf = f64::from(w - border * 2);
    let hf = f64::from(h - border * 2);
    let fw = 12.0;
    let fh = 18.0;
    let mut nw = wf / f64::from(count);
    let mut nh = nw * fh / fw;
    if nh > hf {
        nh = hf;
        nw = fw / fh * nh;
    }
    let mut dot_size = (nh / fh) as i32;
    if dot_size < 1 {
        dot_size = 1;
    }
    (nw as i32 - dot_size, nh as i32, dot_size)
}

/// 逐字形像素画填充圆,每行结束累加横向剪切。
#[allow(clippy::too_many_arguments)]
fn draw_digit(
    img: &mut RgbaImage,
    digit: &[u8; 198],
    x: i32,
    y: i32,
    dot_size: i32,
    max_skew: f64,
    color: [u8; 4],
    rng: &mut impl Rng,
) {
    let skf = rf(rng) * (2.0 * max_skew) - max_skew;
    let mut xs = f64::from(x);
    let y = y + ri_range(rng, -(dot_size / 2), dot_size / 2);
    let r = dot_size / 2;
    let mut x = x;
    for yo in 0..18 {
        for xo in 0..11 {
            if digit[(yo * 11 + xo) as usize] == 1 {
                draw_filled_circle(img, x + xo * dot_size, y + yo * dot_size, r, color);
            }
        }
        xs += skf;
        x = xs as i32;
    }
}

/// 穿透线:沿正弦轨迹以填充圆涂抹横贯线。
fn strike_through(img: &mut RgbaImage, dot_size: i32, color: [u8; 4], rng: &mut impl Rng) {
    let (w, h) = (img.width() as i32, img.height() as i32);
    let y = ri_range(rng, h / 3, h - h / 3);
    let amplitude = rf(rng) * 15.0 + 5.0;
    let period = rf(rng) * 100.0 + 80.0;
    let dx = 2.0 * PI / period;
    for x in 0..w {
        let xo = amplitude * (f64::from(y) * dx).cos();
        let yo = amplitude * (f64::from(x) * dx).sin();
        for yn in 0..dot_size {
            let r = ri_n(rng, dot_size);
            draw_filled_circle(
                img,
                x + xo as i32,
                y + yo as i32 + yn * dot_size,
                r / 2,
                color,
            );
        }
    }
}

/// 干扰圆填充:从调色板取色随机画圆。
fn fill_with_circles(
    img: &mut RgbaImage,
    n: i32,
    max_radius: i32,
    palette: &[[u8; 4]],
    rng: &mut impl Rng,
) {
    let (w, h) = (img.width() as i32, img.height() as i32);
    for _ in 0..n {
        let color_idx = ri_range(rng, 1, n - 1);
        let r = ri_range(rng, 1, max_radius);
        let Some(color) = palette.get(color_idx as usize) else {
            continue;
        };
        draw_filled_circle(
            img,
            ri_range(rng, r, w - r),
            ri_range(rng, r, h - r),
            r,
            *color,
        );
    }
}

// ---------------------------------------------------------------------------
// 渲染:点选
// ---------------------------------------------------------------------------

/// 主图点位(生成侧内部结构)。
struct ClickDotRaw {
    char: char,
    x: i32,
    y: i32,
    size: i32,
    width: i32,
    height: i32,
    angle: i32,
    color: String,
    color2: String,
}

/// 角度采样(六段区间取一,段内闭区间均匀)。
fn click_angle(rng: &mut impl Rng) -> i32 {
    const RANGES: [(i32, i32); 6] = [
        (20, 35),
        (35, 45),
        (45, 60),
        (290, 305),
        (305, 325),
        (325, 330),
    ];
    let (lo, hi) = pick(rng, &RANGES);
    ri_fast(rng, lo, hi)
}

/// 主图点位采样(padding=10;列分布 + 列内抖动 + 双侧截断,
/// 记录 Y 为 `y - size`)。
fn click_master_dots(cfg: &ClickConfig, chars: &[char], rng: &mut impl Rng) -> Vec<ClickDotRaw> {
    let count = chars.len() as i32;
    let padding = 10i32;
    let width = cfg.master_width as i32 - padding;
    let height = cfg.master_height as i32 - padding;
    let dy = 10i32;
    (0..count)
        .map(|i| {
            let size = ri_fast(rng, 26, 32);
            let w = width / count;
            let rd = (w - size).abs();
            let xx = i * w + ri_fast(rng, 0, rd.max(1));
            let x = xx.max(dy).min(width - dy - padding * 2);
            let yy = ri_fast(rng, dy, height + size);
            let y = yy.max(size + dy).min(height + size / 2 - padding * 2);
            ClickDotRaw {
                char: chars[i as usize],
                x,
                y: y - size,
                size,
                width: size,
                height: size,
                angle: click_angle(rng),
                color: pick(rng, &CLICK_COLORS).to_string(),
                color2: pick(rng, &CLICK_THUMB_COLORS).to_string(),
            }
        })
        .collect()
}

/// 主图字符管线:阴影按配置偏移先行、主字形随后,整幅扩幅旋转,
/// 非空包围盒回写点位宽高,覆盖合成到主图。
fn click_draw_glyph(master: &mut RgbaImage, dot: &mut ClickDotRaw, cfg: &ClickConfig) {
    let size = dot.size;
    let (gw, gh) = glyph_dims(dot.char, size);
    let (ox, oy) = if is_han(dot.char) { (10, 0) } else { (12, 0) };
    let mut small = RgbaImage::new((size + 10) as u32, (size + 10) as u32);
    if cfg.display_shadow {
        let shadow_hex = if cfg.shadow_color.is_empty() {
            "#101010"
        } else {
            &cfg.shadow_color
        };
        draw_scaled_glyph(
            &mut small,
            dot.char,
            ox + cfg.shadow_offset_x,
            oy + cfg.shadow_offset_y,
            gw,
            gh,
            parse_hex_color(shadow_hex),
        );
    }
    draw_scaled_glyph(
        &mut small,
        dot.char,
        ox,
        oy,
        gw,
        gh,
        parse_hex_color(&dot.color),
    );
    let rotated = rotate_expand(&small, dot.angle);
    let region = calc_margin_blank(&rotated);
    composite_over(master, &rotated, region, dot.x, dot.y);
    dot.width = region.2;
    dot.height = region.3;
}

/// 渐变背景(公式生成 300×220 底图,目标更小时随机偏移裁剪粘贴)。
fn paste_gradient(rng: &mut impl Rng, dst: &mut RgbaImage) {
    let (tw, th) = (dst.width() as i32, dst.height() as i32);
    let mut cur_x = 0;
    let mut cur_y = 0;
    if 300 - tw > 0 {
        cur_x = ri_fast(rng, 0, 300 - tw);
    }
    if 220 - th > 0 {
        cur_y = ri_fast(rng, 0, 220 - th);
    }
    let copy_w = tw.min(300 - cur_x);
    let copy_h = th.min(220 - cur_y);
    for y in 0..copy_h {
        for x in 0..copy_w {
            let px = gradient_px(x + cur_x, y + cur_y);
            dst.put_pixel(x as u32, y as u32, Rgba(px));
        }
    }
}

fn gradient_px(x: i32, y: i32) -> [u8; 4] {
    [(100 + x % 50) as u8, (150 + y % 50) as u8, 200, 255]
}

/// 缩略图:干扰圆、五像素折线、单元格字符、正弦扭曲;
/// 色表为内置深色系。
fn click_thumb(cfg: &ClickConfig, chars: &[char], rng: &mut impl Rng) -> RgbaImage {
    let mut img =
        RgbaImage::from_pixel(cfg.thumb_width, cfg.thumb_height, Rgba([255, 255, 255, 0]));
    let (w, h) = (img.width() as i32, img.height() as i32);
    // 干扰圆(24 个、半径 1)
    for _ in 0..24 {
        let color = parse_hex_color(pick(rng, &CLICK_THUMB_COLORS));
        let r = ri_fast(rng, 1, 1);
        draw_filled_circle(
            &mut img,
            ri_fast(rng, r, w - r),
            ri_fast(rng, r, h - r),
            r,
            color,
        );
    }
    // 折线(2 条,奇偶分支)
    let first = w / 10;
    let end = first * 9;
    let y = h / 3;
    for i in 0..2 {
        let mut p1 = (ri_n(rng, first), ri_n(rng, y));
        let mut p2 = (ri_n(rng, first) + end, ri_n(rng, y));
        if i % 2 == 0 {
            p1.1 = ri_n(rng, y) + y * 2;
            p2.1 = ri_n(rng, y);
        } else {
            p1.1 = ri_n(rng, y) + y * (i % 2);
            p2.1 = ri_n(rng, y) + y * 2;
        }
        let color = parse_hex_color(pick(rng, &CLICK_THUMB_COLORS));
        draw_beeline(&mut img, p1, p2, color);
    }
    // 单元格字符(尺寸 22..28、深色、不旋转)
    let cell = w / chars.len() as i32;
    for (i, ch) in chars.iter().enumerate() {
        let size = ri_fast(rng, 22, 28);
        let color = parse_hex_color(pick(rng, &CLICK_THUMB_COLORS));
        let dx = (cell * i as i32 + cell / size).max(8);
        let dy = h / 2 + size / 2 - ri_n(rng, h / 16);
        let (gw, gh) = glyph_dims(*ch, size);
        draw_scaled_glyph(&mut img, *ch, dx, dy - gh, gw, gh, color);
    }
    // 扭曲(周期 100..160)
    distort_warp(
        &mut img,
        f64::from(ri_fast(rng, 5, 10)),
        f64::from(ri_fast(rng, 100, 160)),
        [255, 255, 255, 0],
    );
    img
}

/// 点选驱动:主图 JPEG、缩略图 PNG,点位元数据与期望答案同源。
/// 期望答案按数组存储,使逐点 ±10px 的验证语义可用。
fn gen_click(cfg: &ClickConfig, rng: &mut impl Rng) -> Result<(String, String, String), String> {
    let chars_src = if cfg.chars.is_empty() {
        "这的是随了机文我你他字在有不么中"
    } else {
        &cfg.chars
    };
    let pool: Vec<char> = chars_src.chars().collect();
    let count = cfg.captcha_count as i32;
    if count <= 0 || pool.len() < count as usize {
        return Err("character length must be greater than rangeLen.Max".into());
    }
    // 无重复采样(洗牌后截取前 count 个)
    let mut chars = pool;
    chars.shuffle(rng);
    chars.truncate(count as usize);
    let mut master_dots = click_master_dots(cfg, &chars, rng);
    // 选出待验证点位(重排 + 重编号)
    let mut perm: Vec<usize> = (0..chars.len()).collect();
    perm.shuffle(rng);
    let verify: Vec<usize> = perm.into_iter().take(cfg.verify_count).collect();
    // 主图:渐变背景 + 字形管线(回写点位宽高)
    let mut master = RgbaImage::new(cfg.master_width, cfg.master_height);
    paste_gradient(rng, &mut master);
    for dot in &mut master_dots {
        click_draw_glyph(&mut master, dot, cfg);
    }
    // 缩略图:仅待验证字符
    let verify_chars: Vec<char> = verify.iter().map(|&i| chars[i]).collect();
    let thumb = click_thumb(cfg, &verify_chars, rng);
    // 输出元数据与期望答案(同一批点位)
    let mut dots_map = HashMap::with_capacity(verify.len());
    let mut expected: Vec<ExpectedClickDot> = Vec::with_capacity(verify.len());
    for (new_idx, &di) in verify.iter().enumerate() {
        let d = &master_dots[di];
        dots_map.insert(
            new_idx as i32,
            ClickDot {
                x: d.x,
                y: d.y,
                char: String::new(),
                width: d.width,
                height: d.height,
                angle: d.angle,
            },
        );
        expected.push(ExpectedClickDot {
            index: new_idx as i32,
            x: d.x,
            y: d.y,
            size: d.size,
            width: d.width,
            height: d.height,
            text: d.char.to_string(),
            shape: String::new(),
            angle: d.angle,
            color: d.color.clone(),
            color2: d.color2.clone(),
        });
    }
    let id = format!("click_{}", unix_nanos());
    let data = ClickCaptchaData {
        id: id.clone(),
        master_image: jpeg_data_uri(&master)?,
        thumb_image: png_data_uri(&thumb)?,
        dots: dots_map,
    };
    let b64 = serde_json::to_string(&data).map_err(|e| format!("json: {e}"))?;
    let answer = serde_json::to_string(&expected).map_err(|e| format!("json: {e}"))?;
    Ok((id, b64, answer))
}

// ---------------------------------------------------------------------------
// 渲染:滑块
// ---------------------------------------------------------------------------

/// 圆角矩形掩码(滑块缺口与滑块图的形状;`jigsaw_radius`
/// 等其余滑块配置字段为惰性)。
fn in_rounded_rect(px: i32, py: i32, w: i32, h: i32, radius: i32) -> bool {
    if px < 0 || py < 0 || px >= w || py >= h {
        return false;
    }
    let r = radius.clamp(0, (w.min(h) - 1) / 2);
    let cx = px.clamp(r, w - 1 - r);
    let cy = py.clamp(r, h - 1 - r);
    let dx = px - cx;
    let dy = py - cy;
    dx * dx + dy * dy <= r * r
}

/// 滑块驱动:单一图块、左侧留死区,缺口位置 Y 为 [5, H-c-5]
/// 闭区间;渐变背景,缺口区域经圆角掩码提取为滑块图、
/// 主图对应区域亮度乘 0.45。
fn gen_slide(cfg: &SlideConfig, rng: &mut impl Rng) -> Result<(String, String, String), String> {
    let c_w = ri_fast(rng, cfg.tile_width as i32, cfg.tile_width as i32);
    let dp = c_w / 2;
    let block_width = cfg.master_width as i32 - c_w - 20;
    let y = ri_fast(rng, 5, cfg.master_height as i32 - c_w - 5);
    let (mut start, mut end) = (dp + 5, block_width - dp);
    start += c_w;
    end += c_w;
    start = start.max(dp + 5);
    let x = ri_fast(rng, start + 20, end + 20) - dp;
    let mut master = RgbaImage::new(cfg.master_width, cfg.master_height);
    paste_gradient(rng, &mut master);
    let mut tile = RgbaImage::new(c_w.max(1) as u32, c_w.max(1) as u32);
    let radius = cfg.tile_radius as i32;
    for py in 0..c_w {
        for px in 0..c_w {
            if !in_rounded_rect(px, py, c_w, c_w, radius) {
                continue;
            }
            let (mx, my) = (x + px, y + py);
            if mx < 0 || my < 0 || mx >= cfg.master_width as i32 || my >= cfg.master_height as i32 {
                continue;
            }
            let src = *master.get_pixel(mx as u32, my as u32);
            tile.put_pixel(px as u32, py as u32, src);
            let dark = [
                (f32::from(src.0[0]) * 0.45) as u8,
                (f32::from(src.0[1]) * 0.45) as u8,
                (f32::from(src.0[2]) * 0.45) as u8,
                255,
            ];
            master.put_pixel(mx as u32, my as u32, Rgba(dark));
        }
    }
    let id = format!("{x}_{y}");
    let data = SlideCaptchaData {
        id: id.clone(),
        master_image: jpeg_data_uri(&master)?,
        tile_image: png_data_uri(&tile)?,
        x_position: x,
    };
    let b64 = serde_json::to_string(&data).map_err(|e| format!("json: {e}"))?;
    let answer = x.to_string();
    Ok((id, b64, answer))
}

// ---------------------------------------------------------------------------
// 渲染:旋转
// ---------------------------------------------------------------------------

/// 旋转驱动:主图 220×220、缩略边长 {140,150,160,170}
/// 中随机、角度 [30,330] 闭区间(内置常量,`RotateConfig`
/// 字段为惰性)。圆盘为程序生成的径向图案;主图即圆盘未旋转,
/// 缩略图为中心裁剪 + 内切圆掩码后旋转。
fn gen_rotate(rng: &mut impl Rng) -> Result<(String, String, String), String> {
    const SIZE: i32 = 220;
    let thumb_size = pick(rng, &[140i32, 150, 160, 170]);
    let angle = ri_fast(rng, 30, 330);
    let mut disc = RgbaImage::new(SIZE as u32, SIZE as u32);
    let (p1, p2) = (rng.random_range(3.0..=9.0), rng.random_range(2.0..=6.0));
    let center = f64::from(SIZE) / 2.0;
    for y in 0..SIZE {
        for x in 0..SIZE {
            let (dx, dy) = (f64::from(x) - center, f64::from(y) - center);
            if dx * dx + dy * dy > center * center {
                continue;
            }
            let ang = dy.atan2(dx);
            let r = (dx * dx + dy * dy).sqrt();
            let v = (ang * p1).sin() * 127.0 + 128.0;
            let w = (r * p2).sin() * 127.0 + 128.0;
            disc.put_pixel(
                x as u32,
                y as u32,
                Rgba([v as u8, w as u8, ((v + w) / 2.0) as u8, 255]),
            );
        }
    }
    let mut thumb = RgbaImage::new(thumb_size as u32, thumb_size as u32);
    let off = (SIZE - thumb_size) / 2;
    let half = thumb_size / 2;
    for y in 0..thumb_size {
        for x in 0..thumb_size {
            let (cx, cy) = (x - half, y - half);
            if cx * cx + cy * cy > half * half {
                continue;
            }
            let px = *disc.get_pixel((x + off) as u32, (y + off) as u32);
            thumb.put_pixel(x as u32, y as u32, px);
        }
    }
    rotate_inplace(&mut thumb, angle);
    let id = format!("rotate_{}", unix_nanos());
    let data = RotateCaptchaData {
        id: id.clone(),
        master_image: png_data_uri(&disc)?,
        thumb_image: png_data_uri(&thumb)?,
        angle,
    };
    let b64 = serde_json::to_string(&data).map_err(|e| format!("json: {e}"))?;
    let answer = angle.to_string();
    Ok((id, b64, answer))
}

// ---------------------------------------------------------------------------
// 图片编码
// ---------------------------------------------------------------------------

fn png_data_uri(img: &RgbaImage) -> Result<String, String> {
    let mut buf = Vec::new();
    PngEncoder::new(&mut buf)
        .write_image(
            img.as_raw(),
            img.width(),
            img.height(),
            ExtendedColorType::Rgba8,
        )
        .map_err(|e| format!("png encode: {e}"))?;
    Ok(format!(
        "data:image/png;base64,{}",
        base64util::encode(&buf)
    ))
}

/// JPEG(质量 100;JPEG 无 alpha,编码时丢弃)。
fn jpeg_data_uri(img: &RgbaImage) -> Result<String, String> {
    let (w, h) = (img.width(), img.height());
    let mut rgb = RgbImage::new(w, h);
    for y in 0..h {
        for x in 0..w {
            let p = img.get_pixel(x, y).0;
            rgb.put_pixel(x, y, Rgb([p[0], p[1], p[2]]));
        }
    }
    let mut buf = Vec::new();
    JpegEncoder::new_with_quality(&mut buf, 100)
        .write_image(rgb.as_raw(), w, h, ExtendedColorType::Rgb8)
        .map_err(|e| format!("jpeg encode: {e}"))?;
    Ok(format!(
        "data:image/jpeg;base64,{}",
        base64util::encode(&buf)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::GenericImageView;

    fn decode_img(data_uri: &str) -> image::DynamicImage {
        let b64 = data_uri.split_once(',').unwrap().1;
        image::load_from_memory(&base64util::decode(b64).unwrap()).unwrap()
    }

    // ---------- 存储层 ----------

    #[test]
    fn memory_store_ttl() {
        let store = MemoryStore::new();
        store.save("k1", "v1", Duration::from_millis(60)).unwrap();
        assert_eq!(store.get("k1").unwrap().as_deref(), Some("v1"));
        assert!(store.exists("k1").unwrap());
        assert!(store.remaining_ttl("k1").unwrap().is_some());

        store.delete("k1").unwrap();
        assert!(!store.exists("k1").unwrap());
        assert_eq!(store.get("k1").unwrap(), None);
        assert_eq!(store.remaining_ttl("k1").unwrap(), None);

        store.save("k2", "v2", Duration::from_millis(30)).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        assert!(!store.exists("k2").unwrap());
        assert_eq!(store.get("k2").unwrap(), None);
    }

    #[test]
    fn key_prefix_isolation() {
        // 默认前缀 captcha
        let cap = Captcha::new();
        cap.save("manual-id", "answer").unwrap();
        // 自定义前缀
        let cap2 = Captcha::with_config(Config {
            key_prefix: "custom".to_string(),
            ..Config::with_driver(DriverKind::Digit)
        });
        cap2.save("id2", "answer").unwrap();
        // 互不可见对方条目(键含前缀)
        assert!(!cap.exists("id2").unwrap());
        assert!(!cap2.exists("manual-id").unwrap());
        assert!(cap.exists("manual-id").unwrap());
        assert!(cap2.exists("id2").unwrap());
    }

    #[test]
    fn expiry_ends_verification() {
        let cap = Captcha::with_config(Config {
            expire: Some(Duration::from_millis(50)),
            ..Config::with_driver(DriverKind::Digit)
        });
        let (id, _, answer) = cap.generate().unwrap();
        assert!(cap.exists(&id).unwrap());
        std::thread::sleep(Duration::from_millis(120));
        assert!(!cap.exists(&id).unwrap());
        assert!(!cap.verify(&id, &answer).unwrap());
    }

    // ---------- 文本驱动 ----------

    #[test]
    fn digit_roundtrip() {
        let cap = Captcha::with_config(Config::with_driver(DriverKind::Digit));
        let (id, b64, answer) = cap.generate().unwrap();
        assert_eq!(id.len(), 20); // 随机 ID:20 字符取自数字+字母表
        assert!(id.chars().all(|c| ID_CHARS.contains(c)));
        assert_eq!(answer.len(), 4);
        assert!(answer.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(decode_img(&b64).dimensions(), (240, 80));
        assert!(cap.exists(&id).unwrap());
        assert!(cap.get_remaining_time(&id).unwrap().is_some());
        // 一次性校验
        assert!(cap.verify(&id, &answer).unwrap());
        assert!(!cap.exists(&id).unwrap());
        assert!(!cap.verify(&id, &answer).unwrap());
    }

    #[test]
    fn verify_semantics() {
        let cap = Captcha::with_config(Config::with_driver(DriverKind::String));
        let (id, b64, answer) = cap.generate().unwrap();
        assert_eq!(answer.chars().count(), 4);
        assert!(answer.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(decode_img(&b64).dimensions(), (240, 80));
        // 错误答案不删除
        assert!(!cap.verify(&id, "!!!!").unwrap());
        assert!(cap.exists(&id).unwrap());
        // 精确比较:带空白不匹配
        assert!(!cap.verify(&id, &format!(" {answer} ")).unwrap());
        assert!(cap.exists(&id).unwrap());
        // 不存在的条目
        assert!(!cap.verify("nonexistent", "x").unwrap());
        // 正确答案匹配并删除
        assert!(cap.verify(&id, &answer).unwrap());
        assert!(!cap.exists(&id).unwrap());
    }

    #[test]
    fn verify_keep_semantics() {
        let cap = Captcha::with_config(Config::with_driver(DriverKind::String));
        let (id, _, answer) = cap.generate().unwrap();
        assert!(cap.verify_keep(&id, &answer).unwrap());
        assert!(cap.exists(&id).unwrap()); // 不删除
        assert!(cap.verify(&id, &answer).unwrap()); // 显式删除后失效
        assert!(!cap.exists(&id).unwrap());
    }

    #[test]
    fn math_driver() {
        let cap = Captcha::with_config(Config::with_driver(DriverKind::Math));
        let (_, b64, answer) = cap.generate().unwrap();
        assert!(answer.parse::<i64>().is_ok(), "math answer: {answer}");
        assert_eq!(decode_img(&b64).dimensions(), (240, 80));
    }

    /// `Chinese` 驱动字符池取 `language`(默认 "zh")。
    #[test]
    fn chinese_default_pool() {
        let cap = Captcha::with_config(Config::with_driver(DriverKind::Chinese));
        let (_, b64, answer) = cap.generate().unwrap();
        assert_eq!(answer.chars().count(), 4);
        assert!(answer.chars().all(|c| matches!(c, 'z' | 'h')));
        assert_eq!(decode_img(&b64).dimensions(), (240, 80));
    }

    /// 逗号切分段数多于长度时逐字随机取段(词表模式)。
    #[test]
    fn chinese_word_list() {
        let cap = Captcha::with_config(Config {
            chinese_config: Some(ChineseConfig {
                language: "甲乙,丙丁,戊己,庚辛,壬癸,子丑,寅卯,辰巳".to_string(),
                ..ChineseConfig::default()
            }),
            ..Config::with_driver(DriverKind::Chinese)
        });
        let (_, _, answer) = cap.generate().unwrap();
        assert_eq!(answer.chars().count(), 8); // 4 词 × 2 字
        assert!(answer
            .chars()
            .all(|c| "甲乙丙丁戊己庚辛壬癸子丑寅卯辰巳".contains(c)));
    }

    /// 段数不大于长度时回退数字字母表。
    #[test]
    fn chinese_fallback_pool() {
        let cap = Captcha::with_config(Config {
            chinese_config: Some(ChineseConfig {
                language: "甲,乙".to_string(),
                ..ChineseConfig::default()
            }),
            ..Config::with_driver(DriverKind::Chinese)
        });
        let (_, _, answer) = cap.generate().unwrap();
        assert_eq!(answer.chars().count(), 4);
        assert!(answer.chars().all(|c| ID_CHARS.contains(c)));
    }

    #[test]
    fn manual_save_and_remaining() {
        let cap = Captcha::new();
        cap.save("manual-id", "answer").unwrap();
        assert!(cap.exists("manual-id").unwrap());
        let ttl = cap.get_remaining_time("manual-id").unwrap().unwrap();
        assert!(ttl <= Duration::from_secs(300) && ttl > Duration::ZERO);
        assert!(cap.verify("manual-id", "answer").unwrap());
    }

    // ---------- 配置面 ----------

    #[test]
    fn config_get_set() {
        let cap = Captcha::new();
        cap.set_config(Config {
            driver: Some(DriverKind::Chinese),
            expire: Some(Duration::from_secs(30)),
            chinese_config: Some(ChineseConfig {
                language: "甲乙,丙丁,戊己,庚辛,壬癸,子丑,寅卯,辰巳".to_string(),
                captcha_count: 5,
                ..ChineseConfig::default()
            }),
            ..Config::with_driver(DriverKind::Digit)
        });
        let got = cap.get_config();
        assert_eq!(got.driver(), DriverKind::Chinese);
        assert_eq!(got.expire(), Duration::from_secs(30));
        assert_eq!(got.chinese().language.chars().count(), 23); // 16 字 + 7 个逗号
                                                                // 新配置生效:词表模式 5 词
        let (_, _, answer) = cap.generate().unwrap();
        assert_eq!(answer.chars().count(), 10);
    }

    /// 默认配置逐项断言(含惰性字段)。
    #[test]
    fn default_config_values() {
        let cfg = Captcha::new().get_config();
        assert_eq!(cfg.driver(), DriverKind::Digit);
        assert_eq!(cfg.expire(), Duration::from_secs(300));
        assert_eq!(cfg.key_prefix(), "captcha");
        let d = cfg.digit();
        assert_eq!(
            (d.width, d.height, d.captcha_count, d.dot_count),
            (240, 80, 4, 80)
        );
        assert!((d.max_skew - 0.7).abs() < 1e-9);
        assert_eq!(d.bg_color, [255, 255, 255]);
        assert_eq!(d.font_color, [0, 0, 0]);
        let s = cfg.string();
        assert_eq!(
            (s.width, s.height, s.captcha_count, s.dot_count),
            (240, 80, 4, 80)
        );
        assert_eq!(s.source.len(), 62);
        let m = cfg.math();
        assert_eq!((m.width, m.height, m.dot_count), (240, 80, 80));
        assert_eq!(cfg.chinese().language, "zh");
        let sl = cfg.slide();
        assert_eq!(
            (
                sl.master_width,
                sl.master_height,
                sl.tile_width,
                sl.tile_height
            ),
            (300, 220, 60, 60)
        );
        assert_eq!(
            (
                sl.tile_radius,
                sl.jigsaw_radius,
                sl.shadow_offset_x,
                sl.shadow_offset_y,
                sl.shadow_blur
            ),
            (5, 10, 5, 5, 10u32)
        );
        let c = cfg.click();
        assert_eq!(
            (
                c.master_width,
                c.master_height,
                c.thumb_width,
                c.thumb_height
            ),
            (300, 220, 150, 40)
        );
        assert_eq!((c.captcha_count, c.verify_count), (6, 3));
        assert!(c.display_shadow);
        assert_eq!(c.shadow_color, "#000000");
        assert_eq!((c.shadow_offset_x, c.shadow_offset_y), (2, 2));
        assert_eq!(c.chars, "这的是随了机文我你他字在有不么中");
        assert_eq!(c.language, "zh");
        let r = RotateConfig::default(); // 旋转驱动不读该配置,字段惰性
        assert_eq!(
            (
                r.master_width,
                r.master_height,
                r.thumb_width,
                r.thumb_height
            ),
            (300, 300, 150, 150)
        );
    }

    // ---------- 滑块 ----------

    #[test]
    fn slide_shape_and_tolerance() {
        let cap = Captcha::with_config(Config::with_driver(DriverKind::Slide));
        let (id, b64, answer) = cap.generate().unwrap();
        // ID 形如 "{x}_{y}",坐标落在采样域内
        let (x, y) = id.split_once('_').unwrap();
        let (x, y): (i32, i32) = (x.parse().unwrap(), y.parse().unwrap());
        assert!((85..=240).contains(&x));
        assert!((5..=155).contains(&y));
        assert_eq!(answer, x.to_string());
        // JSON 结构与字段
        let data: SlideCaptchaData = serde_json::from_str(&b64).unwrap();
        assert_eq!(data.id, id);
        assert_eq!(data.x_position, x);
        assert!(data.master_image.starts_with("data:image/jpeg;base64,"));
        assert!(data.tile_image.starts_with("data:image/png;base64,"));
        assert_eq!(decode_img(&data.master_image).dimensions(), (300, 220));
        assert_eq!(decode_img(&data.tile_image).dimensions(), (60, 60));
        // 容差:|Δ| ≤ 5 通过、> 5 拒绝
        assert!(cap.verify_keep(&id, &(x + 3).to_string()).unwrap());
        assert!(cap.verify_keep(&id, &(x - 5).to_string()).unwrap());
        assert!(!cap.verify_keep(&id, &(x + 6).to_string()).unwrap());
        // 非数字输入拒绝
        assert!(!cap.verify_keep(&id, "abc").unwrap());
        assert!(!cap.verify_keep(&id, "").unwrap());
        assert!(cap.exists(&id).unwrap()); // verify_keep 未删除
        assert!(cap.verify(&id, &answer).unwrap()); // 精确匹配,一次性
        assert!(!cap.exists(&id).unwrap());
    }

    // ---------- 点选 ----------

    #[test]
    fn click_shape_and_tolerance() {
        let cap = Captcha::with_config(Config::with_driver(DriverKind::Click));
        let (id, b64, answer) = cap.generate().unwrap();
        assert!(id.starts_with("click_"));
        // JSON 结构:dots 元数据与期望答案同源
        let data: ClickCaptchaData = serde_json::from_str(&b64).unwrap();
        assert_eq!(data.id, id);
        assert_eq!(data.dots.len(), 3);
        for d in data.dots.values() {
            assert!(d.char.is_empty()); // 输出恒空
        }
        let exp: Vec<ExpectedClickDot> = serde_json::from_str(&answer).unwrap();
        assert_eq!(exp.len(), 3);
        let mut from_dots: Vec<(i32, i32, i32, i32, i32)> = data
            .dots
            .values()
            .map(|d| (d.x, d.y, d.width, d.height, d.angle))
            .collect();
        from_dots.sort_unstable();
        let mut from_expected: Vec<(i32, i32, i32, i32, i32)> = exp
            .iter()
            .map(|e| (e.x, e.y, e.width, e.height, e.angle))
            .collect();
        from_expected.sort_unstable();
        assert_eq!(from_dots, from_expected);
        for e in &exp {
            assert_eq!(e.shape, "");
            assert_eq!(e.text.chars().count(), 1);
            assert!((10..=260).contains(&e.x)); // 列分布 + 截断
            assert!(e.y >= 10);
            assert!(e.angle >= 20 && (e.angle <= 60 || (290..=330).contains(&e.angle)));
            assert!(e.width > 0 && e.height > 0);
        }
        // 图片
        assert!(data.master_image.starts_with("data:image/jpeg;base64,"));
        assert!(data.thumb_image.starts_with("data:image/png;base64,"));
        assert_eq!(decode_img(&data.master_image).dimensions(), (300, 220));
        assert_eq!(decode_img(&data.thumb_image).dimensions(), (150, 40));
        // 容差:逐点 ±10
        let mk = |dx: f64, dy: f64, n: usize| -> String {
            let pts: Vec<UserClickDot> = exp
                .iter()
                .take(n)
                .map(|e| UserClickDot {
                    x: f64::from(e.x) + dx,
                    y: f64::from(e.y) + dy,
                })
                .collect();
            serde_json::to_string(&pts).unwrap()
        };
        assert!(cap.verify_keep(&id, &mk(0.0, 0.0, 3)).unwrap()); // 精确
        assert!(cap.verify_keep(&id, &mk(10.0, 10.0, 3)).unwrap()); // 恰好 ±10
        assert!(!cap.verify_keep(&id, &mk(11.0, 0.0, 3)).unwrap()); // X 超 ±10
        assert!(!cap.verify_keep(&id, &mk(0.0, 11.0, 3)).unwrap()); // Y 超 ±10
        assert!(!cap.verify_keep(&id, &mk(0.0, 0.0, 2)).unwrap()); // 数量不符
        assert!(!cap.verify_keep(&id, "[]").unwrap());
        assert!(!cap.verify_keep(&id, "garbage").unwrap());
        assert!(cap.exists(&id).unwrap());
        assert!(cap.verify(&id, &mk(0.0, 0.0, 3)).unwrap());
        assert!(!cap.exists(&id).unwrap());
    }

    // ---------- 旋转 ----------

    #[test]
    fn rotate_shape_and_tolerance() {
        let cap = Captcha::with_config(Config::with_driver(DriverKind::Rotate));
        let (id, b64, answer) = cap.generate().unwrap();
        assert!(id.starts_with("rotate_"));
        let data: RotateCaptchaData = serde_json::from_str(&b64).unwrap();
        assert_eq!(data.id, id);
        assert!((30..=330).contains(&data.angle)); // 默认采样域 [30,330]
        assert_eq!(answer, data.angle.to_string());
        assert!(data.master_image.starts_with("data:image/png;base64,"));
        assert!(data.thumb_image.starts_with("data:image/png;base64,"));
        assert_eq!(decode_img(&data.master_image).dimensions(), (220, 220));
        let (tw, th) = decode_img(&data.thumb_image).dimensions();
        assert_eq!(tw, th);
        assert!(matches!(tw, 140 | 150 | 160 | 170)); // 默认边长集合
        let angle = data.angle;
        // 容差 ±5(线性侧)
        assert!(cap.verify_keep(&id, &angle.to_string()).unwrap());
        assert!(cap.verify_keep(&id, &(angle + 5).to_string()).unwrap());
        assert!(cap.verify_keep(&id, &(angle - 5).to_string()).unwrap());
        assert!(!cap.verify_keep(&id, &(angle + 6).to_string()).unwrap());
        assert!(!cap.verify_keep(&id, &(angle - 6).to_string()).unwrap());
        // 环形侧:差 200 折为 160,仍 > 5 拒绝
        assert!(!cap
            .verify_keep(&id, &((angle + 200) % 360).to_string())
            .unwrap());
        assert!(!cap.verify_keep(&id, "abc").unwrap());
        assert!(cap.verify(&id, &answer).unwrap()); // 一次性
        assert!(!cap.exists(&id).unwrap());
    }

    // ---------- 输入解析与字体资产 ----------

    /// 前导十进制整数解析:前导空白、符号、最长数字前缀、溢出失败。
    #[test]
    fn int_prefix_semantics() {
        assert_eq!(parse_int_prefix("12"), Some(12));
        assert_eq!(parse_int_prefix("12abc"), Some(12));
        assert_eq!(parse_int_prefix("  12"), Some(12));
        assert_eq!(parse_int_prefix("-5"), Some(-5));
        assert_eq!(parse_int_prefix("+7"), Some(7));
        assert_eq!(parse_int_prefix("abc"), None);
        assert_eq!(parse_int_prefix(""), None);
        assert_eq!(parse_int_prefix("-"), None);
        assert_eq!(parse_int_prefix("99999999999"), None);
    }

    /// 字体资产:ASCII + CJK 子集完整、表外码点缺位、
    /// 数字位图仅二值且非空。
    #[test]
    fn font_tables_sane() {
        let t = font_table();
        assert!(t.contains_key(&u32::from('A')));
        assert!(t.contains_key(&0x4E00));
        assert!(!t.contains_key(&0x2605)); // ★ 不在子集
        assert_eq!(t.len(), 21087); // 95 ASCII + 20992 CJK
        for digit in DIGIT_FONT {
            assert!(digit.iter().all(|&b| b <= 1));
            assert!(digit.contains(&1));
        }
    }

    // Redis 存储:设置 REDIS_TEST_URL 环境变量后启用
    #[cfg(feature = "captcha-redis")]
    #[test]
    fn redis_store_live() {
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
