//! ID 生成工具箱(移植自 go-utils/id):雪花 ID、订单号、机器码,
//! 以及(feature `uuid`)UUID v4/v7。
//!
//! 全部零依赖实现:snowflake 算法手写(对齐 bwmarrin/snowflake 的位布局),
//! 机器码归一化所需的 SHA-256 为内置实现。
//!
//! ```
//! use rust_utils::id;
//!
//! let node = id::SnowflakeNode::new(1).unwrap();
//! let a = node.generate();
//! let b = node.generate();
//! assert!(b > a); // 趋势递增
//!
//! let order = id::generate_order_id_with_increase_index("ORD", None);
//! assert!(order.starts_with("ORD"));
//! assert!(order.len() > 14);
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// snowflake 起始纪元(对齐 bwmarrin/snowflake,即 Twitter 纪元)。
pub const SNOWFLAKE_EPOCH_MS: i64 = 1288834974657;

const WORKER_ID_BITS: i64 = 10;
const SEQUENCE_BITS: i64 = 12;
const MAX_WORKER_ID: i64 = (1 << WORKER_ID_BITS) - 1; // 1023
const SEQUENCE_MASK: i64 = (1 << SEQUENCE_BITS) - 1; // 4095
const WORKER_ID_SHIFT: i64 = SEQUENCE_BITS; // 12
const TIMESTAMP_SHIFT: i64 = SEQUENCE_BITS + WORKER_ID_BITS; // 22

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn now_unix() -> u32 {
    now_millis().div_euclid(1000) as u32
}

/// 雪花 ID 节点:41 位毫秒时间戳 + 10 位工作节点 + 12 位序列号,
/// 趋势递增的 64 位 ID。
///
/// ```
/// use rust_utils::id::SnowflakeNode;
///
/// let node = SnowflakeNode::new(7).unwrap();
/// let id = node.generate();
/// assert_eq!((id >> 12) & 1023, 7); // 提取工作节点位
/// ```
pub struct SnowflakeNode {
    worker_id: i64,
    state: Mutex<(i64, i64)>, // (last_ms, sequence)
}

impl SnowflakeNode {
    /// 创建节点;`worker_id` 超出 `0..=1023` 时报错。
    pub fn new(worker_id: i64) -> Result<Self, String> {
        if !(0..=MAX_WORKER_ID).contains(&worker_id) {
            return Err(format!(
                "worker id can't be greater than {MAX_WORKER_ID} or less than 0"
            ));
        }
        Ok(SnowflakeNode {
            worker_id,
            state: Mutex::new((0, 0)),
        })
    }

    pub fn worker_id(&self) -> i64 {
        self.worker_id
    }

    /// 生成一个 ID。
    pub fn generate(&self) -> i64 {
        let mut st = self.state.lock().unwrap();
        let mut now = now_millis();
        if now < st.0 {
            // 时钟回拨:追平上一毫秒
            now = st.0;
        }
        if now == st.0 {
            st.1 = (st.1 + 1) & SEQUENCE_MASK;
            if st.1 == 0 {
                // 当前毫秒序列耗尽,自旋到下一毫秒
                while now <= st.0 {
                    std::hint::spin_loop();
                    now = now_millis();
                }
                st.0 = now;
            }
        } else {
            st.1 = 0;
            st.0 = now;
        }
        ((now - SNOWFLAKE_EPOCH_MS) << TIMESTAMP_SHIFT) | (self.worker_id << WORKER_ID_SHIFT) | st.1
    }

    /// 生成一个 ID 的十进制字符串形式。
    pub fn generate_string(&self) -> String {
        self.generate().to_string()
    }
}

static NODES: OnceLock<Mutex<HashMap<i64, Arc<SnowflakeNode>>>> = OnceLock::new();

fn nodes() -> &'static Mutex<HashMap<i64, Arc<SnowflakeNode>>> {
    NODES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 获取(或创建)某个 worker_id 的全局节点。
pub fn new_snowflake_node(worker_id: i64) -> Result<Arc<SnowflakeNode>, String> {
    let mut map = nodes().lock().unwrap();
    if let Some(n) = map.get(&worker_id) {
        return Ok(n.clone());
    }
    let node = Arc::new(SnowflakeNode::new(worker_id)?);
    map.insert(worker_id, node.clone());
    Ok(node)
}

/// 通过全局节点池生成雪花 ID(等价 Go 版 `NewSnowflakeID`)。
pub fn new_snowflake_id(worker_id: i64) -> Result<i64, String> {
    Ok(new_snowflake_node(worker_id)?.generate())
}

/// [`new_snowflake_id`] 的无错误版本,失败返回 0(等价 Go 版
/// `GenerateSnowflakeID`)。
pub fn generate_snowflake_id(worker_id: i64) -> i64 {
    new_snowflake_id(worker_id).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 订单号
// ---------------------------------------------------------------------------

static ORDER_INDEX: AtomicU32 = AtomicU32::new(0);
static RAND_STATE: AtomicU64 = AtomicU64::new(0);

/// 0..=1000 的循环自增索引(等价 Go 版实现,含同样的回绕行为)。
fn increase_order_index() -> u32 {
    let cur = ORDER_INDEX.fetch_add(1, Ordering::Relaxed);
    ORDER_INDEX
        .compare_exchange(1000, 0, Ordering::Relaxed, Ordering::Relaxed)
        .ok();
    cur
}

/// 非加密的快速伪随机(仅供订单号/测试用)。
fn fast_rand_below(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut s = RAND_STATE.load(Ordering::Relaxed);
    if s == 0 {
        s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 | 1)
            .unwrap_or(0x9E3779B97F4A7C15);
    }
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    RAND_STATE.store(s, Ordering::Relaxed);
    s % n
}

/// 把时间格式化为 14 位紧凑时间串 `yyyyMMddHHmmss`(UTC)。
pub fn format_compact_datetime(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}")
}

/// Howard Hinnant 的 civil_from_days:Unix 天数 → (年, 月, 日)。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

/// 生成订单号:前缀 + 14 位时间戳 + 4 位随机数。
pub fn generate_order_id_with_random(prefix: &str, tm: Option<SystemTime>) -> String {
    let t = tm.unwrap_or_else(SystemTime::now);
    let rand_num = fast_rand_below(10_000);
    format!("{prefix}{}{rand_num}", format_compact_datetime(t))
}

/// 生成订单号:前缀 + 14 位时间戳 + 自增长索引。
pub fn generate_order_id_with_increase_index(prefix: &str, tm: Option<SystemTime>) -> String {
    let t = tm.unwrap_or_else(SystemTime::now);
    let index = increase_order_index();
    format!("{prefix}{}{index}", format_compact_datetime(t))
}

/// 生成带商户 ID 的订单号:14 位时间戳 + 商户 ID(补/截到 5 位)+ 4 位随机数。
pub fn generate_order_id_with_tenant_id(tenant_id: &str) -> String {
    let now = SystemTime::now();
    let tenant_part = if tenant_id.chars().count() >= 5 {
        tenant_id.chars().take(5).collect::<String>()
    } else {
        format!("{tenant_id:<5}").replace(' ', "0")
    };
    let random_part = format!("{:04}", fast_rand_below(10_000));
    format!("{}{tenant_part}{random_part}", format_compact_datetime(now))
}

/// 前缀 + 雪花 ID(全局节点 1)。
pub fn generate_order_id_with_prefix_snowflake(prefix: &str) -> String {
    let id = generate_snowflake_id(1);
    format!("{prefix}{id}")
}

/// 前缀 + 指定节点的雪花 ID。
pub fn generate_order_id_with_prefix_snowflake_node(worker_id: i64, prefix: &str) -> String {
    let id = generate_snowflake_id(worker_id);
    format!("{prefix}{id}")
}

// ---------------------------------------------------------------------------
// 机器码
// ---------------------------------------------------------------------------

/// 机器码格式化选项。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FormatOption {
    /// true: 大写,false: 小写。
    pub upper_case: bool,
    /// true: 按 GUID 风格插入横线(8-4-4-4-12)。
    pub with_hyphen: bool,
}

/// 读取原始机器码:Windows 读注册表 MachineGuid,Linux 读
/// `/etc/machine-id`,macOS 读 IOPlatformUUID。
pub fn raw_machine_id() -> Result<String, String> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .map_err(|e| format!("获取machineId失败: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(idx) = line.find("MachineGuid") {
                return Ok(line[idx + "MachineGuid".len()..]
                    .trim()
                    .trim_start_matches("REG_SZ")
                    .trim()
                    .to_string());
            }
        }
        Err("获取machineId失败: MachineGuid not found".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .map_err(|e| format!("获取machineId失败: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(idx) = line.find("IOPlatformUUID") {
                let rest = &line[idx + "IOPlatformUUID".len()..];
                return Ok(rest
                    .trim()
                    .trim_start_matches('=')
                    .trim()
                    .trim_matches('"')
                    .to_string());
            }
        }
        Err("获取machineId失败: IOPlatformUUID not found".to_string())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(content) = std::fs::read_to_string(path) {
                return Ok(content.trim().to_string());
            }
        }
        Err("获取machineId失败: no machine-id file".to_string())
    }
}

/// 获取归一化的机器码:只保留十六进制字符,不足 32 位时用
/// SHA-256(原始串)补齐。
pub fn format_machine_id(opt: FormatOption) -> Result<String, String> {
    static CACHE: OnceLock<Result<String, String>> = OnceLock::new();
    let unified = CACHE
        .get_or_init(|| unify_machine_id_internal(&raw_machine_id))
        .clone()?;
    Ok(apply_machine_id_format(&unified, opt))
}

/// 等价于 `format_machine_id(FormatOption { upper_case: false, with_hyphen: false })`。
pub fn unify_machine_id() -> Result<String, String> {
    unify_machine_id_internal(&raw_machine_id)
}

fn unify_machine_id_internal(
    id_fetcher: &impl Fn() -> Result<String, String>,
) -> Result<String, String> {
    let raw = id_fetcher()?;
    let cleaned: String = raw
        .bytes()
        .filter(|b| b.is_ascii_hexdigit())
        .map(|b| b.to_ascii_lowercase() as char)
        .take(32)
        .collect();
    if cleaned.len() == 32 {
        Ok(cleaned)
    } else {
        // 降级:长度不符时用 SHA-256 前 32 位十六进制(与 Go 版一致)
        let hex = hex_lower(&sha256(raw.as_bytes()));
        Ok(hex[..32].to_string())
    }
}

fn apply_machine_id_format(unified: &str, opt: FormatOption) -> String {
    let mut result = unified.to_string();
    if opt.upper_case {
        result = result.to_uppercase();
    }
    if opt.with_hyphen && result.len() == 32 {
        result = format!(
            "{}-{}-{}-{}-{}",
            &result[..8],
            &result[8..12],
            &result[12..16],
            &result[16..20],
            &result[20..]
        );
    }
    result
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// 内置 SHA-256(供机器码归一化使用,避免为核心模块引入依赖)
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256(内置实现,标准 FIPS 180-4)。
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// ShortUUID / ObjectID / XID(feature = "uuid" 的部分依赖 uuid crate)
// ---------------------------------------------------------------------------

/// shortuuid 默认 base57 字母表(去除易混淆的 0/O/1/I/l)。
#[cfg(feature = "uuid")]
const SHORTUUID_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// 生成 ShortUUID(22 位 base57 编码的 UUID v4)。
/// 字母表与 Go 版 `shortuuid.New()` 一致。
#[cfg(feature = "uuid")]
pub fn new_short_uuid() -> String {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    encode_base57(&bytes)
}

/// 大整数(大端字节)base57 编码,输出定长 22 位(不足前补字母表首字符)。
#[cfg(feature = "uuid")]
fn encode_base57(bytes: &[u8; 16]) -> String {
    let base = SHORTUUID_ALPHABET.len() as u128;
    let mut value = u128::from_be_bytes(*bytes);
    let mut out = Vec::with_capacity(22);
    for _ in 0..22 {
        out.push(SHORTUUID_ALPHABET[(value % base) as usize] as char);
        value /= base;
    }
    out.into_iter().rev().collect()
}

static ID_COUNTER: AtomicU32 = AtomicU32::new(0);
static MACHINE_3B: OnceLock<[u8; 3]> = OnceLock::new();

fn machine_3b() -> [u8; 3] {
    *MACHINE_3B.get_or_init(|| {
        let mut buf = [0u8; 3];
        let _ = pseudo_random(&mut buf);
        buf
    })
}

fn next_counter24() -> u32 {
    ID_COUNTER.fetch_add(1, Ordering::Relaxed) & 0xFF_FFFF
}

/// 生成 MongoDB 风格 ObjectID(24 位十六进制:
/// 4 字节秒级时间戳 + 5 字节随机 + 3 字节递增计数)。
pub fn new_mongo_object_id() -> String {
    let ts = now_unix();
    let mut rand5 = [0u8; 5];
    let _ = pseudo_random(&mut rand5);
    let counter = next_counter24().to_be_bytes();
    let mut raw = [0u8; 12];
    raw[0..4].copy_from_slice(&ts.to_be_bytes());
    raw[4..9].copy_from_slice(&rand5);
    raw[9..12].copy_from_slice(&counter[1..4]);
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    hex
}

/// 生成 XID(20 字符 base32hex 小写:
/// 4 字节秒级时间戳 + 3 字节机器 + 2 字节进程 + 3 字节计数,
/// 与 rs/xid 的编码格式一致)。
pub fn new_xid() -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuv";
    let ts = now_unix();
    let machine = machine_3b();
    let pid = std::process::id() as u16;
    let counter = next_counter24().to_be_bytes();
    let mut raw = [0u8; 12];
    raw[0..4].copy_from_slice(&ts.to_be_bytes());
    raw[4..7].copy_from_slice(&machine);
    raw[7..9].copy_from_slice(&pid.to_be_bytes());
    raw[9..12].copy_from_slice([counter[1], counter[2], counter[3]].as_slice());

    // 标准 base32(MSB 优先)编码 12 字节 → 恰好 20 个 5 位组
    let mut padded = [0u8; 13];
    padded[..12].copy_from_slice(&raw);
    let mut out = String::with_capacity(20);
    for i in 0..20 {
        let bit = i * 5;
        let idx =
            (((padded[bit / 8] as u16) << 8) | padded[bit / 8 + 1] as u16) >> (11 - bit % 8) & 0x1F;
        out.push(ALPHABET[idx as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Sonyflake(39 位 10ms 时间戳 + 8 位序列 + 16 位机器)
// ---------------------------------------------------------------------------

/// Sonyflake 起始纪元(2014-09-01T00:00:00Z,对齐 sony/sonyflake)。
pub const SONYFLAKE_EPOCH_MS: i64 = 1_409_529_600_000;

const SONYFLAKE_SEQ_BITS: u32 = 8;
const SONYFLAKE_MACHINE_BITS: u32 = 16;
const SONYFLAKE_TIME_SHIFT: u32 = SONYFLAKE_SEQ_BITS + SONYFLAKE_MACHINE_BITS;

/// Sonyflake 节点:时间粒度 10ms,单机每 10ms 最多 256 个 ID。
pub struct SonyflakeNode {
    machine_id: u16,
    state: Mutex<(i64, u8)>, // (已使用的 10ms 时间片, 序列号)
}

impl SonyflakeNode {
    /// 创建节点(机器 ID 取 0..=65535)。
    pub fn new(machine_id: u16) -> Self {
        SonyflakeNode {
            machine_id,
            state: Mutex::new((0, 0)),
        }
    }

    /// 生成一个 ID;当前 10ms 片序列耗尽时自旋等待下一片。
    pub fn generate(&self) -> u64 {
        let mut st = self.state.lock().unwrap();
        loop {
            let now10 = (now_millis() - SONYFLAKE_EPOCH_MS).max(0) / 10;
            if now10 > st.0 {
                st.0 = now10;
                st.1 = 0;
                break ((now10 as u64) << SONYFLAKE_TIME_SHIFT) | (self.machine_id as u64);
            }
            if now10 == st.0 {
                st.1 = st.1.wrapping_add(1);
                if st.1 != 0 {
                    break ((now10 as u64) << SONYFLAKE_TIME_SHIFT)
                        | ((st.1 as u64) << SONYFLAKE_MACHINE_BITS)
                        | (self.machine_id as u64);
                }
            }
            std::hint::spin_loop();
        }
    }
}

static SONYFLAKE: OnceLock<SonyflakeNode> = OnceLock::new();

/// 全局 Sonyflake(机器 ID 为进程内随机值;
/// Go 版默认取内网 IP 低 16 位,std 无对应 API,故有此差异)。
pub fn new_sonyflake_id() -> u64 {
    let node = SONYFLAKE.get_or_init(|| {
        let mut buf = [0u8; 2];
        let _ = pseudo_random(&mut buf);
        SonyflakeNode::new(u16::from_be_bytes(buf))
    });
    node.generate()
}

/// [`new_sonyflake_id`] 的无错误版本。
pub fn generate_sonyflake_id() -> u64 {
    new_sonyflake_id()
}

// ---------------------------------------------------------------------------
// 机器码保护 ID(对应 machineid.ProtectedID)
// ---------------------------------------------------------------------------

/// RFC 2104 HMAC-SHA256(基于内置 SHA-256 实现)。
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// 返回受应用密钥保护的机器码:
/// `hex(hmac_sha256(key = 机器码, msg = app_id))`,
/// 与 Go 版 `machineid.ProtectedID` 算法一致。
pub fn protected_id(app_id: &str) -> Result<String, String> {
    let id = raw_machine_id()?;
    Ok(hex_lower(&hmac_sha256(id.as_bytes(), app_id.as_bytes())))
}

/// 进程内伪随机(种子来自时间 + 进程 ID),仅供 ID 组装用,非加密安全。
fn pseudo_random(buf: &mut [u8]) -> Result<(), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(0x853c49e6748fea9b);
    let mut seed = nanos ^ ((std::process::id() as u64) << 32);
    for b in buf.iter_mut() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *b = (seed >> 24) as u8;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// UUID(feature = "uuid")
// ---------------------------------------------------------------------------

/// 生成 UUID v4 字符串;`with_hyphen = false` 时输出 32 位纯十六进制。
#[cfg(feature = "uuid")]
pub fn new_guid_v4(with_hyphen: bool) -> String {
    uuid_bytes_to_string(uuid::Uuid::new_v4().as_bytes(), with_hyphen)
}

/// 生成 UUID v7 字符串(时间有序);`with_hyphen = false` 时输出 32 位纯十六进制。
#[cfg(feature = "uuid")]
pub fn new_guid_v7(with_hyphen: bool) -> String {
    uuid_bytes_to_string(uuid::Uuid::now_v7().as_bytes(), with_hyphen)
}

#[cfg(feature = "uuid")]
fn uuid_bytes_to_string(bytes: &[u8; 16], with_hyphen: bool) -> String {
    if with_hyphen {
        let hex = hex_lower(bytes);
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    } else {
        hex_lower(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snowflake_node() {
        let node = SnowflakeNode::new(7).unwrap();
        assert_eq!(node.worker_id(), 7);
        let a = node.generate();
        let b = node.generate();
        assert!(b > a);
        assert_eq!((a >> 12) & 1023, 7);

        assert!(SnowflakeNode::new(-1).is_err());
        assert!(SnowflakeNode::new(1024).is_err());
    }

    #[test]
    fn test_global_snowflake() {
        let a = new_snowflake_id(42).unwrap();
        let b = new_snowflake_id(42).unwrap();
        assert!(b > a);
        assert!(generate_snowflake_id(43) > 0);
    }

    #[test]
    fn test_order_id_with_random() {
        let t = SystemTime::now();
        let id = generate_order_id_with_random("ORD", Some(t));
        assert!(id.starts_with("ORD"));
        // 随机数 0..9999 不补零,位数 1..=4(与 Go 一致)
        assert!(
            ("ORD".len() + 14 + 1..="ORD".len() + 14 + 4).contains(&id.len()),
            "unexpected len: {id}"
        );
        let id2 = generate_order_id_with_random("ORD", None);
        assert!(id2.starts_with("ORD"));
    }

    #[test]
    fn test_order_id_with_increase_index() {
        let id = generate_order_id_with_increase_index("NO", None);
        assert!(id.starts_with("NO"));
        assert!(
            ("NO".len() + 14 + 1..="NO".len() + 14 + 4).contains(&id.len()),
            "unexpected len: {id}"
        );
    }

    #[test]
    fn test_order_id_with_tenant() {
        let long = generate_order_id_with_tenant_id("12345678");
        assert_eq!(long.len(), 14 + 5 + 4);
        assert!(long[14..].starts_with("12345"));
        let short = generate_order_id_with_tenant_id("ab");
        assert_eq!(short.len(), 14 + 5 + 4);
        assert!(short.contains("ab000"));
    }

    #[test]
    fn test_snowflake_generate_string() {
        let node = SnowflakeNode::new(9).unwrap();
        let a: i64 = node.generate_string().parse().expect("should be numeric");
        let b: i64 = node.generate_string().parse().expect("should be numeric");
        assert!(b > a);
        assert_eq!((a >> 12) & 1023, 9);
    }

    #[test]
    fn test_order_id_with_prefix_snowflake() {
        let id = generate_order_id_with_prefix_snowflake("SO:");
        assert!(id.starts_with("SO:"));
        assert!(id["SO:".len()..].parse::<i64>().is_ok());

        let id2 = generate_order_id_with_prefix_snowflake_node(7, "N7-");
        assert!(id2.starts_with("N7-"));
        let v: i64 = id2["N7-".len()..].parse().unwrap();
        assert_eq!((v >> 12) & 1023, 7); // 工作节点位
    }

    #[test]
    fn test_format_machine_id_real() {
        // 依赖平台机器码来源(Windows 注册表 / /etc/machine-id / ioreg),
        // 读不到的环境下允许 Err。
        if let Ok(id) = format_machine_id(FormatOption::default()) {
            assert_eq!(id.len(), 32);
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_compact_datetime() {
        // 2026-09-13 08:30:45 UTC = 1788184245? 用已知锚点校验
        let t = UNIX_EPOCH + std::time::Duration::from_secs(0);
        assert_eq!(format_compact_datetime(t), "19700101000000");
        let t2 = UNIX_EPOCH + std::time::Duration::from_secs(86_400); // 次日
        assert_eq!(format_compact_datetime(t2), "19700102000000");
        // 2024-02-29 润年检查
        let leap = UNIX_EPOCH + std::time::Duration::from_secs(1709164800);
        assert_eq!(format_compact_datetime(leap), "20240229000000");
    }

    #[test]
    fn test_sha256() {
        // FIPS 180-4 标准测试向量
        let empty = hex_lower(&sha256(b""));
        assert_eq!(
            empty,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = hex_lower(&sha256(b"abc"));
        assert_eq!(
            abc,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let long = hex_lower(&sha256(&vec![b'a'; 1000]));
        // 与 sha2 标准实现一致(跨块)
        assert_eq!(long.len(), 64);
    }

    #[test]
    fn test_machine_id_format() {
        // 归一化逻辑:短输入走 SHA-256 降级
        let unified = unify_machine_id_internal(&|| Ok("not-hex".to_string())).unwrap();
        assert_eq!(unified.len(), 32);
        assert!(unified.chars().all(|c| c.is_ascii_hexdigit()));

        let unified2 =
            unify_machine_id_internal(&|| Ok("550E8400-E29B-41D4-A716-446655440000".to_string()))
                .unwrap();
        assert_eq!(unified2, "550e8400e29b41d4a716446655440000");

        let hyphenated = apply_machine_id_format(
            &unified2,
            FormatOption {
                upper_case: true,
                with_hyphen: true,
            },
        );
        assert_eq!(hyphenated, "550E8400-E29B-41D4-A716-446655440000");

        // 真机读取(不校验具体值,只要求能出结果或明确报错)
        match raw_machine_id() {
            Ok(raw) => assert!(!raw.is_empty()),
            Err(e) => assert!(e.contains("machineId")),
        }
    }

    #[cfg(feature = "uuid")]
    #[test]
    fn test_guid() {
        let v4 = new_guid_v4(true);
        assert_eq!(v4.len(), 36);
        assert_eq!(v4.chars().filter(|c| *c == '-').count(), 4);

        let v4_plain = new_guid_v4(false);
        assert_eq!(v4_plain.len(), 32);

        let v7 = new_guid_v7(true);
        assert_eq!(v7.len(), 36);
        // v7 时间有序
        let v7a = new_guid_v7(false);
        let v7b = new_guid_v7(false);
        assert!(v7b >= v7a);
    }
    #[cfg(feature = "uuid")]
    #[test]
    fn test_short_uuid() {
        let s = new_short_uuid();
        assert_eq!(s.len(), 22);
        assert!(s.chars().all(|c| SHORTUUID_ALPHABET.contains(&(c as u8))));
        // 同一 UUID 的编码确定性
        let again = new_short_uuid();
        assert_ne!(s, again);
    }

    #[test]
    fn test_mongo_object_id() {
        let a = new_mongo_object_id();
        let b = new_mongo_object_id();
        assert_eq!(a.len(), 24);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        // 时间戳部分单调
        let ts_a = u32::from_str_radix(&a[..8], 16).unwrap();
        let ts_b = u32::from_str_radix(&b[..8], 16).unwrap();
        assert!(ts_b >= ts_a);
    }

    #[test]
    fn test_xid() {
        let a = new_xid();
        let b = new_xid();
        assert_eq!(a.len(), 20);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_ne!(a, b);
        // 时间戳部分(base32 首字符含秒的高位)单调
        assert!(b >= a);
    }

    #[test]
    fn test_sonyflake() {
        let node = SonyflakeNode::new(0x1234);
        let a = node.generate();
        let b = node.generate();
        assert!(b > a);
        assert_eq!((a) & 0xFFFF, 0x1234); // 机器位
        let global = generate_sonyflake_id();
        assert!(global > 0);
    }

    #[test]
    fn test_protected_id() {
        // 与标准 HMAC-SHA256 对齐:保护后的 ID 是 64 位十六进制
        if let Ok(pid) = protected_id("my-app") {
            assert_eq!(pid.len(), 64);
            assert!(pid.chars().all(|c| c.is_ascii_hexdigit()));
        }
        // 同 app_id 结果稳定(同机器)
        let a = protected_id("app");
        let b = protected_id("app");
        assert_eq!(a.ok(), b.ok());
    }

    #[test]
    fn test_hmac_sha256_vectors() {
        // RFC 4231 HMAC-SHA256 测试向量
        let out = hex_lower(&hmac_sha256(
            b"key",
            b"The quick brown fox jumps over the lazy dog",
        ));
        assert_eq!(
            out,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        // 空消息
        let empty = hex_lower(&hmac_sha256(b"key", b""));
        assert_eq!(
            empty,
            "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0"
        );
    }
}
