//! SFS2X 二进制协议编解码(移植自 Go `tx7do/go-utils/sfs2x`)——
//! SmartFoxServer 2X 兼容服务的对象序列化与消息帧封装。
//!
//! 线格式:
//!
//! ```text
//! frame = [header 1B][len][payload]
//!   header: bit5 (0x20) = zlib 压缩载荷(阈值可配,官方客户端缺省 1024),
//!           bit3 (0x08) = 长度为 uint32,否则 uint16
//! object = [0x12][u16 count][entries...]
//!   entry = [u16 keyLen][key utf8][1B type][value]
//! 嵌套 SFS_OBJECT / SFS_ARRAY 值不带独立 marker——类型字节即 marker
//! (解码器回退一字节)
//! ```
//!
//! 类型码:
//!
//! ```text
//! NULL=0 BOOL=1 BYTE=2 SHORT=3 INT=4 LONG=5 FLOAT=6 DOUBLE=7 UTF_STRING=8
//! BOOL_ARRAY=9 BYTE_ARRAY=10 SHORT_ARRAY=11 INT_ARRAY=12 LONG_ARRAY=13
//! FLOAT_ARRAY=14 DOUBLE_ARRAY=15 UTF_STRING_ARRAY=16 SFS_ARRAY=17 SFS_OBJECT=18
//! TEXT=20(32 位长度字符串;CLASS=19 需要对端注册表,未实现,解码侧经
//! [`as_class`] 识别官方 $C/$F 约定)
//! ```
//!
//! 范围说明:[`encode_frame`] 恒发短(uint16)长度形态、不带可选变换;
//! [`encode_frame_with_options`] 追加 zlib 压缩(0x20,阈值可配)与
//! AES-128-CBC 加密(0x40,随机 IV + PKCS#7,16 字节 key),顺序为先压后
//! 加密。官方固定 key+IV 模式(`FrameOptions::encryption_iv`)载荷只有密文;
//! 自描述模式(`encryption_iv = None`)把随机 IV 前缀进载荷。解码侧
//! [`decode_frame`] 透明解压;加密帧需 [`decode_frame_with_options`] 给钥匙。
//! 载荷超 65535 字节自动切 BIG_SIZE(0x08,uint32)长度形态,与官方客户端
//! 一致。CLASS(19)与 BLUEBOX(HTTP 隧道)传输未实现。
//!
//! 与 Go 版的差异(适配 Rust):
//!
//! 1. Go 的 `interface{}` 值模型改为 [`Value`] 枚举——类型码由变体承载,
//!    `Put(key, typ, val)` 简化为 [`Object::put`](`put(key, Value::Int(7))`),
//!    取值 getter 返回 `Option<&T>` 而非断言 panic;
//! 2. `Encode` 缺省排序键(确定性),`EncodeOrdered` 保持插入序——两语义由
//!    [`Object::encode`]/[`Object::encode_ordered`] 显式区分,同 Go;
//! 3. 解压炸弹防护与 Go 同款:解压输出上限 64 MiB,超出即报错;
//! 4. `math/rand` 种子属性测试改用固定种子 LCG(零依赖)。
//!
//! 黄金向量:与 ZewSFS Python 参考实现的互操作样本在 `assets/sfs2x/`
//! (不进发布包,缺失时用例自动跳过),断言逐类型码值一致 + 重编码字节级
//! 一致。
//!
//! ```no_run
//! use rust_utils::sfs2x::{Object, Value, encode_frame, decode_frame};
//!
//! // 构造信封形状的对象并帧封装
//! let mut inner = Object::new();
//! inner.put("resourceId", Value::utf_string("22048"));
//! let mut outer = Object::new();
//! outer.put("c", Value::Byte(0));
//! outer.put("a", Value::Short(0));
//! outer.put("p", Value::SfsObject(inner));
//!
//! let frame = encode_frame(&outer);
//! let decoded = decode_frame(&frame).unwrap();
//! let p = decoded.get_object("p").unwrap();
//! assert_eq!(p.get_string("resourceId"), Some("22048"));
//!
//! // 确定性:同内容不同插入序 → 逐字节相同编码
//! let mut a = Object::new();
//! a.put("zz", Value::utf_string("1"));
//! a.put("aa", Value::utf_string("2"));
//! let mut b = Object::new();
//! b.put("aa", Value::utf_string("2"));
//! b.put("zz", Value::utf_string("1"));
//! assert_eq!(a.encode(), b.encode());
//! ```

use std::collections::HashMap;

// ===== 类型码与帧头标志 =====

/// SFS 数据类型码(线上的 1 字节)。
pub mod t {
    /// NULL。
    pub const NULL: u8 = 0;
    /// BOOL。
    pub const BOOL: u8 = 1;
    /// BYTE。
    pub const BYTE: u8 = 2;
    /// SHORT。
    pub const SHORT: u8 = 3;
    /// INT。
    pub const INT: u8 = 4;
    /// LONG。
    pub const LONG: u8 = 5;
    /// FLOAT。
    pub const FLOAT: u8 = 6;
    /// DOUBLE。
    pub const DOUBLE: u8 = 7;
    /// UTF_STRING。
    pub const UTF_STRING: u8 = 8;
    /// BOOL_ARRAY。
    pub const BOOL_ARRAY: u8 = 9;
    /// BYTE_ARRAY。
    pub const BYTE_ARRAY: u8 = 10;
    /// SHORT_ARRAY。
    pub const SHORT_ARRAY: u8 = 11;
    /// INT_ARRAY。
    pub const INT_ARRAY: u8 = 12;
    /// LONG_ARRAY。
    pub const LONG_ARRAY: u8 = 13;
    /// FLOAT_ARRAY。
    pub const FLOAT_ARRAY: u8 = 14;
    /// DOUBLE_ARRAY。
    pub const DOUBLE_ARRAY: u8 = 15;
    /// UTF_STRING_ARRAY。
    pub const UTF_STRING_ARRAY: u8 = 16;
    /// SFS_ARRAY。
    pub const SFS_ARRAY: u8 = 17;
    /// SFS_OBJECT。
    pub const SFS_OBJECT: u8 = 18;
    /// TEXT(32 位长度字符串)。
    pub const TEXT: u8 = 20;
}

/// 帧头:载荷 zlib 压缩标志。
pub const COMPRESSION_MASK: u8 = 0x20;
/// 帧头:长度为 uint32(BIG_SIZE)标志。
pub const LONG_LEN_MASK: u8 = 0x08;
/// 帧头:二进制 SFS 帧签名位。
pub const SIGNATURE: u8 = 0x80;
/// 帧头:AES 加密标志(官方客户端约定)。
pub const ENCRYPTION_MASK: u8 = 0x40;

/// 压缩阈值缺省值(官方客户端口径):载荷超过该字节数时 zlib 压缩。
pub const DEFAULT_COMPRESS_THRESHOLD: usize = 1024;

/// 加密帧载荷的解压/明文上限:1024 字节的炸弹不得膨胀成数 GB 内存。
const MAX_DECOMPRESSED_SIZE: usize = 64 << 20; // 64 MiB

// ===== 值模型 =====

/// SFS 类型化值。变体即类型码(见模块文档的类型码表)。
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// NULL。
    Null,
    /// BOOL。
    Bool(bool),
    /// BYTE。
    Byte(u8),
    /// SHORT。
    Short(i16),
    /// INT。
    Int(i32),
    /// LONG。
    Long(i64),
    /// FLOAT。
    Float(f32),
    /// DOUBLE。
    Double(f64),
    /// UTF_STRING。
    UtfString(String),
    /// BOOL_ARRAY。
    BoolArray(Vec<bool>),
    /// BYTE_ARRAY。
    ByteArray(Vec<u8>),
    /// SHORT_ARRAY。
    ShortArray(Vec<i16>),
    /// INT_ARRAY。
    IntArray(Vec<i32>),
    /// LONG_ARRAY。
    LongArray(Vec<i64>),
    /// FLOAT_ARRAY。
    FloatArray(Vec<f32>),
    /// DOUBLE_ARRAY。
    DoubleArray(Vec<f64>),
    /// UTF_STRING_ARRAY。
    UtfStringArray(Vec<String>),
    /// SFS_ARRAY(元素各自携带完整类型)。
    SfsArray(Vec<Value>),
    /// SFS_OBJECT。
    SfsObject(Object),
    /// TEXT(32 位长度字符串)。
    Text(String),
}

impl Value {
    /// 该值对应的线上类型码。
    #[must_use]
    pub fn type_code(&self) -> u8 {
        match self {
            Value::Null => t::NULL,
            Value::Bool(_) => t::BOOL,
            Value::Byte(_) => t::BYTE,
            Value::Short(_) => t::SHORT,
            Value::Int(_) => t::INT,
            Value::Long(_) => t::LONG,
            Value::Float(_) => t::FLOAT,
            Value::Double(_) => t::DOUBLE,
            Value::UtfString(_) => t::UTF_STRING,
            Value::BoolArray(_) => t::BOOL_ARRAY,
            Value::ByteArray(_) => t::BYTE_ARRAY,
            Value::ShortArray(_) => t::SHORT_ARRAY,
            Value::IntArray(_) => t::INT_ARRAY,
            Value::LongArray(_) => t::LONG_ARRAY,
            Value::FloatArray(_) => t::FLOAT_ARRAY,
            Value::DoubleArray(_) => t::DOUBLE_ARRAY,
            Value::UtfStringArray(_) => t::UTF_STRING_ARRAY,
            Value::SfsArray(_) => t::SFS_ARRAY,
            Value::SfsObject(_) => t::SFS_OBJECT,
            Value::Text(_) => t::TEXT,
        }
    }

    /// `Value::UtfString` 的简写构造(`String`/`&str` 通吃)。
    pub fn utf_string(s: impl Into<String>) -> Value {
        Value::UtfString(s.into())
    }
}

/// 有序的 key → 类型化值映射。`put` 保持首插位置(同 key 覆盖不挪位),
/// [`Object::get_keys`] 返回插入序;[`Object::encode`] 缺省按 key 排序输出
/// (确定性),[`Object::encode_ordered`] 按插入序输出(官方客户端字节忠实)。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Object {
    entries: Vec<(String, Value)>,
    index: HashMap<String, usize>,
}

impl Object {
    /// 创建空 Object。
    #[must_use]
    pub fn new() -> Object {
        Object::default()
    }

    /// 写入类型化值;同 key 覆盖且保持原插入位置。
    pub fn put(&mut self, key: impl Into<String>, val: Value) {
        let key = key.into();
        match self.index.get(&key) {
            Some(&pos) => self.entries[pos].1 = val,
            None => {
                self.index.insert(key.clone(), self.entries.len());
                self.entries.push((key, val));
            }
        }
    }

    /// 读条目值的引用(key 不存在返回 `None`)。
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.index.get(key).map(|&pos| &self.entries[pos].1)
    }

    /// 读条目类型码(key 不存在返回 `None`)。
    #[must_use]
    pub fn get_type(&self, key: &str) -> Option<u8> {
        self.get(key).map(Value::type_code)
    }

    /// 按插入序返回全部 key。
    #[must_use]
    pub fn get_keys(&self) -> Vec<&str> {
        self.entries.iter().map(|(k, _)| k.as_str()).collect()
    }

    /// 读 BYTE 值(缺失或类型不符返回 `None`)。
    #[must_use]
    pub fn get_byte(&self, key: &str) -> Option<u8> {
        match self.get(key) {
            Some(Value::Byte(v)) => Some(*v),
            _ => None,
        }
    }

    /// 读 SHORT 值。
    #[must_use]
    pub fn get_short(&self, key: &str) -> Option<i16> {
        match self.get(key) {
            Some(Value::Short(v)) => Some(*v),
            _ => None,
        }
    }

    /// 读 INT 值。
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i32> {
        match self.get(key) {
            Some(Value::Int(v)) => Some(*v),
            _ => None,
        }
    }

    /// 读 LONG 值。
    #[must_use]
    pub fn get_long(&self, key: &str) -> Option<i64> {
        match self.get(key) {
            Some(Value::Long(v)) => Some(*v),
            _ => None,
        }
    }

    /// 读 UTF_STRING 值。
    #[must_use]
    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::UtfString(v)) => Some(v.as_str()),
            _ => None,
        }
    }

    /// 读 TEXT 值。
    #[must_use]
    pub fn get_text(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::Text(v)) => Some(v.as_str()),
            _ => None,
        }
    }

    /// 读嵌套 SFS_OBJECT 值。
    #[must_use]
    pub fn get_object(&self, key: &str) -> Option<&Object> {
        match self.get(key) {
            Some(Value::SfsObject(v)) => Some(v),
            _ => None,
        }
    }

    /// 读嵌套 SFS_ARRAY 值。
    #[must_use]
    pub fn get_array(&self, key: &str) -> Option<&[Value]> {
        match self.get(key) {
            Some(Value::SfsArray(v)) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// 读 BYTE_ARRAY 值。
    #[must_use]
    pub fn get_byte_array(&self, key: &str) -> Option<&[u8]> {
        match self.get(key) {
            Some(Value::ByteArray(v)) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// 序列化对象,含首部 0x12 marker(顶层/独立形态),key 排序(确定性)。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![t::SFS_OBJECT];
        self.entries_bin_sorted(&mut out);
        out
    }

    /// 序列化对象并保持 key 插入序——与官方客户端编码器字节级兼容
    /// (官方从不重排)。对端按字节比较或依赖 key 顺序时使用;
    /// [`Object::encode`] 保持确定性(排序)。
    #[must_use]
    pub fn encode_ordered(&self) -> Vec<u8> {
        let mut out = vec![t::SFS_OBJECT];
        self.entries_bin_in_insertion_order(&mut out);
        out
    }

    fn entries_bin_sorted(&self, out: &mut Vec<u8>) {
        let mut keys: Vec<&str> = self.get_keys();
        keys.sort_unstable();
        self.entries_bin_with(&keys, out);
    }

    fn entries_bin_in_insertion_order(&self, out: &mut Vec<u8>) {
        let keys: Vec<&str> = self.get_keys();
        self.entries_bin_with(&keys, out);
    }

    fn entries_bin_with(&self, keys: &[&str], out: &mut Vec<u8>) {
        write_u16(out, keys.len());
        for key in keys {
            let val = &self.entries[self.index[*key]].1;
            write_u16(out, key.len());
            out.extend_from_slice(key.as_bytes());
            out.push(val.type_code());
            encode_value(out, val);
        }
    }
}

// ===== 编码 =====

fn write_u16(out: &mut Vec<u8>, v: usize) {
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

fn write_u32(out: &mut Vec<u8>, v: usize) {
    out.push((v >> 24) as u8);
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

fn encode_value(out: &mut Vec<u8>, val: &Value) {
    match val {
        Value::Null => {}
        Value::Bool(b) => out.push(u8::from(*b)),
        Value::Byte(b) => out.push(*b),
        Value::Short(v) => out.extend_from_slice(&v.to_be_bytes()),
        Value::Int(v) => out.extend_from_slice(&v.to_be_bytes()),
        Value::Long(v) => out.extend_from_slice(&v.to_be_bytes()),
        Value::Float(v) => out.extend_from_slice(&v.to_bits().to_be_bytes()),
        Value::Double(v) => out.extend_from_slice(&v.to_bits().to_be_bytes()),
        Value::UtfString(s) => {
            write_u16(out, s.len());
            out.extend_from_slice(s.as_bytes());
        }
        Value::Text(s) => {
            write_u32(out, s.len());
            out.extend_from_slice(s.as_bytes());
        }
        Value::ByteArray(b) => {
            write_u32(out, b.len());
            out.extend_from_slice(b);
        }
        Value::BoolArray(a) => {
            write_u16(out, a.len());
            for x in a {
                out.push(u8::from(*x));
            }
        }
        Value::ShortArray(a) => {
            write_u16(out, a.len());
            for x in a {
                out.extend_from_slice(&x.to_be_bytes());
            }
        }
        Value::IntArray(a) => {
            write_u16(out, a.len());
            for x in a {
                out.extend_from_slice(&x.to_be_bytes());
            }
        }
        Value::LongArray(a) => {
            write_u16(out, a.len());
            for x in a {
                out.extend_from_slice(&x.to_be_bytes());
            }
        }
        Value::FloatArray(a) => {
            write_u16(out, a.len());
            for x in a {
                out.extend_from_slice(&x.to_bits().to_be_bytes());
            }
        }
        Value::DoubleArray(a) => {
            write_u16(out, a.len());
            for x in a {
                out.extend_from_slice(&x.to_bits().to_be_bytes());
            }
        }
        Value::UtfStringArray(a) => {
            write_u16(out, a.len());
            for s in a {
                write_u16(out, s.len());
                out.extend_from_slice(s.as_bytes());
            }
        }
        Value::SfsArray(a) => {
            write_u16(out, a.len());
            for item in a {
                out.push(item.type_code());
                encode_value(out, item);
            }
        }
        Value::SfsObject(sub) => sub.entries_bin_with_inner(out),
    }
}

impl Object {
    // 子对象形态:无首部 marker,直接 count+entries(调用方已写类型字节)。
    fn entries_bin_with_inner(&self, out: &mut Vec<u8>) {
        let mut keys: Vec<&str> = self.get_keys();
        keys.sort_unstable();
        self.entries_bin_with(&keys, out);
    }
}

// ===== 官方 CLASS 约定 =====

/// 官方客户端包裹 CLASS(19)值的 SFSObject 约定键:`$C`(全限定类名)。
pub const CLASS_MARKER_KEY: &str = "$C";
/// 官方 CLASS 约定键:`$F`(按注册表序的字段值 SFS_ARRAY)。
pub const CLASS_FIELDS_KEY: &str = "$F";

/// 识别解码对象上的官方 CLASS 约定。对端发来的 CLASS 值到达时是普通
/// SFS_OBJECT,携带 `$C`(类全名)与 `$F`(字段值数组);形状吻合时返回
/// `(类名, 字段值)`。
#[must_use]
pub fn as_class(o: Option<&Object>) -> Option<(&str, &[Value])> {
    let o = o?;
    let marker = o.get_string(CLASS_MARKER_KEY)?;
    let fields = o.get_array(CLASS_FIELDS_KEY)?;
    if marker.is_empty() {
        return None;
    }
    Some((marker, fields))
}

// ===== 解码 =====

/// 从二进制数据反序列化 SFSObject(数据必须以 0x12 marker 开头)。
/// 畸形或截断输入一律报错,绝不 panic。
pub fn decode(data: &[u8]) -> Result<Object, String> {
    if data.is_empty() {
        return Err("invalid SFSObject marker: empty input".to_string());
    }
    if data[0] != t::SFS_OBJECT {
        return Err(format!("invalid SFSObject marker: {}", data[0]));
    }
    let mut p = Pos { off: 1 }; // 跳过 0x12
    decode_entries(data, &mut p)
}

struct Pos {
    off: usize,
}

/// 报错除非 p.off 处还有 n 字节可用。
fn need(data: &[u8], p: &Pos, n: usize) -> Result<(), String> {
    if p.off + n > data.len() {
        return Err(format!(
            "truncated SFS data: need {n} byte(s) at offset {}, have {}",
            p.off,
            data.len()
        ));
    }
    Ok(())
}

fn read_u8(data: &[u8], p: &mut Pos) -> Result<u8, String> {
    need(data, p, 1)?;
    let v = data[p.off];
    p.off += 1;
    Ok(v)
}

fn read_u16(data: &[u8], p: &mut Pos) -> Result<usize, String> {
    need(data, p, 2)?;
    let v = u16::from_be_bytes([data[p.off], data[p.off + 1]]) as usize;
    p.off += 2;
    Ok(v)
}

fn read_u32(data: &[u8], p: &mut Pos) -> Result<usize, String> {
    need(data, p, 4)?;
    let v = u32::from_be_bytes([
        data[p.off],
        data[p.off + 1],
        data[p.off + 2],
        data[p.off + 3],
    ]) as usize;
    p.off += 4;
    Ok(v)
}

fn read_u64(data: &[u8], p: &mut Pos) -> Result<u64, String> {
    need(data, p, 8)?;
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[p.off..p.off + 8]);
    p.off += 8;
    Ok(u64::from_be_bytes(b))
}

/// 从 count 字段起解析条目(调用方已消费 marker)。
fn decode_entries(data: &[u8], p: &mut Pos) -> Result<Object, String> {
    let count = read_u16(data, p)?;
    let mut o = Object::new();
    for _ in 0..count {
        let kl = read_u16(data, p)?;
        need(data, p, kl)?;
        let key = String::from_utf8_lossy(&data[p.off..p.off + kl]).into_owned();
        p.off += kl;
        let val = decode_value(data, p)?;
        o.put(key, val);
    }
    Ok(o)
}

fn decode_value(data: &[u8], p: &mut Pos) -> Result<Value, String> {
    let typ = read_u8(data, p)?;
    match typ {
        t::NULL => Ok(Value::Null),
        t::BOOL => Ok(Value::Bool(read_u8(data, p)? != 0)),
        t::BYTE => Ok(Value::Byte(read_u8(data, p)?)),
        t::SHORT => Ok(Value::Short(read_u16(data, p)? as i16)),
        t::INT => Ok(Value::Int(read_u32(data, p)? as i32)),
        t::LONG => Ok(Value::Long(read_u64(data, p)? as i64)),
        t::FLOAT => Ok(Value::Float(f32::from_bits(read_u32(data, p)? as u32))),
        t::DOUBLE => Ok(Value::Double(f64::from_bits(read_u64(data, p)?))),
        t::UTF_STRING => {
            let l = read_u16(data, p)?;
            need(data, p, l)?;
            let s = String::from_utf8_lossy(&data[p.off..p.off + l]).into_owned();
            p.off += l;
            Ok(Value::UtfString(s))
        }
        t::TEXT => {
            let l = read_u32(data, p)?;
            need(data, p, l)?;
            let s = String::from_utf8_lossy(&data[p.off..p.off + l]).into_owned();
            p.off += l;
            Ok(Value::Text(s))
        }
        t::BYTE_ARRAY => {
            let l = read_u32(data, p)?;
            need(data, p, l)?;
            let b = data[p.off..p.off + l].to_vec();
            p.off += l;
            Ok(Value::ByteArray(b))
        }
        t::BOOL_ARRAY => {
            let n = read_u16(data, p)?;
            let mut a = Vec::with_capacity(n);
            for _ in 0..n {
                a.push(read_u8(data, p)? != 0);
            }
            Ok(Value::BoolArray(a))
        }
        t::SHORT_ARRAY => {
            let n = read_u16(data, p)?;
            let mut a = Vec::with_capacity(n);
            for _ in 0..n {
                a.push(read_u16(data, p)? as i16);
            }
            Ok(Value::ShortArray(a))
        }
        t::INT_ARRAY => {
            let n = read_u16(data, p)?;
            let mut a = Vec::with_capacity(n);
            for _ in 0..n {
                a.push(read_u32(data, p)? as i32);
            }
            Ok(Value::IntArray(a))
        }
        t::LONG_ARRAY => {
            let n = read_u16(data, p)?;
            let mut a = Vec::with_capacity(n);
            for _ in 0..n {
                a.push(read_u64(data, p)? as i64);
            }
            Ok(Value::LongArray(a))
        }
        t::FLOAT_ARRAY => {
            let n = read_u16(data, p)?;
            let mut a = Vec::with_capacity(n);
            for _ in 0..n {
                a.push(f32::from_bits(read_u32(data, p)? as u32));
            }
            Ok(Value::FloatArray(a))
        }
        t::DOUBLE_ARRAY => {
            let n = read_u16(data, p)?;
            let mut a = Vec::with_capacity(n);
            for _ in 0..n {
                a.push(f64::from_bits(read_u64(data, p)?));
            }
            Ok(Value::DoubleArray(a))
        }
        t::UTF_STRING_ARRAY => {
            let n = read_u16(data, p)?;
            let mut a = Vec::with_capacity(n);
            for _ in 0..n {
                let l = read_u16(data, p)?;
                need(data, p, l)?;
                a.push(String::from_utf8_lossy(&data[p.off..p.off + l]).into_owned());
                p.off += l;
            }
            Ok(Value::UtfStringArray(a))
        }
        // 类型字节即 marker:回退一字节后按 marker+count 解析
        t::SFS_ARRAY => {
            p.off -= 1;
            need(data, p, 3)?;
            let n = read_u16(data, &mut Pos { off: p.off + 1 })?;
            p.off += 3;
            let mut a = Vec::with_capacity(n);
            for _ in 0..n {
                a.push(decode_value(data, p)?);
            }
            Ok(Value::SfsArray(a))
        }
        t::SFS_OBJECT => {
            p.off -= 1;
            need(data, p, 3)?;
            let n = read_u16(data, &mut Pos { off: p.off + 1 })?;
            p.off += 3;
            let mut sub = Object::new();
            for _ in 0..n {
                let kl = read_u16(data, p)?;
                need(data, p, kl)?;
                let key = String::from_utf8_lossy(&data[p.off..p.off + kl]).into_owned();
                p.off += kl;
                let e = decode_value(data, p)?;
                sub.put(key, e);
            }
            Ok(Value::SfsObject(sub))
        }
        _ => Err(format!("unknown SFS type {typ} @ {}", p.off)),
    }
}

// ===== 帧封装 =====

/// [`FrameOptions`] 控制的可选帧变换,见 [`encode_frame_with_options`] /
/// [`decode_frame_with_options`]。
#[derive(Debug, Clone, Default)]
pub struct FrameOptions<'a> {
    /// 载荷超过该字节数时 zlib 压缩(帧头 0x20)。0 禁用压缩。官方客户端
    /// 缺省 1024。
    pub compress_threshold: usize,
    /// 对(可选压缩过的)载荷启用 AES-128-CBC 加密(帧头 0x40)。必须恰好
    /// 16 字节(AES-128)。两种模式:
    /// - [`FrameOptions::encryption_iv`] 有值 → 官方模式:服务器下发的固定
    ///   key+IV,载荷只有密文(无 IV 前缀);
    /// - `None` → 自描述模式:新鲜随机 IV 前缀进载荷(IV || 密文)。
    pub encryption_key: Option<&'a [u8]>,
    /// 选择官方固定 IV 模式(见 [`FrameOptions::encryption_key`])。有值时
    /// 必须恰好 16 字节。服务器经 HTTPS(/BlueBox/CryptoManager)下发
    /// key+IV;用 [`parse_crypto_key_response`] 解析。
    pub encryption_iv: Option<&'a [u8]>,
    /// 以插入序(而非确定性排序序)输出对象 key——与官方客户端编码器
    /// 字节级兼容。解码侧两种顺序通吃。
    pub ordered: bool,
}

impl<'a> FrameOptions<'a> {
    /// 加密钥匙 + 官方固定 IV 模式的简写构造。
    #[must_use]
    pub fn encrypted(key: &'a [u8], iv: &'a [u8]) -> FrameOptions<'a> {
        FrameOptions {
            encryption_key: Some(key),
            encryption_iv: Some(iv),
            ..FrameOptions::default()
        }
    }
}

/// 把 Object 包进 SFS 帧:签名字节、载荷长度、载荷。载荷至多 65535 字节用
/// 短(uint16)长度形态;更大自动切 BIG_SIZE(0x08,uint32)形态——与官方
/// 客户端行为一致。不施加压缩与加密(见 [`encode_frame_with_options`])。
#[must_use]
pub fn encode_frame(o: &Object) -> Vec<u8> {
    let payload = o.encode();
    frame_bytes(SIGNATURE, &payload)
}

/// 把 Object 包进 SFS 帧并施加 [`FrameOptions`] 的可选变换。载荷超 65535
/// 字节自动用 BIG_SIZE(0x08,uint32)长度形态。
///
/// 注意:压缩/加密帧按设计非确定(zlib 输出与随机 IV 都会变);字节稳定
/// 编码只对明文帧成立。
pub fn encode_frame_with_options(o: &Object, opts: &FrameOptions) -> Result<Vec<u8>, String> {
    let payload = if opts.ordered {
        o.encode_ordered()
    } else {
        o.encode()
    };

    let mut hdr_flags = SIGNATURE;
    let mut payload = payload;
    if opts.compress_threshold > 0 && payload.len() > opts.compress_threshold {
        payload = compress_payload(&payload)?;
        hdr_flags |= COMPRESSION_MASK;
    }

    if let Some(key) = opts.encryption_key {
        payload = match opts.encryption_iv {
            Some(iv) => {
                validate_crypto_key_iv(key, iv)?;
                // 官方固定 key+IV 模式:载荷只有密文
                encrypt_payload_fixed_iv(&payload, key, iv)?
            }
            None => {
                // 自描述模式:随机 IV 前缀
                encrypt_payload(&payload, key)?
            }
        };
        hdr_flags |= ENCRYPTION_MASK;
    }

    Ok(frame_bytes(hdr_flags, &payload))
}

fn frame_bytes(hdr_flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    if payload.len() > 0xFFFF {
        out.push(hdr_flags | LONG_LEN_MASK);
        write_u32(&mut out, payload.len());
    } else {
        out.push(hdr_flags);
        write_u16(&mut out, payload.len());
    }
    out.extend_from_slice(payload);
    out
}

/// 从 SFS 帧提取载荷并解析为 [`Object`],透明处理解密(帧带 0x40 标志时用
/// `opts.encryption_key`)与解压(0x20)。两种长度形态通吃。
pub fn decode_frame_with_options(data: &[u8], opts: &FrameOptions) -> Result<Object, String> {
    if data.len() < 3 {
        return Err(format!("frame too short: {}", data.len()));
    }
    let hdr = data[0];
    if hdr & SIGNATURE == 0 {
        return Err(format!("not a binary SFS frame (header {hdr:02x})"));
    }
    let mut off = 1usize;
    let ln;
    if hdr & LONG_LEN_MASK != 0 {
        if data.len() < off + 4 {
            return Err(format!(
                "frame too short for BIG_SIZE header: {}",
                data.len()
            ));
        }
        ln = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as usize;
        off += 4;
    } else {
        ln = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
    }
    if off + ln > data.len() {
        return Err("frame payload truncated".to_string());
    }
    let mut buf = data[off..off + ln].to_vec();

    if hdr & ENCRYPTION_MASK != 0 {
        let key = opts
            .encryption_key
            .ok_or_else(|| "encrypted frame but no decryption key provided".to_string())?;
        buf = match opts.encryption_iv {
            Some(iv) => {
                validate_crypto_key_iv(key, iv)?;
                // 官方固定 key+IV 模式
                decrypt_payload_fixed_iv(&buf, key, iv)?
            }
            None => {
                // 自描述模式(IV 前缀)
                decrypt_payload(&buf, key)?
            }
        };
    }

    if hdr & COMPRESSION_MASK != 0 {
        buf = decompress_payload(&buf)?;
    }

    decode(&buf)
}

/// 从 SFS 帧提取载荷并解析为 [`Object`]。压缩(0x20)帧透明解压;加密
/// (0x40)帧以显式错误拒绝——那些请用 [`decode_frame_with_options`] 给
/// 钥匙。两种长度形态通吃。
pub fn decode_frame(data: &[u8]) -> Result<Object, String> {
    if !data.is_empty() && data[0] & ENCRYPTION_MASK != 0 {
        return Err(
            "encrypted frame but no decryption key provided (use decode_frame_with_options)"
                .to_string(),
        );
    }
    decode_frame_with_options(data, &FrameOptions::default())
}

// ===== zlib 压缩 =====

/// zlib 压缩帧载荷(帧头 0x20)。
fn compress_payload(payload: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(payload)
        .map_err(|e| format!("zlib compress: {e}"))?;
    encoder.finish().map_err(|e| format!("zlib compress: {e}"))
}

/// 解压 zlib 压缩的帧载荷。输出上限 [`MAX_DECOMPRESSED_SIZE`],防解压炸弹。
fn decompress_payload(payload: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let decoder = flate2::read::ZlibDecoder::new(payload);
    let mut out = Vec::new();
    let limit = MAX_DECOMPRESSED_SIZE;
    decoder
        .take((limit + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|e| format!("zlib decompress: {e}"))?;
    if out.len() > limit {
        return Err(format!("zlib decompress: output exceeds {limit} bytes"));
    }
    Ok(out)
}

// ===== AES-128-CBC 加密 =====

/// 官方要求的 AES key 长度(AES-128),对齐官方 SFS2X 加密方案。
pub const AES_KEY_SIZE: usize = 16;
/// AES-CBC 初始化向量长度。
pub const IV_SIZE: usize = 16;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// 官方 SFS2X 加密 key 对:16 字节 AES key + 16 字节 IV,均由服务器经
/// HTTPS(/BlueBox/CryptoManager servlet,响应 = Base64(key || iv))下发,
/// 每个加密帧复用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoKey {
    /// 16 字节 AES key。
    pub key: Vec<u8>,
    /// 16 字节 IV。
    pub iv: Vec<u8>,
}

impl CryptoKey {
    /// 校验 key/IV 长度。
    pub fn validate(&self) -> Result<(), String> {
        validate_crypto_key_iv(&self.key, &self.iv)
    }
}

/// 解析 /BlueBox/CryptoManager servlet 响应:32 裸字节——key(16)后跟
/// IV(16)。
pub fn parse_crypto_key_response(data: &[u8]) -> Result<CryptoKey, String> {
    if data.len() != AES_KEY_SIZE + IV_SIZE {
        return Err(format!(
            "crypto key response must be {} bytes (key||iv), got {}",
            AES_KEY_SIZE + IV_SIZE,
            data.len()
        ));
    }
    Ok(CryptoKey {
        key: data[..AES_KEY_SIZE].to_vec(),
        iv: data[AES_KEY_SIZE..].to_vec(),
    })
}

/// 以 Base64 文本解析 servlet 响应(servlet 经 HTTPS 发的是 Base64 文本)。
pub fn parse_crypto_key_response_base64(s: &str) -> Result<CryptoKey, String> {
    let raw =
        crate::base64util::decode(s).map_err(|e| format!("crypto key response base64: {e}"))?;
    parse_crypto_key_response(&raw)
}

/// 校验官方 key/IV 长度。
fn validate_crypto_key_iv(key: &[u8], iv: &[u8]) -> Result<(), String> {
    if key.len() != AES_KEY_SIZE {
        return Err(format!(
            "encryption key must be {AES_KEY_SIZE} bytes, got {}",
            key.len()
        ));
    }
    if iv.len() != IV_SIZE {
        return Err(format!(
            "encryption iv must be {IV_SIZE} bytes, got {}",
            iv.len()
        ));
    }
    Ok(())
}

/// 官方固定 key+IV 模式 AES-128-CBC 加密:输出只有密文(PKCS#7 填充),
/// 无 IV 前缀——对端用同一对 key/IV 解密。
fn encrypt_payload_fixed_iv(payload: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    // 预留一个完整块给填充
    let mut buf = vec![0u8; payload.len() + IV_SIZE];
    buf[..payload.len()].copy_from_slice(payload);
    let out = Aes128CbcEnc::new_from_slices(key, iv)
        .map_err(|e| format!("aes: {e}"))?
        .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf, payload.len())
        .map_err(|e| format!("aes-cbc encrypt failed: {e}"))?;
    Ok(out.to_vec())
}

/// 官方固定 IV 模式 AES-128-CBC 解密(只有密文,PKCS#7 去填充)。
fn decrypt_payload_fixed_iv(payload: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    if payload.is_empty() || payload.len() % IV_SIZE != 0 {
        return Err(format!(
            "encrypted payload malformed: len {}",
            payload.len()
        ));
    }
    let mut buf = payload.to_vec();
    Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| format!("aes: {e}"))?
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| format!("invalid pkcs7 padding: {e}"))
        .map(<[u8]>::to_vec)
}

/// 自描述模式 AES-128-CBC 加密:新鲜随机 IV,前缀进输出(IV || 密文)。
/// key 必须恰好 16 字节。
fn encrypt_payload(payload: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != AES_KEY_SIZE {
        return Err(format!(
            "encryption key must be {AES_KEY_SIZE} bytes, got {}",
            key.len()
        ));
    }
    let mut iv = [0u8; IV_SIZE];
    getrandom::fill(&mut iv).map_err(|e| format!("generate iv: {e}"))?;
    let mut out = encrypt_payload_fixed_iv(payload, key, &iv)?;
    let mut with_iv = iv.to_vec();
    with_iv.append(&mut out);
    Ok(with_iv)
}

/// 自描述模式 AES-128-CBC 解密:输入 = IV(16B) || 密文,PKCS#7 去填充。
/// key 必须恰好 16 字节。
fn decrypt_payload(payload: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != AES_KEY_SIZE {
        return Err(format!(
            "encryption key must be {AES_KEY_SIZE} bytes, got {}",
            key.len()
        ));
    }
    if payload.len() < IV_SIZE + IV_SIZE || payload.len() % IV_SIZE != 0 {
        return Err(format!(
            "encrypted payload malformed: len {}",
            payload.len()
        ));
    }
    let (iv, ct) = payload.split_at(IV_SIZE);
    decrypt_payload_fixed_iv(ct, key, iv)
}

// ===== 消息信封 =====

/// 众所周知的请求 controller ID。
pub mod controller {
    /// 系统控制器:握手、登录、房间/用户管理……
    pub const SYSTEM: u8 = 0;
    /// 用户 extension 调用。
    pub const EXTENSION: u8 = 1;
    /// 加密初始化、UDP 回落。
    pub const SECURITY: u8 = 2;
    /// 好友列表。
    pub const BUDDY: u8 = 3;
    /// 房间管理。
    pub const ROOM_MANAGER: u8 = 4;
    /// 管理工具/控制台。
    pub const ADMIN: u8 = 5;
}

/// 系统 controller 的 action 码。
pub mod sys_action {
    /// 握手。
    pub const HANDSHAKE: i16 = 0;
    /// 登录。
    pub const LOGIN: i16 = 1;
    /// 登出。
    pub const LOGOUT: i16 = 2;
    /// 取房间列表。
    pub const GET_ROOM_LIST: i16 = 3;
    /// 进房。
    pub const JOIN_ROOM: i16 = 4;
    /// 自动进房。
    pub const AUTO_JOIN: i16 = 5;
    /// 建房。
    pub const CREATE_ROOM: i16 = 6;
    /// 通用消息。
    pub const GENERIC_MESSAGE: i16 = 7;
    /// 改房名。
    pub const CHANGE_ROOM_NAME: i16 = 8;
    /// 改房密码。
    pub const CHANGE_ROOM_PASSWORD: i16 = 9;
    /// 对象消息。
    pub const OBJECT_MESSAGE: i16 = 10;
    /// 设房间变量。
    pub const SET_ROOM_VARIABLES: i16 = 11;
    /// 设用户变量。
    pub const SET_USER_VARIABLES: i16 = 12;
    /// 调 extension。
    pub const CALL_EXTENSION: i16 = 13;
    /// 退房。
    pub const LEAVE_ROOM: i16 = 14;
    /// 订阅房间组。
    pub const SUBSCRIBE_ROOM_GROUP: i16 = 15;
    /// 退订房间组。
    pub const UNSUBSCRIBE_ROOM_GROUP: i16 = 16;
    /// 观战转玩家。
    pub const SPECTATOR_TO_PLAYER: i16 = 17;
    /// 玩家转观战。
    pub const PLAYER_TO_SPECTATOR: i16 = 18;
    /// 改房间容量。
    pub const CHANGE_ROOM_CAPACITY: i16 = 19;
    /// 公聊。
    pub const PUBLIC_MESSAGE: i16 = 20;
    /// 私聊。
    pub const PRIVATE_MESSAGE: i16 = 21;
    /// 管理员消息。
    pub const MODERATOR_MESSAGE: i16 = 22;
    /// 系统消息。
    pub const ADMIN_MESSAGE: i16 = 23;
    /// 踢人。
    pub const KICK_USER: i16 = 24;
    /// 封禁。
    pub const BAN_USER: i16 = 25;
    /// 主动断开。
    pub const MANUAL_DISCONNECTION: i16 = 26;
    /// 找房。
    pub const FIND_ROOMS: i16 = 27;
    /// 找人。
    pub const FIND_USERS: i16 = 28;
    /// 心跳。
    pub const PING_PONG: i16 = 29;
    /// 设用户位置。
    pub const SET_USER_POSITION: i16 = 30;
}

/// 标准 SFS2X 请求/响应信封:
/// `{c: BYTE controller, a: SHORT action, p: SFS_OBJECT params}`。
#[derive(Debug, Clone)]
pub struct Message {
    /// 请求 controller。
    pub controller: u8,
    /// 请求 action。
    pub action: i16,
    /// 参数对象。
    pub params: Object,
}

/// 围绕 params 构建信封。
#[must_use]
pub fn new_message(controller: u8, action: i16, params: Object) -> Message {
    Message {
        controller,
        action,
        params,
    }
}

impl Message {
    /// 序列化信封(帧内包裹的载荷)。
    #[must_use]
    pub fn to_object(&self) -> Object {
        let mut o = Object::new();
        o.put("c", Value::Byte(self.controller));
        o.put("a", Value::Short(self.action));
        o.put("p", Value::SfsObject(self.params.clone()));
        o
    }

    /// 帧封装信封并保持 param key 插入序(官方客户端字节忠实)。
    pub fn encode_ordered_frame(&self) -> Result<Vec<u8>, String> {
        encode_frame_with_options(
            &self.to_object(),
            &FrameOptions {
                ordered: true,
                ..FrameOptions::default()
            },
        )
    }
}

/// 解析帧封装的信封。
pub fn parse_message(data: &[u8]) -> Result<Message, String> {
    parse_message_with_options(data, &FrameOptions::default())
}

/// 解析帧封装的信封并施加给定变换(加密会话的解密 key/IV)。
pub fn parse_message_with_options(data: &[u8], opts: &FrameOptions) -> Result<Message, String> {
    let o = decode_frame_with_options(data, opts)?;
    parse_message_object(&o)
}

/// 把解码出的 SFSObject 解释为信封。
pub fn parse_message_object(o: &Object) -> Result<Message, String> {
    if o.get_type("c") != Some(t::BYTE) || o.get_type("a") != Some(t::SHORT) {
        return Err("not a message envelope (c/a fields missing or mistyped)".to_string());
    }
    let params = o.get_object("p").cloned().unwrap_or_default();
    Ok(Message {
        controller: o.get_byte("c").unwrap_or(0),
        action: o.get_short("a").unwrap_or(0),
        params,
    })
}

/// 握手请求/响应字段名(官方客户端约定)。
pub mod handshake_key {
    /// 客户端 API 版本(请求)。
    pub const API: &str = "api";
    /// 客户端类型字符串(请求)。
    pub const CLIENT_TYPE: &str = "cl";
    /// 重连令牌(请求,可选)。
    pub const RECONNECTION: &str = "rt";
    /// 会话令牌(响应;驱动 HTTPS crypto-key servlet 调用)。
    pub const SESSION_TOKEN: &str = "tk";
    /// 压缩阈值(响应)。
    pub const COMPRESSION: &str = "ct";
    /// 最大消息尺寸(响应)。
    pub const MAX_MESSAGE: &str = "ms";
}

/// 构建连接时的握手请求(controller 0 / action 0)。响应中返回的会话令牌
/// 就是调用方拿去请求 HTTPS crypto-key servlet 的凭据。
#[must_use]
pub fn new_handshake_request(api_version: &str, client_type: &str) -> Message {
    let mut params = Object::new();
    params.put(handshake_key::API, Value::utf_string(api_version));
    params.put(handshake_key::CLIENT_TYPE, Value::utf_string(client_type));
    new_message(controller::SYSTEM, sys_action::HANDSHAKE, params)
}

/// 解析后的服务器握手应答。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandshakeResponse {
    /// `"tk"`——呈递给 crypto-key servlet。
    pub session_token: String,
    /// `"ct"`——缺省时为 0。
    pub compression_threshold: i32,
    /// `"ms"`——缺省时为 0。
    pub max_message_size: i32,
}

/// 提取握手应答字段。
pub fn parse_handshake_response(o: &Object) -> Result<HandshakeResponse, String> {
    let resp = HandshakeResponse {
        session_token: o
            .get_string(handshake_key::SESSION_TOKEN)
            .unwrap_or("")
            .to_string(),
        compression_threshold: match o.get_type(handshake_key::COMPRESSION) {
            Some(t::INT) => o.get_int(handshake_key::COMPRESSION).unwrap_or(0),
            _ => 0,
        },
        max_message_size: match o.get_type(handshake_key::MAX_MESSAGE) {
            Some(t::INT) => o.get_int(handshake_key::MAX_MESSAGE).unwrap_or(0),
            _ => 0,
        },
    };
    if resp.session_token.is_empty() {
        return Err("handshake response without session token".to_string());
    }
    Ok(resp)
}

#[cfg(test)]
mod tests;
