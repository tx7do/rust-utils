//! ip2region xdb v2 查询器(feature `geoip`)。
//!
//! 数据格式:256 字节文件头,其后 512KiB 向量索引(按 IP 前两字节
//! 定位段索引范围),再后为段索引与数据段。IPv4 段索引条目 14 字节
//! (起始/结束 IP 按小端存储,比较时反转为大端),IPv6 条目 38 字节
//! (IP 按原始字节序)。
//!
//! 实现要点:
//!
//! - 数据文件不由库内嵌,各构造函数接收字节序列,由调用方自行
//!   加载;
//! - 越界/畸形输入不 panic:越界读取统一返回不完整读取错误,
//!   含文件头与向量索引的长度校验;
//! - 地域字节串按 UTF-8 有损转为 `String`(真实 xdb 地域串为
//!   UTF-8,仅畸形数据受影响);
//! - IPv4 的 IP 比较为只读的字节反转(索引字节原地不动,比较前
//!   反转为大端);
//! - 查询器池以 `Mutex`+`Condvar` 实现阻塞借还;
//! - 查询器不持有需要关闭的资源,不提供 `Close`。

use crate::geoip::{parse_ip_bytes, GeoResult};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicI32, Ordering as AtomicOrdering};
use std::sync::{Condvar, Mutex};

const STRUCTURE_20: u16 = 2;
const STRUCTURE_30: u16 = 3;
const HEADER_INFO_LENGTH: usize = 256;
const VECTOR_INDEX_ROWS: usize = 256;
const VECTOR_INDEX_COLS: usize = 256;
const VECTOR_INDEX_SIZE: usize = 8;
const VECTOR_INDEX_LENGTH: usize =
    HEADER_INFO_LENGTH + VECTOR_INDEX_ROWS * VECTOR_INDEX_COLS * VECTOR_INDEX_SIZE;

/// IP 版本。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpVersion {
    /// IPv4:地址 4 字节,段索引条目 14 字节,索引内 IP 按小端存储。
    IPv4,
    /// IPv6:地址 16 字节,段索引条目 38 字节,索引内 IP 按原始字节序。
    IPv6,
}

impl IpVersion {
    pub fn id(&self) -> i32 {
        match self {
            Self::IPv4 => 4,
            Self::IPv6 => 6,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::IPv4 => "IPv4",
            Self::IPv6 => "IPv6",
        }
    }

    pub fn bytes(&self) -> usize {
        match self {
            Self::IPv4 => 4,
            Self::IPv6 => 16,
        }
    }

    pub fn segment_index_size(&self) -> usize {
        match self {
            Self::IPv4 => 14,
            Self::IPv6 => 38,
        }
    }
}

// 版本不匹配错误文案引用该字面输出格式。
impl fmt::Display for IpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{id:{}, name:{}, bytes:{}, segment_index_size:{}}}",
            self.id(),
            self.name(),
            self.bytes(),
            self.segment_index_size()
        )
    }
}

/// 缓存策略(三者在本实现中的查询路径等价,差异仅在于是否预载
/// 向量索引副本)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum CachePolicy {
    NoCache = 0,
    VIndexCache = 1,
    BufferCache = 2,
}

/// 策略名解析。
pub fn cache_policy_from_name(name: &str) -> Result<CachePolicy, String> {
    match name.to_lowercase().as_str() {
        "file" | "nocache" => Ok(CachePolicy::NoCache),
        "vectorindex" | "vindex" | "vindexcache" => Ok(CachePolicy::VIndexCache),
        "content" | "buffercache" => Ok(CachePolicy::BufferCache),
        _ => Err(format!("invalid cache policy name `{name}`")),
    }
}

/// 版本名解析。
pub fn version_from_name(name: &str) -> Result<IpVersion, String> {
    match name.to_uppercase().as_str() {
        "V4" | "IPV4" => Ok(IpVersion::IPv4),
        "V6" | "IPV6" => Ok(IpVersion::IPv6),
        _ => Err(format!("invalid version name `{name}`")),
    }
}

/// xdb 文件头(固定 256 字节,前 20 字节为字段)。
#[derive(Debug)]
pub struct Header {
    pub version: u16,
    pub index_policy: u16,
    pub created_at: u32,
    pub start_index_ptr: u32,
    pub end_index_ptr: u32,
    pub ip_version: i32,
    pub runtime_ptr_bytes: i32,
}

/// 头解析(按实际读取范围校验,前 20 字节须齐备)。
fn header_from_bytes(input: &[u8]) -> Result<Header, String> {
    if input.len() < 20 {
        return Err("invalid input buffer".to_string());
    }
    Ok(Header {
        version: u16::from_le_bytes([input[0], input[1]]),
        index_policy: u16::from_le_bytes([input[2], input[3]]),
        created_at: u32::from_le_bytes([input[4], input[5], input[6], input[7]]),
        start_index_ptr: u32::from_le_bytes([input[8], input[9], input[10], input[11]]),
        end_index_ptr: u32::from_le_bytes([input[12], input[13], input[14], input[15]]),
        ip_version: i32::from(u16::from_le_bytes([input[16], input[17]])),
        runtime_ptr_bytes: i32::from(u16::from_le_bytes([input[18], input[19]])),
    })
}

/// 从整文件缓冲装载头(短缓冲返回错误)。
fn load_header_from_buff(c_buff: &[u8]) -> Result<Header, String> {
    if c_buff.len() < HEADER_INFO_LENGTH {
        return Err(format!(
            "buffer too small: need {HEADER_INFO_LENGTH} bytes, got {}",
            c_buff.len()
        ));
    }
    header_from_bytes(c_buff)
}

/// 从整文件缓冲复制向量索引。
fn load_vector_index_from_buff(c_buff: &[u8]) -> Result<Vec<u8>, String> {
    if c_buff.len() < VECTOR_INDEX_LENGTH {
        return Err(format!(
            "buffer too small: need {VECTOR_INDEX_LENGTH} bytes, got {}",
            c_buff.len()
        ));
    }
    Ok(c_buff[HEADER_INFO_LENGTH..VECTOR_INDEX_LENGTH].to_vec())
}

/// 头版本判定(2.0 结构一律按 IPv4;3.0 结构再看 IP 版本字段)。
fn version_from_header(header: &Header) -> Result<IpVersion, String> {
    if header.version == STRUCTURE_20 {
        return Ok(IpVersion::IPv4);
    }
    if header.version != STRUCTURE_30 {
        return Err(format!("invalid version `{}`", header.ip_version));
    }
    match header.ip_version {
        4 => Ok(IpVersion::IPv4),
        6 => Ok(IpVersion::IPv6),
        _ => Err(format!("invalid version `{}`", header.version)),
    }
}

/// 查询器构造配置。
#[derive(Debug)]
pub struct Config {
    cache_policy: CachePolicy,
    ip_version: IpVersion,
    header: Header,
    v_index: Option<Vec<u8>>,
    c_buffer: Vec<u8>,
    searchers: i32,
}

impl Config {
    /// IPv4 配置。
    pub fn new_v4(
        cache_policy: CachePolicy,
        xdb_content: Vec<u8>,
        searchers: i32,
    ) -> Result<Self, String> {
        Self::new(cache_policy, IpVersion::IPv4, xdb_content, searchers)
    }

    /// IPv6 配置。
    pub fn new_v6(
        cache_policy: CachePolicy,
        xdb_content: Vec<u8>,
        searchers: i32,
    ) -> Result<Self, String> {
        Self::new(cache_policy, IpVersion::IPv6, xdb_content, searchers)
    }

    fn new(
        cache_policy: CachePolicy,
        ip_version: IpVersion,
        xdb_content: Vec<u8>,
        searchers: i32,
    ) -> Result<Self, String> {
        if searchers < 1 {
            return Err(format!("searchers={searchers}, > 0 expected"));
        }
        let header = load_header_from_buff(&xdb_content)?;
        let x_ip_version = version_from_header(&header)?;
        if x_ip_version != ip_version {
            return Err(format!(
                "ip version mismatch, xdb version={x_ip_version}, expected={ip_version}"
            ));
        }
        let v_index = if cache_policy == CachePolicy::VIndexCache {
            Some(load_vector_index_from_buff(&xdb_content)?)
        } else {
            None
        };
        Ok(Self {
            cache_policy,
            ip_version,
            header,
            v_index,
            c_buffer: xdb_content,
            searchers,
        })
    }

    pub fn cache_policy(&self) -> i32 {
        self.cache_policy as i32
    }

    pub fn ip_version(&self) -> IpVersion {
        self.ip_version
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn v_index(&self) -> Option<&[u8]> {
        self.v_index.as_deref()
    }

    pub fn c_buffer(&self) -> &[u8] {
        &self.c_buffer
    }

    pub fn searchers(&self) -> i32 {
        self.searchers
    }
}

/// 缓冲读取:越界或部分可读时返回不完整读取错误。
fn read_at(src: &[u8], offset: usize, buf: &mut [u8]) -> Result<(), String> {
    match src.get(offset..offset.wrapping_add(buf.len())) {
        Some(s) => {
            buf.copy_from_slice(s);
            Ok(())
        }
        None => Err(format!(
            "incomplete read: readed bytes should be {}",
            buf.len()
        )),
    }
}

/// IP 比较(IPv4 索引按小端存储,比较前只读反转为大端;IPv6 直接
/// 字节序比较)。
fn ip_compare(version: IpVersion, ip1: &[u8], ip2: &[u8]) -> Ordering {
    match version {
        IpVersion::IPv4 => {
            let reversed = [ip2[3], ip2[2], ip2[1], ip2[0]];
            ip1.cmp(reversed.as_slice())
        }
        IpVersion::IPv6 => ip1.cmp(ip2),
    }
}

/// xdb 查询器(非线程安全,经池串行借用)。
pub struct Searcher {
    version: IpVersion,
    /// 每次查询前重置且从不递增,恒为 0。
    io_count: i32,
    vector_index: Option<Vec<u8>>,
    content_buff: Option<Vec<u8>>,
}

impl Searcher {
    /// 整文件驻留构造。
    pub fn new_with_buffer(version: IpVersion, c_buff: Vec<u8>) -> Result<Self, String> {
        Self::new(version, None, Some(c_buff))
    }

    /// 通用构造(整文件缓冲存在时向量索引副本被忽略;两者皆无时
    /// 不读取任何数据,查询读回全零)。
    pub fn new(
        version: IpVersion,
        v_index: Option<Vec<u8>>,
        c_buff: Option<Vec<u8>>,
    ) -> Result<Self, String> {
        Ok(match c_buff {
            Some(c) => Self {
                version,
                io_count: 0,
                vector_index: None,
                content_buff: Some(c),
            },
            None => Self {
                version,
                io_count: 0,
                vector_index: v_index,
                content_buff: None,
            },
        })
    }

    pub fn ip_version(&self) -> IpVersion {
        self.version
    }

    /// IO 计数(恒为 0,见字段注释)。
    pub fn get_io_count(&self) -> i32 {
        self.io_count
    }

    /// 解析 IP 字符串并查询。
    pub fn search_by_str(&self, ip_str: &str) -> Result<String, String> {
        let ip = parse_ip_bytes(ip_str).ok_or_else(|| format!("invalid ip address: {ip_str}"))?;
        self.search(&ip)
    }

    /// 查询(经向量索引定位段索引范围,段索引二分命中后读取数据段)。
    pub fn search(&self, ip: &[u8]) -> Result<String, String> {
        if ip.len() != self.version.bytes() {
            return Err(format!(
                "invalid ip address({} expected)",
                self.version.name()
            ));
        }

        let idx = ip[0] as usize * VECTOR_INDEX_COLS * VECTOR_INDEX_SIZE
            + ip[1] as usize * VECTOR_INDEX_SIZE;
        // 向量索引读取:优先预载副本,其次整文件缓冲;两者皆无时
        // 不读取,保持全零
        let mut vec = [0u8; 8];
        let src = self
            .vector_index
            .as_deref()
            .or(self.content_buff.as_deref());
        let base = if self.vector_index.is_some() {
            0
        } else {
            HEADER_INFO_LENGTH
        };
        if let Some(src) = src {
            read_at(src, base + idx, &mut vec)?;
        }
        let s_ptr = u32::from_le_bytes([vec[0], vec[1], vec[2], vec[3]]);
        let e_ptr = u32::from_le_bytes([vec[4], vec[5], vec[6], vec[7]]);

        let bytes = ip.len();
        let d_bytes = bytes << 1;
        let seg_index_size = self.version.segment_index_size();
        let mut data_len = 0usize;
        let mut data_ptr = 0u32;
        let mut buff = vec![0u8; seg_index_size];
        let mut l: i64 = 0;
        let mut h: i64 = (e_ptr.wrapping_sub(s_ptr) / seg_index_size as u32) as i64;
        while l <= h {
            let m = (l + h) >> 1;
            let p = s_ptr.wrapping_add((m as u32).wrapping_mul(seg_index_size as u32));
            if let Err(e) = self.read(p as usize, &mut buff) {
                return Err(format!("read segment index at {p}: {e}"));
            }

            if ip_compare(self.version, ip, &buff[..bytes]) == Ordering::Less {
                h = m - 1;
            } else if ip_compare(self.version, ip, &buff[bytes..d_bytes]) == Ordering::Greater {
                l = m + 1;
            } else {
                data_len = u16::from_le_bytes([buff[d_bytes], buff[d_bytes + 1]]) as usize;
                data_ptr = u32::from_le_bytes([
                    buff[d_bytes + 2],
                    buff[d_bytes + 3],
                    buff[d_bytes + 4],
                    buff[d_bytes + 5],
                ]);
                break;
            }
        }

        if data_len == 0 {
            return Ok(String::new());
        }

        let mut region_buff = vec![0u8; data_len];
        if let Err(e) = self.read(data_ptr as usize, &mut region_buff) {
            return Err(format!("read region at {data_ptr}: {e}"));
        }
        Ok(String::from_utf8_lossy(&region_buff).into_owned())
    }

    /// 读取:仅整文件缓冲存在时读取;无缓冲时不读取,缓冲保持全零。
    fn read(&self, offset: usize, buff: &mut [u8]) -> Result<(), String> {
        match &self.content_buff {
            Some(c) => read_at(c, offset, buff),
            None => Ok(()),
        }
    }
}

/// 查询器池(`Mutex`+`Condvar` 实现的阻塞借还,池空时等待)。
pub struct SearcherPool {
    searchers: Mutex<VecDeque<Searcher>>,
    cond: Condvar,
    loan_count: AtomicI32,
}

impl SearcherPool {
    /// 构造并填满池。
    pub fn new(config: &Config) -> Result<Self, String> {
        if config.searchers < 1 {
            return Err("config.searchers must > 0".to_string());
        }
        let mut searchers = VecDeque::with_capacity(config.searchers as usize);
        for i in 0..config.searchers {
            let searcher = Searcher::new_with_buffer(config.ip_version, config.c_buffer.clone())
                .map_err(|e| format!("failed to create the {}th searcher: {e}", i + 1))?;
            searchers.push_back(searcher);
        }
        Ok(Self {
            searchers: Mutex::new(searchers),
            cond: Condvar::new(),
            loan_count: AtomicI32::new(0),
        })
    }

    /// 借出一个查询器执行 `f`,用毕归还(池空时阻塞等待)。
    pub fn with_searcher<R>(&self, f: impl FnOnce(&Searcher) -> R) -> R {
        let mut guard = self.searchers.lock().unwrap_or_else(|e| e.into_inner());
        while guard.is_empty() {
            guard = self.cond.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
        let searcher = guard.pop_front().unwrap();
        drop(guard);

        self.loan_count.fetch_add(1, AtomicOrdering::SeqCst);
        let result = f(&searcher);
        self.loan_count.fetch_sub(1, AtomicOrdering::SeqCst);

        let mut guard = self.searchers.lock().unwrap_or_else(|e| e.into_inner());
        guard.push_back(searcher);
        drop(guard);
        self.cond.notify_one();
        result
    }

    /// 当前借出数。
    pub fn loan_count(&self) -> i32 {
        self.loan_count.load(AtomicOrdering::SeqCst)
    }
}

/// 双栈查询服务(对应版本被禁用时查询返回空串)。BufferCache 走
/// 免池的整文件驻留查询器,其余策略走查询器池。
pub struct Ip2Region {
    v4_pool: Option<SearcherPool>,
    v4_in_mem_searcher: Option<Searcher>,
    v6_pool: Option<SearcherPool>,
    v6_in_mem_searcher: Option<Searcher>,
}

impl Ip2Region {
    /// 以两个版本配置创建,`None` 禁用对应版本。
    pub fn new(v4_config: Option<Config>, v6_config: Option<Config>) -> Result<Self, String> {
        let (v4_pool, v4_in_mem_searcher) = match v4_config {
            None => (None, None),
            Some(c) if c.cache_policy == CachePolicy::BufferCache => {
                let searcher = Searcher::new_with_buffer(c.ip_version, c.c_buffer.clone())
                    .map_err(|e| format!("failed to create v4 in-memory searcher: {e}"))?;
                (None, Some(searcher))
            }
            Some(c) => {
                let pool = SearcherPool::new(&c)
                    .map_err(|e| format!("failed to create v4 searcher pool: {e}"))?;
                (Some(pool), None)
            }
        };
        let (v6_pool, v6_in_mem_searcher) = match v6_config {
            None => (None, None),
            Some(c) if c.cache_policy == CachePolicy::BufferCache => {
                let searcher = Searcher::new_with_buffer(c.ip_version, c.c_buffer.clone())
                    .map_err(|e| format!("failed to create v6 in-memory searcher: {e}"))?;
                (None, Some(searcher))
            }
            Some(c) => {
                let pool = SearcherPool::new(&c).map_err(|e| {
                    // "memeory" 为该错误文案的固定拼写
                    format!("failed to create v6 in-memeory searcher pool: {e}")
                })?;
                (Some(pool), None)
            }
        };
        Ok(Self {
            v4_pool,
            v4_in_mem_searcher,
            v6_pool,
            v6_in_mem_searcher,
        })
    }

    /// 解析 IP 字符串并按字节长度分派。
    pub fn search_by_str(&self, ip_str: &str) -> Result<String, String> {
        let ip_bytes =
            parse_ip_bytes(ip_str).ok_or_else(|| format!("invalid ip address: {ip_str}"))?;
        self.search(&ip_bytes)
    }

    /// 按字节数分派:4 字节走 IPv4,16 字节走 IPv6。
    pub fn search(&self, ip_bytes: &[u8]) -> Result<String, String> {
        match ip_bytes.len() {
            4 => self.v4_search(ip_bytes),
            16 => self.v6_search(ip_bytes),
            l => Err(format!("invalid byte ip address with len={l}")),
        }
    }

    fn v4_search(&self, ip_bytes: &[u8]) -> Result<String, String> {
        if let Some(searcher) = &self.v4_in_mem_searcher {
            return searcher.search(ip_bytes);
        }
        let Some(pool) = &self.v4_pool else {
            // IPv4 查询被禁用时返回空串
            return Ok(String::new());
        };
        pool.with_searcher(|searcher| searcher.search(ip_bytes))
    }

    fn v6_search(&self, ip_bytes: &[u8]) -> Result<String, String> {
        if let Some(searcher) = &self.v6_in_mem_searcher {
            return searcher.search(ip_bytes);
        }
        let Some(pool) = &self.v6_pool else {
            // IPv6 查询被禁用时返回空串
            return Ok(String::new());
        };
        pool.with_searcher(|searcher| searcher.search(ip_bytes))
    }
}

/// 便捷客户端(默认采用向量索引缓存策略与 20 个查询器;由调用方
/// 传入两版数据,`None` 禁用对应版本)。
pub struct Client {
    ip2region: Ip2Region,
}

impl Client {
    pub fn new(v4_db: Option<Vec<u8>>, v6_db: Option<Vec<u8>>) -> Result<Self, String> {
        let v4_config = match v4_db {
            Some(db) => Some(
                Config::new_v4(CachePolicy::VIndexCache, db, 20)
                    .map_err(|e| format!("failed to create v4 config: {e}"))?,
            ),
            None => None,
        };
        let v6_config = match v6_db {
            Some(db) => Some(
                Config::new_v6(CachePolicy::VIndexCache, db, 20)
                    .map_err(|e| format!("failed to create v6 config: {e}"))?,
            ),
            None => None,
        };
        let ip2region = Ip2Region::new(v4_config, v6_config)
            .map_err(|e| format!("failed to create ip2region service: {e}"))?;
        Ok(Self { ip2region })
    }

    /// 以显式配置创建(供需要非默认策略的调用方使用)。
    pub fn with_configs(v4: Option<Config>, v6: Option<Config>) -> Result<Self, String> {
        let ip2region = Ip2Region::new(v4, v6)
            .map_err(|e| format!("failed to create ip2region service: {e}"))?;
        Ok(Self { ip2region })
    }

    /// 归属地查询(地域串按 `|` 恰好切出四段时依次填入国家/省/
    /// 市/ISP,其余一律视为非法数据;结果 `ip` 字段保持为空串)。
    pub fn query(&self, raw_ip: &str) -> Result<GeoResult, String> {
        let region_data = self.ip2region.search_by_str(raw_ip)?;
        let parts: Vec<&str> = region_data.split('|').collect();
        if parts.len() != 4 {
            return Err(format!("invalid region data: {region_data}"));
        }
        Ok(GeoResult {
            ip: String::new(),
            country: parts[0].to_string(),
            province: parts[1].to_string(),
            city: parts[2].to_string(),
            isp: parts[3].to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    /// 构造微型 xdb:头(version=3、ip_version 按版本)后接全量
    /// 复制的向量索引(所有表项一律指向段索引的完整范围)、段索引
    /// 与数据段。
    fn build_xdb(version: IpVersion, segments: &[(&[u8], &[u8], &str)]) -> Vec<u8> {
        let seg_size = version.segment_index_size();
        let seg_base: u32 = VECTOR_INDEX_LENGTH as u32;
        let last: u32 = seg_base + (segments.len() as u32 - 1) * seg_size as u32;

        let mut buf = vec![0u8; HEADER_INFO_LENGTH];
        buf[0..2].copy_from_slice(&STRUCTURE_30.to_le_bytes());
        let ip_version_field = match version {
            IpVersion::IPv4 => 4u16,
            IpVersion::IPv6 => 6u16,
        };
        buf[16..18].copy_from_slice(&ip_version_field.to_le_bytes());
        for _ in 0..VECTOR_INDEX_ROWS * VECTOR_INDEX_COLS {
            buf.extend_from_slice(&seg_base.to_le_bytes());
            buf.extend_from_slice(&last.to_le_bytes());
        }

        let mut data_offsets = Vec::with_capacity(segments.len());
        let mut cursor: u32 = (VECTOR_INDEX_LENGTH + segments.len() * seg_size) as u32;
        for (_, _, region) in segments {
            data_offsets.push(cursor);
            cursor += region.len() as u32;
        }

        for (i, (start, end, region)) in segments.iter().enumerate() {
            let mut entry = Vec::with_capacity(seg_size);
            match version {
                IpVersion::IPv4 => {
                    // IPv4 的段索引 IP 按小端存储(即字节反转)
                    entry.extend(start.iter().copied().rev());
                    entry.extend(end.iter().copied().rev());
                }
                IpVersion::IPv6 => {
                    entry.extend_from_slice(start);
                    entry.extend_from_slice(end);
                }
            }
            entry.extend_from_slice(&(region.len() as u16).to_le_bytes());
            entry.extend_from_slice(&data_offsets[i].to_le_bytes());
            buf.extend_from_slice(&entry);
        }
        for (_, _, region) in segments {
            buf.extend_from_slice(region.as_bytes());
        }
        buf
    }

    fn build_v4_fixture() -> Vec<u8> {
        build_xdb(
            IpVersion::IPv4,
            &[
                (&[1, 2, 0, 0], &[1, 2, 255, 255], "A1|A2|A3|A4"),
                (&[1, 3, 0, 0], &[1, 3, 255, 255], "B1|B2|B3|B4"),
            ],
        )
    }

    fn build_v6_fixture() -> Vec<u8> {
        let start = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut end = [0xff; 16];
        end[..4].copy_from_slice(&start[..4]);
        build_xdb(IpVersion::IPv6, &[(&start, &end, "C1|C2|C3|C4")])
    }

    #[test]
    fn ip2region_v4_fixture_hits() {
        let cfg = Config::new_v4(CachePolicy::VIndexCache, build_v4_fixture(), 2).unwrap();
        let svc = Ip2Region::new(Some(cfg), None).unwrap();
        assert_eq!(svc.search_by_str("1.2.0.5").unwrap(), "A1|A2|A3|A4");
        // 段首/段末含端
        assert_eq!(svc.search_by_str("1.2.255.255").unwrap(), "A1|A2|A3|A4");
        assert_eq!(svc.search_by_str("1.3.0.0").unwrap(), "B1|B2|B3|B4");
        // IPv4 映射形态折叠为 4 字节
        assert_eq!(svc.search_by_str("::ffff:1.2.0.5").unwrap(), "A1|A2|A3|A4");
        // 低于首段/段间空隙/命中表项但无覆盖段 → 未命中
        assert_eq!(svc.search_by_str("1.1.255.254").unwrap(), "");
        assert_eq!(svc.search_by_str("1.4.0.1").unwrap(), "");
        assert_eq!(svc.search_by_str("9.9.9.9").unwrap(), "");
        // IPv6 被禁用 → 空串
        assert_eq!(svc.search_by_str("2001:db8::1").unwrap(), "");
        // 非法输入
        assert_eq!(
            svc.search_by_str("abc").unwrap_err(),
            "invalid ip address: abc"
        );
        assert_eq!(
            svc.search_by_str("1.2.3").unwrap_err(),
            "invalid ip address: 1.2.3"
        );
        assert_eq!(
            svc.search_by_str("1.2.3.4.5").unwrap_err(),
            "invalid ip address: 1.2.3.4.5"
        );
        // 字节数组分派
        assert_eq!(svc.search(&[1, 2, 0, 5]).unwrap(), "A1|A2|A3|A4");
        assert_eq!(svc.search(&[0u8; 16]).unwrap(), "");
        assert_eq!(
            svc.search(&[1, 2, 3]).unwrap_err(),
            "invalid byte ip address with len=3"
        );
    }

    #[test]
    fn ip2region_v6_fixture_hits() {
        // BufferCache → 免池的整文件驻留查询器
        let cfg = Config::new_v6(CachePolicy::BufferCache, build_v6_fixture(), 1).unwrap();
        let svc = Ip2Region::new(None, Some(cfg)).unwrap();
        assert_eq!(svc.search_by_str("2001:db8::1").unwrap(), "C1|C2|C3|C4");
        assert_eq!(svc.search_by_str("2001:db9::1").unwrap(), "");
        assert_eq!(svc.search_by_str("2001:db7::1").unwrap(), "");
        // IPv4 被禁用 → 空串
        assert_eq!(svc.search_by_str("1.2.0.5").unwrap(), "");
    }

    #[test]
    fn ip2region_buffer_cache_in_mem() {
        let cfg = Config::new_v4(CachePolicy::BufferCache, build_v4_fixture(), 1).unwrap();
        let svc = Ip2Region::new(Some(cfg), None).unwrap();
        assert_eq!(svc.search_by_str("1.2.0.5").unwrap(), "A1|A2|A3|A4");
    }

    #[test]
    fn ip2region_client_query() {
        // Client::new 采用默认的 VIndexCache 策略与 20 个查询器
        let client = Client::new(Some(build_v4_fixture()), Some(build_v6_fixture())).unwrap();
        let r = client.query("1.2.0.5").unwrap();
        assert_eq!(r.ip, ""); // ip 字段恒为空串
        assert_eq!(r.country, "A1");
        assert_eq!(r.province, "A2");
        assert_eq!(r.city, "A3");
        assert_eq!(r.isp, "A4");
        let r = client.query("2001:db8::1").unwrap();
        assert_eq!(r.country, "C1");
        assert_eq!(r.province, "C2");
        assert_eq!(r.city, "C3");
        assert_eq!(r.isp, "C4");
        // 未命中的空地域串视为非法数据
        assert_eq!(
            client.query("9.9.9.9").unwrap_err(),
            "invalid region data: "
        );
        assert_eq!(client.query("abc").unwrap_err(), "invalid ip address: abc");
        // 两版全禁用:一律空串 → 非法数据
        let client = Client::with_configs(None, None).unwrap();
        assert_eq!(
            client.query("1.2.0.5").unwrap_err(),
            "invalid region data: "
        );
        assert_eq!(
            client.query("2001:db8::1").unwrap_err(),
            "invalid region data: "
        );
    }

    #[test]
    fn ip2region_version_mismatch() {
        let err = Config::new_v6(CachePolicy::NoCache, build_v4_fixture(), 1).unwrap_err();
        assert_eq!(
            err,
            "ip version mismatch, xdb version={id:4, name:IPv4, bytes:4, segment_index_size:14}, expected={id:6, name:IPv6, bytes:16, segment_index_size:38}"
        );
        let err = Config::new_v4(CachePolicy::NoCache, build_v6_fixture(), 1).unwrap_err();
        assert_eq!(
            err,
            "ip version mismatch, xdb version={id:6, name:IPv6, bytes:16, segment_index_size:38}, expected={id:4, name:IPv4, bytes:4, segment_index_size:14}"
        );
    }

    #[test]
    fn ip2region_header_version_variants() {
        // version=2(Structure20):无视 IP 版本字段一律按 IPv4
        let mut db = build_v4_fixture();
        db[0..2].copy_from_slice(&STRUCTURE_20.to_le_bytes());
        db[16..18].copy_from_slice(&6u16.to_le_bytes());
        assert!(Config::new_v4(CachePolicy::NoCache, db.clone(), 1).is_ok());
        assert_eq!(
            Config::new_v6(CachePolicy::NoCache, db, 1).unwrap_err(),
            "ip version mismatch, xdb version={id:4, name:IPv4, bytes:4, segment_index_size:14}, expected={id:6, name:IPv6, bytes:16, segment_index_size:38}"
        );

        // version=1:错误文案取 IP 版本字段的值
        let mut db = build_v4_fixture();
        db[0..2].copy_from_slice(&1u16.to_le_bytes());
        db[16..18].copy_from_slice(&9u16.to_le_bytes());
        assert_eq!(
            Config::new_v4(CachePolicy::NoCache, db, 1).unwrap_err(),
            "invalid version `9`"
        );

        // version=3 但 IP 版本字段非法:文案取 version 字段的值
        let mut db = build_v4_fixture();
        db[16..18].copy_from_slice(&9u16.to_le_bytes());
        assert_eq!(
            Config::new_v4(CachePolicy::NoCache, db, 1).unwrap_err(),
            "invalid version `3`"
        );
    }

    #[test]
    fn ip2region_short_buffers() {
        // 头装载要求 256 字节,短缓冲返回错误
        assert_eq!(
            Config::new_v4(CachePolicy::NoCache, vec![0u8; 200], 1).unwrap_err(),
            "buffer too small: need 256 bytes, got 200"
        );
        // 向量索引缓存要求 524544 字节
        let db = build_v4_fixture();
        assert_eq!(
            Config::new_v4(
                CachePolicy::VIndexCache,
                db[..VECTOR_INDEX_LENGTH - 1].to_vec(),
                1
            )
            .unwrap_err(),
            "buffer too small: need 524544 bytes, got 524543"
        );
        // NoCache 不校验向量索引:头合法的截断缓冲可构造,
        // 查询时段索引读取越界
        let cfg = Config::new_v4(
            CachePolicy::NoCache,
            db[..VECTOR_INDEX_LENGTH - 1].to_vec(),
            1,
        )
        .unwrap();
        let svc = Ip2Region::new(Some(cfg), None).unwrap();
        let err = svc.search_by_str("1.2.0.5").unwrap_err();
        assert!(err.contains("read segment index at 524544"), "{err}");
        assert!(
            err.contains("incomplete read: readed bytes should be 14"),
            "{err}"
        );
    }

    #[test]
    fn ip2region_data_read_overflow() {
        let mut db = build_v4_fixture();
        // 首段条目的 dataLen 字段(u16 LE,位于条目内偏移 8)改为超长
        let seg_base = VECTOR_INDEX_LENGTH;
        db[seg_base + 8..seg_base + 10].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let cfg = Config::new_v4(CachePolicy::NoCache, db, 1).unwrap();
        let svc = Ip2Region::new(Some(cfg), None).unwrap();
        let err = svc.search_by_str("1.2.0.5").unwrap_err();
        assert!(err.contains("read region at 524572"), "{err}");
        assert!(
            err.contains("incomplete read: readed bytes should be 65535"),
            "{err}"
        );
    }

    #[test]
    fn ip2region_searchers_validation() {
        assert_eq!(
            Config::new_v4(CachePolicy::NoCache, build_v4_fixture(), 0).unwrap_err(),
            "searchers=0, > 0 expected"
        );
        assert_eq!(
            Config::new_v4(CachePolicy::NoCache, build_v4_fixture(), -3).unwrap_err(),
            "searchers=-3, > 0 expected"
        );
    }

    #[test]
    fn ip2region_from_name_tables() {
        assert_eq!(cache_policy_from_name("file"), Ok(CachePolicy::NoCache));
        assert_eq!(cache_policy_from_name("nocache"), Ok(CachePolicy::NoCache));
        assert_eq!(cache_policy_from_name("NoCache"), Ok(CachePolicy::NoCache));
        assert_eq!(
            cache_policy_from_name("vectorindex"),
            Ok(CachePolicy::VIndexCache)
        );
        assert_eq!(
            cache_policy_from_name("vindex"),
            Ok(CachePolicy::VIndexCache)
        );
        assert_eq!(
            cache_policy_from_name("vindexcache"),
            Ok(CachePolicy::VIndexCache)
        );
        assert_eq!(
            cache_policy_from_name("content"),
            Ok(CachePolicy::BufferCache)
        );
        assert_eq!(
            cache_policy_from_name("buffercache"),
            Ok(CachePolicy::BufferCache)
        );
        assert_eq!(
            cache_policy_from_name("bogus").unwrap_err(),
            "invalid cache policy name `bogus`"
        );
        assert_eq!(version_from_name("V4"), Ok(IpVersion::IPv4));
        assert_eq!(version_from_name("ipv4"), Ok(IpVersion::IPv4));
        assert_eq!(version_from_name("IPV6"), Ok(IpVersion::IPv6));
        assert_eq!(
            version_from_name("v5").unwrap_err(),
            "invalid version name `v5`"
        );
    }

    #[test]
    fn ip2region_config_fields() {
        let cfg = Config::new_v4(CachePolicy::VIndexCache, build_v4_fixture(), 2).unwrap();
        assert_eq!(cfg.cache_policy(), 1);
        assert_eq!(cfg.ip_version(), IpVersion::IPv4);
        assert_eq!(cfg.header().version, STRUCTURE_30);
        assert_eq!(cfg.header().ip_version, 4);
        assert_eq!(cfg.header().index_policy, 0); // 夹具未写,保持零
        assert_eq!(cfg.searchers(), 2);
        assert_eq!(
            cfg.v_index().map(|v| v.len()),
            Some(VECTOR_INDEX_ROWS * VECTOR_INDEX_COLS * VECTOR_INDEX_SIZE)
        );
        assert_eq!(cfg.c_buffer().len(), VECTOR_INDEX_LENGTH + 2 * 14 + 22);

        let cfg = Config::new_v4(CachePolicy::NoCache, build_v4_fixture(), 1).unwrap();
        assert_eq!(cfg.cache_policy(), 0);
        assert!(cfg.v_index().is_none());
    }

    #[test]
    fn ip2region_searcher_level() {
        let cfg = Config::new_v4(CachePolicy::NoCache, build_v4_fixture(), 1).unwrap();
        let pool = SearcherPool::new(&cfg).unwrap();
        pool.with_searcher(|searcher| {
            assert_eq!(searcher.ip_version(), IpVersion::IPv4);
            assert_eq!(searcher.get_io_count(), 0);
            assert_eq!(searcher.search(&[1, 2, 0, 5]).unwrap(), "A1|A2|A3|A4");
            assert_eq!(
                searcher.search(&[0u8; 16]).unwrap_err(),
                "invalid ip address(IPv4 expected)"
            );
            assert_eq!(
                searcher.search(&[1, 2, 3]).unwrap_err(),
                "invalid ip address(IPv4 expected)"
            );
            assert_eq!(searcher.search_by_str("1.3.0.5").unwrap(), "B1|B2|B3|B4");
        });
    }

    #[test]
    fn ip2region_pool_serializes_single_searcher() {
        let cfg = Config::new_v4(CachePolicy::NoCache, build_v4_fixture(), 1).unwrap();
        let pool = SearcherPool::new(&cfg).unwrap();
        assert_eq!(pool.loan_count(), 0);
        let barrier = Arc::new(Barrier::new(8));
        let inside = Arc::new(AtomicU32::new(0));
        let max_seen = Arc::new(AtomicU32::new(0));
        let pool_ref = &pool;
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let barrier = barrier.clone();
                let inside = inside.clone();
                let max_seen = max_seen.clone();
                scope.spawn(move || {
                    barrier.wait();
                    let region = pool_ref.with_searcher(|searcher| {
                        // 单查询器池:借出计数恒为 1
                        assert_eq!(pool_ref.loan_count(), 1);
                        let cur = inside.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                        max_seen.fetch_max(cur, AtomicOrdering::SeqCst);
                        std::thread::sleep(Duration::from_millis(2));
                        inside.fetch_sub(1, AtomicOrdering::SeqCst);
                        searcher.search(&[1, 2, 0, 5]).unwrap()
                    });
                    assert_eq!(region, "A1|A2|A3|A4");
                });
            }
        });
        // 8 线程同时冲池,池内仅 1 个查询器 → 并发入界数为 1
        assert_eq!(max_seen.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(pool.loan_count(), 0);
    }

    #[test]
    fn ip2region_pool_two_searchers_overlap() {
        let cfg = Config::new_v4(CachePolicy::NoCache, build_v4_fixture(), 2).unwrap();
        let pool = SearcherPool::new(&cfg).unwrap();
        // 两个查询器:双方须同时借出才能完成握手
        let (tx_a, rx_a) = mpsc::channel::<()>();
        let (tx_b, rx_b) = mpsc::channel::<()>();
        let pool_ref = &pool;
        let (ra, rb) = std::thread::scope(|scope| {
            let ha = scope.spawn(move || {
                pool_ref.with_searcher(|searcher| {
                    tx_a.send(()).unwrap();
                    rx_b.recv_timeout(Duration::from_secs(10))
                        .expect("handshake a");
                    searcher.search(&[1, 2, 0, 5])
                })
            });
            let hb = scope.spawn(move || {
                pool_ref.with_searcher(|searcher| {
                    tx_b.send(()).unwrap();
                    rx_a.recv_timeout(Duration::from_secs(10))
                        .expect("handshake b");
                    searcher.search(&[1, 3, 0, 5])
                })
            });
            (ha.join().unwrap(), hb.join().unwrap())
        });
        assert_eq!(ra.unwrap(), "A1|A2|A3|A4");
        assert_eq!(rb.unwrap(), "B1|B2|B3|B4");
        assert_eq!(pool.loan_count(), 0);
    }
}
