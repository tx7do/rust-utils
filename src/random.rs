//! 随机数工具箱(移植自 go-utils/rand 的常用子集),feature `rand`。
//!
//! 提供可种子化的 [`Randomizer`](带 `StdRng` 后端)以及直接使用线程
//! 随机源的自由函数。包含:基本类型、区间、加权选择、别名表(Alias
//! Method)、骰子/暴击、抖动、正态分布、常用随机串(字母/数字/十六进制)、
//! 中国大陆手机号、IPv4/IPv6、颜色等。
//!
//! ```
//! use rust_utils::random::Randomizer;
//!
//! let mut r1 = Randomizer::with_seed(42);
//! let mut r2 = Randomizer::with_seed(42);
//! assert_eq!(r1.int_range(0, 1000), r2.int_range(0, 1000)); // 种子一致则序列一致
//!
//! let mut r = Randomizer::new();
//! assert!((0..=6).contains(&r.d6()));
//! ```

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use std::time::Duration;

const ALPHANUMERIC: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const HEX_LOWER: &[u8] = b"0123456789abcdef";

/// 可种子化的随机数发生器(`StdRng` 后端)。
pub struct Randomizer {
    rng: StdRng,
}

impl Default for Randomizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Randomizer {
    /// 用系统熵播种。
    pub fn new() -> Self {
        Randomizer {
            rng: StdRng::from_os_rng(),
        }
    }

    /// 用固定种子播种(同种子同序列,便于测试)。
    pub fn with_seed(seed: u64) -> Self {
        Randomizer {
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// [0, 1) 浮点数。
    pub fn float64(&mut self) -> f64 {
        self.rng.random::<f64>()
    }

    /// 闭区间 [min, max] 的整数。
    pub fn int_range(&mut self, min: i64, max: i64) -> i64 {
        if min >= max {
            return min;
        }
        self.rng.random_range(min..=max)
    }

    /// 闭区间 [min, max] 的浮点数。
    pub fn float_range(&mut self, min: f64, max: f64) -> f64 {
        if min >= max {
            return min;
        }
        min + self.float64() * (max - min)
    }

    /// [0, n) 的非负整数。
    pub fn int_n(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.rng.random_range(0..n)
    }

    /// 布尔值。
    pub fn bool(&mut self) -> bool {
        self.rng.random::<bool>()
    }

    /// 以概率 `p ∈ [0,1]` 返回 true。
    pub fn probability_hit(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            return false;
        }
        if p >= 1.0 {
            return true;
        }
        self.float64() < p
    }

    /// 原地洗牌(Fisher–Yates)。
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.int_n((i + 1) as u64) as usize;
            slice.swap(i, j);
        }
    }

    /// 从切片中随机取一个元素的引用。
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            return None;
        }
        let idx = self.int_n(items.len() as u64) as usize;
        items.get(idx)
    }

    /// 从字符串切片中随机取一个。
    pub fn pick_string<'a>(&mut self, items: &'a [&'a str]) -> Option<&'a str> {
        self.pick(items).copied()
    }

    /// 按权重随机选一个下标;权重全 0 或为空返回 `None`。
    pub fn weighted_choice(&mut self, weights: &[u64]) -> Option<usize> {
        let total: u64 = weights.iter().filter(|w| **w > 0).sum();
        if total == 0 || weights.is_empty() {
            return None;
        }
        let mut acc = 0u64;
        let target = self.int_n(total);
        for (i, w) in weights.iter().enumerate() {
            acc += w;
            if target < acc {
                return Some(i);
            }
        }
        weights.iter().rposition(|w| *w > 0)
    }

    /// 别名表法加权采样,构建 O(n)、采样 O(1)。
    pub fn new_alias_table(&self, weights: &[f64]) -> Option<AliasTable> {
        AliasTable::new(weights)
    }

    /// 正态分布 N(mean, std²)(Box–Muller)。
    pub fn normal(&mut self, mean: f64, std: f64) -> f64 {
        if std <= 0.0 {
            return mean;
        }
        let u1 = self.float64().max(f64::MIN_POSITIVE);
        let u2 = self.float64();
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        mean + std * z
    }

    /// 掷 n 面骰子(结果 1..=sides)。
    pub fn dice(&mut self, sides: u32) -> u32 {
        self.int_range(1, sides as i64) as u32
    }

    /// 六面骰。
    pub fn d6(&mut self) -> u32 {
        self.dice(6)
    }

    /// 十面骰。
    pub fn d10(&mut self) -> u32 {
        self.dice(10)
    }

    /// 二十面骰。
    pub fn d20(&mut self) -> u32 {
        self.dice(20)
    }

    /// 一百面骰。
    pub fn d100(&mut self) -> u32 {
        self.dice(100)
    }

    /// 在 `base ± jitter` 范围内取整。
    pub fn jitter_int(&mut self, base: i64, jitter: i64) -> i64 {
        self.int_range(base - jitter, base + jitter)
    }

    /// 在 `base ± jitter` 范围内取时长。
    pub fn jitter_duration(&mut self, base: Duration, jitter: Duration) -> Duration {
        let base_ms = base.as_millis() as i64;
        let jitter_ms = jitter.as_millis() as i64;
        Duration::from_millis(self.jitter_int(base_ms, jitter_ms).max(0) as u64)
    }

    /// 随机字母数字串(长度 `len`)。
    pub fn random_string(&mut self, len: usize) -> String {
        self.string_with_charset(len, ALPHANUMERIC)
    }

    /// 从指定字符集取随机串。
    pub fn string_with_charset(&mut self, len: usize, charset: &[u8]) -> String {
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            let idx = self.int_n(charset.len() as u64) as usize;
            out.push(charset[idx] as char);
        }
        out
    }

    /// 随机小写十六进制串。
    pub fn hex_string(&mut self, len: usize) -> String {
        self.string_with_charset(len, HEX_LOWER)
    }

    /// 随机纯字母串。
    pub fn letter_string(&mut self, len: usize) -> String {
        self.string_with_charset(len, LETTERS)
    }

    /// 随机纯数字串。
    pub fn numeric_string(&mut self, len: usize) -> String {
        self.string_with_charset(len, DIGITS)
    }

    /// 中国大陆手机号(1[3-9] + 9 位数字)。
    pub fn phone_number(&mut self) -> String {
        let second = ["3", "5", "7", "8", "9"][self.int_n(5) as usize];
        format!("1{second}{}", self.numeric_string(9))
    }

    /// 随机 IPv4 地址字符串。
    pub fn random_ipv4(&mut self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.int_range(1, 254),
            self.int_range(0, 255),
            self.int_range(0, 255),
            self.int_range(1, 254)
        )
    }

    /// 随机 IPv6 地址字符串。
    pub fn random_ipv6(&mut self) -> String {
        (0..8)
            .map(|_| format!("{:04x}", self.int_range(0, 0xFFFF)))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// 随机 RGB 颜色。
    pub fn rgb(&mut self) -> (u8, u8, u8) {
        (
            self.int_range(0, 255) as u8,
            self.int_range(0, 255) as u8,
            self.int_range(0, 255) as u8,
        )
    }

    /// 随机十六进制颜色(如 `#3fa2c0`)。
    pub fn color_hex(&mut self) -> String {
        format!("#{}", self.hex_string(6))
    }

    /// 把 `total_point` 个点随机分配到 `attr_count` 个属性上(每项 ≥ 0)。
    pub fn attr_assign(&mut self, total_point: u32, attr_count: u32) -> Vec<u32> {
        if attr_count == 0 {
            return Vec::new();
        }
        let mut attrs = vec![0u32; attr_count as usize];
        for _ in 0..total_point {
            let idx = self.int_n(attr_count as u64) as usize;
            attrs[idx] += 1;
        }
        attrs
    }
}

/// 别名表(Alias Method):O(n) 构建、O(1) 采样。
#[derive(Debug, Clone)]
pub struct AliasTable {
    prob: Vec<f64>,
    alias: Vec<usize>,
}

impl AliasTable {
    pub fn new(weights: &[f64]) -> Option<Self> {
        let n = weights.len();
        if n == 0 {
            return None;
        }
        let total: f64 = weights.iter().filter(|w| **w > 0.0).sum();
        if total <= 0.0 {
            return None;
        }
        let mut scaled: Vec<f64> = weights.iter().map(|w| w / total * n as f64).collect();
        let mut prob = vec![0.0; n];
        let mut alias = vec![0usize; n];
        let mut small: Vec<usize> = Vec::with_capacity(n);
        let mut large: Vec<usize> = Vec::with_capacity(n);
        for (i, p) in scaled.iter().enumerate() {
            if *p < 1.0 {
                small.push(i);
            } else {
                large.push(i);
            }
        }
        while let (Some(s), Some(l)) = (small.last().copied(), large.last().copied()) {
            small.pop();
            large.pop();
            prob[s] = scaled[s];
            alias[s] = l;
            scaled[l] = scaled[l] + scaled[s] - 1.0;
            if scaled[l] < 1.0 {
                small.push(l);
            } else {
                large.push(l);
            }
        }
        for i in large.iter().chain(small.iter()) {
            prob[*i] = 1.0;
        }
        Some(AliasTable { prob, alias })
    }

    /// 采样的加权下标。
    pub fn choose<R: Rng>(&self, rng: &mut R) -> usize {
        let col = rng.random_range(0..self.prob.len());
        if rng.random::<f64>() < self.prob[col] {
            col
        } else {
            self.alias[col]
        }
    }
}

// ---------------------------------------------------------------------------
// 基于线程随机源的自由函数
// ---------------------------------------------------------------------------

/// [0, 1) 浮点。
pub fn float64() -> f64 {
    rand::rng().random()
}

/// 闭区间 [min, max] 整数。
pub fn int_range(min: i64, max: i64) -> i64 {
    if min >= max {
        return min;
    }
    rand::rng().random_range(min..=max)
}

/// 以概率 p 命中。
pub fn probability_hit(p: f64) -> bool {
    if p <= 0.0 {
        return false;
    }
    if p >= 1.0 {
        return true;
    }
    float64() < p
}

/// 随机字母数字串。
pub fn random_string(len: usize) -> String {
    string_with_charset(len, ALPHANUMERIC)
}

/// 指定字符集随机串。
pub fn string_with_charset(len: usize, charset: &[u8]) -> String {
    let mut rng = rand::rng();
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        let idx = rng.random_range(0..charset.len());
        out.push(charset[idx] as char);
    }
    out
}

/// 随机十六进制串。
pub fn hex_string(len: usize) -> String {
    string_with_charset(len, HEX_LOWER)
}

/// 随机中国大陆手机号。
pub fn phone_number() -> String {
    let mut rng = rand::rng();
    let second = ["3", "5", "7", "8", "9"][rng.random_range(0..5)];
    format!("1{second}{}", string_with_charset(9, DIGITS))
}

/// 随机 IPv4。
pub fn random_ipv4() -> String {
    format!(
        "{}.{}.{}.{}",
        int_range(1, 254),
        int_range(0, 255),
        int_range(0, 255),
        int_range(1, 254)
    )
}

/// 随机十六进制颜色。
pub fn color_hex() -> String {
    format!("#{}", hex_string(6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seeded_determinism() {
        let mut r1 = Randomizer::with_seed(42);
        let mut r2 = Randomizer::with_seed(42);
        for _ in 0..100 {
            assert_eq!(r1.int_range(0, 1000), r2.int_range(0, 1000));
            assert_eq!(r1.random_string(10), r2.random_string(10));
        }
    }

    #[test]
    fn test_ranges() {
        let mut r = Randomizer::new();
        for _ in 0..1000 {
            let v = r.int_range(-5, 5);
            assert!((-5..=5).contains(&v));
            let f = r.float_range(1.5, 2.5);
            assert!((1.5..2.5).contains(&f));
        }
        assert_eq!(r.int_range(3, 3), 3);
        assert_eq!(r.int_range(7, 2), 7);
    }

    #[test]
    fn test_weighted_choice_distribution() {
        let mut r = Randomizer::new();
        let weights = [0, 1, 3, 6]; // 期望占比 0%, 10%, 30%, 60%
        let mut counts = [0usize; 4];
        let n = 100_000;
        for _ in 0..n {
            let idx = r.weighted_choice(&weights).unwrap();
            counts[idx] += 1;
        }
        assert_eq!(counts[0], 0);
        assert!((counts[1] as f64 / n as f64 - 0.1).abs() < 0.02);
        assert!((counts[3] as f64 / n as f64 - 0.6).abs() < 0.02);
        assert!(r.weighted_choice(&[]).is_none());
        assert!(r.weighted_choice(&[0, 0]).is_none());
    }

    #[test]
    fn test_alias_table() {
        let mut r = Randomizer::new();
        let table = r.new_alias_table(&[1.0, 2.0, 7.0]).unwrap();
        let mut counts = [0usize; 3];
        let n = 100_000;
        for _ in 0..n {
            counts[table.choose(&mut r.rng)] += 1;
        }
        assert!((counts[0] as f64 / n as f64 - 0.1).abs() < 0.02);
        assert!((counts[2] as f64 / n as f64 - 0.7).abs() < 0.02);
        assert!(AliasTable::new(&[]).is_none());
        assert!(AliasTable::new(&[0.0, 0.0]).is_none());
    }

    #[test]
    fn test_shuffle_pick() {
        let mut r = Randomizer::new();
        let mut v: Vec<i32> = (0..50).collect();
        r.shuffle(&mut v);
        let mut sorted = v.clone();
        sorted.sort();
        assert_eq!(sorted, (0..50).collect::<Vec<i32>>());
        assert_ne!(v, sorted); // 50 个元素全打乱的撞车概率约 1/50!

        assert_eq!(r.pick::<i32>(&[]), None);
        assert_eq!(r.pick(&[42]), Some(&42));
    }

    #[test]
    fn test_strings() {
        let mut r = Randomizer::new();
        let s = r.random_string(32);
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(r.numeric_string(5).len(), 5);
        assert!(r.hex_string(8).chars().all(|c| c.is_ascii_hexdigit()));
        let p = r.phone_number();
        assert_eq!(p.len(), 11);
        assert!(p.starts_with('1'));
        assert!(["3", "5", "7", "8", "9"].contains(&&p[1..2]));
        assert!(r.random_ipv4().contains('.'));
        assert_eq!(r.color_hex().len(), 7);
    }

    #[test]
    fn test_dice_jitter_attr() {
        let mut r = Randomizer::new();
        for _ in 0..200 {
            assert!((1..=6).contains(&r.d6()));
            assert!((1..=100).contains(&r.d100()));
        }
        for _ in 0..200 {
            let j = r.jitter_int(100, 10);
            assert!((90..=110).contains(&j));
        }
        let attrs = r.attr_assign(100, 5);
        assert_eq!(attrs.iter().sum::<u32>(), 100);
        assert_eq!(attrs.len(), 5);
        assert!(r.attr_assign(10, 0).is_empty());
    }

    #[test]
    fn test_normal() {
        let mut r = Randomizer::new();
        let n = 100_000;
        let mut sum = 0.0;
        for _ in 0..n {
            sum += r.normal(10.0, 2.0);
        }
        let mean = sum / n as f64;
        assert!((mean - 10.0).abs() < 0.05, "mean: {mean}");
        assert_eq!(r.normal(5.0, 0.0), 5.0);
    }

    #[test]
    fn test_free_functions() {
        let _ = float64();
        let _ = int_range(0, 10);
        assert!(probability_hit(1.0));
        assert!(!probability_hit(0.0));
        assert_eq!(random_string(10).len(), 10);
        assert_eq!(phone_number().len(), 11);
        assert!(random_ipv4().contains('.'));
        assert_eq!(color_hex().len(), 7);
    }
}
