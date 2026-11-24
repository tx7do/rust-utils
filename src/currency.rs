//! 币种金额换算与 Money 类型(移植自 Go `tx7do/go-utils/currency`)。
//!
//! 两层单位体系:
//!
//! 1. **ISO minor units(分)**:指数表描述各币种的小数位数(CNY/USD 2 位;
//!    JPY/KRW/VND 0 位;KWD/BHD/TND 3 位)。[`to_minor`]/[`to_major`] 服务展示
//!    格式化与支付渠道结算边界;
//! 2. **定精度账本单位(ledger unit)**:[`to_base`]/[`from_base`] 在主单位与
//!    整数账本单位间换算,统一 4 位小数(1 主单位 = 10000 账本单位),与各币种
//!    ISO 指数解耦。
//!
//! 约定:金额换算一律走本模块。内联魔法数换算(×100 / ÷100)是静默舍入 bug
//! 与资金差额的根源。
//!
//! 未知或未指定币种(空串、小写、不在表中)回退 2 位小数——ISO 4217 的主流
//! 档位,回退错了代价最小。新增币种直接加进指数表。
//!
//! 除裸换算外还提供:
//! - [`Money`] 类型:带币种的类型化金额(整数账本单位),币种不匹配即报错的
//!   算术、精确守恒的分配/拆分与比较;
//! - 展示格式化:千分位、符号与 ISO 元数据([`format_base`]/[`format_minor`]/
//!   [`format_symbol_minor`]/[`lookup_info`]);
//! - 显式汇率换算([`convert_minor`]/[`convert_base`])与整数域精确汇率
//!   ([`convert_minor_exact`])、按方向的舍入变体(floor/ceil)。
//!
//! 与 Go 版的差异(适配零依赖纯 `std`):
//!
//! 1. Go 的 `math/big` 精确整数累计改用 `i128`(int64 × int64 最大约 2^126,
//!    `i128` 全程不溢出);乘积落回 `i64` 越界时返回 [`Error::Overflow`]
//!    (Go 个别路径会先在 int64 域静默回绕再进 big.Int,或 `Int64()` 溢出
//!    panic,Rust 侧统一收紧为 fail-fast);
//! 2. JSON 序列化以 [`Money::marshal_json`]/[`Money::unmarshal_json`] 纯函数
//!    提供(字符串形态 `"1,234.56 USD"`),不经 serde;需要 serde 的下游用
//!    newtype 包一层即可;
//! 3. [`Money::cmp`] 返回 [`std::cmp::Ordering`] 而非 -1/0/+1;
//! 4. [`minor_to_base`] 在极端值(> 9.2e14 分)溢出时饱和到 `i64` 边界
//!    (Go 侧静默回绕);其余算术全部 checked。
//!
//! ```
//! use rust_utils::currency::{Money, parse_money};
//!
//! // 金额一律带币种:构造、算术、格式化、解析闭环
//! let price = Money::from_minor("USD", 399);
//! let total = price.mul(5).unwrap();
//! assert_eq!(total.minor(), 1995);
//! assert_eq!(total.to_string(), "19.95 USD");
//!
//! // 经典找零守恒:100 分拆 3 份,余数落最大比例档,总和精确相等
//! let parts = Money::from_minor("USD", 100).split(3).unwrap();
//! assert_eq!(parts.iter().map(|m| m.base()).sum::<i64>(), 10000);
//!
//! // 字符串往返无损
//! let back = parse_money("1,234.56 USD").unwrap();
//! assert_eq!(back.base(), 12345600);
//! ```

use std::fmt;

/// 参考币种:调用方没有币种输入时的缺省回退。
pub const DEFAULT_CODE: &str = "USD";

/// 账本单位保留的小数位数(4:0.0001 步进)。
pub const BASE_DIGITS: u32 = 4;

/// 主单位 → 账本单位换算因子,恒为 `10^BASE_DIGITS = 10000`。
pub const BASE_FACTOR: i64 = 10000;

/// 0 位小数档的 ISO 4217 币种(其余未列出的默认 2 位)。
const ZERO_DECIMAL: &[&str] = &[
    "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "VND", "VUV",
    "XAF", "XOF", "XPF",
];

/// 3 位小数档的 ISO 4217 币种。
const THREE_DECIMAL: &[&str] = &["BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"];

/// 本模块错误:币种不匹配、算术溢出与解析/参数校验三类。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 两个不同币种的 [`Money`] 参与了运算或比较。
    Mismatch { left: String, right: String },
    /// 算术结果超出 `int64`。
    Overflow(String),
    /// 解析或参数校验失败。
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Mismatch { left, right } => {
                write!(
                    f,
                    "currency: money values of different currencies: {left} vs {right}"
                )
            }
            Error::Overflow(detail) => write!(f, "currency: amount overflow: {detail}"),
            Error::Invalid(detail) => write!(f, "currency: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

/// 模块结果类型。
pub type Result<T> = std::result::Result<T, Error>;

fn invalid<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(msg.into()))
}

/// 去除首尾空白并大写化币种代码。空输入保持为空(语义:未指定)。
pub fn normalize(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

/// 归一化币种代码,归一化结果为空(未指定)时返回 `fallback`。
pub fn normalize_or(code: &str, fallback: &str) -> String {
    let c = normalize(code);
    if c.is_empty() {
        fallback.to_string()
    } else {
        c
    }
}

/// 返回币种的 ISO 4217 小数位数(minor unit = 10^-exponent 主单位)。
/// 空码或未知码返回 2。
pub fn exponent(code: &str) -> u32 {
    let c = normalize(code);
    if c.is_empty() {
        return 2;
    }
    if ZERO_DECIMAL.contains(&c.as_str()) {
        0
    } else if THREE_DECIMAL.contains(&c.as_str()) {
        3
    } else {
        2
    }
}

/// 返回"1 主单位 = N minor units"的换算因子(10^exponent)。
/// 空码或未知码返回 100。
pub fn factor(code: &str) -> f64 {
    10f64.powi(exponent(code) as i32)
}

/// 主单位浮点金额 → ISO minor units,round half away from zero(与
/// `f64::round` 同语义,负数金额——退款、调整——对称)。
///
/// * `to_minor(0.3, "USD") = 30`
/// * `to_minor(120, "JPY") = 120`
/// * `to_minor(0.125, "KWD") = 125`
pub fn to_minor(amount: f64, code: &str) -> i64 {
    (amount * factor(code)).round() as i64
}

/// ISO minor units → 主单位浮点。
///
/// * `to_major(160, "USD") = 1.6`
/// * `to_major(120, "JPY") = 120`
pub fn to_major(units: i64, code: &str) -> f64 {
    units as f64 / factor(code)
}

/// ISO minor units → 整数主单位(向零截断,与整数除法同语义)。
/// 供以整数主单位记账但读取 minor-unit 源的系统使用。
pub fn to_major_int(units: i64, code: &str) -> i64 {
    to_major(units, code) as i64
}

// ===== 定精度账本单位 =====
//
// 账本单位是主单位的统一 4 位小数表示(1 主单位 = 10000 账本单位),刻意与
// 各币种 ISO 指数解耦:
//
// - 2 位币种(CNY/USD...):1 minor = 100 账本单位——亚分精度(0.001/0.0001)
//   精确可表示,汇率拆分与比例分配永不丢精度;
// - 0 位币种(JPY/KRW):1 单位 = 10000 账本单位,两位保护位;
// - 3 位币种(KWD):1 fils = 10 账本单位,仍然无损。
//
// 统一 1e4 因子(而非逐币种 exponent+2)让账本只有一套心法:跨币种聚合与
// 换算只需要汇率,永远不需要逐币种档位查询。指数表只服务展示格式化与支付
// 渠道结算边界。

/// 主单位浮点金额 → 整数账本单位(round half away from zero)。账本单位
/// 跨币种统一,无币种参数。
///
/// * `to_base(0.0001) = 1`
/// * `to_base(1.2345) = 12345`
pub fn to_base(amount: f64) -> i64 {
    (amount * BASE_FACTOR as f64).round() as i64
}

/// 整数账本单位 → 主单位浮点。
///
/// * `from_base(12345) = 1.2345`
pub fn from_base(units: i64) -> f64 {
    units as f64 / BASE_FACTOR as f64
}

/// 整数账本单位 → 整数主单位(向零截断,与 [`to_major_int`] 同语义)。
pub fn from_base_int(units: i64) -> i64 {
    units / BASE_FACTOR
}

/// ISO minor units → 账本单位(× 10^(BASE_DIGITS - ISO exponent))。
/// 供支付渠道以 minor units 结算的边界使用;2 位币种恒为 × 100。
/// 极端值溢出时饱和到 `i64` 边界(Go 侧静默回绕,Rust 侧选择饱和)。
pub fn minor_to_base(minor: i64, code: &str) -> i64 {
    let scale = 10i64.pow(BASE_DIGITS - exponent(code));
    minor.saturating_mul(scale)
}

/// 账本单位 → ISO minor units(÷ 10^(BASE_DIGITS - ISO exponent),向零
/// 截断)。只用于向支付渠道签发结算金额;内部记账始终保持完整账本精度。
pub fn base_to_minor(units: i64, code: &str) -> i64 {
    units / 10i64.pow(BASE_DIGITS - exponent(code))
}

// ===== ISO 4217 元数据 =====

/// 币种的展示元数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// ISO 4217 字母码,如 `"USD"`。
    pub code: String,
    /// ISO 4217 数字码,如 `"840"`(未知币种为空串)。
    pub numeric: String,
    /// 展示符号,如 `"$"`(未知币种回退为码本身)。
    pub symbol: String,
    /// 英文展示名(未知币种为空串)。
    pub name: String,
}

fn binary_lookup(
    table: &'static [(&'static str, &'static str)],
    code: &str,
) -> Option<&'static str> {
    table
        .binary_search_by(|(k, _)| (*k).cmp(code))
        .ok()
        .map(|i| table[i].1)
}

/// 返回币种的展示元数据。未知码的数字码/英文名为空,符号回退为码本身。
pub fn lookup_info(code: &str) -> Info {
    let code = normalize(code);
    let symbol = symbol(&code);
    Info {
        numeric: binary_lookup(NUMERIC_TABLE, &code)
            .unwrap_or("")
            .to_string(),
        symbol,
        name: binary_lookup(NAME_TABLE, &code).unwrap_or("").to_string(),
        code,
    }
}

/// 返回币种的展示符号(未知码回退为码本身)。
pub fn symbol(code: &str) -> String {
    let code = normalize(code);
    match binary_lookup(SYMBOL_TABLE, &code) {
        Some(sym) => sym.to_string(),
        None => code,
    }
}

/// 返回 ISO 4217 数字码(未知币种为空串)。
pub fn numeric_code(code: &str) -> String {
    binary_lookup(NUMERIC_TABLE, &normalize(code))
        .unwrap_or("")
        .to_string()
}

/// 解析 ISO 4217 数字码为字母码(`"840"` → `"USD"`)。未知数字码返回空串。
pub fn code_from_numeric(numeric: &str) -> String {
    for (code, n) in NUMERIC_TABLE {
        if *n == numeric {
            return (*code).to_string();
        }
    }
    String::new()
}

/// 返回币种的英文名(未知币种为空串)。
pub fn display_name(code: &str) -> String {
    binary_lookup(NAME_TABLE, &normalize(code))
        .unwrap_or("")
        .to_string()
}

/// 判断币种码是否在本模块的元数据表内。未知不代表非法——换算仍以 2 位
/// 小数回退正常工作。
pub fn is_known(code: &str) -> bool {
    binary_lookup(NUMERIC_TABLE, &normalize(code)).is_some()
}

/// 展示符号 → 币种码。歧义符号(多币种共用,如 `"¥"` 或 `"$"`)优先 USD,
/// 否则取字典序首个。注意与上游一致:查询侧先大写化,故符号表里的小写
/// 符号(`"kr"`/`"Rp"` 等)按原样匹配不中——需要这些币种请传显式码。
/// 未知符号返回空串。
pub fn code_from_symbol(sym: &str) -> String {
    let sym = normalize(sym);
    // 表按码序排布,首命中即字典序首个
    let mut first: Option<&str> = None;
    for (code, s) in SYMBOL_TABLE {
        if *s == sym {
            if first.is_none() {
                first = Some(code);
            }
            if *code == "USD" {
                return "USD".to_string();
            }
        }
    }
    first.unwrap_or("").to_string()
}

// ===== 格式化 =====

/// 每三位插一个逗号:1234567 → "1,234,567"(输入非负)。
fn group_thousands(v: i64) -> String {
    let s = v.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in bytes.iter().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*ch as char);
    }
    out
}

/// 校验显式汇率:必须有限且为正。
fn validate_rate(rate: f64) -> Result<()> {
    if !rate.is_finite() {
        return invalid(format!("rate must be finite, got {rate}"));
    }
    if rate <= 0.0 {
        return invalid(format!("rate must be positive, got {rate}"));
    }
    Ok(())
}

/// 以显式汇率在币种间换算 ISO minor-unit 金额:rate 表示 1 个 `from` 主单位
/// 值多少个 `to` 主单位。结果 round half away from zero。
///
/// rate 是 `f64`——来自汇率源的应用层应把输出当作展示/结算估计值而非账本
/// 真值;账本级换算请把汇率预放大为精确整数并在账本单位域应用
/// (见 [`convert_minor_exact`])。
pub fn convert_minor(minor: i64, from: &str, to: &str, rate: f64) -> Result<i64> {
    validate_rate(rate)?;
    let major_from = to_major(minor, from);
    Ok(to_minor(major_from * rate, to))
}

/// 在币种间换算账本单位金额(rate 语义与注意事项见 [`convert_minor`])。
/// 源金额的亚分精度参与计算;结果 round half away from zero 落到目标账本单位。
pub fn convert_base(base: i64, _from: &str, _to: &str, rate: f64) -> Result<i64> {
    validate_rate(rate)?;
    let major_from = from_base(base);
    Ok(to_base(major_from * rate))
}

/// [`convert_minor`] 的账本级变体:rate 为精确整数比(num/den 个 `to` 主单位
/// 每个欠 `from` 主单位),全程无浮点参与。目标 minor unit 上 round half
/// away from zero。
///
/// ```text
/// USD 100¢ → JPY at 150/1 = 1.00 USD × 150 = 150 JPY = 150 minor
/// USD 100¢ → KWD at 3/10  = 0.30 KWD = 300 fils
/// ```
pub fn convert_minor_exact(minor: i64, from: &str, to: &str, num: i64, den: i64) -> Result<i64> {
    if den == 0 {
        return invalid("rate denominator is zero");
    }
    // minor_to = minor_from × num × 10^exp(to) / (den × 10^exp(from))
    let acc = (minor as i128) * (num as i128) * 10i128.pow(exponent(to));
    let denom = (den as i128) * 10i128.pow(exponent(from));
    let (mut q, r) = (acc / denom, acc % denom);
    // half away from zero:|2r| >= |den| 时向远离零的方向进位
    if r.abs() * 2 >= denom.abs() {
        q += if acc < 0 { -1 } else { 1 };
    }
    i64::try_from(q).map_err(|_| Error::Overflow(format!("{q} overflows int64")))
}

/// [`to_minor`] 的方向变体:向下(→ -inf)取整到 ISO minor units。手续费与
/// PSP 结算金额常要求方向性舍入而非缺省的 half away from zero。
pub fn to_minor_floor(amount: f64, code: &str) -> i64 {
    (amount * factor(code)).floor() as i64
}

/// 向上(→ +inf)取整到 ISO minor units。
pub fn to_minor_ceil(amount: f64, code: &str) -> i64 {
    (amount * factor(code)).ceil() as i64
}

/// [`to_base`] 的方向变体:向下(→ -inf)取整到账本单位。
pub fn to_base_floor(amount: f64) -> i64 {
    (amount * BASE_FACTOR as f64).floor() as i64
}

/// 向上(→ +inf)取整到账本单位。
pub fn to_base_ceil(amount: f64) -> i64 {
    (amount * BASE_FACTOR as f64).ceil() as i64
}

// ===== 解析 =====

/// 拆出金额 token 与币种 token。接受形态:
///
/// ```text
/// "1234.56 USD" / "1234.56USD"  — 显式码
/// "$1,234.56 USD"               — 符号贴在金额上
/// "$1,234.56"                   — 符号作为币种载体
/// "¥120"                        — 符号解析歧义码(字典序首个),
///                                 共用符号请传显式码
/// ```
fn split_amount_code(s: &str) -> Result<(String, String)> {
    let fields: Vec<&str> = s.split_whitespace().collect();
    match fields.len() {
        1 => {
            // 可能是 "$1,234.56" 或裸数字(无币种信息,回退 DefaultCode)
            let tok = fields[0];
            if let Some(sym) = strip_leading_symbol(tok) {
                let code = code_from_symbol(sym);
                if code.is_empty() {
                    return invalid(format!("unknown symbol {sym:?}"));
                }
                return Ok((tok[sym.len()..].to_string(), code));
            }
            Ok((tok.to_string(), DEFAULT_CODE.to_string()))
        }
        2 => {
            let code = normalize(fields[1]);
            let mut amount = fields[0].to_string();
            let mut resolved = code.clone();
            if !is_known(&code) {
                // 第二段可能是符号("$USD" 场景已拆开;这里处理 "12.00 $")
                let by_sym = code_from_symbol(fields[1]);
                if !by_sym.is_empty() {
                    resolved = by_sym;
                    return Ok((amount, resolved));
                }
            }
            if let Some(sym) = strip_leading_symbol(&amount) {
                if symbol(&code) == sym {
                    amount = amount[sym.len()..].to_string();
                }
            }
            Ok((amount, resolved))
        }
        _ => invalid(format!("cannot parse money string {s:?}")),
    }
}

/// 找出金额 token 前挂的最长展示符号("$1,234" → "$";"S$12" → "S$";
/// 最长匹配优先,"HK$5" 才不会被误读成 "H")。
fn strip_leading_symbol(tok: &str) -> Option<&'static str> {
    let mut best: Option<&'static str> = None;
    for (_, sym) in SYMBOL_TABLE {
        if tok.starts_with(sym) && best.map_or(true, |b| sym.len() > b.len()) {
            best = Some(sym);
        }
    }
    best
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|ch| ch.is_ascii_digit())
}

/// 解析展示小数字符串为 ISO minor units。千分位逗号忽略;小数部分不得超过
/// 币种指数——亚分位数字被拒绝而非静默舍入("0.001" USD 报错;请用
/// [`parse_base_string`])。
pub fn parse_minor(s: &str, code: &str) -> Result<i64> {
    let base = parse_base_string(s, code)?;
    // 亚分位拒绝:账本单位里残留 ISO 指数以下精度 → 显式报错而非静默截断
    let scale = 10i64.pow(BASE_DIGITS - exponent(code));
    if base % scale != 0 {
        return invalid(format!(
            "{s:?} carries sub-minor digits beyond {} precision",
            normalize(code)
        ));
    }
    Ok(base_to_minor(base, code))
}

/// 解析展示小数字符串为账本单位。接受可选符号、千分位分隔符与至多
/// [`BASE_DIGITS`] 位小数("1234.5678")。超出账本精度的数字被拒绝而非
/// 静默舍入。
pub fn parse_base_string(s: &str, _code: &str) -> Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        return invalid("empty amount");
    }
    let neg = s.starts_with('-');
    let s = s.strip_prefix('-').unwrap_or(s);
    let s = s.strip_prefix('+').unwrap_or(s);
    let s = s.replace(',', "");
    if s.is_empty() {
        return invalid(format!("no digits in {s:?}"));
    }

    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s.as_str(), None),
    };
    if !all_digits(int_part) {
        return invalid(format!("invalid integer part in {s:?}"));
    }
    let frac_part = match frac_part {
        Some(f) => {
            if !all_digits(f) {
                return invalid(format!("invalid fractional part in {s:?}"));
            }
            if f.len() > BASE_DIGITS as usize {
                return invalid(format!(
                    "{} fractional digits exceed ledger precision ({BASE_DIGITS})",
                    f.len()
                ));
            }
            f.to_string()
        }
        None => String::new(),
    };

    // 分数右补零到账本精度:0.56 → 5600
    let mut digits = String::with_capacity(int_part.len() + BASE_DIGITS as usize);
    digits.push_str(int_part);
    digits.push_str(&frac_part);
    for _ in frac_part.len()..BASE_DIGITS as usize {
        digits.push('0');
    }

    let mut base: i64 = 0;
    for ch in digits.bytes() {
        base = base
            .checked_mul(10)
            .and_then(|v| v.checked_add((ch - b'0') as i64))
            .ok_or_else(|| Error::Overflow(format!("{s} overflows int64")))?;
    }
    Ok(if neg { -base } else { base })
}

/// 解析 money 字符串——`Money::to_string` 的精确输出形态,外加符号前缀
/// 变体(见 [`split_amount_code`])——为 [`Money`]。币种不匹配在构造上即
/// 不可能:码随字符串一起走。
///
/// ```text
/// parse_money(Money::from_minor("USD", 123456).to_string()) // 无损往返
/// ```
pub fn parse_money(s: &str) -> Result<Money> {
    let (amount_tok, code) = split_amount_code(s)?;
    let base = parse_base_string(&amount_tok, &code)?;
    Ok(Money::from_base(&code, base))
}

// ===== Money =====

/// 单一币种的金额,以账本单位存储(1 主单位 = 10000,见 [`BASE_FACTOR`])。
/// 全部算术跑在整数上——浮点从不接触存储值。
///
/// 默认值(`Money::default()`)是币种为空串(未指定)的零金额;与 Go 的零值
/// `Money{}` 一致。构造函数都会归一化币种码,因此币种不匹配检测对未归一化
/// 输入同样生效。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Money {
    code: String,
    base: i64,
}

impl Money {
    /// 返回给定币种的零金额 Money(空码回退 [`DEFAULT_CODE`])。
    pub fn new(code: &str) -> Money {
        Money {
            code: normalize_or(code, DEFAULT_CODE),
            base: 0,
        }
    }

    /// 从整数账本单位构建 Money。
    pub fn from_base(code: &str, base: i64) -> Money {
        Money {
            code: normalize_or(code, DEFAULT_CODE),
            base,
        }
    }

    /// 从 ISO minor units(如分)构建 Money。
    pub fn from_minor(code: &str, minor: i64) -> Money {
        Money::from_base(code, minor_to_base(minor, code))
    }

    /// 从主单位浮点构建 Money,round half away from zero。源金额已是离散值
    /// 时优先用整数构造函数。
    pub fn from_major(code: &str, amount: f64) -> Money {
        Money::from_base(code, to_base(amount))
    }

    /// 返回归一化后的币种码。
    pub fn code(&self) -> &str {
        &self.code
    }

    /// 返回原始账本单位。
    pub fn base(&self) -> i64 {
        self.base
    }

    /// 返回 ISO minor units 金额(向零截断——亚分账本精度在 ISO 边界丢弃)。
    pub fn minor(&self) -> i64 {
        base_to_minor(self.base, &self.code)
    }

    /// 返回主单位浮点金额。
    pub fn major(&self) -> f64 {
        from_base(self.base)
    }

    /// 金额是否恰好为零。
    pub fn is_zero(&self) -> bool {
        self.base == 0
    }

    /// 金额是否大于零。
    pub fn is_positive(&self) -> bool {
        self.base > 0
    }

    /// 金额是否小于零。
    pub fn is_negative(&self) -> bool {
        self.base < 0
    }

    /// 返回 `-m`。
    pub fn neg(&self) -> Money {
        Money {
            code: self.code.clone(),
            base: -self.base,
        }
    }

    /// 返回 `|m|`。
    pub fn abs(&self) -> Money {
        if self.base < 0 {
            self.neg()
        } else {
            self.clone()
        }
    }

    /// 币种一致性检查:归一化码不同即返回 [`Error::Mismatch`]。
    fn same_currency_or(&self, other: &Money) -> Result<()> {
        if self.code != other.code {
            return Err(Error::Mismatch {
                left: self.code.clone(),
                right: other.code.clone(),
            });
        }
        Ok(())
    }

    /// 返回 `a+b`。两值必须同币种;`int64` 溢出返回 [`Error::Overflow`]
    /// 而非静默回绕。
    pub fn add(&self, other: &Money) -> Result<Money> {
        self.same_currency_or(other)?;
        let sum = self.base.checked_add(other.base).ok_or_else(|| {
            Error::Overflow(format!("{} + {} overflows int64", self.base, other.base))
        })?;
        Ok(Money {
            code: self.code.clone(),
            base: sum,
        })
    }

    /// 返回 `a-b`。两值必须同币种;`int64` 溢出返回 [`Error::Overflow`]
    /// 而非静默回绕。
    pub fn sub(&self, other: &Money) -> Result<Money> {
        self.same_currency_or(other)?;
        let diff = self.base.checked_sub(other.base).ok_or_else(|| {
            Error::Overflow(format!("{} - {} overflows int64", self.base, other.base))
        })?;
        Ok(Money {
            code: self.code.clone(),
            base: diff,
        })
    }

    /// 比较两个同币种金额。方法名对齐上游 Go 版的 `Cmp`(不实现
    /// `std::cmp::Ord`:跨币种比较是错误而非全序)。
    #[allow(clippy::should_implement_trait)]
    pub fn cmp(&self, other: &Money) -> Result<std::cmp::Ordering> {
        self.same_currency_or(other)?;
        Ok(self.base.cmp(&other.base))
    }

    /// 金额按整数因子缩放(如 数量 × 单价)。`int64` 溢出返回
    /// [`Error::Overflow`] 而非静默回绕。
    pub fn mul(&self, factor: i64) -> Result<Money> {
        let prod = (self.base as i128) * (factor as i128);
        let base = i64::try_from(prod)
            .map_err(|_| Error::Overflow(format!("{} × {} overflows int64", self.base, factor)))?;
        Ok(Money {
            code: self.code.clone(),
            base,
        })
    }

    /// 按整数比例拆分金额,使各份之和精确等于原额——余数按最大余数法
    /// (逐单位、确定性)分配。负数金额对称分配。比例不得全为零,负比例
    /// 被拒绝。
    pub fn allocate(&self, ratios: &[i64]) -> Result<Vec<Money>> {
        if ratios.is_empty() {
            return invalid("allocate requires at least one ratio");
        }
        let mut total: i64 = 0;
        for (i, r) in ratios.iter().enumerate() {
            if *r < 0 {
                return invalid(format!("allocate ratio[{i}] is negative"));
            }
            total = total.checked_add(*r).ok_or_else(|| {
                Error::Overflow(format!("allocate ratios sum overflows int64 at [{i}]"))
            })?;
        }
        if total == 0 {
            return invalid("allocate ratios sum to zero");
        }

        // 最大余数法,精确整数累计(i128 防 base×ratio 溢出)
        let mut acc: i128 = 0;
        let total_big = total as i128;
        let mut parts: Vec<i64> = Vec::with_capacity(ratios.len());
        let mut prev: i64 = 0;
        for r in ratios {
            acc += (self.base as i128) * (*r as i128);
            let target = acc / total_big; // 截断除法
            let target = i64::try_from(target)
                .map_err(|_| Error::Overflow("allocation target overflows int64".into()))?;
            parts.push(target - prev);
            prev = target;
        }
        // 截断残差(符号随 self.base)归入最大比例档
        let residue = self.base - prev;
        if residue != 0 {
            let mut max_idx = 0;
            for (i, r) in ratios.iter().enumerate() {
                if *r > ratios[max_idx] {
                    max_idx = i;
                }
            }
            parts[max_idx] += residue;
        }

        Ok(parts
            .into_iter()
            .map(|p| Money {
                code: self.code.clone(),
                base: p,
            })
            .collect())
    }

    /// 把金额拆成 n 份近似相等的部分,总和精确等于原额:余数(前若干个
    /// 单位)归入靠前的部分。n 必须为正;负数金额对称拆分。
    pub fn split(&self, n: usize) -> Result<Vec<Money>> {
        if n == 0 {
            return invalid("split count must be positive");
        }
        self.allocate(&vec![1i64; n])
    }

    /// 按 `num/den` 精确整数比缩放金额,账本单位上 round half away from
    /// zero。这是账本级汇率/手续费应用:全程无浮点参与("2.5%" =
    /// `mul_ratio(25, 1000)`)。
    pub fn mul_ratio(&self, num: i64, den: i64) -> Result<Money> {
        if den == 0 {
            return invalid("mul ratio denominator is zero");
        }
        let acc = (self.base as i128) * (num as i128);
        let den_big = den as i128;
        let (mut q, r) = (acc / den_big, acc % den_big);
        // half away from zero:|2r| >= |den| 时向远离零的方向进位
        if r.abs() * 2 >= den_big.abs() {
            q += if acc < 0 { -1 } else { 1 };
        }
        let base = i64::try_from(q)
            .map_err(|_| Error::Overflow(format!("{} × {num}/{den} overflows int64", self.base)))?;
        Ok(Money {
            code: self.code.clone(),
            base,
        })
    }

    /// 返回金额的 pct 百分比("2.5%" = `percent(250)`)。
    /// 等价于 `mul_ratio(pct, 100)`。
    pub fn percent(&self, pct: i64) -> Result<Money> {
        self.mul_ratio(pct, 100)
    }

    /// 归整掉亚分账本尘(round half away from zero),保留币种与账本单位域:
    /// 分配或比例运算后,调用方常需要展示精度上干净无尘的金额。
    pub fn round_to_minor(&self) -> Money {
        Money::from_minor(&self.code, self.minor())
    }

    /// 同币种金额求和(不匹配 → [`Error::Mismatch`])。
    pub fn sum(values: &[Money]) -> Result<Money> {
        let first = values
            .first()
            .ok_or_else(|| Error::Invalid("currency: sum requires at least one value".into()))?;
        let mut total = Money {
            code: first.code.clone(),
            base: 0,
        };
        for m in values {
            total = total.add(m)?;
        }
        Ok(total)
    }

    /// 返回两同币种金额中较小者。
    pub fn min<'a>(a: &'a Money, b: &'a Money) -> Result<&'a Money> {
        if a.cmp(b)?.is_lt() {
            Ok(a)
        } else {
            Ok(b)
        }
    }

    /// 返回两同币种金额中较大者。
    pub fn max<'a>(a: &'a Money, b: &'a Money) -> Result<&'a Money> {
        if a.cmp(b)?.is_gt() {
            Ok(a)
        } else {
            Ok(b)
        }
    }

    /// 判断 `a < b`(同币种)。
    pub fn less_than(&self, other: &Money) -> Result<bool> {
        Ok(self.cmp(other)?.is_lt())
    }

    /// 判断 `a > b`(同币种)。
    pub fn greater_than(&self, other: &Money) -> Result<bool> {
        Ok(self.cmp(other)?.is_gt())
    }

    /// 序列化为 JSON 字符串(`"1,234.56 USD"`,带引号)——自描述且经
    /// [`Money::unmarshal_json`]/[`parse_money`] 往返无损。
    pub fn marshal_json(&self) -> String {
        format!("\"{}\"", self)
    }

    /// 解析 money JSON 字符串(见 [`parse_money`])。`null` 输入产生零值
    /// Money(币种未指定,金额为零)。
    pub fn unmarshal_json(data: &str) -> Result<Money> {
        let s = data.trim();
        if s == "null" {
            return Ok(Money::default());
        }
        if s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
            return invalid(format!("money JSON must be a string, got {s}"));
        }
        parse_money(&s[1..s.len() - 1])
    }
}

impl fmt::Display for Money {
    /// 按展示精度渲染金额并后接币种码,如 `"1,234.56 USD"`、`"120 JPY"`。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", format_base(self.base, &self.code), self.code)
    }
}

/// 按展示精度渲染整数账本单位:千分位分组、至少保留币种指数位小数、只有
/// 账本尾数非零时才追加额外账本数字(如亚分 USD 金额的 `"0.001"`、JPY 的
/// `"120"`、带亚圆账本尘的 JPY `"120.05"`)。
pub fn format_base(base: i64, code: &str) -> String {
    let exp = exponent(code);
    let neg = base < 0;
    let v = base.unsigned_abs();
    let int_part = v / BASE_FACTOR as u64;
    let frac4 = (v % BASE_FACTOR as u64) as u32;

    let mut b = String::new();
    if neg {
        b.push('-');
    }
    b.push_str(&group_thousands(int_part as i64));

    if frac4 == 0 {
        if exp > 0 {
            b.push('.');
            for _ in 0..exp {
                b.push('0');
            }
        }
        return b;
    }

    let mut digits = format!("{frac4:04}");
    let min_len = exp.max(1) as usize;
    // 去尾部零但绝不越过非零位(值不变),且不短于指数位精度
    while digits.len() > min_len && digits.ends_with('0') {
        digits.truncate(digits.len() - 1);
    }
    b.push('.');
    b.push_str(&digits);
    b
}

/// 按展示精度渲染 ISO minor units:千分位分组加恰好币种指数位小数
/// (USD → `"1,234.56"`,JPY → `"120"`,KWD → `"1.234"`)。
pub fn format_minor(minor: i64, code: &str) -> String {
    let exp = exponent(code);
    let neg = minor < 0;
    let v = minor.unsigned_abs();
    let factor = 10u64.pow(exp);

    let mut b = String::new();
    if neg {
        b.push('-');
    }
    if exp == 0 {
        b.push_str(&group_thousands(v as i64));
        return b;
    }
    b.push_str(&group_thousands((v / factor) as i64));
    let frac = v % factor;
    b.push('.');
    b.push_str(&format!("{frac:0width$}", width = exp as usize));
    b
}

/// 类似 [`format_minor`] 但前置币种符号(`"$1,234.56"`、`"¥120"`)。字母
/// 符号加空格分隔(`"kr 12.00"`、`"XYZ 12.00"`);图形符号直接贴附。
pub fn format_symbol_minor(minor: i64, code: &str) -> String {
    let sym = symbol(code);
    let needs_space = sym.chars().any(|r| r.is_ascii_alphabetic());
    if needs_space {
        format!("{sym} {}", format_minor(minor, code))
    } else {
        format!("{sym}{}", format_minor(minor, code))
    }
}

// ISO 4217 活跃币种全量表(数字码 + 英文名)与常用符号子表,从上游
// go-utils/currency/meta.go 同源生成(条目按字母序排布,供二分查找)。

static NUMERIC_TABLE: &[(&str, &str)] = &[
    ("AED", "784"),
    ("AFN", "971"),
    ("ALL", "008"),
    ("AMD", "051"),
    ("AOA", "973"),
    ("ARS", "032"),
    ("AUD", "036"),
    ("AWG", "533"),
    ("AZN", "944"),
    ("BAM", "977"),
    ("BBD", "052"),
    ("BDT", "050"),
    ("BHD", "048"),
    ("BIF", "108"),
    ("BMD", "060"),
    ("BND", "096"),
    ("BOB", "068"),
    ("BRL", "986"),
    ("BSD", "044"),
    ("BTN", "064"),
    ("BWP", "072"),
    ("BYN", "933"),
    ("BZD", "084"),
    ("CAD", "124"),
    ("CDF", "976"),
    ("CHE", "947"),
    ("CHF", "756"),
    ("CHW", "948"),
    ("CLF", "990"),
    ("CLP", "152"),
    ("CNY", "156"),
    ("COP", "170"),
    ("COU", "970"),
    ("CRC", "188"),
    ("CUP", "192"),
    ("CVE", "132"),
    ("CZK", "203"),
    ("DJF", "262"),
    ("DKK", "208"),
    ("DOP", "214"),
    ("DZD", "012"),
    ("EGP", "818"),
    ("ERN", "232"),
    ("ETB", "230"),
    ("EUR", "978"),
    ("FJD", "242"),
    ("FKP", "238"),
    ("GBP", "826"),
    ("GEL", "981"),
    ("GHS", "936"),
    ("GIP", "292"),
    ("GMD", "270"),
    ("GNF", "324"),
    ("GTQ", "320"),
    ("GYD", "328"),
    ("HKD", "344"),
    ("HNL", "340"),
    ("HTG", "332"),
    ("HUF", "348"),
    ("IDR", "360"),
    ("ILS", "376"),
    ("INR", "356"),
    ("IQD", "368"),
    ("IRR", "364"),
    ("ISK", "352"),
    ("JMD", "388"),
    ("JOD", "400"),
    ("JPY", "392"),
    ("KES", "404"),
    ("KGS", "417"),
    ("KHR", "116"),
    ("KMF", "174"),
    ("KPW", "408"),
    ("KRW", "410"),
    ("KWD", "414"),
    ("KYD", "136"),
    ("KZT", "398"),
    ("LAK", "418"),
    ("LBP", "422"),
    ("LKR", "144"),
    ("LRD", "430"),
    ("LSL", "426"),
    ("LYD", "434"),
    ("MAD", "504"),
    ("MDL", "498"),
    ("MGA", "969"),
    ("MKD", "807"),
    ("MMK", "104"),
    ("MNT", "496"),
    ("MOP", "446"),
    ("MRU", "929"),
    ("MUR", "480"),
    ("MVR", "462"),
    ("MWK", "454"),
    ("MXN", "484"),
    ("MXV", "979"),
    ("MYR", "458"),
    ("MZN", "943"),
    ("NAD", "516"),
    ("NGN", "566"),
    ("NIO", "558"),
    ("NOK", "578"),
    ("NPR", "524"),
    ("NZD", "554"),
    ("OMR", "512"),
    ("PAB", "590"),
    ("PEN", "604"),
    ("PGK", "598"),
    ("PHP", "608"),
    ("PKR", "586"),
    ("PLN", "985"),
    ("PYG", "600"),
    ("QAR", "634"),
    ("RON", "946"),
    ("RSD", "941"),
    ("RUB", "643"),
    ("RWF", "646"),
    ("SAR", "682"),
    ("SBD", "090"),
    ("SCR", "690"),
    ("SDG", "938"),
    ("SEK", "752"),
    ("SGD", "702"),
    ("SHP", "654"),
    ("SLE", "925"),
    ("SOS", "706"),
    ("SRD", "968"),
    ("SSP", "728"),
    ("STN", "930"),
    ("SVC", "222"),
    ("SYP", "760"),
    ("SZL", "748"),
    ("THB", "764"),
    ("TJS", "972"),
    ("TMT", "934"),
    ("TND", "788"),
    ("TOP", "776"),
    ("TRY", "949"),
    ("TTD", "780"),
    ("TWD", "901"),
    ("TZS", "834"),
    ("UAH", "980"),
    ("UGX", "800"),
    ("USD", "840"),
    ("UYU", "858"),
    ("UZS", "860"),
    ("VED", "926"),
    ("VES", "928"),
    ("VND", "704"),
    ("VUV", "548"),
    ("WST", "882"),
    ("XAF", "950"),
    ("XCD", "951"),
    ("XCG", "532"),
    ("XDR", "960"),
    ("XOF", "952"),
    ("XPF", "953"),
    ("YER", "886"),
    ("ZAR", "710"),
    ("ZMW", "967"),
    ("ZWG", "924"),
];

static NAME_TABLE: &[(&str, &str)] = &[
    ("AED", "United Arab Emirates dirham"),
    ("AFN", "Afghan afghani"),
    ("ALL", "Albanian lek"),
    ("AMD", "Armenian dram"),
    ("AOA", "Angolan kwanza"),
    ("ARS", "Argentine peso"),
    ("AUD", "Australian dollar"),
    ("AWG", "Aruban florin"),
    ("AZN", "Azerbaijani manat"),
    ("BAM", "Bosnia and Herzegovina convertible mark"),
    ("BBD", "Barbados dollar"),
    ("BDT", "Bangladeshi taka"),
    ("BHD", "Bahraini dinar"),
    ("BIF", "Burundian franc"),
    ("BMD", "Bermudian dollar"),
    ("BND", "Brunei dollar"),
    ("BOB", "Boliviano"),
    ("BRL", "Brazilian real"),
    ("BSD", "Bahamian dollar"),
    ("BTN", "Bhutanese ngultrum"),
    ("BWP", "Botswana pula"),
    ("BYN", "Belarusian ruble"),
    ("BZD", "Belize dollar"),
    ("CAD", "Canadian dollar"),
    ("CDF", "Congolese franc"),
    ("CHE", "WIR euro"),
    ("CHF", "Swiss franc"),
    ("CHW", "WIR franc"),
    ("CLF", "Unidad de Fomento"),
    ("CLP", "Chilean peso"),
    ("CNY", "Renminbi"),
    ("COP", "Colombian peso"),
    ("COU", "Unidad de Valor Real"),
    ("CRC", "Costa Rican colon"),
    ("CUP", "Cuban peso"),
    ("CVE", "Cape Verdean escudo"),
    ("CZK", "Czech koruna"),
    ("DJF", "Djiboutian franc"),
    ("DKK", "Danish krone"),
    ("DOP", "Dominican peso"),
    ("DZD", "Algerian dinar"),
    ("EGP", "Egyptian pound"),
    ("ERN", "Eritrean nakfa"),
    ("ETB", "Ethiopian birr"),
    ("EUR", "Euro"),
    ("FJD", "Fiji dollar"),
    ("FKP", "Falkland Islands pound"),
    ("GBP", "Pound sterling"),
    ("GEL", "Georgian lari"),
    ("GHS", "Ghanaian cedi"),
    ("GIP", "Gibraltar pound"),
    ("GMD", "Gambian dalasi"),
    ("GNF", "Guinean franc"),
    ("GTQ", "Guatemalan quetzal"),
    ("GYD", "Guyanese dollar"),
    ("HKD", "Hong Kong dollar"),
    ("HNL", "Honduran lempira"),
    ("HTG", "Haitian gourde"),
    ("HUF", "Hungarian forint"),
    ("IDR", "Indonesian rupiah"),
    ("ILS", "Israeli new shekel"),
    ("INR", "Indian rupee"),
    ("IQD", "Iraqi dinar"),
    ("IRR", "Iranian rial"),
    ("ISK", "Icelandic krona"),
    ("JMD", "Jamaican dollar"),
    ("JOD", "Jordanian dinar"),
    ("JPY", "Japanese yen"),
    ("KES", "Kenyan shilling"),
    ("KGS", "Kyrgyzstani som"),
    ("KHR", "Cambodian riel"),
    ("KMF", "Comoro franc"),
    ("KPW", "North Korean won"),
    ("KRW", "South Korean won"),
    ("KWD", "Kuwaiti dinar"),
    ("KYD", "Cayman Islands dollar"),
    ("KZT", "Kazakhstani tenge"),
    ("LAK", "Lao kip"),
    ("LBP", "Lebanese pound"),
    ("LKR", "Sri Lankan rupee"),
    ("LRD", "Liberian dollar"),
    ("LSL", "Lesotho loti"),
    ("LYD", "Libyan dinar"),
    ("MAD", "Moroccan dirham"),
    ("MDL", "Moldovan leu"),
    ("MGA", "Malagasy ariary"),
    ("MKD", "Macedonian denar"),
    ("MMK", "Myanmar kyat"),
    ("MNT", "Mongolian togrog"),
    ("MOP", "Macanese pataca"),
    ("MRU", "Mauritanian ouguiya"),
    ("MUR", "Mauritian rupee"),
    ("MVR", "Maldivian rufiyaa"),
    ("MWK", "Malawian kwacha"),
    ("MXN", "Mexican peso"),
    ("MXV", "Mexican Unidad de Inversion"),
    ("MYR", "Malaysian ringgit"),
    ("MZN", "Mozambican metical"),
    ("NAD", "Namibian dollar"),
    ("NGN", "Nigerian naira"),
    ("NIO", "Nicaraguan cordoba"),
    ("NOK", "Norwegian krone"),
    ("NPR", "Nepalese rupee"),
    ("NZD", "New Zealand dollar"),
    ("OMR", "Omani rial"),
    ("PAB", "Panamanian balboa"),
    ("PEN", "Peruvian sol"),
    ("PGK", "Papua New Guinean kina"),
    ("PHP", "Philippine peso"),
    ("PKR", "Pakistani rupee"),
    ("PLN", "Polish zloty"),
    ("PYG", "Paraguayan guarani"),
    ("QAR", "Qatari riyal"),
    ("RON", "Romanian leu"),
    ("RSD", "Serbian dinar"),
    ("RUB", "Russian ruble"),
    ("RWF", "Rwandan franc"),
    ("SAR", "Saudi riyal"),
    ("SBD", "Solomon Islands dollar"),
    ("SCR", "Seychelles rupee"),
    ("SDG", "Sudanese pound"),
    ("SEK", "Swedish krona"),
    ("SGD", "Singapore dollar"),
    ("SHP", "Saint Helena pound"),
    ("SLE", "Sierra Leonean leone"),
    ("SOS", "Somali shilling"),
    ("SRD", "Surinamese dollar"),
    ("SSP", "South Sudanese pound"),
    ("STN", "Sao Tome and Principe dobra"),
    ("SVC", "Salvadoran colon"),
    ("SYP", "Syrian pound"),
    ("SZL", "Swazi lilangeni"),
    ("THB", "Thai baht"),
    ("TJS", "Tajikistani somoni"),
    ("TMT", "Turkmenistani manat"),
    ("TND", "Tunisian dinar"),
    ("TOP", "Tongan paanga"),
    ("TRY", "Turkish lira"),
    ("TTD", "Trinidad and Tobago dollar"),
    ("TWD", "New Taiwan dollar"),
    ("TZS", "Tanzanian shilling"),
    ("UAH", "Ukrainian hryvnia"),
    ("UGX", "Ugandan shilling"),
    ("USD", "United States dollar"),
    ("UYU", "Uruguayan peso"),
    ("UZS", "Uzbekistani sum"),
    ("VED", "Venezuelan digital bolivar"),
    ("VES", "Venezuelan sovereign bolivar"),
    ("VND", "Vietnamese dong"),
    ("VUV", "Vanuatu vatu"),
    ("WST", "Samoan tala"),
    ("XAF", "CFA franc BEAC"),
    ("XCD", "East Caribbean dollar"),
    ("XCG", "Caribbean guilder"),
    ("XDR", "Special drawing rights"),
    ("XOF", "CFA franc BCEAO"),
    ("XPF", "CFP franc"),
    ("YER", "Yemeni rial"),
    ("ZAR", "South African rand"),
    ("ZMW", "Zambian kwacha"),
    ("ZWG", "Zimbabwe Gold"),
];

static SYMBOL_TABLE: &[(&str, &str)] = &[
    ("AUD", "A$"),
    ("BRL", "R$"),
    ("CAD", "C$"),
    ("CHF", "CHF"),
    ("CLP", "$"),
    ("CNY", "¥"),
    ("DKK", "kr"),
    ("EUR", "€"),
    ("GBP", "£"),
    ("HKD", "HK$"),
    ("IDR", "Rp"),
    ("INR", "₹"),
    ("ISK", "kr"),
    ("JPY", "¥"),
    ("KRW", "₩"),
    ("KWD", "KWD"),
    ("MXN", "$"),
    ("MYR", "RM"),
    ("NOK", "kr"),
    ("NZD", "NZ$"),
    ("OMR", "OMR"),
    ("PHP", "₱"),
    ("PLN", "zł"),
    ("RUB", "₽"),
    ("SEK", "kr"),
    ("SGD", "S$"),
    ("THB", "฿"),
    ("TRY", "₺"),
    ("TWD", "NT$"),
    ("USD", "$"),
    ("VND", "₫"),
];

#[cfg(test)]
mod tests;
