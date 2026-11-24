//! 对位上游 go-utils/currency 全部测试(currency_test / money_test /
//! money_json_test),含溢出检测、JSON 往返与格式→解析属性测试。

use super::*;

// ============================================================
// 归一化与指数
// ============================================================

#[test]
fn test_normalize() {
    assert_eq!(normalize("usd"), "USD");
    assert_eq!(normalize("  jpy "), "JPY");
    assert_eq!(normalize(""), "", "unspecified stays empty");
    assert_eq!(normalize("   "), "");
}

#[test]
fn test_normalize_or() {
    assert_eq!(normalize_or("", "USD"), "USD");
    assert_eq!(normalize_or("eur ", "USD"), "EUR");
}

#[test]
fn test_exponent() {
    let cases = [
        ("", 2),           // 未指定 → 2(缺省档)
        ("USD", 2),        // 主流 2 位,不在表内 → 缺省
        ("CNY", 2),        //
        ("EUR", 2),        //
        ("JPY", 0),        // 0 位档
        ("KRW", 0),        //
        ("VND", 0),        //
        ("CLP", 0),        //
        ("KWD", 3),        // 3 位档
        ("BHD", 3),        //
        ("OMR", 3),        //
        ("usd", 2),        // 大小写归一
        (" jpy ", 0),      // 空白归一
        ("XXX", 2),        // 未知码 → 2
        ("CUSTOMCOIN", 2), // 未列码 → 2
    ];
    for (code, want) in cases {
        assert_eq!(exponent(code), want, "Exponent({code:?})");
    }
}

#[test]
fn test_factor() {
    assert_eq!(factor(""), 100.0);
    assert_eq!(factor("USD"), 100.0);
    assert_eq!(factor("JPY"), 1.0);
    assert_eq!(factor("KWD"), 1000.0);
}

// ============================================================
// 两层单位换算
// ============================================================

#[test]
fn test_to_minor() {
    // 2 位:0.3 主单位 = 30 minor;浮点尾差必须被 round 吸收(经典的
    // 0.29 截断 bug)
    assert_eq!(to_minor(0.3, "USD"), 30);
    assert_eq!(to_minor(0.29, "USD"), 29);
    assert_eq!(to_minor(100.0, "CNY"), 10000);
    // 0 位:1 单位仍是 1
    assert_eq!(to_minor(120.0, "JPY"), 120);
    assert_eq!(to_minor(7.3, "KRW"), 7);
    // 3 位
    assert_eq!(to_minor(0.125, "KWD"), 125);
    // 负数(退款):对称,half away from zero
    assert_eq!(to_minor(-0.3, "USD"), -30);
    assert_eq!(to_minor(-0.005, "USD"), -1);
}

#[test]
fn test_to_major() {
    assert_eq!(to_major(160, "USD"), 1.6);
    assert_eq!(to_major(120, "JPY"), 120.0);
    assert_eq!(to_major(125, "KWD"), 0.125);
    assert!((to_major(998976, "USD") - 9989.76).abs() < 1e-9);
}

#[test]
fn test_to_major_int() {
    // 与整数除法同语义(向零截断)
    assert_eq!(to_major_int(9999, "USD"), 99);
    assert_eq!(to_major_int(120, "JPY"), 120);
    assert_eq!(to_major_int(-150, "USD"), -1);
}

/// minor → major → minor 必须无损(金额守恒的地基)。
#[test]
fn test_to_minor_to_major_round_trip() {
    for code in ["USD", "JPY", "KWD"] {
        for units in [1i64, 29, 100, 998976, 1 << 40] {
            assert_eq!(
                to_minor(to_major(units, code), code),
                units,
                "round trip {code} {units}"
            );
        }
    }
}

#[test]
fn test_to_base() {
    // 完整 4 位精度
    assert_eq!(to_base(0.0001), 1);
    assert_eq!(to_base(1.2345), 12345);
    assert_eq!(to_base(0.003), 30);
    assert_eq!(to_base(1.0), 10000);
    // 浮点尾差由 round 吸收
    assert_eq!(to_base(0.2999 - 1e-13), 2999);
    // 负数:对称,half away from zero
    assert_eq!(to_base(-0.0001), -1);
    assert_eq!(to_base(-0.5), -5000);
}

#[test]
fn test_from_base() {
    assert_eq!(from_base(12345), 1.2345);
    assert_eq!(from_base(1), 0.0001);
}

/// ledger → major → ledger 必须无损。
#[test]
fn test_base_round_trip() {
    for units in [1i64, 29, 100, 12345, 99897600, 1 << 40] {
        assert_eq!(to_base(from_base(units)), units, "round trip {units}");
    }
}

#[test]
fn test_from_base_int() {
    // 向零截断,与 to_major_int 同语义
    assert_eq!(from_base_int(12345), 1);
    assert_eq!(from_base_int(9999), 0);
    assert_eq!(from_base_int(-1), 0);
}

#[test]
fn test_minor_base_conversion() {
    // 2 位:minor ↔ ledger = ×100(两位保护位)
    assert_eq!(minor_to_base(30, "USD"), 3000);
    assert_eq!(base_to_minor(3000, "CNY"), 30);
    // 0 位(JPY):unit ↔ ledger = ×1e4
    assert_eq!(
        minor_to_base(120, "JPY"),
        1200000,
        "120 units = 120e4 ledger"
    );
    assert_eq!(base_to_minor(1200000, "JPY"), 120);
    // 3 位(KWD):fils ↔ ledger = ×10
    assert_eq!(minor_to_base(1, "KWD"), 10, "1 fils = 10 ledger");
    assert_eq!(base_to_minor(10, "KWD"), 1);
    // BaseToMinor 截断:5 ledger = 0.5 fils,签发到 minor 边界时丢弃
    // (内部记账不会经过这里)
    assert_eq!(base_to_minor(5, "KWD"), 0);
    // 无损往返(ledger → minor → ledger,整 minor 倍数)
    for units in [100i64, 1000, 3000, 1200000] {
        assert_eq!(
            minor_to_base(base_to_minor(units, "USD"), "USD"),
            units,
            "round trip USD {units}"
        );
    }
}

// ============================================================
// Money 构造与单位回拉
// ============================================================

#[test]
fn test_money_constructors() {
    let m = Money::from_minor("USD", 1234);
    assert_eq!(m.base(), 123400, "1234 分 = 1234×100 账本单位");
    assert_eq!(m.minor(), 1234);

    let m = Money::from_base("USD", 12345678); // 1234.5678
    assert!((m.major() - 1234.5678).abs() < 1e-9);
    assert_eq!(m.minor(), 123456, "Minor 向零截断(丢毫厘位)");

    let m = Money::from_major("JPY", 120.0);
    assert_eq!(m.base(), 1200000, "1 圆 = 1e4 账本单位");
    assert_eq!(m.minor(), 120);

    // 币种码归一 + 缺省回退
    assert_eq!(Money::from_major(" usd ", 1.0).code(), "USD");
    assert_eq!(Money::new("").code(), "USD");
}

// ============================================================
// 算术与比较
// ============================================================

#[test]
fn test_money_arithmetic() {
    let a = Money::from_minor("USD", 1000);
    let b = Money::from_minor("USD", 250);

    let sum = a.add(&b).unwrap();
    assert_eq!(sum.minor(), 1250);

    let diff = a.sub(&b).unwrap();
    assert_eq!(diff.minor(), 750);

    // 币种不匹配必须拒绝
    assert!(matches!(
        a.add(&Money::from_minor("EUR", 1)),
        Err(Error::Mismatch { .. })
    ));
    assert!(matches!(
        a.cmp(&Money::from_minor("EUR", 1)),
        Err(Error::Mismatch { .. })
    ));

    assert_eq!(a.cmp(&b).unwrap(), std::cmp::Ordering::Greater);

    assert!(a.is_positive());
    assert!(Money::from_minor("USD", 0).is_zero());

    let neg = b.sub(&a).unwrap();
    assert!(neg.is_negative());
    let abs = neg.abs();
    assert_eq!(abs.minor(), 750);
    assert_eq!(neg.minor(), -750);
}

#[test]
fn test_money_mul() {
    let unit = Money::from_minor("USD", 399); // 3.99
    let mul = unit.mul(5).unwrap();
    assert_eq!(mul.minor(), 1995, "3.99 × 5");
}

// ============================================================
// Allocate / Split(Fowler Money 分配)
// ============================================================

#[test]
fn test_money_allocate() {
    // 经典用例:100 分拆 3 份等比 → 账本单位 3334/3333/3333(余数进最大
    // 比例档),守恒不变量在账本单位域精确成立
    let m = Money::from_minor("USD", 100);
    let parts = m.split(3).unwrap();
    let got: i64 = parts.iter().map(|p| p.base()).sum();
    assert_eq!(got, m.base(), "拆分总和必须守恒(账本单位域)");
    assert_eq!(parts[0].base(), 3333);
    assert_eq!(parts[2].base(), 3334, "累计截断法余数自然落尾位");

    // 按比例 1:2
    let parts = Money::from_minor("USD", 300).allocate(&[1, 2]).unwrap();
    assert_eq!(parts[0].minor(), 100);
    assert_eq!(parts[1].minor(), 200);

    // 负数对称分配且守恒
    let parts = Money::from_minor("USD", -100).split(3).unwrap();
    let got: i64 = parts.iter().map(|p| p.base()).sum();
    assert_eq!(got, -10000);

    // 账本单位全精度拆分(分下精度不丢)
    let parts = Money::from_base("USD", 10001).split(2).unwrap();
    let got: i64 = parts.iter().map(|p| p.base()).sum();
    assert_eq!(got, 10001);

    // 非法入参
    assert!(m.split(0).is_err());
    assert!(m.allocate(&[]).is_err());
    assert!(m.allocate(&[0, 0]).is_err());
    assert!(m.allocate(&[1, -1]).is_err());
}

// ============================================================
// 格式化
// ============================================================

#[test]
fn test_format_minor() {
    assert_eq!(format_minor(123456, "USD"), "1,234.56");
    assert_eq!(format_minor(-123456, "USD"), "-1,234.56");
    assert_eq!(format_minor(29, "USD"), "0.29");
    assert_eq!(format_minor(120, "JPY"), "120", "0 位币种无小数点");
    assert_eq!(format_minor(1234, "KRW"), "1,234");
    assert_eq!(format_minor(1234, "KWD"), "1.234", "3 位小数");
    assert_eq!(format_minor(1200, "EUR"), "12.00");
}

#[test]
fn test_format_base() {
    // 指数位精度为下限;毫厘位非零则保留
    assert_eq!(format_base(12345600, "USD"), "1,234.56");
    assert_eq!(format_base(12345678, "USD"), "1,234.5678");
    assert_eq!(
        format_base(10, "USD"),
        "0.001",
        "亚分精度保留(base=10 = 0.001)"
    );
    assert_eq!(format_base(1200000, "JPY"), "120");
    assert_eq!(format_base(-5000, "USD"), "-0.50");
    assert_eq!(format_base(12345, "KWD"), "1.2345");
}

#[test]
fn test_format_symbol_minor() {
    assert_eq!(format_symbol_minor(123456, "USD"), "$1,234.56");
    assert_eq!(format_symbol_minor(120, "JPY"), "¥120");
    assert_eq!(format_symbol_minor(1200, "EUR"), "€12.00");
    assert_eq!(
        format_symbol_minor(1200, "XYZ"),
        "XYZ 12.00",
        "未知币种以码为符号"
    );
}

#[test]
fn test_money_string() {
    assert_eq!(Money::from_minor("USD", 123456).to_string(), "1,234.56 USD");
    assert_eq!(Money::from_minor("JPY", 120).to_string(), "120 JPY");
    assert_eq!(
        Money::from_base("USD", 12345678).to_string(),
        "1,234.5678 USD"
    );
}

// ============================================================
// ISO 元数据
// ============================================================

#[test]
fn test_meta() {
    let info = lookup_info("USD");
    assert_eq!(info.numeric, "840");
    assert_eq!(info.symbol, "$");

    assert_eq!(symbol("JPY"), "¥");
    assert_eq!(symbol("XYZ"), "XYZ", "未知币种符号回退为码");
    assert_eq!(numeric_code("EUR"), "978");
    assert_eq!(numeric_code("XYZ"), "");
    assert_eq!(display_name("jpy"), "Japanese yen");
    assert!(is_known("USD"));
    assert!(!is_known("XYZ"));
    // 数字码反查与全量表完整性
    assert_eq!(code_from_numeric("840"), "USD");
    assert_eq!(code_from_numeric("392"), "JPY");
    assert_eq!(code_from_numeric("000"), "");
    assert_eq!(NUMERIC_TABLE.len(), NAME_TABLE.len());
}

// ============================================================
// 汇率换算
// ============================================================

#[test]
fn test_convert_minor() {
    // USD 100 分 × 150 = 150 JPY(大额零头由各币种指数吸收)
    let out = convert_minor(100, "USD", "JPY", 150.0).unwrap();
    assert_eq!(out, 150);

    // rate=1 且同指数 → 恒等
    let out = convert_minor(1234, "USD", "EUR", 1.0).unwrap();
    assert_eq!(out, 1234);

    // 指数差吸收:USD → KWD rate 0.30:1.00 USD = 0.30 KWD = 300 fils
    let out = convert_minor(100, "USD", "KWD", 0.3).unwrap();
    assert_eq!(out, 300);

    // 非法汇率
    assert!(convert_minor(1, "USD", "EUR", 0.0).is_err());
    assert!(convert_minor(1, "USD", "EUR", -1.5).is_err());
    assert!(convert_minor(1, "USD", "EUR", f64::NAN).is_err());
}

#[test]
fn test_convert_base() {
    let out = convert_base(10000, "USD", "JPY", 150.0).unwrap(); // 1.00 USD
    assert_eq!(out, 1500000, "150 JPY = 150e4 账本单位");
}

// ============================================================
// 舍入策略
// ============================================================

#[test]
fn test_rounding_variants() {
    // 缺省 half away from zero
    assert_eq!(to_minor(0.3, "USD"), 30);
    // floor / ceil
    assert_eq!(to_minor_floor(0.2999, "USD"), 29);
    assert_eq!(to_minor_ceil(0.2999, "USD"), 30);
    assert_eq!(to_minor_floor(-0.2999, "USD"), -30, "floor 向 -inf");
    assert_eq!(to_minor_ceil(-0.2999, "USD"), -29, "ceil 向 +inf");
    assert_eq!(to_base_floor(0.00015), 1);
    assert_eq!(to_base_ceil(0.00015), 2);
}

// ============================================================
// Parse(Format 反向)
// ============================================================

#[test]
fn test_parse_money_roundtrip() {
    // Money::to_string → parse_money 必须无损往返
    let cases = [
        Money::from_minor("USD", 123456),
        Money::from_minor("JPY", 120),
        Money::from_base("USD", 12345678),
        Money::from_minor("KWD", 1234),
        Money::from_minor("USD", -9876),
    ];
    for m in cases {
        let parsed = parse_money(&m.to_string())
            .unwrap_or_else(|e| panic!("parse {:?}: {e}", m.to_string()));
        assert_eq!(parsed.code(), m.code());
        assert_eq!(parsed.base(), m.base(), "roundtrip {}", m);
    }
}

#[test]
fn test_parse_minor_variants() {
    let out = parse_minor("1,234.56", "USD").unwrap();
    assert_eq!(out, 123456);

    let parsed = parse_money("$1,234.56 USD").unwrap();
    assert_eq!(parsed.minor(), 123456, "符号前缀剥离走 parse_money");

    let out = parse_minor("-0.5", "USD").unwrap();
    assert_eq!(out, -50);

    // 亚分位拒绝(不静默舍入)
    assert!(parse_minor("0.001", "USD").is_err());

    // 0 位币种拒绝小数
    assert!(parse_minor("120.5", "JPY").is_err());

    let out = parse_minor("120", "JPY").unwrap();
    assert_eq!(out, 120);
}

#[test]
fn test_code_from_symbol() {
    assert_eq!(code_from_symbol("$"), "USD");
    assert_eq!(code_from_symbol("¥"), "CNY", "歧义符号取字典序首个");
    assert_eq!(code_from_symbol("€"), "EUR");
    assert_eq!(code_from_symbol("¤"), "", "未知符号返回空");
}

// ============================================================
// 整数域精确汇率 / 比例乘法
// ============================================================

#[test]
fn test_convert_minor_exact() {
    let out = convert_minor_exact(100, "USD", "JPY", 150, 1).unwrap();
    assert_eq!(out, 150);

    let out = convert_minor_exact(100, "USD", "KWD", 3, 10).unwrap();
    assert_eq!(out, 300);

    // 0 位币种吸收:101¢ × 1.50 = 1.515 JPY → 2 JPY minor(half away)
    let out = convert_minor_exact(101, "USD", "JPY", 150, 100).unwrap();
    assert_eq!(out, 2, "JPY 0 位小数吸收小数结果");

    assert!(convert_minor_exact(1, "USD", "EUR", 1, 0).is_err());
}

#[test]
fn test_money_mul_ratio_and_percent() {
    let m = Money::from_minor("USD", 1000);

    // 2.5% 手续费:1000 × 25/1000 = 25
    let fee = m.mul_ratio(25, 1000).unwrap();
    assert_eq!(fee.minor(), 25);

    let pct = m.percent(250).unwrap(); // 250% = 2.5 倍
    assert_eq!(pct.minor(), 2500);

    // 零除拒绝
    assert!(m.mul_ratio(1, 0).is_err());
}

// ============================================================
// 聚合 / 比较 / 归整
// ============================================================

#[test]
fn test_money_aggregates() {
    let a = Money::from_minor("USD", 100);
    let b = Money::from_minor("USD", 300);

    let sum = Money::sum(&[a.clone(), b.clone(), Money::from_minor("USD", 50)]).unwrap();
    assert_eq!(sum.minor(), 450);

    assert!(Money::sum(&[a.clone(), Money::from_minor("EUR", 1)]).is_err());

    let min = Money::min(&a, &b).unwrap();
    assert_eq!(min.minor(), 100);

    let max = Money::max(&a, &b).unwrap();
    assert_eq!(max.minor(), 300);

    assert!(a.less_than(&b).unwrap());
    assert!(b.greater_than(&a).unwrap());
}

#[test]
fn test_money_round_to_minor() {
    // 分配产生亚分尘 → round_to_minor 归整到展示精度
    let parts = Money::from_minor("USD", 100).split(3).unwrap();
    let dusty = Money::from_base("USD", parts[0].base()); // 3333 账本 = 0.3333
    let rounded = dusty.round_to_minor();
    assert_eq!(rounded.minor(), 33);
    assert_eq!(rounded.base(), 3300, "亚分尘被归整");
}

// ============================================================
// 溢出检查
// ============================================================

#[test]
fn test_money_overflow_detection() {
    let huge = Money::from_base("USD", i64::MAX / 2 + 1);
    assert!(
        matches!(huge.add(&huge), Err(Error::Overflow(_))),
        "正溢出必须报错而非回绕"
    );

    let min_v = Money::from_base("USD", i64::MIN);
    assert!(
        matches!(
            min_v.sub(&Money::from_base("USD", 1)),
            Err(Error::Overflow(_))
        ),
        "负向下溢必须报错"
    );

    assert!(Money::from_base("USD", i64::MAX / 2).mul(4).is_err());

    // 正常运算不受影响
    let ok = Money::from_base("USD", 100)
        .add(&Money::from_base("USD", 200))
        .unwrap();
    assert_eq!(ok.base(), 300);
}

// ============================================================
// JSON 序列化
// ============================================================

#[test]
fn test_money_json() {
    let m = Money::from_minor("USD", 123456);
    let raw = m.marshal_json();
    assert_eq!(raw, r#""1,234.56 USD""#);

    let back = Money::unmarshal_json(&raw).unwrap();
    assert_eq!(back.base(), m.base());
    assert_eq!(back.code(), m.code());

    // null → 零值
    let null_back = Money::unmarshal_json("null").unwrap();
    assert!(null_back.is_zero());

    // 非字符串类型拒绝
    assert!(Money::unmarshal_json("123").is_err());
}

// ============================================================
// fuzz 种子形态的属性检查(确定性快速版)
// ============================================================

#[test]
fn test_money_format_parse_property() {
    // 伪随机(LCG,固定种子)base × 已知/未知币种:format → parse 必须还原
    let codes = ["USD", "JPY", "KWD", "XYZ", "EUR", ""];
    let mut state: u64 = 42;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state >> 16
    };
    for i in 0..2000u32 {
        let base = (next() as i64) - (1i64 << 62);
        let code = codes[(next() as usize) % codes.len()];
        let m = Money::from_base(code, base);
        let parsed = parse_money(&m.to_string())
            .unwrap_or_else(|e| panic!("seed {i} str {:?}: {e}", m.to_string()));
        assert_eq!(parsed.base(), base, "seed {i}");
        assert_eq!(parsed.code(), m.code(), "seed {i}");
    }
}
