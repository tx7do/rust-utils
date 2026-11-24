//! 币种金额换算与 Money 类型。
//!
//! 运行:`cargo run --example currency`(零依赖,默认 feature 即可)

use rust_utils::currency::{self, Money};

fn main() {
    // 1. 两层单位:ISO minor units(分,按币种指数)与定精度账本单位(统一
    //    4 位小数,与币种指数解耦)
    println!(
        "to_minor(0.3, \"USD\")   = {:>6} 分",
        currency::to_minor(0.3, "USD")
    );
    println!(
        "to_minor(120, \"JPY\")   = {:>6} 円(0 位币种)",
        currency::to_minor(120.0, "JPY")
    );
    println!(
        "to_minor(0.125, \"KWD\") = {:>6} fils(3 位币种)",
        currency::to_minor(0.125, "KWD")
    );
    println!(
        "to_base(1.2345)        = {:>6} 账本单位",
        currency::to_base(1.2345)
    );
    println!(
        "minor_to_base(30, \"USD\") = {:>4}(2 位币种 ×100,留两位保护位)",
        currency::minor_to_base(30, "USD")
    );

    // 2. Money:整数账本域算术,币种不匹配即报错、溢出 fail-fast
    let price = Money::from_minor("USD", 399); // 3.99
    let total = price.mul(5).unwrap();
    println!("\n3.99 × 5 = {total}(Display 输出自带币种)");

    let fee = total.percent(250).unwrap(); // 2.5% 手续费
    println!("2.5% 手续费 = {fee}");

    assert!(
        price.add(&Money::from_minor("EUR", 1)).is_err(),
        "跨币种运算必须拒绝"
    );

    // 3. Fowler 式精确守恒分配:100 分拆 3 份,余数落最大比例档
    let parts = Money::from_minor("USD", 100).split(3).unwrap();
    let bases: Vec<i64> = parts.iter().map(|p| p.base()).collect();
    println!(
        "100 分拆 3 份(账本单位): {bases:?},总和 = {}",
        parts.iter().map(|p| p.base()).sum::<i64>()
    );
    assert_eq!(parts.iter().map(|p| p.base()).sum::<i64>(), 10000);

    // 4. 整数域精确汇率:USD 100¢ → JPY at 150/1,全程无浮点
    let jpy = currency::convert_minor_exact(100, "USD", "JPY", 150, 1).unwrap();
    println!("\nUSD 1.00 → JPY @150 = {jpy} 円");
    let fils = currency::convert_minor_exact(100, "USD", "KWD", 3, 10).unwrap();
    println!("USD 1.00 → KWD @0.30 = {fils} fils(指数差吸收)");

    // 5. 格式化与解析:字符串往返无损
    let m = Money::from_base("USD", 12345678); // 1234.5678
    let s = m.to_string();
    let back = currency::parse_money(&s).unwrap();
    println!("\nformat → parse 往返: {s:?} → base {}", back.base());
    assert_eq!(back.base(), m.base());
    println!(
        "符号格式:$1,234.56 = {}",
        currency::format_symbol_minor(123456, "USD")
    );
    println!("JPY 格式:120 = {}", currency::format_minor(120, "JPY"));

    // 6. ISO 元数据:全量活跃码表(数字码 + 英文名 + 常用符号)
    let info = currency::lookup_info("jpy");
    println!(
        "\nJPY = {} / {} / {} / {}",
        info.code, info.numeric, info.symbol, info.name
    );
}
