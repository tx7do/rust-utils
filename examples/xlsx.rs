//! Excel 读写:行式构建导出 + 读回(导入对账场景)。
//!
//! 运行:`cargo run --features xlsx --example xlsx`

use rust_utils::xlsx::{self, SheetOut, XlsxValue};

fn main() {
    // 导出:两张表(表头 + 数据;Empty 留空单元格)
    let mut users = SheetOut::new("用户");
    users.push_header(vec!["姓名".into(), "年龄".into(), "激活".into()]);
    users.push_row(vec!["小明".into(), 18i64.into(), true.into()]);
    users.push_row(vec!["小红".into(), 20i64.into(), false.into()]);
    users.push_row(vec!["小刚".into(), XlsxValue::Empty, true.into()]);

    let mut orders = SheetOut::new("订单");
    orders.push_header(vec!["单号".into(), "金额".into()]);
    orders.push_row(vec!["A-001".into(), 19.99.into()]);
    orders.push_row(vec!["A-002".into(), 128.0.into()]);

    let bytes = xlsx::write_to_bytes(&[users, orders]).unwrap();
    std::fs::write("demo.xlsx", &bytes).unwrap();
    println!("written demo.xlsx({} bytes)", bytes.len());

    // 导入:读回全部表 / 按名读 / 读第一张
    let sheets = xlsx::read_all(&bytes).unwrap();
    for s in &sheets {
        println!(
            "sheet `{}`: {} rows × {} cols",
            s.name,
            s.nrows(),
            s.ncols()
        );
    }
    let orders = xlsx::read_sheet(&bytes, "订单").unwrap();
    assert_eq!(orders.cell(1, 1).as_f64(), Some(19.99));
    assert_eq!(orders.cell(2, 1).as_i64(), Some(128)); // 整数浮点通吃
    assert!(orders.cell(9, 9).is_empty()); // 越界安全

    println!("OK");
}
