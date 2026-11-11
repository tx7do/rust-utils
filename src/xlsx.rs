//! Excel(xlsx)读写(feature `xlsx`):`calamine` 读 + `rust_xlsxwriter` 写。
//!
//! 与 printrender 的 PDF 报表是一对:后台导出 Excel、导入对账。读侧把
//! `calamine` 的 `Data` 收窄为稳定枚举 [`Cell`](日期只保留串行数/ISO 原文,
//! 不引入时间库依赖);写侧行式构建、稀疏留空。整链路「写出 → 读回」
//! 在本模块内闭环可测。
//!
//! ```
//! use rust_utils::xlsx::{self, SheetOut, XlsxValue};
//!
//! let mut sheet = SheetOut::new("用户");
//! sheet.push_row(vec![XlsxValue::from("姓名"), XlsxValue::from("分数")]);
//! sheet.push_row(vec![XlsxValue::from("小明"), XlsxValue::from(96.5)]);
//!
//! let bytes = xlsx::write_to_bytes(&[sheet]).unwrap();
//! let sheets = xlsx::read_all(&bytes).unwrap();
//! assert_eq!(sheets.len(), 1);
//! assert_eq!(sheets[0].name, "用户");
//! assert_eq!(sheets[0].cell(1, 1).as_f64(), Some(96.5));
//! ```

use calamine::{Data, Reader, Xlsx};
use rust_xlsxwriter::Workbook;

/// 读侧单元格值的稳定形态(对 `calamine::Data` 的收窄)。
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Empty,
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    /// Excel 错误值(`#DIV/0!`、`#REF!` 等,Display 文本)。
    Err(String),
    /// 日期/时间:Excel 串行数(1900 纪元浮点)或 ISO 8601 原文——
    /// 本 crate 不做日历换算,需要强类型时间由调用方处理。
    DateTime(String),
}

impl Cell {
    /// 文本形态(错误值与 ISO 日期不在此列)。
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Cell::Str(s) => Some(s),
            _ => None,
        }
    }

    /// 浮点形态(Int 视作浮点)。
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Cell::Int(n) => Some(*n as f64),
            Cell::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// 整数形态:整型直取;浮点无小数部分且在 i64 值域内才接受
    /// (Excel 一律以浮点存数,读回 `42` 可能是 `Int` 也可能是 `Float`)。
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Cell::Int(n) => Some(*n),
            Cell::Float(f)
                if f.fract() == 0.0 && *f >= i64::MIN as f64 && *f <= i64::MAX as f64 =>
            {
                Some(*f as i64)
            }
            _ => None,
        }
    }

    /// 布尔形态。
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Cell::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// 是否空单元格。
    pub fn is_empty(&self) -> bool {
        matches!(self, Cell::Empty)
    }
}

const EMPTY_CELL: Cell = Cell::Empty;

/// 一张工作表:名字 + 行主序单元格(读侧产出)。
#[derive(Debug, Clone, PartialEq)]
pub struct Sheet {
    pub name: String,
    pub rows: Vec<Vec<Cell>>,
}

impl Sheet {
    /// 取单元格,越界(含空表)返回 [`Cell::Empty`] 引用。
    pub fn cell(&self, row: usize, col: usize) -> &Cell {
        self.rows
            .get(row)
            .and_then(|r| r.get(col))
            .unwrap_or(&EMPTY_CELL)
    }

    /// 行数。
    pub fn nrows(&self) -> usize {
        self.rows.len()
    }

    /// 最大列数(行不等长时取最大)。
    pub fn ncols(&self) -> usize {
        self.rows.iter().map(Vec::len).max().unwrap_or(0)
    }
}

fn map_data(d: &Data) -> Cell {
    match d {
        Data::Empty => Cell::Empty,
        Data::Int(n) => Cell::Int(*n),
        Data::Float(f) => Cell::Float(*f),
        Data::String(s) => Cell::Str(s.clone()),
        Data::Bool(b) => Cell::Bool(*b),
        Data::Error(e) => Cell::Err(e.to_string()),
        Data::DateTime(dt) => Cell::DateTime(dt.as_f64().to_string()),
        Data::DateTimeIso(s) | Data::DurationIso(s) => Cell::DateTime(s.clone()),
    }
}

fn read_workbook(bytes: &[u8]) -> Result<Xlsx<std::io::Cursor<&[u8]>>, String> {
    let cursor = std::io::Cursor::new(bytes);
    Xlsx::new(cursor).map_err(|e| format!("xlsx read: open failed: {e}"))
}

/// 读出工作簿全部工作表(保持文件内的表顺序)。
pub fn read_all(bytes: &[u8]) -> Result<Vec<Sheet>, String> {
    let mut wb = read_workbook(bytes)?;
    let names = wb.sheet_names();
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        out.push(read_range(&mut wb, &name)?);
    }
    Ok(out)
}

/// 按名读一张表;不存在时报错。
pub fn read_sheet(bytes: &[u8], name: &str) -> Result<Sheet, String> {
    let mut wb = read_workbook(bytes)?;
    read_range(&mut wb, name)
}

/// 读第一张表(常规导出/导入的快捷入口)。
pub fn read_first(bytes: &[u8]) -> Result<Sheet, String> {
    let mut wb = read_workbook(bytes)?;
    let name = wb
        .sheet_names()
        .into_iter()
        .next()
        .ok_or_else(|| "xlsx read: workbook has no sheets".to_string())?;
    read_range(&mut wb, &name)
}

fn read_range(wb: &mut Xlsx<std::io::Cursor<&[u8]>>, name: &str) -> Result<Sheet, String> {
    let range = wb
        .worksheet_range(name)
        .map_err(|e| format!("xlsx read: sheet `{name}`: {e}"))?;
    let rows = range
        .rows()
        .map(|row| row.iter().map(map_data).collect())
        .collect();
    Ok(Sheet {
        name: name.to_string(),
        rows,
    })
}

// ---------------------------------------------------------------------------
// 写侧:行式构建 → 字节
// ---------------------------------------------------------------------------

/// 写侧单元格值。
#[derive(Debug, Clone, PartialEq)]
pub enum XlsxValue {
    Str(String),
    Float(f64),
    Int(i64),
    Bool(bool),
    /// 留空(不写该单元格)。
    Empty,
}

impl From<&str> for XlsxValue {
    fn from(s: &str) -> Self {
        XlsxValue::Str(s.to_string())
    }
}

impl From<String> for XlsxValue {
    fn from(s: String) -> Self {
        XlsxValue::Str(s)
    }
}

impl From<f64> for XlsxValue {
    fn from(f: f64) -> Self {
        XlsxValue::Float(f)
    }
}

impl From<i64> for XlsxValue {
    fn from(n: i64) -> Self {
        XlsxValue::Int(n)
    }
}

impl From<i32> for XlsxValue {
    fn from(n: i32) -> Self {
        XlsxValue::Int(n as i64)
    }
}

impl From<bool> for XlsxValue {
    fn from(b: bool) -> Self {
        XlsxValue::Bool(b)
    }
}

/// 一张待写出的表(行式;行内 `XlsxValue::Empty` 留空)。
#[derive(Debug, Clone, PartialEq)]
pub struct SheetOut {
    pub name: String,
    pub rows: Vec<Vec<XlsxValue>>,
}

impl SheetOut {
    /// 以表名创建空表。
    pub fn new(name: impl Into<String>) -> Self {
        SheetOut {
            name: name.into(),
            rows: Vec::new(),
        }
    }

    /// 追加一行。
    pub fn push_row(&mut self, row: Vec<XlsxValue>) {
        self.rows.push(row);
    }

    /// 表头便捷写法(等价 push_row,语义可读)。
    pub fn push_header(&mut self, headers: Vec<XlsxValue>) {
        self.push_row(headers);
    }
}

/// 把多张表写为 xlsx 字节流;至少需要一张表。
pub fn write_to_bytes(sheets: &[SheetOut]) -> Result<Vec<u8>, String> {
    if sheets.is_empty() {
        return Err("xlsx write: at least one sheet required".into());
    }
    let mut wb = Workbook::new();
    for sheet in sheets {
        if sheet.name.is_empty() {
            return Err("xlsx write: sheet name must not be empty".into());
        }
        let ws = wb
            .add_worksheet()
            .set_name(sheet.name.as_str())
            .map_err(|e| format!("xlsx write: sheet `{}`: {e}", sheet.name))?;
        for (r, row) in sheet.rows.iter().enumerate() {
            for (c, value) in row.iter().enumerate() {
                if matches!(value, XlsxValue::Empty) {
                    continue;
                }
                let (r, c) = (r as u32, c as u16); // 行 u32、列 u16(表上限 16384 列)
                match value {
                    XlsxValue::Empty => unreachable!("已在上方 continue"),
                    XlsxValue::Str(s) => ws.write_string(r, c, s),
                    XlsxValue::Float(f) => ws.write_number(r, c, *f),
                    XlsxValue::Int(n) => ws.write_number(r, c, *n as f64),
                    XlsxValue::Bool(b) => ws.write_boolean(r, c, *b),
                }
                .map_err(|e| format!("xlsx write: sheet `{}` cell ({r},{c}): {e}", sheet.name))?;
            }
        }
    }
    wb.save_to_buffer()
        .map_err(|e| format!("xlsx write: save failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_workbook() -> Vec<u8> {
        let mut users = SheetOut::new("用户");
        users.push_header(vec!["姓名".into(), "年龄".into(), "激活".into()]);
        users.push_row(vec!["小明".into(), 18i64.into(), true.into()]);
        users.push_row(vec!["小红".into(), 20i64.into(), false.into()]);
        // 稀疏行:中间留空
        users.push_row(vec!["小刚".into(), XlsxValue::Empty, true.into()]);

        let mut orders = SheetOut::new("订单");
        orders.push_header(vec!["单号".into(), "金额".into()]);
        orders.push_row(vec!["A-001".into(), 19.99.into()]);
        orders.push_row(vec!["A-002".into(), 128.0.into()]);

        write_to_bytes(&[users, orders]).unwrap()
    }

    #[test]
    fn write_read_roundtrip_two_sheets() {
        let bytes = sample_workbook();
        // xlsx 本质是 zip 容器
        assert_eq!(&bytes[..2], b"PK");

        let sheets = read_all(&bytes).unwrap();
        assert_eq!(sheets.len(), 2);
        assert_eq!(sheets[0].name, "用户");
        assert_eq!(sheets[1].name, "订单");

        let users = &sheets[0];
        assert_eq!(users.nrows(), 4);
        assert_eq!(users.ncols(), 3);
        assert_eq!(users.cell(0, 0).as_str(), Some("姓名"));
        assert_eq!(users.cell(1, 0).as_str(), Some("小明"));
        assert_eq!(users.cell(1, 1).as_i64(), Some(18));
        assert_eq!(users.cell(1, 2).as_bool(), Some(true));
        assert_eq!(users.cell(2, 2).as_bool(), Some(false));
        // 稀疏留空读回 Empty;越界同样 Empty
        assert!(users.cell(3, 1).is_empty());
        assert!(users.cell(99, 99).is_empty());

        let orders = &sheets[1];
        assert_eq!(orders.cell(1, 1).as_f64(), Some(19.99));
        assert_eq!(orders.cell(2, 1).as_i64(), Some(128));
    }

    #[test]
    fn read_sheet_by_name_and_first() {
        let bytes = sample_workbook();
        let orders = read_sheet(&bytes, "订单").unwrap();
        assert_eq!(orders.nrows(), 3);
        assert_eq!(orders.cell(1, 0).as_str(), Some("A-001"));

        let first = read_first(&bytes).unwrap();
        assert_eq!(first.name, "用户");

        assert!(read_sheet(&bytes, "不存在").is_err());
    }

    #[test]
    fn numeric_type_loose_i64() {
        // 写 42 读回可能是 Int 也可能是 Float,as_i64 都要接住
        let mut sheet = SheetOut::new("nums");
        sheet.push_row(vec![
            XlsxValue::Int(42),
            XlsxValue::Float(3.5),
            XlsxValue::Int(-7),
        ]);
        let bytes = write_to_bytes(&[sheet]).unwrap();
        let s = read_first(&bytes).unwrap();
        assert_eq!(s.cell(0, 0).as_i64(), Some(42));
        assert_eq!(s.cell(0, 1).as_i64(), None, "3.5 不是整数");
        assert_eq!(s.cell(0, 1).as_f64(), Some(3.5));
        assert_eq!(s.cell(0, 2).as_i64(), Some(-7));
        assert_eq!(s.cell(0, 0).as_bool(), None);
        assert_eq!(s.cell(0, 0).as_str(), None);
    }

    #[test]
    fn write_rejects_empty_input_and_names() {
        assert!(write_to_bytes(&[]).is_err());
        let mut sheet = SheetOut::new("");
        sheet.push_row(vec!["x".into()]);
        let err = write_to_bytes(&[sheet]).unwrap_err();
        assert!(err.contains("sheet name"), "err={err}");
    }

    #[test]
    fn read_rejects_garbage_bytes() {
        assert!(read_all(b"not an xlsx").is_err());
        // zip 容器但不是 xlsx
        assert!(read_first(&[0u8; 64]).is_err());
    }

    #[test]
    fn empty_sheet_and_unicode_roundtrip() {
        let mut sheet = SheetOut::new("空表·测试");
        // 一行不写
        let bytes = write_to_bytes(&[sheet.clone()]).unwrap();
        let s = read_first(&bytes).unwrap();
        assert_eq!(s.name, "空表·测试");
        assert_eq!(s.nrows(), 0);
        assert_eq!(s.ncols(), 0);
        assert_eq!(s.cell(0, 0), &Cell::Empty);

        // 全 Empty 值的行在 xlsx 里不产生任何单元格 → 读回 0 行
        // (xlsx 格式语义:空单元格不落盘)
        sheet.push_row(vec![XlsxValue::Empty, XlsxValue::Empty]);
        let bytes = write_to_bytes(&[sheet]).unwrap();
        let s = read_first(&bytes).unwrap();
        assert_eq!(s.name, "空表·测试");
        assert_eq!(s.nrows(), 0);
    }

    #[test]
    fn utf8_long_text_and_special_chars() {
        let mut sheet = SheetOut::new("🦀 crab 表");
        let long_text = "长文本\n带换行\t制表 & <xml> \"引号\" emoji 🎉";
        sheet.push_row(vec![long_text.into(), "A-1 分区".into()]);
        let bytes = write_to_bytes(&[sheet]).unwrap();
        let s = read_first(&bytes).unwrap();
        assert_eq!(s.cell(0, 0).as_str(), Some(long_text));
        assert_eq!(s.cell(0, 1).as_str(), Some("A-1 分区"));
    }
}
