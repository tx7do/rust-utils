//! 银行卡 BIN 查询与校验(移植自 go-utils/bank_card),feature
//! `bank-card`。
//!
//! 内嵌了 Go 版 SQLite 库导出的完整数据(2013 条 BIN 记录、275 家银行,
//! 首次查询时惰性解析为内存表),无需任何数据库依赖。
//!
//! ```
//! use rust_utils::bank_card;
//!
//! assert!(bank_card::is_valid_luhn("6222600260001072444"));
//! assert!(!bank_card::is_valid_luhn("6222600260001072445"));
//!
//! let card = bank_card::query_bank_by_card_number("6222600260001072444");
//! assert!(card.is_some());
//! ```

use std::collections::HashMap;
use std::sync::OnceLock;

/// 储蓄卡。
pub const CARD_TYPE_DC: &str = "DC";
/// 信用卡。
pub const CARD_TYPE_CC: &str = "CC";
/// 准贷记卡。
pub const CARD_TYPE_SCC: &str = "SCC";
/// 预付费卡。
pub const CARD_TYPE_PC: &str = "PC";

const BANK_CARDS_TSV: &str = include_str!("../assets/bank_card/bank_cards.tsv");
const BANKS_TSV: &str = include_str!("../assets/bank_card/banks.tsv");

/// 银行卡信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BankCard {
    /// 银行识别码(BIN)。
    pub bin: u32,
    /// 银行简称。
    pub bank_code: String,
    /// 银行全称(来自 banks 表)。
    pub bank_name: String,
    /// 卡类型:DC / CC / SCC / PC。
    pub card_type: String,
    /// 卡名称。
    pub card_name: String,
    /// 卡号长度。
    pub card_length: u32,
}

impl BankCard {
    /// 卡类型中文名。
    pub fn card_type_name(&self) -> &'static str {
        match self.card_type.as_str() {
            CARD_TYPE_DC => "储蓄卡",
            CARD_TYPE_CC => "信用卡",
            CARD_TYPE_SCC => "准贷记卡",
            CARD_TYPE_PC => "预付费卡",
            _ => "",
        }
    }
}

struct BinRecord {
    bank_code: String,
    card_name: String,
    card_type: String,
    card_length: u32,
}

fn banks_map() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        BANKS_TSV
            .lines()
            .filter_map(|line| {
                let mut parts = line.split('\t');
                let code = parts.next()?;
                let name = parts.next().unwrap_or("");
                Some((code, name))
            })
            .collect()
    })
}

fn bins_map() -> &'static HashMap<u32, BinRecord> {
    static MAP: OnceLock<HashMap<u32, BinRecord>> = OnceLock::new();
    MAP.get_or_init(|| {
        BANK_CARDS_TSV
            .lines()
            .filter_map(|line| {
                let mut parts = line.split('\t');
                let bin: u32 = parts.next()?.parse().ok()?;
                Some((
                    bin,
                    BinRecord {
                        bank_code: parts.next().unwrap_or("").to_string(),
                        card_name: parts.next().unwrap_or("").to_string(),
                        card_type: parts.next().unwrap_or("").to_string(),
                        card_length: parts.next().unwrap_or("0").parse().unwrap_or(0),
                    },
                ))
            })
            .collect()
    })
}

/// 使用 Luhn 算法校验银行卡号(纯数字串)。
pub fn is_valid_luhn(card_no: &str) -> bool {
    if card_no.is_empty() || !card_no.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    let mut second = false;
    for b in card_no.bytes().rev() {
        let mut d = (b - b'0') as u32;
        if second {
            d *= 2;
        }
        sum += d / 10 + d % 10;
        second = !second;
    }
    sum % 10 == 0
}

/// 是否为合法的银行卡号:12~19 位且通过 Luhn 校验。
pub fn is_valid_bank_card_no(card_no: &str) -> bool {
    let len = card_no.len();
    if !(12..=19).contains(&len) {
        return false;
    }
    is_valid_luhn(card_no)
}

/// 通过卡号查询银行卡信息:依次尝试前 8 / 7 / 6 位作为 BIN 精确匹配。
pub fn query_bank_by_card_number(card_no: &str) -> Option<BankCard> {
    if card_no.len() < 6 || !card_no.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let bins = bins_map();
    let banks = banks_map();
    for take in [8usize, 7, 6] {
        if card_no.len() < take {
            continue;
        }
        let bin: u32 = card_no[..take].parse().ok()?;
        if let Some(rec) = bins.get(&bin) {
            let bank_name = banks
                .get(rec.bank_code.as_str())
                .map(|s| (*s).to_string())
                .unwrap_or_default();
            return Some(BankCard {
                bin,
                bank_code: rec.bank_code.clone(),
                bank_name,
                card_type: rec.card_type.clone(),
                card_name: rec.card_name.clone(),
                card_length: rec.card_length,
            });
        }
    }
    None
}

/// 通过卡号前 6 位查询银行名称;查不到返回空串。
pub fn get_name_of_bank(card_no: &str) -> String {
    query_bank_by_card_number(card_no)
        .map(|c| c.bank_name)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn() {
        assert!(is_valid_luhn("6222600260001072444"));
        assert!(!is_valid_luhn("6222600260001072445"));
        assert!(!is_valid_luhn(""));
        assert!(!is_valid_luhn("abc"));
        assert!(!is_valid_luhn("1234567890123456a"));
        assert!(is_valid_luhn("4111111111111111")); // 测试 Visa 卡号
        assert!(!is_valid_luhn("4111111111111112"));
    }

    #[test]
    fn test_bank_card_no_length() {
        // Luhn 通过但长度不足
        assert!(!is_valid_bank_card_no("12345"));
        assert!(is_valid_bank_card_no("6222600260001072444"));
    }

    #[test]
    fn test_query_by_card_number() {
        let card = query_bank_by_card_number("6222600260001072444").expect("should find");
        assert!(!card.bank_code.is_empty());
        assert!(!card.card_name.is_empty());
        assert!(card.card_length >= 12);

        // 前缀过短 / 非数字
        assert!(query_bank_by_card_number("1234").is_none());
        assert!(query_bank_by_card_number("abcdefgh").is_none());
        assert!(query_bank_by_card_number("0000000000000000").is_none());
    }

    #[test]
    fn test_data_loaded() {
        assert_eq!(bins_map().len(), 2013);
        assert_eq!(banks_map().len(), 275);
        // 已知 BIN
        let card = query_bank_by_card_number("6228480000000000").expect("ABC bin");
        assert_eq!(card.card_type_name(), "储蓄卡");
        assert_eq!(card.card_type, CARD_TYPE_DC);
    }

    #[test]
    fn test_get_name_of_bank() {
        let name = get_name_of_bank("6228480000000000");
        // 银行名来自 banks 表
        assert!(!name.is_empty());
        assert_eq!(get_name_of_bank("1234"), "");
    }
}
