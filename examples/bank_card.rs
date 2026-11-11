//! 银行卡:Luhn 校验与 BIN 归属查询(内嵌记录,离线可用)。
//!
//! 运行:`cargo run --features bank-card --example bank_card`

use rust_utils::bank_card;

fn main() {
    for card_no in [
        "6222020200112233456",
        "4111111111111111",
        "6222020200112233457",
    ] {
        let luhn = bank_card::is_valid_luhn(card_no);
        let bank = bank_card::query_bank_by_card_number(card_no);
        println!(
            "{card_no} → luhn: {luhn:<5} bank: {}",
            bank.map(|b| b.card_type_name().to_string())
                .unwrap_or_else(|| "-".into())
        );
    }

    assert!(bank_card::is_valid_luhn("4111111111111111"));
    assert!(!bank_card::is_valid_luhn("4111111111111112"));
    println!("OK");
}
