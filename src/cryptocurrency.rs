//! 加密货币钱包地址的格式校验(移植自 go-utils/cryptocurrency)。
//!
//! 与 Go 版一致,仅做**格式**校验(前缀 + 字符集 + 长度),
//! 不做 base58/checksum 校验。
//!
//! 相对 Go 版的两处修正:
//! - `xmr` 正则里多了一个前导 `/`(永远匹配不上),已去掉;
//! - `trc` 正则未加锚点(任意包含 `T`+33 位子串的字符串都能通过),已加锚点。

/// 钱包类型标识:比特币(BTC / OMNI)。
pub const WALLET_BTC: &str = "btc";
/// 钱包类型标识:比特币金(BTG)。
pub const WALLET_BTG: &str = "btg";
/// 钱包类型标识:达世币(DASH)。
pub const WALLET_DASH: &str = "dash";
/// 钱包类型标识:极特币(DGB)。
pub const WALLET_DGB: &str = "dgb";
/// 钱包类型标识:以太坊(ETH / ERC20)。
pub const WALLET_ETH: &str = "eth";
/// 钱包类型标识:智能币(SMART)。
pub const WALLET_SMART: &str = "smart";
/// 钱包类型标识:瑞波币(XRP)。
pub const WALLET_XRP: &str = "xrp";
/// 钱包类型标识:ZCR。
pub const WALLET_ZCR: &str = "zcr";
/// 钱包类型标识:零币(ZEC)。
pub const WALLET_ZEC: &str = "zec";
/// 钱包类型标识:门罗币(XMR)。
pub const WALLET_XMR: &str = "xmr";
/// 钱包类型标识:波场(TRON / TRC20)。
pub const WALLET_TRC: &str = "trc";
/// `determine_wallet_type` 对未识别前缀的兜底类型。
pub const WALLET_OMINI: &str = "omini";

/// Go 版 `[a-zA-HJ-NP-Z0-9]`:字母数字,排除易混淆的大写 I / O。
fn is_btc_charset(c: char) -> bool {
    c.is_ascii_alphanumeric() && c != 'I' && c != 'O'
}

/// `[a-zA-Z0-9]`。
fn is_alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// TRC20 字符集 `[A-Za-z1-9]`:不含数字 0。
fn is_trc_charset(c: char) -> bool {
    c.is_ascii_alphanumeric() && c != '0'
}

/// base58 字符集 `[1-9A-HJ-NP-Za-km-z]`:不含 0 / I / O / l。
fn is_base58_charset(c: char) -> bool {
    matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
}

fn check(
    address: &str,
    prefix: &str,
    charset: fn(char) -> bool,
    body: impl Fn(usize) -> bool,
) -> bool {
    match address.strip_prefix(prefix) {
        Some(rest) => body(rest.chars().count()) && rest.chars().all(charset),
        None => false,
    }
}

/// 判断钱包地址的类型:按 `eth` → `trc` → `omini` 的顺序做前缀判断,
/// 长度不符时返回错误。
///
/// ```
/// use rust_utils::cryptocurrency::determine_wallet_type;
///
/// assert_eq!(determine_wallet_type("0x15cc4bf4fe84fea178d2b10f89f1a6c914dfc8c2"), Ok("eth"));
/// assert_eq!(determine_wallet_type("TC74QG8tbtixG5Raa4fEifywgjrFs45fNz"), Ok("trc"));
/// assert!(determine_wallet_type("0x1234").is_err());
/// ```
pub fn determine_wallet_type(wallet: &str) -> Result<&'static str, &'static str> {
    if wallet.starts_with("0x") {
        if wallet.chars().count() != 42 {
            return Err("无效的ETH地址");
        }
        Ok(WALLET_ETH)
    } else if wallet.starts_with('T') {
        if wallet.chars().count() != 34 {
            return Err("无效的TRC地址");
        }
        Ok(WALLET_TRC)
    } else if wallet.chars().count() != 34 {
        Err("无效的OMINI地址")
    } else {
        Ok(WALLET_OMINI)
    }
}

/// 是否为格式合法的 BTC 地址(前缀 `1` / `3` / `bc1`)。
pub fn is_valid_btc_address(address: &str) -> bool {
    check(address, "bc1", is_btc_charset, |n| (25..=39).contains(&n))
        || check(address, "1", is_btc_charset, |n| (25..=39).contains(&n))
        || check(address, "3", is_btc_charset, |n| (25..=39).contains(&n))
}

/// 是否为格式合法的 ETH 地址(`0x` + 40 位字母数字)。
pub fn is_valid_eth_address(address: &str) -> bool {
    check(address, "0x", is_alnum, |n| n == 40)
}

/// 是否为格式合法的 TRON 地址(`T` + 33 位,不含数字 0)。
pub fn is_valid_tron_address(address: &str) -> bool {
    check(address, "T", is_trc_charset, |n| n == 33)
}

/// XMR 地址:`4` + `[0-9AB]` + 93 位 base58 字符,共 95 位。
fn is_valid_xmr_address(address: &str) -> bool {
    let chars: Vec<char> = address.chars().collect();
    if chars.len() != 95 || chars[0] != '4' || !matches!(chars[1], '0'..='9' | 'A' | 'B') {
        return false;
    }
    chars[2..].iter().all(|&c| is_base58_charset(c))
}

/// 校验钱包地址,返回命中的钱包类型;未命中返回空字符串。
///
/// 按 btc → btg → dash → dgb → eth → smart → xrp → zcr → zec → xmr → trc
/// 的固定顺序匹配(Go 版依赖 map 遍历,顺序随机)。
pub fn is_valid_cryptocurrency_address(address: &str) -> &'static str {
    if address.is_empty() {
        return "";
    }
    // btc 是 `bc1|[13]` 的复合前缀,单独处理
    if is_valid_btc_address(address) {
        return WALLET_BTC;
    }
    if check(address, "G", is_btc_charset, |n| (24..=34).contains(&n))
        || check(address, "A", is_btc_charset, |n| (24..=34).contains(&n))
    {
        return WALLET_BTG;
    }
    if check(address, "X", is_alnum, |n| n == 33) || check(address, "7", is_alnum, |n| n == 33) {
        return WALLET_DASH;
    }
    if check(address, "D", is_alnum, |n| (24..=33).contains(&n)) {
        return WALLET_DGB;
    }
    if is_valid_eth_address(address) {
        return WALLET_ETH;
    }
    if check(address, "S", is_alnum, |n| n == 33) {
        return WALLET_SMART;
    }
    if check(address, "r", is_alnum, |n| n == 33) {
        return WALLET_XRP;
    }
    if check(address, "Z", is_alnum, |n| n == 33) {
        return WALLET_ZCR;
    }
    if check(address, "t", is_alnum, |n| n == 34) {
        return WALLET_ZEC;
    }
    if is_valid_xmr_address(address) {
        return WALLET_XMR;
    }
    if is_valid_tron_address(address) {
        return WALLET_TRC;
    }
    ""
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_addresses() {
        let cases = [
            ("1CFNjwLjZdSKB8nZopxhLaR8vvqaQKD3Bi", WALLET_BTC),
            ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", WALLET_BTC),
            ("1RAHUEYstWetqabcFn5Au4m4GFg7xJaNVN2", WALLET_BTC),
            ("3J98t1RHT73CNmQwertyyWrnqRhWNLy", WALLET_BTC),
            ("bc1qarsrrr7ASHy5643ydab9re59gtzzwfrah", WALLET_BTC),
            ("GakMJVF7Du16VK9dpN6nhJyLUPLXkTfqSY", WALLET_BTG),
            ("D59P8MiMXkjs7HPn31zAnUSvRNwvNZUBYa", WALLET_DGB),
            ("XiHMBEic8q8wX5aKqVv6zRFec7cAuYGjBV", WALLET_DASH),
            ("0x15cc4bf4fe84fea178d2b10f89f1a6c914dfc8c2", WALLET_ETH),
            ("0xZYXb5d4c32345ced77393b3530b1eed0f346429d", WALLET_ETH),
            ("SbsLb8eM583oraW89qhbkcqZmuR4aYKkea", WALLET_SMART),
            ("rMkfgicNKuCfXojDhcX4W2LnGoHFqhFrr6", WALLET_XRP),
            ("t1SBt3V8MfG4ZJ2ZDTuWfDshn4PuyvqjJV3", WALLET_ZEC),
            ("ZXvpr2M6wvKoFcTJ57WCjT9Wkd38xkL8Fo", WALLET_ZCR),
            ("TC74QG8tbtixG5Raa4fEifywgjrFs45fNz", WALLET_TRC),
            ("TFUD8x3iAZ9dF7NDCGBtSjznemEomE5rP9", WALLET_TRC),
            ("TPcKtz5TRfP4xUZSos81RmXB9K2DBqj2iu", WALLET_TRC),
        ];
        for (addr, want) in cases {
            assert_eq!(is_valid_cryptocurrency_address(addr), want, "addr: {addr}");
        }
    }

    #[test]
    fn test_invalid_addresses() {
        // 这些地址不属于所声称的币种(Go 版测试口径:结果 != 声称类型)
        let cases = [
            ("2CFNjwLjZdSKB8nZopxhLaR8vvqaQKD3Bi", ""),
            ("bc2qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", ""),
            ("b1qarsrrr7ASHy5643ydab9re59gtzzwfrah", ""),
            ("0J98t1RHT73CNmQwertyyWrnqRhWNLy", ""),
            ("DakMJVF7Du16VK9dpN6nhJyLUPLXkTfqSY", WALLET_DGB), // 非 btg,但合法 dgb
            ("G59P8MiMXkjs7HPn31zAnUSvRNwvNZUBYa", WALLET_BTG), // 非 dgb,但合法 btg
            ("QiHMBEic8q8wX5aKqVv6zRFec7cAuYGjBV", ""),
            ("1x15cc4bf4fe84fea178d2b10f89f1a6c914dfc8c2", ""),
            ("sbsLb8eM583oraW89qhbkcqZmuR4aYKkea", ""),
            ("RMkfgicNKuCfXojDhcX4W2LnGoHFqhFrr6", ""),
            ("z1SBt3V8MfG4ZJ2ZDTuWfDshn4PuyvqjJV3", ""),
            ("zXvpr2M6wvKoFcTJ57WCjT9Wkd38xkL8Fo", ""),
            ("", ""),
        ];
        for (addr, want) in cases {
            assert_eq!(is_valid_cryptocurrency_address(addr), want, "addr: {addr}");
        }
    }

    #[test]
    fn test_determine_wallet_type() {
        assert_eq!(
            determine_wallet_type("0x15cc4bf4fe84fea178d2b10f89f1a6c914dfc8c2"),
            Ok(WALLET_ETH)
        );
        assert_eq!(
            determine_wallet_type("TC74QG8tbtixG5Raa4fEifywgjrFs45fNz"),
            Ok(WALLET_TRC)
        );
        assert_eq!(
            determine_wallet_type("1CFNjwLjZdSKB8nZopxhLaR8vvqaQKD3Bi"),
            Ok(WALLET_OMINI)
        );
        assert_eq!(determine_wallet_type("0x1234"), Err("无效的ETH地址"));
        assert_eq!(determine_wallet_type("Tshort"), Err("无效的TRC地址"));
        assert_eq!(determine_wallet_type("short"), Err("无效的OMINI地址"));
    }
}
