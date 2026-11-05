//! 手机号归一:国内裸号与 E.164 两形(对齐上游 `sms/phone.go`)。
//!
//! 接受两类输入:E.164(可带 `+86` 前缀)与中国大陆 11 位裸号(`1` 开头,自动补
//! `+86`)。其他形态一律拒绝——短信目标错了没有"发到别家去"的软失败,宁可让这一
//! 次投递失败在调用方的记录里说清楚。分隔符(空格/横线/括号)先剥掉:用户从通讯
//! 录粘出来的号常带。
//!
//! 返回两形:`national`(无 `+86` 前缀,阿里云国内短信收裸号)与 `e164`(带 `+`,
//! 腾讯云 `PhoneNumberSet` 只认 E.164)。入口处可用它做快反馈;各渠道在投递前
//! 还会再跑一遍作最终裁决。

/// 归一手机号为 (国内裸号, E.164) 两形。
///
/// 错误文案点名原始输入,例:`"abc" is not a valid MSISDN (5-20 digits,
/// optional +86 prefix)`。
pub fn normalize_phone_number(raw: &str) -> Result<(String, String), String> {
    // 分隔符剥离:空格/横线/括号是排版记号,不是号码的一部分。
    let mut cleaned = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b != b' ' && b != b'-' && b != b'(' && b != b')' {
            cleaned.push(b as char);
        }
    }
    if cleaned.is_empty() {
        return Err(format!("phone number {raw:?} is empty"));
    }

    // 位数校验对去掉前导 + 的主体做:+ 是格式记号,不是数字。
    let body = cleaned.strip_prefix('+').unwrap_or(&cleaned);
    let digit_count = body.bytes().filter(|b| b.is_ascii_digit()).count();
    if digit_count != body.len() || !(5..=20).contains(&digit_count) {
        return Err(format!(
            "phone number {raw:?} is not a valid MSISDN (5-20 digits, optional +86 prefix)"
        ));
    }

    // 至此字符串已验证为 ASCII 数字与 '+',按字节切片安全。
    if let Some(national) = cleaned.strip_prefix("+86") {
        return Ok((national.to_string(), cleaned));
    }
    if let Some(national) = cleaned.strip_prefix('+') {
        return Ok((national.to_string(), cleaned));
    }
    // 中国大陆 11 位裸号:1 开头,自动补 +86。
    if digit_count == 11 && cleaned.starts_with('1') {
        let e164 = format!("+86{cleaned}");
        return Ok((cleaned, e164));
    }
    Err(format!(
        "phone number {raw:?} must be E.164 (with country code) or a CN mobile number"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 对齐上游 `sms_test.go` 的 TestNormalizePhoneNumber:两种接受形态、
    /// 分隔符剥离与拒绝形态。
    #[test]
    fn test_normalize_phone_number() {
        let cases = [
            ("13800138000", "13800138000", "+8613800138000"),
            // 通讯录粘贴形态
            ("138 0013-8000", "13800138000", "+8613800138000"),
            ("+8613800138000", "13800138000", "+8613800138000"),
            // 非中国号:原样两形
            ("+12025550123", "12025550123", "+12025550123"),
        ];
        for (raw, want_national, want_e164) in &cases {
            let (national, e164) =
                normalize_phone_number(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            assert_eq!(&national, want_national, "national of {raw:?}");
            assert_eq!(&e164, want_e164, "e164 of {raw:?}");
        }
        // 拒绝形态:裸 5 位既不是 E.164 也不是 CN 手机 / 混入字母 / 超 20 位 / 空
        for raw in ["12345", "1380013800a", "13800138000112345678", ""] {
            assert!(normalize_phone_number(raw).is_err(), "{raw:?} should be rejected");
        }
    }

    /// 错误文案点名原始输入(对账排障时不至于两头懵)。
    /// 分支对齐上游 Go 版:混入字母连位数关都过不了,归 MSISDN 形态错;
    /// 裸 5 位数字过了位数关,但既非 E.164 也非 CN 手机,归另一条文案。
    #[test]
    fn test_error_message_names_raw_input() {
        let err = normalize_phone_number("abc").unwrap_err();
        assert!(err.contains("abc"), "{err}");
        assert!(err.contains("MSISDN"), "{err}");
        let err = normalize_phone_number("12345").unwrap_err();
        assert!(err.contains("12345"), "{err}");
        assert!(err.contains("must be E.164"), "{err}");
    }
}
