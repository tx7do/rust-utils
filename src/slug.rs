//! URL slug 生成(移植自 go-utils/slug),feature `slug`。
//!
//! 基于 `slug` crate:unicode 转写为 ASCII、小写化、非法字符替换为 `-`。
//! Go 版的德语等语言特化入口未移植(`slug` crate 的转写规则已覆盖
//! 常见西文)。
//!
//! ```
//! use rust_utils::slug;
//!
//! assert_eq!(slug::generate("Hello, World!"), "hello-world");
//! assert_eq!(slug::generate("你好世界"), "ni-hao-shi-jie"); // 转写为拼音
//! ```

/// 生成 URL slug(小写)。
pub fn generate(input: &str) -> String {
    slug::slugify(input)
}

/// [`generate`] 的别名(Go 版 `GenerateEnglish`)。
pub fn generate_english(input: &str) -> String {
    slug::slugify(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        assert_eq!(generate("Hello, World!"), "hello-world");
        assert_eq!(generate("hello world"), "hello-world");
        assert_eq!(generate("  multiple   spaces  "), "multiple-spaces");
        assert_eq!(generate("Café & Crème"), "cafe-creme");
        assert_eq!(generate("你好世界"), "ni-hao-shi-jie");
    }

    #[test]
    fn test_generate_english() {
        assert_eq!(generate_english("Rust: Fast & Safe"), "rust-fast-safe");
    }
}
