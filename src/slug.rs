//! URL slug 生成,feature `slug`。
//!
//! 基于 `slug` crate:unicode 转写为 ASCII、小写化、非法字符替换为 `-`。
//! 德语等语言特化的转写规则已由 `slug` crate 覆盖常见西文。
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

/// [`generate`] 的英文 slug 快捷别名。
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
