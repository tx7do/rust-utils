//! 分页偏移量与字符串宽松解析(零依赖常用件)。
//!
//! 运行:`cargo run --example pagination`

use rust_utils::{pagination, stringutil};

fn main() {
    // 页号从 1 起;不做钳制(越界语义由调用方决定)
    println!(
        "page 1  size 20 → offset {}",
        pagination::get_page_offset(1, 20)
    );
    println!(
        "page 3  size 20 → offset {}",
        pagination::get_page_offset(3, 20)
    );
    println!(
        "page 0  size 20 → offset {}",
        pagination::get_page_offset(0, 20)
    );

    // 宽松解析:空串/非法回退默认值(配置与 query 兜底常用)
    assert_eq!(stringutil::parse_or("42", 0), 42);
    assert_eq!(stringutil::parse_or("", 0), 0);
    assert_eq!(stringutil::parse_or("abc", 7), 7);
    // 布尔只认 1/t/true 与 0/f/false 三组形态(含大小写变体)
    assert_eq!(stringutil::parse_bool("true"), Some(true));
    assert_eq!(stringutil::parse_bool("T"), Some(true));
    assert_eq!(stringutil::parse_bool("0"), Some(false));
    assert_eq!(stringutil::parse_bool("yes"), None);
    println!("OK");
}
