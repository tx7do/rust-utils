//! 驼峰/蛇形/烤肉串转换与缩写词识别。
//!
//! 运行:`cargo run --example stringcase`

use rust_utils::stringcase;

fn main() {
    let inputs = [
        "userID",
        "HTTPServer",
        "oauth2_token",
        "XMLHttpRequest",
        "v2_beta_3",
    ];
    for s in inputs {
        println!(
            "{s:>16} → snake: {:<20} camel: {:<18} kebab: {kebab} (pascal: {pascal})",
            stringcase::to_snake_case(s),
            stringcase::camel_case(s),
            kebab = stringcase::kebab_case(s),
            pascal = stringcase::pascal_case(s),
        );
    }

    assert_eq!(stringcase::to_snake_case("userID"), "user_id");
    assert_eq!(stringcase::to_snake_case("HTTPServer"), "http_server");
    assert_eq!(stringcase::camel_case("oauth2_token"), "oauth2Token");
    assert_eq!(stringcase::upper_camel_case("user_name"), "UserName");
    println!("OK");
}
