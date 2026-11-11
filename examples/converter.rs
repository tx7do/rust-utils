//! REST 路径 / operationID → `resource:action` 权限码。
//!
//! 运行:`cargo run --features converter --example converter`

use rust_utils::converter::ApiPermissionConverter;

fn main() {
    let conv = ApiPermissionConverter::new();

    // operationID 形态(Kratos 风格):UserServiceGetUser
    let code = conv.convert_code_by_operation_id("UserServiceGetUser");
    println!("operationID UserServiceGetUser → {code}");

    // REST 路径形态:方法 + 带参数路径(参数段归一为 *)
    let code = conv.convert_code_by_path("GET", "/api/v1/users/123");
    println!("GET /api/v1/users/123          → {code}");

    println!("OK");
}
