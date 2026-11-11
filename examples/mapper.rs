//! entity ↔ DTO 字段映射:重命名、嵌套搬移、枚举转换、缺省与白名单。
//!
//! 运行:`cargo run --features mapper --example mapper`

use rust_utils::mapper::Mapper;
use serde_json::json;

fn main() {
    // 库里实体:蛇形命名 + 数字枚举 + 敏感字段
    let entity = json!({
        "id": 1001,
        "user_name": "alice",
        "profile": { "email": "a@x.com", "phone": "13800000000" },
        "status": 1,
        "password_hash": "…",
    });

    let mapper = Mapper::new()
        .rename("id", "uid")
        .rename("user_name", "userName")
        .rename("profile.email", "email") // 嵌套搬到顶层
        .rename("status", "state")
        .map_enum("status", |t| {
            t.entry(1, "active").entry(2, "frozen").entry(3, "disabled");
        })
        .default_field("role", json!("viewer"))
        .exclude("password_hash");

    let dto = mapper.apply(&entity).unwrap();
    println!("dto: {dto:#}");

    assert_eq!(dto["uid"], 1001);
    assert_eq!(dto["userName"], "alice");
    assert_eq!(dto["email"], "a@x.com");
    assert_eq!(dto["state"], "active"); // 枚举转换
    assert_eq!(dto["role"], "viewer"); // 缺省补齐
    assert!(dto.get("password_hash").is_none());

    // 强类型出口:Value → DTO 结构体
    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)] // 演示结构体,字段经 Debug 打印
    struct UserDto {
        uid: i64,
        user_name: String,
        state: String,
    }
    let typed: UserDto = mapper.convert(&entity).unwrap();
    println!("typed: {typed:?}");
    assert_eq!(typed.user_name, "alice");

    println!("OK");
}
