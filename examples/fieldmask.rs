//! 字段掩码:嵌套掩码树 + filter/prune/overwrite/validate(serde_json)。
//!
//! 运行:`cargo run --features fieldmask --example fieldmask`

use rust_utils::fieldmask::NestedMask;
use serde_json::json;

fn main() {
    let mask = NestedMask::from_paths(&[
        "id".to_string(),
        "name".to_string(),
        "profile.email".to_string(),
        "tags".to_string(),
    ]);

    // filter:只保留掩码声明的字段(白名单裁剪)
    let mut value = json!({
        "id": 1,
        "name": "alice",
        "profile": { "email": "a@x.com", "phone": "13800000000" },
        "tags": ["vip"],
        "internal": "hidden",
    });
    mask.filter(&mut value);
    println!("filtered: {value}");
    assert_eq!(value["profile"]["email"], "a@x.com");
    assert!(value.get("phone").is_none());
    assert!(value.get("internal").is_none());

    // prune:把掩码声明但值为空的分支剪掉
    let mut sparse = json!({ "id": 1, "name": null, "profile": { "email": null } });
    mask.prune(&mut sparse);
    println!("pruned:   {sparse}");

    // validate:模板校验(掩码字段必须能在模板中定位)
    let template = json!({ "id": 0, "name": "", "profile": { "email": "" }, "tags": [] });
    assert!(mask.validate(&template).is_ok());

    println!("OK");
}
