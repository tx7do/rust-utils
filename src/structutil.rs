//! 结构体字段遍历(feature `structutil`,serde 桥)。
//!
//! 对位上游 `go-utils/structutil` 的 `ForEach` / `ToMap`:遍历结构体
//! 可见字段、收集为键值映射,`skip_serializing` 字段对应上游的 `-` 标签
//! 跳过、`rename` 后的键名对应上游的 tag 重映射 —— 这些语义在 Rust 侧
//! 由 serde 属性在序列化时天然完成,本模块只是把"序列化 → 只取顶层
//! 对象字段"的惯用路径收拢成两个入口。
//!
//! 与上游的对应关系:
//! - `ForEach(struct, func(key, value, tag))` → [`for_each`](遍历顶层
//!   字段的键与值;Rust 侧没有运行时 tag,`rename`/`skip` 语义已在
//!   序列化产物中体现);
//! - `ToMap(struct, tags...)` → [`to_map`](结构体 → 键值映射);
//! - 仅顶层字段(上游 `reflect.VisibleFields` 同语义,嵌套结构体作为
//!   一个值出现,不递归展开)。
//!
//! 非 object 序列化产物(元组结构体、标量、序列)返回错误 —— 上游
//! `ForEach` 对非结构体同样无字段可遍历。
//!
//! ```
//! use rust_utils::structutil;
//! use serde::Serialize;
//!
//! #[derive(Serialize)]
//! struct User {
//!     id: u64,
//!     #[serde(rename = "userName")]
//!     user_name: String,
//!     #[serde(skip_serializing)]
//!     password_hash: String,
//! }
//!
//! let user = User { id: 7, user_name: "alice".into(), password_hash: "x".into() };
//! let map = structutil::to_map(&user).unwrap();
//! assert_eq!(map["id"], 7);
//! assert_eq!(map["userName"], "alice");
//! // skip_serializing 对应上游 tag 值 "-" 的跳过语义
//! assert!(!map.contains_key("password_hash"));
//!
//! let mut keys = Vec::new();
//! structutil::for_each(&user, |key, _value| keys.push(key.to_string()));
//! assert_eq!(keys, vec!["id".to_string(), "userName".to_string()]);
//! ```

use serde::Serialize;
use serde_json::{Map, Value};

/// 结构体 → 顶层字段键值映射(上游 `ToMap`)。
///
/// 序列化产物不是 JSON object(元组结构体/标量/序列)时报错。
pub fn to_map<T: Serialize + ?Sized>(value: &T) -> Result<Map<String, Value>, String> {
    let v = serde_json::to_value(value).map_err(|e| format!("structutil: serialize: {e}"))?;
    match v {
        Value::Object(map) => Ok(map),
        other => Err(format!(
            "structutil: expected a struct (JSON object), got {}",
            type_name(&other)
        )),
    }
}

/// 遍历结构体顶层字段(上游 `ForEach`):对每个字段调用
/// `f(键名, 值)`。`rename` 后的键名即此处键名;`skip_serializing`
/// 字段不会出现(上游 `-` 标签语义)。**遍历顺序为键名字典序**
/// (serde_json 缺省 Map 形态;上游 Go map 本就无序,此处排序只为
/// 可复现)。
pub fn for_each<T: Serialize + ?Sized, F>(value: &T, mut f: F) -> Result<(), String>
where
    F: FnMut(&str, &Value),
{
    let map = to_map(value)?;
    for (key, v) in &map {
        f(key, v);
    }
    Ok(())
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, PartialEq)]
    struct User {
        id: u64,
        #[serde(rename = "userName")]
        user_name: String,
        #[serde(rename = "emailAddress", skip_serializing)]
        email: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        nickname: Option<String>,
        active: bool,
    }

    fn sample() -> User {
        User {
            id: 7,
            user_name: "alice".into(),
            email: "a@x.com".into(),
            nickname: Some("al".into()),
            active: true,
        }
    }

    #[test]
    fn to_map_respects_rename_and_skip() {
        let map = to_map(&sample()).unwrap();
        assert_eq!(map.len(), 4);
        assert_eq!(map["id"], 7);
        assert_eq!(map["userName"], "alice");
        // rename + skip:键名重映射且整个字段被跳过(上游 tag "-" 语义)
        assert!(!map.contains_key("email"));
        assert!(!map.contains_key("emailAddress"));
        // skip_serializing_if 为假值时字段缺席
        let mut none = sample();
        none.nickname = None;
        let map = to_map(&none).unwrap();
        assert_eq!(map.len(), 3);
        assert!(!map.contains_key("nickname"));
    }

    #[test]
    fn for_each_visits_every_serialized_field() {
        let mut seen = Vec::new();
        for_each(&sample(), |key, value| {
            seen.push((key.to_string(), value.clone()));
        })
        .unwrap();
        // serde_json 缺省 Map 按键字典序(与上游 Go map 无序遍历一致,
        // 排序只为可复现)
        let mut keys: Vec<&str> = seen.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["active", "id", "nickname", "userName"]);
        // 值一一对应
        let map = to_map(&sample()).unwrap();
        for (k, v) in &seen {
            assert_eq!(&map[k], v, "key={k}");
        }
    }

    #[test]
    fn nested_struct_stays_whole() {
        // 上游 VisibleFields 同语义:嵌套结构体作为一个值,不递归展开
        #[derive(Serialize)]
        struct Profile {
            city: String,
        }
        #[derive(Serialize)]
        struct Outer {
            name: String,
            profile: Profile,
        }
        let map = to_map(&Outer {
            name: "o".into(),
            profile: Profile { city: "hz".into() },
        })
        .unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map["profile"]["city"], "hz");
    }

    #[test]
    fn non_struct_errors() {
        // 元组结构体/标量/序列无字段可遍历,报错而非空图
        assert!(to_map(&(1, 2)).is_err());
        assert!(to_map(&42).is_err());
        assert!(to_map(&vec![1, 2]).is_err());
        assert!(to_map(&"s".to_string()).is_err());
        assert!(for_each(&42, |_k, _v| {}).is_err());
        let err = to_map(&42).unwrap_err();
        assert!(err.contains("expected a struct"), "err={err}");
    }

    #[test]
    fn deserialize_side_unaffected() {
        // 上游只管序列化方向;此处验证与 Deserialize 协作无干扰
        #[derive(Debug, Deserialize)]
        struct In {
            #[serde(rename = "userName")]
            user_name: String,
        }
        let map = to_map(&sample()).unwrap();
        let json = Value::Object(map);
        let back: In = serde_json::from_value(json).unwrap();
        assert_eq!(back.user_name, "alice");
    }
}
