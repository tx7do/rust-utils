//! entity ↔ DTO 字段映射(feature `mapper`,serde_json 桥)。
//!
//! 对齐上游 `go-utils/mapper` + `copierutil` 的定位:实体与 DTO 字段名
//! 不一致、枚举表示不同(库里存数字、线上出字符串)、部分字段要补缺省
//! 或剔除时的搬运层。Rust 侧不做反射,以 `serde_json::Value` 为桥:
//! `T → serde_json → Mapper.apply → U`(强类型入口 [`Mapper::convert`])。
//!
//! 路径语义:点路径(嵌套对象 + 数字数组下标)。`rename("a.b", "c")`
//! 把嵌套值搬到顶层,`rename("x", "c.d")` 反向嵌入——存在即取、缺失即跳。
//!
//! 失败面(全部 fail-fast 报错,不静默产错值):
//! - 输入非 JSON object;
//! - 枚举映射登记了表但命中值不在表内;
//! - `convert` 的 serde 序列化/反序列化失败。
//!
//! ```
//! use rust_utils::mapper::Mapper;
//! use serde_json::json;
//!
//! let m = Mapper::new()
//!     .rename("user_name", "userName")
//!     .rename("profile.email", "email")
//!     .map_enum("status", |t| { t.entry(1, "active"); })
//!     .default_field("role", json!("viewer"))
//!     .exclude("password_hash");
//!
//! let dto = m.apply(&json!({
//!     "user_name": "alice",
//!     "profile": { "email": "a@x.com" },
//!     "status": 1,
//!     "password_hash": "…",
//! })).unwrap();
//! assert_eq!(dto["userName"], "alice");
//! assert_eq!(dto["email"], "a@x.com");
//! assert_eq!(dto["status"], "active");
//! assert_eq!(dto["role"], "viewer");
//! assert!(dto.get("password_hash").is_none());
//! ```

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Value};

/// 字段映射器。
#[derive(Debug, Clone, Default)]
pub struct Mapper {
    /// (from 点路径, to 点路径) 重命名/搬移。
    renames: Vec<(String, String)>,
    /// 枚举值转换:from 路径 → (原值文本 → 新值)。
    enum_maps: BTreeMap<String, BTreeMap<String, Value>>,
    /// 输出字段缺省值(to 路径 → 值)。
    defaults: BTreeMap<String, Value>,
    /// 剔除的输入字段(from 路径)。
    excludes: Vec<String>,
    /// 只保留显式映射过的字段(白名单模式,缺省 false)。
    only_mapped: bool,
}

impl Mapper {
    /// 空映射器(恒等搬运)。
    pub fn new() -> Self {
        Self::default()
    }

    /// 字段重命名/搬移(点路径;同 to 目标的多条 rename 后写覆盖先写)。
    pub fn rename(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.renames.push((from.into(), to.into()));
        self
    }

    /// 枚举值转换:登记 `field` 路径的取值表,构建回调里逐项 `entry`。
    pub fn map_enum(
        mut self,
        field: impl Into<String>,
        build: impl FnOnce(&mut EnumTable),
    ) -> Self {
        let mut table = EnumTable::default();
        build(&mut table);
        self.enum_maps.insert(field.into(), table.inner);
        self
    }

    /// 输出字段缺省值(输入缺失该 to 路径时补上)。
    pub fn default_field(mut self, to_path: impl Into<String>, value: Value) -> Self {
        self.defaults.insert(to_path.into(), value);
        self
    }

    /// 剔除输入字段。
    pub fn exclude(mut self, from_path: impl Into<String>) -> Self {
        self.excludes.push(from_path.into());
        self
    }

    /// 白名单模式:只保留显式 rename/enum 映射过的字段。
    pub fn only_mapped(mut self) -> Self {
        self.only_mapped = true;
        self
    }

    /// 应用映射(输入必须是 JSON object)。
    pub fn apply(&self, input: &Value) -> Result<Value, String> {
        let obj = input.as_object().ok_or_else(|| {
            format!(
                "mapper: input must be a JSON object, got {}",
                type_name(input)
            )
        })?;
        let mut out = Map::new();

        // 白名单模式下未显式映射的字段不透传
        if !self.only_mapped {
            for (k, v) in obj {
                if self.excludes.iter().any(|e| e == k) {
                    continue;
                }
                set_path(&mut out, k, v.clone());
            }
        }

        // 显式 rename/enum 映射
        for (from, to) in &self.renames {
            if self.excludes.iter().any(|e| e == from) {
                continue;
            }
            let Some(found) = get_path(obj, from) else {
                continue; // 源字段缺失即跳,交由 defaults 兜底
            };
            let mut value = found.clone();
            if let Some(table) = self.enum_maps.get(from) {
                value = convert_enum(value, table, from)?;
            }
            set_path(&mut out, to, value);
            // 搬移后源字段不再以原名透传
            if from != to && !self.only_mapped {
                remove_path(&mut out, from);
            }
        }
        // 枚举表里登记了但没配 rename 的字段(原地转换)
        for (field, table) in &self.enum_maps {
            if self.renames.iter().any(|(f, _)| f == field) {
                continue;
            }
            if self.excludes.iter().any(|e| e == field) {
                continue;
            }
            if let Some(found) = get_path(obj, field) {
                let value = convert_enum(found.clone(), table, field)?;
                set_path(&mut out, field, value);
            }
        }

        // 缺省补齐
        for (to, value) in &self.defaults {
            if get_path(&out, to).is_none() {
                set_path(&mut out, to, value.clone());
            }
        }

        Ok(Value::Object(out))
    }

    /// 强类型入口:`T → serde_json → apply → U`。
    pub fn convert<T: Serialize, U: DeserializeOwned>(&self, input: &T) -> Result<U, String> {
        let value = serde_json::to_value(input).map_err(|e| format!("mapper: serialize: {e}"))?;
        let mapped = self.apply(&value)?;
        serde_json::from_value(mapped).map_err(|e| format!("mapper: deserialize: {e}"))
    }
}

/// 枚举转换表的构建器(键取 JSON 值的文本形态:数字/布尔/字符串均可)。
#[derive(Debug, Default)]
pub struct EnumTable {
    inner: BTreeMap<String, Value>,
}

impl EnumTable {
    /// 登记 一条转换(`from` 取原值的 [`enum_key`] 文本形态),可链式。
    pub fn entry(&mut self, from: impl ToString, to: impl Into<Value>) -> &mut Self {
        self.inner.insert(from.to_string(), to.into());
        self
    }
}

/// JSON 值到映射表键的文本形态:字符串原样、数字/布尔用 JSON 文本。
fn enum_key(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn convert_enum(
    value: Value,
    table: &BTreeMap<String, Value>,
    field: &str,
) -> Result<Value, String> {
    let key = enum_key(&value);
    table
        .get(&key)
        .cloned()
        .ok_or_else(|| format!("mapper: enum map for `{field}` has no entry for `{key}`"))
}

/// 点路径取值(存在即 Some;缺失/越界 None,不做报错——映射语义里
/// "缺" 是常态,交由 defaults 处理)。
fn get_path<'a>(obj: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut cur: &Value = obj.get(parts.next()?)?;
    for part in parts {
        cur = match cur {
            Value::Object(m) => m.get(part)?,
            Value::Array(a) => a.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// 点路径写入(逐段创建中间对象)。
fn set_path(out: &mut Map<String, Value>, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut cur = out;
    for part in &parts[..parts.len() - 1] {
        let entry = cur
            .entry(part.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        cur = entry.as_object_mut().expect("刚保证为 object");
    }
    cur.insert(parts[parts.len() - 1].to_string(), value);
}

/// 点路径移除(存在才删;中间段不是对象即忽略)。
fn remove_path(out: &mut Map<String, Value>, path: &str) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut cur = out;
    for part in &parts[..parts.len() - 1] {
        match cur.get_mut(*part) {
            Some(Value::Object(m)) => cur = m,
            _ => return,
        }
    }
    cur.remove(parts[parts.len() - 1]);
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
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    #[test]
    fn identity_passthrough_by_default() {
        let m = Mapper::new();
        let out = m.apply(&json!({ "a": 1, "b": { "c": [1, 2] } })).unwrap();
        assert_eq!(out, json!({ "a": 1, "b": { "c": [1, 2] } }));
        // 非对象输入报错
        assert!(m.apply(&json!([1, 2])).is_err());
        assert!(m.apply(&json!("x")).is_err());
        assert!(m.apply(&Value::Null).is_err());
    }

    #[test]
    fn rename_flat_and_nested() {
        let m = Mapper::new()
            .rename("user_name", "userName")
            .rename("profile.email", "email")
            .rename("token", "meta.token");
        let out = m
            .apply(&json!({
                "user_name": "alice",
                "profile": { "email": "a@x.com", "phone": "13800000000" },
                "token": "t-1",
            }))
            .unwrap();
        assert_eq!(out["userName"], "alice");
        assert_eq!(out["email"], "a@x.com");
        // 嵌套源里未搬移的兄弟字段保留
        assert_eq!(out["profile"]["phone"], "13800000000");
        // 源顶层字段已搬入嵌套目标
        assert_eq!(out["meta"]["token"], "t-1");
        assert!(out.get("user_name").is_none());
        assert!(out.get("token").is_none());
    }

    #[test]
    fn enum_mapping() {
        let m = Mapper::new().map_enum("status", |t| {
            t.entry(1, "active").entry(2, "disabled");
        });
        let out = m.apply(&json!({ "status": 1 })).unwrap();
        assert_eq!(out["status"], "active");
        // 未登记取值 fail-fast
        let err = m.apply(&json!({ "status": 3 })).unwrap_err();
        assert!(err.contains("no entry for `3`"), "err={err}");
        // rename + enum 组合
        let m2 = Mapper::new()
            .rename("user_type", "role")
            .map_enum("user_type", |t| {
                t.entry(0, "staff").entry(1, "guest");
            });
        let out = m2.apply(&json!({ "user_type": 1 })).unwrap();
        assert_eq!(out["role"], "guest");
    }

    #[test]
    fn defaults_exclude_and_whitelist() {
        let m = Mapper::new()
            .default_field("role", json!("viewer"))
            .default_field("nested.flag", json!(true))
            .exclude("secret");
        let out = m.apply(&json!({ "name": "a", "secret": "s" })).unwrap();
        assert_eq!(out["role"], "viewer");
        assert_eq!(out["nested"]["flag"], true);
        assert_eq!(out["name"], "a");
        assert!(out.get("secret").is_none());
        // 输入已有值时缺省不覆盖
        let out = m.apply(&json!({ "role": "admin" })).unwrap();
        assert_eq!(out["role"], "admin");

        // 白名单:未映射字段不透传
        let w = Mapper::new()
            .rename("id", "uid")
            .only_mapped()
            .default_field("kind", json!("user"));
        let out = w.apply(&json!({ "id": 7, "junk": true })).unwrap();
        assert_eq!(out, json!({ "uid": 7, "kind": "user" }));
    }

    #[test]
    fn typed_convert_roundtrip() {
        #[derive(Debug, Serialize)]
        struct Entity {
            user_name: String,
            status: i64,
            password_hash: String,
        }
        #[derive(Debug, PartialEq, Deserialize)]
        struct Dto {
            #[serde(rename = "userName")]
            user_name: String,
            status: String,
        }
        let m = Mapper::new()
            .rename("user_name", "userName")
            .map_enum("status", |t| {
                t.entry(0, "active").entry(1, "frozen");
            })
            .exclude("password_hash")
            .only_mapped();
        let e = Entity {
            user_name: "bob".into(),
            status: 1,
            password_hash: "x".into(),
        };
        let dto: Dto = m.convert(&e).unwrap();
        assert_eq!(
            dto,
            Dto {
                user_name: "bob".into(),
                status: "frozen".into(),
            }
        );
    }

    #[test]
    fn array_index_paths() {
        let m = Mapper::new().rename("items.0", "first");
        let out = m.apply(&json!({ "items": ["a", "b"] })).unwrap();
        assert_eq!(out["first"], "a");
        // 越界即跳过(交由 defaults)
        let m2 = Mapper::new()
            .rename("items.5", "x")
            .default_field("x", json!("fallback"));
        let out = m2.apply(&json!({ "items": ["a"] })).unwrap();
        assert_eq!(out["x"], "fallback");
    }
}
