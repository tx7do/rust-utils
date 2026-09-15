//! 字段掩码(feature `fieldmask`),作用于 `serde_json::Value`。
//!
//! [`NestedMask`] 为递归掩码树,提供构建与 Filter/Prune/
//! Overwrite/Validate。JSON 对象同时对应普通字段与 map 字段,
//! 统一采用保守语义(掩码内标量同样要求出现在掩码中,详见各
//! 方法文档)。
//!
//! - `Validate` 以模板 JSON 对象充当消息描述符(检查键存在
//!   与可下钻性);proto 消息描述符与字段号→路径转换不在
//!   范围内,不提供;
//! - `NormalizePaths`:先做 `id_`/`_id` → `id` 的修正,
//!   再转 snake_case([`crate::stringcase::snake_case`])。
//!
//! ```
//! use rust_utils::fieldmask::NestedMask;
//! use serde_json::json;
//!
//! let mut doc = json!({"a": 1, "b": {"c": 2, "d": 3}});
//! NestedMask::from_paths(&["b.c".to_string()]).filter(&mut doc);
//! assert_eq!(doc, json!({"b": {"c": 2}}));
//! ```

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::stringcase::snake_case;

/// 递归掩码树(叶子与空子树等价)。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NestedMask(BTreeMap<String, NestedMask>);

impl NestedMask {
    /// 由点分路径构建。
    ///
    /// 例如 `["foo.bar", "foo.baz"]` 得到 `{"foo": {"bar": {}, "baz": {}}}`。
    /// 空路径、空前段/后段为无效输入,跳过。
    pub fn from_paths(paths: &[String]) -> NestedMask {
        let mut mask = NestedMask::default();
        for p in paths {
            add_segment(p, &mut mask);
        }
        mask
    }

    /// 保留掩码列出的字段、清除其余。
    ///
    /// 空掩码不做任何事。复合值(对象、数组中的对象元素)在非空
    /// 子掩码下递归。
    pub fn filter(&self, value: &mut Value) {
        if self.0.is_empty() {
            return;
        }
        let Value::Object(map) = value else {
            return;
        };
        let keys: Vec<String> = map.keys().cloned().collect();
        for key in keys {
            match self.0.get(&key) {
                None => {
                    map.remove(&key);
                }
                Some(sub) if sub.0.is_empty() => {}
                Some(sub) => {
                    if let Some(v) = map.get_mut(&key) {
                        recurse_composite(sub, v, |m, v| m.filter(v));
                    }
                }
            }
        }
    }

    /// 清除掩码列出的字段、保留其余([`Self::filter`] 的反操作)。
    ///
    /// 标量键在非空子掩码下保留。
    pub fn prune(&self, value: &mut Value) {
        if self.0.is_empty() {
            return;
        }
        let Value::Object(map) = value else {
            return;
        };
        let keys: Vec<String> = map.keys().cloned().collect();
        for key in keys {
            match self.0.get(&key) {
                Some(sub) if sub.0.is_empty() => {
                    map.remove(&key);
                }
                Some(sub) => {
                    if let Some(v) = map.get_mut(&key) {
                        recurse_composite(sub, v, |m, v| m.prune(v));
                    }
                }
                None => {}
            }
        }
    }

    /// 把 `src` 中掩码列出的字段覆写到 `dest`。
    ///
    /// 空子掩码:源中存在且非 null 即整体覆盖,否则(缺失或
    /// null)清除目标键。非空子掩码:复合值递归,目标
    /// 侧缺失或类型不符的对象/数组先初始化再递归;数组按源长度
    /// 截断/补齐后逐元素处理。
    pub fn overwrite(&self, src: &Value, dest: &mut Value) {
        if self.0.is_empty() {
            return;
        }
        let (Value::Object(src_map), Value::Object(dest_map)) = (src, dest) else {
            return;
        };
        for (key, sub) in &self.0 {
            if sub.0.is_empty() {
                match src_map.get(key) {
                    Some(sv) if !sv.is_null() => {
                        dest_map.insert(key.clone(), sv.clone());
                    }
                    _ => {
                        dest_map.remove(key);
                    }
                }
            } else if let Some(sv) = src_map.get(key) {
                match sv {
                    Value::Object(_) => {
                        let entry = dest_map
                            .entry(key.clone())
                            .or_insert_with(|| Value::Object(Map::new()));
                        if entry.is_object() {
                            sub.overwrite(sv, entry);
                        }
                    }
                    Value::Array(src_items) => {
                        let entry = dest_map
                            .entry(key.clone())
                            .or_insert_with(|| Value::Array(Vec::new()));
                        if let Value::Array(dest_items) = entry {
                            dest_items.resize(src_items.len(), Value::Null);
                            for (si, di) in src_items.iter().zip(dest_items.iter_mut()) {
                                match si {
                                    Value::Object(_) => {
                                        if !di.is_object() {
                                            *di = Value::Object(Map::new());
                                        }
                                        sub.overwrite(si, di);
                                    }
                                    _ => *di = si.clone(),
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// 校验掩码路径对模板对象的合法性(模板 JSON 对象充当消息
    /// 描述符)。
    pub fn validate(&self, template: &Value) -> Result<(), String> {
        match self.validate_inner("", template) {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("invalid mask: {e}")),
        }
    }

    fn validate_inner(&self, path_prefix: &str, template: &Value) -> Result<(), String> {
        let Value::Object(tmpl) = template else {
            return Ok(());
        };
        for (field, submask) in &self.0 {
            let Some(tv) = tmpl.get(field) else {
                return Err(format!("unknown path: '{}'", full_path(path_prefix, field)));
            };
            if submask.0.is_empty() {
                continue;
            }
            let nested = match tv {
                Value::Object(_) => tv,
                Value::Array(items) => {
                    let Some(first) = items.iter().find(|i| i.is_object()) else {
                        return Err(format!(
                            "'{}': list element isn't message kind",
                            full_path(path_prefix, field)
                        ));
                    };
                    first
                }
                _ => {
                    return Err(format!(
                        "'{}': can't get nested fields",
                        full_path(path_prefix, field)
                    ));
                }
            };
            submask.validate_inner(&full_path(path_prefix, field), nested)?;
        }
        Ok(())
    }
}

fn add_segment(path: &str, mask: &mut NestedMask) {
    if path.is_empty() {
        return;
    }
    match path.split_once('.') {
        None => {
            mask.0.insert(path.to_string(), NestedMask::default());
        }
        Some((field, rest)) => {
            if field.is_empty() {
                return;
            }
            let nested = mask.0.entry(field.to_string()).or_default();
            add_segment(rest, nested);
        }
    }
}

fn recurse_composite(sub: &NestedMask, value: &mut Value, f: impl Fn(&NestedMask, &mut Value)) {
    match value {
        Value::Object(_) => f(sub, value),
        Value::Array(items) => {
            for item in items.iter_mut() {
                if item.is_object() {
                    f(sub, item);
                }
            }
        }
        _ => {}
    }
}

fn full_path(path_prefix: &str, field: &str) -> String {
    if path_prefix.is_empty() {
        return field.to_string();
    }
    format!("{path_prefix}.{field}")
}

/// 掩码路径归一化(`id_`/`_id` 修正为 `id`,再转 snake_case)。
pub fn normalize_paths(paths: &mut [String]) {
    for p in paths.iter_mut() {
        if p == "id_" || p == "_id" {
            *p = "id".to_string();
        }
        *p = snake_case(p);
    }
}

/// 返回顶层缺位(null 或缺失)的路径集合。
pub fn nil_value_paths(value: &Value, paths: &[String]) -> Vec<String> {
    let Value::Object(map) = value else {
        return Vec::new();
    };
    paths
        .iter()
        .filter(|p| matches!(map.get(*p), None | Some(Value::Null)))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_mask_from_paths_table() {
        // from_paths 的用例表
        assert_eq!(
            nested_mask_paths(&["a", "b", "c"]),
            m(&[("a", leaf()), ("b", leaf()), ("c", leaf())])
        );
        assert_eq!(
            nested_mask_paths(&["aaa.bb.c", "dd.e", "f"]),
            m(&[
                ("aaa", m(&[("bb", m(&[("c", leaf())]))])),
                ("dd", m(&[("e", leaf())])),
                ("f", leaf())
            ])
        );
        assert_eq!(nested_mask_paths(&["a"]), m(&[("a", leaf())]));
        assert_eq!(nested_mask_paths(&[]), NestedMask::default());
        assert_eq!(
            nested_mask_paths(&[".", "..", "...", ".a.", ""]),
            NestedMask::default()
        );
    }

    /// 路径列表构造(字符串切片便捷形态)。
    fn nested_mask_paths(paths: &[&str]) -> NestedMask {
        let owned: Vec<String> = paths.iter().map(|s| s.to_string()).collect();
        NestedMask::from_paths(&owned)
    }

    /// 期望树构造(叶子即空掩码)。
    fn m(fields: &[(&str, NestedMask)]) -> NestedMask {
        NestedMask(
            fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    fn leaf() -> NestedMask {
        NestedMask::default()
    }

    #[test]
    fn filter_keeps_listed() {
        let mut doc =
            json!({"a": 1, "b": {"c": 2, "d": 3}, "e": [ {"x": 1, "y": 2}, {"x": 3, "y": 4} ]});
        nested_mask_paths(&["b.c", "e.x"]).filter(&mut doc);
        assert_eq!(doc, json!({"b": {"c": 2}, "e": [ {"x": 1}, {"x": 3} ]}));
    }

    #[test]
    fn filter_empty_mask_keeps_all() {
        let mut doc = json!({"a": 1, "b": {"c": 2}});
        NestedMask::default().filter(&mut doc);
        assert_eq!(doc, json!({"a": 1, "b": {"c": 2}}));
    }

    #[test]
    fn prune_clears_listed() {
        let mut doc = json!({"a": 1, "b": {"c": 2, "d": 3}, "e": [{"x": 1, "y": 2}]});
        nested_mask_paths(&["b.c", "e.y"]).prune(&mut doc);
        assert_eq!(doc, json!({"a": 1, "b": {"d": 3}, "e": [{"x": 1}]}));
    }

    #[test]
    fn prune_scalar_with_nested_mask_kept() {
        // 保守语义:标量键 + 非空子掩码 → 保留
        let mut doc = json!({"a": 1, "b": 2});
        nested_mask_paths(&["b.zz"]).prune(&mut doc);
        assert_eq!(doc, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn overwrite_copies_masked() {
        let src = json!({"a": 1, "b": {"c": 2, "d": 3}, "keep": true});
        let mut dest = json!({"a": 0, "b": {"c": 0, "d": 0}, "unlisted": 9});
        nested_mask_paths(&["a", "b.d"]).overwrite(&src, &mut dest);
        // 掩码内:覆写;掩码外:不动
        assert_eq!(dest, json!({"a": 1, "b": {"c": 0, "d": 3}, "unlisted": 9}));
        assert!(src.get("keep").is_some());
    }

    #[test]
    fn overwrite_missing_src_clears_dest() {
        let src = json!({});
        let mut dest = json!({"a": 1, "b": 2});
        nested_mask_paths(&["a"]).overwrite(&src, &mut dest);
        assert_eq!(dest, json!({"b": 2}));
    }

    #[test]
    fn overwrite_creates_missing_objects_and_resizes_arrays() {
        let src = json!({"b": {"x": 1}, "arr": [{"x": 1}, {"x": 2}]});
        let mut dest = json!({"arr": [{"y": 9}]});
        nested_mask_paths(&["b.x", "arr.x"]).overwrite(&src, &mut dest);
        // 掩码外字段(y)按 Overwrite 语义保留;掩码内字段逐元素覆写,
        // 数组按源长度补齐
        assert_eq!(
            dest,
            json!({"b": {"x": 1}, "arr": [ {"x": 1, "y": 9}, {"x": 2} ]})
        );
    }

    #[test]
    fn overwrite_empty_mask_noop() {
        let src = json!({"a": 1});
        let mut dest = json!({"b": 2});
        NestedMask::default().overwrite(&src, &mut dest);
        assert_eq!(dest, json!({"b": 2}));
    }

    #[test]
    fn validate_paths() {
        let template = json!({"foo": {"bar": 1, "baz": 2}, "list": [{"inner": 1}]});
        assert!(nested_mask_paths(&["foo.bar", "foo", "list.inner"])
            .validate(&template)
            .is_ok());
        assert_eq!(
            nested_mask_paths(&["nope"])
                .validate(&template)
                .unwrap_err(),
            "invalid mask: unknown path: 'nope'"
        );
        assert_eq!(
            nested_mask_paths(&["foo.deep.nope"])
                .validate(&template)
                .unwrap_err(),
            "invalid mask: unknown path: 'foo.deep'"
        );
        assert_eq!(
            nested_mask_paths(&["scalar.deep"])
                .validate(&template)
                .unwrap_err(),
            // 顶层字段缺位(无前缀形态)
            "invalid mask: unknown path: 'scalar'"
        );
        let scalar_template = json!({"scalar": 1});
        assert_eq!(
            nested_mask_paths(&["scalar.deep"])
                .validate(&scalar_template)
                .unwrap_err(),
            "invalid mask: 'scalar': can't get nested fields"
        );
    }

    #[test]
    fn normalize_paths_snake_and_id() {
        let mut paths: Vec<String> = ["FooBar", "ID", "id_", "_id", "userName"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        normalize_paths(&mut paths);
        assert_eq!(paths, ["foo_bar", "id", "id", "id", "user_name"]);
    }

    #[test]
    fn nil_value_paths_top_level() {
        let doc = json!({"a": 1, "b": null});
        assert_eq!(
            nil_value_paths(&doc, &["a".to_string(), "b".to_string(), "c".to_string()]),
            vec!["b".to_string(), "c".to_string()]
        );
    }
}
