//! 字段级读写裁剪原语(feature `fieldperm`),作用于 [`serde_json::Value`]。
//!
//! 移植自 Go 库 `github.com/tx7do/go-utils/fieldperm`。隐藏字段集来源于令牌
//! claim(登录期按角色并集聚合),执行侧用它对消息做读写两向裁剪:
//!
//! - **读路径**([`apply_read_mask`] / [`apply_read_mask_list`]):就地清除
//!   (删键)命中的顶层字段;
//! - **写路径**([`strip_write_fields`]):清除载荷中命中字段的值,并从
//!   field_mask 路径中剔除命中项,防止 Update 的按 mask 过滤语义把已清空的
//!   值当作显式置零写库。
//!
//! # 重要取舍:protoreflect → serde_json
//!
//! 上游基于 protoreflect 反射操作 proto Message + `fieldmaskpb`,依赖
//! protoc 生成的字段描述符;Rust 侧无 protoc/描述符依赖,统一以
//! `serde_json::Value`(JSON 对象)为消息载体,路径语义逐式对齐 Go 源码:
//!
//! - **条目格式**:每条一个 `"资源.字段"` 串,**首个 `.` 切分**(对齐
//!   `strings.Cut`);无点号、资源名或字段名为空的条目整条静默跳过。上游
//!   **没有** `"res:field1,field2;res2:*"` 组合格式,也**没有** `*`(全隐藏)
//!   /`-` 之类的特殊字段语义——以此源码为准;重复条目靠集合去重。
//! - **"清除" = 删键而非置 null**:Go 的 `m.Clear(fd)` 是移除字段,配合
//!   protojson 默认不输出未填充字段,"清值"即"从 JSON 响应中移除"。Rust 端
//!   对应删除 JSON 键(而非置 `null`)。
//! - **双拼写命中**:Go 借描述符知道同一字段的 proto 名(snake_case)与
//!   json_name(camelCase)两种拼写并逐一比对;JSON 载体没有描述符,Rust 端
//!   改为对键名做 snake↔camel 拼写变体匹配(`to_json_name` 采用 protoc
//!   的 jsonName 规则),净效果与 Go 一致:隐藏集里放任一拼写都能命中同一
//!   字段。注意 `parse_token_entries` 本身**按原样存储**、不做拼写转换
//!   (对齐上游);因此**写路径**的 mask 路径剔除同样按原样逐字匹配(见
//!   [`strip_write_fields`]),令牌条目建议同时收录两种拼写。
//! - **只裁顶层,不递归**:与上游一致,嵌套对象/数组内部不受影响——本原语
//!   只管顶层业务字段。
//! - **`strip_write_fields` 不按 mask 白名单裁剪 data**(对齐 Go 源码与上游
//!   测试):"按 field_mask 路径白名单裁剪写入数据"是调用方 Update/
//!   `FilterByFieldMask` 的职责,本函数只做 ①清值 ②从 mask 路径中剔除
//!   顶层段命中项(`"field.sub"` 只看顶层段)。若确需白名单式子树裁剪,
//!   参见 [`crate::fieldmask::NestedMask::filter`]。
//! - **错误处理**:上游全部原语均不报错(非法条目静默跳过、未知字段忽略),
//!   故本模块 API 不引入 `Result`;如需 `Result<_, String>` 风格的掩码校验,
//!   参见 [`crate::fieldmask`]。
//!
//! # API 对照(Go → Rust)
//!
//! | Go | Rust | 说明 |
//! |----|------|------|
//! | `ParseTokenEntries` | [`parse_token_entries`] | `"资源.字段"` → 资源名 → 字段集合 |
//! | `HiddenFieldsOf` | [`hidden_fields_of`] | 无配置返回 `None`(对应 nil) |
//! | `IsEmpty` | [`is_empty`] | 空集 = 无需裁剪 |
//! | `ApplyReadMask` | [`apply_read_mask`] | 顶层命中字段删键,双拼写命中 |
//! | `ApplyReadMaskList` | [`apply_read_mask_list`] | 列表逐元素裁剪 |
//! | `StripWriteFields` | [`strip_write_fields`] | 清值 + 剔除 mask 命中路径 |
//!
//! # Examples
//!
//! ```
//! use rust_utils::fieldperm::{apply_read_mask, hidden_fields_of, strip_write_fields};
//! use serde_json::json;
//!
//! // 令牌 claim 里的隐藏字段条目:"资源.字段"(建议同时收录两种拼写)
//! let entries = vec![
//!     "User.passwordHash".to_string(),
//!     "User.password_hash".to_string(),
//!     "User.salt".to_string(),
//! ];
//! let hidden = hidden_fields_of(&entries, "User").unwrap();
//!
//! // 读路径:命中字段被就地删键,等价于从 JSON 响应中移除
//! let mut user = json!({"name": "alice", "passwordHash": "h4x", "salt": "s3cr3t"});
//! apply_read_mask(&mut user, &hidden);
//! assert_eq!(user, json!({"name": "alice"}));
//!
//! // 写路径:清值 + 从 field_mask 路径中剔除命中项(路径按顶层段逐字匹配)
//! let mut payload = json!({"name": "bob", "passwordHash": "leak"});
//! let mut mask = vec!["name".to_string(), "password_hash.sub".to_string()];
//! strip_write_fields(&mut payload, Some(&mut mask), &hidden);
//! assert_eq!(payload, json!({"name": "bob"}));
//! assert_eq!(mask, ["name"]);
//! ```

use std::collections::{HashMap, HashSet};

use serde_json::Value;

/// 单个资源的隐藏字段集(字段名按令牌条目原样存储,不转换拼写)。
///
/// 对应 Go 的 `map[string]struct{}`。
pub type HiddenFields = HashSet<String>;

/// 令牌条目的解析结果:资源名 → 隐藏字段集。
///
/// 对应 Go 的 `map[string]map[string]struct{}`。
pub type TokenHiddenMap = HashMap<String, HiddenFields>;

/// 把令牌隐藏字段条目(`"资源.字段"` 串)解析为资源名 → 字段名集合。
///
/// 语义逐式对齐 Go `ParseTokenEntries`:
///
/// - 在**第一个** `.` 处切分(`strings.Cut` 语义):`"a.b.c"` 解析为资源
///   `"a"`、字段 `"b.c"`;
/// - 无点号、资源名为空或字段名为空的条目整条静默跳过(不产生半截聚合);
/// - 字段名**按原样存入集合**,不做任何拼写转换;重复条目靠集合去重。
///
/// 返回值恒为映射结构(可能为空),对应 Go 的"非 nil 空结构"约定。
///
/// # Examples
///
/// ```
/// use rust_utils::fieldperm::parse_token_entries;
///
/// let entries = vec![
///     "User.passwordHash".to_string(),
///     "User.salt".to_string(),
///     "noDot".to_string(),
///     ".orphan".to_string(),
///     "User.passwordHash".to_string(), // 重复条目被去重
/// ];
/// let parsed = parse_token_entries(&entries);
/// assert_eq!(parsed.len(), 1);
/// assert!(parsed["User"].contains("passwordHash"));
/// assert!(parsed["User"].contains("salt"));
/// ```
pub fn parse_token_entries(entries: &[String]) -> TokenHiddenMap {
    let mut result = TokenHiddenMap::new();
    for entry in entries {
        // strings.Cut 语义:在第一个 '.' 处切分;无点号整条跳过。
        let Some((resource, field)) = entry.split_once('.') else {
            continue;
        };
        // 缺资源或缺字段的条目整条跳过。
        if resource.is_empty() || field.is_empty() {
            continue;
        }
        result
            .entry(resource.to_string())
            .or_default()
            .insert(field.to_string());
    }
    result
}

/// 返回指定资源在令牌条目中的隐藏字段集;无配置返回 `None`(对应 Go 的 nil)。
///
/// 与 Go 一致,每次调用重新解析;需要按资源多次取用时,可先
/// [`parse_token_entries`] 一次再自行查表。
///
/// # Examples
///
/// ```
/// use rust_utils::fieldperm::hidden_fields_of;
///
/// let entries = vec!["User.passwordHash".to_string()];
/// assert!(hidden_fields_of(&entries, "User").is_some());
/// assert!(hidden_fields_of(&entries, "Order").is_none());
/// ```
pub fn hidden_fields_of(entries: &[String], resource: &str) -> Option<HiddenFields> {
    let mut parsed = parse_token_entries(entries);
    parsed.remove(resource)
}

/// 判断隐藏字段集是否为空(空集 = 无需裁剪)。
///
/// 对应 Go `IsEmpty`:nil 与空 map 均为空;Rust 端空集即
/// [`HiddenFields::new()`]。
pub fn is_empty(hidden: &HiddenFields) -> bool {
    hidden.is_empty()
}

/// 就地清除消息(JSON 对象)顶层命中隐藏集的字段。
///
/// 语义逐式对齐 Go `ApplyReadMask`:
///
/// - **双拼写命中**:隐藏集里放 proto 字段名(snake_case)或 json_name
///   (camelCase)都能命中同一字段(Go 先按 `fd.Name()` 再按 `fd.JSONName()`
///   比对;JSON 载体无描述符,这里对键名做拼写变体匹配,净效果一致);
/// - **只裁顶层,不递归**:嵌套对象、数组内部的同名字段不受影响;
/// - 空隐藏集 no-op;
/// - 非对象载体(`null`/标量/数组)等价于 Go 的 nil/无效消息,安静返回,
///   不 panic。
///
/// # Examples
///
/// ```
/// use rust_utils::fieldperm::{apply_read_mask, HiddenFields};
/// use serde_json::json;
///
/// let mut msg = json!({"name": "alice", "passwordHash": "h4x"});
/// // proto 名与 json_name 两种拼写任选其一即可命中
/// let hidden: HiddenFields = ["password_hash", "passwordHash"]
///     .iter()
///     .map(|s| s.to_string())
///     .collect();
/// apply_read_mask(&mut msg, &hidden);
/// assert_eq!(msg, json!({"name": "alice"}));
/// ```
pub fn apply_read_mask(msg: &mut Value, hidden: &HiddenFields) {
    if is_empty(hidden) {
        return;
    }
    let Value::Object(map) = msg else {
        // nil/无效消息等价物:安静返回。
        return;
    };
    map.retain(|key, _| !hits_hidden(hidden, key));
}

/// 对消息列表逐个应用读裁剪(List 响应的 items)。
///
/// 对应泛型版 Go `ApplyReadMaskList`:`items` 为 JSON 数组的元素切片
/// (`Value::Array` 可先 `as_array_mut` 再传入)。空隐藏集整体 no-op。
pub fn apply_read_mask_list(items: &mut [Value], hidden: &HiddenFields) {
    if is_empty(hidden) {
        return;
    }
    for item in items {
        apply_read_mask(item, hidden);
    }
}

/// 剥离写请求载荷中的隐藏字段。
///
/// 语义逐式对齐 Go `StripWriteFields`:
///
/// 1. 对 `data` 应用 [`apply_read_mask`](双拼写清值,ent 侧 nil-skip 语义下
///    等于"忽略该字段");
/// 2. 从 `field_mask` 路径中**逐字**剔除命中项:路径可能是 `"field"` 或
///    `"field.sub"`,**顶层段**命中隐藏集即整条剔除;此处不做拼写转换
///    (上游测试佐证:隐藏集存 `createdBy` 时,mask 路径 `created_by` 不会被
///    剔除,仅字段值被清)——防止"mask 声明了该字段但值为零"被当成显式清空
///    写库。为保证写路径完整防护,令牌条目建议同时收录两种拼写。
///
/// `field_mask` 用点分路径的 [`Vec`]`<`[`String`]`>` 承载,`None` 对应 Go 的
/// nil `*fieldmaskpb.FieldMask`(仅清值,不触碰任何 mask);空路径列表同样
/// 不做剔除。空隐藏集下 data 与 mask 均原样不动。
///
/// 注意:本函数**不**按 field_mask 白名单裁剪 `data`——那是调用方 Update
/// 的 `FilterByFieldMask` 语义的职责(如需白名单式子树裁剪,参见
/// [`crate::fieldmask::NestedMask::filter`])。
///
/// # Examples
///
/// ```
/// use rust_utils::fieldperm::{strip_write_fields, HiddenFields};
/// use serde_json::json;
///
/// let hidden: HiddenFields = ["passwordHash", "password_hash"]
///     .iter()
///     .map(|s| s.to_string())
///     .collect();
/// let mut payload = json!({"name": "bob", "passwordHash": "leak"});
/// let mut mask = vec!["name".to_string(), "passwordHash.reveal".to_string()];
/// strip_write_fields(&mut payload, Some(&mut mask), &hidden);
/// assert_eq!(payload, json!({"name": "bob"}));
/// // 顶层段 "passwordHash" 命中,"passwordHash.reveal" 整条被剔除
/// assert_eq!(mask, ["name"]);
/// ```
pub fn strip_write_fields(
    data: &mut Value,
    field_mask: Option<&mut Vec<String>>,
    hidden: &HiddenFields,
) {
    if is_empty(hidden) {
        return;
    }

    apply_read_mask(data, hidden);

    if let Some(paths) = field_mask {
        // field_mask 路径可能是 "field" 或 "field.sub"——顶层段命中即整条剔除。
        // 逐字比对(strings.IndexByte 取顶层段),不做拼写转换。
        paths.retain(|p| {
            let top = match p.find('.') {
                Some(idx) => &p[..idx],
                None => p.as_str(),
            };
            !hidden.contains(top)
        });
    }
}

/// 双拼写命中判定:键名直接命中,或其 snake↔camel 拼写变体命中。
///
/// Go 版借 protoreflect 描述符枚举字段的 proto 名与 json_name 两种拼写并逐一
/// 比对;JSON 载体没有描述符,这里对**现存键名**同时尝试两种拼写变体:
/// - snake_case 键按 protoc jsonName 规则转 camel;
/// - camelCase 键按"大写字母前插下划线并转小写"转 snake;
/// - 两种拼写一致的键(如 `description`)变体与原样相同,不重复比对。
///
/// 净效果与 Go 一致:隐藏集里放任一拼写都能命中同一字段。
fn hits_hidden(hidden: &HiddenFields, key: &str) -> bool {
    if hidden.contains(key) {
        return true;
    }
    let camel = to_json_name(key);
    if camel != key && hidden.contains(&camel) {
        return true;
    }
    let snake = to_snake_name(key);
    snake != key && hidden.contains(&snake)
}

/// protoc 的 jsonName 规则([`ToJsonName`]):去掉下划线,并把下划线后的首个
/// 字母大写;其余字符原样保留。`created_by` → `createdBy`;无下划线时原样返回。
///
/// [`ToJsonName`]: https://github.com/protocolbuffers/protobuf
fn to_json_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut cap_next = false;
    for ch in name.chars() {
        if ch == '_' {
            cap_next = true;
            continue;
        }
        if cap_next {
            out.extend(ch.to_uppercase());
            cap_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// camelCase → snake_case(推测 proto 字段名):每个大写字母前插下划线并转
/// 小写(首个字符除外)。`createdBy` → `created_by`;无大写字母时原样返回。
fn to_snake_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `strip_write_fields_mask_path_filtering` 的用例五元组(名字、输入、mask、hidden、期望)。
    type MaskCase<'a> = (
        &'a str,
        &'a str,
        &'a [&'a str],
        &'a [&'a str],
        Option<&'a str>,
    );
    use serde_json::json;

    /// Plan 消息参与测试的三个字段的 json_name 键名(对齐上游 testpb.Plan):
    /// `created_by` 的 json_name(createdBy)与 proto 名拼写不同,
    /// 覆盖双拼写命中路径;description / remark 两种拼写一致,作保留对照。
    const KEY_CREATED_BY: &str = "createdBy";
    const KEY_DESCRIPTION: &str = "description";
    const KEY_REMARK: &str = "remark";
    const ALL_PLAN_JSON_KEYS: [&str; 3] = [KEY_CREATED_BY, KEY_DESCRIPTION, KEY_REMARK];

    /// 对齐上游 newPopulatedPlan:三字段全部填充的 Plan 消息
    /// (proto 字段用 JSON 对象模拟,protojson 输出即 json_name 键)。
    fn new_populated_plan() -> Value {
        json!({
            "createdBy": 42,
            "description": "desc-value",
            "remark": "remark-value"
        })
    }

    /// 对齐上游 assertKeys:断言消息对象中各键的存在性。
    /// serde_json 载体下直接断言对象键,比 protojson 字符串包含更强且等价。
    fn assert_keys(ctx: &str, msg: &Value, present: &[&str], absent: &[&str]) {
        let map = msg
            .as_object()
            .unwrap_or_else(|| panic!("[{ctx}] 消息载体必须是 JSON 对象"));
        for k in present {
            assert!(map.contains_key(*k), "[{ctx}] 字段 {k} 应保留在输出中");
        }
        for k in absent {
            assert!(!map.contains_key(*k), "[{ctx}] 字段 {k} 应被从输出中清除");
        }
    }

    /// 构造隐藏集。
    fn hidden(items: &[&str]) -> HiddenFields {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// 构造令牌条目列表。
    fn entries(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// 构造期望的解析结果:资源名 → 字段集合。
    fn res_map(spec: &[(&str, &[&str])]) -> TokenHiddenMap {
        spec.iter()
            .map(|(resource, fields)| ((*resource).to_string(), hidden(fields)))
            .collect()
    }

    // ===== parse_test.go 移植 =====

    /// 对齐 TestParseTokenEntries_ValidEntriesAggregated:合法条目按资源聚合,
    /// 重复条目被集合去重;空输入得到空映射(非"nil")。
    #[test]
    fn parse_token_entries_valid_entries_aggregated() {
        let cases: [(&str, &[&str], TokenHiddenMap); 4] = [
            (
                "single entry",
                &["resourceA.fieldX"],
                res_map(&[("resourceA", &["fieldX"])]),
            ),
            (
                "multiple resources and fields aggregated",
                &["resourceA.field1", "resourceB.field2", "resourceA.field3"],
                res_map(&[
                    ("resourceA", &["field1", "field3"]),
                    ("resourceB", &["field2"]),
                ]),
            ),
            (
                "duplicate entries deduplicated by set",
                &["resourceA.field1", "resourceA.field1"],
                res_map(&[("resourceA", &["field1"])]),
            ),
            ("empty input yields empty map", &[], TokenHiddenMap::new()),
        ];
        for (name, input, expected) in cases {
            let got = parse_token_entries(&entries(input));
            assert_eq!(got, expected, "case {name}");
        }
    }

    /// 对齐 TestParseTokenEntries_InvalidEntriesSkipped:缺资源、缺字段或无点号
    /// 的条目整条跳过,不得产生半截聚合,也不得污染其它合法条目。
    #[test]
    fn parse_token_entries_invalid_entries_skipped() {
        let cases: [(&str, &[&str], TokenHiddenMap); 5] = [
            ("no dot separator", &["nodot"], TokenHiddenMap::new()),
            ("missing resource", &[".fieldOnly"], TokenHiddenMap::new()),
            ("missing field", &["resourceOnly."], TokenHiddenMap::new()),
            ("empty string entry", &[""], TokenHiddenMap::new()),
            (
                "invalid entries mixed with valid ones",
                &["goodRes.goodField", "bad-no-dot", ".noRes", "noField.", ""],
                res_map(&[("goodRes", &["goodField"])]),
            ),
        ];
        for (name, input, expected) in cases {
            let got = parse_token_entries(&entries(input));
            assert_eq!(got, expected, "case {name}");
        }
    }

    /// 对齐 TestParseTokenEntries_CutsAtFirstDot:首个点号处切分,
    /// `"a.b.c"` 解析为资源 `"a"`、字段 `"b.c"`——记录该切分语义。
    #[test]
    fn parse_token_entries_cuts_at_first_dot() {
        let got = parse_token_entries(&entries(&["a.b.c"]));
        assert_eq!(got.len(), 1);
        assert!(got.contains_key("a"));
        assert_eq!(got["a"], hidden(&["b.c"]));
    }

    /// 对齐 TestHiddenFieldsOf_HitAndMiss:命中资源返回其字段集合;
    /// 未命中资源(含从未出现的资源)返回 `None`。
    #[test]
    fn hidden_fields_of_hit_and_miss() {
        let entries = entries(&["resourceA.field1", "resourceA.field2", "resourceB.field3"]);

        let hit = hidden_fields_of(&entries, "resourceA").expect("命中的资源必须返回字段集合");
        assert_eq!(hit, hidden(&["field1", "field2"]));

        for missing in ["resourceB.typo", "resourceC", ""] {
            assert!(
                hidden_fields_of(&entries, missing).is_none(),
                "未命中资源 {missing} 必须返回 None"
            );
        }
    }

    /// 对齐 TestIsEmpty:空集为空(无需裁剪),非空集合不为空。
    /// Go 的 nil 与空 map 在 Rust 端同为空集。
    #[test]
    fn is_empty_matches_go_semantics() {
        let cases: [(&str, HiddenFields, bool); 3] = [
            ("nil map", hidden(&[]), true),
            ("empty map", HiddenFields::new(), true),
            ("non-empty map", hidden(&["x"]), false),
        ];
        for (name, set, want) in cases {
            assert_eq!(is_empty(&set), want, "case {name}");
        }
    }

    // ===== mask_test.go 移植 =====

    /// 对齐 TestApplyReadMask_HiddenSpellingVariants:隐藏集里无论放 json_name
    /// 拼写还是 proto 字段名拼写,都应命中同一字段并清除之;未命中字段保留。
    #[test]
    fn apply_read_mask_hidden_spelling_variants() {
        let cases: [(&str, &str, &str); 4] = [
            ("json spelling hit", "createdBy", KEY_CREATED_BY),
            ("proto spelling hit", "created_by", KEY_CREATED_BY),
            ("same-spelling field hit", "description", KEY_DESCRIPTION),
            ("same-spelling field hit remark", "remark", KEY_REMARK),
        ];
        for (name, spelling, absent_key) in cases {
            let mut plan = new_populated_plan();
            // 前置:裁剪前三键俱全。
            assert_keys(name, &plan, &ALL_PLAN_JSON_KEYS, &[]);

            apply_read_mask(&mut plan, &hidden(&[spelling]));

            let kept: Vec<&str> = ALL_PLAN_JSON_KEYS
                .iter()
                .copied()
                .filter(|k| *k != absent_key)
                .collect();
            assert_keys(name, &plan, &kept, &[absent_key]);
        }
    }

    /// 对齐 TestApplyReadMask_NonMatchingHiddenSet:未知字段名/空集不清除任何
    /// 字段(Go 的 nil 集在 Rust 端同为空集)。
    #[test]
    fn apply_read_mask_non_matching_hidden_set() {
        let cases: [(&str, HiddenFields); 3] = [
            ("unknown field name", hidden(&["noSuchField"])),
            ("empty hidden set", hidden(&[])),
            ("nil hidden set", HiddenFields::new()),
        ];
        for (name, set) in cases {
            let mut plan = new_populated_plan();
            apply_read_mask(&mut plan, &set);
            assert_keys(name, &plan, &ALL_PLAN_JSON_KEYS, &[]);
        }
    }

    /// 对齐 TestApplyReadMask_NilMessage:nil 消息入参必须安静返回,不得 panic。
    /// Rust 载体下以 `Value::Null` 模拟 nil 消息。
    #[test]
    fn apply_read_mask_nil_message_quiet() {
        let mut null_msg = Value::Null;
        apply_read_mask(&mut null_msg, &hidden(&["createdBy"]));
        assert_eq!(null_msg, Value::Null);
    }

    /// 对齐 TestApplyReadMask_TypedNilMessageInvalid:类型化 nil(接口非 nil 但
    /// 指针为 nil)的反射消息无效,应安静返回。Rust 载体下以非对象值
    /// (标量/数组)模拟无效消息:整体不进入字段遍历,数组元素也不被递归触碰。
    #[test]
    fn apply_read_mask_invalid_message_quiet() {
        let mut scalar = json!("createdBy");
        apply_read_mask(&mut scalar, &hidden(&["createdBy"]));
        assert_eq!(scalar, json!("createdBy"));

        let mut arr = json!([{"createdBy": 1}]);
        apply_read_mask(&mut arr, &hidden(&["createdBy"]));
        assert_eq!(arr, json!([{"createdBy": 1}]));
    }

    /// 对齐 TestApplyReadMaskList_AppliesToEveryItem:列表裁剪必须作用于每个
    /// 元素,命中字段(双拼写)在所有元素上都被清除。
    #[test]
    fn apply_read_mask_list_applies_to_every_item() {
        for spelling in ["createdBy", "created_by"] {
            let mut plans = vec![
                new_populated_plan(),
                new_populated_plan(),
                new_populated_plan(),
            ];
            apply_read_mask_list(&mut plans, &hidden(&[spelling]));
            // 每个元素都必须被裁剪,无一遗漏。
            for (i, plan) in plans.iter().enumerate() {
                assert_keys(
                    &format!("spelling/{spelling}/item{i}"),
                    plan,
                    &[KEY_DESCRIPTION, KEY_REMARK],
                    &[KEY_CREATED_BY],
                );
            }
        }
    }

    /// 对齐 TestApplyReadMaskList_EmptyHiddenSetNoop:空隐藏集下列表整体不动
    /// (Go 的 nil 与空 map 在 Rust 端同为空集)。
    #[test]
    fn apply_read_mask_list_empty_hidden_set_noop() {
        let mut plans = vec![new_populated_plan(), new_populated_plan()];
        for hidden_set in [hidden(&[]), HiddenFields::new()] {
            apply_read_mask_list(&mut plans, &hidden_set);
            for (i, plan) in plans.iter().enumerate() {
                assert_keys(&format!("hidden#{i}"), plan, &ALL_PLAN_JSON_KEYS, &[]);
            }
        }
    }

    /// 对齐 TestStripWriteFields_MaskPathFiltering:写路径裁剪——
    /// data 消息按读路径规则清值(双拼写);field_mask 路径中顶层段命中隐藏集
    /// 的路径(含 "field.sub" 只看顶层段的形式)被整条剔除,未命中路径保留且
    /// 顺序不变。注意路径剔除按字面量查集合:顶层段拼写必须与集合键完全一致。
    #[test]
    fn strip_write_fields_mask_path_filtering() {
        let cases: [MaskCase; 4] = [
            (
                "proto spelling hit removes path with and without sub-path",
                "created_by",
                &["created_by", "created_by.sub", "description", "remark.sub"],
                &["description", "remark.sub"],
                Some(KEY_CREATED_BY),
            ),
            (
                "same-spelling hit removes nested-top path",
                "description",
                &["description", "description.deep.sub", "remark"],
                &["remark"],
                Some(KEY_DESCRIPTION),
            ),
            (
                "json spelling clears data but not mask path",
                "createdBy",
                &["created_by", "description"],
                &["created_by", "description"],
                Some(KEY_CREATED_BY),
            ),
            (
                "unrelated hidden key keeps everything",
                "zzz",
                &["description", "remark"],
                &["description", "remark"],
                None,
            ),
        ];
        for (name, hidden_key, paths, want_paths, cleared) in cases {
            let mut plan = new_populated_plan();
            let mut mask: Vec<String> = paths.iter().map(|p| (*p).to_string()).collect();

            strip_write_fields(&mut plan, Some(&mut mask), &hidden(&[hidden_key]));

            // data 部分:命中的字段被清值,其余保留。
            let kept: Vec<&str> = ALL_PLAN_JSON_KEYS
                .iter()
                .copied()
                .filter(|k| Some(*k) != cleared)
                .collect();
            let absent: &[&str] = match cleared {
                Some(k) => &[k],
                None => &[],
            };
            assert_keys(name, &plan, &kept, absent);

            // mask 部分:路径按顶层段命中情况过滤,顺序保持不变。
            assert_eq!(mask, want_paths, "case {name}: mask 路径过滤结果");
        }
    }

    /// 对齐 TestStripWriteFields_NilAndEmptyMask:nil(`None`)或空路径的 mask
    /// 不做任何剔除,但 data 消息仍按隐藏集正常清值。
    #[test]
    fn strip_write_fields_nil_and_empty_mask() {
        // nil mask:Go 的 var mask *fieldmaskpb.FieldMask = nil → Rust 的 None。
        let mut plan = new_populated_plan();
        strip_write_fields(&mut plan, None, &hidden(&["created_by"]));
        assert_keys(
            "nil mask",
            &plan,
            &[KEY_DESCRIPTION, KEY_REMARK],
            &[KEY_CREATED_BY],
        );

        // 空路径 mask:data 清值照常,mask 保持为空。
        let mut plan = new_populated_plan();
        let mut mask: Vec<String> = Vec::new();
        strip_write_fields(&mut plan, Some(&mut mask), &hidden(&["description"]));
        assert_keys(
            "empty paths mask",
            &plan,
            &[KEY_CREATED_BY, KEY_REMARK],
            &[KEY_DESCRIPTION],
        );
        assert!(mask.is_empty());
    }

    /// 对齐 TestStripWriteFields_EmptyHiddenSetNoop:空隐藏集下 data 与 mask 均
    /// 原样不动(Go 的 nil 与空 map 在 Rust 端同为空集)。
    #[test]
    fn strip_write_fields_empty_hidden_set_noop() {
        for hidden_set in [hidden(&[]), HiddenFields::new()] {
            let mut plan = new_populated_plan();
            let mut mask = vec!["description".to_string(), "remark".to_string()];
            strip_write_fields(&mut plan, Some(&mut mask), &hidden_set);
            assert_keys("empty hidden", &plan, &ALL_PLAN_JSON_KEYS, &[]);
            assert_eq!(mask, ["description", "remark"]);
        }
    }

    /// 对齐 TestApplyReadMask_ProtectedFieldsSanityBeforeMasking:前置健全性
    /// 检查——未裁剪前三个字段都以 json_name 拼写出现,保证后续"消失"断言
    /// 确实源于裁剪而非构造缺省。
    #[test]
    fn apply_read_mask_protected_fields_sanity_before_masking() {
        let plan = new_populated_plan();
        for k in ALL_PLAN_JSON_KEYS {
            assert!(
                plan.as_object().unwrap().contains_key(k),
                "字段 {k} 初始必须存在"
            );
        }
    }

    // ===== serde_json 载体特有边界(嵌套对象、数组、双拼写键并存) =====

    /// 只裁顶层、不递归:顶层无命中的情况下,嵌套对象里的同名字段不受影响
    /// (对齐上游"本原语只管顶层业务字段"的语义);隐藏顶层键则整棵子树清除。
    #[test]
    fn read_mask_not_recursive_on_nested_objects() {
        let mut msg = json!({"profile": {"passwordHash": "h4x", "name": "n"}, "name": "alice"});
        apply_read_mask(&mut msg, &hidden(&["passwordHash"]));
        assert_eq!(
            msg,
            json!({"profile": {"passwordHash": "h4x", "name": "n"}, "name": "alice"}),
            "嵌套对象内部不受影响"
        );

        let mut msg = json!({"profile": {"passwordHash": "h4x"}, "name": "alice"});
        apply_read_mask(&mut msg, &hidden(&["profile"]));
        assert_eq!(msg, json!({"name": "alice"}), "隐藏顶层键清除整棵子树");
    }

    /// 数组字段:整体作为顶层字段可被隐藏清除;数组元素对象的内部字段不被
    /// 递归触碰。
    #[test]
    fn read_mask_array_fields_not_recurse() {
        let mut msg = json!({"items": [{"secret": 1}, {"secret": 2}], "total": 2});
        apply_read_mask(&mut msg, &hidden(&["secret"]));
        assert_eq!(
            msg,
            json!({"items": [{"secret": 1}, {"secret": 2}], "total": 2}),
            "数组元素内部不被递归裁剪"
        );

        let mut msg = json!({"items": [{"secret": 1}, {"secret": 2}], "total": 2});
        apply_read_mask(&mut msg, &hidden(&["items"]));
        assert_eq!(msg, json!({"total": 2}), "数组字段本身可被隐藏清除");
    }

    /// JSON 载体允许同一字段的双拼写键并存(Go 单消息不可能):隐藏集任一
    /// 拼写命中时,两种拼写的键都应被清除。
    #[test]
    fn read_mask_clears_both_spelled_keys() {
        let mut msg = json!({"created_by": 1, "createdBy": 2, "description": "d"});
        apply_read_mask(&mut msg, &hidden(&["created_by"]));
        assert_eq!(msg, json!({"description": "d"}));
    }
}
