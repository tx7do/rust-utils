//! 模板驱动的代码生成器(feature `code-generator`,serde_json 上下文)。
//!
//! 对齐上游 `go-utils/code_generator` 的定位:内嵌/文件系统模板 + 渲染 +
//! 按规则落盘,给管理后台的 CRUD 代码生成流程当后端。模板语法为 mustache
//! 子集(纯 std 手写,不引模板引擎依赖):
//!
//! - `{{field}}` / `{{user.name}}` —— 点路径取值;**缺失即报错**(代码生成
//!   宁可失败也不静默产出空壳);
//! - `{{.}}` —— 当前上下文值(数组元素的标量渲染用);
//! - `{{#field}}…{{/field}}` —— 段落:对象 → 以其为上下文渲染一次;数组 →
//!   逐元素渲染;真值标量 → 以当前上下文渲染一次;缺失/false/空数组 → 跳过;
//! - `{{^field}}…{{/field}}` —— 反转段落(缺失/false/空数组时渲染);
//! - 不做 HTML 转义(目标是代码/配置,不是网页)。
//!
//! 落盘([`Generator::render_to`]):输出文件名同样吃模板占位;缺省拒绝
//! 覆盖已有文件,渲染出的路径不允许逃出输出目录(fail-closed)。
//!
//! ```
//! use rust_utils::code_generator::{CodeTemplate, Generator};
//! use serde_json::json;
//!
//! let g = Generator::new().register(CodeTemplate {
//!     name: "model.rs.tmpl".into(),
//!     content: "pub struct {{.Struct}} {\n{{#fields}}    pub {{.name}}: {{.ty}},\n{{/fields}}}\n".into(),
//! });
//! let code = g.render("model.rs.tmpl", &json!({
//!     "Struct": "User",
//!     "fields": [
//!         { "name": "id", "ty": "u64" },
//!         { "name": "name", "ty": "String" },
//!     ],
//! })).unwrap();
//! assert!(code.contains("pub struct User {"));
//! assert!(code.contains("pub id: u64,"));
//! assert!(code.contains("pub name: String,"));
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// 一份命名模板。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeTemplate {
    /// 模板名(目录来源时为相对路径,`/` 分隔)。
    pub name: String,
    /// 模板正文。
    pub content: String,
}

/// 模板生成器:装载模板、按 JSON 上下文渲染、按规则落盘。
#[derive(Debug, Clone, Default)]
pub struct Generator {
    templates: HashMap<String, String>,
    /// 落盘是否允许覆盖已有文件(缺省拒绝,fail-closed)。
    pub overwrite: bool,
}

impl Generator {
    /// 空生成器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册一份模板(链式;同名覆盖)。
    pub fn register(mut self, template: CodeTemplate) -> Self {
        self.templates.insert(template.name, template.content);
        self
    }

    /// 批量注册。
    pub fn register_all(mut self, templates: impl IntoIterator<Item = CodeTemplate>) -> Self {
        for t in templates {
            self.templates.insert(t.name, t.content);
        }
        self
    }

    /// 从目录装载:递归收集全部文件,模板名为相对路径(`/` 分隔)。
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, String> {
        let dir = dir.as_ref();
        if !dir.is_dir() {
            return Err(format!(
                "code_generator: `{}` is not a directory",
                dir.display()
            ));
        }
        let mut templates = Vec::new();
        collect_templates(dir, dir, &mut templates)?;
        Ok(Generator::new().register_all(templates))
    }

    /// 已装载的模板名(无序)。
    pub fn template_names(&self) -> Vec<&str> {
        self.templates.keys().map(String::as_str).collect()
    }

    /// 渲染指定模板。
    pub fn render(&self, name: &str, ctx: &Value) -> Result<String, String> {
        let content = self
            .templates
            .get(name)
            .ok_or_else(|| format!("code_generator: unknown template `{name}`"))?;
        render_template(content, ctx)
    }

    /// 渲染并落盘:`out_path` 自身可含 `{{占位}}`(以同一上下文渲染),
    /// 结果为相对路径时落在 `out_dir` 下;缺省拒绝覆盖。
    pub fn render_to(
        &self,
        name: &str,
        ctx: &Value,
        out_dir: impl AsRef<Path>,
        out_path: &str,
    ) -> Result<PathBuf, String> {
        let rendered = self.render(name, ctx)?;
        let file = render_template(out_path, ctx)?;
        if file.is_empty() {
            return Err("code_generator: rendered output path is empty".into());
        }
        let target = join_and_check(out_dir.as_ref(), &file)?;

        if target.exists() && !self.overwrite {
            return Err(format!(
                "code_generator: refuse to overwrite `{}` (set overwrite=true to allow)",
                target.display()
            ));
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("code_generator: create dir `{}`: {e}", parent.display()))?;
        }
        std::fs::write(&target, rendered)
            .map_err(|e| format!("code_generator: write `{}`: {e}", target.display()))?;
        Ok(target)
    }
}

fn collect_templates(root: &Path, dir: &Path, out: &mut Vec<CodeTemplate>) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("code_generator: read dir `{}`: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_templates(root, &path, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("code_generator: strip prefix: {e}"))?;
            let name = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let content = std::fs::read_to_string(&path)
                .map_err(|e| format!("code_generator: read `{}`: {e}", path.display()))?;
            out.push(CodeTemplate { name, content });
        }
    }
    Ok(())
}

/// `out_dir` + 渲染出的相对路径;拒绝绝对路径与 `..` 逃逸。
fn join_and_check(out_dir: &Path, file: &str) -> Result<PathBuf, String> {
    if Path::new(file).is_absolute() {
        return Err(format!(
            "code_generator: output path must be relative, got `{file}`"
        ));
    }
    let joined = out_dir.join(file);
    // 逐段检查(规范化对不存在的路径不可靠)
    for comp in Path::new(file).components() {
        if matches!(comp, std::path::Component::ParentDir) {
            return Err(format!(
                "code_generator: output path must not contain `..`, got `{file}`"
            ));
        }
    }
    Ok(joined)
}

// ---------------------------------------------------------------------------
// mustache 子集渲染引擎
// ---------------------------------------------------------------------------

const MAX_RENDER_DEPTH: usize = 64;

fn render_template(template: &str, ctx: &Value) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    render_into(&mut out, template, ctx, 0)?;
    Ok(out)
}

fn render_into(out: &mut String, template: &str, ctx: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_RENDER_DEPTH {
        return Err("code_generator: template nesting too deep (possible runaway section)".into());
    }
    let chars = template.char_indices().peekable();
    let bytes = template.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        match template[cursor..].find("{{") {
            Some(rel) => {
                let tag_start = cursor + rel;
                out.push_str(&template[cursor..tag_start]);
                let close = match template[tag_start + 2..].find("}}") {
                    Some(r) => tag_start + 2 + r,
                    None => {
                        return Err("code_generator: unclosed `{{` in template".into());
                    }
                };
                let tag = template[tag_start + 2..close].trim();
                cursor = close + 2;
                match tag.chars().next() {
                    // 段落 / 反转段落:找到配对闭合标签,递归渲染
                    Some('#') | Some('^') => {
                        let inverted = tag.starts_with('^');
                        let key = tag[1..].trim();
                        let (body, next) = find_section_end(template, cursor, key)?;
                        cursor = next;
                        if should_enter(ctx, key) != inverted {
                            let val = lookup(ctx, key);
                            match val {
                                // 数组:逐元素,元素即上下文
                                Ok(Value::Array(items)) if !inverted => {
                                    for item in items {
                                        render_into(out, body, item, depth + 1)?;
                                    }
                                }
                                // 对象:以其为上下文渲染一次
                                Ok(v @ Value::Object(_)) => {
                                    render_into(out, body, v, depth + 1)?;
                                }
                                // 标量真值 / 反转段落的假值:上下文不变渲染一次
                                _ => render_into(out, body, ctx, depth + 1)?,
                            }
                        }
                    }
                    // 当前上下文值(`{{.}}`);`{{.field}}` 等价点路径(兼容 Go 习惯)
                    Some('.') if tag == "." => {
                        out.push_str(&value_to_string(ctx)?);
                    }
                    _ => {
                        out.push_str(&value_to_string(lookup(ctx, tag)?)?);
                    }
                }
            }
            None => {
                out.push_str(&template[cursor..]);
                break;
            }
        }
        let _ = chars;
    }
    Ok(())
}

/// 找到与起点段标签配对的 `{{/key}}`(支持同名嵌套),返回
/// (段体, 闭合标签之后的偏移)。
fn find_section_end<'a>(
    template: &'a str,
    start: usize,
    key: &str,
) -> Result<(&'a str, usize), String> {
    let mut depth = 1usize;
    let mut cursor = start;
    let close_tag = format!("{{{{/{key}}}}}");
    let open_tag = format!("{{{{#{key}}}}}");
    while let Some(rel) = template[cursor..].find("{{") {
        let tag_start = cursor + rel;
        let rest = &template[tag_start..];
        if rest.starts_with(&open_tag) {
            depth += 1;
        } else if rest.starts_with(&close_tag) {
            depth -= 1;
            if depth == 0 {
                let end = tag_start + close_tag.len();
                return Ok((&template[start..tag_start], end));
            }
        }
        // 跳过这个标签(到它的 }} 之后)
        let close_rel = template[tag_start + 2..]
            .find("}}")
            .ok_or_else(|| "code_generator: unclosed `{{` in template".to_string())?;
        cursor = tag_start + 2 + close_rel + 2;
    }
    Err(format!("code_generator: section `{key}` is not closed"))
}

/// 段落进入判定:对象恒真、数组非空为真、Null/false/空数组为假、
/// 其余按 JSON 真值(0/"" 为假)。
fn should_enter(ctx: &Value, key: &str) -> bool {
    match lookup(ctx, key) {
        Ok(v) => match v {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Array(a) => !a.is_empty(),
            Value::String(s) => !s.is_empty(),
            Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
            Value::Object(_) => true,
        },
        // 缺失键:段落视为假,不报错(与 `{{field}}` 的 fail-fast 区分)
        Err(_) => false,
    }
}

/// 点路径取值;数组下标用数字段(`items.0.id`);兼容 Go 风格的前导点
/// (`{{.user.name}}` 与 `{{user.name}}` 同义)。
fn lookup<'a>(ctx: &'a Value, path: &str) -> Result<&'a Value, String> {
    let path = path.strip_prefix('.').unwrap_or(path);
    let mut cur = ctx;
    for part in path.split('.') {
        if part.is_empty() {
            return Err(format!("code_generator: empty path segment in `{path}`"));
        }
        match cur {
            Value::Object(map) => {
                cur = map.get(part).ok_or_else(|| {
                    format!("code_generator: missing field `{part}` in path `{path}`")
                })?;
            }
            Value::Array(arr) => {
                let idx: usize = part.parse().map_err(|_| {
                    format!("code_generator: `{part}` is not an array index in path `{path}`")
                })?;
                cur = arr.get(idx).ok_or_else(|| {
                    format!("code_generator: index {idx} out of range in path `{path}`")
                })?;
            }
            other => {
                return Err(format!(
                    "code_generator: cannot descend into `{}` via `{path}`",
                    type_name(other)
                ));
            }
        }
    }
    Ok(cur)
}

fn value_to_string(v: &Value) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok(String::new()),
        other => Err(format!(
            "code_generator: cannot render {} as text (wrap it in a field)",
            type_name(other)
        )),
    }
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
    use serde_json::json;

    #[test]
    fn variable_and_dot_path_substitution() {
        let out = render_template(
            "Hello, {{name}}! ({{user.age}})",
            &json!({
                "name": "小明",
                "user": { "age": 18 },
            }),
        )
        .unwrap();
        assert_eq!(out, "Hello, 小明! (18)");

        // 数字/布尔标量渲染
        let out = render_template("{{n}}{{b}}", &json!({ "n": 42, "b": true })).unwrap();
        assert_eq!(out, "42true");
        // null 渲染为空
        let out = render_template("[{{x}}]", &json!({ "x": null })).unwrap();
        assert_eq!(out, "[]");
    }

    #[test]
    fn missing_field_fails_fast() {
        let err = render_template("{{nope}}", &json!({ "x": 1 })).unwrap_err();
        assert!(err.contains("missing field `nope`"), "err={err}");
        // 深层缺失同样报错
        let err = render_template("{{a.b.c}}", &json!({ "a": { "b": {} } })).unwrap_err();
        assert!(err.contains("missing field `c`"), "err={err}");
        // 非对象上下文不可下钻
        let err = render_template("{{a.b}}", &json!({ "a": 1 })).unwrap_err();
        assert!(err.contains("cannot descend"), "err={err}");
        // 未闭合标签报错
        assert!(render_template("{{oops", &json!({})).is_err());
    }

    #[test]
    fn dot_renders_current_context() {
        let out = render_template(
            "{{#items}}[{{.}}]{{/items}}",
            &json!({ "items": ["a", "b", 3] }),
        )
        .unwrap();
        assert_eq!(out, "[a][b][3]");
    }

    #[test]
    fn section_semantics() {
        // 对象:以其为上下文渲染一次
        let out = render_template(
            "{{#user}}{{name}} <{{email}}>{{/user}}",
            &json!({ "user": { "name": "A", "email": "a@x.com" } }),
        )
        .unwrap();
        assert_eq!(out, "A <a@x.com>");

        // 数组:逐元素(元素为对象)
        let out = render_template(
            "{{#rows}}{{id}};{{/rows}}",
            &json!({ "rows": [ { "id": 1 }, { "id": 2 } ] }),
        )
        .unwrap();
        assert_eq!(out, "1;2;");

        // 真值标量:渲染一次
        assert_eq!(
            render_template("{{#on}}yes{{/on}}", &json!({ "on": true })).unwrap(),
            "yes"
        );
        assert_eq!(
            render_template("{{#n}}yes{{/n}}", &json!({ "n": 5 })).unwrap(),
            "yes"
        );
        // false/null/空数组/缺失:跳过
        assert_eq!(
            render_template("{{#off}}yes{{/off}}", &json!({ "off": false })).unwrap(),
            ""
        );
        assert_eq!(
            render_template("{{#e}}yes{{/e}}", &json!({ "e": [] })).unwrap(),
            ""
        );
        assert_eq!(
            render_template("{{#z}}yes{{/z}}", &json!({ "z": 0 })).unwrap(),
            ""
        );
        assert_eq!(
            render_template("x{{#nope}}yes{{/nope}}y", &json!({})).unwrap(),
            "xy"
        );
    }

    #[test]
    fn inverted_section_semantics() {
        assert_eq!(
            render_template("{{^off}}shown{{/off}}", &json!({ "off": false })).unwrap(),
            "shown"
        );
        assert_eq!(
            render_template("{{^nope}}shown{{/nope}}", &json!({})).unwrap(),
            "shown"
        );
        assert_eq!(
            render_template("{{^e}}shown{{/e}}", &json!({ "e": [] })).unwrap(),
            "shown"
        );
        assert_eq!(
            render_template("{{^on}}shown{{/on}}", &json!({ "on": true })).unwrap(),
            ""
        );
        // 数组非空不渲染
        let out = render_template("{{^items}}none{{/items}}", &json!({ "items": [1] })).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn nested_sections_and_index_paths() {
        let tpl = "{{#groups}}{{name}}:{{#members}}{{.}}({{.}}){{/members}};{{/groups}}";
        // 标量数组内层 {{.}} 取元素本身
        let out = render_template(
            "{{#groups}}{{name}}:{{#members}}{{.}},{{/members}};{{/groups}}",
            &json!({ "groups": [
                { "name": "g1", "members": ["a", "b"] },
                { "name": "g2", "members": [] },
            ]}),
        )
        .unwrap();
        assert_eq!(out, "g1:a,b,;g2:;");
        let _ = tpl;

        // 数组下标路径
        let out = render_template("{{items.1}}", &json!({ "items": ["x", "y"] })).unwrap();
        assert_eq!(out, "y");
        let err = render_template("{{items.5}}", &json!({ "items": ["x"] })).unwrap_err();
        assert!(err.contains("out of range"), "err={err}");
    }

    #[test]
    fn unbalanced_sections_rejected() {
        let err = render_template("{{#a}}open...", &json!({ "a": 1 })).unwrap_err();
        assert!(err.contains("not closed"), "err={err}");
        // 同名嵌套闭合正确配对
        let out = render_template(
            "{{#a}}{{#a}}deep{{/a}}{{/a}}",
            &json!({ "a": { "a": true } }),
        )
        .unwrap();
        assert_eq!(out, "deep");
        // 未闭合的内层标签
        let err = render_template("{{#a}}{{#b}}{{/a}}{{/a}}", &json!({ "a": 1 })).unwrap_err();
        assert!(err.contains("not closed"), "err={err}");
    }

    #[test]
    fn render_to_writes_file_and_refuses_overwrite() {
        let dir = temp_test_dir("cg_overwrite");
        let g = Generator::new().register(CodeTemplate {
            name: "t.tmpl".into(),
            content: "package {{.pkg}}\n".into(),
        });
        let ctx = json!({ "pkg": "demo" });

        let p1 = g
            .render_to("t.tmpl", &ctx, &dir, "out/{{.pkg}}.rs")
            .unwrap();
        assert_eq!(p1, dir.join("out/demo.rs"));
        assert_eq!(std::fs::read_to_string(&p1).unwrap(), "package demo\n");

        // 缺省拒绝覆盖
        let err = g
            .render_to("t.tmpl", &ctx, &dir, "out/{{.pkg}}.rs")
            .unwrap_err();
        assert!(err.contains("refuse to overwrite"), "err={err}");
        // 允许覆盖后成功
        let mut g2 = g.clone();
        g2.overwrite = true;
        let p2 = g2
            .render_to("t.tmpl", &ctx, &dir, "out/{{.pkg}}.rs")
            .unwrap();
        assert_eq!(p1, p2);
        cleanup_test_dir(&dir);
    }

    #[test]
    fn render_to_rejects_path_escape() {
        let dir = temp_test_dir("cg_escape");
        let g = Generator::new().register(CodeTemplate {
            name: "t.tmpl".into(),
            content: "x".into(),
        });
        let ctx = json!({});
        assert!(g.render_to("t.tmpl", &ctx, &dir, "../escape.rs").is_err());
        assert!(g.render_to("t.tmpl", &ctx, &dir, "/abs/escape.rs").is_err());
        // 空文件名
        assert!(g.render_to("t.tmpl", &ctx, &dir, "").is_err());
        cleanup_test_dir(&dir);
    }

    #[test]
    fn generator_from_dir_and_unknown_template() {
        let dir = temp_test_dir("cg_dir");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.tmpl"), "A={{.v}}").unwrap();
        std::fs::write(dir.join("sub/b.tmpl"), "B={{.v}}").unwrap();

        let g = Generator::from_dir(&dir).unwrap();
        let mut names = g.template_names();
        names.sort();
        assert_eq!(names, vec!["a.tmpl", "sub/b.tmpl"]);
        assert_eq!(g.render("sub/b.tmpl", &json!({ "v": 1 })).unwrap(), "B=1");

        // 非目录 / 未知模板
        assert!(Generator::from_dir(dir.join("nope")).is_err());
        let empty = Generator::new();
        assert!(empty.render("none", &json!({})).is_err());
        cleanup_test_dir(&dir);
    }

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rust-utils-cg-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // 残留清理
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup_test_dir(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }
}
