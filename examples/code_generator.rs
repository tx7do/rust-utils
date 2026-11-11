//! 模板驱动代码生成:mustache 子集渲染 + 落盘守卫。
//!
//! 运行:`cargo run --features code-generator --example code_generator`

use rust_utils::code_generator::{CodeTemplate, Generator};
use serde_json::json;

fn main() {
    let g = Generator::new()
        .register(CodeTemplate {
            name: "model.rs.tmpl".into(),
            content: r#"//! {{.Comment}}
#[derive(Debug, Clone)]
pub struct {{.Struct}} {
{{#fields}}    pub {{.name}}: {{.ty}},
{{/fields}}}
"#
            .into(),
        })
        .register(CodeTemplate {
            name: "repo.rs.tmpl".into(),
            content: "impl Repo for {{.Struct}}Repo {{^debug}}/* release */{{/debug}}{}\n".into(),
        });

    let ctx = json!({
        "Struct": "User",
        "Comment": "系统用户",
        "fields": [
            { "name": "id", "ty": "u64" },
            { "name": "user_name", "ty": "String" },
            { "name": "status", "ty": "i32" },
        ],
    });

    let code = g.render("model.rs.tmpl", &ctx).unwrap();
    println!("--- model.rs.tmpl ---\n{code}");
    assert!(code.contains("pub struct User {"));
    assert!(code.contains("pub user_name: String,"));

    // 落盘:文件名也吃模板占位;缺省拒绝覆盖
    let out_dir = std::env::temp_dir().join("rust-utils-codegen-demo");
    let written = g
        .render_to("model.rs.tmpl", &ctx, &out_dir, "{{.Struct}}.rs")
        .unwrap();
    println!("written: {}", written.display());

    // 目录模板源(模板名 = 相对路径)
    let _ = std::fs::create_dir_all(out_dir.join("tpl"));
    std::fs::write(out_dir.join("tpl/hello.tmpl"), "Hello {{.name}}!").unwrap();
    let from_dir = Generator::from_dir(out_dir.join("tpl")).unwrap();
    assert_eq!(
        from_dir
            .render("hello.tmpl", &json!({ "name": "Rust" }))
            .unwrap(),
        "Hello Rust!"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
    println!("OK");
}
