//! 授权管理器:内置 RBAC 引擎(builtin)的策略装载与判定。
//!
//! 运行:`cargo run --features authorizer --example authorizer`

use std::sync::Arc;

use rust_utils::authorizer::{
    Authorizer, EngineConfig, ModelDataMap, PermissionData, PermissionDataMap, Provider,
};

/// 权限数据源:一般来自数据库的角色-权限表。
struct DbProvider;

impl Provider for DbProvider {
    fn provide_models(&self, _engine_name: &str) -> ModelDataMap {
        ModelDataMap::new()
    }
    fn provide_policies(&self) -> Result<PermissionDataMap, String> {
        let mut m = PermissionDataMap::new();
        // admin:全部接口全部方法(路径模式 ** 跨段)
        m.insert(
            "admin".into(),
            vec![PermissionData {
                path: "/api/v1/**".into(),
                method: "*".into(),
                domain: String::new(),
            }],
        );
        // viewer:只读报表
        m.insert(
            "viewer".into(),
            vec![PermissionData {
                path: "/api/v1/reports/*".into(),
                method: "GET".into(),
                domain: String::new(),
            }],
        );
        Ok(m)
    }
}

fn main() {
    let authz = Authorizer::new(Some(&EngineConfig::new("builtin")), Arc::new(DbProvider));
    authz.reset_policies().unwrap();
    let engine = authz.engine().unwrap();
    println!("engine: {}", engine.name());

    let check = |subject: &str, method: &str, path: &str| {
        let ok = engine.is_authorized(subject, method, path, "").unwrap();
        println!(
            "{subject:<8} {method:<5} {path:<22} → {}",
            if ok { "ALLOW" } else { "DENY" }
        );
        ok
    };

    assert!(check("admin", "DELETE", "/api/v1/users/42"));
    assert!(check("viewer", "GET", "/api/v1/reports/1"));
    assert!(!check("viewer", "DELETE", "/api/v1/reports/1"));
    assert!(!check("stranger", "GET", "/api/v1/anything"));

    // 过滤族:列出主体可用的 (资源, 动作) 对
    let pairs = vec![
        rust_utils::authorizer::make_pair("/api/v1/reports/1", "GET"),
        rust_utils::authorizer::make_pair("/api/v1/users", "POST"),
    ];
    let allowed = engine
        .filter_authorized_pairs(&["viewer".into()], &pairs)
        .unwrap();
    println!("viewer allowed pairs: {allowed:?}");
    assert_eq!(allowed.len(), 1);

    println!("OK");
}
