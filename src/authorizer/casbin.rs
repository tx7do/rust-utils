//! casbin 引擎(feature `authorizer-casbin`)—— 把壳的 `"casbin"` 类型
//! 从 DenyAll 兜底升级为真实引擎。
//!
//! 以 [`casbin::Enforcer`](内置 `MemoryAdapter`)承载策略,判定走
//! casbin 的同步 `enforce`(`Engine` trait 是同步面,构造/装载的
//! async 调用经进程级 tokio runtime `block_on` 收口)。
//!
//! # 模型
//!
//! 缺省模型见 [`DEFAULT_CASBIN_MODEL`]:RBAC(`g = _, _`)+ 四元策略
//! `(sub, dom, obj, act)` + 双匹配器(`keyMatch2` + `keyMatch`,任一命中):
//!
//! - 精确路径:`/api/v1/users`;
//! - `/*` 尾通配:keyMatch2 把 `/*` 转正则尾通配,`/api/v1/*` 命中其下
//!   全部层级(注意与内置 [`PolicyEngine`](crate::authorizer::PolicyEngine)
//!   的单段语义不同,这里跟 casbin 的 keyMatch2 走);
//! - `/**`:keyMatch 首个 `*` 前缀匹配,同样命中全部层级;
//! - `:param` 单段:keyMatch2 的 `/users/:id`;
//! - `dom`(域/项目):策略侧 `""` 视为任意域,其余 keyMatch2/keyMatch。
//!
//! 自定义模型可用 [`CasbinEngine::with_model`] 传入 casbin 模型文本
//! (策略四元形态需与 `r = sub, dom, obj, act` 对齐)。
//!
//! # 策略装载
//!
//! [`Engine::set_policies`] 接受壳已生成的两种形态:Casbin 规则
//! (`v0=主体 v1=路径 v2=方法 v3=域`,非 `"p"` 类型跳过)与 OPA 形态
//! (键即角色)。`roles`(主体 → 角色)转为 casbin 的 `g` 绑定规则。
//! 每次装载整建 `Enforcer`(整体替换语义,与内置引擎的热更一致)。
//!
//! 经壳 `reset_policies` 装载时 roles 恒为 `None`(Provider 不承载
//! 角色绑定),主体直绑权限可用;角色绑定需调用方自行 `set_policies`。

use std::future::Future;
use std::sync::{OnceLock, RwLock};

// CoreApi 提供 Enforcer::new(异步)与同步的 enforce 判定入口
use casbin::{Adapter, CoreApi, Enforcer, MemoryAdapter};

use crate::authorizer::{Engine, Pair, PolicyMap, PolicyValue, Projects, RoleMap, Subject};

/// 缺省模型:RBAC + 四元策略 + keyMatch2/keyMatch 双匹配器。
///
/// 元序对齐壳的 [`PolicyRule`](crate::authorizer::PolicyRule) 数据面
/// (`v0=主体 v1=路径 v2=方法 v3=域`):`r/p = sub, obj, act, dom`。
/// 方法与域支持规则侧 `*`/空串通配(方法 * 通配全部;域空串通配全部)。
pub const DEFAULT_CASBIN_MODEL: &str = r#"
[request_definition]
r = sub, obj, act, dom

[policy_definition]
p = sub, obj, act, dom

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (g(r.sub, p.sub) || r.sub == p.sub) && (r.act == p.act || p.act == "*") && (keyMatch2(r.obj, p.obj) || keyMatch(r.obj, p.obj)) && (p.dom == "" || keyMatch2(r.dom, p.dom) || keyMatch(r.dom, p.dom))
"#;

/// casbin 的 async 构造/装载收口到进程级 tokio runtime
/// (`Engine` 面为同步;runtime 复用,不随引擎实例创建)。
fn block_on<T>(fut: impl Future<Output = T>) -> Result<T, String> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt.block_on(fut));
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("authorizer-casbin: build tokio runtime: {e}"))?;
    let _ = RUNTIME.set(rt);
    RUNTIME
        .get()
        .map(|rt| rt.block_on(fut))
        .ok_or_else(|| "authorizer-casbin: runtime init".to_string())
}

fn build_enforcer(
    model_text: &str,
    p_rules: &[Vec<String>],
    g_rules: &[Vec<String>],
) -> Result<Enforcer, String> {
    // block_on 的 Err 仅承载 runtime 构建失败,内层再摊平引擎构建错误
    block_on(async {
        let mut adapter = MemoryAdapter::default();
        for rule in p_rules {
            adapter
                .add_policy("p", "p", rule.clone())
                .await
                .map_err(|e| format!("authorizer-casbin: load policy: {e}"))?;
        }
        for rule in g_rules {
            adapter
                .add_policy("g", "g", rule.clone())
                .await
                .map_err(|e| format!("authorizer-casbin: load grouping: {e}"))?;
        }
        let model = casbin::DefaultModel::from_str(model_text)
            .await
            .map_err(|e| format!("authorizer-casbin: parse model: {e}"))?;
        Enforcer::new(model, adapter)
            .await
            .map_err(|e| format!("authorizer-casbin: build enforcer: {e}"))
    })
    .and_then(|inner| inner)
}

/// casbin 授权引擎(策略整体替换、判定同步)。
pub struct CasbinEngine {
    model_text: String,
    enforcer: RwLock<Enforcer>,
}

impl CasbinEngine {
    /// 以缺省模型创建(空策略起步 —— fail-closed)。
    pub fn new() -> Result<Self, String> {
        Self::with_model(DEFAULT_CASBIN_MODEL)
    }

    /// 以自定义 casbin 模型文本创建。
    pub fn with_model(model_text: impl Into<String>) -> Result<Self, String> {
        let model_text = model_text.into();
        let enforcer = build_enforcer(&model_text, &[], &[])?;
        Ok(CasbinEngine {
            model_text,
            enforcer: RwLock::new(enforcer),
        })
    }

    /// 从策略载荷抽取 casbin `p` 规则(CasbinRules + OpaPaths 两形态)与
    /// `g` 绑定规则。
    fn extract_rules(
        policies: &PolicyMap,
        roles: Option<&RoleMap>,
    ) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
        let mut p_rules = Vec::new();
        let mut g_rules = Vec::new();
        for (key, value) in policies {
            match value {
                PolicyValue::CasbinRules(rules) => {
                    for rule in rules {
                        if rule.p_type != "p" {
                            continue;
                        }
                        p_rules.push(vec![
                            rule.v0.clone(),
                            rule.v1.clone(),
                            rule.v2.clone(),
                            rule.v3.clone(),
                        ]);
                    }
                }
                // OPA 形态:键即角色 → (角色, 路径, 方法, 空域)
                PolicyValue::OpaPaths(paths) => {
                    for path in paths {
                        p_rules.push(vec![
                            key.clone(),
                            path.pattern.clone(),
                            path.method.clone(),
                            String::new(),
                        ]);
                    }
                }
                PolicyValue::Projects(_) => {}
            }
        }
        if let Some(role_map) = roles {
            for (subject, role_list) in role_map {
                for role in role_list {
                    g_rules.push(vec![subject.clone(), role.clone()]);
                }
            }
        }
        (p_rules, g_rules)
    }
}

impl Engine for CasbinEngine {
    fn name(&self) -> &str {
        "casbin"
    }

    fn is_authorized(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        project: &str,
    ) -> Result<bool, String> {
        // r = sub, obj, act, dom:project 即域
        let enforcer = self.enforcer.read().unwrap_or_else(|e| e.into_inner());
        enforcer
            .enforce((subject, resource, action, project))
            .map_err(|e| format!("authorizer-casbin: enforce: {e}"))
    }

    fn projects_authorized(
        &self,
        subjects: &[Subject],
        action: &str,
        resource: &str,
        projects: &[crate::authorizer::Project],
    ) -> Result<Projects, String> {
        let enforcer = self.enforcer.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for project in projects {
            let authorized = subjects.iter().any(|s| {
                enforcer
                    .enforce((s.as_str(), resource, action, project.as_str()))
                    .map_err(|e| format!("authorizer-casbin: enforce: {e}"))
                    .unwrap_or(false)
            });
            if authorized {
                out.push(project.clone());
            }
        }
        Ok(out)
    }

    fn filter_authorized_pairs(
        &self,
        subjects: &[Subject],
        pairs: &[Pair],
    ) -> Result<Vec<Pair>, String> {
        let enforcer = self.enforcer.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for pair in pairs {
            let authorized = subjects.iter().any(|s| {
                enforcer
                    .enforce((s.as_str(), pair.resource.as_str(), pair.action.as_str(), ""))
                    .map_err(|e| format!("authorizer-casbin: enforce: {e}"))
                    .unwrap_or(false)
            });
            if authorized {
                out.push(pair.clone());
            }
        }
        Ok(out)
    }

    fn filter_authorized_projects(&self, _subjects: &[Subject]) -> Result<Projects, String> {
        // 项目维度无策略数据(与内置引擎同语义),恒空
        Ok(Projects::new())
    }

    fn set_policies(&self, policies: &PolicyMap, roles: Option<&RoleMap>) -> Result<(), String> {
        let (p_rules, g_rules) = Self::extract_rules(policies, roles);
        let enforcer = build_enforcer(&self.model_text, &p_rules, &g_rules)?;
        // 整体替换(锁毒化容忍对齐 Go 无毒化语义)
        *self.enforcer.write().unwrap_or_else(|e| e.into_inner()) = enforcer;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorizer::make_pair;
    use std::collections::HashMap;

    fn opa_policies(entries: &[(&str, &str, &str)]) -> PolicyMap {
        let mut map: HashMap<String, Vec<crate::authorizer::OpaPolicyPath>> = HashMap::new();
        for (role, pattern, method) in entries {
            map.entry(role.to_string())
                .or_default()
                .push(crate::authorizer::OpaPolicyPath {
                    pattern: pattern.to_string(),
                    method: method.to_string(),
                });
        }
        map.into_iter()
            .map(|(k, v)| (k, PolicyValue::OpaPaths(v)))
            .collect()
    }

    fn casbin_policies(entries: &[(&str, &str, &str, &str)]) -> PolicyMap {
        let rules: Vec<crate::authorizer::PolicyRule> = entries
            .iter()
            .map(|(sub, path, method, dom)| crate::authorizer::PolicyRule {
                p_type: "p".to_string(),
                v0: sub.to_string(),
                v1: path.to_string(),
                v2: method.to_string(),
                v3: dom.to_string(),
            })
            .collect();
        let mut map = PolicyMap::new();
        map.insert("policies".to_string(), PolicyValue::CasbinRules(rules));
        map
    }

    #[test]
    fn direct_subject_rules_allow_and_deny() {
        let e = CasbinEngine::new().unwrap();
        assert_eq!(e.name(), "casbin");
        e.set_policies(
            &casbin_policies(&[("alice", "/api/v1/users", "GET", "")]),
            None,
        )
        .unwrap();
        assert!(e
            .is_authorized("alice", "GET", "/api/v1/users", "")
            .unwrap());
        // 换方法/换路径/换主体/空主体拒绝
        assert!(!e
            .is_authorized("alice", "POST", "/api/v1/users", "")
            .unwrap());
        assert!(!e
            .is_authorized("alice", "GET", "/api/v1/orders", "")
            .unwrap());
        assert!(!e.is_authorized("bob", "GET", "/api/v1/users", "").unwrap());
        assert!(!e.is_authorized("", "GET", "/api/v1/users", "").unwrap());
        // 空策略起步即全拒(fail-closed)
        assert!(!CasbinEngine::new()
            .unwrap()
            .is_authorized("u", "GET", "/x", "")
            .unwrap());
    }

    #[test]
    fn key_match_semantics_pinned() {
        // keyMatch2:`/*` 尾通配(全层级);keyMatch:`/**` 首星前缀(全层级)
        let e = CasbinEngine::new().unwrap();
        e.set_policies(
            &casbin_policies(&[
                ("r-single", "/api/v1/*", "GET", ""),
                ("r-deep", "/api/v1/**", "GET", ""),
                ("r-exact", "/healthz", "GET", ""),
            ]),
            None,
        )
        .unwrap();
        let t = |sub: &str, path: &str| e.is_authorized(sub, "GET", path, "").unwrap();
        assert!(t("r-exact", "/healthz"));
        assert!(!t("r-exact", "/healthz/x"));
        // /* 与 /** 在 casbin 侧同为层级尾通配(与内置引擎单段语义的差异见模块文档)
        assert!(t("r-single", "/api/v1/users"));
        assert!(t("r-single", "/api/v1/users/42"));
        assert!(!t("r-single", "/api/v2/users"));
        assert!(t("r-deep", "/api/v1/a/b/c"));
        assert!(!t("r-deep", "/api/v1")); // 前缀本身不算
    }

    #[test]
    fn role_bindings_via_g_rules() {
        let e = CasbinEngine::new().unwrap();
        let mut roles = RoleMap::new();
        roles.insert("alice".to_string(), vec!["editor".to_string()]);
        roles.insert("editor".to_string(), vec!["viewer".to_string()]);
        e.set_policies(
            &opa_policies(&[
                ("viewer", "/reports/*", "GET"),
                ("editor", "/articles/*", "*"),
            ]),
            Some(&roles),
        )
        .unwrap();
        // 直绑角色 editor 的 * 方法
        assert!(e
            .is_authorized("alice", "DELETE", "/articles/1", "")
            .unwrap());
        // 传递继承 viewer
        assert!(e.is_authorized("alice", "GET", "/reports/1", "").unwrap());
        // 未绑定主体
        assert!(!e.is_authorized("mallory", "GET", "/reports/1", "").unwrap());
    }

    #[test]
    fn opa_shape_keyed_by_role() {
        // OPA 形态:键即角色
        let e = CasbinEngine::new().unwrap();
        e.set_policies(&opa_policies(&[("ops", "/api/ops/*", "POST")]), None)
            .unwrap();
        assert!(e
            .is_authorized("ops", "POST", "/api/ops/restart", "")
            .unwrap());
        assert!(!e
            .is_authorized("ops", "GET", "/api/ops/restart", "")
            .unwrap());
    }

    #[test]
    fn domain_wildcard_when_policy_dom_empty() {
        // 策略域为空 = 任意域;请求域(项目)不影响判定
        let e = CasbinEngine::new().unwrap();
        e.set_policies(&casbin_policies(&[("u", "/x", "GET", "")]), None)
            .unwrap();
        assert!(e.is_authorized("u", "GET", "/x", "").unwrap());
        assert!(e.is_authorized("u", "GET", "/x", "tenant-1").unwrap());
        // 策略指定域:非空域按 keyMatch 精确
        let e2 = CasbinEngine::new().unwrap();
        e2.set_policies(&casbin_policies(&[("u", "/x", "GET", "t1")]), None)
            .unwrap();
        assert!(e2.is_authorized("u", "GET", "/x", "t1").unwrap());
        assert!(!e2.is_authorized("u", "GET", "/x", "t2").unwrap());
    }

    #[test]
    fn rebuild_replaces_wholesale() {
        let e = CasbinEngine::new().unwrap();
        e.set_policies(&casbin_policies(&[("u", "/old", "GET", "")]), None)
            .unwrap();
        assert!(e.is_authorized("u", "GET", "/old", "").unwrap());
        e.set_policies(&casbin_policies(&[("u", "/new", "GET", "")]), None)
            .unwrap();
        assert!(!e.is_authorized("u", "GET", "/old", "").unwrap());
        assert!(e.is_authorized("u", "GET", "/new", "").unwrap());
    }

    #[test]
    fn filters_and_projects() {
        let e = CasbinEngine::new().unwrap();
        e.set_policies(&opa_policies(&[("viewer", "/reports/*", "GET")]), None)
            .unwrap();
        let subjects = vec!["viewer".to_string(), "stranger".to_string()];
        let pairs = vec![
            make_pair("/reports/1", "GET"),
            make_pair("/reports/1", "DELETE"),
        ];
        let allowed = e.filter_authorized_pairs(&subjects, &pairs).unwrap();
        assert_eq!(allowed, vec![make_pair("/reports/1", "GET")]);

        let projects = vec!["p1".to_string(), "p2".to_string()];
        assert_eq!(
            e.projects_authorized(&subjects, "GET", "/reports/1", &projects)
                .unwrap(),
            projects
        );
        assert!(e
            .projects_authorized(&subjects, "DELETE", "/reports/1", &projects)
            .unwrap()
            .is_empty());
        assert!(e.filter_authorized_projects(&subjects).unwrap().is_empty());
    }

    #[test]
    fn end_to_end_via_authorizer_shell() {
        // 走管理器:casbin 分派 → CasbinRules 装载 → 判定
        struct Provider;
        impl crate::authorizer::Provider for Provider {
            fn provide_models(&self, _engine_name: &str) -> crate::authorizer::ModelDataMap {
                crate::authorizer::ModelDataMap::new()
            }
            fn provide_policies(&self) -> Result<crate::authorizer::PermissionDataMap, String> {
                let mut m = crate::authorizer::PermissionDataMap::new();
                m.insert(
                    "admin".to_string(),
                    vec![crate::authorizer::PermissionData {
                        path: "/api/v1/**".to_string(),
                        method: "GET".to_string(),
                        domain: String::new(),
                    }],
                );
                Ok(m)
            }
        }
        let a = crate::authorizer::Authorizer::new(
            Some(&crate::authorizer::EngineConfig::new("casbin")),
            std::sync::Arc::new(Provider),
        );
        a.reset_policies().unwrap();
        let engine = a.engine().unwrap();
        assert_eq!(engine.name(), "casbin");
        assert!(engine
            .is_authorized("admin", "GET", "/api/v1/users/1", "")
            .unwrap());
        assert!(!engine
            .is_authorized("admin", "POST", "/api/v1/users", "")
            .unwrap());
    }

    #[test]
    fn custom_model_is_accepted() {
        // 无 g 定义、直比 sub 的极简模型
        let model = r#"
[request_definition]
r = sub, obj
[policy_definition]
p = sub, obj
[priority]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj
"#;
        let e = CasbinEngine::with_model(model).unwrap();
        e.set_policies(&casbin_policies(&[("alice", "/only", "", "")]), None)
            .unwrap();
        // r 只有 sub, obj 两元:enforce 需两参 —— 但 Engine trait 固定四参,
        // 自定义模型与 r 元数不匹配时应报错而非误判
        assert!(e.is_authorized("alice", "GET", "/only", "").is_err());
    }
}
