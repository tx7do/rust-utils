//! 授权管理器壳(移植自 Go `tx7do/go-utils/authorizer`)。
//!
//! 上游是一个授权管理器壳:按 [`EngineConfig`] 的引擎类型选择授权引擎,
//! 从 [`Provider`] 拉取 角色→(path, method) 权限数据并按引擎格式装载,
//! 对外暴露引擎能力面(布尔判定、项目过滤、(资源,动作)对过滤、策略写入)。
//! 本 crate 只移植"壳";真正的 casbin / opa / zanzibar 引擎在上游位于
//! `tx7do/kratos-authz`,Rust 侧没有对应生态,故不移植。
//!
//! # 与上游的差异(重要取舍)
//!
//! 1. **引擎实现**:上游壳依赖 `kratos-authz` 的四类引擎,本 crate
//!    改为 [`Engine`] trait(能力面逐一对齐上游 `engine.Engine` 接口,方法名
//!    snake_case)+ 三个内置实现:
//!    - [`NoopEngine`]:语义判断依据来自上游 `kratos-authz/engine/noop` 源码
//!      (`State.IsAuthorized` 恒返回 `true, nil`;`ProjectsAuthorized` /
//!      `FilterAuthorizedPairs` / `FilterAuthorizedProjects` 恒返回空集;
//!      `SetPolicies` 静默丢弃并返回 nil)——即"布尔判定恒放行、过滤族恒空、
//!      策略写入空转"的放行器,而非恒拒绝;
//!    - [`DenyAllEngine`]:上游 `deny_all_engine.go` 逐式移植,恒拒绝
//!      (fail-closed),错误信息随每次拒绝返回。
//! 2. **引擎类型分派**:`""` 与 `"noop"` → [`NoopEngine`];`"builtin"` →
//!    [`PolicyEngine`](Rust 侧新增的零依赖内置 RBAC 引擎);`"casbin"` →
//!    feature `authorizer-casbin` 启用时为真实 casbin 引擎(见 `casbin`
//!    模块),未启用时按 fail-closed 降级 [`DenyAllEngine`];`"opa"` /
//!    `"zanzibar"` 在 Rust 侧无引擎实现,统一降级为 [`DenyAllEngine`]——
//!    与上游对"不可用/不可解析的 OPA 模型"兜底为 denyAllEngine 的精神
//!    一致;其余未知类型按上游行为 fallthrough 到 noop。注:上游
//!    `newEngineZanzibar` 返回 nil 引擎,这里统一改为 DenyAll——因为
//!    Rust 侧"引擎为 None"已让位给"未配置授权"语义(见下条),配置了
//!    引擎类型却拿不到引擎时应显式拒绝,而非表现得像未配置。
//! 3. **nil config → 引擎为 None**:上游 `NewAuthorizer(nil cfg)` 保持引擎
//!    为 nil、不静默降级为放行的 noop;Rust 侧用 `Option<Arc<dyn Engine>>`
//!    承载同一语义([`Authorizer::engine`] 返回 `None`,`reset_policies`
//!    报错)。
//! 4. **OPA 模型探测塌缩**:上游 `newEngineOPA` 会取 Provider 的
//!    `rbac.rego` 模型(缺失 → nil 引擎;不可解析 → denyAllEngine),
//!    Rust 侧 OPA 引擎本体不存在,模型无从加载,故 `"opa"` 一律 DenyAll,
//!    上游"模型缺失/模型损坏"两分支被其吸收。
//! 5. **上下文与日志移除**:上游的 `context.Context`、`bLogger` 日志参数
//!    面在本 crate(纯 std、零依赖)没有对应物,签名中删除;
//!    [`Provider::provide_policies`] 同样不再携带 context。
//! 6. **`PolicyMap` 收窄**:上游 `PolicyMap` 是 `map[string]interface{}`,
//!    Rust 侧零依赖无 serde,收窄为 [`PolicyValue`] 枚举(casbin 规则 /
//!    OPA path 集 / 项目集);[`generate_casbin_policies`] /
//!    [`generate_opa_policies`] 只移植与引擎无关的数据变换部分,且它们
//!    本就不可能失败,上游的 error 返回值被移除。
//!
//! # 示例
//!
//! ```
//! use std::collections::HashMap;
//! use std::sync::Arc;
//! use rust_utils::authorizer::{
//!     Authorizer, EngineConfig, ModelDataMap, PermissionDataMap, Provider,
//! };
//!
//! struct EmptyProvider;
//!
//! impl Provider for EmptyProvider {
//!     fn provide_models(&self, _engine_name: &str) -> ModelDataMap {
//!         HashMap::new()
//!     }
//!     fn provide_policies(&self) -> Result<PermissionDataMap, String> {
//!         Ok(HashMap::new())
//!     }
//! }
//!
//! // noop 引擎:布尔判定恒放行,策略重载为空操作
//! let a = Authorizer::new(Some(&EngineConfig::new("noop")), Arc::new(EmptyProvider));
//! let engine = a.engine().expect("noop 引擎必须就绪");
//! assert_eq!(engine.name(), "noop");
//! assert!(engine.is_authorized("user-1", "GET", "/api/v1/users", "").unwrap());
//! assert!(a.reset_policies().is_ok());
//!
//! // 未配置授权:引擎保持 None,不静默降级为放行
//! let b = Authorizer::new(None, Arc::new(EmptyProvider));
//! assert!(b.engine().is_none());
//! assert!(b.reset_policies().is_err());
//! ```

use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "authorizer-casbin")]
pub mod casbin;

/// 主体标识(上游 `engine.Subject`,string)。
pub type Subject = String;
/// 主体标识列表(上游 `engine.Subjects`)。
pub type Subjects = Vec<Subject>;
/// 动作(上游 `engine.Action`,string)。
pub type Action = String;
/// 资源(上游 `engine.Resource`,string)。
pub type Resource = String;
/// 项目(上游 `engine.Project`,string)。
pub type Project = String;
/// 项目列表(上游 `engine.Projects`)。
pub type Projects = Vec<Project>;

/// (资源, 动作) 对(上游 `engine.Pair`)。
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct Pair {
    /// 资源(上游 `Pair.Resource`)。
    pub resource: Resource,
    /// 动作(上游 `Pair.Action`)。
    pub action: Action,
}

/// (资源, 动作) 对列表(上游 `engine.Pairs`)。
pub type Pairs = Vec<Pair>;

/// 构造 (资源, 动作) 对(上游 `engine.MakePair`)。
pub fn make_pair(resource: &str, action: &str) -> Pair {
    Pair {
        resource: resource.to_string(),
        action: action.to_string(),
    }
}

/// 构造项目列表(上游 `engine.MakeProjects` 的变参收窄为切片)。
pub fn make_projects(projects: &[&str]) -> Projects {
    projects.iter().map(|p| (*p).to_string()).collect()
}

/// Casbin 策略规则(上游 `casbin.PolicyRule` 中壳会填充的字段子集)。
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct PolicyRule {
    /// 规则类型,壳固定填 `"p"`(上游 `PType`)。
    pub p_type: String,
    /// 角色/主体(上游 `V0`)。
    pub v0: String,
    /// 路径(上游 `V1`)。
    pub v1: String,
    /// HTTP 方法(上游 `V2`)。
    pub v2: String,
    /// 域(上游 `V3`)。
    pub v3: String,
}

/// OPA 策略路径条目(上游 `generateOpaPolicies` 内的 `OpaPolicyPath`)。
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct OpaPolicyPath {
    /// 路径模式(上游 `Pattern`,json `pattern`)。
    pub pattern: String,
    /// HTTP 方法(上游 `Method`,json `method`)。
    pub method: String,
}

/// 策略载荷:上游 `PolicyMap`(`map[string]interface{}`)在零依赖约束下
/// 的收窄。键与上游保持一致:`"policies"`(casbin 规则)、`"projects"`
/// (项目集),或角色码 → OPA path 集。
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyValue {
    /// Casbin 规则集(上游 `[]casbin.PolicyRule`)。
    CasbinRules(Vec<PolicyRule>),
    /// OPA path 集(角色 → pattern/method 列表,上游 `[]OpaPolicyPath`)。
    OpaPaths(Vec<OpaPolicyPath>),
    /// 项目集(上游 `engine.Projects`)。
    Projects(Projects),
}

/// 策略映射(上游 `engine.PolicyMap`)。
pub type PolicyMap = HashMap<String, PolicyValue>;

/// 角色映射(上游 `engine.RoleMap`,`map[string]interface{}` 收窄为
/// 角色 → 主体列表;壳的装载路径不产生它,仅透传给引擎)。
pub type RoleMap = HashMap<String, Vec<String>>;

/// 兜底引擎的统一拒绝错误(上游 `errDenyAllEngine`)。
pub const ERR_DENY_ALL_ENGINE: &str =
    "authorization engine unavailable: custom policy model failed to load";

/// 引擎未初始化时重载策略的错误(上游 `fmt.Errorf` 文案)。
pub const ERR_ENGINE_NOT_INITIALIZED: &str = "authorization engine is not initialized";

/// 授权引擎能力面(上游 `kratos-authz/engine.Engine` = `Authorizer` +
/// `Writer`,方法名 snake_case)。
pub trait Engine: Send + Sync {
    /// 引擎名:`"noop"` / `"deny-all"`(上游 `Name() string`;壳据此
    /// 分派策略装载格式)。
    fn name(&self) -> &str;

    /// 布尔判定(上游 `IsAuthorized`)。
    fn is_authorized(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        project: &str,
    ) -> Result<bool, String>;

    /// 过滤出主体在给定项目内被授权的项目集(上游 `ProjectsAuthorized`)。
    fn projects_authorized(
        &self,
        subjects: &[Subject],
        action: &str,
        resource: &str,
        projects: &[Project],
    ) -> Result<Projects, String>;

    /// 过滤出被授权的 (资源, 动作) 对(上游 `FilterAuthorizedPairs`)。
    fn filter_authorized_pairs(
        &self,
        subjects: &[Subject],
        pairs: &[Pair],
    ) -> Result<Pairs, String>;

    /// 过滤出主体被授权的项目集(上游 `FilterAuthorizedProjects`)。
    fn filter_authorized_projects(&self, subjects: &[Subject]) -> Result<Projects, String>;

    /// 写入策略(上游 `SetPolicies`;`roles` 对应上游可 nil 的 `RoleMap`)。
    fn set_policies(&self, policies: &PolicyMap, roles: Option<&RoleMap>) -> Result<(), String>;
}

/// 权限数据(上游 `PermissionData`)。
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct PermissionData {
    /// 路径(上游 `Path`)。
    pub path: String,
    /// HTTP 方法(上游 `Method`)。
    pub method: String,
    /// 域(上游 `Domain`)。
    pub domain: String,
}

/// 权限数据列表(上游 `PermissionDataArray`)。
pub type PermissionDataArray = Vec<PermissionData>;

/// 角色 → 权限数据映射(上游 `PermissionDataMap`)。
pub type PermissionDataMap = HashMap<String, PermissionDataArray>;

/// 模型数据映射:引擎名 → 模型字节(上游 `ModelDataMap`)。
pub type ModelDataMap = HashMap<String, Vec<u8>>;

/// 权限数据提供者(上游 `Provider`)。
pub trait Provider: Send + Sync {
    /// 提供模型数据(上游 `ProvideModels(engineName)`)。
    fn provide_models(&self, engine_name: &str) -> ModelDataMap;

    /// 提供策略数据(上游 `ProvidePolicies(ctx)`;context 已移除)。
    fn provide_policies(&self) -> Result<PermissionDataMap, String>;
}

/// 引擎选择配置(上游 `EngineConfig`)。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineConfig {
    /// 引擎类型(上游字段 `Type`,因 `type` 为 Rust 保留字改名):
    /// `"noop"` | `"casbin"` | `"opa"` | `"zanzibar"`;空串按 noop 处理,
    /// casbin/opa/zanzibar 在 Rust 侧降级为 [`DenyAllEngine`]。
    pub engine_type: String,
}

impl EngineConfig {
    /// 以给定引擎类型构造配置(上游按字段字面量构造)。
    pub fn new(engine_type: impl Into<String>) -> Self {
        EngineConfig {
            engine_type: engine_type.into(),
        }
    }
}

/// noop 引擎(上游 `kratos-authz/engine/noop.State` 的语义复刻)。
///
/// 判断依据(见模块文档):布尔判定恒放行、过滤族恒返回空集、
/// 策略写入静默丢弃——noop 即"逻辑空转的放行器"。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopEngine;

impl Engine for NoopEngine {
    fn name(&self) -> &str {
        "noop"
    }

    fn is_authorized(
        &self,
        _subject: &str,
        _action: &str,
        _resource: &str,
        _project: &str,
    ) -> Result<bool, String> {
        // 上游 State.IsAuthorized:恒返回 (true, nil)
        Ok(true)
    }

    fn projects_authorized(
        &self,
        _subjects: &[Subject],
        _action: &str,
        _resource: &str,
        _projects: &[Project],
    ) -> Result<Projects, String> {
        // 上游 State.ProjectsAuthorized:恒返回空集
        Ok(Projects::new())
    }

    fn filter_authorized_pairs(
        &self,
        _subjects: &[Subject],
        _pairs: &[Pair],
    ) -> Result<Pairs, String> {
        // 上游 State.FilterAuthorizedPairs:恒返回空集
        Ok(Pairs::new())
    }

    fn filter_authorized_projects(&self, _subjects: &[Subject]) -> Result<Projects, String> {
        // 上游 State.FilterAuthorizedProjects:恒返回空集
        Ok(Projects::new())
    }

    fn set_policies(&self, _policies: &PolicyMap, _roles: Option<&RoleMap>) -> Result<(), String> {
        // 上游 State.SetPolicies:静默丢弃
        Ok(())
    }
}

/// 拒绝一切判定与策略写入的兜底引擎(上游 `deny_all_engine.go` 逐式移植)。
///
/// 上游 opa.NewEngine 对无法解析的自定义模型吞掉错误并回退编译内置资产
/// 策略、仍返回非 nil 引擎——运营者部署了损坏的自定义模型时会带着一套
/// 并非本意的默认策略静默上线。该情形(以及本 crate 中 casbin/opa/
/// zanzibar 引擎不可用的所有情形)改用本引擎:全部请求拒绝(fail-closed),
/// 错误信息随每次拒绝可观测。
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllEngine;

impl Engine for DenyAllEngine {
    fn name(&self) -> &str {
        "deny-all"
    }

    fn is_authorized(
        &self,
        _subject: &str,
        _action: &str,
        _resource: &str,
        _project: &str,
    ) -> Result<bool, String> {
        Err(ERR_DENY_ALL_ENGINE.to_string())
    }

    fn projects_authorized(
        &self,
        _subjects: &[Subject],
        _action: &str,
        _resource: &str,
        _projects: &[Project],
    ) -> Result<Projects, String> {
        Err(ERR_DENY_ALL_ENGINE.to_string())
    }

    fn filter_authorized_pairs(
        &self,
        _subjects: &[Subject],
        _pairs: &[Pair],
    ) -> Result<Pairs, String> {
        Err(ERR_DENY_ALL_ENGINE.to_string())
    }

    fn filter_authorized_projects(&self, _subjects: &[Subject]) -> Result<Projects, String> {
        Err(ERR_DENY_ALL_ENGINE.to_string())
    }

    fn set_policies(&self, _policies: &PolicyMap, _roles: Option<&RoleMap>) -> Result<(), String> {
        Err(ERR_DENY_ALL_ENGINE.to_string())
    }
}

/// 内置 RBAC 策略引擎(纯 std,零依赖)——把"壳"从只有 noop/deny-all
/// 变成开箱可用。
///
/// 策略形态:
/// - **授权规则**:角色/主体 → (路径模式, HTTP 方法) 集合。装载入口
///   [`Engine::set_policies`] 同时接受 OPA 形态(键即角色,
///   [`PolicyValue::OpaPaths`])与 Casbin 形态(`"policies"` 键下的
///   [`PolicyValue::CasbinRules`,`v0`=角色 `v1`=路径 `v2`=方法,
///   非 `"p"` 类型跳过),二者可混装。
/// - **角色绑定**:`set_policies` 的 `roles` 参数:主体 → 角色(可传递,
///   环保护;主体 ID 本身永远参与匹配,即"用户直绑权限")。
///
/// 匹配语义(fail-closed:无命中一律 `Ok(false)`):
/// - 方法:精确相等,或规则侧 `*` 通配全部方法;
/// - 路径:精确相等;`/api/v1/*` 单段通配(不跨 `/`);
///   `/api/v1/**` 后缀通配(跨段);模式中段的 `*` 不通配(按字面量)。
/// - 项目维度:本壳不装载项目级策略,`filter_authorized_projects` 恒空
///   (与 noop 的过滤族同语义);`projects_authorized` 在
///   (方法, 路径) 已被授权时放行全部候选项目。
///
/// 策略读写走 `RwLock`,支持运行期热更;引擎跨线程共享。
#[derive(Debug, Default)]
pub struct PolicyEngine {
    /// 角色/主体 → (路径模式, 方法) 授权规则。
    rules: std::sync::RwLock<HashMap<String, Vec<OpaPolicyPath>>>,
    /// 主体 → 角色(可传递)。
    role_bindings: std::sync::RwLock<RoleMap>,
}

impl PolicyEngine {
    /// 创建空策略引擎(等待 [`Engine::set_policies`] 装载)。
    pub fn new() -> Self {
        Self::default()
    }

    /// 解析主体可达的"角色/主体"节点集:自身 + 绑定角色的传递闭包(环保护)。
    fn resolve_nodes(&self, subject: &str) -> Vec<String> {
        let bindings = self.role_bindings.read().expect("PolicyEngine 角色绑定锁");
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut queue = vec![subject.to_string()];
        let mut nodes = Vec::new();
        while let Some(node) = queue.pop() {
            if !seen.insert(node.clone()) {
                continue;
            }
            if let Some(parents) = bindings.get(&node) {
                for parent in parents {
                    if !seen.contains(parent) {
                        queue.push(parent.clone());
                    }
                }
            }
            nodes.push(node);
        }
        nodes
    }

    /// 主体(经角色闭包)是否有任一规则命中 (方法, 路径)。
    fn matches_any(&self, subject: &str, action: &str, resource: &str) -> bool {
        if subject.is_empty() {
            return false;
        }
        let rules = self.rules.read().expect("PolicyEngine 规则锁");
        for node in self.resolve_nodes(subject) {
            if let Some(paths) = rules.get(&node) {
                if paths.iter().any(|p| {
                    method_matches(&p.method, action) && path_matches(&p.pattern, resource)
                }) {
                    return true;
                }
            }
        }
        false
    }
}

/// 方法匹配:精确相等,或规则侧 `*` 通配。
fn method_matches(rule_method: &str, action: &str) -> bool {
    rule_method == "*" || rule_method.eq_ignore_ascii_case(action)
}

/// 路径匹配:精确;`*` 全通配;`/*` 结尾单段通配;`/**` 结尾跨段通配。
fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" || pattern == path {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("**") {
        return path.starts_with(prefix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix) && !path[prefix.len()..].contains('/');
    }
    false
}

impl Engine for PolicyEngine {
    fn name(&self) -> &str {
        "builtin"
    }

    fn is_authorized(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        _project: &str,
    ) -> Result<bool, String> {
        Ok(self.matches_any(subject, action, resource))
    }

    fn projects_authorized(
        &self,
        subjects: &[Subject],
        action: &str,
        resource: &str,
        projects: &[Project],
    ) -> Result<Projects, String> {
        // 项目维度无策略:(方法, 路径) 已授权 → 全部候选项目放行
        if subjects
            .iter()
            .any(|s| self.matches_any(s, action, resource))
        {
            Ok(projects.to_vec())
        } else {
            Ok(Projects::new())
        }
    }

    fn filter_authorized_pairs(
        &self,
        subjects: &[Subject],
        pairs: &[Pair],
    ) -> Result<Pairs, String> {
        Ok(pairs
            .iter()
            .filter(|p| {
                subjects
                    .iter()
                    .any(|s| self.matches_any(s, &p.action, &p.resource))
            })
            .cloned()
            .collect())
    }

    fn filter_authorized_projects(&self, _subjects: &[Subject]) -> Result<Projects, String> {
        // 项目维度无策略(见类型文档),恒空
        Ok(Projects::new())
    }

    fn set_policies(&self, policies: &PolicyMap, roles: Option<&RoleMap>) -> Result<(), String> {
        let mut rules: HashMap<String, Vec<OpaPolicyPath>> = HashMap::new();
        for (key, value) in policies {
            match value {
                PolicyValue::OpaPaths(paths) => {
                    rules
                        .entry(key.clone())
                        .or_default()
                        .extend(paths.iter().cloned());
                }
                PolicyValue::CasbinRules(casbin_rules) => {
                    for rule in casbin_rules {
                        if rule.p_type != "p" {
                            continue;
                        }
                        rules
                            .entry(rule.v0.clone())
                            .or_default()
                            .push(OpaPolicyPath {
                                pattern: rule.v1.clone(),
                                method: rule.v2.clone(),
                            });
                    }
                }
                PolicyValue::Projects(_) => {}
            }
        }
        *self.rules.write().expect("PolicyEngine 规则锁") = rules;
        *self.role_bindings.write().expect("PolicyEngine 角色绑定锁") =
            roles.cloned().unwrap_or_default();
        Ok(())
    }
}

/// `"casbin"` 类型的引擎构造:feature 启用走真实 casbin 引擎(内嵌
/// 模型解析失败时 fail-closed 兜底 DenyAll),未启用直接 DenyAll。
#[cfg(feature = "authorizer-casbin")]
fn casbin_engine() -> Arc<dyn Engine> {
    match casbin::CasbinEngine::new() {
        Ok(e) => Arc::new(e),
        Err(_) => Arc::new(DenyAllEngine),
    }
}

#[cfg(not(feature = "authorizer-casbin"))]
fn casbin_engine() -> Arc<dyn Engine> {
    Arc::new(DenyAllEngine)
}

/// 生成 Casbin 策略(上游 `generateCasbinPolicies` 的数据变换部分)。
///
/// 角色 → 权限列表 展平为 `"p"` 规则(`v0=角色, v1=路径, v2=方法,
/// v3=域`),连同空的 `"projects"` 集一起装入策略映射。纯数据变换,
/// 不可能失败,上游的 error 返回值被移除。
pub fn generate_casbin_policies(data: &PermissionDataMap) -> PolicyMap {
    let mut rules = Vec::new();
    for (role_code, a_rules) in data {
        for api in a_rules {
            rules.push(PolicyRule {
                p_type: "p".to_string(),
                v0: role_code.clone(),
                v1: api.path.clone(),
                v2: api.method.clone(),
                v3: api.domain.clone(),
            });
        }
    }

    let mut policies = PolicyMap::new();
    policies.insert("policies".to_string(), PolicyValue::CasbinRules(rules));
    policies.insert(
        "projects".to_string(),
        PolicyValue::Projects(make_projects(&[])),
    );
    policies
}

/// 生成 OPA 策略(上游 `generateOpaPolicies` 的数据变换部分)。
///
/// 角色 → 权限列表 变换为 角色 → (pattern, method) 列表。纯数据变换,
/// 不可能失败,上游的 error 返回值被移除。
pub fn generate_opa_policies(data: &PermissionDataMap) -> PolicyMap {
    let mut policies = PolicyMap::with_capacity(data.len());
    for (role_code, a_rule) in data {
        let paths = a_rule
            .iter()
            .map(|api| OpaPolicyPath {
                pattern: api.path.clone(),
                method: api.method.clone(),
            })
            .collect();
        policies.insert(role_code.clone(), PolicyValue::OpaPaths(paths));
    }
    policies
}

/// 权限管理器(上游 `Authorizer`):按配置选择授权引擎,从
/// [`Provider`] 拉取 角色→(path, method) 策略并按引擎格式装载。
///
/// - 配置为 `None` 表示"未配置授权",引擎保持 [`None`](与上游 nil
///   config 语义一致,不静默降级为放行的 noop,调用方应先判
///   [`Authorizer::engine`]);
/// - 引擎以 `Arc<dyn Engine>` 承载,可跨线程共享([`Engine`] 要求
///   `Send + Sync`)。
pub struct Authorizer {
    engine: Option<Arc<dyn Engine>>,
    provider: Arc<dyn Provider>,
}

impl Authorizer {
    /// 创建权限管理器(上游 `NewAuthorizer`;context 与 logger 参数面
    /// 已移除,见模块文档)。
    pub fn new(cfg: Option<&EngineConfig>, provider: Arc<dyn Provider>) -> Self {
        let mut a = Authorizer {
            engine: None,
            provider,
        };
        a.init(cfg);
        a
    }

    /// 装载引擎(上游 `init`;cfg 为 nil 时仅告警并保持引擎为 nil,
    /// 本 crate 无日志面,静默保持 `None`)。
    fn init(&mut self, cfg: Option<&EngineConfig>) {
        let Some(cfg) = cfg else {
            return;
        };
        self.engine = Some(Self::new_engine(cfg));
    }

    /// 引擎访问器(上游 `Engine()`;`None` 对应上游 nil 引擎,即
    /// "未配置授权")。
    pub fn engine(&self) -> Option<Arc<dyn Engine>> {
        self.engine.clone()
    }

    /// 重置策略(上游 `ResetPolicies`):从 Provider 拉取权限数据,按
    /// 引擎名分派格式生成策略并写入引擎。
    ///
    /// 注意与上游一致的顺序:先拉取 Provider 数据,再按引擎名分派——
    /// 即使是 noop(装载为空操作),Provider 失败也会报错;引擎为
    /// `None`(未配置授权)时直接报错。
    pub fn reset_policies(&self) -> Result<(), String> {
        let Some(engine) = self.engine.as_ref() else {
            return Err(ERR_ENGINE_NOT_INITIALIZED.to_string());
        };

        let result = self.provider.provide_policies()?;

        let policies = match engine.name() {
            "casbin" => generate_casbin_policies(&result),
            "opa" | "builtin" => generate_opa_policies(&result),
            "noop" => return Ok(()),
            other => return Err(format!("unknown engine name: {other}")),
        };

        engine.set_policies(&policies, None)?;

        Ok(())
    }

    /// 创建权限引擎(上游 `newEngine` 的分派)。
    ///
    /// - `""` / `"noop"` → [`NoopEngine`];
    /// - `"builtin"` → [`PolicyEngine`](Rust 侧新增的内置 RBAC 引擎,
    ///   上游无对应物——casbin/opa 生态不在时的零依赖替代);
    /// - `"casbin"` → feature `authorizer-casbin` 启用时走真实 casbin
    ///   引擎(见 `casbin` 模块),否则 DenyAll 兜底;
    /// - `"opa"` / `"zanzibar"` → [`DenyAllEngine`]
    ///   (fail-closed,见模块文档差异 2/4);
    /// - 未知类型 → 按上游 default fallthrough 到 noop。
    fn new_engine(cfg: &EngineConfig) -> Arc<dyn Engine> {
        match cfg.engine_type.as_str() {
            "" | "noop" => Arc::new(NoopEngine),
            "builtin" => Arc::new(PolicyEngine::new()),
            "casbin" => casbin_engine(),
            "opa" | "zanzibar" => Arc::new(DenyAllEngine),
            _ => Arc::new(NoopEngine),
        }
    }

    /// 以外部引擎构造管理器(仅测试注入用,替代上游对真实引擎的依赖)。
    #[cfg(test)]
    fn with_engine(engine: Arc<dyn Engine>, provider: Arc<dyn Provider>) -> Self {
        Authorizer {
            engine: Some(engine),
            provider,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 空模型/空策略桩(上游 stubProvider)。
    struct StubProvider;

    impl Provider for StubProvider {
        fn provide_models(&self, _engine_name: &str) -> ModelDataMap {
            ModelDataMap::new()
        }

        fn provide_policies(&self) -> Result<PermissionDataMap, String> {
            Ok(PermissionDataMap::new())
        }
    }

    /// 固定策略与模型的桩(上游 policiesProvider)。
    struct PoliciesProvider;

    impl Provider for PoliciesProvider {
        fn provide_models(&self, _engine_name: &str) -> ModelDataMap {
            let mut m = ModelDataMap::new();
            m.insert(
                "rbac.rego".to_string(),
                b"package rbac\n\nallow = true\n".to_vec(),
            );
            m
        }

        fn provide_policies(&self) -> Result<PermissionDataMap, String> {
            let mut m = PermissionDataMap::new();
            m.insert(
                "admin".to_string(),
                vec![PermissionData {
                    path: "/api/v1/users".to_string(),
                    method: "GET".to_string(),
                    domain: String::new(),
                }],
            );
            Ok(m)
        }
    }

    /// Provider 失败桩(上游 errProvider)。
    struct ErrProvider;

    impl Provider for ErrProvider {
        fn provide_models(&self, _engine_name: &str) -> ModelDataMap {
            ModelDataMap::new()
        }

        fn provide_policies(&self) -> Result<PermissionDataMap, String> {
            Err("provider failure".to_string())
        }
    }

    /// 记录 set_policies 载荷的探针引擎。
    struct RecordingEngine {
        engine_name: &'static str,
        received: Mutex<Option<PolicyMap>>,
    }

    impl RecordingEngine {
        fn new(engine_name: &'static str) -> Self {
            RecordingEngine {
                engine_name,
                received: Mutex::new(None),
            }
        }

        fn received(&self) -> PolicyMap {
            self.received
                .lock()
                .expect("探针引擎互斥锁不应中毒")
                .clone()
                .expect("set_policies 应已被调用")
        }
    }

    impl Engine for RecordingEngine {
        fn name(&self) -> &str {
            self.engine_name
        }

        fn is_authorized(
            &self,
            _subject: &str,
            _action: &str,
            _resource: &str,
            _project: &str,
        ) -> Result<bool, String> {
            Ok(true)
        }

        fn projects_authorized(
            &self,
            _subjects: &[Subject],
            _action: &str,
            _resource: &str,
            _projects: &[Project],
        ) -> Result<Projects, String> {
            Ok(Projects::new())
        }

        fn filter_authorized_pairs(
            &self,
            _subjects: &[Subject],
            _pairs: &[Pair],
        ) -> Result<Pairs, String> {
            Ok(Pairs::new())
        }

        fn filter_authorized_projects(&self, _subjects: &[Subject]) -> Result<Projects, String> {
            Ok(Projects::new())
        }

        fn set_policies(
            &self,
            policies: &PolicyMap,
            _roles: Option<&RoleMap>,
        ) -> Result<(), String> {
            *self.received.lock().expect("探针引擎互斥锁不应中毒") = Some(policies.clone());
            Ok(())
        }
    }

    #[test]
    fn nil_config_keeps_engine_none() {
        // 上游 TestNewAuthorizer_NilConfigKeepsEngineNil:未配置授权时
        // 引擎必须保持 None,不得静默降级为放行;重载策略必须报错
        let a = Authorizer::new(None, Arc::new(StubProvider));
        assert!(a.engine().is_none());
        let err = a.reset_policies().unwrap_err();
        assert_eq!(err, ERR_ENGINE_NOT_INITIALIZED);
    }

    #[test]
    fn noop_engine_is_ready_and_reset_is_noop() {
        // 上游 TestNewAuthorizer_NoopEngine:noop 引擎就绪,重载策略成功
        let a = Authorizer::new(Some(&EngineConfig::new("noop")), Arc::new(StubProvider));
        let engine = a.engine().expect("引擎应已创建");
        assert_eq!(engine.name(), "noop");
        assert!(a.reset_policies().is_ok(), "noop 引擎无需装载策略");
    }

    #[test]
    fn empty_type_defaults_to_noop() {
        // 上游 TestNewAuthorizer_EmptyTypeDefaultsNoop
        let a = Authorizer::new(Some(&EngineConfig::default()), Arc::new(StubProvider));
        let engine = a.engine().expect("引擎应已创建");
        assert_eq!(engine.name(), "noop");
    }

    #[test]
    fn unknown_type_falls_through_to_noop() {
        // 上游 newEngine 的 default fallthrough:未知类型按 noop 处理
        let a = Authorizer::new(
            Some(&EngineConfig::new("some-future-engine")),
            Arc::new(StubProvider),
        );
        let engine = a.engine().expect("引擎应已创建");
        assert_eq!(engine.name(), "noop");
        assert!(engine.is_authorized("u", "GET", "/x", "").unwrap());
    }

    #[test]
    fn unavailable_engine_types_become_deny_all() {
        // 上游 opa/zanzibar 引擎在 Rust 侧不可用:按 fail-closed
        // 统一降级为 deny-all(吸收上游"OPA 模型缺失 → nil、模型损坏 →
        // deny-all"的两种 fail-closed 形态,见模块文档差异 2/4)
        for ty in ["opa", "zanzibar"] {
            let a = Authorizer::new(Some(&EngineConfig::new(ty)), Arc::new(StubProvider));
            let engine = a.engine().expect("引擎应已创建");
            assert_eq!(engine.name(), "deny-all", "类型 {ty} 应降级为 deny-all");

            // 上游 TestNewAuthorizer_OPABrokenModelDeniesAll 的契约:
            // 拒绝判定 + 拒绝策略写入
            let ok = engine.is_authorized("", "", "", "").unwrap_err();
            assert_eq!(ok, ERR_DENY_ALL_ENGINE);
            assert!(engine.set_policies(&PolicyMap::new(), None).is_err());
        }
        // casbin:feature 启用时为真实引擎(见 casbin 模块端到端测试),
        // 未启用时同样降级 deny-all
        let a = Authorizer::new(Some(&EngineConfig::new("casbin")), Arc::new(StubProvider));
        let engine = a.engine().expect("引擎应已创建");
        if cfg!(feature = "authorizer-casbin") {
            assert_eq!(engine.name(), "casbin");
        } else {
            assert_eq!(engine.name(), "deny-all");
            assert_eq!(
                engine.is_authorized("", "", "", "").unwrap_err(),
                ERR_DENY_ALL_ENGINE
            );
        }
    }

    #[test]
    fn noop_engine_allows_and_filters_to_empty() {
        // noop 语义(上游 kratos-authz engine/noop):布尔判定恒放行,
        // 过滤族恒空集,策略写入静默成功
        let e = NoopEngine;
        assert!(e.is_authorized("u", "GET", "/x", "p1").unwrap());
        assert!(e
            .projects_authorized(&["u".to_string()], "GET", "/x", &["p1".to_string()])
            .unwrap()
            .is_empty());
        assert!(e
            .filter_authorized_pairs(&["u".to_string()], &[make_pair("/x", "GET")])
            .unwrap()
            .is_empty());
        assert!(e
            .filter_authorized_projects(&["u".to_string()])
            .unwrap()
            .is_empty());
        assert!(e.set_policies(&PolicyMap::new(), None).is_ok());
    }

    #[test]
    fn deny_all_engine_rejects_everything() {
        // 上游 deny_all_engine.go 逐式语义:五个方法全部拒绝并可观测
        let e = DenyAllEngine;
        assert_eq!(e.name(), "deny-all");
        assert_eq!(
            e.is_authorized("", "", "", "").unwrap_err(),
            ERR_DENY_ALL_ENGINE
        );
        assert_eq!(
            e.projects_authorized(&["u".to_string()], "GET", "/x", &["p1".to_string()])
                .unwrap_err(),
            ERR_DENY_ALL_ENGINE
        );
        assert_eq!(
            e.filter_authorized_pairs(&["u".to_string()], &[make_pair("/x", "GET")])
                .unwrap_err(),
            ERR_DENY_ALL_ENGINE
        );
        assert_eq!(
            e.filter_authorized_projects(&["u".to_string()])
                .unwrap_err(),
            ERR_DENY_ALL_ENGINE
        );
        assert_eq!(
            e.set_policies(&PolicyMap::new(), None).unwrap_err(),
            ERR_DENY_ALL_ENGINE
        );
    }

    #[test]
    fn reset_policies_provider_error_propagates() {
        // 上游 TestResetPolicies_ProviderError:引擎存在时 Provider 失败
        // 必须上抛(此处引擎为降级后的 deny-all,Provider 拉取先于
        // 引擎名分派,错误信息即 Provider 的失败原因)
        let a = Authorizer::new(Some(&EngineConfig::new("casbin")), Arc::new(ErrProvider));
        assert!(a.engine().is_some());
        assert_eq!(a.reset_policies().unwrap_err(), "provider failure");
    }

    #[test]
    fn reset_policies_fetches_provider_even_for_noop() {
        // 上游顺序:先 ProvidePolicies 再按引擎名分派——noop 引擎也会
        // 先拉取 Provider,失败同样上抛
        let a = Authorizer::new(Some(&EngineConfig::new("noop")), Arc::new(ErrProvider));
        assert_eq!(a.reset_policies().unwrap_err(), "provider failure");
    }

    #[test]
    fn reset_policies_loads_casbin_policies() {
        // 装载路径(casbin 格式):展平为 "p" 规则 + 空 projects
        let probe = Arc::new(RecordingEngine::new("casbin"));
        let a = Authorizer::with_engine(probe.clone(), Arc::new(PoliciesProvider));
        assert!(a.reset_policies().is_ok());

        let policies = probe.received();
        assert_eq!(policies.len(), 2);
        let PolicyValue::CasbinRules(rules) = &policies["policies"] else {
            panic!("policies 键应为 casbin 规则集");
        };
        assert_eq!(
            rules,
            &[PolicyRule {
                p_type: "p".to_string(),
                v0: "admin".to_string(),
                v1: "/api/v1/users".to_string(),
                v2: "GET".to_string(),
                v3: String::new(),
            }]
        );
        assert_eq!(policies["projects"], PolicyValue::Projects(Vec::new()));
    }

    #[test]
    fn reset_policies_loads_opa_policies() {
        // 装载路径(OPA 格式):角色 → (pattern, method) 列表
        let probe = Arc::new(RecordingEngine::new("opa"));
        let a = Authorizer::with_engine(probe.clone(), Arc::new(PoliciesProvider));
        assert!(a.reset_policies().is_ok());

        let policies = probe.received();
        assert_eq!(policies.len(), 1);
        assert_eq!(
            policies["admin"],
            PolicyValue::OpaPaths(vec![OpaPolicyPath {
                pattern: "/api/v1/users".to_string(),
                method: "GET".to_string(),
            }])
        );
    }

    #[test]
    fn reset_policies_unknown_engine_name_errors() {
        // 上游 default 分支:未知引擎名在装载分派时报错
        let probe = Arc::new(RecordingEngine::new("mystery"));
        let a = Authorizer::with_engine(probe, Arc::new(PoliciesProvider));
        assert_eq!(
            a.reset_policies().unwrap_err(),
            "unknown engine name: mystery"
        );
    }

    #[test]
    fn generate_casbin_policies_flattens_roles() {
        // 数据变换:多角色多条权限展平为 "p" 规则;域透传
        let mut data = PermissionDataMap::new();
        data.insert(
            "admin".to_string(),
            vec![
                PermissionData {
                    path: "/api/v1/users".to_string(),
                    method: "GET".to_string(),
                    domain: String::new(),
                },
                PermissionData {
                    path: "/api/v1/users".to_string(),
                    method: "POST".to_string(),
                    domain: "example.com".to_string(),
                },
            ],
        );
        data.insert(
            "viewer".to_string(),
            vec![PermissionData {
                path: "/api/v1/reports".to_string(),
                method: "GET".to_string(),
                domain: String::new(),
            }],
        );

        let policies = generate_casbin_policies(&data);
        let PolicyValue::CasbinRules(rules) = &policies["policies"] else {
            panic!("policies 键应为 casbin 规则集");
        };
        assert_eq!(rules.len(), 3);
        assert!(rules.iter().all(|r| r.p_type == "p"));
        assert!(rules.contains(&PolicyRule {
            p_type: "p".to_string(),
            v0: "admin".to_string(),
            v1: "/api/v1/users".to_string(),
            v2: "POST".to_string(),
            v3: "example.com".to_string(),
        }));
        assert_eq!(policies["projects"], PolicyValue::Projects(Vec::new()));
    }

    #[test]
    fn generate_opa_policies_groups_by_role() {
        // 数据变换:角色 → (pattern, method) 列表
        let mut data = PermissionDataMap::new();
        data.insert(
            "admin".to_string(),
            vec![
                PermissionData {
                    path: "/api/v1/users".to_string(),
                    method: "GET".to_string(),
                    domain: "ignored".to_string(),
                },
                PermissionData {
                    path: "/api/v1/users".to_string(),
                    method: "DELETE".to_string(),
                    domain: String::new(),
                },
            ],
        );

        let policies = generate_opa_policies(&data);
        assert_eq!(
            policies["admin"],
            PolicyValue::OpaPaths(vec![
                OpaPolicyPath {
                    pattern: "/api/v1/users".to_string(),
                    method: "GET".to_string(),
                },
                OpaPolicyPath {
                    pattern: "/api/v1/users".to_string(),
                    method: "DELETE".to_string(),
                },
            ])
        );
    }

    #[test]
    fn pair_and_project_helpers() {
        // 上游 MakePair / MakeProjects 的收窄形态
        assert_eq!(
            make_pair("/x", "GET"),
            Pair {
                resource: "/x".to_string(),
                action: "GET".to_string(),
            }
        );
        assert_eq!(make_projects(&[]), Vec::<Project>::new());
        assert_eq!(
            make_projects(&["p1", "p2"]),
            vec!["p1".to_string(), "p2".to_string()]
        );
    }

    #[test]
    fn authorizer_and_engines_are_send_sync() {
        // 引擎以 Arc 跨线程共享:管理器与两个内置引擎必须 Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Authorizer>();
        assert_send_sync::<NoopEngine>();
        assert_send_sync::<DenyAllEngine>();
        assert_send_sync::<PolicyEngine>();

        // 跨线程实际使用引擎
        let a = Arc::new(Authorizer::new(
            Some(&EngineConfig::new("noop")),
            Arc::new(StubProvider),
        ));
        let engine = a.engine().expect("引擎应已创建");
        let handle = std::thread::spawn(move || {
            assert_eq!(engine.name(), "noop");
            assert!(engine.is_authorized("u", "GET", "/x", "").unwrap());
        });
        handle.join().expect("子线程不应 panic");
    }

    // -------------------------------------------------------------------
    // 内置 RBAC 引擎(PolicyEngine)
    // -------------------------------------------------------------------

    fn opa_policies(entries: &[(&str, &str, &str)]) -> PolicyMap {
        let mut map: HashMap<String, Vec<OpaPolicyPath>> = HashMap::new();
        for (role, pattern, method) in entries {
            map.entry(role.to_string())
                .or_default()
                .push(OpaPolicyPath {
                    pattern: pattern.to_string(),
                    method: method.to_string(),
                });
        }
        map.into_iter()
            .map(|(k, v)| (k, PolicyValue::OpaPaths(v)))
            .collect()
    }

    #[test]
    fn policy_engine_direct_subject_binding() {
        // 用户直绑权限:subject 即规则键
        let e = PolicyEngine::new();
        e.set_policies(&opa_policies(&[("user-1", "/api/v1/users", "GET")]), None)
            .unwrap();
        assert_eq!(e.name(), "builtin");
        assert!(e
            .is_authorized("user-1", "GET", "/api/v1/users", "")
            .unwrap());
        // 换方法/换路径/换主体/空主体全部拒绝(fail-closed,Ok(false))
        assert!(!e
            .is_authorized("user-1", "POST", "/api/v1/users", "")
            .unwrap());
        assert!(!e
            .is_authorized("user-1", "GET", "/api/v1/orders", "")
            .unwrap());
        assert!(!e
            .is_authorized("user-2", "GET", "/api/v1/users", "")
            .unwrap());
        assert!(!e.is_authorized("", "GET", "/api/v1/users", "").unwrap());
        // 无策略时也拒绝
        assert!(!PolicyEngine::new()
            .is_authorized("u", "GET", "/x", "")
            .unwrap());
    }

    #[test]
    fn policy_engine_role_bindings_and_inheritance() {
        // 角色绑定 + 传递闭包:alice→editor→viewer;环保护(a→b→a)
        let e = PolicyEngine::new();
        e.set_policies(
            &opa_policies(&[
                ("viewer", "/api/v1/reports", "GET"),
                ("editor", "/api/v1/articles", "*"),
            ]),
            Some(&{
                let mut m = RoleMap::new();
                m.insert("alice".to_string(), vec!["editor".to_string()]);
                m.insert("editor".to_string(), vec!["viewer".to_string()]);
                // 环:carol→dave→carol,carol 自身仍需能解析
                m.insert("carol".to_string(), vec!["dave".to_string()]);
                m.insert("dave".to_string(), vec!["carol".to_string()]);
                m
            }),
        )
        .unwrap();
        // 直绑角色 editor:* 通配全部方法
        assert!(e
            .is_authorized("alice", "POST", "/api/v1/articles", "")
            .unwrap());
        assert!(e
            .is_authorized("alice", "DELETE", "/api/v1/articles", "")
            .unwrap());
        // 传递继承 viewer
        assert!(e
            .is_authorized("alice", "GET", "/api/v1/reports", "")
            .unwrap());
        // viewer 未授权 articles
        assert!(!e
            .is_authorized("alice", "GET", "/api/v1/reports/x", "")
            .unwrap());
        // 未绑定主体拒绝
        assert!(!e
            .is_authorized("mallory", "GET", "/api/v1/reports", "")
            .unwrap());
        // 环保护:carol 可解析(空集),不栈溢出
        assert!(!e
            .is_authorized("carol", "GET", "/api/v1/reports", "")
            .unwrap());
    }

    #[test]
    fn policy_engine_path_patterns() {
        let e = PolicyEngine::new();
        e.set_policies(
            &opa_policies(&[
                ("r-exact", "/api/v1/users", "GET"),
                ("r-single", "/api/v1/orders/*", "GET"),
                ("r-deep", "/files/**", "GET"),
                ("r-method-star", "*", "POST"),
            ]),
            None,
        )
        .unwrap();
        let t = |subject: &str, method: &str, path: &str| {
            e.is_authorized(subject, method, path, "").unwrap()
        };
        // 精确
        assert!(t("r-exact", "GET", "/api/v1/users"));
        // 单段通配:匹配一段,不跨 /
        assert!(t("r-single", "GET", "/api/v1/orders/123"));
        assert!(!t("r-single", "GET", "/api/v1/orders/123/items"));
        assert!(!t("r-single", "GET", "/api/v1/orders"));
        // 后缀 ** 跨段
        assert!(t("r-deep", "GET", "/files/a"));
        assert!(t("r-deep", "GET", "/files/a/b/c.txt"));
        assert!(!t("r-deep", "GET", "/files")); // 前缀本身不算
                                                // 路径 * + 方法 * 的组合(资源级全放行只对 POST 方法)
        assert!(t("r-method-star", "POST", "/anything/here"));
        assert!(!t("r-method-star", "GET", "/anything/here"));
    }

    #[test]
    fn policy_engine_accepts_casbin_rules_and_ignores_non_p() {
        // Casbin 形态装载;g 规则跳过(角色绑定走 roles 参数)
        let e = PolicyEngine::new();
        let mut policies = PolicyMap::new();
        policies.insert(
            "policies".to_string(),
            PolicyValue::CasbinRules(vec![
                PolicyRule {
                    p_type: "p".to_string(),
                    v0: "admin".to_string(),
                    v1: "/api/v1/**".to_string(),
                    v2: "GET".to_string(),
                    v3: String::new(),
                },
                PolicyRule {
                    p_type: "g".to_string(),
                    v0: "alice".to_string(),
                    v1: "admin".to_string(),
                    v2: String::new(),
                    v3: String::new(),
                },
            ]),
        );
        e.set_policies(&policies, None).unwrap();
        assert!(e
            .is_authorized("admin", "GET", "/api/v1/anything/deep", "")
            .unwrap());
        assert!(!e
            .is_authorized("alice", "GET", "/api/v1/anything", "")
            .unwrap());
        // projects/projects 值被宽容忽略
        policies.insert(
            "projects".to_string(),
            PolicyValue::Projects(make_projects(&["p1"])),
        );
        assert!(e.set_policies(&policies, None).is_ok());
    }

    #[test]
    fn policy_engine_filters() {
        let e = PolicyEngine::new();
        e.set_policies(&opa_policies(&[("viewer", "/api/v1/reports", "GET")]), None)
            .unwrap();
        let subjects = vec!["viewer".to_string(), "stranger".to_string()];

        // 过滤 (资源, 动作) 对
        let pairs = vec![
            make_pair("/api/v1/reports", "GET"),
            make_pair("/api/v1/reports", "DELETE"),
            make_pair("/api/v1/users", "GET"),
        ];
        let allowed = e.filter_authorized_pairs(&subjects, &pairs).unwrap();
        assert_eq!(allowed, vec![make_pair("/api/v1/reports", "GET")]);

        // projects_authorized:已授权 → 全部候选;未授权 → 空
        let projects = make_projects(&["p1", "p2"]);
        assert_eq!(
            e.projects_authorized(&subjects, "GET", "/api/v1/reports", &projects)
                .unwrap(),
            projects
        );
        assert!(e
            .projects_authorized(&subjects, "DELETE", "/api/v1/reports", &projects)
            .unwrap()
            .is_empty());
        // filter_authorized_projects:项目维度无策略,恒空(见类型文档)
        assert!(e.filter_authorized_projects(&subjects).unwrap().is_empty());
    }

    #[test]
    fn policy_engine_hot_reload_and_case_insensitive_methods() {
        let e = PolicyEngine::new();
        e.set_policies(&opa_policies(&[("u", "/x", "get")]), None)
            .unwrap();
        // 方法大小写宽容
        assert!(e.is_authorized("u", "GET", "/x", "").unwrap());

        // 热更:整体替换,旧规则消失
        e.set_policies(&opa_policies(&[("u", "/y", "GET")]), None)
            .unwrap();
        assert!(!e.is_authorized("u", "GET", "/x", "").unwrap());
        assert!(e.is_authorized("u", "GET", "/y", "").unwrap());
    }

    #[test]
    fn builtin_engine_end_to_end_via_authorizer() {
        // 走管理器全程:builtin 分派 → OPA 格式装载 → 判定
        struct RoleProvider;
        impl Provider for RoleProvider {
            fn provide_models(&self, _engine_name: &str) -> ModelDataMap {
                ModelDataMap::new()
            }
            fn provide_policies(&self) -> Result<PermissionDataMap, String> {
                let mut m = PermissionDataMap::new();
                m.insert(
                    "admin".to_string(),
                    vec![PermissionData {
                        path: "/api/v1/**".to_string(),
                        method: "GET".to_string(),
                        domain: String::new(),
                    }],
                );
                m.insert(
                    "auditor".to_string(),
                    vec![PermissionData {
                        path: "/api/v1/audit".to_string(),
                        method: "GET".to_string(),
                        domain: String::new(),
                    }],
                );
                Ok(m)
            }
        }
        let a = Authorizer::new(Some(&EngineConfig::new("builtin")), Arc::new(RoleProvider));
        a.reset_policies().unwrap();
        let engine = a.engine().expect("builtin 引擎应已创建");
        assert_eq!(engine.name(), "builtin");
        assert!(engine
            .is_authorized("admin", "GET", "/api/v1/users/42", "")
            .unwrap());
        assert!(engine
            .is_authorized("auditor", "GET", "/api/v1/audit", "")
            .unwrap());
        assert!(!engine
            .is_authorized("auditor", "GET", "/api/v1/users", "")
            .unwrap());
    }

    #[test]
    fn policy_engine_is_send_sync_and_hot_swappable_across_threads() {
        // 策略热更与判定并发安全(RwLock)
        let e = Arc::new(PolicyEngine::new());
        e.set_policies(&opa_policies(&[("u", "/x", "GET")]), None)
            .unwrap();
        let reader = e.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..50 {
                assert!(reader.is_authorized("u", "GET", "/x", "").unwrap());
            }
        });
        for _ in 0..50 {
            assert!(e.is_authorized("u", "GET", "/x", "").unwrap());
        }
        handle.join().unwrap();
    }
}
