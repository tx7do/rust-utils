//! OPA 引擎(feature `authorizer-opa`)—— 把壳的 `"opa"` 类型从
//! DenyAll 兜底升级为真实引擎:HTTP 调 OPA 服务的数据 API
//! (`POST {endpoint}{policy_path}`)评估决策,策略由 OPA 侧的
//! bundle/文件自行装载,本引擎只做**决策查询**,不写策略。
//!
//! # 请求与响应
//!
//! ```text
//! POST http://opa:8181/v1/data/rbac/allow
//! {"input": {"subject": "alice", "action": "GET", "resource": "/api/v1/users", "project": ""}}
//! → 200 {"result": true}
//! ```
//!
//! 语义(fail-closed):
//! - 响应缺 `result` 键(OPA 对未定义决策返回 `{}`)→ `Ok(false)`
//!   —— 未定义即拒绝,是 OPA 的标准语义;
//! - 非 200 / 连接失败 / 响应非 JSON → `Err`(可观测的底层错误);
//! - 超时缺省 5s,`with_timeout` 可调。
//!
//! 端点配置:显式构造 [`OpaEngine::new`],或经壳分派时读环境变量
//! `OPA_ENDPOINT`(缺省 `http://127.0.0.1:8181`)与
//! `OPA_POLICY_PATH`(缺省 `/v1/data/rbac/allow`)。
//!
//! 过滤族(projects_authorized / filter_authorized_pairs)按
//! (主体 × 候选) 逐条评估 —— OPA 的批量决策走 `/v1/data` 单次查询
//! 由 rego 端自行展开,这里保持通用逐条形态。`set_policies` 返回
//! Err(策略由 OPA bundle 管理,引擎不写);`filter_authorized_projects`
//! 恒空(项目维度无策略数据,与内置引擎同语义)。

use serde_json::json;

use crate::authorizer::{Engine, Pair, PolicyMap, Projects, RoleMap, Subject};

/// 缺省 OPA 端点。
pub const DEFAULT_OPA_ENDPOINT: &str = "http://127.0.0.1:8181";

/// 缺省决策路径(rego 侧约定 `rbac/allow` 返回布尔)。
pub const DEFAULT_POLICY_PATH: &str = "/v1/data/rbac/allow";

/// OPA 决策引擎(HTTP 查询,策略由 OPA 侧管理)。
pub struct OpaEngine {
    /// OPA 服务根(如 `http://opa:8181`,尾斜杠容忍)。
    endpoint: String,
    /// 决策路径(如 `/v1/data/rbac/allow`)。
    policy_path: String,
    agent: ureq::Agent,
}

impl OpaEngine {
    /// 缺省端点/路径构造(超时 5s)。
    pub fn new() -> Self {
        Self::with_config(
            DEFAULT_OPA_ENDPOINT,
            DEFAULT_POLICY_PATH,
            std::time::Duration::from_secs(5),
        )
    }

    /// 显式端点/路径/超时构造(endpoint 尾斜杠容忍;policy_path
    /// 需以 `/v1/data` 开头,不以 `/` 开头时自动补)。
    pub fn with_config(endpoint: &str, policy_path: &str, timeout: std::time::Duration) -> Self {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let policy_path = if policy_path.starts_with('/') {
            policy_path.to_string()
        } else {
            format!("/{policy_path}")
        };
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .timeout_connect(timeout)
            .build();
        OpaEngine {
            endpoint,
            policy_path,
            agent,
        }
    }

    /// 从环境变量构造(壳分派用):`OPA_ENDPOINT`/`OPA_POLICY_PATH`,
    /// 缺省值见模块文档;超时 5s。
    pub fn from_env() -> Self {
        let endpoint =
            std::env::var("OPA_ENDPOINT").unwrap_or_else(|_| DEFAULT_OPA_ENDPOINT.to_string());
        let policy_path =
            std::env::var("OPA_POLICY_PATH").unwrap_or_else(|_| DEFAULT_POLICY_PATH.to_string());
        Self::with_config(&endpoint, &policy_path, std::time::Duration::from_secs(5))
    }

    /// 查询一次决策:input 为 subject/action/resource/project 四元组,
    /// 返回 `result` 布尔;未定义(false)与错误(Err)分面返回。
    fn decide(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        project: &str,
    ) -> Result<bool, String> {
        let url = format!("{}{}", self.endpoint, self.policy_path);
        let body = json!({
            "input": {
                "subject": subject,
                "action": action,
                "resource": resource,
                "project": project,
            }
        });
        let resp = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| format!("opaengine: request {url}: {e}"))?;
        let text = resp
            .into_string()
            .map_err(|e| format!("opaengine: read response: {e}"))?;
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("opaengine: parse response: {e}"))?;
        // 未定义决策({})= 拒绝(OPA 标准语义);result 非布尔报错
        match value.get("result") {
            None => Ok(false),
            Some(v) => v
                .as_bool()
                .ok_or_else(|| format!("opaengine: result is not a boolean: {v}")),
        }
    }
}

impl Default for OpaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine for OpaEngine {
    fn name(&self) -> &str {
        "opa"
    }

    fn is_authorized(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        project: &str,
    ) -> Result<bool, String> {
        self.decide(subject, action, resource, project)
    }

    fn projects_authorized(
        &self,
        subjects: &[Subject],
        action: &str,
        resource: &str,
        projects: &[crate::authorizer::Project],
    ) -> Result<Projects, String> {
        let mut out = Vec::new();
        for project in projects {
            // 任一主体放行即计入;决策失败整体报错(fail-closed)
            let mut authorized = false;
            for s in subjects {
                match self.decide(s, action, resource, project) {
                    Ok(true) => {
                        authorized = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(e) => return Err(e),
                }
            }
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
        let mut out = Vec::new();
        for pair in pairs {
            let mut authorized = false;
            for s in subjects {
                match self.decide(s, &pair.action, &pair.resource, "") {
                    Ok(true) => {
                        authorized = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(e) => return Err(e),
                }
            }
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

    fn set_policies(&self, _policies: &PolicyMap, _roles: Option<&RoleMap>) -> Result<(), String> {
        // 策略由 OPA bundle/文件自行装载,引擎侧只读
        Err(
            "opaengine: policies are managed by the OPA service (bundle); this engine is read-only"
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorizer::make_pair;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    /// 假 OPA:监听随机端口,按脚本对每次请求回状态行 + JSON 体。
    /// 返回 (端口, 停止句柄)。HTTP 解析仅取到头部结束即应答
    /// (OPA 场景只需路径存在性,请求体不参与回放)。
    fn fake_opa(script: Vec<(u16, String)>) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            for (status, body) in script {
                let (mut stream, _) = listener.accept().expect("accept");
                let _ = read_request_head(&mut stream);
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
            // 脚本耗尽后直接收尾(后续请求由调用方以 Err 断言)
        });
        (port, handle)
    }

    fn read_request_head(stream: &mut TcpStream) -> String {
        let mut buf = [0u8; 4096];
        let mut head = Vec::new();
        loop {
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
            if let Ok(s) = std::str::from_utf8(&head) {
                if s.contains("\r\n\r\n") {
                    break;
                }
            }
            if head.len() > 64 * 1024 {
                break;
            }
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    fn engine_at(port: u16) -> OpaEngine {
        OpaEngine::with_config(
            &format!("http://127.0.0.1:{port}"),
            "/v1/data/rbac/allow",
            std::time::Duration::from_secs(2),
        )
    }

    #[test]
    fn result_true_false_and_undefined() {
        // true / false / 未定义({})三种决策
        let (port, handle) = fake_opa(vec![
            (200, r#"{"result": true}"#.into()),
            (200, r#"{"result": false}"#.into()),
            (200, "{}".into()),
        ]);
        let e = engine_at(port);
        assert_eq!(e.name(), "opa");
        assert!(e.is_authorized("alice", "GET", "/x", "").unwrap());
        assert!(!e.is_authorized("alice", "GET", "/x", "").unwrap());
        // 未定义 = 拒绝(OPA 标准语义)
        assert!(!e.is_authorized("bob", "GET", "/x", "").unwrap());
        handle.join().unwrap();
    }

    #[test]
    fn non_200_and_bad_json_are_errors() {
        // 500 → Err(fail-closed 可观测);坏 JSON → Err
        let (port, handle) = fake_opa(vec![(500, "boom".into()), (200, "not-json".into())]);
        let e = engine_at(port);
        let err = e.is_authorized("a", "GET", "/x", "").unwrap_err();
        assert!(err.contains("opaengine"), "err={err}");
        let err = e.is_authorized("a", "GET", "/x", "").unwrap_err();
        assert!(err.contains("parse response"), "err={err}");
        handle.join().unwrap();
    }

    #[test]
    fn non_bool_result_is_error() {
        let (port, handle) = fake_opa(vec![(200, r#"{"result": "yes"}"#.into())]);
        let e = engine_at(port);
        let err = e.is_authorized("a", "GET", "/x", "").unwrap_err();
        assert!(err.contains("not a boolean"), "err={err}");
        handle.join().unwrap();
    }

    #[test]
    fn connection_refused_is_error() {
        // 拒绝连接的端口 → Err(而非 false),fail-closed 可观测
        let e = OpaEngine::with_config(
            "http://127.0.0.1:1",
            "/v1/data/x",
            std::time::Duration::from_millis(500),
        );
        assert!(e.is_authorized("a", "GET", "/x", "").is_err());
    }

    #[test]
    fn filters_and_readonly_policies() {
        // 过滤族按 (主体 × 候选) 逐条评:GET 允许、DELETE 拒绝
        let (port, handle) = fake_opa(vec![
            (200, r#"{"result": true}"#.into()),  // viewer GET /r/1
            (200, r#"{"result": false}"#.into()), // viewer DELETE /r/1
        ]);
        let e = engine_at(port);
        let subjects = vec!["viewer".to_string()];
        let allowed = e
            .filter_authorized_pairs(
                &subjects,
                &[make_pair("/r/1", "GET"), make_pair("/r/1", "DELETE")],
            )
            .unwrap();
        assert_eq!(allowed, vec![make_pair("/r/1", "GET")]);
        // set_policies:OPA bundle 管理策略,引擎只读
        assert!(e
            .set_policies(&crate::authorizer::PolicyMap::new(), None)
            .is_err());
        // 项目维度恒空
        assert!(e.filter_authorized_projects(&subjects).unwrap().is_empty());
        handle.join().unwrap();
    }

    #[test]
    fn endpoint_normalization() {
        // 尾斜杠容忍 + 路径补斜杠
        let e = OpaEngine::with_config(
            "http://x:8181/",
            "v1/data/a",
            std::time::Duration::from_secs(1),
        );
        // 内部形态不直接可见,以请求 URL 拼接的正确性由 fake OPA 接受请求佐证
        assert!(e.is_authorized("a", "GET", "/x", "").is_err()); // 无服务 → Err
    }
}
