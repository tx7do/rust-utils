//! etcd 分布式锁后端(feature `distlock-etcd`)。
//!
//! 协议(标准 lease+txn 抢锁形态):
//! - **获取**:`lease grant(TTL)` → 事务(`version(key)==0` →
//!   `put(key, token, with_lease)`),失败回收租约并退避重试;
//! - **续期**:lease keep-alive 单次往返,并回读键值确认仍持锁
//!   (锁已释放/过期时续期报错,与 Redis 后端语义一致);
//! - **释放**:事务(`value(key)==token` → `delete`),成功后
//!   回收租约。
//!
//! 令牌为 16 随机字节的 raw-base64url(与 Redis 后端同款);重试为
//! 线性退避限次,期限以锁 TTL 为界;`with_block_wait` 选项在本后端
//! 生效(以 `max_wait_time` 为等待期限,0 按 TTL 处理)。请求路径
//! 依赖运行中的 etcd 实例(端点缺省 `http://127.0.0.1:2379`,可用
//! `ETCD_ENDPOINTS` 覆盖,逗号分隔);离线测试覆盖选项/令牌与无监听
//! 端点的错误透传,实例测试在端点可用时自动执行(互斥/续期/过期/
//! 阻塞等待)。
//!
//! async 收口:etcd-client 为 tokio 生态,进程级 runtime 复用,
//! `Locker`/`Lock` 仍为同步面。

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use etcd_client::{Client, Compare, CompareOp, PutOptions, Txn, TxnOp};

use crate::distlock::{
    compose_lock_value, BackoffRunner, Lock, LockOption, Locker, OnRefreshError, StopHandle,
    ERR_NOT_OBTAINED,
};

const DEFAULT_TTL: Duration = Duration::from_secs(30);
const DEFAULT_MAX_RETRIES: i64 = 10;
const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// 缺省端点(可用 `ETCD_ENDPOINTS` 环境变量覆盖,逗号分隔)。
pub const DEFAULT_ENDPOINTS: &str = "http://127.0.0.1:2379";

/// 锁获取与续期行为配置(零值字段自动补全默认值,与 Redis 后端同构)。
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// 锁的有效期;默认 30s(etcd 租约按整秒授予,不足 1s 按 1s)。
    pub ttl: Duration,
    /// 争抢锁时的最大重试次数;默认 10。
    pub max_retries: i64,
    /// 线性退避的步长;默认 100ms。
    pub retry_delay: Duration,
    /// 后台续期间隔;默认 TTL/3。
    pub refresh_interval: Duration,
}

impl Options {
    /// 补全默认值。
    pub fn with_defaults(mut self) -> Self {
        if self.ttl <= Duration::ZERO {
            self.ttl = DEFAULT_TTL;
        }
        if self.max_retries <= 0 {
            self.max_retries = DEFAULT_MAX_RETRIES;
        }
        if self.retry_delay <= Duration::ZERO {
            self.retry_delay = DEFAULT_RETRY_DELAY;
        }
        if self.refresh_interval <= Duration::ZERO {
            self.refresh_interval = self.ttl / 3;
        }
        self
    }
}

/// etcd 请求的 async 收口(进程级 runtime 复用)。
fn block_on<T>(fut: impl Future<Output = T>) -> Result<T, String> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt.block_on(fut));
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("etcdlock: build tokio runtime: {e}"))?;
    let _ = RUNTIME.set(rt);
    RUNTIME
        .get()
        .map(|rt| rt.block_on(fut))
        .ok_or_else(|| "etcdlock: runtime init".to_string())
}

/// 已获取的 etcd 锁。
pub struct EtcdLock {
    inner: Arc<LockInner>,
}

/// 锁的共享状态(供后台续期线程持有,以引用计数保持存活)。
/// TTL 由租约在服务端承载,续期走 keep-alive 不需要本地值。
struct LockInner {
    client: Client,
    key: String,
    token: String,
    lease_id: i64,
    refresh_interval: Duration,
}

impl LockInner {
    /// 续期一次:keep-alive 单次往返;租约 TTL 归零(已过期/回收)
    /// 或键值不再持有本令牌时报错。
    fn run_refresh(&self) -> Result<(), String> {
        block_on(async {
            let mut client = self.client.clone();
            let (mut keeper, mut stream) = client
                .lease_keep_alive(self.lease_id)
                .await
                .map_err(|e| format!("etcdlock: keep alive: {e}"))?;
            keeper
                .keep_alive()
                .await
                .map_err(|e| format!("etcdlock: keep alive send: {e}"))?;
            let resp = stream
                .message()
                .await
                .map_err(|e| format!("etcdlock: keep alive recv: {e}"))?;
            match resp {
                Some(r) if r.ttl() > 0 => {}
                _ => return Err("etcdlock: lease expired".to_string()),
            }
            // 键仍持有本令牌才算续期成功(锁被释放/被接管后不应再续)
            let resp = client
                .get(self.key.clone(), None)
                .await
                .map_err(|e| format!("etcdlock: get: {e}"))?;
            let held = resp
                .kvs()
                .first()
                .map(|kv| kv.value_str().unwrap_or_default() == self.token)
                .unwrap_or(false);
            if held {
                Ok(())
            } else {
                Err("etcdlock: not obtained".to_string())
            }
        })
        .and_then(|inner| inner)
    }

    /// 剩余有效期:lease_time_to_live 取剩余秒;租约失效(-1)报错。
    fn run_ttl(&self) -> Result<Duration, String> {
        block_on(async {
            let mut client = self.client.clone();
            let resp = client
                .lease_time_to_live(self.lease_id, None)
                .await
                .map_err(|e| format!("etcdlock: time to live: {e}"))?;
            if resp.ttl() >= 0 {
                Ok(Duration::from_secs(resp.ttl() as u64))
            } else {
                Err("etcdlock: not obtained".to_string())
            }
        })
        .and_then(|inner| inner)
    }

    /// 释放:事务(值等于令牌 → 删除),成功后回收租约。
    fn run_release(&self) -> Result<(), String> {
        block_on(async {
            let mut client = self.client.clone();
            let txn = Txn::new()
                .when(vec![Compare::value(
                    self.key.clone(),
                    CompareOp::Equal,
                    self.token.clone(),
                )])
                .and_then(vec![TxnOp::delete(self.key.clone(), None)]);
            let resp = client
                .txn(txn)
                .await
                .map_err(|e| format!("etcdlock: release txn: {e}"))?;
            if resp.succeeded() {
                // 键已删除,租约随即回收(失败不影响释放语义)
                let _ = client.lease_revoke(self.lease_id).await;
                Ok(())
            } else {
                Err("etcdlock: lock not held".to_string())
            }
        })
        .and_then(|inner| inner)
    }
}

impl Lock for EtcdLock {
    fn key(&self) -> String {
        self.inner.key.clone()
    }

    fn release(&self) -> Result<(), String> {
        self.inner.run_release()
    }

    fn refresh(&self) -> Result<(), String> {
        self.inner.run_refresh()
    }

    fn ttl(&self) -> Result<Duration, String> {
        self.inner.run_ttl()
    }

    fn start_refresh(&self, on_error: Option<OnRefreshError>) -> StopHandle {
        // 固定间隔定时续期;续期失败即回调并退出。停止信道被
        // 丢弃时同样退出(见包级文档)。
        let (sender, receiver) = std::sync::mpsc::channel::<()>();
        let inner = Arc::clone(&self.inner);
        let interval = self.inner.refresh_interval;
        let thread = std::thread::spawn(move || loop {
            match receiver.recv_timeout(interval) {
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if let Err(e) = inner.run_refresh() {
                        if let Some(callback) = &on_error {
                            callback(&e);
                        }
                        return;
                    }
                }
                _ => return,
            }
        });
        StopHandle {
            sender: Some(sender),
            thread: Some(thread),
        }
    }
}

/// etcd 分布式锁后端。
pub struct EtcdLocker {
    client: Client,
    opts: Options,
}

impl EtcdLocker {
    /// 连接 etcd 集群(endpoints 任一可达即可;opts 补全默认值)。
    pub fn new(endpoints: &[String], opts: Options) -> Result<Self, String> {
        let client = block_on(Client::connect(endpoints, None))
            .map_err(|rt_err| format!("etcdlock: build runtime: {rt_err}"))
            .and_then(|inner| inner.map_err(|e| format!("etcdlock: connect: {e}")))?;
        Ok(EtcdLocker {
            client,
            opts: opts.with_defaults(),
        })
    }

    /// 以缺省端点(`ETCD_ENDPOINTS` 或 `http://127.0.0.1:2379`)连接。
    pub fn with_default_endpoint(opts: Options) -> Result<Self, String> {
        let raw = std::env::var("ETCD_ENDPOINTS").unwrap_or_else(|_| DEFAULT_ENDPOINTS.to_string());
        let endpoints: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self::new(&endpoints, opts)
    }

    /// 单次抢锁尝试:授租约 → 事务(version==0 → put with lease)。
    /// 成功返回租约 ID;事务失败回收租约返回 None;底层错误上抛
    /// (事务报错时同样回收租约,避免空租约滞留)。
    fn try_obtain(&self, key: &str, token: &str, ttl_secs: i64) -> Result<Option<i64>, String> {
        block_on(async {
            let mut client = self.client.clone();
            let lease = client
                .lease_grant(ttl_secs, None)
                .await
                .map_err(|e| format!("etcdlock: lease grant: {e}"))?;
            let lease_id = lease.id();
            let txn = Txn::new()
                .when(vec![Compare::version(key, CompareOp::Equal, 0)])
                .and_then(vec![TxnOp::put(
                    key,
                    token,
                    Some(PutOptions::new().with_lease(lease_id)),
                )]);
            let outcome = client.txn(txn).await;
            match outcome {
                Ok(resp) if resp.succeeded() => Ok(Some(lease_id)),
                Ok(_) => {
                    let _ = client.lease_revoke(lease_id).await;
                    Ok(None)
                }
                Err(e) => {
                    let _ = client.lease_revoke(lease_id).await;
                    Err(format!("etcdlock: acquire txn: {e}"))
                }
            }
        })
        .and_then(|inner| inner)
    }
}

impl Locker for EtcdLocker {
    fn obtain(&self, key: &str, opts: &[LockOption]) -> Result<Box<dyn Lock>, String> {
        // 锁值 = 令牌(自定义或随机)+ 元数据;重试策略自 LockConfig
        // (Linear/Exponential/NoRetry);block_wait 模式以 max_wait_time
        // 为等待期限,其余以锁 TTL 为界
        let mut cfg = crate::distlock::default_lock_config();
        for opt in opts {
            opt(&mut cfg);
        }
        let (token, _token_len) = compose_lock_value(cfg.token.as_deref(), cfg.metadata.as_deref());
        let ttl_secs = (self.opts.ttl.as_secs().max(1)) as i64;
        // 等待期限:阻塞模式用 max_wait_time(0 按 TTL 兜底),否则锁 TTL
        let wait = if cfg.block_wait && cfg.max_wait_time > Duration::ZERO {
            cfg.max_wait_time
        } else {
            self.opts.ttl
        };
        let deadline = Instant::now().checked_add(wait);
        let retry_delay = if cfg.retry_delay > Duration::ZERO {
            cfg.retry_delay
        } else {
            self.opts.retry_delay
        };
        let mut backoff = BackoffRunner::new(
            cfg.backoff,
            retry_delay,
            self.opts.ttl,
            self.opts.max_retries,
        );
        loop {
            if let Some(lease_id) = self.try_obtain(key, &token, ttl_secs)? {
                return Ok(Box::new(EtcdLock {
                    inner: Arc::new(LockInner {
                        client: self.client.clone(),
                        key: key.to_string(),
                        token,
                        lease_id,
                        refresh_interval: self.opts.refresh_interval,
                    }),
                }));
            }
            let backoff = backoff.next();
            if backoff < Duration::from_millis(1) {
                return Err(ERR_NOT_OBTAINED.to_string());
            }
            if !deadline.is_some_and(|d| Instant::now() < d) {
                return Err("context deadline exceeded".to_string());
            }
            std::thread::sleep(backoff);
        }
    }

    fn close(&self) -> Result<(), String> {
        // 客户端随 Arc 存活,无显式关闭面
        Ok(())
    }

    fn is_locked(&self, key: &str) -> Result<bool, String> {
        // 以获取探测;未拿到 → 已加锁;其它错误透传;
        // 拿到 → 立即释放并返回未加锁
        match self.obtain(key, &[]) {
            Err(e) if e == ERR_NOT_OBTAINED => Ok(true),
            Err(e) => Err(e),
            Ok(lock) => {
                let _ = lock.release();
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn etcd_options_defaults() {
        // 零值补默认(30s/10/100ms/refresh=TTL/3),非零字段保留
        let o = Options::default().with_defaults();
        assert_eq!(o.ttl, Duration::from_secs(30));
        assert_eq!(o.max_retries, 10);
        assert_eq!(o.retry_delay, Duration::from_millis(100));
        assert_eq!(o.refresh_interval, Duration::from_secs(10));
        let o = Options {
            ttl: Duration::from_secs(90),
            ..Default::default()
        }
        .with_defaults();
        assert_eq!(o.ttl, Duration::from_secs(90));
        assert_eq!(o.refresh_interval, Duration::from_secs(30));
    }

    #[test]
    fn etcd_token_rawurl() {
        // raw-base64url 向量已收敛到 distlock 共用层;此处钉死锁值合成
        let (value, token_len) = compose_lock_value(None, None);
        assert_eq!(value.len(), 22);
        assert_eq!(token_len, 22);
        let (value, token_len) = compose_lock_value(Some("tok"), Some("|meta"));
        assert_eq!(value, "tok|meta");
        assert_eq!(token_len, 3);
    }

    #[test]
    fn etcd_dead_endpoint_errors_transparently() {
        // 无监听端点:连接与获取均透传底层错误,非未获取哨兵
        let locker = EtcdLocker::new(
            &["http://127.0.0.1:1".to_string()],
            Options {
                ttl: Duration::from_secs(1),
                max_retries: 1,
                retry_delay: Duration::from_millis(1),
                refresh_interval: Duration::from_millis(1),
            },
        );
        match locker {
            // 端口 1 无 etcd:连接即失败(个别环境若存在代理则跳过)
            Err(e) => {
                assert!(e.contains("etcdlock: connect"), "err={e}");
            }
            Ok(locker) => {
                let err = locker.obtain("k", &[]).err().unwrap();
                assert_ne!(err, ERR_NOT_OBTAINED);
                let err = locker.is_locked("k").err().unwrap();
                assert_ne!(err, ERR_NOT_OBTAINED);
            }
        }
    }

    // ---- 以下为实例测试:端点可用时自动执行,不可用即跳过 ----

    fn live_locker(opts: Options) -> Option<EtcdLocker> {
        // etcd-client 连接为惰性拨号,构造成功不代表实例可达;
        // 用一次真实 RPC(is_locked → lease_grant)探测
        match EtcdLocker::with_default_endpoint(opts) {
            Ok(locker) => match locker.is_locked("rust-utils/etcd/probe") {
                Ok(_) => Some(locker),
                Err(e) => {
                    eprintln!("skip: etcd 实例不可用({e})");
                    None
                }
            },
            Err(e) => {
                eprintln!("skip: etcd 实例不可用({e})");
                None
            }
        }
    }

    #[test]
    fn etcd_live_obtain_release_roundtrip() {
        let Some(locker) = live_locker(Options::default()) else {
            return;
        };
        let lock = locker.obtain("rust-utils/etcd/roundtrip", &[]).unwrap();
        assert_eq!(lock.key(), "rust-utils/etcd/roundtrip");
        // 互斥:持锁期间他人拿不到
        let err = locker
            .obtain("rust-utils/etcd/roundtrip", &[])
            .err()
            .unwrap();
        assert_eq!(err, ERR_NOT_OBTAINED);
        assert!(locker.is_locked("rust-utils/etcd/roundtrip").unwrap());
        // 释放后可再次获取
        lock.release().unwrap();
        assert!(!locker.is_locked("rust-utils/etcd/roundtrip").unwrap());
        let lock2 = locker.obtain("rust-utils/etcd/roundtrip", &[]).unwrap();
        lock2.release().unwrap();
    }

    #[test]
    fn etcd_live_release_twice_is_not_held_error() {
        let Some(locker) = live_locker(Options::default()) else {
            return;
        };
        let lock = locker.obtain("rust-utils/etcd/release-twice", &[]).unwrap();
        lock.release().unwrap();
        // 二次释放:值比对失败 → lock not held
        let err = lock.release().unwrap_err();
        assert_eq!(err, "etcdlock: lock not held");
    }

    #[test]
    fn etcd_live_refresh_extends_and_fails_after_release() {
        let Some(locker) = live_locker(Options::default()) else {
            return;
        };
        let lock = locker.obtain("rust-utils/etcd/refresh", &[]).unwrap();
        // 持锁期间续期成功
        lock.refresh().unwrap();
        // 后台续期线程启动后立刻停止(句柄语义)
        let mut handle = lock.start_refresh(None);
        handle.stop();
        // 释放后续期报错(键已删)
        lock.release().unwrap();
        let err = lock.refresh().unwrap_err();
        assert!(err.contains("etcdlock"), "err={err}");
    }

    #[test]
    fn etcd_live_lease_expiry_frees_lock() {
        // 1s TTL,不续期 → 到期后他人可获取
        let Some(locker) = live_locker(Options {
            ttl: Duration::from_secs(1),
            max_retries: 1,
            retry_delay: Duration::from_millis(50),
            refresh_interval: Duration::from_secs(60),
        }) else {
            return;
        };
        let lock = locker.obtain("rust-utils/etcd/expiry", &[]).unwrap();
        std::mem::forget(lock); // 模拟持锁方崩溃:不释放、不续期
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut freed = false;
        while Instant::now() < deadline {
            match locker.obtain("rust-utils/etcd/expiry", &[]) {
                Ok(new_lock) => {
                    new_lock.release().unwrap();
                    freed = true;
                    break;
                }
                Err(e) if e == ERR_NOT_OBTAINED => std::thread::sleep(Duration::from_millis(200)),
                Err(e) => panic!("unexpected: {e}"),
            }
        }
        assert!(freed, "租约到期后锁应被释放");
    }

    #[test]
    fn etcd_live_block_wait_waits_for_release() {
        // 持锁方 300ms 后释放,阻塞等待方应在期限内拿到
        let Some(a) = live_locker(Options::default()) else {
            return;
        };
        let Some(b) = live_locker(Options {
            retry_delay: Duration::from_millis(50),
            ..Default::default()
        }) else {
            return;
        };
        let lock = a.obtain("rust-utils/etcd/blockwait", &[]).unwrap();
        let handle = std::thread::spawn(move || {
            b.obtain(
                "rust-utils/etcd/blockwait",
                &[crate::distlock::with_block_wait(Duration::from_secs(3))],
            )
            .unwrap()
            .release()
        });
        std::thread::sleep(Duration::from_millis(300));
        lock.release().unwrap();
        // 等待方应已成功获取并释放(线程返回释放的 Result)
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn etcd_live_refresh_thread_exits_on_error() {
        // 续期失败即回调并退出(释放锁后线程在下个间隔失败退出)
        let Some(locker) = live_locker(Options {
            refresh_interval: Duration::from_millis(30),
            ..Default::default()
        }) else {
            return;
        };
        let lock = locker.obtain("rust-utils/etcd/thread-exit", &[]).unwrap();
        let hit = Arc::new(AtomicBool::new(false));
        let hit2 = Arc::clone(&hit);
        let mut handle = lock.start_refresh(Some(Box::new(move |_e| {
            hit2.store(true, Ordering::SeqCst);
        })));
        lock.release().unwrap();
        for _ in 0..100 {
            if hit.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        handle.stop();
        assert!(hit.load(Ordering::SeqCst));
    }

    #[test]
    fn etcd_live_ttl_and_options() {
        let Some(locker) = live_locker(Options {
            ttl: Duration::from_secs(10),
            ..Default::default()
        }) else {
            return;
        };
        // ttl():持锁期在 (0, TTL] 内
        let lock = locker
            .obtain(
                "rust-utils/etcd/ttl",
                &[crate::distlock::with_token("fixed-tok")],
            )
            .unwrap();
        let remaining = lock.ttl().unwrap();
        assert!(remaining <= Duration::from_secs(10));
        assert!(remaining > Duration::ZERO, "持锁期应还有剩余");
        // 锁值 = 自定义令牌(经 etcdctl 可查,这里以获取探测证明值已落)
        let err = locker.obtain("rust-utils/etcd/ttl", &[]).err().unwrap();
        assert_eq!(err, ERR_NOT_OBTAINED);
        lock.release().unwrap();
        // 释放后 ttl 报错(租约已回收)
        assert!(lock.ttl().is_err());

        // NoRetry:争抢失败立即返回哨兵(不重试不等待)
        let holder = locker.obtain("rust-utils/etcd/noretry", &[]).unwrap();
        let t0 = Instant::now();
        let err = locker
            .obtain(
                "rust-utils/etcd/noretry",
                &[crate::distlock::with_backoff(
                    crate::distlock::Backoff::NoRetry,
                )],
            )
            .err()
            .unwrap();
        assert_eq!(err, ERR_NOT_OBTAINED);
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "NoRetry 应即时返回"
        );
        holder.release().unwrap();
    }

    #[test]
    fn etcd_live_metadata_value_composition() {
        // 元数据附加到锁值:同一令牌 + 不同元数据 = 不同锁值,
        // 释放以完整锁值比对
        let Some(locker) = live_locker(Options::default()) else {
            return;
        };
        let lock = locker
            .obtain(
                "rust-utils/etcd/meta",
                &[
                    crate::distlock::with_token("tok"),
                    crate::distlock::with_metadata("|node-1"),
                ],
            )
            .unwrap();
        // 释放成功(完整锁值 tok|node-1 比对命中)
        lock.release().unwrap();
        // 二次释放失败
        assert_eq!(lock.release().unwrap_err(), "etcdlock: lock not held");
    }
}
