//! Redis 分布式锁后端(feature `distlock-redis`)。
//!
//! 线上协议兼容 bsm/redislock v0.9.4:获取经 Lua 脚本(`SET NX
//! PX` 的原子包裹,附带同令牌前缀下的重入分支),续期/释放为
//! 令牌比较的 `PEXPIRE`/`DEL` 脚本;令牌为 16 随机字节的
//! raw-base64url。重试为线性退避限次策略,由锁级 [`Options`]
//! 喂入。
//!
//! TTL 查询脚本、`Metadata`/`Token` 自定义选项、
//! `NoRetry`/`ExponentialBackoff` 等策略暂未提供。重试期限以
//! 锁 TTL 为界。请求路径依赖运行中的 Redis 实例,离线测试
//! 覆盖协议文本、令牌、选项与策略、续期线程的停止语义,以及
//! 无监听端点的错误透传。

use crate::distlock::{
    compose_lock_value, BackoffRunner, Lock, LockOption, Locker, OnRefreshError, StopHandle,
    ERR_NOT_OBTAINED,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_TTL: Duration = Duration::from_secs(30);
const DEFAULT_MAX_RETRIES: i64 = 10;
const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// 续期脚本。
const LUA_REFRESH: &str = "if redis.call(\"get\", KEYS[1]) == ARGV[1] then return redis.call(\"pexpire\", KEYS[1], ARGV[2]) else return 0 end";

/// 释放脚本。
const LUA_RELEASE: &str = "if redis.call(\"get\", KEYS[1]) == ARGV[1] then return redis.call(\"del\", KEYS[1]) else return 0 end";

/// 获取脚本(NX PX 的原子包裹,同令牌前缀下重入)。
const LUA_OBTAIN: &str = r#"
if redis.call("set", KEYS[1], ARGV[1], "NX", "PX", ARGV[3]) then return redis.status_reply("OK") end

local offset = tonumber(ARGV[2])
if redis.call("getrange", KEYS[1], 0, offset-1) == string.sub(ARGV[1], 1, offset) then return redis.call("set", KEYS[1], ARGV[1], "PX", ARGV[3]) end
"#;

/// 锁获取与续期行为配置(零值字段自动补全默认值)。
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// 锁的有效期;默认 30s。
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

/// 已获取的 Redis 锁(锁值 = 令牌 + 可选元数据)。
pub struct RedisLock {
    inner: Arc<LockInner>,
}

/// 锁的共享状态(供后台续期线程持有,以引用计数保持存活)。
struct LockInner {
    client: redis::Client,
    key: String,
    value: String,
    ttl: Duration,
    refresh_interval: Duration,
}

impl LockInner {
    /// 运行续期脚本(应答 1 → 成功,其余 →
    /// `redislock: not obtained`)。
    fn run_refresh_script(&self) -> Result<(), String> {
        let mut con = self.client.get_connection().map_err(|e| e.to_string())?;
        let status = redis::Script::new(LUA_REFRESH)
            .key(self.key.as_str())
            .arg(self.value.as_str())
            .arg(self.ttl.as_millis() as i64)
            .invoke::<i64>(&mut con)
            .map_err(|e| e.to_string())?;
        if status == 1 {
            return Ok(());
        }
        Err("redislock: not obtained".to_string())
    }

    /// 运行释放脚本(应答非 1 一律返回
    /// `redislock: lock not held`)。
    fn run_release_script(&self) -> Result<(), String> {
        let mut con = self.client.get_connection().map_err(|e| e.to_string())?;
        let status = redis::Script::new(LUA_RELEASE)
            .key(self.key.as_str())
            .arg(self.value.as_str())
            .invoke::<i64>(&mut con)
            .map_err(|e| e.to_string())?;
        if status == 1 {
            return Ok(());
        }
        Err("redislock: lock not held".to_string())
    }

    /// 查询剩余有效期(PTTL):毫秒数直取;-1 无过期(不应出现)、
    /// -2 键不存在,均按错误返回。
    fn run_ttl(&self) -> Result<Duration, String> {
        let mut con = self.client.get_connection().map_err(|e| e.to_string())?;
        let ms: i64 = redis::cmd("PTTL")
            .arg(self.key.as_str())
            .query(&mut con)
            .map_err(|e| e.to_string())?;
        match ms {
            m if m >= 0 => Ok(Duration::from_millis(m as u64)),
            -1 => Err("redislock: no expire".to_string()),
            _ => Err("redislock: not obtained".to_string()),
        }
    }
}

impl Lock for RedisLock {
    fn key(&self) -> String {
        // 返回锁键
        self.inner.key.clone()
    }

    fn release(&self) -> Result<(), String> {
        self.inner.run_release_script()
    }

    fn refresh(&self) -> Result<(), String> {
        self.inner.run_refresh_script()
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
                    if let Err(e) = inner.run_refresh_script() {
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

/// Redis 分布式锁后端。
pub struct RedisLocker {
    client: redis::Client,
    opts: Options,
}

impl RedisLocker {
    /// 创建(opts 补全默认值)。
    pub fn new(client: redis::Client, opts: Options) -> Self {
        Self {
            client,
            opts: opts.with_defaults(),
        }
    }

    /// 运行获取脚本(status 应答 → 拿到;nil 应答 → 未拿到
    /// 继续退避;其余为底层错误)。`token_len` 为重入前缀比对界
    /// (锁值 = 令牌 + 元数据,元数据不参与重入)。
    fn run_obtain_script(
        &self,
        key: &str,
        value: &str,
        token_len: usize,
        ttl_ms: i64,
    ) -> Result<bool, String> {
        let mut con = self.client.get_connection().map_err(|e| e.to_string())?;
        // Option<()>:脚本返回 nil 映射为 None(未拿到),
        // status 应答映射为 Some(())(拿到)
        let outcome = redis::Script::new(LUA_OBTAIN)
            .key(key)
            .arg(value)
            .arg(token_len)
            .arg(ttl_ms.to_string())
            .invoke::<Option<()>>(&mut con)
            .map_err(|e| e.to_string())?;
        Ok(outcome.is_some())
    }
}

impl Locker for RedisLocker {
    fn obtain(&self, key: &str, opts: &[LockOption]) -> Result<Box<dyn Lock>, String> {
        // 锁值 = 令牌(自定义或随机)+ 元数据;重试策略自 LockConfig
        // (Linear/Exponential/NoRetry),期限以锁 TTL 为界,
        // block_wait 模式以 max_wait_time 为界
        let mut cfg = crate::distlock::default_lock_config();
        for opt in opts {
            opt(&mut cfg);
        }
        let (value, token_len) = compose_lock_value(cfg.token.as_deref(), cfg.metadata.as_deref());
        let retry_delay = if cfg.retry_delay > Duration::ZERO {
            cfg.retry_delay
        } else {
            self.opts.retry_delay
        };
        let wait = if cfg.block_wait && cfg.max_wait_time > Duration::ZERO {
            cfg.max_wait_time
        } else {
            self.opts.ttl
        };
        let ttl_ms = self.opts.ttl.as_millis() as i64;
        let deadline = Instant::now().checked_add(wait);
        let mut backoff = BackoffRunner::new(
            cfg.backoff,
            retry_delay,
            self.opts.ttl,
            self.opts.max_retries,
        );
        loop {
            if self.run_obtain_script(key, &value, token_len, ttl_ms)? {
                return Ok(Box::new(RedisLock {
                    inner: Arc::new(LockInner {
                        client: self.client.clone(),
                        key: key.to_string(),
                        value,
                        ttl: self.opts.ttl,
                        refresh_interval: self.opts.refresh_interval,
                    }),
                }));
            }
            // 重试预算耗尽 → 未获取哨兵;期限已到 → ctx 到期
            // 错误文案
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
        // 无待关闭资源,Close 为空操作
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
    fn redis_options_defaults() {
        // 零值补默认(30s/10/100ms/refresh=TTL/3)
        let o = Options::default().with_defaults();
        assert_eq!(o.ttl, Duration::from_secs(30));
        assert_eq!(o.max_retries, 10);
        assert_eq!(o.retry_delay, Duration::from_millis(100));
        assert_eq!(o.refresh_interval, Duration::from_secs(10));
        // 非零字段保留;refresh 默认随 TTL 变化
        let o = Options {
            ttl: Duration::from_secs(90),
            ..Default::default()
        }
        .with_defaults();
        assert_eq!(o.ttl, Duration::from_secs(90));
        assert_eq!(o.max_retries, 10);
        assert_eq!(o.refresh_interval, Duration::from_secs(30));
        let o = Options {
            max_retries: 5,
            retry_delay: Duration::from_millis(250),
            ..Default::default()
        }
        .with_defaults();
        assert_eq!(o.max_retries, 5);
        assert_eq!(o.retry_delay, Duration::from_millis(250));
        assert_eq!(o.refresh_interval, Duration::from_secs(10));
    }

    #[test]
    fn redis_locker_applies_defaults() {
        // 构造时补全默认值
        let client = redis::Client::open("redis://127.0.0.1:1/").unwrap();
        let locker = RedisLocker::new(client, Options::default());
        assert_eq!(locker.opts.ttl, Duration::from_secs(30));
        assert_eq!(locker.opts.max_retries, 10);
        assert_eq!(locker.opts.refresh_interval, Duration::from_secs(10));
    }

    #[test]
    fn redis_dead_endpoint_errors() {
        // 无监听端点:连接错误即时透传,非未获取哨兵
        let client = redis::Client::open("redis://127.0.0.1:1/").unwrap();
        let locker = RedisLocker::new(
            client,
            Options {
                ttl: Duration::from_secs(1),
                max_retries: 1,
                retry_delay: Duration::from_millis(1),
                refresh_interval: Duration::from_millis(1),
            },
        );
        let err = locker.obtain("k", &[]).err().unwrap();
        assert_ne!(err, ERR_NOT_OBTAINED);
        assert!(!err.is_empty());
        let err = locker.is_locked("k").err().unwrap();
        assert_ne!(err, ERR_NOT_OBTAINED);
    }

    #[test]
    fn redis_scripts_verbatim() {
        // 锁定协议文本(兼容 bsm/redislock v0.9.4,逐字)
        assert_eq!(
            LUA_REFRESH,
            "if redis.call(\"get\", KEYS[1]) == ARGV[1] then return redis.call(\"pexpire\", KEYS[1], ARGV[2]) else return 0 end"
        );
        assert_eq!(
            LUA_RELEASE,
            "if redis.call(\"get\", KEYS[1]) == ARGV[1] then return redis.call(\"del\", KEYS[1]) else return 0 end"
        );
        assert_eq!(
            LUA_OBTAIN,
            "
if redis.call(\"set\", KEYS[1], ARGV[1], \"NX\", \"PX\", ARGV[3]) then return redis.status_reply(\"OK\") end

local offset = tonumber(ARGV[2])
if redis.call(\"getrange\", KEYS[1], 0, offset-1) == string.sub(ARGV[1], 1, offset) then return redis.call(\"set\", KEYS[1], ARGV[1], \"PX\", ARGV[3]) end
"
        );
    }

    #[test]
    fn redis_token_rawurl() {
        // raw-base64url 编码向量已收敛到 distlock 共用层(见其单测);
        // 此处钉死锁值合成与令牌长度约定
        let (value, token_len) = compose_lock_value(None, None);
        assert_eq!(value.len(), 22);
        assert_eq!(token_len, 22);
        let (value, token_len) = compose_lock_value(Some("tok"), Some("|meta"));
        assert_eq!(value, "tok|meta");
        assert_eq!(token_len, 3);
    }

    #[test]
    fn redis_obtain_script_uses_token_prefix_len() {
        // 获取脚本的重入分支参数是令牌长度(锁值 = 令牌 + 元数据)
        // —— 通过死端点验证调用透传,协议文本另测
        let client = redis::Client::open("redis://127.0.0.1:1/").unwrap();
        let locker = RedisLocker::new(client, Options::default());
        let err = locker
            .run_obtain_script("k", "tok|meta", 3, 1_000)
            .err()
            .unwrap();
        assert!(!err.is_empty());
        assert_ne!(err, ERR_NOT_OBTAINED);
    }

    fn dead_lock(interval: Duration) -> RedisLock {
        RedisLock {
            inner: Arc::new(LockInner {
                client: redis::Client::open("redis://127.0.0.1:1/").unwrap(),
                key: "k".to_string(),
                value: "t".to_string(),
                ttl: Duration::from_secs(30),
                refresh_interval: interval,
            }),
        }
    }

    #[test]
    fn redis_stop_handle_stops_promptly() {
        // 停止句柄:信号即时取消(10s 间隔下亚秒返回),且幂等
        let lock = dead_lock(Duration::from_secs(10));
        let mut handle = lock.start_refresh(None);
        let t0 = Instant::now();
        handle.stop();
        handle.stop();
        assert!(t0.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn redis_refresh_thread_exits_on_error() {
        // 续期失败即回调并退出(死端点 → 连接错误)
        let lock = dead_lock(Duration::from_millis(20));
        let hit = Arc::new(AtomicBool::new(false));
        let hit2 = Arc::clone(&hit);
        let mut handle = lock.start_refresh(Some(Box::new(move |_e| {
            hit2.store(true, Ordering::SeqCst);
        })));
        for _ in 0..100 {
            if hit.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        handle.stop();
        assert!(hit.load(Ordering::SeqCst));
    }
}
