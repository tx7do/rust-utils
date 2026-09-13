//! Redis 分布式锁后端(对应 Go 版 `distlock/redis_locker.go`,
//! feature `distlock-redis`)。
//!
//! 线上协议为上游依赖 bsm/redislock v0.9.4 的逐式复刻:获取经
//! Lua 脚本(`SET NX PX` 的原子包裹,附带同令牌前缀下的重入
//! 分支),续期/释放为令牌比较的 `PEXPIRE`/`DEL` 脚本;令牌为
//! 16 随机字节的 raw-base64url(上游 `randomToken`)。重试为
//! 线性退避限次策略(上游 `LinearBackoff` + `LimitRetry`,由
//! 锁级 [`Options`] 喂入)。
//!
//! 未移植(均未被上游包装层使用):TTL 查询脚本、`Metadata`/
//! `Token` 自定义选项、`NoRetry`/`ExponentialBackoff` 策略。
//! 重试期限以锁 TTL 为界(上游以调用方 ctx 的 deadline 兜底)。
//! 请求路径依赖运行中的 Redis 实例,离线测试覆盖协议文本、
//! 令牌、选项与策略、续期线程的停止语义,以及无监听端点的
//! 错误透传。

use crate::distlock::{Lock, LockOption, Locker, OnRefreshError, StopHandle, ERR_NOT_OBTAINED};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_TTL: Duration = Duration::from_secs(30);
const DEFAULT_MAX_RETRIES: i64 = 10;
const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// 续期脚本(上游 redislock `luaRefresh`)。
const LUA_REFRESH: &str = "if redis.call(\"get\", KEYS[1]) == ARGV[1] then return redis.call(\"pexpire\", KEYS[1], ARGV[2]) else return 0 end";

/// 释放脚本(上游 redislock `luaRelease`)。
const LUA_RELEASE: &str = "if redis.call(\"get\", KEYS[1]) == ARGV[1] then return redis.call(\"del\", KEYS[1]) else return 0 end";

/// 获取脚本(上游 redislock `luaObtain`:NX PX 的原子包裹,
/// 同令牌前缀下重入)。
const LUA_OBTAIN: &str = r#"
if redis.call("set", KEYS[1], ARGV[1], "NX", "PX", ARGV[3]) then return redis.status_reply("OK") end

local offset = tonumber(ARGV[2])
if redis.call("getrange", KEYS[1], 0, offset-1) == string.sub(ARGV[1], 1, offset) then return redis.call("set", KEYS[1], ARGV[1], "PX", ARGV[3]) end
"#;

/// 锁获取与续期行为配置(上游 `distlock.Options`;零值字段自动
/// 补全默认值)。
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
    /// 补全默认值(上游 `withDefaults`)。
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

/// 线性退避(上游 redislock `LinearBackoff`:恒定间隔)。
struct LinearBackoff(Duration);

impl LinearBackoff {
    fn next_backoff(&self) -> Duration {
        self.0
    }
}

/// 限次重试(上游 redislock `LimitRetry`:计数达到上限后归零)。
struct LimitedRetry {
    inner: LinearBackoff,
    cnt: AtomicI64,
    max: i64,
}

impl LimitedRetry {
    fn next_backoff(&self) -> Duration {
        if self.cnt.load(Ordering::Relaxed) >= self.max {
            return Duration::ZERO;
        }
        self.cnt.fetch_add(1, Ordering::Relaxed);
        self.inner.next_backoff()
    }
}

/// 随机令牌(上游 redislock `randomToken`:16 随机字节 →
/// raw-base64url)。
fn random_token() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("getrandom");
    base64_rawurl_encode(&buf)
}

/// raw-base64url 编码(上游 `base64.RawURLEncoding`:URL 安全
/// 字母表、无填充)。
fn base64_rawurl_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6 & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

/// 已获取的 Redis 锁(上游 `redisLock` 与 redislock.Lock 的合并:
/// 上游包装层不设元数据,锁值即令牌)。
pub struct RedisLock {
    inner: Arc<LockInner>,
}

/// 锁的共享状态(供后台续期线程持有;上游 Go 协程按 GC 存活
/// 持有锁对象,此处以引用计数等价)。
struct LockInner {
    client: redis::Client,
    key: String,
    value: String,
    ttl: Duration,
    refresh_interval: Duration,
}

impl LockInner {
    /// 运行续期脚本(上游 redislock `Refresh`:应答 1 → 成功,
    /// 其余 → 上游 `redislock: not obtained`)。
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

    /// 运行释放脚本(上游 redislock `Release`:应答非 1 一律
    /// 上游 `redislock: lock not held`)。
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
}

impl Lock for RedisLock {
    fn key(&self) -> String {
        // 上游 Key():redislock 返回其锁键
        self.inner.key.clone()
    }

    fn release(&self) -> Result<(), String> {
        self.inner.run_release_script()
    }

    fn refresh(&self) -> Result<(), String> {
        self.inner.run_refresh_script()
    }

    fn start_refresh(&self, on_error: Option<OnRefreshError>) -> StopHandle {
        // 上游:固定间隔的 ticker,ctx 取消即时生效;续期失败
        // 即回调并退出。停止信道被丢弃时同样退出(见包级文档)。
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

/// Redis 分布式锁后端(上游 `RedisLocker`)。
pub struct RedisLocker {
    client: redis::Client,
    opts: Options,
}

impl RedisLocker {
    /// 创建(上游 `NewRedisLocker`;opts 补全默认值)。
    pub fn new(client: redis::Client, opts: Options) -> Self {
        Self {
            client,
            opts: opts.with_defaults(),
        }
    }

    /// 运行获取脚本(上游 redislock `obtain`:status 应答 →
    /// 拿到;nil 应答 → 未拿到继续退避;其余为底层错误)。
    fn run_obtain_script(&self, key: &str, value: &str, ttl_ms: i64) -> Result<bool, String> {
        let mut con = self.client.get_connection().map_err(|e| e.to_string())?;
        // Option<()>:脚本返回 nil 映射为 None(上游 redis.Nil
        // → 未拿到),status 应答映射为 Some(())(上游 → 拿到)
        let outcome = redis::Script::new(LUA_OBTAIN)
            .key(key)
            .arg(value)
            .arg(value.len())
            .arg(ttl_ms.to_string())
            .invoke::<Option<()>>(&mut con)
            .map_err(|e| e.to_string())?;
        Ok(outcome.is_some())
    }
}

impl Locker for RedisLocker {
    fn obtain(&self, key: &str, _opts: &[LockOption]) -> Result<Box<dyn Lock>, String> {
        // 上游:每次尝试的锁值为随机令牌(无元数据),TTL 以
        // 毫秒串传入脚本;重试为线性退避限次,期限以 TTL 为界
        let value = random_token();
        let ttl_ms = self.opts.ttl.as_millis() as i64;
        let deadline = Instant::now().checked_add(self.opts.ttl);
        let retry = LimitedRetry {
            inner: LinearBackoff(self.opts.retry_delay),
            cnt: AtomicI64::new(0),
            max: self.opts.max_retries,
        };
        loop {
            if self.run_obtain_script(key, &value, ttl_ms)? {
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
            // 上游:重试预算耗尽 → 未获取哨兵;期限已到 → 上游
            // ctx 到期错误文案
            let backoff = retry.next_backoff();
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
        // 上游:redislock 无待关闭资源,Close 为 no-op
        Ok(())
    }

    fn is_locked(&self, key: &str) -> Result<bool, String> {
        // 上游:以获取探测;未拿到 → 已加锁;其它错误透传;
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
    use std::sync::atomic::AtomicBool;

    #[test]
    fn redis_options_defaults() {
        // 上游 withDefaults:零值补默认(30s/10/100ms/refresh=TTL/3)
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
        // 上游 NewRedisLocker:构造时补全默认值
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
        // 锁定协议文本(上游 redislock v0.9.4 逐字)
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
        // 独立预计算的 raw-base64url 向量(上游 RawURLEncoding)
        assert_eq!(base64_rawurl_encode(&[0u8; 16]), "AAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(
            base64_rawurl_encode(&(0u8..16).collect::<Vec<u8>>()),
            "AAECAwQFBgcICQoLDA0ODw"
        );
        // 令牌:22 字符且两次采样不同
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), 22);
        assert_eq!(b.len(), 22);
        assert_ne!(a, b);
    }

    #[test]
    fn redis_retry_strategies() {
        // 线性退避恒定
        let linear = LinearBackoff(Duration::from_millis(5));
        assert_eq!(linear.next_backoff(), Duration::from_millis(5));
        assert_eq!(linear.next_backoff(), Duration::from_millis(5));
        // 限次策略:预算内取内层间隔,耗尽后归零
        let limited = LimitedRetry {
            inner: LinearBackoff(Duration::from_millis(5)),
            cnt: AtomicI64::new(0),
            max: 2,
        };
        assert_eq!(limited.next_backoff(), Duration::from_millis(5));
        assert_eq!(limited.next_backoff(), Duration::from_millis(5));
        assert_eq!(limited.next_backoff(), Duration::ZERO);
        assert_eq!(limited.next_backoff(), Duration::ZERO);
        // 零预算:立即归零
        let exhausted = LimitedRetry {
            inner: LinearBackoff(Duration::from_millis(5)),
            cnt: AtomicI64::new(0),
            max: 0,
        };
        assert_eq!(exhausted.next_backoff(), Duration::ZERO);
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
