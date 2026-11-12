//! 分布式锁(接口与获取选项为 feature `distlock`;Redis 后端为
//! feature `distlock-redis`,etcd 后端为 feature `distlock-etcd`)。
//!
//! 实现要点:
//!
//! - 提供 Redis 落地(兼容 bsm/redislock v0.9.4 线上协议)与 etcd 落地
//!   (lease+txn 抢锁,keep-alive 续期,令牌比对释放);轮询等待选项
//!   (blockWait/maxWaitTime/retryDelay)与自定义令牌、锁值元数据、
//!   退避策略(Linear/Exponential/NoRetry)由 [`LockOption`] 承载,
//!   etcd 后端消费 `block_wait`/`max_wait_time`,其余选项两后端通用;
//! - 错误以字符串返回;未获取到锁时返回哨兵常量
//!   [`ERR_NOT_OBTAINED`],按字符串相等判断;
//! - `obtain` 以锁 TTL 为等待期限(后端在 `block_wait` 模式下
//!   以 `max_wait_time` 为期限);
//! - [`Lock::start_refresh`] 返回停止句柄 [`StopHandle`];句柄
//!   被丢弃即视作停止(信道断开,线程退出)。

use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::Duration;

#[cfg(feature = "distlock-etcd")]
pub mod etcd_locker;
#[cfg(feature = "distlock-redis")]
pub mod redis_locker;

/// 未获取到锁时返回的哨兵错误串(锁已被其他节点持有)。
pub const ERR_NOT_OBTAINED: &str = "distlock: lock not obtained";

/// 后台续期失败回调(以 `Box<dyn Fn>` 承载,错误字符串化)。
pub type OnRefreshError = Box<dyn Fn(&str) + Send>;

/// 已持有的锁。
pub trait Lock {
    /// 锁的键名。
    fn key(&self) -> String;

    /// 立即释放锁;若锁已过期或已被释放,返回底层错误。
    fn release(&self) -> Result<(), String>;

    /// 以锁构造时的 TTL 续期一次。
    fn refresh(&self) -> Result<(), String>;

    /// 剩余有效期(键已不存在/租约已失效时报错)。
    fn ttl(&self) -> Result<Duration, String>;

    /// 启动后台续期线程,按锁的续期间隔定期调用
    /// [`refresh`](Lock::refresh);续期失败时调用 `on_error` 后
    /// 线程自行退出。返回停止句柄。
    fn start_refresh(&self, on_error: Option<OnRefreshError>) -> StopHandle;
}

/// 锁后端抽象。
pub trait Locker {
    /// 尝试获取 key 对应的锁(锁已被持有时返回
    /// [`ERR_NOT_OBTAINED`],其他错误为底层错误)。
    fn obtain(&self, key: &str, opts: &[LockOption]) -> Result<Box<dyn Lock>, String>;

    /// 关闭后端资源(Redis 后端为空操作)。
    fn close(&self) -> Result<(), String>;

    /// 检查 key 是否已被锁定(以获取探测,仅供监控/调试,不能
    /// 替代 `obtain` 的原子性保证)。
    fn is_locked(&self, key: &str) -> Result<bool, String>;
}

/// 后台续期线程的停止句柄([`Lock::start_refresh`] 返回;取消
/// 并阻塞等待线程退出,幂等)。句柄被丢弃时同样视作停止
/// (见模块文档)。
pub struct StopHandle {
    sender: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl StopHandle {
    /// 取消续期线程并阻塞等待其退出(幂等)。
    pub fn stop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// 锁获取行为的函数选项(以 `Box<dyn Fn>` 承载)。
pub type LockOption = Box<dyn Fn(&mut LockConfig)>;

/// 重试退避策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backoff {
    /// 线性退避:恒定 `retry_delay`(默认,对齐上游线性重试)。
    #[default]
    Linear,
    /// 指数退避:自 `retry_delay` 起步逐次翻倍,上限为锁 TTL。
    Exponential,
    /// 不重试:首次争抢失败即返回
    /// [`ERR_NOT_OBTAINED`](上游 `NoRetry`)。
    NoRetry,
}

/// 锁获取行为的配置(选项闭包的修改目标)。
pub struct LockConfig {
    /// 是否阻塞等待。
    pub block_wait: bool,
    /// 最大等待时间,0 表示无限等待。
    pub max_wait_time: Duration,
    /// 重试基础间隔(`ZERO` 表示未指定,回落到后端 `Options` 的值)。
    pub retry_delay: Duration,
    /// 重试退避策略(默认线性)。
    pub backoff: Backoff,
    /// 自定义锁值令牌(缺省为 16 随机字节 raw-base64url)。
    pub token: Option<String>,
    /// 追加到锁值尾部的元数据(Redis 后端的同令牌前缀重入分支
    /// 以令牌长度为界,元数据不参与重入判定)。
    pub metadata: Option<String>,
}

/// 启用阻塞等待模式,并设置最大等待时间。
pub fn with_block_wait(max_wait: Duration) -> LockOption {
    Box::new(move |cfg| {
        cfg.block_wait = true;
        cfg.max_wait_time = max_wait;
    })
}

/// 设置重试退避间隔。
pub fn with_retry_delay(delay: Duration) -> LockOption {
    Box::new(move |cfg| {
        cfg.retry_delay = delay;
    })
}

/// 设置重试退避策略。
pub fn with_backoff(backoff: Backoff) -> LockOption {
    Box::new(move |cfg| {
        cfg.backoff = backoff;
    })
}

/// 自定义锁值令牌(锁值 = 令牌 + 元数据;重入判定只看令牌)。
pub fn with_token(token: impl Into<String>) -> LockOption {
    let token = token.into();
    Box::new(move |cfg| {
        cfg.token = Some(token.clone());
    })
}

/// 追加锁值元数据(如持有方标识/租约上下文)。
pub fn with_metadata(metadata: impl Into<String>) -> LockOption {
    let metadata = metadata.into();
    Box::new(move |cfg| {
        cfg.metadata = Some(metadata.clone());
    })
}

/// 默认配置。
pub fn default_lock_config() -> LockConfig {
    LockConfig {
        block_wait: false,
        max_wait_time: Duration::ZERO,
        retry_delay: Duration::ZERO, // ZERO = 未指定,回落到后端 Options
        backoff: Backoff::default(),
        token: None,
        metadata: None,
    }
}

/// 锁值合成:令牌(缺省随机)+ 元数据。返回 (锁值, 令牌长度) ——
/// Redis 获取脚本的重入分支以令牌长度为前缀比对界。
pub(crate) fn compose_lock_value(
    custom_token: Option<&str>,
    metadata: Option<&str>,
) -> (String, usize) {
    let token = match custom_token {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => {
            let mut buf = [0u8; 16];
            getrandom::fill(&mut buf).expect("getrandom");
            base64_rawurl_encode(&buf)
        }
    };
    let token_len = token.len();
    let mut value = token;
    if let Some(md) = metadata {
        value.push_str(md);
    }
    (value, token_len)
}

/// raw-base64url 编码(URL 安全字母表、无填充;两后端共用)。
pub(crate) fn base64_rawurl_encode(data: &[u8]) -> String {
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

/// 退避序列(消费端按次取值;返回 `ZERO` 即停止重试)。
/// 限次逻辑内建:`max`(后端 `Options.max_retries`)耗尽即归零。
pub(crate) enum BackoffRunner {
    Linear {
        delay: Duration,
        cnt: i64,
        max: i64,
    },
    Exponential {
        cur: Duration,
        cap: Duration,
        cnt: i64,
        max: i64,
    },
    NoRetry,
}

impl BackoffRunner {
    /// 按配置构建;指数退避以 `retry_delay` 起步、以 `cap`(一般取
    /// 锁 TTL)封顶;`max` 为后端 Options 的最大重试次数。
    pub(crate) fn new(
        kind: Backoff,
        retry_delay: Duration,
        cap: Duration,
        max_retries: i64,
    ) -> Self {
        match kind {
            Backoff::Linear => BackoffRunner::Linear {
                delay: retry_delay,
                cnt: 0,
                max: max_retries,
            },
            Backoff::Exponential => BackoffRunner::Exponential {
                cur: retry_delay,
                cap,
                cnt: 0,
                max: max_retries,
            },
            Backoff::NoRetry => BackoffRunner::NoRetry,
        }
    }

    /// 取下一次退避间隔。
    pub(crate) fn next(&mut self) -> Duration {
        match self {
            BackoffRunner::Linear { delay, cnt, max } => {
                if *cnt >= *max {
                    return Duration::ZERO;
                }
                *cnt += 1;
                *delay
            }
            BackoffRunner::Exponential { cur, cap, cnt, max } => {
                if *cnt >= *max {
                    return Duration::ZERO;
                }
                *cnt += 1;
                let out = *cur;
                *cur = cur.saturating_mul(2).min(*cap);
                out
            }
            BackoffRunner::NoRetry => Duration::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_config_defaults_and_options() {
        // 默认配置值(retry_delay ZERO = 未指定,回落后端 Options)
        let cfg = default_lock_config();
        assert!(!cfg.block_wait);
        assert_eq!(cfg.max_wait_time, Duration::ZERO);
        assert_eq!(cfg.retry_delay, Duration::ZERO);
        assert_eq!(cfg.backoff, Backoff::Linear);
        assert!(cfg.token.is_none());
        assert!(cfg.metadata.is_none());
        // 选项的应用
        let mut cfg = default_lock_config();
        (with_block_wait(Duration::from_secs(5)))(&mut cfg);
        (with_retry_delay(Duration::from_millis(250)))(&mut cfg);
        (with_backoff(Backoff::Exponential))(&mut cfg);
        (with_token("my-token"))(&mut cfg);
        (with_metadata("|meta"))(&mut cfg);
        assert!(cfg.block_wait);
        assert_eq!(cfg.max_wait_time, Duration::from_secs(5));
        assert_eq!(cfg.retry_delay, Duration::from_millis(250));
        assert_eq!(cfg.backoff, Backoff::Exponential);
        assert_eq!(cfg.token.as_deref(), Some("my-token"));
        assert_eq!(cfg.metadata.as_deref(), Some("|meta"));
    }

    #[test]
    fn compose_lock_value_token_and_metadata() {
        // 自定义令牌 + 元数据:锁值拼接,重入界为令牌长度
        let (value, token_len) = compose_lock_value(Some("tok"), Some("|meta"));
        assert_eq!(value, "tok|meta");
        assert_eq!(token_len, 3);
        // 仅元数据:令牌随机生成
        let (value, token_len) = compose_lock_value(None, Some("|m"));
        assert!(value.ends_with("|m"));
        assert_eq!(value.len(), token_len + 2);
        assert_eq!(token_len, 22); // 16 字节 raw-base64url
                                   // 空令牌视作未指定;无元数据则锁值即令牌
        let (value, token_len) = compose_lock_value(Some(""), None);
        assert_eq!(value.len(), 22);
        assert_eq!(token_len, value.len());
    }

    #[test]
    fn base64_rawurl_vectors() {
        assert_eq!(base64_rawurl_encode(&[0u8; 16]), "AAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(
            base64_rawurl_encode(&(0u8..16).collect::<Vec<u8>>()),
            "AAECAwQFBgcICQoLDA0ODw"
        );
    }

    #[test]
    fn backoff_runner_strategies() {
        // 线性:恒定;限次耗尽归零
        let mut b = BackoffRunner::new(
            Backoff::Linear,
            Duration::from_millis(100),
            Duration::from_secs(1),
            2,
        );
        assert_eq!(b.next(), Duration::from_millis(100));
        assert_eq!(b.next(), Duration::from_millis(100));
        assert_eq!(b.next(), Duration::ZERO);
        // 指数:翻倍且封顶;限次耗尽归零
        let mut b = BackoffRunner::new(
            Backoff::Exponential,
            Duration::from_millis(100),
            Duration::from_millis(500),
            4,
        );
        assert_eq!(b.next(), Duration::from_millis(100));
        assert_eq!(b.next(), Duration::from_millis(200));
        assert_eq!(b.next(), Duration::from_millis(400));
        assert_eq!(b.next(), Duration::from_millis(500));
        assert_eq!(b.next(), Duration::ZERO);
        // 不重试:首次即停
        let mut b = BackoffRunner::new(
            Backoff::NoRetry,
            Duration::from_millis(100),
            Duration::from_secs(1),
            10,
        );
        assert_eq!(b.next(), Duration::ZERO);
    }

    #[test]
    fn stop_handle_stops_thread_and_is_idempotent() {
        // 直接构造句柄:线程等到停止信号后退出
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let mut handle = StopHandle {
            sender: Some(tx),
            thread: Some(thread),
        };
        // 重复 stop 幂等:第一次等待线程退出,第二次直接返回
        handle.stop();
        handle.stop();
        assert!(handle.sender.is_none());
        assert!(handle.thread.is_none());
    }

    #[test]
    fn stop_handle_with_finished_thread() {
        // 线程自行结束、发送端已失效时 stop 仍安全
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        drop(rx);
        let thread = std::thread::spawn(|| {});
        let mut handle = StopHandle {
            sender: Some(tx),
            thread: Some(thread),
        };
        handle.stop();
    }
}
