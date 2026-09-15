//! 分布式锁(接口与获取选项为 feature `distlock`,Redis 后端为
//! feature `distlock-redis`)。
//!
//! 实现要点:
//!
//! - 当前提供 Redis 落地;暂未提供 etcd 后端。轮询等待选项
//!   (blockWait/maxWaitTime/retryDelay)保留在接口签名的
//!   [`LockOption`] 中,Redis 后端忽略它们;
//! - 错误以字符串返回;未获取到锁时返回哨兵常量
//!   [`ERR_NOT_OBTAINED`],按字符串相等判断;
//! - Redis 后端兼容 bsm/redislock v0.9.4 线上协议(Lua 脚本与
//!   token 格式);TTL 查询、`Metadata`/`Token` 自定义选项、
//!   `NoRetry`/`ExponentialBackoff` 等策略暂未提供;
//! - `obtain` 以锁 TTL 为等待期限;
//! - [`Lock::start_refresh`] 返回停止句柄 [`StopHandle`];句柄
//!   被丢弃即视作停止(信道断开,线程退出)。

use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::Duration;

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
///
/// 这些选项暂无后端消费:当前仅提供 Redis 后端,后者忽略
/// 它们(见模块文档)。
pub type LockOption = Box<dyn Fn(&mut LockConfig)>;

/// 锁获取行为的配置(选项闭包的修改目标)。
pub struct LockConfig {
    /// 是否阻塞等待。
    pub block_wait: bool,
    /// 最大等待时间,0 表示无限等待。
    pub max_wait_time: Duration,
    /// 重试基础间隔。
    pub retry_delay: Duration,
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

/// 默认配置。
pub fn default_lock_config() -> LockConfig {
    LockConfig {
        block_wait: false,
        max_wait_time: Duration::ZERO,
        retry_delay: Duration::from_millis(100),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_config_defaults_and_options() {
        // 默认配置值
        let cfg = default_lock_config();
        assert!(!cfg.block_wait);
        assert_eq!(cfg.max_wait_time, Duration::ZERO);
        assert_eq!(cfg.retry_delay, Duration::from_millis(100));
        // 阻塞等待与重试间隔选项的应用
        let mut cfg = default_lock_config();
        (with_block_wait(Duration::from_secs(5)))(&mut cfg);
        assert!(cfg.block_wait);
        assert_eq!(cfg.max_wait_time, Duration::from_secs(5));
        assert_eq!(cfg.retry_delay, Duration::from_millis(100));
        let mut cfg = default_lock_config();
        (with_retry_delay(Duration::from_millis(250)))(&mut cfg);
        assert!(!cfg.block_wait);
        assert_eq!(cfg.retry_delay, Duration::from_millis(250));
    }
}
