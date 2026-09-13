//! 分布式锁(对应 Go 版 `distlock` 包;接口与获取选项为 feature
//! `distlock`,Redis 后端为 feature `distlock-redis`,对应上游
//! 的 `redis_locker.go`)。
//!
//! 与上游的差异:
//!
//! - etcd locker 未移植(jetcd 的 concurrency 包——session/mutex
//!   ——在 Rust 生态无对应,`etcd-client` 不提供锁抽象,不为此
//!   引入重依赖);上游 etcd 路径消费的 [`LockOption`](
//!   blockWait/maxWaitTime/retryDelay 的轮询等待)随之无宿主,
//!   选项类型保留在接口签名中,Redis 后端与上游一样忽略它们;
//! - 错误以字符串返回;上游的 `ErrNotObtained` 哨兵为
//!   [`ERR_NOT_OBTAINED`],按字符串相等判断(上游用
//!   `errors.Is`);
//! - Redis 后端的线上协议按 bsm/redislock v0.9.4 逐式复刻,其
//!   未被上游包装层使用的部分(TTL 查询、`Metadata`/`Token`
//!   自定义选项、`NoRetry`/`ExponentialBackoff` 策略)未移植;
//! - 上游 `Obtain` 以调用方 ctx 的 deadline 兜底重试循环,此处
//!   固定以锁 TTL 为期限;
//! - 上游 `StartRefresh` 返回的 stop 未被调用时,续期协程在
//!   无失败的情况下永不退出;Rust 版 [`StopHandle`] 被丢弃即
//!   视作停止(信道断开,线程退出)。

use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::Duration;

#[cfg(feature = "distlock-redis")]
pub mod redis_locker;

/// 上游 `distlock.ErrNotObtained`(锁已被其他节点持有)。
pub const ERR_NOT_OBTAINED: &str = "distlock: lock not obtained";

/// 后台续期失败回调(上游 `onError func(error)`;上游为捕获闭包,
/// 此处以 `Box<dyn Fn>` 承载,错误字符串化)。
pub type OnRefreshError = Box<dyn Fn(&str) + Send>;

/// 已持有的锁(上游 `distlock.Lock`)。
pub trait Lock {
    /// 锁的键名(上游 `Key`)。
    fn key(&self) -> String;

    /// 立即释放锁;若锁已过期或已被释放,返回底层错误(上游
    /// `Release`)。
    fn release(&self) -> Result<(), String>;

    /// 以锁构造时的 TTL 续期一次(上游 `Refresh`)。
    fn refresh(&self) -> Result<(), String>;

    /// 启动后台续期线程,按锁的续期间隔定期调用
    /// [`refresh`](Lock::refresh);续期失败时调用 `on_error` 后
    /// 线程自行退出。返回停止句柄(上游 `StartRefresh`)。
    fn start_refresh(&self, on_error: Option<OnRefreshError>) -> StopHandle;
}

/// 锁后端抽象(上游 `distlock.Locker`)。
pub trait Locker {
    /// 尝试获取 key 对应的锁(上游 `Obtain`;锁已被持有时返回
    /// [`ERR_NOT_OBTAINED`],其他错误为底层错误)。
    fn obtain(&self, key: &str, opts: &[LockOption]) -> Result<Box<dyn Lock>, String>;

    /// 关闭后端资源(上游 `Close`;Redis 后端为空操作)。
    fn close(&self) -> Result<(), String>;

    /// 检查 key 是否已被锁定(上游 `IsLocked`:以获取探测,仅供
    /// 监控/调试,不能替代 Obtain 的原子性保证)。
    fn is_locked(&self, key: &str) -> Result<bool, String>;
}

/// 后台续期线程的停止句柄(上游 `StartRefresh` 返回的 stop 函数:
/// 取消并阻塞等待线程退出,幂等)。句柄被丢弃时同样视作停止
/// (见模块文档对上游差异的说明)。
pub struct StopHandle {
    sender: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl StopHandle {
    /// 取消续期线程并阻塞等待其退出(上游 `sync.Once` 的幂等语义)。
    pub fn stop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// 锁获取行为的函数选项(上游 `LockOption`;上游为捕获参数的
/// 闭包,此处以 `Box<dyn Fn>` 承载)。
///
/// 仅上游 etcd 后端的阻塞等待路径消费这些选项;该后端未移植,
/// Redis 后端与上游一样忽略它们(见模块文档)。
pub type LockOption = Box<dyn Fn(&mut LockConfig)>;

/// 上游 `lockConfig`。
pub struct LockConfig {
    /// 是否阻塞等待(上游 `blockWait`)。
    pub block_wait: bool,
    /// 最大等待时间,0 表示无限等待(上游 `maxWaitTime`)。
    pub max_wait_time: Duration,
    /// 重试基础间隔(上游 `retryDelay`)。
    pub retry_delay: Duration,
}

/// 启用阻塞等待模式(上游 `WithBlockWait`)。
pub fn with_block_wait(max_wait: Duration) -> LockOption {
    Box::new(move |cfg| {
        cfg.block_wait = true;
        cfg.max_wait_time = max_wait;
    })
}

/// 设置重试退避间隔(上游 `WithRetryDelay`)。
pub fn with_retry_delay(delay: Duration) -> LockOption {
    Box::new(move |cfg| {
        cfg.retry_delay = delay;
    })
}

/// 默认配置(上游 `defaultLockConfig`)。
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
        // 上游 defaultLockConfig 的默认值
        let cfg = default_lock_config();
        assert!(!cfg.block_wait);
        assert_eq!(cfg.max_wait_time, Duration::ZERO);
        assert_eq!(cfg.retry_delay, Duration::from_millis(100));
        // 上游 WithBlockWait/WithRetryDelay 的选项应用
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
