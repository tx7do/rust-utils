//! 单线程优先级事件循环,支持"帧驱动"模式(游戏服务器风格),
//! 移植自 go-utils/eventloop。
//!
//! 三个有界优先级队列(高/中/低),事件循环线程严格按优先级处理:
//! 每次取事件前都重新检查高/中优先级,低优先级事件始终让位。
//! 帧驱动模式下以固定帧率(默认 50ms/帧)唤醒,并遵守每帧时间预算。
//!
//! 与 Go 版的差异:
//! - 事件载荷是泛型 `T`(Go 里是 `any`),回调通道为
//!   [`std::sync::mpsc::SyncSender`];
//! - 没有 per-event context,`SubmitBlocking` 用超时代替取消;
//! - 日志接口未移植(丢弃回调时静默),统计接口([`Metrics`])保留。
//!
//! ```
//! use rust_utils::eventloop::{new_request_event, Event, EventLoop, EventProcessor, EventResult};
//! use std::sync::{Arc, Mutex};
//! use std::time::Duration;
//!
//! struct Collector(Arc<Mutex<Vec<String>>>);
//!
//! impl EventProcessor<String> for Collector {
//!     fn process(&mut self, event: Event<String>) -> EventResult<String> {
//!         self.0.lock().unwrap().push(event.event_type.clone());
//!         EventResult::ok(event.data)
//!     }
//! }
//!
//! let seen = Arc::new(Mutex::new(Vec::new()));
//! let loop_ = EventLoop::new(16, Collector(seen.clone()), false);
//! loop_.start();
//!
//! // 请求事件带回执,便于确定性地等待处理完成
//! let (ev, rx) = new_request_event("ping", Some("hello".to_string()));
//! loop_.submit(ev).unwrap();
//! let reply = rx.recv_timeout(Duration::from_secs(5)).unwrap();
//! loop_.stop();
//!
//! assert_eq!(*seen.lock().unwrap(), vec!["ping"]);
//! assert_eq!(reply.data.as_deref(), Some("hello"));
//! ```

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

/// 默认队列缓冲长度。
pub const DEFAULT_BUFFER_SIZE: usize = 100;
/// 默认回调投递超时。
pub const DEFAULT_CALLBACK_TIMEOUT: Duration = Duration::from_secs(1);
/// 帧间隔:20Hz 逻辑帧。
pub const FRAME_INTERVAL: Duration = Duration::from_millis(50);
/// 每帧时间预算(预留 50% 缓冲)。
pub const FRAME_BUDGET: Duration = Duration::from_millis(25);
/// 低优先级每帧最多占用时间。
pub const MAX_LOW_TIME: Duration = Duration::from_millis(2);

/// 事件优先级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Priority {
    High,
    Medium,
    Low,
}

impl Priority {
    pub const ALL: [Priority; 3] = [Priority::High, Priority::Medium, Priority::Low];

    fn index(self) -> usize {
        match self {
            Priority::High => 0,
            Priority::Medium => 1,
            Priority::Low => 2,
        }
    }
}

/// 回调结果载体。
#[derive(Debug, Default)]
pub struct EventResult<T> {
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> EventResult<T> {
    pub fn ok(data: Option<T>) -> Self {
        EventResult { data, error: None }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        EventResult {
            data: None,
            error: Some(msg.into()),
        }
    }
}

/// 统一事件结构。
pub struct Event<T> {
    /// 事件优先级(默认 [`Priority::Low`])。
    pub priority: Priority,
    /// 事件类型。
    pub event_type: String,
    /// 事件数据。
    pub data: Option<T>,
    /// 回调通道(由 [`new_request_event`] 或 [`Event::with_callback`] 设置)。
    pub callback: Option<CbSender<EventResult<T>>>,
    /// 事件发送时间。
    pub ts: SystemTime,
}

impl<T> Event<T> {
    /// 创建事件,默认低优先级,时间戳自动设置。
    pub fn new(event_type: impl Into<String>, data: Option<T>) -> Self {
        Event {
            priority: Priority::Low,
            event_type: event_type.into(),
            data,
            callback: None,
            ts: SystemTime::now(),
        }
    }

    /// 设置优先级。
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// 设置回调通道。
    pub fn with_callback(mut self, callback: CbSender<EventResult<T>>) -> Self {
        self.callback = Some(callback);
        self
    }
}

impl<T> fmt::Debug for Event<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Event")
            .field("priority", &self.priority)
            .field("event_type", &self.event_type)
            .field("has_data", &self.data.is_some())
            .field("has_callback", &self.callback.is_some())
            .finish()
    }
}

/// 创建带 reply 通道的请求事件,返回事件与接收端。
pub fn new_request_event<T>(
    event_type: impl Into<String>,
    data: Option<T>,
) -> (Event<T>, CbReceiver<EventResult<T>>) {
    let (tx, rx) = callback_channel(1);
    (Event::new(event_type, data).with_callback(tx), rx)
}

/// 事件处理器接口,由业务层实现,在事件循环线程内被串行调用。
pub trait EventProcessor<T>: Send + 'static {
    fn process(&mut self, event: Event<T>) -> EventResult<T>;
}

/// 注入式统计接口。
pub trait Metrics: Send + Sync {
    fn observe_processing_duration(&self, priority: Priority, elapsed: Duration);
}

/// 空统计实现(默认)。
pub struct NoopMetrics;

impl Metrics for NoopMetrics {
    fn observe_processing_duration(&self, _priority: Priority, _elapsed: Duration) {}
}

/// 简单统计实现:按优先级累计处理次数与总耗时。
#[derive(Default)]
pub struct SimpleMetrics {
    cells: [[AtomicU64; 2]; 3], // [priority][count, total_us]
}

/// [`SimpleMetrics`] 的快照:每个优先级的 (处理次数, 累计耗时)。
pub type MetricsSnapshot = [(u64, Duration); 3];

impl SimpleMetrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        Priority::ALL.map(|p| {
            let cell = &self.cells[p.index()];
            (
                cell[0].load(Ordering::Relaxed),
                Duration::from_micros(cell[1].load(Ordering::Relaxed)),
            )
        })
    }
}

impl Metrics for SimpleMetrics {
    fn observe_processing_duration(&self, priority: Priority, elapsed: Duration) {
        let cell = &self.cells[priority.index()];
        cell[0].fetch_add(1, Ordering::Relaxed);
        cell[1].fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    }
}

/// 事件循环错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventLoopError {
    /// 事件循环未启动。
    NotRunning,
    /// 事件循环已停止。
    Stopped,
    /// 对应优先级队列已满。
    QueueFull(Priority),
    /// 阻塞提交等待超时。
    SubmitTimeout,
}

impl fmt::Display for EventLoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventLoopError::NotRunning => write!(f, "event loop not running"),
            EventLoopError::Stopped => write!(f, "event loop stopped"),
            EventLoopError::QueueFull(p) => write!(f, "{p:?} priority queue full"),
            EventLoopError::SubmitTimeout => write!(f, "submit blocking timeout"),
        }
    }
}

impl Error for EventLoopError {}

/// 各内部队列的当前长度快照。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueLengths {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub callback: usize,
}

type CallbackPair<T> = (CbSender<EventResult<T>>, EventResult<T>);

struct Queues<T> {
    high: VecDeque<Event<T>>,
    medium: VecDeque<Event<T>>,
    low: VecDeque<Event<T>>,
    callback: VecDeque<CallbackPair<T>>,
    stopped: bool,
}

impl<T> Queues<T> {
    fn queue(&mut self, priority: Priority) -> &mut VecDeque<Event<T>> {
        match priority {
            Priority::High => &mut self.high,
            Priority::Medium => &mut self.medium,
            Priority::Low => &mut self.low,
        }
    }
}

struct Config {
    cb_inline: bool,
    cb_timeout: Duration,
    frame_interval: Duration,
    frame_budget: Duration,
    max_low_time: Duration,
}

struct Inner<T> {
    capacity: usize,
    frame_driven: bool,
    processor: Mutex<Option<Box<dyn EventProcessor<T>>>>,
    metrics: Box<dyn Metrics>,
    logger: std::sync::RwLock<Arc<dyn EventLogger>>,
    queues: Mutex<Queues<T>>,
    event_cv: Condvar,    // 事件循环线程等待新事件/停止
    space_cv: Condvar,    // 阻塞提交等待队列空间
    callback_cv: Condvar, // 回调分发线程等待新回调项
    config: Mutex<Config>,
    running: AtomicBool,
    started: Mutex<bool>,
    started_cv: Condvar,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

/// 单线程优先级事件循环。
///
/// `T` 为事件载荷类型;克隆出的多个句柄共享同一循环(内部为 `Arc`)。
pub struct EventLoop<T> {
    inner: Arc<Inner<T>>,
}

impl<T> Clone for EventLoop<T> {
    fn clone(&self) -> Self {
        EventLoop {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Send + 'static> EventLoop<T> {
    /// 创建事件循环。`buffer_size` 为 0 时使用 [`DEFAULT_BUFFER_SIZE`];
    /// `frame_driven` 启用帧驱动模式;`metrics` 传 `None` 时使用 [`NoopMetrics`]。
    pub fn new(buffer_size: usize, processor: impl EventProcessor<T>, frame_driven: bool) -> Self {
        EventLoop::with_metrics(buffer_size, processor, frame_driven, None)
    }

    /// 同 [`EventLoop::new`],但可注入自定义 [`Metrics`]。
    pub fn with_metrics(
        buffer_size: usize,
        processor: impl EventProcessor<T>,
        frame_driven: bool,
        metrics: Option<Box<dyn Metrics>>,
    ) -> Self {
        EventLoop::with_logger(buffer_size, processor, frame_driven, metrics, None)
    }

    /// 同 [`EventLoop::new`],但可注入自定义 [`EventLogger`]。
    pub fn with_logger(
        buffer_size: usize,
        processor: impl EventProcessor<T>,
        frame_driven: bool,
        metrics: Option<Box<dyn Metrics>>,
        logger: Option<Arc<dyn EventLogger>>,
    ) -> Self {
        let buffer_size = if buffer_size == 0 {
            DEFAULT_BUFFER_SIZE
        } else {
            buffer_size
        };
        EventLoop {
            inner: Arc::new(Inner {
                capacity: buffer_size,
                frame_driven,
                processor: Mutex::new(Some(Box::new(processor))),
                metrics: metrics.unwrap_or_else(|| Box::new(NoopMetrics)),
                logger: std::sync::RwLock::new(logger.unwrap_or_else(|| Arc::new(NoopLogger))),
                queues: Mutex::new(Queues {
                    high: VecDeque::with_capacity(buffer_size),
                    medium: VecDeque::with_capacity(buffer_size),
                    low: VecDeque::with_capacity(buffer_size),
                    callback: VecDeque::with_capacity(buffer_size),
                    stopped: false,
                }),
                event_cv: Condvar::new(),
                space_cv: Condvar::new(),
                callback_cv: Condvar::new(),
                config: Mutex::new(Config {
                    cb_inline: false,
                    cb_timeout: DEFAULT_CALLBACK_TIMEOUT,
                    frame_interval: FRAME_INTERVAL,
                    frame_budget: FRAME_BUDGET,
                    max_low_time: MAX_LOW_TIME,
                }),
                running: AtomicBool::new(false),
                started: Mutex::new(false),
                started_cv: Condvar::new(),
                handles: Mutex::new(Vec::new()),
            }),
        }
    }

    /// 启动事件循环;重复调用直接返回。
    pub fn start(&self) {
        if self
            .inner
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        *self.inner.started.lock().unwrap() = false;
        self.inner.queues.lock().unwrap().stopped = false;

        let inner = self.inner.clone();
        let handle = if self.inner.frame_driven {
            thread::Builder::new()
                .name("event-loop-frame".into())
                .spawn(move || frame_loop(inner))
                .expect("spawn frame loop")
        } else {
            thread::Builder::new()
                .name("event-loop".into())
                .spawn(move || event_loop(inner))
                .expect("spawn event loop")
        };
        self.push_handle(handle);

        let inline = self.inner.config.lock().unwrap().cb_inline;
        if !inline {
            let inner = self.inner.clone();
            let handle = thread::Builder::new()
                .name("event-loop-callback".into())
                .spawn(move || callback_dispatcher(inner))
                .expect("spawn callback dispatcher");
            self.push_handle(handle);
        }

        // 最多等 50ms 让循环就绪(Go 版同款超时)
        let deadline = Instant::now() + Duration::from_millis(50);
        let mut started = self.inner.started.lock().unwrap();
        while !*started && Instant::now() < deadline {
            let (guard, _) = self
                .inner
                .started_cv
                .wait_timeout(started, Duration::from_millis(50))
                .unwrap();
            started = guard;
        }
    }

    fn push_handle(&self, handle: JoinHandle<()>) {
        self.inner.handles.lock().unwrap().push(handle);
    }

    /// 停止事件循环并等待线程退出;未在运行时为空操作。
    /// 队列中未处理的事件被丢弃(与 Go 版一致)。
    pub fn stop(&self) {
        stop_inner(&self.inner);
    }

    /// 事件循环是否正在运行。
    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::SeqCst)
    }

    /// 当前各队列长度快照(非阻塞)。
    pub fn queue_lengths(&self) -> QueueLengths {
        let q = self.inner.queues.lock().unwrap();
        QueueLengths {
            high: q.high.len(),
            medium: q.medium.len(),
            low: q.low.len(),
            callback: q.callback.len(),
        }
    }

    /// 运行时注入日志实现(默认 [`NoopLogger`];Go 版 `SetLogger` 同款)。
    pub fn set_logger(&self, logger: Arc<dyn EventLogger>) {
        *self.inner.logger.write().unwrap() = logger;
    }

    /// 切换回调投递模式;`inline = true` 表示在事件循环内同步投递,
    /// `timeout` 控制投递超时(`Some(Duration::ZERO)` 表示无限等待)。
    pub fn set_callback_inline(&self, inline: bool, timeout: Option<Duration>) {
        let mut cfg = self.inner.config.lock().unwrap();
        cfg.cb_inline = inline;
        if let Some(t) = timeout {
            cfg.cb_timeout = t;
        }
    }

    /// 设置帧驱动参数;传 `None` 表示保持不变。
    pub fn set_frame_parameters(
        &self,
        interval: Option<Duration>,
        budget: Option<Duration>,
        max_low: Option<Duration>,
    ) {
        let mut cfg = self.inner.config.lock().unwrap();
        if let Some(v) = interval {
            if v > Duration::ZERO {
                cfg.frame_interval = v;
            }
        }
        if let Some(v) = budget {
            if v > Duration::ZERO {
                cfg.frame_budget = v;
            }
        }
        if let Some(v) = max_low {
            cfg.max_low_time = v;
        }
    }

    /// 非阻塞提交事件;队列满或循环未运行时返回错误。
    pub fn submit(&self, event: Event<T>) -> Result<(), EventLoopError> {
        if !self.is_running() {
            return Err(EventLoopError::NotRunning);
        }
        let mut q = self.inner.queues.lock().unwrap();
        if q.stopped {
            return Err(EventLoopError::Stopped);
        }
        let queue = q.queue(event.priority);
        if queue.len() >= self.inner.capacity {
            return Err(EventLoopError::QueueFull(event.priority));
        }
        queue.push_back(event);
        drop(q);
        self.inner.event_cv.notify_one();
        Ok(())
    }

    /// 阻塞提交事件,队列满时等待;`timeout` 为 `None` 时一直等待
    /// 到有空间或循环停止。
    pub fn submit_blocking(
        &self,
        event: Event<T>,
        timeout: Option<Duration>,
    ) -> Result<(), EventLoopError> {
        if !self.is_running() {
            return Err(EventLoopError::NotRunning);
        }
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut q = self.inner.queues.lock().unwrap();
        loop {
            if q.stopped {
                return Err(EventLoopError::Stopped);
            }
            {
                let queue = q.queue(event.priority);
                if queue.len() < self.inner.capacity {
                    queue.push_back(event);
                    drop(q);
                    self.inner.event_cv.notify_one();
                    return Ok(());
                }
            }
            match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return Err(EventLoopError::SubmitTimeout);
                    }
                    let (guard, _) = self.inner.space_cv.wait_timeout(q, d - now).unwrap();
                    q = guard;
                }
                None => {
                    q = self.inner.space_cv.wait(q).unwrap();
                }
            }
        }
    }
}

fn stop_inner<T>(inner: &Arc<Inner<T>>) {
    if !inner.running.swap(false, Ordering::SeqCst) {
        return;
    }
    inner.queues.lock().unwrap().stopped = true;
    inner.event_cv.notify_all();
    inner.space_cv.notify_all();
    inner.callback_cv.notify_all();

    let handles: Vec<_> = std::mem::take(&mut *inner.handles.lock().unwrap());
    for h in handles {
        let _ = h.join();
    }
}

fn mark_started<T>(inner: &Inner<T>) {
    let mut started = inner.started.lock().unwrap();
    *started = true;
    inner.started_cv.notify_all();
}

fn take_processor<T>(inner: &Inner<T>) -> Option<Box<dyn EventProcessor<T>>> {
    inner.processor.lock().unwrap().take()
}

/// 连续模式事件循环:严格按 高 → 中 → 低 优先级逐个取事件。
fn event_loop<T: Send + 'static>(inner: Arc<Inner<T>>) {
    mark_started(&inner);
    let Some(mut processor) = take_processor(&inner) else {
        return;
    };

    loop {
        // 取下一个事件:高 → 中 → 低,取不到就阻塞等待
        let event = {
            let mut q = inner.queues.lock().unwrap();
            loop {
                if q.stopped {
                    return;
                }
                let next = q
                    .high
                    .pop_front()
                    .or_else(|| q.medium.pop_front())
                    .or_else(|| q.low.pop_front());
                if let Some(ev) = next {
                    inner.space_cv.notify_all();
                    break ev;
                }
                q = inner.event_cv.wait(q).unwrap();
            }
        };
        handle_event(&inner, processor.as_mut(), event);
    }
}

/// 帧驱动模式事件循环:每帧唤醒一次,按预算处理。
fn frame_loop<T: Send + 'static>(inner: Arc<Inner<T>>) {
    mark_started(&inner);
    let Some(mut processor) = take_processor(&inner) else {
        return;
    };

    let mut next_frame = Instant::now();
    loop {
        {
            let mut q = inner.queues.lock().unwrap();
            loop {
                if q.stopped {
                    return;
                }
                let now = Instant::now();
                if now >= next_frame {
                    next_frame = now + inner.config.lock().unwrap().frame_interval;
                    break;
                }
                let (guard, _) = inner.event_cv.wait_timeout(q, next_frame - now).unwrap();
                q = guard;
            }
        }
        process_frame(&inner, processor.as_mut());
    }
}

/// 处理单帧:高/中优先级清空(受帧预算约束),低优先级限时处理。
fn process_frame<T: Send + 'static>(inner: &Arc<Inner<T>>, processor: &mut dyn EventProcessor<T>) {
    let frame_start = Instant::now();
    let (frame_budget, max_low_time) = {
        let cfg = inner.config.lock().unwrap();
        (cfg.frame_budget, cfg.max_low_time)
    };

    for priority in [Priority::High, Priority::Medium] {
        loop {
            let event = {
                let mut q = inner.queues.lock().unwrap();
                q.queue(priority).pop_front()
            };
            let Some(event) = event else { break };
            inner.space_cv.notify_all();
            handle_event(inner, &mut *processor, event);
            if frame_start.elapsed() >= frame_budget {
                inner.log_warn("frame budget exceeded, defer rest events to next frame");
                // 帧预算超支,放弃本帧剩余事件
                return;
            }
        }
    }

    let low_deadline = frame_start + max_low_time;
    while Instant::now() < low_deadline {
        let event = {
            let mut q = inner.queues.lock().unwrap();
            q.low.pop_front()
        };
        let Some(event) = event else { break };
        inner.space_cv.notify_all();
        handle_event(inner, &mut *processor, event);
    }
}

fn handle_event<T: Send + 'static>(
    inner: &Arc<Inner<T>>,
    processor: &mut dyn EventProcessor<T>,
    mut event: Event<T>,
) {
    let priority = event.priority;
    let callback = event.callback.take();

    let start = Instant::now();
    let result = processor.process(event);
    let elapsed = start.elapsed();
    inner.metrics.observe_processing_duration(priority, elapsed);

    if let Some(cb) = callback {
        deliver_result(inner, cb, result);
    }
}

/// 投递回调结果:inline 模式在当前线程同步投递,否则入队由分发线程投递。
fn deliver_result<T: Send + 'static>(
    inner: &Arc<Inner<T>>,
    cb: CbSender<EventResult<T>>,
    result: EventResult<T>,
) {
    let (inline, timeout) = {
        let cfg = inner.config.lock().unwrap();
        (cfg.cb_inline, cfg.cb_timeout)
    };

    if inline {
        if timeout.is_zero() {
            let _ = cb.send(result);
        } else {
            // 超时后静默丢弃(Go 版记录 warn)
            let _ = cb.send_timeout(result, timeout);
        }
        return;
    }

    // 异步模式:尝试快速入队;队列满时后台重试,超时放弃
    {
        let mut q = inner.queues.lock().unwrap();
        if q.callback.len() < inner.capacity {
            q.callback.push_back((cb, result));
            drop(q);
            inner.callback_cv.notify_one();
            return;
        }
    }

    let inner2 = inner.clone();
    let _ = thread::Builder::new()
        .name("event-callback-retry".into())
        .spawn(move || {
            let deadline = Instant::now() + timeout;
            let mut q = inner2.queues.lock().unwrap();
            loop {
                if q.callback.len() < inner2.capacity {
                    q.callback.push_back((cb, result));
                    drop(q);
                    inner2.callback_cv.notify_one();
                    return;
                }
                if q.stopped {
                    return;
                }
                let now = Instant::now();
                if now >= deadline {
                    inner2.log_warn("enqueue callback timeout, discard result");
                    return;
                }
                let (guard, _) = inner2.callback_cv.wait_timeout(q, deadline - now).unwrap();
                q = guard;
            }
        });
}

/// 回调分发线程:把结果可靠地送到目标通道,超时或停止时放弃。
fn callback_dispatcher<T: Send + 'static>(inner: Arc<Inner<T>>) {
    loop {
        let item = {
            let mut q = inner.queues.lock().unwrap();
            loop {
                if q.stopped {
                    return;
                }
                if let Some(item) = q.callback.pop_front() {
                    break item;
                }
                q = inner.callback_cv.wait(q).unwrap();
            }
        };
        let (cb, result) = item;
        let timeout = inner.config.lock().unwrap().cb_timeout;
        if timeout.is_zero() {
            let _ = cb.send(result);
        } else if let Err(CbSendTimeoutError::Timeout(_)) = cb.send_timeout(result, timeout) {
            inner.log_warn("callback deliver timeout, discard result");
        }
    }
}

impl<T> Drop for EventLoop<T> {
    fn drop(&mut self) {
        // 只剩最后一个句柄时负责停掉循环
        if Arc::strong_count(&self.inner) == 1 {
            stop_inner(&self.inner);
        }
    }
}

// ---------------------------------------------------------------------------
// Logger(注入式日志接口,对应 Go 版 logger.go)
// ---------------------------------------------------------------------------

/// 注入式日志接口;默认 [`NoopLogger`] 静默。
pub trait EventLogger: Send + Sync {
    fn warn(&self, msg: &str);
}

/// 空日志(默认)。
pub struct NoopLogger;

impl EventLogger for NoopLogger {
    fn warn(&self, _msg: &str) {}
}

/// 标准错误日志。
pub struct StdLogger;

impl EventLogger for StdLogger {
    fn warn(&self, msg: &str) {
        eprintln!("[eventloop] warn: {msg}");
    }
}

impl<T> Inner<T> {
    fn log_warn(&self, msg: &str) {
        let logger = self.logger.read().unwrap();
        logger.warn(msg);
    }
}

// ---------------------------------------------------------------------------
// 内置有界回调通道(std 的 SyncSender::send_timeout 尚未稳定,故手写)
// ---------------------------------------------------------------------------

/// 回调发送端:有界容量,支持阻塞 / 超时投递。
pub struct CbSender<T> {
    shared: Arc<CbShared<T>>,
}

/// 回调接收端。
pub struct CbReceiver<T> {
    shared: Arc<CbShared<T>>,
}

struct CbShared<T> {
    queue: Mutex<CbQueue<T>>,
    cv: Condvar,
    capacity: usize,
}

struct CbQueue<T> {
    items: VecDeque<T>,
    closed: bool,
}

/// 创建容量为 `cap` 的回调通道。
pub fn callback_channel<T>(cap: usize) -> (CbSender<T>, CbReceiver<T>) {
    let shared = Arc::new(CbShared {
        queue: Mutex::new(CbQueue {
            items: VecDeque::with_capacity(cap.max(1)),
            closed: false,
        }),
        cv: Condvar::new(),
        capacity: cap.max(1),
    });
    (
        CbSender {
            shared: shared.clone(),
        },
        CbReceiver { shared },
    )
}

/// `send` 失败:接收端已关闭。
pub struct CbSendError<T>(pub T);

/// `send_timeout` 失败。
pub enum CbSendTimeoutError<T> {
    /// 接收端已关闭。
    Disconnected(T),
    /// 等待超时,值原样返回。
    Timeout(T),
}

/// `recv_timeout` 失败。
#[derive(Debug, PartialEq, Eq)]
pub enum CbRecvTimeoutError {
    /// 等待超时。
    Timeout,
    /// 通道关闭且已取空。
    Disconnected,
}

impl<T> Clone for CbSender<T> {
    fn clone(&self) -> Self {
        CbSender {
            shared: self.shared.clone(),
        }
    }
}

impl<T> CbSender<T> {
    /// 阻塞投递;接收端关闭时返回错误(值原样带回)。
    pub fn send(&self, value: T) -> Result<(), CbSendError<T>> {
        let mut q = self.shared.queue.lock().unwrap();
        loop {
            if q.closed {
                return Err(CbSendError(value));
            }
            if q.items.len() < self.shared.capacity {
                q.items.push_back(value);
                drop(q);
                self.shared.cv.notify_one();
                return Ok(());
            }
            q = self.shared.cv.wait(q).unwrap();
        }
    }

    /// 带超时的投递。
    pub fn send_timeout(&self, value: T, timeout: Duration) -> Result<(), CbSendTimeoutError<T>> {
        let deadline = Instant::now() + timeout;
        let mut q = self.shared.queue.lock().unwrap();
        loop {
            if q.closed {
                return Err(CbSendTimeoutError::Disconnected(value));
            }
            if q.items.len() < self.shared.capacity {
                q.items.push_back(value);
                drop(q);
                self.shared.cv.notify_one();
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(CbSendTimeoutError::Timeout(value));
            }
            let (guard, _) = self.shared.cv.wait_timeout(q, deadline - now).unwrap();
            q = guard;
        }
    }
}

impl<T> CbReceiver<T> {
    /// 带超时的接收;通道关闭且取空后返回 `Disconnected`。
    pub fn recv_timeout(&self, timeout: Duration) -> Result<T, CbRecvTimeoutError> {
        let deadline = Instant::now() + timeout;
        let mut q = self.shared.queue.lock().unwrap();
        loop {
            if let Some(v) = q.items.pop_front() {
                self.shared.cv.notify_all(); // 通知等待投递的发送端
                return Ok(v);
            }
            if q.closed {
                return Err(CbRecvTimeoutError::Disconnected);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(CbRecvTimeoutError::Timeout);
            }
            let (guard, _) = self.shared.cv.wait_timeout(q, deadline - now).unwrap();
            q = guard;
        }
    }

    /// 阻塞接收。
    pub fn recv(&self) -> Result<T, CbRecvTimeoutError> {
        let mut q = self.shared.queue.lock().unwrap();
        loop {
            if let Some(v) = q.items.pop_front() {
                self.shared.cv.notify_all();
                return Ok(v);
            }
            if q.closed {
                return Err(CbRecvTimeoutError::Disconnected);
            }
            q = self.shared.cv.wait(q).unwrap();
        }
    }

    fn close(&self) {
        let mut q = self.shared.queue.lock().unwrap();
        q.closed = true;
        drop(q);
        self.shared.cv.notify_all();
    }
}

impl<T> Drop for CbReceiver<T> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Collector(Arc<Mutex<Vec<(Priority, String)>>>);

    impl EventProcessor<String> for Collector {
        fn process(&mut self, event: Event<String>) -> EventResult<String> {
            self.0
                .lock()
                .unwrap()
                .push((event.priority, event.event_type.clone()));
            EventResult::ok(event.data)
        }
    }

    fn wait_for(cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < deadline, "timeout waiting for condition");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn test_priority_order() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        // 先让一个事件堵住闸门,保证后面三个事件全部入队后才开始消费
        let processor_events: Vec<Event<String>> = Vec::new();
        struct GateAndCollect {
            gate: Arc<(Mutex<bool>, Condvar)>,
            seen: Arc<Mutex<Vec<String>>>,
        }
        impl EventProcessor<String> for GateAndCollect {
            fn process(&mut self, event: Event<String>) -> EventResult<String> {
                {
                    let (lock, cv) = &*self.gate;
                    let mut open = lock.lock().unwrap();
                    while !*open {
                        open = cv.wait(open).unwrap();
                    }
                }
                self.seen.lock().unwrap().push(event.event_type.clone());
                EventResult::ok(event.data)
            }
        }
        let _ = processor_events;
        let loop_ = EventLoop::new(
            16,
            GateAndCollect {
                gate: gate.clone(),
                seen: seen.clone(),
            },
            false,
        );
        loop_.start();

        loop_
            .submit(Event::new("blocker", None).with_priority(Priority::High))
            .unwrap();
        thread::sleep(Duration::from_millis(50)); // blocker 已进入处理并阻塞

        loop_
            .submit(Event::new("low", None).with_priority(Priority::Low))
            .unwrap();
        loop_
            .submit(Event::new("medium", None).with_priority(Priority::Medium))
            .unwrap();
        loop_
            .submit(Event::new("high", None).with_priority(Priority::High))
            .unwrap();

        {
            let (lock, cv) = &*gate;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }

        wait_for(|| seen.lock().unwrap().len() == 4);
        loop_.stop();

        let guard = seen.lock().unwrap();
        let order: Vec<&str> = guard.iter().map(|s| s.as_str()).collect();
        assert_eq!(order, vec!["blocker", "high", "medium", "low"]);
    }

    #[test]
    fn test_request_event_roundtrip() {
        struct Echo;
        impl EventProcessor<String> for Echo {
            fn process(&mut self, event: Event<String>) -> EventResult<String> {
                EventResult::ok(event.data.map(|d| format!("echo: {d}")))
            }
        }
        let loop_ = EventLoop::new(16, Echo, false);
        loop_.start();

        let (ev, rx) = new_request_event("req", Some("ping".to_string()));
        loop_.submit(ev).unwrap();
        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        loop_.stop();

        assert_eq!(result.data.as_deref(), Some("echo: ping"));
    }

    /// 处理器闸门:第一个事件被取出后阻塞在闸门上,便于确定性测试队列状态。
    struct Gated {
        gate: Arc<(Mutex<bool>, Condvar)>,
    }

    impl Gated {
        fn open(self_arc: &Arc<(Mutex<bool>, Condvar)>) {
            let (lock, cv) = &**self_arc;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }
    }

    impl EventProcessor<u32> for Gated {
        fn process(&mut self, event: Event<u32>) -> EventResult<u32> {
            let (lock, cv) = &*self.gate;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
            EventResult::ok(event.data)
        }
    }

    #[test]
    fn test_queue_full() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let loop_ = EventLoop::new(1, Gated { gate: gate.clone() }, false);
        loop_.start();

        // a 被循环取出并阻塞在闸门里,b 填满队列
        loop_
            .submit(Event::new("a", None).with_priority(Priority::High))
            .unwrap();
        thread::sleep(Duration::from_millis(50));
        loop_
            .submit(Event::new("b", None).with_priority(Priority::High))
            .unwrap();
        let err = loop_
            .submit(Event::new("c", None).with_priority(Priority::High))
            .unwrap_err();
        assert_eq!(err, EventLoopError::QueueFull(Priority::High));

        Gated::open(&gate);
        loop_.stop();
    }

    #[test]
    fn test_submit_blocking_timeout() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let loop_ = EventLoop::new(1, Gated { gate: gate.clone() }, false);
        loop_.start();

        loop_
            .submit(Event::new("a", None).with_priority(Priority::High))
            .unwrap();
        thread::sleep(Duration::from_millis(50));
        loop_
            .submit(Event::new("b", None).with_priority(Priority::High))
            .unwrap();
        let err = loop_
            .submit_blocking(
                Event::new("c", None).with_priority(Priority::High),
                Some(Duration::from_millis(50)),
            )
            .unwrap_err();
        assert_eq!(err, EventLoopError::SubmitTimeout);

        Gated::open(&gate);
        loop_.stop();
    }

    #[test]
    fn test_not_running() {
        struct N;
        impl EventProcessor<u32> for N {
            fn process(&mut self, _event: Event<u32>) -> EventResult<u32> {
                EventResult::ok(None)
            }
        }
        let loop_ = EventLoop::new(4, N, false);
        assert_eq!(
            loop_.submit(Event::new("x", None)),
            Err(EventLoopError::NotRunning)
        );
        loop_.start();
        loop_.stop();
        assert_eq!(
            loop_.submit(Event::new("x", None)),
            Err(EventLoopError::NotRunning)
        );
    }

    #[test]
    fn test_frame_driven() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let loop_ = EventLoop::new(16, Collector(seen.clone()), true);
        loop_.set_frame_parameters(
            Some(Duration::from_millis(10)),
            Some(Duration::from_millis(25)),
            Some(Duration::from_millis(2)),
        );
        loop_.start();
        loop_
            .submit(Event::new("frame-ev", None).with_priority(Priority::High))
            .unwrap();
        wait_for(|| !seen.lock().unwrap().is_empty());
        loop_.stop();
        assert_eq!(seen.lock().unwrap()[0].1, "frame-ev");
    }

    #[test]
    fn test_metrics() {
        let metrics = Arc::new(SimpleMetrics::default());
        let loop_ = EventLoop::with_metrics(
            16,
            Collector(Arc::new(Mutex::new(Vec::new()))),
            false,
            Some(Box::new(SharedMetrics(metrics.clone()))),
        );
        loop_.start();
        loop_
            .submit(Event::new("m", None).with_priority(Priority::Medium))
            .unwrap();
        wait_for(|| metrics.snapshot()[1].0 > 0);
        loop_.stop();
        assert_eq!(metrics.snapshot()[1].0, 1);
    }

    struct SharedMetrics(Arc<SimpleMetrics>);
    impl Metrics for SharedMetrics {
        fn observe_processing_duration(&self, p: Priority, e: Duration) {
            self.0.observe_processing_duration(p, e);
        }
    }

    #[test]
    fn test_inline_callback_mode() {
        struct Echo;
        impl EventProcessor<String> for Echo {
            fn process(&mut self, event: Event<String>) -> EventResult<String> {
                EventResult::ok(event.data.map(|d| format!("inline: {d}")))
            }
        }
        let loop_ = EventLoop::new(16, Echo, false);
        loop_.set_callback_inline(true, Some(Duration::from_secs(1)));
        loop_.start();

        // inline 模式下由事件循环线程直接投递回调(不启动分发线程)
        let (ev, rx) = new_request_event("req", Some("ping".to_string()));
        loop_.submit(ev).unwrap();
        let reply = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        loop_.stop();
        assert_eq!(reply.data.as_deref(), Some("inline: ping"));
    }

    #[test]
    fn test_queue_lengths() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let loop_ = EventLoop::new(8, Gated { gate: gate.clone() }, false);
        loop_.start();

        // blocker 被取走并阻塞在闸门里
        loop_
            .submit(Event::new("a", None).with_priority(Priority::High))
            .unwrap();
        thread::sleep(Duration::from_millis(50));

        // 三个优先级队列各堆一个
        loop_
            .submit(Event::new("h", None).with_priority(Priority::High))
            .unwrap();
        loop_
            .submit(Event::new("m", None).with_priority(Priority::Medium))
            .unwrap();
        loop_
            .submit(Event::new("l", None).with_priority(Priority::Low))
            .unwrap();

        let ql = loop_.queue_lengths();
        assert_eq!((ql.high, ql.medium, ql.low), (1, 1, 1));

        Gated::open(&gate);
        wait_for(|| {
            let ql = loop_.queue_lengths();
            (ql.high, ql.medium, ql.low) == (0, 0, 0)
        });
        loop_.stop();
    }

    #[test]
    fn test_logger_receives_warnings() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Counter(Arc<AtomicUsize>);
        impl EventLogger for Counter {
            fn warn(&self, _msg: &str) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        // 帧预算压到 1ns:任何事件处理都会超支并触发 warn 日志
        let counter = Arc::new(AtomicUsize::new(0));
        let loop_ = EventLoop::with_logger(
            16,
            Collector(Arc::new(Mutex::new(Vec::new()))),
            true,
            None,
            Some(Arc::new(Counter(counter.clone()))),
        );
        loop_.set_frame_parameters(
            Some(Duration::from_millis(10)),
            Some(Duration::from_nanos(1)),
            Some(Duration::ZERO),
        );
        loop_.start();
        loop_
            .submit(Event::new("budget", None).with_priority(Priority::High))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while counter.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        loop_.stop();
        assert!(
            counter.load(Ordering::Relaxed) >= 1,
            "logger should have received warnings"
        );
    }
}
