//! 进程内事件总线(移植自 Go tx7do/go-utils/eventbus)。
//!
//! 功能清单与上游逐式对应:
//! - 事件对象 [`Event`](id/type/source/priority/metadata/data/timestamp);
//! - 处理器契约 [`Handler`] 与三个组合子:[`AsyncHandler`] / [`ChainHandler`] /
//!   [`FilterHandler`];
//! - 总线 [`DefaultEventBus`] 与契约 [`EventBus`]:订阅 / 异步订阅 / 一次性订阅 /
//!   退订 / 发布 / 异步发布 / 关闭;
//! - 中间件:Recovery / Timeout / Retry / Logging / Metrics 与组合子 [`chain`];
//! - 多总线管理器 [`Manager`](空名与 "global" 都是全局总线的别名)。
//!
//! 全部 API 同步、纯 `std`(`Mutex`/`RwLock`/`Arc`/`mpsc`/`thread`),
//! 无 async 运行时;错误统一为 `Result<_, String>`。
//!
//! # 与 Go 版的差异(适配点)
//!
//! 1. **无 context**:上游 `Handler.Handle(ctx, event)` / `Publish(ctx, event)`
//!    携带 `context.Context`;本移植整体去掉 ctx,**没有取消传播**。
//! 2. **日志**:上游 Logging/Metrics/Recovery 中间件依赖 `bLogger.Helper`;
//!    这里改为接受 [`LoggerFn`](`Arc<dyn Fn(&str) + Send + Sync>`)回调的变体,
//!    回调收到一条已拼好的日志文本。Recovery 另有无日志的
//!    [`recovery_middleware`] 便于纯逻辑使用。
//! 3. **事件数据**:上游 `Data any` + `GetData` 经 JSON 反序列化到任意类型;
//!    本 crate 无 serde 依赖,`data` 建模为 JSON 文本 `Option<String>`,
//!    用 [`Event::data`] / [`Event::set_data`] 取值/设值,由消费方自行解析,
//!    "类型不匹配报错"路径随之不存在。
//! 4. **事件 ID**:上游用 `crypto/rand`;纯 std 环境下改为
//!    UTC 时间戳 + splitmix64(纳秒时钟 + 进程内 `AtomicU64` 计数器)的
//!    非加密随机。事件 ID 不是安全材料,足够了;上游"随机源不可用则
//!    降级为重复字符"的兜底路径不存在对应故障模式,一并省去。
//!    上游时间戳取本地时间,纯 std 无时区库,这里改用 UTC。
//! 5. **错误**:`Result<_, String>`。上游 `PanicError` / `TimeoutError` 建模为
//!    轻量枚举 [`MiddlewareError`],经 `to_string()` 融入字符串错误流,
//!    保留上游固定消息前缀("panic in event handler" / "event handling timeout"),
//!    按枚举字段比较即可区分。
//! 6. **统计**:上游 `Manager.GetStats() map[string]interface{}` 改为结构体
//!    [`ManagerStats`]。
//! 7. **Timeout 中间件**:`thread::spawn + mpsc::channel + recv_timeout` 实现;
//!    没有 ctx 可取消,超时后内层线程继续跑完、结果被丢弃——与上游
//!    "ctx 到期后内层仍会执行完只是无人关心"的实效一致。
//! 8. **异步**:[`AsyncHandler`] / [`EventBus::publish_async`] 用分离的
//!    `thread::spawn` 实现,立即返回;上游 PublishAsync 的 30s 超时 ctx
//!    只对感知 ctx 的处理器有意义,随之省去。
//! 9. **事件类型枚举**:上游 `GetEventTypes` 返回 map 遍历(无序),
//!    [`DefaultEventBus::event_types`] 返回排序去重的 `Vec<String>`,便于确定性断言。
//! 10. **锁语义**:与上游一致,`publish` 在读锁内执行处理器——处理器里
//!     再对同一总线做订阅/退订/关闭(写操作)会死锁,上游同样如此,不要这么做。
//!     处理器 panic 会穿透发布(与上游一致);锁做了毒化容忍,总线仍可用,
//!     建议订阅时套 [`recovery_middleware`]。
//!
//! # 示例
//!
//! ```
//! use rust_utils::eventbus::{
//!     chain, logging_middleware, recovery_middleware, timeout_middleware, DefaultEventBus,
//!     EventBus, Event,
//! };
//! use std::sync::mpsc;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! let bus = Arc::new(DefaultEventBus::new());
//!
//! // 订阅:闭包经 Handler 的 blanket impl 直接作为处理器(对应 EventHandlerFunc)
//! let (tx, rx) = mpsc::channel();
//! bus.subscribe("user.created", Arc::new(move |event: &Event| -> Result<(), String> {
//!     let _ = tx.send(event.event_type.clone());
//!     Ok(())
//! })).unwrap();
//!
//! // 中间件链(首参数为最外层):恢复 -> 日志 -> 超时 -> 业务处理器
//! let with_middleware = chain(vec![
//!     recovery_middleware(),
//!     logging_middleware(Arc::new(|_msg: &str| { /* 接入日志系统 */ })),
//!     timeout_middleware(Duration::from_secs(5)),
//! ]);
//! bus.subscribe("task.started", with_middleware(Arc::new(|event: &Event| -> Result<(), String> {
//!     assert_eq!(event.event_type, "task.started");
//!     Ok(())
//! }))).unwrap();
//!
//! // 同步发布(data 为 JSON 文本)
//! bus.publish(&Event::new("user.created", Some(r#"{"username":"john"}"#.to_string()))).unwrap();
//! assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), "user.created");
//!
//! // 异步发布:立即返回,后台线程投递
//! bus.clone().publish_async(Event::new("user.created", None)).unwrap();
//! assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), "user.created");
//!
//! // 一次性订阅:首次发布后自动移除
//! bus.subscribe_once("init", Arc::new(|_: &Event| -> Result<(), String> { Ok(()) })).unwrap();
//! bus.publish(&Event::new("init", None)).unwrap();
//! assert_eq!(bus.subscriber_count("init"), 0);
//!
//! bus.close().unwrap();
//! ```

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// 事件对象(上游 event.go)
// ---------------------------------------------------------------------------

/// 事件对象:一次发布的完整载荷(上游 `Event` 结构体)。
///
/// `data` 为 JSON 文本(见模块头第 3 条);[`Clone`] 即上游 `Clone()` 的
/// 深拷贝语义(metadata 独立成表)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// 事件唯一 ID(UTC 时间戳 + 非加密随机后缀,构造时自动生成)。
    pub id: String,
    /// 事件类型(如 "email.received"、"user.created")。
    pub event_type: String,
    /// 事件来源标识。
    pub source: String,
    /// 事件载荷:JSON 文本;无载荷为 [`None`]。
    pub data: Option<String>,
    /// 附加元数据。
    pub metadata: HashMap<String, String>,
    /// 事件创建时间。
    pub timestamp: SystemTime,
    /// 优先级(越大越重要;上游仅作标注字段,总线不据此排序)。
    pub priority: i32,
}

impl Event {
    /// 创建事件:自动生成 ID 与时间戳,metadata 初始化为空表
    /// (上游 `NewEvent`;时间戳为本地时间,这里为 UTC)。
    pub fn new(event_type: impl Into<String>, data: Option<String>) -> Self {
        Event {
            id: generate_event_id(),
            event_type: event_type.into(),
            source: String::new(),
            data,
            metadata: HashMap::new(),
            timestamp: SystemTime::now(),
            priority: 0,
        }
    }

    /// 设置来源(链式;上游 `WithSource`)。
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    /// 设置优先级(链式;上游 `WithPriority`)。
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// 追加一条元数据(链式;上游 `WithMetadata`)。
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// 取载荷 JSON 文本;无载荷返回 [`None`]。
    pub fn data(&self) -> Option<&str> {
        self.data.as_deref()
    }

    /// 设值/清空载荷。
    ///
    /// 上游 `GetData(v)` 的"反序列化到任意类型"在本移植中不存在
    /// (无 serde,见模块头第 3 条):载荷以 JSON 文本原样携带,
    /// 由消费方用自己的 JSON 库解析。
    pub fn set_data(&mut self, data: Option<String>) {
        self.data = data;
    }
}

/// 事件 ID 的进程内序号:与纳秒时钟一起作为随机种子,
/// 保证同一纳秒内多次生成的 ID 也互不相同。
static EVENT_ID_SEQ: AtomicU64 = AtomicU64::new(0);

/// 生成事件 ID:`UTC 时间戳(YYYYMMDDhhmmss.ffffff) + 8 位随机后缀`
/// (上游 `generateEventID`;本地时间改为 UTC,见模块头第 4 条)。
fn generate_event_id() -> String {
    format!(
        "{}{}",
        format_timestamp(SystemTime::now()),
        random_string(8)
    )
}

/// splitmix64:把 64 位状态均匀打散(非加密,仅供事件 ID 去重使用)。
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// 生成长度 `length` 的小写字母数字随机串(上游 `randomString`)。
///
/// 纯 std 没有加密随机源:以纳秒时钟 + 进程内计数器做种子,
/// 经 splitmix64 打散后取模映射到字符集。事件 ID 非安全材料(模块头第 4 条)。
fn random_string(length: usize) -> String {
    const CHARSET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = EVENT_ID_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut state = nanos ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut out = String::with_capacity(length);
    for _ in 0..length {
        let idx = (splitmix64(&mut state) % CHARSET.len() as u64) as usize;
        out.push(CHARSET[idx] as char);
    }
    out
}

/// 把 [`SystemTime`] 格式化为 `YYYYMMDDhhmmss.ffffff`(UTC;
/// 上游为 `time.Now().Format("20060102150405.000000")` 的本地时间)。
fn format_timestamp(t: SystemTime) -> String {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let micros = dur.subsec_micros();
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}.{:06}",
        year,
        month,
        day,
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60,
        micros
    )
}

/// 距 Unix 纪元的天数 -> 公历日期 `(年, 月, 日)`
/// (Howard Hinnant 的 civil_from_days 算法,纯整数运算)。
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------------
// 处理器(上游 handler.go)
// ---------------------------------------------------------------------------

/// 共享处理器指针:订阅表里存的就是它;退订按指针同一性
/// ([`Arc::ptr_eq`])匹配——对应上游按 `%p` 比较处理器指针的语义。
pub type SharedHandler = Arc<dyn Handler>;

/// 处理器契约:上游 `Handler` 接口的对应物(无 ctx,见模块头第 1 条)。
///
/// 普通函数/闭包经下方 blanket impl 自动成为处理器
/// (对应上游 `EventHandlerFunc` 函数适配器)。
pub trait Handler: Send + Sync {
    /// 处理一个事件。`Err(_)` 表示处理器内部失败;总线发布时会忽略
    /// 单个处理器的错误继续投递其余处理器(与上游一致)。
    fn handle(&self, event: &Event) -> Result<(), String>;
}

/// `Fn` 闭包到 [`Handler`] 的适配(上游 `EventHandlerFunc`)。
impl<F> Handler for F
where
    F: Fn(&Event) -> Result<(), String> + Send + Sync,
{
    fn handle(&self, event: &Event) -> Result<(), String> {
        self(event)
    }
}

/// 异步包装:构造即返回,内层处理器在独立分离线程中执行
/// (上游 `AsyncHandler`)。
///
/// 内层的返回值(含错误)被丢弃;没有取消传播,线程跑完自然结束。
pub struct AsyncHandler {
    handler: SharedHandler,
}

impl AsyncHandler {
    /// 包装 `handler` 使其异步执行(上游 `NewAsyncHandler`)。
    pub fn new(handler: SharedHandler) -> Self {
        AsyncHandler { handler }
    }
}

impl Handler for AsyncHandler {
    fn handle(&self, event: &Event) -> Result<(), String> {
        let handler = Arc::clone(&self.handler);
        let event = event.clone();
        thread::spawn(move || {
            let _ = handler.handle(&event);
        });
        Ok(())
    }
}

/// 链式处理器:按声明顺序执行全部成员,首个错误即短路并向上透传
/// (上游 `ChainHandler`)。
pub struct ChainHandler {
    handlers: Vec<SharedHandler>,
}

impl ChainHandler {
    /// 聚合多个处理器(上游 `NewChainHandler` 的可变参数收成 [`Vec`])。
    pub fn new(handlers: Vec<SharedHandler>) -> Self {
        ChainHandler { handlers }
    }
}

impl Handler for ChainHandler {
    fn handle(&self, event: &Event) -> Result<(), String> {
        for handler in &self.handlers {
            handler.handle(event)?;
        }
        Ok(())
    }
}

/// 事件过滤器:返回 `true` 才放行(上游 `FilterHandler.filter` 字段)。
pub type EventFilter = Arc<dyn Fn(&Event) -> bool + Send + Sync>;

/// 过滤处理器:谓词为真才调用内层处理器,为假静默返回成功
/// (上游 `FilterHandler`)。
pub struct FilterHandler {
    filter: EventFilter,
    handler: SharedHandler,
}

impl FilterHandler {
    /// 用 `filter` 守卫 `handler`(上游 `NewFilterHandler`)。
    pub fn new(filter: EventFilter, handler: SharedHandler) -> Self {
        FilterHandler { filter, handler }
    }
}

impl Handler for FilterHandler {
    fn handle(&self, event: &Event) -> Result<(), String> {
        if (self.filter)(event) {
            return self.handler.handle(event);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 总线(上游 eventbus.go)
// ---------------------------------------------------------------------------

/// 总线契约:上游 `EventBus` 接口的逐式复刻。
///
/// 全部同步 API。`publish_async` 以 `Arc<Self>` 为接收者:
/// 投递线程需要持有总线本身(调用方一般已持有 `Arc`,克隆即可)。
pub trait EventBus: Send + Sync {
    /// 注册订阅;总线关闭后报错。
    fn subscribe(&self, event_type: &str, handler: SharedHandler) -> Result<(), String>;

    /// 异步订阅:处理器被 [`AsyncHandler`] 包装,在独立线程执行。
    /// 默认实现即上游 `DefaultEventBus.SubscribeAsync` 的做法。
    fn subscribe_async(&self, event_type: &str, handler: SharedHandler) -> Result<(), String> {
        self.subscribe(event_type, Arc::new(AsyncHandler::new(handler)))
    }

    /// 一次性订阅:首次发布执行后随整组移除;退订 API 不作用于它
    /// (对 once 订阅退订会报 "handler not found")。
    fn subscribe_once(&self, event_type: &str, handler: SharedHandler) -> Result<(), String>;

    /// 退订:按处理器指针同一性移除**一份**注册;
    /// 找不到(含主题不存在)报 "handler not found for event type: …"。
    fn unsubscribe(&self, event_type: &str, handler: &SharedHandler) -> Result<(), String>;

    /// 同步发布到该类型的全部订阅者(普通订阅先于 once 订阅);
    /// 单个处理器失败不影响发布结果;无订阅者静默成功;总线关闭后报错。
    fn publish(&self, event: &Event) -> Result<(), String>;

    /// 异步发布:立即返回成功,后台线程执行与 [`EventBus::publish`]
    /// 相同的投递流程;内部失败(如总线已关闭)不外露(上游仅记日志)。
    fn publish_async(self: Arc<Self>, event: Event) -> Result<(), String>;

    /// 关闭总线并清空订阅表;重复关闭报错。关闭后订阅与发布都被拒绝。
    fn close(&self) -> Result<(), String>;
}

/// [`DefaultEventBus`] 的内部状态(上游 DefaultEventBus 的字段,
/// 由一把 `RwLock` 保护——与上游 `sync.RWMutex` 一致)。
#[derive(Default)]
struct BusState {
    handlers: HashMap<String, Vec<SharedHandler>>,
    once_handlers: HashMap<String, Vec<SharedHandler>>,
    closed: bool,
}

/// [`EventBus`] 的默认实现(上游 `DefaultEventBus`)。
///
/// 并发模型与上游一致:订阅表由一把 `RwLock` 保护;`publish` 在
/// **读锁内**执行处理器,执行完 once 处理器后重新拿写锁把该主题的
/// once 订阅整组移除(执行期间新注册的 once 订阅也会被删除——
/// 上游存在同样的竞态,逐式保留)。
pub struct DefaultEventBus {
    state: RwLock<BusState>,
}

impl Default for DefaultEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultEventBus {
    /// 创建空总线(上游 `NewEventBus`;日志器参数随之省去)。
    pub fn new() -> Self {
        DefaultEventBus {
            state: RwLock::new(BusState::default()),
        }
    }

    /// 读锁;锁被毒化(处理器 panic 穿透)时继续用残余数据,
    /// 对齐 Go 无毒化语义。
    fn read_state(&self) -> RwLockReadGuard<'_, BusState> {
        self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    /// 写锁;毒化容忍同 [`Self::read_state`]。
    fn write_state(&self) -> RwLockWriteGuard<'_, BusState> {
        self.state.write().unwrap_or_else(|e| e.into_inner())
    }

    /// 某主题的订阅数(普通订阅 + once 订阅都计入;
    /// 上游 `GetSubscriberCount`)。
    pub fn subscriber_count(&self, event_type: &str) -> usize {
        let state = self.read_state();
        let regular = state.handlers.get(event_type).map_or(0, Vec::len);
        let once = state.once_handlers.get(event_type).map_or(0, Vec::len);
        regular + once
    }

    /// 所有有订阅者的主题,排序去重(上游 `GetEventTypes`;
    /// 上游为 map 遍历无序,这里排序便于确定性断言,模块头第 9 条)。
    pub fn event_types(&self) -> Vec<String> {
        let state = self.read_state();
        let mut types: Vec<String> = state
            .handlers
            .keys()
            .chain(state.once_handlers.keys())
            .cloned()
            .collect();
        types.sort();
        types.dedup();
        types
    }
}

impl EventBus for DefaultEventBus {
    fn subscribe(&self, event_type: &str, handler: SharedHandler) -> Result<(), String> {
        let mut state = self.write_state();
        if state.closed {
            return Err("event bus is closed".into());
        }
        state
            .handlers
            .entry(event_type.to_string())
            .or_default()
            .push(handler);
        Ok(())
    }

    fn subscribe_once(&self, event_type: &str, handler: SharedHandler) -> Result<(), String> {
        let mut state = self.write_state();
        if state.closed {
            return Err("event bus is closed".into());
        }
        state
            .once_handlers
            .entry(event_type.to_string())
            .or_default()
            .push(handler);
        Ok(())
    }

    fn unsubscribe(&self, event_type: &str, handler: &SharedHandler) -> Result<(), String> {
        let mut state = self.write_state();
        // 只作用于普通订阅表;once 订阅不可退订(上游同此)。
        if let Some(list) = state.handlers.get_mut(event_type) {
            if let Some(pos) = list.iter().position(|h| Arc::ptr_eq(h, handler)) {
                list.remove(pos);
                return Ok(());
            }
        }
        Err(format!("handler not found for event type: {event_type}"))
    }

    fn publish(&self, event: &Event) -> Result<(), String> {
        // 读锁贯穿投递,与上游 Publish 持 RLock 执行处理器一致。
        let state = self.read_state();
        if state.closed {
            return Err("event bus is closed".into());
        }
        let handlers = state
            .handlers
            .get(&event.event_type)
            .cloned()
            .unwrap_or_default();
        let once = state
            .once_handlers
            .get(&event.event_type)
            .cloned()
            .unwrap_or_default();
        if handlers.is_empty() && once.is_empty() {
            // 无订阅者:正常情形,不算错误(上游直接返回 nil)。
            return Ok(());
        }

        for handler in &handlers {
            // 单个处理器失败仅忽略(上游记错误日志),继续投递其余处理器。
            let _ = handler.handle(event);
        }
        for handler in &once {
            let _ = handler.handle(event);
        }
        drop(state);

        // 与上游一致:重新拿写锁,把该主题的 once 订阅整组删除。
        if !once.is_empty() {
            self.write_state().once_handlers.remove(&event.event_type);
        }
        Ok(())
    }

    fn publish_async(self: Arc<Self>, event: Event) -> Result<(), String> {
        // 分离线程投递;内部失败(如总线已关闭)不外露,上游仅记日志。
        // 上游为后台 goroutine 套了 30s 超时 ctx,只对感知 ctx 的处理器
        // 有意义,本移植无 ctx,随之省去(模块头第 8 条)。
        thread::spawn(move || {
            let _ = self.publish(&event);
        });
        Ok(())
    }

    fn close(&self) -> Result<(), String> {
        let mut state = self.write_state();
        if state.closed {
            return Err("event bus already closed".into());
        }
        state.closed = true;
        state.handlers = HashMap::new();
        state.once_handlers = HashMap::new();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 中间件(上游 middleware.go)
// ---------------------------------------------------------------------------

/// 中间件:包一层处理器(上游 `type Middleware func(Handler) Handler`)。
pub type Middleware = Arc<dyn Fn(SharedHandler) -> SharedHandler + Send + Sync>;

/// 日志回调:收到一条已拼好的日志文本
/// (替代上游注入的 `bLogger.Helper`,模块头第 2 条)。
pub type LoggerFn = Arc<dyn Fn(&str) + Send + Sync>;

/// 中间件产生的可识别错误:上游 `PanicError` / `TimeoutError` 的轻量枚举。
///
/// 处理器错误流是 `Result<_, String>`;两者经 [`Display`](std::fmt::Display) 拼成带固定前缀的
/// 字符串融入错误流——前缀与上游 `Error()` 一致
/// ("panic in event handler" / "event handling timeout"),之后附加字段值,
/// 按枚举字段比较即可区分(模块头第 5 条)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiddlewareError {
    /// 处理器 panic,被 Recovery 捕获(`value` 对应上游 `PanicError.Value`)。
    Panic {
        /// panic 载荷的可读文本。
        value: String,
    },
    /// 处理器超时(字段对应上游 `TimeoutError` 三字段)。
    Timeout {
        /// 超时事件的 ID。
        event_id: String,
        /// 超时事件的类型。
        event_type: String,
        /// 触发超时的时间阈值。
        timeout: Duration,
    },
}

impl fmt::Display for MiddlewareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MiddlewareError::Panic { value } => write!(f, "panic in event handler: {value}"),
            MiddlewareError::Timeout {
                event_id,
                event_type,
                timeout,
            } => write!(
                f,
                "event handling timeout: event={event_type} id={event_id} timeout={timeout:?}"
            ),
        }
    }
}

impl std::error::Error for MiddlewareError {}

impl From<MiddlewareError> for String {
    fn from(e: MiddlewareError) -> String {
        e.to_string()
    }
}

/// 从 panic 载荷提取可读消息;非字符串载荷给出占位说明
/// (上游 `PanicError.Value` 为 `interface{}`,这里统一字符串化)。
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic value>".to_string()
    }
}

/// Recovery 中间件(无日志):捕获内层 panic 转为
/// [`MiddlewareError::Panic`] 字符串错误;正常错误原样透传而非吞掉。
pub fn recovery_middleware() -> Middleware {
    recovery_inner(None)
}

/// Recovery 中间件(带日志回调):捕获 panic 时额外调用 `on_panic`
/// (对齐上游 `RecoveryMiddleware(logger)` 的错误日志)。
pub fn recovery_middleware_with_logger(on_panic: LoggerFn) -> Middleware {
    recovery_inner(Some(on_panic))
}

fn recovery_inner(on_panic: Option<LoggerFn>) -> Middleware {
    Arc::new(move |next: SharedHandler| {
        let next = Arc::clone(&next);
        let on_panic = on_panic.clone();
        Arc::new(move |event: &Event| {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| next.handle(event))) {
                Ok(result) => result,
                Err(payload) => {
                    let value = panic_message(&*payload);
                    if let Some(log) = &on_panic {
                        log(&format!(
                            "Panic recovered in event handler for {}: {value}",
                            event.event_type
                        ));
                    }
                    Err(MiddlewareError::Panic { value }.to_string())
                }
            }
        }) as SharedHandler
    })
}

/// Logging 中间件(上游 `LoggingMiddleware` 的回调变体):
/// 处理前后各发一条日志文本,结果原样透传。
pub fn logging_middleware(logger: LoggerFn) -> Middleware {
    Arc::new(move |next: SharedHandler| {
        let next = Arc::clone(&next);
        let logger = Arc::clone(&logger);
        Arc::new(move |event: &Event| {
            logger(&format!(
                "Handling event: type={}, id={}, source={}",
                event.event_type, event.id, event.source
            ));
            let result = next.handle(event);
            match &result {
                Err(err) => logger(&format!("Error handling event {}: {err}", event.id)),
                Ok(()) => logger(&format!("Successfully handled event: {}", event.id)),
            }
            result
        }) as SharedHandler
    })
}

/// Timeout 中间件(上游 `TimeoutMiddleware` 的线程版):
/// 内层在独立线程执行,`recv_timeout` 等待;超时返回
/// [`MiddlewareError::Timeout`]。
///
/// 与上游的差异:没有 ctx 可取消,超时后内层线程继续跑完、结果被丢弃
/// (模块头第 7 条)。每次调用会 `thread::spawn`,高吞吐场景请自行权衡。
pub fn timeout_middleware(timeout: Duration) -> Middleware {
    Arc::new(move |next: SharedHandler| {
        let next = Arc::clone(&next);
        Arc::new(move |event: &Event| {
            let (tx, rx) = mpsc::channel();
            let handler = Arc::clone(&next);
            let owned = event.clone();
            thread::spawn(move || {
                // 接收端可能已因超时被丢弃:发送失败即线程自然结束。
                let _ = tx.send(handler.handle(&owned));
            });
            match rx.recv_timeout(timeout) {
                Ok(result) => result,
                Err(mpsc::RecvTimeoutError::Timeout) => Err(MiddlewareError::Timeout {
                    event_id: event.id.clone(),
                    event_type: event.event_type.clone(),
                    timeout,
                }
                .to_string()),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    Err("event handler thread terminated unexpectedly".into())
                }
            }
        }) as SharedHandler
    })
}

/// Retry 中间件(上游 `RetryMiddleware`):失败重试至多 `max_retries`
/// 次(`max_retries=0` 即只执行一次,共 1+max_retries 次尝试),
/// 每次重试前睡 `delay`;中途成功立即返回,耗尽后返回最后一次错误。
pub fn retry_middleware(max_retries: usize, delay: Duration) -> Middleware {
    Arc::new(move |next: SharedHandler| {
        let next = Arc::clone(&next);
        Arc::new(move |event: &Event| {
            let mut last_err = String::new();
            for attempt in 0..=max_retries {
                match next.handle(event) {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        last_err = err;
                        if attempt < max_retries {
                            thread::sleep(delay);
                        }
                    }
                }
            }
            Err(last_err)
        }) as SharedHandler
    })
}

/// Metrics 中间件(上游 `MetricsMiddleware` 的回调变体):
/// 发一条带耗时的指标文本,只观测不改写结果。
pub fn metrics_middleware(logger: LoggerFn) -> Middleware {
    Arc::new(move |next: SharedHandler| {
        let next = Arc::clone(&next);
        let logger = Arc::clone(&logger);
        Arc::new(move |event: &Event| {
            let start = Instant::now();
            let result = next.handle(event);
            logger(&format!(
                "Event handling metrics: type={}, duration={:?}, success={}",
                event.event_type,
                start.elapsed(),
                result.is_ok()
            ));
            result
        }) as SharedHandler
    })
}

/// 组合多个中间件:**首参数为最外层**(上游 `Chain`)。
///
/// 例如 `chain(vec![recovery_middleware(), timeout_middleware(d)])`
/// 中 Recovery 在最外层,能兜住内层(含 Timeout)的 panic;
/// 调换顺序 panic 将穿透到调用方。
pub fn chain(middlewares: Vec<Middleware>) -> Middleware {
    Arc::new(move |handler: SharedHandler| {
        let mut wrapped = handler;
        // 从右往左包裹,首个中间件落在最外层(与上游一致)。
        for middleware in middlewares.iter().rev() {
            wrapped = middleware(wrapped);
        }
        wrapped
    })
}

// ---------------------------------------------------------------------------
// 多总线管理器(上游 manager.go)
// ---------------------------------------------------------------------------

/// [`Manager::get_stats`] 的统计快照
/// (替代上游 `GetStats() map[string]interface{}`,模块头第 6 条)。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManagerStats {
    /// 具名总线数量(不含全局总线)。
    pub total_buses: usize,
    /// 具名总线明细:名称 -> 订阅主题列表(排序)。
    pub buses: HashMap<String, Vec<String>>,
    /// 全局总线订阅主题列表(排序)。
    pub global_bus: Vec<String>,
}

/// 多总线管理器(上游 `Manager`)。
///
/// 空名与 `"global"` 都是全局总线的别名——否则经不同入口的订阅与发布
/// 会分属两个总线实例、永远错开(上游注释同款修复)。
pub struct Manager {
    buses: RwLock<HashMap<String, Arc<DefaultEventBus>>>,
    global: Arc<DefaultEventBus>,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    /// 创建管理器并附带全局总线(上游 `NewManager`;日志器参数省去)。
    pub fn new() -> Self {
        Manager {
            buses: RwLock::new(HashMap::new()),
            global: Arc::new(DefaultEventBus::new()),
        }
    }

    /// 读锁;毒化容忍对齐 Go 无毒化语义。
    fn read_buses(&self) -> RwLockReadGuard<'_, HashMap<String, Arc<DefaultEventBus>>> {
        self.buses.read().unwrap_or_else(|e| e.into_inner())
    }

    /// 写锁;毒化容忍同上。
    fn write_buses(&self) -> RwLockWriteGuard<'_, HashMap<String, Arc<DefaultEventBus>>> {
        self.buses.write().unwrap_or_else(|e| e.into_inner())
    }

    /// 取具名总线;不存在则惰性创建。空名与 `"global"` 返回全局总线
    /// (上游 `GetBus`)。
    pub fn get_bus(&self, name: &str) -> Arc<DefaultEventBus> {
        if name.is_empty() || name == "global" {
            return Arc::clone(&self.global);
        }
        let mut buses = self.write_buses();
        if let Some(bus) = buses.get(name) {
            return Arc::clone(bus);
        }
        let bus = Arc::new(DefaultEventBus::new());
        buses.insert(name.to_string(), Arc::clone(&bus));
        bus
    }

    /// 全局总线(上游 `Global`)。
    pub fn global(&self) -> Arc<DefaultEventBus> {
        Arc::clone(&self.global)
    }

    /// 发布到指定总线(空名落到全局总线;总线可能被惰性创建)。
    pub fn publish(&self, bus_name: &str, event: &Event) -> Result<(), String> {
        self.get_bus(bus_name).publish(event)
    }

    /// 发布到全局总线(上游 `PublishGlobal`)。
    pub fn publish_global(&self, event: &Event) -> Result<(), String> {
        self.global.publish(event)
    }

    /// 订阅到指定总线(空名 -> 全局总线)。
    pub fn subscribe(
        &self,
        bus_name: &str,
        event_type: &str,
        handler: SharedHandler,
    ) -> Result<(), String> {
        self.get_bus(bus_name).subscribe(event_type, handler)
    }

    /// 订阅到全局总线(上游 `SubscribeGlobal`)。
    pub fn subscribe_global(&self, event_type: &str, handler: SharedHandler) -> Result<(), String> {
        self.global.subscribe(event_type, handler)
    }

    /// 关闭全部总线(含全局)。已单独关闭的总线报错被逐一容忍并忽略
    /// (上游记日志后仍返回 nil),整体永远成功。
    pub fn close(&self) -> Result<(), String> {
        let mut buses = self.write_buses();
        for bus in buses.values() {
            let _ = bus.close();
        }
        buses.clear();
        let _ = self.global.close();
        Ok(())
    }

    /// 各总线统计快照(上游 `GetStats`)。
    pub fn get_stats(&self) -> ManagerStats {
        let buses = self.read_buses();
        let named: HashMap<String, Vec<String>> = buses
            .iter()
            .map(|(name, bus)| (name.clone(), bus.event_types()))
            .collect();
        ManagerStats {
            total_buses: named.len(),
            buses: named,
            global_bus: self.global.event_types(),
        }
    }
}

// ---------------------------------------------------------------------------
// 测试(移植自上游 *_test.go 的核心用例;异步等待全部用 channel + 超时,
// 保证确定性)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc::Receiver;
    use std::sync::Mutex;

    /// 等待事件的超时窗口(防死锁挂死)。
    const WAIT: Duration = Duration::from_secs(2);
    /// 负向验证的静默窗口。
    const QUIET: Duration = Duration::from_millis(200);

    fn new_bus() -> Arc<DefaultEventBus> {
        Arc::new(DefaultEventBus::new())
    }

    fn noop_logger() -> LoggerFn {
        Arc::new(|_| {})
    }

    /// 把日志文本收进 Vec 供断言(上游 quietLogger 的观测替代)。
    fn collecting_logger(sink: &Arc<Mutex<Vec<String>>>) -> LoggerFn {
        let sink = Arc::clone(sink);
        Arc::new(move |msg: &str| sink.lock().unwrap().push(msg.to_string()))
    }

    /// 在超时窗口内等待事件抵达;超时即失败(对应上游 waitEvent)。
    fn wait_event(rx: &Receiver<Event>) -> Event {
        rx.recv_timeout(WAIT)
            .expect("超时窗口内未收到事件:处理器未执行或订阅链路断裂")
    }

    /// 断言在短窗口内不再有事件抵达(退订/once 移除后的负向验证;
    /// 对应上游 expectNoEvent)。
    ///
    /// 发送端关闭且缓冲已空(`Disconnected`)同样满足负向断言:
    /// once 订阅执行后处理器被移除,其内部持有的 Sender 随之析构,
    /// 此后永远不可能再有事件抵达。
    fn expect_no_event(rx: &Receiver<Event>) {
        match rx.recv_timeout(QUIET) {
            Ok(ev) => panic!("不应再收到事件,却收到: {ev:?}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {}
        }
    }

    /// 把事件克隆进通道的订阅处理器(测试惯用件)。
    fn channel_handler(tx: mpsc::Sender<Event>) -> SharedHandler {
        Arc::new(move |event: &Event| -> Result<(), String> {
            let _ = tx.send(event.clone());
            Ok(())
        })
    }

    // ------------------------------ Event ------------------------------

    #[test]
    fn test_new_event_default_fields() {
        let ev = Event::new("user.created", Some(r#"{"k":"v"}"#.to_string()));
        assert!(!ev.id.is_empty(), "事件 ID 必须自动生成");
        assert_eq!(ev.event_type, "user.created");
        assert_eq!(ev.data(), Some(r#"{"k":"v"}"#));
        assert_ne!(ev.timestamp, UNIX_EPOCH, "时间戳必须自动填充");
        assert_eq!(ev.priority, 0);
        assert!(ev.metadata.is_empty(), "metadata 必须初始化为空表");
    }

    #[test]
    fn test_event_builder_chaining() {
        let ev = Event::new("builder", None)
            .with_source("test-source")
            .with_priority(7)
            .with_metadata("trace", "abc");
        assert_eq!(ev.source, "test-source");
        assert_eq!(ev.priority, 7);
        assert_eq!(ev.metadata.get("trace").map(String::as_str), Some("abc"));
    }

    #[test]
    fn test_event_data_get_set() {
        // 上游 GetData 的 JSON 往返在本移植中简化为文本直存直取(无 serde,
        // 模块头第 3 条):载荷原样携带,由消费方解析。
        let payload = r#"{"emailId":"email-1","from":"a@example.com","subject":"hi"}"#;
        let mut ev = Event::new("email.received", Some(payload.to_string()));
        assert_eq!(ev.data(), Some(payload), "JSON 文本必须原样保留");

        ev.set_data(None);
        assert_eq!(ev.data(), None, "清空载荷后取值应为 None");

        ev.set_data(Some("42".to_string()));
        assert_eq!(ev.data(), Some("42"));
    }

    #[test]
    fn test_event_clone_deep_copy_metadata() {
        let origin = Event::new("clone.me", Some("payload".to_string()))
            .with_source("src")
            .with_priority(3)
            .with_metadata("k1", "v1");

        let mut clone = origin.clone();
        clone.metadata.insert("k2".to_string(), "v2".to_string());
        clone.metadata.remove("k1");
        assert_eq!(
            origin.metadata.get("k1").map(String::as_str),
            Some("v1"),
            "原件元数据不得被克隆篡改"
        );

        assert_eq!(origin.id, clone.id);
        assert_eq!(origin.event_type, clone.event_type);
        assert_eq!(origin.source, clone.source);
        assert_eq!(origin.data, clone.data);
        assert_eq!(origin.priority, clone.priority);
        assert_eq!(origin.timestamp, clone.timestamp);
    }

    #[test]
    fn test_event_id_unique_and_shaped() {
        let first = Event::new("id.check", None);
        // 14 位日期时间 + '.' + 6 位微秒 + 8 位随机后缀 = 29 字符。
        assert_eq!(first.id.len(), 21 + 8);
        assert!(
            first
                .id
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c.is_ascii_lowercase()),
            "ID 只能含数字/点/小写字母数字后缀: {}",
            first.id
        );
        let mut seen = HashSet::new();
        for _ in 0..2_000 {
            assert!(seen.insert(generate_event_id()), "事件 ID 不得重复");
        }
    }

    #[test]
    fn test_format_timestamp_utc() {
        assert_eq!(format_timestamp(UNIX_EPOCH), "19700101000000.000000");
        // 2000-03-01 00:00:00 UTC = 951868800s,覆盖闰月分支。
        let t = UNIX_EPOCH + Duration::from_secs(951_868_800);
        assert_eq!(format_timestamp(t), "20000301000000.000000");
    }

    // ------------------------------ Handler ------------------------------

    #[test]
    fn test_handler_closure_adapter() {
        // 闭包经 blanket impl 直接成为处理器(上游 EventHandlerFunc)。
        let called = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&called);
        let f: SharedHandler = Arc::new(move |ev: &Event| -> Result<(), String> {
            counter.fetch_add(1, Ordering::Relaxed);
            assert_eq!(ev.event_type, "adapted");
            Err("boom".to_string())
        });
        let err = f.handle(&Event::new("adapted", None)).unwrap_err();
        assert_eq!(err, "boom", "返回值必须原样透传");
        assert_eq!(
            called.load(Ordering::Relaxed),
            1,
            "适配器必须转发到内层函数"
        );
    }

    #[test]
    fn test_async_handler_returns_immediately_and_runs_in_background() {
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        let async_h = AsyncHandler::new(channel_handler(tx));
        async_h
            .handle(&Event::new("async", None))
            .expect("异步包装必须立即返回成功");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "异步包装必须立即返回,不等待内层执行"
        );
        assert_eq!(wait_event(&rx).event_type, "async", "内层必须于后台执行");
    }

    #[test]
    fn test_chain_handler_runs_all_in_order() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let mk = |tag: &'static str, sink: Arc<Mutex<Vec<&'static str>>>| -> SharedHandler {
            Arc::new(move |_: &Event| -> Result<(), String> {
                sink.lock().unwrap().push(tag);
                Ok(())
            })
        };
        let chain = ChainHandler::new(vec![
            mk("first", Arc::clone(&order)),
            mk("second", Arc::clone(&order)),
            mk("third", Arc::clone(&order)),
        ]);
        chain.handle(&Event::new("chain", None)).unwrap();
        assert_eq!(
            *order.lock().unwrap(),
            vec!["first", "second", "third"],
            "链式处理器必须按声明顺序执行"
        );
    }

    #[test]
    fn test_chain_handler_short_circuits_on_first_error() {
        let second_called = Arc::new(AtomicUsize::new(0));
        let flag = Arc::clone(&second_called);
        let chain = ChainHandler::new(vec![
            Arc::new(|_: &Event| -> Result<(), String> { Err("boom".to_string()) }),
            Arc::new(move |_: &Event| -> Result<(), String> {
                flag.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }),
        ]);
        let err = chain.handle(&Event::new("chain.err", None)).unwrap_err();
        assert_eq!(err, "boom", "成员错误必须透传");
        assert_eq!(
            second_called.load(Ordering::Relaxed),
            0,
            "首个错误后必须短路,后续成员不得执行"
        );
    }

    #[test]
    fn test_filter_handler_filter_decides_invocation() {
        let invoked = Arc::new(AtomicUsize::new(0));
        let inner_pass = {
            let invoked = Arc::clone(&invoked);
            Arc::new(move |_: &Event| -> Result<(), String> {
                invoked.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        };
        let passing = FilterHandler::new(Arc::new(|_: &Event| true), inner_pass);
        passing.handle(&Event::new("pass", None)).unwrap();
        assert_eq!(
            invoked.load(Ordering::Relaxed),
            1,
            "谓词为真时内层必须被调用"
        );

        let inner_block = {
            let invoked = Arc::clone(&invoked);
            Arc::new(move |_: &Event| -> Result<(), String> {
                invoked.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        };
        let blocking = FilterHandler::new(Arc::new(|_: &Event| false), inner_block);
        blocking
            .handle(&Event::new("blocked", None))
            .expect("谓词为假时必须静默返回成功");
        assert_eq!(
            invoked.load(Ordering::Relaxed),
            1,
            "谓词为假时内层不得被调用"
        );
    }

    // ------------------------------ 总线 ------------------------------

    #[test]
    fn test_subscribe_and_publish_sync_delivery() {
        let bus = new_bus();
        let (tx, rx) = mpsc::channel();
        bus.subscribe("unit.test", channel_handler(tx)).unwrap();

        let event = Event::new("unit.test", Some(r#"{"payload":1}"#.to_string()))
            .with_source("unit-source");
        bus.publish(&event).unwrap();

        let ev = wait_event(&rx);
        assert_eq!(ev.event_type, "unit.test");
        assert_eq!(ev.source, "unit-source");
        assert_eq!(ev.data(), Some(r#"{"payload":1}"#));
        bus.close().unwrap();
    }

    #[test]
    fn test_publish_all_handlers_receive() {
        let bus = new_bus();
        const SUBS: usize = 3;
        let mut receivers = Vec::new();
        for _ in 0..SUBS {
            let (tx, rx) = mpsc::channel();
            receivers.push(rx);
            bus.subscribe("fanout", channel_handler(tx)).unwrap();
        }
        bus.publish(&Event::new("fanout", None)).unwrap();
        for rx in &receivers {
            assert_eq!(wait_event(rx).event_type, "fanout");
        }
        bus.close().unwrap();
    }

    #[test]
    fn test_publish_unknown_topic_no_handlers() {
        let bus = new_bus();
        bus.publish(&Event::new("nobody-listens", None))
            .expect("未知主题(无订阅者)发布不应报错");
        bus.close().unwrap();
    }

    #[test]
    fn test_publish_handler_error_does_not_fail_publish() {
        let bus = new_bus();
        bus.subscribe(
            "flaky",
            Arc::new(|_: &Event| -> Result<(), String> { Err("flaky failure".to_string()) }),
        )
        .unwrap();
        let (tx, rx) = mpsc::channel();
        bus.subscribe("flaky", channel_handler(tx)).unwrap();

        bus.publish(&Event::new("flaky", None))
            .expect("单个处理器失败不得导致发布失败");
        wait_event(&rx); // 第二个处理器仍须执行
        bus.close().unwrap();
    }

    #[test]
    fn test_unsubscribe_stops_delivery() {
        let bus = new_bus();
        let (tx, rx) = mpsc::channel();
        let handler = channel_handler(tx);
        bus.subscribe("gone", Arc::clone(&handler)).unwrap();
        assert_eq!(bus.subscriber_count("gone"), 1);

        bus.unsubscribe("gone", &handler).unwrap();
        assert_eq!(bus.subscriber_count("gone"), 0);

        bus.publish(&Event::new("gone", None)).unwrap();
        expect_no_event(&rx);

        let err = bus.unsubscribe("gone", &handler).unwrap_err();
        assert!(
            err.contains("handler not found"),
            "已移除的处理器再次退订必须报错: {err}"
        );
        bus.close().unwrap();
    }

    #[test]
    fn test_unsubscribe_unknown_topic_or_handler() {
        let bus = new_bus();
        let never: SharedHandler = Arc::new(|_: &Event| -> Result<(), String> { Ok(()) });
        let err = bus.unsubscribe("ghost-topic", &never).unwrap_err();
        assert!(err.contains("handler not found"));
        bus.close().unwrap();
    }

    #[test]
    fn test_unsubscribe_removes_single_registration() {
        let bus = new_bus();
        let handler: SharedHandler = Arc::new(|_: &Event| -> Result<(), String> { Ok(()) });
        bus.subscribe("dup", Arc::clone(&handler)).unwrap();
        bus.subscribe("dup", Arc::clone(&handler)).unwrap();
        assert_eq!(bus.subscriber_count("dup"), 2);

        bus.unsubscribe("dup", &handler).unwrap();
        assert_eq!(bus.subscriber_count("dup"), 1, "一次退订只移除一份注册");
        bus.unsubscribe("dup", &handler).unwrap();
        assert_eq!(bus.subscriber_count("dup"), 0);
        bus.close().unwrap();
    }

    #[test]
    fn test_subscribe_async_async_delivery() {
        let bus = new_bus();
        let (tx, rx) = mpsc::channel();
        bus.subscribe_async("async.topic", channel_handler(tx))
            .unwrap();
        assert_eq!(bus.subscriber_count("async.topic"), 1);

        bus.publish(&Event::new("async.topic", None)).unwrap();
        assert_eq!(wait_event(&rx).event_type, "async.topic");
        bus.close().unwrap();
    }

    #[test]
    fn test_subscribe_once_fires_once_and_auto_removed() {
        let bus = new_bus();
        let (tx, rx) = mpsc::channel();
        bus.subscribe_once("once.topic", channel_handler(tx))
            .unwrap();
        assert_eq!(
            bus.subscriber_count("once.topic"),
            1,
            "单次订阅在触发前计入订阅数"
        );

        bus.publish(&Event::new("once.topic", None)).unwrap();
        wait_event(&rx); // 首次发布必须触达
        assert_eq!(
            bus.subscriber_count("once.topic"),
            0,
            "单次订阅执行后必须被自动移除"
        );

        bus.publish(&Event::new("once.topic", None)).unwrap();
        expect_no_event(&rx); // 后续发布不得再触达
        bus.close().unwrap();
    }

    #[test]
    fn test_subscribe_once_error_handler_still_removed() {
        let bus = new_bus();
        bus.subscribe_once(
            "once.err",
            Arc::new(|_: &Event| -> Result<(), String> { Err("boom".to_string()) }),
        )
        .unwrap();
        assert_eq!(bus.subscriber_count("once.err"), 1);

        bus.publish(&Event::new("once.err", None))
            .expect("once 处理器出错不得导致发布失败");
        assert_eq!(
            bus.subscriber_count("once.err"),
            0,
            "出错的单次订阅也必须被执行后移除"
        );
        bus.close().unwrap();
    }

    #[test]
    fn test_subscribe_once_cannot_be_unsubscribed() {
        let bus = new_bus();
        let handler: SharedHandler = Arc::new(|_: &Event| -> Result<(), String> { Ok(()) });
        bus.subscribe_once("once.forever", Arc::clone(&handler))
            .unwrap();

        let err = bus.unsubscribe("once.forever", &handler).unwrap_err();
        assert!(
            err.contains("handler not found"),
            "退订不得移除单次订阅: {err}"
        );
        assert_eq!(bus.subscriber_count("once.forever"), 1);
        bus.close().unwrap();
    }

    #[test]
    fn test_publish_async_delivers_in_background() {
        let bus = new_bus();
        let (tx, rx) = mpsc::channel();
        bus.subscribe("bg.topic", channel_handler(tx)).unwrap();

        bus.clone()
            .publish_async(Event::new("bg.topic", None))
            .expect("异步发布必须立即成功返回");
        assert_eq!(wait_event(&rx).event_type, "bg.topic");
        bus.close().unwrap();
    }

    #[test]
    fn test_get_subscriber_count_per_type() {
        let bus = new_bus();
        let handler: SharedHandler = Arc::new(|_: &Event| -> Result<(), String> { Ok(()) });
        bus.subscribe("a", Arc::clone(&handler)).unwrap();
        bus.subscribe("a", Arc::clone(&handler)).unwrap();
        bus.subscribe_once("b", Arc::clone(&handler)).unwrap();

        assert_eq!(bus.subscriber_count("a"), 2);
        assert_eq!(bus.subscriber_count("b"), 1);
        assert_eq!(bus.subscriber_count("c"), 0);
        bus.close().unwrap();
    }

    #[test]
    fn test_get_event_types_unions_regular_and_once() {
        let bus = new_bus();
        let handler: SharedHandler = Arc::new(|_: &Event| -> Result<(), String> { Ok(()) });
        bus.subscribe("regular.topic", Arc::clone(&handler))
            .unwrap();
        bus.subscribe_once("once.topic", Arc::clone(&handler))
            .unwrap();

        assert_eq!(
            bus.event_types(),
            vec!["once.topic".to_string(), "regular.topic".to_string()],
            "事件类型枚举应包含普通与单次订阅的主题"
        );
        bus.close().unwrap();
    }

    #[test]
    fn test_publish_async_on_closed_bus_inner_error_swallowed() {
        let bus = new_bus();
        bus.close().unwrap();

        bus.clone()
            .publish_async(Event::new("closed", None))
            .expect("异步发布外壳必须无条件返回成功");
        // 仅让步给后台线程走完内部错误路径,不承担断言时序职责(上游同此)。
        thread::sleep(Duration::from_millis(50));
    }

    #[test]
    fn test_close_rejects_further_operations() {
        let bus = new_bus();
        let handler: SharedHandler = Arc::new(|_: &Event| -> Result<(), String> { Ok(()) });
        bus.subscribe("close.me", Arc::clone(&handler)).unwrap();
        bus.subscribe_once("close.me", Arc::clone(&handler))
            .unwrap();
        assert_eq!(bus.subscriber_count("close.me"), 2);

        bus.close().unwrap();

        assert_eq!(bus.subscriber_count("close.me"), 0, "关闭后订阅表必须清空");
        assert!(bus.event_types().is_empty());

        let err = bus.subscribe("close.me", Arc::clone(&handler)).unwrap_err();
        assert!(
            err.contains("event bus is closed"),
            "关闭后订阅必须被拒绝: {err}"
        );
        let err = bus
            .subscribe_once("close.me", Arc::clone(&handler))
            .unwrap_err();
        assert!(err.contains("event bus is closed"));

        let err = bus.publish(&Event::new("close.me", None)).unwrap_err();
        assert!(
            err.contains("event bus is closed"),
            "关闭后发布必须被拒绝: {err}"
        );

        let err = bus.close().unwrap_err();
        assert!(err.contains("already closed"), "重复关闭必须报错: {err}");
    }

    // ------------------------------ 中间件 ------------------------------

    #[test]
    fn test_logging_middleware_passes_through_result() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let mw = logging_middleware(collecting_logger(&sink));
        let ev = Event::new("log.me", None);

        let succeed = mw(Arc::new(|_: &Event| -> Result<(), String> { Ok(()) }));
        succeed.handle(&ev).unwrap();
        let failing = mw(Arc::new(|_: &Event| -> Result<(), String> {
            Err("bad".to_string())
        }));
        assert_eq!(
            failing.handle(&ev).unwrap_err(),
            "bad",
            "失败路径必须原样透传错误"
        );

        let logs = sink.lock().unwrap();
        assert!(
            logs.iter()
                .any(|l| l.contains("Handling event: type=log.me")),
            "处理前必须发日志: {logs:?}"
        );
        assert!(logs
            .iter()
            .any(|l| l.contains("Successfully handled event")));
        assert!(logs.iter().any(|l| l.contains("Error handling event")));
    }

    #[test]
    fn test_recovery_middleware_converts_panic_to_error() {
        let mw = recovery_middleware();
        let ev = Event::new("panic.me", None);

        // 注意:panic! 会先经默认 hook 打到 stderr 再被捕获,测试输出里的
        // panic 噪音属预期(catch_unwind 已兜住,不影响结果)。
        let panicking = mw(Arc::new(|_: &Event| -> Result<(), String> {
            panic!("boom")
        }));
        let err = panicking.handle(&ev).unwrap_err();
        assert_eq!(
            err,
            MiddlewareError::Panic {
                value: "boom".to_string()
            }
            .to_string(),
            "panic 必须转为可识别的错误返回"
        );
        assert!(
            err.starts_with("panic in event handler"),
            "错误消息前缀与上游一致"
        );

        let calm = mw(Arc::new(|_: &Event| -> Result<(), String> {
            Err("pass-through".to_string())
        }));
        assert_eq!(
            calm.handle(&ev).unwrap_err(),
            "pass-through",
            "无 panic 时原错误必须透传而非吞掉"
        );
    }

    #[test]
    fn test_recovery_middleware_with_logger_reports_panic() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let mw = recovery_middleware_with_logger(collecting_logger(&sink));
        let ev = Event::new("panic.log", None);
        let panicking = mw(Arc::new(|_: &Event| -> Result<(), String> {
            panic!("inner boom")
        }));
        assert!(panicking.handle(&ev).is_err());
        let logs = sink.lock().unwrap();
        assert_eq!(logs.len(), 1, "panic 日志应恰好一条: {logs:?}");
        assert!(
            logs[0].contains("panic.log") && logs[0].contains("inner boom"),
            "日志应带事件类型与 panic 值: {}",
            logs[0]
        );
    }

    #[test]
    fn test_timeout_middleware_times_out_slow_handler() {
        let mw = timeout_middleware(Duration::from_millis(50));
        let ev = Event::new("too.slow", None);

        let slow = mw(Arc::new(|_: &Event| -> Result<(), String> {
            thread::sleep(Duration::from_millis(500));
            Ok(())
        }));
        let start = Instant::now();
        let err = slow.handle(&ev).unwrap_err();
        assert!(
            start.elapsed() < Duration::from_millis(400),
            "超时必须在阈值附近返回而非等满内层"
        );
        assert_eq!(
            err,
            MiddlewareError::Timeout {
                event_id: ev.id.clone(),
                event_type: "too.slow".to_string(),
                timeout: Duration::from_millis(50),
            }
            .to_string()
        );
        assert!(
            err.starts_with("event handling timeout"),
            "错误消息前缀与上游一致"
        );
    }

    #[test]
    fn test_timeout_middleware_passes_through_fast_handler() {
        let mw = timeout_middleware(Duration::from_secs(1));
        let fast = mw(Arc::new(|_: &Event| -> Result<(), String> { Ok(()) }));
        fast.handle(&Event::new("fast", None)).unwrap();
    }

    #[test]
    fn test_retry_middleware_exhausts_retries() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        let mw = retry_middleware(2, Duration::from_millis(1));
        let handler = mw(Arc::new(move |_: &Event| -> Result<(), String> {
            counter.fetch_add(1, Ordering::Relaxed);
            Err("always fails".to_string())
        }));

        let err = handler
            .handle(&Event::new("always.fails", None))
            .unwrap_err();
        assert_eq!(err, "always fails", "重试耗尽后必须返回最后的错误");
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            3,
            "maxRetries=2 意味着共尝试 1+2 次"
        );
    }

    #[test]
    fn test_retry_middleware_stops_on_success() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        let mw = retry_middleware(5, Duration::from_millis(1));
        let handler = mw(Arc::new(move |_: &Event| -> Result<(), String> {
            let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
            if n < 2 {
                Err("first fails".to_string())
            } else {
                Ok(())
            }
        }));

        handler
            .handle(&Event::new("succeeds.second", None))
            .expect("第二次尝试成功必须返回成功");
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            2,
            "第二次成功后必须停止重试"
        );
    }

    #[test]
    fn test_metrics_middleware_passes_through_result() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let mw = metrics_middleware(collecting_logger(&sink));

        let succeed = mw(Arc::new(|_: &Event| -> Result<(), String> { Ok(()) }));
        succeed.handle(&Event::new("ok", None)).unwrap();
        let failing = mw(Arc::new(|_: &Event| -> Result<(), String> {
            Err("bad".to_string())
        }));
        assert_eq!(failing.handle(&Event::new("err", None)).unwrap_err(), "bad");

        let logs = sink.lock().unwrap();
        assert_eq!(logs.len(), 2, "指标中间件只观测不改写结果: {logs:?}");
        assert!(logs[0].contains("type=ok") && logs[0].contains("success=true"));
        assert!(logs[1].contains("success=false"));
    }

    #[test]
    fn test_chain_composes_in_order() {
        // 首参数最外层:Recovery 在最外层时必须兜住内层 panic;
        // 调换顺序则 panic 会穿透到调用方(上游 TestChain_ComposesInOrder)。
        let composed = chain(vec![
            recovery_middleware(),
            logging_middleware(noop_logger()),
        ]);
        let wrapped = composed(Arc::new(|_: &Event| -> Result<(), String> {
            panic!("inner boom")
        }));

        let err = wrapped
            .handle(&Event::new("chain.panic", None))
            .unwrap_err();
        assert_eq!(
            err,
            MiddlewareError::Panic {
                value: "inner boom".to_string()
            }
            .to_string(),
            "Recovery 在最外层时必须兜住 panic"
        );
    }

    // ------------------------------ 管理器 ------------------------------

    #[test]
    fn test_manager_global_bus_aliases() {
        let m = Manager::new();
        let global = m.global();
        assert!(
            Arc::ptr_eq(&m.get_bus(""), &global),
            "空名必须是全局总线的别名"
        );
        assert!(
            Arc::ptr_eq(&m.get_bus("global"), &global),
            "\"global\" 必须是全局总线的别名"
        );
        m.close().unwrap();
    }

    #[test]
    fn test_manager_get_bus_creates_and_caches() {
        let m = Manager::new();
        let first = m.get_bus("metrics");
        let second = m.get_bus("metrics");
        assert!(Arc::ptr_eq(&first, &second), "同名总线必须缓存复用同一实例");
        assert!(
            !Arc::ptr_eq(&first, &m.global()),
            "具名总线不得与全局总线混同"
        );

        let stats = m.get_stats();
        assert_eq!(stats.total_buses, 1, "仅应创建一个具名总线");
        m.close().unwrap();
    }

    #[test]
    fn test_manager_subscribe_publish_round_trip_on_named_bus() {
        let m = Manager::new();
        let (tx, rx) = mpsc::channel();
        m.subscribe("jobs", "job.done", channel_handler(tx))
            .unwrap();

        m.publish("jobs", &Event::new("job.done", None)).unwrap();
        assert_eq!(wait_event(&rx).event_type, "job.done");
        m.close().unwrap();
    }

    #[test]
    fn test_manager_global_round_trip() {
        let m = Manager::new();
        let (alias_tx, alias_rx) = mpsc::channel();
        let (global_tx, global_rx) = mpsc::channel();
        m.subscribe("", "sys.echo", channel_handler(alias_tx))
            .unwrap();
        m.subscribe_global("sys.echo", channel_handler(global_tx))
            .unwrap();

        m.publish_global(&Event::new("sys.echo", None)).unwrap();
        m.publish("", &Event::new("sys.echo", None)).unwrap();

        assert_eq!(wait_event(&alias_rx).event_type, "sys.echo");
        assert_eq!(wait_event(&global_rx).event_type, "sys.echo");
        m.close().unwrap();
    }

    #[test]
    fn test_manager_publish_to_subscriberless_bus() {
        let m = Manager::new();
        m.publish("lazy.bus", &Event::new("nobody", None))
            .expect("发布到无订阅者的总线应成功(总线惰性创建)");
        m.close().unwrap();
    }

    #[test]
    fn test_manager_get_stats_structure() {
        let m = Manager::new();
        let handler: SharedHandler = Arc::new(|_: &Event| -> Result<(), String> { Ok(()) });
        m.subscribe("telemetry", "telemetry.beat", Arc::clone(&handler))
            .unwrap();
        m.subscribe_global("global.beat", Arc::clone(&handler))
            .unwrap();

        let stats = m.get_stats();
        assert_eq!(stats.total_buses, 1);
        assert_eq!(
            stats.buses.get("telemetry"),
            Some(&vec!["telemetry.beat".to_string()]),
            "具名总线明细应反映订阅主题"
        );
        assert_eq!(
            stats.global_bus,
            vec!["global.beat".to_string()],
            "全局总线明细应反映订阅主题"
        );
        m.close().unwrap();
    }

    #[test]
    fn test_manager_close_closes_all_buses() {
        let m = Manager::new();
        let stale = m.get_bus("stale");
        stale.close().expect("预先单独关闭一个具名总线");
        // 全局总线也预先关闭:Manager::close 对已关闭总线的错误必须逐一容忍。
        m.global().close().unwrap();

        m.close().expect("已关闭总线应被容忍,close 整体仍返回成功");

        let stats = m.get_stats();
        assert_eq!(stats.total_buses, 0, "关闭后具名总线统计必须归零");
        assert!(stats.buses.is_empty());

        let err = m
            .subscribe_global(
                "after.close",
                Arc::new(|_: &Event| -> Result<(), String> { Ok(()) }),
            )
            .unwrap_err();
        assert!(
            err.contains("event bus is closed"),
            "全局总线已关闭,订阅必须被拒绝: {err}"
        );
    }
}
