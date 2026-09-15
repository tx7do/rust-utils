//! 关联数据回填工具:把按 ID 批量取到的
//! 资源填充回结果对象或对象树,附带回退式并行执行器。
//!
//! 典型场景:列表页查出 N 条主对象,再按 `user_id` 批量取用户,
//! 一次性回填,避免 N+1 查询。
//!
//! ```
//! use rust_utils::aggregator::populate;
//! use std::collections::HashMap;
//!
//! struct Order { id: u32, user_name: Option<String> }
//!
//! let mut orders = vec![Order { id: 1, user_name: None }];
//! let users: HashMap<u32, String> = [(1, "张三".to_string())].into();
//!
//! populate(
//!     &mut orders,
//!     &users,
//!     |order| order.id,
//!     |order, name| order.user_name = Some(name),
//! );
//! assert_eq!(orders[0].user_name.as_deref(), Some("张三"));
//! ```

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

/// 扁平列表回填:按 `id_getter` 从 `data` 取值,命中则调用 `setter`。
pub fn populate<K, T, R>(
    items: &mut [R],
    data: &HashMap<K, T>,
    id_getter: impl Fn(&R) -> K,
    setter: impl Fn(&mut R, T),
) where
    K: Eq + Hash,
    T: Clone,
{
    if items.is_empty() || data.is_empty() {
        return;
    }
    for item in items {
        if let Some(val) = data.get(&id_getter(item)) {
            setter(item, val.clone());
        }
    }
}

/// 单个对象回填。
pub fn populate_one<K, T, R>(
    item: &mut R,
    data: &HashMap<K, T>,
    id_getter: impl Fn(&R) -> K,
    setter: impl Fn(&mut R, T),
) where
    K: Eq + Hash,
    T: Clone,
{
    if let Some(val) = data.get(&id_getter(item)) {
        setter(item, val.clone());
    }
}

/// 树状结构回填:`children` 返回节点的可变子节点切片。
///
/// ```
/// use rust_utils::aggregator::populate_tree;
/// use std::collections::HashMap;
///
/// #[derive(Debug)]
/// struct Node { id: u32, label: Option<String>, children: Vec<Node> }
///
/// let mut roots = [Node {
///     id: 1, label: None,
///     children: vec![Node { id: 2, label: None, children: vec![] }],
/// }];
/// let labels: HashMap<u32, String> =
///     [(1, "根".into()), (2, "子".into())].into();
///
/// populate_tree(
///     &mut roots, &labels,
///     |n: &Node| n.id,
///     |n, label| n.label = Some(label),
///     |n| &mut n.children,
/// );
/// assert_eq!(roots[0].children[0].label.as_deref(), Some("子"));
/// ```
pub fn populate_tree<K, T, R>(
    items: &mut [R],
    data: &HashMap<K, T>,
    id_getter: impl Fn(&R) -> K,
    setter: impl Fn(&mut R, T),
    children: impl Fn(&mut R) -> &mut [R],
) where
    K: Eq + Hash,
    T: Clone,
{
    populate_tree_inner(items, data, &id_getter, &setter, &children);
}

fn populate_tree_inner<K, T, R>(
    items: &mut [R],
    data: &HashMap<K, T>,
    id_getter: &impl Fn(&R) -> K,
    setter: &impl Fn(&mut R, T),
    children: &impl Fn(&mut R) -> &mut [R],
) where
    K: Eq + Hash,
    T: Clone,
{
    if items.is_empty() || data.is_empty() {
        return;
    }
    for item in items {
        if let Some(val) = data.get(&id_getter(item)) {
            setter(item, val.clone());
        }
        let child_list = children(item);
        if !child_list.is_empty() {
            populate_tree_inner(child_list, data, id_getter, setter, children);
        }
    }
}

/// 扁平列表回填(一对多):`id_getter` 返回多个 ID,命中的值按 ID
/// 顺序收集成 `Vec<T>` 后经 `setter` 填回;没有任何命中的项不调用 setter。
pub fn populate_multi<K, T, R>(
    items: &mut [R],
    data: &HashMap<K, T>,
    id_list_getter: impl Fn(&R) -> Vec<K>,
    setter: impl Fn(&mut R, Vec<T>),
) where
    K: Eq + Hash,
    T: Clone,
{
    if items.is_empty() || data.is_empty() {
        return;
    }
    for item in items {
        let ids = id_list_getter(item);
        if ids.is_empty() {
            continue;
        }
        let vals: Vec<T> = ids.iter().filter_map(|id| data.get(id).cloned()).collect();
        if !vals.is_empty() {
            setter(item, vals);
        }
    }
}

/// 树状结构回填(一对多)。
pub fn populate_tree_multi<K, T, R>(
    items: &mut [R],
    data: &HashMap<K, T>,
    id_list_getter: impl Fn(&R) -> Vec<K>,
    setter: impl Fn(&mut R, Vec<T>),
    children: impl Fn(&mut R) -> &mut [R],
) where
    K: Eq + Hash,
    T: Clone,
{
    populate_tree_multi_inner(items, data, &id_list_getter, &setter, &children);
}

fn populate_tree_multi_inner<K, T, R>(
    items: &mut [R],
    data: &HashMap<K, T>,
    id_list_getter: &impl Fn(&R) -> Vec<K>,
    setter: &impl Fn(&mut R, Vec<T>),
    children: &impl Fn(&mut R) -> &mut [R],
) where
    K: Eq + Hash,
    T: Clone,
{
    if items.is_empty() || data.is_empty() {
        return;
    }
    for item in items {
        let ids = id_list_getter(item);
        if !ids.is_empty() {
            let vals: Vec<T> = ids.iter().filter_map(|id| data.get(id).cloned()).collect();
            if !vals.is_empty() {
                setter(item, vals);
            }
        }
        let child_list = children(item);
        if !child_list.is_empty() {
            populate_tree_multi_inner(child_list, data, id_list_getter, setter, children);
        }
    }
}

/// 并行任务:返回 `Ok(())` 表示成功,`Err` 为错误。
/// 任务可能被重试多次,因此是 `Fn` 而非 `FnOnce`。
pub type ParallelTask =
    Box<dyn Fn() -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send>;

/// 并行执行的错误。
#[derive(Debug)]
pub enum ParallelError {
    /// 整体超时(任务线程继续在后台运行)。
    Timeout,
    /// 某个任务最终失败(所有重试耗尽),保留首个错误。
    Task(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for ParallelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParallelError::Timeout => write!(f, "parallel execution timeout"),
            ParallelError::Task(e) => write!(f, "parallel fetcher failed: {e}"),
        }
    }
}

impl std::error::Error for ParallelError {}

/// 并行执行选项:并发上限、超时、重试次数。
#[derive(Debug, Clone)]
pub struct ParallelOptions {
    /// 最大并发数(默认 20)。
    pub limit: usize,
    /// 整体超时;`None` 表示不限。
    pub timeout: Option<Duration>,
    /// 每个任务失败后的重试次数(默认 0)。
    pub retry: u32,
}

impl Default for ParallelOptions {
    fn default() -> Self {
        ParallelOptions {
            limit: 20,
            timeout: None,
            retry: 0,
        }
    }
}

/// 并行执行多个任务;任一任务最终失败即返回该错误(但会等所有任务结束),
/// 整体超时返回 [`ParallelError::Timeout`]。
pub fn execute_parallel(
    tasks: Vec<ParallelTask>,
    options: ParallelOptions,
) -> Result<(), ParallelError> {
    use std::collections::VecDeque;
    use std::sync::mpsc::RecvTimeoutError;
    use std::sync::{Condvar, Mutex as StdMutex};
    use std::time::Instant;

    if tasks.is_empty() {
        return Ok(());
    }
    let limit = if options.limit == 0 {
        20
    } else {
        options.limit
    };
    let deadline = options.timeout.map(|t| Instant::now() + t);

    let queue = Arc::new((StdMutex::new(VecDeque::from(tasks)), Condvar::new()));
    let (tx, rx) =
        std::sync::mpsc::channel::<Result<(), Box<dyn std::error::Error + Send + Sync>>>();
    let total = {
        let (q, _) = &*queue;
        q.lock().unwrap().len()
    };
    let worker_count = limit.min(total);

    for _ in 0..worker_count {
        let queue = queue.clone();
        let tx = tx.clone();
        let retry = options.retry;
        std::thread::spawn(move || loop {
            let task = {
                let (q, _cv) = &*queue;
                let mut guard = q.lock().unwrap();
                match guard.pop_front() {
                    Some(t) => t,
                    None => return, // 队列空,收工
                }
            };

            let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
            for attempt in 0..=retry {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(&task)) {
                    Ok(Ok(())) => {
                        last_err = None;
                        break;
                    }
                    Ok(Err(e)) => last_err = Some(e),
                    // panic 转错误
                    Err(p) => {
                        last_err = Some(Box::new(std::io::Error::other(format!(
                            "parallel fetcher panic: {p:?}"
                        ))))
                    }
                }
                if attempt < retry {
                    backoff_wait(attempt);
                }
            }
            let _ = tx.send(match last_err {
                None => Ok(()),
                Some(e) => Err(e),
            });
        });
    }
    drop(tx);

    let mut remaining = total;
    let mut first_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    loop {
        if remaining == 0 {
            break;
        }
        let wait = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        match wait {
            Some(zero) if zero.is_zero() => return Err(ParallelError::Timeout),
            Some(d) => match rx.recv_timeout(d) {
                Ok(res) => {
                    remaining -= 1;
                    if let Err(e) = res {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => return Err(ParallelError::Timeout),
                Err(RecvTimeoutError::Disconnected) => break,
            },
            None => match rx.recv() {
                Ok(res) => {
                    remaining -= 1;
                    if let Err(e) = res {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    }
                }
                Err(_) => break,
            },
        }
    }

    match first_err {
        Some(e) => Err(ParallelError::Task(e)),
        None => Ok(()),
    }
}

/// 指数退避等待,带抖动(20ms 起步、2s 封顶)。
fn backoff_wait(attempt: u32) {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const BASE_DELAY: Duration = Duration::from_millis(20);
    const MAX_DELAY: Duration = Duration::from_secs(2);

    let delay = if attempt >= 30 {
        MAX_DELAY
    } else {
        BASE_DELAY.saturating_mul(1u32 << attempt).min(MAX_DELAY)
    };
    // 非加密随机抖动:[delay/2, delay/2 + delay)
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(7);
    let jitter = nanos % delay.as_millis().max(1) as u64;
    std::thread::sleep(delay / 2 + Duration::from_millis(jitter));
}

// ---------------------------------------------------------------------------
// DataLoader 风格的缓存批量加载器(同步版)
// ---------------------------------------------------------------------------

/// 批量取数函数:一次拿到所有未缓存键对应的资源(取不到的键不出现
/// 在返回的映射里)。
pub type BatchFetch<K, V> = Arc<dyn Fn(&[K]) -> HashMap<K, V> + Send + Sync>;

/// 缓存式批量加载器:相同键只取一次,多个未命中键合并为一次批量取数
/// (避免 N+1 查询)。
///
/// 与异步 DataLoader 的请求级自动批处理不同,这里是显式的同步批量
/// 加载:批处理由调用方触发(`load_many`),不做后台窗口合并。
/// 取不到的键会记为"已查询缺失",在 [`clear`](Self::clear) 之前不再
/// 触发取数(与 DataLoader 的错误缓存语义一致)。
///
/// ```
/// use rust_utils::aggregator::Loader;
/// use std::sync::atomic::{AtomicUsize, Ordering};
///
/// let calls = std::sync::Arc::new(AtomicUsize::new(0));
/// let calls2 = calls.clone();
/// let loader = Loader::new(move |keys: &[u32]| {
///     calls2.fetch_add(1, Ordering::Relaxed);
///     keys.iter().map(|k| (*k, k * 10)).collect()
/// });
///
/// let got = loader.load_many(&[1, 2, 3]);
/// assert_eq!(got[&2].as_ref(), &20);
/// // 已缓存键不再触发取数
/// loader.load_many(&[2, 3]);
/// loader.load(1);
/// assert_eq!(calls.load(Ordering::Relaxed), 1);
/// ```
pub struct Loader<K, V> {
    cache: std::sync::Mutex<HashMap<K, Option<Arc<V>>>>,
    fetch: BatchFetch<K, V>,
}

impl<K, V> Loader<K, V>
where
    K: Eq + std::hash::Hash + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    /// 创建加载器,`fetch` 为批量取数函数。
    pub fn new(fetch: impl Fn(&[K]) -> HashMap<K, V> + Send + Sync + 'static) -> Self {
        Loader {
            cache: std::sync::Mutex::new(HashMap::new()),
            fetch: Arc::new(fetch),
        }
    }

    /// 批量加载:未命中(含未查询过)的键去重后一次性交给 fetch,
    /// 结果写入缓存。返回命中的键值对。
    pub fn load_many(&self, keys: &[K]) -> HashMap<K, Arc<V>> {
        let mut cache = self.cache.lock().unwrap();
        let mut seen = std::collections::HashSet::new();
        let pending: Vec<K> = keys
            .iter()
            .filter(|k| !cache.contains_key(*k) && seen.insert((*k).clone()))
            .cloned()
            .collect();
        if !pending.is_empty() {
            let mut fetched = (self.fetch)(&pending);
            for k in &pending {
                let entry = fetched.remove(k).map(Arc::new);
                cache.insert(k.clone(), entry);
            }
        }
        keys.iter()
            .filter_map(|k| {
                cache
                    .get(k)
                    .and_then(|v| v.as_ref().map(|arc| (k.clone(), arc.clone())))
            })
            .collect()
    }

    /// 单键加载;未命中时触发一次单键批量取数,缺失返回 `None`。
    pub fn load(&self, key: K) -> Option<Arc<V>> {
        self.load_many(std::slice::from_ref(&key))
            .get(&key)
            .cloned()
    }

    /// 当前缓存条目数(含已查询缺失的键)。
    pub fn cache_len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// 清空缓存(之后重新触发取数)。
    pub fn clear(&self) {
        self.cache.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod loader_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[test]
    fn test_loader_batches_and_caches() {
        let calls = Arc::new(AtomicUsize::new(0));
        let requested: Arc<Mutex<Vec<Vec<u32>>>> = Arc::new(Mutex::new(Vec::new()));

        let c2 = calls.clone();
        let r2 = requested.clone();
        let loader = Loader::new(move |keys: &[u32]| {
            c2.fetch_add(1, Ordering::Relaxed);
            r2.lock().unwrap().push(keys.to_vec());
            keys.iter().map(|k| (*k, k * 10)).collect()
        });

        let got = loader.load_many(&[1, 2, 3]);
        assert_eq!(got.len(), 3);
        assert_eq!(got[&2].as_ref(), &20);

        // 重复调用命中缓存,不触发取数
        loader.load_many(&[2, 3, 3]);
        let one = loader.load(1);
        assert_eq!(one.as_deref(), Some(&10));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(loader.cache_len(), 3);

        // 去重:同一批里的重复键只发一次
        loader.clear();
        let _ = loader.load_many(&[7, 7, 7]);
        assert_eq!(requested.lock().unwrap().last().unwrap(), &vec![7]);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_loader_missing_keys_not_refetched() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let loader = Loader::new(move |keys: &[u32]| {
            c2.fetch_add(1, Ordering::Relaxed);
            keys.iter()
                .filter(|k| **k % 2 == 0)
                .map(|k| (*k, ()))
                .collect()
        });

        assert!(loader.load(1).is_none()); // 奇数缺失
        assert!(loader.load(2).is_some());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        // 已查询缺失的键不再触发
        assert!(loader.load(1).is_none());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(loader.cache_len(), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Debug)]
    struct Order {
        id: u32,
        user_name: Option<String>,
        tags: Vec<String>,
    }

    fn orders() -> Vec<Order> {
        vec![
            Order {
                id: 1,
                user_name: None,
                tags: vec![],
            },
            Order {
                id: 2,
                user_name: None,
                tags: vec![],
            },
            Order {
                id: 3,
                user_name: None,
                tags: vec![],
            },
        ]
    }

    fn users() -> HashMap<u32, String> {
        [(1, "张三".to_string()), (2, "李四".to_string())].into()
    }

    #[test]
    fn test_populate() {
        let mut items = orders();
        populate(
            &mut items,
            &users(),
            |o| o.id,
            |o, name| o.user_name = Some(name),
        );
        assert_eq!(items[0].user_name.as_deref(), Some("张三"));
        assert_eq!(items[1].user_name.as_deref(), Some("李四"));
        assert_eq!(items[2].user_name, None);
    }

    #[test]
    fn test_populate_one() {
        let mut item = Order {
            id: 2,
            user_name: None,
            tags: vec![],
        };
        populate_one(
            &mut item,
            &users(),
            |o| o.id,
            |o, name| o.user_name = Some(name),
        );
        assert_eq!(item.user_name.as_deref(), Some("李四"));
    }

    #[test]
    fn test_populate_multi() {
        let mut items = orders();
        populate_multi(
            &mut items,
            &users(),
            |o| vec![o.id, 1], // 每单再挂一个用户1
            |o, names| o.tags = names,
        );
        assert_eq!(items[0].tags, vec!["张三", "张三"]); // 重复 ID 各取一次
        assert_eq!(items[1].tags, vec!["李四", "张三"]);
        assert_eq!(items[2].tags, vec!["张三"]);
    }

    #[test]
    fn test_populate_tree() {
        #[derive(Debug)]
        struct Node {
            id: u32,
            label: Option<String>,
            children: Vec<Node>,
        }
        let mut tree = Node {
            id: 1,
            label: None,
            children: vec![Node {
                id: 2,
                label: None,
                children: vec![Node {
                    id: 3,
                    label: None,
                    children: vec![],
                }],
            }],
        };
        let labels: HashMap<u32, String> =
            [(1, "a".into()), (2, "b".into()), (3, "c".into())].into();
        populate_tree(
            std::slice::from_mut(&mut tree),
            &labels,
            |n: &Node| n.id,
            |n, label| n.label = Some(label),
            |n| &mut n.children,
        );
        assert_eq!(tree.label.as_deref(), Some("a"));
        assert_eq!(tree.children[0].label.as_deref(), Some("b"));
        assert_eq!(tree.children[0].children[0].label.as_deref(), Some("c"));
    }

    #[test]
    fn test_populate_tree_multi() {
        #[derive(Debug)]
        struct Node {
            id: u32,
            tags: Vec<String>,
            children: Vec<Node>,
        }
        let mut tree = Node {
            id: 1,
            tags: vec![],
            children: vec![Node {
                id: 2,
                tags: vec![],
                children: vec![],
            }],
        };
        populate_tree_multi(
            std::slice::from_mut(&mut tree),
            &users(),
            |n: &Node| vec![n.id],
            |n, tags| n.tags = tags,
            |n| &mut n.children,
        );
        assert_eq!(tree.tags, vec!["张三"]);
        assert_eq!(tree.children[0].tags, vec!["李四"]);
    }

    #[test]
    fn test_execute_parallel() {
        let tasks: Vec<ParallelTask> = (0..50)
            .map(|_| Box::new(|| Ok(())) as ParallelTask)
            .collect();
        execute_parallel(
            tasks,
            ParallelOptions {
                limit: 4,
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn test_execute_parallel_with_error_and_retry() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = Arc::new(AtomicU32::new(0));
        let a = attempts.clone();
        let failing: ParallelTask = Box::new(move || {
            a.fetch_add(1, Ordering::Relaxed);
            Err("boom".into())
        });
        let ok: ParallelTask = Box::new(|| Ok(()));
        let err = execute_parallel(
            vec![failing, ok],
            ParallelOptions {
                retry: 2,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, ParallelError::Task(_)));
        assert_eq!(attempts.load(Ordering::Relaxed), 3); // 1 次原始 + 2 次重试
    }

    #[test]
    fn test_execute_parallel_timeout() {
        let slow: ParallelTask = Box::new(|| {
            std::thread::sleep(std::time::Duration::from_secs(2));
            Ok(())
        });
        let err = execute_parallel(
            vec![slow],
            ParallelOptions {
                timeout: Some(Duration::from_millis(50)),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, ParallelError::Timeout));
    }
}
