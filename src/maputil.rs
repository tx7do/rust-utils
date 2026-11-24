//! 映射表辅助函数。
//!
//! 键/值遍历 Rust 迭代器原生覆盖,这里补充常用的集合级操作。

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::RwLock;

/// 返回所有键的集合(顺序不保证)。
pub fn keys<K: Eq + Hash + Clone, V>(m: &HashMap<K, V>) -> Vec<K> {
    m.keys().cloned().collect()
}

/// 返回所有值的集合(顺序不保证)。
pub fn values<K: Eq + Hash, V: Clone>(m: &HashMap<K, V>) -> Vec<V> {
    m.values().cloned().collect()
}

/// 从左到右合并多个映射,后面的覆盖前面的同名键。
pub fn merge<K: Eq + Hash + Clone, V: Clone>(
    maps: impl IntoIterator<Item = HashMap<K, V>>,
) -> HashMap<K, V> {
    let mut out = HashMap::new();
    for m in maps {
        for (k, v) in m {
            out.insert(k, v);
        }
    }
    out
}

/// 原地删除 `keys` 中列出的键。
pub fn drop_keys<K: Eq + Hash, V>(m: &mut HashMap<K, V>, keys: &[K]) {
    for k in keys {
        m.remove(k);
    }
}

/// 过滤映射,保留谓词为真的键值对,返回新映射。
pub fn filter<K: Eq + Hash + Clone, V: Clone>(
    m: &HashMap<K, V>,
    predicate: impl Fn(&K, &V) -> bool,
) -> HashMap<K, V> {
    m.iter()
        .filter(|(k, v)| predicate(k, v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// 类型化并发映射(移植自 Go `tx7do/go-utils/maputils` 的 `SyncMap`):
/// 调用点无任何类型断言。
///
/// 语义对齐上游:键类型 `K`、值类型 `V`,`load` 缺键返回 `None`,
/// `load_or_store` 返回 `(值, 是否为既有值)`。需要迭代、快照或复杂不变量
/// 时优先普通 `HashMap` + `Mutex`/`RwLock`——本类型与上游 `sync.Map` 同样
/// 面向 append-only / 键不相交的并发负载。
///
/// 与 Go 版的差异(适配纯 `std`):
///
/// 1. 上游包 `sync.Map`(无锁读);Rust 侧以 `RwLock<HashMap>` 等价实现,
///    读多写少场景行为一致,无需第三方依赖;
/// 2. [`SyncMap::len`] 为 O(1)(`HashMap` 记账)——上游因 `sync.Map` 不记
///    尺寸只能 O(n) 数一遍;
/// 3. [`SyncMap::range`] 在读锁下顺序遍历,回调返回 `false` 提前终止;
///    回调内不得再对本表做写操作(会死锁),写场景请先收集再处理;
/// 4. 取值返回 `Option<V>`/`Vec` 克隆(锁不能跨返回值存活),`V` 需要
///    `Clone`。
///
/// ```
/// use rust_utils::maputil::SyncMap;
///
/// let s = SyncMap::new();
/// s.store("a", 1);
/// assert_eq!(s.load(&"a"), Some(1));
/// assert_eq!(s.load(&"missing"), None);
///
/// // load_or_store:首次存入返回给定值,已存在时返回既有值
/// let names: SyncMap<&str, &str> = SyncMap::new();
/// let (v, loaded) = names.load_or_store("k", "first");
/// assert_eq!((v, loaded), ("first", false));
/// let (v, loaded) = names.load_or_store("k", "second");
/// assert_eq!((v, loaded), ("first", true));
/// ```
#[derive(Debug)]
pub struct SyncMap<K: Eq + Hash, V> {
    inner: RwLock<HashMap<K, V>>,
}

impl<K: Eq + Hash, V> Default for SyncMap<K, V> {
    fn default() -> Self {
        SyncMap {
            inner: RwLock::new(HashMap::new()),
        }
    }
}

impl<K: Eq + Hash + Clone, V: Clone> SyncMap<K, V> {
    /// 创建空并发映射。
    #[must_use]
    pub fn new() -> SyncMap<K, V> {
        SyncMap::default()
    }

    /// 返回 key 下存储的值;缺键返回 `None`。
    pub fn load(&self, key: &K) -> Option<V> {
        self.inner.read().ok()?.get(key).cloned()
    }

    /// key 已存在时返回既有值(`loaded = true`);否则存入给定值并返回
    /// 它(`loaded = false`)。与 Go `LoadOrStore` 语义一致。
    pub fn load_or_store(&self, key: K, val: V) -> (V, bool) {
        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(_) => return (val, false),
        };
        match guard.get(&key) {
            Some(existing) => (existing.clone(), true),
            None => {
                guard.insert(key, val.clone());
                (val, false)
            }
        }
    }

    /// 设置 key 的值。
    pub fn store(&self, key: K, val: V) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(key, val);
        }
    }

    /// 删除 key 的值。
    pub fn delete(&self, key: &K) {
        if let Ok(mut guard) = self.inner.write() {
            guard.remove(key);
        }
    }

    /// 顺序遍历每个键值对;回调返回 `false` 提前终止。回调持有读锁执行,
    /// 内部不得再对本表做写操作。
    pub fn range(&self, mut f: impl FnMut(&K, &V) -> bool) {
        let Ok(guard) = self.inner.read() else {
            return;
        };
        for (k, v) in guard.iter() {
            if !f(k, v) {
                break;
            }
        }
    }

    /// 条目数。O(1)——上游 `sync.Map` 不记尺寸只能 O(n) 数,这里直接记账。
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// 表是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map<const N: usize>(pairs: [(&str, i32); N]) -> HashMap<String, i32> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn test_keys_values() {
        let m = map([("a", 1), ("b", 2)]);
        let mut k = keys(&m);
        k.sort();
        assert_eq!(k, vec!["a", "b"]);
        let mut v = values(&m);
        v.sort();
        assert_eq!(v, vec![1, 2]);
    }

    #[test]
    fn test_merge() {
        let m1 = map([("a", 1), ("b", 2)]);
        let m2 = map([("b", 20), ("c", 3)]);
        let merged = merge([m1, m2]);
        assert_eq!(merged.get("a"), Some(&1));
        assert_eq!(merged.get("b"), Some(&20)); // 后者覆盖
        assert_eq!(merged.get("c"), Some(&3));
    }

    #[test]
    fn test_drop_filter() {
        let mut m = map([("a", 1), ("b", 2), ("c", 3)]);
        drop_keys(&mut m, &["a".to_string(), "c".to_string()]);
        assert_eq!(m.len(), 1);

        let m2 = map([("a", 1), ("b", 2)]);
        let filtered = filter(&m2, |_, v| *v > 1);
        assert_eq!(filtered.get("b"), Some(&2));
        assert!(!filtered.contains_key("a"));
    }

    // ============================================================
    // SyncMap(对位上游 sync_map_test.go)
    // ============================================================

    #[test]
    fn test_sync_map_basic() {
        let s = SyncMap::new();

        s.store("a", 1);
        s.store("b", 2);

        assert_eq!(s.load(&"a"), Some(1));
        assert_eq!(s.load(&"missing"), None);

        s.delete(&"a");
        assert_eq!(s.load(&"a"), None);
    }

    #[test]
    fn test_sync_map_load_or_store() {
        let s = SyncMap::<String, String>::new();

        let (v, loaded) = s.load_or_store("k".to_string(), "first".to_string());
        assert!(!loaded);
        assert_eq!(v, "first");

        let (v, loaded) = s.load_or_store("k".to_string(), "second".to_string());
        assert!(loaded, "已存在时返回既有值");
        assert_eq!(v, "first");

        assert_eq!(s.load(&"k".to_string()), Some("first".to_string()));
    }

    #[test]
    fn test_sync_map_range_and_len() {
        let s = SyncMap::new();
        for i in 0..10 {
            s.store(i, "v");
        }
        assert_eq!(s.len(), 10);

        let mut seen = 0;
        s.range(|_key, _val| {
            seen += 1;
            seen < 5 // 第 5 个停
        });
        assert_eq!(seen, 5);

        assert!(!s.is_empty());
        assert!(SyncMap::<i32, i32>::new().is_empty());
    }

    #[test]
    fn test_sync_map_concurrent_access() {
        use std::sync::Arc;
        let s = Arc::new(SyncMap::new());
        let mut handles = Vec::new();
        for id in 0..8u32 {
            let s = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                for i in 0..1000u32 {
                    let k = id * 1000 + i;
                    s.store(k, i as i32);
                    assert!(s.load(&k).is_some(), "own key {k} missing");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(s.len(), 8000);
    }
}
