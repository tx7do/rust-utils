//! 映射表辅助函数(移植自 go-utils/maputils)。
//!
//! 键/值遍历 Rust 迭代器原生覆盖,这里保留 Go 版的核心集合操作。

use std::collections::HashMap;
use std::hash::Hash;

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
}
