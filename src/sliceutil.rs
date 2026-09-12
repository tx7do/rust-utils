//! 切片辅助函数(移植自 go-utils/sliceutil)。
//!
//! 过滤/映射/规约这类操作 Rust 迭代器原生覆盖(`iter().filter()`、
//! `iter().map()`、`iter().sum()`),这里只保留 Go 版中有增量价值的部分:
//! 查找族、集合运算、去重、分块、展平等。
//!
//! 两个与 Go 版不同的修正:
//! - `find_last_index` / `find_last_index_of`:Go 版从 `len-1` 遍历到 `i > 0`,
//!   永远检查不到下标 0,这里修正为完整遍历;
//! - 空切片集合运算在 Go 中可能触发空切片下标,这里做了保护。

/// 查找第一个满足条件的元素。
pub fn find<'a, T>(slice: &'a [T], predicate: impl Fn(&T, usize) -> bool) -> Option<&'a T> {
    slice.iter().enumerate().find_map(|(i, el)| {
        if predicate(el, i) {
            Some(el)
        } else {
            None
        }
    })
}

/// 查找第一个满足条件的元素下标。
pub fn find_index<T>(slice: &[T], predicate: impl Fn(&T, usize) -> bool) -> Option<usize> {
    slice.iter().enumerate().find_map(|(i, el)| {
        if predicate(el, i) {
            Some(i)
        } else {
            None
        }
    })
}

/// 查找第一个等于 `value` 的元素下标。
pub fn find_index_of<T: PartialEq>(slice: &[T], value: &T) -> Option<usize> {
    slice.iter().position(|el| el == value)
}

/// 从尾部起查找第一个满足条件的元素下标。
pub fn find_last_index<T>(slice: &[T], predicate: impl Fn(&T, usize) -> bool) -> Option<usize> {
    slice
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, el)| if predicate(el, i) { Some(i) } else { None })
}

/// 从尾部起查找第一个等于 `value` 的元素下标。
pub fn find_last_index_of<T: PartialEq>(slice: &[T], value: &T) -> Option<usize> {
    slice.iter().rposition(|el| el == value)
}

/// 返回所有满足条件的元素下标。
pub fn find_indexes<T>(slice: &[T], predicate: impl Fn(&T, usize) -> bool) -> Vec<usize> {
    slice
        .iter()
        .enumerate()
        .filter(|(i, el)| predicate(el, *i))
        .map(|(i, _)| i)
        .collect()
}

/// 返回所有等于 `value` 的元素下标。
pub fn find_indexes_of<T: PartialEq>(slice: &[T], value: &T) -> Vec<usize> {
    slice
        .iter()
        .enumerate()
        .filter(|(_, el)| *el == value)
        .map(|(i, _)| i)
        .collect()
}

/// 判断切片中是否包含 `value`。
pub fn includes<T: PartialEq>(slice: &[T], value: &T) -> bool {
    slice.contains(value)
}

/// 是否存在满足条件的元素(等价于 `iter().any()`)。
pub fn some<T>(slice: &[T], predicate: impl Fn(&T, usize) -> bool) -> bool {
    slice.iter().enumerate().any(|(i, el)| predicate(el, i))
}

/// 是否所有元素都满足条件(等价于 `iter().all()`)。
pub fn every<T>(slice: &[T], predicate: impl Fn(&T, usize) -> bool) -> bool {
    slice.iter().enumerate().all(|(i, el)| predicate(el, i))
}

/// 按顺序拼接多个切片。
pub fn merge<T: Clone>(slices: &[&[T]]) -> Vec<T> {
    let cap = slices.iter().map(|s| s.len()).sum();
    let mut out = Vec::with_capacity(cap);
    for s in slices {
        out.extend_from_slice(s);
    }
    out
}

/// 返回去掉下标 `index` 处元素后的新切片;越界时返回原切片的拷贝。
pub fn remove<T: Clone>(slice: &[T], index: usize) -> Vec<T> {
    let mut out = slice.to_vec();
    if index < out.len() {
        out.remove(index);
    }
    out
}

/// 取多个切片的交集,顺序跟随第一个切片,结果去重。
pub fn intersection<T: Eq + std::hash::Hash + Clone>(slices: &[&[T]]) -> Vec<T> {
    if slices.is_empty() {
        return Vec::new();
    }
    let mut possible: std::collections::HashMap<T, usize> = std::collections::HashMap::new();
    for (i, slice) in slices.iter().enumerate() {
        for el in *slice {
            if i == 0 {
                possible.insert(el.clone(), 0);
            } else if possible.contains_key(el) {
                possible.insert(el.clone(), i);
            }
        }
    }
    let last = slices.len() - 1;
    let mut out = Vec::new();
    for el in slices[0] {
        if possible.get(el) == Some(&last) {
            out.push(el.clone());
            possible.remove(el);
        }
    }
    out
}

/// 取多个切片的差异:只出现在其中一个切片中的元素(重复元素按原样保留)。
pub fn difference<T: Eq + std::hash::Hash + Clone>(slices: &[&[T]]) -> Vec<T> {
    let mut possible: std::collections::HashMap<T, usize> = std::collections::HashMap::new();
    let mut non_different: std::collections::HashMap<T, usize> = std::collections::HashMap::new();
    for (i, slice) in slices.iter().enumerate() {
        for el in *slice {
            match possible.get(el) {
                Some(&last) if last != i => {
                    non_different.insert(el.clone(), i);
                }
                None => {
                    possible.insert(el.clone(), i);
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    for slice in slices {
        for el in *slice {
            if !non_different.contains_key(el) {
                out.push(el.clone());
            }
        }
    }
    out
}

/// 取多个切片的并集(去重)。
pub fn union<T: Eq + std::hash::Hash + Clone>(slices: &[&[T]]) -> Vec<T> {
    unique(&merge(slices))
}

/// 去重,保留首次出现的顺序。
pub fn unique<T: Eq + std::hash::Hash + Clone>(slice: &[T]) -> Vec<T> {
    let mut seen = std::collections::HashSet::with_capacity(slice.len());
    let mut out = Vec::new();
    for el in slice {
        if seen.insert(el) {
            out.push(el.clone());
        }
    }
    out
}

/// 按 `size` 分块,返回借用原切片的子切片视图;`size` 为 0 时 panic。
pub fn chunk<T>(slice: &[T], size: usize) -> Vec<&[T]> {
    slice.chunks(size).collect()
}

/// 用 getter 从每个元素抽取字段,getter 返回 `None` 的元素被跳过。
pub fn pluck<I, O>(input: &[I], getter: impl Fn(&I) -> Option<O>) -> Vec<O> {
    input.iter().filter_map(getter).collect()
}

/// 展平二维切片。
pub fn flatten<T: Clone>(input: &[Vec<T>]) -> Vec<T> {
    let cap = input.iter().map(|v| v.len()).sum();
    let mut out = Vec::with_capacity(cap);
    for v in input {
        out.extend(v.iter().cloned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_family() {
        let v = vec![1, 2, 3, 4, 3];
        assert_eq!(find(&v, |x, _| *x > 2), Some(&3));
        assert_eq!(find_index(&v, |x, _| *x > 2), Some(2));
        assert_eq!(find_index(&v, |x, _| *x > 9), None);
        assert_eq!(find_index_of(&v, &3), Some(2));
        assert_eq!(find_last_index(&v, |x, _| *x > 2), Some(4));
        // Go 版跳过下标 0 的回归用例:唯一的奇数在下标 0
        let w = vec![5, 2];
        assert_eq!(find_last_index(&w, |x, _| *x % 2 == 1), Some(0));
        assert_eq!(find_last_index_of(&v, &3), Some(4));
        assert_eq!(find_indexes(&v, |x, _| *x % 2 == 0), vec![1, 3]);
        assert_eq!(find_indexes_of(&v, &3), vec![2, 4]);
    }

    #[test]
    fn test_includes_some_every() {
        let v = vec![1, 2, 3];
        assert!(includes(&v, &2));
        assert!(!includes(&v, &9));
        assert!(some(&v, |x, _| *x > 2));
        assert!(!some(&v, |x, _| *x > 9));
        assert!(every(&v, |x, _| *x > 0));
        assert!(!every(&v, |x, _| *x > 1));
    }

    #[test]
    fn test_merge() {
        let a = [1, 2];
        let b: [i32; 0] = [];
        let c = [3];
        assert_eq!(merge(&[&a[..], &b[..], &c[..]]), vec![1, 2, 3]);
    }

    #[test]
    fn test_remove() {
        let v = vec![1, 2, 3];
        assert_eq!(remove(&v, 0), vec![2, 3]);
        assert_eq!(remove(&v, 1), vec![1, 3]);
        assert_eq!(remove(&v, 2), vec![1, 2]);
        assert_eq!(remove(&v, 9), v); // 越界返回原样
        assert_eq!(v, vec![1, 2, 3]); // 原切片不变
    }

    #[test]
    fn test_set_operations() {
        let a = [1, 2, 3];
        let b = [1, 7, 3];
        assert_eq!(intersection(&[&a[..], &b[..]]), vec![1, 3]);
        let c = [2, 3, 4];
        let d = [3, 4, 5];
        assert_eq!(difference(&[&a[..], &c[..], &d[..]]), vec![1, 5]);
        assert_eq!(union(&[&a[..], &c[..], &d[..]]), vec![1, 2, 3, 4, 5]);
        assert_eq!(unique(&[1, 2, 1, 3, 2]), vec![1, 2, 3]);
        // 空输入保护
        let none: Vec<i32> = intersection(&[]);
        assert!(none.is_empty());
        let none2: Vec<i32> = difference(&[]);
        assert!(none2.is_empty());
    }

    #[test]
    fn test_chunk_pluck_flatten() {
        let v = vec![1, 2, 3, 4, 5];
        assert_eq!(chunk(&v, 2), vec![&[1, 2][..], &[3, 4][..], &[5][..]]);
        let users = vec![("a", Some(1)), ("b", None), ("c", Some(3))];
        assert_eq!(pluck(&users, |u| u.1), vec![1, 3]);
        let nested = vec![vec![1, 2], vec![], vec![3]];
        assert_eq!(flatten(&nested), vec![1, 2, 3]);
    }
}
