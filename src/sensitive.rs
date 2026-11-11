//! 敏感词过滤:词典树(trie)逐位最长匹配,纯 std、零依赖。
//!
//! 典型场景:UGC 发布前的敏感词拦截与打码。词典装载一次、反复匹配;
//! 构造期把词表压进 trie,匹配为 O(文本字符数 × 词长) 的逐位扫描——
//! 对管理后台的量级(千词词典、千字文本)足够,不追求 Aho-Corasick 的
//! 极致吞吐。
//!
//! 匹配语义:**自左向右、每位取最长词、命中即消费**(非重叠,与常见
//! "替换打码"的直觉一致)。ASCII 可选大小写不敏感;可指定"穿插字符"
//! (如 `*`、空格)在匹配中可被跳过——"敏*感*词"也能命中"敏感词"。
//! 跳过为贪心式:穿插字符只在已匹配前缀与下一候选字符之间被消费,
//! 不做回溯分支(语义可预期,详见 [`find_all`])。
//!
//! ```
//! use rust_utils::sensitive::SensitiveFilter;
//!
//! let f = SensitiveFilter::new(["敏感词", "badword"]);
//! assert!(f.is_hit("这句里有敏感词,拦下"));
//! assert_eq!(f.mask("这句里有敏感词,拦下", '*'), "这句里有***,拦下");
//!
//! let f = SensitiveFilter::builder()
//!     .case_insensitive()
//!     .ignore_chars(['*', ' '])
//!     .words(["badword"])
//!     .build();
//! assert!(f.is_hit("b a d w o r d"));
//! ```

use std::collections::{HashMap, HashSet};

/// 一处命中:字节区间(可安全切片)与命中的词。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// 起始字节偏移(char 边界对齐,`&text[start..end]` 安全)。
    pub start: usize,
    /// 结束字节偏移(不含)。
    pub end: usize,
    /// 命中的词(词典原文,不含被跳过的穿插字符)。
    pub word: String,
}

#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<char, TrieNode>,
    /// 终结节点持有词典原文(大小写不敏感时与匹配文本形态不同,
    /// 按词典原文回报)。
    word: Option<String>,
}

impl TrieNode {
    fn insert(&mut self, word: &str, fold_case: bool) {
        let mut node = self;
        for ch in word.chars() {
            let ch = if fold_case {
                ch.to_ascii_lowercase()
            } else {
                ch
            };
            node = node.children.entry(ch).or_default();
        }
        node.word = Some(word.to_string());
    }
}

/// 敏感词过滤器。
#[derive(Debug)]
pub struct SensitiveFilter {
    root: TrieNode,
    /// 匹配中可跳过的穿插字符。
    ignore_chars: HashSet<char>,
    /// ASCII 大小写不敏感(Unicode 不折叠)。
    case_insensitive: bool,
}

/// [`SensitiveFilter`] 的构造器(选项式装载)。
#[derive(Debug, Default)]
pub struct SensitiveFilterBuilder {
    words: Vec<String>,
    ignore_chars: HashSet<char>,
    case_insensitive: bool,
}

impl SensitiveFilterBuilder {
    /// 追加词表(可链式多次调用;空词与重复词自动忽略/去重)。
    pub fn words<I: IntoIterator<Item = impl AsRef<str>>>(mut self, words: I) -> Self {
        for w in words {
            let w = w.as_ref();
            if !w.is_empty() {
                self.words.push(w.to_string());
            }
        }
        self
    }

    /// 开启 ASCII 大小写不敏感(`BadWord` 命中 `badword`;中文不受影响)。
    pub fn case_insensitive(mut self) -> Self {
        self.case_insensitive = true;
        self
    }

    /// 指定匹配中可跳过的穿插字符(如 `*`、空格、`\t`)。
    pub fn ignore_chars<I: IntoIterator<Item = char>>(mut self, chars: I) -> Self {
        self.ignore_chars.extend(chars);
        self
    }

    /// 构建过滤器。
    pub fn build(self) -> SensitiveFilter {
        let mut root = TrieNode::default();
        for w in &self.words {
            root.insert(w, self.case_insensitive);
        }
        SensitiveFilter {
            root,
            ignore_chars: self.ignore_chars,
            case_insensitive: self.case_insensitive,
        }
    }
}

impl SensitiveFilter {
    /// 以默认选项装载词表(大小写敏感、无穿插跳过)。
    pub fn new<I: IntoIterator<Item = impl AsRef<str>>>(words: I) -> Self {
        SensitiveFilter::builder().words(words).build()
    }

    /// 选项式构造。
    pub fn builder() -> SensitiveFilterBuilder {
        SensitiveFilterBuilder::default()
    }

    /// 文本是否命中任一敏感词。
    pub fn is_hit(&self, text: &str) -> bool {
        text.char_indices()
            .any(|(start, _)| self.match_at(text, start).is_some())
    }

    /// 找出全部命中(自左向右、每位取最长、命中即消费——结果互不重叠)。
    ///
    /// 穿插字符的跳过是贪心的:在已匹配前缀之后,若下一字符是穿插字符
    /// 且 trie 仍有后继,则消费之继续匹配;因此穿插字符不会被计入命中
    /// 区间,词形以词典原文为准。
    pub fn find_all(&self, text: &str) -> Vec<Match> {
        let mut out = Vec::new();
        let char_indices: Vec<(usize, char)> = text.char_indices().collect();
        let mut i = 0;
        while i < char_indices.len() {
            if let Some((end, word)) = self.match_at(text, char_indices[i].0) {
                out.push(Match {
                    start: char_indices[i].0,
                    end,
                    word,
                });
                // 消费命中区间内的全部字符
                i += char_indices[i..]
                    .iter()
                    .take_while(|(pos, _)| *pos < end)
                    .count();
            } else {
                i += 1;
            }
        }
        out
    }

    /// 打码:命中区间按**字符数**逐字替换为 `replacement`,其余原样保留。
    pub fn mask(&self, text: &str, replacement: char) -> String {
        let matches = self.find_all(text);
        if matches.is_empty() {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in &matches {
            out.push_str(&text[last..m.start]);
            let masked = text[m.start..m.end].chars().count();
            for _ in 0..masked {
                out.push(replacement);
            }
            last = m.end;
        }
        out.push_str(&text[last..]);
        out
    }

    /// 从 `start` 字节偏移(char 边界)起,取最长命中。
    /// 返回 (结束字节偏移, 命中词)。
    fn match_at(&self, text: &str, start: usize) -> Option<(usize, String)> {
        let fold = |ch: char| {
            if self.case_insensitive {
                ch.to_ascii_lowercase()
            } else {
                ch
            }
        };
        let mut node = &self.root;
        let mut best: Option<(usize, String)> = None;
        for (off, ch) in text[start..].char_indices() {
            let folded = fold(ch);
            // 贪心穿插跳过:当前字符可跳且 trie 有后继 → 消费并继续
            if self.ignore_chars.contains(&folded) && !node.children.is_empty() {
                continue;
            }
            match node.children.get(&folded) {
                Some(next) => {
                    node = next;
                    if let Some(word) = &node.word {
                        best = Some((start + off + ch.len_utf8(), word.clone()));
                    }
                }
                None => break,
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_and_miss_basics() {
        let f = SensitiveFilter::new(["敏感词", "badword"]);
        assert!(f.is_hit("这句里有敏感词,拦下"));
        assert!(f.is_hit("contains badword inside"));
        assert!(!f.is_hit("完全正常的一句话"));
        assert!(!f.is_hit("goodword"));
        assert!(!f.is_hit(""));
        assert!(!SensitiveFilter::new(Vec::<String>::new()).is_hit("anything"));
    }

    #[test]
    fn find_all_positions_and_slices() {
        let f = SensitiveFilter::new(["敏感词", "badword"]);
        let text = "前缀敏感词中间badword后缀";
        let hits = f.find_all(text);
        assert_eq!(hits.len(), 2);
        assert_eq!(&text[hits[0].start..hits[0].end], "敏感词");
        assert_eq!(hits[0].word, "敏感词");
        assert_eq!(&text[hits[1].start..hits[1].end], "badword");
        assert_eq!(hits[1].word, "badword");
    }

    #[test]
    fn longest_match_wins() {
        // 同起点多候选:取最长
        let f = SensitiveFilter::new(["ab", "abcd"]);
        let hits = f.find_all("abcd");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].word, "abcd");

        // 短词命中后消费区间,不再吐出重叠短词
        let f = SensitiveFilter::new(["abc", "cde"]);
        let hits = f.find_all("abcde");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].word, "abc");

        // 错开起点则各自命中
        let f = SensitiveFilter::new(["ab", "cd"]);
        assert_eq!(f.find_all("abcd").len(), 2);
    }

    #[test]
    fn mask_preserves_length_and_context() {
        let f = SensitiveFilter::new(["敏感词", "badword"]);
        assert_eq!(f.mask("这句里有敏感词,拦下", '*'), "这句里有***,拦下");
        assert_eq!(f.mask("x badword y", '*'), "x ******* y");
        // 无命中原样返回(内容相等)
        assert_eq!(f.mask("干净文本", '*'), "干净文本");
        assert_eq!(f.mask("", '*'), "");
        // 打码字符可自选,多字节词按字符数打码(3+7=10 个 #)
        assert_eq!(f.mask("敏感词badword", '#'), "##########");
    }

    #[test]
    fn case_insensitive_option() {
        let on = SensitiveFilter::builder()
            .case_insensitive()
            .words(["badword"])
            .build();
        assert!(on.is_hit("BadWord"));
        assert!(on.is_hit("BADWORD"));
        assert_eq!(on.find_all("BadWord")[0].word, "badword");

        // 默认大小写敏感
        let off = SensitiveFilter::new(["badword"]);
        assert!(!off.is_hit("BadWord"));
    }

    #[test]
    fn ignore_chars_greedy_skip() {
        let f = SensitiveFilter::builder()
            .ignore_chars(['*', ' '])
            .words(["敏感词"])
            .build();
        assert!(f.is_hit("敏*感*词"));
        assert!(f.is_hit("敏 感 词"));
        assert!(!f.is_hit("敏x感x词"));
        let hits = f.find_all("前有敏*感*词后有");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].word, "敏感词");
        // 穿插字符计入命中区间(整词区间覆盖),打码按区间字符数
        assert_eq!(f.mask("前有敏*感*词后有", '*'), "前有*****后有");

        // 穿插字符只在词中跳,词外照常
        let f = SensitiveFilter::builder()
            .ignore_chars([' '])
            .words(["ab"])
            .build();
        assert!(f.is_hit("a b"));
        assert!(!f.is_hit("ba"));
    }

    #[test]
    fn word_set_normalization() {
        // 空词忽略、重复词去重(trie 天然去重)
        let f = SensitiveFilter::new(["", "ab", "ab", "abc"]);
        let hits = f.find_all("abcab");
        // 起点0取最长 abc,消费后余下 "ab" 再命中
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].word, "abc");
        assert_eq!(hits[1].word, "ab");
        assert_eq!(f.mask("abcab", '*'), "*****");
    }

    #[test]
    fn find_all_non_overlapping_consumption() {
        // 命中消费整段,不重复扫描
        let f = SensitiveFilter::new(["aa"]);
        assert_eq!(f.find_all("aaaa").len(), 2);
        assert_eq!(f.mask("aaaa", '*'), "****");

        // 混合多字节:字节偏移切分安全
        let f = SensitiveFilter::new(["中文"]);
        let text = "a中b文c中文";
        let hits = f.find_all(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(&text[hits[0].start..hits[0].end], "中文");
    }

    #[test]
    fn builder_chaining_and_defaults() {
        // 默认无穿插跳过、大小写敏感
        let f = SensitiveFilter::builder().words(["word"]).build();
        assert!(!f.is_hit("w o r d"));
        assert!(!f.is_hit("WORD"));
        // 词表多次追加
        let f = SensitiveFilter::builder().words(["a"]).words(["b"]).build();
        assert!(f.is_hit("a") && f.is_hit("b"));
    }
}
