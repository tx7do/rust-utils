//! 随机昵称 / 姓名生成器(移植自 go-utils/name_generator),feature
//! `name-generator`。
//!
//! 内嵌了 Go 版的 17 份词库(形容词/物品/称谓/前后缀/动词/敏感词,
//! 中文姓名与英文姓名语料,日语语料),`include_str!` 编译期打包。
//!
//! ```
//! use rust_utils::name_generator::{Generator, SCHEME3};
//!
//! let gen = Generator::new();
//! let nick = gen.generate(&SCHEME3);           // 前缀+名字+形容词
//! assert!(!nick.is_empty());
//!
//! let name = gen.generate_chinese_name(2, true, false); // 两字女性中文名
//! assert_eq!(name.chars().count(), 3);
//! ```

use std::collections::HashMap;
use std::fmt;

/// 词库类型标识。
pub type DictionaryType = &'static str;

pub const DICTIONARY_TYPE_ADJECTIVE: DictionaryType = "adjective";
pub const DICTIONARY_TYPE_GOODS: DictionaryType = "goods";
pub const DICTIONARY_TYPE_NAME: DictionaryType = "name";
pub const DICTIONARY_TYPE_PREFIX: DictionaryType = "prefix";
pub const DICTIONARY_TYPE_ROLE: DictionaryType = "role";
pub const DICTIONARY_TYPE_VERB: DictionaryType = "verb";
pub const DICTIONARY_TYPE_SENSITIVE: DictionaryType = "sensitive";

pub const DICTIONARY_TYPE_SINGLE_SURNAMES: DictionaryType = "single_surnames";
pub const DICTIONARY_TYPE_COMPOUND_SURNAMES: DictionaryType = "compound_surnames";
pub const DICTIONARY_TYPE_CHINESE_FIRST_NAME_FEMALE: DictionaryType = "chinese_first_name_female";
pub const DICTIONARY_TYPE_CHINESE_FIRST_NAME_MALE: DictionaryType = "chinese_first_name_male";

pub const DICTIONARY_TYPE_ENGLISH_FIRST_NAME_FEMALE: DictionaryType = "english_first_name_female";
pub const DICTIONARY_TYPE_ENGLISH_FIRST_NAME_MALE: DictionaryType = "english_first_name_male";
pub const DICTIONARY_TYPE_ENGLISH_LAST_NAME: DictionaryType = "english_last_name";

pub const DICTIONARY_TYPE_JAPANESE_NAME: DictionaryType = "japanese_name";
pub const DICTIONARY_TYPE_JAPANESE_SURNAMES: DictionaryType = "japanese_surnames";
pub const DICTIONARY_TYPE_JAPANESE_LAST_NAME: DictionaryType = "japanese_last_name";

/// 组合词库方案:按顺序从各词库抽词拼接。
pub type CombinedDictionaryType = &'static [DictionaryType];

pub const SCHEME1: CombinedDictionaryType = &[
    DICTIONARY_TYPE_PREFIX,
    DICTIONARY_TYPE_NAME,
    DICTIONARY_TYPE_VERB,
];
pub const SCHEME2: CombinedDictionaryType = &[
    DICTIONARY_TYPE_PREFIX,
    DICTIONARY_TYPE_ROLE,
    DICTIONARY_TYPE_VERB,
];
pub const SCHEME3: CombinedDictionaryType = &[
    DICTIONARY_TYPE_PREFIX,
    DICTIONARY_TYPE_NAME,
    DICTIONARY_TYPE_ADJECTIVE,
];
pub const SCHEME4: CombinedDictionaryType = &[
    DICTIONARY_TYPE_PREFIX,
    DICTIONARY_TYPE_VERB,
    DICTIONARY_TYPE_ROLE,
];
pub const SCHEME5: CombinedDictionaryType = &[
    DICTIONARY_TYPE_PREFIX,
    DICTIONARY_TYPE_VERB,
    DICTIONARY_TYPE_NAME,
];
pub const SCHEME6: CombinedDictionaryType = &[
    DICTIONARY_TYPE_NAME,
    DICTIONARY_TYPE_PREFIX,
    DICTIONARY_TYPE_GOODS,
];

pub const SCHEME_CHINESE_NAME_FEMALE: CombinedDictionaryType = &[
    DICTIONARY_TYPE_SINGLE_SURNAMES,
    DICTIONARY_TYPE_CHINESE_FIRST_NAME_FEMALE,
];
pub const SCHEME_CHINESE_NAME_MALE: CombinedDictionaryType = &[
    DICTIONARY_TYPE_SINGLE_SURNAMES,
    DICTIONARY_TYPE_CHINESE_FIRST_NAME_MALE,
];

macro_rules! dict {
    ($name:literal) => {
        include_str!(concat!("../assets/name_generator/", $name, ".txt"))
    };
}

const D_ADJECTIVE: &str = dict!("adjective");
const D_GOODS: &str = dict!("goods");
const D_NAME: &str = dict!("name");
const D_PREFIX: &str = dict!("prefix");
const D_ROLE: &str = dict!("role");
const D_VERB: &str = dict!("verb");
const D_SENSITIVE: &str = dict!("sensitive");
const D_CHINESE_SINGLE_SURNAMES: &str = dict!("chinese_single_surnames");
const D_CHINESE_COMPOUND_SURNAMES: &str = dict!("chinese_compound_surnames");
const D_CHINESE_FIRST_NAME_FEMALE: &str = dict!("chinese_first_name_female");
const D_CHINESE_FIRST_NAME_MALE: &str = dict!("chinese_first_name_male");
const D_ENGLISH_FIRST_NAME_FEMALE: &str = dict!("english_first_name_female");
const D_ENGLISH_FIRST_NAME_MALE: &str = dict!("english_first_name_male");
const D_ENGLISH_LAST_NAME: &str = dict!("english_last_name");
const D_JAPANESE_NAMES_CORPUS: &str = dict!("japanese_names_corpus");
const D_JAPANESE_SURNAMES: &str = dict!("japanese_surnames");
const D_JAPANESE_LAST_NAME: &str = dict!("japanese_last_name");

/// 把词库文本按行解析为词条(去空白、跳过空行)。
fn parse_dict(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// 姓名生成器。
pub struct Generator {
    dictionaries: HashMap<DictionaryType, Vec<String>>,
}

impl Default for Generator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Generator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generator")
            .field("dict_count", &self.dictionaries.len())
            .finish()
    }
}

impl Generator {
    /// 创建生成器并加载全部内嵌词库。
    pub fn new() -> Self {
        let mut g = Generator {
            dictionaries: HashMap::new(),
        };
        for (dict_type, text) in [
            (DICTIONARY_TYPE_ADJECTIVE, D_ADJECTIVE),
            (DICTIONARY_TYPE_GOODS, D_GOODS),
            (DICTIONARY_TYPE_NAME, D_NAME),
            (DICTIONARY_TYPE_PREFIX, D_PREFIX),
            (DICTIONARY_TYPE_ROLE, D_ROLE),
            (DICTIONARY_TYPE_VERB, D_VERB),
            (DICTIONARY_TYPE_SENSITIVE, D_SENSITIVE),
            (DICTIONARY_TYPE_SINGLE_SURNAMES, D_CHINESE_SINGLE_SURNAMES),
            (
                DICTIONARY_TYPE_COMPOUND_SURNAMES,
                D_CHINESE_COMPOUND_SURNAMES,
            ),
            (
                DICTIONARY_TYPE_CHINESE_FIRST_NAME_FEMALE,
                D_CHINESE_FIRST_NAME_FEMALE,
            ),
            (
                DICTIONARY_TYPE_CHINESE_FIRST_NAME_MALE,
                D_CHINESE_FIRST_NAME_MALE,
            ),
        ] {
            let _ = g.load_dict(dict_type, text);
        }
        g
    }

    /// 创建空生成器(不加载任何词库)。
    pub fn empty() -> Self {
        Generator {
            dictionaries: HashMap::new(),
        }
    }

    /// 加载词库文本;同名词库已存在时报错。
    pub fn load_dict(&mut self, dict_type: DictionaryType, text: &str) -> Result<(), String> {
        if self.dictionaries.contains_key(dict_type) {
            return Err(format!("dictionary already exists for type: {dict_type}"));
        }
        self.dictionaries.insert(dict_type, parse_dict(text));
        Ok(())
    }

    /// 从文件加载词库;同名词库已存在时报错。
    pub fn load_dict_from_file(
        &mut self,
        dict_type: DictionaryType,
        path: &std::path::Path,
    ) -> Result<(), String> {
        if self.dictionaries.contains_key(dict_type) {
            return Err(format!("dictionary already exists for type: {dict_type}"));
        }
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read dict file failed: {e}"))?;
        self.dictionaries.insert(dict_type, parse_dict(&text));
        Ok(())
    }

    /// 词库是否存在。
    pub fn exist_dict(&self, dict_type: DictionaryType) -> bool {
        self.dictionaries.contains_key(dict_type)
    }

    /// 已加载的词库数量。
    pub fn dict_count(&self) -> usize {
        self.dictionaries.len()
    }

    /// 某个词库的词条数量(不存在返回 0)。
    pub fn dict_item_count(&self, dict_type: DictionaryType) -> usize {
        self.dictionaries.get(dict_type).map(Vec::len).unwrap_or(0)
    }

    fn random_word(&self, dict_type: DictionaryType) -> &str {
        use rand::Rng;
        let Some(dict) = self.dictionaries.get(dict_type) else {
            return "";
        };
        if dict.is_empty() {
            return "";
        }
        let idx = rand::rng().random_range(0..dict.len());
        dict[idx].as_str()
    }

    /// 按组合方案随机生成一个字符串(各词拼接)。
    pub fn generate(&self, dict_types: &[DictionaryType]) -> String {
        self.generate_parts(dict_types).join("")
    }

    /// 按组合方案随机生成各词(缺词的字典跳过)。
    pub fn generate_parts(&self, dict_types: &[DictionaryType]) -> Vec<String> {
        dict_types
            .iter()
            .map(|t| self.random_word(t))
            .filter(|w| !w.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// 生成中文名:姓 + `first_name_count` 个名用字。
    pub fn generate_chinese_name(
        &self,
        first_name_count: usize,
        is_female: bool,
        is_compound_surname: bool,
    ) -> String {
        let mut dict_types: Vec<DictionaryType> = Vec::with_capacity(first_name_count + 1);
        dict_types.push(if is_compound_surname {
            DICTIONARY_TYPE_COMPOUND_SURNAMES
        } else {
            DICTIONARY_TYPE_SINGLE_SURNAMES
        });
        let given = if is_female {
            DICTIONARY_TYPE_CHINESE_FIRST_NAME_FEMALE
        } else {
            DICTIONARY_TYPE_CHINESE_FIRST_NAME_MALE
        };
        for _ in 0..first_name_count {
            dict_types.push(given);
        }
        self.generate(&dict_types)
    }

    /// 生成英文名(空格分隔);`first_name_count` 须在 1..=2,
    /// `last_name_count` 至少 1,参数非法时返回空串。词库惰性加载。
    pub fn generate_english_name(
        &mut self,
        first_name_count: usize,
        middle_name_count: usize,
        last_name_count: usize,
        is_female: bool,
    ) -> String {
        if !self.exist_dict(DICTIONARY_TYPE_ENGLISH_FIRST_NAME_FEMALE) {
            let _ = self.load_dict(
                DICTIONARY_TYPE_ENGLISH_FIRST_NAME_FEMALE,
                D_ENGLISH_FIRST_NAME_FEMALE,
            );
        }
        if !self.exist_dict(DICTIONARY_TYPE_ENGLISH_FIRST_NAME_MALE) {
            let _ = self.load_dict(
                DICTIONARY_TYPE_ENGLISH_FIRST_NAME_MALE,
                D_ENGLISH_FIRST_NAME_MALE,
            );
        }
        if !self.exist_dict(DICTIONARY_TYPE_ENGLISH_LAST_NAME) {
            let _ = self.load_dict(DICTIONARY_TYPE_ENGLISH_LAST_NAME, D_ENGLISH_LAST_NAME);
        }
        if !(1..=2).contains(&first_name_count) || last_name_count < 1 {
            return String::new();
        }
        let mut dict_types: Vec<DictionaryType> = Vec::new();
        let first = if is_female {
            DICTIONARY_TYPE_ENGLISH_FIRST_NAME_FEMALE
        } else {
            DICTIONARY_TYPE_ENGLISH_FIRST_NAME_MALE
        };
        dict_types.extend(std::iter::repeat(first).take(first_name_count + middle_name_count));
        dict_types
            .extend(std::iter::repeat(DICTIONARY_TYPE_ENGLISH_LAST_NAME).take(last_name_count));
        dict_types
            .iter()
            .map(|t| self.random_word(t))
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// 生成日文姓名(汉字,惰性加载姓名语料)。
    pub fn generate_japanese_name_cn(&mut self) -> String {
        if !self.exist_dict(DICTIONARY_TYPE_JAPANESE_NAME) {
            let _ = self.load_dict(DICTIONARY_TYPE_JAPANESE_NAME, D_JAPANESE_NAMES_CORPUS);
        }
        self.generate(&[DICTIONARY_TYPE_JAPANESE_NAME])
    }

    /// 生成日文姓名(姓 + 名,惰性加载词库)。
    pub fn generate_japanese_name(&mut self) -> String {
        if !self.exist_dict(DICTIONARY_TYPE_JAPANESE_SURNAMES) {
            let _ = self.load_dict(DICTIONARY_TYPE_JAPANESE_SURNAMES, D_JAPANESE_SURNAMES);
        }
        if !self.exist_dict(DICTIONARY_TYPE_JAPANESE_LAST_NAME) {
            let _ = self.load_dict(DICTIONARY_TYPE_JAPANESE_LAST_NAME, D_JAPANESE_LAST_NAME);
        }
        self.generate(&[
            DICTIONARY_TYPE_JAPANESE_SURNAMES,
            DICTIONARY_TYPE_JAPANESE_LAST_NAME,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_dicts_loaded() {
        let g = Generator::new();
        assert_eq!(g.dict_count(), 11);
        assert!(g.dict_item_count(DICTIONARY_TYPE_NAME) > 0);
        assert!(g.dict_item_count(DICTIONARY_TYPE_SINGLE_SURNAMES) > 0);
        assert_eq!(g.dict_item_count("no-such-dict"), 0);
        assert!(g.exist_dict(DICTIONARY_TYPE_ADJECTIVE));
        assert!(!g.exist_dict(DICTIONARY_TYPE_ENGLISH_LAST_NAME)); // 惰性加载
    }

    #[test]
    fn test_load_dict_conflict() {
        let mut g = Generator::new();
        assert!(g.load_dict(DICTIONARY_TYPE_NAME, "a\nb\n").is_err());
        let mut empty = Generator::empty();
        assert!(empty.load_dict(DICTIONARY_TYPE_NAME, "a\nb\n").is_ok());
        assert_eq!(empty.dict_item_count(DICTIONARY_TYPE_NAME), 2);
    }

    #[test]
    fn test_generate_schemes() {
        let g = Generator::new();
        for scheme in [SCHEME1, SCHEME2, SCHEME3, SCHEME4, SCHEME5, SCHEME6] {
            let s = g.generate(scheme);
            assert!(!s.is_empty(), "scheme produced empty name");
        }
    }

    #[test]
    fn test_generate_chinese_name() {
        let g = Generator::new();
        let female = g.generate_chinese_name(2, true, false);
        assert_eq!(female.chars().count(), 3);
        let male1 = g.generate_chinese_name(1, false, false);
        assert_eq!(male1.chars().count(), 2);
        let compound = g.generate_chinese_name(1, true, true);
        assert!((2..=3).contains(&compound.chars().count()));
    }

    #[test]
    fn test_generate_english_name() {
        let mut g = Generator::new();
        let name = g.generate_english_name(1, 0, 1, true);
        assert!(!name.is_empty());
        assert!(name.contains(' '));
        // 参数校验:非法参数返回空串
        assert!(g.generate_english_name(0, 0, 1, false).is_empty());
        assert!(g.generate_english_name(3, 0, 1, false).is_empty());
        assert!(g.generate_english_name(1, 0, 0, false).is_empty());
        assert!(g.exist_dict(DICTIONARY_TYPE_ENGLISH_LAST_NAME)); // 惰性加载后存在
    }

    #[test]
    fn test_generate_japanese() {
        let mut g = Generator::new();
        let name = g.generate_japanese_name();
        assert!(!name.is_empty());
        let cn = g.generate_japanese_name_cn();
        assert!(!cn.is_empty());
        assert!(g.exist_dict(DICTIONARY_TYPE_JAPANESE_SURNAMES));
    }
}
