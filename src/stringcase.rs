//! 命名风格转换:驼峰 / 蛇形 / 烤肉串,附带一个能识别缩写词与数字段的
//! 自定义分词器(移植自 go-utils/stringcase)。
//!
//! 与 `heck` 等现成 crate 的区别在于对缩写词与数字的处理:
//! `HTTPStatusCode` → `http_status_code`、`Numbers123Test` → `numbers123_test`、
//! `ParseURL.DoParse` → `parse_url_do_parse`。
//!
//! ```
//! use rust_utils::stringcase;
//!
//! assert_eq!(stringcase::snake_case("HTTPStatusCode"), "http_status_code");
//! assert_eq!(stringcase::upper_camel_case("parse_url.do_parse"), "ParseUrlDoParse");
//! assert_eq!(stringcase::kebab_case("Numbers123Test"), "numbers123-test");
//! ```

fn is_digit(c: char) -> bool {
    c.is_numeric()
}

fn is_upper(c: char) -> bool {
    c.is_uppercase()
}

fn to_lower(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

fn to_upper(c: char) -> char {
    c.to_uppercase().next().unwrap_or(c)
}

fn is_letter(c: char) -> bool {
    c.is_alphabetic()
}

/// 逐字符读取 "CamelCase" 字符串的读取器,移植自 Go 版的 `rdr`。
/// `pos` 始终指向"下一个待读字符";`rd` 为上一个已读字符,`nxt` 为前瞻字符。
struct Rdr<'a> {
    input: &'a [char],
    pos: usize,
    has_next: bool,
    rd: char,
    nxt: char,
}

impl<'a> Rdr<'a> {
    fn new(input: &'a [char]) -> Self {
        Rdr {
            input,
            pos: 0,
            has_next: false,
            rd: '\0',
            nxt: '\0',
        }
    }

    fn read_rune(&mut self) {
        self.rd = self.input[self.pos];
        self.pos += 1;
        self.has_next = self.pos < self.input.len();
        if self.has_next {
            self.nxt = self.input[self.pos];
        }
    }

    fn unread_rune(&mut self) {
        self.pos -= 1;
        self.nxt = self.rd;
        self.rd = self.input[self.pos];
        self.has_next = true;
    }

    /// 判断当前正在读取的词是否命中某个"不可拆分"候选词的前缀。
    fn is_no_split_word(&self, s_idx: usize, no_split: &[&str]) -> bool {
        let current: String = self.input[s_idx..=self.pos].iter().collect();
        no_split
            .iter()
            .any(|w| w.starts_with(current.as_str()))
    }

    fn read_next_part(&mut self, no_split: &[&str]) -> String {
        let s_idx = self.pos;
        self.read_rune();
        if is_digit(self.rd) {
            self.read_number(s_idx, no_split)
        } else {
            self.read_word(s_idx, no_split)
        }
    }

    fn read_number(&mut self, s_idx: usize, no_split: &[&str]) -> String {
        if self.has_next && is_digit(self.nxt) {
            while self.has_next && (is_digit(self.nxt) || self.is_no_split_word(s_idx, no_split)) {
                self.read_rune();
            }
        }
        self.input[s_idx..self.pos].iter().collect()
    }

    fn read_word(&mut self, s_idx: usize, no_split: &[&str]) -> String {
        if self.has_next && is_upper(self.nxt) {
            // 大写开头:吞掉连续大写(缩写词);若后面跟小写则回退一个,
            // 使 "ParseURL" 拆为 "Parse" + "URL" 而不是 "Parse" + "UR" + "L"。
            while self.has_next && (is_upper(self.nxt) || self.is_no_split_word(s_idx, no_split)) {
                self.read_rune();
            }
            if self.has_next && !is_upper(self.nxt) && !is_digit(self.nxt) {
                self.unread_rune();
            }
        } else {
            while self.has_next
                && (self.is_no_split_word(s_idx, no_split)
                    || (!is_upper(self.nxt) && !is_digit(self.nxt)))
            {
                self.read_rune();
            }
        }
        self.input[s_idx..self.pos].iter().collect()
    }
}

fn split_inner(input: &str, no_split: &[&str]) -> Vec<String> {
    if input.is_empty() {
        return vec![input.to_string()];
    }
    let chars: Vec<char> = input.chars().collect();
    let mut rdr = Rdr::new(&chars);
    let mut out = Vec::new();
    while rdr.pos < chars.len() {
        out.push(rdr.read_next_part(no_split));
    }
    out
}

/// 按驼峰式词边界拆分字符串。
///
/// 先剔除所有非字母数字分隔符,再对每个连续段做驼峰拆分。
/// 空字符串返回 `[ ""]`。
pub fn split(input: &str) -> Vec<String> {
    split_with(input, &[])
}

/// 同 [`split`],但 `no_split` 中的词保持完整、不被拆分(例如缩写词表)。
pub fn split_with(input: &str, no_split: &[&str]) -> Vec<String> {
    if input.is_empty() {
        return vec![input.to_string()];
    }
    let mut out = Vec::new();
    for part in split_by_non_alphanumeric(input) {
        out.extend(split_inner(part.trim(), no_split));
    }
    out
}

/// 大驼峰 / 帕斯卡命名法(`PascalCase`)。
pub fn upper_camel_case(input: &str) -> String {
    camel_case_impl(input, true)
}

/// 小驼峰命名法(`lowerCamelCase`)。
pub fn lower_camel_case(input: &str) -> String {
    camel_case_impl(input, false)
}

/// [`upper_camel_case`] 的别名。
pub fn pascal_case(input: &str) -> String {
    camel_case_impl(input, true)
}

/// [`lower_camel_case`] 的别名。
pub fn camel_case(input: &str) -> String {
    camel_case_impl(input, false)
}

fn camel_case_impl(input: &str, upper: bool) -> String {
    let input = input.trim();
    if input.is_empty() {
        return input.to_string();
    }
    let words: Vec<String> = split(input)
        .into_iter()
        .filter(|w| !w.trim().is_empty())
        .collect();
    if words.is_empty() {
        return String::new();
    }
    words
        .into_iter()
        .enumerate()
        .map(|(i, word)| {
            let mut chars: Vec<char> = word.chars().collect();
            if !chars.is_empty() {
                if i == 0 && !upper {
                    chars[0] = to_lower(chars[0]);
                } else {
                    chars[0] = to_upper(chars[0]);
                }
                for c in chars.iter_mut().skip(1) {
                    *c = to_lower(*c);
                }
            }
            chars.into_iter().collect::<String>()
        })
        .collect()
}

/// 蛇形命名法(`snake_case`)。
pub fn snake_case(s: &str) -> String {
    delimiter_case(s, '_', false)
}

/// [`snake_case`] 的别名。
pub fn to_snake_case(s: &str) -> String {
    snake_case(s)
}

/// 大写蛇形命名法(`UPPER_SNAKE_CASE`)。
pub fn upper_snake_case(s: &str) -> String {
    delimiter_case(s, '_', true)
}

/// 烤肉串命名法(`kebab-case`)。
pub fn kebab_case(s: &str) -> String {
    delimiter_case(s, '-', false)
}

/// 大写烤肉串命名法(`KEBAB-CASE`)。
pub fn upper_kebab_case(s: &str) -> String {
    delimiter_case(s, '-', true)
}

fn is_letters_only(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_letter)
}

fn is_digits_only(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_digit)
}

/// 与 Go 版一致:相邻两个词若在原输入里位置相接,且前词纯字母、后词纯数字,
/// 则合并(`numbers123` 不被拆开)。
fn merge_adjacent_digit_words(input: &str, words: Vec<String>) -> Vec<String> {
    let mut merged: Vec<String> = Vec::with_capacity(words.len());
    let mut offset = 0usize;
    let mut prev_end: Option<usize> = None;

    for w in words {
        let start = input[offset..].find(w.as_str()).map(|idx| offset + idx);
        match start {
            Some(start) if prev_end == Some(start) && !merged.is_empty() => {
                let prev = merged.last().unwrap().clone();
                if is_letters_only(&prev) && is_digits_only(&w) {
                    let joined = prev + w.as_str();
                    *merged.last_mut().unwrap() = joined;
                    prev_end = Some(start + w.len());
                    offset = prev_end.unwrap();
                    continue;
                }
                let w_len = w.len();
                merged.push(w);
                prev_end = Some(start + w_len);
                offset = prev_end.unwrap();
            }
            Some(start) => {
                let w_len = w.len();
                merged.push(w);
                prev_end = Some(start + w_len);
                offset = prev_end.unwrap();
            }
            None => {
                // 找不到位置时推进到末尾,避免死循环。
                merged.push(w);
                offset = input.len();
                prev_end = Some(offset);
            }
        }
    }
    merged
}

fn delimiter_case(input: &str, delimiter: char, upper_case: bool) -> String {
    let input = input.trim();
    if input.is_empty() {
        return String::new();
    }
    let words: Vec<String> = split(input)
        .into_iter()
        .filter(|w| !w.trim().is_empty())
        .collect();
    if words.is_empty() {
        return String::new();
    }
    let merged = merge_adjacent_digit_words(input, words);
    let mapped: Vec<String> = merged
        .into_iter()
        .map(|word| {
            word.chars()
                .map(|c| if upper_case { to_upper(c) } else { to_lower(c) })
                .collect()
        })
        .collect();
    mapped.join(&delimiter.to_string())
}

/// 判断字符串是否为合法的 `snake_case`:
/// 非空、首尾无下划线、无大写字母、无连续下划线,且只含小写字母/数字/下划线。
pub fn is_snake_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut prev_underscore = false;
    for (i, c) in s.chars().enumerate() {
        if (i == 0 || i == s.chars().count() - 1) && c == '_' {
            return false;
        }
        match c {
            'a'..='z' | '0'..='9' => prev_underscore = false,
            '_' => {
                if prev_underscore {
                    return false;
                }
                prev_underscore = true;
            }
            _ => return false,
        }
    }
    true
}

/// 把所有非 ASCII 字母/数字的连续字符替换为 `replacement`(为空则用 `_`)。
pub fn replace_non_alphanumeric(s: &str, replacement: &str) -> String {
    let replacement = if replacement.is_empty() { "_" } else { replacement };
    let mut out = String::with_capacity(s.len());
    let mut in_run = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            in_run = false;
        } else {
            if !in_run {
                out.push_str(replacement);
                in_run = true;
            }
        }
    }
    out
}

/// 按非字母数字字符切分字符串(等价于:先替换成空格再按空白分词)。
pub fn split_by_non_alphanumeric(input: &str) -> Vec<String> {
    input
        .chars()
        .map(|c| if is_letter(c) || is_digit(c) { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// 切分字符串但保留分隔符:每个分隔符自成一个元素。
pub fn split_and_keep_delimiters(input: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut buf = String::new();
    for c in input.chars() {
        if is_letter(c) || is_digit(c) {
            buf.push(c);
        } else {
            if !buf.is_empty() {
                result.push(std::mem::take(&mut buf));
            }
            result.push(c.to_string());
        }
    }
    if !buf.is_empty() {
        result.push(buf);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upper_camel_case() {
        let cases = [
            ("hello world", "HelloWorld"),
            ("hello_world", "HelloWorld"),
            ("hello-world", "HelloWorld"),
            ("hello.world", "HelloWorld"),
            ("helloWorld", "HelloWorld"),
            ("HelloWorld", "HelloWorld"),
            ("HTTPStatusCode", "HttpStatusCode"),
            ("ParseURL.DoParse", "ParseUrlDoParse"),
            ("ParseUrl.DoParse", "ParseUrlDoParse"),
            ("parse_url.do_parse", "ParseUrlDoParse"),
            ("convert space", "ConvertSpace"),
            ("convert-dash", "ConvertDash"),
            ("skip___multiple_underscores", "SkipMultipleUnderscores"),
            ("skip   multiple spaces", "SkipMultipleSpaces"),
            ("skip---multiple-dashes", "SkipMultipleDashes"),
            ("", ""),
            ("a", "A"),
            ("Z", "Z"),
            ("special-characters_test", "SpecialCharactersTest"),
            ("numbers123test", "Numbers123Test"),
            ("hello world!", "HelloWorld"),
            ("test@with#symbols", "TestWithSymbols"),
            ("complexCase123!@#", "ComplexCase123"),
            ("snake_case_string", "SnakeCaseString"),
            ("kebab-case-string", "KebabCaseString"),
            ("PascalCaseString", "PascalCaseString"),
            ("camelCaseString", "CamelCaseString"),
            ("HTTPRequest", "HttpRequest"),
            ("user ID", "UserId"),
            ("UserId", "UserId"),
            ("userID", "UserId"),
            ("UserID", "UserId"),
            ("123NumberPrefix", "123NumberPrefix"),
            ("__leading_underscores", "LeadingUnderscores"),
            ("trailing_underscores__", "TrailingUnderscores"),
            ("multiple___underscores", "MultipleUnderscores"),
            (" spaces around ", "SpacesAround"),
        ];
        for (input, expected) in cases {
            assert_eq!(upper_camel_case(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_lower_camel_case() {
        let cases = [
            ("hello world", "helloWorld"),
            ("hello_world", "helloWorld"),
            ("hello-world", "helloWorld"),
            ("hello.world", "helloWorld"),
            ("helloWorld", "helloWorld"),
            ("HelloWorld", "helloWorld"),
            ("HTTPStatusCode", "httpStatusCode"),
            ("ParseURL.DoParse", "parseUrlDoParse"),
            ("ParseUrl.DoParse", "parseUrlDoParse"),
            ("parse_url.do_parse", "parseUrlDoParse"),
            ("convert space", "convertSpace"),
            ("convert-dash", "convertDash"),
            ("skip___multiple_underscores", "skipMultipleUnderscores"),
            ("skip   multiple spaces", "skipMultipleSpaces"),
            ("skip---multiple-dashes", "skipMultipleDashes"),
            ("", ""),
            ("a", "a"),
            ("Z", "z"),
            ("special-characters_test", "specialCharactersTest"),
            ("numbers123test", "numbers123Test"),
            ("hello world!", "helloWorld"),
            ("test@with#symbols", "testWithSymbols"),
            ("complexCase123!@#", "complexCase123"),
            ("snake_case_string", "snakeCaseString"),
            ("kebab-case-string", "kebabCaseString"),
            ("PascalCaseString", "pascalCaseString"),
            ("camelCaseString", "camelCaseString"),
            ("HTTPRequest", "httpRequest"),
            ("user ID", "userId"),
            ("UserId", "userId"),
            ("userID", "userId"),
            ("UserID", "userId"),
            ("123NumberPrefix", "123NumberPrefix"),
            ("__leading_underscores", "leadingUnderscores"),
            ("trailing_underscores__", "trailingUnderscores"),
            ("multiple___underscores", "multipleUnderscores"),
            (" spaces around ", "spacesAround"),
        ];
        for (input, expected) in cases {
            assert_eq!(lower_camel_case(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_to_snake_case() {
        let cases = [
            ("snake_case", "snake_case"),
            ("CamelCase", "camel_case"),
            ("lowerCamelCase", "lower_camel_case"),
            ("F", "f"),
            ("Foo", "foo"),
            ("FooB", "foo_b"),
            ("FooID", "foo_id"),
            (" FooBar\t", "foo_bar"),
            ("HTTPStatusCode", "http_status_code"),
            ("ParseURL.DoParse", "parse_url_do_parse"),
            ("Convert Space", "convert_space"),
            ("Convert-dash", "convert_dash"),
            ("Skip___MultipleUnderscores", "skip_multiple_underscores"),
            ("Skip   MultipleSpaces", "skip_multiple_spaces"),
            ("Skip---MultipleDashes", "skip_multiple_dashes"),
            ("Hello World", "hello_world"),
            ("Multiple Words Example", "multiple_words_example"),
            ("", ""),
            ("A", "a"),
            ("z", "z"),
            ("Special-Characters_Test", "special_characters_test"),
            ("Numbers123Test", "numbers123_test"),
            ("Hello World!", "hello_world"),
            ("Test@With#Symbols", "test_with_symbols"),
            ("ComplexCase123!@#", "complex_case123"),
            ("md5_hash", "md5_hash"),
            ("md5Hash", "md5_hash"),
            ("md5SHA", "md5_sha"),
            ("userID", "user_id"),
            ("ID123", "id123"),
            ("ID123Test", "id123_test"),
            ("id", "id"),
            ("Id", "id"),
            ("ID", "id"),
        ];
        for (input, expected) in cases {
            assert_eq!(snake_case(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_upper_snake_case() {
        let cases = [
            ("snake_case", "SNAKE_CASE"),
            ("CamelCase", "CAMEL_CASE"),
            ("lowerCamelCase", "LOWER_CAMEL_CASE"),
            ("F", "F"),
            ("Foo", "FOO"),
            ("FooB", "FOO_B"),
            ("FooID", "FOO_ID"),
            (" FooBar\t", "FOO_BAR"),
            ("HTTPStatusCode", "HTTP_STATUS_CODE"),
            ("ParseURL.DoParse", "PARSE_URL_DO_PARSE"),
            ("Convert Space", "CONVERT_SPACE"),
            ("Convert-dash", "CONVERT_DASH"),
            ("Skip___MultipleUnderscores", "SKIP_MULTIPLE_UNDERSCORES"),
            ("Skip   MultipleSpaces", "SKIP_MULTIPLE_SPACES"),
            ("Skip---MultipleDashes", "SKIP_MULTIPLE_DASHES"),
            ("Hello World", "HELLO_WORLD"),
            ("Multiple Words Example", "MULTIPLE_WORDS_EXAMPLE"),
            ("", ""),
            ("A", "A"),
            ("z", "Z"),
            ("Special-Characters_Test", "SPECIAL_CHARACTERS_TEST"),
            ("Numbers123Test", "NUMBERS123_TEST"),
            ("Hello World!", "HELLO_WORLD"),
            ("Test@With#Symbols", "TEST_WITH_SYMBOLS"),
            ("ComplexCase123!@#", "COMPLEX_CASE123"),
        ];
        for (input, expected) in cases {
            assert_eq!(upper_snake_case(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_is_snake_case() {
        let cases = [
            ("snake_case", true),
            ("md5_hash", true),
            ("123", true),
            ("a", true),
            ("foo_bar123_baz", true),
            ("Snake_case", false),
            ("md5Hash", false),
            ("", false),
            ("_a", false),
            ("a_", false),
            ("a__b", false),
            ("_", false),
            ("hello-world", false),
            ("hello!", false),
        ];
        for (input, want) in cases {
            assert_eq!(is_snake_case(input), want, "input: {input:?}");
        }
    }

    #[test]
    fn test_kebab_case() {
        let cases = [
            ("HelloWorld", "hello-world"),
            ("helloWorld", "hello-world"),
            ("Hello World", "hello-world"),
            ("hello world!", "hello-world"),
            ("Numbers123Test", "numbers123-test"),
            ("", ""),
            ("_", ""),
            ("__Hello__World__", "hello-world"),
        ];
        for (input, expected) in cases {
            assert_eq!(kebab_case(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_upper_kebab_case() {
        let cases = [
            ("HelloWorld", "HELLO-WORLD"),
            ("helloWorld", "HELLO-WORLD"),
            ("Hello World", "HELLO-WORLD"),
            ("hello world!", "HELLO-WORLD"),
            ("Numbers123Test", "NUMBERS123-TEST"),
            ("", ""),
            ("_", ""),
            ("__Hello__World__", "HELLO-WORLD"),
        ];
        for (input, expected) in cases {
            assert_eq!(upper_kebab_case(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_split() {
        let cases: &[(&str, &[&str])] = &[
            ("hello world", &["hello", "world"]),
            ("hello_world", &["hello", "world"]),
            ("hello-world", &["hello", "world"]),
            ("hello.world", &["hello", "world"]),
            ("helloWorld", &["hello", "World"]),
            ("HelloWorld", &["Hello", "World"]),
            ("HTTPStatusCode", &["HTTP", "Status", "Code"]),
            ("ParseURLDoParse", &["Parse", "URL", "Do", "Parse"]),
            ("ParseUrlDoParse", &["Parse", "Url", "Do", "Parse"]),
            ("ParseUrl.DoParse", &["Parse", "Url", "Do", "Parse"]),
            ("ParseURL.DoParse", &["Parse", "URL", "Do", "Parse"]),
            ("ParseURL", &["Parse", "URL"]),
            ("ParseURL.", &["Parse", "URL"]),
            ("parse_url.do_parse", &["parse", "url", "do", "parse"]),
            ("convert space", &["convert", "space"]),
            ("convert-dash", &["convert", "dash"]),
            ("skip___multiple_underscores", &["skip", "multiple", "underscores"]),
            ("skip   multiple spaces", &["skip", "multiple", "spaces"]),
            ("skip---multiple-dashes", &["skip", "multiple", "dashes"]),
            ("", &[""]),
            ("a", &["a"]),
            ("Z", &["Z"]),
            ("special-characters_test", &["special", "characters", "test"]),
            ("numbers123test", &["numbers", "123", "test"]),
            ("hello world!", &["hello", "world"]),
            ("test@with#symbols", &["test", "with", "symbols"]),
            ("complexCase123!@#", &["complex", "Case", "123"]),
            ("snake_case_string", &["snake", "case", "string"]),
            ("kebab-case-string", &["kebab", "case", "string"]),
            ("PascalCaseString", &["Pascal", "Case", "String"]),
            ("camelCaseString", &["camel", "Case", "String"]),
            ("HTTPRequest", &["HTTP", "Request"]),
            ("user ID", &["user", "ID"]),
            ("UserId", &["User", "Id"]),
            ("userID", &["user", "ID"]),
            ("UserID", &["User", "ID"]),
            ("123NumberPrefix", &["123", "Number", "Prefix"]),
            ("__leading_underscores", &["leading", "underscores"]),
            ("trailing_underscores__", &["trailing", "underscores"]),
            ("multiple___underscores", &["multiple", "underscores"]),
            (" spaces around ", &["spaces", "around"]),
        ];
        for (input, expected) in cases {
            let result = split(input);
            let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
            assert_eq!(result, expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_split_by_non_alphanumeric() {
        let cases: &[(&str, &[&str])] = &[
            ("hello-world", &["hello", "world"]),
            ("hello_world", &["hello", "world"]),
            ("hello.world", &["hello", "world"]),
            ("hello world", &["hello", "world"]),
            ("hello123world", &["hello123world"]),
            ("hello123 world", &["hello123", "world"]),
            ("hello-world_123", &["hello", "world", "123"]),
            ("!hello@world#", &["hello", "world"]),
        ];
        for (input, expected) in cases {
            let result = split_by_non_alphanumeric(input);
            let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
            assert_eq!(result, expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_split_and_keep_delimiters() {
        let cases: &[(&str, &[&str])] = &[
            ("hello-world", &["hello", "-", "world"]),
            ("hello_world", &["hello", "_", "world"]),
            ("hello.world", &["hello", ".", "world"]),
            ("hello world", &["hello", " ", "world"]),
            ("hello123world", &["hello123world"]),
            ("hello123 world", &["hello123", " ", "world"]),
            ("hello-world_123", &["hello", "-", "world", "_", "123"]),
            ("!hello@world#", &["!", "hello", "@", "world", "#"]),
        ];
        for (input, expected) in cases {
            let result = split_and_keep_delimiters(input);
            let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
            assert_eq!(result, expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_split_with_no_split() {
        // noSplit 的词从词首匹配时保护整词不被拆分
        let result = split_with("HTTPStatusCode", &["StatusCode"]);
        assert_eq!(result, vec!["HTTP", "StatusCode"]);
        // 不从词首开始时,无保护效果(与 Go 版一致)
        let result2 = split_with("HTTPStatusCode", &["Status"]);
        assert_eq!(result2, vec!["HTTP", "Status", "Code"]);
    }
}
