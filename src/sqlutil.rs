//! PostgreSQL 词法级 SQL 脱敏与表名提取。
//!
//! 手写的逐字节词法扫描器,不依赖任何 SQL 解析库:
//!
//! - [`mask_sql`] 函数:把字符串字面量(`'…'`、`E'…'`、`$tag$…$tag$`)与数值字面量
//!   整体替换为 `***`,保留 SQL 结构(关键字、双引号标识符、`$n` 占位符、
//!   注释、`::` 类型转换),常用于生成"同构 SQL"的脱敏指纹(按 digest 分组);
//! - [`extract_tables`] 函数:从(已脱敏的)SQL 文本提取被访问的数据表名,覆盖
//!   FROM / INSERT INTO / UPDATE / DELETE FROM / JOIN 及 FROM 的逗号多表。
//!
//! 词法规则(照 PostgreSQL 语义逐式复刻):
//!
//! - 单引号串内 `'` 与 `\'` 均按转义处理(宁多掩不漏掩:普通串在
//!   standard_conforming_strings 下 `'\'` 是字面反斜杠,按转义处理只会
//!   多吞字符、不会提前截断导致漏脱敏);
//! - 美元引用支持空标签 `$$` 与 `$tag$`,可跨行,整体脱敏;
//! - 块注释支持嵌套;注释与双引号标识符中的引号不会被误判;
//! - `$n` 占位符原样保留(参数值本就不在 SQL 文本中)。
//!
//! ```
//! use rust_utils::sqlutil;
//!
//! let masked = sqlutil::mask_sql(
//!     "SELECT id FROM sys_users WHERE email = 'a@b.c' AND age > 25 LIMIT 10",
//! );
//! assert_eq!(
//!     masked,
//!     "SELECT id FROM sys_users WHERE email = *** AND age > *** LIMIT ***"
//! );
//!
//! let tables = sqlutil::extract_tables(
//!     "SELECT * FROM \"sys_users\" AS u JOIN \"sys_roles\" r ON u.rid = r.id",
//! );
//! assert_eq!(tables, ["sys_users", "sys_roles"]);
//! ```

use std::collections::HashSet;

/// 字面量脱敏后的统一占位符(Go 版 `maskToken`)。
pub const MASK_TOKEN: &str = "***";

/// 当前脱敏策略标识,调用方可随审计记录落库留痕(Go 版 `MaskingRules`)。
pub const MASKING_RULES: &str = "sql_literals:v1";

/// 对 SQL 文本做字面量级脱敏(Go 版 `MaskSQL`):字符串字面量(`'…'`、
/// `E'…'`、`$tag$…$tag$`)与数值字面量整体替换为 [`MASK_TOKEN`],保留 SQL
/// 结构(关键字、双引号标识符、`$n` 占位符、注释、`::` 类型转换)。
///
/// 字面量不同、结构相同的 SQL 脱敏后结果一致,可直接作指纹分组。
///
/// ```
/// use rust_utils::sqlutil::{mask_sql, MASK_TOKEN};
///
/// assert_eq!(mask_sql("WHERE n = 'O''Brien'"), format!("WHERE n = {MASK_TOKEN}"));
/// assert_eq!(mask_sql("WHERE id = $1"), "WHERE id = $1");
/// assert_eq!(mask_sql("SET a = ''"), "SET a = ***");
/// ```
pub fn mask_sql(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let n = bytes.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        let c = bytes[i];
        if c == b'\'' {
            // 单引号串(含 '' 与 \' 转义):整体脱敏
            out.extend_from_slice(MASK_TOKEN.as_bytes());
            i = scan_string(bytes, i + 1);
        } else if c == b'"' {
            // 双引号标识符:原样保留
            i = copy_verbatim(&mut out, bytes, i, scan_quoted_ident(bytes, i + 1));
        } else if c == b'-' && i + 1 < n && bytes[i + 1] == b'-' {
            // 行注释:原样保留
            i = copy_verbatim(&mut out, bytes, i, scan_line_comment(bytes, i));
        } else if c == b'/' && i + 1 < n && bytes[i + 1] == b'*' {
            // 块注释(可嵌套):原样保留
            i = copy_verbatim(&mut out, bytes, i, scan_block_comment(bytes, i));
        } else if c == b'$' {
            i = mask_dollar(&mut out, bytes, i);
        } else if (c == b'e' || c == b'E') && i + 1 < n && bytes[i + 1] == b'\'' {
            // E'…' 转义串:与普通串同一套扫描('\' 已按转义处理)
            out.extend_from_slice(MASK_TOKEN.as_bytes());
            i = scan_string(bytes, i + 2);
        } else if is_digit(c) || (c == b'.' && i + 1 < n && is_digit(bytes[i + 1])) {
            // 数值字面量(整数/小数/科学计数/十六进制):整体脱敏
            out.extend_from_slice(MASK_TOKEN.as_bytes());
            i = scan_number(bytes, i);
        } else {
            out.push(c);
            i += 1;
        }
    }
    // 扫描只按 ASCII 边界切分,原文按字节原样拷贝,拼接结果必为合法 UTF-8。
    String::from_utf8(out).expect("mask_sql 输出必为合法 UTF-8")
}

/// 从(已脱敏的)SQL 文本提取被访问的数据表名(Go 版 `ExtractTables`)。
/// 覆盖 FROM / INSERT INTO / UPDATE / DELETE FROM / JOIN 及 FROM 的逗号多表;
/// 跳过子查询括号(内层 FROM 会在主扫描中被再次捕获);按首个出现顺序去重。
/// 依赖 [`mask_sql`] 的词法扫描器(字符串/注释不拆词、双引号标识符整体成词)。
///
/// ```
/// use rust_utils::sqlutil::extract_tables;
///
/// assert_eq!(extract_tables("DELETE FROM \"sys_users\" WHERE \"id\" = $1"), ["sys_users"]);
/// assert_eq!(
///     extract_tables("SELECT * FROM \"a\", \"b\" WHERE x = y"),
///     ["a", "b"]
/// );
/// assert_eq!(extract_tables("SHOW server_version"), [""; 0]);
/// ```
pub fn extract_tables(sql: &str) -> Vec<String> {
    let toks = lex_sql(sql);
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add = |name: &str| {
        let lower = name.to_lowercase();
        if lower.is_empty() || seen.contains(&lower) {
            return;
        }
        seen.insert(lower);
        out.push(name.to_string());
    };
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        // 关键字判断只认裸词;引号标识符一律不是关键字
        if t.kind != TokKind::Ident || t.quoted {
            i += 1;
            continue;
        }
        let multi = match t.text.to_ascii_uppercase().as_str() {
            "FROM" | "INTO" => true,
            "UPDATE" | "JOIN" => false,
            _ => {
                i += 1;
                continue;
            }
        };
        i = parse_tables(&toks, i + 1, multi, &mut add);
    }
    out
}

// ---- 脱敏词法扫描器(sqlmask.go) ----

/// 扫描单引号串,`i` 为开引号后首字节,返回闭引号后一字节索引。
fn scan_string(sql: &[u8], mut i: usize) -> usize {
    let n = sql.len();
    while i < n {
        match sql[i] {
            b'\\' => i += 2, // \' 转义(E 串标准语义;普通串宁多掩不漏掩)
            b'\'' => {
                if i + 1 < n && sql[i + 1] == b'\'' {
                    i += 2; // '' 转义
                    continue;
                }
                return i + 1;
            }
            _ => i += 1,
        }
    }
    n // 未闭合:脱敏到末尾
}

/// 扫描双引号标识符(`""` 为转义引号),内容不脱敏。
fn scan_quoted_ident(sql: &[u8], mut i: usize) -> usize {
    let n = sql.len();
    while i < n {
        if sql[i] == b'"' {
            if i + 1 < n && sql[i + 1] == b'"' {
                i += 2;
                continue;
            }
            return i + 1;
        }
        i += 1;
    }
    n // 未闭合:保留到末尾
}

/// 扫描行注释(不含换行符),内容原样保留。
fn scan_line_comment(sql: &[u8], mut i: usize) -> usize {
    let n = sql.len();
    while i < n && sql[i] != b'\n' {
        i += 1;
    }
    i
}

/// 扫描块注释(PG 支持嵌套),内容原样保留。
fn scan_block_comment(sql: &[u8], mut i: usize) -> usize {
    let n = sql.len();
    let mut depth = 0;
    while i < n {
        if sql[i] == b'/' && i + 1 < n && sql[i + 1] == b'*' {
            depth += 1;
            i += 2;
            continue;
        }
        if sql[i] == b'*' && i + 1 < n && sql[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return i;
            }
            continue;
        }
        i += 1;
    }
    n
}

/// 处理 `'$'`:`$n` 占位符原样保留;`$tag$…$tag$` 美元引用整体脱敏;
/// 其余(非法或结尾 `'$'`)原样保留单字节。
fn mask_dollar(out: &mut Vec<u8>, sql: &[u8], i: usize) -> usize {
    let n = sql.len();
    // $n 占位符:数字后跟非标识字符
    let mut j = i + 1;
    while j < n && is_digit(sql[j]) {
        j += 1;
    }
    if j > i + 1 && (j >= n || !is_ident_char(sql[j])) {
        copy_verbatim(out, sql, i, j);
        return j;
    }
    // 美元引用:$tag$(tag 可为空,不以数字开头)
    let mut k = i + 1;
    if k < n && !is_digit(sql[k]) {
        while k < n && is_ident_char(sql[k]) {
            k += 1;
        }
    }
    if k < n && sql[k] == b'$' {
        // tag 仅含 '$' 与标识字符,必为合法 UTF-8 切片
        let tag = &sql[i..k + 1];
        if let Some(rest) = find_subslice(&sql[k + 1..], tag) {
            out.extend_from_slice(MASK_TOKEN.as_bytes());
            return k + 1 + rest + tag.len();
        }
    }
    out.push(b'$');
    i + 1
}

/// 扫描数值字面量(整数/小数/科学计数/十六进制)。
fn scan_number(sql: &[u8], i: usize) -> usize {
    let n = sql.len();
    let mut j = i;
    while j < n {
        let c = sql[j];
        if is_digit(c) || c == b'.' || is_ident_char(c) {
            j += 1;
            continue;
        }
        if (c == b'+' || c == b'-')
            && j > i
            && (sql[j - 1] == b'e' || sql[j - 1] == b'E')
            && j + 1 < n
            && is_digit(sql[j + 1])
        {
            j += 1; // 科学计数指数符号
            continue;
        }
        break;
    }
    j
}

/// 把 `sql[start..end]` 原样写入输出,返回 `end`。
fn copy_verbatim(out: &mut Vec<u8>, sql: &[u8], start: usize, end: usize) -> usize {
    out.extend_from_slice(&sql[start..end]);
    end
}

/// 字节串查找(`strings.Index` 语义;needle 恒非空)。
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn is_ident_char(c: u8) -> bool {
    c == b'_' || c.is_ascii_lowercase() || c.is_ascii_uppercase() || c.is_ascii_digit()
}

// ---- 简化词法器:ident(裸词/双引号)与单字节标点(extract_tables.go) ----

/// token 类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokKind {
    /// 裸词或双引号标识符。
    Ident,
    /// 单字节标点。
    Punct,
}

/// 词法 token。文本在退化边界(未闭合引号标识符、引号恰在串末尾、
/// 引号外的非 ASCII 字节)按损失转换,不 panic;下游只比较 ASCII 标点。
#[derive(Debug, Clone, PartialEq, Eq)]
struct SqlToken {
    text: String,
    kind: TokKind,
    quoted: bool,
}

/// 把 SQL 切成 token:字符串字面量与注释整体跳过(复用 sqlmask 的扫描器),
/// 双引号标识符去引号成 ident(quoted=true,关键字判断只认裸词)。
fn lex_sql(sql: &str) -> Vec<SqlToken> {
    let bytes = sql.as_bytes();
    let n = bytes.len();
    let mut toks: Vec<SqlToken> = Vec::new();
    let mut i = 0;
    while i < n {
        let c = bytes[i];
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
            i += 1;
        } else if c == b'\'' {
            i = scan_string(bytes, i + 1);
        } else if c == b'-' && i + 1 < n && bytes[i + 1] == b'-' {
            i = scan_line_comment(bytes, i);
        } else if c == b'/' && i + 1 < n && bytes[i + 1] == b'*' {
            i = scan_block_comment(bytes, i);
        } else if c == b'"' {
            let j = scan_quoted_ident(bytes, i + 1);
            // 未闭合标识符与 Go 版一致取 [i+1, j-1)(丢最后一个字节);
            // 引号恰在串末尾时 Go 会越界 panic,这里钳制为空串。
            let start = i + 1;
            let end = (j - 1).max(start);
            toks.push(SqlToken {
                kind: TokKind::Ident,
                quoted: true,
                text: String::from_utf8_lossy(&bytes[start..end]).into_owned(),
            });
            i = j;
        } else if is_ident_char(c) {
            let mut j = i;
            while j < n && is_ident_char(bytes[j]) {
                j += 1;
            }
            // 裸词仅含 ASCII,切片必为字符边界
            toks.push(SqlToken {
                kind: TokKind::Ident,
                quoted: false,
                text: sql[i..j].to_string(),
            });
            i = j;
        } else {
            toks.push(SqlToken {
                kind: TokKind::Punct,
                quoted: false,
                text: String::from_utf8_lossy(&bytes[i..i + 1]).into_owned(),
            });
            i += 1;
        }
    }
    toks
}

/// 表引用位置的裸词黑名单:出现在这里说明不是表名
/// (如 ON CONFLICT ... DO UPDATE SET 中的 SET——UPDATE 关键字误触发时兜底)。
fn is_table_stop_word(word: &str) -> bool {
    matches!(
        word,
        "AS" | "SET"
            | "WHERE"
            | "SELECT"
            | "VALUES"
            | "ON"
            | "DO"
            | "NOTHING"
            | "RETURNING"
            | "GROUP"
            | "ORDER"
            | "LIMIT"
            | "OFFSET"
            | "JOIN"
            | "LEFT"
            | "RIGHT"
            | "INNER"
            | "OUTER"
            | "CROSS"
            | "FULL"
            | "USING"
            | "UNION"
            | "EXCEPT"
            | "INTERSECT"
            | "EXCLUDED"
            | "DEFAULT"
            | "WITH"
            | "FOR"
            | "TO"
            | "WHEN"
            | "THEN"
            | "ELSE"
            | "END"
            | "AND"
            | "OR"
            | "NOT"
            | "IS"
            | "NULL"
            | "IN"
            | "EXISTS"
            | "BETWEEN"
            | "LIKE"
            | "ILIKE"
            | "HAVING"
            | "DISTINCT"
            | "ALL"
            | "CASE"
            | "ASC"
            | "DESC"
            | "ONLY"
            | "NOWAIT"
            | "SKIP"
    )
}

/// 从 `toks[i]` 起解析表引用:`[schema.]table [AS alias]`,multi 时
/// 支持逗号连接多个。遇到子查询 `'('`、停用词或其它非标识 token 即止,
/// 返回停止处的 token 下标(供主扫描继续找后续关键字,如 JOIN)。
fn parse_tables(
    toks: &[SqlToken],
    mut i: usize,
    multi: bool,
    add: &mut dyn FnMut(&str),
) -> usize {
    while i < toks.len() {
        let (name, next) = match parse_ident_ref(toks, i) {
            Some(found) => found,
            None => return i,
        };
        add(&name);
        i = next;
        // 可选 AS 别名(别名可为裸词或引号标识符,不计入表名)
        if i < toks.len()
            && toks[i].kind == TokKind::Ident
            && !toks[i].quoted
            && toks[i].text.eq_ignore_ascii_case("AS")
        {
            i += 1;
            if i < toks.len() && toks[i].kind == TokKind::Ident {
                i += 1;
            }
        }
        if multi && i < toks.len() && toks[i].kind == TokKind::Punct && toks[i].text == "," {
            i += 1;
            continue;
        }
        return i;
    }
    i
}

/// 解析单个(可 schema 限定的)表引用,返回完整名与下一 token 下标。
/// 裸词且命中停用词黑名单时视为非表名(返回 None)。
fn parse_ident_ref(toks: &[SqlToken], i: usize) -> Option<(String, usize)> {
    if i >= toks.len() || toks[i].kind != TokKind::Ident {
        return None;
    }
    let first = &toks[i];
    if !first.quoted && is_table_stop_word(first.text.to_ascii_uppercase().as_str()) {
        return None;
    }
    let mut parts = Vec::with_capacity(2);
    parts.push(first.text.clone());
    let mut i = i + 1;
    // schema.table:'.' 后再接一个标识符
    if i + 1 < toks.len()
        && toks[i].kind == TokKind::Punct
        && toks[i].text == "."
        && toks[i + 1].kind == TokKind::Ident
    {
        parts.push(toks[i + 1].text.clone());
        i += 2;
    }
    Some((parts.join("."), i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_sql() {
        // 上游 sqlmask_test.go 的 TestMaskSQL 用例
        let cases: &[(&str, &str, &str)] = &[
            (
                "字符串字面量脱敏",
                "SELECT id FROM t WHERE email = 'a@b.c'",
                "SELECT id FROM t WHERE email = ***",
            ),
            (
                "双单引号转义整体脱敏",
                "WHERE n = 'O''Brien'",
                "WHERE n = ***",
            ),
            (
                "反斜杠转义整体脱敏",
                r"WHERE n = 'O\'Brien'",
                "WHERE n = ***",
            ),
            (
                "E 转义串",
                r"WHERE a = E'x\ny'",
                "WHERE a = ***",
            ),
            (
                "数值字面量脱敏",
                "WHERE age > 25 AND score = 1.5e-3",
                "WHERE age > *** AND score = ***",
            ),
            (
                "占位符保留",
                r#"WHERE id = $1 AND t."uid" = $12"#,
                r#"WHERE id = $1 AND t."uid" = $12"#,
            ),
            (
                "双引号标识符保留",
                r#"SELECT "sys_users"."password" FROM "sys_users""#,
                r#"SELECT "sys_users"."password" FROM "sys_users""#,
            ),
            (
                "行注释原样且引号不误判",
                "SELECT 1 -- don't leak 'x'\nFROM t",
                "SELECT *** -- don't leak 'x'\nFROM t",
            ),
            (
                "嵌套块注释原样",
                r"/* 'a' /* 'b' */ 'c' */ SELECT 'd'",
                r"/* 'a' /* 'b' */ 'c' */ SELECT ***",
            ),
            (
                "美元引用空标签整体脱敏",
                "DO $$ BEGIN RAISE 'hi'; END $$",
                "DO ***",
            ),
            (
                "美元引用带标签整体脱敏",
                "$fn$ body 'q' $fn$",
                "***",
            ),
            (
                "INSERT VALUES 与 RETURNING",
                "INSERT INTO t (a,b) VALUES ('x', 42) RETURNING id",
                "INSERT INTO t (a,b) VALUES (***, ***) RETURNING id",
            ),
            (
                "类型转换保留",
                "WHERE x = 'a'::text AND n = 5::int",
                "WHERE x = ***::text AND n = ***::int",
            ),
            (
                "空串脱敏",
                "SET a = ''",
                "SET a = ***",
            ),
            (
                "十六进制串",
                "INSERT INTO t VALUES (X'deadbeef')",
                "INSERT INTO t VALUES (X***)",
            ),
            (
                "LIMIT/OFFSET 数值",
                "SELECT * FROM t LIMIT 10 OFFSET 0",
                "SELECT * FROM t LIMIT *** OFFSET ***",
            ),
            (
                "未闭合串脱敏到末尾",
                "WHERE a = 'abc",
                "WHERE a = ***",
            ),
            (
                "UPDATE SET",
                "UPDATE users SET nickname = '喵', age = 30 WHERE id = 5",
                "UPDATE users SET nickname = ***, age = *** WHERE id = ***",
            ),
        ];
        for (name, input, want) in cases {
            assert_eq!(mask_sql(input), *want, "case: {name}");
        }
    }

    /// 指纹稳定性:字面量不同、结构相同的 SQL 脱敏后应一致(digest 分组语义)。
    #[test]
    fn test_mask_sql_fingerprint() {
        let a = mask_sql("SELECT * FROM users WHERE email = 'alice@x.com' AND age > 20");
        let b = mask_sql("SELECT * FROM users WHERE email = 'bob@y.org' AND age > 35");
        assert_eq!(a, b, "同构 SQL 脱敏后不一致");
    }

    /// 脱敏词法的边角分支(上游 TestMaskSQLLexerEdges):
    /// 未闭合字符串脱敏到末尾、引号标识符内的 "" 转义与未闭合标识符原样保留、
    /// 嵌套与未闭合块注释原样保留、行注释原样保留、$1 处于串末尾仍按占位符保留、
    /// 孤立 $ 原样单字节、美元引用整体脱敏、十六进制数值按数值脱敏。
    #[test]
    fn test_mask_sql_lexer_edges() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "未闭合字符串脱敏到末尾",
                "WHERE a = 'abc",
                "WHERE a = ***",
            ),
            (
                "引号标识符内双引号转义原样保留",
                r#"SELECT "a""b" FROM t"#,
                r#"SELECT "a""b" FROM t"#,
            ),
            (
                "未闭合引号标识符原样保留到末尾",
                r#"SELECT "unterminated"#,
                r#"SELECT "unterminated"#,
            ),
            (
                "嵌套块注释原样保留(其中数字仍脱敏)",
                "SELECT /* a /* b */ c */ 1",
                "SELECT /* a /* b */ c */ ***",
            ),
            (
                "未闭合块注释原样保留到末尾(前导数字仍脱敏)",
                "SELECT 1 /* xx",
                "SELECT *** /* xx",
            ),
            (
                "行注释原样保留(前导数字仍脱敏)",
                "SELECT 1 -- trailing comment",
                "SELECT *** -- trailing comment",
            ),
            (
                "占位符处于串末尾",
                "WHERE id = $1",
                "WHERE id = $1",
            ),
            (
                "孤立美元符号原样保留",
                "a $ b",
                "a $ b",
            ),
            (
                "美元引用整体脱敏",
                "SELECT $tag$secret body$tag$ FROM t",
                "SELECT *** FROM t",
            ),
            (
                "空标签美元引用整体脱敏",
                "SELECT $$secret$$ FROM t",
                "SELECT *** FROM t",
            ),
            (
                "十六进制数值脱敏",
                "WHERE a = 0xFF",
                "WHERE a = ***",
            ),
        ];
        for (name, input, want) in cases {
            assert_eq!(mask_sql(input), *want, "case: {name}");
        }
    }

    /// 上游 extract_tables_test.go 的 TestExtractTables 用例;
    /// 每条用例同时跑在原始与脱敏文本上(提取应两者皆可)。
    #[test]
    fn test_extract_tables() {
        let cases: &[(&str, &str, &[&str])] = &[
            (
                "ent select quoted",
                r#"SELECT "sys_users"."id" FROM "sys_users" WHERE "sys_users"."id" = $1 LIMIT *** OFFSET ***"#,
                &["sys_users"],
            ),
            (
                "select count",
                r#"SELECT COUNT("sys_policy_evaluation_logs"."id") FROM "sys_policy_evaluation_logs""#,
                &["sys_policy_evaluation_logs"],
            ),
            (
                "insert into",
                r#"INSERT INTO "sys_users" ("name", "age") VALUES ($1, $2) RETURNING "id""#,
                &["sys_users"],
            ),
            (
                "upsert on conflict do update",
                r#"INSERT INTO "sys_users" ("id", "name") VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name = $3"#,
                &["sys_users"],
            ),
            (
                "update set",
                r#"UPDATE "sys_users" SET "name" = $1 WHERE "id" = $2"#,
                &["sys_users"],
            ),
            (
                "delete from",
                r#"DELETE FROM "sys_users" WHERE "id" = $1"#,
                &["sys_users"],
            ),
            (
                "joins",
                r#"SELECT * FROM "sys_user_org_units" AS u0 JOIN "sys_org_units" AS u1 ON u0."org" = u1."id" LEFT JOIN "sys_positions" p ON u1."id" = p."org""#,
                &["sys_user_org_units", "sys_org_units", "sys_positions"],
            ),
            (
                "from comma list",
                r#"SELECT * FROM "a", "b" WHERE x = y"#,
                &["a", "b"],
            ),
            (
                "subquery paren skipped",
                r#"SELECT * FROM (SELECT "id" FROM "sys_users") AS t WHERE t."id" = ***"#,
                &["sys_users"],
            ),
            (
                "dedupe",
                r#"SELECT * FROM "sys_users" JOIN "sys_roles" ON 1=1 JOIN "sys_users" ON 2=2"#,
                &["sys_users", "sys_roles"],
            ),
            (
                "schema qualified keeps full name",
                r#"SELECT * FROM public."sys_users""#,
                &["public.sys_users"],
            ),
            (
                "bare unquoted",
                "select * from sys_users where id = 1",
                &["sys_users"],
            ),
            (
                "no from ddl-ish",
                "SHOW server_version",
                &[],
            ),
            (
                "masked literals present",
                r#"SELECT "t"."a" FROM "t" WHERE "t"."name" = *** AND "t"."n" > ***"#,
                &["t"],
            ),
        ];
        for (name, sql, want) in cases {
            for input in [sql.to_string(), mask_sql(sql)] {
                let got = extract_tables(&input);
                if got.is_empty() && want.is_empty() {
                    continue;
                }
                assert_eq!(got, *want, "case: {name}");
            }
        }
    }

    /// Rust 侧新增的退化边界(Go 版在引号恰在末尾时会越界 panic、
    /// 非 ASCII 标点会切出非法字节串,这里保证不 panic 且语义不变)。
    #[test]
    fn test_lexer_degenerate_edges() {
        // 引号恰在末尾:空 ident,不 panic
        assert!(extract_tables("SELECT \"").is_empty());
        // 未闭合引号标识符:与 Go 版一致丢最后一个字节
        let toks = lex_sql(r#"FROM "unterminated"#);
        assert_eq!(toks[1].text, "unterminate");
        assert!(toks[1].quoted);
        // 引号外的多字节字符:逐字节损失转换,不 panic
        assert_eq!(extract_tables("SELECT * FROM t AS 别名"), ["t"]);
        assert_eq!(mask_sql("SELECT '喵'"), "SELECT ***");
    }
}
