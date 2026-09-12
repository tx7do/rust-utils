//! MySQL `CREATE TABLE` DDL 解析器(移植自 go-utils/ddl_parser)。
//!
//! 手写的分词/解析,不依赖任何 SQL 解析库。能提取表名、列定义
//! (类型、可空性、主键、默认值、注释、自增、唯一)以及表级属性
//! (ENGINE / CHARSET / COLLATE / COMMENT),并跳过表级约束
//! (PRIMARY KEY / FOREIGN KEY / UNIQUE KEY / INDEX / KEY)。
//!
//! ```
//! use rust_utils::ddl_parser;
//!
//! let table = ddl_parser::parse_create_table(
//!     "CREATE TABLE `users` (\
//!         `id` BIGINT AUTO_INCREMENT PRIMARY KEY, \
//!         `userName` VARCHAR(100) NOT NULL COMMENT '用户名'\
//!     ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表'",
//! )
//! .unwrap();
//!
//! assert_eq!(table.name, "users");
//! assert_eq!(table.columns.len(), 2);
//! assert!(table.columns[0].auto_increment);
//! assert_eq!(table.columns[1].comment, "用户名");
//! assert_eq!(table.engine, "innodb");
//! assert_eq!(table.charset, "utf8mb4");
//! assert_eq!(table.comment, "用户表");
//! ```

/// 列定义。
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ColumnDef {
    /// 列名(去除引号/反引号)。
    pub name: String,
    /// 原始类型(如 `varchar(100)`),已随语句统一转为小写。
    pub column_type: String,
    /// 是否可空。
    pub nullable: bool,
    /// 是否主键。
    pub primary_key: bool,
    /// 默认值字面量(未设置时为空串)。
    pub default: String,
    /// 注释内容。
    pub comment: String,
    /// 是否自增。
    pub auto_increment: bool,
    /// 是否唯一。
    pub unique: bool,
}

/// 表定义。
#[derive(Debug, Default, Clone, PartialEq)]
pub struct TableDef {
    /// 表名。
    pub name: String,
    /// 列定义。
    pub columns: Vec<ColumnDef>,
    /// 索引定义(当前版本不填充,表级索引被跳过)。
    pub indexes: Vec<String>,
    /// 存储引擎(MySQL 特有)。
    pub engine: String,
    /// 字符集(MySQL 特有)。
    pub charset: String,
    /// 表注释。
    pub comment: String,
    /// 排序规则。
    pub collation: String,
}

/// 标准化 SQL:去掉块注释与行注释、引号外转小写、压平空白。
fn normalize_sql(sql: &str) -> String {
    let sql = remove_block_comments(sql);
    let sql = remove_line_comments(&sql);
    let lowered = lowercase_preserving_quotes(&sql);
    lowered.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// 移除 `/* ... */` 块注释(非贪婪,到最近的 `*/`)。
fn remove_block_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut rest = sql;
    loop {
        match rest.find("/*") {
            Some(start) => match rest[start..].find("*/") {
                Some(end_rel) => {
                    out.push_str(&rest[..start]);
                    out.push(' ');
                    rest = &rest[start + end_rel + 2..];
                }
                // 未闭合的块注释:吞掉剩余全部(与正则行为一致)
                None => {
                    out.push_str(&rest[..start]);
                    out.push(' ');
                    break;
                }
            },
            None => {
                out.push_str(rest);
                break;
            }
        }
    }
    out
}

/// 移除 `-- ...` 行注释(到行尾)。
///
/// 注:Go 版正则 `--.*?$` 未开多行模式,只能删掉末尾一行的注释,
/// 这里修正为标准的"删到行尾"语义。
fn remove_line_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    for line in sql.split('\n') {
        match line.find("--") {
            Some(idx) => {
                out.push_str(&line[..idx]);
                out.push(' ');
                out.push('\n');
            }
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    // 上面按行补了换行,末尾多出的一个不影响后续空白压平
    out
}

/// 引号内(单引号/双引号/反引号)保留原样,其余转小写。
fn lowercase_preserving_quotes(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let (mut in_single, mut in_double, mut in_backtick) = (false, false, false);
    for ch in sql.chars() {
        if ch == '\'' && !in_double && !in_backtick {
            in_single = !in_single;
        } else if ch == '"' && !in_single && !in_backtick {
            in_double = !in_double;
        } else if ch == '`' && !in_single && !in_double {
            in_backtick = !in_backtick;
        }
        if in_single || in_double || in_backtick {
            out.push(ch);
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out
}

/// 提取表名(支持 `IF NOT EXISTS` 与引号/反引号包裹)。
fn extract_table_name(sql: &str) -> Result<String, String> {
    let mut rest = sql;
    // 标准化后空白已被压平,直接找 "create table "
    let Some(idx) = rest.find("create table") else {
        return Err(format!("无法提取表名: {}", truncate(sql, 50)));
    };
    rest = &rest[idx + "create table".len()..];
    let rest = rest.trim_start();
    let rest = match rest.strip_prefix("if not exists") {
        Some(r) => r.trim_start(),
        None => rest,
    };
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '`' | '"'))
        .collect();
    if name.is_empty() {
        return Err(format!("无法提取表名: {}", truncate(sql, 50)));
    }
    Ok(name.trim_matches(|c| c == '`' || c == '"').to_string())
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// 提取括号内的字段定义块(处理嵌套括号)。
fn extract_column_block(sql: &str) -> Result<String, String> {
    let Some(left_idx) = sql.find('(') else {
        return Err("未找到字段定义块".to_string());
    };
    let right_idx = find_matching_paren(sql, left_idx);
    match right_idx {
        Some(r) => Ok(sql[left_idx + 1..r].to_string()),
        None => Err("括号不匹配".to_string()),
    }
}

/// 在 `left_idx`(一个 `(`)处寻找匹配的 `)`,返回其字节下标。
fn find_matching_paren(sql: &str, left_idx: usize) -> Option<usize> {
    let bytes = sql.as_bytes();
    let mut level = 0i32;
    for (i, &b) in bytes.iter().enumerate().skip(left_idx) {
        match b {
            b'(' => level += 1,
            b')' => {
                level -= 1;
                if level == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// 解析字段定义块。
fn parse_columns(block: &str) -> Vec<ColumnDef> {
    let mut columns: Vec<ColumnDef> = Vec::new();
    let mut primary_key_columns: Vec<String> = Vec::new();

    for part in split_columns(block) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let part_lower = part.to_lowercase();

        if part_lower.starts_with("primary key") {
            primary_key_columns.extend(extract_primary_key_columns(part));
            continue;
        }

        if is_table_constraint(&part_lower) {
            continue;
        }

        if let Ok(col) = parse_column(part) {
            columns.push(col);
        }
    }

    if !primary_key_columns.is_empty() {
        for col in columns.iter_mut() {
            if primary_key_columns.iter().any(|pk| *pk == col.name) {
                col.primary_key = true;
            }
        }
    }
    columns
}

/// 从表级 `PRIMARY KEY (col1, col2, ...)` 约束中提取列名。
fn extract_primary_key_columns(constraint_def: &str) -> Vec<String> {
    let lower = constraint_def.to_lowercase();
    let Some(idx) = lower.find("primary key") else {
        return Vec::new();
    };
    let rest = lower[idx + "primary key".len()..].trim_start();
    let Some(rest) = rest.strip_prefix('(') else {
        return Vec::new();
    };
    let Some(end) = rest.find(')') else {
        return Vec::new();
    };
    rest[..end]
        .split(',')
        .map(|c| c.trim().trim_matches(|c| c == '`' || c == '"').to_string())
        .filter(|c| !c.is_empty())
        .collect()
}

/// 判断是否为表级约束(不是列定义)。
fn is_table_constraint(part_lower: &str) -> bool {
    const PREFIXES: [&str; 6] = [
        "foreign key",
        "constraint",
        "fulltext",
        "spatial",
        "unique key",
        "unique index",
    ];
    if PREFIXES.iter().any(|p| part_lower.starts_with(p)) {
        return true;
    }
    // `KEY name (...)` / `INDEX name (...)` / `KEY (...)` / `INDEX (...)`
    for kw in ["key", "index"] {
        if let Some(rest) = part_lower.strip_prefix(kw) {
            let rest = rest.trim_start();
            if rest.starts_with('(') {
                return true;
            }
            let mut it = rest.splitn(2, char::is_whitespace);
            if let (Some(first_word), Some(after)) = (it.next(), it.next()) {
                if !first_word.is_empty() && after.trim_start().starts_with('(') {
                    return true;
                }
            }
        }
    }
    false
}

/// 智能按逗号分割字段定义(跳过括号与引号内的逗号)。
fn split_columns(block: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let (mut in_single, mut in_double) = (false, false);
    let mut paren_level = 0i32;

    for ch in block.chars() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '(' if !in_single && !in_double => paren_level += 1,
            ')' if !in_single && !in_double => paren_level -= 1,
            ',' if paren_level == 0 && !in_single && !in_double => {
                parts.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// 解析单个字段定义。
fn parse_column(def: &str) -> Result<ColumnDef, String> {
    // 先提取 COMMENT(注释内容可能含空格)
    let mut def = def.to_string();
    let mut comment = String::new();
    if let Some(comment_idx) = find_ignore_ascii_case(&def, "comment") {
        let comment_part = def[comment_idx + "comment".len()..].trim();
        if let Some(quote) = comment_part.chars().next() {
            if quote == '\'' || quote == '"' {
                let inner = &comment_part[quote.len_utf8()..];
                if let Some(end) = inner.find(quote) {
                    comment = inner[..end].to_string();
                    def.truncate(comment_idx);
                }
            }
        }
    }

    let parts: Vec<&str> = def.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("字段定义过短: {def}"));
    }

    let mut col = ColumnDef {
        name: parts[0].trim_matches(|c| c == '`' || c == '"').to_string(),
        nullable: true,
        comment,
        ..Default::default()
    };

    // 类型可能带括号且跨 token(如 `decimal(10, 2)`)
    let mut column_type = parts[1]
        .trim_matches(|c| c == '`' || c == '"')
        .to_string();
    let mut i = 2;
    while i < parts.len() && parts[i - 1].contains('(') && !parts[i - 1].contains(')') {
        column_type.push(' ');
        column_type.push_str(parts[i].trim_matches(|c| c == '`' || c == '"'));
        i += 1;
    }
    col.column_type = column_type;

    // 约束
    let mut j = i;
    while j < parts.len() {
        let token = parts[j].to_lowercase();
        match token.as_str() {
            "not" | "null" => {
                if j > 0 && parts[j - 1].eq_ignore_ascii_case("not") {
                    col.nullable = false;
                }
            }
            "primary" | "key" => {
                if j > 0 && parts[j - 1].eq_ignore_ascii_case("primary") {
                    col.primary_key = true;
                    col.nullable = false;
                }
            }
            "auto_increment" => {
                col.nullable = false;
                col.auto_increment = true;
            }
            "unique" => col.unique = true,
            "default" => {
                if j + 1 < parts.len() {
                    col.default = parts[j + 1].to_string();
                    j += 1;
                }
            }
            _ => {}
        }
        j += 1;
    }

    // MySQL 的 auto_increment 隐含主键
    if find_ignore_ascii_case(&def, "auto_increment").is_some() {
        col.primary_key = true;
    }

    Ok(col)
}

/// ASCII 大小写无关的子串查找,返回 `haystack` 中的字节下标。
/// 关键词须为 ASCII;非 ASCII 字节永不匹配,因此偏移量可直接用于原串。
fn find_ignore_ascii_case(haystack: &str, needle: &str) -> Option<usize> {
    debug_assert!(needle.is_ascii());
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    if n.is_empty() || h.len() < n.len() {
        return if n.is_empty() { Some(0) } else { None };
    }
    (0..=h.len() - n.len()).find(|&i| {
        h[i..i + n.len()]
            .iter()
            .zip(n)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

/// 提取表级属性(ENGINE / CHARSET / COLLATE / COMMENT)。
fn extract_table_attributes(sql: &str) -> TableDef {
    let attrs_sql = match sql.find('(') {
        Some(left_idx) => match find_matching_paren(sql, left_idx) {
            Some(right_idx) if right_idx + 1 < sql.len() => &sql[right_idx + 1..],
            _ => sql,
        },
        None => sql,
    };

    let mut table = TableDef::default();

    // ENGINE=InnoDB
    if let Some(v) = find_kv(attrs_sql, &["engine"], false) {
        table.engine = v;
    }
    // DEFAULT CHARSET=utf8mb4 / CHARACTER SET latin1
    if let Some(v) = find_kv(attrs_sql, &["charset", "character set"], true) {
        table.charset = v;
    }
    // COLLATE=utf8mb4_unicode_ci / COLLATION=...
    if let Some(v) = find_kv(attrs_sql, &["collate", "collation"], false) {
        table.collation = v;
    }
    // COMMENT='...' / COMMENT "..." (等号可有可无)
    if let Some(v) = find_quoted_value(attrs_sql, "comment") {
        table.comment = v;
    }
    table
}

/// 在 `sql` 中寻找关键词后跟(可选)等号的词值;返回的值为小写。
fn find_kv(sql: &str, keywords: &[&str], _require_eq: bool) -> Option<String> {
    let mut best: Option<(usize, usize)> = None; // (关键词位置, 关键词长度)
    for kw in keywords {
        let mut from = 0;
        while let Some(pos) = find_ignore_ascii_case(&sql[from..], kw) {
            let abs = from + pos;
            // 词边界:前面不能是字母数字/下划线
            let boundary_before = abs == 0
                || !sql.as_bytes()[abs - 1].is_ascii_alphanumeric()
                    && sql.as_bytes()[abs - 1] != b'_';
            if boundary_before {
                if best.is_none() || best.is_some_and(|(b, _)| abs < b) {
                    best = Some((abs, kw.len()));
                }
                break;
            }
            from = abs + kw.len();
        }
    }
    let (pos, kw_len) = best?;
    let rest = sql[pos + kw_len..].trim_start();
    let rest = rest.trim_start_matches([' ', '=']).trim_start();
    let value: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if value.is_empty() {
        None
    } else {
        Some(value.to_lowercase())
    }
}

/// 在 `sql` 中寻找 `keyword` 后跟引号包裹的值(等号可有可无),原样返回。
fn find_quoted_value(sql: &str, keyword: &str) -> Option<String> {
    let mut from = 0;
    while let Some(pos) = find_ignore_ascii_case(&sql[from..], keyword) {
        let abs = from + pos;
        let boundary_before = abs == 0
            || !sql.as_bytes()[abs - 1].is_ascii_alphanumeric() && sql.as_bytes()[abs - 1] != b'_';
        if boundary_before {
            let rest = sql[abs + keyword.len()..].trim_start();
            let rest = rest.trim_start_matches([' ', '=']).trim_start();
            if let Some(quote) = rest.chars().next() {
                if quote == '\'' || quote == '"' {
                    let inner = &rest[quote.len_utf8()..];
                    if let Some(end) = inner.find(quote) {
                        return Some(inner[..end].to_string());
                    }
                }
            }
        }
        from = abs + keyword.len();
    }
    None
}

/// 解析单条 `CREATE TABLE` 语句。
///
/// 支持多数据库基础语法;解析失败的列会被跳过(容错)。
pub fn parse_create_table(sql: &str) -> Result<TableDef, String> {
    let sql = normalize_sql(sql);

    let name = extract_table_name(&sql)?;
    let column_block = extract_column_block(&sql)?;
    let columns = parse_columns(&column_block);
    let mut table = extract_table_attributes(&sql);
    table.name = name;
    table.columns = columns;
    Ok(table)
}

/// 解析一条 SQL 字符串中的多个 `CREATE TABLE` 语句,
/// 非 CREATE TABLE 语句被忽略。
pub fn parse_create_tables(sql: &str) -> Result<Vec<TableDef>, String> {
    let mut tables = Vec::new();
    for stmt in split_sql_statements(sql) {
        let stmt = stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        if !is_create_table_statement(stmt) {
            continue;
        }
        tables.push(parse_create_table(stmt).map_err(|e| format!("parse create table failed: {e}"))?);
    }
    Ok(tables)
}

fn is_create_table_statement(stmt: &str) -> bool {
    let mut words = stmt.split_whitespace();
    while let Some(w) = words.next() {
        if w.eq_ignore_ascii_case("create") {
            if let Some(next) = words.next() {
                if next.eq_ignore_ascii_case("table") {
                    return true;
                }
            }
        }
    }
    false
}

/// 按分号切分 SQL 语句,跳过引号与括号内的分号。
fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let (mut in_single, mut in_double, mut in_backtick) = (false, false, false);
    let mut paren_level = 0i32;

    for ch in sql.chars() {
        match ch {
            '\'' if !in_double && !in_backtick => in_single = !in_single,
            '"' if !in_single && !in_backtick => in_double = !in_double,
            '`' if !in_single && !in_double => in_backtick = !in_backtick,
            '(' if !in_single && !in_double && !in_backtick => paren_level += 1,
            ')' if !in_single && !in_double && !in_backtick && paren_level > 0 => {
                paren_level -= 1
            }
            ';' if !in_single && !in_double && !in_backtick && paren_level == 0 => {
                parts.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    if !current.trim().is_empty() {
        parts.push(current);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        let sql = "CREATE TABLE users (\
            id INT PRIMARY KEY, \
            name VARCHAR(100) NOT NULL, \
            email VARCHAR(255) UNIQUE\
        )";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "users");
        assert_eq!(table.columns.len(), 3);
        assert_eq!(table.columns[0].name, "id");
        assert!(table.columns[0].primary_key);
        assert!(!table.columns[0].nullable);
        assert_eq!(table.columns[1].name, "name");
        assert_eq!(table.columns[1].column_type, "varchar(100)");
        assert!(!table.columns[1].nullable);
        assert!(table.columns[2].unique);
    }

    #[test]
    fn test_quoted_names() {
        let sql = "CREATE TABLE `user_profiles` (\n\
            `user_id` INT NOT NULL,\n\
            `profile_data` TEXT\n\
        )";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "user_profiles");
        assert_eq!(table.columns[0].name, "user_id");
        assert_eq!(table.columns[1].name, "profile_data");
    }

    #[test]
    fn test_with_comments() {
        let sql = "/* 创建用户表 */\n\
        CREATE TABLE users (\n\
            id INT PRIMARY KEY, -- 用户ID\n\
            -- 用户名称\n\
            name VARCHAR(100)\n\
        )";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "users");
        assert_eq!(table.columns.len(), 2);
    }

    #[test]
    fn test_complex_types() {
        let sql = "CREATE TABLE test_types (\n\
            id BIGINT PRIMARY KEY,\n\
            amount DECIMAL(10, 2),\n\
            description TEXT,\n\
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n\
            is_active BOOLEAN NOT NULL DEFAULT true\n\
        )";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "test_types");
        assert_eq!(table.columns.len(), 5);
        assert_eq!(table.columns[1].name, "amount");
        assert!(table.columns[1].column_type.contains("decimal"));
        assert_eq!(table.columns[2].column_type, "text");
        assert!(!table.columns[3].default.is_empty());
        assert_eq!(table.columns[4].default, "true");
        assert!(!table.columns[4].nullable);
    }

    #[test]
    fn test_table_constraints() {
        let sql = "CREATE TABLE orders (\n\
            id INT,\n\
            user_id INT NOT NULL,\n\
            total DECIMAL(10,2),\n\
            PRIMARY KEY (id),\n\
            FOREIGN KEY (user_id) REFERENCES users(id),\n\
            INDEX idx_user (user_id)\n\
        )";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "orders");
        assert_eq!(table.columns.len(), 3);
        // 表级 PRIMARY KEY 应标记到对应列
        assert!(table.columns[0].primary_key);
    }

    #[test]
    fn test_comment_on_column() {
        let sql = "CREATE TABLE t (\
            `userName` VARCHAR(100) NOT NULL COMMENT '用户名', \
            `age` INT DEFAULT 18\
        )";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns[0].name, "userName");
        assert_eq!(table.columns[0].comment, "用户名");
        assert!(!table.columns[0].nullable);
        assert_eq!(table.columns[1].default, "18");
    }

    #[test]
    fn test_table_attributes() {
        let sql = "CREATE TABLE t (id INT) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户表'";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.engine, "innodb");
        assert_eq!(table.charset, "utf8mb4");
        assert_eq!(table.collation, "utf8mb4_unicode_ci");
        assert_eq!(table.comment, "用户表");
    }

    #[test]
    fn test_auto_increment_implies_primary_key() {
        let sql = "CREATE TABLE t (id BIGINT AUTO_INCREMENT, name VARCHAR(10))";
        let table = parse_create_table(sql).unwrap();
        assert!(table.columns[0].auto_increment);
        assert!(table.columns[0].primary_key);
        assert!(!table.columns[0].nullable);
    }

    #[test]
    fn test_if_not_exists() {
        let sql = "CREATE TABLE IF NOT EXISTS logs (id INT)";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "logs");
    }

    #[test]
    fn test_parse_create_tables() {
        let sql = "\
            CREATE TABLE a (id INT);\n\
            INSERT INTO a VALUES (1);\n\
            CREATE TABLE b (id INT, name VARCHAR(10));\
        ";
        let tables = parse_create_tables(sql).unwrap();
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].name, "a");
        assert_eq!(tables[1].name, "b");
    }

    #[test]
    fn test_errors() {
        assert!(parse_create_table("SELECT 1").is_err());
        assert!(parse_create_table("CREATE TABLE t").is_err()); // 没有括号块
        assert!(parse_create_table("CREATE TABLE t (id INT").is_err()); // 括号不匹配
    }
}
