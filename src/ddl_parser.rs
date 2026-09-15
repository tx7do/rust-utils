//! MySQL `CREATE TABLE` DDL 解析器。
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
            if primary_key_columns.contains(&col.name) {
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
    let mut column_type = parts[1].trim_matches(|c| c == '`' || c == '"').to_string();
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
            "default" if j + 1 < parts.len() => {
                col.default = parts[j + 1].to_string();
                j += 1;
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
        tables
            .push(parse_create_table(stmt).map_err(|e| format!("parse create table failed: {e}"))?);
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
            ')' if !in_single && !in_double && !in_backtick && paren_level > 0 => paren_level -= 1,
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

    #[test]
    fn test_mysql_with_engine_and_charset() {
        let sql = "CREATE TABLE products (\
            id INT AUTO_INCREMENT PRIMARY KEY, \
            name VARCHAR(100) NOT NULL COMMENT '产品名称', \
            price DECIMAL(10,2) DEFAULT 0.00\
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "products");
        assert_eq!(table.engine, "innodb");
        assert_eq!(table.charset, "utf8mb4");
        assert!(table.columns[0].primary_key);
        assert_eq!(table.columns[1].comment, "产品名称");
        assert_eq!(table.columns[2].default, "0.00");
    }

    #[test]
    fn test_multiple_engine_formats() {
        let cases = [
            (
                "CREATE TABLE t1 (id INT) ENGINE=InnoDB CHARSET=utf8",
                "innodb",
                "utf8",
            ),
            (
                "CREATE TABLE t2 (id INT) ENGINE=MyISAM DEFAULT CHARSET=latin1",
                "myisam",
                "latin1",
            ),
            ("CREATE TABLE t3 (id INT) ENGINE=Memory", "memory", ""),
            ("CREATE TABLE t4 (id INT)", "", ""),
        ];
        for (sql, engine, charset) in cases {
            let table = parse_create_table(sql).unwrap();
            assert_eq!(table.engine, engine, "sql: {sql}");
            assert_eq!(table.charset, charset, "sql: {sql}");
        }
    }

    #[test]
    fn test_case_insensitive() {
        let sql = "create table Users (\n ID int primary key,\n NAME varchar(100) NOT NULL\n)";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "users");
        assert_eq!(table.columns[0].name, "id");
        assert_eq!(table.columns[1].name, "name");
    }

    #[test]
    fn test_nullable_fields() {
        let sql = "CREATE TABLE test (field1 INT NULL, field2 INT NOT NULL, field3 INT)";
        let table = parse_create_table(sql).unwrap();
        assert!(table.columns[0].nullable); // 显式 NULL
        assert!(!table.columns[1].nullable); // NOT NULL
        assert!(table.columns[2].nullable); // 默认可空
    }

    #[test]
    fn test_default_values() {
        let sql = "CREATE TABLE settings (\
            id INT PRIMARY KEY, \
            timeout INT DEFAULT 30, \
            name VARCHAR(50) DEFAULT 'unknown', \
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, \
            is_enabled BOOLEAN DEFAULT false\
        )";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns[0].default, "");
        assert_eq!(table.columns[1].default, "30");
        assert_eq!(table.columns[2].default, "'unknown'"); // 引号保留
        assert!(!table.columns[3].default.is_empty());
        assert_eq!(table.columns[4].default, "false");
    }

    #[test]
    fn test_invalid_sql() {
        let cases = [
            "CREATE TABLE (id INT)",      // 没有表名
            "CREATE TABLE users",         // 没有括号
            "CREATE TABLE users (id INT", // 括号不匹配
            "SELECT * FROM users",        // 不是 CREATE TABLE
        ];
        for sql in cases {
            assert!(parse_create_table(sql).is_err(), "should error: {sql}");
        }
    }

    #[test]
    fn test_empty_table() {
        let table = parse_create_table("CREATE TABLE empty_table ()").unwrap();
        assert_eq!(table.name, "empty_table");
        assert!(table.columns.is_empty());
    }

    #[test]
    fn test_complex_real_world() {
        let sql = concat!(
            "/* 用户订单表 */\n",
            "CREATE TABLE IF NOT EXISTS user_orders (\n",
            "  order_id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '订单ID',\n",
            "  user_id BIGINT NOT NULL COMMENT '用户ID',\n",
            "  order_number VARCHAR(50) NOT NULL COMMENT '订单号',\n",
            "  total_amount DECIMAL(15,2) NOT NULL DEFAULT 0.00 COMMENT '总金额',\n",
            "  status VARCHAR(20) NOT NULL DEFAULT 'pending' COMMENT '订单状态',\n",
            "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n",
            "  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n",
            "  deleted_at TIMESTAMP NULL COMMENT '删除时间',\n",
            "  INDEX idx_user_id (user_id),\n",
            "  INDEX idx_order_number (order_number),\n",
            "  CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id)\n",
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户订单表';\n"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "user_orders");
        assert_eq!(table.engine, "innodb");
        assert_eq!(table.charset, "utf8mb4");
        assert!(table.columns.len() >= 6, "got {}", table.columns.len());
        assert_eq!(table.columns[0].name, "order_id");
        assert!(table.columns[0].primary_key);
        assert_eq!(table.columns[0].comment, "订单ID");
        let total = table
            .columns
            .iter()
            .find(|c| c.name == "total_amount")
            .unwrap();
        assert_eq!(total.default, "0.00");
        assert!(!total.nullable);
    }

    #[test]
    fn test_mysql_engine_types() {
        for engine in ["InnoDB", "MyISAM", "Memory", "Archive", "CSV"] {
            let sql = format!("CREATE TABLE test (id INT) ENGINE={engine}");
            let table = parse_create_table(&sql).unwrap();
            assert_eq!(table.engine, engine.to_lowercase(), "engine: {engine}");
        }
    }

    #[test]
    fn test_mysql_charset_and_collation() {
        let cases = [
            ("CREATE TABLE t (id INT) CHARSET=utf8", "utf8"),
            ("CREATE TABLE t (id INT) DEFAULT CHARSET=utf8mb4", "utf8mb4"),
            ("CREATE TABLE t (id INT) CHARACTER SET latin1", "latin1"),
        ];
        for (sql, charset) in cases {
            let table = parse_create_table(sql).unwrap();
            assert_eq!(table.charset, charset, "sql: {sql}");
        }
    }

    #[test]
    fn test_mysql_data_types() {
        let sql = concat!(
            "CREATE TABLE mysql_types (",
            " tiny_col TINYINT, small_col SMALLINT, medium_col MEDIUMINT, int_col INT,",
            " big_col BIGINT, decimal_col DECIMAL(10,2), float_col FLOAT, double_col DOUBLE,",
            " char_col CHAR(10), varchar_col VARCHAR(255), text_col TEXT,",
            " mediumtext_col MEDIUMTEXT, longtext_col LONGTEXT, blob_col BLOB,",
            " date_col DATE, datetime_col DATETIME, timestamp_col TIMESTAMP, year_col YEAR,",
            " enum_col ENUM('a','b','c'), set_col SET('x','y','z'), json_col JSON",
            ")"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "mysql_types");
        let type_of = |n: &str| {
            table
                .columns
                .iter()
                .find(|c| c.name == n)
                .map(|c| c.column_type.clone())
                .unwrap_or_default()
        };
        assert!(type_of("tiny_col").contains("tinyint"));
        assert!(type_of("varchar_col").contains("varchar"));
        assert!(type_of("decimal_col").contains("decimal"));
        assert!(type_of("json_col").contains("json"));
        // ENUM / SET 里的逗号不能被当成字段分隔符
        assert!(type_of("enum_col").contains("enum"));
        assert!(type_of("set_col").contains("set"));
    }

    #[test]
    fn test_mysql_timestamps_on_update() {
        let sql = concat!(
            "CREATE TABLE events (",
            " id INT PRIMARY KEY,",
            " created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,",
            " updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
            ")"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns.len(), 3);
        assert!(table.columns[1]
            .default
            .to_lowercase()
            .contains("current_timestamp"));
        assert!(table.columns[2]
            .default
            .to_lowercase()
            .contains("current_timestamp"));
    }

    #[test]
    fn test_mysql_unsigned_and_zerofill() {
        let sql = concat!(
            "CREATE TABLE test (",
            " id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,",
            " amount DECIMAL(10,2) UNSIGNED,",
            " code INT ZEROFILL",
            ")"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns.len(), 3);
        assert!(table.columns[0].primary_key);
    }

    #[test]
    fn test_mysql_fulltext_index() {
        let sql = concat!(
            "CREATE TABLE articles (",
            " id INT PRIMARY KEY,",
            " title VARCHAR(200),",
            " content TEXT,",
            " FULLTEXT INDEX ft_content (content),",
            " FULLTEXT INDEX ft_title_content (title, content)",
            ") ENGINE=InnoDB"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns.len(), 3); // FULLTEXT 索引被跳过
    }

    #[test]
    fn test_mysql_partitioned_table() {
        let sql = concat!(
            "CREATE TABLE sales (",
            " id INT, sale_date DATE, amount DECIMAL(10,2)",
            ") ENGINE=InnoDB",
            " PARTITION BY RANGE(YEAR(sale_date)) (",
            " PARTITION p0 VALUES LESS THAN (2020),",
            " PARTITION p1 VALUES LESS THAN (2021)",
            ")"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "sales");
        assert_eq!(table.engine, "innodb");
        assert_eq!(table.columns.len(), 3);
    }

    #[test]
    fn test_postgresql_serial_types() {
        let sql =
            "CREATE TABLE users (id SERIAL PRIMARY KEY, big_id BIGSERIAL, small_id SMALLSERIAL)";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns.len(), 3);
        assert!(table.columns[0]
            .column_type
            .to_lowercase()
            .contains("serial"));
    }

    #[test]
    fn test_postgresql_array_types() {
        let sql =
            "CREATE TABLE test (id SERIAL PRIMARY KEY, tags TEXT[], numbers INTEGER[], matrix INTEGER[][])";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns.len(), 4);
    }

    #[test]
    fn test_postgresql_check_constraint() {
        let sql = concat!(
            "CREATE TABLE products (",
            " id SERIAL PRIMARY KEY,",
            " name VARCHAR(100) NOT NULL,",
            " price DECIMAL(10,2) CHECK (price > 0),",
            " quantity INT CHECK (quantity >= 0)",
            ")"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns.len(), 4);
    }

    #[test]
    fn test_postgresql_function_defaults() {
        let sql = concat!(
            "CREATE TABLE users (",
            " id SERIAL PRIMARY KEY,",
            " created_at TIMESTAMP DEFAULT NOW(),",
            " updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,",
            " uuid UUID DEFAULT gen_random_uuid()",
            ")"
        );
        let table = parse_create_table(sql).unwrap();
        assert!(!table.columns[1].default.is_empty());
        assert!(!table.columns[3].default.is_empty());
    }

    #[test]
    fn test_postgresql_generated_columns() {
        let sql = concat!(
            "CREATE TABLE people (",
            " id SERIAL PRIMARY KEY,",
            " first_name TEXT, last_name TEXT,",
            " full_name TEXT GENERATED ALWAYS AS (first_name || ' ' || last_name) STORED",
            ")"
        );
        let table = parse_create_table(sql).unwrap();
        assert!(table.columns.len() >= 3);
    }

    #[test]
    fn test_postgresql_inherited_tables() {
        let sql = concat!(
            "CREATE TABLE employees (",
            " id SERIAL PRIMARY KEY, name VARCHAR(100), salary DECIMAL(10,2)",
            ") INHERITS (persons)"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "employees");
        assert_eq!(table.columns.len(), 3);
    }

    #[test]
    fn test_sqlite_autoincrement() {
        let sql = "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)";
        let table = parse_create_table(sql).unwrap();
        assert!(table.columns[0].primary_key);
    }

    #[test]
    fn test_sqlite_data_types() {
        let sql = concat!(
            "CREATE TABLE sqlite_types (",
            " int_col INTEGER, text_col TEXT, real_col REAL, blob_col BLOB, numeric_col NUMERIC",
            ")"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns.len(), 5);
        let type_of = |n: &str| {
            table
                .columns
                .iter()
                .find(|c| c.name == n)
                .map(|c| c.column_type.clone())
                .unwrap_or_default()
        };
        assert!(type_of("int_col").contains("integer"));
        assert!(type_of("text_col").contains("text"));
        assert!(type_of("real_col").contains("real"));
        assert!(type_of("blob_col").contains("blob"));
    }

    #[test]
    fn test_sqlite_without_rowid() {
        let sql = "CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "config");
        assert_eq!(table.columns.len(), 2);
        assert!(table.columns[0].primary_key);
    }

    #[test]
    fn test_sqlite_paren_default() {
        let sql = concat!(
            "CREATE TABLE logs (",
            " id INTEGER PRIMARY KEY AUTOINCREMENT,",
            " message TEXT NOT NULL,",
            " created_at TEXT DEFAULT (datetime('now')),",
            " level TEXT DEFAULT 'INFO'",
            ")"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns.len(), 4);
        assert!(table.columns[2].default.contains("datetime"));
        assert_eq!(table.columns[3].default, "'INFO'");
    }

    #[test]
    fn test_sqlite_strict_tables() {
        let sql =
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INTEGER) STRICT";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.columns.len(), 3);
    }

    #[test]
    fn test_crossdb_nullable_constraints() {
        for sql in [
            "CREATE TABLE t (id INT NOT NULL, name VARCHAR(50) NULL)",
            "CREATE TABLE t (id INTEGER NOT NULL, name TEXT)",
        ] {
            let table = parse_create_table(sql).unwrap();
            assert!(!table.columns[0].nullable, "sql: {sql}");
        }
    }

    #[test]
    fn test_crossdb_primary_key_variants() {
        let cases = [
            "CREATE TABLE t (id INT PRIMARY KEY, name TEXT)",
            "CREATE TABLE t (id1 INT, id2 INT, name TEXT, PRIMARY KEY(id1, id2))",
            "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)",
            "CREATE TABLE t (id SERIAL PRIMARY KEY)",
            "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT)",
        ];
        for sql in cases {
            let table = parse_create_table(sql).unwrap();
            assert!(
                table.columns.iter().any(|c| c.primary_key),
                "should have a primary key: {sql}"
            );
        }
    }

    #[test]
    fn test_crossdb_quoted_identifiers() {
        let cases = [
            (
                "CREATE TABLE `my_table` (`my_column` INT)",
                "my_table",
                "my_column",
            ),
            (
                "CREATE TABLE \"my_table\" (\"my_column\" INT)",
                "my_table",
                "my_column",
            ),
            (
                "CREATE TABLE `table1` (\"col1\" INT, `col2` TEXT)",
                "table1",
                "col1",
            ),
        ];
        for (sql, table_name, col_name) in cases {
            let table = parse_create_table(sql).unwrap();
            assert_eq!(table.name, table_name, "sql: {sql}");
            assert_eq!(table.columns[0].name, col_name, "sql: {sql}");
        }
    }

    #[test]
    fn test_parse_create_tables_semicolon_in_string() {
        let sql = concat!(
            "\n",
            "CREATE TABLE messages (\n",
            " id INT PRIMARY KEY,\n",
            " content VARCHAR(100) DEFAULT 'a; b; c'\n",
            ");\n",
            "CREATE TABLE audit (id INT PRIMARY KEY, note TEXT);\n"
        );
        let tables = parse_create_tables(sql).unwrap();
        assert_eq!(tables.len(), 2); // 字符串里的分号不会切断语句
        assert_eq!(tables[0].name, "messages");
        assert_eq!(tables[1].name, "audit");
    }

    #[test]
    fn test_table_comment_double_quotes() {
        let sql =
            "CREATE TABLE products (id INT PRIMARY KEY, name VARCHAR(255)) COMMENT=\"产品表\"";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.comment, "产品表");
    }

    #[test]
    fn test_collation_and_collate_keyword() {
        let t1 = parse_create_table(
            "CREATE TABLE orders (id INT PRIMARY KEY, content TEXT) COLLATION=utf8mb4_unicode_ci",
        )
        .unwrap();
        assert_eq!(t1.collation, "utf8mb4_unicode_ci");

        let t2 = parse_create_table(
            "CREATE TABLE articles (id INT PRIMARY KEY, title VARCHAR(255)) COLLATE=utf8mb4_general_ci",
        )
        .unwrap();
        assert_eq!(t2.collation, "utf8mb4_general_ci");
    }

    #[test]
    fn test_all_table_attributes_combined() {
        let sql = concat!(
            "CREATE TABLE users_v2 (",
            " id INT PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255)",
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户表'"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.engine, "innodb");
        assert_eq!(table.charset, "utf8mb4");
        assert_eq!(table.collation, "utf8mb4_unicode_ci");
        assert_eq!(table.comment, "用户表");
    }

    #[test]
    fn test_comment_with_special_chars() {
        let sql =
            "CREATE TABLE config (id INT PRIMARY KEY, value TEXT) COMMENT='配置表: 用于存储系统配置'";
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.comment, "配置表: 用于存储系统配置");
    }

    #[test]
    fn test_latin1_collation() {
        let sql = concat!(
            "CREATE TABLE archive (",
            " id INT PRIMARY KEY, data VARCHAR(255)",
            ") DEFAULT CHARSET=latin1 COLLATE=latin1_general_ci"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.charset, "latin1");
        assert_eq!(table.collation, "latin1_general_ci");
    }

    #[test]
    fn test_decimal_with_space_and_field_comments() {
        // 来自真实解析错误报告:DECIMAL(10, 2) 含空格 + 全字段 COMMENT + 表 COMMENT 无等号
        let sql = concat!(
            "\n",
            "CREATE TABLE products (\n",
            " id INT PRIMARY KEY COMMENT 'Product ID',\n",
            " name VARCHAR(255) NOT NULL COMMENT 'Product Name',\n",
            " price DECIMAL(10, 2) NOT NULL COMMENT 'Product Price',\n",
            " stock INT DEFAULT 0 COMMENT 'Stock Quantity'\n",
            ") COMMENT 'Products Table';\n"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "products");
        assert_eq!(table.comment, "Products Table");
        assert_eq!(table.columns.len(), 4);

        let c = &table.columns;
        assert_eq!(c[0].column_type, "int");
        assert!(c[0].primary_key);
        assert_eq!(c[0].comment, "Product ID");
        assert_eq!(c[1].column_type, "varchar(255)");
        assert!(!c[1].nullable);
        assert_eq!(c[1].comment, "Product Name");
        assert!(c[2].column_type.contains("decimal"));
        assert!(!c[2].nullable);
        assert_eq!(c[2].comment, "Product Price");
        assert_eq!(c[3].column_type, "int");
        assert!(c[3].nullable);
        assert_eq!(c[3].default, "0");
        assert_eq!(c[3].comment, "Stock Quantity");
    }

    #[test]
    fn test_decimal_variations_with_comments() {
        let cases = [
            (
                "CREATE TABLE t (amount DECIMAL(10, 2) NOT NULL COMMENT 'Amount')",
                "decimal",
            ),
            (
                "CREATE TABLE t (amount DECIMAL(10,2) NOT NULL COMMENT 'Amount')",
                "decimal",
            ),
            (
                "CREATE TABLE t (value NUMERIC(12, 4) COMMENT 'Value')",
                "numeric",
            ),
            (
                "CREATE TABLE t (price DECIMAL(10) COMMENT 'Price')",
                "decimal",
            ),
        ];
        for (sql, exp) in cases {
            let table = parse_create_table(sql).unwrap();
            assert_eq!(table.columns.len(), 1, "sql: {sql}");
            assert!(table.columns[0].column_type.contains(exp), "sql: {sql}");
            assert!(!table.columns[0].comment.is_empty(), "sql: {sql}");
        }
    }

    #[test]
    fn test_all_fields_with_comments() {
        let sql = concat!(
            "CREATE TABLE users (",
            " id BIGINT PRIMARY KEY COMMENT '用户ID',",
            " username VARCHAR(50) NOT NULL UNIQUE COMMENT '用户名',",
            " email VARCHAR(100) NOT NULL COMMENT '邮箱地址',",
            " age INT DEFAULT 18 COMMENT '年龄',",
            " balance DECIMAL(15, 2) DEFAULT 0.00 COMMENT '账户余额',",
            " is_active BOOLEAN DEFAULT true COMMENT '是否激活',",
            " created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',",
            " updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'",
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表'"
        );
        let table = parse_create_table(sql).unwrap();
        assert_eq!(table.name, "users");
        assert_eq!(table.comment, "用户表");
        for (i, col) in table.columns.iter().enumerate() {
            assert!(
                !col.comment.is_empty(),
                "column {i} ({}) missing comment",
                col.name
            );
        }
        let balance = &table.columns[4];
        assert_eq!(balance.name, "balance");
        assert_eq!(balance.comment, "账户余额");
        assert_eq!(balance.default, "0.00");
        assert!(balance.column_type.contains("decimal"));
    }

    #[test]
    fn test_comment_with_special_characters_in_fields() {
        let cases = [
            (
                "CREATE TABLE t (id INT COMMENT 'ID: 主键')",
                "id",
                "ID: 主键",
            ),
            (
                "CREATE TABLE t (val INT COMMENT 'Value, important')",
                "val",
                "Value, important",
            ),
            (
                "CREATE TABLE t (code VARCHAR(50) COMMENT '代码(编码)')",
                "code",
                "代码(编码)",
            ),
        ];
        for (sql, col, cmt) in cases {
            let table = parse_create_table(sql).unwrap();
            assert_eq!(table.columns.len(), 1, "sql: {sql}");
            assert_eq!(table.columns[0].name, col, "sql: {sql}");
            assert_eq!(table.columns[0].comment, cmt, "sql: {sql}");
        }
    }
}
