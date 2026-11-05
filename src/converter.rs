//! REST 路径 / OpenAPI operationID → `resource:action` 权限码映射(纯字符串处理,零依赖)。
//!
//! 逐式移植自 Go `tx7do/go-utils/converter`(api.go):
//!
//! - [`ApiPermissionConverter::convert_code_by_operation_id`]:把 RPC 风格的
//!   operationID(如 `TaskService_ListTaskTypeName`)拆成服务名/动作/名称,
//!   逐段单数化后转 kebab-case,并把动作归一为 `view`/`create`/`edit`/`delete`;
//! - [`ApiPermissionConverter::convert_code_by_path`]:把 REST 路径剥掉版本
//!   前缀(`/api/`、`/vN/`)与路径参数(`{id}`),取首段资源(单数化),再按
//!   HTTP method 映射动作(GET→view、POST→create、PUT/PATCH→edit、DELETE→delete)。
//!
//! 上游依赖的两件外物在这里零依赖复刻:正则(`rpcNameRe`、`segVersionRe`、
//! `paramSegmentRe`)以手写等价匹配替代;单数化则把 `jinzhu/inflection` 的
//! Singular 规则链(不可数名词、不规则变形、28 条常规规则及其编译后的
//! 全大写/原样/忽略大小写三变体与逆序)逐条搬过来。
//!
//! ```
//! use rust_utils::converter::ApiPermissionConverter;
//!
//! let c = ApiPermissionConverter::new();
//! assert_eq!(c.convert_code_by_path("GET", "/v1/users"), "user:view");
//! assert_eq!(c.convert_code_by_path("DELETE", "/v1/users/{id}"), "user:delete");
//! assert_eq!(
//!     c.convert_code_by_operation_id("TaskService_ListTaskTypeName"),
//!     "task:task-type-name:view"
//! );
//! ```

use crate::stringcase::kebab_case;

/// REST 路径 / operationID → 权限码转换器。
///
/// 与上游一致为空结构体,全部状态都在参数里;通过 [`ApiPermissionConverter::new`]
/// 构造(对齐 `NewApiPermissionConverter()`)。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApiPermissionConverter;

impl ApiPermissionConverter {
    /// 构造转换器(对齐上游 `NewApiPermissionConverter()`)。
    pub fn new() -> Self {
        ApiPermissionConverter
    }

    /// 通过 operationID 生成 `resource:action` 风格的 code
    /// (如 `users:delete`、`task:task-type-name:view`)。
    ///
    /// 拆分失败(不符合 `[Xxx]Service_` / `[Xxx]_` 的 RPC 命名形态)返回空串。
    pub fn convert_code_by_operation_id(&self, operation_id: &str) -> String {
        let Some((service, mut action, name)) = self.split_operation_id(operation_id) else {
            return String::new();
        };

        let service = self.singularize_segments(&service);
        let mut resource = kebab_case(&service);
        if !name.is_empty() {
            resource = format!("{}:{}", resource, kebab_case(&name));
        }

        action = kebab_case(&action);
        match action.as_str() {
            "list" | "get" | "retrieve" | "query" | "exist" => action = "view".to_string(),
            "create" | "add" | "new" => action = "create".to_string(),
            "update" | "edit" | "modify" | "change" => action = "edit".to_string(),
            "delete" | "remove" | "del" => action = "delete".to_string(),
            _ => {}
        }

        format!("{}:{}", resource, action)
    }

    /// 通过 HTTP 方法和路径生成 `resource:action` 风格的 code
    /// (如 `user:view`、`user-group:create`)。
    pub fn convert_code_by_path(&self, method: &str, path: &str) -> String {
        let resource = self.path_to_resource(path);
        let action = self.method_to_action(method, path);
        format!("{}:{}", resource, action)
    }

    /// 将 HTTP 方法转换为动作字符串。
    ///
    /// 以 `/list` 结尾的路径一律视为查询动作;否则按大写方法名查表,
    /// 未命中时退化为方法名本身的小写形式。
    fn method_to_action(&self, method: &str, path: &str) -> String {
        // 特殊路径处理
        if path.ends_with("/list") {
            return "view".to_string();
        }

        // 映射常见方法到动作
        match method.to_uppercase().as_str() {
            "GET" => "view".to_string(),
            "POST" => "create".to_string(),
            "PUT" => "edit".to_string(),
            "PATCH" => "edit".to_string(),
            "DELETE" => "delete".to_string(),
            // 默认使用小写方法名作为动作
            _ => method.to_lowercase(),
        }
    }

    /// 从路径中解析资源标识符:剥版本前缀、去路径参数,再取首段
    /// (单数化,并截取 `:` 之前的主资源名)。
    fn path_to_resource(&self, path: &str) -> String {
        if path.is_empty() {
            return String::new();
        }

        // 预处理路径
        let path = self.strip_version_prefix(path);
        let path = self.remove_path_params(&path);
        if path.is_empty() {
            return String::new();
        }

        // 折叠多级路径为单级资源标识符,仅保留第一个路径段的主要部分
        let p = path.split('/').next().unwrap_or("");
        let raw = p.trim();
        if raw.is_empty() {
            return String::new();
        }

        let raw = self.singularize_segments(raw);
        raw.split(':').next().unwrap_or("").to_string()
    }

    /// 分割 operationID 为 `(service, action, name)`,不匹配时返回 `None`。
    ///
    /// 等价正则:`^(?:([A-Za-z0-9]+)Service|([A-Za-z0-9]+))_([A-Za-z]+)([A-Za-z0-9_]*)$`。
    /// `Service` 后缀形态优先(备选分支从左到右、贪婪由长到短回溯);
    /// 无尾随名称段时,再从动作词中按驼峰边界拆出名称
    /// (如 `ListTaskTypeName` → `List` + `TaskTypeName`)。
    fn split_operation_id(&self, operation_id: &str) -> Option<(String, String, String)> {
        if operation_id.is_empty() {
            return None;
        }
        // 正则首尾锚定,整串只能含 [A-Za-z0-9_]
        if !operation_id.bytes().all(is_word_byte) {
            return None;
        }
        let b = operation_id.as_bytes();

        // 前导 [A-Za-z0-9]+ 连续段长度(贪婪回溯只可能发生在这段之内)
        let mut run = 0usize;
        while run < b.len() && b[run].is_ascii_alphanumeric() {
            run += 1;
        }

        // 备选一:`Service` 后缀形态;贪婪取最长的服务段(k 由大到小)
        for k in (1..=run).rev() {
            if b[k..].starts_with(b"Service_") {
                let rest = &operation_id[k + "Service_".len()..];
                if let Some(result) = self.assemble_split(&operation_id[..k], rest) {
                    return Some(result);
                }
            }
        }

        // 备选二:普通 `Xxx_Action` 形态(前导段后必须紧跟 `_`)
        if run >= 1 && run < b.len() && b[run] == b'_' {
            let rest = &operation_id[run + 1..];
            if let Some(result) = self.assemble_split(&operation_id[..run], rest) {
                return Some(result);
            }
        }

        None
    }

    /// 拆分收尾:rest 匹配 `([A-Za-z]+)([A-Za-z0-9_]*)$`;当无尾随名称段时,
    /// 再按驼峰边界从动作词中拆出名称(如 `ListTaskTypeName` → `List` + `TaskTypeName`)。
    fn assemble_split(&self, service: &str, rest: &str) -> Option<(String, String, String)> {
        let (action_raw, name_raw) = split_letters_run(rest)?;
        if name_raw.is_empty() {
            let (action, name) = self.split_camel_after_first_word(&action_raw);
            Some((service.to_string(), action.to_string(), name.to_string()))
        } else {
            Some((service.to_string(), action_raw, name_raw))
        }
    }

    /// 将驼峰字符串拆为第一个大写词和剩余部分。
    /// 例如 `ListTaskTypeName` → `("List", "TaskTypeName")`,`List` → `("List", "")`。
    fn split_camel_after_first_word<'a>(&self, s: &'a str) -> (&'a str, &'a str) {
        if s.is_empty() {
            return ("", "");
        }
        for (i, ch) in s.bytes().enumerate().skip(1) {
            if ch.is_ascii_uppercase() {
                // ASCII 大写字母不可能是多字节字符的后续字节,此处必为字符边界
                return (&s[..i], &s[i..]);
            }
        }
        (s, "")
    }

    /// 移除路径开头的 `/api/` 和 `/vN/`。
    ///
    /// 例如:
    ///
    /// - `/api/v1/admin/settings` → `admin/settings`
    /// - `/admin/api/v1/settings` → `settings`
    /// - `/v1/users`              → `users`
    /// - `/v2`                    → `""`
    fn strip_version_prefix(&self, p: &str) -> String {
        if p.trim().is_empty() {
            return String::new();
        }
        let p = p.trim().trim_matches('/');
        if p.is_empty() {
            return String::new();
        }

        let mut parts: Vec<&str> = p.split('/').collect();

        // 去掉开头的 "api"
        if parts.first().is_some_and(|first| first.eq_ignore_ascii_case("api")) {
            parts.remove(0);
        }

        // 找到第一个版本段
        let idx = parts.iter().position(|seg| is_version_segment(seg));

        // 如果找到了且位置在前两段(索引 0 或 1),移除从头到该版本段(含)
        if let Some(i) = idx {
            if i <= 1 {
                parts.drain(..=i);
            }
        }

        // 过滤空段及残余的 "api"
        let mut out: Vec<&str> = Vec::new();
        for seg in parts {
            let seg = seg.trim();
            if seg.is_empty() || seg.eq_ignore_ascii_case("api") {
                continue;
            }
            out.push(seg);
        }

        out.join("/")
    }

    /// 移除路径中的参数段(形如 `/{id}` 或 `/{id}/`)。
    /// 返回的结果不包含首尾斜杠,空或全为参数时返回空字符串。
    fn remove_path_params(&self, p: &str) -> String {
        if p.trim().is_empty() {
            return String::new();
        }
        let p = p.trim().trim_matches('/');
        if p.is_empty() {
            return String::new();
        }

        let mut out: Vec<&str> = Vec::new();
        for seg in p.split('/') {
            let seg = seg.trim();
            if seg.is_empty() {
                continue;
            }
            // 如果是参数段则跳过
            if is_param_segment(seg) {
                continue;
            }
            out.push(seg);
        }

        out.join("/")
    }

    /// 将输入按非字母数字字符分段,单独对每个段做单数化,然后保留原始分隔符拼回。
    /// 例如:`tasks:names` → `task:name`、`tasks-users` → `task-user`。
    fn singularize_segments(&self, s: &str) -> String {
        if s.trim().is_empty() {
            return s.to_string();
        }

        let mut b = String::with_capacity(s.len());
        let mut token = String::new();
        for r in s.chars() {
            // 与上游 unicode.IsLetter || unicode.IsDigit 对齐;
            // Rust 的 is_numeric 额外覆盖 Nl/No 类(如 `Ⅻ`、`①`),属可忽略差异
            if r.is_alphabetic() || r.is_numeric() {
                token.push(r);
                continue;
            }
            // 非字母数字为分隔符:先结算当前 token,再原样写入分隔符
            if !token.is_empty() {
                b.push_str(&singular_word(&token));
                token.clear();
            }
            b.push(r);
        }
        if !token.is_empty() {
            b.push_str(&singular_word(&token));
        }
        b
    }
}

/// 判断字节是否属于 `[A-Za-z0-9_]`。
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// 匹配 `([A-Za-z]+)([A-Za-z0-9_]*)$:返回 `(字母段, 其余部分)`,字母段为空则 `None`。
fn split_letters_run(s: &str) -> Option<(String, String)> {
    let mut n = 0usize;
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            n += 1;
        } else {
            break;
        }
    }
    if n == 0 {
        return None;
    }
    Some((s[..n].to_string(), s[n..].to_string()))
}

/// 等价正则 `(?i)^v[0-9]+(?:\.[0-9]+)?$`:版本段(`v1`、`V2.9` 等)。
fn is_version_segment(seg: &str) -> bool {
    let b = seg.as_bytes();
    if b.len() < 2 || (b[0] != b'v' && b[0] != b'V') {
        return false;
    }
    let mut i = 1usize;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == 1 {
        return false; // "v" 后至少要有一位数字
    }
    if i == b.len() {
        return true;
    }
    if b[i] != b'.' {
        return false;
    }
    let mut j = i + 1;
    while j < b.len() && b[j].is_ascii_digit() {
        j += 1;
    }
    j == b.len() && j > i + 1
}

/// 等价正则 `^\{\s*[^/{}]+\s*}$`:路径参数段(`{id}`、`{ postId }` 等)。
fn is_param_segment(seg: &str) -> bool {
    let Some(inner) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return false;
    };
    let inner = inner.trim();
    !inner.is_empty()
        && !inner.contains('/')
        && !inner.contains('{')
        && !inner.contains('}')
}

// ---------------------------------------------------------------------------
// 单数化:逐式移植 jinzhu/inflection v1.0.0 的 Singular 规则链。
//
// 上游把规则编译成一条有序链:不可数名词 → 不规则变形(每条再展开
// 全大写/首字母大写/原样 三个变体)→ 常规规则逆序(每条同样展开
// 全大写/原样/`(?i)` 忽略大小写 三个变体)。这里按同样的顺序手写匹配。
// ---------------------------------------------------------------------------

/// 大小写变体模式,对应上游为每条正则编译出的三个变体。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `strings.ToUpper(规则)` 的变体:匹配全大写字面,替换模板同样大写。
    Upper,
    /// 原样规则,大小写敏感。
    Exact,
    /// `(?i)` 前缀变体:匹配忽略 ASCII 大小写,替换模板保持原样。
    /// (Go 的 `(?i)` 是 Unicode 折叠,这里取 ASCII 折叠,对 API 路径等价。)
    Ci,
}

/// 取替换模板字面量在当前模式下的大小写形态。
fn lit<'a>(lower: &'a str, upper: &'a str, m: Mode) -> &'a str {
    if m == Mode::Upper {
        upper
    } else {
        lower
    }
}

/// 按模式比较文本与字面量是否相等。
fn eq_mode(text: &str, lit: &str, m: Mode) -> bool {
    match m {
        Mode::Exact => text == lit,
        Mode::Upper => {
            text.len() == lit.len()
                && text.bytes().zip(lit.bytes()).all(|(a, b)| a == b.to_ascii_uppercase())
        }
        Mode::Ci => text.eq_ignore_ascii_case(lit),
    }
}

/// 按模式剥离字面后缀(`Exact`/`Upper` 精确匹配对应形态,`Ci` 忽略大小写)。
fn strip_mode<'a>(s: &'a str, lower: &str, upper: &str, m: Mode) -> Option<&'a str> {
    match m {
        Mode::Exact => s.strip_suffix(lower),
        Mode::Upper => s.strip_suffix(upper),
        Mode::Ci => strip_suffix_ci(s, lower),
    }
}

/// ASCII 忽略大小写的 `strip_suffix`。
fn strip_suffix_ci<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    if suffix.is_empty() {
        return Some(s);
    }
    if s.len() < suffix.len() {
        return None;
    }
    let start = s.len() - suffix.len();
    if !s.is_char_boundary(start) {
        return None;
    }
    if s[start..].eq_ignore_ascii_case(suffix) {
        Some(&s[..start])
    } else {
        None
    }
}

/// `(组)(尾)$` 型规则的通用匹配:组与尾均为字面候选,整体命中最左匹配,
/// 同一位置按候选声明顺序(对应正则的备选顺序与贪婪语义)。
/// 返回 `前缀 + 组文本 + 附加字面量`。
fn gt_replace(s: &str, m: Mode, groups: &[&str], tails: &[&str], extra: (&str, &str)) -> Option<String> {
    let mut best: Option<(usize, usize, usize)> = None; // (起点, 组序, 尾序)
    for (gi, g) in groups.iter().enumerate() {
        for (ti, t) in tails.iter().enumerate() {
            let total = g.len() + t.len();
            if s.len() < total {
                continue;
            }
            let start = s.len() - total;
            let gs = start + g.len();
            if !s.is_char_boundary(start) || !s.is_char_boundary(gs) {
                continue;
            }
            if !eq_mode(&s[start..gs], g, m) || !eq_mode(&s[gs..], t, m) {
                continue;
            }
            let better = match best {
                None => true,
                Some((bs, bgi, bti)) => start < bs || (start == bs && (gi, ti) < (bgi, bti)),
            };
            if better {
                best = Some((start, gi, ti));
            }
        }
    }
    best.map(|(start, gi, _)| {
        format!(
            "{}{}{}",
            &s[..start],
            &s[start..start + groups[gi].len()],
            lit(extra.0, extra.1, m)
        )
    })
}

/// `([类])尾$` 型规则:剥离尾字面后,组是紧邻尾部的单个字符,须命中字符集
/// (`negate` 为 true 表示取反,如 `[^f]`)。返回 `前缀 + 组字符 + 附加字面量`。
fn class_tail_replace(s: &str, m: Mode, tail: (&str, &str), set: &str, negate: bool, extra: (&str, &str)) -> Option<String> {
    let pre = strip_mode(s, tail.0, tail.1, m)?;
    let idx = pre.char_indices().next_back()?.0;
    let c = pre[idx..].chars().next()?;
    let hit = set.chars().any(|w| eq_mode_char(c, w, m));
    if hit == negate {
        return None;
    }
    Some(format!("{}{}{}", &pre[..idx], &pre[idx..], lit(extra.0, extra.1, m)))
}

/// 按模式比较单字符(集合字符一律以小写声明)。
fn eq_mode_char(c: char, w: char, m: Mode) -> bool {
    match m {
        Mode::Exact => c == w,
        Mode::Upper => c == w.to_ascii_uppercase(),
        Mode::Ci => c.eq_ignore_ascii_case(&w),
    }
}

type RuleFn = fn(&str, Mode) -> Option<String>;

/// `jinzhu/inflection` 的 `singularInflections` 规则表(原声明顺序);
/// 应用时逆序遍历,与 `compile()` 产出的编译链顺序一致。
const SINGULAR_RULES: &[RuleFn] = &[
    r_strip_s,     // {"s$", ""}
    r_keep_ss,     // {"(ss)$", "${1}"}
    r_news,        // {"(n)ews$", "${1}ews"}
    r_ta_um,       // {"([ti])a$", "${1}um"}
    r_osis,        // {"((a)naly|(b)a|(d)iagno|(p)arenthe|(p)rogno|(s)ynop|(t)he)(sis|ses)$", "${1}sis"}
    r_analy,       // {"(^analy)(sis|ses)$", "${1}sis"}
    r_ves_fe,      // {"([^f])ves$", "${1}fe"}
    r_hives,       // {"(hive)s$", "${1}"}
    r_tives,       // {"(tive)s$", "${1}"}
    r_lr_ves_f,    // {"([lr])ves$", "${1}f"}
    r_consonant_y, // {"([^aeiouy]|qu)ies$", "${1}y"}
    r_series,      // {"(s)eries$", "${1}eries"}
    r_movies,      // {"(m)ovies$", "${1}ovie"}
    r_cookies,     // {"(c)ookies$", "${1}ookie"}
    r_xch_es,      // {"(x|ch|ss|sh)es$", "${1}"}
    r_mice,        // {"^(m|l)ice$", "${1}ouse"}
    r_bus,         // {"(bus)(es)?$", "${1}"}
    r_oes,         // {"(o)es$", "${1}"}
    r_shoes,       // {"(shoe)s$", "${1}"}
    r_cris_test,   // {"(cris|test)(is|es)$", "${1}is"}
    r_axis,        // {"^(a)x[ie]s$", "${1}xis"}
    r_octopus,     // {"(octop|vir)(us|i)$", "${1}us"}
    r_alias_status,// {"(alias|status)(es)?$", "${1}"}
    r_oxen,        // {"^(ox)en", "${1}"}
    r_vert_ex,     // {"(vert|ind)ices$", "${1}ex"}
    r_matr_ix,     // {"(matr)ices$", "${1}ix"}
    r_quiz,        // {"(quiz)zes$", "${1}"}
    r_databases,   // {"(database)s$", "${1}"}
];

// —— 常规规则,逐条对应 singularInflections(下标即原序) ——

/// `{"s$", ""}`:去掉一个尾随 s。
fn r_strip_s(s: &str, m: Mode) -> Option<String> {
    strip_mode(s, "s", "S", m).map(str::to_string)
}

/// `{"(ss)$", "${1}"}`:以 ss 结尾原样保留(避免被上一条吞掉)。
fn r_keep_ss(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["ss"], &[""], ("", ""))
}

/// `{"(n)ews$", "${1}ews"}`:news 族原样保留(防止被去 s 规则误伤)。
fn r_news(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["n"], &["ews"], ("ews", "EWS"))
}

/// `{"([ti])a$", "${1}um"}`:data → datum、media → medium。
fn r_ta_um(s: &str, m: Mode) -> Option<String> {
    class_tail_replace(s, m, ("a", "A"), "ti", false, ("um", "UM"))
}

/// `{"((a)naly|(b)a|(d)iagno|(p)arenthe|(p)rogno|(s)ynop|(t)he)(sis|ses)$", "${1}sis"}`。
fn r_osis(s: &str, m: Mode) -> Option<String> {
    gt_replace(
        s,
        m,
        &["analy", "ba", "diagno", "parenthe", "progno", "synop", "he"],
        &["sis", "ses"],
        ("sis", "SIS"),
    )
}

/// `{"(^analy)(sis|ses)$", "${1}sis"}`:analyses → analysis。
fn r_analy(s: &str, m: Mode) -> Option<String> {
    if s.len() < 8 || !s.is_char_boundary(5) {
        return None;
    }
    let g = &s[..5];
    if !eq_mode(g, "analy", m) {
        return None;
    }
    let tail = &s[5..];
    if strip_mode(tail, "sis", "SIS", m).is_some() || strip_mode(tail, "ses", "SES", m).is_some() {
        return Some(format!("{}{}", g, lit("sis", "SIS", m)));
    }
    None
}

/// `{"([^f])ves$", "${1}fe"}`。
fn r_ves_fe(s: &str, m: Mode) -> Option<String> {
    class_tail_replace(s, m, ("ves", "VES"), "f", true, ("fe", "FE"))
}

/// `{"(hive)s$", "${1}"}`。
fn r_hives(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["hive"], &["s"], ("", ""))
}

/// `{"(tive)s$", "${1}"}`。
fn r_tives(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["tive"], &["s"], ("", ""))
}

/// `{"([lr])ves$", "${1}f"}`:wolves → wolf。
fn r_lr_ves_f(s: &str, m: Mode) -> Option<String> {
    class_tail_replace(s, m, ("ves", "VES"), "lr", false, ("f", "F"))
}

/// `{"([^aeiouy]|qu)ies$", "${1}y"}`:studies → study、inquiries → inquiry。
fn r_consonant_y(s: &str, m: Mode) -> Option<String> {
    let pre = strip_mode(s, "ies", "IES", m)?;
    // 正则备选顺序:先试单字符类(非元音),再退回双字符 "qu"
    if let Some(idx) = pre.char_indices().next_back().map(|(i, _)| i) {
        let c = pre[idx..].chars().next()?;
        if !eq_mode_char_set(c, "aeiouy", m) {
            return Some(format!("{}{}{}", &pre[..idx], &pre[idx..], lit("y", "Y", m)));
        }
    }
    if pre.len() >= 2 && pre.is_char_boundary(pre.len() - 2) && eq_mode(&pre[pre.len() - 2..], "qu", m) {
        return Some(format!("{}{}{}", &pre[..pre.len() - 2], &pre[pre.len() - 2..], lit("y", "Y", m)));
    }
    None
}

/// 单字符是否按模式命中字符集(集合字符以小写声明)。
fn eq_mode_char_set(c: char, set: &str, m: Mode) -> bool {
    set.chars().any(|w| eq_mode_char(c, w, m))
}

/// `{"(s)eries$", "${1}eries"}`:series 原样保留。
fn r_series(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["s"], &["eries"], ("eries", "ERIES"))
}

/// `{"(m)ovies$", "${1}ovie"}`:movies → movie。
fn r_movies(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["m"], &["ovies"], ("ovie", "OVIE"))
}

/// `{"(c)ookies$", "${1}ookie"}`:cookies → cookie。
fn r_cookies(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["c"], &["ookies"], ("ookie", "OOKIE"))
}

/// `{"(x|ch|ss|sh)es$", "${1}"}`:boxes → box、passes → pass。
fn r_xch_es(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["x", "ch", "ss", "sh"], &["es"], ("", ""))
}

/// `{"^(m|l)ice$", "${1}ouse"}`:mice → mouse。
fn r_mice(s: &str, m: Mode) -> Option<String> {
    if s.len() != 4 || !s.is_char_boundary(1) {
        return None;
    }
    let g = &s[..1];
    if !(eq_mode(g, "m", m) || eq_mode(g, "l", m)) {
        return None;
    }
    if !eq_mode(&s[1..], "ice", m) {
        return None;
    }
    Some(format!("{}{}", g, lit("ouse", "OUSE", m)))
}

/// `{"(bus)(es)?$", "${1}"}`:buses → bus。
fn r_bus(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["bus"], &["es", ""], ("", ""))
}

/// `{"(o)es$", "${1}"}`:potatoes → potato。
fn r_oes(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["o"], &["es"], ("", ""))
}

/// `{"(shoe)s$", "${1}"}`。
fn r_shoes(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["shoe"], &["s"], ("", ""))
}

/// `{"(cris|test)(is|es)$", "${1}is"}`:crises → crisis。
fn r_cris_test(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["cris", "test"], &["is", "es"], ("is", "IS"))
}

/// `{"^(a)x[ie]s$", "${1}xis"}`:axes → axis。
fn r_axis(s: &str, m: Mode) -> Option<String> {
    if s.len() != 4 || !s.is_char_boundary(1) {
        return None;
    }
    let g = &s[..1];
    if !eq_mode(g, "a", m) || !eq_mode(&s[1..2], "x", m) || !eq_mode(&s[3..], "s", m) {
        return None;
    }
    let mid = &s[2..3];
    if !eq_mode(mid, "i", m) && !eq_mode(mid, "e", m) {
        return None;
    }
    Some(format!("{}{}", g, lit("xis", "XIS", m)))
}

/// `{"(octop|vir)(us|i)$", "${1}us"}`:octopi → octopus、viri → virus。
fn r_octopus(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["octop", "vir"], &["us", "i"], ("us", "US"))
}

/// `{"(alias|status)(es)?$", "${1}"}`:statuses → status。
fn r_alias_status(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["alias", "status"], &["es", ""], ("", ""))
}

/// `{"^(ox)en", "${1}"}`:仅首部锚定,oxenhope → oxhope。
fn r_oxen(s: &str, m: Mode) -> Option<String> {
    if s.len() < 4 || !s.is_char_boundary(2) || !s.is_char_boundary(4) {
        return None;
    }
    let g = &s[..2];
    if !eq_mode(g, "ox", m) || !eq_mode(&s[2..4], "en", m) {
        return None;
    }
    format!("{}{}", g, &s[4..]).into()
}

/// `{"(vert|ind)ices$", "${1}ex"}`:indices → index。
fn r_vert_ex(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["vert", "ind"], &["ices"], ("ex", "EX"))
}

/// `{"(matr)ices$", "${1}ix"}`:matrices → matrix。
fn r_matr_ix(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["matr"], &["ices"], ("ix", "IX"))
}

/// `{"(quiz)zes$", "${1}"}`:quizzes → quiz。
fn r_quiz(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["quiz"], &["zes"], ("", ""))
}

/// `{"(database)s$", "${1}"}`:databases → database。
fn r_databases(s: &str, m: Mode) -> Option<String> {
    gt_replace(s, m, &["database"], &["s"], ("", ""))
}

/// 不可数名词表(整词命中即原样返回)。
const UNCOUNTABLES: [&str; 10] = [
    "equipment",
    "information",
    "rice",
    "money",
    "species",
    "series",
    "fish",
    "sheep",
    "jeans",
    "police",
];

/// 不规则变形表 `(复数, 单数)`,按声明顺序尝试。
const IRREGULARS: [(&str, &str); 6] = [
    ("people", "person"),
    ("men", "man"),
    ("children", "child"),
    ("sexes", "sex"),
    ("moves", "move"),
    ("mombies", "mombie"),
];

/// 首字母大写(对齐 Go `strings.Title` 在单词上的行为)。
fn title_case(w: &str) -> String {
    let mut cs = w.chars();
    match cs.next() {
        Some(f) => f.to_uppercase().collect::<String>() + cs.as_str(),
        None => String::new(),
    }
}

/// 单个词的单数化,逐条对齐 `jinzhu/inflection` 编译后的 Singular 规则链。
fn singular_word(s: &str) -> String {
    // 1) 不可数名词:`^(?i)(词)$`,原样返回
    for w in UNCOUNTABLES {
        if s.eq_ignore_ascii_case(w) {
            return s.to_string();
        }
    }

    // 2) 不规则变形:每条按 全大写 / 首字母大写 / 原样 三个变体
    for (plural, singular) in IRREGULARS {
        let up = plural.to_ascii_uppercase();
        if let Some(pre) = s.strip_suffix(up.as_str()) {
            return format!("{}{}", pre, singular.to_ascii_uppercase());
        }
        let titled = title_case(plural);
        if let Some(pre) = s.strip_suffix(titled.as_str()) {
            return format!("{}{}", pre, title_case(singular));
        }
        if let Some(pre) = s.strip_suffix(plural) {
            return format!("{}{}", pre, singular);
        }
    }

    // 3) 常规规则:逆序逐条,每条依次尝试 全大写 / 原样 / 忽略大小写 三个变体
    for rule in SINGULAR_RULES.iter().rev() {
        for mode in [Mode::Upper, Mode::Exact, Mode::Ci] {
            if let Some(out) = rule(s, mode) {
                return out;
            }
        }
    }

    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::ApiPermissionConverter;

    #[test]
    fn test_convert_by_path() {
        let c = ApiPermissionConverter::new();

        let cases: [(&str, &str, &str, &str); 9] = [
            ("get list users", "GET", "/v1/users", "user:view"),
            ("get single user", "GET", "/v1/users/{id}", "user:view"),
            ("create user", "POST", "/v1/users", "user:create"),
            ("update user", "PUT", "/v1/users/{id}", "user:edit"),
            ("delete user", "DELETE", "/v1/users/{id}", "user:delete"),
            ("nested admin settings", "GET", "/api/v1/admin/settings", "admin:view"),
            ("hyphen group", "GET", "/v1/user-groups", "user-group:view"),
            ("get task by typeNames", "GET", "/admin/v1/tasks:type-names", "task:view"),
            ("walk route", "GET", "/admin/v1/apis/walk-route", "api:view"),
        ];

        for (name, method, path, want) in cases {
            let got = c.convert_code_by_path(method, path);
            assert_eq!(got, want, "ConvertCodeByPath({method:?}, {path:?}) [{name}]");
        }
    }

    #[test]
    fn test_convert_by_operation_id() {
        let c = ApiPermissionConverter::new();

        let cases: [(&str, &str, &str); 5] = [
            ("rpc with service and name", "TaskService_ListTaskTypeName", "task:task-type-name:view"),
            ("rpc without Service suffix", "Task_ListTaskTypeName", "task:task-type-name:view"),
            ("get walk route data", "ApiService_GetWalkRouteData", "api:walk-route-data:view"),
            ("rpc without name", "Task_List", "task:view"),
            ("invalid rpc format", "GetStatus", ""),
        ];

        for (name, op, want) in cases {
            let got = c.convert_code_by_operation_id(op);
            assert_eq!(got, want, "ConvertCodeByOperationID({op:?}) [{name}]");
        }
    }

    #[test]
    fn test_strip_version_prefix() {
        let c = ApiPermissionConverter::new();

        let cases: [(&str, &str, &str); 12] = [
            ("empty", "", ""),
            ("root slash", "/", ""),
            ("no leading slash v1/users", "v1/users", "users"),
            ("v1 users", "/v1/users", "users"),
            ("api v1 admin", "/api/v1/admin/settings", "admin/settings"),
            ("v2 only", "/v2", ""),
            ("v10 without slash", "v10", ""),
            ("api v10", "/api/v10", ""),
            ("double slash after version", "/api/v1//admin", "admin"),
            ("version with minor", "/api/v1.9/admin", "admin"),
            ("no version path", "/foo/bar", "foo/bar"),
            ("no version path with colon", "/admin/v1/tasks:type-names", "tasks:type-names"),
        ];

        for (name, input, want) in cases {
            let got = c.strip_version_prefix(input);
            assert_eq!(got, want, "stripVersionPrefix({input:?}) [{name}]");
        }
    }

    #[test]
    fn test_remove_path_params() {
        let c = ApiPermissionConverter::new();

        let cases: [(&str, &str, &str); 13] = [
            ("empty", "", ""),
            ("root slash", "/", ""),
            ("only param", "/{id}", ""),
            ("only param no slash", "{id}", ""),
            ("param with spaces", "/{ id }/", ""),
            ("simple resource", "/users", "users"),
            ("resource with param", "/users/{id}", "users"),
            ("nested resources", "/users/{id}/posts/{postId}", "users/posts"),
            ("trailing slash", "/users/{id}/posts/", "users/posts"),
            ("leading param", "/{id}/users", "users"),
            ("all params", "/{id}/{pid}", ""),
            ("double slashes", "/users//{id}//posts", "users/posts"),
            ("colon segment", "/tasks:type-names/{id}", "tasks:type-names"),
        ];

        for (name, input, want) in cases {
            let got = c.remove_path_params(input);
            assert_eq!(got, want, "removePathParams({input:?}) [{name}]");
        }
    }

    #[test]
    fn test_singularize_segments() {
        let c = ApiPermissionConverter::new();

        let cases: [(&str, &str, &str); 10] = [
            ("empty", "", ""),
            ("already singular", "user:profile", "user:profile"),
            ("simple plural", "tasks", "task"),
            ("colon segments", "tasks:type-names", "task:type-name"),
            ("hyphen segments", "tasks-users", "task-user"),
            ("underline segments", "tasks_users", "task_user"),
            ("slash and underscore", "tasks/type_names", "task/type_name"),
            ("mixed separators", "tasks::names--items", "task::name--item"),
            ("irregular plural", "statuses:passes", "status:pass"),
            ("multiple separators preserved", "tasks--and__more::names", "task--and__more::name"),
        ];

        for (name, input, want) in cases {
            let got = c.singularize_segments(input);
            assert_eq!(got, want, "singularizeSegments({input:?}) [{name}]");
        }
    }

    #[test]
    fn test_method_to_action() {
        let c = ApiPermissionConverter::new();

        let cases: [(&str, &str, &str, &str); 10] = [
            ("GET -> view", "GET", "/v1/users", "view"),
            ("get lowercase -> view", "get", "/v1/users", "view"),
            ("POST -> create", "POST", "/v1/users", "create"),
            ("mixed case POST -> create", "PoSt", "/v1/users", "create"),
            ("PUT -> edit", "PUT", "/v1/users/1", "edit"),
            ("PATCH -> edit", "PATCH", "/v1/users/1", "edit"),
            ("DELETE -> delete", "DELETE", "/v1/users/1", "delete"),
            ("unknown method -> lowercase", "OPTIONS", "/v1/users", "options"),
            ("path ends with /list overrides method", "POST", "/v1/users/list", "view"),
            ("path ends with /list and GET", "GET", "/v1/users/list", "view"),
        ];

        for (name, method, path, want) in cases {
            let got = c.method_to_action(method, path);
            assert_eq!(got, want, "methodToAction({method:?}, {path:?}) [{name}]");
        }
    }

    // ---- 以下补 api.go 解析链的边角分支(移植 api_edge_test.go) ----

    #[test]
    fn test_split_operation_id_edges_second_capture_group() {
        // 无 Service 后缀走第二捕获组
        let c = ApiPermissionConverter::new();
        let (svc, action, name) = c.split_operation_id("Foo_Bar").unwrap();
        assert_eq!(svc, "Foo");
        assert_eq!(action, "Bar");
        assert!(name.is_empty());
    }

    #[test]
    fn test_split_operation_id_edges_trailing_name() {
        // 带尾随 name 段(捕获组不含 "Service" 后缀)
        let c = ApiPermissionConverter::new();
        let (svc, action, name) = c.split_operation_id("TaskService_Update_TaskName").unwrap();
        assert_eq!(svc, "Task");
        assert_eq!(action, "Update");
        assert_eq!(name, "_TaskName");
    }

    #[test]
    fn test_split_operation_id_edges_no_match() {
        let c = ApiPermissionConverter::new();
        for input in ["", "Foo_", "Foo-Bar_Baz", "_List", "Service_"] {
            assert!(
                c.split_operation_id(input).is_none(),
                "splitOperationID({input:?}) 不应匹配"
            );
        }
    }

    /// 带 name 段与全小写 action 的完整组合:
    /// resource 追加 ":"+kebab(name),小写 action 仍命中 view 归一臂。
    #[test]
    fn test_convert_code_by_operation_id_name_arm() {
        let c = ApiPermissionConverter::new();
        assert_eq!(c.convert_code_by_operation_id("TaskService_Update_TaskName"), "task:task-name:edit");
        assert_eq!(c.convert_code_by_operation_id("Foo_list"), "foo:view");
    }

    #[test]
    fn test_split_camel_after_first_word_edges() {
        let c = ApiPermissionConverter::new();
        let cases: [(&str, &str, &str); 4] =
            [("", "", ""), ("lower", "lower", ""), ("List", "List", ""), ("ListFoo", "List", "Foo")];
        for (input, first, rest) in cases {
            let (f, r) = c.split_camel_after_first_word(input);
            assert_eq!(f, first, "first({input:?})");
            assert_eq!(r, rest, "rest({input:?})");
        }
    }

    #[test]
    fn test_path_to_resource_edges() {
        let c = ApiPermissionConverter::new();
        // 注:首段空白的早退分支经管道不可达——stripVersionPrefix 已做 TrimSpace
        // 归一,空白段在进入 pathToResource 前即被清除。
        assert_eq!(c.path_to_resource(""), "");
        assert_eq!(c.path_to_resource("/"), "");
        // 资源段经 singularizeSegments 单数化(users→user)
        assert_eq!(c.path_to_resource("/api/v1/users"), "user");
    }

    #[test]
    fn test_strip_version_prefix_edge_cases() {
        let c = ApiPermissionConverter::new();
        assert_eq!(c.strip_version_prefix("/API/V1/x"), "x", "api/vN 剥离大小写不敏感");
        assert_eq!(c.strip_version_prefix("/v1/api/users"), "users", "中段 api 段被过滤");
        assert_eq!(c.strip_version_prefix("/api"), "", "仅 api 段归空");
        assert_eq!(c.strip_version_prefix("   "), "", "空白归空");
    }

    /// 动作归一化的 create/delete 臂(view/edit 臂已由上文与既有测试覆盖)。
    #[test]
    fn test_convert_code_by_operation_id_action_arms() {
        let c = ApiPermissionConverter::new();
        let cases: [(&str, &str); 6] = [
            ("Foo_Create", "foo:create"),
            ("Foo_add", "foo:create"),
            ("Foo_new", "foo:create"),
            ("Foo_Delete", "foo:delete"),
            ("Foo_remove", "foo:delete"),
            ("Foo_del", "foo:delete"),
        ];
        for (input, want) in cases {
            assert_eq!(c.convert_code_by_operation_id(input), want, "ConvertCodeByOperationID({input:?})");
        }
    }
}
