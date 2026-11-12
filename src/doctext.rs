//! 从常见文档格式中抽取纯文本,供知识库 RAG 入库使用。
//!
//! 移植自 Go 库 tx7do/go-utils 的 [`doctext`] 包。支持格式:
//!
//! - 纯文本族(不需要任何子 feature):`txt` / `md` / `markdown` / `csv` / `log` /
//!   `json` / `xml` / `yml` / `yaml` / `html` / `htm` —— 仅做清洗(规范化换行、
//!   替换无效 UTF-8),原样返回;
//! - `docx`(zip 容器 + `word/document.xml` XML 解析,`doctext` feature);
//! - `pdf`(抽取文本层,非 OCR,`doctext-pdf` feature;关闭该 feature 时 pdf
//!   扩展名直接返回"需要启用 `doctext-pdf`"类错误);
//! - `xlsx`(表格文本化,`doctext-xlsx` feature,复用 `xlsx` 模块;每表一段,
//!   行内单元格制表符相连、行尾空单元格剪掉,表间以 `[sheet]` 名行分隔;
//!   关闭该 feature 时 xlsx 扩展名按不支持拒绝)。
//!
//! 其余扩展名直接拒绝——宁可报"不支持"也不要把二进制乱码灌进向量库。
//!
//! 通用语义(与上游逐式对齐):
//! - 空字节串、超过 `MAX_FILE_SIZE`(10MB)直接报错(大小检查先于扩展名分派);
//! - 扩展名大小写不敏感(`Extract("A.DOCX")` 与 `"a.docx"` 等价);
//! - 不支持的扩展名报 `unsupported file type`(含支持清单提示)。
//!
//! # 示例
//!
//! ```
//! use rust_utils::doctext;
//!
//! let text = doctext::extract("hello.txt", "hello 世界\r\nsecond".as_bytes()).unwrap();
//! assert_eq!(text, "hello 世界\nsecond");
//!
//! // 按扩展名分派,不认识的直接拒绝
//! assert!(doctext::extract("virus.exe", b"x").is_err());
//! assert!(doctext::extract("empty.txt", b"").is_err());
//! ```
//!
//! [`doctext`]: https://github.com/tx7do/go-utils/tree/main/doctext
//!
//! # 与上游 Go 版的适配点
//!
//! 1. **docx**:上游用 `archive/zip` 读出 `word/document.xml` 后做字面量替换
//!    (`</w:p>`→换行、`<w:br/>`→换行、`<w:tab/>`→制表)再逐字节剥掉全部 XML
//!    标签;这里用 zip crate 打开内存字节 + quick-xml 走事件流,语义一致:段落
//!    闭合、换行、制表产生可读边界,其余标签全部丢弃,文本内容按 XML 原文收集、
//!    **最后统一反转义**(顺序与上游一致)。quick-xml 要求 XML 良构,因此烂 XML
//!    在这里报错而上游会剥出残渣;上游对注释/CDATA 的字节级剥离缺陷(例如
//!    `<![CDATA[x]]>` 会剥成 `]]>` 残渣)不复刻,quick-xml 直接取 CDATA 内部原文。
//! 2. **实体解码**:上游 `html.UnescapeString` 带完整 HTML5 实体表;这里手写
//!    常见命名实体(`amp` / `lt` / `gt` / `quot` / `apos` / `nbsp`)加十进制与
//!    十六进制数字引用,非法码点(0、代理区、超出 Unicode 上限)替换为 U+FFFD。
//!    解码为单遍(解码产物不再二次展开),与上游一致;HTML5 对 0x80-0x9F 码点的
//!    windows-1252 重映射不实现——XML 文档的数字引用按 XML 语义取码点原值。
//! 3. **html**:上游把 `.html`/`.htm` 归入纯文本族(只清洗、不去标签、不解实体;
//!    实体解码只发生在 docx 路径),这里保持一致。
//! 4. **pdf**:上游逐页走 ledongthuc/pdf(单页失败跳过不阻断整本,页间补换行);
//!    这里用 pdf-extract 的 `extract_text_from_mem_by_pages`(整本解析,按页
//!    拼接换行,页序一致)。无文本层的 PDF(扫描件/图片型)必须报错而非返回空串。
//! 5. 大小写扩展名、空文件、超限、不支持扩展名、纯文本全空白等处理语义逐式保留。

use std::io::{Cursor, Read};
use std::str;

use quick_xml::events::Event;
use quick_xml::Reader;
use zip::result::ZipError;
use zip::ZipArchive;

/// 上传文件大小上限(10MB)。
pub const MAX_FILE_SIZE: usize = 10 << 20;

/// 纯文本族的扩展名集合(含 html,但不含 docx/pdf)。
const PLAIN_TEXT_EXTS: &[&str] = &[
    ".txt",
    ".md",
    ".markdown",
    ".csv",
    ".log",
    ".json",
    ".xml",
    ".yml",
    ".yaml",
    ".html",
    ".htm",
];

/// 提取失败的原因。`Display` 消息与上游 Go 版的错误文案逐字对齐(便于测试与
/// 日志里做子串匹配)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocTextError {
    /// 空文件(0 字节)。
    EmptyFile,
    /// 文件超过 [`MAX_FILE_SIZE`] 上限,携带实际字节数。
    TooLarge(usize),
    /// 纯文本族清洗后没有可用的非空白内容。
    NoTextExtracted,
    /// docx 提取失败(打开 zip、缺 `word/document.xml`、解析失败、无文本等),
    /// 携带内层原因。
    Docx(String),
    /// pdf 提取失败(解析失败、无文本层、未启用 `doctext-pdf` feature 等),
    /// 携带内层原因。
    Pdf(String),
    /// xlsx 提取失败(打开失败、坏容器等,`xlsx` feature)。
    Xlsx(String),
    /// 不支持的扩展名(已小写化,含点)。
    Unsupported(String),
}

impl std::fmt::Display for DocTextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DocTextError::EmptyFile => write!(f, "file is empty"),
            DocTextError::TooLarge(size) => {
                write!(f, "file too large: {size} bytes (max {MAX_FILE_SIZE})")
            }
            DocTextError::NoTextExtracted => write!(f, "no text content extracted"),
            DocTextError::Docx(inner) => write!(f, "docx extract: {inner}"),
            DocTextError::Pdf(inner) => write!(f, "pdf extract: {inner}"),
            DocTextError::Xlsx(inner) => write!(f, "xlsx extract: {inner}"),
            DocTextError::Unsupported(ext) => write!(
                f,
                "unsupported file type {ext:?} (supported: {})",
                supported_extensions().join(" ")
            ),
        }
    }
}

impl std::error::Error for DocTextError {}

/// 支持的扩展名清单(管理页提示用)。恒含 `.pdf` 与 `.xlsx`,即使
/// `doctext-pdf`/`xlsx` feature 未启用——清单描述的是"这套 API 认识什么",
/// 而不是"当前构建能解什么"。
pub fn supported_extensions() -> &'static [&'static str] {
    &[
        ".txt",
        ".md",
        ".markdown",
        ".csv",
        ".log",
        ".json",
        ".xml",
        ".yml",
        ".yaml",
        ".html",
        ".htm",
        ".docx",
        ".pdf",
        ".xlsx",
    ]
}

/// 按扩展名抽取纯文本。同步阻塞;入参为文件名字节串。
///
/// 扩展名大小写不敏感;先做空文件与 10MB 大小检查,再按扩展名分派。
pub fn extract(file_name: &str, data: &[u8]) -> Result<String, DocTextError> {
    if data.is_empty() {
        return Err(DocTextError::EmptyFile);
    }
    if data.len() > MAX_FILE_SIZE {
        return Err(DocTextError::TooLarge(data.len()));
    }

    let ext = file_ext_lower(file_name);
    match ext.as_str() {
        ".docx" => extract_docx(data),
        ".pdf" => extract_pdf(data),
        #[cfg(feature = "xlsx")]
        ".xlsx" => extract_xlsx(data),
        _ if PLAIN_TEXT_EXTS.contains(&ext.as_str()) => {
            let text = sanitize_text(data);
            if text.trim().is_empty() {
                return Err(DocTextError::NoTextExtracted);
            }
            Ok(text)
        }
        _ => Err(DocTextError::Unsupported(ext)),
    }
}

/// xlsx → 文本(feature `xlsx`):每表一段,行内单元格以制表符相连,
/// 行尾空单元格剪掉;表间以 `[sheet]` 名行分隔。单元格形态与
/// [`crate::xlsx::Cell`] 一致:错误值以 Display 文本、日期以串行数
/// 字符串落文。
#[cfg(feature = "xlsx")]
fn extract_xlsx(data: &[u8]) -> Result<String, DocTextError> {
    let sheets = crate::xlsx::read_all(data).map_err(DocTextError::Xlsx)?;
    let mut out = String::new();
    let mut any_row = false;
    for (i, sheet) in sheets.iter().enumerate() {
        // 表间以空行分隔(首表前不留)
        if i > 0 {
            out.push('\n');
        }
        out.push('[');
        out.push_str(&sheet.name);
        out.push_str("]\n");
        for row in &sheet.rows {
            // 行尾空单元格剪掉,行中间的空单元格保留制表位
            let mut last = row.len();
            while last > 0 && row[last - 1].is_empty() {
                last -= 1;
            }
            for (i, cell) in row[..last].iter().enumerate() {
                if i > 0 {
                    out.push('\t');
                }
                out.push_str(&cell_text(cell));
            }
            out.push('\n');
            any_row = true;
        }
    }
    // 所有表都无数据行(只有表名行)视作无文本
    if !any_row {
        return Err(DocTextError::NoTextExtracted);
    }
    Ok(out)
}

/// 单元格 → 文本(错误值/日期同样转字符串形态落文)。
#[cfg(feature = "xlsx")]
fn cell_text(cell: &crate::xlsx::Cell) -> String {
    use crate::xlsx::Cell;
    match cell {
        Cell::Empty => String::new(),
        Cell::Int(n) => n.to_string(),
        Cell::Float(f) => f.to_string(),
        Cell::Str(s) => s.clone(),
        Cell::Bool(b) => b.to_string(),
        Cell::Err(e) => e.clone(),
        Cell::DateTime(s) => s.clone(),
    }
}

/// 清洗纯文本:无效 UTF-8 连续段替换为单个 U+FFFD、规范化 `\r\n` 为 `\n`。
///
/// 对齐上游 `sanitizeText`(`strings.ToValidUTF8` + `strings.ReplaceAll`,
/// 只处理 `\r\n`,不处理孤立的 `\r`)。
fn sanitize_text(bytes: &[u8]) -> String {
    let s = to_valid_utf8(bytes);
    s.replace("\r\n", "\n")
}

/// 对齐 Go `strings.ToValidUTF8` 的"整段 run 一次替换"语义:每一段**连续**的
/// 无效 UTF-8 字节合并为一个 run,整体替换成单个 U+FFFD。
///
/// `std::str::from_utf8` 的错误粒度是"每个最大无效子序列各一个 U+FFFD",
/// 因此这里在迭代错误时把字节相邻的无效子序列并回同一个 run。
fn to_valid_utf8(bytes: &[u8]) -> String {
    if let Ok(s) = str::from_utf8(bytes) {
        return s.to_string();
    }
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        match str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                // e.valid_up_to() 之前一定合法
                let valid = e.valid_up_to();
                out.push_str(str::from_utf8(&rest[..valid]).expect("validated utf8 prefix"));
                let mut run_end = valid + e.error_len().unwrap_or(rest.len() - valid);
                // 吞并紧邻的无效子序列,合并为一个 run
                while run_end < rest.len() {
                    match str::from_utf8(&rest[run_end..]) {
                        Ok(_) => break,
                        Err(e2) if e2.valid_up_to() == 0 => {
                            run_end += e2.error_len().unwrap_or(rest.len() - run_end);
                        }
                        Err(_) => break,
                    }
                }
                out.push('\u{FFFD}');
                rest = &rest[run_end..];
            }
        }
    }
    out
}

/// 提取扩展名并小写化。对齐 Go `strings.ToLower(filepath.Ext(...))`:
/// 从尾部向前找最后一个 `.`,遇到路径分隔符即止;找不到返回空串。
fn file_ext_lower(file_name: &str) -> String {
    let bytes = file_name.as_bytes();
    let mut dot = None;
    for (i, b) in bytes.iter().enumerate().rev() {
        if *b == b'/' || *b == b'\\' {
            break;
        }
        if *b == b'.' {
            dot = Some(i);
            break;
        }
    }
    match dot {
        Some(i) => file_name[i..].to_lowercase(),
        None => String::new(),
    }
}

/// 解 docx(zip 容器):读出 `word/document.xml`,把段落/换行/制表转成可读
/// 边界、剥全部 XML 标签、反转义实体,再走通用清洗与 trim。
///
/// 对齐上游 `extractDocx`:失败时错误前缀 `docx extract`,缺 `word/document.xml`
/// 报 `word/document.xml not found in docx`,剥完没有可见文本报
/// `no text content extracted from docx`。
fn extract_docx(data: &[u8]) -> Result<String, DocTextError> {
    const DOC_XML: &str = "word/document.xml";
    let mut archive = ZipArchive::new(Cursor::new(data))
        .map_err(|e| DocTextError::Docx(format!("open zip: {e}")))?;

    let mut xml_content = Vec::new();
    {
        let mut member = archive.by_name(DOC_XML).map_err(|e| match e {
            ZipError::FileNotFound => DocTextError::Docx(format!("{DOC_XML} not found in docx")),
            other => DocTextError::Docx(format!("open {DOC_XML}: {other}")),
        })?;
        member
            .read_to_end(&mut xml_content)
            .map_err(|e| DocTextError::Docx(format!("read {DOC_XML}: {e}")))?;
    }

    // 上游顺序:剥标签 → 反转义 → 清洗 → trim。语言要求"进 String 必须合法
    // UTF-8",所以 UTF-8 修复被迫提前到反转义之前(对纯 ASCII 的实体语法无影响)。
    let raw = docx_collect_text(&xml_content)?;
    let escaped = to_valid_utf8(&raw);
    let text = sanitize_text(unescape_entities(&escaped).as_bytes());
    let text = text.trim();
    if text.is_empty() {
        return Err(DocTextError::Docx(
            "no text content extracted from docx".to_string(),
        ));
    }
    Ok(text.to_string())
}

/// 走 quick-xml 事件流收集 `word/document.xml` 的可见文本(实体引用保持原样)。
///
/// 边界规则逐式对齐上游的字面量替换(见模块文档"适配点 1"):
/// - `</w:p>` 段落闭合 → 换行;
/// - `<w:br/>` 空元素 → 换行;
/// - `<w:tab/>` 空元素 → 制表符;
/// - 其余标签(含声明/注释/PI/DOCTYPE)全部丢弃,文本节点按 XML 原文保留。
fn docx_collect_text(xml: &[u8]) -> Result<Vec<u8>, DocTextError> {
    const DOC_XML: &str = "word/document.xml";
    let mut reader = Reader::from_reader(xml);
    // 散落的孤立 `&` 在良构 XML 里不可能出现,但放开检查以便把
    // `R&D company` 这类脏数据剥出可读文本而不是直接报错(对齐上游的宽容度)。
    reader.config_mut().allow_dangling_amp = true;

    let mut out = Vec::with_capacity(xml.len());
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| DocTextError::Docx(format!("parse {DOC_XML}: {e}")))?;
        match event {
            // 实体引用(如 &amp; / &#39;)原样重建为 "&name;" 字节,最后统一反转义
            Event::GeneralRef(r) => {
                out.push(b'&');
                out.extend_from_slice(&r);
                out.push(b';');
            }
            Event::Text(t) => out.extend_from_slice(&t),
            Event::CData(c) => out.extend_from_slice(&c),
            // 段落边界:上游把 "</w:p>" 字面替换为换行
            Event::End(e) => {
                if e.name().as_ref() == b"w:p" {
                    out.push(b'\n');
                }
            }
            // 空元素:上游把 "<w:br/>"/"<w:tab/>" 字面替换为换行/制表
            Event::Empty(e) => match e.name().as_ref() {
                b"w:br" => out.push(b'\n'),
                b"w:tab" => out.push(b'\t'),
                _ => {}
            },
            Event::Eof => break,
            // Start/Decl/Comment/PI/DocType 等:标签本身,丢弃
            _ => {}
        }
    }
    Ok(out)
}

/// 常见命名实体 → 替换文本。上游用完整 HTML5 实体表,这里覆盖上游测试与
/// 实际 docx 场景的最常用子集(见模块文档"适配点 2")。
fn named_entity(name: &str) -> Option<&'static str> {
    match name {
        "amp" => Some("&"),
        "lt" => Some("<"),
        "gt" => Some(">"),
        "quot" => Some("\""),
        "apos" => Some("'"),
        "nbsp" => Some("\u{00a0}"),
        _ => None,
    }
}

/// 解码单个实体引用(入参从 `&` 开始)。返回 (解码文本, 消费的字节数)。
///
/// 对齐 Go `html.UnescapeString` 的数字引用语义:`&#0;`、代理区、超出 Unicode
/// 上限、溢出都替换为 U+FFFD;解码是单遍的,产物不再二次展开。
fn decode_entity(src: &str) -> Option<(String, usize)> {
    // HTML5 最长命名实体(含分隔符)32 字节,超出窗口视为普通文本
    let window = &src[..src.len().min(33)];
    let semi = window.find(';')?;
    let name = &src[1..semi];
    if name.is_empty() {
        return None;
    }
    if let Some(digits) = name.strip_prefix('#') {
        let (radix, digits) = match digits
            .strip_prefix('x')
            .or_else(|| digits.strip_prefix('X'))
        {
            Some(hex) => (16u32, hex),
            None => (10u32, digits),
        };
        let all_digits = digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (radix == 16 && matches!(b, b'a'..=b'f' | b'A'..=b'F')));
        if !all_digits {
            return None;
        }
        // 溢出视作超限码点(对齐 Go:超限 → U+FFFD)
        let cp = u64::from_str_radix(digits, radix).unwrap_or(u64::MAX);
        let ch = if cp == 0 || (0xD800..=0xDFFF).contains(&cp) || cp > 0x10FFFF {
            '\u{FFFD}'
        } else {
            char::from_u32(cp as u32).expect("checked codepoint range")
        };
        Some((ch.to_string(), semi + 1))
    } else {
        named_entity(name).map(|s| (s.to_string(), semi + 1))
    }
}

/// 实体反转义,对齐上游"剥完标签后统一调 `html.UnescapeString`"的顺序:
/// 拼接串里的 `&...;` 逐个解码,无法识别的保持原样。
fn unescape_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        match decode_entity(tail) {
            Some((text, consumed)) => {
                out.push_str(&text);
                rest = &tail[consumed..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// 抽取 PDF 文本层(非 OCR:扫描件无文本层会得到空内容并报错)。
///
/// 上游逐页抽文本、单页失败跳过、页间补换行;这里用 pdf-extract 的按页提取
/// 接口(整本解析,按页拼接换行,页序一致),拼接语义与上游逐字等价。
#[cfg(feature = "doctext-pdf")]
fn extract_pdf(data: &[u8]) -> Result<String, DocTextError> {
    let pages = pdf_extract::extract_text_from_mem_by_pages(data)
        .map_err(|e| DocTextError::Pdf(format!("open pdf: {e}")))?;

    let text = sanitize_text(pages.join("\n").as_bytes());
    let text = text.trim();
    if text.replace('\n', "").trim().is_empty() {
        return Err(DocTextError::Pdf(
            "no text layer found (scanned/image pdf is not supported)".to_string(),
        ));
    }
    Ok(text.to_string())
}

/// `doctext-pdf` feature 未启用时,pdf 扩展名直接拒绝。
#[cfg(not(feature = "doctext-pdf"))]
fn extract_pdf(_data: &[u8]) -> Result<String, DocTextError> {
    Err(DocTextError::Pdf(
        "pdf support requires the `doctext-pdf` feature".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 纯文本族 ----

    #[test]
    fn test_extract_plain_text_family() {
        for ext in [
            ".txt",
            ".md",
            ".markdown",
            ".csv",
            ".log",
            ".json",
            ".xml",
            ".yml",
            ".yaml",
            ".html",
            ".htm",
        ] {
            let text = extract(&format!("doc{ext}"), "hello 世界".as_bytes())
                .unwrap_or_else(|e| panic!("{ext}: {e}"));
            assert_eq!(text, "hello 世界", "ext={ext}");
        }
    }

    #[test]
    fn test_extract_normalizes_crlf_and_sanitizes_utf8() {
        let text = extract("a.txt", b"l1\r\nl2").unwrap();
        assert_eq!(text, "l1\nl2");

        // 无效 UTF-8 字节段(连续 run)替换为 U+FFFD,有效部分保留
        let text = extract("b.txt", b"ok\xff\xfe").unwrap();
        assert!(text.contains("ok"));
        assert!(text.contains('\u{FFFD}'));
    }

    #[test]
    fn test_extract_rejects_empty_blank_oversize() {
        let err = extract("a.txt", &[]).unwrap_err();
        assert!(err.to_string().contains("file is empty"));

        let err = extract("a.txt", b" \t\n \r\n ").unwrap_err();
        assert!(err.to_string().contains("no text content extracted"));

        let oversize = vec![b'a'; MAX_FILE_SIZE + 1];
        let err = extract("a.pdf", &oversize).unwrap_err();
        assert!(err.to_string().contains("file too large"));
    }

    #[test]
    fn test_extract_rejects_unsupported_extension() {
        // 扩展名大小写不敏感(extract 内部小写化):.EXE 仍落在拒绝分支
        for name in ["a.exe", "b.doc", "noext", "c.pdf.txtx", "d.EXE"] {
            let err = extract(name, b"hello").unwrap_err();
            assert!(
                err.to_string().contains("unsupported file type"),
                "name={name}, err={err}"
            );
        }
    }

    #[test]
    fn test_supported_extensions() {
        assert_eq!(
            supported_extensions(),
            &[
                ".txt",
                ".md",
                ".markdown",
                ".csv",
                ".log",
                ".json",
                ".xml",
                ".yml",
                ".yaml",
                ".html",
                ".htm",
                ".docx",
                ".pdf",
                ".xlsx",
            ]
        );
    }

    // ---- docx ----

    /// 测试夹具:在内存里现做一个小 docx(zip 容器)。
    fn build_docx(members: &[(&str, &str)]) -> Vec<u8> {
        use std::io::Write as _;
        let mut buf = Cursor::new(Vec::new());
        let mut zw = zip::write::ZipWriter::new(&mut buf);
        for (name, content) in members {
            zw.start_file(
                (*name).to_string(),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap_or_else(|e| panic!("start_file {name}: {e}"));
            zw.write_all(content.as_bytes())
                .unwrap_or_else(|e| panic!("write {name}: {e}"));
        }
        zw.finish().expect("finish zip");
        buf.into_inner()
    }

    #[test]
    fn test_extract_docx() {
        // 覆盖:非 document 成员被跳过、段落边界与 br/tab 转可读边界、
        // XML 标签全剥、实体反转义。组合后的精确输出被钉死(对齐上游断言)。
        let doc_xml = "<w:document><w:body>\
            <w:p>first</w:p><w:p>second</w:p>\
            <w:p>l1<w:br/>l2</w:p>\
            <w:p>x<w:tab/>y</w:p>\
            <w:p>a &amp; b</w:p>\
            </w:body></w:document>";
        let data = build_docx(&[
            ("[Content_Types].xml", "<?xml version=\"1.0\"?><Types/>"),
            ("word/document.xml", doc_xml),
        ]);
        let text = extract("a.docx", &data).unwrap();
        assert_eq!(text, "first\nsecond\nl1\nl2\nx\ty\na & b");
    }

    #[test]
    fn test_extract_docx_with_wt_runs() {
        // 真实 docx 的文本包在 <w:t> 里,混着带属性的 rPr/pPr 等节点:
        // 标签(含属性)全剥,只留文本;相邻 run 直接拼接,不补空格。
        let doc_xml =
            "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
            <w:body><w:p><w:pPr><w:rPr/></w:pPr><w:r><w:rPr/></w:r>\
            <w:t>你好</w:t><w:t xml:space=\"preserve\"> world</w:t></w:p></w:body></w:document>";
        let data = build_docx(&[("word/document.xml", doc_xml)]);
        let text = extract("A.DOCX", &data).unwrap();
        assert_eq!(text, "你好 world");
    }

    #[test]
    fn test_extract_docx_unescapes_common_entities() {
        // 常见命名实体 + 十进制/十六进制数字引用;单遍解码:
        // "&#x26;amp;" 先解出 '&' 再接字面 "amp;",不再二次展开。
        let doc_xml = "<w:p>&lt;tag&gt; &quot;q&quot; &apos;a&apos;</w:p>\
            <w:p>&nbsp;X&#39;Y&#x26;amp;</w:p>";
        let data = build_docx(&[("word/document.xml", doc_xml)]);
        let text = extract("a.docx", &data).unwrap();
        assert_eq!(text, "<tag> \"q\" 'a'\n\u{00a0}X'Y&amp;");
    }

    #[test]
    fn test_extract_docx_missing_document() {
        let data = build_docx(&[("word/settings.xml", "<settings/>")]);
        let err = extract("a.docx", &data).unwrap_err();
        assert!(err
            .to_string()
            .contains("word/document.xml not found in docx"));
    }

    #[test]
    fn test_extract_docx_corrupt_zip() {
        let err = extract("a.docx", b"this is not a zip at all").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("docx extract"), "err={msg}");
        assert!(msg.contains("open zip"), "err={msg}");
    }

    #[test]
    fn test_extract_docx_no_text() {
        let data = build_docx(&[("word/document.xml", "<w:p></w:p>")]);
        let err = extract("a.docx", &data).unwrap_err();
        assert!(err
            .to_string()
            .contains("no text content extracted from docx"));
    }

    // ---- pdf ----

    /// 构造一个最小合法的单页 PDF,contentStream 为页面内容流。
    /// 传文本绘制算子得到带文本层的页面;传路径算子得到无文本层页面
    /// (扫描件等价物)。xref 偏移按实际字节位置计算,保证结构合法。
    fn build_pdf(content_stream: &str) -> Vec<u8> {
        fn put_obj(b: &mut Vec<u8>, offsets: &mut [usize; 6], n: usize, body: &str) {
            offsets[n] = b.len();
            b.extend_from_slice(format!("{n} 0 obj\n{body}\nendobj\n").as_bytes());
        }

        let mut b: Vec<u8> = Vec::new();
        let mut offsets = [0usize; 6];
        b.extend_from_slice(b"%PDF-1.4\n");
        put_obj(&mut b, &mut offsets, 1, "<< /Type /Catalog /Pages 2 0 R >>");
        put_obj(
            &mut b,
            &mut offsets,
            2,
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        );
        put_obj(
            &mut b,
            &mut offsets,
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        );
        put_obj(
            &mut b,
            &mut offsets,
            4,
            &format!(
                "<< /Length {} >>\nstream\n{}\nendstream",
                content_stream.len(),
                content_stream
            ),
        );
        put_obj(
            &mut b,
            &mut offsets,
            5,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        );
        let xref = b.len();
        b.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
        for off in &offsets[1..=5] {
            b.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        b.extend_from_slice(
            format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );
        b
    }

    #[cfg(feature = "doctext-pdf")]
    #[test]
    fn test_extract_pdf_text_layer() {
        let stream = "BT\n/F1 12 Tf\n72 720 Td\n(HELLO PDF) Tj\nET";
        let text = extract("a.pdf", &build_pdf(stream)).unwrap();
        assert!(text.contains("HELLO PDF"), "text={text:?}");
    }

    #[cfg(feature = "doctext-pdf")]
    #[test]
    fn test_extract_pdf_no_text_layer() {
        // 只有路径绘制算子:无文本层(扫描件等价物)必须报错而非返回空串成功
        let stream = "1 1 m\n10 10 l\nS";
        let err = extract("a.pdf", &build_pdf(stream)).unwrap_err();
        assert!(err.to_string().contains("no text layer"), "err={err}");
    }

    #[cfg(feature = "doctext-pdf")]
    #[test]
    fn test_extract_pdf_corrupt() {
        let err = extract("a.pdf", b"definitely not a pdf").unwrap_err();
        assert!(err.to_string().contains("pdf extract"), "err={err}");
    }

    #[cfg(not(feature = "doctext-pdf"))]
    #[test]
    fn test_extract_pdf_requires_feature() {
        let err = extract("a.pdf", b"%PDF-not-really").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pdf extract"), "err={msg}");
        assert!(msg.contains("doctext-pdf"), "err={msg}");
    }

    // ---- 实体解码 / UTF-8 run 语义的单元级补充 ----

    #[test]
    fn test_unescape_entities_passthrough() {
        // 无法识别的实体、孤立 '&' 原样保留
        assert_eq!(unescape_entities("a & b"), "a & b");
        assert_eq!(unescape_entities("&unknown;"), "&unknown;");
        assert_eq!(unescape_entities("R&D company"), "R&D company");
        // 超窗口/无分号不展开
        assert_eq!(unescape_entities("&amp"), "&amp");
        // 单遍解码:产物不二次展开
        assert_eq!(unescape_entities("&amp;amp;"), "&amp;");
    }

    #[test]
    fn test_to_valid_utf8_run_semantics() {
        // 连续无效字节合并为一个 run → 单个 U+FFFD(对齐 Go ToValidUTF8)
        assert_eq!(to_valid_utf8(b"ok\xff\xfe"), "ok\u{FFFD}");
        // 被合法字节隔开的 run 各自替换
        assert_eq!(to_valid_utf8(b"a\xffb\xfec"), "a\u{FFFD}b\u{FFFD}c");
        // 截断的多字节序列
        assert_eq!(to_valid_utf8(b"ok\xe4\xb8"), "ok\u{FFFD}");
        // 合法串原样
        assert_eq!(to_valid_utf8("世界".as_bytes()), "世界");
    }

    // ---- xlsx(feature `doctext-xlsx`;未启用时按不支持拒绝) ----

    #[cfg(feature = "xlsx")]
    fn sample_xlsx() -> Vec<u8> {
        use crate::xlsx::{SheetOut, XlsxValue};
        let mut sheet = SheetOut::new("用户");
        sheet.push_header(vec![
            XlsxValue::from("姓名"),
            XlsxValue::from("年龄"),
            XlsxValue::from("激活"),
        ]);
        sheet.push_row(vec![
            XlsxValue::from("小明"),
            XlsxValue::Int(18),
            XlsxValue::Bool(true),
        ]);
        // 行尾空单元格:文本化时剪掉
        sheet.push_row(vec![
            XlsxValue::from("小红"),
            XlsxValue::Empty,
            XlsxValue::Empty,
        ]);
        let mut orders = SheetOut::new("订单");
        orders.push_row(vec![XlsxValue::from("A-001"), XlsxValue::Float(19.99)]);
        crate::xlsx::write_to_bytes(&[sheet, orders]).unwrap()
    }

    #[cfg(feature = "xlsx")]
    #[test]
    fn test_extract_xlsx_text() {
        let bytes = sample_xlsx();
        let text = extract("报表.xlsx", &bytes).unwrap();
        let expect = "[用户]\n姓名\t年龄\t激活\n小明\t18\ttrue\n小红\n\n[订单]\nA-001\t19.99\n";
        assert_eq!(text, expect);
        // 扩展名大小写不敏感
        assert!(extract("报表.XLSX", &bytes).is_ok());
        // 坏容器报 Xlsx 内层错误
        let err = extract("broken.xlsx", b"not a zip").unwrap_err();
        assert!(err.to_string().contains("xlsx extract"), "err={err}");
        // 全空表 → 无文本
        let empty = crate::xlsx::write_to_bytes(&[crate::xlsx::SheetOut::new("空")]).unwrap();
        assert!(matches!(
            extract("empty.xlsx", &empty),
            Err(DocTextError::NoTextExtracted)
        ));
    }

    #[cfg(not(feature = "xlsx"))]
    #[test]
    fn test_xlsx_unsupported_without_feature() {
        // feature 关闭时 xlsx 按不支持拒绝(清单仍列出,语义见其文档)
        assert!(extract("a.xlsx", b"x").is_err());
    }
}
