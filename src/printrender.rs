//! 服务端打印渲染：把前端渲染管线（go-wind-print 内核）产出的最终 HTML 用
//! 本机 Chrome/Edge（chromiumoxide 驱 CDP，自动探测安装路径）打印成 PDF，
//! 或截成 PNG/JPEG 图（列表缩略图、报表预览图）。
//!
//! 分工边界：分页/毫米布局/字体全部由前端内核完成（两遍渲染：测量→分页→
//! 最终 HTML），本模块只做 HTML → PDF / 图片这一步（Page.printToPDF /
//! Page.captureScreenshot），纸张宽高与方向由调用方按模板元数据传入——
//! 保证"预览即所得"（同一 Chromium 引擎），后端不重排、不理解模板。
//!
//! 渲染器留接口（[`Renderer`]）：默认本机 Chrome 的 CDP 实现；部署侧如偏好
//! 伴生容器（Playwright + Chromium 镜像），实现 [`Renderer`] 换入即可。

use std::sync::OnceLock;
use std::time::Duration;

/// 打印/截图的内容来源。
#[derive(Debug, Clone)]
pub enum PrintSource {
    /// 前端内核产出的最终文档（已完成分页），应为完整 `<html>` 文档。
    Html(String),
    /// 直接导航到 URL（等待 load 后再渲染；http(s)/file 均可）。
    Url(String),
}

/// 一次 PDF 打印的参数。
///
/// 版面字段全有缺省（A4 纵向、零边距、1.0 缩放、整篇、无页眉脚、300ms 沉降），
/// 典型用法 `PrintOptions { source: PrintSource::Html(html), ..Default::default() }`。
#[derive(Debug, Clone)]
pub struct PrintOptions {
    pub source: PrintSource,
    /// 纸张尺寸（毫米），前端按模板 paperSize 解析后传入。
    pub paper_width_mm: f64,
    pub paper_height_mm: f64,
    /// 横向（前端按模板方向交换宽高后传 false，避免二次旋转）。
    pub landscape: bool,
    /// 打印背景色/背景图（printToPDF 默认不打印背景）。
    pub background: bool,
    /// 页边距（毫米，>= 0）。前端零边距自绘页眉脚的模板保持 0。
    pub margin_top_mm: f64,
    pub margin_right_mm: f64,
    pub margin_bottom_mm: f64,
    pub margin_left_mm: f64,
    /// 页面缩放（0.1~2.0，CDP 的取值域），1.0 即不缩放。
    pub scale: f64,
    /// 页码范围（如 `"1-5, 8, 11-13"`），空串 = 全部。只做语法检查，
    /// 顺序/越界由 Chromium 裁决。
    pub page_ranges: String,
    /// 打印浏览器自带的页眉/页脚（页码/URL/日期）。自绘模板用
    /// `header_html`/`footer_html`（`<span class=…>` 由 Chromium 填充）。
    pub display_header_footer: bool,
    pub header_html: String,
    pub footer_html: String,
    /// 内容写入后的布局沉降等待（毫秒，字体/图片就绪兜底）。
    pub settle_ms: u64,
}

impl Default for PrintOptions {
    fn default() -> Self {
        PrintOptions {
            source: PrintSource::Html(String::new()),
            paper_width_mm: 210.0,
            paper_height_mm: 297.0,
            landscape: false,
            background: false,
            margin_top_mm: 0.0,
            margin_right_mm: 0.0,
            margin_bottom_mm: 0.0,
            margin_left_mm: 0.0,
            scale: 1.0,
            page_ranges: String::new(),
            display_header_footer: false,
            header_html: String::new(),
            footer_html: String::new(),
            settle_ms: 300,
        }
    }
}

impl PrintOptions {
    /// 参数体检：触碰浏览器之前执行，无 Chrome 的环境也能单测。
    pub fn validate(&self) -> Result<(), String> {
        match &self.source {
            PrintSource::Html(html) => {
                if html.is_empty() {
                    return Err("printrender: empty html".into());
                }
            }
            PrintSource::Url(url) => {
                if url.is_empty() {
                    return Err("printrender: empty url".into());
                }
                if !(url.starts_with("http://")
                    || url.starts_with("https://")
                    || url.starts_with("file://"))
                {
                    return Err("printrender: url must start with http(s):// or file://".into());
                }
            }
        }
        for (name, v) in [
            ("paper width", self.paper_width_mm),
            ("paper height", self.paper_height_mm),
        ] {
            if !v.is_finite() || v <= 0.0 {
                return Err("printrender: paper size required (mm)".into());
            }
            let _ = name;
        }
        for (name, v) in [
            ("top", self.margin_top_mm),
            ("right", self.margin_right_mm),
            ("bottom", self.margin_bottom_mm),
            ("left", self.margin_left_mm),
        ] {
            if !v.is_finite() || v < 0.0 {
                return Err(format!(
                    "printrender: margin {name} must be a finite mm >= 0"
                ));
            }
        }
        if !self.scale.is_finite() || !(0.1..=2.0).contains(&self.scale) {
            return Err("printrender: scale must be a finite number within 0.1..=2.0".into());
        }
        if !page_ranges_valid(&self.page_ranges) {
            return Err("printrender: invalid page ranges (expect like \"1-5, 8, 11-13\")".into());
        }
        if self.settle_ms > 60_000 {
            return Err("printrender: settle_ms too large (max 60000)".into());
        }
        Ok(())
    }
}

/// 页码范围语法检查：空 = 全部；否则逗号分隔的页号或页号区间
/// （`"3"`、`"1-5"`，允许空白）。非负整数才合法——负号会在这里被拒。
pub fn page_ranges_valid(ranges: &str) -> bool {
    if ranges.is_empty() {
        return true;
    }
    ranges.split(',').all(|part| {
        let part = part.trim();
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (a.trim(), b.trim());
                !a.is_empty()
                    && !b.is_empty()
                    && a.bytes().all(|c| c.is_ascii_digit())
                    && b.bytes().all(|c| c.is_ascii_digit())
            }
            None => !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()),
        }
    })
}

/// 一次截图的参数。
#[derive(Debug, Clone)]
pub struct ScreenshotOptions {
    pub source: PrintSource,
    /// PNG（无损，默认）或 JPEG（体积小，`quality` 生效）。
    pub jpeg: bool,
    /// JPEG 质量 1~100（CDP 取值域）；PNG 时忽略。
    pub quality: u8,
    /// 整页长截图（滚动并截全）；false 只截视口。
    pub full_page: bool,
    /// 内容写入后的布局沉降等待（毫秒）。
    pub settle_ms: u64,
}

impl Default for ScreenshotOptions {
    fn default() -> Self {
        ScreenshotOptions {
            source: PrintSource::Html(String::new()),
            jpeg: false,
            quality: 80,
            full_page: false,
            settle_ms: 300,
        }
    }
}

impl ScreenshotOptions {
    /// 参数体检：触碰浏览器之前执行。
    pub fn validate(&self) -> Result<(), String> {
        match &self.source {
            PrintSource::Html(html) => {
                if html.is_empty() {
                    return Err("printrender: empty html".into());
                }
            }
            PrintSource::Url(url) => {
                if url.is_empty() {
                    return Err("printrender: empty url".into());
                }
                if !(url.starts_with("http://")
                    || url.starts_with("https://")
                    || url.starts_with("file://"))
                {
                    return Err("printrender: url must start with http(s):// or file://".into());
                }
            }
        }
        if self.jpeg && !(1..=100).contains(&self.quality) {
            return Err("printrender: jpeg quality must be within 1..=100".into());
        }
        if self.settle_ms > 60_000 {
            return Err("printrender: settle_ms too large (max 60000)".into());
        }
        Ok(())
    }
}

/// HTML/URL → PDF、图片 渲染器接口（可换远程 print-render 服务实现）。
pub trait Renderer: Send + Sync {
    fn render_pdf(
        &self,
        opts: PrintOptions,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;

    fn render_screenshot(
        &self,
        opts: ScreenshotOptions,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;
}

/// 浏览器查找：CHROME_PATH 环境变量 → PATH 探测 → 常见安装路径 → Edge 兜底。
fn find_browser() -> Result<String, String> {
    if let Ok(p) = std::env::var("CHROME_PATH") {
        let p = p.trim().to_string();
        if !p.is_empty() && std::path::Path::new(&p).exists() {
            return Ok(p);
        }
    }
    for name in [
        "chrome",
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ] {
        if let Ok(path) = which_look_path(name) {
            return Ok(path);
        }
    }
    let candidates = [
        // Windows 服务器常无 Chrome，Edge 同 Chromium 协议兜底。
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        "/usr/bin/microsoft-edge",
    ];
    for p in candidates {
        if std::path::Path::new(p).exists() {
            return Ok(p.to_string());
        }
    }
    Err(
        "printrender: no Chrome/Edge found (set CHROME_PATH or install chromium in the image)"
            .into(),
    )
}

/// PATH 探测（`which` 的最小实现；无 PATH 命中返回 Err）。
fn which_look_path(name: &str) -> Result<String, String> {
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let candidate = std::path::Path::new(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    Err(format!("{name} not on PATH"))
}

/// Linux 下 root 运行时 Chrome 需 --no-sandbox 才能启动（容器默认用户）；
/// PRINTRENDER_NO_SANDBOX=0 可强制关闭该行为。
fn needs_no_sandbox() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    if std::env::var("PRINTRENDER_NO_SANDBOX").as_deref() == Ok("0") {
        return false;
    }
    // 无 geteuid 稳定跨平台口；libc 不入依赖树，读 /proc 自我状态兜底。
    std::fs::read_to_string("/proc/self/status")
        .map(|s| {
            s.lines()
                .any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(1) == Some("0"))
        })
        .unwrap_or(false)
}

/// 进程级复用的浏览器实例（与上游 ChromeRenderer 的 allocator 复用同语义：
/// 一次启动、多页渲染；打印服务无网络/扩展需求，收窄攻击面）。
static BROWSER: OnceLock<chromiumoxide::Browser> = OnceLock::new();

async fn browser() -> Result<&'static chromiumoxide::Browser, String> {
    if let Some(b) = BROWSER.get() {
        return Ok(b);
    }
    let path = find_browser()?;
    let mut config = chromiumoxide::BrowserConfig::builder()
        .chrome_executable(path)
        // 打印服务无网络/扩展需求：收窄攻击面
        .arg("--disable-extensions")
        .arg("--no-first-run")
        .arg("--no-default-browser-check");
    if needs_no_sandbox() {
        config = config.arg("--no-sandbox");
    }
    let config = config
        .build()
        .map_err(|e| format!("printrender: browser config: {e}"))?;
    let (browser, mut handler) = chromiumoxide::Browser::launch(config)
        .await
        .map_err(|e| format!("printrender: launch browser: {e}"))?;
    // CDP 连接泵：常驻后台，进程生命周期内随浏览器共存亡。
    tokio::spawn(
        async move { while futures_util::StreamExt::next(&mut handler).await.is_some() {} },
    );
    let _ = BROWSER.set(browser);
    BROWSER
        .get()
        .ok_or_else(|| "printrender: browser init".into())
}

/// 把内容送进页面：Html 走 set_content（document.write 同语义），
/// Url 走导航（等待 load 事件）。返回前统一做布局沉降等待。
async fn load_source(
    page: &chromiumoxide::Page,
    source: &PrintSource,
    settle_ms: u64,
) -> Result<(), String> {
    match source {
        PrintSource::Html(html) => {
            page.set_content(html)
                .await
                .map_err(|e| format!("printrender: set content: {e}"))?;
        }
        PrintSource::Url(url) => {
            let params = chromiumoxide::cdp::browser_protocol::page::NavigateParams::builder()
                .url(url)
                .build()
                .map_err(|e| format!("printrender: navigate params: {e}"))?;
            page.goto(params)
                .await
                .map_err(|e| format!("printrender: navigate: {e}"))?;
        }
    }
    tokio::time::sleep(Duration::from_millis(settle_ms)).await;
    Ok(())
}

/// 本机 Chrome 的 CDP 渲染器（默认实现）。
pub struct ChromeRenderer;

impl Renderer for ChromeRenderer {
    async fn render_pdf(&self, opts: PrintOptions) -> Result<Vec<u8>, String> {
        use chromiumoxide::cdp::browser_protocol::page::PrintToPdfParams;

        opts.validate()?;

        let browser = browser().await?;
        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| format!("printrender: new page: {e}"))?;
        load_source(&page, &opts.source, opts.settle_ms).await?;

        let mm_to_inch = |mm: f64| mm / 25.4;
        // 纸张毫米转英寸（PrintToPDF 以英寸为单位）。
        let params = PrintToPdfParams {
            landscape: Some(opts.landscape),
            print_background: Some(opts.background),
            display_header_footer: Some(opts.display_header_footer),
            header_template: (!opts.header_html.is_empty()).then(|| opts.header_html.clone()),
            footer_template: (!opts.footer_html.is_empty()).then(|| opts.footer_html.clone()),
            paper_width: Some(mm_to_inch(opts.paper_width_mm)),
            paper_height: Some(mm_to_inch(opts.paper_height_mm)),
            margin_top: Some(mm_to_inch(opts.margin_top_mm)),
            margin_bottom: Some(mm_to_inch(opts.margin_bottom_mm)),
            margin_left: Some(mm_to_inch(opts.margin_left_mm)),
            margin_right: Some(mm_to_inch(opts.margin_right_mm)),
            scale: Some(opts.scale),
            page_ranges: (!opts.page_ranges.is_empty()).then(|| opts.page_ranges.clone()),
            ..Default::default()
        };
        let pdf = page
            .pdf(params)
            .await
            .map_err(|e| format!("printrender: print to pdf: {e}"))?;
        if pdf.is_empty() {
            return Err("printrender: empty pdf".into());
        }
        Ok(pdf)
    }

    async fn render_screenshot(&self, opts: ScreenshotOptions) -> Result<Vec<u8>, String> {
        use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
        use chromiumoxide::page::ScreenshotParams;

        opts.validate()?;

        let browser = browser().await?;
        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| format!("printrender: new page: {e}"))?;
        load_source(&page, &opts.source, opts.settle_ms).await?;

        let format = if opts.jpeg {
            CaptureScreenshotFormat::Jpeg
        } else {
            CaptureScreenshotFormat::Png
        };
        let mut params = ScreenshotParams::builder()
            .format(format)
            .full_page(opts.full_page);
        if opts.jpeg {
            params = params.quality(i64::from(opts.quality));
        }
        let image = page
            .screenshot(params.build())
            .await
            .map_err(|e| format!("printrender: screenshot: {e}"))?;
        if image.is_empty() {
            return Err("printrender: empty screenshot".into());
        }
        Ok(image)
    }
}

/// 用默认渲染器打印 PDF。
pub async fn render_pdf(opts: PrintOptions) -> Result<Vec<u8>, String> {
    ChromeRenderer.render_pdf(opts).await
}

/// 用默认渲染器截图（PNG/JPEG）。
pub async fn render_screenshot(opts: ScreenshotOptions) -> Result<Vec<u8>, String> {
    ChromeRenderer.render_screenshot(opts).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // 参数校验在触碰浏览器之前执行,无 Chrome 的环境也能跑。
    #[tokio::test]
    async fn render_pdf_rejects_empty_html() {
        let err = render_pdf(PrintOptions::default()).await.unwrap_err();
        assert_eq!(err, "printrender: empty html");
    }

    #[tokio::test]
    async fn render_pdf_rejects_non_positive_paper_size() {
        for (w, h) in [(0.0, 297.0), (210.0, 0.0), (-1.0, 297.0), (210.0, -1.0)] {
            let opts = PrintOptions {
                source: PrintSource::Html("<html><body>x</body></html>".into()),
                paper_width_mm: w,
                paper_height_mm: h,
                ..Default::default()
            };
            let err = render_pdf(opts).await.unwrap_err();
            assert_eq!(err, "printrender: paper size required (mm)", "w={w} h={h}");
        }
    }

    fn html_opts() -> PrintOptions {
        PrintOptions {
            source: PrintSource::Html("<html><body>x</body></html>".into()),
            ..Default::default()
        }
    }

    #[test]
    fn validate_accepts_minimal_html_options() {
        assert_eq!(html_opts().validate(), Ok(()));
        // Default 的 html 为空 → 拒;补上 html → 过
        assert!(PrintOptions::default().validate().is_err());
    }

    #[test]
    fn validate_url_source_scheme() {
        for (url, ok) in [
            ("https://example.com/report", true),
            ("http://127.0.0.1:8080/print/1", true),
            ("file:///srv/reports/a.html", true),
            ("ftp://example.com/a", false),
            ("javascript:alert(1)", false),
            ("example.com/report", false),
            ("", false),
        ] {
            let opts = PrintOptions {
                source: PrintSource::Url(url.into()),
                ..Default::default()
            };
            assert_eq!(opts.validate().is_ok(), ok, "url={url:?}");
        }
    }

    #[test]
    fn validate_scale_bounds() {
        for (scale, ok) in [
            (1.0, true),
            (0.1, true),
            (2.0, true),
            (0.09, false),
            (2.01, false),
            (0.0, false),
            (-1.0, false),
        ] {
            let mut opts = html_opts();
            opts.scale = scale;
            let err = opts.validate();
            assert_eq!(err.is_ok(), ok, "scale={scale} err={err:?}");
            if !ok {
                assert!(err.unwrap_err().contains("scale"));
            }
        }
        // NaN 也必须被拒(比较运算对 NaN 恒 false 的经典陷阱)
        let mut opts = html_opts();
        opts.scale = f64::NAN;
        assert!(opts.validate().is_err());
    }

    #[test]
    fn validate_margins_non_negative() {
        let mut opts = html_opts();
        opts.margin_top_mm = 10.0;
        opts.margin_right_mm = 5.5;
        opts.margin_bottom_mm = 12.0;
        opts.margin_left_mm = 0.0;
        assert_eq!(opts.validate(), Ok(()));

        for set in [(0, -0.1), (1, -3.0)] {
            let mut opts = html_opts();
            match set.0 {
                0 => opts.margin_top_mm = set.1,
                _ => opts.margin_right_mm = set.1,
            }
            let err = opts.validate().unwrap_err();
            assert!(err.contains("margin"), "err={err}");
        }
        let mut opts = html_opts();
        opts.margin_bottom_mm = f64::NAN;
        assert!(opts.validate().is_err());
    }

    #[test]
    fn validate_settle_ms_cap() {
        let mut opts = html_opts();
        opts.settle_ms = 60_000;
        assert_eq!(opts.validate(), Ok(()));
        opts.settle_ms = 60_001;
        let err = opts.validate().unwrap_err();
        assert!(err.contains("settle_ms"), "err={err}");
    }

    #[test]
    fn page_ranges_syntax() {
        for (ranges, ok) in [
            ("", true),
            ("1", true),
            ("1-5", true),
            ("1-5, 8, 11-13", true),
            (" 3 - 7 , 12 ", true),
            ("1,", false),
            (",1", false),
            ("1--2", false),
            ("a-5", false),
            ("1-b", false),
            ("-3", false),
            ("3-", false),
            ("1.5", false),
            ("1;2", false),
        ] {
            assert_eq!(page_ranges_valid(ranges), ok, "ranges={ranges:?}");
        }
        // 非法页码范围会被 validate 整体拒绝
        let mut opts = html_opts();
        opts.page_ranges = "1,".into();
        let err = opts.validate().unwrap_err();
        assert!(err.contains("page ranges"), "err={err}");
    }

    #[test]
    fn validate_screenshot_options() {
        let mut s = ScreenshotOptions {
            source: PrintSource::Html("<html><body>x</body></html>".into()),
            ..Default::default()
        };
        assert_eq!(s.validate(), Ok(()));
        // jpeg 质量域
        s.jpeg = true;
        for (quality, ok) in [(1, true), (80, true), (100, true), (0, false), (101, false)] {
            s.quality = quality;
            let err = s.validate();
            assert_eq!(err.is_ok(), ok, "quality={quality} err={err:?}");
            if !ok {
                assert!(err.unwrap_err().contains("quality"));
            }
        }
        // png 忽略质量,0 也可
        s.jpeg = false;
        s.quality = 0;
        assert_eq!(s.validate(), Ok(()));
        // 空来源拒
        let s = ScreenshotOptions::default();
        assert!(s.validate().is_err());
    }

    #[test]
    fn print_options_default_is_a4() {
        let opts = PrintOptions::default();
        assert_eq!(opts.paper_width_mm, 210.0);
        assert_eq!(opts.paper_height_mm, 297.0);
        assert!(!opts.landscape);
        assert_eq!(opts.scale, 1.0);
        assert_eq!(opts.settle_ms, 300);
        assert!(!opts.display_header_footer);
    }
}
