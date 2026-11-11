//! QR 码生成(feature `qrcode`,基于 `qrcode` crate;PNG 落地需再开
//! `qrcode-png` 复用 `image`)。
//!
//! 与验证码/otpauth 是一组搭档:扫码登录、两步验证密钥展示、支付码。
//! [`encode`] 产出模块矩阵([`QrMatrix`]),由调用方决定最终载体——
//! 终端演示用 [`QrMatrix::to_unicode`],网页嵌入用 [`QrMatrix::to_svg`],
//! 位图用 [`encode_png`](feature `qrcode-png`)。
//!
//! 静区(quiet zone)由输出函数的 `quiet_modules` 参数控制(规范建议 4)。
//!
//! ```
//! use rust_utils::qrcode::{self, EcLevel};
//!
//! let qr = qrcode::encode("https://example.com/join/42", EcLevel::M).unwrap();
//! assert!(qr.version() >= 1);
//! assert_eq!(qr.size(), qr.version() as usize * 4 + 17);
//! // 三个定位角左上/右上/左下的外环必为暗模块
//! assert!(qr.module(0, 0) && qr.module(qr.size() - 1, 0) && qr.module(0, qr.size() - 1));
//! ```

use qrcode::types::{Color, EcLevel as QrEcLevel, Version};

/// 纠错级别(规范四档;级别越高可修复的损伤越多,容量越小)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EcLevel {
    /// 低(7% 可修复),容量最大。
    L,
    /// 中(15%),缺省。
    #[default]
    M,
    /// 四分位(25%)。
    Q,
    /// 高(30%),容量最小。
    H,
}

impl EcLevel {
    fn to_qr(self) -> QrEcLevel {
        match self {
            EcLevel::L => QrEcLevel::L,
            EcLevel::M => QrEcLevel::M,
            EcLevel::Q => QrEcLevel::Q,
            EcLevel::H => QrEcLevel::H,
        }
    }
}

/// QR 模块矩阵:行主序,`true` 为暗模块。坐标约定 `module(x, y)`
/// 中 `x` 为列、`y` 为行,原点在左上角。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    version: i16,
    size: usize,
    modules: Vec<bool>,
}

/// 把文本编码为 QR 矩阵。
///
/// `text` 过长超出对应纠错级别的版本 40 容量时报错。
pub fn encode(text: &str, ec: EcLevel) -> Result<QrMatrix, String> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), ec.to_qr())
        .map_err(|e| format!("qrcode encode failed: {e}"))?;
    let size = code.width();
    let version = match code.version() {
        Version::Normal(v) => v,
        other => return Err(format!("qrcode unexpected version: {other:?}")),
    };
    let modules = code
        .to_colors()
        .into_iter()
        .map(|c| c == Color::Dark)
        .collect();
    Ok(QrMatrix {
        version,
        size,
        modules,
    })
}

impl QrMatrix {
    /// QR 版本号(1~40)。
    pub fn version(&self) -> i16 {
        self.version
    }

    /// 边长(模块数,= version × 4 + 17)。
    pub fn size(&self) -> usize {
        self.size
    }

    /// 取模块:`x` 列 `y` 行,`true` 为暗。
    pub fn module(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x]
    }

    /// 暗模块总数(测试与统计用)。
    pub fn dark_count(&self) -> usize {
        self.modules.iter().filter(|m| **m).count()
    }

    /// 输出 SVG(每暗模块一个 `M` 路径命令;`quiet_modules` 为四周静区)。
    ///
    /// viewBox 以模块为单位、每模块边长 1,由调用方按需缩放。
    pub fn to_svg(&self, quiet_modules: usize) -> String {
        let total = self.size + quiet_modules * 2;
        let mut path = String::new();
        for y in 0..self.size {
            for x in 0..self.size {
                if self.module(x, y) {
                    path.push_str(&format!(
                        "M{} {}h1v1h-1z",
                        x + quiet_modules,
                        y + quiet_modules
                    ));
                }
            }
        }
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" shape-rendering="crispEdges"><rect width="{total}" height="{total}" fill="#fff"/><path d="{path}" fill="#000"/></svg>"##
        )
    }

    /// 输出终端块字符(两行合成一行:`▀`/`▄`/`█`/空格;`▀`=上暗,
    /// `▄`=下暗,`█`=全暗)。奇数行尾巴按"下一行为亮"补齐。
    pub fn to_unicode(&self, quiet_modules: usize) -> String {
        let total = self.size + quiet_modules * 2;
        let at = |x: i64, y: i64| -> bool {
            let (qx, qy) = (x - quiet_modules as i64, y - quiet_modules as i64);
            qx >= 0
                && qy >= 0
                && (qx as usize) < self.size
                && (qy as usize) < self.size
                && self.module(qx as usize, qy as usize)
        };
        let mut out = String::new();
        let mut y: i64 = 0;
        while y < total as i64 {
            for x in 0..total as i64 {
                let top = at(x, y);
                let bottom = at(x, y + 1);
                out.push(match (top, bottom) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                });
            }
            out.push('\n');
            y += 2;
        }
        out
    }
}

/// 编码为 PNG 位图(`scale` 像素/模块,四周 `quiet_modules` 静区)。
#[cfg(feature = "qrcode-png")]
pub fn encode_png(
    text: &str,
    ec: EcLevel,
    scale: u32,
    quiet_modules: u32,
) -> Result<Vec<u8>, String> {
    if scale == 0 || scale > 64 {
        return Err("qrcode png: scale must be within 1..=64".into());
    }
    if quiet_modules > 32 {
        return Err("qrcode png: quiet_modules too large (max 32)".into());
    }
    let qr = encode(text, ec)?;
    let total = (qr.size as u32 + quiet_modules * 2) * scale;
    let mut img = image::GrayImage::new(total, total);
    for py in 0..total {
        for px in 0..total {
            let mx = px / scale;
            let my = py / scale;
            let (qx, qy) = (
                mx as i64 - quiet_modules as i64,
                my as i64 - quiet_modules as i64,
            );
            let dark = qx >= 0
                && qy >= 0
                && (qx as usize) < qr.size
                && (qy as usize) < qr.size
                && qr.module(qx as usize, qy as usize);
            img.put_pixel(px, py, image::Luma([if dark { 0 } else { 255 }]));
        }
    }
    let mut buf = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
        .map_err(|e| format!("qrcode png encode failed: {e}"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_versions_and_sizes() {
        // 小文本低纠错 → 版本 1(21×21);纠错越高同文本版本越大
        let v1 = encode("hello", EcLevel::L).unwrap();
        assert_eq!(v1.version(), 1);
        assert_eq!(v1.size(), 21);
        // "hello" 各级纠错都装进版本 1
        for ec in [EcLevel::L, EcLevel::M, EcLevel::Q, EcLevel::H] {
            assert_eq!(encode("hello", ec).unwrap().version(), 1, "ec={ec:?}");
        }
        // 36 字节文本:版本随纠错级别抬升(H 容量最小)
        let long = "hello world hello world hello world!";
        let low = encode(long, EcLevel::L).unwrap();
        let high = encode(long, EcLevel::H).unwrap();
        assert!(
            high.version() > low.version(),
            "H({}) 应大于 L({})",
            high.version(),
            low.version()
        );

        // 长文本推高版本;超容量报错
        let big = encode("x".repeat(500).as_str(), EcLevel::L).unwrap();
        assert!(big.version() > 1);
        assert!(encode("x".repeat(3000).as_str(), EcLevel::H).is_err());
        // 空串与 UTF-8 多字节同样可编码
        assert!(encode("", EcLevel::M).is_ok());
        assert!(encode("二维码·测试", EcLevel::M).is_ok());
    }

    #[test]
    fn encode_is_deterministic() {
        let a = encode("deterministic", EcLevel::Q).unwrap();
        let b = encode("deterministic", EcLevel::Q).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn finder_patterns_at_three_corners() {
        // 左上/右上/左下三个 7×7 定位环:外环全暗,环外一圈(分隔符)全亮
        let qr = encode("finder", EcLevel::M).unwrap();
        let s = qr.size();
        let corners = [(0usize, 0usize), (s - 7, 0), (0, s - 7)];
        for (ox, oy) in corners {
            for i in 0..7 {
                // 外环四边
                assert!(qr.module(ox + i, oy), "top edge ({ox}+{i},{oy})");
                assert!(qr.module(ox + i, oy + 6), "bottom edge");
                assert!(qr.module(ox, oy + i), "left edge");
                assert!(qr.module(ox + 6, oy + i), "right edge");
                // 中心行/列:3×3 全暗(i=2..=4),1 与 5 是亮环
                if (2..=4).contains(&i) {
                    assert!(qr.module(ox + i, oy + 3), "center row ({ox}+{i})");
                    assert!(qr.module(ox + 3, oy + i), "center col ({oy}+{i})");
                } else if (1..=5).contains(&i) {
                    assert!(!qr.module(ox + i, oy + 3), "light ring row ({ox}+{i})");
                    assert!(!qr.module(ox + 3, oy + i), "light ring col ({oy}+{i})");
                }
                // 紧贴外环的分隔符必亮(左上角的 (7,y)/(x,7) 等)
                if ox == 0 && oy == 0 {
                    assert!(!qr.module(7, i), "separator col x=7,y={i}");
                    assert!(!qr.module(i, 7), "separator row x={i},y=7");
                }
            }
        }
    }

    #[test]
    fn timing_patterns_alternate() {
        // 行 6 / 列 6 的时序图案:在两定位角之间交替暗亮
        let qr = encode("timing", EcLevel::M).unwrap();
        let s = qr.size();
        for i in 8..s - 8 {
            assert_eq!(qr.module(i, 6), i % 2 == 0, "row6 x={i}");
            assert_eq!(qr.module(6, i), i % 2 == 0, "col6 y={i}");
        }
    }

    #[test]
    fn svg_shape_and_module_count() {
        let qr = encode("svg-out", EcLevel::M).unwrap();
        let dark = qr.dark_count();
        let quiet = 4;
        let svg = qr.to_svg(quiet);
        assert!(svg.starts_with("<svg "));
        assert!(svg.contains("viewBox=\"0 0 29 29\"")); // 21 + 2*4
                                                        // 每个暗模块一个 M 命令
        assert_eq!(svg.matches('M').count(), dark);
        // 静区为亮:模块 (0,0) 对应 svg 里 M4 4 前不应有更靠边的暗块命令
        assert!(!svg.contains("M0 0") && !svg.contains("M3 3"));
    }

    #[test]
    fn unicode_layout_dimensions() {
        let qr = encode("uni", EcLevel::M).unwrap();
        let quiet = 2usize;
        let out = qr.to_unicode(quiet);
        let total = qr.size() + quiet * 2; // 21 + 4 = 25
        let lines: Vec<&str> = out.lines().collect();
        // 奇数总行 → 向上取整的行数(最后一行按亮底补齐)
        assert_eq!(lines.len(), total.div_ceil(2));
        for line in &lines {
            assert_eq!(line.chars().count(), total, "line width {line:?}");
        }
        // 只有四种块字符
        assert!(out
            .chars()
            .all(|c| c == '█' || c == '▀' || c == '▄' || c == ' ' || c == '\n'));
        // 精确守恒:█ 覆盖 2 个暗模块,▀/▄ 各覆盖 1 个,空格 0 个
        let solid = out.chars().filter(|c| *c == '█').count();
        let top_half = out.chars().filter(|c| *c == '▀').count();
        let bottom_half = out.chars().filter(|c| *c == '▄').count();
        assert_eq!(
            qr.dark_count(),
            2 * solid + top_half + bottom_half,
            "暗模块数应与块字符覆盖数守恒"
        );
    }

    // PNG 落地 + rqrr 扫码回读:生成→解码→原文,整链路校验。
    #[cfg(feature = "qrcode-png")]
    #[test]
    fn png_roundtrip_decodable_by_rqrr() {
        let text = "https://example.com/verify?token=abc123";
        let png = encode_png(text, EcLevel::M, 8, 4).unwrap();
        assert!(png.starts_with(&[0x89, b'P', b'N', b'G']));

        let img = image::load_from_memory(&png).unwrap().into_luma8();
        let (w, h) = (img.width() as usize, img.height() as usize);
        let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| {
            img.get_pixel(x as u32, y as u32)[0]
        });
        let grids = prepared.detect_grids();
        assert!(!grids.is_empty(), "应识别出至少一个 QR");
        let (_, content) = grids[0].decode().map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(content, text);
    }

    #[cfg(feature = "qrcode-png")]
    #[test]
    fn png_rejects_invalid_params() {
        assert!(encode_png("x", EcLevel::M, 0, 4).is_err());
        assert!(encode_png("x", EcLevel::M, 65, 4).is_err());
        assert!(encode_png("x", EcLevel::M, 4, 33).is_err());
    }
}
