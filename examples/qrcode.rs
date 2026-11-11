//! QR 码:编码为矩阵,输出 SVG / 终端块字符(与 otp 扫码绑定登录配套)。
//!
//! 运行:`cargo run --example qrcode`
//! PNG 落地:`cargo run --features qrcode-png --example qrcode -- png`

use rust_utils::qrcode::{self, EcLevel};

fn main() {
    let text = "https://example.com/join?code=RUST42";
    let qr = qrcode::encode(text, EcLevel::M).unwrap();
    println!(
        "version: {}({}×{}),dark modules: {}\n",
        qr.version(),
        qr.size(),
        qr.size(),
        qr.dark_count()
    );

    // 终端直显(两行合一行的块字符)
    println!("{}", qr.to_unicode(2));

    // SVG(网页嵌入;viewBox 以模块为单位)
    let svg = qr.to_svg(4);
    assert!(svg.starts_with("<svg "));
    println!("svg bytes: {}", svg.len());

    // 位图落地(feature qrcode-png)
    if std::env::args().any(|a| a == "png") {
        let png = qrcode::encode_png(text, EcLevel::M, 8, 4).unwrap();
        std::fs::write("qrcode-demo.png", &png).unwrap();
        println!("written: qrcode-demo.png({} bytes)", png.len());
    }

    // 编码确定性 + 定位角
    assert_eq!(qr, qrcode::encode(text, EcLevel::M).unwrap());
    assert!(qr.module(0, 0) && qr.module(qr.size() - 1, 0) && qr.module(0, qr.size() - 1));
    println!("OK");
}
