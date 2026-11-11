//! SSRF 防护与可信代理链下的客户端 IP。
//!
//! 运行:`cargo run --features netutil --example netutil`

use rust_utils::netutil;

fn main() {
    // 1. URL 语法校验:仅 http/https、拒绝 userinfo 混淆、拒绝缺 host
    for url in [
        "https://example.com/api",     // 合法
        "http://127.0.0.1:8080/admin", // 字面量 IP(语法合法,黑名单另行判定)
        "http://admin@example.com/",   // userinfo 混淆
        "file:///etc/passwd",          // 非法协议
    ] {
        println!(
            "{url:<38} → {:?}",
            netutil::validate_url(url)
                .map(|_| "语法通过")
                .map_err(|e| e.to_string())
        );
    }
    assert!(netutil::validate_url("https://example.com/api").is_ok());
    assert!(netutil::validate_url("http://admin@example.com/").is_err());
    assert!(netutil::validate_url("file:///etc/passwd").is_err());

    // 2. 黑名单网段判定(回环/内网/链路本地等全局信任黑名单):
    //    出站前的完整 SSRF 防线 = validate_url(语法) + is_blocked_ip(目标)
    assert!(netutil::is_blocked_ip("127.0.0.1"));
    assert!(
        netutil::is_blocked_ip("169.254.169.254"),
        "云元数据端点在黑名单"
    );
    assert!(!netutil::is_blocked_ip("8.8.8.8"));
    println!("blocked checks: loopback/metadata denied, public allowed");

    // 3. 可信代理链的客户端 IP:配置信任网段后,X-Forwarded-For 从右向左
    //    取第一个不可信地址(伪造的头部不可信)
    netutil::set_trusted_proxies(&["10.0.0.0/8"]);
    let req = netutil::RequestInfo::new("10.0.0.5:443")
        .with_header("X-Forwarded-For", "1.2.3.4, 10.0.0.9");
    let ip = netutil::client_ip_from_request(Some(&req));
    println!("client ip: {ip}(链: 1.2.3.4 ← 10.0.0.9 ← 10.0.0.5)");
    assert_eq!(ip, "1.2.3.4");

    println!("OK");
}
