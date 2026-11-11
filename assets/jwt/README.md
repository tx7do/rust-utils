# jwt 测试密钥对

仅供 src/jwt.rs 的单测使用(openssl 一次性生成,私钥无任何真实价值)。
cargo publish 时本目录被 Cargo.toml 的 exclude 排除,包内缺失时相关用例自动跳过 —— 与 assets/geoip 同款约定。
