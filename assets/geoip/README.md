# geoip 测试数据

`GeoLite2-City.mmdb` 仅供本 crate 的单元测试使用(`src/geoip/geolite.rs`),
**不随库内嵌、不进入 crates.io 发布包**(见 `Cargo.toml` 的 `package.exclude`)。

来源与上游 `tx7do/go-utils/geoip/geolite/assets` 内嵌的是同一份文件
(`go:embed` 供 Go 侧开箱即用;Rust 侧按既有分工由调用方 `from_bytes` 加载,
测试期从 `CARGO_MANIFEST_DIR` 运行时读取)。

许可:GeoLite2 按 CC BY-SA 4.0 分发,须保留署名:

> This product includes GeoLite2 data created by MaxMind, available from
> <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data>.
>
> <https://www.maxmind.com/en/geolite2/eula-and-attribution>

更新数据时替换本文件即可,测试断言钉死的是该文件的查询结果,换库后需复核。
