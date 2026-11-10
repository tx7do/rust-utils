# geoip 测试数据

仅供本 crate 的单元测试使用(`src/geoip/`),**不随库内嵌、不进入 crates.io
发布包**(见 `Cargo.toml` 的 `package.exclude`)。与上游 `tx7do/go-utils`
各 geoip 子包 `go:embed` 的是同一批文件(Go 侧内嵌开箱即用;Rust 侧按既有
分工由调用方自行加载,测试期从 `CARGO_MANIFEST_DIR` 运行时读取)。

| 文件 | 来源 | 许可/署名 |
| --- | --- | --- |
| `GeoLite2-City.mmdb` | MaxMind GeoLite2(与 go-utils/geoip/geolite/assets 同源) | CC BY-SA 4.0,须署名:<https://dev.maxmind.com/geoip/geolite2-free-geolocation-data>;This product includes GeoLite2 data created by MaxMind, available from <https://www.maxmind.com> |
| `ip2region_v4.xdb` | [ip2region](https://github.com/lionsoul2014/ip2region)(与 go-utils/geoip/ip2region/assets 同源) | Apache-2.0(Lion) |
| `ip2region_v6.xdb` | 同上 | 同上 |
| `qqwry.dat` | [CZ88 纯真网络](https://update.cz88.net/geo-public)(与 go-utils/geoip/qqwry/assets 同源) | 纯真社区免费版,随上游 go-utils 一同分发 |

更新数据时替换对应文件即可;测试断言钉死的是这些文件的查询结果,换库后需复核
(参考:MaxMind 更新省名后 go-utils 侧"四川省"旧断言已失效)。
