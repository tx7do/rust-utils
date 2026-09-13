# TLS 测试证书

本目录下的六个文件是为 `tls` 模块单元测试生成的一次性
EC P-256 证书组(`CN=Test CA` / `CN=localhost` / `CN=Test Client`,
由测试 CA 签发,有效期至 2126 年),与任何真实身份无关,
私钥全部公开提交,可直接复用或重新生成:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out test_ca.key
openssl req -new -x509 -key test_ca.key -out test_ca.cert -days 36500 \
    -subj "//CN=Test CA" -addext "basicConstraints=critical,CA:TRUE"
# server/client 由该 CA 签发(server 带 SAN localhost/127.0.0.1)
```
