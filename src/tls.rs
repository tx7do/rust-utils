//! TLS 证书加载,feature `tls`。
//!
//! 从 PEM 文件或字节序列组装 rustls 的
//! [`ServerConfig`]/[`ClientConfig`]:
//!
//! - 服务端(`load_server_tls_config_*`):证书 + 私钥必填;
//!   提供 CA 时为双向认证(`WebPkiClientVerifier`),否则单向
//!   (`with_no_client_auth`)。
//! - 客户端(`load_client_tls_config_*`):私钥与证书**任一为空**
//!   即返回零配置形态(信任系统根、无客户端证书);两者齐备时
//!   加载客户端证书,根信任取 CA(缺省时回落系统根)。
//!
//! 行为要点:
//!
//! - `insecure_skip_verify` 参数保留但为空操作——本库不提供
//!   关闭证书校验的途径;
//! - PEM 解析基于 `rustls-pemfile`,只认 `CERTIFICATE` 与私钥块,
//!   逐块扫描。
//!
//! ````ignore
//! let cfg = rust_utils::tls::load_server_tls_config_file(
//!     "server.key", "server.crt", "", false).unwrap();
//! ````

use std::fs;
use std::io::Cursor;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// 从 PEM 文件路径创建服务端 TLS 配置。`ca_file` 为空表示单向认证。
pub fn load_server_tls_config_file(
    key_file: &str,
    cert_file: &str,
    ca_file: &str,
    insecure_skip_verify: bool,
) -> Result<ServerConfig, String> {
    let (key_pem, cert_pem, ca_pem) = read_keypair_and_ca(key_file, cert_file, ca_file)?;
    load_server_tls_config_pem(
        &key_pem,
        &cert_pem,
        if ca_pem.is_empty() {
            None
        } else {
            Some(&ca_pem[..])
        },
        insecure_skip_verify,
    )
}

/// 从 PEM 字节创建服务端 TLS 配置。`ca_pem` 为 `None` 表示单向认证。
pub fn load_server_tls_config_pem(
    key_pem: &[u8],
    cert_pem: &[u8],
    ca_pem: Option<&[u8]>,
    _insecure_skip_verify: bool,
) -> Result<ServerConfig, String> {
    if key_pem.is_empty() || cert_pem.is_empty() {
        return Err(format!(
            "KeyPEMBlock and CertPEMBlock must both be present[key: {}, cert: {}]",
            key_pem.len(),
            cert_pem.len()
        ));
    }
    let chain = certs_from_pem(cert_pem)?;
    let key = key_from_pem(key_pem)?;
    let builder = rustls::ServerConfig::builder();
    match ca_pem {
        Some(ca) => {
            let verifier = WebPkiClientVerifier::builder(roots_from_pem(ca)?.into())
                .build()
                .map_err(|e| format!("tls client verifier build failed: {e}"))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(chain, key)
                .map_err(|e| format!("tls server config build failed: {e}"))
        }
        None => builder
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| format!("tls server config build failed: {e}")),
    }
}

/// 从 PEM 文件路径创建客户端 TLS 配置。私钥或证书任一为空时返回
/// 零配置形态(信任系统根、无客户端证书,`ca_file` 被忽略)。
pub fn load_client_tls_config_file(
    key_file: &str,
    cert_file: &str,
    ca_file: &str,
) -> Result<ClientConfig, String> {
    let (key_pem, cert_pem, ca_pem) = read_keypair_and_ca(key_file, cert_file, ca_file)?;
    load_client_tls_config_pem(
        &key_pem,
        &cert_pem,
        if ca_pem.is_empty() {
            None
        } else {
            Some(&ca_pem[..])
        },
    )
}

/// 从 PEM 字节创建客户端 TLS 配置。私钥或证书任一为空时返回零配置形态。
pub fn load_client_tls_config_pem(
    key_pem: &[u8],
    cert_pem: &[u8],
    ca_pem: Option<&[u8]>,
) -> Result<ClientConfig, String> {
    if key_pem.is_empty() || cert_pem.is_empty() {
        // 零配置形态:系统根、无客户端证书
        let roots = system_roots()?;
        return Ok(ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth());
    }
    let chain = certs_from_pem(cert_pem)?;
    let key = key_from_pem(key_pem)?;
    let roots = match ca_pem {
        Some(ca) if !ca.is_empty() => roots_from_pem(ca)?,
        _ => system_roots()?,
    };
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|e| format!("tls client config build failed: {e}"))
}

/// 三段 PEM 字节数据(私钥、证书、CA;路径为空时对应段为空)。
type KeyPairAndCa = (Vec<u8>, Vec<u8>, Vec<u8>);

fn read_keypair_and_ca(
    key_file: &str,
    cert_file: &str,
    ca_file: &str,
) -> Result<KeyPairAndCa, String> {
    let key = if key_file.is_empty() {
        Vec::new()
    } else {
        fs::read(key_file).map_err(|e| format!("read {key_file}: {e}"))?
    };
    let cert = if cert_file.is_empty() {
        Vec::new()
    } else {
        fs::read(cert_file).map_err(|e| format!("read {cert_file}: {e}"))?
    };
    let ca = if ca_file.is_empty() {
        Vec::new()
    } else {
        fs::read(ca_file).map_err(|e| format!("read {ca_file}: {e}"))?
    };
    Ok((key, cert, ca))
}

fn certs_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut cursor = Cursor::new(pem);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("tls cert pem parse failed: {e}"))?;
    if certs.is_empty() {
        return Err("tls: no certificate found in pem".to_string());
    }
    Ok(certs)
}

fn key_from_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    let mut cursor = Cursor::new(pem);
    rustls_pemfile::private_key(&mut cursor)
        .map_err(|e| format!("tls key pem parse failed: {e}"))?
        .ok_or_else(|| "tls: no private key found in pem".to_string())
}

fn roots_from_pem(pem: &[u8]) -> Result<RootCertStore, String> {
    let certs = certs_from_pem(pem)?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| format!("tls add root cert failed: {e}"))?;
    }
    Ok(roots)
}

fn system_roots() -> Result<RootCertStore, String> {
    let res = rustls_native_certs::load_native_certs();
    if !res.errors.is_empty() {
        return Err(format!(
            "tls load native certs failed: {} errors",
            res.errors.len()
        ));
    }
    let mut roots = RootCertStore::empty();
    for cert in res.certs {
        roots
            .add(cert)
            .map_err(|e| format!("tls add root cert failed: {e}"))?;
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        format!("{}/assets/tls/{}", env!("CARGO_MANIFEST_DIR"), name)
    }

    #[test]
    fn server_one_way_from_files() {
        // cert/key 必填、无 CA → 单向认证
        let cfg = load_server_tls_config_file(
            &fixture("test_server.key"),
            &fixture("test_server.cert"),
            "",
            false,
        );
        assert!(cfg.is_ok());
    }

    #[test]
    fn server_mutual_from_pem_bytes() {
        // 提供 CA → RequireAndVerifyClientCert(双向)
        let key = fs::read(fixture("test_server.key")).unwrap();
        let cert = fs::read(fixture("test_server.cert")).unwrap();
        let ca = fs::read(fixture("test_ca.cert")).unwrap();
        assert!(load_server_tls_config_pem(&key, &cert, Some(&ca), false).is_ok());
    }

    #[test]
    fn server_missing_key_or_cert() {
        // KeyPEMBlock 和 CertPEMBlock 必须同时存在
        let err = load_server_tls_config_pem(&[], &[], None, false).unwrap_err();
        assert_eq!(
            err,
            "KeyPEMBlock and CertPEMBlock must both be present[key: 0, cert: 0]"
        );
    }

    #[test]
    fn server_key_cert_mismatch() {
        // 服务端证书配客户端私钥 → 组装失败
        let key = fs::read(fixture("test_client.key")).unwrap();
        let cert = fs::read(fixture("test_server.cert")).unwrap();
        assert!(load_server_tls_config_pem(&key, &cert, None, false).is_err());
    }

    #[test]
    fn server_garbage_pem() {
        assert!(load_server_tls_config_pem(
            b"-----BEGIN GARBAGE-----\nAAAA\n-----END GARBAGE-----\n".as_slice(),
            b"not a pem".as_slice(),
            None,
            false
        )
        .is_err());
        // 证书里有 PEM 但无私钥块
        let cert = fs::read(fixture("test_server.cert")).unwrap();
        assert!(load_server_tls_config_pem(&cert, &cert, None, false).is_err());
    }

    #[test]
    fn client_with_ca_and_client_cert() {
        // 客户端证书 + CA 根(双向认证的客户端侧)
        let cfg = load_client_tls_config_file(
            &fixture("test_client.key"),
            &fixture("test_client.cert"),
            &fixture("test_ca.cert"),
        );
        assert!(cfg.is_ok());
    }

    #[test]
    fn client_empty_key_or_cert_returns_zero_config() {
        // key/cert 任一为空 → 零配置形态(系统根,caFile 被忽略)
        assert!(load_client_tls_config_file("", "", &fixture("test_ca.cert")).is_ok());
        let cfg = load_client_tls_config_pem(&[], &[], None);
        assert!(cfg.is_ok());
    }

    #[test]
    fn client_key_cert_mismatch() {
        let key = fs::read(fixture("test_client.key")).unwrap();
        let cert = fs::read(fixture("test_server.cert")).unwrap();
        assert!(load_client_tls_config_pem(&key, &cert, None).is_err());
    }

    #[test]
    fn client_missing_files() {
        // 文件不存在 → 错误传播
        assert!(load_client_tls_config_file("no-such.key", "no-such.crt", "").is_err());
        assert!(load_server_tls_config_file("no-such.key", "no-such.crt", "", false).is_err());
    }
}
