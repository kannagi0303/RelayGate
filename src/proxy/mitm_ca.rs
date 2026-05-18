use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use sha1::{Digest, Sha1};
use tokio_rustls::TlsAcceptor;

use crate::path_mode::{app_path_mode, AppPathMode};

#[derive(Debug, Clone)]
pub(crate) struct MitmPreparation {
    pub(crate) ca: MitmCaMaterial,
    pub(crate) leaf: GeneratedLeafCert,
}

#[derive(Debug, Clone)]
pub(crate) struct MitmCaMaterial {
    pub(crate) cert_path: PathBuf,
    pub(crate) key_path: PathBuf,
    pub(crate) cert_pem: Vec<u8>,
    pub(crate) key_pem: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct GeneratedLeafCert {
    /// Cache key, usually `host:port`.
    pub(crate) cache_key: String,
    /// Target host name.
    pub(crate) host: String,
    /// Generated leaf certificate in PEM form.
    pub(crate) cert_pem: String,
    /// Generated leaf private key in PEM form.
    pub(crate) key_pem: String,
    /// Generated leaf certificate in DER form.
    pub(crate) cert_der: Vec<u8>,
    /// Generated leaf private key in DER form.
    pub(crate) key_der: Vec<u8>,
}

pub(crate) fn load_ca_material() -> Result<MitmCaMaterial> {
    let storage_dir = mitm_storage_dir()?;
    fs::create_dir_all(&storage_dir).with_context(|| {
        format!(
            "failed to create RelayGate MITM storage directory: {}",
            storage_dir.display()
        )
    })?;

    let cert_path = storage_dir.join("relaygate-ca-cert.pem");
    let key_path = storage_dir.join("relaygate-ca-key.pem");

    if !cert_path.exists() || !key_path.exists() {
        generate_and_store_ca(&cert_path, &key_path)?;
    }

    let cert_pem = fs::read(&cert_path)
        .with_context(|| format!("failed to read CA certificate: {}", cert_path.display()))?;
    let key_pem = fs::read(&key_path)
        .with_context(|| format!("failed to read CA private key: {}", key_path.display()))?;

    validate_pem_block(&cert_pem, &["BEGIN CERTIFICATE"])?;
    validate_pem_block(
        &key_pem,
        &[
            "BEGIN PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
        ],
    )?;

    Ok(MitmCaMaterial {
        cert_path,
        key_path,
        cert_pem,
        key_pem,
    })
}

pub(crate) fn generate_leaf_certificate(
    ca: &MitmCaMaterial,
    host: &str,
    _port: u16,
    cache_key: &str,
) -> Result<GeneratedLeafCert> {
    let ca_key_pem = std::str::from_utf8(&ca.key_pem).context("CA key is not valid UTF-8 PEM")?;
    let ca_cert_pem =
        std::str::from_utf8(&ca.cert_pem).context("CA certificate is not valid UTF-8 PEM")?;

    let ca_key = KeyPair::from_pem(ca_key_pem).context("failed to parse CA private key")?;
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key)
        .context("failed to parse CA certificate for rcgen issuer")?;

    let subject_alt_names = leaf_subject_alt_names(host);
    let mut params = CertificateParams::new(subject_alt_names)
        .context("failed to create leaf certificate params")?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, host.to_string());
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.use_authority_key_identifier_extension = true;

    let leaf_key = KeyPair::generate().context("failed to generate leaf key pair")?;
    let cert = params
        .signed_by(&leaf_key, &issuer)
        .context("failed to sign leaf certificate with CA")?;

    Ok(GeneratedLeafCert {
        cache_key: cache_key.to_string(),
        host: host.to_string(),
        cert_pem: cert.pem(),
        key_pem: leaf_key.serialize_pem(),
        cert_der: cert.der().to_vec(),
        key_der: leaf_key.serialize_der(),
    })
}

fn leaf_subject_alt_names(host: &str) -> Vec<String> {
    let normalized = host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if normalized.is_empty() {
        return vec![host.to_string()];
    }

    let mut names = vec![normalized.clone()];

    if let Some(registrable_domain) = conservative_registrable_domain(&normalized) {
        let wildcard = format!("*.{registrable_domain}");
        if wildcard != normalized && !names.iter().any(|name| name == &wildcard) {
            names.push(wildcard);
        }
    }

    names
}

fn conservative_registrable_domain(host: &str) -> Option<String> {
    if host.parse::<std::net::IpAddr>().is_ok() || host == "localhost" {
        return None;
    }

    let labels = host
        .split('.')
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();

    if labels.len() < 2 || labels.iter().any(|label| label.contains('*')) {
        return None;
    }

    let suffix_label_count = if labels.len() >= 3
        && labels.last().is_some_and(|label| label.len() == 2)
        && labels
            .get(labels.len().saturating_sub(2))
            .is_some_and(|label| label.len() <= 3)
    {
        3
    } else {
        2
    };

    if labels.len() < suffix_label_count {
        return None;
    }

    Some(labels[labels.len() - suffix_label_count..].join("."))
}

pub(crate) fn build_tls_acceptor(
    leaf: &GeneratedLeafCert,
    downstream_http2: bool,
) -> Result<TlsAcceptor> {
    let cert_chain: Vec<CertificateDer<'static>> =
        vec![CertificateDer::from(leaf.cert_der.clone())];
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf.key_der.clone()));

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("failed to build rustls ServerConfig for MITM leaf certificate")?;

    if downstream_http2 {
        // Advertise HTTP/2 only when explicitly enabled. HTTP/1.1 remains the
        // fallback ALPN for existing downstream MITM behavior.
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    } else {
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

pub(crate) fn normalize_authority(authority: &str) -> Result<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        bail!("CONNECT authority is empty");
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest
            .find(']')
            .context("invalid CONNECT authority: missing closing `]` for IPv6 host")?;
        let host = &rest[..closing];
        if host.is_empty() {
            bail!("CONNECT authority host is empty");
        }

        let suffix = &rest[closing + 1..];
        if suffix.is_empty() {
            return Ok((host.to_string(), 443));
        }
        if let Some(port_text) = suffix.strip_prefix(':') {
            let port = port_text.parse::<u16>().with_context(|| {
                format!("invalid CONNECT authority port for IPv6 host: {port_text}")
            })?;
            return Ok((host.to_string(), port));
        }

        bail!("invalid CONNECT authority after IPv6 host: {suffix}");
    }

    if let Some((host, port_text)) = authority.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port_text.parse::<u16>() {
                if !host.is_empty() {
                    return Ok((host.to_string(), port));
                }
            }
        }
    }

    Ok((authority.to_string(), 443))
}

pub fn mitm_storage_dir() -> Result<PathBuf> {
    // MITM CA material is RelayGate-owned persistent state.
    // Keep the storage path fixed under data/state/mitm and do not recreate the
    // deprecated pre-layout MITM directory when a fresh CA is generated.
    let storage_dir = match app_path_mode() {
        AppPathMode::Workspace => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("state")
            .join("mitm"),
        AppPathMode::Portable => executable_base_dir()
            .context("failed to resolve executable directory for MITM storage")?
            .join("data")
            .join("state")
            .join("mitm"),
    };

    Ok(storage_dir)
}

pub fn create_and_trust_local_ca() -> Result<()> {
    let ca_material = load_ca_material()?;

    #[cfg(windows)]
    ensure_ca_installed_in_windows_user_root(&ca_material)?;

    Ok(())
}

fn validate_pem_block(bytes: &[u8], accepted_headers: &[&str]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("PEM file is not valid UTF-8 text")?;

    if accepted_headers.iter().any(|header| text.contains(header)) {
        return Ok(());
    }

    bail!(
        "PEM file does not contain any accepted header: {}",
        accepted_headers.join(", ")
    )
}

fn executable_base_dir() -> Result<PathBuf> {
    let exe = env::current_exe().context("failed to resolve current executable path")?;
    let parent = exe
        .parent()
        .context("current executable path does not have a parent directory")?;
    Ok(parent.to_path_buf())
}

#[cfg(test)]
mod authority_tests {
    use super::normalize_authority;

    #[test]
    fn normalizes_bracketed_ipv6_authority_with_port() {
        let parsed = normalize_authority("[::1]:8443").unwrap();

        assert_eq!(parsed, ("::1".to_string(), 8443));
    }

    #[test]
    fn normalizes_bracketed_ipv6_authority_without_port() {
        let parsed = normalize_authority("[::1]").unwrap();

        assert_eq!(parsed, ("::1".to_string(), 443));
    }
}

fn generate_and_store_ca(cert_path: &Path, key_path: &Path) -> Result<()> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .context("failed to create CA certificate params")?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "RelayGate Local CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "RelayGate");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let ca_key = KeyPair::generate().context("failed to generate RelayGate CA key pair")?;
    let ca_cert = params
        .self_signed(&ca_key)
        .context("failed to self-sign RelayGate CA certificate")?;

    fs::write(cert_path, ca_cert.pem().as_bytes())
        .with_context(|| format!("failed to write CA certificate: {}", cert_path.display()))?;
    fs::write(key_path, ca_key.serialize_pem().as_bytes())
        .with_context(|| format!("failed to write CA private key: {}", key_path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn ensure_ca_installed_in_windows_user_root(ca: &MitmCaMaterial) -> Result<()> {
    let thumbprint = sha1_thumbprint_from_pem(&ca.cert_pem)?;

    if windows_root_contains_thumbprint(&thumbprint)? {
        tracing::debug!(
            thumbprint = thumbprint,
            "RelayGate CA already present in Windows CurrentUser Root store"
        );
        return Ok(());
    }

    install_ca_in_windows_user_root_native(ca, &thumbprint)?;
    tracing::debug!(
        thumbprint = thumbprint,
        "RelayGate CA installed into Windows CurrentUser Root store via native API"
    );

    if !windows_root_contains_thumbprint(&thumbprint)? {
        bail!("RelayGate CA installation reported success, but the certificate is still missing from Windows CurrentUser Root store");
    }

    Ok(())
}

#[cfg(windows)]
fn install_ca_in_windows_user_root_native(ca: &MitmCaMaterial, thumbprint: &str) -> Result<()> {
    let installed_thumbprint = crate::web::windows_cert_store::add_certificate_bytes_to_root(
        crate::web::windows_cert_store::RootStoreScope::CurrentUser,
        &ca.cert_pem,
    )?;

    if installed_thumbprint != thumbprint {
        bail!(
            "installed CA thumbprint mismatch: expected {thumbprint}, got {installed_thumbprint}"
        );
    }

    Ok(())
}

#[cfg(windows)]
fn windows_root_contains_thumbprint(thumbprint: &str) -> Result<bool> {
    let locations = crate::web::windows_cert_store::root_locations_for_thumbprint(thumbprint)?;
    Ok(!locations.is_empty())
}

#[cfg(windows)]
fn sha1_thumbprint_from_pem(cert_pem: &[u8]) -> Result<String> {
    let pem = std::str::from_utf8(cert_pem).context("certificate PEM is not valid UTF-8")?;
    let body = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let der = base64_simple_decode(&body)?;

    let digest = Sha1::digest(&der);
    Ok(digest.iter().map(|b| format!("{:02X}", b)).collect())
}

#[cfg(windows)]
fn base64_simple_decode(input: &str) -> Result<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = Vec::new();
    let mut chunk = Vec::new();

    for byte in input.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            chunk.push(64);
        } else if let Some(index) = TABLE.iter().position(|candidate| *candidate == byte) {
            chunk.push(index as u8);
        } else {
            bail!("invalid base64 character in certificate PEM");
        }

        if chunk.len() == 4 {
            decode_base64_chunk(&chunk, &mut output);
            chunk.clear();
        }
    }

    if !chunk.is_empty() {
        bail!("invalid base64 length in certificate PEM");
    }

    Ok(output)
}

#[cfg(windows)]
fn decode_base64_chunk(chunk: &[u8], output: &mut Vec<u8>) {
    let first = chunk[0];
    let second = chunk[1];
    let third = chunk[2];
    let fourth = chunk[3];

    output.push((first << 2) | (second >> 4));
    if third != 64 {
        output.push((second << 4) | (third >> 2));
    }
    if fourth != 64 {
        output.push((third << 6) | fourth);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_subject_alt_names_include_registrable_wildcard_for_apex_domain() {
        let names = leaf_subject_alt_names("tver.jp");
        assert_eq!(names[0], "tver.jp");
        assert!(names.contains(&"*.tver.jp".to_string()));
    }

    #[test]
    fn leaf_subject_alt_names_include_registrable_wildcard_for_subdomain() {
        let names = leaf_subject_alt_names("service-api.tver.jp");
        assert_eq!(names[0], "service-api.tver.jp");
        assert!(names.contains(&"*.tver.jp".to_string()));
    }

    #[test]
    fn leaf_subject_alt_names_handle_common_second_level_tlds_conservatively() {
        let names = leaf_subject_alt_names("www.example.com.tw");
        assert_eq!(names[0], "www.example.com.tw");
        assert!(names.contains(&"*.example.com.tw".to_string()));
        assert!(!names.contains(&"*.com.tw".to_string()));
    }

    #[test]
    fn leaf_subject_alt_names_do_not_add_wildcard_for_ip_addresses() {
        assert_eq!(leaf_subject_alt_names("127.0.0.1"), vec!["127.0.0.1"]);
        assert_eq!(leaf_subject_alt_names("::1"), vec!["::1"]);
    }
}
