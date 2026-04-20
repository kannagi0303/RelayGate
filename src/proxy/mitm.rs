use std::{
    collections::HashMap,
    env,
    error::Error as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, CONTENT_TYPE};
use reqwest::Client;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::{
    adblock::{self, SharedAdblockState},
    config::RelayGateConfig,
    diagnostics,
    path_mode::{app_path_mode, AppPathMode},
    proxy::{
        rules::{RuleEffect, RuleEngine, RuleRequestContext, RuleResponseContext},
        upstream::UpstreamRegistry,
    },
    rewrite::SharedRewriteRegistry,
    traffic::{self, SharedTrafficState, TrafficAction, TrafficResponseDecision},
};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
const SLOW_MITM_TOTAL_MS: u128 = 1000;
const SLOW_MITM_FETCH_HEADERS_MS: u128 = 400;
const SLOW_MITM_BUFFER_BODY_MS: u128 = 500;
const SLOW_MITM_REWRITE_STAGE_MS: u128 = 120;

/// HTTPS MITM state and logic.
///
/// This module keeps MITM logic separate from the normal CONNECT tunnel path.
/// It covers:
/// - CA certificate loading
/// - dynamic leaf certificate generation per target host
/// - client-side TLS accept
/// - upstream TLS connect
/// - request and response rewriting
#[derive(Clone)]
pub struct MitmEngine {
    config: Arc<RelayGateConfig>,
    rules: RuleEngine,
    upstreams: UpstreamRegistry,
    rewrite_registry: SharedRewriteRegistry,
    adblock_state: SharedAdblockState,
    traffic_state: SharedTrafficState,
    cert_cache: Arc<Mutex<HashMap<String, GeneratedLeafCert>>>,
    http_client_cache: Arc<Mutex<HashMap<String, Client>>>,
}

#[derive(Debug, Clone, Default)]
struct RewritePerfStats {
    patch_ms: u128,
    render_ms: u128,
    adblock_injection_ms: u128,
}

impl MitmEngine {
    pub fn new(
        config: Arc<RelayGateConfig>,
        rules: RuleEngine,
        upstreams: UpstreamRegistry,
        rewrite_registry: SharedRewriteRegistry,
        adblock_state: SharedAdblockState,
        traffic_state: SharedTrafficState,
    ) -> Self {
        Self {
            config,
            rules,
            upstreams,
            rewrite_registry,
            adblock_state,
            traffic_state,
            cert_cache: Arc::new(Mutex::new(HashMap::new())),
            http_client_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check whether MITM is enabled.
    pub fn enabled(&self) -> bool {
        adblock::is_enabled(&self.adblock_state)
            || self
                .rewrite_registry
                .read()
                .map(|registry| registry.rule_count() > 0)
                .unwrap_or(false)
    }

    pub fn should_intercept_host(&self, authority_or_host: &str) -> bool {
        if adblock::is_enabled(&self.adblock_state) {
            return true;
        }

        self.rewrite_registry
            .read()
            .map(|registry| registry.should_mitm_host(authority_or_host))
            .unwrap_or(false)
    }

    /// Entry point for CONNECT requests that go into the MITM handler.
    ///
    /// This keeps TLS, certificates, and HTTP parsing out of `proxy/server.rs`.
    pub async fn handle_connect(
        &self,
        client_stream: &mut TcpStream,
        authority: &str,
    ) -> Result<()> {
        let total_started_at = std::time::Instant::now();
        let preparation = self.prepare_interception(authority)?;
        debug!(
            authority = authority,
            host = preparation.leaf.host,
            ca_cert = %preparation.ca.cert_path.display(),
            ca_key = %preparation.ca.key_path.display(),
            leaf_cache_key = preparation.leaf.cache_key,
            leaf_cert_len = preparation.leaf.cert_pem.len(),
            leaf_key_len = preparation.leaf.key_pem.len(),
            "CONNECT routed to MITM engine"
        );

        let tls_acceptor = build_tls_acceptor(&preparation.leaf)?;
        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
            .await?;

        let mut tls_stream = tls_acceptor
            .accept(client_stream)
            .await
            .context("failed to accept TLS from client during MITM handshake")?;

        let request_bytes = read_http_request(&mut tls_stream).await?;
        if request_bytes.is_empty() {
            bail!("client closed TLS stream before sending HTTP request");
        }

        let request = parse_http_request(&request_bytes)?;
        let target_url = build_https_target_url(authority, &request)?;
        debug!(authority = authority, url = %target_url, "MITM decrypted HTTPS request");

        let request_context = RuleRequestContext {
            host: Some(preparation.leaf.host.clone()),
            url: target_url.clone(),
            method: request.method.clone(),
            headers: request.headers.clone(),
        };

        let request_decision = self.rules.evaluate_request(&request_context);
        if request_decision
            .effects
            .iter()
            .any(|effect| matches!(effect, RuleEffect::Block))
        {
            let response = simple_http_response_bytes(
                403,
                "Forbidden",
                "Blocked by RelayGate MITM request rule.",
            );
            tls_stream.write_all(&response).await?;
            tls_stream.shutdown().await?;
            return Ok(());
        }

        let request_type = adblock::classify_request_type(&request.method, &request.headers);
        let source_url = adblock::source_url_for_request(&target_url, &request.headers);
        let fetch_site = adblock::fetch_site_for_request(&request.headers);
        let adblock_match = adblock::check_url(
            &self.adblock_state,
            &target_url,
            &source_url,
            request_type,
            fetch_site.as_deref(),
        )?;
        if let Some(redirect) = adblock_match.redirect.as_ref() {
            let response = simple_http_response_bytes_with_content_type(
                200,
                "OK",
                &redirect.content_type,
                &redirect.body,
            );
            tls_stream.write_all(&response).await?;
            tls_stream.shutdown().await?;
            return Ok(());
        }
        if adblock_match.matched {
            if should_abort_adblock_request(&adblock_match.request_type) {
                tls_stream.shutdown().await?;
            } else {
                let response =
                    simple_http_response_bytes(403, "Forbidden", "Blocked by RelayGate adblock.");
                tls_stream.write_all(&response).await?;
                tls_stream.shutdown().await?;
            }
            return Ok(());
        }

        let upstream_id = request_decision
            .effects
            .iter()
            .find_map(|effect| match effect {
                RuleEffect::UseUpstream { upstream_id } => Some(upstream_id.as_str()),
                _ => None,
            });

        let observe_traffic = self
            .traffic_state
            .is_controlled_host(&preparation.leaf.host)
            && request.method.eq_ignore_ascii_case("GET")
            && request_type == "document";

        for attempt in 0..=self.config.traffic.internal_retry_limit {
            let traffic_action = self.traffic_state.action_for_request(
                &preparation.leaf.host,
                &request.method,
                request_type,
                &self.config.traffic,
            );
            let mut observed_permit =
                if observe_traffic && matches!(traffic_action, TrafficAction::Bypass) {
                    self.traffic_state
                        .begin_observed_request(&preparation.leaf.host)
                } else {
                    None
                };
            let mut traffic_permit = match traffic_action {
                TrafficAction::Managed => Some(
                    self.traffic_state
                        .acquire(&preparation.leaf.host, &self.config.traffic)
                        .await?,
                ),
                TrafficAction::Bypass => None,
            };
            let allow_invalid_upstream_certs =
                self.should_tolerate_invalid_upstream_cert(&preparation.leaf.host);
            let client = self.build_http_client(upstream_id, allow_invalid_upstream_certs)?;
            let mut outbound = client.request(
                reqwest::Method::from_bytes(request.method.as_bytes())?,
                &target_url,
            );

            for (name, value) in &request.headers {
                if should_forward_request_header(name) {
                    outbound = outbound.header(name, value);
                }
            }

            for effect in &request_decision.effects {
                if let RuleEffect::RewriteHeader { name, value } = effect {
                    outbound = outbound.header(name, value);
                }
            }

            outbound = outbound.header(ACCEPT_ENCODING, "identity");

            if !request.body.is_empty() {
                outbound = outbound.body(request.body.clone());
            }

            let upstream_started_at = std::time::Instant::now();
            let upstream_response = match outbound.send().await {
                Ok(response) => response,
                Err(error) => {
                    if is_upstream_certificate_error(&error) && !allow_invalid_upstream_certs {
                        let response =
                            upstream_tls_failure_response(&preparation.leaf.host, &target_url);
                        tls_stream.write_all(&response).await?;
                        tls_stream.shutdown().await?;
                        return Ok(());
                    }

                    if observe_traffic {
                        self.traffic_state.on_fatal_error(&preparation.leaf.host);
                    }
                    return Err(anyhow::Error::from(error));
                }
            };
            let fetch_headers_ms = upstream_started_at.elapsed().as_millis();
            let status = upstream_response.status();
            let mut response_headers = upstream_response.headers().clone();
            let response_header_pairs = header_pairs_from_reqwest(&response_headers);
            let response_context = RuleResponseContext {
                url: target_url.clone(),
                status_code: status.as_u16(),
                headers: response_header_pairs.clone(),
                body_preview: None,
            };
            let response_decision = self.rules.evaluate_response(&response_context);

            if status.as_u16() == 429
                && self
                    .traffic_state
                    .is_controlled_host(&preparation.leaf.host)
                && request.method.eq_ignore_ascii_case("GET")
                && request_type == "document"
            {
                let retry_after = traffic::parse_retry_after_secs(&response_header_pairs);
                drop(observed_permit.take());
                drop(traffic_permit.take());
                match self.traffic_state.decide_429_response(
                    &preparation.leaf.host,
                    attempt,
                    retry_after,
                    &self.config.traffic,
                ) {
                    TrafficResponseDecision::RetryAfterDelay(delay) => {
                        self.traffic_state.begin_retry_wait(&preparation.leaf.host);
                        time::sleep(delay).await;
                        self.traffic_state.end_retry_wait(&preparation.leaf.host);
                        continue;
                    }
                    TrafficResponseDecision::ReloadPage(delay) => {
                        let response = traffic::reload_page_response(delay, &target_url);
                        tls_stream.write_all(&response).await?;
                        tls_stream.shutdown().await?;
                        return Ok(());
                    }
                    TrafficResponseDecision::Forward => {}
                }
            } else if matches!(traffic_action, TrafficAction::Managed) {
                self.traffic_state
                    .on_success(&preparation.leaf.host, &self.config.traffic);
            }

            if !self.should_buffer_response(
                &response_context.url,
                request_type,
                &response_headers,
                &response_decision.effects,
            ) {
                stream_https_response(
                    &mut tls_stream,
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("OK"),
                    &response_headers,
                    upstream_response,
                )
                .await?;
                drop(observed_permit.take());
                tls_stream.shutdown().await?;
                log_slow_mitm_stage(
                    "fetch_headers",
                    &response_context.url,
                    fetch_headers_ms,
                    &format!("mode=stream status={}", status.as_u16()),
                    SLOW_MITM_FETCH_HEADERS_MS,
                );
                log_slow_mitm_stage(
                    "total",
                    &response_context.url,
                    total_started_at.elapsed().as_millis(),
                    &format!("mode=stream status={}", status.as_u16()),
                    SLOW_MITM_TOTAL_MS,
                );
                return Ok(());
            }

            let buffer_started_at = std::time::Instant::now();
            let response_body = upstream_response
                .bytes()
                .await
                .map_err(|error| {
                    if observe_traffic {
                        self.traffic_state.on_fatal_error(&preparation.leaf.host);
                    }
                    anyhow::Error::from(error)
                })?
                .to_vec();
            let buffer_body_ms = buffer_started_at.elapsed().as_millis();

            let response_context = RuleResponseContext {
                url: response_context.url,
                status_code: response_context.status_code,
                headers: response_context.headers,
                body_preview: Some(
                    String::from_utf8_lossy(&response_body)
                        .chars()
                        .take(200)
                        .collect(),
                ),
            };
            let response_body = apply_response_effects(response_body, &response_decision.effects);
            let (response_body, rewrite_perf) = self
                .apply_site_specific_response_rewrite(
                    &response_context.url,
                    &source_url,
                    request_type,
                    fetch_site.as_deref(),
                    &mut response_headers,
                    response_body,
                )
                .with_context(|| {
                    format!(
                        "failed to apply site-specific MITM rewrite for {}",
                        response_context.url
                    )
                })?;
            if self.config.logging.log_response_body {
                log_response_body(
                    "mitm",
                    &response_context.url,
                    response_headers
                        .get("content-type")
                        .and_then(|value| value.to_str().ok()),
                    &response_body,
                );
            }
            log_slow_mitm_stage(
                "fetch_headers",
                &response_context.url,
                fetch_headers_ms,
                &format!("mode=buffer status={}", status.as_u16()),
                SLOW_MITM_FETCH_HEADERS_MS,
            );
            log_slow_mitm_stage(
                "buffer_body",
                &response_context.url,
                buffer_body_ms,
                &format!("bytes={}", response_body.len()),
                SLOW_MITM_BUFFER_BODY_MS,
            );
            log_slow_mitm_stage(
                "rewrite_patch",
                &response_context.url,
                rewrite_perf.patch_ms,
                "",
                SLOW_MITM_REWRITE_STAGE_MS,
            );
            log_slow_mitm_stage(
                "rewrite_render",
                &response_context.url,
                rewrite_perf.render_ms,
                "",
                SLOW_MITM_REWRITE_STAGE_MS,
            );
            log_slow_mitm_stage(
                "rewrite_adblock_injection",
                &response_context.url,
                rewrite_perf.adblock_injection_ms,
                "",
                SLOW_MITM_REWRITE_STAGE_MS,
            );
            let response_bytes = build_https_response_bytes(
                status.as_u16(),
                status.canonical_reason().unwrap_or("OK"),
                &response_headers,
                response_body,
            );

            tls_stream.write_all(&response_bytes).await?;
            drop(observed_permit.take());
            tls_stream.shutdown().await?;
            log_slow_mitm_stage(
                "total",
                &response_context.url,
                total_started_at.elapsed().as_millis(),
                &format!("mode=buffer status={}", status.as_u16()),
                SLOW_MITM_TOTAL_MS,
            );
            return Ok(());
        }

        Ok(())
    }

    /// Prepare MITM state before interception:
    /// - load and validate the local CA certificate and key
    /// - build or fetch the leaf certificate plan for the target authority
    fn prepare_interception(&self, authority: &str) -> Result<MitmPreparation> {
        let ca = self.load_ca_material()?;
        let leaf = self.get_or_prepare_leaf(authority)?;
        Ok(MitmPreparation { ca, leaf })
    }

    fn load_ca_material(&self) -> Result<MitmCaMaterial> {
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

        let ca_material = MitmCaMaterial {
            cert_path,
            key_path,
            cert_pem,
            key_pem,
        };

        Ok(ca_material)
    }

    fn get_or_prepare_leaf(&self, authority: &str) -> Result<GeneratedLeafCert> {
        let ca = self.load_ca_material()?;
        let (host, port) = normalize_authority(authority)?;
        let cache_key = format!("{host}:{port}");

        let mut cache = self
            .cert_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("failed to acquire MITM certificate cache lock"))?;

        if let Some(cached) = cache.get(&cache_key) {
            return Ok(cached.clone());
        }

        let generated = generate_leaf_certificate(&ca, &host, port, &cache_key)?;

        cache.insert(cache_key, generated.clone());
        Ok(generated)
    }

    fn build_http_client(
        &self,
        upstream_id: Option<&str>,
        allow_invalid_certs: bool,
    ) -> Result<Client> {
        let cache_key = format!(
            "{}:{}",
            upstream_id.unwrap_or(""),
            if allow_invalid_certs {
                "allow-invalid"
            } else {
                "strict"
            }
        );
        if let Some(client) = self
            .http_client_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("failed to acquire MITM HTTP client cache lock"))?
            .get(&cache_key)
            .cloned()
        {
            return Ok(client);
        }

        let mut builder = Client::builder().redirect(reqwest::redirect::Policy::none());
        if allow_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(upstream_id) = upstream_id {
            let upstream = self.upstreams.resolve(upstream_id).with_context(|| {
                format!("MITM request references missing upstream `{upstream_id}`")
            })?;
            builder = builder.proxy(reqwest::Proxy::all(&upstream.address)?);
        }

        let client = builder.build()?;
        self.http_client_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("failed to acquire MITM HTTP client cache lock"))?
            .insert(cache_key, client.clone());
        Ok(client)
    }

    fn should_tolerate_invalid_upstream_cert(&self, host: &str) -> bool {
        let target = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        self.config
            .proxy
            .mitm
            .tolerate_invalid_upstream_cert_hosts
            .iter()
            .map(|item| item.trim().trim_matches(['[', ']']).to_ascii_lowercase())
            .any(|item| item == target)
    }

    fn should_buffer_response(
        &self,
        target_url: &str,
        request_type: &str,
        response_headers: &HeaderMap,
        response_effects: &[RuleEffect],
    ) -> bool {
        if self.config.logging.log_response_body {
            return true;
        }

        if response_effects
            .iter()
            .any(|effect| matches!(effect, RuleEffect::RewriteResponseBody { .. }))
        {
            return true;
        }

        let content_type = response_headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let is_document = matches!(request_type, "document" | "subdocument");
        let html_like = content_type.is_empty()
            || content_type.contains("text/html")
            || content_type.contains("application/xhtml");

        if is_document && html_like && adblock::is_enabled(&self.adblock_state) {
            return true;
        }

        self.rewrite_registry
            .read()
            .map(|registry| {
                (html_like && registry.has_render_rule_match(target_url))
                    || registry.has_patch_rule_match(target_url, &content_type)
            })
            .unwrap_or(true)
    }

    /// Let the MITM path apply site-specific rewrites instead of limiting them to the gateway path.
    /// MITM only uses external rewrite rules for now. If a site has no rule file, it is left untouched.
    fn apply_site_specific_response_rewrite(
        &self,
        target_url: &str,
        source_url: &str,
        request_type: &str,
        fetch_site: Option<&str>,
        response_headers: &mut HeaderMap,
        response_body: Vec<u8>,
    ) -> Result<(Vec<u8>, RewritePerfStats)> {
        let mut perf = RewritePerfStats::default();
        let content_type = response_headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();

        let patch_started_at = std::time::Instant::now();
        let patch_result = {
            let registry = self
                .rewrite_registry
                .read()
                .map_err(|_| anyhow::anyhow!("rewrite registry lock poisoned"))?;
            registry.apply_patch_rules(&response_body, target_url, &content_type)?
        };
        perf.patch_ms = patch_started_at.elapsed().as_millis();
        let response_body = patch_result.body;
        if patch_result.modified {
            response_headers.remove("content-encoding");
            response_headers.remove("content-length");
            response_headers.remove("transfer-encoding");
        }

        if !is_html_content_type(&content_type) {
            return Ok((response_body, perf));
        }

        let render_started_at = std::time::Instant::now();
        let render_result = {
            let registry = self
                .rewrite_registry
                .read()
                .map_err(|_| anyhow::anyhow!("rewrite registry lock poisoned"))?;
            registry.apply_matching_rule(&response_body, target_url)?
        };
        perf.render_ms = render_started_at.elapsed().as_millis();
        let csp_directives = adblock::csp_directives_for_request(
            &self.adblock_state,
            target_url,
            source_url,
            request_type,
            fetch_site,
        )?;
        let inject_started_at = std::time::Instant::now();
        let (rewritten, injected) =
            if render_result.matched && !render_result.allow_adblock_injection {
                (render_result.body, false)
            } else {
                inject_adblock_document(target_url, render_result.body, &self.adblock_state)
            };
        perf.adblock_injection_ms = inject_started_at.elapsed().as_millis();

        response_headers.remove("content-encoding");
        response_headers.remove("content-security-policy");
        response_headers.remove("content-security-policy-report-only");
        response_headers.remove("content-length");
        response_headers.remove("transfer-encoding");
        if !injected {
            if let Some(csp_directives) = csp_directives.filter(|item| !item.trim().is_empty()) {
                response_headers.insert(
                    HeaderName::from_static("content-security-policy"),
                    HeaderValue::from_str(&csp_directives)
                        .context("failed to encode adblock CSP directives as header value")?,
                );
            }
        }
        response_headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );

        Ok((rewritten, perf))
    }
}

fn inject_adblock_document(
    target_url: &str,
    response_body: Vec<u8>,
    adblock_state: &SharedAdblockState,
) -> (Vec<u8>, bool) {
    let Some(snippet) =
        adblock::render_document_injection(adblock_state, target_url, &response_body)
    else {
        return (response_body, false);
    };

    let document = String::from_utf8_lossy(&response_body).into_owned();
    (inject_html_snippet(&document, &snippet).into_bytes(), true)
}

fn inject_html_snippet(document: &str, snippet: &str) -> String {
    let lower = document.to_ascii_lowercase();
    if let Some(head_start) = lower.find("<head") {
        if let Some(head_end_offset) = lower[head_start..].find('>') {
            let index = head_start + head_end_offset + 1;
            let mut output = String::with_capacity(document.len() + snippet.len() + 1);
            output.push_str(&document[..index]);
            output.push('\n');
            output.push_str(snippet);
            output.push('\n');
            output.push_str(&document[index..]);
            return output;
        }
    }

    if let Some(index) = lower.find("</head>") {
        let mut output = String::with_capacity(document.len() + snippet.len() + 1);
        output.push_str(&document[..index]);
        output.push_str(snippet);
        output.push('\n');
        output.push_str(&document[index..]);
        return output;
    }

    if let Some(index) = lower.find("</body>") {
        let mut output = String::with_capacity(document.len() + snippet.len() + 1);
        output.push_str(&document[..index]);
        output.push_str(snippet);
        output.push('\n');
        output.push_str(&document[index..]);
        return output;
    }

    let mut output = String::with_capacity(document.len() + snippet.len() + 1);
    output.push_str(snippet);
    output.push('\n');
    output.push_str(document);
    output
}

fn generate_leaf_certificate(
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

    let mut params = CertificateParams::new(vec![host.to_string()])
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

fn build_tls_acceptor(leaf: &GeneratedLeafCert) -> Result<TlsAcceptor> {
    let cert_chain: Vec<CertificateDer<'static>> =
        vec![CertificateDer::from(leaf.cert_der.clone())];
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf.key_der.clone()));

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("failed to build rustls ServerConfig for MITM leaf certificate")?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

#[derive(Debug, Clone)]
struct MitmPreparation {
    ca: MitmCaMaterial,
    leaf: GeneratedLeafCert,
}

#[derive(Debug, Clone)]
struct MitmCaMaterial {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

#[derive(Debug, Clone)]
struct GeneratedLeafCert {
    /// Cache key, usually `host:port`.
    cache_key: String,
    /// Target host name.
    host: String,
    /// Generated leaf certificate in PEM form.
    cert_pem: String,
    /// Generated leaf private key in PEM form.
    key_pem: String,
    /// Generated leaf certificate in DER form.
    cert_der: Vec<u8>,
    /// Generated leaf private key in DER form.
    key_der: Vec<u8>,
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

fn normalize_authority(authority: &str) -> Result<(String, u16)> {
    let authority = authority.trim();
    let authority = authority
        .strip_prefix('[')
        .unwrap_or(authority)
        .trim_end_matches(']');

    if let Some((host, port_text)) = authority.rsplit_once(':') {
        if let Ok(port) = port_text.parse::<u16>() {
            if !host.is_empty() {
                return Ok((host.to_string(), port));
            }
        }
    }

    if authority.is_empty() {
        bail!("CONNECT authority is empty");
    }

    Ok((authority.to_string(), 443))
}

pub fn mitm_storage_dir() -> Result<PathBuf> {
    let preferred = match app_path_mode() {
        AppPathMode::Workspace => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("mitm"),
        AppPathMode::Portable => executable_base_dir()
            .context("failed to resolve executable directory for MITM storage")?
            .join("data")
            .join("mitm"),
    };

    migrate_legacy_mitm_storage_if_needed(&preferred)?;
    Ok(preferred)
}

pub fn create_and_trust_local_ca() -> Result<()> {
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

    let ca_material = MitmCaMaterial {
        cert_path,
        key_path,
        cert_pem,
        key_pem,
    };

    #[cfg(windows)]
    ensure_ca_installed_in_windows_user_root(&ca_material)?;

    Ok(())
}

fn executable_base_dir() -> Result<PathBuf> {
    let exe = env::current_exe().context("failed to resolve current executable path")?;
    let parent = exe
        .parent()
        .context("current executable path does not have a parent directory")?;
    Ok(parent.to_path_buf())
}

fn migrate_legacy_mitm_storage_if_needed(preferred_dir: &Path) -> Result<()> {
    if preferred_dir.exists() {
        return Ok(());
    }

    let Some(legacy_dir) = legacy_mitm_storage_dir() else {
        return Ok(());
    };

    if !legacy_dir.exists() {
        return Ok(());
    }

    let legacy_cert = legacy_dir.join("relaygate-ca-cert.pem");
    let legacy_key = legacy_dir.join("relaygate-ca-key.pem");
    if !legacy_cert.exists() && !legacy_key.exists() {
        return Ok(());
    }

    fs::create_dir_all(preferred_dir).with_context(|| {
        format!(
            "failed to create preferred MITM storage directory during migration: {}",
            preferred_dir.display()
        )
    })?;

    let preferred_cert = preferred_dir.join("relaygate-ca-cert.pem");
    let preferred_key = preferred_dir.join("relaygate-ca-key.pem");

    if legacy_cert.exists() && !preferred_cert.exists() {
        fs::copy(&legacy_cert, &preferred_cert).with_context(|| {
            format!(
                "failed to migrate legacy CA certificate from {} to {}",
                legacy_cert.display(),
                preferred_cert.display()
            )
        })?;
    }

    if legacy_key.exists() && !preferred_key.exists() {
        fs::copy(&legacy_key, &preferred_key).with_context(|| {
            format!(
                "failed to migrate legacy CA private key from {} to {}",
                legacy_key.display(),
                preferred_key.display()
            )
        })?;
    }

    Ok(())
}

fn legacy_mitm_storage_dir() -> Option<PathBuf> {
    let workspace_legacy = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("mitm");
    if workspace_legacy.exists() {
        return Some(workspace_legacy);
    }

    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        return Some(PathBuf::from(local_app_data).join("RelayGate").join("mitm"));
    }

    if let Some(app_data) = env::var_os("APPDATA") {
        return Some(PathBuf::from(app_data).join("RelayGate").join("mitm"));
    }

    None
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

#[derive(Debug, Clone)]
struct ParsedMitmHttpRequest {
    method: String,
    uri_text: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn read_http_request<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let read_count = stream.read(&mut temp).await?;
        if read_count == 0 {
            break;
        }

        buffer.extend_from_slice(&temp[..read_count]);

        if header_end.is_none() {
            header_end = find_header_end(&buffer);
            if let Some(index) = header_end {
                content_length = parse_content_length(&buffer[..index])?;
            }
        }

        if let Some(index) = header_end {
            let expected_total = index + 4 + content_length;
            if buffer.len() >= expected_total {
                break;
            }
        }
    }

    Ok(buffer)
}

fn parse_http_request(bytes: &[u8]) -> Result<ParsedMitmHttpRequest> {
    let header_end =
        find_header_end(bytes).context("invalid MITM HTTP request: missing header terminator")?;
    let header_text = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = header_text.split("\r\n");

    let request_line = lines
        .next()
        .context("invalid MITM HTTP request: missing request line")?;
    let mut request_parts = request_line.splitn(3, ' ');
    let method = request_parts
        .next()
        .context("invalid MITM HTTP request: missing method")?;
    let uri_text = request_parts
        .next()
        .context("invalid MITM HTTP request: missing uri")?;
    request_parts
        .next()
        .context("invalid MITM HTTP request: missing version")?;

    let headers = lines
        .filter(|line| !line.is_empty())
        .map(parse_header_line)
        .collect::<Result<Vec<_>>>()?;

    Ok(ParsedMitmHttpRequest {
        method: method.to_string(),
        uri_text: uri_text.to_string(),
        headers,
        body: bytes[header_end + 4..].to_vec(),
    })
}

fn parse_header_line(line: &str) -> Result<(String, String)> {
    let (name, value) = line
        .split_once(':')
        .with_context(|| format!("invalid MITM HTTP header line: {line}"))?;
    Ok((name.trim().to_string(), value.trim().to_string()))
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(header_bytes: &[u8]) -> Result<usize> {
    let header_text = std::str::from_utf8(header_bytes)?;

    for line in header_text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return Ok(value.trim().parse::<usize>()?);
            }
        }
    }

    Ok(0)
}

fn build_https_target_url(authority: &str, request: &ParsedMitmHttpRequest) -> Result<String> {
    if request.uri_text.starts_with("https://") {
        return Ok(request.uri_text.clone());
    }

    let (host, port) = normalize_authority(authority)?;
    let path = if request.uri_text.is_empty() {
        "/"
    } else {
        request.uri_text.as_str()
    };

    if port == 443 {
        Ok(format!("https://{host}{path}"))
    } else {
        Ok(format!("https://{host}:{port}{path}"))
    }
}

fn should_forward_request_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "proxy-connection" | "content-length" | "host" | "accept-encoding"
    )
}

fn should_abort_adblock_request(request_type: &str) -> bool {
    !matches!(request_type, "document" | "subdocument")
}

fn header_pairs_from_reqwest(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect()
}

fn apply_response_effects(mut body: Vec<u8>, effects: &[RuleEffect]) -> Vec<u8> {
    for effect in effects {
        if let RuleEffect::RewriteResponseBody { find, replace } = effect {
            let rewritten = String::from_utf8_lossy(&body).replace(find, replace);
            body = rewritten.into_bytes();
        }
    }

    body
}

fn build_https_response_bytes(
    status_code: u16,
    reason_phrase: &str,
    headers: &reqwest::header::HeaderMap,
    body: Vec<u8>,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(format!("HTTP/1.1 {status_code} {reason_phrase}\r\n").as_bytes());

    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }

        if let Ok(value_text) = value.to_str() {
            output.extend_from_slice(format!("{}: {}\r\n", name.as_str(), value_text).as_bytes());
        }
    }

    output.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    output.extend_from_slice(b"Connection: close\r\n\r\n");
    output.extend_from_slice(&body);
    output
}

fn build_https_response_head(
    status_code: u16,
    reason_phrase: &str,
    headers: &reqwest::header::HeaderMap,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(format!("HTTP/1.1 {status_code} {reason_phrase}\r\n").as_bytes());

    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(lower.as_str(), "transfer-encoding" | "connection") {
            continue;
        }

        if let Ok(value_text) = value.to_str() {
            output.extend_from_slice(format!("{}: {}\r\n", name.as_str(), value_text).as_bytes());
        }
    }

    output.extend_from_slice(b"Connection: close\r\n\r\n");
    output
}

async fn stream_https_response(
    tls_stream: &mut tokio_rustls::server::TlsStream<&mut TcpStream>,
    status_code: u16,
    reason_phrase: &str,
    headers: &reqwest::header::HeaderMap,
    mut upstream_response: reqwest::Response,
) -> Result<()> {
    let response_head = build_https_response_head(status_code, reason_phrase, headers);
    tls_stream.write_all(&response_head).await?;

    while let Some(chunk) = upstream_response.chunk().await? {
        tls_stream.write_all(&chunk).await?;
    }

    Ok(())
}

fn log_slow_mitm_stage(stage: &str, url: &str, elapsed_ms: u128, extra: &str, threshold_ms: u128) {
    if elapsed_ms < threshold_ms {
        return;
    }

    let extra = extra.trim();
    let suffix = if extra.is_empty() {
        String::new()
    } else {
        format!(" {extra}")
    };
    let _ = diagnostics::append_proxy_perf_diagnostic(&format!(
        "ts={} event=perf_mitm stage={} elapsed_ms={} url={}{}",
        diagnostics::diagnostic_timestamp(),
        stage,
        elapsed_ms,
        url,
        suffix
    ));
}

fn simple_http_response_bytes(status_code: u16, reason_phrase: &str, body: &str) -> Vec<u8> {
    simple_http_response_bytes_with_content_type(
        status_code,
        reason_phrase,
        "text/plain; charset=utf-8",
        body.as_bytes(),
    )
}

fn simple_http_response_bytes_with_content_type(
    status_code: u16,
    reason_phrase: &str,
    content_type: &str,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_code} {reason_phrase}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

fn upstream_tls_failure_response(host: &str, target_url: &str) -> Vec<u8> {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>RelayGate Upstream TLS Verification Failed</title></head><body><h1>RelayGate</h1><p>Upstream TLS certificate verification failed.</p><p>Host: {}</p><p>URL: {}</p><p>RelayGate keeps standard upstream TLS verification enabled by default. If this host must be tolerated temporarily, add it to <code>proxy.mitm.tolerate_invalid_upstream_cert_hosts</code>.</p></body></html>",
        html_escape_text(host),
        html_escape_text(target_url)
    );
    simple_http_response_bytes_with_content_type(
        526,
        "Invalid SSL Certificate",
        "text/html; charset=utf-8",
        body.as_bytes(),
    )
}

fn is_upstream_certificate_error(error: &reqwest::Error) -> bool {
    let mut current = error.source();
    while let Some(source) = current {
        let text = source.to_string().to_ascii_lowercase();
        if text.contains("certificate")
            || text.contains("cert verify")
            || text.contains("invalid peer certificate")
            || text.contains("unknownissuer")
            || text.contains("expired")
        {
            return true;
        }
        current = source.source();
    }

    let top = error.to_string().to_ascii_lowercase();
    top.contains("certificate")
        || top.contains("cert verify")
        || top.contains("invalid peer certificate")
        || top.contains("unknownissuer")
        || top.contains("expired")
}

fn html_escape_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn hidden_command(program: &str) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

#[cfg(windows)]
fn ensure_ca_installed_in_windows_user_root(ca: &MitmCaMaterial) -> Result<()> {
    let thumbprint = sha1_thumbprint_from_pem(&ca.cert_pem)?;
    let check_script = format!(
        r#"$thumb = '{thumbprint}'
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
  [System.Security.Cryptography.X509Certificates.StoreName]::Root,
  [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
)
try {{
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
  $existing = @($store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumb }})
  if ($existing.Count -gt 0) {{ Write-Output 'present' }} else {{ Write-Output 'missing' }}
}} finally {{
  $store.Close()
}}"#
    );

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &check_script])
        .output()
        .context("failed to execute PowerShell for CA trust check")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to check RelayGate CA in Windows user Root store: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim() == "present" {
        debug!(
            thumbprint = thumbprint,
            "RelayGate CA already present in Windows CurrentUser Root store"
        );
        return Ok(());
    }

    let install_output = hidden_command("certutil")
        .args([
            "-user",
            "-addstore",
            "Root",
            &ca.cert_path.to_string_lossy(),
        ])
        .output()
        .context("failed to execute certutil for CA trust installation")?;

    if !install_output.status.success() {
        let stderr = String::from_utf8_lossy(&install_output.stderr);
        let stdout = String::from_utf8_lossy(&install_output.stdout);
        bail!(
            "failed to install RelayGate CA into Windows user Root store via certutil\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    let verify_output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &check_script])
        .output()
        .context("failed to execute PowerShell for CA trust verification")?;

    if !verify_output.status.success() {
        let stderr = String::from_utf8_lossy(&verify_output.stderr);
        bail!("failed to verify RelayGate CA after installation: {stderr}");
    }

    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    if verify_stdout.trim() != "present" {
        bail!("RelayGate CA installation reported success, but the certificate is still missing from CurrentUser\\Root");
    }

    debug!(
        thumbprint = thumbprint,
        "RelayGate CA installed into Windows CurrentUser Root store"
    );

    Ok(())
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

    for byte in input.bytes().filter(|b| !b.is_ascii_whitespace()) {
        if byte == b'=' {
            chunk.push(64);
        } else if let Some(index) = TABLE.iter().position(|value| *value == byte) {
            chunk.push(index as u8);
        } else {
            bail!("invalid base64 character in PEM body");
        }

        if chunk.len() == 4 {
            decode_base64_chunk(&chunk, &mut output);
            chunk.clear();
        }
    }

    if !chunk.is_empty() {
        bail!("invalid base64 length in PEM body");
    }

    Ok(output)
}

#[cfg(windows)]
fn decode_base64_chunk(chunk: &[u8], output: &mut Vec<u8>) {
    let b0 = chunk[0];
    let b1 = chunk[1];
    let b2 = chunk[2];
    let b3 = chunk[3];

    output.push((b0 << 2) | (b1 >> 4));
    if b2 != 64 {
        output.push(((b1 & 0x0F) << 4) | (b2 >> 2));
    }
    if b3 != 64 {
        output.push(((b2 & 0x03) << 6) | b3);
    }
}

fn log_response_body(source: &str, url: &str, content_type: Option<&str>, body: &[u8]) {
    if is_probably_text_content(content_type) {
        let text = String::from_utf8_lossy(body);
        info!(target: "relaygate::body", source = source, url = url, body = %text, "response body");
    } else {
        info!(
            target: "relaygate::body",
            source = source,
            url = url,
            content_type = ?content_type,
            body_len = body.len(),
            "response body skipped for non-text content"
        );
    }
}

fn is_probably_text_content(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return false;
    };

    let content_type = content_type.to_ascii_lowercase();
    content_type.contains("text/")
        || content_type.contains("json")
        || content_type.contains("xml")
        || content_type.contains("javascript")
        || content_type.contains("x-www-form-urlencoded")
}

fn is_html_content_type(content_type: &str) -> bool {
    content_type.contains("text/html") || content_type.contains("application/xhtml")
}
