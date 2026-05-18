use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use axum::http::Uri;
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
};
use reqwest::{Body, Client, StatusCode};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time,
};
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::{
    adblock::{self, SharedAdblockState},
    config::RelayGateConfig,
    diagnostics,
    dns::SharedDnsResolver,
    proxy::{
        downstream_status::{self, DownstreamStatusProtocol},
        happy_eyeballs::{connect_happy_eyeballs, resolve_target_addresses},
        header_hop::should_apply_request_header_rewrite,
        http_framing,
        http_parse::{parse_http_response_head, read_http_response_head},
        mitm_ca::{
            build_tls_acceptor, generate_leaf_certificate, load_ca_material, normalize_authority,
            GeneratedLeafCert, MitmCaMaterial, MitmPreparation,
        },
        mitm_core::{
            allow_active_h3_buffered_for_request, has_browser_storage_access_header,
            mitm_response_pipeline_decision, prepare_mitm_request, process_mitm_response_body,
            response_body_pipeline_preflight_reason, MitmLocalResponse, MitmLocalResponseBody,
            MitmRequestDecision, MitmRequestState, MitmResponseState, PreparedMitmRequest,
        },
        mitm_http::{
            build_https_response_bytes, build_https_target_url, connection_header_tokens,
            header_pairs_from_reqwest, is_upstream_certificate_error, log_response_body,
            log_slow_mitm_stage, parse_http_request, record_adaptive_stream_failure,
            should_forward_request_header, simple_http_response_bytes,
            simple_http_response_bytes_with_content_type, stream_https_response,
            upstream_tls_failure_response, MitmBodyCompletion, MitmResponseConnection,
            MitmStreamBodyMode,
        },
        mitm_upstream::MitmUpstreamConnector,
        pipeline::{PipelineDecision, PipelineRoute},
        protocol_runtime::{ProtocolRuntimeConfig, ProtocolRuntimeSnapshot},
        resource_replace::SharedResourceReplaceRegistry,
        rules::{RuleEffect, RuleEngine, RuleResponseContext},
        upstream::SharedUpstreamRegistry,
        upstream_h3,
        upstream_model::RelayUpstreamBufferedResponse,
    },
    rewrite::SharedRewriteRegistry,
    traffic::{self, SharedTrafficState, TrafficAction, TrafficResponseDecision},
    user_script::SharedUserScriptRegistry,
};

pub use crate::proxy::mitm_ca::{create_and_trust_local_ca, mitm_storage_dir};

const SLOW_MITM_TOTAL_MS: u128 = 1000;
const SLOW_MITM_FETCH_HEADERS_MS: u128 = 400;
const SLOW_MITM_BUFFER_BODY_MS: u128 = 500;
const SLOW_MITM_REWRITE_STAGE_MS: u128 = 120;
const MITM_WEBSOCKET_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MITM_WEBSOCKET_UPSTREAM_RESPONSE_HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const MITM_UPSTREAM_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MITM_REQUEST_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_MITM_LEAF_CERT_CACHE_ENTRIES: usize = 2048;
const MITM_WEBSOCKET_HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(100);
const MITM_STREAM_BUFFER_BYTES: usize = 64 * 1024;
const MITM_REQUEST_BODY_PIPE_BYTES: usize = 256 * 1024;

// P1-06K: navigation/main document responses are a connection lifecycle
// boundary and are not admitted into the downstream keep-alive reuse loop.

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
    upstreams: SharedUpstreamRegistry,
    resource_replace_registry: SharedResourceReplaceRegistry,
    rewrite_registry: SharedRewriteRegistry,
    adblock_state: SharedAdblockState,
    traffic_state: SharedTrafficState,
    dns_resolver: SharedDnsResolver,
    user_script_registry: SharedUserScriptRegistry,
    protocol_runtime: ProtocolRuntimeConfig,
    cert_cache: Arc<Mutex<MitmLeafCertCache>>,
    http_client_cache: Arc<Mutex<HashMap<String, Client>>>,
}

#[derive(Debug, Clone)]
enum MitmRequestBodyForwardMode {
    None,
    StreamingContentLength {
        content_length: usize,
        prebuffered_body: Vec<u8>,
        expect_100_continue: bool,
    },
    StreamingChunked {
        prebuffered_body: Vec<u8>,
        expect_100_continue: bool,
    },
}

#[derive(Default)]
struct MitmLeafCertCache {
    entries: HashMap<String, GeneratedLeafCert>,
    lru: VecDeque<String>,
}

impl MitmLeafCertCache {
    fn get(&mut self, cache_key: &str) -> Option<GeneratedLeafCert> {
        let cached = self.entries.get(cache_key).cloned()?;
        self.touch(cache_key);
        Some(cached)
    }

    fn insert(&mut self, cache_key: String, cert: GeneratedLeafCert) {
        self.entries.insert(cache_key.clone(), cert);
        self.touch(&cache_key);
        self.prune_to_limit();
    }

    fn touch(&mut self, cache_key: &str) {
        self.lru.retain(|key| key != cache_key);
        self.lru.push_back(cache_key.to_string());
    }

    fn prune_to_limit(&mut self) {
        while self.entries.len() > MAX_MITM_LEAF_CERT_CACHE_ENTRIES {
            let Some(oldest) = self.lru.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

impl MitmRequestBodyForwardMode {
    fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StreamingContentLength { .. } => "mitm_streaming_content_length",
            Self::StreamingChunked { .. } => "mitm_streaming_chunked",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{
        mitm_core::PreparedMitmRequest,
        mitm_http::ParsedMitmHttpRequest,
        mitm_upstream::{MitmUpstreamProtocolPolicy, MitmUpstreamRequestIntent},
    };

    fn websocket_request(uri_text: &str) -> ParsedMitmHttpRequest {
        ParsedMitmHttpRequest {
            method: "GET".to_string(),
            uri_text: uri_text.to_string(),
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Connection".to_string(), "keep-alive, Upgrade".to_string()),
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Sec-WebSocket-Key".to_string(), "abc".to_string()),
                ("Sec-WebSocket-Version".to_string(), "13".to_string()),
                ("Proxy-Connection".to_string(), "keep-alive".to_string()),
                ("Content-Length".to_string(), "0".to_string()),
            ],
            body: Vec::new(),
        }
    }

    fn prepared_request() -> PreparedMitmRequest {
        PreparedMitmRequest {
            target_url: "https://example.com/socket".to_string(),
            method: "GET".to_string(),
            headers: websocket_request("/socket").headers,
            request_effects: Vec::new(),
            request_type: "websocket".to_string(),
            source_url: "https://example.com/".to_string(),
            fetch_site: None,
            upstream: MitmUpstreamRequestIntent::new(None, MitmUpstreamProtocolPolicy::Auto),
            traffic_host: "example.com".to_string(),
            observe_traffic: false,
        }
    }

    #[test]
    fn websocket_upgrade_detection_requires_connection_token() {
        let request = websocket_request("/socket");
        assert!(request_is_websocket_upgrade(&request));

        let mut missing_connection_token = request.clone();
        missing_connection_token.headers[1] = ("Connection".to_string(), "keep-alive".to_string());
        assert!(!request_is_websocket_upgrade(&missing_connection_token));
    }

    #[test]
    fn websocket_upstream_request_preserves_websocket_headers() {
        let request = websocket_request("https://example.com/socket?room=1");
        let prepared = prepared_request();
        let bytes = build_mitm_websocket_upstream_request("example.com:443", &request, &prepared);
        let text = String::from_utf8(bytes).unwrap();

        assert!(text.starts_with("GET /socket?room=1 HTTP/1.1\r\n"));
        assert!(text.contains("\r\nHost: example.com:443\r\n"));
        assert!(text.contains("\r\nConnection: Upgrade\r\n"));
        assert!(text.contains("\r\nUpgrade: websocket\r\n"));
        assert!(text.contains("\r\nSec-WebSocket-Key: abc\r\n"));
        assert!(text.contains("\r\nSec-WebSocket-Version: 13\r\n"));
        assert!(!text.contains("\r\nProxy-Connection:"));
        assert!(!text.contains("\r\nContent-Length:"));
    }

    #[test]
    fn mitm_passthrough_host_patterns_match_configured_authorities() {
        let patterns = vec![
            "*.example.net".to_string(),
            "media.example.org".to_string(),
            "*stream*".to_string(),
        ];

        assert!(mitm_passthrough_host_matches(
            "edge.example.net:8443",
            &patterns
        ));
        assert!(mitm_passthrough_host_matches(
            "media.example.org:443",
            &patterns
        ));
        assert!(mitm_passthrough_host_matches(
            "video-stream.example.com:443",
            &patterns
        ));
        assert!(!mitm_passthrough_host_matches(
            "other.example.com:443",
            &patterns
        ));
    }

    #[test]
    fn h3_active_direct_path_requires_direct_auto_policy() {
        assert!(h3_active_direct_path_allowed(
            &MitmUpstreamRequestIntent::new(None, MitmUpstreamProtocolPolicy::Auto,)
        ));
        assert!(!h3_active_direct_path_allowed(
            &MitmUpstreamRequestIntent::new(
                Some("osaka".to_string()),
                MitmUpstreamProtocolPolicy::Auto,
            )
        ));
        assert!(!h3_active_direct_path_allowed(
            &MitmUpstreamRequestIntent::new(None, MitmUpstreamProtocolPolicy::Http1Only,)
        ));
        assert!(!h3_active_direct_path_allowed(
            &MitmUpstreamRequestIntent::new(None, MitmUpstreamProtocolPolicy::Http2PriorKnowledge,)
        ));
    }
}

#[derive(Debug, Default)]
struct MitmChunkedRequestBodyStats {
    request_body_bytes: usize,
    chunk_count: usize,
    trailers_seen: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MitmRequestOutcome {
    Close,
    ContinueEligible,
    ClientClosed,
}

impl MitmRequestOutcome {
    fn as_str(self) -> &'static str {
        match self {
            MitmRequestOutcome::Close => "close",
            MitmRequestOutcome::ContinueEligible => "continue_eligible",
            MitmRequestOutcome::ClientClosed => "client_closed",
        }
    }
}

fn debug_mitm_request_outcome(
    outcome: MitmRequestOutcome,
    reason: &str,
    method: Option<&str>,
    url: Option<&str>,
    mitm_keep_alive: bool,
    mitm_request_index: usize,
) {
    debug!(
        mitm_keep_alive = mitm_keep_alive,
        mitm_request_index = mitm_request_index,
        mitm_request_outcome = outcome.as_str(),
        reason = reason,
        method = method.unwrap_or_default(),
        url = url.unwrap_or_default(),
        "MITM request outcome"
    );
}

fn debug_mitm_loop_action(
    mitm_keep_alive: bool,
    mitm_request_index: usize,
    outcome: MitmRequestOutcome,
    action: &str,
    reason: &str,
) {
    debug!(
        mitm_keep_alive = mitm_keep_alive,
        mitm_request_index = mitm_request_index,
        mitm_loop_action = action,
        mitm_request_outcome = outcome.as_str(),
        reason = reason,
        "MITM keep-alive loop action"
    );
}

fn request_connection_token_present(
    request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
    token: &str,
) -> bool {
    connection_header_tokens(&request.headers)
        .iter()
        .any(|item| item.eq_ignore_ascii_case(token))
}

fn request_has_upgrade(request: &crate::proxy::mitm_http::ParsedMitmHttpRequest) -> bool {
    request_connection_token_present(request, "upgrade")
        || request
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
}

fn request_is_websocket_upgrade(request: &crate::proxy::mitm_http::ParsedMitmHttpRequest) -> bool {
    request_connection_token_present(request, "upgrade")
        && request_header_value(request, "upgrade")
            .map(|value| value.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
}

fn h3_active_direct_path_allowed(
    upstream: &crate::proxy::mitm_upstream::MitmUpstreamRequestIntent,
) -> bool {
    // Active H3 currently opens a direct QUIC connection to the origin. If a
    // request is routed through a RelayGate upstream proxy, or if the upstream
    // protocol policy explicitly asks for H1/H2, taking the active H3 path would
    // no longer be semantically equivalent to the established reqwest path.
    upstream.upstream_id.is_none()
        && matches!(
            upstream.protocol_policy,
            crate::proxy::mitm_upstream::MitmUpstreamProtocolPolicy::Auto
        )
}

fn mitm_passthrough_host_matches(authority_or_host: &str, patterns: &[String]) -> bool {
    let host = normalize_passthrough_host(authority_or_host);
    !host.is_empty()
        && patterns
            .iter()
            .map(|pattern| pattern.trim().to_ascii_lowercase())
            .any(|pattern| host_pattern_matches(&host, &pattern))
}

fn normalize_passthrough_host(authority_or_host: &str) -> String {
    let trimmed = authority_or_host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let host = trimmed
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(trimmed);
    host.trim_matches(['[', ']']).to_ascii_lowercase()
}

fn host_pattern_matches(host: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    if pattern == "*" || pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
        return host.contains(pattern.trim_matches('*'));
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return host.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return host.starts_with(prefix);
    }
    false
}

fn is_unclean_tls_shutdown_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let text = error.to_string();
    text.contains("peer closed connection without sending TLS close_notify")
        || text.contains("unexpected eof")
        || text.contains("unexpected EOF")
}

fn request_header_value<'a>(
    request: &'a crate::proxy::mitm_http::ParsedMitmHttpRequest,
    header_name: &str,
) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(header_name))
        .map(|(_, value)| value.as_str())
}

fn request_sec_fetch_mode(
    request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
) -> Option<&str> {
    request_header_value(request, "sec-fetch-mode")
}

fn request_sec_fetch_dest(
    request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
) -> Option<&str> {
    request_header_value(request, "sec-fetch-dest")
}

fn request_accepts_html(request: &crate::proxy::mitm_http::ParsedMitmHttpRequest) -> bool {
    request_header_value(request, "accept")
        .map(|value| value.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

fn request_is_navigation_document(
    request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
) -> bool {
    request_sec_fetch_mode(request)
        .map(|value| value.eq_ignore_ascii_case("navigate"))
        .unwrap_or(false)
        || request_sec_fetch_dest(request)
            .map(|value| value.eq_ignore_ascii_case("document"))
            .unwrap_or(false)
}

fn response_is_html_document(headers: &HeaderMap) -> bool {
    response_content_type_value(headers)
        .map(|value| {
            let lower = value.to_ascii_lowercase();
            lower.contains("text/html") || lower.contains("application/xhtml")
        })
        .unwrap_or(false)
}

fn request_response_is_navigation_document(
    request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
    headers: &HeaderMap,
) -> bool {
    request_is_navigation_document(request)
        || (request_accepts_html(request) && response_is_html_document(headers))
}

fn response_connection_token_present(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|value: &HeaderValue| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|item| item.trim().eq_ignore_ascii_case(token))
}

fn response_has_upgrade(status_code: u16, headers: &HeaderMap) -> bool {
    status_code == 101
        || headers.contains_key("upgrade")
        || response_connection_token_present(headers, "upgrade")
}

fn upstream_requested_connection_close(headers: &HeaderMap) -> bool {
    response_connection_token_present(headers, "close")
}

fn response_content_length_header(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value: &HeaderValue| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn known_streaming_content_length(
    headers: &HeaderMap,
    response_content_length: Option<u64>,
) -> Option<u64> {
    response_content_length.or_else(|| response_content_length_header(headers))
}

fn response_is_no_body(method: &str, status_code: u16) -> bool {
    method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || matches!(status_code, 204 | 304)
}

fn response_content_type_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value: &HeaderValue| value.to_str().ok())
}

fn response_content_type_lower(headers: &HeaderMap) -> String {
    response_content_type_value(headers)
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn response_is_event_stream(headers: &HeaderMap) -> bool {
    response_content_type_lower(headers).contains("text/event-stream")
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MitmResponseBoundary {
    ContentLength,
    BufferedContentLength,
    ChunkedReencoded,
    NoBody,
    EventStream,
    Upgrade,
    Unknown,
}

impl MitmResponseBoundary {
    fn label(self) -> &'static str {
        match self {
            MitmResponseBoundary::ContentLength => "content_length",
            MitmResponseBoundary::BufferedContentLength => "buffered_content_length",
            MitmResponseBoundary::ChunkedReencoded => "chunked_reencoded",
            MitmResponseBoundary::NoBody => "no_body",
            MitmResponseBoundary::EventStream => "event_stream",
            MitmResponseBoundary::Upgrade => "upgrade",
            MitmResponseBoundary::Unknown => "unknown",
        }
    }

    fn body_end_known(self) -> bool {
        matches!(
            self,
            MitmResponseBoundary::ContentLength
                | MitmResponseBoundary::BufferedContentLength
                | MitmResponseBoundary::NoBody
                | MitmResponseBoundary::ChunkedReencoded
        )
    }

    fn allows_keep_alive(self) -> bool {
        self.body_end_known()
    }

    fn rejected_reason(self) -> &'static str {
        match self {
            MitmResponseBoundary::ContentLength
            | MitmResponseBoundary::BufferedContentLength
            | MitmResponseBoundary::NoBody
            | MitmResponseBoundary::ChunkedReencoded => "response_boundary_allows_keep_alive",
            MitmResponseBoundary::EventStream => "event_stream_response_not_keep_alive_safe",
            MitmResponseBoundary::Upgrade => "response_upgrade_not_supported",
            MitmResponseBoundary::Unknown => "response_body_boundary_unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MitmConnectionReuseDecision {
    KeepAlive { reason: &'static str },
    Close { reason: &'static str },
}

impl MitmConnectionReuseDecision {
    fn label(self) -> &'static str {
        match self {
            MitmConnectionReuseDecision::KeepAlive { .. } => "keep_alive",
            MitmConnectionReuseDecision::Close { .. } => "close",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            MitmConnectionReuseDecision::KeepAlive { reason }
            | MitmConnectionReuseDecision::Close { reason } => reason,
        }
    }

    fn keep_alive_allowed(self) -> bool {
        matches!(self, MitmConnectionReuseDecision::KeepAlive { .. })
    }

    fn keep_alive_admission(self) -> bool {
        self.keep_alive_allowed()
    }
}

fn streaming_response_boundary(
    request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
    status_code: u16,
    headers: &HeaderMap,
    response_content_length: Option<u64>,
) -> MitmResponseBoundary {
    if response_has_upgrade(status_code, headers) {
        MitmResponseBoundary::Upgrade
    } else if response_is_no_body(&request.method, status_code) {
        MitmResponseBoundary::NoBody
    } else if response_is_event_stream(headers) {
        MitmResponseBoundary::EventStream
    } else if known_streaming_content_length(headers, response_content_length).is_some() {
        MitmResponseBoundary::ContentLength
    } else {
        // P1-06F2: keep-alive is decided by message framing, not by
        // resource type. If upstream does not expose a Content-Length,
        // RelayGate can still make the downstream body boundary explicit
        // by re-encoding the streaming body as HTTP/1.1 chunked.
        MitmResponseBoundary::ChunkedReencoded
    }
}

fn stream_body_mode_for_boundary(
    response_boundary: MitmResponseBoundary,
    expected_content_length: Option<u64>,
) -> MitmStreamBodyMode {
    match response_boundary {
        MitmResponseBoundary::NoBody => MitmStreamBodyMode::NoBody,
        MitmResponseBoundary::ChunkedReencoded => MitmStreamBodyMode::ChunkedReencoded,
        _ => MitmStreamBodyMode::Raw {
            expected_content_length,
        },
    }
}

fn buffered_response_boundary(
    request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
    status_code: u16,
    headers: &HeaderMap,
) -> MitmResponseBoundary {
    if response_has_upgrade(status_code, headers) {
        MitmResponseBoundary::Upgrade
    } else if response_is_no_body(&request.method, status_code) {
        MitmResponseBoundary::NoBody
    } else if response_is_event_stream(headers) {
        MitmResponseBoundary::EventStream
    } else {
        // DeepPath has a Vec<u8> body and build_https_response_bytes() rebuilds
        // Content-Length, so the downstream body boundary is explicit even for
        // HTML or navigation responses.
        MitmResponseBoundary::BufferedContentLength
    }
}

fn connection_for_reuse_decision(decision: MitmConnectionReuseDecision) -> MitmResponseConnection {
    match decision {
        MitmConnectionReuseDecision::KeepAlive { .. } => MitmResponseConnection::KeepAlive,
        MitmConnectionReuseDecision::Close { .. } => MitmResponseConnection::Close,
    }
}

fn header_map_from_relay_buffered_response(
    response: &RelayUpstreamBufferedResponse,
) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in &response.head.headers {
        if name.starts_with(':') {
            continue;
        }
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid H3 response header name `{name}`"))?;
        let header_value = HeaderValue::from_str(value)
            .with_context(|| format!("invalid H3 response header value for `{name}`"))?;
        headers.append(header_name, header_value);
    }
    Ok(headers)
}

fn status_reason_phrase(status_code: u16) -> &'static str {
    StatusCode::from_u16(status_code)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("OK")
}

fn request_limit_response_bytes(error: http_framing::RequestLimitError) -> Vec<u8> {
    match error {
        http_framing::RequestLimitError::HeaderTooLarge => simple_http_response_bytes(
            431,
            "Request Header Fields Too Large",
            "RelayGate rejected the request because its headers exceed the configured limit.",
        ),
        http_framing::RequestLimitError::PayloadTooLarge => simple_http_response_bytes(
            413,
            "Payload Too Large",
            "RelayGate rejected the request because its body exceeds the configured limit.",
        ),
    }
}

fn response_buffer_limit_response_bytes() -> Vec<u8> {
    simple_http_response_bytes(
        502,
        "Bad Gateway",
        "RelayGate response buffer limit exceeded while preparing rewrite, patch, or injection.",
    )
}

async fn write_local_mitm_response<W>(
    writer: &mut W,
    response: MitmLocalResponse,
    include_body: bool,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match response.body {
        MitmLocalResponseBody::Bytes(body) => {
            if include_body {
                let response_bytes = simple_http_response_bytes_with_content_type(
                    response.status_code,
                    response.reason_phrase,
                    &response.content_type,
                    &body,
                );
                writer.write_all(&response_bytes).await?;
            } else {
                let response_head = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status_code,
                    response.reason_phrase,
                    response.content_type,
                    body.len(),
                );
                writer.write_all(response_head.as_bytes()).await?;
            }
        }
        MitmLocalResponseBody::Resource(replacement) => {
            crate::proxy::local_response::write_resource_replacement_response(
                writer,
                &replacement,
                include_body,
            )
            .await?;
        }
    }
    Ok(())
}

fn websocket_request_target(request_uri: &str) -> String {
    if request_uri.starts_with("http://") || request_uri.starts_with("https://") {
        if let Ok(uri) = request_uri.parse::<Uri>() {
            return uri
                .path_and_query()
                .map(|value| value.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
        }
    }

    if request_uri.is_empty() {
        "/".to_string()
    } else {
        request_uri.to_string()
    }
}

fn upsert_header(headers: &mut Vec<(String, String)>, target_name: &str, target_value: &str) {
    if let Some((_, value)) = headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case(target_name))
    {
        *value = target_value.to_string();
        return;
    }

    headers.push((target_name.to_string(), target_value.to_string()));
}

fn should_forward_websocket_handshake_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "content-length"
            | "expect"
            | "host"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

pub(crate) fn build_mitm_websocket_upstream_request_from_parts(
    authority: &str,
    method: &str,
    request_target: &str,
    prepared_request: &PreparedMitmRequest,
) -> Vec<u8> {
    let mut headers = prepared_request
        .headers
        .iter()
        .filter(|(name, _)| should_forward_websocket_handshake_header(name))
        .cloned()
        .collect::<Vec<_>>();

    for effect in &prepared_request.request_effects {
        if let RuleEffect::RewriteHeader { name, value } = effect {
            if should_apply_request_header_rewrite(name) {
                upsert_header(&mut headers, name, value);
            }
        }
    }

    headers.retain(|(name, _)| should_forward_websocket_handshake_header(name));
    upsert_header(&mut headers, "Host", authority);
    upsert_header(&mut headers, "Connection", "Upgrade");
    upsert_header(&mut headers, "Upgrade", "websocket");

    let mut output = Vec::new();
    output
        .extend_from_slice(format!("{} {} {}\r\n", method, request_target, "HTTP/1.1").as_bytes());
    for (name, value) in headers {
        output.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    output.extend_from_slice(b"\r\n");
    output
}

fn build_mitm_websocket_upstream_request(
    authority: &str,
    request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
    prepared_request: &PreparedMitmRequest,
) -> Vec<u8> {
    build_mitm_websocket_upstream_request_from_parts(
        authority,
        &request.method,
        &websocket_request_target(&request.uri_text),
        prepared_request,
    )
}

fn build_websocket_tls_connector() -> TlsConnector {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
}

fn mitm_upstream_proxy_address(
    upstreams: &SharedUpstreamRegistry,
    intent: &crate::proxy::mitm_upstream::MitmUpstreamRequestIntent,
) -> Result<Option<String>> {
    let Some(upstream_id) = intent.upstream_id.as_deref() else {
        return Ok(None);
    };

    let registry = upstreams
        .read()
        .map_err(|_| anyhow::anyhow!("upstream registry lock poisoned"))?;
    Ok(Some(
        registry
            .resolve(upstream_id)
            .with_context(|| format!("MITM WebSocket references missing upstream `{upstream_id}`"))?
            .address
            .clone(),
    ))
}

fn upstream_proxy_target(address: &str) -> Result<String> {
    let uri = address.parse::<Uri>()?;
    let host = uri
        .host()
        .context("configured upstream proxy is missing host")?;
    let port = uri.port_u16().unwrap_or(80);
    Ok(format!("{host}:{port}"))
}

fn build_upstream_connect_request(authority: &str) -> Vec<u8> {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

async fn connect_mitm_websocket_tcp(
    authority: &str,
    target_host: &str,
    target_port: u16,
    upstream_address: Option<&str>,
    dns_resolver: &SharedDnsResolver,
) -> Result<TcpStream> {
    if let Some(upstream_address) = upstream_address {
        let upstream_target = upstream_proxy_target(upstream_address)?;
        let addresses = resolve_target_addresses(&upstream_target, dns_resolver, true)
            .await
            .with_context(|| format!("failed to resolve upstream proxy `{upstream_target}`"))?;
        let connection = connect_happy_eyeballs(
            &upstream_target,
            addresses,
            MITM_WEBSOCKET_HAPPY_EYEBALLS_DELAY,
        )
        .await
        .with_context(|| format!("failed to connect upstream proxy `{upstream_target}`"))?;
        let mut stream = connection.stream;
        stream
            .write_all(&build_upstream_connect_request(authority))
            .await?;
        let response_head = time::timeout(
            MITM_WEBSOCKET_UPSTREAM_RESPONSE_HEAD_TIMEOUT,
            read_http_response_head(&mut stream),
        )
        .await
        .with_context(|| {
            format!("timed out waiting for upstream CONNECT response for WebSocket {authority}")
        })??;
        let response_meta = parse_http_response_head(&response_head)?;
        if !(200..300).contains(&response_meta.status_code) {
            bail!(
                "upstream proxy failed CONNECT for WebSocket {authority}: HTTP {}",
                response_meta.status_code
            );
        }
        return Ok(stream);
    }

    let target = format!("{target_host}:{target_port}");
    let addresses = resolve_target_addresses(&target, dns_resolver, true).await?;
    let result = connect_happy_eyeballs(
        &target,
        addresses.clone(),
        MITM_WEBSOCKET_HAPPY_EYEBALLS_DELAY,
    )
    .await;
    match &result {
        Ok(connection) => {
            dns_resolver.record_origin_connect_attempt(
                target_host,
                &connection.failed_addrs,
                Some(connection.selected_addr.ip()),
                Some(connection.connect_ms()),
            );
        }
        Err(_) => dns_resolver.record_origin_connect_attempt(target_host, &addresses, None, None),
    }
    let connection =
        result.with_context(|| format!("failed to connect WebSocket upstream `{target}`"))?;
    Ok(connection.stream)
}

async fn read_limited_response_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let mut body = Vec::new();
    loop {
        let next_chunk = time::timeout(MITM_UPSTREAM_BODY_IDLE_TIMEOUT, response.chunk())
            .await
            .context("timed out reading MITM upstream response body")??;
        let Some(chunk) = next_chunk else {
            break;
        };

        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }

    Ok(Some(body))
}

fn debug_mitm_request_body_mode(
    request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
    mode: &str,
    request_body_bytes: usize,
    request_body_limit: usize,
    request_body_limited: bool,
    reason: &str,
) {
    let content_length = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();

    debug!(
        request_body_mode = mode,
        request_body_bytes = request_body_bytes,
        request_body_limit = request_body_limit,
        request_body_limited = request_body_limited,
        method = %request.method,
        content_length = %content_length,
        reason = reason,
        "MITM request body handling decision"
    );
}

async fn send_mitm_content_length_request<S>(
    outbound: reqwest::RequestBuilder,
    client_stream: &mut S,
    content_length: usize,
    prebuffered_body: Vec<u8>,
    expect_100_continue: bool,
    request_body_limit: usize,
    method: &str,
) -> Result<reqwest::Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if content_length > request_body_limit {
        return Err(http_framing::RequestLimitError::PayloadTooLarge.into());
    }

    if expect_100_continue {
        client_stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await?;
    }

    let (body_reader, body_writer) = tokio::io::duplex(MITM_REQUEST_BODY_PIPE_BYTES);
    let body_stream = async_stream::stream! {
        let mut reader = body_reader;
        let mut buffer = vec![0_u8; MITM_STREAM_BUFFER_BYTES];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read_count) => {
                    yield Ok::<Vec<u8>, std::io::Error>(buffer[..read_count].to_vec());
                }
                Err(err) => {
                    yield Err::<Vec<u8>, std::io::Error>(err);
                    break;
                }
            }
        }
    };

    let outbound = outbound
        .header(CONTENT_LENGTH, content_length.to_string())
        .body(Body::wrap_stream(body_stream));
    let send_future = async { outbound.send().await.map_err(anyhow::Error::new) };
    let pump_future = pump_mitm_content_length_request_body(
        client_stream,
        body_writer,
        content_length,
        prebuffered_body,
        request_body_limit,
    );
    let (response, request_body_bytes) = tokio::try_join!(send_future, pump_future)?;

    debug!(
        request_body_mode = "mitm_streaming_content_length",
        request_body_bytes = request_body_bytes,
        request_body_limit = request_body_limit,
        request_body_limited = false,
        method = %method,
        content_length = content_length,
        "streamed MITM Content-Length request body to upstream"
    );

    Ok(response)
}

async fn pump_mitm_content_length_request_body<S>(
    client_stream: &mut S,
    mut body_writer: tokio::io::DuplexStream,
    content_length: usize,
    prebuffered_body: Vec<u8>,
    request_body_limit: usize,
) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    if content_length > request_body_limit || prebuffered_body.len() > content_length {
        return Err(http_framing::RequestLimitError::PayloadTooLarge.into());
    }

    let mut forwarded = 0usize;
    if !prebuffered_body.is_empty() {
        body_writer.write_all(&prebuffered_body).await?;
        forwarded += prebuffered_body.len();
    }

    let mut buffer = vec![0_u8; MITM_STREAM_BUFFER_BYTES];
    while forwarded < content_length {
        let remaining = content_length - forwarded;
        let read_len = remaining.min(buffer.len());
        let read_count = time::timeout(
            MITM_REQUEST_BODY_IDLE_TIMEOUT,
            client_stream.read(&mut buffer[..read_len]),
        )
        .await
        .context("timed out reading MITM streaming request body from client")??;
        if read_count == 0 {
            bail!("client closed before completing MITM streaming request body");
        }
        forwarded += read_count;
        if forwarded > request_body_limit {
            return Err(http_framing::RequestLimitError::PayloadTooLarge.into());
        }
        body_writer.write_all(&buffer[..read_count]).await?;
    }

    body_writer.shutdown().await?;
    Ok(forwarded)
}

async fn send_mitm_chunked_request<S>(
    outbound: reqwest::RequestBuilder,
    client_stream: &mut S,
    prebuffered_body: Vec<u8>,
    expect_100_continue: bool,
    request_read_limits: http_framing::RequestReadLimits,
    method: &str,
) -> Result<reqwest::Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if expect_100_continue {
        client_stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await?;
    }

    let (body_reader, body_writer) = tokio::io::duplex(MITM_REQUEST_BODY_PIPE_BYTES);
    let body_stream = async_stream::stream! {
        let mut reader = body_reader;
        let mut buffer = vec![0_u8; MITM_STREAM_BUFFER_BYTES];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read_count) => {
                    yield Ok::<Vec<u8>, std::io::Error>(buffer[..read_count].to_vec());
                }
                Err(err) => {
                    yield Err::<Vec<u8>, std::io::Error>(err);
                    break;
                }
            }
        }
    };

    let outbound = outbound.body(Body::wrap_stream(body_stream));
    let send_future = async { outbound.send().await.map_err(anyhow::Error::new) };
    let pump_future = pump_mitm_chunked_request_body(
        client_stream,
        body_writer,
        prebuffered_body,
        request_read_limits,
    );
    let (response, stats) = tokio::try_join!(send_future, pump_future)?;

    debug!(
        request_body_mode = "mitm_streaming_chunked",
        request_body_bytes = stats.request_body_bytes,
        request_body_limit = request_read_limits.max_chunked_body_bytes,
        chunk_count = stats.chunk_count,
        trailers_seen = stats.trailers_seen,
        request_body_limited = false,
        method = %method,
        "streamed MITM chunked request body to upstream"
    );

    Ok(response)
}

async fn pump_mitm_chunked_request_body<S>(
    client_stream: &mut S,
    mut body_writer: tokio::io::DuplexStream,
    prebuffered_body: Vec<u8>,
    limits: http_framing::RequestReadLimits,
) -> Result<MitmChunkedRequestBodyStats>
where
    S: AsyncRead + Unpin,
{
    if prebuffered_body.len() > limits.max_chunked_body_bytes {
        return Err(http_framing::RequestLimitError::PayloadTooLarge.into());
    }

    let mut buffer = prebuffered_body;
    let mut stats = MitmChunkedRequestBodyStats::default();

    loop {
        read_until_mitm_chunk_size_line_available(client_stream, &mut buffer).await?;
        let line_end = find_mitm_chunk_line_end(&buffer)
            .context("invalid MITM chunked request body: missing chunk size terminator")?;
        let size_line = std::str::from_utf8(&buffer[..line_end.index])?;
        let chunk_size = parse_mitm_chunk_size_line(size_line)?;
        if stats.request_body_bytes.saturating_add(chunk_size) > limits.max_chunked_body_bytes {
            warn!(
                request_body_mode = "mitm_streaming_chunked",
                request_body_bytes = stats.request_body_bytes,
                request_body_limit = limits.max_chunked_body_bytes,
                chunk_count = stats.chunk_count,
                trailers_seen = stats.trailers_seen,
                request_body_limited = true,
                next_chunk_bytes = chunk_size,
                "MITM chunked request body would exceed configured limit"
            );
            return Err(http_framing::RequestLimitError::PayloadTooLarge.into());
        }

        let size_line_end = line_end.index + line_end.delimiter_len;
        buffer.drain(..size_line_end);

        if chunk_size == 0 {
            let trailers_seen =
                drain_mitm_chunked_trailers(client_stream, &mut buffer, limits).await?;
            stats.trailers_seen = trailers_seen;
            body_writer.shutdown().await?;
            return Ok(stats);
        }

        stream_mitm_exact_chunk_data(
            client_stream,
            &mut body_writer,
            &mut buffer,
            chunk_size,
            &mut stats,
        )
        .await?;
        drain_mitm_chunk_data_terminator(client_stream, &mut buffer).await?;
        stats.chunk_count = stats.chunk_count.saturating_add(1);
    }
}

async fn read_more_mitm_chunked_request_body<S>(
    client_stream: &mut S,
    buffer: &mut Vec<u8>,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut temp = vec![0_u8; MITM_STREAM_BUFFER_BYTES];
    let read_count = time::timeout(
        MITM_REQUEST_BODY_IDLE_TIMEOUT,
        client_stream.read(&mut temp),
    )
    .await
    .context("timed out reading MITM streaming chunked request body from client")??;
    if read_count == 0 {
        bail!("client closed before completing MITM streaming chunked request body");
    }
    buffer.extend_from_slice(&temp[..read_count]);
    Ok(())
}

async fn read_until_mitm_chunk_size_line_available<S>(
    client_stream: &mut S,
    buffer: &mut Vec<u8>,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    while find_mitm_chunk_line_end(buffer).is_none() {
        read_more_mitm_chunked_request_body(client_stream, buffer).await?;
    }
    Ok(())
}

async fn stream_mitm_exact_chunk_data<S>(
    client_stream: &mut S,
    body_writer: &mut tokio::io::DuplexStream,
    buffer: &mut Vec<u8>,
    mut remaining: usize,
    stats: &mut MitmChunkedRequestBodyStats,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    while remaining > 0 {
        if buffer.is_empty() {
            read_more_mitm_chunked_request_body(client_stream, buffer).await?;
        }
        let write_len = remaining.min(buffer.len());
        body_writer.write_all(&buffer[..write_len]).await?;
        buffer.drain(..write_len);
        remaining -= write_len;
        stats.request_body_bytes = stats.request_body_bytes.saturating_add(write_len);
    }
    Ok(())
}

async fn drain_mitm_chunk_data_terminator<S>(
    client_stream: &mut S,
    buffer: &mut Vec<u8>,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    while find_mitm_chunk_line_end(buffer).is_none() {
        read_more_mitm_chunked_request_body(client_stream, buffer).await?;
    }
    let line_end = find_mitm_chunk_line_end(buffer)
        .context("invalid MITM chunked request body: missing chunk data terminator")?;
    if line_end.index != 0 {
        bail!("invalid MITM chunked request body: malformed chunk data terminator");
    }
    let terminator_len = line_end.delimiter_len;
    buffer.drain(..terminator_len);
    Ok(())
}

async fn drain_mitm_chunked_trailers<S>(
    client_stream: &mut S,
    buffer: &mut Vec<u8>,
    limits: http_framing::RequestReadLimits,
) -> Result<bool>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(trailer_end) = mitm_chunked_trailer_end(buffer) {
            let trailers_seen = trailer_end.trailers_seen;
            buffer.drain(..trailer_end.encoded_len);
            return Ok(trailers_seen);
        }

        if buffer.len() > limits.max_header_bytes {
            bail!("MITM chunked request trailers exceed configured header limit");
        }
        read_more_mitm_chunked_request_body(client_stream, buffer).await?;
    }
}

#[derive(Debug, Clone, Copy)]
struct MitmChunkedTrailerEnd {
    encoded_len: usize,
    trailers_seen: bool,
}

fn mitm_chunked_trailer_end(buffer: &[u8]) -> Option<MitmChunkedTrailerEnd> {
    if buffer.starts_with(b"\r\n") {
        return Some(MitmChunkedTrailerEnd {
            encoded_len: 2,
            trailers_seen: false,
        });
    }
    if buffer.starts_with(b"\n") {
        return Some(MitmChunkedTrailerEnd {
            encoded_len: 1,
            trailers_seen: false,
        });
    }

    http_framing::find_header_end(buffer).map(|end| MitmChunkedTrailerEnd {
        encoded_len: end.index + end.delimiter_len,
        trailers_seen: end.index > 0,
    })
}

fn find_mitm_chunk_line_end(bytes: &[u8]) -> Option<http_framing::HeaderEnd> {
    if let Some(index) = bytes.windows(2).position(|window| window == b"\r\n") {
        return Some(http_framing::HeaderEnd {
            index,
            delimiter_len: 2,
        });
    }

    bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|index| http_framing::HeaderEnd {
            index,
            delimiter_len: 1,
        })
}

fn parse_mitm_chunk_size_line(line: &str) -> Result<usize> {
    let size_text = line.split(';').next().unwrap_or_default().trim();
    if size_text.is_empty() {
        bail!("invalid MITM chunked request body: empty chunk size");
    }
    usize::from_str_radix(size_text, 16)
        .context("invalid MITM chunked request body: invalid chunk size")
}

impl MitmEngine {
    pub(crate) fn new(
        config: Arc<RelayGateConfig>,
        rules: RuleEngine,
        upstreams: SharedUpstreamRegistry,
        resource_replace_registry: SharedResourceReplaceRegistry,
        rewrite_registry: SharedRewriteRegistry,
        adblock_state: SharedAdblockState,
        traffic_state: SharedTrafficState,
        dns_resolver: SharedDnsResolver,
        user_script_registry: SharedUserScriptRegistry,
        protocol_runtime: ProtocolRuntimeConfig,
    ) -> Self {
        Self {
            config,
            rules,
            upstreams,
            resource_replace_registry,
            rewrite_registry,
            adblock_state,
            traffic_state,
            dns_resolver,
            user_script_registry,
            protocol_runtime,
            cert_cache: Arc::new(Mutex::new(MitmLeafCertCache::default())),
            http_client_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn mitm_request_state(&self) -> MitmRequestState<'_> {
        let protocol_snapshot = self.protocol_snapshot();
        MitmRequestState {
            rules: &self.rules,
            upstreams: &self.upstreams,
            resource_replace_registry: &self.resource_replace_registry,
            adblock_state: &self.adblock_state,
            traffic_state: &self.traffic_state,
            upstream_protocol_policy: protocol_snapshot.upstream_protocol_policy,
        }
    }

    pub(crate) fn protocol_snapshot(&self) -> ProtocolRuntimeSnapshot {
        self.protocol_runtime.snapshot()
    }

    pub(crate) fn mitm_response_state(&self) -> MitmResponseState<'_> {
        MitmResponseState {
            config: self.config.as_ref(),
            rewrite_registry: &self.rewrite_registry,
            adblock_state: &self.adblock_state,
            user_script_registry: &self.user_script_registry,
        }
    }

    pub(crate) fn traffic_state(&self) -> &SharedTrafficState {
        &self.traffic_state
    }

    pub(crate) fn dns_resolver(&self) -> &SharedDnsResolver {
        &self.dns_resolver
    }

    pub(crate) fn status_endpoint_enabled(&self) -> bool {
        self.config.proxy.mitm.enabled
    }

    pub(crate) fn evaluate_mitm_response_rules(
        &self,
        context: &RuleResponseContext,
    ) -> crate::proxy::rules::RuleDecision {
        self.rules.evaluate_response(context)
    }

    /// Check whether MITM is enabled.
    pub fn enabled(&self) -> bool {
        adblock::is_enabled(&self.adblock_state)
            || self
                .resource_replace_registry
                .read()
                .map(|registry| registry.enabled_rule_count() > 0)
                .unwrap_or(false)
            || self
                .rewrite_registry
                .read()
                .map(|registry| registry.rule_count() > 0)
                .unwrap_or(false)
    }

    pub fn should_intercept_host(&self, authority_or_host: &str) -> bool {
        if mitm_passthrough_host_matches(
            authority_or_host,
            &self.config.proxy.mitm.passthrough_hosts,
        ) {
            debug!(
                authority = authority_or_host,
                "CONNECT host matched MITM passthrough list"
            );
            return false;
        }

        if adblock::is_enabled(&self.adblock_state) {
            return true;
        }

        if self
            .resource_replace_registry
            .read()
            .map(|registry| registry.should_mitm_host(authority_or_host))
            .unwrap_or(false)
        {
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

        let protocol_snapshot = self.protocol_snapshot();
        let downstream_http2_enabled = protocol_snapshot.downstream_http2_enabled;
        let tls_acceptor = build_tls_acceptor(&preparation.leaf, downstream_http2_enabled)?;
        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
            .await?;

        let mut tls_stream = tls_acceptor
            .accept(client_stream)
            .await
            .context("failed to accept TLS from client during MITM handshake")?;

        let negotiated_alpn = tls_stream
            .get_ref()
            .1
            .alpn_protocol()
            .map(|protocol| protocol.to_vec());
        let negotiated_alpn_label = negotiated_alpn
            .as_deref()
            .and_then(|protocol| std::str::from_utf8(protocol).ok())
            .unwrap_or("none");
        debug!(
            authority = authority,
            downstream_http2_enabled = downstream_http2_enabled,
            downstream_preference = ?protocol_snapshot.downstream_preference,
            negotiated_alpn = negotiated_alpn_label,
            "MITM downstream TLS ALPN negotiated"
        );

        if negotiated_alpn.as_deref() == Some(b"h2") {
            crate::proxy::mitm_h2::handle_mitm_h2_connection(
                self.clone(),
                tls_stream,
                authority.to_string(),
                preparation.leaf.host.clone(),
            )
            .await?;
            return Ok(());
        }

        if !self.config.proxy.mitm.keep_alive {
            let outcome = self
                .handle_one_mitm_request(
                    &mut tls_stream,
                    authority,
                    &preparation,
                    total_started_at,
                    false,
                    1,
                    negotiated_alpn_label,
                )
                .await?;
            debug_mitm_loop_action(false, 1, outcome, "close", "keep_alive_disabled");
            tls_stream.shutdown().await?;
            return Ok(());
        }

        for request_index in 1..=self.config.proxy.mitm.max_requests_per_connection {
            let outcome = self
                .handle_one_mitm_request(
                    &mut tls_stream,
                    authority,
                    &preparation,
                    std::time::Instant::now(),
                    true,
                    request_index,
                    negotiated_alpn_label,
                )
                .await?;

            match outcome {
                MitmRequestOutcome::ContinueEligible
                    if request_index < self.config.proxy.mitm.max_requests_per_connection =>
                {
                    debug_mitm_loop_action(
                        true,
                        request_index,
                        outcome,
                        "continue",
                        "continue_eligible",
                    );
                    continue;
                }
                MitmRequestOutcome::ContinueEligible => {
                    debug_mitm_loop_action(
                        true,
                        request_index,
                        outcome,
                        "max_requests_reached",
                        "max_requests_reached",
                    );
                    break;
                }
                MitmRequestOutcome::Close => {
                    debug_mitm_loop_action(
                        true,
                        request_index,
                        outcome,
                        "close",
                        "request_outcome_close",
                    );
                    break;
                }
                MitmRequestOutcome::ClientClosed => {
                    debug_mitm_loop_action(
                        true,
                        request_index,
                        outcome,
                        "client_closed",
                        "client_closed",
                    );
                    break;
                }
            }
        }

        tls_stream.shutdown().await?;
        Ok(())
    }

    async fn handle_one_mitm_request(
        &self,
        tls_stream: &mut tokio_rustls::server::TlsStream<&mut TcpStream>,
        authority: &str,
        preparation: &MitmPreparation,
        total_started_at: std::time::Instant,
        mitm_keep_alive: bool,
        mitm_request_index: usize,
        negotiated_alpn_label: &str,
    ) -> Result<MitmRequestOutcome> {
        let mut request_method: Option<String> = None;
        let mut request_url: Option<String> = None;

        macro_rules! close_request {
            ($reason:expr) => {{
                debug_mitm_request_outcome(
                    MitmRequestOutcome::Close,
                    $reason,
                    request_method.as_deref(),
                    request_url.as_deref(),
                    mitm_keep_alive,
                    mitm_request_index,
                );
                return Ok(MitmRequestOutcome::Close);
            }};
        }

        macro_rules! client_closed {
            ($reason:expr) => {{
                debug_mitm_request_outcome(
                    MitmRequestOutcome::ClientClosed,
                    $reason,
                    request_method.as_deref(),
                    request_url.as_deref(),
                    mitm_keep_alive,
                    mitm_request_index,
                );
                return Ok(MitmRequestOutcome::ClientClosed);
            }};
        }

        let request_head = match http_framing::read_http_request_head_limited(
            tls_stream,
            self.request_read_limits(),
        )
        .await
        {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                client_closed!("client_closed_before_request")
            }
            Err(error) => {
                if let Some(limit_error) = error.downcast_ref::<http_framing::RequestLimitError>() {
                    let response = request_limit_response_bytes(*limit_error);
                    tls_stream.write_all(&response).await?;
                    close_request!("request_limit_error");
                }
                return Err(error);
            }
        };

        let request = parse_http_request(&request_head.head_bytes)?;
        request_method = Some(request.method.clone());
        let target_url = build_https_target_url(authority, &request)?;
        request_url = Some(target_url.clone());
        debug!(authority = authority, url = %target_url, "MITM decrypted HTTPS request");
        downstream_status::record_mitm_request(
            DownstreamStatusProtocol::MitmHttp1,
            authority,
            &target_url,
            negotiated_alpn_label,
        );

        if downstream_status::is_downstream_status_url(&target_url) {
            let response = downstream_status::mitm_status_response(
                DownstreamStatusProtocol::MitmHttp1,
                self.config.as_ref(),
                authority,
                &target_url,
                negotiated_alpn_label,
            );
            write_local_mitm_response(
                tls_stream,
                response,
                !request.method.eq_ignore_ascii_case("HEAD"),
            )
            .await?;
            close_request!("relaygate_downstream_status");
        }

        let prepared_request = match prepare_mitm_request(
            &self.mitm_request_state(),
            &preparation.leaf.host,
            target_url.clone(),
            request.method.clone(),
            request.headers.clone(),
        )? {
            MitmRequestDecision::Continue(prepared_request) => prepared_request,
            MitmRequestDecision::Respond { response, reason } => {
                write_local_mitm_response(
                    tls_stream,
                    response,
                    !request.method.eq_ignore_ascii_case("HEAD"),
                )
                .await?;
                close_request!(reason);
            }
            MitmRequestDecision::Close { reason } => {
                close_request!(reason);
            }
        };
        let request_type = prepared_request.request_type.as_str();
        let source_url = prepared_request.source_url.clone();
        let fetch_site = prepared_request.fetch_site.clone();

        if request_is_websocket_upgrade(&request) {
            if !matches!(request_head.body_kind, http_framing::RequestBodyKind::None) {
                let response = simple_http_response_bytes(
                    400,
                    "Bad Request",
                    "RelayGate rejected WebSocket upgrade with a request body.",
                );
                tls_stream.write_all(&response).await?;
                close_request!("websocket_upgrade_with_request_body");
            }

            if let Err(error) = self
                .handle_mitm_websocket_upgrade(
                    tls_stream,
                    authority,
                    &preparation.leaf.host,
                    &request,
                    &prepared_request,
                )
                .await
            {
                let _ = diagnostics::append_proxy_diagnostic(&format!(
                    "{} event=mitm_websocket_failed authority={} url={} error_chain={}",
                    diagnostics::diagnostic_timestamp(),
                    authority,
                    target_url,
                    diagnostics::format_error_chain(&error)
                ));
                return Err(error);
            }
            close_request!("websocket_upgrade_tunnel_closed");
        }

        let request_body_mode = match request_head.body_kind {
            http_framing::RequestBodyKind::None => {
                debug_mitm_request_body_mode(
                    &request,
                    "none",
                    0,
                    self.config.limits.max_request_body_bytes,
                    false,
                    "no_request_body",
                );
                MitmRequestBodyForwardMode::None
            }
            http_framing::RequestBodyKind::ContentLength(content_length) => {
                debug_mitm_request_body_mode(
                    &request,
                    "mitm_streaming_content_length",
                    content_length,
                    self.config.limits.max_request_body_bytes,
                    false,
                    "content_length_streaming_after_request_decision",
                );
                MitmRequestBodyForwardMode::StreamingContentLength {
                    content_length,
                    prebuffered_body: request_head.prebuffered_body.clone(),
                    expect_100_continue: request_head.expect_100_continue,
                }
            }
            http_framing::RequestBodyKind::Chunked => {
                debug_mitm_request_body_mode(
                    &request,
                    "mitm_streaming_chunked",
                    request_head.prebuffered_body.len(),
                    self.config.limits.max_chunked_body_bytes,
                    false,
                    "chunked_streaming_after_request_decision",
                );
                MitmRequestBodyForwardMode::StreamingChunked {
                    prebuffered_body: request_head.prebuffered_body.clone(),
                    expect_100_continue: request_head.expect_100_continue,
                }
            }
        };

        let target_url = prepared_request.target_url.clone();
        let upstream = prepared_request.upstream.clone();
        let traffic_host = prepared_request.traffic_host.clone();
        let observe_traffic = prepared_request.observe_traffic;

        for attempt in 0..=self.config.traffic.internal_retry_limit {
            let traffic_action = self.traffic_state.action_for_request(
                &traffic_host,
                &prepared_request.method,
                request_type,
                &self.config.traffic,
            );
            let mut observed_permit =
                if observe_traffic && matches!(traffic_action, TrafficAction::Bypass) {
                    self.traffic_state.begin_observed_request(&traffic_host)
                } else {
                    None
                };
            let mut traffic_permit = match traffic_action {
                TrafficAction::Managed => Some(
                    self.traffic_state
                        .acquire(&traffic_host, &self.config.traffic)
                        .await?,
                ),
                TrafficAction::Bypass => None,
            };
            let allow_invalid_upstream_certs =
                self.should_tolerate_invalid_upstream_cert(&preparation.leaf.host);
            let h3_request_body_is_empty =
                matches!(&request_body_mode, MitmRequestBodyForwardMode::None)
                    && request.body.is_empty();

            let protocol_snapshot = self.protocol_snapshot();
            let h3_direct_path_allowed = h3_active_direct_path_allowed(&prepared_request.upstream);
            let response_state = self.mitm_response_state();
            let browser_storage_access_request =
                has_browser_storage_access_header(&prepared_request.headers);
            let response_rule_preview = self.evaluate_mitm_response_rules(&RuleResponseContext {
                url: target_url.clone(),
                status_code: 0,
                headers: Vec::new(),
                body_preview: None,
            });
            let body_pipeline_preflight_reason = response_body_pipeline_preflight_reason(
                &response_state,
                &target_url,
                request_type,
                &response_rule_preview.effects,
            );
            if h3_direct_path_allowed
                && protocol_snapshot.upstream_http3_buffered_enabled
                && !browser_storage_access_request
                && allow_active_h3_buffered_for_request(
                    &response_state,
                    request_type,
                    body_pipeline_preflight_reason,
                )
            {
                if let Some(h3_result) = self
                    .upstream_connector()
                    .try_http3_buffered_response_for_mitm_parts(
                        true,
                        &prepared_request.method,
                        &target_url,
                        &prepared_request.traffic_host,
                        &prepared_request.headers,
                        &prepared_request.request_effects,
                        h3_request_body_is_empty,
                    )
                    .await
                {
                    match h3_result {
                        Ok(h3_response) => {
                            let status_code = h3_response.status_code();
                            let response_headers =
                                header_map_from_relay_buffered_response(&h3_response)?;
                            let response_header_pairs =
                                header_pairs_from_reqwest(&response_headers);

                            if status_code == 429
                                && self.traffic_state.is_controlled_host(&traffic_host)
                                && prepared_request.method.eq_ignore_ascii_case("GET")
                                && request_type == "document"
                            {
                                let h3_candidate = upstream_h3::active_candidate_for_authority(
                                    &prepared_request.traffic_host,
                                );
                                upstream_h3::record_http3_active_buffered_fallback(
                                    "h1",
                                    &prepared_request.traffic_host,
                                    h3_candidate.as_ref(),
                                    Some(status_code),
                                    Some(response_headers.len()),
                                    Some(h3_response.body.len()),
                                    "traffic_control_429",
                                    "deferred to reqwest path so existing traffic-control 429 handling can run",
                                );
                                debug!(
                                    status = status_code,
                                    url = %target_url,
                                    "MITM active H3 buffered response deferred to reqwest path for traffic-control 429 handling"
                                );
                            } else {
                                let response_context = RuleResponseContext {
                                    url: target_url.clone(),
                                    status_code,
                                    headers: response_header_pairs,
                                    body_preview: None,
                                };
                                let response_decision =
                                    self.rules.evaluate_response(&response_context);
                                let pipeline_route = self.response_pipeline_decision(
                                    &response_context.url,
                                    request_type,
                                    status_code,
                                    &response_headers,
                                    &response_decision.effects,
                                );

                                if pipeline_route.is_fast_path() {
                                    if matches!(traffic_action, TrafficAction::Managed) {
                                        self.traffic_state
                                            .on_success(&traffic_host, &self.config.traffic);
                                    }

                                    let response_boundary = buffered_response_boundary(
                                        &request,
                                        status_code,
                                        &response_headers,
                                    );
                                    let reuse_decision = self.decide_mitm_connection_reuse(
                                        &request,
                                        response_boundary,
                                        upstream_requested_connection_close(&response_headers),
                                        request_response_is_navigation_document(
                                            &request,
                                            &response_headers,
                                        ),
                                    );
                                    let response_connection =
                                        connection_for_reuse_decision(reuse_decision);
                                    let body_len = h3_response.body.len();
                                    let response_bytes = build_https_response_bytes(
                                        status_code,
                                        status_reason_phrase(status_code),
                                        &response_headers,
                                        h3_response.body.clone(),
                                        response_connection,
                                    );
                                    tls_stream.write_all(&response_bytes).await?;
                                    tls_stream.flush().await?;
                                    let body_completion = if matches!(
                                        response_boundary,
                                        MitmResponseBoundary::NoBody
                                    ) {
                                        MitmBodyCompletion::CompleteNoBody
                                    } else {
                                        MitmBodyCompletion::CompleteBufferedContentLength {
                                            bytes: body_len,
                                        }
                                    };
                                    let (outcome, reason) = self
                                        .mitm_response_outcome_after_body_completion(
                                            &request,
                                            &response_context.url,
                                            mitm_request_index,
                                            status_code,
                                            response_boundary,
                                            reuse_decision,
                                            body_completion,
                                            "h3_buffered_response_written",
                                        );
                                    drop(observed_permit.take());
                                    drop(traffic_permit.take());
                                    let h3_candidate = upstream_h3::active_candidate_for_authority(
                                        &prepared_request.traffic_host,
                                    );
                                    upstream_h3::record_http3_active_buffered_served(
                                        "h1",
                                        &prepared_request.traffic_host,
                                        h3_candidate.as_ref(),
                                        status_code,
                                        response_headers.len(),
                                        body_len,
                                    );
                                    debug!(
                                        status = status_code,
                                        body_bytes = body_len,
                                        url = %response_context.url,
                                        "MITM active H3 buffered response written; skipping reqwest path"
                                    );
                                    debug_mitm_request_outcome(
                                        outcome,
                                        reason,
                                        request_method.as_deref(),
                                        request_url.as_deref(),
                                        mitm_keep_alive,
                                        mitm_request_index,
                                    );
                                    return Ok(outcome);
                                }

                                let h3_candidate = upstream_h3::active_candidate_for_authority(
                                    &prepared_request.traffic_host,
                                );
                                upstream_h3::record_http3_active_buffered_fallback(
                                    "h1",
                                    &prepared_request.traffic_host,
                                    h3_candidate.as_ref(),
                                    Some(status_code),
                                    Some(response_headers.len()),
                                    Some(h3_response.body.len()),
                                    "deep_pipeline_required",
                                    format!(
                                        "{} — {}",
                                        pipeline_route.pipeline_label(),
                                        pipeline_route.reason
                                    ),
                                );
                                debug!(
                                    pipeline = %pipeline_route.pipeline_label(),
                                    reason = %pipeline_route.reason,
                                    status = status_code,
                                    url = %response_context.url,
                                    "MITM active H3 buffered response deferred to reqwest path because response needs deep pipeline"
                                );
                            }
                        }
                        Err(h3_probe) => {
                            let reason_code = h3_probe
                                .fallback_error
                                .as_ref()
                                .map(|error| error.kind.code())
                                .unwrap_or("not_buffered_response");
                            let reason_detail = h3_probe
                                .fallback_error
                                .as_ref()
                                .map(|error| error.detail.clone())
                                .unwrap_or_else(|| {
                                    "H3 active buffered path did not produce a forwardable buffered response"
                                        .to_string()
                                });
                            upstream_h3::record_http3_active_buffered_fallback(
                                "h1",
                                &h3_probe.authority,
                                h3_probe.attempt_plan.h3_candidate.as_ref(),
                                None,
                                None,
                                None,
                                reason_code,
                                reason_detail,
                            );
                            debug!(
                                authority = %h3_probe.authority,
                                decision = h3_probe.decision_label(),
                                fallback = h3_probe.fallback_label(),
                                error = h3_probe.fallback_error_code().unwrap_or("none"),
                                "MITM active H3 buffered response unavailable; continuing reqwest path"
                            );
                        }
                    }
                }
            }

            // Guardrail for the current H1 baseline, not a prohibition on future
            // H1/H3 streaming support: the writer-plan probe can send an upstream
            // H3 request, but the H1 downstream byte pump is not wired yet. Falling
            // through into the stable reqwest path afterwards could duplicate safe
            // upstream requests. Keep H1 on the buffered H3 path or stable fallback
            // until a real end-to-end H1 streaming writer owns both the upstream
            // response and downstream byte pump.

            if h3_direct_path_allowed
                && !protocol_snapshot.upstream_http3_buffered_enabled
                && !protocol_snapshot.upstream_http3_streaming_enabled
                && protocol_snapshot.upstream_http3_probe_enabled
            {
                if let Some(h3_probe) = self
                    .upstream_connector()
                    .probe_http3_for_mitm_parts(
                        true,
                        &prepared_request.method,
                        &target_url,
                        &prepared_request.traffic_host,
                        &prepared_request.headers,
                        &prepared_request.request_effects,
                        h3_request_body_is_empty,
                    )
                    .await
                {
                    debug!(
                        authority = %h3_probe.authority,
                        decision = h3_probe.decision_label(),
                        fallback = h3_probe.fallback_label(),
                        error = h3_probe.fallback_error_code().unwrap_or("none"),
                        "MITM upstream H3 forwarding probe completed; continuing reqwest path"
                    );
                }
            }
            let client = self
                .upstream_connector()
                .client_for_request(&upstream, allow_invalid_upstream_certs)?;
            let mut outbound = client.request(
                reqwest::Method::from_bytes(prepared_request.method.as_bytes())?,
                &target_url,
            );

            let connection_tokens = connection_header_tokens(&prepared_request.headers);
            for (name, value) in &prepared_request.headers {
                if should_forward_request_header(name, &connection_tokens) {
                    outbound = outbound.header(name, value);
                }
            }

            for effect in &prepared_request.request_effects {
                if let RuleEffect::RewriteHeader { name, value } = effect {
                    if should_apply_request_header_rewrite(name) {
                        outbound = outbound.header(name, value);
                    }
                }
            }

            outbound = outbound.header(
                ACCEPT_ENCODING,
                crate::proxy::mount_forward::relaygate_body_pipeline_accept_encoding(),
            );

            if !request.body.is_empty() {
                outbound = outbound.body(request.body.clone());
            }

            let upstream_started_at = std::time::Instant::now();
            let upstream_response_result: Result<reqwest::Response> = match &request_body_mode {
                MitmRequestBodyForwardMode::StreamingContentLength {
                    content_length,
                    prebuffered_body,
                    expect_100_continue,
                } => {
                    send_mitm_content_length_request(
                        outbound,
                        tls_stream,
                        *content_length,
                        prebuffered_body.clone(),
                        *expect_100_continue,
                        self.config.limits.max_request_body_bytes,
                        &prepared_request.method,
                    )
                    .await
                }
                MitmRequestBodyForwardMode::StreamingChunked {
                    prebuffered_body,
                    expect_100_continue,
                } => {
                    send_mitm_chunked_request(
                        outbound,
                        tls_stream,
                        prebuffered_body.clone(),
                        *expect_100_continue,
                        self.request_read_limits(),
                        &prepared_request.method,
                    )
                    .await
                }
                MitmRequestBodyForwardMode::None => {
                    outbound.send().await.map_err(anyhow::Error::new)
                }
            };
            let upstream_response: reqwest::Response = match upstream_response_result {
                Ok(response) => response,
                Err(error) => {
                    if let Some(limit_error) =
                        error.downcast_ref::<http_framing::RequestLimitError>()
                    {
                        let request_body_limit = match &request_body_mode {
                            MitmRequestBodyForwardMode::StreamingChunked { .. } => {
                                self.config.limits.max_chunked_body_bytes
                            }
                            _ => self.config.limits.max_request_body_bytes,
                        };
                        warn!(
                            request_body_mode = request_body_mode.label(),
                            request_body_bytes = 0usize,
                            request_body_limit = request_body_limit,
                            request_body_limited = true,
                            method = %request.method,
                            error = %limit_error,
                            "MITM streaming request body exceeded limit after upstream send started; closing connection"
                        );
                        let _ = diagnostics::append_proxy_diagnostic(&format!(
                            "{} event=mitm_request_body_limit url={} method={} body_mode={} limit={} error={}",
                            diagnostics::diagnostic_timestamp(),
                            target_url,
                            request.method,
                            request_body_mode.label(),
                            request_body_limit,
                            limit_error
                        ));
                        close_request!("streaming_request_body_limit_error");
                    }

                    if let Some(reqwest_error) = error.downcast_ref::<reqwest::Error>() {
                        if is_upstream_certificate_error(reqwest_error)
                            && !allow_invalid_upstream_certs
                        {
                            let response =
                                upstream_tls_failure_response(&preparation.leaf.host, &target_url);
                            tls_stream.write_all(&response).await?;
                            close_request!("upstream_tls_failure_response");
                        }
                    }

                    if observe_traffic {
                        self.traffic_state.on_fatal_error(&traffic_host);
                    }
                    let _ = diagnostics::append_proxy_diagnostic(&format!(
                        "{} event=mitm_upstream_request_failed url={} method={} body_mode={} error_chain={}",
                        diagnostics::diagnostic_timestamp(),
                        target_url,
                        request.method,
                        request_body_mode.label(),
                        diagnostics::format_error_chain(&error)
                    ));
                    return Err(error);
                }
            };
            if upstream.upstream_id.is_none() {
                if let Some(remote_addr) = upstream_response.remote_addr() {
                    self.dns_resolver.record_origin_connect_success_observed(
                        &prepared_request.traffic_host,
                        remote_addr.ip(),
                    );
                }
            }

            downstream_status::record_upstream_response(
                &prepared_request.traffic_host,
                &target_url,
                upstream_response.version(),
                protocol_snapshot.upstream_protocol_policy_config,
            );
            downstream_status::record_upstream_alt_svc(
                &prepared_request.traffic_host,
                upstream_response.headers(),
            );
            let fetch_headers_ms = upstream_started_at.elapsed().as_millis();
            let status = upstream_response.status();
            let mut response_headers: HeaderMap = upstream_response.headers().clone();
            let response_header_pairs = header_pairs_from_reqwest(&response_headers);
            let response_context = RuleResponseContext {
                url: target_url.clone(),
                status_code: status.as_u16(),
                headers: response_header_pairs.clone(),
                body_preview: None,
            };
            let response_decision = self.rules.evaluate_response(&response_context);

            if status.as_u16() == 429
                && self.traffic_state.is_controlled_host(&traffic_host)
                && prepared_request.method.eq_ignore_ascii_case("GET")
                && request_type == "document"
            {
                let retry_after = traffic::parse_retry_after_secs(&response_header_pairs);
                drop(observed_permit.take());
                drop(traffic_permit.take());
                match self.traffic_state.decide_429_response(
                    &traffic_host,
                    attempt,
                    retry_after,
                    &self.config.traffic,
                ) {
                    TrafficResponseDecision::RetryAfterDelay(delay) => {
                        self.traffic_state.begin_retry_wait(&traffic_host);
                        time::sleep(delay).await;
                        self.traffic_state.end_retry_wait(&traffic_host);
                        continue;
                    }
                    TrafficResponseDecision::ReloadPage(delay) => {
                        let response = traffic::reload_page_response(delay, &target_url);
                        tls_stream.write_all(&response).await?;
                        close_request!("traffic_reload_page");
                    }
                    TrafficResponseDecision::Forward => {}
                }
            } else if matches!(traffic_action, TrafficAction::Managed) {
                self.traffic_state
                    .on_success(&traffic_host, &self.config.traffic);
            }

            let pipeline_route = self.response_pipeline_decision(
                &response_context.url,
                request_type,
                status.as_u16(),
                &response_headers,
                &response_decision.effects,
            );
            let response_content_type = response_content_type_lower(&response_headers);
            let upstream_content_length = upstream_response.content_length();
            debug!(
                pipeline = %pipeline_route.pipeline_label(),
                reason = %pipeline_route.reason,
                request_type = %request_type,
                content_type = %response_content_type,
                status = status.as_u16(),
                url = %response_context.url,
                "MITM response pipeline decision"
            );

            if pipeline_route.is_fast_path() {
                let response_boundary = streaming_response_boundary(
                    &request,
                    status.as_u16(),
                    &response_headers,
                    upstream_content_length,
                );
                let reuse_decision = self.decide_mitm_connection_reuse(
                    &request,
                    response_boundary,
                    upstream_requested_connection_close(&response_headers),
                    request_response_is_navigation_document(&request, &response_headers),
                );
                let response_connection = connection_for_reuse_decision(reuse_decision);
                let stream_body_mode = stream_body_mode_for_boundary(
                    response_boundary,
                    known_streaming_content_length(&response_headers, upstream_content_length),
                );
                debug!(
                    mitm_connection_header = response_connection.tracing_label(),
                    response_boundary = response_boundary.label(),
                    body_end_known = response_boundary.body_end_known(),
                    keep_alive_allowed = reuse_decision.keep_alive_allowed(),
                    keep_alive_rejected_reason = if reuse_decision.keep_alive_allowed() { "" } else { reuse_decision.reason() },
                    reencode_chunked = stream_body_mode.reencode_chunked(),
                    sec_fetch_mode = ?request_sec_fetch_mode(&request),
                    sec_fetch_dest = ?request_sec_fetch_dest(&request),
                    navigation_request = request_is_navigation_document(&request),
                    document_response = response_is_html_document(&response_headers),
                    content_length = ?known_streaming_content_length(&response_headers, upstream_content_length),
                    transfer_encoding = ?response_headers.get("transfer-encoding").and_then(|value: &HeaderValue| value.to_str().ok()),
                    content_type = ?response_headers.get(CONTENT_TYPE).and_then(|value: &HeaderValue| value.to_str().ok()),
                    reason = reuse_decision.reason(),
                    method = %request.method,
                    status = status.as_u16(),
                    url = %response_context.url,
                    "MITM response connection decision"
                );
                let body_completion = stream_https_response(
                    tls_stream,
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("OK"),
                    &response_context.url,
                    request_type,
                    &response_headers,
                    upstream_response,
                    response_connection,
                    stream_body_mode,
                    known_streaming_content_length(&response_headers, upstream_content_length),
                )
                .await
                .map_err(|error| {
                    record_adaptive_stream_failure(&response_context.url);
                    let _ = diagnostics::append_proxy_diagnostic(&format!(
                        "{} event=mitm_response_stream_failed url={} method={} status={} error_chain={}",
                        diagnostics::diagnostic_timestamp(),
                        response_context.url,
                        request.method,
                        status.as_u16(),
                        diagnostics::format_error_chain(&error)
                    ));
                    error
                })?;
                let (outcome, reason) = self.mitm_response_outcome_after_body_completion(
                    &request,
                    &response_context.url,
                    mitm_request_index,
                    status.as_u16(),
                    response_boundary,
                    reuse_decision,
                    body_completion,
                    "fast_path_response_written",
                );
                drop(observed_permit.take());
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
                debug_mitm_request_outcome(
                    outcome,
                    reason,
                    request_method.as_deref(),
                    request_url.as_deref(),
                    mitm_keep_alive,
                    mitm_request_index,
                );
                return Ok(outcome);
            }

            if !response_is_no_body(&request.method, status.as_u16())
                && upstream_content_length.is_some_and(|length| {
                    length > self.config.limits.max_response_buffer_bytes as u64
                })
            {
                warn!(
                    pipeline = %PipelineDecision::Block.as_str(),
                    reason = "response_buffer_limit_content_length_blocked",
                    request_type = %request_type,
                    content_type = %response_content_type,
                    url = %response_context.url,
                    limit = self.config.limits.max_response_buffer_bytes,
                    "MITM response body exceeds buffer limit while deep response pipeline is required"
                );
                let response = response_buffer_limit_response_bytes();
                tls_stream.write_all(&response).await?;
                drop(observed_permit.take());
                close_request!("response_buffer_limit_content_length");
            }

            let buffer_started_at = std::time::Instant::now();
            let response_body = match read_limited_response_body(
                upstream_response,
                self.config.limits.max_response_buffer_bytes,
            )
            .await
            .map_err(|error| {
                if observe_traffic {
                    self.traffic_state.on_fatal_error(&traffic_host);
                }
                anyhow::Error::from(error)
            })? {
                Some(body) => body,
                None => {
                    warn!(
                        pipeline = %PipelineDecision::Block.as_str(),
                        reason = "response_buffer_limit_exceeded_after_buffering",
                        request_type = %request_type,
                        content_type = %response_content_type,
                        url = %response_context.url,
                        limit = self.config.limits.max_response_buffer_bytes,
                        "MITM response body exceeded buffer limit after buffering started"
                    );
                    let response = response_buffer_limit_response_bytes();
                    tls_stream.write_all(&response).await?;
                    drop(observed_permit.take());
                    close_request!("response_buffer_limit_exceeded");
                }
            };
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
            let processed_response = process_mitm_response_body(
                &self.mitm_response_state(),
                &response_context.url,
                &source_url,
                request_type,
                fetch_site.as_deref(),
                &mut response_headers,
                response_body,
                &response_decision.effects,
            )
            .await
            .with_context(|| {
                format!(
                    "failed to process MITM response body for {}",
                    response_context.url
                )
            })?;
            let response_body = processed_response.body;
            let rewrite_perf = processed_response.rewrite_perf;
            if self.config.logging.log_response_body {
                log_response_body(
                    "mitm",
                    &response_context.url,
                    response_headers
                        .get("content-type")
                        .and_then(|value: &HeaderValue| value.to_str().ok()),
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
            let buffered_response_body_len = response_body.len();
            let response_boundary =
                buffered_response_boundary(&request, status.as_u16(), &response_headers);
            let reuse_decision = self.decide_mitm_connection_reuse(
                &request,
                response_boundary,
                upstream_requested_connection_close(&response_headers),
                request_response_is_navigation_document(&request, &response_headers),
            );
            let response_connection = connection_for_reuse_decision(reuse_decision);
            debug!(
                mitm_connection_header = response_connection.tracing_label(),
                response_boundary = response_boundary.label(),
                body_end_known = response_boundary.body_end_known(),
                keep_alive_allowed = reuse_decision.keep_alive_allowed(),
                keep_alive_rejected_reason = if reuse_decision.keep_alive_allowed() { "" } else { reuse_decision.reason() },
                sec_fetch_mode = ?request_sec_fetch_mode(&request),
                sec_fetch_dest = ?request_sec_fetch_dest(&request),
                navigation_request = request_is_navigation_document(&request),
                document_response = response_is_html_document(&response_headers),
                content_length = buffered_response_body_len,
                transfer_encoding = ?response_headers.get("transfer-encoding").and_then(|value: &HeaderValue| value.to_str().ok()),
                content_type = ?response_headers.get(CONTENT_TYPE).and_then(|value: &HeaderValue| value.to_str().ok()),
                reason = reuse_decision.reason(),
                method = %request.method,
                status = status.as_u16(),
                url = %response_context.url,
                "MITM response connection decision"
            );
            let response_bytes = build_https_response_bytes(
                status.as_u16(),
                status.canonical_reason().unwrap_or("OK"),
                &response_headers,
                response_body,
                response_connection,
            );

            tls_stream.write_all(&response_bytes).await?;
            tls_stream.flush().await?;
            let body_completion = MitmBodyCompletion::CompleteBufferedContentLength {
                bytes: buffered_response_body_len,
            };
            let (outcome, reason) = self.mitm_response_outcome_after_body_completion(
                &request,
                &response_context.url,
                mitm_request_index,
                status.as_u16(),
                response_boundary,
                reuse_decision,
                body_completion,
                "buffered_response_written",
            );
            drop(observed_permit.take());
            log_slow_mitm_stage(
                "total",
                &response_context.url,
                total_started_at.elapsed().as_millis(),
                &format!("mode=buffer status={}", status.as_u16()),
                SLOW_MITM_TOTAL_MS,
            );
            debug_mitm_request_outcome(
                outcome,
                reason,
                request_method.as_deref(),
                request_url.as_deref(),
                mitm_keep_alive,
                mitm_request_index,
            );
            return Ok(outcome);
        }

        close_request!("internal_retry_limit_exhausted");
    }

    pub(crate) async fn open_mitm_websocket_upstream_tls(
        &self,
        authority: &str,
        target_host: &str,
        prepared_request: &PreparedMitmRequest,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let (_, target_port) = normalize_authority(authority)?;
        let upstream_address =
            mitm_upstream_proxy_address(&self.upstreams, &prepared_request.upstream)?;
        let tcp_stream = time::timeout(
            MITM_WEBSOCKET_UPSTREAM_CONNECT_TIMEOUT,
            connect_mitm_websocket_tcp(
                authority,
                target_host,
                target_port,
                upstream_address.as_deref(),
                &self.dns_resolver,
            ),
        )
        .await
        .with_context(|| format!("timed out connecting WebSocket upstream for `{authority}`"))??;

        let connector = build_websocket_tls_connector();
        let server_name = ServerName::try_from(target_host.to_string())
            .with_context(|| format!("invalid WebSocket TLS server name `{target_host}`"))?;
        time::timeout(
            MITM_WEBSOCKET_UPSTREAM_CONNECT_TIMEOUT,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .with_context(|| format!("timed out completing WebSocket TLS for `{authority}`"))?
        .with_context(|| format!("failed WebSocket TLS handshake for `{authority}`"))
    }

    async fn handle_mitm_websocket_upgrade(
        &self,
        tls_stream: &mut tokio_rustls::server::TlsStream<&mut TcpStream>,
        authority: &str,
        target_host: &str,
        request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
        prepared_request: &PreparedMitmRequest,
    ) -> Result<()> {
        // This is a fallback bridge for hosts that were already selected for MITM.
        // True WSS passthrough must happen earlier at CONNECT host routing, because
        // the WebSocket Upgrade headers are encrypted until MITM has started.
        if !request.method.eq_ignore_ascii_case("GET") {
            let response = simple_http_response_bytes(
                405,
                "Method Not Allowed",
                "RelayGate only supports WebSocket upgrade for GET requests.",
            );
            tls_stream.write_all(&response).await?;
            return Ok(());
        }

        let (_, target_port) = normalize_authority(authority)?;
        let upstream_address =
            mitm_upstream_proxy_address(&self.upstreams, &prepared_request.upstream)?;
        let tcp_stream = time::timeout(
            MITM_WEBSOCKET_UPSTREAM_CONNECT_TIMEOUT,
            connect_mitm_websocket_tcp(
                authority,
                target_host,
                target_port,
                upstream_address.as_deref(),
                &self.dns_resolver,
            ),
        )
        .await
        .with_context(|| format!("timed out connecting WebSocket upstream for `{authority}`"))??;

        let connector = build_websocket_tls_connector();
        let server_name = ServerName::try_from(target_host.to_string())
            .with_context(|| format!("invalid WebSocket TLS server name `{target_host}`"))?;
        let mut upstream_tls = time::timeout(
            MITM_WEBSOCKET_UPSTREAM_CONNECT_TIMEOUT,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .with_context(|| format!("timed out completing WebSocket TLS for `{authority}`"))?
        .with_context(|| format!("failed WebSocket TLS handshake for `{authority}`"))?;

        let upstream_request =
            build_mitm_websocket_upstream_request(authority, request, prepared_request);
        upstream_tls.write_all(&upstream_request).await?;
        let response_head = time::timeout(
            MITM_WEBSOCKET_UPSTREAM_RESPONSE_HEAD_TIMEOUT,
            read_http_response_head(&mut upstream_tls),
        )
        .await
        .with_context(|| {
            format!("timed out waiting for WebSocket upgrade response from `{authority}`")
        })??;
        let response_meta = parse_http_response_head(&response_head)?;

        tls_stream.write_all(&response_head).await?;
        if response_meta.status_code == 101 {
            match tokio::io::copy_bidirectional(tls_stream, &mut upstream_tls).await {
                Ok(_) => {}
                Err(error) if is_unclean_tls_shutdown_error(&error) => {
                    debug!(
                        authority = authority,
                        target_host = target_host,
                        url = %prepared_request.target_url,
                        error = %error,
                        "MITM WebSocket tunnel ended with unclean TLS shutdown"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            debug!(
                authority = authority,
                status = response_meta.status_code,
                "MITM WebSocket upstream did not switch protocols"
            );
            let _ = diagnostics::append_proxy_diagnostic(&format!(
                "{} event=mitm_websocket_upstream_non101 authority={} url={} status={}",
                diagnostics::diagnostic_timestamp(),
                authority,
                prepared_request.target_url,
                response_meta.status_code
            ));
        }

        Ok(())
    }

    fn decide_mitm_connection_reuse(
        &self,
        request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
        response_boundary: MitmResponseBoundary,
        upstream_requested_close: bool,
        navigation_document: bool,
    ) -> MitmConnectionReuseDecision {
        if !self.config.proxy.mitm.keep_alive {
            return MitmConnectionReuseDecision::Close {
                reason: "keep_alive_disabled",
            };
        }

        if request_connection_token_present(request, "close") {
            return MitmConnectionReuseDecision::Close {
                reason: "client_requested_connection_close",
            };
        }

        if request_has_upgrade(request) {
            return MitmConnectionReuseDecision::Close {
                reason: "request_upgrade_not_supported",
            };
        }

        if response_boundary == MitmResponseBoundary::Upgrade {
            return MitmConnectionReuseDecision::Close {
                reason: "response_upgrade_not_supported",
            };
        }

        if response_boundary == MitmResponseBoundary::EventStream {
            return MitmConnectionReuseDecision::Close {
                reason: "event_stream_response_not_keep_alive_safe",
            };
        }

        if upstream_requested_close {
            return MitmConnectionReuseDecision::Close {
                reason: "upstream_requested_connection_close",
            };
        }

        if !response_boundary.allows_keep_alive() {
            return MitmConnectionReuseDecision::Close {
                reason: response_boundary.rejected_reason(),
            };
        }

        if navigation_document {
            // P1-06K: navigation/main-document responses are a downstream
            // keep-alive admission boundary. The body framing and completion
            // can still be fully valid, but RelayGate intentionally does not
            // admit this browsing-lifecycle boundary into the reuse loop.
            // Subresources and API calls continue to use normal keep-alive
            // when their response body completion is safe.
            return MitmConnectionReuseDecision::Close {
                reason: "navigation_connection_boundary",
            };
        }

        MitmConnectionReuseDecision::KeepAlive {
            reason: "response_boundary_allows_keep_alive",
        }
    }

    fn mitm_response_outcome_after_body_completion(
        &self,
        request: &crate::proxy::mitm_http::ParsedMitmHttpRequest,
        response_url: &str,
        mitm_request_index: usize,
        status_code: u16,
        response_boundary: MitmResponseBoundary,
        decision: MitmConnectionReuseDecision,
        body_completion: MitmBodyCompletion,
        response_path_reason: &'static str,
    ) -> (MitmRequestOutcome, &'static str) {
        let (outcome, reason) =
            if decision.keep_alive_allowed() && body_completion.keep_alive_safe() {
                (MitmRequestOutcome::ContinueEligible, response_path_reason)
            } else if decision.keep_alive_allowed() {
                (MitmRequestOutcome::Close, body_completion.rejected_reason())
            } else {
                (MitmRequestOutcome::Close, decision.reason())
            };

        debug!(
            mitm_keep_alive_candidate = decision.keep_alive_allowed(),
            keep_alive_allowed = matches!(outcome, MitmRequestOutcome::ContinueEligible),
            response_framing_decision = response_boundary.label(),
            connection_reuse_decision = decision.label(),
            close_reason = if matches!(outcome, MitmRequestOutcome::ContinueEligible) { "" } else { reason },
            keep_alive_admission = decision.keep_alive_admission(),
            admission_reason = decision.reason(),
            reason = reason,
            method = %request.method,
            url = %response_url,
            status = status_code,
            response_boundary = response_boundary.label(),
            body_end_known = response_boundary.body_end_known(),
            body_completion = body_completion.tracing_label(),
            body_completion_keep_alive_safe = body_completion.keep_alive_safe(),
            response_body_bytes = body_completion.bytes(),
            chunk_count = body_completion.chunks(),
            mitm_request_index,
            sec_fetch_mode = ?request_sec_fetch_mode(request),
            sec_fetch_dest = ?request_sec_fetch_dest(request),
            upstream_requested_close = decision.reason() == "upstream_requested_connection_close",
            navigation_connection_boundary = decision.reason() == "navigation_connection_boundary",
            "MITM connection reuse decision after body completion"
        );

        (outcome, reason)
    }

    fn request_read_limits(&self) -> http_framing::RequestReadLimits {
        http_framing::RequestReadLimits {
            max_header_bytes: self.config.limits.max_header_bytes,
            max_request_body_bytes: self.config.limits.max_request_body_bytes,
            max_chunked_body_bytes: self.config.limits.max_chunked_body_bytes,
        }
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
        load_ca_material()
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
            return Ok(cached);
        }

        let generated = generate_leaf_certificate(&ca, &host, port, &cache_key)?;

        cache.insert(cache_key, generated.clone());
        Ok(generated)
    }

    pub(crate) fn upstream_connector(&self) -> MitmUpstreamConnector {
        MitmUpstreamConnector::new(
            self.upstreams.clone(),
            self.dns_resolver.clone(),
            self.http_client_cache.clone(),
        )
    }

    pub(crate) fn should_tolerate_invalid_upstream_cert(&self, host: &str) -> bool {
        let target = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        self.config
            .proxy
            .mitm
            .tolerate_invalid_upstream_cert_hosts
            .iter()
            .map(|item| item.trim().trim_matches(['[', ']']).to_ascii_lowercase())
            .any(|item| item == target)
    }

    fn response_pipeline_decision(
        &self,
        target_url: &str,
        request_type: &str,
        status_code: u16,
        response_headers: &HeaderMap,
        response_effects: &[RuleEffect],
    ) -> PipelineRoute {
        mitm_response_pipeline_decision(
            &self.mitm_response_state(),
            target_url,
            request_type,
            status_code,
            response_headers,
            response_effects,
        )
    }
}
