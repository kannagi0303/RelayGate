use std::{
    io::ErrorKind,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use axum::http::Uri;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, CONTENT_TYPE};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};
use tracing::{debug, info, warn};

use crate::{
    adblock::{self, SharedAdblockState},
    client_access,
    config::{MountSiteConfig, RelayGateConfig},
    diagnostics,
    dns::SharedDnsResolver,
    gateway::fetch,
    proxy::{
        body_classification::{
            response_headers_are_html_like, response_is_partial_content,
            should_treat_response_body_as_html,
        },
        connect::{handle_connect_tunnel, ConnectTunnelState},
        control_panel_proxy::{handle_control_panel_proxy, is_control_panel_request},
        downstream_status,
        happy_eyeballs::{connect_happy_eyeballs, resolve_target_addresses},
        header_hop::{connection_header_tokens, should_skip_response_header, upgrade_header_value},
        http_forward::{
            build_target_url, build_upstream_request_with_body_len,
            build_upstream_request_with_chunked_body, extract_host_from_pairs,
            resolve_forward_target,
        },
        http_framing,
        http_parse::{
            find_response_header_end, parse_http_request, parse_http_response_head,
            read_http_response_head, ParsedHttpRequest,
        },
        local_response::{build_buffered_response_bytes, simple_response_bytes},
        mitm::MitmEngine,
        mount_forward::{
            apply_response_effects_with_metadata_cleanup, apply_site_specific_gateway_rewrite,
            build_gateway_http_client, build_gateway_request_headers, header_pairs_from_reqwest,
            log_response_body, passthrough_response_headers,
            relaygate_body_pipeline_accept_encoding, should_forward_gateway_header,
        },
        outbound::{prepare_outbound_request, OutboundRequestDecision, OutboundRequestState},
        pipeline::{PipelineDecision, PipelineRoute},
        protocol_runtime::ProtocolRuntimeConfig,
        resource_replace::SharedResourceReplaceRegistry,
        response_head::{build_http_forward_response_head, log_invalid_upstream_response_head},
        rules::{RuleEffect, RuleEngine, RuleRequestContext, RuleResponseContext},
        server_errors::{is_expected_proxy_abort, log_connection_error},
        upstream::SharedUpstreamRegistry,
    },
    rewrite::SharedRewriteRegistry,
    runtime::AppRuntime,
    traffic::{self, SharedTrafficState, TrafficAction, TrafficResponseDecision},
    user_script::{self, SharedUserScriptRegistry},
    web::server::{build_app as build_control_panel_app, build_state as build_web_state},
};

const CLIENT_KEEP_ALIVE_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const UPSTREAM_RESPONSE_HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UPSTREAM_REUSE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
const SMALL_RESPONSE_BUFFER_LIMIT: usize = 64 * 1024;
const STREAM_COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Local HTTP proxy server.
///
/// The goal of this version is to get browser proxying working first:
/// - normal HTTP: forward directly
/// - HTTPS: support a minimal CONNECT tunnel
///
/// Still not covered yet:
/// - HTTPS MITM
/// - full response rewriting
/// - complex connection reuse and full HTTP compatibility
pub(crate) struct ProxyServer {
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
    control_panel_app: axum::Router,
}

#[derive(Clone)]
struct ProxyAppState {
    config: Arc<RelayGateConfig>,
    mitm: MitmEngine,
    rules: RuleEngine,
    upstreams: SharedUpstreamRegistry,
    resource_replace_registry: SharedResourceReplaceRegistry,
    rewrite_registry: SharedRewriteRegistry,
    adblock_state: SharedAdblockState,
    traffic_state: SharedTrafficState,
    dns_resolver: SharedDnsResolver,
    user_script_registry: SharedUserScriptRegistry,
    control_panel_app: axum::Router,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientConnectionAction {
    Continue,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistentResponseBodyMode {
    NoBody,
    ContentLength(usize),
    Chunked,
}

enum RequestBodyForwardMode {
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

impl RequestBodyForwardMode {
    fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StreamingContentLength { .. } => "streaming",
            Self::StreamingChunked { .. } => "streaming_chunked",
        }
    }
}

#[derive(Debug, Default)]
struct ChunkedRequestBodyStats {
    request_body_bytes: usize,
    chunk_count: usize,
    trailers_seen: bool,
}

#[derive(Default)]
struct ClientConnectionContext {
    reusable_upstream: Option<ReusableUpstreamConnection>,
}

struct ReusableUpstreamConnection {
    target: String,
    stream: TcpStream,
    last_used: Instant,
}

struct ConnectedUpstream {
    stream: TcpStream,
    reused: bool,
}

impl ProxyAppState {
    fn connect_tunnel_state(&self) -> ConnectTunnelState {
        ConnectTunnelState {
            mitm: self.mitm.clone(),
            rules: self.rules.clone(),
            upstreams: self.upstreams.clone(),
            dns_resolver: self.dns_resolver.clone(),
            connect_policy: self.config.proxy.connect.clone(),
        }
    }

    fn outbound_request_state(&self) -> OutboundRequestState {
        OutboundRequestState {
            rules: self.rules.clone(),
            upstreams: self.upstreams.clone(),
            resource_replace_registry: self.resource_replace_registry.clone(),
            adblock_state: self.adblock_state.clone(),
            traffic_state: self.traffic_state.clone(),
        }
    }
}

impl ProxyServer {
    pub(crate) fn new(
        config: Arc<RelayGateConfig>,
        rewrite_registry: SharedRewriteRegistry,
        resource_replace_registry: SharedResourceReplaceRegistry,
        adblock_state: SharedAdblockState,
        traffic_state: SharedTrafficState,
        upstreams: SharedUpstreamRegistry,
        dns_resolver: SharedDnsResolver,
        user_script_registry: SharedUserScriptRegistry,
        protocol_runtime: ProtocolRuntimeConfig,
        runtime: AppRuntime,
    ) -> Self {
        let rules = RuleEngine::from_config(&config.rules);

        Self {
            config: config.clone(),
            rules,
            upstreams: upstreams.clone(),
            resource_replace_registry: resource_replace_registry.clone(),
            rewrite_registry: rewrite_registry.clone(),
            adblock_state: adblock_state.clone(),
            traffic_state: traffic_state.clone(),
            dns_resolver: dns_resolver.clone(),
            user_script_registry: user_script_registry.clone(),
            protocol_runtime: protocol_runtime.clone(),
            control_panel_app: build_control_panel_app(build_web_state(
                config.clone(),
                rewrite_registry.clone(),
                resource_replace_registry.clone(),
                adblock_state.clone(),
                traffic_state,
                upstreams.clone(),
                dns_resolver.clone(),
                user_script_registry.clone(),
                protocol_runtime.clone(),
                runtime.clone(),
            )),
        }
    }

    pub(crate) async fn run(self) -> Result<()> {
        let addr: SocketAddr = self.config.proxy.listen.parse().with_context(|| {
            format!("invalid proxy listen address: {}", self.config.proxy.listen)
        })?;

        info!(listen = %addr, "proxy ready");
        self.log_bootstrap_summary();
        self.demo_rule_flow();

        let state = ProxyAppState {
            config: self.config.clone(),
            mitm: MitmEngine::new(
                self.config.clone(),
                self.rules.clone(),
                self.upstreams.clone(),
                self.resource_replace_registry.clone(),
                self.rewrite_registry.clone(),
                self.adblock_state.clone(),
                self.traffic_state.clone(),
                self.dns_resolver.clone(),
                self.user_script_registry.clone(),
                self.protocol_runtime.clone(),
            ),
            rules: self.rules,
            upstreams: self.upstreams,
            resource_replace_registry: self.resource_replace_registry,
            rewrite_registry: self.rewrite_registry,
            adblock_state: self.adblock_state,
            traffic_state: self.traffic_state,
            dns_resolver: self.dns_resolver,
            user_script_registry: self.user_script_registry,
            control_panel_app: self.control_panel_app,
        };

        let listener = TcpListener::bind(addr).await?;

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            if !client_access::is_client_ip_allowed(
                peer_addr.ip(),
                self.config.proxy.allow_lan,
                &self.config.proxy.allowed_clients,
            ) {
                warn!(peer = %peer_addr, "rejected proxy client: client IP is not allowed");
                tokio::spawn(async move {
                    reject_disallowed_proxy_client(stream).await;
                });
                continue;
            }

            if let Err(error) = stream.set_nodelay(true) {
                debug!(peer = %peer_addr, error = %error, "failed to set TCP_NODELAY for proxy client");
            }
            let state = state.clone();

            tokio::spawn(async move {
                if let Err(error) = handle_client(state, stream).await {
                    log_connection_error(peer_addr, &error);
                }
            });
        }
    }

    fn log_bootstrap_summary(&self) {
        let (upstream_count, upstream_route_count) = self
            .upstreams
            .read()
            .map(|registry| (registry.len(), registry.route_len()))
            .unwrap_or((0, 0));
        debug!(
            rule_count = self.rules.rule_count(),
            upstream_count,
            upstream_route_count,
            adblock_rules = adblock::rule_count(&self.adblock_state),
            adblock_resources = adblock::resource_count(&self.adblock_state),
            adblock_enabled = adblock::is_enabled(&self.adblock_state),
            "proxy pipeline initialized"
        );
    }

    fn demo_rule_flow(&self) {
        let request = RuleRequestContext {
            host: Some("example.com".to_string()),
            url: "http://example.com/demo".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
        };

        let request_decision = self.rules.evaluate_request(&request);
        debug!(?request_decision, "request rule evaluation preview");

        let response = RuleResponseContext {
            url: request.url.clone(),
            status_code: 200,
            headers: Vec::new(),
            body_preview: Some("demo response".to_string()),
        };

        let response_decision = self.rules.evaluate_response(&response);
        debug!(?response_decision, "response rule evaluation preview");
    }
}

async fn reject_disallowed_proxy_client(mut stream: TcpStream) {
    let response =
        simple_response_bytes(403, "Forbidden", "RelayGate proxy rejected this client IP.");
    let _ = stream.write_all(&response).await;
    let _ = stream.shutdown().await;
}

fn request_read_limits(config: &RelayGateConfig) -> http_framing::RequestReadLimits {
    http_framing::RequestReadLimits {
        max_header_bytes: config.limits.max_header_bytes,
        max_request_body_bytes: config.limits.max_request_body_bytes,
        max_chunked_body_bytes: config.limits.max_chunked_body_bytes,
    }
}

fn request_limit_response_bytes(error: http_framing::RequestLimitError) -> Vec<u8> {
    match error {
        http_framing::RequestLimitError::HeaderTooLarge => simple_response_bytes(
            431,
            "Request Header Fields Too Large",
            "RelayGate rejected the request because its headers exceed the configured limit.",
        ),
        http_framing::RequestLimitError::PayloadTooLarge => simple_response_bytes(
            413,
            "Payload Too Large",
            "RelayGate rejected the request because its body exceeds the configured limit.",
        ),
    }
}

fn response_buffer_limit_response_bytes() -> Vec<u8> {
    simple_response_bytes(
        502,
        "Bad Gateway",
        "RelayGate response buffer limit exceeded while preparing rewrite, patch, or injection.",
    )
}

async fn handle_client(state: ProxyAppState, mut client_stream: TcpStream) -> Result<()> {
    let mut client_context = ClientConnectionContext::default();

    loop {
        let request_head = match time::timeout(
            CLIENT_KEEP_ALIVE_IDLE_TIMEOUT,
            http_framing::read_http_request_head_limited(
                &mut client_stream,
                request_read_limits(state.config.as_ref()),
            ),
        )
        .await
        {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(error)) => {
                if let Some(limit_error) = error.downcast_ref::<http_framing::RequestLimitError>() {
                    warn!(
                        request_body_limited = true,
                        request_body_limit = state.config.limits.max_request_body_bytes,
                        request_chunked_body_limit = state.config.limits.max_chunked_body_bytes,
                        error = %limit_error,
                        "rejected request while reading HTTP request head"
                    );
                    let response = request_limit_response_bytes(*limit_error);
                    write_client_all(&mut client_stream, &response).await?;
                    client_stream.shutdown().await?;
                    return Ok(());
                }
                return Err(error);
            }
            Err(_) => {
                debug!("client keep-alive idle timeout");
                client_stream.shutdown().await?;
                return Ok(());
            }
        };

        match proxy_request(
            state.clone(),
            &mut client_context,
            &mut client_stream,
            request_head,
        )
        .await
        {
            Ok(ClientConnectionAction::Continue) => continue,
            Ok(ClientConnectionAction::Close) => return Ok(()),
            Err(error) => {
                if is_expected_proxy_abort(&error) {
                    debug!(error = %error, "proxy request ended before completion");
                    return Ok(());
                }

                let error_chain = diagnostics::format_error_chain(&error);
                let console_error = diagnostics::format_error_for_console(&error);
                let console_error_chain = diagnostics::format_error_chain_for_console(&error);
                let _ = diagnostics::append_proxy_diagnostic(&format!(
                    "ts={} peer={} event=proxy_request_failed error_chain={}",
                    diagnostics::diagnostic_timestamp(),
                    client_stream
                        .peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "unknown".to_string()),
                    error_chain
                ));
                warn!(
                    error = %console_error,
                    error_chain = %console_error_chain,
                    "proxy request failed"
                );
                let response_bytes = simple_response_bytes(
                    502,
                    "Bad Gateway",
                    &format!("RelayGate proxy error: {error}"),
                );
                client_stream.write_all(&response_bytes).await?;
                client_stream.shutdown().await?;
                return Ok(());
            }
        }
    }
}

async fn proxy_request(
    state: ProxyAppState,
    client_context: &mut ClientConnectionContext,
    client_stream: &mut TcpStream,
    request_head: http_framing::RequestHeadFrame,
) -> Result<ClientConnectionAction> {
    let request = parse_http_request(&request_head.head_bytes)?;

    if let Some(response) =
        downstream_status::http_proxy_status_response_bytes(&request, state.config.as_ref())
    {
        client_context.reusable_upstream.take();
        write_client_all(client_stream, &response).await?;
        client_stream.shutdown().await?;
        return Ok(ClientConnectionAction::Close);
    }

    if let Some(mount) = find_gateway_mount(state.config.as_ref(), &request.uri_text) {
        client_context.reusable_upstream.take();
        let Some(request) = buffer_request_for_existing_path(
            client_stream,
            request_head,
            state.config.as_ref(),
            "gateway_mount_existing_buffered_request_body",
        )
        .await?
        else {
            return Ok(ClientConnectionAction::Close);
        };
        handle_gateway_mount(state, client_stream, request, mount).await?;
        return Ok(ClientConnectionAction::Close);
    }

    if is_control_panel_request(&request, state.config.as_ref()) {
        client_context.reusable_upstream.take();
        if !is_web_ui_client_allowed(client_stream, &state) {
            let peer = client_stream
                .peer_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            warn!(peer = %peer, "rejected web UI client through proxy: client IP is not allowed");
            let response = simple_response_bytes(
                403,
                "Forbidden",
                "RelayGate web UI rejected this client IP.",
            );
            write_client_all(client_stream, &response).await?;
            client_stream.shutdown().await?;
            return Ok(ClientConnectionAction::Close);
        }
        let Some(request) = buffer_request_for_existing_path(
            client_stream,
            request_head,
            state.config.as_ref(),
            "control_panel_existing_buffered_request_body",
        )
        .await?
        else {
            return Ok(ClientConnectionAction::Close);
        };
        handle_control_panel_proxy(state.control_panel_app.clone(), client_stream, request).await?;
        return Ok(ClientConnectionAction::Close);
    }

    if request.method.eq_ignore_ascii_case("CONNECT") {
        client_context.reusable_upstream.take();
        handle_connect_tunnel(state.connect_tunnel_state(), client_stream, &request).await?;
        return Ok(ClientConnectionAction::Close);
    }

    let Some((request, body_mode)) = prepare_http_forward_request_body(
        client_stream,
        request,
        request_head,
        state.config.as_ref(),
    )
    .await?
    else {
        return Ok(ClientConnectionAction::Close);
    };
    handle_http_forward(state, client_context, client_stream, request, body_mode).await
}

async fn buffer_request_for_existing_path(
    client_stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    request_head: http_framing::RequestHeadFrame,
    config: &RelayGateConfig,
    reason: &'static str,
) -> Result<Option<ParsedHttpRequest>> {
    let body =
        match read_remaining_request_body_or_reject(client_stream, &request_head, config).await? {
            Some(body) => body,
            None => return Ok(None),
        };
    debug_request_body_mode(
        request_head.header_bytes(),
        "buffered",
        body.len(),
        request_body_limit_for_kind(config, request_head.body_kind),
        false,
        reason,
    );
    let request_bytes = request_head.into_request_bytes(body);
    Ok(Some(parse_http_request(&request_bytes)?))
}

async fn prepare_http_forward_request_body(
    _client_stream: &mut TcpStream,
    request: ParsedHttpRequest,
    request_head: http_framing::RequestHeadFrame,
    config: &RelayGateConfig,
) -> Result<Option<(ParsedHttpRequest, RequestBodyForwardMode)>> {
    match request_head.body_kind {
        http_framing::RequestBodyKind::None => {
            debug_request_body_mode(
                request_head.header_bytes(),
                "none",
                0,
                request_body_limit_for_kind(config, request_head.body_kind),
                false,
                "no_request_body",
            );
            Ok(Some((request, RequestBodyForwardMode::None)))
        }
        http_framing::RequestBodyKind::ContentLength(content_length) => {
            debug_request_body_mode(
                request_head.header_bytes(),
                "streaming",
                content_length,
                config.limits.max_request_body_bytes,
                false,
                "content_length_streaming_forward",
            );
            Ok(Some((
                request,
                RequestBodyForwardMode::StreamingContentLength {
                    content_length,
                    prebuffered_body: request_head.prebuffered_body,
                    expect_100_continue: request_head.expect_100_continue,
                },
            )))
        }
        http_framing::RequestBodyKind::Chunked => {
            debug_request_body_mode(
                request_head.header_bytes(),
                "streaming_chunked",
                0,
                config.limits.max_chunked_body_bytes,
                false,
                "chunked_streaming_forward_after_request_decision",
            );
            Ok(Some((
                request,
                RequestBodyForwardMode::StreamingChunked {
                    prebuffered_body: request_head.prebuffered_body,
                    expect_100_continue: request_head.expect_100_continue,
                },
            )))
        }
    }
}

async fn read_remaining_request_body_or_reject(
    client_stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    request_head: &http_framing::RequestHeadFrame,
    config: &RelayGateConfig,
) -> Result<Option<Vec<u8>>> {
    if request_head.expect_100_continue
        && request_head.body_kind != http_framing::RequestBodyKind::None
    {
        write_client_all(client_stream, b"HTTP/1.1 100 Continue\r\n\r\n").await?;
    }

    match time::timeout(
        UPSTREAM_BODY_IDLE_TIMEOUT,
        http_framing::read_remaining_request_body_limited(
            client_stream,
            request_head,
            request_read_limits(config),
        ),
    )
    .await
    {
        Ok(Ok(body)) => Ok(Some(body)),
        Ok(Err(error)) => {
            if let Some(limit_error) = error.downcast_ref::<http_framing::RequestLimitError>() {
                warn!(
                    request_body_mode = "buffered",
                    request_body_limit = request_body_limit_for_kind(config, request_head.body_kind),
                    request_body_limited = true,
                    error = %limit_error,
                    "request body exceeded configured limit"
                );
                let response = request_limit_response_bytes(*limit_error);
                write_client_all(client_stream, &response).await?;
                client_stream.shutdown().await?;
                return Ok(None);
            }
            Err(error)
        }
        Err(_) => {
            client_stream.shutdown().await?;
            anyhow::bail!("timed out reading request body from client")
        }
    }
}

fn request_body_limit_for_kind(
    config: &RelayGateConfig,
    body_kind: http_framing::RequestBodyKind,
) -> usize {
    match body_kind {
        http_framing::RequestBodyKind::Chunked => config.limits.max_chunked_body_bytes,
        http_framing::RequestBodyKind::None | http_framing::RequestBodyKind::ContentLength(_) => {
            config.limits.max_request_body_bytes
        }
    }
}

fn debug_request_body_mode(
    header_bytes: &[u8],
    mode: &'static str,
    bytes: usize,
    limit: usize,
    limited: bool,
    reason: &'static str,
) {
    let method = request_method_from_header_bytes(header_bytes);
    let content_length = request_content_length_from_header_bytes(header_bytes)
        .map(|value| value.to_string())
        .unwrap_or_default();
    let transfer_encoding =
        request_header_value_from_header_bytes(header_bytes, "transfer-encoding")
            .unwrap_or_default();
    debug!(
        request_body_mode = mode,
        request_body_bytes = bytes,
        request_body_limit = limit,
        request_body_limited = limited,
        method = %method,
        content_length = %content_length,
        transfer_encoding = %transfer_encoding,
        reason = reason,
        "request body handling decision"
    );
}

fn request_method_from_header_bytes(header_bytes: &[u8]) -> String {
    std::str::from_utf8(header_bytes)
        .ok()
        .and_then(|text| text.lines().next())
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_default()
        .to_string()
}

fn request_content_length_from_header_bytes(header_bytes: &[u8]) -> Option<usize> {
    request_header_value_from_header_bytes(header_bytes, "content-length")
        .and_then(|value| value.trim().parse::<usize>().ok())
}

fn request_header_value_from_header_bytes(
    header_bytes: &[u8],
    target_name: &str,
) -> Option<String> {
    let text = std::str::from_utf8(header_bytes).ok()?;
    text.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case(target_name) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

async fn handle_http_forward(
    state: ProxyAppState,
    client_context: &mut ClientConnectionContext,
    client_stream: &mut TcpStream,
    request: ParsedHttpRequest,
    body_mode: RequestBodyForwardMode,
) -> Result<ClientConnectionAction> {
    let uri = request.uri_text.parse::<Uri>()?;
    let target_url = build_target_url(&uri, &request.headers)?;
    let host = uri
        .host()
        .map(str::to_string)
        .or_else(|| extract_host_from_pairs(&request.headers));

    let prepared = match prepare_outbound_request(
        &state.outbound_request_state(),
        &request,
        target_url,
        host,
        request.headers.clone(),
        None,
        "request rule decision",
        "Blocked by RelayGate request rule.",
        "resource replacement matched HTTP request",
    )? {
        OutboundRequestDecision::Continue(prepared) => prepared,
        OutboundRequestDecision::Respond(response) => {
            client_stream.write_all(&response).await?;
            client_stream.shutdown().await?;
            return Ok(ClientConnectionAction::Close);
        }
        OutboundRequestDecision::Close => {
            client_stream.shutdown().await?;
            return Ok(ClientConnectionAction::Close);
        }
    };
    let upstream_label = prepared.upstream_id.as_deref().unwrap_or("direct");
    debug!(
        method = %request.method,
        url = %prepared.target_url,
        upstream = %upstream_label,
        "forwarding request"
    );

    let response_rule_preview_context = RuleResponseContext {
        url: prepared.target_url.clone(),
        status_code: 0,
        headers: Vec::new(),
        body_preview: None,
    };
    let response_rule_preview_decision = state
        .rules
        .evaluate_response(&response_rule_preview_context);

    for attempt in 0..=state.config.traffic.internal_retry_limit {
        let traffic_action = state.traffic_state.action_for_request(
            &prepared.traffic_host,
            &request.method,
            &prepared.request_type,
            &state.config.traffic,
        );
        let mut observed_permit =
            if prepared.observe_traffic && matches!(traffic_action, TrafficAction::Bypass) {
                state
                    .traffic_state
                    .begin_observed_request(&prepared.traffic_host)
            } else {
                None
            };
        let mut traffic_permit = match traffic_action {
            TrafficAction::Managed => Some(
                state
                    .traffic_state
                    .acquire(&prepared.traffic_host, &state.config.traffic)
                    .await?,
            ),
            TrafficAction::Bypass => None,
        };
        let mut outbound_request_source = request.clone();
        outbound_request_source.headers = prepared.headers.clone();
        let upgrade_request = upgrade_header_value(&outbound_request_source.headers);
        let prepare_response_body_pipeline = upgrade_request.is_none()
            && plain_http_may_need_response_body_pipeline(
                &state,
                &prepared.target_url,
                &response_rule_preview_decision.effects,
            );
        if prepare_response_body_pipeline {
            // Plain HTTP normally stays on a raw byte streaming path. When an
            // existing rewrite/injection feature may need response bytes, ask
            // the origin for identity encoding before the request is sent so
            // the buffered body pipeline sees plain bytes instead of gzip/br.
            set_header_pair(
                &mut outbound_request_source.headers,
                ACCEPT_ENCODING.as_str(),
                relaygate_body_pipeline_accept_encoding(),
            );
        }
        let forward_target =
            resolve_forward_target(&state.upstreams, &uri, prepared.upstream_id.as_deref())?;
        let can_reuse_upstream = prepared.upstream_id.is_none()
            && upgrade_request.is_none()
            && request_method_can_reuse_upstream(&request.method)
            && matches!(&body_mode, RequestBodyForwardMode::None);
        let request_body_len = match &body_mode {
            RequestBodyForwardMode::StreamingContentLength { content_length, .. } => {
                Some(*content_length)
            }
            RequestBodyForwardMode::None | RequestBodyForwardMode::StreamingChunked { .. } => None,
        };
        let outbound_request =
            if matches!(&body_mode, RequestBodyForwardMode::StreamingChunked { .. }) {
                build_upstream_request_with_chunked_body(
                    &outbound_request_source,
                    &uri,
                    &prepared.request_effects,
                    prepared.upstream_id.as_deref(),
                    upgrade_request.as_deref(),
                    can_reuse_upstream,
                )?
            } else {
                build_upstream_request_with_body_len(
                    &outbound_request_source,
                    &uri,
                    &prepared.request_effects,
                    prepared.upstream_id.as_deref(),
                    upgrade_request.as_deref(),
                    can_reuse_upstream,
                    request_body_len,
                )?
            };
        let connected_upstream = take_or_connect_upstream(
            client_context,
            &forward_target,
            can_reuse_upstream,
            &prepared.target_url,
            prepared.observe_traffic,
            &prepared.traffic_host,
            &state,
            prepared.upstream_id.is_none(),
        )
        .await?;
        let mut upstream_stream = connected_upstream.stream;
        let mut response_head_result = send_http_forward_request_and_read_response_head(
            &mut upstream_stream,
            &outbound_request,
            client_stream,
            &body_mode,
            state.config.as_ref(),
            &forward_target,
            &prepared.target_url,
        )
        .await;
        if connected_upstream.reused && response_head_result.is_err() {
            debug!(
                target = %forward_target,
                url = %prepared.target_url,
                "reused upstream connection failed; reconnecting once"
            );
            upstream_stream = connect_upstream(
                &forward_target,
                &prepared.target_url,
                prepared.observe_traffic,
                &prepared.traffic_host,
                &state,
                prepared.upstream_id.is_none(),
            )
            .await?;
            response_head_result = send_http_forward_request_and_read_response_head(
                &mut upstream_stream,
                &outbound_request,
                client_stream,
                &body_mode,
                state.config.as_ref(),
                &forward_target,
                &prepared.target_url,
            )
            .await;
        }
        let response_head = response_head_result.map_err(|error| {
            if prepared.observe_traffic {
                state.traffic_state.on_fatal_error(&prepared.traffic_host);
            }
            error
        })?;
        let response_meta = parse_http_response_head(&response_head).map_err(|error| {
            log_invalid_upstream_response_head(
                "http_forward",
                &prepared.target_url,
                &forward_target,
                &response_head,
                &error,
            );
            if prepared.observe_traffic {
                state.traffic_state.on_fatal_error(&prepared.traffic_host);
            }
            error
        })?;

        if let Some(_upgrade) = upgrade_request.as_deref() {
            write_client_all(client_stream, &response_head).await?;
            if response_meta.status_code == 101 {
                drop(observed_permit.take());
                io::copy_bidirectional(client_stream, &mut upstream_stream).await?;
                return Ok(ClientConnectionAction::Close);
            }

            time::timeout(
                UPSTREAM_BODY_IDLE_TIMEOUT,
                io::copy(&mut upstream_stream, client_stream),
            )
            .await
            .context("timed out streaming upgraded upstream response body")??;
            drop(observed_permit.take());
            client_stream.shutdown().await?;
            return Ok(ClientConnectionAction::Close);
        }

        if response_meta.status_code == 429
            && state
                .traffic_state
                .is_controlled_host(&prepared.traffic_host)
            && request.method.eq_ignore_ascii_case("GET")
            && prepared.request_type == "document"
            && matches!(&body_mode, RequestBodyForwardMode::None)
        {
            let retry_after = traffic::parse_retry_after_secs(&response_meta.headers);
            drop(observed_permit.take());
            drop(traffic_permit.take());
            match state.traffic_state.decide_429_response(
                &prepared.traffic_host,
                attempt,
                retry_after,
                &state.config.traffic,
            ) {
                TrafficResponseDecision::RetryAfterDelay(delay) => {
                    drop(upstream_stream);
                    state.traffic_state.begin_retry_wait(&prepared.traffic_host);
                    time::sleep(delay).await;
                    state.traffic_state.end_retry_wait(&prepared.traffic_host);
                    continue;
                }
                TrafficResponseDecision::ReloadPage(delay) => {
                    let response = traffic::reload_page_response(delay, &prepared.target_url);
                    write_client_all(client_stream, &response).await?;
                    client_stream.shutdown().await?;
                    return Ok(ClientConnectionAction::Close);
                }
                TrafficResponseDecision::Forward => {}
            }
        } else if matches!(traffic_action, TrafficAction::Managed) {
            state
                .traffic_state
                .on_success(&prepared.traffic_host, &state.config.traffic);
        }

        let response_head_end = find_response_header_end(&response_head)
            .context("valid parsed HTTP response lost header terminator")?;
        let prebuffered_body =
            &response_head[response_head_end.index + response_head_end.delimiter_len..];
        let persistent_body_mode = persistent_response_body_mode(&request, &response_meta);
        let keep_client_alive =
            should_keep_client_connection_alive(&request) && persistent_body_mode.is_some();
        let keep_upstream_alive = can_reuse_upstream
            && keep_client_alive
            && should_keep_upstream_connection_alive(&response_meta);
        let http_forward_content_type = content_type_from_header_pairs(&response_meta.headers);
        let response_context = RuleResponseContext {
            url: prepared.target_url.clone(),
            status_code: response_meta.status_code,
            headers: response_meta.headers.clone(),
            body_preview: None,
        };
        let response_decision = state.rules.evaluate_response(&response_context);
        let http_forward_pipeline_route = plain_http_response_pipeline_decision(
            &state,
            &request.method,
            &prepared.target_url,
            &prepared.request_type,
            &response_meta.headers,
            &response_decision.effects,
            response_meta.status_code,
        );
        debug!(
            pipeline = %http_forward_pipeline_route.pipeline_label(),
            reason = %http_forward_pipeline_route.reason,
            request_type = %prepared.request_type,
            content_type = %http_forward_content_type,
            status = response_meta.status_code,
            url = %prepared.target_url,
            "HTTP forward response pipeline decision"
        );

        if !http_forward_pipeline_route.is_fast_path() {
            let response_body = match read_limited_plain_http_response_body(
                &mut upstream_stream,
                prebuffered_body,
                persistent_body_mode,
                state.config.limits.max_response_buffer_bytes,
            )
            .await
            .map_err(|error| {
                if prepared.observe_traffic {
                    state.traffic_state.on_fatal_error(&prepared.traffic_host);
                }
                error
            })? {
                Some(body) => body,
                None => {
                    warn!(
                        pipeline = %PipelineDecision::Block.as_str(),
                        reason = "plain_http_response_buffer_limit_exceeded",
                        request_type = %prepared.request_type,
                        content_type = %http_forward_content_type,
                        url = %prepared.target_url,
                        limit = state.config.limits.max_response_buffer_bytes,
                        "plain HTTP response body exceeded buffer limit before rewrite"
                    );
                    let response = response_buffer_limit_response_bytes();
                    write_client_all(client_stream, &response).await?;
                    drop(observed_permit.take());
                    client_stream.shutdown().await?;
                    return Ok(ClientConnectionAction::Close);
                }
            };

            let mut response_headers = header_map_from_pairs(&response_meta.headers);
            let mut response_body = apply_response_effects_with_metadata_cleanup(
                response_body,
                &response_decision.effects,
                &mut response_headers,
            );
            response_body = apply_site_specific_gateway_rewrite(
                &state.rewrite_registry,
                &state.adblock_state,
                &prepared.target_url,
                &prepared.source_url,
                &prepared.request_type,
                prepared.fetch_site.as_deref(),
                &state.user_script_registry,
                &mut response_headers,
                response_body,
            )?;

            if state.config.logging.log_response_body {
                log_response_body(
                    "http_forward",
                    &prepared.target_url,
                    response_headers
                        .get(CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    &response_body,
                );
            }

            let headers =
                http_forward_buffered_response_headers(&response_headers, response_body.len());
            let response = build_buffered_response_bytes(
                response_meta.status_code,
                &response_meta.reason_phrase,
                headers,
                response_body,
            );
            write_client_all(client_stream, &response).await?;
            drop(observed_permit.take());
            client_stream.shutdown().await?;
            return Ok(ClientConnectionAction::Close);
        }

        let client_response_head =
            build_http_forward_response_head(&response_meta, keep_client_alive);
        write_client_all(client_stream, &client_response_head).await?;
        if let Some(body_mode) = persistent_body_mode {
            // Response framing is independent from client connection reuse.
            // Even when the downstream client asks to close, a Content-Length
            // or chunked upstream response should be forwarded by its declared
            // boundary instead of waiting for the upstream TCP connection to
            // close. This keeps plain HTTP fast path from stalling on origins
            // that keep their side alive despite RelayGate closing downstream.
            forward_persistent_response_body(
                &mut upstream_stream,
                client_stream,
                prebuffered_body,
                body_mode,
            )
            .await?;
        } else {
            write_client_all(client_stream, prebuffered_body).await?;
            time::timeout(
                UPSTREAM_BODY_IDLE_TIMEOUT,
                io::copy(&mut upstream_stream, client_stream),
            )
            .await
            .context("timed out streaming upstream response body")??;
        }
        drop(observed_permit.take());
        if keep_client_alive {
            if keep_upstream_alive {
                client_context.reusable_upstream = Some(ReusableUpstreamConnection {
                    target: forward_target,
                    stream: upstream_stream,
                    last_used: Instant::now(),
                });
            }
            return Ok(ClientConnectionAction::Continue);
        }

        client_stream.shutdown().await?;
        return Ok(ClientConnectionAction::Close);
    }

    client_stream.shutdown().await?;
    Ok(ClientConnectionAction::Close)
}

fn is_web_ui_client_allowed(client_stream: &TcpStream, state: &ProxyAppState) -> bool {
    let Ok(peer_addr) = client_stream.peer_addr() else {
        return false;
    };

    client_access::is_client_ip_allowed(
        peer_addr.ip(),
        state.config.web.allow_lan,
        &state.config.web.allowed_clients,
    )
}

fn should_keep_client_connection_alive(request: &ParsedHttpRequest) -> bool {
    if header_has_token(&request.headers, "connection", "close")
        || header_has_token(&request.headers, "proxy-connection", "close")
    {
        return false;
    }

    if request.version.eq_ignore_ascii_case("HTTP/1.1") {
        return true;
    }

    request.version.eq_ignore_ascii_case("HTTP/1.0")
        && (header_has_token(&request.headers, "connection", "keep-alive")
            || header_has_token(&request.headers, "proxy-connection", "keep-alive"))
}

fn persistent_response_body_mode(
    request: &ParsedHttpRequest,
    response: &crate::proxy::http_parse::ParsedHttpResponseHead,
) -> Option<PersistentResponseBodyMode> {
    if !response.version.eq_ignore_ascii_case("HTTP/1.1") {
        return None;
    }

    if response_has_no_body(&request.method, response.status_code) {
        return Some(PersistentResponseBodyMode::NoBody);
    }

    if has_chunked_transfer_encoding(&response.headers) {
        return Some(PersistentResponseBodyMode::Chunked);
    }

    response_content_length(&response.headers).map(PersistentResponseBodyMode::ContentLength)
}

fn response_has_no_body(method: &str, status_code: u16) -> bool {
    method.eq_ignore_ascii_case("HEAD") || matches!(status_code, 204 | 304)
}

fn response_content_length(headers: &[(String, String)]) -> Option<usize> {
    let mut parsed = None;

    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        let length = value.trim().parse::<usize>().ok()?;
        if parsed.is_some_and(|existing| existing != length) {
            return None;
        }
        parsed = Some(length);
    }

    parsed
}

fn plain_http_may_need_response_body_pipeline(
    state: &ProxyAppState,
    target_url: &str,
    response_effects: &[RuleEffect],
) -> bool {
    if state.config.logging.log_response_body || response_effects_rewrite_body(response_effects) {
        return true;
    }

    if adblock::is_enabled(&state.adblock_state)
        || user_script::has_enabled_scripts(&state.user_script_registry)
    {
        return true;
    }

    match state.rewrite_registry.read() {
        Ok(registry) => {
            registry.has_render_rule_match(target_url)
                || registry.has_patch_rule_match(target_url, "text/html")
                || registry.has_patch_rule_match(target_url, "application/json")
        }
        Err(_) => true,
    }
}

fn plain_http_response_pipeline_decision(
    state: &ProxyAppState,
    method: &str,
    target_url: &str,
    request_type: &str,
    response_headers: &[(String, String)],
    response_effects: &[RuleEffect],
    status_code: u16,
) -> PipelineRoute {
    if response_has_no_body(method, status_code) {
        return PipelineRoute::fast_path("plain_http_response_has_no_body");
    }

    if response_is_partial_content(
        status_code,
        header_pairs_have(response_headers, "content-range"),
    ) {
        return PipelineRoute::fast_path("partial_content_passthrough");
    }

    if state.config.logging.log_response_body {
        return PipelineRoute::deep_path("logging_response_body_enabled");
    }

    if response_effects_rewrite_body(response_effects) {
        return PipelineRoute::deep_path("response_rule_rewrite_body");
    }

    let content_type = content_type_from_header_pairs(response_headers);
    let html_like = response_headers_are_html_like(request_type, &content_type);
    if html_like
        && (adblock::is_enabled(&state.adblock_state)
            || user_script::has_enabled_scripts(&state.user_script_registry))
    {
        return PipelineRoute::deep_path(if matches!(request_type, "document" | "subdocument") {
            "plain_http_document_html_injection"
        } else {
            "plain_http_html_response_injection"
        });
    }

    match state.rewrite_registry.read() {
        Ok(registry) => {
            if html_like && registry.has_render_rule_match(target_url) {
                return PipelineRoute::deep_path("plain_http_site_render_rule_match");
            }

            if registry.has_patch_rule_match(target_url, &content_type) {
                return PipelineRoute::deep_path("plain_http_site_patch_rule_match");
            }

            PipelineRoute::fast_path("plain_http_forward_stream")
        }
        Err(_) => PipelineRoute::deep_path("plain_http_rewrite_registry_lock_failed_fail_safe"),
    }
}

fn response_effects_rewrite_body(response_effects: &[RuleEffect]) -> bool {
    response_effects
        .iter()
        .any(|effect| matches!(effect, RuleEffect::RewriteResponseBody { .. }))
}

fn set_header_pair(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
    headers.push((name.to_string(), value.to_string()));
}

fn header_map_from_pairs(headers: &[(String, String)]) -> HeaderMap {
    let mut result = HeaderMap::new();
    for (name, value) in headers {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(value) else {
            continue;
        };
        result.append(name, value);
    }
    result
}

fn http_forward_buffered_response_headers(
    headers: &HeaderMap,
    body_len: usize,
) -> Vec<(String, String)> {
    let header_pairs = header_pairs_from_header_map(headers);
    let connection_tokens = connection_header_tokens(&header_pairs);
    let mut result = Vec::new();

    for (name, value) in headers {
        let name_text = name.as_str();
        let lower = name_text.to_ascii_lowercase();
        if should_skip_response_header(name_text, &connection_tokens)
            || matches!(lower.as_str(), "content-length" | "transfer-encoding")
        {
            continue;
        }

        if let Ok(value_text) = value.to_str() {
            result.push((name_text.to_string(), value_text.to_string()));
        }
    }

    result.push(("Content-Length".to_string(), body_len.to_string()));
    result.push(("Connection".to_string(), "close".to_string()));
    result
}

fn header_pairs_from_header_map(headers: &HeaderMap) -> Vec<(String, String)> {
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

async fn read_limited_plain_http_response_body(
    upstream_stream: &mut TcpStream,
    prebuffered_body: &[u8],
    body_mode: Option<PersistentResponseBodyMode>,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    match body_mode {
        Some(PersistentResponseBodyMode::NoBody) => Ok(Some(Vec::new())),
        Some(PersistentResponseBodyMode::ContentLength(content_length)) => {
            read_limited_plain_http_content_length_body(
                upstream_stream,
                prebuffered_body,
                content_length,
                max_bytes,
            )
            .await
        }
        Some(PersistentResponseBodyMode::Chunked) => {
            read_limited_plain_http_chunked_body(upstream_stream, prebuffered_body, max_bytes).await
        }
        None => {
            read_limited_plain_http_close_delimited_body(
                upstream_stream,
                prebuffered_body,
                max_bytes,
            )
            .await
        }
    }
}

async fn read_limited_plain_http_content_length_body(
    upstream_stream: &mut TcpStream,
    prebuffered_body: &[u8],
    content_length: usize,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    if content_length > max_bytes {
        return Ok(None);
    }
    if prebuffered_body.len() > content_length {
        anyhow::bail!("prebuffered upstream response body exceeds Content-Length");
    }

    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(prebuffered_body);
    if body.len() < content_length {
        let start = body.len();
        body.resize(content_length, 0);
        time::timeout(
            UPSTREAM_BODY_IDLE_TIMEOUT,
            upstream_stream.read_exact(&mut body[start..]),
        )
        .await
        .context("timed out reading buffered plain HTTP response body")??;
    }

    Ok(Some(body))
}

async fn read_limited_plain_http_chunked_body(
    upstream_stream: &mut TcpStream,
    prebuffered_body: &[u8],
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let mut encoded = Vec::from(prebuffered_body);
    let encoded_limit = max_bytes.saturating_mul(4).saturating_add(64 * 1024);
    let mut buffer = vec![0_u8; STREAM_COPY_BUFFER_BYTES];

    loop {
        if encoded.len() > encoded_limit
            || http_framing::chunked_decoded_len_exceeds(&encoded, max_bytes)?
        {
            return Ok(None);
        }

        if let Some(encoded_len) = http_framing::chunked_encoded_len(&encoded)? {
            encoded.truncate(encoded_len);
            let decoded = http_framing::decode_chunked_body(&encoded)?;
            if decoded.len() > max_bytes {
                return Ok(None);
            }
            return Ok(Some(decoded));
        }

        let read_count = time::timeout(
            UPSTREAM_BODY_IDLE_TIMEOUT,
            upstream_stream.read(&mut buffer),
        )
        .await
        .context("timed out reading chunked plain HTTP response body")??;
        if read_count == 0 {
            anyhow::bail!("upstream closed before completing chunked plain HTTP response body");
        }
        encoded.extend_from_slice(&buffer[..read_count]);
    }
}

async fn read_limited_plain_http_close_delimited_body(
    upstream_stream: &mut TcpStream,
    prebuffered_body: &[u8],
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let mut body = Vec::from(prebuffered_body);
    if body.len() > max_bytes {
        return Ok(None);
    }

    let mut buffer = vec![0_u8; STREAM_COPY_BUFFER_BYTES];
    loop {
        let read_count = time::timeout(
            UPSTREAM_BODY_IDLE_TIMEOUT,
            upstream_stream.read(&mut buffer),
        )
        .await
        .context("timed out reading close-delimited plain HTTP response body")??;
        if read_count == 0 {
            return Ok(Some(body));
        }
        if body.len().saturating_add(read_count) > max_bytes {
            return Ok(None);
        }
        body.extend_from_slice(&buffer[..read_count]);
    }
}

fn should_keep_upstream_connection_alive(
    response: &crate::proxy::http_parse::ParsedHttpResponseHead,
) -> bool {
    response.version.eq_ignore_ascii_case("HTTP/1.1")
        && !header_has_token(&response.headers, "connection", "close")
}

fn request_method_can_reuse_upstream(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

fn has_chunked_transfer_encoding(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|(_, value)| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
}

fn header_has_token(headers: &[(String, String)], header_name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(header_name))
        .flat_map(|(_, value)| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case(token))
}

async fn take_or_connect_upstream(
    client_context: &mut ClientConnectionContext,
    forward_target: &str,
    can_reuse_upstream: bool,
    target_url: &str,
    observe_traffic: bool,
    traffic_host: &str,
    state: &ProxyAppState,
    use_relaygate_dns: bool,
) -> Result<ConnectedUpstream> {
    if can_reuse_upstream {
        if let Some(reusable) = client_context.reusable_upstream.take() {
            if reusable.target == forward_target
                && reusable.last_used.elapsed() <= UPSTREAM_REUSE_IDLE_TIMEOUT
                && reusable_upstream_is_ready(&reusable.stream).await?
            {
                return Ok(ConnectedUpstream {
                    stream: reusable.stream,
                    reused: true,
                });
            }
        }
    } else {
        client_context.reusable_upstream.take();
    }

    let upstream_stream = connect_upstream(
        forward_target,
        target_url,
        observe_traffic,
        traffic_host,
        state,
        use_relaygate_dns,
    )
    .await?;
    Ok(ConnectedUpstream {
        stream: upstream_stream,
        reused: false,
    })
}

async fn reusable_upstream_is_ready(stream: &TcpStream) -> Result<bool> {
    let mut probe = [0_u8; 1];
    match time::timeout(Duration::from_millis(1), stream.peek(&mut probe)).await {
        Err(_) => Ok(true),
        Ok(Ok(0)) => Ok(false),
        Ok(Ok(_)) => Ok(false),
        Ok(Err(error)) if error.kind() == ErrorKind::WouldBlock => Ok(true),
        Ok(Err(error)) => Err(error.into()),
    }
}

async fn connect_upstream(
    forward_target: &str,
    target_url: &str,
    observe_traffic: bool,
    traffic_host: &str,
    state: &ProxyAppState,
    use_relaygate_dns: bool,
) -> Result<TcpStream> {
    let connection = time::timeout(UPSTREAM_CONNECT_TIMEOUT, async {
        let addresses =
            resolve_target_addresses(forward_target, &state.dns_resolver, use_relaygate_dns)
                .await?;
        connect_happy_eyeballs(forward_target, addresses, HAPPY_EYEBALLS_DELAY).await
    })
    .await
    .with_context(|| {
        format!("timed out connecting upstream target `{forward_target}` for `{target_url}`")
    })?
    .with_context(|| {
        format!("failed to connect upstream target `{forward_target}` for `{target_url}`")
    })
    .map_err(|error| {
        if observe_traffic {
            state.traffic_state.on_fatal_error(traffic_host);
        }
        error
    })?;

    debug!(
        target = %forward_target,
        selected_ip = %connection.selected_addr.ip(),
        selected_ip_family = connection.selected_ip_family(),
        connect_ms = connection.connect_ms(),
        happy_eyeballs_delay_ms = connection.delay_ms(),
        request_type = "http_forward",
        "Happy Eyeballs selected upstream address"
    );

    let upstream_stream = connection.stream;
    if let Err(error) = upstream_stream.set_nodelay(true) {
        debug!(
            target = %forward_target,
            error = %error,
            "failed to set TCP_NODELAY for upstream connection"
        );
    }

    Ok(upstream_stream)
}

async fn send_http_forward_request_and_read_response_head(
    upstream_stream: &mut TcpStream,
    outbound_request: &[u8],
    client_stream: &mut TcpStream,
    body_mode: &RequestBodyForwardMode,
    config: &RelayGateConfig,
    forward_target: &str,
    target_url: &str,
) -> Result<Vec<u8>> {
    match body_mode {
        RequestBodyForwardMode::StreamingContentLength {
            content_length,
            prebuffered_body,
            expect_100_continue,
        } => {
            upstream_stream.write_all(outbound_request).await?;
            if *expect_100_continue {
                write_client_all(client_stream, b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            }
            let forwarded = stream_content_length_request_body(
                client_stream,
                upstream_stream,
                *content_length,
                prebuffered_body,
            )
            .await
            .with_context(|| {
                format!(
                    "failed streaming request body to upstream target `{forward_target}` for `{target_url}`"
                )
            })?;
            debug!(
                request_body_mode = body_mode.label(),
                request_body_bytes = forwarded,
                request_body_limit = config.limits.max_request_body_bytes,
                request_body_limited = false,
                "streamed request body to upstream"
            );
            time::timeout(UPSTREAM_RESPONSE_HEAD_TIMEOUT, read_http_response_head(upstream_stream))
                .await
                .with_context(|| {
                    format!(
                        "timed out waiting for upstream response headers from `{forward_target}` for `{target_url}`"
                    )
                })?
        }
        RequestBodyForwardMode::StreamingChunked {
            prebuffered_body,
            expect_100_continue,
        } => {
            upstream_stream.write_all(outbound_request).await?;
            if *expect_100_continue {
                write_client_all(client_stream, b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            }
            let stats = match stream_chunked_request_body(
                client_stream,
                upstream_stream,
                prebuffered_body,
                request_read_limits(config),
            )
            .await
            {
                Ok(stats) => stats,
                Err(error) => {
                    if let Some(limit_error) =
                        error.downcast_ref::<http_framing::RequestLimitError>()
                    {
                        warn!(
                            request_body_mode = body_mode.label(),
                            request_body_bytes = 0usize,
                            request_body_limit = config.limits.max_chunked_body_bytes,
                            chunk_count = 0usize,
                            trailers_seen = false,
                            request_body_limited = true,
                            error = %limit_error,
                            "chunked request body exceeded configured limit after upstream request started; closing tunnel"
                        );
                        let _ = upstream_stream.shutdown().await;
                        let response = request_limit_response_bytes(*limit_error);
                        let _ = write_client_all(client_stream, &response).await;
                        let _ = client_stream.shutdown().await;
                        anyhow::bail!(
                            "request body limit handled after upstream started: chunked request body exceeded configured limit"
                        );
                    }
                    return Err(error).with_context(|| {
                        format!(
                            "failed streaming chunked request body to upstream target `{forward_target}` for `{target_url}`"
                        )
                    });
                }
            };
            debug!(
                request_body_mode = body_mode.label(),
                request_body_bytes = stats.request_body_bytes,
                request_body_limit = config.limits.max_chunked_body_bytes,
                chunk_count = stats.chunk_count,
                trailers_seen = stats.trailers_seen,
                request_body_limited = false,
                "streamed chunked request body to upstream"
            );
            time::timeout(UPSTREAM_RESPONSE_HEAD_TIMEOUT, read_http_response_head(upstream_stream))
                .await
                .with_context(|| {
                    format!(
                        "timed out waiting for upstream response headers from `{forward_target}` for `{target_url}`"
                    )
                })?
        }
        RequestBodyForwardMode::None => {
            send_request_and_read_response_head(
                upstream_stream,
                outbound_request,
                forward_target,
                target_url,
            )
            .await
        }
    }
}

async fn stream_content_length_request_body(
    client_stream: &mut TcpStream,
    upstream_stream: &mut TcpStream,
    content_length: usize,
    prebuffered_body: &[u8],
) -> Result<usize> {
    if prebuffered_body.len() > content_length {
        anyhow::bail!("prebuffered request body exceeds Content-Length");
    }

    let mut forwarded = 0usize;
    if !prebuffered_body.is_empty() {
        upstream_stream.write_all(prebuffered_body).await?;
        forwarded += prebuffered_body.len();
    }

    let mut buffer = vec![0_u8; STREAM_COPY_BUFFER_BYTES];
    while forwarded < content_length {
        let remaining = content_length - forwarded;
        let read_len = remaining.min(buffer.len());
        let read_count = time::timeout(
            UPSTREAM_BODY_IDLE_TIMEOUT,
            client_stream.read(&mut buffer[..read_len]),
        )
        .await
        .context("timed out reading streaming request body from client")??;
        if read_count == 0 {
            anyhow::bail!("client closed before completing streaming request body");
        }
        upstream_stream.write_all(&buffer[..read_count]).await?;
        forwarded += read_count;
    }

    Ok(forwarded)
}

async fn stream_chunked_request_body(
    client_stream: &mut TcpStream,
    upstream_stream: &mut TcpStream,
    prebuffered_body: &[u8],
    limits: http_framing::RequestReadLimits,
) -> Result<ChunkedRequestBodyStats> {
    let mut buffer = Vec::from(prebuffered_body);
    let mut stats = ChunkedRequestBodyStats::default();

    loop {
        read_until_chunk_size_line_available(client_stream, &mut buffer).await?;
        let line_end = find_chunk_line_end(&buffer)
            .context("invalid chunked request body: missing chunk size terminator")?;
        let size_line = std::str::from_utf8(&buffer[..line_end.index])?;
        let chunk_size = parse_chunk_size_line(size_line)?;
        if stats.request_body_bytes.saturating_add(chunk_size) > limits.max_chunked_body_bytes {
            warn!(
                request_body_mode = "streaming_chunked",
                request_body_bytes = stats.request_body_bytes,
                request_body_limit = limits.max_chunked_body_bytes,
                chunk_count = stats.chunk_count,
                trailers_seen = stats.trailers_seen,
                request_body_limited = true,
                next_chunk_bytes = chunk_size,
                "chunked request body would exceed configured limit"
            );
            return Err(http_framing::RequestLimitError::PayloadTooLarge.into());
        }

        let size_line_end = line_end.index + line_end.delimiter_len;
        upstream_stream.write_all(&buffer[..size_line_end]).await?;
        buffer.drain(..size_line_end);

        if chunk_size == 0 {
            let trailers_seen =
                stream_chunked_trailers(client_stream, upstream_stream, &mut buffer, limits)
                    .await?;
            stats.trailers_seen = trailers_seen;
            return Ok(stats);
        }

        stream_exact_chunk_data(
            client_stream,
            upstream_stream,
            &mut buffer,
            chunk_size,
            &mut stats,
        )
        .await?;
        stream_chunk_data_terminator(client_stream, upstream_stream, &mut buffer).await?;
        stats.chunk_count = stats.chunk_count.saturating_add(1);
    }
}

async fn read_more_chunked_request_body(
    client_stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<()> {
    let mut temp = vec![0_u8; STREAM_COPY_BUFFER_BYTES];
    let read_count = time::timeout(UPSTREAM_BODY_IDLE_TIMEOUT, client_stream.read(&mut temp))
        .await
        .context("timed out reading streaming chunked request body from client")??;
    if read_count == 0 {
        anyhow::bail!("client closed before completing streaming chunked request body");
    }
    buffer.extend_from_slice(&temp[..read_count]);
    Ok(())
}

async fn read_until_chunk_size_line_available(
    client_stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<()> {
    while find_chunk_line_end(buffer).is_none() {
        read_more_chunked_request_body(client_stream, buffer).await?;
    }
    Ok(())
}

async fn stream_exact_chunk_data(
    client_stream: &mut TcpStream,
    upstream_stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    mut remaining: usize,
    stats: &mut ChunkedRequestBodyStats,
) -> Result<()> {
    while remaining > 0 {
        if buffer.is_empty() {
            read_more_chunked_request_body(client_stream, buffer).await?;
        }
        let write_len = remaining.min(buffer.len());
        upstream_stream.write_all(&buffer[..write_len]).await?;
        buffer.drain(..write_len);
        remaining -= write_len;
        stats.request_body_bytes = stats.request_body_bytes.saturating_add(write_len);
    }
    Ok(())
}

async fn stream_chunk_data_terminator(
    client_stream: &mut TcpStream,
    upstream_stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<()> {
    while find_chunk_line_end(buffer).is_none() {
        read_more_chunked_request_body(client_stream, buffer).await?;
    }
    let line_end = find_chunk_line_end(buffer)
        .context("invalid chunked request body: missing chunk data terminator")?;
    if line_end.index != 0 {
        anyhow::bail!("invalid chunked request body: malformed chunk data terminator");
    }
    let terminator_len = line_end.delimiter_len;
    upstream_stream.write_all(&buffer[..terminator_len]).await?;
    buffer.drain(..terminator_len);
    Ok(())
}

async fn stream_chunked_trailers(
    client_stream: &mut TcpStream,
    upstream_stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    limits: http_framing::RequestReadLimits,
) -> Result<bool> {
    loop {
        if let Some(trailer_end) = chunked_trailer_end(buffer) {
            let trailers_seen = trailer_end.trailers_seen;
            upstream_stream
                .write_all(&buffer[..trailer_end.encoded_len])
                .await?;
            buffer.drain(..trailer_end.encoded_len);
            return Ok(trailers_seen);
        }

        if buffer.len() > limits.max_header_bytes {
            anyhow::bail!("chunked request trailers exceed configured header limit");
        }
        read_more_chunked_request_body(client_stream, buffer).await?;
    }
}

struct ChunkedTrailerEnd {
    encoded_len: usize,
    trailers_seen: bool,
}

fn chunked_trailer_end(buffer: &[u8]) -> Option<ChunkedTrailerEnd> {
    if buffer.starts_with(b"\r\n") {
        return Some(ChunkedTrailerEnd {
            encoded_len: 2,
            trailers_seen: false,
        });
    }
    if buffer.starts_with(b"\n") {
        return Some(ChunkedTrailerEnd {
            encoded_len: 1,
            trailers_seen: false,
        });
    }

    http_framing::find_header_end(buffer).map(|end| ChunkedTrailerEnd {
        encoded_len: end.index + end.delimiter_len,
        trailers_seen: end.index > 0,
    })
}

fn find_chunk_line_end(bytes: &[u8]) -> Option<http_framing::HeaderEnd> {
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

fn parse_chunk_size_line(line: &str) -> Result<usize> {
    let size_text = line.split(';').next().unwrap_or_default().trim();
    if size_text.is_empty() {
        anyhow::bail!("invalid chunked request body: empty chunk size");
    }
    usize::from_str_radix(size_text, 16).context("invalid chunked request body: invalid chunk size")
}

async fn send_request_and_read_response_head(
    upstream_stream: &mut TcpStream,
    outbound_request: &[u8],
    forward_target: &str,
    target_url: &str,
) -> Result<Vec<u8>> {
    time::timeout(UPSTREAM_RESPONSE_HEAD_TIMEOUT, async {
        upstream_stream.write_all(outbound_request).await?;
        read_http_response_head(upstream_stream).await
    })
    .await
    .with_context(|| {
        format!("timed out waiting for upstream response headers from `{forward_target}` for `{target_url}`")
    })?
}

async fn write_client_all(
    client_stream: &mut (impl AsyncWrite + Unpin),
    bytes: &[u8],
) -> Result<()> {
    time::timeout(CLIENT_WRITE_TIMEOUT, client_stream.write_all(bytes))
        .await
        .context("timed out writing response to client")??;
    Ok(())
}

async fn forward_persistent_response_body(
    upstream_stream: &mut TcpStream,
    client_stream: &mut TcpStream,
    prebuffered_body: &[u8],
    mode: PersistentResponseBodyMode,
) -> Result<()> {
    match mode {
        PersistentResponseBodyMode::NoBody => Ok(()),
        PersistentResponseBodyMode::ContentLength(content_length) => {
            if content_length <= SMALL_RESPONSE_BUFFER_LIMIT {
                let mut body = Vec::with_capacity(content_length);
                let prebuffered_len = prebuffered_body.len().min(content_length);
                body.extend_from_slice(&prebuffered_body[..prebuffered_len]);

                let remaining = content_length.saturating_sub(prebuffered_len);
                if remaining > 0 {
                    let start_len = body.len();
                    body.resize(content_length, 0);
                    upstream_stream.read_exact(&mut body[start_len..]).await?;
                }

                write_client_all(client_stream, &body).await?;
                return Ok(());
            }

            let prebuffered_len = prebuffered_body.len().min(content_length);
            write_client_all(client_stream, &prebuffered_body[..prebuffered_len]).await?;

            let mut remaining = content_length.saturating_sub(prebuffered_len);
            let mut buffer = vec![0_u8; STREAM_COPY_BUFFER_BYTES];
            while remaining > 0 {
                let read_len = remaining.min(buffer.len());
                time::timeout(
                    UPSTREAM_BODY_IDLE_TIMEOUT,
                    upstream_stream.read_exact(&mut buffer[..read_len]),
                )
                .await
                .context("timed out reading upstream response body")??;
                write_client_all(client_stream, &buffer[..read_len]).await?;
                remaining -= read_len;
            }

            Ok(())
        }
        PersistentResponseBodyMode::Chunked => {
            forward_chunked_response_body(upstream_stream, client_stream, prebuffered_body).await
        }
    }
}

async fn forward_chunked_response_body(
    upstream_stream: &mut TcpStream,
    client_stream: &mut TcpStream,
    prebuffered_body: &[u8],
) -> Result<()> {
    let mut body_buffer = Vec::from(prebuffered_body);
    if let Some(encoded_len) = http_framing::chunked_encoded_len(&body_buffer)? {
        write_client_all(client_stream, &body_buffer[..encoded_len]).await?;
        return Ok(());
    }

    if !prebuffered_body.is_empty() {
        write_client_all(client_stream, prebuffered_body).await?;
    }

    let mut forwarded_len = prebuffered_body.len();
    let mut buffer = vec![0_u8; STREAM_COPY_BUFFER_BYTES];
    loop {
        let read_count = time::timeout(
            UPSTREAM_BODY_IDLE_TIMEOUT,
            upstream_stream.read(&mut buffer),
        )
        .await
        .context("timed out reading chunked upstream response body")??;
        if read_count == 0 {
            anyhow::bail!("upstream closed before completing chunked response body");
        }

        body_buffer.extend_from_slice(&buffer[..read_count]);
        if let Some(encoded_len) = http_framing::chunked_encoded_len(&body_buffer)? {
            if encoded_len > forwarded_len {
                write_client_all(client_stream, &body_buffer[forwarded_len..encoded_len]).await?;
            }
            return Ok(());
        }

        write_client_all(client_stream, &buffer[..read_count]).await?;
        forwarded_len += read_count;
    }
}

async fn handle_gateway_mount(
    state: ProxyAppState,
    client_stream: &mut TcpStream,
    request: ParsedHttpRequest,
    mount: MountSiteConfig,
) -> Result<()> {
    let target_url = fetch::build_target_url(&mount, &request.uri_text)?;
    let uri = target_url.parse::<Uri>()?;
    let host = uri
        .host()
        .context("gateway target URL is missing host")?
        .to_string();
    let target_headers = build_gateway_request_headers(&mount, &request.headers, &uri);
    let prepared = match prepare_outbound_request(
        &state.outbound_request_state(),
        &request,
        target_url,
        Some(host.clone()),
        target_headers,
        mount.upstream_id.clone(),
        "mount request rule decision",
        "Blocked by RelayGate mount request rule.",
        "resource replacement matched mount request",
    )? {
        OutboundRequestDecision::Continue(prepared) => prepared,
        OutboundRequestDecision::Respond(response) => {
            client_stream.write_all(&response).await?;
            client_stream.shutdown().await?;
            return Ok(());
        }
        OutboundRequestDecision::Close => {
            client_stream.shutdown().await?;
            return Ok(());
        }
    };
    let upstream_label = prepared.upstream_id.as_deref().unwrap_or("direct");
    debug!(
        method = %request.method,
        url = %prepared.target_url,
        upstream = %upstream_label,
        "mount forwarding request"
    );

    for attempt in 0..=state.config.traffic.internal_retry_limit {
        let traffic_action = state.traffic_state.action_for_request(
            &prepared.traffic_host,
            &request.method,
            &prepared.request_type,
            &state.config.traffic,
        );
        let mut observed_permit =
            if prepared.observe_traffic && matches!(traffic_action, TrafficAction::Bypass) {
                state
                    .traffic_state
                    .begin_observed_request(&prepared.traffic_host)
            } else {
                None
            };
        let mut traffic_permit = match traffic_action {
            TrafficAction::Managed => Some(
                state
                    .traffic_state
                    .acquire(&prepared.traffic_host, &state.config.traffic)
                    .await?,
            ),
            TrafficAction::Bypass => None,
        };

        let client = build_gateway_http_client(
            &state.upstreams,
            &state.dns_resolver,
            prepared.upstream_id.as_deref(),
        )?;
        let mut outbound = client.request(
            reqwest::Method::from_bytes(request.method.as_bytes())?,
            &prepared.target_url,
        );
        for (name, value) in &prepared.headers {
            if should_forward_gateway_header(name) {
                outbound = outbound.header(name, value);
            }
        }
        if !mount.passthrough_mode {
            outbound = outbound.header(ACCEPT_ENCODING, relaygate_body_pipeline_accept_encoding());
        }
        if !request.body.is_empty() {
            outbound = outbound.body(request.body.clone());
        }

        let upstream_response = match outbound.send().await {
            Ok(response) => response,
            Err(error) => {
                if prepared.observe_traffic {
                    state.traffic_state.on_fatal_error(&prepared.traffic_host);
                }
                return Err(anyhow::Error::from(error));
            }
        };
        let status = upstream_response.status();
        let mut response_headers = upstream_response.headers().clone();
        let response_header_pairs = header_pairs_from_reqwest(&response_headers);
        let response_context = RuleResponseContext {
            url: prepared.target_url.clone(),
            status_code: status.as_u16(),
            headers: response_header_pairs.clone(),
            body_preview: None,
        };
        let response_decision = state.rules.evaluate_response(&response_context);
        let gateway_pipeline_route = gateway_response_pipeline_decision(
            &mount,
            &response_decision.effects,
            state.config.logging.log_response_body,
        );
        let gateway_content_type = content_type_from_reqwest_headers(&response_headers);
        debug!(
            pipeline = %gateway_pipeline_route.pipeline_label(),
            reason = %gateway_pipeline_route.reason,
            request_type = %prepared.request_type,
            content_type = %gateway_content_type,
            status = status.as_u16(),
            url = %prepared.target_url,
            "gateway response pipeline decision"
        );

        if status.as_u16() == 429
            && state
                .traffic_state
                .is_controlled_host(&prepared.traffic_host)
            && request.method.eq_ignore_ascii_case("GET")
            && prepared.request_type == "document"
        {
            let retry_after = traffic::parse_retry_after_secs(&response_header_pairs);
            drop(observed_permit.take());
            drop(traffic_permit.take());
            match state.traffic_state.decide_429_response(
                &prepared.traffic_host,
                attempt,
                retry_after,
                &state.config.traffic,
            ) {
                TrafficResponseDecision::RetryAfterDelay(delay) => {
                    state.traffic_state.begin_retry_wait(&prepared.traffic_host);
                    time::sleep(delay).await;
                    state.traffic_state.end_retry_wait(&prepared.traffic_host);
                    continue;
                }
                TrafficResponseDecision::ReloadPage(delay) => {
                    let response = traffic::reload_page_response(delay, &request.uri_text);
                    client_stream.write_all(&response).await?;
                    client_stream.shutdown().await?;
                    return Ok(());
                }
                TrafficResponseDecision::Forward => {}
            }
        } else if matches!(traffic_action, TrafficAction::Managed) {
            state
                .traffic_state
                .on_success(&prepared.traffic_host, &state.config.traffic);
        }

        let response_body = match read_limited_response_body(
            upstream_response,
            state.config.limits.max_response_buffer_bytes,
        )
        .await
        .map_err(|error| {
            if prepared.observe_traffic {
                state.traffic_state.on_fatal_error(&prepared.traffic_host);
            }
            anyhow::Error::from(error)
        })? {
            Some(body) => body,
            None => {
                warn!(
                    pipeline = %PipelineDecision::Block.as_str(),
                    reason = "response_buffer_limit_exceeded_after_buffering",
                    request_type = %prepared.request_type,
                    content_type = %gateway_content_type,
                    url = %prepared.target_url,
                    limit = state.config.limits.max_response_buffer_bytes,
                    "gateway response body exceeded buffer limit"
                );
                let response = response_buffer_limit_response_bytes();
                client_stream.write_all(&response).await?;
                drop(observed_permit.take());
                client_stream.shutdown().await?;
                return Ok(());
            }
        };
        let mut response_body = apply_response_effects_with_metadata_cleanup(
            response_body,
            &response_decision.effects,
            &mut response_headers,
        );
        response_body = apply_site_specific_gateway_rewrite(
            &state.rewrite_registry,
            &state.adblock_state,
            &prepared.target_url,
            &prepared.source_url,
            &prepared.request_type,
            prepared.fetch_site.as_deref(),
            &state.user_script_registry,
            &mut response_headers,
            response_body,
        )?;

        let content_type = response_headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_ascii_lowercase());
        if !mount.passthrough_mode
            && should_treat_response_body_as_html(
                &prepared.request_type,
                content_type.as_deref().unwrap_or_default(),
                &response_body,
            )
        {
            if let Some(minimal_mode) = &mount.minimal_page_mode {
                response_body = crate::gateway::rewrite::rewrite_minimal_page(
                    &response_body,
                    &mount,
                    minimal_mode,
                    &prepared.target_url,
                )?;
                response_headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                );
            } else if mount.rewrite_links {
                let current_content_type = response_headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.to_string());
                response_body = crate::gateway::rewrite::rewrite_html_links(
                    &response_body,
                    current_content_type.as_deref(),
                    &mount,
                )?;
            }
            response_headers.remove("content-encoding");
            response_headers.remove("content-length");
            response_headers.remove("transfer-encoding");
        }

        if state.config.logging.log_response_body {
            log_response_body(
                "gateway",
                &prepared.target_url,
                response_headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                &response_body,
            );
        }

        let headers = if mount.passthrough_mode {
            passthrough_response_headers(&response_headers, response_body.len())
        } else {
            fetch::rewrite_response_headers(&response_headers, &mount, response_body.len())
        };
        let response = build_buffered_response_bytes(
            status.as_u16(),
            status.canonical_reason().unwrap_or("OK"),
            headers,
            response_body,
        );
        client_stream.write_all(&response).await?;
        drop(observed_permit.take());
        client_stream.shutdown().await?;
        return Ok(());
    }

    client_stream.shutdown().await?;
    Ok(())
}

fn gateway_response_pipeline_decision(
    mount: &MountSiteConfig,
    response_effects: &[RuleEffect],
    log_response_body: bool,
) -> PipelineRoute {
    if log_response_body {
        return PipelineRoute::deep_path("logging_response_body_enabled");
    }

    if response_effects
        .iter()
        .any(|effect| matches!(effect, RuleEffect::RewriteResponseBody { .. }))
    {
        return PipelineRoute::deep_path("response_rule_rewrite_body");
    }

    if mount.passthrough_mode {
        return PipelineRoute::deep_path("gateway_passthrough_mode_existing_buffered_body");
    }

    if mount.minimal_page_mode.is_some() {
        return PipelineRoute::deep_path("gateway_minimal_page_rewrite_available");
    }

    if mount.rewrite_links {
        return PipelineRoute::deep_path("gateway_link_rewrite_available");
    }

    PipelineRoute::deep_path("gateway_mount_body_pipeline")
}

fn content_type_from_reqwest_headers(headers: &HeaderMap) -> String {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn content_type_from_header_pairs(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default()
}

fn header_pairs_have(headers: &[(String, String)], name: &str) -> bool {
    headers
        .iter()
        .any(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
}

async fn read_limited_response_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Ok(None);
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }

    Ok(Some(body))
}

fn find_gateway_mount(
    config: &RelayGateConfig,
    request_path: &str,
) -> Option<crate::config::MountSiteConfig> {
    let lookup_path = mount_lookup_path(request_path);
    if lookup_path.starts_with('/') {
        if let Ok(config) = RelayGateConfig::load_default() {
            return config.find_mount_by_path(&lookup_path).cloned();
        }
    }

    config.find_mount_by_path(&lookup_path).cloned()
}

fn mount_lookup_path(request_target: &str) -> String {
    request_target
        .parse::<Uri>()
        .ok()
        .and_then(|uri| uri.path_and_query().map(|value| value.as_str().to_string()))
        .unwrap_or_else(|| request_target.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{http_framing::RequestHeadFrame, http_parse::ParsedHttpResponseHead};
    use tokio::io::duplex;

    fn request(version: &str, headers: Vec<(&str, &str)>) -> ParsedHttpRequest {
        ParsedHttpRequest {
            method: "GET".to_string(),
            uri_text: "http://www.example.com/".to_string(),
            version: version.to_string(),
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    fn response(status_code: u16, headers: Vec<(&str, &str)>) -> ParsedHttpResponseHead {
        ParsedHttpResponseHead {
            version: "HTTP/1.1".to_string(),
            status_code,
            reason_phrase: "OK".to_string(),
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        }
    }

    #[test]
    fn http_11_request_keeps_client_connection_alive_by_default() {
        let request = request("HTTP/1.1", vec![("Host", "www.example.com")]);

        assert!(should_keep_client_connection_alive(&request));
    }

    #[test]
    fn connection_close_disables_client_keep_alive() {
        let request = request(
            "HTTP/1.1",
            vec![("Host", "www.example.com"), ("Connection", "close")],
        );

        assert!(!should_keep_client_connection_alive(&request));
    }

    #[test]
    fn persistent_response_requires_known_body_boundary() {
        let request = request("HTTP/1.1", vec![("Host", "www.example.com")]);

        assert_eq!(
            persistent_response_body_mode(&request, &response(200, vec![("Content-Length", "5")])),
            Some(PersistentResponseBodyMode::ContentLength(5))
        );
        assert_eq!(
            persistent_response_body_mode(
                &request,
                &response(200, vec![("Transfer-Encoding", "chunked")])
            ),
            Some(PersistentResponseBodyMode::Chunked)
        );
        assert_eq!(
            persistent_response_body_mode(&request, &response(200, Vec::new())),
            None
        );
    }

    #[test]
    fn no_body_status_can_keep_client_connection_alive() {
        let request = request("HTTP/1.1", vec![("Host", "www.example.com")]);

        assert_eq!(
            persistent_response_body_mode(&request, &response(204, Vec::new())),
            Some(PersistentResponseBodyMode::NoBody)
        );
    }

    #[test]
    fn interim_status_does_not_enable_client_keep_alive() {
        let request = request("HTTP/1.1", vec![("Host", "www.example.com")]);

        assert_eq!(
            persistent_response_body_mode(&request, &response(103, Vec::new())),
            None
        );
    }

    #[test]
    fn upstream_reuse_respects_connection_close_response() {
        assert!(!should_keep_upstream_connection_alive(&response(
            200,
            vec![("Connection", "close")]
        )));
        assert!(should_keep_upstream_connection_alive(&response(
            200,
            vec![("Content-Length", "0")]
        )));
    }

    #[test]
    fn upstream_reuse_only_allows_safe_methods() {
        assert!(request_method_can_reuse_upstream("GET"));
        assert!(request_method_can_reuse_upstream("HEAD"));
        assert!(!request_method_can_reuse_upstream("POST"));
    }

    #[tokio::test]
    async fn control_panel_request_buffers_post_body_before_dispatch() {
        let config = RelayGateConfig::default();
        let body = br#"{"upstream_protocol":"guarded_h3","downstream_protocol":"http2_enabled"}"#;
        let content_length = body.len();
        let request_head = RequestHeadFrame {
            head_bytes: format!(
                "POST http://127.0.0.1:8787/backend/actions/update-protocol-settings HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\n\r\n"
            )
            .into_bytes(),
            prebuffered_body: Vec::new(),
            body_kind: http_framing::RequestBodyKind::ContentLength(content_length),
            expect_100_continue: false,
        };

        let (mut client_stream, mut writer) = duplex(1024);
        let write_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            writer.write_all(body).await.unwrap();
        });

        let parsed = buffer_request_for_existing_path(
            &mut client_stream,
            request_head,
            &config,
            "test_control_panel_existing_buffered_request_body",
        )
        .await
        .unwrap()
        .unwrap();

        write_task.await.unwrap();
        assert_eq!(parsed.body, body);
    }
}
