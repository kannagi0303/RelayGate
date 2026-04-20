use std::{io::ErrorKind, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{Request, Uri},
};
use http_body_util::BodyExt;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};
use tower::util::ServiceExt;
use tracing::{debug, info, warn};

use crate::{
    adblock::{self, AdblockMatch, SharedAdblockState},
    config::RelayGateConfig,
    diagnostics,
    gateway::fetch::{fetch_mount, GatewayResponse},
    proxy::{
        mitm::MitmEngine,
        rules::{RuleEffect, RuleEngine, RuleRequestContext, RuleResponseContext},
        upstream::UpstreamRegistry,
    },
    rewrite::SharedRewriteRegistry,
    runtime::AppRuntime,
    traffic::{self, SharedTrafficState, TrafficAction, TrafficResponseDecision},
    web::server::{build_app as build_control_panel_app, build_state as build_web_state},
};

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
pub struct ProxyServer {
    config: Arc<RelayGateConfig>,
    rules: RuleEngine,
    upstreams: UpstreamRegistry,
    rewrite_registry: SharedRewriteRegistry,
    adblock_state: SharedAdblockState,
    traffic_state: SharedTrafficState,
    control_panel_app: axum::Router,
}

#[derive(Clone)]
struct ProxyAppState {
    config: Arc<RelayGateConfig>,
    mitm: MitmEngine,
    rules: RuleEngine,
    upstreams: UpstreamRegistry,
    adblock_state: SharedAdblockState,
    traffic_state: SharedTrafficState,
    control_panel_app: axum::Router,
}

#[derive(Debug, Clone)]
struct ParsedHttpRequest {
    method: String,
    uri_text: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ProxyServer {
    pub fn new(
        config: Arc<RelayGateConfig>,
        rewrite_registry: SharedRewriteRegistry,
        adblock_state: SharedAdblockState,
        traffic_state: SharedTrafficState,
        runtime: AppRuntime,
    ) -> Self {
        let rules = RuleEngine::from_config(&config.rules);
        let upstreams = UpstreamRegistry::from_config(&config.upstreams);

        Self {
            config: config.clone(),
            rules,
            upstreams,
            rewrite_registry: rewrite_registry.clone(),
            adblock_state: adblock_state.clone(),
            traffic_state: traffic_state.clone(),
            control_panel_app: build_control_panel_app(build_web_state(
                config.clone(),
                rewrite_registry.clone(),
                adblock_state.clone(),
                traffic_state,
                runtime.clone(),
            )),
        }
    }

    pub async fn run(self) -> Result<()> {
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
                self.rewrite_registry.clone(),
                self.adblock_state.clone(),
                self.traffic_state.clone(),
            ),
            rules: self.rules,
            upstreams: self.upstreams,
            adblock_state: self.adblock_state,
            traffic_state: self.traffic_state,
            control_panel_app: self.control_panel_app,
        };

        let listener = TcpListener::bind(addr).await?;

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let state = state.clone();

            tokio::spawn(async move {
                if let Err(error) = handle_client(state, stream).await {
                    log_connection_error(peer_addr, &error);
                }
            });
        }
    }

    fn log_bootstrap_summary(&self) {
        debug!(
            rule_count = self.rules.rule_count(),
            upstream_count = self.upstreams.len(),
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

async fn handle_client(state: ProxyAppState, mut client_stream: TcpStream) -> Result<()> {
    let request_bytes = read_http_request(&mut client_stream).await?;

    match proxy_request(state, &mut client_stream, &request_bytes).await {
        Ok(()) => Ok(()),
        Err(error) => {
            if is_expected_disconnect(&error)
                || is_incomplete_http_request(&error)
                || is_expected_mitm_handshake_abort(&error)
            {
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
            Ok(())
        }
    }
}

async fn proxy_request(
    state: ProxyAppState,
    client_stream: &mut TcpStream,
    request_bytes: &[u8],
) -> Result<()> {
    let request = parse_http_request(request_bytes)?;

    if is_control_panel_request(&request, state.config.as_ref()) {
        return handle_control_panel_proxy(state, client_stream, request).await;
    }

    if let Some(mount) = state.config.find_mount_by_path(&request.uri_text).cloned() {
        return handle_gateway_mount(state, client_stream, request, mount).await;
    }

    if request.method.eq_ignore_ascii_case("CONNECT") {
        return handle_connect_tunnel(state, client_stream, &request).await;
    }

    handle_http_forward(state, client_stream, request).await
}

async fn handle_control_panel_proxy(
    state: ProxyAppState,
    client_stream: &mut TcpStream,
    request: ParsedHttpRequest,
) -> Result<()> {
    let app_request = build_control_panel_request(&request)?;

    let mut response = state
        .control_panel_app
        .clone()
        .oneshot(app_request)
        .await
        .context("failed to dispatch control panel request")?;

    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("OK");
    let mut head = Vec::new();
    head.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason).as_bytes());

    let mut is_streaming = false;
    for (name, value) in response.headers() {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "content-type"
            && value
                .to_str()
                .map(|text| text.contains("text/event-stream"))
                .unwrap_or(false)
        {
            is_streaming = true;
        }

        if lower == "connection" || lower == "transfer-encoding" {
            continue;
        }

        if let Ok(value_text) = value.to_str() {
            head.extend_from_slice(format!("{}: {}\r\n", name.as_str(), value_text).as_bytes());
        }
    }

    if !is_streaming {
        let collected = response
            .body_mut()
            .collect()
            .await
            .context("failed to collect control panel response body")?
            .to_bytes();
        head.extend_from_slice(format!("Content-Length: {}\r\n", collected.len()).as_bytes());
        head.extend_from_slice(b"Connection: close\r\n\r\n");
        client_stream.write_all(&head).await?;
        client_stream.write_all(&collected).await?;
        client_stream.shutdown().await?;
        return Ok(());
    }

    head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    client_stream.write_all(&head).await?;

    let mut body = response.into_body();
    while let Some(frame) = body.frame().await {
        let frame = frame.context("failed to read control panel streaming frame")?;
        if let Some(data) = frame.data_ref() {
            let chunk_prefix = format!("{:X}\r\n", data.len());
            client_stream.write_all(chunk_prefix.as_bytes()).await?;
            client_stream.write_all(data).await?;
            client_stream.write_all(b"\r\n").await?;
        }
    }
    client_stream.write_all(b"0\r\n\r\n").await?;
    client_stream.shutdown().await?;
    Ok(())
}

async fn handle_http_forward(
    state: ProxyAppState,
    client_stream: &mut TcpStream,
    request: ParsedHttpRequest,
) -> Result<()> {
    let uri = request.uri_text.parse::<Uri>()?;
    let target_url = build_target_url(&uri, &request.headers)?;
    let host = uri
        .host()
        .map(str::to_string)
        .or_else(|| extract_host_from_pairs(&request.headers));

    let request_context = RuleRequestContext {
        host,
        url: target_url.clone(),
        method: request.method.clone(),
        headers: request.headers.clone(),
    };

    let request_decision = state.rules.evaluate_request(&request_context);
    debug!(?request_decision, "request rule decision");

    if request_decision
        .effects
        .iter()
        .any(|effect| matches!(effect, RuleEffect::Block))
    {
        let response =
            simple_response_bytes(403, "Forbidden", "Blocked by RelayGate request rule.");
        client_stream.write_all(&response).await?;
        client_stream.shutdown().await?;
        return Ok(());
    }

    let request_type = adblock::classify_request_type(&request.method, &request.headers);
    let adblock_match = adblock_match_for_request(
        &state.adblock_state,
        &request.method,
        &target_url,
        &request.headers,
    )?;
    if let Some(redirect) = adblock_match.redirect.as_ref() {
        let response = simple_response_bytes_with_content_type(
            200,
            "OK",
            &redirect.content_type,
            &redirect.body,
        );
        client_stream.write_all(&response).await?;
        client_stream.shutdown().await?;
        return Ok(());
    }
    if adblock_match.matched {
        if should_abort_adblock_request(&adblock_match.request_type) {
            client_stream.shutdown().await?;
        } else {
            let response = simple_response_bytes(403, "Forbidden", "Blocked by RelayGate adblock.");
            client_stream.write_all(&response).await?;
            client_stream.shutdown().await?;
        }
        return Ok(());
    }

    let upstream_id = request_decision
        .effects
        .iter()
        .find_map(|effect| match effect {
            RuleEffect::UseUpstream { upstream_id } => Some(upstream_id.clone()),
            _ => None,
        });

    let traffic_host = normalize_request_host(
        request_context
            .host
            .as_deref()
            .or_else(|| uri.host())
            .unwrap_or("unknown"),
    );
    let observe_traffic = state.traffic_state.is_controlled_host(&traffic_host)
        && request.method.eq_ignore_ascii_case("GET")
        && request_type == "document";
    let upstream_label = upstream_id.as_deref().unwrap_or("direct");
    debug!(
        method = %request.method,
        url = %target_url,
        upstream = %upstream_label,
        "forwarding request"
    );

    let response_context = RuleResponseContext {
        url: target_url.clone(),
        status_code: 0,
        headers: Vec::new(),
        body_preview: None,
    };
    let response_decision = state.rules.evaluate_response(&response_context);
    if response_decision
        .effects
        .iter()
        .any(|effect| matches!(effect, RuleEffect::RewriteResponseBody { .. }))
    {
        warn!("response body rewrite is not applied in raw streaming mode yet");
    }

    for attempt in 0..=state.config.traffic.internal_retry_limit {
        let traffic_action = state.traffic_state.action_for_request(
            &traffic_host,
            &request.method,
            request_type,
            &state.config.traffic,
        );
        let mut observed_permit =
            if observe_traffic && matches!(traffic_action, TrafficAction::Bypass) {
                state.traffic_state.begin_observed_request(&traffic_host)
            } else {
                None
            };
        let mut traffic_permit = match traffic_action {
            TrafficAction::Managed => Some(
                state
                    .traffic_state
                    .acquire(&traffic_host, &state.config.traffic)
                    .await?,
            ),
            TrafficAction::Bypass => None,
        };
        let outbound_request = build_upstream_request(
            &request,
            &uri,
            &request_decision.effects,
            upstream_id.as_deref(),
        )?;
        let forward_target =
            resolve_forward_target(&state.upstreams, &uri, upstream_id.as_deref())?;
        let mut upstream_stream = TcpStream::connect(&forward_target)
            .await
            .with_context(|| {
                format!(
                    "failed to connect upstream target `{forward_target}` for `{}`",
                    request_context.url
                )
            })
            .map_err(|error| {
                if observe_traffic {
                    state.traffic_state.on_fatal_error(&traffic_host);
                }
                error
            })?;
        upstream_stream
            .write_all(&outbound_request)
            .await
            .map_err(|error| {
                if observe_traffic {
                    state.traffic_state.on_fatal_error(&traffic_host);
                }
                anyhow::Error::from(error)
            })?;
        upstream_stream.shutdown().await.map_err(|error| {
            if observe_traffic {
                state.traffic_state.on_fatal_error(&traffic_host);
            }
            anyhow::Error::from(error)
        })?;

        let response_head = read_http_response_head(&mut upstream_stream)
            .await
            .map_err(|error| {
                if observe_traffic {
                    state.traffic_state.on_fatal_error(&traffic_host);
                }
                error
            })?;
        let response_meta = parse_http_response_head(&response_head).map_err(|error| {
            if observe_traffic {
                state.traffic_state.on_fatal_error(&traffic_host);
            }
            error
        })?;

        if response_meta.status_code == 429
            && state.traffic_state.is_controlled_host(&traffic_host)
            && request.method.eq_ignore_ascii_case("GET")
            && request_type == "document"
        {
            let retry_after = traffic::parse_retry_after_secs(&response_meta.headers);
            drop(observed_permit.take());
            drop(traffic_permit.take());
            match state.traffic_state.decide_429_response(
                &traffic_host,
                attempt,
                retry_after,
                &state.config.traffic,
            ) {
                TrafficResponseDecision::RetryAfterDelay(delay) => {
                    drop(upstream_stream);
                    state.traffic_state.begin_retry_wait(&traffic_host);
                    time::sleep(delay).await;
                    state.traffic_state.end_retry_wait(&traffic_host);
                    continue;
                }
                TrafficResponseDecision::ReloadPage(delay) => {
                    let response = traffic::reload_page_response(delay, &target_url);
                    client_stream.write_all(&response).await?;
                    client_stream.shutdown().await?;
                    return Ok(());
                }
                TrafficResponseDecision::Forward => {}
            }
        } else if matches!(traffic_action, TrafficAction::Managed) {
            state
                .traffic_state
                .on_success(&traffic_host, &state.config.traffic);
        }

        client_stream.write_all(&response_head).await?;
        io::copy(&mut upstream_stream, client_stream).await?;
        drop(observed_permit.take());
        client_stream.shutdown().await?;
        return Ok(());
    }

    Ok(())
}

async fn handle_gateway_mount(
    state: ProxyAppState,
    client_stream: &mut TcpStream,
    request: ParsedHttpRequest,
    mount: crate::config::MountSiteConfig,
) -> Result<()> {
    let gateway_response = fetch_mount(
        &mount,
        &request.method,
        &request.uri_text,
        &request.headers,
        &request.body,
        &state.config.upstreams,
        state.config.logging.log_response_body,
    )
    .await?;

    let response_bytes = build_gateway_response_bytes(gateway_response);
    client_stream.write_all(&response_bytes).await?;
    client_stream.shutdown().await?;
    Ok(())
}

async fn handle_connect_tunnel(
    state: ProxyAppState,
    client_stream: &mut TcpStream,
    request: &ParsedHttpRequest,
) -> Result<()> {
    let authority = request.uri_text.trim();

    if state.mitm.enabled() && state.mitm.should_intercept_host(authority) {
        return state.mitm.handle_connect(client_stream, authority).await;
    }

    let connect_target = resolve_connect_target(&state.upstreams, authority)?;

    let host = authority
        .split(':')
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let request_context = RuleRequestContext {
        host,
        url: format!("https://{authority}"),
        method: request.method.clone(),
        headers: request.headers.clone(),
    };

    let request_decision = state.rules.evaluate_request(&request_context);
    debug!(?request_decision, "connect rule decision");

    if request_decision
        .effects
        .iter()
        .any(|effect| matches!(effect, RuleEffect::Block))
    {
        let response =
            simple_response_bytes(403, "Forbidden", "Blocked by RelayGate CONNECT rule.");
        client_stream.write_all(&response).await?;
        client_stream.shutdown().await?;
        return Ok(());
    }

    let mut upstream_stream = TcpStream::connect(&connect_target).await.with_context(|| {
        format!("failed to connect CONNECT target `{connect_target}` for authority `{authority}`")
    })?;
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
        .await?;
    io::copy_bidirectional(client_stream, &mut upstream_stream).await?;
    Ok(())
}

fn adblock_match_for_request(
    adblock_state: &SharedAdblockState,
    method: &str,
    target_url: &str,
    headers: &[(String, String)],
) -> Result<AdblockMatch> {
    let request_type = adblock::classify_request_type(method, headers);
    let source_url = adblock::source_url_for_request(target_url, headers);
    let fetch_site = adblock::fetch_site_for_request(headers);
    adblock::check_url(
        adblock_state,
        target_url,
        &source_url,
        request_type,
        fetch_site.as_deref(),
    )
}

fn should_abort_adblock_request(request_type: &str) -> bool {
    !matches!(request_type, "document" | "subdocument")
}

fn build_target_url(uri: &Uri, headers: &[(String, String)]) -> Result<String> {
    if let Some(scheme) = uri.scheme_str() {
        if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
            return Ok(uri.to_string());
        }
    }

    let host =
        extract_host_from_pairs(headers).context("missing Host header for proxied HTTP request")?;
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    Ok(format!("http://{host}{path}"))
}

fn is_control_panel_request(request: &ParsedHttpRequest, config: &RelayGateConfig) -> bool {
    let host = request
        .uri_text
        .parse::<Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_string))
        .or_else(|| extract_host_from_pairs(&request.headers));

    let Some(host) = host else {
        return false;
    };

    matches!(
        host.as_str(),
        "rg.local"
            | "rg.localhost"
            | "127.0.0.1:8787"
            | "localhost:8787"
            | "127.0.0.1:8788"
            | "localhost:8788"
    ) || matches_listen_address(&host, &config.proxy.listen)
        || matches_listen_address(&host, &config.web.listen)
}

fn matches_listen_address(request_host: &str, listen: &str) -> bool {
    let Some((listen_host, listen_port)) = split_host_port(listen) else {
        return request_host.eq_ignore_ascii_case(listen);
    };
    let Some((request_only_host, request_port)) = split_host_port(request_host) else {
        return false;
    };

    if request_port != listen_port {
        return false;
    }

    let normalized_listen_host = listen_host.trim_matches(['[', ']']);
    let normalized_request_host = request_only_host.trim_matches(['[', ']']);

    if normalized_listen_host.eq_ignore_ascii_case(normalized_request_host) {
        return true;
    }

    matches!(normalized_listen_host, "0.0.0.0" | "::" | "::0")
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    value.rsplit_once(':')
}

fn build_control_panel_request(request: &ParsedHttpRequest) -> Result<Request<Body>> {
    let uri = request.uri_text.parse::<Uri>()?;
    let target = if uri.scheme().is_some() {
        uri.path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    } else if request.uri_text.is_empty() {
        "/".to_string()
    } else {
        request.uri_text.clone()
    };

    let mut builder = Request::builder()
        .method(request.method.as_str())
        .uri(target);

    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "proxy-connection" | "connection" | "content-length"
        ) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }

    Ok(builder.body(Body::from(request.body.clone()))?)
}

fn resolve_forward_target(
    upstreams: &UpstreamRegistry,
    uri: &Uri,
    upstream_id: Option<&str>,
) -> Result<String> {
    if let Some(upstream_id) = upstream_id {
        let upstream = upstreams
            .resolve(upstream_id)
            .with_context(|| format!("upstream `{upstream_id}` not found or disabled"))?;

        let upstream_uri = upstream.address.parse::<Uri>()?;
        let host = upstream_uri
            .host()
            .context("configured upstream proxy is missing host")?;
        let port = upstream_uri.port_u16().unwrap_or(80);
        return Ok(format!("{host}:{port}"));
    }

    let host = uri.host().context("target URI is missing host")?;
    let port = uri.port_u16().unwrap_or(80);
    Ok(format!("{host}:{port}"))
}

fn resolve_connect_target(upstreams: &UpstreamRegistry, authority: &str) -> Result<String> {
    // The first CONNECT version goes straight to the target host and skips upstream proxies.
    // If CONNECT should support upstreams later, extend this part.
    let _ = upstreams;

    if authority.contains(':') {
        return Ok(authority.to_string());
    }

    Ok(format!("{authority}:443"))
}

fn build_upstream_request(
    request: &ParsedHttpRequest,
    uri: &Uri,
    effects: &[RuleEffect],
    upstream_id: Option<&str>,
) -> Result<Vec<u8>> {
    let request_target = if upstream_id.is_some() {
        build_target_url(uri, &request.headers)?
    } else {
        uri.path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    };

    let mut headers = request.headers.clone();
    headers.retain(|(name, _)| !should_skip_request_header(name));

    for effect in effects {
        if let RuleEffect::RewriteHeader { name, value } = effect {
            upsert_header(&mut headers, name, value);
        }
    }

    if extract_host_from_pairs(&headers).is_none() {
        if let Some(host) = uri.host() {
            let host_value = match uri.port_u16() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            headers.push(("Host".to_string(), host_value));
        }
    }

    upsert_header(&mut headers, "Connection", "close");
    upsert_header(
        &mut headers,
        "Content-Length",
        &request.body.len().to_string(),
    );

    let mut output = Vec::new();
    output.extend_from_slice(
        format!(
            "{} {} {}\r\n",
            request.method, request_target, request.version
        )
        .as_bytes(),
    );

    for (name, value) in headers {
        output.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&request.body);
    Ok(output)
}

async fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
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

fn parse_http_request(bytes: &[u8]) -> Result<ParsedHttpRequest> {
    let header_end =
        find_header_end(bytes).context("invalid HTTP request: missing header terminator")?;
    let header_text = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = header_text.split("\r\n");

    let request_line = lines
        .next()
        .context("invalid HTTP request: missing request line")?;
    let mut request_parts = request_line.splitn(3, ' ');
    let method = request_parts
        .next()
        .context("invalid HTTP request: missing method")?;
    let uri_text = request_parts
        .next()
        .context("invalid HTTP request: missing uri")?;
    let version = request_parts
        .next()
        .context("invalid HTTP request: missing version")?;

    let headers = lines
        .filter(|line| !line.is_empty())
        .map(parse_header_line)
        .collect::<Result<Vec<_>>>()?;

    Ok(ParsedHttpRequest {
        method: method.to_string(),
        uri_text: uri_text.to_string(),
        version: version.to_string(),
        headers,
        body: bytes[header_end + 4..].to_vec(),
    })
}

fn parse_header_line(line: &str) -> Result<(String, String)> {
    let (name, value) = line
        .split_once(':')
        .with_context(|| format!("invalid HTTP header line: {line}"))?;
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

async fn read_http_response_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];

    loop {
        let read_count = stream.read(&mut temp).await?;
        if read_count == 0 {
            break;
        }

        buffer.extend_from_slice(&temp[..read_count]);
        if find_header_end(&buffer).is_some() {
            break;
        }
    }

    Ok(buffer)
}

fn parse_http_response_head(bytes: &[u8]) -> Result<ParsedHttpResponseHead> {
    let header_end =
        find_header_end(bytes).context("invalid HTTP response: missing header terminator")?;
    let header_text = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .context("invalid HTTP response: missing status line")?;
    let mut status_parts = status_line.splitn(3, ' ');
    status_parts
        .next()
        .context("invalid HTTP response: missing version")?;
    let status_code = status_parts
        .next()
        .context("invalid HTTP response: missing status code")?
        .parse::<u16>()?;
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(parse_header_line)
        .collect::<Result<Vec<_>>>()?;

    Ok(ParsedHttpResponseHead {
        status_code,
        headers,
    })
}

fn extract_host_from_pairs(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.clone())
}

fn normalize_request_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase()
}

fn should_skip_request_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "proxy-connection" | "connection" | "content-length"
    )
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

fn simple_response_bytes(status_code: u16, reason_phrase: &str, body: &str) -> Vec<u8> {
    let body_bytes = body.as_bytes();
    simple_response_bytes_with_content_type(
        status_code,
        reason_phrase,
        "text/plain; charset=utf-8",
        body_bytes,
    )
}

fn simple_response_bytes_with_content_type(
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

fn build_gateway_response_bytes(response: GatewayResponse) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(
        format!(
            "HTTP/1.1 {} {}\r\n",
            response.status_code, response.reason_phrase
        )
        .as_bytes(),
    );

    for (name, value) in response.headers {
        output.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&response.body);
    output
}

struct ParsedHttpResponseHead {
    status_code: u16,
    headers: Vec<(String, String)>,
}

fn log_connection_error(peer_addr: SocketAddr, error: &anyhow::Error) {
    if is_expected_disconnect(error)
        || is_incomplete_http_request(error)
        || is_expected_mitm_handshake_abort(error)
    {
        debug!(peer = %peer_addr, error = %error, "proxy connection closed early");
        return;
    }

    let error_chain = diagnostics::format_error_chain(error);
    let console_error = diagnostics::format_error_for_console(error);
    let console_error_chain = diagnostics::format_error_chain_for_console(error);
    let _ = diagnostics::append_proxy_diagnostic(&format!(
        "ts={} peer={} event=proxy_connection_failed error_chain={}",
        diagnostics::diagnostic_timestamp(),
        peer_addr,
        error_chain
    ));
    warn!(
        peer = %peer_addr,
        error = %console_error,
        error_chain = %console_error_chain,
        "proxy connection failed"
    );
}

fn is_expected_disconnect(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io_error| {
            io_error.kind() == ErrorKind::ConnectionAborted
                || io_error.kind() == ErrorKind::ConnectionReset
                || matches!(io_error.raw_os_error(), Some(10053 | 10054))
        })
}

fn is_incomplete_http_request(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .to_string()
            .contains("invalid HTTP request: missing header terminator")
    })
}

fn is_expected_mitm_handshake_abort(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let text = cause.to_string();
        text.contains("failed to accept TLS from client during MITM handshake")
            || text.contains("received fatal alert")
            || text.contains("unexpected eof")
            || text.contains("peer closed connection without sending TLS close_notify")
            || text.contains("Handshake not complete")
    })
}
