use std::{
    collections::{hash_map::DefaultHasher, BTreeSet},
    fmt,
    future::poll_fn,
    hash::{Hash, Hasher},
    net::IpAddr,
    time::Duration,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode, Uri};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
    Body,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time,
};
use tracing::{debug, warn};

use crate::{
    config::Http3StreamingResponseModeConfig,
    diagnostics,
    proxy::{
        downstream_status::{self, DownstreamStatusProtocol},
        header_hop::should_apply_request_header_rewrite,
        http_parse::{parse_http_response_head, read_http_response_head},
        mitm::{build_mitm_websocket_upstream_request_from_parts, MitmEngine},
        mitm_ca::normalize_authority,
        mitm_core::{
            allow_active_h3_buffered_for_request, has_browser_storage_access_header,
            mitm_response_pipeline_decision, prepare_mitm_request, process_mitm_response_body,
            response_body_pipeline_preflight_reason, MitmLocalResponse, MitmLocalResponseBody,
            MitmRequestDecision, PreparedMitmRequest,
        },
        mitm_http::{is_upstream_certificate_error, log_response_body},
        mount_forward::header_pairs_from_reqwest,
        rules::{RuleEffect, RuleResponseContext},
        upstream_h3,
        upstream_model::{RelayUpstreamBufferedResponse, RelayUpstreamStreamingResponse},
    },
    traffic::{self, TrafficAction, TrafficResponseDecision},
};

const DOWNSTREAM_H2_DATA_FRAME_BYTES: usize = 16 * 1024;
const H2_WEBSOCKET_UPSTREAM_RESPONSE_HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Downstream HTTP/2 MITM adapter.
///
/// This module owns only browser -> RelayGate HTTP/2 connection and stream
/// framing. RelayGate features such as DNS, adblock, rewrite, patch, replace,
/// upstream routing, and traffic control must continue to live in the shared
/// MITM core / upstream connector instead of being duplicated here.

#[derive(Debug)]
struct DownstreamH2StreamCancelled {
    operation: &'static str,
    detail: String,
}

impl fmt::Display for DownstreamH2StreamCancelled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "downstream HTTP/2 stream cancelled while {}: {}",
            self.operation, self.detail
        )
    }
}

impl std::error::Error for DownstreamH2StreamCancelled {}

fn downstream_h2_stream_cancelled(
    operation: &'static str,
    error: impl fmt::Display,
) -> anyhow::Error {
    DownstreamH2StreamCancelled {
        operation,
        detail: error.to_string(),
    }
    .into()
}

fn is_downstream_h2_stream_cancelled(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<DownstreamH2StreamCancelled>()
        .is_some()
}

fn is_expected_h2_upstream_connect_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let text = cause.to_string().to_ascii_lowercase();
        text.contains("dns error")
            || text.contains("failed to resolve")
            || text.contains("tcp connect error")
            || text.contains("error sending request")
            || text.contains("client error (connect)")
            || text.contains("os error 10060")
            || text.contains("timed out")
            || text.contains("連線嘗試失敗")
    })
}

fn h3_streaming_backend_error_should_cooldown(kind: upstream_h3::UpstreamBackendErrorKind) -> bool {
    matches!(
        kind,
        upstream_h3::UpstreamBackendErrorKind::DnsError
            | upstream_h3::UpstreamBackendErrorKind::UdpError
            | upstream_h3::UpstreamBackendErrorKind::QuicConnectTimeout
            | upstream_h3::UpstreamBackendErrorKind::QuicHandshakeError
            | upstream_h3::UpstreamBackendErrorKind::TlsError
            | upstream_h3::UpstreamBackendErrorKind::H3Error
    )
}

fn is_expected_h2_accept_shutdown(error: &h2::Error) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("connection error detected")
        || text.contains("excessive load generating behavior")
        || text.contains("stream no longer needed")
        || text.contains("cancel")
}

pub(crate) async fn handle_mitm_h2_connection<IO>(
    engine: MitmEngine,
    io: IO,
    authority: String,
    host: String,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    debug!(authority = %authority, "MITM downstream HTTP/2 adapter starting");

    let mut builder = h2::server::Builder::new();
    builder.enable_connect_protocol();
    let mut connection = builder
        .handshake(io)
        .await
        .context("failed to accept downstream HTTP/2 MITM connection")?;

    while let Some(accepted) = connection.accept().await {
        let (request, respond) = match accepted {
            Ok(item) => item,
            Err(error) => {
                if is_expected_h2_accept_shutdown(&error) {
                    debug!(
                        authority = %authority,
                        error = %error,
                        "downstream HTTP/2 MITM connection closed while accepting streams"
                    );
                } else {
                    warn!(
                        authority = %authority,
                        error = %error,
                        "failed to accept downstream HTTP/2 MITM stream"
                    );
                }
                break;
            }
        };

        let stream_engine = engine.clone();
        let stream_authority = authority.clone();
        let stream_host = host.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_mitm_h2_stream(
                stream_engine,
                stream_authority.clone(),
                stream_host,
                request,
                respond,
            )
            .await
            {
                if is_downstream_h2_stream_cancelled(&error) {
                    debug!(error = %error, "downstream HTTP/2 MITM stream ended by client reset/cancel");
                } else {
                    let error_chain = diagnostics::format_error_chain_for_console(&error);
                    let _ = diagnostics::append_proxy_diagnostic(&format!(
                        "{} event=mitm_h2_stream_failed authority={} error_chain={}",
                        diagnostics::diagnostic_timestamp(),
                        stream_authority,
                        diagnostics::format_error_chain(&error)
                    ));
                    warn!(error = %error_chain, "failed to handle downstream HTTP/2 MITM stream");
                }
            }
        });
    }

    debug!(authority = %authority, "MITM downstream HTTP/2 adapter finished");
    Ok(())
}

async fn handle_mitm_h2_stream(
    engine: MitmEngine,
    authority: String,
    host: String,
    request: Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
) -> Result<()> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let extended_connect_protocol = request
        .extensions()
        .get::<h2::ext::Protocol>()
        .map(|protocol| protocol.as_str().to_string());
    let (parts, body) = request.into_parts();
    let target_url = h2_target_url(&authority, &uri)?;
    let target_authority = h2_target_authority(&authority, &uri);
    let method_text = method.as_str().to_string();
    let core_headers = h2_headers_for_core(&headers, &target_authority);

    debug!(
        authority = %authority,
        method = %method,
        uri = %uri,
        url = %target_url,
        headers = headers.len(),
        "MITM downstream HTTP/2 stream accepted"
    );
    downstream_status::record_mitm_request(
        DownstreamStatusProtocol::MitmHttp2,
        &authority,
        &target_url,
        "h2",
    );

    if downstream_status::is_downstream_status_url(&target_url) {
        drain_h2_request_body(body).await?;
        let response = downstream_status::mitm_status_response(
            DownstreamStatusProtocol::MitmHttp2,
            engine.mitm_response_state().config,
            &authority,
            &target_url,
            "h2",
        );
        return send_h2_local_response(respond, response, method == http::Method::HEAD).await;
    }

    let prepared_request = match prepare_mitm_request(
        &engine.mitm_request_state(),
        &host,
        target_url.clone(),
        method_text.clone(),
        core_headers,
    )? {
        MitmRequestDecision::Continue(prepared_request) => prepared_request,
        MitmRequestDecision::Respond { response, reason } => {
            if h2_request_decision_should_reset_stream(reason) {
                debug!(
                    reason = reason,
                    url = %target_url,
                    "MITM HTTP/2 request block reset downstream stream"
                );
                return reset_h2_stream(respond, h2::Reason::CANCEL);
            }

            drain_h2_request_body(body).await?;
            debug!(reason = reason, url = %target_url, "MITM HTTP/2 local response");
            return send_h2_local_response(respond, response, method == http::Method::HEAD).await;
        }
        MitmRequestDecision::Close { reason } => {
            if h2_request_decision_should_reset_stream(reason) {
                debug!(
                    reason = reason,
                    url = %target_url,
                    "MITM HTTP/2 request close reset downstream stream"
                );
                return reset_h2_stream(respond, h2::Reason::CANCEL);
            }

            drain_h2_request_body(body).await?;
            debug!(
                reason = reason,
                url = %target_url,
                "MITM HTTP/2 close decision reset downstream stream"
            );
            return reset_h2_stream(respond, h2::Reason::CANCEL);
        }
    };

    if method == http::Method::CONNECT {
        if h2_extended_connect_is_websocket(extended_connect_protocol.as_deref()) {
            return handle_h2_websocket_extended_connect(
                engine,
                &target_authority,
                &uri,
                body,
                prepared_request,
                respond,
            )
            .await;
        }

        drain_h2_request_body(body).await?;
        return send_h2_not_implemented_response(
            respond,
            "RelayGate downstream HTTP/2 CONNECT streams are not implemented yet.\n",
        )
        .await;
    }

    let is_head = parts.method == http::Method::HEAD;
    let request_body = if method == http::Method::GET || method == http::Method::HEAD {
        // GET/HEAD should not carry a request body in normal browser traffic. Drain
        // any unexpected DATA frames so HTTP/2 flow-control capacity is returned.
        tokio::spawn(async move {
            if let Err(error) = drain_h2_request_body(body).await {
                if is_downstream_h2_stream_cancelled(&error) {
                    debug!(error = %error, "downstream HTTP/2 request body drain ended by client reset/cancel");
                } else {
                    warn!(error = %error, "failed to drain downstream HTTP/2 request body");
                }
            }
        });
        None
    } else {
        Some(body)
    };

    send_h2_upstream_request(
        engine,
        &host,
        prepared_request,
        &headers,
        request_body,
        is_head,
        respond,
    )
    .await
}

fn h2_extended_connect_is_websocket(protocol: Option<&str>) -> bool {
    protocol.is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

async fn handle_h2_websocket_extended_connect(
    engine: MitmEngine,
    target_authority: &str,
    uri: &Uri,
    body: h2::RecvStream,
    prepared_request: PreparedMitmRequest,
    respond: h2::server::SendResponse<Bytes>,
) -> Result<()> {
    let (target_host, _) = normalize_authority(target_authority)?;
    let mut upstream_tls = engine
        .open_mitm_websocket_upstream_tls(target_authority, &target_host, &prepared_request)
        .await?;

    let request_target = h2_websocket_request_target(uri, &prepared_request.target_url);
    let upstream_request = build_mitm_websocket_upstream_request_from_parts(
        target_authority,
        "GET",
        &request_target,
        &prepared_request,
    );
    upstream_tls.write_all(&upstream_request).await?;

    let response_head = time::timeout(
        H2_WEBSOCKET_UPSTREAM_RESPONSE_HEAD_TIMEOUT,
        read_http_response_head(&mut upstream_tls),
    )
    .await
    .with_context(|| {
        format!(
            "timed out waiting for HTTP/2 WebSocket upstream response from `{target_authority}`"
        )
    })??;
    let response_meta = parse_http_response_head(&response_head)?;

    if response_meta.status_code != 101 {
        debug!(
            authority = target_authority,
            status = response_meta.status_code,
            url = %prepared_request.target_url,
            "MITM HTTP/2 WebSocket upstream did not switch protocols"
        );
        return send_h2_local_response(
            respond,
            MitmLocalResponse::text(
                502,
                "Bad Gateway",
                "RelayGate upstream WebSocket handshake did not switch protocols.\n",
            ),
            false,
        )
        .await;
    }

    let response_headers = HeaderMap::new();
    let mut send_stream = send_h2_response_headers(respond, 200, &response_headers, None, false)?;
    debug!(
        authority = target_authority,
        url = %prepared_request.target_url,
        "MITM HTTP/2 extended CONNECT WebSocket bridge established"
    );

    bridge_h2_websocket_stream(body, &mut send_stream, upstream_tls).await
}

async fn bridge_h2_websocket_stream(
    downstream_body: h2::RecvStream,
    downstream_send: &mut h2::SendStream<Bytes>,
    upstream_tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Result<()> {
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_tls);

    let downstream_to_upstream = async move {
        pump_h2_websocket_downstream_to_upstream(downstream_body, &mut upstream_writer).await
    };
    let upstream_to_downstream = async move {
        pump_h2_websocket_upstream_to_downstream(&mut upstream_reader, downstream_send).await
    };

    tokio::try_join!(downstream_to_upstream, upstream_to_downstream)?;
    Ok(())
}

async fn pump_h2_websocket_downstream_to_upstream<W>(
    mut body: h2::RecvStream,
    upstream_writer: &mut W,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|error| {
            downstream_h2_stream_cancelled("reading WebSocket DATA frame", error)
        })?;
        let len = chunk.len();
        if len > 0 {
            upstream_writer
                .write_all(&chunk)
                .await
                .context("failed to forward HTTP/2 WebSocket DATA frame upstream")?;
            body.flow_control().release_capacity(len).map_err(|error| {
                downstream_h2_stream_cancelled(
                    "releasing WebSocket request flow-control capacity",
                    error,
                )
            })?;
        }
    }

    upstream_writer
        .shutdown()
        .await
        .context("failed to finish HTTP/2 WebSocket upstream write half")?;
    Ok(())
}

async fn pump_h2_websocket_upstream_to_downstream<R>(
    upstream_reader: &mut R,
    downstream_send: &mut h2::SendStream<Bytes>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; DOWNSTREAM_H2_DATA_FRAME_BYTES];
    loop {
        let read_count = upstream_reader
            .read(&mut buffer)
            .await
            .context("failed reading upstream WebSocket bytes")?;
        if read_count == 0 {
            break;
        }

        let bytes = Bytes::copy_from_slice(&buffer[..read_count]);
        if let Err(error) = send_h2_body_bytes(
            downstream_send,
            bytes,
            false,
            DOWNSTREAM_H2_DATA_FRAME_BYTES,
        ) {
            return Err(downstream_h2_stream_cancelled(
                "sending WebSocket DATA frame downstream",
                error,
            ));
        }
    }

    if let Err(error) = downstream_send.send_data(Bytes::new(), true) {
        return Err(downstream_h2_stream_cancelled(
            "finishing WebSocket downstream stream",
            error,
        ));
    }
    Ok(())
}

fn h2_websocket_request_target(uri: &Uri, target_url: &str) -> String {
    if let Some(path) = uri.path_and_query() {
        let path = path.as_str();
        if !path.is_empty() {
            return path.to_string();
        }
    }

    target_url
        .parse::<Uri>()
        .ok()
        .and_then(|uri| uri.path_and_query().map(|value| value.as_str().to_string()))
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| "/".to_string())
}

async fn send_h2_upstream_request(
    engine: MitmEngine,
    host: &str,
    prepared_request: crate::proxy::mitm_core::PreparedMitmRequest,
    downstream_headers: &HeaderMap,
    request_body: Option<h2::RecvStream>,
    is_head: bool,
    respond: h2::server::SendResponse<Bytes>,
) -> Result<()> {
    let allow_invalid_upstream_certs = engine.should_tolerate_invalid_upstream_cert(host);
    let max_request_body_bytes = engine
        .mitm_response_state()
        .config
        .limits
        .max_request_body_bytes;
    let max_attempt = if request_body.is_none() {
        engine
            .mitm_response_state()
            .config
            .traffic
            .internal_retry_limit
    } else {
        0
    };
    let mut request_body = request_body;

    for attempt in 0..=max_attempt {
        let traffic_action = engine.traffic_state().action_for_request(
            &prepared_request.traffic_host,
            &prepared_request.method,
            &prepared_request.request_type,
            &engine.mitm_response_state().config.traffic,
        );
        let mut observed_permit = if prepared_request.observe_traffic
            && matches!(traffic_action, TrafficAction::Bypass)
        {
            engine
                .traffic_state()
                .begin_observed_request(&prepared_request.traffic_host)
        } else {
            None
        };
        let mut traffic_permit = match traffic_action {
            TrafficAction::Managed => Some(
                engine
                    .traffic_state()
                    .acquire(
                        &prepared_request.traffic_host,
                        &engine.mitm_response_state().config.traffic,
                    )
                    .await?,
            ),
            TrafficAction::Bypass => None,
        };

        let h3_direct_path_allowed = h3_active_direct_path_allowed(&prepared_request.upstream);
        let protocol_snapshot = engine.protocol_snapshot();
        let browser_storage_access_request =
            has_browser_storage_access_header(&prepared_request.headers);
        let response_rule_preview = engine.evaluate_mitm_response_rules(&RuleResponseContext {
            url: prepared_request.target_url.clone(),
            status_code: 0,
            headers: Vec::new(),
            body_preview: None,
        });
        let body_pipeline_preflight_reason = response_body_pipeline_preflight_reason(
            &engine.mitm_response_state(),
            &prepared_request.target_url,
            &prepared_request.request_type,
            &response_rule_preview.effects,
        );

        if h3_direct_path_allowed
            && !browser_storage_access_request
            && prepared_request.method.eq_ignore_ascii_case("GET")
            && request_body.is_none()
            && protocol_snapshot.upstream_http3_buffered_enabled
            && allow_active_h3_buffered_for_request(
                &engine.mitm_response_state(),
                &prepared_request.request_type,
                body_pipeline_preflight_reason,
            )
        {
            if let Some(h3_result) = engine
                .upstream_connector()
                .try_http3_buffered_response_for_mitm_parts(
                    true,
                    &prepared_request.method,
                    &prepared_request.target_url,
                    &prepared_request.traffic_host,
                    &prepared_request.headers,
                    &prepared_request.request_effects,
                    request_body.is_none(),
                )
                .await
            {
                match h3_result {
                    Ok(h3_response) => {
                        let status_code = h3_response.status_code();
                        let response_headers =
                            header_map_from_relay_buffered_response(&h3_response)?;
                        let response_header_pairs = header_pairs_from_reqwest(&response_headers);

                        if status_code == 429
                            && engine
                                .traffic_state()
                                .is_controlled_host(&prepared_request.traffic_host)
                            && prepared_request.method.eq_ignore_ascii_case("GET")
                            && prepared_request.request_type == "document"
                        {
                            let h3_candidate = upstream_h3::active_candidate_for_authority(
                                &prepared_request.traffic_host,
                            );
                            upstream_h3::record_http3_active_buffered_fallback(
                                "h2",
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
                                url = %prepared_request.target_url,
                                "MITM HTTP/2 active H3 buffered response deferred to reqwest path for traffic-control 429 handling"
                            );
                        } else {
                            let response_context = RuleResponseContext {
                                url: prepared_request.target_url.clone(),
                                status_code,
                                headers: response_header_pairs,
                                body_preview: None,
                            };
                            let response_decision =
                                engine.evaluate_mitm_response_rules(&response_context);
                            let response_state = engine.mitm_response_state();
                            let pipeline_route = mitm_response_pipeline_decision(
                                &response_state,
                                &response_context.url,
                                &prepared_request.request_type,
                                status_code,
                                &response_headers,
                                &response_decision.effects,
                            );

                            if pipeline_route.is_fast_path() {
                                if matches!(traffic_action, TrafficAction::Managed) {
                                    engine.traffic_state().on_success(
                                        &prepared_request.traffic_host,
                                        &engine.mitm_response_state().config.traffic,
                                    );
                                }
                                let body_len = h3_response.body.len();
                                send_h2_buffered_response(
                                    respond,
                                    status_code,
                                    &response_headers,
                                    Bytes::from(h3_response.body.clone()),
                                )?;
                                drop(observed_permit.take());
                                drop(traffic_permit.take());
                                let h3_candidate = upstream_h3::active_candidate_for_authority(
                                    &prepared_request.traffic_host,
                                );
                                upstream_h3::record_http3_active_buffered_served(
                                    "h2",
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
                                    "MITM HTTP/2 active H3 buffered response written; skipping reqwest path"
                                );
                                return Ok(());
                            }

                            let h3_candidate = upstream_h3::active_candidate_for_authority(
                                &prepared_request.traffic_host,
                            );
                            upstream_h3::record_http3_active_buffered_fallback(
                                "h2",
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
                                "MITM HTTP/2 active H3 buffered response deferred to reqwest path because response needs deep pipeline"
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
                            "h2",
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
                            "MITM HTTP/2 active H3 buffered response unavailable; continuing reqwest path"
                        );
                    }
                }
            }
        }

        let h3_streaming_mode = if protocol_snapshot.upstream_http3_streaming_enabled {
            protocol_snapshot.upstream_http3_streaming_mode
        } else {
            Http3StreamingResponseModeConfig::Disabled
        };

        let h3_streaming_gate = h3_streaming_request_gate(
            h3_direct_path_allowed,
            request_body.is_none(),
            engine.mitm_response_state().config.disable_mitm_fast_path,
            h3_streaming_mode,
            browser_storage_access_request,
            body_pipeline_preflight_reason,
            &prepared_request.method,
            &prepared_request.request_type,
            &prepared_request.target_url,
        );
        let mut h3_streaming_trace = H3StreamingPathTrace::new(h3_streaming_gate);

        if h3_streaming_gate.allowed {
            let h3_candidate =
                upstream_h3::active_candidate_for_authority(&prepared_request.traffic_host);
            if let Err(error) = upstream_h3::reserve_http3_active_streaming_authority_slot(
                &prepared_request.traffic_host,
            ) {
                h3_streaming_trace.mark("slot_rejected", error.kind.code());
                upstream_h3::record_http3_active_streaming_writer_fallback(
                    "h2_stream",
                    &prepared_request.traffic_host,
                    h3_candidate.as_ref(),
                    None,
                    None,
                    error.kind.code(),
                    error.detail,
                );
            } else if let Some(h3_streaming_result) = engine
                .upstream_connector()
                .try_http3_streaming_response_for_mitm_parts(
                    true,
                    &prepared_request.method,
                    &prepared_request.target_url,
                    &prepared_request.traffic_host,
                    &prepared_request.headers,
                    &prepared_request.request_effects,
                    request_body.is_none(),
                )
                .await
            {
                h3_streaming_trace.mark("attempt_returned", "connector returned a result");
                match h3_streaming_result {
                    Ok(h3_response) => {
                        h3_streaming_trace
                            .mark("response_received", "HTTP/3 response headers received");
                        let status_code = h3_response.status_code();
                        let response_headers =
                            header_map_from_relay_response_head(&h3_response.head)?;
                        let header_count = response_headers.len();
                        let response_header_pairs = header_pairs_from_reqwest(&response_headers);

                        let response_context = RuleResponseContext {
                            url: prepared_request.target_url.clone(),
                            status_code,
                            headers: response_header_pairs,
                            body_preview: None,
                        };
                        let url_summary = MitmUrlLogSummary::from_url(&response_context.url);
                        let h3_precommit_rejection_fallback =
                            should_fallback_h3_rejection_before_downstream(
                                status_code,
                                &url_summary.path,
                            );
                        if status_code >= 400 {
                            if h3_precommit_rejection_fallback
                                || is_expected_rejection_noise(status_code, &url_summary.path)
                                || is_signed_media_rejection_noise(status_code, &url_summary.path)
                                || is_adblock_test_probe_rejection_noise(
                                    &prepared_request.method,
                                    &prepared_request.source_url,
                                    status_code,
                                    &url_summary.path,
                                )
                            {
                                debug!(
                                    status = status_code,
                                    headers = header_count,
                                    url_path = %url_summary.path,
                                    path_query_hash = %url_summary.path_query_hash,
                                    path_query_len = url_summary.path_query_len,
                                    source = %h3_response.source,
                                    fallback = h3_precommit_rejection_fallback,
                                    "MITM HTTP/2 active H3 streaming response has retriable/noisy rejection status before downstream forwarding"
                                );
                            } else {
                                warn!(
                                    status = status_code,
                                    headers = header_count,
                                    url_path = %url_summary.path,
                                    path_query_hash = %url_summary.path_query_hash,
                                    path_query_len = url_summary.path_query_len,
                                    source = %h3_response.source,
                                    "MITM HTTP/2 active H3 streaming response has rejection-like status before downstream forwarding"
                                );
                            }
                        }
                        let response_decision =
                            engine.evaluate_mitm_response_rules(&response_context);
                        let response_state = engine.mitm_response_state();
                        let pipeline_route = mitm_response_pipeline_decision(
                            &response_state,
                            &response_context.url,
                            &prepared_request.request_type,
                            status_code,
                            &response_headers,
                            &response_decision.effects,
                        );

                        let mut h3_response = Some(h3_response);
                        if pipeline_route.is_fast_path() && !h3_precommit_rejection_fallback {
                            upstream_h3::record_http3_active_streaming_writer_ready(
                                "h2_stream",
                                &prepared_request.traffic_host,
                                h3_candidate.as_ref(),
                                status_code,
                                header_count,
                            );
                            match stream_h2_h3_response(
                                respond,
                                h3_response.take().expect(
                                    "H3 streaming response should be present before byte-pump",
                                ),
                                &response_headers,
                            )
                            .await
                            {
                                Ok(H2H3StreamingOutcome::Completed { body_bytes }) => {
                                    if matches!(traffic_action, TrafficAction::Managed) {
                                        engine.traffic_state().on_success(
                                            &prepared_request.traffic_host,
                                            &engine.mitm_response_state().config.traffic,
                                        );
                                    }
                                    upstream_h3::clear_http3_active_streaming_authority_failure(
                                        &prepared_request.traffic_host,
                                    );
                                    drop(observed_permit.take());
                                    drop(traffic_permit.take());
                                    debug!(
                                        status = status_code,
                                        headers = header_count,
                                        response_body_bytes = body_bytes,
                                        url = %response_context.url,
                                        "MITM HTTP/2 H3 streaming response forwarded to downstream H2 DATA frames"
                                    );
                                    return Ok(());
                                }
                                Ok(H2H3StreamingOutcome::ResetAfterHeaders {
                                    body_bytes,
                                    reason_code,
                                    reason_detail,
                                }) => {
                                    drop(observed_permit.take());
                                    drop(traffic_permit.take());
                                    upstream_h3::record_http3_active_streaming_writer_fallback(
                                        "h2_stream",
                                        &prepared_request.traffic_host,
                                        h3_candidate.as_ref(),
                                        Some(status_code),
                                        Some(header_count),
                                        reason_code,
                                        reason_detail.clone(),
                                    );
                                    upstream_h3::record_http3_active_streaming_authority_failure(
                                        &prepared_request.traffic_host,
                                        reason_code,
                                        reason_detail,
                                    );
                                    warn!(
                                        status = status_code,
                                        headers = header_count,
                                        response_body_bytes = body_bytes,
                                        url = %response_context.url,
                                        reason = reason_code,
                                        "MITM HTTP/2 H3 streaming response reset downstream stream after upstream body error; authority is cooling down"
                                    );
                                    return Ok(());
                                }
                                Ok(H2H3StreamingOutcome::DownstreamClosedAfterHeaders {
                                    body_bytes,
                                    operation,
                                    reason_detail,
                                }) => {
                                    drop(observed_permit.take());
                                    drop(traffic_permit.take());
                                    upstream_h3::record_http3_active_streaming_writer_fallback(
                                        "h2_stream",
                                        &prepared_request.traffic_host,
                                        h3_candidate.as_ref(),
                                        Some(status_code),
                                        Some(header_count),
                                        "downstream_closed",
                                        reason_detail.clone(),
                                    );
                                    debug!(
                                        status = status_code,
                                        headers = header_count,
                                        response_body_bytes = body_bytes,
                                        url = %response_context.url,
                                        operation,
                                        error = %reason_detail,
                                        "MITM HTTP/2 H3 streaming response stopped because downstream closed the stream"
                                    );
                                    return Ok(());
                                }
                                Err(error) => {
                                    let reason_detail = diagnostics::format_error_chain(&error);
                                    upstream_h3::record_http3_active_streaming_writer_fallback(
                                        "h2_stream",
                                        &prepared_request.traffic_host,
                                        h3_candidate.as_ref(),
                                        Some(status_code),
                                        Some(header_count),
                                        "downstream_stream_error",
                                        reason_detail.clone(),
                                    );
                                    upstream_h3::record_http3_active_streaming_authority_failure(
                                        &prepared_request.traffic_host,
                                        "downstream_stream_error",
                                        reason_detail,
                                    );
                                    return Err(error);
                                }
                            }
                        }

                        {
                            if let Some(mut h3_response) = h3_response {
                                h3_response.body.stop();
                            }
                            let (fallback_reason_code, fallback_reason_detail) =
                                if h3_precommit_rejection_fallback {
                                    (
                                            "rejection_status_precommit",
                                            format!(
                                                "H3 returned status {status_code} before downstream headers; retrying stable upstream path"
                                            ),
                                        )
                                } else {
                                    (
                                        "deep_pipeline_required",
                                        format!(
                                            "{} — {}",
                                            pipeline_route.pipeline_label(),
                                            pipeline_route.reason
                                        ),
                                    )
                                };
                            upstream_h3::record_http3_active_streaming_writer_fallback(
                                "h2_stream",
                                &prepared_request.traffic_host,
                                h3_candidate.as_ref(),
                                Some(status_code),
                                Some(header_count),
                                fallback_reason_code,
                                fallback_reason_detail.clone(),
                            );
                            if h3_precommit_rejection_fallback {
                                upstream_h3::record_http3_active_streaming_authority_failure(
                                    &prepared_request.traffic_host,
                                    fallback_reason_code,
                                    fallback_reason_detail.clone(),
                                );
                                debug!(
                                    status = status_code,
                                    headers = header_count,
                                    url = %response_context.url,
                                    reason = fallback_reason_code,
                                    detail = %fallback_reason_detail,
                                    "MITM HTTP/2 H3 streaming response deferred to stable path before downstream headers because upstream rejected the H3 request"
                                );
                            } else {
                                debug!(
                                    pipeline = %pipeline_route.pipeline_label(),
                                    reason = %pipeline_route.reason,
                                    status = status_code,
                                    url = %response_context.url,
                                    "MITM HTTP/2 H3 streaming response deferred to reqwest path because response needs deep pipeline"
                                );
                            }
                            h3_streaming_trace.mark(
                                fallback_reason_code,
                                if h3_precommit_rejection_fallback {
                                    "fallback before downstream headers"
                                } else {
                                    pipeline_route.pipeline_label()
                                },
                            );
                        }
                    }
                    Err(h3_probe) => {
                        let reason_code = h3_probe
                            .fallback_error
                            .as_ref()
                            .map(|error| error.kind.code())
                            .unwrap_or("not_streaming_response");
                        let reason_detail = h3_probe
                            .fallback_error
                            .as_ref()
                            .map(|error| error.detail.clone())
                            .unwrap_or_else(|| {
                                "H3 active streaming path did not produce a forwardable streaming response"
                                    .to_string()
                            });

                        h3_streaming_trace.mark("connector_error", reason_code);
                        upstream_h3::record_http3_active_streaming_writer_fallback(
                            "h2_stream",
                            &h3_probe.authority,
                            h3_probe.attempt_plan.h3_candidate.as_ref(),
                            None,
                            None,
                            reason_code,
                            reason_detail.clone(),
                        );
                        if let Some(error) = &h3_probe.fallback_error {
                            if h3_streaming_backend_error_should_cooldown(error.kind) {
                                upstream_h3::record_http3_active_streaming_authority_failure(
                                    &h3_probe.authority,
                                    reason_code,
                                    reason_detail.clone(),
                                );
                            }
                        }
                        debug!(
                            authority = %h3_probe.authority,
                            decision = h3_probe.decision_label(),
                            fallback = h3_probe.fallback_label(),
                            error = h3_probe.fallback_error_code().unwrap_or("none"),
                            "MITM HTTP/2 H3 streaming response unavailable; continuing reqwest path"
                        );
                    }
                }
            } else {
                h3_streaming_trace.mark("connector_not_attempted", "connector returned None");
            }
        }

        if h3_direct_path_allowed
            && !protocol_snapshot.upstream_http3_buffered_enabled
            && !protocol_snapshot.upstream_http3_streaming_enabled
            && protocol_snapshot.upstream_http3_probe_enabled
        {
            if let Some(h3_probe) = engine
                .upstream_connector()
                .probe_http3_for_mitm_parts(
                    true,
                    &prepared_request.method,
                    &prepared_request.target_url,
                    &prepared_request.traffic_host,
                    &prepared_request.headers,
                    &prepared_request.request_effects,
                    request_body.is_none(),
                )
                .await
            {
                debug!(
                    authority = %h3_probe.authority,
                    decision = h3_probe.decision_label(),
                    fallback = h3_probe.fallback_label(),
                    error = h3_probe.fallback_error_code().unwrap_or("none"),
                    "MITM HTTP/2 upstream H3 forwarding probe completed; continuing reqwest path"
                );
            }
        }

        let client = engine
            .upstream_connector()
            .client_for_request(&prepared_request.upstream, allow_invalid_upstream_certs)?;
        let mut outbound = client.request(
            reqwest::Method::from_bytes(prepared_request.method.as_bytes())?,
            &prepared_request.target_url,
        );

        for (name, value) in downstream_headers {
            if should_forward_h2_request_header(name) {
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

        let upstream_response_result = match request_body.take() {
            Some(body) => {
                // Baseline guardrail for sustained H2 upload throughput: preserve the
                // known request body length when bridging downstream H2 uploads into
                // reqwest's streaming body. H2 framing itself does not require
                // Content-Length, but reqwest/hyper uses exact body metadata differently
                // from unknown-length streaming, and the baseline speedtest fix depends
                // on that parity. This is still intentionally not generic header
                // forwarding: the original Content-Length is stripped below so RelayGate
                // owns the body pipeline, then re-applied only after validation. Future
                // upload-pipeline fixes can replace this, but should re-test long
                // sustained uploads before removing the exact-length metadata.
                let content_length = h2_request_content_length_for_upstream(downstream_headers);
                send_h2_upstream_request_with_body(
                    outbound,
                    body,
                    max_request_body_bytes,
                    &prepared_request.method,
                    &prepared_request.target_url,
                    content_length,
                )
                .await
            }
            None => outbound.send().await.map_err(anyhow::Error::new),
        };

        let upstream_response = match upstream_response_result {
            Ok(response) => response,
            Err(error) => {
                if is_downstream_h2_stream_cancelled(&error) {
                    return Err(error);
                }

                if error
                    .downcast_ref::<crate::proxy::http_framing::RequestLimitError>()
                    .is_some()
                {
                    warn!(
                        request_body_mode = "h2_streaming",
                        request_body_limit = max_request_body_bytes,
                        method = %prepared_request.method,
                        url = %prepared_request.target_url,
                        "MITM HTTP/2 request body exceeded configured limit"
                    );
                    return send_h2_local_response(
                        respond,
                        MitmLocalResponse::text(
                            413,
                            "Payload Too Large",
                            "RelayGate request body limit exceeded.",
                        ),
                        is_head,
                    )
                    .await;
                }

                if let Some(reqwest_error) = error.downcast_ref::<reqwest::Error>() {
                    if is_upstream_certificate_error(reqwest_error) && !allow_invalid_upstream_certs
                    {
                        return send_h2_local_response(
                            respond,
                            MitmLocalResponse::text(
                                502,
                                "Bad Gateway",
                                "RelayGate could not validate the upstream TLS certificate.",
                            ),
                            is_head,
                        )
                        .await;
                    }
                }

                if is_expected_h2_upstream_connect_failure(&error) {
                    debug!(
                        url = %prepared_request.target_url,
                        method = %prepared_request.method,
                        request_type = %prepared_request.request_type,
                        error = %diagnostics::format_error_chain_for_console(&error),
                        "MITM HTTP/2 upstream connect/DNS failure; resetting downstream stream"
                    );
                    return reset_h2_stream(respond, h2::Reason::CANCEL);
                }

                let _ = diagnostics::append_proxy_diagnostic(&format!(
                    "{} event=mitm_h2_upstream_request_failed url={} method={} request_body={} error_chain={}",
                    diagnostics::diagnostic_timestamp(),
                    prepared_request.target_url,
                    prepared_request.method,
                    if request_body.is_some() { "streaming" } else { "none" },
                    diagnostics::format_error_chain(&error)
                ));

                if prepared_request.observe_traffic {
                    engine
                        .traffic_state()
                        .on_fatal_error(&prepared_request.traffic_host);
                }
                return Err(error);
            }
        };

        if prepared_request.upstream.upstream_id.is_none() {
            if let Some(remote_addr) = upstream_response.remote_addr() {
                engine
                    .dns_resolver()
                    .record_origin_connect_success_observed(
                        &prepared_request.traffic_host,
                        remote_addr.ip(),
                    );
            }
        }

        downstream_status::record_upstream_response(
            &prepared_request.traffic_host,
            &prepared_request.target_url,
            upstream_response.version(),
            engine
                .mitm_response_state()
                .config
                .proxy
                .upstream
                .protocol_policy,
        );
        downstream_status::record_upstream_alt_svc(
            &prepared_request.traffic_host,
            upstream_response.headers(),
        );
        let status = upstream_response.status();
        if status.as_u16() >= 400 {
            let url_summary = MitmUrlLogSummary::from_url(&prepared_request.target_url);
            let request_header_fingerprint =
                MitmRequestHeaderFingerprint::from_header_pairs(&prepared_request.headers);
            let h3_candidate =
                upstream_h3::active_candidate_for_authority(&prepared_request.traffic_host);
            let h3_observation = upstream_h3::observation_snapshot();
            let h3_candidate_state = if h3_candidate.is_some() {
                "active_candidate"
            } else {
                "no_active_alt_svc_candidate"
            };
            let h3_recent_authorities = h3_observation
                .recent_h3_authorities
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            let rejection_correlation =
                if h3_streaming_trace.stage() == "rejection_status_precommit" {
                    "h3_precommit_then_stable_rejected"
                } else if h3_streaming_trace.stage() == "slot_rejected" {
                    "h3_slot_rejected_then_stable_rejected"
                } else if h3_streaming_trace.stage() == "connector_error" {
                    "h3_connector_error_then_stable_rejected"
                } else if h3_streaming_trace.stage() == "deep_pipeline_required" {
                    "stable_deep_pipeline_rejected"
                } else {
                    "stable_rejected_without_h3_service"
                };

            if is_expected_rejection_noise(status.as_u16(), &url_summary.path)
                || is_stable_rejection_diagnostic_noise(
                    status.as_u16(),
                    &url_summary.path,
                    rejection_correlation,
                )
                || is_routine_stable_upstream_rejection_noise(
                    status.as_u16(),
                    rejection_correlation,
                )
                || is_adblock_test_probe_rejection_noise(
                    &prepared_request.method,
                    &prepared_request.source_url,
                    status.as_u16(),
                    &url_summary.path,
                )
            {
                debug!(
                    status = status.as_u16(),
                    method = %prepared_request.method,
                    authority = %prepared_request.traffic_host,
                    url_path = %url_summary.path,
                    path_query_hash = %url_summary.path_query_hash,
                    path_query_len = url_summary.path_query_len,
                    signed_ip_family = %url_summary.signed_ip_family,
                    request_type = %prepared_request.request_type,
                    upstream_version = ?upstream_response.version(),
                    h3_streaming_gate = h3_streaming_trace.gate_reason(),
                    h3_streaming_stage = h3_streaming_trace.stage(),
                    h3_streaming_detail = h3_streaming_trace.detail(),
                    rejection_correlation = rejection_correlation,
                    "MITM HTTP/2 stable upstream response has expected noisy rejection status after active H3 streaming did not serve request"
                );
            } else {
                warn!(
                    status = status.as_u16(),
                    method = %prepared_request.method,
                    authority = %prepared_request.traffic_host,
                    url_path = %url_summary.path,
                    path_query_hash = %url_summary.path_query_hash,
                    path_query_len = url_summary.path_query_len,
                    signed_ip_family = %url_summary.signed_ip_family,
                    stable_remote_addr_family = "unavailable_from_reqwest_response",
                    request_type = %prepared_request.request_type,
                    upstream_version = ?upstream_response.version(),
                    h3_streaming_gate = h3_streaming_trace.gate_reason(),
                    h3_streaming_stage = h3_streaming_trace.stage(),
                    h3_streaming_detail = h3_streaming_trace.detail(),
                    rejection_correlation = rejection_correlation,
                    h3_direct_path_allowed = h3_direct_path_allowed,
                    h3_candidate_state = h3_candidate_state,
                    h3_active_candidates = h3_observation.active_h3_candidates.len(),
                    h3_recent_authorities = %h3_recent_authorities,
                    upstream_route = if prepared_request.upstream.upstream_id.is_some() { "configured_upstream" } else { "direct" },
                    upstream_policy = ?prepared_request.upstream.protocol_policy,
                    downstream_header_count = request_header_fingerprint.header_count,
                    downstream_header_names_hash = %request_header_fingerprint.header_names_hash,
                    downstream_header_names = %request_header_fingerprint.header_names,
                    downstream_header_names_without_accept_encoding_hash = %request_header_fingerprint.header_names_without_accept_encoding_hash,
                    downstream_semantic_header_names_hash = %request_header_fingerprint.semantic_header_names_hash,
                    downstream_semantic_header_names = %request_header_fingerprint.semantic_header_names,
                    downstream_has_host = request_header_fingerprint.has_host,
                    has_range = request_header_fingerprint.has_range,
                    has_cookie = request_header_fingerprint.has_cookie,
                    has_referer = request_header_fingerprint.has_referer,
                    has_origin = request_header_fingerprint.has_origin,
                    has_user_agent = request_header_fingerprint.has_user_agent,
                    has_sec_fetch = request_header_fingerprint.has_sec_fetch,
                    accept_encoding = request_header_fingerprint.accept_encoding.as_deref().unwrap_or("<none>"),
                    effective_upstream_accept_encoding = crate::proxy::mount_forward::relaygate_body_pipeline_accept_encoding(),
                    "MITM HTTP/2 stable upstream response has rejection-like status after active H3 streaming did not serve request"
                );
            }
        }
        let response_header_pairs = header_pairs_from_reqwest(upstream_response.headers());
        if status.as_u16() == 429
            && engine
                .traffic_state()
                .is_controlled_host(&prepared_request.traffic_host)
            && prepared_request.method.eq_ignore_ascii_case("GET")
            && prepared_request.request_type == "document"
        {
            let retry_after = traffic::parse_retry_after_secs(&response_header_pairs);
            drop(observed_permit.take());
            drop(traffic_permit.take());
            match engine.traffic_state().decide_429_response(
                &prepared_request.traffic_host,
                attempt,
                retry_after,
                &engine.mitm_response_state().config.traffic,
            ) {
                TrafficResponseDecision::RetryAfterDelay(delay) => {
                    engine
                        .traffic_state()
                        .begin_retry_wait(&prepared_request.traffic_host);
                    time::sleep(delay).await;
                    engine
                        .traffic_state()
                        .end_retry_wait(&prepared_request.traffic_host);
                    continue;
                }
                TrafficResponseDecision::ReloadPage(delay) => {
                    return send_h2_local_response(
                        respond,
                        traffic_reload_local_response(delay, &prepared_request.target_url),
                        is_head,
                    )
                    .await;
                }
                TrafficResponseDecision::Forward => {}
            }
        } else if matches!(traffic_action, TrafficAction::Managed) {
            engine.traffic_state().on_success(
                &prepared_request.traffic_host,
                &engine.mitm_response_state().config.traffic,
            );
        }

        return handle_h2_upstream_response(
            engine,
            prepared_request,
            upstream_response,
            is_head,
            respond,
        )
        .await;
    }

    send_h2_local_response(
        respond,
        MitmLocalResponse::text(
            502,
            "Bad Gateway",
            "RelayGate HTTP/2 traffic retry flow ended unexpectedly.",
        ),
        is_head,
    )
    .await
}

async fn handle_h2_upstream_response(
    engine: MitmEngine,
    prepared_request: crate::proxy::mitm_core::PreparedMitmRequest,
    upstream_response: reqwest::Response,
    is_head: bool,
    respond: h2::server::SendResponse<Bytes>,
) -> Result<()> {
    let status = upstream_response.status();
    let mut response_headers = upstream_response.headers().clone();
    let upstream_content_length = upstream_response.content_length();
    let response_header_pairs = header_pairs_from_reqwest(&response_headers);
    let response_context = RuleResponseContext {
        url: prepared_request.target_url.clone(),
        status_code: status.as_u16(),
        headers: response_header_pairs,
        body_preview: None,
    };
    let response_decision = engine.evaluate_mitm_response_rules(&response_context);

    if is_head || h2_status_has_no_body(status.as_u16()) {
        let content_length = if is_head {
            upstream_content_length
        } else {
            None
        };
        send_h2_response_headers(
            respond,
            status.as_u16(),
            &response_headers,
            content_length,
            true,
        )?;
        return Ok(());
    }

    let response_state = engine.mitm_response_state();
    let pipeline_route = mitm_response_pipeline_decision(
        &response_state,
        &response_context.url,
        &prepared_request.request_type,
        status.as_u16(),
        &response_headers,
        &response_decision.effects,
    );
    let response_content_type = response_content_type_lower(&response_headers);
    debug!(
        pipeline = %pipeline_route.pipeline_label(),
        reason = %pipeline_route.reason,
        request_type = %prepared_request.request_type,
        content_type = %response_content_type,
        status = status.as_u16(),
        url = %response_context.url,
        "MITM HTTP/2 response pipeline decision"
    );

    if pipeline_route.is_fast_path() {
        return stream_h2_upstream_response(
            respond,
            status.as_u16(),
            &response_headers,
            upstream_content_length,
            upstream_response,
        )
        .await;
    }

    let max_response_buffer_bytes = response_state.config.limits.max_response_buffer_bytes;
    if upstream_content_length.is_some_and(|length| length > max_response_buffer_bytes as u64) {
        warn!(
            pipeline = "block",
            reason = "response_buffer_limit_content_length_blocked",
            request_type = %prepared_request.request_type,
            content_type = %response_content_type,
            url = %response_context.url,
            limit = max_response_buffer_bytes,
            "MITM HTTP/2 response body exceeds buffer limit while deep response pipeline is required"
        );
        return send_h2_local_response(
            respond,
            MitmLocalResponse::text(
                502,
                "Bad Gateway",
                "RelayGate response buffer limit exceeded while preparing rewrite, patch, or injection.",
            ),
            false,
        )
        .await;
    }

    let response_body = match read_limited_h2_response_body(
        upstream_response,
        max_response_buffer_bytes,
    )
    .await?
    {
        Some(body) => body,
        None => {
            warn!(
                pipeline = "block",
                reason = "response_buffer_limit_exceeded_after_buffering",
                request_type = %prepared_request.request_type,
                content_type = %response_content_type,
                url = %response_context.url,
                limit = max_response_buffer_bytes,
                "MITM HTTP/2 response body exceeded buffer limit after buffering started"
            );
            return send_h2_local_response(
                respond,
                MitmLocalResponse::text(
                    502,
                    "Bad Gateway",
                    "RelayGate response buffer limit exceeded while preparing rewrite, patch, or injection.",
                ),
                false,
            )
            .await;
        }
    };

    let processed_response = process_mitm_response_body(
        &response_state,
        &response_context.url,
        &prepared_request.source_url,
        &prepared_request.request_type,
        prepared_request.fetch_site.as_deref(),
        &mut response_headers,
        response_body,
        &response_decision.effects,
    )
    .await
    .with_context(|| {
        format!(
            "failed to process MITM HTTP/2 response body for {}",
            response_context.url
        )
    })?;
    let response_body = processed_response.body;

    if response_state.config.logging.log_response_body {
        log_response_body(
            "mitm-h2",
            &response_context.url,
            response_headers
                .get(CONTENT_TYPE)
                .and_then(|value: &HeaderValue| value.to_str().ok()),
            &response_body,
        );
    }

    debug!(
        response_body_bytes = response_body.len(),
        patch_ms = processed_response.rewrite_perf.patch_ms,
        render_ms = processed_response.rewrite_perf.render_ms,
        adblock_injection_ms = processed_response.rewrite_perf.adblock_injection_ms,
        status = status.as_u16(),
        url = %response_context.url,
        "MITM HTTP/2 deep-path response processed"
    );

    send_h2_buffered_response(
        respond,
        status.as_u16(),
        &response_headers,
        Bytes::from(response_body),
    )
}

fn traffic_reload_local_response(
    delay: std::time::Duration,
    target_url: &str,
) -> MitmLocalResponse {
    MitmLocalResponse::with_content_type(
        503,
        "Service Unavailable",
        "text/html; charset=utf-8",
        traffic::reload_page_body(delay, target_url),
    )
}

async fn send_h2_upstream_request_with_body(
    mut outbound: reqwest::RequestBuilder,
    body: h2::RecvStream,
    max_request_body_bytes: usize,
    method: &str,
    target_url: &str,
    content_length: Option<u64>,
) -> Result<reqwest::Response> {
    if let Some(content_length) = content_length {
        outbound = outbound.header(CONTENT_LENGTH, content_length.to_string());
    }

    let (body_reader, body_writer) = tokio::io::duplex(256 * 1024);
    let body_stream = async_stream::stream! {
        let mut reader = body_reader;
        let mut buffer = vec![0_u8; 64 * 1024];
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
    let pump_future = pump_h2_request_body(body, body_writer, max_request_body_bytes);
    let (response, forwarded_bytes) = tokio::try_join!(send_future, pump_future)?;

    debug!(
        request_body_mode = "h2_streaming",
        request_body_bytes = forwarded_bytes,
        request_body_limit = max_request_body_bytes,
        request_body_has_content_length = content_length.is_some(),
        request_body_content_length = content_length.unwrap_or(0),
        request_body_content_length_matches = content_length
            .is_some_and(|length| length == forwarded_bytes as u64),
        method = %method,
        url = %target_url,
        "streamed MITM HTTP/2 request body to upstream"
    );

    Ok(response)
}

async fn pump_h2_request_body(
    mut body: h2::RecvStream,
    mut body_writer: tokio::io::DuplexStream,
    max_request_body_bytes: usize,
) -> Result<usize> {
    let mut forwarded = 0usize;

    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|error| {
            downstream_h2_stream_cancelled("reading request body DATA frame", error)
        })?;
        let len = chunk.len();
        if forwarded.saturating_add(len) > max_request_body_bytes {
            return Err(crate::proxy::http_framing::RequestLimitError::PayloadTooLarge.into());
        }

        if len > 0 {
            body_writer
                .write_all(&chunk)
                .await
                .context("failed to forward downstream HTTP/2 request body chunk")?;
            forwarded = forwarded.saturating_add(len);
            body.flow_control().release_capacity(len).map_err(|error| {
                downstream_h2_stream_cancelled(
                    "releasing request body flow-control capacity",
                    error,
                )
            })?;
        }
    }

    body_writer
        .shutdown()
        .await
        .context("failed to finish downstream HTTP/2 request body stream")?;
    Ok(forwarded)
}

enum H2H3StreamingOutcome {
    Completed {
        body_bytes: usize,
    },
    ResetAfterHeaders {
        body_bytes: usize,
        reason_code: &'static str,
        reason_detail: String,
    },
    DownstreamClosedAfterHeaders {
        body_bytes: usize,
        operation: &'static str,
        reason_detail: String,
    },
}

async fn stream_h2_h3_response(
    respond: h2::server::SendResponse<Bytes>,
    mut h3_response: RelayUpstreamStreamingResponse,
    response_headers: &HeaderMap,
) -> Result<H2H3StreamingOutcome> {
    let status = h3_response.status_code();
    let upstream_content_length = parse_response_content_length(response_headers);
    let mut sent_body_bytes = 0usize;
    let mut streaming_headers = response_headers.clone();
    normalize_h2_streaming_response_headers(&mut streaming_headers);

    let headers_only = h2_status_has_no_body(status) || upstream_content_length == Some(0);
    let mut send_stream =
        send_h2_response_headers(respond, status, &streaming_headers, None, headers_only)?;

    if headers_only {
        h3_response.body.stop();
        return Ok(H2H3StreamingOutcome::Completed { body_bytes: 0 });
    }

    loop {
        let chunk = match h3_response.body.next_chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) if error.is_benign_end() => {
                debug!(
                    response_body_bytes_sent = sent_body_bytes,
                    status,
                    error_kind = error.kind.code(),
                    error = %error.detail,
                    "upstream HTTP/3 streaming body ended with benign client-close signal"
                );
                break;
            }
            Err(error) => {
                let reason_code = error.kind.code();
                let reason_detail = error.detail.clone();
                h3_response.body.stop();
                send_stream.send_reset(h2::Reason::CANCEL);
                return Ok(H2H3StreamingOutcome::ResetAfterHeaders {
                    body_bytes: sent_body_bytes,
                    reason_code,
                    reason_detail,
                });
            }
        };

        if chunk.is_empty() {
            continue;
        }

        let chunk_len = chunk.len();
        if let Err(error) = send_h2_body_bytes(
            &mut send_stream,
            chunk,
            false,
            DOWNSTREAM_H2_DATA_FRAME_BYTES,
        ) {
            h3_response.body.stop();
            debug!(
                response_body_bytes_sent = sent_body_bytes,
                status,
                error = %error,
                "downstream HTTP/2 stream stopped while sending active H3 streaming response body"
            );
            return Ok(H2H3StreamingOutcome::DownstreamClosedAfterHeaders {
                body_bytes: sent_body_bytes,
                operation: "sending active H3 streaming response body DATA frame",
                reason_detail: error.to_string(),
            });
        }
        sent_body_bytes = sent_body_bytes.saturating_add(chunk_len);
    }

    if let Some(expected_length) = upstream_content_length {
        if sent_body_bytes as u64 != expected_length {
            warn!(
                status,
                response_body_bytes_sent = sent_body_bytes,
                upstream_content_length = expected_length,
                "active H3 streaming response reached end-of-stream with content-length mismatch; downstream content-length was stripped, ending H2 stream cleanly"
            );
        }
    }

    if let Err(error) = send_stream.send_data(Bytes::new(), true) {
        h3_response.body.stop();
        return Ok(H2H3StreamingOutcome::DownstreamClosedAfterHeaders {
            body_bytes: sent_body_bytes,
            operation: "finishing active H3 streaming response body",
            reason_detail: error.to_string(),
        });
    }

    Ok(H2H3StreamingOutcome::Completed {
        body_bytes: sent_body_bytes,
    })
}

fn parse_response_content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn normalize_h2_streaming_response_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_LENGTH);
    headers.remove("transfer-encoding");
    headers.remove("trailer");
    headers.remove("connection");
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
    headers.remove("upgrade");
}

async fn stream_h2_upstream_response(
    respond: h2::server::SendResponse<Bytes>,
    status: u16,
    response_headers: &HeaderMap,
    upstream_content_length: Option<u64>,
    mut upstream_response: reqwest::Response,
) -> Result<()> {
    let mut send_stream = send_h2_response_headers(
        respond,
        status,
        response_headers,
        upstream_content_length,
        false,
    )?;
    let mut sent_body_bytes = 0usize;

    while let Some(chunk) = upstream_response
        .chunk()
        .await
        .context("failed to read upstream response chunk for downstream HTTP/2")?
    {
        if chunk.is_empty() {
            continue;
        }

        let chunk_len = chunk.len();
        if let Err(error) = send_h2_body_bytes(
            &mut send_stream,
            chunk,
            false,
            DOWNSTREAM_H2_DATA_FRAME_BYTES,
        ) {
            debug!(
                response_body_bytes_sent = sent_body_bytes,
                status,
                error = %error,
                "downstream HTTP/2 stream stopped while sending response body"
            );
            return Err(downstream_h2_stream_cancelled(
                "sending response body DATA frame",
                error,
            ));
        }
        sent_body_bytes = sent_body_bytes.saturating_add(chunk_len);
    }

    if let Err(error) = send_stream.send_data(Bytes::new(), true) {
        debug!(
            response_body_bytes_sent = sent_body_bytes,
            status,
            error = %error,
            "downstream HTTP/2 stream stopped while finishing response body"
        );
        return Err(downstream_h2_stream_cancelled(
            "finishing response body stream",
            error,
        ));
    }

    debug!(
        response_body_bytes_sent = sent_body_bytes,
        status, "streamed upstream response to downstream HTTP/2 stream"
    );
    Ok(())
}

fn send_h2_buffered_response(
    respond: h2::server::SendResponse<Bytes>,
    status: u16,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<()> {
    let body_len = body.len() as u64;
    let mut send_stream =
        send_h2_response_headers(respond, status, headers, Some(body_len), false)?;
    if let Err(error) =
        send_h2_body_bytes(&mut send_stream, body, true, DOWNSTREAM_H2_DATA_FRAME_BYTES)
    {
        return Err(downstream_h2_stream_cancelled(
            "sending buffered response body",
            error,
        ));
    }
    Ok(())
}

fn send_h2_body_bytes(
    send_stream: &mut h2::SendStream<Bytes>,
    bytes: Bytes,
    end_stream: bool,
    chunk_bytes: usize,
) -> std::result::Result<(), h2::Error> {
    if bytes.is_empty() {
        return send_stream.send_data(bytes, end_stream);
    }

    if bytes.len() <= chunk_bytes {
        return send_stream.send_data(bytes, end_stream);
    }

    let mut offset = 0usize;
    while offset < bytes.len() {
        let end = (offset + chunk_bytes).min(bytes.len());
        let chunk = bytes.slice(offset..end);
        let chunk_end_stream = end_stream && end == bytes.len();
        send_stream.send_data(chunk, chunk_end_stream)?;
        offset = end;
    }
    Ok(())
}

async fn read_limited_h2_response_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read upstream response body for downstream HTTP/2 deep path")?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }

    Ok(Some(body))
}

async fn drain_h2_request_body(mut body: h2::RecvStream) -> Result<()> {
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|error| {
            downstream_h2_stream_cancelled("draining request body DATA frame", error)
        })?;
        let len = chunk.len();
        if len > 0 {
            body.flow_control().release_capacity(len).map_err(|error| {
                downstream_h2_stream_cancelled(
                    "releasing drained request flow-control capacity",
                    error,
                )
            })?;
        }
    }
    Ok(())
}

fn h2_request_decision_should_reset_stream(reason: &str) -> bool {
    // Baseline guardrail, not a permanent ban on future policy changes: H2
    // request-rule/adblock block hits are currently surfaced as
    // RST_STREAM(CANCEL), not synthetic 204/403/404 responses. This keeps the
    // blocked request out of upstream and matches the blocker-like cancellation
    // behavior verified by the baseline tests. If a later fix needs a different
    // H2 blocked-response policy, re-verify adblock.turtlecute.org, normal page
    // loads, and sites that observe blocked subresource status codes.
    matches!(reason, "adblock_blocked" | "request_rule_block")
}

async fn send_h2_local_response(
    respond: h2::server::SendResponse<Bytes>,
    response: MitmLocalResponse,
    is_head: bool,
) -> Result<()> {
    match response.body {
        MitmLocalResponseBody::Bytes(body) => {
            send_h2_local_bytes_response(
                respond,
                response.status_code,
                &response.content_type,
                body,
                is_head,
            )
            .await
        }
        MitmLocalResponseBody::Resource(replacement) => {
            send_h2_resource_replacement_response(respond, replacement, is_head).await
        }
    }
}

async fn send_h2_local_bytes_response(
    respond: h2::server::SendResponse<Bytes>,
    status_code: u16,
    content_type: &str,
    body: Vec<u8>,
    is_head: bool,
) -> Result<()> {
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .context("failed to encode HTTP/2 local response content-type")?,
    );
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string())
            .context("failed to encode HTTP/2 local response content-length")?,
    );
    let end_stream_with_headers = is_head || h2_status_has_no_body(status_code) || body.is_empty();
    let mut send_stream = send_h2_response_headers(
        respond,
        status_code,
        &headers,
        Some(body.len() as u64),
        end_stream_with_headers,
    )?;
    if !end_stream_with_headers {
        if let Err(error) = send_stream.send_data(Bytes::from(body), true) {
            return Err(downstream_h2_stream_cancelled(
                "sending local response body",
                error,
            ));
        }
    }
    Ok(())
}

async fn send_h2_resource_replacement_response(
    respond: h2::server::SendResponse<Bytes>,
    replacement: crate::proxy::resource_replace::ResourceReplacement,
    is_head: bool,
) -> Result<()> {
    let mut file = tokio::fs::File::open(&replacement.path)
        .await
        .with_context(|| {
            format!(
                "failed to open replacement resource for rule `{}`: {}",
                replacement.rule_id,
                replacement.path.display()
            )
        })?;
    let content_length = file
        .metadata()
        .await
        .with_context(|| {
            format!(
                "failed to inspect replacement resource for rule `{}`: {}",
                replacement.rule_id,
                replacement.path.display()
            )
        })?
        .len();

    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        HeaderValue::from_str(&replacement.content_type)
            .context("failed to encode HTTP/2 resource replacement content-type")?,
    );
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string())
            .context("failed to encode HTTP/2 resource replacement content-length")?,
    );

    let end_stream_with_headers =
        is_head || h2_status_has_no_body(replacement.status) || content_length == 0;
    let mut send_stream = send_h2_response_headers(
        respond,
        replacement.status,
        &headers,
        Some(content_length),
        end_stream_with_headers,
    )?;
    if end_stream_with_headers {
        return Ok(());
    }

    let mut buffer = vec![0u8; DOWNSTREAM_H2_DATA_FRAME_BYTES];
    let mut bytes_sent = 0u64;
    while bytes_sent < content_length {
        let remaining = (content_length - bytes_sent) as usize;
        let read_limit = remaining.min(buffer.len());
        let read_count = file.read(&mut buffer[..read_limit]).await?;
        if read_count == 0 {
            send_h2_data_with_flow_control(
                &mut send_stream,
                Bytes::new(),
                true,
                "ending local resource replacement body",
            )
            .await?;
            break;
        }
        bytes_sent = bytes_sent.saturating_add(read_count as u64);
        let end_stream = bytes_sent >= content_length;
        send_h2_data_with_flow_control(
            &mut send_stream,
            Bytes::copy_from_slice(&buffer[..read_count]),
            end_stream,
            "sending local resource replacement body",
        )
        .await?;
    }
    Ok(())
}

async fn send_h2_data_with_flow_control(
    send_stream: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
    operation: &'static str,
) -> Result<()> {
    if data.is_empty() {
        if let Err(error) = send_stream.send_data(data, end_stream) {
            return Err(downstream_h2_stream_cancelled(operation, error));
        }
        return Ok(());
    }

    while !data.is_empty() {
        if send_stream.capacity() == 0 {
            send_stream.reserve_capacity(data.len());
            match poll_fn(|cx| send_stream.poll_capacity(cx)).await {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(downstream_h2_stream_cancelled(operation, error)),
                None => anyhow::bail!("downstream HTTP/2 stream closed while reserving capacity"),
            }
        }

        let send_len = send_stream.capacity().min(data.len());
        let remaining = data.split_off(send_len);
        let is_final_chunk = remaining.is_empty() && end_stream;
        if let Err(error) = send_stream.send_data(data, is_final_chunk) {
            return Err(downstream_h2_stream_cancelled(operation, error));
        }
        data = remaining;
    }
    Ok(())
}

async fn send_h2_not_implemented_response(
    respond: h2::server::SendResponse<Bytes>,
    message: &'static str,
) -> Result<()> {
    let response = MitmLocalResponse::text(501, "Not Implemented", message);
    send_h2_local_response(respond, response, false).await
}

fn reset_h2_stream(mut respond: h2::server::SendResponse<Bytes>, reason: h2::Reason) -> Result<()> {
    respond.send_reset(reason);
    Ok(())
}

fn send_h2_response_headers(
    mut respond: h2::server::SendResponse<Bytes>,
    status: u16,
    headers: &HeaderMap,
    content_length: Option<u64>,
    end_stream: bool,
) -> Result<h2::SendStream<Bytes>> {
    let no_body_status = h2_status_has_no_body(status);
    let status = StatusCode::from_u16(status).context("invalid downstream HTTP/2 status code")?;
    let mut builder = Response::builder().status(status);

    for (name, value) in headers {
        let is_content_length = name.as_str().eq_ignore_ascii_case(CONTENT_LENGTH.as_str());
        if (content_length.is_some() || no_body_status) && is_content_length {
            continue;
        }
        if should_forward_h2_response_header(name) {
            builder = builder.header(name, value);
        }
    }

    if !no_body_status {
        if let Some(length) = content_length {
            builder = builder.header(CONTENT_LENGTH, length.to_string());
        }
    }

    let response = builder
        .body(())
        .context("failed to build downstream HTTP/2 response")?;
    respond
        .send_response(response, end_stream)
        .map_err(|error| downstream_h2_stream_cancelled("sending response headers", error))
}

fn header_map_from_relay_response_head(
    head: &crate::proxy::upstream_model::RelayUpstreamResponseHead,
) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in &head.headers {
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

#[derive(Debug)]
struct MitmUrlLogSummary {
    path: String,
    path_query_hash: String,
    path_query_len: usize,
    signed_ip_family: String,
}

impl MitmUrlLogSummary {
    fn from_url(url: &str) -> Self {
        let path_query = mitm_url_path_query(url);
        let path = path_query
            .split('?')
            .next()
            .unwrap_or(path_query)
            .to_string();
        Self {
            path,
            path_query_hash: stable_short_hash(path_query),
            path_query_len: path_query.len(),
            signed_ip_family: signed_ip_family_label(signed_ip_family_from_path_query(path_query))
                .to_string(),
        }
    }
}

#[derive(Debug)]
struct MitmRequestHeaderFingerprint {
    header_count: usize,
    header_names_hash: String,
    header_names: String,
    header_names_without_accept_encoding_hash: String,
    semantic_header_names_hash: String,
    semantic_header_names: String,
    has_host: bool,
    has_range: bool,
    has_cookie: bool,
    has_referer: bool,
    has_origin: bool,
    has_user_agent: bool,
    has_sec_fetch: bool,
    accept_encoding: Option<String>,
}

impl MitmRequestHeaderFingerprint {
    fn from_header_pairs(headers: &[(String, String)]) -> Self {
        let mut header_names = headers
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .collect::<Vec<_>>();
        header_names.sort();
        let unique_header_names = header_names
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let header_names_without_accept_encoding = unique_header_names
            .iter()
            .filter(|name| name.as_str() != "accept-encoding")
            .cloned()
            .collect::<Vec<_>>();
        let semantic_header_names = unique_header_names
            .iter()
            .filter(|name| !is_h1_transport_header_name(name))
            .cloned()
            .collect::<Vec<_>>();

        let has_named = |needle: &str| unique_header_names.iter().any(|name| name == needle);
        let has_sec_fetch = unique_header_names
            .iter()
            .any(|name| name.starts_with("sec-fetch-"));
        let accept_encoding = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
            .map(|(_, value)| value.clone());

        Self {
            header_count: headers.len(),
            header_names_hash: stable_short_hash(&unique_header_names.join(",")),
            header_names: unique_header_names.join(","),
            header_names_without_accept_encoding_hash: stable_short_hash(
                &header_names_without_accept_encoding.join(","),
            ),
            semantic_header_names_hash: stable_short_hash(&semantic_header_names.join(",")),
            semantic_header_names: semantic_header_names.join(","),
            has_host: has_named("host"),
            has_range: has_named("range"),
            has_cookie: has_named("cookie"),
            has_referer: has_named("referer"),
            has_origin: has_named("origin"),
            has_user_agent: has_named("user-agent"),
            has_sec_fetch,
            accept_encoding,
        }
    }
}

fn is_h1_transport_header_name(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "te"
    )
}

fn mitm_url_path_query(url: &str) -> &str {
    let without_fragment = url.split('#').next().unwrap_or(url);
    let after_scheme = without_fragment
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(without_fragment);
    after_scheme
        .find('/')
        .map(|index| &after_scheme[index..])
        .unwrap_or("/")
}

fn is_expected_rejection_noise(status: u16, path: &str) -> bool {
    status == 404
        || path.ends_with(".map")
        || path.ends_with(".sourcemap")
        || path == "/feeds/videos.xml"
}

fn is_signed_media_rejection_noise(status: u16, path: &str) -> bool {
    status == 403 && path == "/videoplayback"
}

fn is_adblock_test_probe_rejection_noise(
    method: &str,
    source_url: &str,
    status: u16,
    path: &str,
) -> bool {
    if !method.eq_ignore_ascii_case("HEAD") {
        return false;
    }
    if !(400..=599).contains(&status) {
        return false;
    }
    if !source_url.contains("adblock.turtlecute.org") {
        return false;
    }

    // adblock.turtlecute.org intentionally probes many ad/tracker domains with
    // HEAD requests to synthetic paths. Their expected upstream rejections are
    // useful for benchmark scoring but not useful as RelayGate warn-level health
    // signals. Keep them at debug so real H3/stable-path regressions stand out.
    path == "/fakepage.html"
        || path == "/adv/metrika"
        || path.starts_with("/campaignmanager/answer/")
}

fn is_stable_rejection_diagnostic_noise(status: u16, path: &str, correlation: &str) -> bool {
    is_signed_media_rejection_noise(status, path)
        && matches!(
            correlation,
            "h3_precommit_then_stable_rejected"
                | "h3_slot_rejected_then_stable_rejected"
                | "h3_connector_error_then_stable_rejected"
        )
}

fn is_routine_stable_upstream_rejection_noise(status: u16, correlation: &str) -> bool {
    // Once active H3 did not serve a request, the stable path receiving a
    // normal HTTP 4xx usually means origin/application state, not a RelayGate
    // H3/H2 health issue. Keep these at debug so real transport failures stand
    // out while browsing remains quiet. 5xx stays visible unless a narrower
    // expected-noise rule catches it.
    (400..=499).contains(&status)
        && matches!(
            correlation,
            "h3_precommit_then_stable_rejected"
                | "h3_slot_rejected_then_stable_rejected"
                | "h3_connector_error_then_stable_rejected"
                | "stable_deep_pipeline_rejected"
                | "stable_rejected_without_h3_service"
        )
}

fn should_fallback_h3_rejection_before_downstream(status: u16, path: &str) -> bool {
    if is_expected_rejection_noise(status, path) {
        return false;
    }

    // Baseline guardrail, not a claim that H3 can never serve these statuses:
    // active H3 is an optimization, while the stable reqwest path is the source
    // of truth for origin/security-sensitive application rejections before any
    // downstream bytes are committed. A precommit 400-class response can be
    // tied to browser security/challenge state, one-shot tokens, or egress-path
    // differences; forwarding it immediately can turn a recoverable H3 probe
    // mismatch into a visible page failure. Future H3 fixes can narrow this
    // fallback gate, but should prove the stable path would return the same
    // result and re-test Cloudflare/security challenges before doing so.
    matches!(status, 400 | 401 | 403 | 407 | 409 | 416 | 429) || status >= 500
}

fn signed_ip_family_from_path_query(path_query: &str) -> Option<&'static str> {
    signed_ip_value_from_path_query(path_query)
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .map(|addr| match addr {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        })
}

fn signed_ip_value_from_path_query(path_query: &str) -> Option<String> {
    let query = path_query.split_once('?')?.1;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name == "ip" {
            return Some(percent_decode_query_component(value));
        }
    }
    None
}

fn percent_decode_query_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn signed_ip_family_label(family: Option<&'static str>) -> &'static str {
    family.unwrap_or("none")
}

fn stable_short_hash(value: &str) -> String {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[derive(Debug, Clone, Copy)]
struct H3StreamingRequestGate {
    allowed: bool,
    reason: &'static str,
}

#[derive(Debug)]
struct H3StreamingPathTrace {
    gate: H3StreamingRequestGate,
    stage: String,
    detail: String,
}

impl H3StreamingPathTrace {
    fn new(gate: H3StreamingRequestGate) -> Self {
        Self {
            gate,
            stage: if gate.allowed {
                "eligible"
            } else {
                "not_eligible"
            }
            .to_string(),
            detail: gate.reason.to_string(),
        }
    }

    fn mark(&mut self, stage: impl Into<String>, detail: impl Into<String>) {
        self.stage = stage.into();
        self.detail = detail.into();
    }

    fn gate_reason(&self) -> &'static str {
        self.gate.reason
    }

    fn stage(&self) -> &str {
        &self.stage
    }

    fn detail(&self) -> &str {
        &self.detail
    }
}

fn h3_streaming_request_gate(
    h3_direct_path_allowed: bool,
    request_body_empty: bool,
    disable_mitm_fast_path: bool,
    mode: Http3StreamingResponseModeConfig,
    browser_storage_access_request: bool,
    response_body_pipeline_preflight_reason: Option<&'static str>,
    method: &str,
    request_type: &str,
    target_url: &str,
) -> H3StreamingRequestGate {
    if !h3_direct_path_allowed {
        return H3StreamingRequestGate {
            allowed: false,
            reason: "active_h3_direct_path_not_semantically_allowed",
        };
    }
    if !request_body_empty {
        return H3StreamingRequestGate {
            allowed: false,
            reason: "request_body_present",
        };
    }
    if disable_mitm_fast_path {
        return H3StreamingRequestGate {
            allowed: false,
            reason: "mitm_fast_path_disabled",
        };
    }
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return H3StreamingRequestGate {
            allowed: false,
            reason: "method_not_supported_by_active_h3_request_writer",
        };
    }
    if browser_storage_access_request {
        return H3StreamingRequestGate {
            allowed: false,
            reason: "browser_storage_access_request",
        };
    }
    if let Some(reason) = response_body_pipeline_preflight_reason {
        return H3StreamingRequestGate {
            allowed: false,
            reason,
        };
    }

    match mode {
        Http3StreamingResponseModeConfig::Disabled => H3StreamingRequestGate {
            allowed: false,
            reason: "h3_streaming_mode_disabled",
        },
        Http3StreamingResponseModeConfig::FastPathProbe => H3StreamingRequestGate {
            allowed: true,
            reason: "fast_path_probe",
        },
        Http3StreamingResponseModeConfig::MediaOnly => {
            let path = h3_streaming_url_path_lower(target_url);
            if h3_streaming_path_is_manifest_or_text(&path)
                || h3_streaming_path_is_obvious_non_media(&path)
            {
                return H3StreamingRequestGate {
                    allowed: false,
                    reason: "media_only_excluded_path",
                };
            }
            if request_type == "media" || h3_streaming_path_is_media_like(&path) {
                H3StreamingRequestGate {
                    allowed: true,
                    reason: "media_only_candidate",
                }
            } else {
                H3StreamingRequestGate {
                    allowed: false,
                    reason: "media_only_not_media_like",
                }
            }
        }
    }
}

fn h3_active_direct_path_allowed(
    upstream: &crate::proxy::mitm_upstream::MitmUpstreamRequestIntent,
) -> bool {
    // Active H3 currently opens a direct QUIC connection to the origin. If a
    // request is routed through a RelayGate upstream proxy, or if the upstream
    // protocol policy explicitly asks for H1/H2, taking the active H3 path would
    // no longer be semantically equivalent to the established reqwest path.
    // That can matter for signed media URLs, IP-bound sessions, enterprise
    // routing, and any host whose authorization depends on the egress path.
    upstream.upstream_id.is_none()
        && matches!(
            upstream.protocol_policy,
            crate::proxy::mitm_upstream::MitmUpstreamProtocolPolicy::Auto
        )
}

fn h3_streaming_url_path_lower(target_url: &str) -> String {
    let without_fragment = target_url.split('#').next().unwrap_or(target_url);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    without_query.to_ascii_lowercase()
}

fn h3_streaming_path_is_media_like(path: &str) -> bool {
    path.ends_with(".m4s")
        || path.ends_with(".cmfv")
        || path.ends_with(".cmfa")
        || path.ends_with(".cmaf")
        || path.ends_with(".mp4")
        || path.ends_with(".m4v")
        || path.ends_with(".mov")
        || path.ends_with(".webm")
        || path.ends_with(".ts")
        || path.ends_with(".mp3")
        || path.ends_with(".m4a")
        || path.ends_with(".aac")
        || path.ends_with(".ogg")
}

fn h3_streaming_path_is_manifest_or_text(path: &str) -> bool {
    path.ends_with(".m3u8")
        || path.ends_with(".mpd")
        || path.ends_with(".vtt")
        || path.ends_with(".srt")
}

fn h3_streaming_path_is_obvious_non_media(path: &str) -> bool {
    path.ends_with(".html")
        || path.ends_with(".htm")
        || path.ends_with(".js")
        || path.ends_with(".mjs")
        || path.ends_with(".css")
        || path.ends_with(".json")
        || path.ends_with(".xml")
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
        || path.ends_with(".ttf")
        || path.ends_with(".otf")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".gif")
        || path.ends_with(".webp")
        || path.ends_with(".svg")
        || path.ends_with(".ico")
}

fn h2_status_has_no_body(status: u16) -> bool {
    (100..200).contains(&status) || matches!(status, 204 | 304)
}

fn response_content_type_lower(headers: &HeaderMap) -> String {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value: &HeaderValue| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn h2_target_url(default_authority: &str, uri: &Uri) -> Result<String> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri.to_string());
    }

    let authority = uri
        .authority()
        .map(|item| item.as_str())
        .unwrap_or(default_authority);
    let path = uri
        .path_and_query()
        .map(|item| item.as_str())
        .unwrap_or("/");
    Ok(format!("https://{authority}{path}"))
}

fn h2_target_authority(default_authority: &str, uri: &Uri) -> String {
    uri.authority()
        .map(|item| item.as_str().to_string())
        .unwrap_or_else(|| default_authority.to_string())
}

fn h2_headers_for_core(headers: &HeaderMap, authority: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut has_host = false;
    let mut cookie_values = Vec::new();

    for (name, value) in headers {
        let name_text = name.as_str();
        if name_text.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        if !should_include_h2_header_for_core(name) {
            continue;
        }
        if let Ok(value_text) = value.to_str() {
            if name_text.eq_ignore_ascii_case("cookie") {
                let trimmed = value_text.trim();
                if !trimmed.is_empty() {
                    cookie_values.push(trimmed.to_string());
                }
            } else {
                result.push((name_text.to_string(), value_text.to_string()));
            }
        }
    }

    // HTTP/2 may split Cookie into multiple header fields. The shared MITM
    // core and HTTP/1.1 upstream path should see the canonical browser request
    // shape: one Cookie header with values joined by "; ". This avoids partial
    // cookie forwarding on origins that are strict about session/API cookies.
    if !cookie_values.is_empty() {
        result.push(("cookie".to_string(), cookie_values.join("; ")));
    }
    if !has_host {
        result.push(("host".to_string(), authority.to_string()));
    }
    result
}

fn should_include_h2_header_for_core(name: &HeaderName) -> bool {
    let name = name.as_str();
    !name.starts_with(':') && !is_hop_by_hop_or_h2_prohibited_header(name)
}

fn h2_request_content_length_for_upstream(headers: &HeaderMap) -> Option<u64> {
    // Only propagate a syntactically valid downstream Content-Length. If it is
    // absent or malformed, keep the upstream body as unknown-length streaming.
    let value = headers.get(CONTENT_LENGTH)?;
    let value = value.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }

    value.parse::<u64>().ok()
}

fn should_forward_h2_request_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    if name.starts_with(':') || is_hop_by_hop_or_h2_prohibited_header(name) {
        return false;
    }

    // Match the established MITM H1 outbound behavior: RelayGate owns the
    // upstream body pipeline and asks origins for identity bodies so rewrite,
    // patch, adblock injection, and rgoff bypass never receive compressed
    // bytes with stripped/mismatched encoding headers.
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "accept-encoding" | "content-length" | "expect" | "host"
    )
}

fn should_forward_h2_response_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    !name.starts_with(':') && !is_hop_by_hop_or_h2_prohibited_header(name)
}

fn is_hop_by_hop_or_h2_prohibited_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
    )
}
