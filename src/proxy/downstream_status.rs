use std::{
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::http::Uri;

use crate::{
    config::{Http3StreamingResponseModeConfig, RelayGateConfig, UpstreamProtocolPolicyConfig},
    proxy::{
        http_forward::extract_host_from_pairs,
        http_parse::ParsedHttpRequest,
        mitm_core::MitmLocalResponse,
        upstream_h3::{
            self, UpstreamAttemptPlan, UpstreamHttp3ActiveBufferedForwardingEvent,
            UpstreamHttp3ActiveStreamingWriterEvent, UpstreamHttp3Candidate,
            UpstreamHttp3DiagnosticsEvent, UpstreamHttp3ProbeDiagnosticsEvent,
        },
        upstream_h3_backend::{
            experimental_h3_streaming_split_summary, experimental_quic_client_config_summary,
            experimental_quic_connect_summary,
        },
    },
};

pub(crate) const DOWNSTREAM_STATUS_PATH: &str = "/__relaygate/downstream";

const DOWNSTREAM_STATUS_HOSTS: &[&str] = &[
    "rg.local",
    "rg.localhost",
    "relaygate.local",
    "relaygate.localhost",
];

#[derive(Debug, Clone, Copy)]
pub(crate) enum DownstreamStatusProtocol {
    HttpProxyH1,
    MitmHttp1,
    MitmHttp2,
}

impl DownstreamStatusProtocol {
    fn label(self) -> &'static str {
        match self {
            Self::HttpProxyH1 => "HTTP/1.1 explicit proxy request",
            Self::MitmHttp1 => "HTTPS MITM downstream HTTP/1.1",
            Self::MitmHttp2 => "HTTPS MITM downstream HTTP/2",
        }
    }

    fn short(self) -> &'static str {
        match self {
            Self::HttpProxyH1 | Self::MitmHttp1 => "H1",
            Self::MitmHttp2 => "H2",
        }
    }

    fn mitm_tls(self) -> bool {
        matches!(self, Self::MitmHttp1 | Self::MitmHttp2)
    }
}

#[derive(Debug, Clone, Default)]
struct DownstreamObservationState {
    http_proxy_h1_requests: u64,
    mitm_h1_requests: u64,
    mitm_h2_streams: u64,
    last: Option<DownstreamObservationEvent>,
}

#[derive(Debug, Clone)]
struct DownstreamObservationEvent {
    protocol: DownstreamStatusProtocol,
    authority: String,
    target_url: String,
    negotiated_alpn: String,
    observed_at: String,
}

#[derive(Debug, Clone, Default)]
struct DownstreamObservationSnapshot {
    http_proxy_h1_requests: u64,
    mitm_h1_requests: u64,
    mitm_h2_streams: u64,
    last: Option<DownstreamObservationEvent>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum UpstreamObservedProtocol {
    Http1,
    Http2,
    Other,
}

impl UpstreamObservedProtocol {
    fn from_reqwest_version(version: reqwest::Version) -> Self {
        if version == reqwest::Version::HTTP_2 {
            Self::Http2
        } else if version == reqwest::Version::HTTP_10 || version == reqwest::Version::HTTP_11 {
            Self::Http1
        } else {
            Self::Other
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Http1 => "RelayGate -> upstream HTTP/1.x",
            Self::Http2 => "RelayGate -> upstream HTTP/2",
            Self::Other => "RelayGate -> upstream other HTTP version",
        }
    }

    fn short(self) -> &'static str {
        match self {
            Self::Http1 => "H1",
            Self::Http2 => "H2",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct UpstreamObservationState {
    http1_responses: u64,
    http2_responses: u64,
    other_responses: u64,
    last: Option<UpstreamObservationEvent>,
}

#[derive(Debug, Clone)]
struct UpstreamObservationEvent {
    protocol: UpstreamObservedProtocol,
    version_detail: String,
    authority: String,
    target_url: String,
    policy: UpstreamProtocolPolicyConfig,
    observed_at: String,
}

#[derive(Debug, Clone, Default)]
struct UpstreamObservationSnapshot {
    http1_responses: u64,
    http2_responses: u64,
    other_responses: u64,
    last: Option<UpstreamObservationEvent>,
}

fn observation_state() -> &'static Mutex<DownstreamObservationState> {
    static STATE: OnceLock<Mutex<DownstreamObservationState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(DownstreamObservationState::default()))
}

fn upstream_observation_state() -> &'static Mutex<UpstreamObservationState> {
    static STATE: OnceLock<Mutex<UpstreamObservationState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(UpstreamObservationState::default()))
}

pub(crate) fn record_http_proxy_status_request(request: &ParsedHttpRequest) {
    let Some((host, path)) = request_host_and_path(request) else {
        return;
    };
    let url = if request.uri_text.starts_with("http://") || request.uri_text.starts_with("https://")
    {
        request.uri_text.clone()
    } else {
        format!("http://{host}{path}")
    };
    record_downstream_observation(
        DownstreamStatusProtocol::HttpProxyH1,
        &host,
        &url,
        "none (plain HTTP proxy request)",
    );
}

pub(crate) fn record_mitm_request(
    protocol: DownstreamStatusProtocol,
    authority: &str,
    target_url: &str,
    negotiated_alpn: &str,
) {
    record_downstream_observation(protocol, authority, target_url, negotiated_alpn);
}

pub(crate) fn record_upstream_response(
    authority: &str,
    target_url: &str,
    version: reqwest::Version,
    policy: UpstreamProtocolPolicyConfig,
) {
    let protocol = UpstreamObservedProtocol::from_reqwest_version(version);
    let Ok(mut state) = upstream_observation_state().lock() else {
        return;
    };

    match protocol {
        UpstreamObservedProtocol::Http1 => {
            state.http1_responses = state.http1_responses.saturating_add(1);
        }
        UpstreamObservedProtocol::Http2 => {
            state.http2_responses = state.http2_responses.saturating_add(1);
        }
        UpstreamObservedProtocol::Other => {
            state.other_responses = state.other_responses.saturating_add(1);
        }
    }

    state.last = Some(UpstreamObservationEvent {
        protocol,
        version_detail: format!("{version:?}"),
        authority: authority.to_string(),
        target_url: target_url.to_string(),
        policy,
        observed_at: unix_seconds_now(),
    });
}

pub(crate) fn record_upstream_alt_svc(authority: &str, headers: &reqwest::header::HeaderMap) {
    upstream_h3::record_alt_svc(authority, headers);
}

fn record_downstream_observation(
    protocol: DownstreamStatusProtocol,
    authority: &str,
    target_url: &str,
    negotiated_alpn: &str,
) {
    let Ok(mut state) = observation_state().lock() else {
        return;
    };

    match protocol {
        DownstreamStatusProtocol::HttpProxyH1 => {
            state.http_proxy_h1_requests = state.http_proxy_h1_requests.saturating_add(1);
        }
        DownstreamStatusProtocol::MitmHttp1 => {
            state.mitm_h1_requests = state.mitm_h1_requests.saturating_add(1);
        }
        DownstreamStatusProtocol::MitmHttp2 => {
            state.mitm_h2_streams = state.mitm_h2_streams.saturating_add(1);
        }
    }

    state.last = Some(DownstreamObservationEvent {
        protocol,
        authority: authority.to_string(),
        target_url: target_url.to_string(),
        negotiated_alpn: negotiated_alpn.to_string(),
        observed_at: unix_seconds_now(),
    });
}

fn observation_snapshot() -> DownstreamObservationSnapshot {
    let Ok(state) = observation_state().lock() else {
        return DownstreamObservationSnapshot::default();
    };
    DownstreamObservationSnapshot {
        http_proxy_h1_requests: state.http_proxy_h1_requests,
        mitm_h1_requests: state.mitm_h1_requests,
        mitm_h2_streams: state.mitm_h2_streams,
        last: state.last.clone(),
    }
}

fn upstream_observation_snapshot() -> UpstreamObservationSnapshot {
    let Ok(state) = upstream_observation_state().lock() else {
        return UpstreamObservationSnapshot::default();
    };
    UpstreamObservationSnapshot {
        http1_responses: state.http1_responses,
        http2_responses: state.http2_responses,
        other_responses: state.other_responses,
        last: state.last.clone(),
    }
}

pub(crate) fn is_downstream_status_connect_target(host: &str, port: u16) -> bool {
    port == 443 && is_downstream_status_host(host)
}

pub(crate) fn is_downstream_status_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };

    let Some(host) = parsed.host_str() else {
        return false;
    };

    is_downstream_status_host(host) && path_matches(parsed.path())
}

pub(crate) fn http_proxy_status_response_bytes(
    request: &ParsedHttpRequest,
    config: &RelayGateConfig,
) -> Option<Vec<u8>> {
    let (host, path) = request_host_and_path(request)?;
    if !is_downstream_status_host(&host) || !path_matches(&path) {
        return None;
    }

    let url = if request.uri_text.starts_with("http://") || request.uri_text.starts_with("https://")
    {
        request.uri_text.clone()
    } else {
        format!("http://{host}{path}")
    };
    record_http_proxy_status_request(request);
    let body = build_status_html(
        DownstreamStatusProtocol::HttpProxyH1,
        config,
        &host,
        &url,
        "none (plain HTTP proxy request)",
    );
    Some(build_http_response_bytes(
        200,
        "OK",
        "text/html; charset=utf-8",
        body.as_bytes(),
    ))
}

pub(crate) fn mitm_status_response(
    protocol: DownstreamStatusProtocol,
    config: &RelayGateConfig,
    authority: &str,
    target_url: &str,
    negotiated_alpn: &str,
) -> MitmLocalResponse {
    MitmLocalResponse::with_content_type(
        200,
        "OK",
        "text/html; charset=utf-8",
        build_status_html(protocol, config, authority, target_url, negotiated_alpn),
    )
}

pub(crate) fn is_downstream_status_host(host: &str) -> bool {
    let host = strip_optional_port(host).to_ascii_lowercase();
    DOWNSTREAM_STATUS_HOSTS
        .iter()
        .any(|candidate| host == *candidate)
}

fn request_host_and_path(request: &ParsedHttpRequest) -> Option<(String, String)> {
    if let Ok(uri) = request.uri_text.parse::<Uri>() {
        if let Some(host) = uri.host() {
            let path = uri
                .path_and_query()
                .map(|value| value.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            return Some((host.to_string(), path));
        }
    }

    let host = extract_host_from_pairs(&request.headers)?;
    let path = if request.uri_text.is_empty() {
        "/".to_string()
    } else {
        request.uri_text.clone()
    };
    Some((host, path))
}

fn path_matches(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path == DOWNSTREAM_STATUS_PATH || path == "/__relaygate/downstream/"
}

fn strip_optional_port(host: &str) -> &str {
    let host = host.trim();
    if host.starts_with('[') {
        return host;
    }
    host.rsplit_once(':')
        .and_then(|(name, port)| port.parse::<u16>().ok().map(|_| name))
        .unwrap_or(host)
}

fn build_status_html(
    protocol: DownstreamStatusProtocol,
    config: &RelayGateConfig,
    authority: &str,
    target_url: &str,
    negotiated_alpn: &str,
) -> String {
    let generated_at = unix_seconds_now();
    let observation = observation_snapshot();
    let upstream_observation = upstream_observation_snapshot();
    let upstream_alt_svc_observation = upstream_h3::observation_snapshot();
    let last_protocol_short = observation
        .last
        .as_ref()
        .map(|event| event.protocol.short())
        .unwrap_or("none");
    let last_protocol_label = observation
        .last
        .as_ref()
        .map(|event| event.protocol.label())
        .unwrap_or("no downstream request observed yet");
    let last_authority = observation
        .last
        .as_ref()
        .map(|event| event.authority.as_str())
        .unwrap_or("none");
    let last_target_url = observation
        .last
        .as_ref()
        .map(|event| event.target_url.as_str())
        .unwrap_or("none");
    let last_alpn = observation
        .last
        .as_ref()
        .map(|event| event.negotiated_alpn.as_str())
        .unwrap_or("none");
    let last_observed_at = observation
        .last
        .as_ref()
        .map(|event| event.observed_at.as_str())
        .unwrap_or("never");
    let last_upstream_protocol_short = upstream_observation
        .last
        .as_ref()
        .map(|event| event.protocol.short())
        .unwrap_or("none");
    let last_upstream_protocol_label = upstream_observation
        .last
        .as_ref()
        .map(|event| event.protocol.label())
        .unwrap_or("no upstream response observed yet");
    let last_upstream_version = upstream_observation
        .last
        .as_ref()
        .map(|event| event.version_detail.as_str())
        .unwrap_or("none");
    let last_upstream_authority = upstream_observation
        .last
        .as_ref()
        .map(|event| event.authority.as_str())
        .unwrap_or("none");
    let last_upstream_target_url = upstream_observation
        .last
        .as_ref()
        .map(|event| event.target_url.as_str())
        .unwrap_or("none");
    let last_upstream_policy = upstream_observation
        .last
        .as_ref()
        .map(|event| upstream_policy_config_value(event.policy))
        .unwrap_or("none");
    let last_upstream_observed_at = upstream_observation
        .last
        .as_ref()
        .map(|event| event.observed_at.as_str())
        .unwrap_or("never");
    let last_h3_authority = upstream_alt_svc_observation
        .last_h3
        .as_ref()
        .map(|event| event.authority.as_str())
        .unwrap_or("none");
    let last_h3_alt_svc = upstream_alt_svc_observation
        .last_h3
        .as_ref()
        .map(|event| event.alt_svc.as_str())
        .unwrap_or("none");
    let last_h3_observed_at = upstream_alt_svc_observation
        .last_h3
        .as_ref()
        .map(|event| event.observed_at.as_str())
        .unwrap_or("never");
    let recent_h3_authorities = if upstream_alt_svc_observation
        .recent_h3_authorities
        .is_empty()
    {
        "none".to_string()
    } else {
        upstream_alt_svc_observation
            .recent_h3_authorities
            .join(", ")
    };
    let active_h3_candidates =
        format_h3_candidate_cache(&upstream_alt_svc_observation.active_h3_candidates);
    let active_h3_candidates_present =
        if upstream_alt_svc_observation.active_h3_candidates.is_empty() {
            "no"
        } else {
            "yes"
        };
    let h3_attempt_plan_authority = upstream_alt_svc_observation
        .last_h3
        .as_ref()
        .map(|event| event.authority.as_str())
        .or_else(|| {
            upstream_observation
                .last
                .as_ref()
                .map(|event| event.authority.as_str())
        })
        .unwrap_or(authority);
    let current_h3_attempt_plan =
        upstream_h3::default_http3_attempt_plan_for_authority(h3_attempt_plan_authority);
    let current_h3_attempt_plan = format_h3_attempt_plan(&current_h3_attempt_plan);
    let http3_diagnostics = upstream_h3::http3_diagnostics_snapshot();
    let last_http3_diagnostics_event =
        format_http3_diagnostics_event(http3_diagnostics.last_event.as_ref());
    let last_http3_network_event =
        format_http3_diagnostics_event(http3_diagnostics.last_network_event.as_ref());
    let http3_probe_diagnostics = upstream_h3::http3_probe_diagnostics_snapshot();
    let last_http3_probe_event =
        format_http3_probe_diagnostics_event(http3_probe_diagnostics.last_event.as_ref());
    let last_http3_eligible_probe_event = format_http3_probe_diagnostics_event(
        http3_probe_diagnostics.last_h3_eligible_event.as_ref(),
    );
    let last_http3_response_probe_event = format_http3_probe_diagnostics_event(
        http3_probe_diagnostics.last_http3_response_event.as_ref(),
    );
    let http3_active_buffered_diagnostics =
        upstream_h3::http3_active_buffered_forwarding_snapshot();
    let last_http3_active_buffered_event = format_http3_active_buffered_forwarding_event(
        http3_active_buffered_diagnostics.last_event.as_ref(),
    );
    let last_http3_active_buffered_served_event = format_http3_active_buffered_forwarding_event(
        http3_active_buffered_diagnostics.last_served_event.as_ref(),
    );
    let http3_active_buffered_failure_cooldown =
        upstream_h3::http3_active_buffered_failure_cooldown_snapshot();
    let http3_active_buffered_failure_cooldown_entries =
        format_http3_active_buffered_failure_cooldown(&http3_active_buffered_failure_cooldown);
    let http3_active_streaming_writer_diagnostics =
        upstream_h3::http3_active_streaming_writer_snapshot();
    let last_http3_active_streaming_writer_event = format_http3_active_streaming_writer_event(
        http3_active_streaming_writer_diagnostics
            .last_event
            .as_ref(),
    );
    let last_http3_active_streaming_writer_ready_event = format_http3_active_streaming_writer_event(
        http3_active_streaming_writer_diagnostics
            .last_ready_event
            .as_ref(),
    );
    let last_http3_active_streaming_writer_candidate_miss_event =
        format_http3_active_streaming_writer_event(
            http3_active_streaming_writer_diagnostics
                .last_candidate_miss_event
                .as_ref(),
        );
    let downstream_http2 = config.proxy.mitm.downstream_http2;
    let h2_state = if downstream_http2 {
        "advertised"
    } else {
        "disabled"
    };
    let http3_probe_enabled = config.proxy.upstream.http3_probe_enabled;
    let http3_buffered_response_enabled = config.proxy.upstream.http3_buffered_response_enabled;
    let http3_buffered_response_state = if http3_buffered_response_enabled {
        "enabled"
    } else {
        "disabled"
    };
    let http3_buffered_response_behavior = if http3_buffered_response_enabled {
        "default-on guarded active path may use complete small buffered H3 responses; streaming, non-buffered, deep-pipeline, or failed cases fall back to reqwest auto"
    } else {
        "inactive; H3 responses are only observed by dry-run diagnostics and are not used for downstream forwarding"
    };
    let http3_streaming_response_enabled = config.proxy.upstream.http3_streaming_response_enabled;
    let http3_streaming_response_mode = config.proxy.upstream.http3_streaming_response_mode;
    let http3_streaming_response_state = if http3_streaming_response_enabled {
        match http3_streaming_response_mode {
            Http3StreamingResponseModeConfig::Disabled => "disabled",
            Http3StreamingResponseModeConfig::MediaOnly => "media_only",
            Http3StreamingResponseModeConfig::FastPathProbe => "fast_path_probe",
        }
    } else {
        "disabled"
    };
    let http3_streaming_response_behavior = if http3_streaming_response_enabled {
        match http3_streaming_response_mode {
            Http3StreamingResponseModeConfig::Disabled => "inactive; streaming H3 responses keep using reqwest fallback and the streaming writer guard is not exercised",
            Http3StreamingResponseModeConfig::MediaOnly => "media-only active path: H2 may progressively forward upstream H3 response bodies only for narrow video/audio media targets; regular pages, scripts, styles, JSON, images, manifests, deep-pipeline cases, and failed paths fall back to reqwest auto",
            Http3StreamingResponseModeConfig::FastPathProbe => "diagnostic fast-path probe: non-document fast-path subresources may exercise the H3->H2 byte-pump; deep-pipeline and failed paths fall back to reqwest auto before downstream headers when possible",
        }
    } else {
        "inactive; streaming H3 responses keep using reqwest fallback and the streaming writer guard is not exercised"
    };
    let http3_probe_cooldown_secs = upstream_h3::h3_handshake_probe_cooldown_seconds();
    let http3_streaming_split_summary = experimental_h3_streaming_split_summary();
    let http3_probe_state = if http3_probe_enabled {
        "enabled"
    } else {
        "disabled"
    };
    let http3_probe_behavior = if http3_probe_enabled {
        "dry-run probe may exercise the H3 request model, QUIC handshake, HTTP/3 response-header I/O, limited small-body buffering, and buffered response adapter readiness with per-authority cooldown, then still continue the normal reqwest path"
    } else {
        "inactive; no H3 probe work is performed before reqwest forwarding"
    };
    let http3_rollout_combined_test_summary = format_http3_rollout_combined_test_summary(
        config,
        active_h3_candidates_present == "yes",
        &http3_active_buffered_diagnostics,
        &http3_active_buffered_failure_cooldown,
        &http3_active_streaming_writer_diagnostics,
    );
    let upstream_policy = config.proxy.upstream.protocol_policy;
    let upstream_policy_value = upstream_policy_config_value(upstream_policy);
    let upstream_policy_label = upstream_policy_label(upstream_policy);
    let tls_state = if protocol.mitm_tls() { "yes" } else { "no" };
    let fake_https_url = format!("https://rg.local{DOWNSTREAM_STATUS_PATH}");
    let fake_http_url = format!("http://rg.local{DOWNSTREAM_STATUS_PATH}");

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RelayGate Status</title>
  <style>
    :root {{ color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ margin: 0; padding: 28px; background: Canvas; color: CanvasText; }}
    main {{ max-width: 1040px; margin: 0 auto; }}
    h1 {{ margin: 0 0 6px; font-size: 28px; letter-spacing: -.02em; }}
    h2 {{ margin: 0 0 12px; font-size: 18px; }}
    .sub {{ opacity: .72; margin-bottom: 18px; line-height: 1.5; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin: 18px 0; }}
    .card {{ border: 1px solid color-mix(in srgb, CanvasText 16%, transparent); border-radius: 16px; padding: 14px 16px; background: color-mix(in srgb, CanvasText 3%, transparent); }}
    .card h2 {{ display: flex; align-items: center; justify-content: space-between; gap: 10px; }}
    .line {{ margin: 7px 0; line-height: 1.5; }}
    .muted {{ opacity: .72; }}
    .tiny {{ font-size: 12px; opacity: .72; }}
    .pill {{ display: inline-block; padding: 3px 9px; border-radius: 999px; border: 1px solid color-mix(in srgb, CanvasText 20%, transparent); font-weight: 700; white-space: nowrap; }}
    .ok {{ color: light-dark(#146c2e, #8ee59c); }}
    .warn {{ color: light-dark(#8a5a00, #ffd479); }}
    .info {{ color: light-dark(#245caa, #9fc4ff); }}
    code {{ padding: 2px 6px; border-radius: 6px; background: color-mix(in srgb, CanvasText 10%, transparent); }}
    details {{ margin: 12px 0; border: 1px solid color-mix(in srgb, CanvasText 14%, transparent); border-radius: 14px; overflow: hidden; }}
    details > summary {{ cursor: pointer; padding: 13px 16px; font-weight: 700; background: color-mix(in srgb, CanvasText 5%, transparent); }}
    details[open] > summary {{ border-bottom: 1px solid color-mix(in srgb, CanvasText 12%, transparent); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 11px 14px; border-bottom: 1px solid color-mix(in srgb, CanvasText 10%, transparent); vertical-align: top; }}
    tr:last-child th, tr:last-child td {{ border-bottom: 0; }}
    th {{ width: 250px; opacity: .78; font-weight: 650; }}
    ul {{ margin: 6px 0; padding-left: 22px; }}
    .yaml {{ display: block; margin-top: 8px; padding: 12px; border-radius: 10px; background: color-mix(in srgb, CanvasText 8%, transparent); white-space: pre; overflow-x: auto; }}
  </style>
</head>
<body>
<main>
  <h1>RelayGate Status</h1>
  <div class="sub">Local runtime snapshot. H3 is experimental, guarded, and falls back to <code>{h3_failure_fallback}</code> on unsafe or failed paths.</div>

  <div class="grid">
    <section class="card">
      <h2>Downstream <span class="pill">{protocol_short}</span></h2>
      <div class="line">{protocol_label}</div>
      <div class="line">ALPN <code>{negotiated_alpn}</code> · MITM TLS <code>{tls_state}</code></div>
      <div class="line muted">H2 config <code>{downstream_http2}</code> ({h2_state}) · current authority <code>{authority}</code></div>
    </section>

    <section class="card">
      <h2>Upstream reqwest <span class="pill">{last_upstream_protocol_short}</span></h2>
      <div class="line">policy <code>{upstream_policy_value}</code> — {upstream_policy_label}</div>
      <div class="line muted">H1 <code>{upstream_h1_responses}</code> · H2 <code>{upstream_h2_responses}</code> · other <code>{upstream_other_responses}</code></div>
      <div class="line muted">last <code>{last_upstream_authority}</code> at <code>{last_upstream_observed_at}</code></div>
    </section>

    <section class="card">
      <h2>HTTP/3 rollout <span class="pill info">experimental</span></h2>
      <div class="line">backend <code>{http3_backend_status}</code></div>
      <div class="line">candidates <code>{active_h3_candidates_present}</code> · Alt-Svc ads <code>{h3_alt_svc_advertisements}</code></div>
      <div class="line muted">buffered <code>{http3_buffered_response_enabled}</code> · streaming <code>{http3_streaming_response_enabled}</code> · probe <code>{http3_probe_enabled}</code></div>
    </section>

    <section class="card">
      <h2>H3 health <span class="pill ok">fallback-safe</span></h2>
      <div class="line">backend success <code>{http3_successes}</code>/<code>{http3_attempts}</code> · fallbacks <code>{http3_fallbacks}</code></div>
      <div class="line">buffered served <code>{http3_active_buffered_served}</code>/<code>{http3_active_buffered_attempts}</code> · streaming ready <code>{http3_active_streaming_writer_ready}</code>/<code>{http3_active_streaming_writer_attempts}</code></div>
      <div class="line muted">failure cooldown: {http3_active_buffered_failure_cooldown_entries}</div>
    </section>
  </div>

  <details open>
    <summary>H3 rollout summary</summary>
    <table>
      <tr><th>Buffered active forwarding</th><td><code>{http3_buffered_response_state}</code><br>{http3_buffered_response_behavior}</td></tr>
      <tr><th>Streaming active forwarding</th><td><code>{http3_streaming_response_state}</code><br>{http3_streaming_response_behavior}<br><span class="muted">Media-only guard: active byte-pump is restricted to video/audio-like targets; any unsafe case falls back before downstream headers are sent.</span></td></tr>
      <tr><th>Combined check</th><td>{http3_rollout_combined_test_summary}</td></tr>
      <tr><th>Active buffered diagnostics</th><td>attempts <code>{http3_active_buffered_attempts}</code> · served <code>{http3_active_buffered_served}</code> · fallbacks <code>{http3_active_buffered_fallbacks}</code></td></tr>
      <tr><th>Streaming writer diagnostics</th><td>attempts <code>{http3_active_streaming_writer_attempts}</code> · ready <code>{http3_active_streaming_writer_ready}</code> · fallbacks <code>{http3_active_streaming_writer_fallbacks}</code> · candidate misses <code>{http3_active_streaming_writer_candidate_misses}</code></td></tr>
      <tr><th>Cancellation policy</th><td>{http3_streaming_split_summary}</td></tr>
    </table>
  </details>

  <details>
    <summary>Last important H3 events</summary>
    <table>
      <tr><th>Last active buffered served</th><td>{last_http3_active_buffered_served_event}</td></tr>
      <tr><th>Last active buffered event</th><td>{last_http3_active_buffered_event}</td></tr>
      <tr><th>Last streaming writer ready</th><td>{last_http3_active_streaming_writer_ready_event}</td></tr>
      <tr><th>Last streaming writer event</th><td>{last_http3_active_streaming_writer_event}</td></tr>
      <tr><th>Last streaming candidate miss</th><td>{last_http3_active_streaming_writer_candidate_miss_event}</td></tr>
      <tr><th>Last backend network event</th><td>{last_http3_network_event}</td></tr>
      <tr><th>Last successful dry-run response</th><td>{last_http3_response_probe_event}</td></tr>
    </table>
  </details>

  <details>
    <summary>H3 candidates and backend internals</summary>
    <table>
      <tr><th>Recent H3 authorities</th><td><code>{recent_h3_authorities}</code></td></tr>
      <tr><th>Active H3 candidate cache</th><td>{active_h3_candidates}</td></tr>
      <tr><th>Current attempt plan</th><td>{current_h3_attempt_plan}</td></tr>
      <tr><th>Last H3-capable upstream</th><td>authority <code>{last_h3_authority}</code><br>Alt-Svc <code>{last_h3_alt_svc}</code><br>at unix seconds <code>{last_h3_observed_at}</code></td></tr>
      <tr><th>QUIC transport</th><td><code>{quic_transport_status}</code></td></tr>
      <tr><th>QUIC client config</th><td>{quic_client_config_summary}</td></tr>
      <tr><th>QUIC timing / limits</th><td>{quic_connect_summary}<br>handshake cooldown: <code>{http3_probe_cooldown_secs}s</code> per authority</td></tr>
      <tr><th>Buffered failure cooldown</th><td>cooldown: <code>{http3_active_buffered_failure_cooldown_secs}s</code> per authority after DNS/UDP/QUIC/TLS/H3 failure<br>{http3_active_buffered_failure_cooldown_entries}</td></tr>
      <tr><th>Probe hook</th><td><code>{http3_probe_state}</code><br>{http3_probe_behavior}</td></tr>
      <tr><th>Backend diagnostics</th><td>attempts <code>{http3_attempts}</code> · successes <code>{http3_successes}</code> · fallbacks <code>{http3_fallbacks}</code></td></tr>
      <tr><th>Last backend event</th><td>{last_http3_diagnostics_event}</td></tr>
      <tr><th>Dry-run probe diagnostics</th><td>probes <code>{http3_probe_count}</code> · H3 responses <code>{http3_probe_http3_responses}</code> · reqwest fallbacks <code>{http3_probe_fallbacks}</code></td></tr>
      <tr><th>Last dry-run probe</th><td>{last_http3_probe_event}</td></tr>
      <tr><th>Last H3-eligible probe</th><td>{last_http3_eligible_probe_event}</td></tr>
    </table>
  </details>

  <details>
    <summary>HTTP protocol observations</summary>
    <table>
      <tr><th>Current request URL</th><td><code>{target_url}</code></td></tr>
      <tr><th>Last upstream</th><td><span class="pill">{last_upstream_protocol_short}</span> {last_upstream_protocol_label}<br>version <code>{last_upstream_version}</code><br>authority <code>{last_upstream_authority}</code><br>policy <code>{last_upstream_policy}</code><br>at unix seconds <code>{last_upstream_observed_at}</code></td></tr>
      <tr><th>Last upstream URL</th><td><code>{last_upstream_target_url}</code></td></tr>
      <tr><th>Downstream totals</th><td>plain proxy H1 <code>{http_proxy_h1_requests}</code> · MITM H1 <code>{mitm_h1_requests}</code> · MITM H2 streams <code>{mitm_h2_streams}</code></td></tr>
      <tr><th>Last downstream</th><td><span class="pill">{last_protocol_short}</span> {last_protocol_label}<br>authority <code>{last_authority}</code><br>ALPN <code>{last_alpn}</code><br>at unix seconds <code>{last_observed_at}</code></td></tr>
      <tr><th>Last downstream URL</th><td><code>{last_target_url}</code></td></tr>
      <tr><th>MITM keep-alive</th><td><code>{keep_alive}</code></td></tr>
      <tr><th>H1 max requests / connection</th><td><code>{max_requests}</code></td></tr>
    </table>
  </details>

  <details>
    <summary>URLs, lifetime, and YAML reminder</summary>
    <table>
      <tr><th>Preferred diagnostic URL</th><td><code>{fake_https_url}</code></td></tr>
      <tr><th>Plain HTTP fallback</th><td><code>{fake_http_url}</code></td></tr>
      <tr><th>Fallback strategy</th><td>When <code>downstream_http2</code> is disabled, RelayGate does not advertise <code>h2</code>. When it is enabled, browsers may negotiate either H2 or H1 per connection; this page reports the actual current request and recent observations.</td></tr>
      <tr><th>Diagnostics lifetime</th><td>All protocol and H3 counters on this page are runtime-only process memory. They reset when RelayGate restarts and are not written to YAML, logs, or a database.</td></tr>
      <tr><th>Generated at</th><td>unix seconds <code>{generated_at}</code></td></tr>
      <tr><th>YAML reminder</th><td><code class="yaml">listen: 127.0.0.1:8787</code></td></tr>
    </table>
  </details>
</main>
</body>
</html>"#,
        protocol_short = protocol.short(),
        protocol_label = html_escape(protocol.label()),
        tls_state = tls_state,
        negotiated_alpn = html_escape(negotiated_alpn),
        authority = html_escape(authority),
        target_url = html_escape(target_url),
        downstream_http2 = downstream_http2,
        h2_state = h2_state,
        upstream_policy_value = html_escape(upstream_policy_value),
        upstream_policy_label = html_escape(upstream_policy_label),
        upstream_h1_responses = upstream_observation.http1_responses,
        upstream_h2_responses = upstream_observation.http2_responses,
        upstream_other_responses = upstream_observation.other_responses,
        last_upstream_protocol_short = html_escape(last_upstream_protocol_short),
        last_upstream_protocol_label = html_escape(last_upstream_protocol_label),
        last_upstream_version = html_escape(last_upstream_version),
        last_upstream_authority = html_escape(last_upstream_authority),
        last_upstream_policy = html_escape(last_upstream_policy),
        last_upstream_observed_at = html_escape(last_upstream_observed_at),
        last_upstream_target_url = html_escape(last_upstream_target_url),
        h3_alt_svc_advertisements = upstream_alt_svc_observation.h3_advertisements,
        last_h3_authority = html_escape(last_h3_authority),
        last_h3_alt_svc = html_escape(last_h3_alt_svc),
        last_h3_observed_at = html_escape(last_h3_observed_at),
        recent_h3_authorities = html_escape(&recent_h3_authorities),
        active_h3_candidates = active_h3_candidates,
        quic_transport_status = html_escape(upstream_h3::quic_transport_status_label()),
        quic_client_config_summary = html_escape(experimental_quic_client_config_summary()),
        quic_connect_summary = html_escape(&experimental_quic_connect_summary()),
        http3_backend_status = html_escape(upstream_h3::http3_backend_status_label()),
        http3_probe_enabled = http3_probe_enabled,
        http3_buffered_response_enabled = http3_buffered_response_enabled,
        http3_buffered_response_state = html_escape(http3_buffered_response_state),
        http3_buffered_response_behavior = html_escape(http3_buffered_response_behavior),
        http3_streaming_response_enabled = http3_streaming_response_enabled,
        http3_streaming_response_state = html_escape(http3_streaming_response_state),
        http3_streaming_response_behavior = html_escape(http3_streaming_response_behavior),
        http3_streaming_split_summary = html_escape(http3_streaming_split_summary),
        http3_active_streaming_writer_attempts = http3_active_streaming_writer_diagnostics.attempts,
        http3_active_streaming_writer_ready =
            http3_active_streaming_writer_diagnostics.writer_plans_ready,
        http3_active_streaming_writer_fallbacks =
            http3_active_streaming_writer_diagnostics.fallbacks,
        http3_active_streaming_writer_candidate_misses =
            http3_active_streaming_writer_diagnostics.candidate_misses,
        last_http3_active_streaming_writer_event = last_http3_active_streaming_writer_event,
        last_http3_active_streaming_writer_ready_event =
            last_http3_active_streaming_writer_ready_event,
        last_http3_active_streaming_writer_candidate_miss_event =
            last_http3_active_streaming_writer_candidate_miss_event,
        http3_rollout_combined_test_summary = http3_rollout_combined_test_summary,
        http3_active_buffered_failure_cooldown_secs =
            http3_active_buffered_failure_cooldown.cooldown_secs,
        http3_active_buffered_failure_cooldown_entries =
            http3_active_buffered_failure_cooldown_entries,
        http3_active_buffered_attempts = http3_active_buffered_diagnostics.attempts,
        http3_active_buffered_served = http3_active_buffered_diagnostics.served,
        http3_active_buffered_fallbacks = http3_active_buffered_diagnostics.fallbacks,
        last_http3_active_buffered_event = last_http3_active_buffered_event,
        last_http3_active_buffered_served_event = last_http3_active_buffered_served_event,
        http3_probe_cooldown_secs = http3_probe_cooldown_secs,
        http3_probe_state = html_escape(http3_probe_state),
        http3_probe_behavior = html_escape(http3_probe_behavior),
        active_h3_candidates_present = html_escape(active_h3_candidates_present),
        current_h3_attempt_plan = current_h3_attempt_plan,
        http3_attempts = http3_diagnostics.attempts,
        http3_successes = http3_diagnostics.successes,
        http3_fallbacks = http3_diagnostics.fallbacks,
        last_http3_diagnostics_event = last_http3_diagnostics_event,
        last_http3_network_event = last_http3_network_event,
        http3_probe_count = http3_probe_diagnostics.probes,
        http3_probe_http3_responses = http3_probe_diagnostics.http3_responses,
        http3_probe_fallbacks = http3_probe_diagnostics.fallbacks,
        last_http3_probe_event = last_http3_probe_event,
        last_http3_eligible_probe_event = last_http3_eligible_probe_event,
        last_http3_response_probe_event = last_http3_response_probe_event,
        h3_failure_fallback = html_escape(upstream_h3::h3_failure_fallback_label()),
        keep_alive = config.proxy.mitm.keep_alive,
        max_requests = config.proxy.mitm.max_requests_per_connection,
        http_proxy_h1_requests = observation.http_proxy_h1_requests,
        mitm_h1_requests = observation.mitm_h1_requests,
        mitm_h2_streams = observation.mitm_h2_streams,
        last_protocol_short = html_escape(last_protocol_short),
        last_protocol_label = html_escape(last_protocol_label),
        last_authority = html_escape(last_authority),
        last_alpn = html_escape(last_alpn),
        last_observed_at = html_escape(last_observed_at),
        last_target_url = html_escape(last_target_url),
        generated_at = generated_at,
        fake_https_url = fake_https_url,
        fake_http_url = fake_http_url,
    )
}

fn format_h3_attempt_plan(plan: &UpstreamAttemptPlan) -> String {
    let candidate = if let Some(candidate) = plan.h3_candidate.as_ref() {
        format!(
            "<code>{}</code> via <code>{}</code>",
            html_escape(&candidate.authority),
            html_escape(&candidate.protocol),
        )
    } else {
        "<code>none</code>".to_string()
    };
    let skip_code = plan.h3_skip_code().unwrap_or("none");
    let skip_detail = plan
        .h3_skip_reason
        .as_ref()
        .map(|error| error.detail.as_str())
        .unwrap_or("none");

    format!(
        "authority <code>{}</code><br>selected backend <code>{}</code><br>H3 candidate {}<br>H3 skip <code>{}</code> — {}<br>fallback <code>{}</code>",
        html_escape(&plan.authority),
        html_escape(plan.label()),
        candidate,
        html_escape(skip_code),
        html_escape(skip_detail),
        html_escape(plan.fallback_label()),
    )
}

fn format_http3_diagnostics_event(event: Option<&UpstreamHttp3DiagnosticsEvent>) -> String {
    let Some(event) = event else {
        return "<code>none</code>".to_string();
    };

    let candidate = if let Some(candidate) = event.candidate.as_ref() {
        format!(
            "<code>{}</code> via <code>{}</code>",
            html_escape(&candidate.authority),
            html_escape(&candidate.protocol),
        )
    } else {
        "<code>none</code>".to_string()
    };
    let error = if let Some(error) = event.error.as_ref() {
        format!(
            "<code>{}</code> — {}",
            html_escape(error.kind.code()),
            html_escape(&error.detail),
        )
    } else {
        "<code>none</code>".to_string()
    };

    format!(
        "outcome <code>{}</code><br>authority <code>{}</code><br>candidate {}<br>error {}<br>at unix seconds <code>{}</code>",
        html_escape(event.outcome.label()),
        html_escape(&event.authority),
        candidate,
        error,
        html_escape(&event.observed_at),
    )
}

fn format_http3_probe_diagnostics_event(
    event: Option<&UpstreamHttp3ProbeDiagnosticsEvent>,
) -> String {
    let Some(event) = event else {
        return "<code>none</code>".to_string();
    };

    let candidate = if let Some(candidate) = event.candidate.as_ref() {
        format!(
            "<code>{}</code> via <code>{}</code>",
            html_escape(&candidate.authority),
            html_escape(&candidate.protocol),
        )
    } else {
        "<code>none</code>".to_string()
    };
    let response = event
        .response_summary
        .as_ref()
        .map(|summary| html_escape(summary))
        .unwrap_or_else(|| "none".to_string());
    let error = if let Some(error) = event.fallback_error.as_ref() {
        format!(
            "<code>{}</code> — {}",
            html_escape(error.kind.code()),
            html_escape(&error.detail),
        )
    } else {
        "<code>none</code>".to_string()
    };

    format!(
        "decision <code>{}</code><br>authority <code>{}</code><br>selected backend <code>{}</code><br>candidate {}<br>response {}<br>fallback error {}<br>fallback <code>{}</code><br>at unix seconds <code>{}</code>",
        html_escape(event.decision.label()),
        html_escape(&event.authority),
        html_escape(event.selected_backend.label()),
        candidate,
        response,
        error,
        html_escape(event.fallback_backend.label()),
        html_escape(&event.observed_at),
    )
}

fn format_http3_active_buffered_failure_cooldown(
    snapshot: &upstream_h3::UpstreamHttp3ActiveBufferedFailureCooldownSnapshot,
) -> String {
    if snapshot.active_entries.is_empty() {
        return "<code>none</code>".to_string();
    }

    let mut output = String::from("<ul>");
    for entry in &snapshot.active_entries {
        output.push_str(&format!(
            "<li><code>{}</code> · <code>{}</code> · remaining <code>{}s</code> · last failure unix <code>{}</code><br>{}</li>",
            html_escape(&entry.authority),
            html_escape(&entry.reason_code),
            entry.remaining_secs,
            html_escape(&entry.last_failure_at),
            html_escape(&entry.reason_detail),
        ));
    }
    output.push_str("</ul>");
    output
}

fn format_http3_rollout_combined_test_summary(
    config: &RelayGateConfig,
    active_candidates_present: bool,
    buffered: &upstream_h3::UpstreamHttp3ActiveBufferedForwardingSnapshot,
    failure_cooldown: &upstream_h3::UpstreamHttp3ActiveBufferedFailureCooldownSnapshot,
    streaming: &upstream_h3::UpstreamHttp3ActiveStreamingWriterSnapshot,
) -> String {
    let buffered_state = if !config.proxy.upstream.http3_buffered_response_enabled {
        "disabled"
    } else if buffered.served > 0 {
        "serving"
    } else if active_candidates_present {
        "warming"
    } else {
        "waiting_for_h3_candidate"
    };
    let served_ratio = if buffered.attempts == 0 {
        "n/a".to_string()
    } else {
        format!(
            "{:.1}%",
            (buffered.served as f64 / buffered.attempts as f64) * 100.0
        )
    };
    let cooldown_state = if failure_cooldown.active_entries.is_empty() {
        "clear".to_string()
    } else {
        format!(
            "cooling {} authority",
            failure_cooldown.active_entries.len()
        )
    };
    let streaming_state = if config.proxy.upstream.http3_streaming_response_enabled {
        match config.proxy.upstream.http3_streaming_response_mode {
            Http3StreamingResponseModeConfig::Disabled => "disabled_safe",
            Http3StreamingResponseModeConfig::MediaOnly => {
                if streaming.writer_plans_ready > 0 {
                    "media_only_ready_observed"
                } else {
                    "media_only_waiting"
                }
            }
            Http3StreamingResponseModeConfig::FastPathProbe => {
                if streaming.writer_plans_ready > 0 {
                    "fast_path_probe_ready_observed"
                } else {
                    "fast_path_probe_waiting"
                }
            }
        }
    } else {
        "disabled_safe"
    };

    format!(
        "buffered fast-path <code>{}</code> · served ratio <code>{}</code> (<code>{}</code>/<code>{}</code>)<br>fallbacks <code>{}</code> · failure cooldown <code>{}</code> · streaming <code>{}</code> · streaming candidate misses <code>{}</code><br>combined check: browse normal H1/H2 pages; expect no broken JS/CSS/fonts, served may increase for small complete responses, H2 streaming may progressively forward according to mode, and upstream body errors should either fall back before downstream headers or reset only the affected stream",
        html_escape(buffered_state),
        html_escape(&served_ratio),
        buffered.served,
        buffered.attempts,
        buffered.fallbacks,
        html_escape(&cooldown_state),
        html_escape(streaming_state),
        streaming.candidate_misses,
    )
}

fn format_http3_active_buffered_forwarding_event(
    event: Option<&UpstreamHttp3ActiveBufferedForwardingEvent>,
) -> String {
    let Some(event) = event else {
        return "<code>none</code>".to_string();
    };

    let candidate = if let Some(candidate) = event.candidate.as_ref() {
        format!(
            "<code>{}</code> via <code>{}</code>",
            html_escape(&candidate.authority),
            html_escape(&candidate.protocol),
        )
    } else {
        "<code>none</code>".to_string()
    };
    let status = event
        .status_code
        .map(|status| format!("<code>{status}</code>"))
        .unwrap_or_else(|| "<code>none</code>".to_string());
    let headers = event
        .header_count
        .map(|count| format!("<code>{count}</code>"))
        .unwrap_or_else(|| "<code>none</code>".to_string());
    let body = event
        .body_bytes
        .map(|bytes| format!("<code>{bytes}</code>"))
        .unwrap_or_else(|| "<code>none</code>".to_string());
    let reason = match (event.reason_code.as_ref(), event.reason_detail.as_ref()) {
        (Some(code), Some(detail)) => format!(
            "<code>{}</code> — {}",
            html_escape(code),
            html_escape(detail),
        ),
        (Some(code), None) => format!("<code>{}</code>", html_escape(code)),
        _ => "<code>none</code>".to_string(),
    };

    format!(
        "outcome <code>{}</code><br>downstream <code>{}</code><br>authority <code>{}</code><br>candidate {}<br>status {} · headers {} · body bytes {}<br>reason {}<br>at unix seconds <code>{}</code>",
        html_escape(event.outcome.label()),
        html_escape(&event.downstream_protocol),
        html_escape(&event.authority),
        candidate,
        status,
        headers,
        body,
        reason,
        html_escape(&event.observed_at),
    )
}

fn format_http3_active_streaming_writer_event(
    event: Option<&UpstreamHttp3ActiveStreamingWriterEvent>,
) -> String {
    let Some(event) = event else {
        return "<code>none</code>".to_string();
    };

    let candidate = if let Some(candidate) = event.candidate.as_ref() {
        format!(
            "<code>{}</code> via <code>{}</code>",
            html_escape(&candidate.authority),
            html_escape(&candidate.protocol),
        )
    } else {
        "<code>none</code>".to_string()
    };
    let status = event
        .status_code
        .map(|status| format!("<code>{status}</code>"))
        .unwrap_or_else(|| "<code>none</code>".to_string());
    let headers = event
        .header_count
        .map(|count| format!("<code>{count}</code>"))
        .unwrap_or_else(|| "<code>none</code>".to_string());
    let reason = match (event.reason_code.as_ref(), event.reason_detail.as_ref()) {
        (Some(code), Some(detail)) => format!(
            "<code>{}</code> — {}",
            html_escape(code),
            html_escape(detail),
        ),
        (Some(code), None) => format!("<code>{}</code>", html_escape(code)),
        _ => "<code>none</code>".to_string(),
    };

    format!(
        "outcome <code>{}</code><br>downstream <code>{}</code><br>authority <code>{}</code><br>candidate {}<br>status {} · headers {}<br>reason {}<br>at unix seconds <code>{}</code>",
        html_escape(event.outcome.label()),
        html_escape(&event.downstream_protocol),
        html_escape(&event.authority),
        candidate,
        status,
        headers,
        reason,
        html_escape(&event.observed_at),
    )
}

fn format_h3_candidate_cache(candidates: &[UpstreamHttp3Candidate]) -> String {
    if candidates.is_empty() {
        return "<code>none</code>".to_string();
    }

    let mut output = String::from("<ul>");
    for candidate in candidates {
        let port = candidate
            .advertised_port
            .map(|value| value.to_string())
            .unwrap_or_else(|| "default".to_string());
        let ma = candidate
            .ma_seconds
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let expires = candidate
            .expires_at_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        output.push_str("<li>");
        output.push_str(&format!(
            "<code>{}</code> via <code>{}</code> port <code>{}</code> · ma <code>{}</code> · expires unix <code>{}</code> · observed <code>{}</code><br><small>Alt-Svc <code>{}</code></small>",
            html_escape(&candidate.authority),
            html_escape(&candidate.protocol),
            html_escape(&port),
            html_escape(&ma),
            html_escape(&expires),
            html_escape(&candidate.observed_at),
            html_escape(&candidate.alt_svc),
        ));
        output.push_str("</li>");
    }
    output.push_str("</ul>");
    output
}

fn upstream_policy_config_value(policy: UpstreamProtocolPolicyConfig) -> &'static str {
    match policy {
        UpstreamProtocolPolicyConfig::Auto => "auto",
        UpstreamProtocolPolicyConfig::Http1Only => "http1_only",
        UpstreamProtocolPolicyConfig::Http2PriorKnowledge => "http2_prior_knowledge",
    }
}

fn upstream_policy_label(policy: UpstreamProtocolPolicyConfig) -> &'static str {
    match policy {
        UpstreamProtocolPolicyConfig::Auto => "reqwest negotiates upstream H1/H2 automatically",
        UpstreamProtocolPolicyConfig::Http1Only => "force upstream HTTP/1.x",
        UpstreamProtocolPolicyConfig::Http2PriorKnowledge => {
            "force upstream H2 prior knowledge for controlled targets"
        }
    }
}

fn unix_seconds_now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn build_http_response_bytes(
    status_code: u16,
    reason_phrase: &str,
    content_type: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut output = format!(
        "HTTP/1.1 {status_code} {reason_phrase}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    output.extend_from_slice(body);
    output
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_status_url() {
        assert!(is_downstream_status_url(
            "https://rg.local/__relaygate/downstream"
        ));
        assert!(is_downstream_status_url(
            "https://relaygate.local/__relaygate/downstream/"
        ));
        assert!(!is_downstream_status_url(
            "https://example.com/__relaygate/downstream"
        ));
    }
}
