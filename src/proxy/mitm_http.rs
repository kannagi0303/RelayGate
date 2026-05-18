use std::{
    collections::{HashMap, VecDeque},
    error::Error as _,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, CONTENT_LENGTH, CONTENT_TYPE};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{debug, info};

use crate::{
    diagnostics,
    proxy::{http_framing, mitm_ca::normalize_authority, rules::RuleEffect},
};

#[derive(Debug, Clone)]
pub(crate) struct ParsedMitmHttpRequest {
    pub(crate) method: String,
    pub(crate) uri_text: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

pub(crate) fn parse_http_request(bytes: &[u8]) -> Result<ParsedMitmHttpRequest> {
    let header_end = http_framing::find_header_end(bytes)
        .context("invalid MITM HTTP request: missing header terminator")?;
    let header_text = std::str::from_utf8(&bytes[..header_end.index])?;
    let mut lines = header_text.lines();

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

    let raw_body = &bytes[header_end.index + header_end.delimiter_len..];
    let body = http_framing::request_body_bytes(&bytes[..header_end.index], raw_body)?;

    Ok(ParsedMitmHttpRequest {
        method: method.to_string(),
        uri_text: uri_text.to_string(),
        headers,
        body,
    })
}

pub(crate) fn build_https_target_url(
    authority: &str,
    request: &ParsedMitmHttpRequest,
) -> Result<String> {
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

pub(crate) fn connection_header_tokens(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

pub(crate) fn should_forward_request_header(name: &str, connection_tokens: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    !connection_tokens.iter().any(|token| token == &lower)
        && !matches!(
            lower.as_str(),
            "connection"
                | "proxy-connection"
                | "content-length"
                | "expect"
                | "host"
                | "accept-encoding"
                | "keep-alive"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        )
}

pub(crate) fn header_pairs_from_reqwest(headers: &HeaderMap) -> Vec<(String, String)> {
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

pub(crate) fn apply_response_effects(mut body: Vec<u8>, effects: &[RuleEffect]) -> Vec<u8> {
    for effect in effects {
        if let RuleEffect::RewriteResponseBody { find, replace } = effect {
            let rewritten = String::from_utf8_lossy(&body).replace(find, replace);
            body = rewritten.into_bytes();
        }
    }

    body
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MitmResponseConnection {
    KeepAlive,
    Close,
}

impl MitmResponseConnection {
    pub(crate) fn header_value(self) -> &'static str {
        match self {
            MitmResponseConnection::KeepAlive => "keep-alive",
            MitmResponseConnection::Close => "close",
        }
    }

    pub(crate) fn tracing_label(self) -> &'static str {
        match self {
            MitmResponseConnection::KeepAlive => "keep_alive",
            MitmResponseConnection::Close => "close",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MitmStreamBodyMode {
    /// Forward upstream body bytes exactly as received. When
    /// `expected_content_length` is present, the response writer validates that
    /// the upstream body actually completed at the declared boundary before the
    /// MITM connection is allowed to be reused.
    Raw {
        expected_content_length: Option<u64>,
    },
    /// Re-frame the upstream streaming body as HTTP/1.1 chunked for downstream.
    /// This gives the browser an explicit body boundary while preserving
    /// streaming and allowing the MITM TLS connection to stay alive safely.
    ChunkedReencoded,
    /// Do not write a response body. Used for HEAD / 1xx / 204 / 304.
    NoBody,
}

impl MitmStreamBodyMode {
    pub(crate) fn tracing_label(self) -> &'static str {
        match self {
            MitmStreamBodyMode::Raw { .. } => "raw",
            MitmStreamBodyMode::ChunkedReencoded => "chunked_reencoded",
            MitmStreamBodyMode::NoBody => "no_body",
        }
    }

    pub(crate) fn reencode_chunked(self) -> bool {
        matches!(self, MitmStreamBodyMode::ChunkedReencoded)
    }

    pub(crate) fn expected_content_length(self) -> Option<u64> {
        match self {
            MitmStreamBodyMode::Raw {
                expected_content_length,
            } => expected_content_length,
            MitmStreamBodyMode::ChunkedReencoded | MitmStreamBodyMode::NoBody => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MitmBodyCompletion {
    CompleteKnownLength { bytes: usize, expected: u64 },
    CompleteBufferedContentLength { bytes: usize },
    IncompleteKnownLength { bytes: usize, expected: u64 },
    CompleteChunkedReencoded { bytes: usize, chunks: usize },
    CompleteNoBody,
    CompleteCloseDelimited { bytes: usize },
}

impl MitmBodyCompletion {
    pub(crate) fn tracing_label(self) -> &'static str {
        match self {
            MitmBodyCompletion::CompleteKnownLength { .. } => "complete_known_length",
            MitmBodyCompletion::CompleteBufferedContentLength { .. } => {
                "complete_buffered_content_length"
            }
            MitmBodyCompletion::IncompleteKnownLength { .. } => "incomplete_known_length",
            MitmBodyCompletion::CompleteChunkedReencoded { .. } => "complete_chunked_reencoded",
            MitmBodyCompletion::CompleteNoBody => "complete_no_body",
            MitmBodyCompletion::CompleteCloseDelimited { .. } => "complete_close_delimited",
        }
    }

    pub(crate) fn keep_alive_safe(self) -> bool {
        matches!(
            self,
            MitmBodyCompletion::CompleteKnownLength { .. }
                | MitmBodyCompletion::CompleteBufferedContentLength { .. }
                | MitmBodyCompletion::CompleteChunkedReencoded { .. }
                | MitmBodyCompletion::CompleteNoBody
        )
    }

    pub(crate) fn rejected_reason(self) -> &'static str {
        match self {
            MitmBodyCompletion::CompleteKnownLength { .. }
            | MitmBodyCompletion::CompleteBufferedContentLength { .. }
            | MitmBodyCompletion::CompleteChunkedReencoded { .. }
            | MitmBodyCompletion::CompleteNoBody => "response_body_completed",
            MitmBodyCompletion::IncompleteKnownLength { .. } => {
                "response_body_incomplete_known_length"
            }
            MitmBodyCompletion::CompleteCloseDelimited { .. } => "response_body_close_delimited",
        }
    }

    pub(crate) fn bytes(self) -> usize {
        match self {
            MitmBodyCompletion::CompleteKnownLength { bytes, .. }
            | MitmBodyCompletion::CompleteBufferedContentLength { bytes }
            | MitmBodyCompletion::IncompleteKnownLength { bytes, .. }
            | MitmBodyCompletion::CompleteChunkedReencoded { bytes, .. }
            | MitmBodyCompletion::CompleteCloseDelimited { bytes } => bytes,
            MitmBodyCompletion::CompleteNoBody => 0,
        }
    }

    pub(crate) fn chunks(self) -> usize {
        match self {
            MitmBodyCompletion::CompleteChunkedReencoded { chunks, .. } => chunks,
            _ => 0,
        }
    }
}

pub(crate) fn build_https_response_bytes(
    status_code: u16,
    reason_phrase: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
    connection: MitmResponseConnection,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(format!("HTTP/1.1 {status_code} {reason_phrase}\r\n").as_bytes());

    append_forwardable_response_headers(&mut output, headers, true);

    output.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    output
        .extend_from_slice(format!("Connection: {}\r\n\r\n", connection.header_value()).as_bytes());
    output.extend_from_slice(&body);
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlushPolicy {
    /// Flush the first body chunk promptly, then allow later chunks to coalesce.
    FirstChunk,
    /// Flush every body chunk. Keep this for true live streams such as SSE.
    EveryChunk,
    /// Flush after at least this many pending body bytes.
    PeriodicBytes(usize),
}

const DEFAULT_MEDIA_FLUSH_BYTES: usize = 128 * 1024;
const MAX_PERIODIC_FLUSH_INTERVAL: Duration = Duration::from_millis(250);
const LOW_LATENCY_RESPONSE_BYTES: u64 = 64 * 1024;
const LARGE_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const BALANCED_FLUSH_BYTES: usize = 256 * 1024;
const THROUGHPUT_FLUSH_BYTES: usize = 1024 * 1024;
const CONSERVATIVE_FLUSH_BYTES: usize = 64 * 1024;
const CRITICAL_ASSET_FLUSH_BYTES: usize = 32 * 1024;
const ADAPTIVE_MIN_SAMPLE_BYTES: usize = 512 * 1024;
const ADAPTIVE_MIN_SAMPLE_INTERVAL_SECS: u64 = 5;
const MAX_ADAPTIVE_HOSTS: usize = 512;
const EWMA_ALPHA: f64 = 0.2;

#[derive(Debug, Clone, Default)]
struct HostAdaptiveStats {
    throughput_bytes_per_sec: f64,
    error_score: f64,
    last_sample_at: Option<Instant>,
}

#[derive(Debug, Default)]
struct AdaptiveFlushState {
    stats: HashMap<String, HostAdaptiveStats>,
    order: VecDeque<String>,
}

fn adaptive_flush_state() -> &'static Mutex<AdaptiveFlushState> {
    static STATE: OnceLock<Mutex<AdaptiveFlushState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(AdaptiveFlushState::default()))
}

pub(crate) async fn stream_https_response(
    tls_stream: &mut tokio_rustls::server::TlsStream<&mut TcpStream>,
    status_code: u16,
    reason_phrase: &str,
    target_url: &str,
    request_type: &str,
    headers: &HeaderMap,
    mut upstream_response: reqwest::Response,
    connection: MitmResponseConnection,
    body_mode: MitmStreamBodyMode,
    expected_content_length: Option<u64>,
) -> Result<MitmBodyCompletion> {
    let response_head =
        build_https_response_head(status_code, reason_phrase, headers, connection, body_mode);
    let flush_policy =
        flush_policy_for_response(target_url, request_type, headers, expected_content_length);
    let stream_started_at = Instant::now();

    // Always flush headers. This lets the browser start processing the response early,
    // without forcing every body to use low-latency chunk flushing.
    tls_stream.write_all(&response_head).await?;
    tls_stream.flush().await?;

    let mut chunk_index = 0usize;
    let mut pending_flush_bytes = 0usize;
    let mut pending_flush_started_at = Instant::now();
    let mut response_body_bytes = 0usize;

    let completion = if matches!(body_mode, MitmStreamBodyMode::NoBody) {
        MitmBodyCompletion::CompleteNoBody
    } else {
        while let Some(chunk) = upstream_response.chunk().await? {
            if body_mode.reencode_chunked() {
                let chunk_head = format!("{:X}\r\n", chunk.len());
                tls_stream.write_all(chunk_head.as_bytes()).await?;
                tls_stream.write_all(&chunk).await?;
                tls_stream.write_all(b"\r\n").await?;
                pending_flush_bytes = pending_flush_bytes
                    .saturating_add(chunk_head.len())
                    .saturating_add(chunk.len())
                    .saturating_add(2);
            } else {
                tls_stream.write_all(&chunk).await?;
                pending_flush_bytes = pending_flush_bytes.saturating_add(chunk.len());
            }
            response_body_bytes = response_body_bytes.saturating_add(chunk.len());

            if should_flush_after_chunk(
                flush_policy,
                chunk_index,
                pending_flush_bytes,
                pending_flush_started_at.elapsed(),
            ) {
                tls_stream.flush().await?;
                pending_flush_bytes = 0;
                pending_flush_started_at = Instant::now();
            }

            chunk_index += 1;
        }

        if body_mode.reencode_chunked() {
            tls_stream.write_all(b"0\r\n\r\n").await?;
            MitmBodyCompletion::CompleteChunkedReencoded {
                bytes: response_body_bytes,
                chunks: chunk_index,
            }
        } else if let Some(expected) = body_mode.expected_content_length() {
            if response_body_bytes as u64 == expected {
                MitmBodyCompletion::CompleteKnownLength {
                    bytes: response_body_bytes,
                    expected,
                }
            } else {
                MitmBodyCompletion::IncompleteKnownLength {
                    bytes: response_body_bytes,
                    expected,
                }
            }
        } else {
            MitmBodyCompletion::CompleteCloseDelimited {
                bytes: response_body_bytes,
            }
        }
    };

    debug!(
        response_body_mode = body_mode.tracing_label(),
        reencode_chunked = body_mode.reencode_chunked(),
        chunk_count = chunk_index,
        response_body_bytes = response_body_bytes,
        body_completion = completion.tracing_label(),
        body_completion_keep_alive_safe = completion.keep_alive_safe(),
        mitm_connection_header = connection.tracing_label(),
        status = status_code,
        url = %target_url,
        "MITM streamed response body"
    );

    // Keep response completion deterministic, especially before the outer MITM layer shuts down TLS.
    tls_stream.flush().await?;
    record_adaptive_stream_success(target_url, response_body_bytes, stream_started_at.elapsed());

    Ok(completion)
}

pub(crate) fn record_adaptive_stream_failure(target_url: &str) {
    let Some(host) = target_url_host(target_url) else {
        return;
    };
    let Ok(mut state) = adaptive_flush_state().lock() else {
        return;
    };
    ensure_adaptive_host_slot(&mut state, &host);
    let stats = state.stats.entry(host).or_default();
    stats.error_score = ewma(stats.error_score, 1.0);
}

pub(crate) fn flush_policy_for_response(
    target_url: &str,
    request_type: &str,
    headers: &HeaderMap,
    expected_content_length: Option<u64>,
) -> FlushPolicy {
    let path = lower_url_path_without_query(target_url);
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if is_event_stream(&content_type) {
        return FlushPolicy::EveryChunk;
    }

    if is_segment_stream(&path, &content_type) {
        return FlushPolicy::PeriodicBytes(CONSERVATIVE_FLUSH_BYTES);
    }

    if is_playlist_or_manifest(&path, &content_type) {
        return FlushPolicy::FirstChunk;
    }

    if expected_content_length.is_some_and(|length| length <= LOW_LATENCY_RESPONSE_BYTES)
        && is_latency_sensitive_small_response(&path, request_type, &content_type)
    {
        return FlushPolicy::FirstChunk;
    }

    if is_critical_subresource(request_type, &path, &content_type) {
        return FlushPolicy::PeriodicBytes(CRITICAL_ASSET_FLUSH_BYTES);
    }

    if expected_content_length.is_some_and(|length| length >= LARGE_RESPONSE_BYTES) {
        return FlushPolicy::PeriodicBytes(adaptive_throughput_flush_bytes(
            target_url,
            THROUGHPUT_FLUSH_BYTES,
        ));
    }

    if is_general_media(&path, request_type, &content_type) {
        return FlushPolicy::PeriodicBytes(DEFAULT_MEDIA_FLUSH_BYTES);
    }

    FlushPolicy::PeriodicBytes(adaptive_balanced_flush_bytes(
        target_url,
        BALANCED_FLUSH_BYTES,
    ))
}

fn record_adaptive_stream_success(
    target_url: &str,
    response_body_bytes: usize,
    elapsed: std::time::Duration,
) {
    if response_body_bytes < ADAPTIVE_MIN_SAMPLE_BYTES {
        return;
    }
    let Some(host) = target_url_host(target_url) else {
        return;
    };
    let elapsed_secs = elapsed.as_secs_f64();
    if elapsed_secs <= 0.0 {
        return;
    }

    let now = Instant::now();
    let bytes_per_sec = response_body_bytes as f64 / elapsed_secs;
    let Ok(mut state) = adaptive_flush_state().lock() else {
        return;
    };
    ensure_adaptive_host_slot(&mut state, &host);
    let stats = state.stats.entry(host).or_default();
    if stats
        .last_sample_at
        .and_then(|last| now.checked_duration_since(last))
        .is_some_and(|age| age.as_secs() < ADAPTIVE_MIN_SAMPLE_INTERVAL_SECS)
    {
        return;
    }

    stats.last_sample_at = Some(now);
    stats.throughput_bytes_per_sec = if stats.throughput_bytes_per_sec == 0.0 {
        bytes_per_sec
    } else {
        ewma(stats.throughput_bytes_per_sec, bytes_per_sec)
    };
    stats.error_score = ewma(stats.error_score, 0.0);
}

fn adaptive_throughput_flush_bytes(target_url: &str, default_bytes: usize) -> usize {
    let Some(stats) = adaptive_stats_for_target(target_url) else {
        return default_bytes;
    };
    if stats.error_score >= 0.25 {
        return BALANCED_FLUSH_BYTES;
    }
    if stats.throughput_bytes_per_sec >= 64.0 * 1024.0 * 1024.0 {
        return 2 * 1024 * 1024;
    }
    if stats.throughput_bytes_per_sec <= 8.0 * 1024.0 * 1024.0 {
        return BALANCED_FLUSH_BYTES;
    }
    default_bytes
}

fn adaptive_balanced_flush_bytes(target_url: &str, default_bytes: usize) -> usize {
    let Some(stats) = adaptive_stats_for_target(target_url) else {
        return default_bytes;
    };
    if stats.error_score >= 0.25 {
        return CONSERVATIVE_FLUSH_BYTES;
    }
    if stats.throughput_bytes_per_sec >= 64.0 * 1024.0 * 1024.0 {
        return 512 * 1024;
    }
    default_bytes
}

fn adaptive_stats_for_target(target_url: &str) -> Option<HostAdaptiveStats> {
    let host = target_url_host(target_url)?;
    adaptive_flush_state()
        .lock()
        .ok()
        .and_then(|state| state.stats.get(&host).cloned())
}

fn ensure_adaptive_host_slot(state: &mut AdaptiveFlushState, host: &str) {
    if state.stats.contains_key(host) {
        return;
    }
    while state.stats.len() >= MAX_ADAPTIVE_HOSTS {
        let Some(oldest) = state.order.pop_front() else {
            break;
        };
        state.stats.remove(&oldest);
    }
    state.order.push_back(host.to_string());
}

fn ewma(previous: f64, sample: f64) -> f64 {
    (previous * (1.0 - EWMA_ALPHA)) + (sample * EWMA_ALPHA)
}

fn target_url_host(target_url: &str) -> Option<String> {
    let without_scheme = target_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(target_url);
    let authority = without_scheme.split('/').next()?.trim();
    let host = authority
        .trim_start_matches('[')
        .trim_end_matches(']')
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority)
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn should_flush_after_chunk(
    flush_policy: FlushPolicy,
    chunk_index: usize,
    pending_flush_bytes: usize,
    pending_flush_age: Duration,
) -> bool {
    match flush_policy {
        FlushPolicy::FirstChunk => chunk_index == 0,
        FlushPolicy::EveryChunk => true,
        // Even throughput-oriented responses must release the first body bytes
        // promptly. Some modern sites serve media/API assets from extensionless
        // or generic `application/octet-stream` URLs, so classification can miss
        // them. Waiting for a large periodic threshold before the first flush can
        // make the browser believe the resource is stalled and cancel dependent
        // requests. After the first chunk, keep the coalescing threshold for
        // throughput.
        FlushPolicy::PeriodicBytes(threshold) => {
            chunk_index == 0
                || pending_flush_bytes >= threshold
                || pending_flush_age >= MAX_PERIODIC_FLUSH_INTERVAL
        }
    }
}

fn lower_url_path_without_query(target_url: &str) -> String {
    let without_scheme = target_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(target_url);
    let path_and_query = without_scheme
        .find('/')
        .map(|index| &without_scheme[index..])
        .unwrap_or("/");

    path_and_query
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(path_and_query)
        .to_ascii_lowercase()
}

fn is_event_stream(content_type: &str) -> bool {
    content_type.starts_with("text/event-stream")
}

fn is_latency_sensitive_small_response(path: &str, request_type: &str, content_type: &str) -> bool {
    matches!(
        request_type,
        "document" | "subdocument" | "script" | "stylesheet"
    ) || content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("javascript")
        || content_type.contains("xml")
        || path.ends_with(".json")
        || path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".html")
}

fn is_segment_stream(path: &str, content_type: &str) -> bool {
    path.ends_with(".m4s")
        || path.ends_with(".ts")
        || path.ends_with(".cmfv")
        || path.ends_with(".cmfa")
        || path.ends_with(".cmaf")
        || content_type.contains("video/iso.segment")
        || content_type.contains("audio/iso.segment")
}

fn is_playlist_or_manifest(path: &str, content_type: &str) -> bool {
    path.ends_with(".m3u8")
        || path.ends_with(".mpd")
        || content_type.contains("application/vnd.apple.mpegurl")
        || content_type.contains("application/x-mpegurl")
        || content_type.contains("application/dash+xml")
}

fn is_general_media(path: &str, request_type: &str, content_type: &str) -> bool {
    request_type == "media"
        || content_type.starts_with("video/")
        || content_type.starts_with("audio/")
        || path.ends_with(".mp4")
        || path.ends_with(".m4v")
        || path.ends_with(".mov")
        || path.ends_with(".webm")
        || path.ends_with(".mp3")
        || path.ends_with(".m4a")
        || path.ends_with(".aac")
        || path.ends_with(".ogg")
}

fn is_critical_subresource(request_type: &str, path: &str, content_type: &str) -> bool {
    matches!(
        request_type,
        "script" | "stylesheet" | "xmlhttprequest" | "font"
    ) || content_type.contains("javascript")
        || content_type.contains("json")
        || content_type.contains("css")
        || content_type.contains("font/")
        || path.ends_with(".js")
        || path.ends_with(".mjs")
        || path.ends_with(".css")
        || path.ends_with(".json")
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
}

pub(crate) fn log_slow_mitm_stage(
    stage: &str,
    url: &str,
    elapsed_ms: u128,
    extra: &str,
    threshold_ms: u128,
) {
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

pub(crate) fn simple_http_response_bytes(
    status_code: u16,
    reason_phrase: &str,
    body: &str,
) -> Vec<u8> {
    simple_http_response_bytes_with_content_type(
        status_code,
        reason_phrase,
        "text/plain; charset=utf-8",
        body.as_bytes(),
    )
}

pub(crate) fn simple_http_response_bytes_with_content_type(
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

pub(crate) fn upstream_tls_failure_response(host: &str, target_url: &str) -> Vec<u8> {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>RelayGate Upstream TLS Verification Failed</title></head><body><h1>RelayGate</h1><p>Upstream TLS certificate verification failed.</p><p>Host: {}</p><p>URL: {}</p><p>RelayGate keeps standard upstream TLS verification enabled by default.</p></body></html>",
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

pub(crate) fn is_upstream_certificate_error(error: &reqwest::Error) -> bool {
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

pub(crate) fn log_response_body(source: &str, url: &str, content_type: Option<&str>, body: &[u8]) {
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

fn parse_header_line(line: &str) -> Result<(String, String)> {
    let (name, value) = line
        .split_once(':')
        .with_context(|| format!("invalid MITM HTTP header line: {line}"))?;
    Ok((name.trim().to_string(), value.trim().to_string()))
}

fn build_https_response_head(
    status_code: u16,
    reason_phrase: &str,
    headers: &HeaderMap,
    connection: MitmResponseConnection,
    body_mode: MitmStreamBodyMode,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(format!("HTTP/1.1 {status_code} {reason_phrase}\r\n").as_bytes());

    append_forwardable_response_headers(&mut output, headers, body_mode.reencode_chunked());

    if body_mode.reencode_chunked() {
        output.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    } else if let MitmStreamBodyMode::Raw {
        expected_content_length: Some(length),
    } = body_mode
    {
        // reqwest can expose a reliable decoded body length even when the upstream
        // response header map no longer contains Content-Length. Downstream HTTP/1.1
        // still needs an explicit body boundary; otherwise a keep-alive response has
        // neither Content-Length nor Transfer-Encoding and the browser can treat later
        // bytes/resources as a broken response.
        if !headers.contains_key(CONTENT_LENGTH) {
            output.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        }
    }

    output
        .extend_from_slice(format!("Connection: {}\r\n\r\n", connection.header_value()).as_bytes());
    output
}

fn append_forwardable_response_headers(
    output: &mut Vec<u8>,
    headers: &HeaderMap,
    skip_content_length: bool,
) {
    let connection_tokens = response_connection_header_tokens(headers);

    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop_response_header(&lower, &connection_tokens)
            || (skip_content_length && lower == "content-length")
        {
            continue;
        }

        if let Ok(value_text) = value.to_str() {
            output.extend_from_slice(format!("{}: {}\r\n", name.as_str(), value_text).as_bytes());
        }
    }
}

fn response_connection_header_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

fn is_hop_by_hop_response_header(lower_name: &str, connection_tokens: &[String]) -> bool {
    connection_tokens.iter().any(|token| token == lower_name)
        || matches!(
            lower_name,
            "connection"
                | "proxy-connection"
                | "keep-alive"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        )
}

fn html_escape_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
        headers
    }

    fn reset_adaptive_state() {
        *adaptive_flush_state().lock().unwrap() = AdaptiveFlushState::default();
    }

    fn adaptive_test_guard() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn adaptive_flush_prefers_low_latency_for_small_text() {
        let _guard = adaptive_test_guard();
        reset_adaptive_state();
        let policy = flush_policy_for_response(
            "https://example.test/api/data.json",
            "xmlhttprequest",
            &headers("application/json"),
            Some(1024),
        );

        assert_eq!(policy, FlushPolicy::FirstChunk);
    }

    #[test]
    fn adaptive_flush_prefers_throughput_for_large_body() {
        let _guard = adaptive_test_guard();
        reset_adaptive_state();
        let policy = flush_policy_for_response(
            "https://example.test/download.bin",
            "other",
            &headers("application/octet-stream"),
            Some(10 * 1024 * 1024),
        );

        assert_eq!(policy, FlushPolicy::PeriodicBytes(THROUGHPUT_FLUSH_BYTES));
    }

    #[test]
    fn adaptive_flush_keeps_event_stream_low_latency() {
        let _guard = adaptive_test_guard();
        reset_adaptive_state();
        let policy = flush_policy_for_response(
            "https://example.test/events",
            "xmlhttprequest",
            &headers("text/event-stream"),
            None,
        );

        assert_eq!(policy, FlushPolicy::EveryChunk);
    }

    #[test]
    fn adaptive_flush_keeps_media_segments_streaming_without_every_chunk_flush() {
        let _guard = adaptive_test_guard();
        reset_adaptive_state();
        let policy = flush_policy_for_response(
            "https://video.example.test/chunk-1.m4s",
            "media",
            &headers("video/iso.segment"),
            Some(2 * 1024 * 1024),
        );

        assert_eq!(policy, FlushPolicy::PeriodicBytes(CONSERVATIVE_FLUSH_BYTES));
    }

    #[test]
    fn adaptive_flush_increases_large_body_threshold_for_fast_hosts() {
        let _guard = adaptive_test_guard();
        reset_adaptive_state();
        record_adaptive_stream_success(
            "https://fast.example.test/download.bin",
            128 * 1024 * 1024,
            std::time::Duration::from_secs(1),
        );

        let policy = flush_policy_for_response(
            "https://fast.example.test/download.bin",
            "other",
            &headers("application/octet-stream"),
            Some(128 * 1024 * 1024),
        );

        assert_eq!(policy, FlushPolicy::PeriodicBytes(2 * 1024 * 1024));
    }

    #[test]
    fn adaptive_flush_ignores_tiny_success_samples() {
        let _guard = adaptive_test_guard();
        reset_adaptive_state();
        record_adaptive_stream_success(
            "https://fast.example.test/small.json",
            32 * 1024,
            std::time::Duration::from_millis(10),
        );

        let policy = flush_policy_for_response(
            "https://fast.example.test/download.bin",
            "other",
            &headers("application/octet-stream"),
            Some(128 * 1024 * 1024),
        );

        assert_eq!(policy, FlushPolicy::PeriodicBytes(THROUGHPUT_FLUSH_BYTES));
    }

    #[test]
    fn adaptive_flush_backs_off_after_stream_errors() {
        let _guard = adaptive_test_guard();
        reset_adaptive_state();
        record_adaptive_stream_failure("https://unstable.example.test/download.bin");
        record_adaptive_stream_failure("https://unstable.example.test/download.bin");

        let policy = flush_policy_for_response(
            "https://unstable.example.test/download.bin",
            "other",
            &headers("application/octet-stream"),
            Some(128 * 1024 * 1024),
        );

        assert_eq!(policy, FlushPolicy::PeriodicBytes(BALANCED_FLUSH_BYTES));
    }

    #[test]
    fn adaptive_flush_keeps_critical_subresources_conservative() {
        let _guard = adaptive_test_guard();
        reset_adaptive_state();
        record_adaptive_stream_success(
            "https://fast.example.test/app.js",
            128 * 1024 * 1024,
            std::time::Duration::from_secs(1),
        );

        let policy = flush_policy_for_response(
            "https://fast.example.test/app.js",
            "script",
            &headers("application/javascript"),
            Some(2 * 1024 * 1024),
        );

        assert_eq!(
            policy,
            FlushPolicy::PeriodicBytes(CRITICAL_ASSET_FLUSH_BYTES)
        );
    }

    #[test]
    fn periodic_flush_policy_releases_first_chunk_promptly() {
        assert!(should_flush_after_chunk(
            FlushPolicy::PeriodicBytes(THROUGHPUT_FLUSH_BYTES),
            0,
            1024,
            Duration::ZERO
        ));
        assert!(!should_flush_after_chunk(
            FlushPolicy::PeriodicBytes(THROUGHPUT_FLUSH_BYTES),
            1,
            1024,
            Duration::ZERO
        ));
        assert!(should_flush_after_chunk(
            FlushPolicy::PeriodicBytes(THROUGHPUT_FLUSH_BYTES),
            1,
            THROUGHPUT_FLUSH_BYTES,
            Duration::ZERO
        ));
        assert!(should_flush_after_chunk(
            FlushPolicy::PeriodicBytes(THROUGHPUT_FLUSH_BYTES),
            1,
            1024,
            MAX_PERIODIC_FLUSH_INTERVAL
        ));
    }

    #[test]
    fn h1_streaming_head_adds_content_length_when_reqwest_knows_it() {
        let head = build_https_response_head(
            200,
            "OK",
            &headers("application/javascript"),
            MitmResponseConnection::KeepAlive,
            MitmStreamBodyMode::Raw {
                expected_content_length: Some(123),
            },
        );
        let text = String::from_utf8(head).unwrap();

        assert!(text.contains("Content-Length: 123\r\n"));
        assert!(!text.contains("Transfer-Encoding: chunked\r\n"));
    }

    #[test]
    fn h1_streaming_head_keeps_chunked_boundary_for_unknown_length() {
        let head = build_https_response_head(
            200,
            "OK",
            &headers("application/octet-stream"),
            MitmResponseConnection::KeepAlive,
            MitmStreamBodyMode::ChunkedReencoded,
        );
        let text = String::from_utf8(head).unwrap();

        assert!(text.contains("Transfer-Encoding: chunked\r\n"));
        assert!(!text.contains("Content-Length:"));
    }
}
