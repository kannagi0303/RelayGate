use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, Bytes};
use quinn::crypto::rustls::QuicClientConfig;
use tokio::{task::JoinHandle, time::timeout};
use tracing::{debug, warn};

use crate::{
    dns::SharedDnsResolver,
    proxy::{
        upstream_h3::{
            active_candidate_for_authority, h3_handshake_probe_cooldown_seconds,
            preflight_request_for_http3, record_http3_attempt, record_http3_fallback,
            reserve_http3_handshake_probe_slot, UpstreamAttemptPlan, UpstreamBackendError,
            UpstreamBackendErrorKind, UpstreamHttp3Backend, UpstreamHttp3BackendStatus,
            UpstreamHttp3Future, UpstreamQuicTransport, UpstreamQuicTransportStatus,
        },
        upstream_model::{
            RelayUpstreamOwnedStreamingResponseHandoff, RelayUpstreamRequest,
            RelayUpstreamResponseBodyMode, RelayUpstreamResponseBodyProbe,
            RelayUpstreamResponseHead, RelayUpstreamResponseModel, RelayUpstreamStreamingBody,
            RelayUpstreamStreamingReadError, RelayUpstreamStreamingResponse,
        },
    },
};

const H3_ALPN: &[u8] = b"h3";
const H3_29_ALPN: &[u8] = b"h3-29";
const DEFAULT_H3_CONNECT_TIMEOUT: Duration = Duration::from_millis(750);
const DEFAULT_H3_RESPONSE_HEADERS_TIMEOUT: Duration = Duration::from_millis(1500);
const DEFAULT_H3_RESPONSE_BODY_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const DEFAULT_H3_SMALL_BODY_BUFFER_LIMIT_BYTES: usize = 64 * 1024;
const DEFAULT_H3_PORT: u16 = 443;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamilyHint {
    Ipv4,
    Ipv6,
}

impl IpFamilyHint {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

/// Experimental Quinn-backed QUIC transport seam.
///
/// This type now owns the first concrete Quinn-facing helper layer: creating a
/// client endpoint and a rustls/QUIC client configuration with HTTP/3 ALPN. It
/// is still not called by the normal forwarding path, and Quinn types remain
/// contained inside this backend module.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ExperimentalUpstreamQuicTransport;

impl UpstreamQuicTransport for ExperimentalUpstreamQuicTransport {
    fn status(&self) -> UpstreamQuicTransportStatus {
        UpstreamQuicTransportStatus::ExperimentalHandshakeProbe
    }
}

/// Private Quinn endpoint holder for the experimental upstream QUIC backend.
///
/// The wrapper intentionally stays in this module so shared core code never
/// needs to know about `quinn::Endpoint`. Future connection code can borrow the
/// endpoint from here, then convert success/failure back into RelayGate-owned
/// response/error types.
#[allow(dead_code)]
pub(crate) struct ExperimentalQuicClientEndpoint {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
}

impl ExperimentalQuicClientEndpoint {
    #[allow(dead_code)]
    pub(crate) fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    #[allow(dead_code)]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// Private result of a Quinn connection attempt.
///
/// This intentionally remains inside the experimental backend module. Shared
/// forwarding code should only see RelayGate-owned response/error models, not a
/// raw `quinn::Connection`.
#[allow(dead_code)]
pub(crate) struct ExperimentalQuicConnected {
    connection: quinn::Connection,
    remote_addr: SocketAddr,
    server_name: String,
}

impl ExperimentalQuicConnected {
    #[allow(dead_code)]
    pub(crate) fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    #[allow(dead_code)]
    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    #[allow(dead_code)]
    pub(crate) fn server_name(&self) -> &str {
        &self.server_name
    }
}

impl ExperimentalUpstreamQuicTransport {
    /// Short timeout used by the experimental upstream H3 connection seam.
    ///
    /// H3 is a speculative optimization path. It must fail quickly and let the
    /// stable reqwest upstream connector continue the request.
    #[allow(dead_code)]
    pub(crate) fn connect_timeout(&self) -> Duration {
        DEFAULT_H3_CONNECT_TIMEOUT
    }

    /// Resolves an active Alt-Svc H3 candidate into socket addresses using
    /// RelayGate's existing DNS resolver.
    ///
    /// This keeps upstream H3 on the same DNS routing/cache policy as the
    /// current reqwest path. No UDP socket is opened here.
    #[allow(dead_code)]
    pub(crate) async fn resolve_h3_candidate_addrs(
        &self,
        dns_resolver: &SharedDnsResolver,
        candidate: &crate::proxy::upstream_h3::UpstreamHttp3Candidate,
    ) -> Result<Vec<SocketAddr>, UpstreamBackendError> {
        let host = candidate_server_name(candidate)?;
        let port = candidate_port(candidate);
        let addrs = dns_resolver
            .resolve_socket_addrs(&host, port)
            .await
            .map_err(|error| {
                UpstreamBackendError::new(
                    UpstreamBackendErrorKind::DnsError,
                    format!(
                        "failed to resolve upstream H3 candidate {} via RelayGate DNS: {error}",
                        candidate.authority
                    ),
                )
            })?;

        if addrs.is_empty() {
            return Err(UpstreamBackendError::new(
                UpstreamBackendErrorKind::DnsError,
                format!(
                    "RelayGate DNS returned no addresses for upstream H3 candidate {}",
                    candidate.authority
                ),
            ));
        }

        Ok(addrs)
    }

    /// Attempts only the QUIC handshake for an upstream H3 candidate.
    ///
    /// This helper is not used by the active forwarding path yet. If a future
    /// probe calls it, every error must remain a clean reqwest fallback reason.
    #[allow(dead_code)]
    pub(crate) async fn connect_h3_candidate_with_timeout(
        &self,
        dns_resolver: &SharedDnsResolver,
        candidate: &crate::proxy::upstream_h3::UpstreamHttp3Candidate,
    ) -> Result<ExperimentalQuicConnected, UpstreamBackendError> {
        self.connect_h3_candidate_with_timeout_for_request(dns_resolver, candidate, None)
            .await
    }

    pub(crate) async fn connect_h3_candidate_with_timeout_for_relay_request(
        &self,
        dns_resolver: &SharedDnsResolver,
        candidate: &crate::proxy::upstream_h3::UpstreamHttp3Candidate,
        request: &RelayUpstreamRequest,
    ) -> Result<ExperimentalQuicConnected, UpstreamBackendError> {
        self.connect_h3_candidate_with_timeout_for_request(dns_resolver, candidate, Some(request))
            .await
    }

    async fn connect_h3_candidate_with_timeout_for_request(
        &self,
        dns_resolver: &SharedDnsResolver,
        candidate: &crate::proxy::upstream_h3::UpstreamHttp3Candidate,
        request: Option<&RelayUpstreamRequest>,
    ) -> Result<ExperimentalQuicConnected, UpstreamBackendError> {
        let server_name = candidate_server_name(candidate)?;
        let addrs = self
            .resolve_h3_candidate_addrs(dns_resolver, candidate)
            .await?;
        let signed_ip_family = request.and_then(|request| signed_ip_family_from_url(&request.url));
        let remote_addr = select_h3_remote_addr_for_signed_ip_family(&addrs, signed_ip_family);
        let client_endpoint = self.build_http3_client_endpoint_for_remote_addr(remote_addr)?;
        let timeout_duration = self.connect_timeout();

        debug!(
            server_name = %server_name,
            %remote_addr,
            remote_addr_family = remote_addr_family_label(remote_addr),
            signed_ip_family = signed_ip_family_label(signed_ip_family),
            signed_ip_matches_remote_family = signed_ip_matches_remote_family_label(signed_ip_family, remote_addr),
            resolved_addr_count = addrs.len(),
            resolved_addr_families = %resolved_addr_families_label(&addrs),
            local_bind_addr = %client_endpoint.local_addr(),
            candidate_authority = %candidate.authority,
            "selected upstream HTTP/3 remote address"
        );

        let connecting = client_endpoint
            .endpoint()
            .connect(remote_addr, &server_name)
            .map_err(|error| {
                UpstreamBackendError::new(
                    UpstreamBackendErrorKind::QuicHandshakeError,
                    format!(
                        "failed to start QUIC connect to {server_name} at {remote_addr}: {error}"
                    ),
                )
            })?;

        let connection = timeout(timeout_duration, connecting)
            .await
            .map_err(|_| {
                UpstreamBackendError::new(
                    UpstreamBackendErrorKind::QuicConnectTimeout,
                    format!(
                        "timed out after {}ms connecting QUIC to {server_name} at {remote_addr}",
                        timeout_duration.as_millis()
                    ),
                )
            })?
            .map_err(|error| {
                UpstreamBackendError::new(
                    UpstreamBackendErrorKind::QuicHandshakeError,
                    format!("QUIC handshake failed for {server_name} at {remote_addr}: {error}"),
                )
            })?;

        Ok(ExperimentalQuicConnected {
            connection,
            remote_addr,
            server_name,
        })
    }

    /// Builds the HTTP/3 TLS/QUIC client config used by future upstream H3
    /// requests.
    ///
    /// Upstream H3 is a client-side connection from RelayGate to the real
    /// target server, so it uses public WebPKI/Mozilla roots for server
    /// certificate verification. This is separate from RelayGate's MITM CA,
    /// which is used only for the downstream browser-facing certificate chain.
    #[allow(dead_code)]
    pub(crate) fn build_http3_client_config(
        &self,
    ) -> Result<quinn::ClientConfig, UpstreamBackendError> {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![H3_ALPN.to_vec(), H3_29_ALPN.to_vec()];

        let quic_tls = QuicClientConfig::try_from(tls_config).map_err(|error| {
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::TlsError,
                format!("failed to build QUIC-compatible rustls client config: {error}"),
            )
        })?;

        Ok(quinn::ClientConfig::new(Arc::new(quic_tls)))
    }

    /// Creates a Quinn client endpoint and installs the HTTP/3 client config.
    ///
    /// This only prepares the local UDP endpoint. It does not resolve DNS, does
    /// not call `connect`, and does not emit HTTP/3 traffic.
    #[allow(dead_code)]
    pub(crate) fn build_http3_client_endpoint(
        &self,
    ) -> Result<ExperimentalQuicClientEndpoint, UpstreamBackendError> {
        self.build_http3_client_endpoint_for_bind_addr(default_quic_client_bind_addr())
    }

    fn build_http3_client_endpoint_for_remote_addr(
        &self,
        remote_addr: SocketAddr,
    ) -> Result<ExperimentalQuicClientEndpoint, UpstreamBackendError> {
        self.build_http3_client_endpoint_for_bind_addr(
            default_quic_client_bind_addr_for_remote_addr(remote_addr),
        )
    }

    fn build_http3_client_endpoint_for_bind_addr(
        &self,
        bind_addr: SocketAddr,
    ) -> Result<ExperimentalQuicClientEndpoint, UpstreamBackendError> {
        let client_config = self.build_http3_client_config()?;

        let mut endpoint = quinn::Endpoint::client(bind_addr).map_err(|error| {
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::UdpError,
                format!("failed to create Quinn client endpoint on {bind_addr}: {error}"),
            )
        })?;

        endpoint.set_default_client_config(client_config);
        let local_addr = endpoint.local_addr().unwrap_or(bind_addr);

        Ok(ExperimentalQuicClientEndpoint {
            endpoint,
            local_addr,
        })
    }
}

fn default_quic_client_bind_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
}

fn default_quic_client_bind_addr_for_remote_addr(remote_addr: SocketAddr) -> SocketAddr {
    if remote_addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    } else {
        default_quic_client_bind_addr()
    }
}

fn candidate_server_name(
    candidate: &crate::proxy::upstream_h3::UpstreamHttp3Candidate,
) -> Result<String, UpstreamBackendError> {
    let authority = candidate.authority.trim();
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default().trim()
    } else {
        authority.split(':').next().unwrap_or_default().trim()
    };

    if host.is_empty() {
        return Err(UpstreamBackendError::new(
            UpstreamBackendErrorKind::DnsError,
            format!(
                "cannot derive upstream H3 server name from authority `{}`",
                candidate.authority
            ),
        ));
    }

    Ok(host.trim_end_matches('.').to_ascii_lowercase())
}

fn candidate_port(candidate: &crate::proxy::upstream_h3::UpstreamHttp3Candidate) -> u16 {
    candidate
        .advertised_port
        .or_else(|| authority_port(&candidate.authority))
        .unwrap_or(DEFAULT_H3_PORT)
}

fn authority_port(authority: &str) -> Option<u16> {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        let after_bracket = rest.split_once(']')?.1;
        return after_bracket.strip_prefix(':')?.parse().ok();
    }

    let mut parts = authority.rsplitn(2, ':');
    let port = parts.next()?;
    let host = parts.next()?;
    if host.is_empty() || port.is_empty() || host.contains(':') {
        return None;
    }
    port.parse().ok()
}

pub(crate) fn experimental_quic_client_config_summary() -> &'static str {
    "Quinn endpoint builder available; TLS ALPN h3/h3-29 configured; WebPKI/Mozilla trust roots wired for upstream server verification"
}

pub(crate) fn experimental_quic_connect_summary() -> String {
    format!(
        "RelayGate DNS resolver available; QUIC timeout {}ms; H3 response-head timeout {}ms; small-body probe timeout {}ms; small-body buffer limit {} KiB; probe cooldown {}s per authority; unsafe/failed paths fall back to reqwest auto",
        DEFAULT_H3_CONNECT_TIMEOUT.as_millis(),
        DEFAULT_H3_RESPONSE_HEADERS_TIMEOUT.as_millis(),
        DEFAULT_H3_RESPONSE_BODY_PROBE_TIMEOUT.as_millis(),
        DEFAULT_H3_SMALL_BODY_BUFFER_LIMIT_BYTES / 1024,
        h3_handshake_probe_cooldown_seconds()
    )
}

pub(crate) fn experimental_h3_streaming_split_summary() -> &'static str {
    "Body handling is split: small complete bodies may use the buffered path. H2 streaming is currently guard-only after a rollback from active byte-pump because mid-stream upstream H3 closes can surface to browsers as HTTP/2 protocol errors. H3 stream cancellation uses drop-close cleanup instead of h3-quinn stop_sending() to avoid a known h3-quinn 0.0.10 cancellation panic."
}

fn opportunistic_direct_h3_candidate_for_request(
    request: &RelayUpstreamRequest,
) -> Option<crate::proxy::upstream_h3::UpstreamHttp3Candidate> {
    if active_candidate_for_authority(&request.authority).is_some() {
        return None;
    }
    if !request.is_get_or_head() || !request.body.is_empty() {
        return None;
    }
    if !request_url_is_media_like(request.url.as_str()) {
        return None;
    }

    Some(crate::proxy::upstream_h3::UpstreamHttp3Candidate {
        authority: request.authority.clone(),
        protocol: "h3".to_string(),
        advertised_port: Some(DEFAULT_H3_PORT),
        ma_seconds: Some(0),
        expires_at_unix: None,
        alt_svc: "opportunistic-direct-h3".to_string(),
        observed_at: unix_seconds_now_string(),
    })
}

fn request_url_is_media_like(url: &str) -> bool {
    let path_query = request_path_query(url).to_ascii_lowercase();
    let path = path_query.split('?').next().unwrap_or(path_query.as_str());

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
        || path_query.contains("mime=video%2f")
        || path_query.contains("mime=audio%2f")
        || path_query.contains("mime=video/")
        || path_query.contains("mime=audio/")
}

fn request_path_query(url: &str) -> &str {
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

fn unix_seconds_now_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExperimentalH3BodyHandling {
    ProbeSmallBody,
    PreserveStreamingBody,
}

/// Private owned streaming response skeleton for future active H3 streaming.
///
/// The real `h3::client::RequestStream` is deliberately kept inside this
/// backend module. Shared RelayGate code receives only
/// `RelayUpstreamOwnedStreamingResponseHandoff`, which contains safe metadata
/// and never exposes Quinn/h3 concrete types.
#[allow(dead_code)]
struct ExperimentalH3OwnedStreamingResponse<S, B>
where
    S: h3::quic::RecvStream,
    B: Buf,
{
    handoff: RelayUpstreamOwnedStreamingResponseHandoff,
    request_stream: h3::client::RequestStream<S, B>,
    server_name: String,
    remote_addr: SocketAddr,
}

#[allow(dead_code)]
impl<S, B> ExperimentalH3OwnedStreamingResponse<S, B>
where
    S: h3::quic::RecvStream,
    B: Buf,
{
    fn new(
        head: RelayUpstreamResponseHead,
        request_stream: h3::client::RequestStream<S, B>,
        server_name: impl Into<String>,
        remote_addr: SocketAddr,
    ) -> Self {
        let server_name = server_name.into();
        let handoff = RelayUpstreamOwnedStreamingResponseHandoff::new(
            head,
            true,
            format!("h3://{server_name} at {remote_addr}"),
        );

        Self {
            handoff,
            request_stream,
            server_name,
            remote_addr,
        }
    }

    fn handoff(&self) -> &RelayUpstreamOwnedStreamingResponseHandoff {
        &self.handoff
    }

    fn cancel(self) {
        // Do not call h3-quinn RequestStream::stop_sending() here.
        // h3-quinn 0.0.10 can panic if stop_sending is invoked while an
        // ordered read future temporarily owns the underlying RecvStream.
        // This experimental backend uses one QUIC/H3 connection per upstream
        // request, so dropping the owned stream is the safer cancellation
        // boundary for now.
    }
}

struct ExperimentalH3StreamingBody<S, B>
where
    S: h3::quic::RecvStream,
    B: Buf,
{
    request_stream: h3::client::RequestStream<S, B>,
    server_name: String,
    remote_addr: SocketAddr,
    request_fingerprint: H3RequestFingerprint,
    response_status: u16,
    body_bytes_read: usize,
    body_chunks_read: usize,
    terminal_logged: bool,
    connection_task: Option<JoinHandle<()>>,
    send_request_keepalive_task: Option<JoinHandle<()>>,
    stopped: bool,
}

impl<S, B> ExperimentalH3StreamingBody<S, B>
where
    S: h3::quic::RecvStream,
    B: Buf,
{
    fn new(
        request_stream: h3::client::RequestStream<S, B>,
        server_name: impl Into<String>,
        remote_addr: SocketAddr,
        request_fingerprint: H3RequestFingerprint,
        response_status: u16,
        connection_task: JoinHandle<()>,
        send_request_keepalive_task: JoinHandle<()>,
    ) -> Self {
        Self {
            request_stream,
            server_name: server_name.into(),
            remote_addr,
            request_fingerprint,
            response_status,
            body_bytes_read: 0,
            body_chunks_read: 0,
            terminal_logged: false,
            connection_task: Some(connection_task),
            send_request_keepalive_task: Some(send_request_keepalive_task),
            stopped: false,
        }
    }

    fn log_terminal_outcome(&mut self, outcome: &'static str, reason_detail: Option<&str>) {
        if self.terminal_logged {
            return;
        }
        self.terminal_logged = true;
        debug!(
            outcome,
            status = self.response_status,
            server_name = %self.server_name,
            %self.remote_addr,
            method = %self.request_fingerprint.method,
            authority = %self.request_fingerprint.authority,
            uri_scheme = %self.request_fingerprint.uri_scheme,
            path = %self.request_fingerprint.path,
            path_query_hash = %self.request_fingerprint.path_query_hash,
            path_query_len = self.request_fingerprint.path_query_len,
            body_bytes_read = self.body_bytes_read,
            body_chunks_read = self.body_chunks_read,
            stopped = self.stopped,
            reason = reason_detail.unwrap_or("<none>"),
            "upstream HTTP/3 streaming body terminal outcome"
        );
    }

    fn abort_background_tasks(&mut self) {
        if let Some(task) = self.send_request_keepalive_task.take() {
            task.abort();
        }
        if let Some(task) = self.connection_task.take() {
            task.abort();
        }
    }
}

impl<S, B> RelayUpstreamStreamingBody for ExperimentalH3StreamingBody<S, B>
where
    S: h3::quic::RecvStream + Send + 'static,
    B: Buf + Send + 'static,
{
    fn next_chunk<'a>(
        &'a mut self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<Bytes>, RelayUpstreamStreamingReadError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let maybe_chunk = self.request_stream.recv_data().await.map_err(|error| {
                let detail = format!(
                    "failed to read HTTP/3 streaming body from {} at {}: {error}",
                    self.server_name, self.remote_addr
                );
                let benign = is_h3_benign_client_close_error(&error.to_string());
                if benign {
                    debug!(
                        status = self.response_status,
                        server_name = %self.server_name,
                        %self.remote_addr,
                        method = %self.request_fingerprint.method,
                        authority = %self.request_fingerprint.authority,
                        path = %self.request_fingerprint.path,
                        path_query_hash = %self.request_fingerprint.path_query_hash,
                        body_bytes_read = self.body_bytes_read,
                        body_chunks_read = self.body_chunks_read,
                        error = %detail,
                        "upstream HTTP/3 streaming body ended with benign read boundary"
                    );
                    self.log_terminal_outcome("benign_read_boundary", Some(&detail));
                    RelayUpstreamStreamingReadError::benign_end(detail)
                } else {
                    warn!(
                        status = self.response_status,
                        server_name = %self.server_name,
                        %self.remote_addr,
                        method = %self.request_fingerprint.method,
                        authority = %self.request_fingerprint.authority,
                        path = %self.request_fingerprint.path,
                        path_query_hash = %self.request_fingerprint.path_query_hash,
                        body_bytes_read = self.body_bytes_read,
                        body_chunks_read = self.body_chunks_read,
                        error = %detail,
                        "upstream HTTP/3 streaming body read error"
                    );
                    self.log_terminal_outcome("read_error", Some(&detail));
                    RelayUpstreamStreamingReadError::new(detail)
                }
            })?;
            let Some(mut chunk) = maybe_chunk else {
                self.log_terminal_outcome("end_of_stream", None);
                return Ok(None);
            };

            let len = chunk.remaining();
            if len == 0 {
                return Ok(Some(Bytes::new()));
            }

            let mut bytes = vec![0_u8; len];
            chunk.copy_to_slice(&mut bytes);
            self.body_bytes_read = self.body_bytes_read.saturating_add(len);
            self.body_chunks_read = self.body_chunks_read.saturating_add(1);
            Ok(Some(Bytes::from(bytes)))
        })
    }

    fn stop(&mut self) {
        if !self.stopped {
            // Intentionally avoid RequestStream::stop_sending() for now.
            // With h3-quinn 0.0.10, browser refresh/downstream cancel can drop
            // this body while recv_data() is in-flight; stop_sending() then
            // reaches an internal Option::unwrap() on a temporarily-taken
            // RecvStream. Mark the body stopped and let dropping the per-request
            // H3 stream/connection perform cleanup.
            self.stopped = true;
            self.log_terminal_outcome("stopped_by_downstream", None);
            self.abort_background_tasks();
        }
    }
}

impl<S, B> Drop for ExperimentalH3StreamingBody<S, B>
where
    S: h3::quic::RecvStream,
    B: Buf,
{
    fn drop(&mut self) {
        // Drop must be cancellation-safe. Do not call h3-quinn stop_sending()
        // from Drop; a downstream refresh can cancel the task while recv_data()
        // is pending, and h3-quinn 0.0.10 may panic in that state.
        self.stopped = true;
        self.log_terminal_outcome("dropped_before_terminal", None);
        self.abort_background_tasks();
    }
}

fn is_h3_benign_client_close_error(error: &str) -> bool {
    error.contains("H3_NO_ERROR") && error.contains("Connection closed by client")
}

#[derive(Debug, Clone)]
struct H3RequestFingerprint {
    method: String,
    authority: String,
    uri_scheme: String,
    path: String,
    path_query_hash: String,
    path_query_len: usize,
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
    signed_ip_family: String,
}

impl H3RequestFingerprint {
    fn from_relay_request(request: &RelayUpstreamRequest) -> Self {
        let uri = request.url.parse::<http::Uri>().ok();
        let uri_scheme = uri
            .as_ref()
            .and_then(|uri| uri.scheme_str())
            .unwrap_or("unknown")
            .to_string();
        let path_query = uri
            .as_ref()
            .and_then(|uri| uri.path_and_query().map(|value| value.as_str()))
            .unwrap_or_else(|| request.url.as_str());
        let path = uri
            .as_ref()
            .map(|uri| uri.path().to_string())
            .unwrap_or_else(|| {
                request
                    .url
                    .split_once('?')
                    .map(|(path, _)| path.to_string())
                    .unwrap_or_else(|| request.url.clone())
            });

        let mut header_names = request
            .headers
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .collect::<Vec<_>>();
        header_names.sort();

        let header_names_without_accept_encoding = header_names
            .iter()
            .filter(|name| name.as_str() != "accept-encoding")
            .cloned()
            .collect::<Vec<_>>();
        let semantic_header_names = header_names
            .iter()
            .filter(|name| !is_h1_transport_header_name(name))
            .cloned()
            .collect::<Vec<_>>();

        let has_named = |needle: &str| header_names.iter().any(|name| name == needle);
        let has_sec_fetch = header_names
            .iter()
            .any(|name| name.starts_with("sec-fetch-"));
        let accept_encoding = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
            .map(|(_, value)| value.clone());

        Self {
            method: request.method.clone(),
            authority: request.authority.clone(),
            uri_scheme,
            path,
            path_query_hash: stable_short_hash(path_query),
            path_query_len: path_query.len(),
            header_count: request.headers.len(),
            header_names_hash: stable_short_hash(&header_names.join(",")),
            header_names: header_names.join(","),
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
            signed_ip_family: signed_ip_family_label(signed_ip_family_from_url(&request.url))
                .to_string(),
        }
    }

    fn log_attempt(&self, path: &'static str) {
        debug!(
            path,
            method = %self.method,
            authority = %self.authority,
            uri_scheme = %self.uri_scheme,
            path = %self.path,
            path_query_hash = %self.path_query_hash,
            path_query_len = self.path_query_len,
            header_count = self.header_count,
            header_names_hash = %self.header_names_hash,
            header_names = %self.header_names,
            header_names_without_accept_encoding_hash = %self.header_names_without_accept_encoding_hash,
            semantic_header_names_hash = %self.semantic_header_names_hash,
            semantic_header_names = %self.semantic_header_names,
            has_host = self.has_host,
            has_range = self.has_range,
            has_cookie = self.has_cookie,
            has_referer = self.has_referer,
            has_origin = self.has_origin,
            has_user_agent = self.has_user_agent,
            has_sec_fetch = self.has_sec_fetch,
            accept_encoding = self.accept_encoding.as_deref().unwrap_or("<none>"),
            signed_ip_family = %self.signed_ip_family,
            "upstream HTTP/3 request fingerprint"
        );
    }

    fn warn_rejected(
        &self,
        path: &'static str,
        status: u16,
        server_name: &str,
        remote_addr: SocketAddr,
    ) {
        if is_expected_h3_rejection_noise(status, &self.path)
            || is_signed_media_h3_diagnostic_noise(
                status,
                &self.path,
                signed_ip_family_from_label(&self.signed_ip_family),
                remote_addr,
            )
        {
            debug!(
                path,
                status,
                server_name,
                %remote_addr,
                method = %self.method,
                authority = %self.authority,
                uri_scheme = %self.uri_scheme,
                path = %self.path,
                path_query_hash = %self.path_query_hash,
                path_query_len = self.path_query_len,
                header_count = self.header_count,
                header_names_hash = %self.header_names_hash,
                header_names_without_accept_encoding_hash = %self.header_names_without_accept_encoding_hash,
                semantic_header_names_hash = %self.semantic_header_names_hash,
                has_host = self.has_host,
                has_range = self.has_range,
                has_cookie = self.has_cookie,
                has_referer = self.has_referer,
                has_origin = self.has_origin,
                has_user_agent = self.has_user_agent,
                has_sec_fetch = self.has_sec_fetch,
                accept_encoding = self.accept_encoding.as_deref().unwrap_or("<none>"),
                signed_ip_family = %self.signed_ip_family,
                remote_addr_family = remote_addr_family_label(remote_addr),
                signed_ip_matches_remote_family = signed_ip_matches_remote_family_label(signed_ip_family_from_label(&self.signed_ip_family), remote_addr),
                "upstream HTTP/3 request returned non-actionable diagnostic status"
            );
            return;
        }

        warn!(
            path,
            status,
            server_name,
            %remote_addr,
            method = %self.method,
            authority = %self.authority,
            uri_scheme = %self.uri_scheme,
            path = %self.path,
            path_query_hash = %self.path_query_hash,
            path_query_len = self.path_query_len,
            header_count = self.header_count,
            header_names_hash = %self.header_names_hash,
            header_names = %self.header_names,
            header_names_without_accept_encoding_hash = %self.header_names_without_accept_encoding_hash,
            semantic_header_names_hash = %self.semantic_header_names_hash,
            semantic_header_names = %self.semantic_header_names,
            has_host = self.has_host,
            has_range = self.has_range,
            has_cookie = self.has_cookie,
            has_referer = self.has_referer,
            has_origin = self.has_origin,
            has_user_agent = self.has_user_agent,
            has_sec_fetch = self.has_sec_fetch,
            accept_encoding = self.accept_encoding.as_deref().unwrap_or("<none>"),
            signed_ip_family = %self.signed_ip_family,
            remote_addr_family = remote_addr_family_label(remote_addr),
            signed_ip_matches_remote_family = signed_ip_matches_remote_family_label(signed_ip_family_from_label(&self.signed_ip_family), remote_addr),
            "upstream HTTP/3 request returned rejection-like status; compare this fingerprint with the stable reqwest path"
        );
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

fn is_expected_h3_rejection_noise(status: u16, path: &str) -> bool {
    match status {
        // 400 is already handled by the higher-level precommit fallback gate
        // before a response is committed downstream. Keep the backend fingerprint
        // log below warn level so normal fallback diagnostics do not look like
        // proxy health issues.
        400 => true,
        // 404 is a normal origin/application response, especially for browser
        // probes, HEAD checks, stale links, and source-map lookups. Treat it as
        // non-actionable H3 diagnostic noise by default; if a future bug needs
        // to compare H3-vs-stable 404 behavior, raise the narrower diagnostic
        // site instead of making all origin 404s warn-level again.
        404 => true,
        _ => path.ends_with(".map") || path.ends_with(".sourcemap") || path == "/feeds/videos.xml",
    }
}

fn is_signed_media_h3_diagnostic_noise(
    status: u16,
    path: &str,
    signed_ip_family: Option<IpFamilyHint>,
    remote_addr: SocketAddr,
) -> bool {
    status == 403
        && path == "/videoplayback"
        && signed_ip_matches_remote_family(signed_ip_family, remote_addr)
}

fn signed_ip_family_from_url(url: &str) -> Option<IpFamilyHint> {
    signed_ip_value_from_path_query(request_path_query(url))
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .map(|addr| match addr {
            IpAddr::V4(_) => IpFamilyHint::Ipv4,
            IpAddr::V6(_) => IpFamilyHint::Ipv6,
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

fn select_h3_remote_addr_for_signed_ip_family(
    addrs: &[SocketAddr],
    signed_ip_family: Option<IpFamilyHint>,
) -> SocketAddr {
    if let Some(family) = signed_ip_family {
        if let Some(addr) = addrs
            .iter()
            .copied()
            .find(|addr| socket_addr_matches_family(*addr, family))
        {
            return addr;
        }
    }

    addrs[0]
}

fn socket_addr_matches_family(addr: SocketAddr, family: IpFamilyHint) -> bool {
    matches!(
        (addr.ip(), family),
        (IpAddr::V4(_), IpFamilyHint::Ipv4) | (IpAddr::V6(_), IpFamilyHint::Ipv6)
    )
}

fn remote_addr_family_label(addr: SocketAddr) -> &'static str {
    match addr.ip() {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

fn resolved_addr_families_label(addrs: &[SocketAddr]) -> String {
    let has_ipv4 = addrs.iter().any(|addr| addr.is_ipv4());
    let has_ipv6 = addrs.iter().any(|addr| addr.is_ipv6());
    match (has_ipv4, has_ipv6) {
        (true, true) => "ipv4,ipv6".to_string(),
        (true, false) => "ipv4".to_string(),
        (false, true) => "ipv6".to_string(),
        (false, false) => "none".to_string(),
    }
}

fn signed_ip_family_label(family: Option<IpFamilyHint>) -> &'static str {
    family.map(IpFamilyHint::as_str).unwrap_or("none")
}

fn signed_ip_family_from_label(label: &str) -> Option<IpFamilyHint> {
    match label {
        "ipv4" => Some(IpFamilyHint::Ipv4),
        "ipv6" => Some(IpFamilyHint::Ipv6),
        _ => None,
    }
}

fn signed_ip_matches_remote_family(
    signed_ip_family: Option<IpFamilyHint>,
    remote_addr: SocketAddr,
) -> bool {
    matches!(signed_ip_family, Some(family) if socket_addr_matches_family(remote_addr, family))
}

fn signed_ip_matches_remote_family_label(
    signed_ip_family: Option<IpFamilyHint>,
    remote_addr: SocketAddr,
) -> &'static str {
    match signed_ip_family {
        Some(family) if socket_addr_matches_family(remote_addr, family) => "true",
        Some(_) => "false",
        None => "unknown",
    }
}

fn stable_short_hash(value: &str) -> String {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[allow(dead_code)]
async fn execute_empty_http3_request_preserving_streaming_body(
    connected: ExperimentalQuicConnected,
    request: &RelayUpstreamRequest,
) -> Result<RelayUpstreamResponseModel, UpstreamBackendError> {
    execute_empty_http3_request_with_body_handling(
        connected,
        request,
        ExperimentalH3BodyHandling::PreserveStreamingBody,
    )
    .await
}

async fn execute_empty_http3_request_streaming_response(
    connected: ExperimentalQuicConnected,
    request: &RelayUpstreamRequest,
) -> Result<RelayUpstreamStreamingResponse, UpstreamBackendError> {
    let server_name = connected.server_name().to_string();
    let remote_addr = connected.remote_addr();
    let quic_connection = h3_quinn::Connection::new(connected.connection().clone());
    let request_fingerprint = H3RequestFingerprint::from_relay_request(request);
    let request_fingerprint_for_request = request_fingerprint.clone();
    let (mut h3_connection, mut send_request) = h3::client::new(quic_connection)
        .await
        .map_err(|error| {
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::H3Error,
                format!(
                    "failed to initialize HTTP/3 streaming client connection for {server_name} at {remote_addr}: {error}"
                ),
            )
        })?;

    let connection_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_connection.poll_close(cx)).await;
    });

    let (request_stream, response) = timeout(DEFAULT_H3_RESPONSE_HEADERS_TIMEOUT, async {
        let h3_request = build_h3_empty_request(request)?;
        request_fingerprint_for_request.log_attempt("streaming_response");
        let mut request_stream = send_request
            .send_request(h3_request)
            .await
            .map_err(|error| {
                UpstreamBackendError::new(
                    UpstreamBackendErrorKind::H3Error,
                    format!(
                        "failed to send HTTP/3 streaming request headers for {server_name} at {remote_addr}: {error}"
                    ),
                )
            })?;

        request_stream.finish().await.map_err(|error| {
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::H3Error,
                format!(
                    "failed to finish empty HTTP/3 streaming request body for {server_name} at {remote_addr}: {error}"
                ),
            )
        })?;

        let response = request_stream.recv_response().await.map_err(|error| {
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::H3Error,
                format!(
                    "failed to receive HTTP/3 streaming response headers for {server_name} at {remote_addr}: {error}"
                ),
            )
        })?;

        let status_code = response.status().as_u16();
        if status_code >= 400 {
            request_fingerprint_for_request.warn_rejected(
                "streaming_response",
                status_code,
                &server_name,
                remote_addr,
            );
        }

        Ok::<_, UpstreamBackendError>((request_stream, response))
    })
    .await
    .map_err(|_| {
        UpstreamBackendError::new(
            UpstreamBackendErrorKind::H3Error,
            format!(
                "timed out after {}ms waiting for HTTP/3 streaming response headers from {server_name} at {remote_addr}",
                DEFAULT_H3_RESPONSE_HEADERS_TIMEOUT.as_millis()
            ),
        )
    })??;

    let response_model = relay_response_model_from_h3_response(&response, request.is_head());
    let response_status = response_model.head.status_code;
    debug!(
        status = response_status,
        server_name = %server_name,
        %remote_addr,
        method = %request_fingerprint.method,
        authority = %request_fingerprint.authority,
        path = %request_fingerprint.path,
        path_query_hash = %request_fingerprint.path_query_hash,
        path_query_len = request_fingerprint.path_query_len,
        header_count = response_model.head.headers.len(),
        signed_ip_family = %request_fingerprint.signed_ip_family,
        remote_addr_family = remote_addr_family_label(remote_addr),
        signed_ip_matches_remote_family = signed_ip_matches_remote_family_label(signed_ip_family_from_label(&request_fingerprint.signed_ip_family), remote_addr),
        "upstream HTTP/3 streaming response headers received"
    );

    let send_request_keepalive_task = tokio::spawn(async move {
        let _keepalive = send_request;
        std::future::pending::<()>().await;
    });

    let body = ExperimentalH3StreamingBody::new(
        request_stream,
        server_name.clone(),
        remote_addr,
        request_fingerprint,
        response_status,
        connection_task,
        send_request_keepalive_task,
    );

    Ok(RelayUpstreamStreamingResponse::new(
        response_model.head,
        Box::new(body),
        format!("h3://{server_name} at {remote_addr}"),
    ))
}

async fn execute_empty_http3_request_with_body_handling(
    connected: ExperimentalQuicConnected,
    request: &RelayUpstreamRequest,
    body_handling: ExperimentalH3BodyHandling,
) -> Result<RelayUpstreamResponseModel, UpstreamBackendError> {
    let server_name = connected.server_name().to_string();
    let remote_addr = connected.remote_addr();
    let quic_connection = h3_quinn::Connection::new(connected.connection().clone());
    let (mut h3_connection, mut send_request) = h3::client::new(quic_connection)
        .await
        .map_err(|error| {
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::H3Error,
                format!(
                    "failed to initialize HTTP/3 client connection for {server_name} at {remote_addr}: {error}"
                ),
            )
        })?;

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_connection.poll_close(cx)).await;
    });

    let (mut request_stream, response) = timeout(DEFAULT_H3_RESPONSE_HEADERS_TIMEOUT, async {
        let h3_request = build_h3_empty_request(request)?;
        let request_fingerprint = H3RequestFingerprint::from_relay_request(request);
        request_fingerprint.log_attempt("buffered_response");
        let mut request_stream = send_request
            .send_request(h3_request)
            .await
            .map_err(|error| {
                UpstreamBackendError::new(
                    UpstreamBackendErrorKind::H3Error,
                    format!(
                        "failed to send HTTP/3 request headers for {server_name} at {remote_addr}: {error}"
                    ),
                )
            })?;

        request_stream.finish().await.map_err(|error| {
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::H3Error,
                format!(
                    "failed to finish empty HTTP/3 request body for {server_name} at {remote_addr}: {error}"
                ),
            )
        })?;

        let response = request_stream.recv_response().await.map_err(|error| {
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::H3Error,
                format!(
                    "failed to receive HTTP/3 response headers for {server_name} at {remote_addr}: {error}"
                ),
            )
        })?;

        let status_code = response.status().as_u16();
        if status_code >= 400 {
            request_fingerprint.warn_rejected(
                "buffered_response",
                status_code,
                &server_name,
                remote_addr,
            );
        }

        Ok::<_, UpstreamBackendError>((request_stream, response))
    })
    .await
    .map_err(|_| {
        UpstreamBackendError::new(
            UpstreamBackendErrorKind::H3Error,
            format!(
                "timed out after {}ms waiting for HTTP/3 response headers from {server_name} at {remote_addr}",
                DEFAULT_H3_RESPONSE_HEADERS_TIMEOUT.as_millis()
            ),
        )
    })??;

    let mut response_model = relay_response_model_from_h3_response(&response, request.is_head());
    if response_model.body_mode == RelayUpstreamResponseBodyMode::Streaming {
        match body_handling {
            ExperimentalH3BodyHandling::ProbeSmallBody => {
                let body_probe = probe_small_http3_response_body_buffer(
                    &mut request_stream,
                    &server_name,
                    remote_addr,
                )
                .await?;
                response_model.body_probe = Some(body_probe.probe);
                if let Some(buffered_body) = body_probe.complete_body {
                    response_model.body_mode = RelayUpstreamResponseBodyMode::Buffered;
                    response_model.buffered_body = Some(buffered_body);
                }
            }
            ExperimentalH3BodyHandling::PreserveStreamingBody => {
                response_model.body_probe = Some(RelayUpstreamResponseBodyProbe::not_attempted(
                    DEFAULT_H3_SMALL_BODY_BUFFER_LIMIT_BYTES,
                ));
                // Preserve mode deliberately does not read from `request_stream`. U8-I now
                // proves ownership by moving the unconsumed stream into a private H3-owned
                // response skeleton. The response model can now describe the downstream
                // writer plan, then cancels because byte pumping is not wired yet.
                // Future active streaming forwarding should keep this owned response
                // alive and pump it to the downstream writer.
                let owned_streaming_response = ExperimentalH3OwnedStreamingResponse::new(
                    response_model.head.clone(),
                    request_stream,
                    server_name.clone(),
                    remote_addr,
                );
                response_model.streaming_handoff = Some(owned_streaming_response.handoff().clone());
                owned_streaming_response.cancel();
            }
        }
    } else {
        response_model.body_probe = Some(RelayUpstreamResponseBodyProbe::not_attempted(
            DEFAULT_H3_SMALL_BODY_BUFFER_LIMIT_BYTES,
        ));
        response_model.buffered_body = Some(Vec::new());
    }

    Ok(response_model)
}

fn build_h3_empty_request(
    request: &RelayUpstreamRequest,
) -> Result<http::Request<()>, UpstreamBackendError> {
    let mut builder = http::Request::builder()
        .method(request.method.as_str())
        .uri(request.url.as_str());

    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }

    builder.body(()).map_err(|error| {
        UpstreamBackendError::new(
            UpstreamBackendErrorKind::H3Error,
            format!(
                "failed to build HTTP/3 request model for {} {}: {error}",
                request.method, request.url
            ),
        )
    })
}

fn relay_response_model_from_h3_response(
    response: &http::Response<()>,
    request_is_head: bool,
) -> RelayUpstreamResponseModel {
    let status_code = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            let value = value
                .to_str()
                .map(str::to_string)
                .unwrap_or_else(|_| String::from_utf8_lossy(value.as_bytes()).into_owned());
            (name.as_str().to_string(), value)
        })
        .collect();

    RelayUpstreamResponseModel {
        head: RelayUpstreamResponseHead {
            status_code,
            headers,
        },
        body_mode: relay_response_body_mode(status_code, request_is_head),
        body_probe: None,
        buffered_body: None,
        streaming_handoff: None,
    }
}

struct ExperimentalH3BodyProbeResult {
    probe: RelayUpstreamResponseBodyProbe,
    complete_body: Option<Vec<u8>>,
}

async fn probe_small_http3_response_body_buffer<S, B>(
    request_stream: &mut h3::client::RequestStream<S, B>,
    server_name: &str,
    remote_addr: SocketAddr,
) -> Result<ExperimentalH3BodyProbeResult, UpstreamBackendError>
where
    S: h3::quic::RecvStream,
    B: Buf,
{
    let mut bytes_read = 0usize;
    let mut chunks_read = 0usize;
    let limit_bytes = DEFAULT_H3_SMALL_BODY_BUFFER_LIMIT_BYTES;
    let mut body = Vec::new();

    match timeout(DEFAULT_H3_RESPONSE_BODY_PROBE_TIMEOUT, async {
        loop {
            let Some(mut chunk) = request_stream.recv_data().await.map_err(|error| {
                UpstreamBackendError::new(
                    UpstreamBackendErrorKind::H3Error,
                    format!(
                        "failed to read HTTP/3 response body probe for {server_name} at {remote_addr}: {error}"
                    ),
                )
            })? else {
                return Ok::<ExperimentalH3BodyProbeResult, UpstreamBackendError>(
                    ExperimentalH3BodyProbeResult {
                        probe: RelayUpstreamResponseBodyProbe::complete(
                            bytes_read,
                            chunks_read,
                            limit_bytes,
                        ),
                        complete_body: Some(body),
                    },
                );
            };

            chunks_read = chunks_read.saturating_add(1);
            let chunk_len = chunk.remaining();
            let remaining_capacity = limit_bytes.saturating_sub(bytes_read);
            if chunk_len > remaining_capacity {
                if remaining_capacity > 0 {
                    let start = body.len();
                    body.resize(start + remaining_capacity, 0);
                    chunk.copy_to_slice(&mut body[start..]);
                }
                bytes_read = limit_bytes;
                // Avoid RequestStream::stop_sending() here. If the probe limit
                // is hit while the receive stream is internally in-flight,
                // h3-quinn 0.0.10 can panic. The per-request H3 connection is
                // dropped after the probe result is returned.
                return Ok(ExperimentalH3BodyProbeResult {
                    probe: RelayUpstreamResponseBodyProbe::truncated(
                        bytes_read,
                        chunks_read,
                        limit_bytes,
                    ),
                    complete_body: None,
                });
            }

            let start = body.len();
            body.resize(start + chunk_len, 0);
            chunk.copy_to_slice(&mut body[start..]);
            bytes_read = bytes_read.saturating_add(chunk_len);
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => {
            // Do not call stop_sending() after timeout. The timed-out recv
            // future may have left h3-quinn's RecvStream temporarily owned by
            // its internal read future; dropping the per-request stream is the
            // safer cleanup boundary.
            Ok(ExperimentalH3BodyProbeResult {
                probe: RelayUpstreamResponseBodyProbe::timed_out(
                    bytes_read,
                    chunks_read,
                    limit_bytes,
                ),
                complete_body: None,
            })
        }
    }
}

fn relay_response_body_mode(
    status_code: u16,
    request_is_head: bool,
) -> RelayUpstreamResponseBodyMode {
    if request_is_head || matches!(status_code, 100..=199 | 204 | 304) {
        RelayUpstreamResponseBodyMode::Empty
    } else {
        RelayUpstreamResponseBodyMode::Streaming
    }
}

/// Experimental upstream HTTP/3 backend seam.
///
/// The backend is now selected as RelayGate's default H3 skeleton, and dry-run
/// probes can read response headers plus a complete small-body buffer for
/// eligible empty-body GET/HEAD responses that fit the limit. The response model
/// can now describe both buffered and future streaming adapter readiness. Active
/// forwarding only uses complete buffered responses. Streaming responses now have
/// an explicit body-handling split: dry-run probes may consume a bounded prefix,
/// while future active streaming must choose preserve-streaming mode before any
/// body bytes are read.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ExperimentalUpstreamHttp3Backend;

impl ExperimentalUpstreamHttp3Backend {
    pub(crate) fn execute_request_streaming_response<'a>(
        &'a self,
        dns_resolver: &'a SharedDnsResolver,
        request: &'a RelayUpstreamRequest,
    ) -> UpstreamHttp3Future<'a, RelayUpstreamStreamingResponse> {
        Box::pin(async move {
            let plan = self.attempt_plan_for_request(request);

            if let Some(reason) = plan.h3_skip_reason.as_ref() {
                record_http3_fallback(&request.authority, plan.h3_candidate.as_ref(), reason);
                return Err(reason.clone());
            }

            let Some(candidate) = plan.h3_candidate.as_ref() else {
                let error = UpstreamBackendError::new(
                    UpstreamBackendErrorKind::NoCandidate,
                    "HTTP/3 streaming attempt selected without an active candidate",
                );
                record_http3_fallback(&request.authority, None, &error);
                return Err(error);
            };

            record_http3_attempt(&request.authority, plan.h3_candidate.as_ref());

            let quic_transport = ExperimentalUpstreamQuicTransport;
            let connected = match quic_transport
                .connect_h3_candidate_with_timeout_for_relay_request(
                    dns_resolver,
                    candidate,
                    request,
                )
                .await
            {
                Ok(connected) => connected,
                Err(error) => {
                    record_http3_fallback(&request.authority, plan.h3_candidate.as_ref(), &error);
                    return Err(error);
                }
            };

            match execute_empty_http3_request_streaming_response(connected, request).await {
                Ok(response) => {
                    crate::proxy::upstream_h3::record_http3_success(
                        &request.authority,
                        plan.h3_candidate.as_ref(),
                    );
                    Ok(response)
                }
                Err(error) => {
                    record_http3_fallback(&request.authority, plan.h3_candidate.as_ref(), &error);
                    Err(error)
                }
            }
        })
    }

    pub(crate) fn execute_request_preserving_streaming_body<'a>(
        &'a self,
        dns_resolver: &'a SharedDnsResolver,
        request: &'a RelayUpstreamRequest,
    ) -> UpstreamHttp3Future<'a, RelayUpstreamResponseModel> {
        self.execute_request_with_body_handling(
            dns_resolver,
            request,
            ExperimentalH3BodyHandling::PreserveStreamingBody,
            true,
        )
    }

    fn execute_request_with_body_handling<'a>(
        &'a self,
        dns_resolver: &'a SharedDnsResolver,
        request: &'a RelayUpstreamRequest,
        body_handling: ExperimentalH3BodyHandling,
        use_probe_cooldown: bool,
    ) -> UpstreamHttp3Future<'a, RelayUpstreamResponseModel> {
        Box::pin(async move {
            let plan = self.attempt_plan_for_request(request);

            if let Some(reason) = plan.h3_skip_reason.as_ref() {
                record_http3_fallback(&request.authority, plan.h3_candidate.as_ref(), reason);
                return Err(reason.clone());
            }

            let Some(candidate) = plan.h3_candidate.as_ref() else {
                let error = UpstreamBackendError::new(
                    UpstreamBackendErrorKind::NoCandidate,
                    "HTTP/3 attempt selected without an active candidate",
                );
                record_http3_fallback(&request.authority, None, &error);
                return Err(error);
            };

            if use_probe_cooldown {
                if let Err(error) = reserve_http3_handshake_probe_slot(&request.authority) {
                    record_http3_fallback(&request.authority, plan.h3_candidate.as_ref(), &error);
                    return Err(error);
                }
            }

            record_http3_attempt(&request.authority, plan.h3_candidate.as_ref());

            let quic_transport = ExperimentalUpstreamQuicTransport;
            let connected = match quic_transport
                .connect_h3_candidate_with_timeout_for_relay_request(
                    dns_resolver,
                    candidate,
                    request,
                )
                .await
            {
                Ok(connected) => connected,
                Err(error) => {
                    record_http3_fallback(&request.authority, plan.h3_candidate.as_ref(), &error);
                    return Err(error);
                }
            };

            match execute_empty_http3_request_with_body_handling(connected, request, body_handling)
                .await
            {
                Ok(response) => {
                    crate::proxy::upstream_h3::record_http3_success(
                        &request.authority,
                        plan.h3_candidate.as_ref(),
                    );
                    Ok(response)
                }
                Err(error) => {
                    record_http3_fallback(&request.authority, plan.h3_candidate.as_ref(), &error);
                    Err(error)
                }
            }
        })
    }
}

impl UpstreamHttp3Backend for ExperimentalUpstreamHttp3Backend {
    fn status(&self) -> UpstreamHttp3BackendStatus {
        UpstreamHttp3BackendStatus::ExperimentalStreamingH2BytePumpGuarded
    }

    fn attempt_plan_for_authority(&self, authority: &str) -> UpstreamAttemptPlan {
        if let Some(candidate) = active_candidate_for_authority(authority) {
            return UpstreamAttemptPlan::try_http3(authority, candidate);
        }

        UpstreamAttemptPlan::skip_http3(
            authority,
            None,
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::NoCandidate,
                "no active HTTP/3 Alt-Svc candidate for authority",
            ),
        )
    }

    fn attempt_plan_for_request(&self, request: &RelayUpstreamRequest) -> UpstreamAttemptPlan {
        let preflight = preflight_request_for_http3(request);
        if preflight.is_try_http3() {
            return preflight.into_attempt_plan();
        }

        if let Some(candidate) = opportunistic_direct_h3_candidate_for_request(request) {
            debug!(
                authority = %request.authority,
                path_query_hash = %stable_short_hash(request_path_query(request.url.as_str())),
                path_query_len = request_path_query(request.url.as_str()).len(),
                signed_ip_family = signed_ip_family_label(signed_ip_family_from_url(&request.url)),
                "upstream HTTP/3 selected opportunistic direct candidate for media-like request without Alt-Svc"
            );
            return UpstreamAttemptPlan::try_http3(&request.authority, candidate);
        }

        preflight.into_attempt_plan()
    }

    fn execute_request<'a>(
        &'a self,
        dns_resolver: &'a SharedDnsResolver,
        request: &'a RelayUpstreamRequest,
    ) -> UpstreamHttp3Future<'a, RelayUpstreamResponseModel> {
        self.execute_request_with_body_handling(
            dns_resolver,
            request,
            ExperimentalH3BodyHandling::ProbeSmallBody,
            true,
        )
    }
}
