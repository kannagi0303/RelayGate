use std::{future::Future, pin::Pin};

use bytes::Bytes;

use crate::proxy::header_hop::should_apply_request_header_rewrite;

/// RelayGate-owned upstream request/response model.
///
/// These types are deliberately independent from `reqwest`, Quinn, h3, and
/// downstream H1/H2 framing. Upstream backends can use this model as the common
/// request intent and then adapt it into their own concrete client types.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamRequest {
    pub(crate) method: String,
    pub(crate) url: String,
    pub(crate) authority: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: RelayUpstreamBody,
}

impl RelayUpstreamRequest {
    /// Builds the first experimental H3-safe request shape.
    ///
    /// U7 intentionally starts with empty-body GET/HEAD only. POST, PUT,
    /// PATCH, and other body-carrying methods should keep using reqwest until
    /// request body replay semantics are explicitly implemented.
    #[allow(dead_code)]
    pub(crate) fn empty_get_head(
        method: impl Into<String>,
        url: impl Into<String>,
        authority: impl Into<String>,
        headers: Vec<(String, String)>,
    ) -> Result<Self, RelayUpstreamRequestBuildError> {
        let method = method.into();
        if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
            return Err(RelayUpstreamRequestBuildError::new(
                RelayUpstreamRequestBuildErrorKind::UnsupportedMethod,
                "experimental upstream HTTP/3 request model only accepts GET/HEAD",
            ));
        }

        Ok(Self {
            method,
            url: url.into(),
            authority: authority.into(),
            headers,
            body: RelayUpstreamBody::Empty,
        })
    }

    /// Builds an upstream request model from the post-core MITM request data.
    ///
    /// This mirrors the current reqwest outbound header boundary for the first
    /// HTTP/3 experiment: only empty-body GET/HEAD requests are eligible,
    /// hop-by-hop/body-owned headers are removed, rewrite header effects are
    /// appended after the base request headers, and RelayGate owns
    /// `Accept-Encoding` so the existing body pipeline still receives identity
    /// bytes.
    #[allow(dead_code)]
    pub(crate) fn empty_get_head_from_mitm_parts(
        method: impl Into<String>,
        url: impl Into<String>,
        authority: impl Into<String>,
        headers: &[(String, String)],
        rewrite_headers: Vec<(String, String)>,
        relaygate_accept_encoding: impl Into<String>,
    ) -> Result<Self, RelayUpstreamRequestBuildError> {
        let method = method.into();
        if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
            return Err(RelayUpstreamRequestBuildError::new(
                RelayUpstreamRequestBuildErrorKind::UnsupportedMethod,
                "experimental upstream HTTP/3 MITM request builder only accepts GET/HEAD",
            ));
        }

        let mut upstream_headers = Vec::new();
        let connection_tokens = relay_connection_header_tokens(headers);
        for (name, value) in headers {
            if should_forward_relay_upstream_request_header(name, &connection_tokens) {
                upstream_headers.push((name.clone(), value.clone()));
            }
        }

        upstream_headers.extend(
            rewrite_headers
                .into_iter()
                .filter(|(name, _)| should_apply_request_header_rewrite(name)),
        );
        upstream_headers.push((
            "accept-encoding".to_string(),
            relaygate_accept_encoding.into(),
        ));

        Ok(Self {
            method,
            url: url.into(),
            authority: authority.into(),
            headers: upstream_headers,
            body: RelayUpstreamBody::Empty,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn is_get_or_head(&self) -> bool {
        self.method.eq_ignore_ascii_case("GET") || self.method.eq_ignore_ascii_case("HEAD")
    }

    #[allow(dead_code)]
    pub(crate) fn is_head(&self) -> bool {
        self.method.eq_ignore_ascii_case("HEAD")
    }

    #[allow(dead_code)]
    pub(crate) fn has_replayable_body(&self) -> bool {
        self.body.is_replayable()
    }
}

fn relay_connection_header_tokens(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

fn should_forward_relay_upstream_request_header(name: &str, connection_tokens: &[String]) -> bool {
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

/// Request body abstraction visible to RelayGate upstream backends.
///
/// `Streaming` is a deliberate marker for "do not try H3 yet" in this stage.
/// It avoids pretending that a downstream body can be replayed after an H3
/// failure. That matters for safe fallback behavior.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelayUpstreamBody {
    Empty,
    ReplayableBytes(Vec<u8>),
    Streaming,
}

impl RelayUpstreamBody {
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    #[allow(dead_code)]
    pub(crate) fn is_replayable(&self) -> bool {
        matches!(self, Self::Empty | Self::ReplayableBytes(_))
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> Option<usize> {
        match self {
            Self::Empty => Some(0),
            Self::ReplayableBytes(bytes) => Some(bytes.len()),
            Self::Streaming => None,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamResponseHead {
    pub(crate) status_code: u16,
    pub(crate) headers: Vec<(String, String)>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayUpstreamResponseBodyMode {
    Empty,
    Streaming,
    Buffered,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayUpstreamResponseBodyProbeState {
    NotAttempted,
    Complete,
    Truncated,
    TimedOut,
}

impl RelayUpstreamResponseBodyProbeState {
    #[allow(dead_code)]
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::Complete => "complete",
            Self::Truncated => "truncated",
            Self::TimedOut => "timed_out",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamResponseBodyProbe {
    pub(crate) state: RelayUpstreamResponseBodyProbeState,
    pub(crate) bytes_read: usize,
    pub(crate) chunks_read: usize,
    pub(crate) limit_bytes: usize,
}

impl RelayUpstreamResponseBodyProbe {
    #[allow(dead_code)]
    pub(crate) fn not_attempted(limit_bytes: usize) -> Self {
        Self {
            state: RelayUpstreamResponseBodyProbeState::NotAttempted,
            bytes_read: 0,
            chunks_read: 0,
            limit_bytes,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn complete(bytes_read: usize, chunks_read: usize, limit_bytes: usize) -> Self {
        Self {
            state: RelayUpstreamResponseBodyProbeState::Complete,
            bytes_read,
            chunks_read,
            limit_bytes,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn truncated(bytes_read: usize, chunks_read: usize, limit_bytes: usize) -> Self {
        Self {
            state: RelayUpstreamResponseBodyProbeState::Truncated,
            bytes_read,
            chunks_read,
            limit_bytes,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn timed_out(bytes_read: usize, chunks_read: usize, limit_bytes: usize) -> Self {
        Self {
            state: RelayUpstreamResponseBodyProbeState::TimedOut,
            bytes_read,
            chunks_read,
            limit_bytes,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamResponseModel {
    pub(crate) head: RelayUpstreamResponseHead,
    pub(crate) body_mode: RelayUpstreamResponseBodyMode,
    pub(crate) body_probe: Option<RelayUpstreamResponseBodyProbe>,
    /// Complete response body bytes captured by a dry-run H3 probe.
    ///
    /// This is intentionally limited to small/complete responses. Truncated or
    /// timed-out body probes keep this as `None` so future forwarding code does
    /// not accidentally treat a partial body as replayable. Diagnostics only
    /// expose the captured length, never the body contents.
    pub(crate) buffered_body: Option<Vec<u8>>,
    /// Metadata proving a future streaming adapter can own an unconsumed body
    /// stream.
    ///
    /// The actual H3/QUIC stream object remains private to the experimental H3
    /// backend. Shared core only sees this RelayGate-owned handoff summary.
    pub(crate) streaming_handoff: Option<RelayUpstreamOwnedStreamingResponseHandoff>,
}

impl RelayUpstreamResponseModel {
    /// Builds a future-forwarding adapter for responses whose body is fully
    /// owned by RelayGate.
    ///
    /// This is still dry-run infrastructure for upstream H3: it does not write
    /// to downstream sockets and it does not invoke rewrite/adblock pipelines.
    /// The point is to make the next forwarding step explicit: only complete
    /// small buffered responses (or no-body responses) can become a replayable
    /// response adapter. Truncated or timed-out probes stay non-forwardable.
    #[allow(dead_code)]
    pub(crate) fn buffered_response_adapter(
        &self,
    ) -> Result<RelayUpstreamBufferedResponse, RelayUpstreamBufferedResponseAdapterError> {
        match self.body_mode {
            RelayUpstreamResponseBodyMode::Empty => Ok(RelayUpstreamBufferedResponse {
                head: self.head.clone(),
                body: Vec::new(),
            }),
            RelayUpstreamResponseBodyMode::Buffered => {
                let Some(probe) = self.body_probe.as_ref() else {
                    return Err(RelayUpstreamBufferedResponseAdapterError::new(
                        RelayUpstreamBufferedResponseAdapterErrorKind::BodyProbeMissing,
                        "buffered H3 response is missing body probe metadata",
                    ));
                };

                if probe.state != RelayUpstreamResponseBodyProbeState::Complete {
                    return Err(RelayUpstreamBufferedResponseAdapterError::new(
                        RelayUpstreamBufferedResponseAdapterErrorKind::BodyProbeIncomplete,
                        format!(
                            "buffered response adapter requires a complete body probe, got {}",
                            probe.state.label()
                        ),
                    ));
                }

                let Some(body) = self.buffered_body.as_ref() else {
                    return Err(RelayUpstreamBufferedResponseAdapterError::new(
                        RelayUpstreamBufferedResponseAdapterErrorKind::BufferedBodyMissing,
                        "buffered H3 response is missing captured body bytes",
                    ));
                };

                if body.len() != probe.bytes_read {
                    return Err(RelayUpstreamBufferedResponseAdapterError::new(
                        RelayUpstreamBufferedResponseAdapterErrorKind::BufferedBodyLengthMismatch,
                        format!(
                            "buffered body length {} does not match probe bytes_read {}",
                            body.len(),
                            probe.bytes_read
                        ),
                    ));
                }

                Ok(RelayUpstreamBufferedResponse {
                    head: self.head.clone(),
                    body: body.clone(),
                })
            }
            RelayUpstreamResponseBodyMode::Streaming => {
                Err(RelayUpstreamBufferedResponseAdapterError::new(
                    RelayUpstreamBufferedResponseAdapterErrorKind::BodyNotBuffered,
                    "streaming H3 response is not eligible for buffered forwarding adapter",
                ))
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn buffered_response_adapter_summary(&self) -> String {
        match self.buffered_response_adapter() {
            Ok(adapter) => format!(
                "ready · status {} · content-length {} · headers {}",
                adapter.status_code(),
                adapter.content_length(),
                adapter.header_count()
            ),
            Err(error) => format!("not_ready {} — {}", error.kind.code(), error.detail),
        }
    }

    /// Describes whether this response could become a streaming forwarding
    /// adapter without losing bytes.
    ///
    /// Current H3 probes intentionally read a small prefix to validate body I/O.
    /// Once any bytes have been consumed by the probe, that stream cannot be
    /// handed to downstream forwarding unless those bytes are replayed first.
    /// This readiness check makes that boundary explicit before active H3
    /// streaming forwarding is wired.
    #[allow(dead_code)]
    pub(crate) fn streaming_response_adapter_readiness(
        &self,
    ) -> RelayUpstreamStreamingResponseAdapterReadiness {
        match self.body_mode {
            RelayUpstreamResponseBodyMode::Empty => {
                RelayUpstreamStreamingResponseAdapterReadiness::new(
                    RelayUpstreamStreamingResponseAdapterReadinessKind::BodyNotStreaming,
                    "empty/no-body H3 response should use the buffered adapter path",
                )
            }
            RelayUpstreamResponseBodyMode::Buffered => {
                RelayUpstreamStreamingResponseAdapterReadiness::new(
                    RelayUpstreamStreamingResponseAdapterReadinessKind::BodyAlreadyBuffered,
                    "complete small H3 response should use the buffered adapter path",
                )
            }
            RelayUpstreamResponseBodyMode::Streaming => {
                let Some(probe) = self.body_probe.as_ref() else {
                    return RelayUpstreamStreamingResponseAdapterReadiness::new(
                        RelayUpstreamStreamingResponseAdapterReadinessKind::BodyProbeMissing,
                        "streaming H3 response has no probe metadata; keep falling back until the streaming adapter owns the unconsumed stream",
                    );
                };

                match probe.state {
                    RelayUpstreamResponseBodyProbeState::NotAttempted if probe.bytes_read == 0 => {
                        RelayUpstreamStreamingResponseAdapterReadiness::new(
                            RelayUpstreamStreamingResponseAdapterReadinessKind::Ready,
                            "streaming H3 response body is unconsumed and can be handed to a future streaming adapter",
                        )
                    }
                    RelayUpstreamResponseBodyProbeState::NotAttempted => {
                        RelayUpstreamStreamingResponseAdapterReadiness::new(
                            RelayUpstreamStreamingResponseAdapterReadinessKind::BodyProbeConsumedPrefix,
                            format!(
                                "streaming H3 response probe unexpectedly consumed {} bytes before adapter handoff",
                                probe.bytes_read
                            ),
                        )
                    }
                    RelayUpstreamResponseBodyProbeState::Complete => {
                        RelayUpstreamStreamingResponseAdapterReadiness::new(
                            RelayUpstreamStreamingResponseAdapterReadinessKind::BodyProbeCompleted,
                            "streaming H3 response body was fully consumed by the probe; use buffered adapter only if complete bytes were captured",
                        )
                    }
                    RelayUpstreamResponseBodyProbeState::Truncated => {
                        RelayUpstreamStreamingResponseAdapterReadiness::new(
                            RelayUpstreamStreamingResponseAdapterReadinessKind::BodyProbeConsumedPrefix,
                            format!(
                                "streaming H3 response probe consumed {} bytes across {} chunks before truncation; active streaming must replay or avoid probing this prefix",
                                probe.bytes_read, probe.chunks_read
                            ),
                        )
                    }
                    RelayUpstreamResponseBodyProbeState::TimedOut => {
                        RelayUpstreamStreamingResponseAdapterReadiness::new(
                            RelayUpstreamStreamingResponseAdapterReadinessKind::BodyProbeTimedOut,
                            format!(
                                "streaming H3 response probe timed out after consuming {} bytes across {} chunks; active streaming must start from an unconsumed stream",
                                probe.bytes_read, probe.chunks_read
                            ),
                        )
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn streaming_response_adapter_summary(&self) -> String {
        let readiness = self.streaming_response_adapter_readiness();
        if readiness.is_ready() {
            format!(
                "ready · status {} · headers {} · unconsumed body stream",
                self.head.status_code,
                self.head.headers.len()
            )
        } else {
            format!("not_ready {} — {}", readiness.kind.code(), readiness.detail)
        }
    }

    #[allow(dead_code)]
    pub(crate) fn owned_streaming_handoff_summary(&self) -> String {
        match self.streaming_handoff.as_ref() {
            Some(handoff) => handoff.summary(),
            None => "not_ready owned_stream_missing — H3 streaming response ownership has not been handed off yet".to_string(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn streaming_downstream_writer_plan_summary(
        &self,
        downstream_protocol: &str,
    ) -> String {
        match self.streaming_handoff.as_ref() {
            Some(handoff) => match handoff.downstream_writer_plan(downstream_protocol) {
                Ok(plan) => plan.summary(),
                Err(error) => format!("not_ready {} — {}", error.kind.code(), error.detail),
            },
            None => "not_ready owned_stream_missing — downstream streaming writer needs an owned, unconsumed H3 body stream".to_string(),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamOwnedStreamingResponseHandoff {
    pub(crate) head: RelayUpstreamResponseHead,
    pub(crate) body_stream_unconsumed: bool,
    pub(crate) source: String,
}

impl RelayUpstreamOwnedStreamingResponseHandoff {
    #[allow(dead_code)]
    pub(crate) fn new(
        head: RelayUpstreamResponseHead,
        body_stream_unconsumed: bool,
        source: impl Into<String>,
    ) -> Self {
        Self {
            head,
            body_stream_unconsumed,
            source: source.into(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_ready(&self) -> bool {
        self.body_stream_unconsumed
    }

    #[allow(dead_code)]
    pub(crate) fn status_code(&self) -> u16 {
        self.head.status_code
    }

    #[allow(dead_code)]
    pub(crate) fn header_count(&self) -> usize {
        self.head.headers.len()
    }

    #[allow(dead_code)]
    pub(crate) fn summary(&self) -> String {
        if self.is_ready() {
            format!(
                "ready · status {} · headers {} · unconsumed body stream owned by {}",
                self.status_code(),
                self.header_count(),
                self.source
            )
        } else {
            format!(
                "not_ready body_stream_consumed — status {} · headers {} · source {}",
                self.status_code(),
                self.header_count(),
                self.source
            )
        }
    }

    #[allow(dead_code)]
    pub(crate) fn downstream_writer_plan(
        &self,
        downstream_protocol: impl Into<String>,
    ) -> Result<
        RelayUpstreamStreamingDownstreamWriterPlan,
        RelayUpstreamStreamingDownstreamWriterPlanError,
    > {
        if !self.is_ready() {
            return Err(RelayUpstreamStreamingDownstreamWriterPlanError::new(
                RelayUpstreamStreamingDownstreamWriterPlanErrorKind::BodyStreamConsumed,
                "owned H3 streaming response body is not available for downstream writer handoff",
            ));
        }

        Ok(RelayUpstreamStreamingDownstreamWriterPlan {
            downstream_protocol: downstream_protocol.into(),
            head: self.head.clone(),
            source: self.source.clone(),
            flush_policy: "flush_response_head_then_each_data_chunk".to_string(),
            cancellation_policy: "cancel_h3_recv_stream_on_downstream_error_or_cancel".to_string(),
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamStreamingDownstreamWriterPlan {
    pub(crate) downstream_protocol: String,
    pub(crate) head: RelayUpstreamResponseHead,
    pub(crate) source: String,
    pub(crate) flush_policy: String,
    pub(crate) cancellation_policy: String,
}

impl RelayUpstreamStreamingDownstreamWriterPlan {
    #[allow(dead_code)]
    pub(crate) fn status_code(&self) -> u16 {
        self.head.status_code
    }

    #[allow(dead_code)]
    pub(crate) fn header_count(&self) -> usize {
        self.head.headers.len()
    }

    #[allow(dead_code)]
    pub(crate) fn summary(&self) -> String {
        format!(
            "ready · downstream {} · status {} · headers {} · source {} · flush {} · cancel {}",
            self.downstream_protocol,
            self.status_code(),
            self.header_count(),
            self.source,
            self.flush_policy,
            self.cancellation_policy
        )
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayUpstreamStreamingDownstreamWriterPlanErrorKind {
    OwnedStreamMissing,
    BodyStreamConsumed,
}

impl RelayUpstreamStreamingDownstreamWriterPlanErrorKind {
    #[allow(dead_code)]
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::OwnedStreamMissing => "owned_stream_missing",
            Self::BodyStreamConsumed => "body_stream_consumed",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamStreamingDownstreamWriterPlanError {
    pub(crate) kind: RelayUpstreamStreamingDownstreamWriterPlanErrorKind,
    pub(crate) detail: String,
}

impl RelayUpstreamStreamingDownstreamWriterPlanError {
    #[allow(dead_code)]
    pub(crate) fn new(
        kind: RelayUpstreamStreamingDownstreamWriterPlanErrorKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamBufferedResponse {
    pub(crate) head: RelayUpstreamResponseHead,
    pub(crate) body: Vec<u8>,
}

impl RelayUpstreamBufferedResponse {
    #[allow(dead_code)]
    pub(crate) fn status_code(&self) -> u16 {
        self.head.status_code
    }

    #[allow(dead_code)]
    pub(crate) fn header_count(&self) -> usize {
        self.head.headers.len()
    }

    #[allow(dead_code)]
    pub(crate) fn content_length(&self) -> usize {
        self.body.len()
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayUpstreamBufferedResponseAdapterErrorKind {
    BodyNotBuffered,
    BodyProbeMissing,
    BodyProbeIncomplete,
    BufferedBodyMissing,
    BufferedBodyLengthMismatch,
}

impl RelayUpstreamBufferedResponseAdapterErrorKind {
    #[allow(dead_code)]
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::BodyNotBuffered => "body_not_buffered",
            Self::BodyProbeMissing => "body_probe_missing",
            Self::BodyProbeIncomplete => "body_probe_incomplete",
            Self::BufferedBodyMissing => "buffered_body_missing",
            Self::BufferedBodyLengthMismatch => "buffered_body_length_mismatch",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamBufferedResponseAdapterError {
    pub(crate) kind: RelayUpstreamBufferedResponseAdapterErrorKind,
    pub(crate) detail: String,
}

impl RelayUpstreamBufferedResponseAdapterError {
    #[allow(dead_code)]
    pub(crate) fn new(
        kind: RelayUpstreamBufferedResponseAdapterErrorKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayUpstreamStreamingResponseAdapterReadinessKind {
    Ready,
    BodyNotStreaming,
    BodyAlreadyBuffered,
    BodyProbeMissing,
    BodyProbeConsumedPrefix,
    BodyProbeCompleted,
    BodyProbeTimedOut,
}

impl RelayUpstreamStreamingResponseAdapterReadinessKind {
    #[allow(dead_code)]
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::BodyNotStreaming => "body_not_streaming",
            Self::BodyAlreadyBuffered => "body_already_buffered",
            Self::BodyProbeMissing => "body_probe_missing",
            Self::BodyProbeConsumedPrefix => "body_probe_consumed_prefix",
            Self::BodyProbeCompleted => "body_probe_completed",
            Self::BodyProbeTimedOut => "body_probe_timed_out",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamStreamingResponseAdapterReadiness {
    pub(crate) kind: RelayUpstreamStreamingResponseAdapterReadinessKind,
    pub(crate) detail: String,
}

impl RelayUpstreamStreamingResponseAdapterReadiness {
    #[allow(dead_code)]
    pub(crate) fn new(
        kind: RelayUpstreamStreamingResponseAdapterReadinessKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_ready(&self) -> bool {
        self.kind == RelayUpstreamStreamingResponseAdapterReadinessKind::Ready
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayUpstreamStreamingReadErrorKind {
    UpstreamRead,
    BenignEnd,
}

impl RelayUpstreamStreamingReadErrorKind {
    #[allow(dead_code)]
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::UpstreamRead => "upstream_read_error",
            Self::BenignEnd => "benign_end",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamStreamingReadError {
    pub(crate) kind: RelayUpstreamStreamingReadErrorKind,
    pub(crate) detail: String,
}

impl RelayUpstreamStreamingReadError {
    #[allow(dead_code)]
    pub(crate) fn new(detail: impl Into<String>) -> Self {
        Self {
            kind: RelayUpstreamStreamingReadErrorKind::UpstreamRead,
            detail: detail.into(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn benign_end(detail: impl Into<String>) -> Self {
        Self {
            kind: RelayUpstreamStreamingReadErrorKind::BenignEnd,
            detail: detail.into(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_benign_end(&self) -> bool {
        self.kind == RelayUpstreamStreamingReadErrorKind::BenignEnd
    }
}

/// Opaque streaming body owned by an upstream backend.
///
/// The concrete H3/QUIC stream stays inside the backend module. Downstream
/// adapters only receive this RelayGate-owned trait object and can pull bytes
/// without seeing Quinn or h3 types.
#[allow(dead_code)]
pub(crate) trait RelayUpstreamStreamingBody: Send {
    fn next_chunk<'a>(
        &'a mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<Bytes>, RelayUpstreamStreamingReadError>> + Send + 'a,
        >,
    >;

    fn stop(&mut self);
}

#[allow(dead_code)]
pub(crate) struct RelayUpstreamStreamingResponse {
    pub(crate) head: RelayUpstreamResponseHead,
    pub(crate) body: Box<dyn RelayUpstreamStreamingBody>,
    pub(crate) source: String,
}

impl RelayUpstreamStreamingResponse {
    #[allow(dead_code)]
    pub(crate) fn new(
        head: RelayUpstreamResponseHead,
        body: Box<dyn RelayUpstreamStreamingBody>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            head,
            body,
            source: source.into(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn status_code(&self) -> u16 {
        self.head.status_code
    }

    #[allow(dead_code)]
    pub(crate) fn header_count(&self) -> usize {
        self.head.headers.len()
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayUpstreamRequestBuildErrorKind {
    UnsupportedMethod,
}

impl RelayUpstreamRequestBuildErrorKind {
    #[allow(dead_code)]
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::UnsupportedMethod => "unsupported_method",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayUpstreamRequestBuildError {
    pub(crate) kind: RelayUpstreamRequestBuildErrorKind,
    pub(crate) detail: String,
}

impl RelayUpstreamRequestBuildError {
    #[allow(dead_code)]
    pub(crate) fn new(kind: RelayUpstreamRequestBuildErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}
