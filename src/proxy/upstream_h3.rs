use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

#[path = "upstream_h3_alt_svc.rs"]
mod upstream_h3_alt_svc;

pub(crate) use upstream_h3_alt_svc::{
    active_candidate_for_authority, observation_snapshot, record_alt_svc, UpstreamHttp3Candidate,
};

use crate::{
    dns::SharedDnsResolver,
    proxy::{
        upstream_h3_backend::{
            ExperimentalUpstreamHttp3Backend, ExperimentalUpstreamQuicTransport,
        },
        upstream_model::{RelayUpstreamRequest, RelayUpstreamResponseModel},
    },
};

const DEFAULT_H3_HANDSHAKE_PROBE_COOLDOWN_SECS: u64 = 30;
const DEFAULT_H3_ACTIVE_BUFFERED_FAILURE_COOLDOWN_SECS: u64 = 60;
const DEFAULT_H3_ACTIVE_STREAMING_FAILURE_COOLDOWN_SECS: u64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamHttp3DiagnosticOutcome {
    Attempt,
    Success,
    Fallback,
}

impl UpstreamHttp3DiagnosticOutcome {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Attempt => "attempt",
            Self::Success => "success",
            Self::Fallback => "fallback",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UpstreamHttp3DiagnosticsEvent {
    pub(crate) authority: String,
    pub(crate) candidate: Option<UpstreamHttp3Candidate>,
    pub(crate) outcome: UpstreamHttp3DiagnosticOutcome,
    pub(crate) error: Option<UpstreamBackendError>,
    pub(crate) observed_at: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UpstreamHttp3DiagnosticsSnapshot {
    pub(crate) attempts: u64,
    pub(crate) successes: u64,
    pub(crate) fallbacks: u64,
    pub(crate) last_event: Option<UpstreamHttp3DiagnosticsEvent>,
    pub(crate) last_network_event: Option<UpstreamHttp3DiagnosticsEvent>,
}

#[derive(Debug, Clone, Default)]
struct UpstreamHttp3DiagnosticsState {
    attempts: u64,
    successes: u64,
    fallbacks: u64,
    last_event: Option<UpstreamHttp3DiagnosticsEvent>,
    last_network_event: Option<UpstreamHttp3DiagnosticsEvent>,
}

fn upstream_http3_diagnostics_state() -> &'static Mutex<UpstreamHttp3DiagnosticsState> {
    static STATE: OnceLock<Mutex<UpstreamHttp3DiagnosticsState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(UpstreamHttp3DiagnosticsState::default()))
}

pub(crate) fn http3_diagnostics_snapshot() -> UpstreamHttp3DiagnosticsSnapshot {
    let Ok(state) = upstream_http3_diagnostics_state().lock() else {
        return UpstreamHttp3DiagnosticsSnapshot::default();
    };

    UpstreamHttp3DiagnosticsSnapshot {
        attempts: state.attempts,
        successes: state.successes,
        fallbacks: state.fallbacks,
        last_event: state.last_event.clone(),
        last_network_event: state.last_network_event.clone(),
    }
}

pub(crate) fn record_http3_attempt(authority: &str, candidate: Option<&UpstreamHttp3Candidate>) {
    let Ok(mut state) = upstream_http3_diagnostics_state().lock() else {
        return;
    };

    state.attempts = state.attempts.saturating_add(1);
    let event = UpstreamHttp3DiagnosticsEvent {
        authority: authority.to_string(),
        candidate: candidate.cloned(),
        outcome: UpstreamHttp3DiagnosticOutcome::Attempt,
        error: None,
        observed_at: unix_seconds_now(),
    };
    state.last_event = Some(event.clone());
    state.last_network_event = Some(event);
}

#[allow(dead_code)]
pub(crate) fn record_http3_success(authority: &str, candidate: Option<&UpstreamHttp3Candidate>) {
    let Ok(mut state) = upstream_http3_diagnostics_state().lock() else {
        return;
    };

    state.successes = state.successes.saturating_add(1);
    let event = UpstreamHttp3DiagnosticsEvent {
        authority: authority.to_string(),
        candidate: candidate.cloned(),
        outcome: UpstreamHttp3DiagnosticOutcome::Success,
        error: None,
        observed_at: unix_seconds_now(),
    };
    state.last_event = Some(event.clone());
    state.last_network_event = Some(event);
}

pub(crate) fn record_http3_fallback(
    authority: &str,
    candidate: Option<&UpstreamHttp3Candidate>,
    error: &UpstreamBackendError,
) {
    let Ok(mut state) = upstream_http3_diagnostics_state().lock() else {
        return;
    };

    state.fallbacks = state.fallbacks.saturating_add(1);
    let event = UpstreamHttp3DiagnosticsEvent {
        authority: authority.to_string(),
        candidate: candidate.cloned(),
        outcome: UpstreamHttp3DiagnosticOutcome::Fallback,
        error: Some(error.clone()),
        observed_at: unix_seconds_now(),
    };
    state.last_event = Some(event.clone());
    if should_record_http3_network_event(error.kind) {
        state.last_network_event = Some(event);
    }
}

fn should_record_http3_network_event(kind: UpstreamBackendErrorKind) -> bool {
    !matches!(
        kind,
        UpstreamBackendErrorKind::BackendNotBuilt
            | UpstreamBackendErrorKind::NoCandidate
            | UpstreamBackendErrorKind::UnsupportedMethod
            | UpstreamBackendErrorKind::RequestBodyNotReplayable
            | UpstreamBackendErrorKind::ProbeCooldown
            | UpstreamBackendErrorKind::AuthorityFailureCooldown
    )
}

#[derive(Debug, Clone)]
pub(crate) struct UpstreamHttp3ProbeDiagnosticsEvent {
    pub(crate) authority: String,
    pub(crate) decision: UpstreamHttp3ExecutionDecision,
    pub(crate) selected_backend: UpstreamAttemptBackend,
    pub(crate) candidate: Option<UpstreamHttp3Candidate>,
    pub(crate) response_summary: Option<String>,
    pub(crate) fallback_error: Option<UpstreamBackendError>,
    pub(crate) fallback_backend: UpstreamH3FallbackBackend,
    pub(crate) observed_at: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UpstreamHttp3ProbeDiagnosticsSnapshot {
    pub(crate) probes: u64,
    pub(crate) http3_responses: u64,
    pub(crate) fallbacks: u64,
    pub(crate) last_event: Option<UpstreamHttp3ProbeDiagnosticsEvent>,
    pub(crate) last_h3_eligible_event: Option<UpstreamHttp3ProbeDiagnosticsEvent>,
    pub(crate) last_http3_response_event: Option<UpstreamHttp3ProbeDiagnosticsEvent>,
}

#[derive(Debug, Clone, Default)]
struct UpstreamHttp3ProbeDiagnosticsState {
    probes: u64,
    http3_responses: u64,
    fallbacks: u64,
    last_event: Option<UpstreamHttp3ProbeDiagnosticsEvent>,
    last_h3_eligible_event: Option<UpstreamHttp3ProbeDiagnosticsEvent>,
    last_http3_response_event: Option<UpstreamHttp3ProbeDiagnosticsEvent>,
}

fn upstream_http3_probe_diagnostics_state() -> &'static Mutex<UpstreamHttp3ProbeDiagnosticsState> {
    static STATE: OnceLock<Mutex<UpstreamHttp3ProbeDiagnosticsState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(UpstreamHttp3ProbeDiagnosticsState::default()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamHttp3ActiveBufferedForwardingOutcome {
    Served,
    Fallback,
}

impl UpstreamHttp3ActiveBufferedForwardingOutcome {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Served => "served_via_h3_buffered",
            Self::Fallback => "fallback_to_reqwest",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UpstreamHttp3ActiveBufferedForwardingEvent {
    pub(crate) downstream_protocol: String,
    pub(crate) authority: String,
    pub(crate) candidate: Option<UpstreamHttp3Candidate>,
    pub(crate) outcome: UpstreamHttp3ActiveBufferedForwardingOutcome,
    pub(crate) status_code: Option<u16>,
    pub(crate) header_count: Option<usize>,
    pub(crate) body_bytes: Option<usize>,
    pub(crate) reason_code: Option<String>,
    pub(crate) reason_detail: Option<String>,
    pub(crate) observed_at: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UpstreamHttp3ActiveBufferedForwardingSnapshot {
    pub(crate) attempts: u64,
    pub(crate) served: u64,
    pub(crate) fallbacks: u64,
    pub(crate) last_event: Option<UpstreamHttp3ActiveBufferedForwardingEvent>,
    pub(crate) last_served_event: Option<UpstreamHttp3ActiveBufferedForwardingEvent>,
}

#[derive(Debug, Clone, Default)]
struct UpstreamHttp3ActiveBufferedForwardingState {
    attempts: u64,
    served: u64,
    fallbacks: u64,
    last_event: Option<UpstreamHttp3ActiveBufferedForwardingEvent>,
    last_served_event: Option<UpstreamHttp3ActiveBufferedForwardingEvent>,
}

fn upstream_http3_active_buffered_forwarding_state(
) -> &'static Mutex<UpstreamHttp3ActiveBufferedForwardingState> {
    static STATE: OnceLock<Mutex<UpstreamHttp3ActiveBufferedForwardingState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(UpstreamHttp3ActiveBufferedForwardingState::default()))
}

pub(crate) fn http3_active_buffered_forwarding_snapshot(
) -> UpstreamHttp3ActiveBufferedForwardingSnapshot {
    let Ok(state) = upstream_http3_active_buffered_forwarding_state().lock() else {
        return UpstreamHttp3ActiveBufferedForwardingSnapshot::default();
    };

    UpstreamHttp3ActiveBufferedForwardingSnapshot {
        attempts: state.attempts,
        served: state.served,
        fallbacks: state.fallbacks,
        last_event: state.last_event.clone(),
        last_served_event: state.last_served_event.clone(),
    }
}

pub(crate) fn record_http3_active_buffered_served(
    downstream_protocol: &str,
    authority: &str,
    candidate: Option<&UpstreamHttp3Candidate>,
    status_code: u16,
    header_count: usize,
    body_bytes: usize,
) {
    let Ok(mut state) = upstream_http3_active_buffered_forwarding_state().lock() else {
        return;
    };

    state.attempts = state.attempts.saturating_add(1);
    state.served = state.served.saturating_add(1);
    let event = UpstreamHttp3ActiveBufferedForwardingEvent {
        downstream_protocol: downstream_protocol.to_string(),
        authority: authority.to_string(),
        candidate: candidate.cloned(),
        outcome: UpstreamHttp3ActiveBufferedForwardingOutcome::Served,
        status_code: Some(status_code),
        header_count: Some(header_count),
        body_bytes: Some(body_bytes),
        reason_code: None,
        reason_detail: None,
        observed_at: unix_seconds_now(),
    };
    state.last_event = Some(event.clone());
    state.last_served_event = Some(event);
    drop(state);
    clear_http3_active_buffered_authority_failure(authority);
}

pub(crate) fn record_http3_active_buffered_fallback(
    downstream_protocol: &str,
    authority: &str,
    candidate: Option<&UpstreamHttp3Candidate>,
    status_code: Option<u16>,
    header_count: Option<usize>,
    body_bytes: Option<usize>,
    reason_code: impl Into<String>,
    reason_detail: impl Into<String>,
) {
    let Ok(mut state) = upstream_http3_active_buffered_forwarding_state().lock() else {
        return;
    };

    state.attempts = state.attempts.saturating_add(1);
    state.fallbacks = state.fallbacks.saturating_add(1);
    state.last_event = Some(UpstreamHttp3ActiveBufferedForwardingEvent {
        downstream_protocol: downstream_protocol.to_string(),
        authority: authority.to_string(),
        candidate: candidate.cloned(),
        outcome: UpstreamHttp3ActiveBufferedForwardingOutcome::Fallback,
        status_code,
        header_count,
        body_bytes,
        reason_code: Some(reason_code.into()),
        reason_detail: Some(reason_detail.into()),
        observed_at: unix_seconds_now(),
    });
}

#[derive(Debug, Clone)]
pub(crate) struct UpstreamHttp3ActiveBufferedFailureCooldownEntry {
    pub(crate) authority: String,
    pub(crate) reason_code: String,
    pub(crate) reason_detail: String,
    pub(crate) last_failure_at: String,
    pub(crate) remaining_secs: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UpstreamHttp3ActiveBufferedFailureCooldownSnapshot {
    pub(crate) cooldown_secs: u64,
    pub(crate) active_entries: Vec<UpstreamHttp3ActiveBufferedFailureCooldownEntry>,
}

#[derive(Debug, Clone)]
struct UpstreamHttp3ActiveBufferedFailureEntry {
    reason_code: String,
    reason_detail: String,
    last_failure_at_unix: u64,
}

#[derive(Debug, Default)]
struct UpstreamHttp3ActiveBufferedFailureCooldownState {
    last_failure_by_authority: HashMap<String, UpstreamHttp3ActiveBufferedFailureEntry>,
}

fn upstream_http3_active_buffered_failure_cooldown_state(
) -> &'static Mutex<UpstreamHttp3ActiveBufferedFailureCooldownState> {
    static STATE: OnceLock<Mutex<UpstreamHttp3ActiveBufferedFailureCooldownState>> =
        OnceLock::new();
    STATE.get_or_init(|| Mutex::new(UpstreamHttp3ActiveBufferedFailureCooldownState::default()))
}

fn prune_active_buffered_failure_cooldown_locked(
    state: &mut UpstreamHttp3ActiveBufferedFailureCooldownState,
    now: u64,
) {
    state.last_failure_by_authority.retain(|_, entry| {
        now.saturating_sub(entry.last_failure_at_unix)
            < DEFAULT_H3_ACTIVE_BUFFERED_FAILURE_COOLDOWN_SECS
    });
}

pub(crate) fn http3_active_buffered_failure_cooldown_snapshot(
) -> UpstreamHttp3ActiveBufferedFailureCooldownSnapshot {
    let now = unix_seconds_now_u64();
    let Ok(mut state) = upstream_http3_active_buffered_failure_cooldown_state().lock() else {
        return UpstreamHttp3ActiveBufferedFailureCooldownSnapshot {
            cooldown_secs: DEFAULT_H3_ACTIVE_BUFFERED_FAILURE_COOLDOWN_SECS,
            active_entries: Vec::new(),
        };
    };

    prune_active_buffered_failure_cooldown_locked(&mut state, now);

    let mut active_entries = state
        .last_failure_by_authority
        .iter()
        .map(|(authority, entry)| {
            let elapsed = now.saturating_sub(entry.last_failure_at_unix);
            UpstreamHttp3ActiveBufferedFailureCooldownEntry {
                authority: authority.clone(),
                reason_code: entry.reason_code.clone(),
                reason_detail: entry.reason_detail.clone(),
                last_failure_at: entry.last_failure_at_unix.to_string(),
                remaining_secs: DEFAULT_H3_ACTIVE_BUFFERED_FAILURE_COOLDOWN_SECS
                    .saturating_sub(elapsed),
            }
        })
        .collect::<Vec<_>>();
    active_entries.sort_by(|left, right| left.authority.cmp(&right.authority));

    UpstreamHttp3ActiveBufferedFailureCooldownSnapshot {
        cooldown_secs: DEFAULT_H3_ACTIVE_BUFFERED_FAILURE_COOLDOWN_SECS,
        active_entries,
    }
}

pub(crate) fn reserve_http3_active_buffered_authority_slot(
    authority: &str,
) -> Result<(), UpstreamBackendError> {
    let authority_key = normalize_h3_authority_key(authority);
    if authority_key.is_empty() {
        return Ok(());
    }

    let now = unix_seconds_now_u64();
    let Ok(mut state) = upstream_http3_active_buffered_failure_cooldown_state().lock() else {
        return Ok(());
    };

    prune_active_buffered_failure_cooldown_locked(&mut state, now);

    let Some(entry) = state.last_failure_by_authority.get(&authority_key).cloned() else {
        return Ok(());
    };

    let elapsed = now.saturating_sub(entry.last_failure_at_unix);
    if elapsed >= DEFAULT_H3_ACTIVE_BUFFERED_FAILURE_COOLDOWN_SECS {
        state.last_failure_by_authority.remove(&authority_key);
        return Ok(());
    }

    Err(UpstreamBackendError::new(
        UpstreamBackendErrorKind::AuthorityFailureCooldown,
        format!(
            "skipping active buffered H3 attempt for {authority}; last failure was {elapsed}s ago ({reason_code}), cooldown is {cooldown}s",
            reason_code = entry.reason_code,
            cooldown = DEFAULT_H3_ACTIVE_BUFFERED_FAILURE_COOLDOWN_SECS,
        ),
    ))
}

pub(crate) fn record_http3_active_buffered_authority_failure(
    authority: &str,
    error: &UpstreamBackendError,
) {
    if !should_backoff_active_buffered_failure(error.kind) {
        return;
    }

    let authority_key = normalize_h3_authority_key(authority);
    if authority_key.is_empty() {
        return;
    }

    let Ok(mut state) = upstream_http3_active_buffered_failure_cooldown_state().lock() else {
        return;
    };

    prune_active_buffered_failure_cooldown_locked(&mut state, unix_seconds_now_u64());

    state.last_failure_by_authority.insert(
        authority_key,
        UpstreamHttp3ActiveBufferedFailureEntry {
            reason_code: error.kind.code().to_string(),
            reason_detail: error.detail.clone(),
            last_failure_at_unix: unix_seconds_now_u64(),
        },
    );
}

pub(crate) fn clear_http3_active_buffered_authority_failure(authority: &str) {
    let authority_key = normalize_h3_authority_key(authority);
    if authority_key.is_empty() {
        return;
    }

    let Ok(mut state) = upstream_http3_active_buffered_failure_cooldown_state().lock() else {
        return;
    };

    state.last_failure_by_authority.remove(&authority_key);
}

fn should_backoff_active_buffered_failure(kind: UpstreamBackendErrorKind) -> bool {
    matches!(
        kind,
        UpstreamBackendErrorKind::DnsError
            | UpstreamBackendErrorKind::UdpError
            | UpstreamBackendErrorKind::QuicConnectTimeout
            | UpstreamBackendErrorKind::QuicHandshakeError
            | UpstreamBackendErrorKind::TlsError
            | UpstreamBackendErrorKind::H3Error
    )
}

fn normalize_h3_authority_key(authority: &str) -> String {
    authority.trim().to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamHttp3ActiveStreamingWriterOutcome {
    WriterPlanReady,
    Fallback,
}

impl UpstreamHttp3ActiveStreamingWriterOutcome {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::WriterPlanReady => "writer_plan_ready",
            Self::Fallback => "fallback_to_reqwest",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UpstreamHttp3ActiveStreamingWriterEvent {
    pub(crate) downstream_protocol: String,
    pub(crate) authority: String,
    pub(crate) candidate: Option<UpstreamHttp3Candidate>,
    pub(crate) outcome: UpstreamHttp3ActiveStreamingWriterOutcome,
    pub(crate) status_code: Option<u16>,
    pub(crate) header_count: Option<usize>,
    pub(crate) reason_code: Option<String>,
    pub(crate) reason_detail: Option<String>,
    pub(crate) observed_at: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UpstreamHttp3ActiveStreamingWriterSnapshot {
    pub(crate) attempts: u64,
    pub(crate) writer_plans_ready: u64,
    pub(crate) fallbacks: u64,
    pub(crate) candidate_misses: u64,
    pub(crate) last_event: Option<UpstreamHttp3ActiveStreamingWriterEvent>,
    pub(crate) last_ready_event: Option<UpstreamHttp3ActiveStreamingWriterEvent>,
    pub(crate) last_candidate_miss_event: Option<UpstreamHttp3ActiveStreamingWriterEvent>,
}

#[derive(Debug, Clone, Default)]
struct UpstreamHttp3ActiveStreamingWriterState {
    attempts: u64,
    writer_plans_ready: u64,
    fallbacks: u64,
    candidate_misses: u64,
    last_event: Option<UpstreamHttp3ActiveStreamingWriterEvent>,
    last_ready_event: Option<UpstreamHttp3ActiveStreamingWriterEvent>,
    last_candidate_miss_event: Option<UpstreamHttp3ActiveStreamingWriterEvent>,
}

fn upstream_http3_active_streaming_writer_state(
) -> &'static Mutex<UpstreamHttp3ActiveStreamingWriterState> {
    static STATE: OnceLock<Mutex<UpstreamHttp3ActiveStreamingWriterState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(UpstreamHttp3ActiveStreamingWriterState::default()))
}

pub(crate) fn http3_active_streaming_writer_snapshot() -> UpstreamHttp3ActiveStreamingWriterSnapshot
{
    let Ok(state) = upstream_http3_active_streaming_writer_state().lock() else {
        return UpstreamHttp3ActiveStreamingWriterSnapshot::default();
    };

    UpstreamHttp3ActiveStreamingWriterSnapshot {
        attempts: state.attempts,
        writer_plans_ready: state.writer_plans_ready,
        fallbacks: state.fallbacks,
        candidate_misses: state.candidate_misses,
        last_event: state.last_event.clone(),
        last_ready_event: state.last_ready_event.clone(),
        last_candidate_miss_event: state.last_candidate_miss_event.clone(),
    }
}

pub(crate) fn record_http3_active_streaming_writer_ready(
    downstream_protocol: &str,
    authority: &str,
    candidate: Option<&UpstreamHttp3Candidate>,
    status_code: u16,
    header_count: usize,
) {
    let Ok(mut state) = upstream_http3_active_streaming_writer_state().lock() else {
        return;
    };

    state.attempts = state.attempts.saturating_add(1);
    state.writer_plans_ready = state.writer_plans_ready.saturating_add(1);
    let event = UpstreamHttp3ActiveStreamingWriterEvent {
        downstream_protocol: downstream_protocol.to_string(),
        authority: authority.to_string(),
        candidate: candidate.cloned(),
        outcome: UpstreamHttp3ActiveStreamingWriterOutcome::WriterPlanReady,
        status_code: Some(status_code),
        header_count: Some(header_count),
        reason_code: None,
        reason_detail: None,
        observed_at: unix_seconds_now(),
    };
    state.last_event = Some(event.clone());
    state.last_ready_event = Some(event);
}

#[derive(Debug, Clone)]
struct UpstreamHttp3ActiveStreamingFailureEntry {
    reason_code: String,
    reason_detail: String,
    last_failure_at_unix: u64,
}

#[derive(Debug, Default)]
struct UpstreamHttp3ActiveStreamingFailureCooldownState {
    last_failure_by_authority: HashMap<String, UpstreamHttp3ActiveStreamingFailureEntry>,
}

fn upstream_http3_active_streaming_failure_cooldown_state(
) -> &'static Mutex<UpstreamHttp3ActiveStreamingFailureCooldownState> {
    static STATE: OnceLock<Mutex<UpstreamHttp3ActiveStreamingFailureCooldownState>> =
        OnceLock::new();
    STATE.get_or_init(|| Mutex::new(UpstreamHttp3ActiveStreamingFailureCooldownState::default()))
}

fn prune_active_streaming_failure_cooldown_locked(
    state: &mut UpstreamHttp3ActiveStreamingFailureCooldownState,
    now: u64,
) {
    state.last_failure_by_authority.retain(|_, entry| {
        now.saturating_sub(entry.last_failure_at_unix)
            < DEFAULT_H3_ACTIVE_STREAMING_FAILURE_COOLDOWN_SECS
    });
}

pub(crate) fn reserve_http3_active_streaming_authority_slot(
    authority: &str,
) -> Result<(), UpstreamBackendError> {
    let authority_key = normalize_h3_authority_key(authority);
    if authority_key.is_empty() {
        return Ok(());
    }

    let now = unix_seconds_now_u64();
    let Ok(mut state) = upstream_http3_active_streaming_failure_cooldown_state().lock() else {
        return Ok(());
    };

    prune_active_streaming_failure_cooldown_locked(&mut state, now);

    let Some(entry) = state.last_failure_by_authority.get(&authority_key).cloned() else {
        return Ok(());
    };

    let elapsed = now.saturating_sub(entry.last_failure_at_unix);
    if elapsed >= DEFAULT_H3_ACTIVE_STREAMING_FAILURE_COOLDOWN_SECS {
        state.last_failure_by_authority.remove(&authority_key);
        return Ok(());
    }

    Err(UpstreamBackendError::new(
        UpstreamBackendErrorKind::AuthorityFailureCooldown,
        format!(
            "skipping active streaming H3 attempt for {authority}; last failure was {elapsed}s ago ({reason_code}: {reason_detail}), cooldown is {cooldown}s",
            reason_code = entry.reason_code,
            reason_detail = entry.reason_detail,
            cooldown = DEFAULT_H3_ACTIVE_STREAMING_FAILURE_COOLDOWN_SECS,
        ),
    ))
}

pub(crate) fn record_http3_active_streaming_authority_failure(
    authority: &str,
    reason_code: impl Into<String>,
    reason_detail: impl Into<String>,
) {
    let authority_key = normalize_h3_authority_key(authority);
    if authority_key.is_empty() {
        return;
    }

    let Ok(mut state) = upstream_http3_active_streaming_failure_cooldown_state().lock() else {
        return;
    };

    prune_active_streaming_failure_cooldown_locked(&mut state, unix_seconds_now_u64());

    state.last_failure_by_authority.insert(
        authority_key,
        UpstreamHttp3ActiveStreamingFailureEntry {
            reason_code: reason_code.into(),
            reason_detail: reason_detail.into(),
            last_failure_at_unix: unix_seconds_now_u64(),
        },
    );
}

pub(crate) fn clear_http3_active_streaming_authority_failure(authority: &str) {
    let authority_key = normalize_h3_authority_key(authority);
    if authority_key.is_empty() {
        return;
    }

    let Ok(mut state) = upstream_http3_active_streaming_failure_cooldown_state().lock() else {
        return;
    };

    state.last_failure_by_authority.remove(&authority_key);
}

pub(crate) fn record_http3_active_streaming_writer_fallback(
    downstream_protocol: &str,
    authority: &str,
    candidate: Option<&UpstreamHttp3Candidate>,
    status_code: Option<u16>,
    header_count: Option<usize>,
    reason_code: impl Into<String>,
    reason_detail: impl Into<String>,
) {
    let Ok(mut state) = upstream_http3_active_streaming_writer_state().lock() else {
        return;
    };

    let reason_code = reason_code.into();
    let reason_detail = reason_detail.into();
    let event = UpstreamHttp3ActiveStreamingWriterEvent {
        downstream_protocol: downstream_protocol.to_string(),
        authority: authority.to_string(),
        candidate: candidate.cloned(),
        outcome: UpstreamHttp3ActiveStreamingWriterOutcome::Fallback,
        status_code,
        header_count,
        reason_code: Some(reason_code.clone()),
        reason_detail: Some(reason_detail),
        observed_at: unix_seconds_now(),
    };

    state.attempts = state.attempts.saturating_add(1);
    state.fallbacks = state.fallbacks.saturating_add(1);
    if reason_code == UpstreamBackendErrorKind::NoCandidate.code() {
        state.candidate_misses = state.candidate_misses.saturating_add(1);
        state.last_candidate_miss_event = Some(event.clone());
    }
    state.last_event = Some(event);
}

#[derive(Debug, Default)]
struct UpstreamHttp3HandshakeProbeGateState {
    last_probe_by_authority: HashMap<String, u64>,
}

fn upstream_http3_handshake_probe_gate_state(
) -> &'static Mutex<UpstreamHttp3HandshakeProbeGateState> {
    static STATE: OnceLock<Mutex<UpstreamHttp3HandshakeProbeGateState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(UpstreamHttp3HandshakeProbeGateState::default()))
}

fn prune_http3_handshake_probe_gate_locked(
    state: &mut UpstreamHttp3HandshakeProbeGateState,
    now: u64,
) {
    state.last_probe_by_authority.retain(|_, last_probe| {
        now.saturating_sub(*last_probe) < DEFAULT_H3_HANDSHAKE_PROBE_COOLDOWN_SECS
    });
}

pub(crate) const fn h3_handshake_probe_cooldown_seconds() -> u64 {
    DEFAULT_H3_HANDSHAKE_PROBE_COOLDOWN_SECS
}

/// Reserves a short dry-run QUIC handshake probe slot for an authority.
///
/// The forwarding probe is enabled by default during the experimental H3 phase,
/// but it must not open a new UDP/QUIC handshake for every eligible GET/HEAD
/// resource. This runtime-only gate keeps probing observable while preventing
/// repeated handshakes from turning into browsing noise.
pub(crate) fn reserve_http3_handshake_probe_slot(
    authority: &str,
) -> Result<(), UpstreamBackendError> {
    let now = unix_seconds_now_u64();
    let Ok(mut state) = upstream_http3_handshake_probe_gate_state().lock() else {
        return Ok(());
    };

    let authority_key = authority.trim().to_ascii_lowercase();
    if authority_key.is_empty() {
        return Ok(());
    }

    prune_http3_handshake_probe_gate_locked(&mut state, now);

    if let Some(last_probe) = state.last_probe_by_authority.get(&authority_key).copied() {
        let elapsed = now.saturating_sub(last_probe);
        if elapsed < DEFAULT_H3_HANDSHAKE_PROBE_COOLDOWN_SECS {
            return Err(UpstreamBackendError::new(
                UpstreamBackendErrorKind::ProbeCooldown,
                format!(
                    "skipping dry-run QUIC handshake probe for {authority}; last probe was {elapsed}s ago, cooldown is {}s",
                    DEFAULT_H3_HANDSHAKE_PROBE_COOLDOWN_SECS
                ),
            ));
        }
    }

    state.last_probe_by_authority.insert(authority_key, now);
    Ok(())
}

pub(crate) fn http3_probe_diagnostics_snapshot() -> UpstreamHttp3ProbeDiagnosticsSnapshot {
    let Ok(state) = upstream_http3_probe_diagnostics_state().lock() else {
        return UpstreamHttp3ProbeDiagnosticsSnapshot::default();
    };

    UpstreamHttp3ProbeDiagnosticsSnapshot {
        probes: state.probes,
        http3_responses: state.http3_responses,
        fallbacks: state.fallbacks,
        last_event: state.last_event.clone(),
        last_h3_eligible_event: state.last_h3_eligible_event.clone(),
        last_http3_response_event: state.last_http3_response_event.clone(),
    }
}

fn describe_probe_response_model(response: &RelayUpstreamResponseModel) -> String {
    let body_probe = response.body_probe.as_ref().map(|probe| {
        format!(
            " · body probe {} · {} bytes · {} chunks · limit {} bytes",
            probe.state.label(),
            probe.bytes_read,
            probe.chunks_read,
            probe.limit_bytes
        )
    });
    let buffered_body = response
        .buffered_body
        .as_ref()
        .map(|body| format!(" · buffered {} bytes", body.len()));
    let buffered_adapter = response.buffered_response_adapter_summary();
    let streaming_adapter = response.streaming_response_adapter_summary();
    let owned_streaming_handoff = response.owned_streaming_handoff_summary();
    let h1_streaming_writer = response.streaming_downstream_writer_plan_summary("h1");
    let h2_streaming_writer = response.streaming_downstream_writer_plan_summary("h2");

    format!(
        "status {} · body {:?} · headers {}{}{} · buffered adapter {} · streaming adapter {} · owned streaming handoff {} · streaming writer h1 {} · streaming writer h2 {}",
        response.head.status_code,
        response.body_mode,
        response.head.headers.len(),
        body_probe.as_deref().unwrap_or(""),
        buffered_body.as_deref().unwrap_or(""),
        buffered_adapter,
        streaming_adapter,
        owned_streaming_handoff,
        h1_streaming_writer,
        h2_streaming_writer
    )
}

/// Records the disabled-by-default forwarding probe outcome.
///
/// This is intentionally separate from backend diagnostics. A dry-run probe can
/// decide to fall back before any HTTP/3 backend is attempted, and that should
/// be visible without pretending a real QUIC/H3 request was sent.
pub(crate) fn record_http3_probe_outcome(outcome: &UpstreamHttp3ExecutionOutcome) {
    let Ok(mut state) = upstream_http3_probe_diagnostics_state().lock() else {
        return;
    };

    state.probes = state.probes.saturating_add(1);
    match outcome.decision {
        UpstreamHttp3ExecutionDecision::Http3Response => {
            state.http3_responses = state.http3_responses.saturating_add(1);
        }
        UpstreamHttp3ExecutionDecision::FallbackToReqwest => {
            state.fallbacks = state.fallbacks.saturating_add(1);
        }
    }

    let event = UpstreamHttp3ProbeDiagnosticsEvent {
        authority: outcome.authority.clone(),
        decision: outcome.decision,
        selected_backend: outcome.attempt_plan.preferred_backend,
        candidate: outcome.attempt_plan.h3_candidate.clone(),
        response_summary: outcome.response.as_ref().map(describe_probe_response_model),
        fallback_error: outcome.fallback_error.clone(),
        fallback_backend: outcome.fallback_backend,
        observed_at: unix_seconds_now(),
    };
    state.last_event = Some(event.clone());
    if outcome.attempt_plan.preferred_backend == UpstreamAttemptBackend::Http3 {
        state.last_h3_eligible_event = Some(event.clone());
    }
    if outcome.decision == UpstreamHttp3ExecutionDecision::Http3Response {
        state.last_http3_response_event = Some(event);
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamQuicTransportStatus {
    NotBuilt,
    ExperimentalSkeleton,
    ExperimentalEndpointConfigSkeleton,
    ExperimentalConnectSkeleton,
    ExperimentalHandshakeProbe,
}

impl UpstreamQuicTransportStatus {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NotBuilt => "not built",
            Self::ExperimentalSkeleton => "experimental skeleton",
            Self::ExperimentalEndpointConfigSkeleton => "experimental endpoint/config skeleton",
            Self::ExperimentalConnectSkeleton => "experimental DNS/connect timeout skeleton",
            Self::ExperimentalHandshakeProbe => "experimental QUIC handshake probe",
        }
    }
}

/// Runtime status for the RelayGate -> upstream HTTP/3 backend.
///
/// This is backend-level, not crate-level. It can be implemented by an
/// experimental `h3 + h3-quinn + quinn` backend now, and by a future stable
/// reqwest HTTP/3 backend later.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamHttp3BackendStatus {
    NotBuilt,
    ExperimentalSkeleton,
    ExperimentalRequestIoSkeleton,
    ExperimentalBodyProbeSkeleton,
    ExperimentalSmallBodyBufferSkeleton,
    ExperimentalBufferedAdapterSkeleton,
    ExperimentalStreamingAdapterSkeleton,
    ExperimentalActiveStreamingSplitSkeleton,
    ExperimentalOwnedStreamingResponseSkeleton,
    ExperimentalStreamingDownstreamWriterSkeleton,
    ExperimentalStreamingWriterGuardSkeleton,
    ExperimentalStreamingH2BytePumpGuarded,
}

impl UpstreamHttp3BackendStatus {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NotBuilt => "not built",
            Self::ExperimentalSkeleton => "experimental skeleton",
            Self::ExperimentalRequestIoSkeleton => "experimental request I/O skeleton",
            Self::ExperimentalBodyProbeSkeleton => "experimental response body probe skeleton",
            Self::ExperimentalSmallBodyBufferSkeleton => "experimental small-body buffer skeleton",
            Self::ExperimentalBufferedAdapterSkeleton => {
                "experimental buffered response adapter skeleton"
            }
            Self::ExperimentalStreamingAdapterSkeleton => {
                "experimental streaming response adapter skeleton"
            }
            Self::ExperimentalActiveStreamingSplitSkeleton => {
                "experimental active streaming mode split skeleton"
            }
            Self::ExperimentalOwnedStreamingResponseSkeleton => {
                "experimental owned streaming response skeleton"
            }
            Self::ExperimentalStreamingDownstreamWriterSkeleton => {
                "experimental streaming downstream writer skeleton"
            }
            Self::ExperimentalStreamingWriterGuardSkeleton => {
                "experimental streaming H1/H2 writer guard skeleton"
            }
            Self::ExperimentalStreamingH2BytePumpGuarded => {
                "experimental streaming H2 guard-only rollback path"
            }
        }
    }
}

#[allow(dead_code)]
pub(crate) trait UpstreamQuicTransport: Send + Sync {
    fn status(&self) -> UpstreamQuicTransportStatus;
}

pub(crate) type UpstreamHttp3Result<T> = Result<T, UpstreamBackendError>;
pub(crate) type UpstreamHttp3Future<'a, T> =
    Pin<Box<dyn Future<Output = UpstreamHttp3Result<T>> + Send + 'a>>;

#[allow(dead_code)]
pub(crate) trait UpstreamHttp3Backend: Send + Sync {
    fn status(&self) -> UpstreamHttp3BackendStatus;
    fn attempt_plan_for_authority(&self, authority: &str) -> UpstreamAttemptPlan;

    fn attempt_plan_for_request(&self, request: &RelayUpstreamRequest) -> UpstreamAttemptPlan {
        preflight_request_for_http3(request).into_attempt_plan()
    }

    /// Executes an upstream HTTP/3 request attempt.
    ///
    /// U7 keeps this as a safe boundary: callers can exercise fallback behavior
    /// while the experimental backend gradually advances from preflight to QUIC
    /// handshake and later H3 request I/O. A real backend should return a
    /// RelayGate-owned response model, never raw Quinn or h3 types.
    fn execute_request<'a>(
        &'a self,
        dns_resolver: &'a SharedDnsResolver,
        request: &'a RelayUpstreamRequest,
    ) -> UpstreamHttp3Future<'a, RelayUpstreamResponseModel>;
}

/// Placeholder QUIC transport used until a real implementation is selected.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NotBuiltUpstreamQuicTransport;

impl UpstreamQuicTransport for NotBuiltUpstreamQuicTransport {
    fn status(&self) -> UpstreamQuicTransportStatus {
        UpstreamQuicTransportStatus::NotBuilt
    }
}

/// Placeholder HTTP/3 backend used until dependencies and implementation are
/// explicitly approved.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NotBuiltUpstreamHttp3Backend;

impl UpstreamHttp3Backend for NotBuiltUpstreamHttp3Backend {
    fn status(&self) -> UpstreamHttp3BackendStatus {
        UpstreamHttp3BackendStatus::NotBuilt
    }

    fn attempt_plan_for_authority(&self, authority: &str) -> UpstreamAttemptPlan {
        let candidate = active_candidate_for_authority(authority);
        UpstreamAttemptPlan::skip_http3(
            authority,
            candidate,
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::BackendNotBuilt,
                "upstream HTTP/3 backend is not built",
            ),
        )
    }

    fn attempt_plan_for_request(&self, request: &RelayUpstreamRequest) -> UpstreamAttemptPlan {
        let candidate = active_candidate_for_authority(&request.authority);
        UpstreamAttemptPlan::skip_http3(
            &request.authority,
            candidate,
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::BackendNotBuilt,
                "upstream HTTP/3 backend is not built",
            ),
        )
    }

    fn execute_request<'a>(
        &'a self,
        _dns_resolver: &'a SharedDnsResolver,
        request: &'a RelayUpstreamRequest,
    ) -> UpstreamHttp3Future<'a, RelayUpstreamResponseModel> {
        Box::pin(async move {
            let candidate = active_candidate_for_authority(&request.authority);
            record_http3_attempt(&request.authority, candidate.as_ref());

            let error = UpstreamBackendError::new(
                UpstreamBackendErrorKind::BackendNotBuilt,
                "upstream HTTP/3 backend is not built",
            );
            record_http3_fallback(&request.authority, candidate.as_ref(), &error);
            Err(error)
        })
    }
}

/// Request-level preflight result for an upstream HTTP/3 attempt.
///
/// This gate is intentionally separate from the concrete backend. It answers
/// whether a request is safe to try over H3 before any QUIC connection is
/// opened. Future forwarding code can call this first and keep reqwest fallback
/// behavior centralized.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamHttp3PreflightDecision {
    TryHttp3,
    SkipHttp3,
}

impl UpstreamHttp3PreflightDecision {
    #[allow(dead_code)]
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::TryHttp3 => "try_http3",
            Self::SkipHttp3 => "skip_http3",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct UpstreamHttp3Preflight {
    pub(crate) authority: String,
    pub(crate) decision: UpstreamHttp3PreflightDecision,
    pub(crate) candidate: Option<UpstreamHttp3Candidate>,
    pub(crate) skip_reason: Option<UpstreamBackendError>,
    pub(crate) fallback_backend: UpstreamH3FallbackBackend,
}

impl UpstreamHttp3Preflight {
    pub(crate) fn try_http3(authority: &str, candidate: UpstreamHttp3Candidate) -> Self {
        Self {
            authority: authority.to_string(),
            decision: UpstreamHttp3PreflightDecision::TryHttp3,
            candidate: Some(candidate),
            skip_reason: None,
            fallback_backend: UpstreamH3FallbackBackend::ReqwestAuto,
        }
    }

    pub(crate) fn skip_http3(
        authority: &str,
        candidate: Option<UpstreamHttp3Candidate>,
        reason: UpstreamBackendError,
    ) -> Self {
        Self {
            authority: authority.to_string(),
            decision: UpstreamHttp3PreflightDecision::SkipHttp3,
            candidate,
            skip_reason: Some(reason),
            fallback_backend: UpstreamH3FallbackBackend::ReqwestAuto,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_try_http3(&self) -> bool {
        self.decision == UpstreamHttp3PreflightDecision::TryHttp3
    }

    #[allow(dead_code)]
    pub(crate) fn label(&self) -> &'static str {
        self.decision.label()
    }

    #[allow(dead_code)]
    pub(crate) fn fallback_label(&self) -> &'static str {
        self.fallback_backend.label()
    }

    #[allow(dead_code)]
    pub(crate) fn skip_code(&self) -> Option<&'static str> {
        self.skip_reason.as_ref().map(|error| error.kind.code())
    }

    pub(crate) fn into_attempt_plan(self) -> UpstreamAttemptPlan {
        let authority = self.authority;
        match (self.decision, self.candidate, self.skip_reason) {
            (UpstreamHttp3PreflightDecision::TryHttp3, Some(candidate), _) => {
                UpstreamAttemptPlan::try_http3(&authority, candidate)
            }
            (_, candidate, Some(reason)) => {
                UpstreamAttemptPlan::skip_http3(&authority, candidate, reason)
            }
            _ => UpstreamAttemptPlan::skip_http3(
                &authority,
                None,
                UpstreamBackendError::new(
                    UpstreamBackendErrorKind::H3Error,
                    "invalid HTTP/3 preflight state",
                ),
            ),
        }
    }
}

#[allow(dead_code)]
pub(crate) fn preflight_request_for_http3(
    request: &RelayUpstreamRequest,
) -> UpstreamHttp3Preflight {
    let candidate = active_candidate_for_authority(&request.authority);

    if !request.is_get_or_head() {
        return UpstreamHttp3Preflight::skip_http3(
            &request.authority,
            candidate,
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::UnsupportedMethod,
                "experimental upstream HTTP/3 only preflights GET/HEAD requests",
            ),
        );
    }

    if !request.body.is_empty() {
        return UpstreamHttp3Preflight::skip_http3(
            &request.authority,
            candidate,
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::RequestBodyNotReplayable,
                "experimental upstream HTTP/3 only preflights empty request bodies",
            ),
        );
    }

    let Some(candidate) = candidate else {
        return UpstreamHttp3Preflight::skip_http3(
            &request.authority,
            None,
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::NoCandidate,
                "no active HTTP/3 Alt-Svc candidate for authority",
            ),
        );
    };

    UpstreamHttp3Preflight::try_http3(&request.authority, candidate)
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamAttemptBackend {
    Http3,
    ReqwestAuto,
}

impl UpstreamAttemptBackend {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Http3 => "http3",
            Self::ReqwestAuto => "reqwest auto",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamH3FallbackBackend {
    ReqwestAuto,
}

impl UpstreamH3FallbackBackend {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ReqwestAuto => "reqwest auto",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamBackendErrorKind {
    BackendNotBuilt,
    NoCandidate,
    UnsupportedMethod,
    DnsError,
    UdpError,
    QuicConnectTimeout,
    QuicHandshakeError,
    TlsError,
    H3Error,
    RequestBodyNotReplayable,
    DownstreamCancel,
    ProbeCooldown,
    AuthorityFailureCooldown,
}

impl UpstreamBackendErrorKind {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::BackendNotBuilt => "backend_not_built",
            Self::NoCandidate => "no_candidate",
            Self::UnsupportedMethod => "unsupported_method",
            Self::DnsError => "dns_error",
            Self::UdpError => "udp_error",
            Self::QuicConnectTimeout => "quic_connect_timeout",
            Self::QuicHandshakeError => "quic_handshake_error",
            Self::TlsError => "tls_error",
            Self::H3Error => "h3_error",
            Self::RequestBodyNotReplayable => "request_body_not_replayable",
            Self::DownstreamCancel => "downstream_cancel",
            Self::ProbeCooldown => "probe_cooldown",
            Self::AuthorityFailureCooldown => "authority_failure_cooldown",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct UpstreamBackendError {
    pub(crate) kind: UpstreamBackendErrorKind,
    pub(crate) detail: String,
}

impl UpstreamBackendError {
    pub(crate) fn new(kind: UpstreamBackendErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// Result of the outer upstream HTTP/3 execution adapter.
///
/// This is deliberately not a forwarding response yet. It lets future MITM H1/H2
/// adapters ask "did H3 produce a response, or should I use the normal reqwest
/// fallback path?" without learning about Quinn, h3, or backend-specific errors.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamHttp3ExecutionDecision {
    Http3Response,
    FallbackToReqwest,
}

impl UpstreamHttp3ExecutionDecision {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Http3Response => "http3_response",
            Self::FallbackToReqwest => "fallback_to_reqwest",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct UpstreamHttp3ExecutionOutcome {
    pub(crate) authority: String,
    pub(crate) decision: UpstreamHttp3ExecutionDecision,
    pub(crate) attempt_plan: UpstreamAttemptPlan,
    pub(crate) response: Option<RelayUpstreamResponseModel>,
    pub(crate) fallback_error: Option<UpstreamBackendError>,
    pub(crate) fallback_backend: UpstreamH3FallbackBackend,
}

impl UpstreamHttp3ExecutionOutcome {
    pub(crate) fn http3_response(
        authority: &str,
        attempt_plan: UpstreamAttemptPlan,
        response: RelayUpstreamResponseModel,
    ) -> Self {
        let fallback_backend = attempt_plan.fallback_backend;
        Self {
            authority: authority.to_string(),
            decision: UpstreamHttp3ExecutionDecision::Http3Response,
            attempt_plan,
            response: Some(response),
            fallback_error: None,
            fallback_backend,
        }
    }

    pub(crate) fn fallback_to_reqwest(
        authority: &str,
        attempt_plan: UpstreamAttemptPlan,
        error: UpstreamBackendError,
    ) -> Self {
        let fallback_backend = attempt_plan.fallback_backend;
        Self {
            authority: authority.to_string(),
            decision: UpstreamHttp3ExecutionDecision::FallbackToReqwest,
            attempt_plan,
            response: None,
            fallback_error: Some(error),
            fallback_backend,
        }
    }

    pub(crate) fn decision_label(&self) -> &'static str {
        self.decision.label()
    }

    pub(crate) fn fallback_label(&self) -> &'static str {
        self.fallback_backend.label()
    }

    pub(crate) fn fallback_error_code(&self) -> Option<&'static str> {
        self.fallback_error.as_ref().map(|error| error.kind.code())
    }
}

/// Executes the H3 attempt adapter and converts every skip/error into an
/// explicit reqwest fallback outcome.
///
/// This is still a skeleton seam: it does not write to downstream sockets and it
/// does not replace the existing reqwest path. The value is the outer control
/// shape: preflight -> optional H3 backend -> explicit fallback outcome.
#[allow(dead_code)]
pub(crate) async fn execute_http3_with_fallback<B>(
    backend: &B,
    dns_resolver: &SharedDnsResolver,
    request: &RelayUpstreamRequest,
) -> UpstreamHttp3ExecutionOutcome
where
    B: UpstreamHttp3Backend + ?Sized,
{
    let attempt_plan = backend.attempt_plan_for_request(request);

    if attempt_plan.preferred_backend != UpstreamAttemptBackend::Http3 {
        let error = attempt_plan.h3_skip_reason.clone().unwrap_or_else(|| {
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::H3Error,
                "HTTP/3 attempt plan skipped without a reason",
            )
        });
        return UpstreamHttp3ExecutionOutcome::fallback_to_reqwest(
            &request.authority,
            attempt_plan,
            error,
        );
    }

    match backend.execute_request(dns_resolver, request).await {
        Ok(response) => UpstreamHttp3ExecutionOutcome::http3_response(
            &request.authority,
            attempt_plan,
            response,
        ),
        Err(error) => UpstreamHttp3ExecutionOutcome::fallback_to_reqwest(
            &request.authority,
            attempt_plan,
            error,
        ),
    }
}

#[allow(dead_code)]
pub(crate) async fn execute_http3_preserving_streaming_with_fallback(
    backend: &ExperimentalUpstreamHttp3Backend,
    dns_resolver: &SharedDnsResolver,
    request: &RelayUpstreamRequest,
) -> UpstreamHttp3ExecutionOutcome {
    let attempt_plan = backend.attempt_plan_for_request(request);

    if attempt_plan.preferred_backend != UpstreamAttemptBackend::Http3 {
        let error = attempt_plan.h3_skip_reason.clone().unwrap_or_else(|| {
            UpstreamBackendError::new(
                UpstreamBackendErrorKind::H3Error,
                "HTTP/3 attempt plan skipped without a reason",
            )
        });
        return UpstreamHttp3ExecutionOutcome::fallback_to_reqwest(
            &request.authority,
            attempt_plan,
            error,
        );
    }

    match backend
        .execute_request_preserving_streaming_body(dns_resolver, request)
        .await
    {
        Ok(response) => UpstreamHttp3ExecutionOutcome::http3_response(
            &request.authority,
            attempt_plan,
            response,
        ),
        Err(error) => UpstreamHttp3ExecutionOutcome::fallback_to_reqwest(
            &request.authority,
            attempt_plan,
            error,
        ),
    }
}

/// RelayGate-owned upstream attempt plan.
///
/// The shared core should reason about this plan rather than about concrete
/// reqwest, Quinn, or h3 crate types. The current experimental backend can
/// decide that a request is H3-eligible, while execution still remains a safe
/// skeleton that falls back to reqwest until QUIC/H3 I/O is wired.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct UpstreamAttemptPlan {
    pub(crate) authority: String,
    pub(crate) preferred_backend: UpstreamAttemptBackend,
    pub(crate) h3_candidate: Option<UpstreamHttp3Candidate>,
    pub(crate) h3_skip_reason: Option<UpstreamBackendError>,
    pub(crate) fallback_backend: UpstreamH3FallbackBackend,
}

impl UpstreamAttemptPlan {
    pub(crate) fn skip_http3(
        authority: &str,
        candidate: Option<UpstreamHttp3Candidate>,
        reason: UpstreamBackendError,
    ) -> Self {
        Self {
            authority: authority.to_string(),
            preferred_backend: UpstreamAttemptBackend::ReqwestAuto,
            h3_candidate: candidate,
            h3_skip_reason: Some(reason),
            fallback_backend: UpstreamH3FallbackBackend::ReqwestAuto,
        }
    }

    pub(crate) fn try_http3(authority: &str, candidate: UpstreamHttp3Candidate) -> Self {
        Self {
            authority: authority.to_string(),
            preferred_backend: UpstreamAttemptBackend::Http3,
            h3_candidate: Some(candidate),
            h3_skip_reason: None,
            fallback_backend: UpstreamH3FallbackBackend::ReqwestAuto,
        }
    }

    pub(crate) fn label(&self) -> &'static str {
        self.preferred_backend.label()
    }

    pub(crate) fn fallback_label(&self) -> &'static str {
        self.fallback_backend.label()
    }

    pub(crate) fn h3_skip_code(&self) -> Option<&'static str> {
        self.h3_skip_reason.as_ref().map(|error| error.kind.code())
    }
}

pub(crate) fn default_quic_transport() -> ExperimentalUpstreamQuicTransport {
    ExperimentalUpstreamQuicTransport
}

pub(crate) fn default_http3_backend() -> ExperimentalUpstreamHttp3Backend {
    ExperimentalUpstreamHttp3Backend
}

#[allow(dead_code)]
pub(crate) fn default_http3_attempt_plan_for_authority(authority: &str) -> UpstreamAttemptPlan {
    default_http3_backend().attempt_plan_for_authority(authority)
}

pub(crate) fn quic_transport_status_label() -> &'static str {
    default_quic_transport().status().label()
}

pub(crate) fn http3_backend_status_label() -> &'static str {
    default_http3_backend().status().label()
}

pub(crate) fn h3_failure_fallback_label() -> &'static str {
    UpstreamH3FallbackBackend::ReqwestAuto.label()
}

fn unix_seconds_now() -> String {
    unix_seconds_now_u64().to_string()
}

fn unix_seconds_now_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        config::DnsConfig,
        dns::RelayGateDnsResolver,
        proxy::upstream_model::{RelayUpstreamBody, RelayUpstreamRequest},
    };

    use super::*;

    fn get_request(authority: &str) -> RelayUpstreamRequest {
        RelayUpstreamRequest::empty_get_head(
            "GET",
            format!("https://{authority}/index.html"),
            authority,
            Vec::new(),
        )
        .expect("valid GET request")
    }

    fn record_candidate(authority: &str) {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "alt-svc",
            reqwest::header::HeaderValue::from_static(r#"h3=":443"; ma=120"#),
        );
        record_alt_svc(authority, &headers);
    }

    #[test]
    fn preflight_allows_empty_get_with_active_candidate() {
        let authority = "preflight-ok.example";
        record_candidate(authority);

        let preflight = preflight_request_for_http3(&get_request(authority));

        assert_eq!(preflight.decision, UpstreamHttp3PreflightDecision::TryHttp3);
        assert!(preflight.is_try_http3());
        assert_eq!(preflight.skip_code(), None);
        assert_eq!(preflight.fallback_label(), "reqwest auto");
    }

    #[test]
    fn preflight_skips_without_candidate() {
        let request = get_request("preflight-no-candidate.example");

        let preflight = preflight_request_for_http3(&request);

        assert_eq!(
            preflight.decision,
            UpstreamHttp3PreflightDecision::SkipHttp3
        );
        assert_eq!(preflight.skip_code(), Some("no_candidate"));
        assert!(preflight.candidate.is_none());
    }

    #[test]
    fn preflight_skips_unsupported_method_before_candidate_requirement() {
        let request = RelayUpstreamRequest {
            method: "POST".to_string(),
            url: "https://preflight-post.example/upload".to_string(),
            authority: "preflight-post.example".to_string(),
            headers: Vec::new(),
            body: RelayUpstreamBody::Empty,
        };

        let preflight = preflight_request_for_http3(&request);

        assert_eq!(
            preflight.decision,
            UpstreamHttp3PreflightDecision::SkipHttp3
        );
        assert_eq!(preflight.skip_code(), Some("unsupported_method"));
    }

    #[test]
    fn preflight_skips_non_empty_body_before_candidate_requirement() {
        let request = RelayUpstreamRequest {
            method: "GET".to_string(),
            url: "https://preflight-body.example/search".to_string(),
            authority: "preflight-body.example".to_string(),
            headers: Vec::new(),
            body: RelayUpstreamBody::ReplayableBytes(b"q=test".to_vec()),
        };

        let preflight = preflight_request_for_http3(&request);

        assert_eq!(
            preflight.decision,
            UpstreamHttp3PreflightDecision::SkipHttp3
        );
        assert_eq!(preflight.skip_code(), Some("request_body_not_replayable"));
    }

    #[tokio::test]
    async fn execute_http3_with_fallback_returns_reqwest_fallback_on_preflight_skip() {
        let request = get_request("fallback-no-candidate.example");
        let dns_resolver = Arc::new(RelayGateDnsResolver::new(DnsConfig::default()));
        let backend = default_http3_backend();

        let outcome = execute_http3_with_fallback(&backend, &dns_resolver, &request).await;

        assert_eq!(
            outcome.decision,
            UpstreamHttp3ExecutionDecision::FallbackToReqwest
        );
        assert_eq!(outcome.fallback_label(), "reqwest auto");
        assert_eq!(outcome.fallback_error_code(), Some("no_candidate"));
        assert!(outcome.response.is_none());
    }

    #[test]
    fn pruning_removes_expired_h3_runtime_cooldowns() {
        let now = 1_000_u64;

        let mut buffered = UpstreamHttp3ActiveBufferedFailureCooldownState::default();
        buffered.last_failure_by_authority.insert(
            "old-buffered.example".to_string(),
            UpstreamHttp3ActiveBufferedFailureEntry {
                reason_code: "h3_error".to_string(),
                reason_detail: "old".to_string(),
                last_failure_at_unix: now - DEFAULT_H3_ACTIVE_BUFFERED_FAILURE_COOLDOWN_SECS,
            },
        );
        buffered.last_failure_by_authority.insert(
            "fresh-buffered.example".to_string(),
            UpstreamHttp3ActiveBufferedFailureEntry {
                reason_code: "h3_error".to_string(),
                reason_detail: "fresh".to_string(),
                last_failure_at_unix: now - 1,
            },
        );
        prune_active_buffered_failure_cooldown_locked(&mut buffered, now);
        assert!(!buffered
            .last_failure_by_authority
            .contains_key("old-buffered.example"));
        assert!(buffered
            .last_failure_by_authority
            .contains_key("fresh-buffered.example"));

        let mut streaming = UpstreamHttp3ActiveStreamingFailureCooldownState::default();
        streaming.last_failure_by_authority.insert(
            "old-streaming.example".to_string(),
            UpstreamHttp3ActiveStreamingFailureEntry {
                reason_code: "h3_error".to_string(),
                reason_detail: "old".to_string(),
                last_failure_at_unix: now - DEFAULT_H3_ACTIVE_STREAMING_FAILURE_COOLDOWN_SECS,
            },
        );
        streaming.last_failure_by_authority.insert(
            "fresh-streaming.example".to_string(),
            UpstreamHttp3ActiveStreamingFailureEntry {
                reason_code: "h3_error".to_string(),
                reason_detail: "fresh".to_string(),
                last_failure_at_unix: now - 1,
            },
        );
        prune_active_streaming_failure_cooldown_locked(&mut streaming, now);
        assert!(!streaming
            .last_failure_by_authority
            .contains_key("old-streaming.example"));
        assert!(streaming
            .last_failure_by_authority
            .contains_key("fresh-streaming.example"));

        let mut probe = UpstreamHttp3HandshakeProbeGateState::default();
        probe.last_probe_by_authority.insert(
            "old-probe.example".to_string(),
            now - DEFAULT_H3_HANDSHAKE_PROBE_COOLDOWN_SECS,
        );
        probe
            .last_probe_by_authority
            .insert("fresh-probe.example".to_string(), now - 1);
        prune_http3_handshake_probe_gate_locked(&mut probe, now);
        assert!(!probe
            .last_probe_by_authority
            .contains_key("old-probe.example"));
        assert!(probe
            .last_probe_by_authority
            .contains_key("fresh-probe.example"));
    }

    #[test]
    fn clear_streaming_authority_failure_removes_cooldown() {
        let authority = "streaming-clear-cooldown.example";

        record_http3_active_streaming_authority_failure(authority, "h3_error", "test failure");
        assert!(reserve_http3_active_streaming_authority_slot(authority).is_err());

        clear_http3_active_streaming_authority_failure(authority);
        assert!(reserve_http3_active_streaming_authority_slot(authority).is_ok());
    }
}
