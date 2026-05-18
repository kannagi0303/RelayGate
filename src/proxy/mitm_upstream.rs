use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use reqwest::Client;

const MITM_REQWEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

use crate::{
    config::UpstreamProtocolPolicyConfig,
    dns::{ReqwestDnsResolver, SharedDnsResolver},
    proxy::{
        rules::RuleEffect,
        upstream::SharedUpstreamRegistry,
        upstream_h3::{
            self, UpstreamAttemptPlan, UpstreamBackendError, UpstreamBackendErrorKind,
            UpstreamHttp3ExecutionOutcome, UpstreamHttp3Preflight,
        },
        upstream_model::{
            RelayUpstreamBufferedResponse, RelayUpstreamRequest, RelayUpstreamRequestBuildError,
            RelayUpstreamRequestBuildErrorKind, RelayUpstreamStreamingResponse,
        },
    },
};

/// Protocol policy for RelayGate -> upstream origin/proxy connections.
///
/// Downstream HTTP/1.1, HTTP/2, or future HTTP/3 adapters should not decide
/// the upstream transport directly. They produce a request intent; the upstream
/// connector applies this policy and owns client/cache selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MitmUpstreamProtocolPolicy {
    /// Let the current HTTP client negotiate the best supported upstream
    /// protocol. With the existing reqwest configuration this preserves the
    /// current behavior, including HTTP/2 where reqwest/rustls can negotiate it.
    Auto,
    /// Force the upstream reqwest client to use HTTP/1.x.
    Http1Only,
    /// Force reqwest's HTTP/2 prior-knowledge mode.
    ///
    /// This is an explicit mode, not a graceful preference. It is mainly useful
    /// for controlled targets and future protocol testing.
    Http2PriorKnowledge,
}

impl MitmUpstreamProtocolPolicy {
    fn cache_fragment(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Http1Only => "http1-only",
            Self::Http2PriorKnowledge => "http2-prior-knowledge",
        }
    }
}

impl From<UpstreamProtocolPolicyConfig> for MitmUpstreamProtocolPolicy {
    fn from(value: UpstreamProtocolPolicyConfig) -> Self {
        match value {
            UpstreamProtocolPolicyConfig::Auto => Self::Auto,
            UpstreamProtocolPolicyConfig::Http1Only => Self::Http1Only,
            UpstreamProtocolPolicyConfig::Http2PriorKnowledge => Self::Http2PriorKnowledge,
        }
    }
}

/// Protocol-neutral upstream request intent produced by the shared MITM core.
///
/// This deliberately contains no downstream framing details. Future upstream
/// HTTP/3 support can extend the policy/connector side without making H1/H2
/// downstream adapters duplicate DNS, route, adblock, rewrite, or replace logic.
#[derive(Debug, Clone)]
pub(crate) struct MitmUpstreamRequestIntent {
    pub(crate) upstream_id: Option<String>,
    pub(crate) protocol_policy: MitmUpstreamProtocolPolicy,
}

impl MitmUpstreamRequestIntent {
    pub(crate) fn new(
        upstream_id: Option<String>,
        protocol_policy: MitmUpstreamProtocolPolicy,
    ) -> Self {
        Self {
            upstream_id,
            protocol_policy,
        }
    }
}

#[derive(Debug, Clone)]
struct MitmUpstreamConnectionPlan {
    upstream_address: Option<String>,
    allow_invalid_certs: bool,
    protocol_policy: MitmUpstreamProtocolPolicy,
}

impl MitmUpstreamConnectionPlan {
    fn cache_key(&self) -> String {
        format!(
            "upstream={};tls={};protocol={}",
            self.upstream_address.as_deref().unwrap_or("direct"),
            if self.allow_invalid_certs {
                "allow-invalid"
            } else {
                "strict"
            },
            self.protocol_policy.cache_fragment(),
        )
    }
}

/// Owns RelayGate -> upstream HTTP client selection for MITM traffic.
///
/// Today this wraps the existing reqwest client path. The boundary is useful now
/// because downstream H2 can reuse it unchanged, and future upstream H2/H3 policy
/// work has a single connector seam instead of leaking into protocol adapters.
pub(crate) struct MitmUpstreamConnector {
    upstreams: SharedUpstreamRegistry,
    dns_resolver: SharedDnsResolver,
    http_client_cache: Arc<Mutex<HashMap<String, Client>>>,
}

impl MitmUpstreamConnector {
    pub(crate) fn new(
        upstreams: SharedUpstreamRegistry,
        dns_resolver: SharedDnsResolver,
        http_client_cache: Arc<Mutex<HashMap<String, Client>>>,
    ) -> Self {
        Self {
            upstreams,
            dns_resolver,
            http_client_cache,
        }
    }

    pub(crate) fn client_for_request(
        &self,
        intent: &MitmUpstreamRequestIntent,
        allow_invalid_certs: bool,
    ) -> Result<Client> {
        let plan = self.connection_plan(intent, allow_invalid_certs)?;
        self.client_for_plan(&plan)
    }

    /// Builds the future upstream HTTP/3 attempt plan for an authority.
    ///
    /// This is a skeleton seam only. It does not change forwarding behavior and
    /// currently returns a not-built plan that falls back to reqwest auto.
    #[allow(dead_code)]
    pub(crate) fn http3_attempt_plan_for_authority(&self, authority: &str) -> UpstreamAttemptPlan {
        upstream_h3::default_http3_attempt_plan_for_authority(authority)
    }

    /// Preflights whether a request is safe to try with upstream HTTP/3.
    ///
    /// This is not wired into forwarding yet. It only centralizes the future
    /// H3 gate: empty-body GET/HEAD, active Alt-Svc candidate, and reqwest-auto
    /// fallback on any skip or failure.
    #[allow(dead_code)]
    pub(crate) fn http3_preflight_for_request(
        &self,
        request: &RelayUpstreamRequest,
    ) -> UpstreamHttp3Preflight {
        upstream_h3::preflight_request_for_http3(request)
    }

    /// Runs the future HTTP/3 execution adapter and always returns an explicit
    /// outcome: either an H3 response model or a reqwest-auto fallback decision.
    ///
    /// This powers the dry-run probe and the guarded buffered active path. It may
    /// open a QUIC/H3 request attempt, but callers still decide whether the
    /// response is eligible for active forwarding or must fall back to reqwest.
    #[allow(dead_code)]
    pub(crate) async fn try_http3_for_request(
        &self,
        request: &RelayUpstreamRequest,
    ) -> UpstreamHttp3ExecutionOutcome {
        let backend = upstream_h3::default_http3_backend();
        upstream_h3::execute_http3_with_fallback(&backend, &self.dns_resolver, request).await
    }

    /// Dry-run hook for the upstream HTTP/3 forwarding path.
    ///
    /// When `probe_enabled` is false, this returns `None` and performs no work.
    /// When enabled, it builds the RelayGate-owned H3 request model and runs the
    /// current H3 execution adapter. The pure probe caller must still continue
    /// the normal reqwest path, while the guarded active buffered caller may use
    /// the response only after a stricter complete-body adapter check.
    #[allow(dead_code)]
    pub(crate) async fn probe_http3_for_mitm_parts(
        &self,
        probe_enabled: bool,
        method: &str,
        target_url: &str,
        authority: &str,
        headers: &[(String, String)],
        request_effects: &[RuleEffect],
        request_body_is_empty: bool,
    ) -> Option<UpstreamHttp3ExecutionOutcome> {
        if !probe_enabled {
            return None;
        }

        if !request_body_is_empty {
            let backend_error = UpstreamBackendError::new(
                UpstreamBackendErrorKind::RequestBodyNotReplayable,
                "upstream HTTP/3 forwarding probe only accepts empty request bodies",
            );
            let candidate = upstream_h3::active_candidate_for_authority(authority);
            let attempt_plan =
                UpstreamAttemptPlan::skip_http3(authority, candidate, backend_error.clone());
            let outcome = UpstreamHttp3ExecutionOutcome::fallback_to_reqwest(
                authority,
                attempt_plan,
                backend_error,
            );
            upstream_h3::record_http3_probe_outcome(&outcome);
            return Some(outcome);
        }

        let request = match self.build_http3_request_from_mitm_parts(
            method,
            target_url,
            authority,
            headers,
            request_effects,
        ) {
            Ok(request) => request,
            Err(error) => {
                let backend_error = UpstreamBackendError::new(
                    match error.kind {
                        RelayUpstreamRequestBuildErrorKind::UnsupportedMethod => {
                            UpstreamBackendErrorKind::UnsupportedMethod
                        }
                    },
                    error.detail,
                );
                let candidate = upstream_h3::active_candidate_for_authority(authority);
                let attempt_plan =
                    UpstreamAttemptPlan::skip_http3(authority, candidate, backend_error.clone());
                let outcome = UpstreamHttp3ExecutionOutcome::fallback_to_reqwest(
                    authority,
                    attempt_plan,
                    backend_error,
                );
                upstream_h3::record_http3_probe_outcome(&outcome);
                return Some(outcome);
            }
        };

        let outcome = self.try_http3_for_request(&request).await;
        upstream_h3::record_http3_probe_outcome(&outcome);
        Some(outcome)
    }

    /// Attempts the guarded active buffered HTTP/3 forwarding path.
    ///
    /// This is intentionally stricter than the dry-run probe. It only returns a
    /// buffered response when the current H3 backend produced a complete
    /// RelayGate-owned body adapter. All skips, failures, streaming responses,
    /// truncated probes, and timed-out probes are returned as fallback outcomes
    /// so callers can continue the normal reqwest path.
    #[allow(dead_code)]
    pub(crate) async fn try_http3_buffered_response_for_mitm_parts(
        &self,
        buffered_response_enabled: bool,
        method: &str,
        target_url: &str,
        authority: &str,
        headers: &[(String, String)],
        request_effects: &[RuleEffect],
        request_body_is_empty: bool,
    ) -> Option<Result<RelayUpstreamBufferedResponse, UpstreamHttp3ExecutionOutcome>> {
        if !buffered_response_enabled {
            return None;
        }

        if request_body_is_empty {
            if let Err(error) = upstream_h3::reserve_http3_active_buffered_authority_slot(authority)
            {
                let candidate = upstream_h3::active_candidate_for_authority(authority);
                let attempt_plan =
                    UpstreamAttemptPlan::skip_http3(authority, candidate, error.clone());
                let outcome = UpstreamHttp3ExecutionOutcome::fallback_to_reqwest(
                    authority,
                    attempt_plan,
                    error,
                );
                return Some(Err(outcome));
            }
        }

        let outcome = self
            .probe_http3_for_mitm_parts(
                true,
                method,
                target_url,
                authority,
                headers,
                request_effects,
                request_body_is_empty,
            )
            .await?;

        if let Some(error) = outcome.fallback_error.as_ref() {
            upstream_h3::record_http3_active_buffered_authority_failure(authority, error);
        }

        if let Some(response) = outcome.response.as_ref() {
            if let Ok(buffered_response) = response.buffered_response_adapter() {
                return Some(Ok(buffered_response));
            }
        }

        Some(Err(outcome))
    }

    /// Attempts the experimental active H2 streaming response path.
    ///
    /// Unlike the writer-plan guard, this returns an opaque RelayGate streaming
    /// response whose body still owns the unconsumed H3 stream. The caller may
    /// pump it to downstream H2 only after its own fast-path checks pass. All
    /// skips and failures return an explicit fallback outcome so reqwest remains
    /// the safe default.
    #[allow(dead_code)]
    pub(crate) async fn try_http3_streaming_response_for_mitm_parts(
        &self,
        streaming_response_enabled: bool,
        method: &str,
        target_url: &str,
        authority: &str,
        headers: &[(String, String)],
        request_effects: &[RuleEffect],
        request_body_is_empty: bool,
    ) -> Option<Result<RelayUpstreamStreamingResponse, UpstreamHttp3ExecutionOutcome>> {
        if !streaming_response_enabled {
            return None;
        }

        if !request_body_is_empty {
            let backend_error = UpstreamBackendError::new(
                UpstreamBackendErrorKind::RequestBodyNotReplayable,
                "upstream HTTP/3 active streaming response only accepts empty request bodies",
            );
            let candidate = upstream_h3::active_candidate_for_authority(authority);
            let attempt_plan = UpstreamAttemptPlan::skip_http3(
                authority,
                candidate.clone(),
                backend_error.clone(),
            );
            let outcome = UpstreamHttp3ExecutionOutcome::fallback_to_reqwest(
                authority,
                attempt_plan,
                backend_error.clone(),
            );
            return Some(Err(outcome));
        }

        let request = match self.build_http3_request_from_mitm_parts(
            method,
            target_url,
            authority,
            headers,
            request_effects,
        ) {
            Ok(request) => request,
            Err(error) => {
                let backend_error = UpstreamBackendError::new(
                    match error.kind {
                        RelayUpstreamRequestBuildErrorKind::UnsupportedMethod => {
                            UpstreamBackendErrorKind::UnsupportedMethod
                        }
                    },
                    error.detail,
                );
                let candidate = upstream_h3::active_candidate_for_authority(authority);
                let attempt_plan = UpstreamAttemptPlan::skip_http3(
                    authority,
                    candidate.clone(),
                    backend_error.clone(),
                );
                let outcome = UpstreamHttp3ExecutionOutcome::fallback_to_reqwest(
                    authority,
                    attempt_plan,
                    backend_error.clone(),
                );
                return Some(Err(outcome));
            }
        };

        let backend = upstream_h3::default_http3_backend();
        let attempt_plan = upstream_h3::preflight_request_for_http3(&request).into_attempt_plan();
        match backend
            .execute_request_streaming_response(&self.dns_resolver, &request)
            .await
        {
            Ok(response) => Some(Ok(response)),
            Err(error) => {
                let outcome = UpstreamHttp3ExecutionOutcome::fallback_to_reqwest(
                    authority,
                    attempt_plan,
                    error.clone(),
                );
                Some(Err(outcome))
            }
        }
    }

    // H1 active H3 streaming intentionally has no writer-plan guard here.
    // A guard that opens an upstream H3 stream without a downstream byte pump
    // can duplicate safe requests when the H1 path falls back to reqwest.
    // H2 active H3 streaming owns its byte pump in `mitm_h2.rs`.

    /// Builds the RelayGate-owned HTTP/3 request model from the already prepared
    /// MITM request fields.
    ///
    /// This is still only a model seam. It mirrors the current reqwest outbound
    /// header shaping for empty-body GET/HEAD requests, but it is not wired into
    /// active forwarding yet.
    #[allow(dead_code)]
    pub(crate) fn build_http3_request_from_mitm_parts(
        &self,
        method: &str,
        target_url: &str,
        authority: &str,
        headers: &[(String, String)],
        request_effects: &[RuleEffect],
    ) -> Result<RelayUpstreamRequest, RelayUpstreamRequestBuildError> {
        let rewrite_headers = request_effects
            .iter()
            .filter_map(|effect| {
                if let RuleEffect::RewriteHeader { name, value } = effect {
                    Some((name.clone(), value.clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        RelayUpstreamRequest::empty_get_head_from_mitm_parts(
            method,
            target_url,
            authority,
            headers,
            rewrite_headers,
            crate::proxy::mount_forward::relaygate_body_pipeline_accept_encoding(),
        )
    }

    fn connection_plan(
        &self,
        intent: &MitmUpstreamRequestIntent,
        allow_invalid_certs: bool,
    ) -> Result<MitmUpstreamConnectionPlan> {
        let upstream_address = if let Some(upstream_id) = intent.upstream_id.as_deref() {
            let registry = self
                .upstreams
                .read()
                .map_err(|_| anyhow::anyhow!("upstream registry lock poisoned"))?;
            Some(
                registry
                    .resolve(upstream_id)
                    .with_context(|| {
                        format!("MITM request references missing upstream `{upstream_id}`")
                    })?
                    .address
                    .clone(),
            )
        } else {
            None
        };

        Ok(MitmUpstreamConnectionPlan {
            upstream_address,
            allow_invalid_certs,
            protocol_policy: intent.protocol_policy,
        })
    }

    fn client_for_plan(&self, plan: &MitmUpstreamConnectionPlan) -> Result<Client> {
        let cache_key = plan.cache_key();
        if let Some(client) = self
            .http_client_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("failed to acquire MITM HTTP client cache lock"))?
            .get(&cache_key)
            .cloned()
        {
            return Ok(client);
        }

        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(MITM_REQWEST_CONNECT_TIMEOUT)
            .dns_resolver(Arc::new(ReqwestDnsResolver::new(self.dns_resolver.clone())));
        if plan.allow_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }

        builder = match plan.protocol_policy {
            MitmUpstreamProtocolPolicy::Auto => builder,
            MitmUpstreamProtocolPolicy::Http1Only => builder.http1_only(),
            MitmUpstreamProtocolPolicy::Http2PriorKnowledge => builder.http2_prior_knowledge(),
        };

        if let Some(upstream_address) = &plan.upstream_address {
            builder = builder.proxy(reqwest::Proxy::all(upstream_address)?);
        }

        let client = builder.build()?;
        self.http_client_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("failed to acquire MITM HTTP client cache lock"))?
            .insert(cache_key, client.clone());
        Ok(client)
    }
}
