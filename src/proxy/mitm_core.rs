use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_RANGE, CONTENT_TYPE};
use tracing::debug;

use crate::{
    adblock::{self, SharedAdblockState},
    config::RelayGateConfig,
    proxy::{
        body_classification::{
            response_headers_are_html_like, response_is_partial_content,
            should_treat_response_body_as_html,
        },
        mitm_http::apply_response_effects,
        mitm_inject::{apply_relaygate_csp_headers, inject_relaygate_document},
        mitm_upstream::{MitmUpstreamProtocolPolicy, MitmUpstreamRequestIntent},
        mount_forward::remove_mutated_body_metadata_headers,
        pipeline::PipelineRoute,
        resource_replace::SharedResourceReplaceRegistry,
        rules::{RuleEffect, RuleEngine, RuleRequestContext},
        upstream::SharedUpstreamRegistry,
    },
    rewrite::SharedRewriteRegistry,
    traffic::SharedTrafficState,
    user_script::{self, SharedUserScriptRegistry},
};

/// Shared MITM request-side state used by downstream protocol adapters.
///
/// This module intentionally stops before any HTTP/1.1 or HTTP/2 framing work.
/// It evaluates RelayGate's existing request features and returns a protocol-neutral
/// decision that the downstream adapter can encode as H1 bytes, H2 frames, or a
/// future H3 response.
pub(crate) struct MitmRequestState<'a> {
    pub(crate) rules: &'a RuleEngine,
    pub(crate) upstreams: &'a SharedUpstreamRegistry,
    pub(crate) resource_replace_registry: &'a SharedResourceReplaceRegistry,
    pub(crate) adblock_state: &'a SharedAdblockState,
    pub(crate) traffic_state: &'a SharedTrafficState,
    pub(crate) upstream_protocol_policy: MitmUpstreamProtocolPolicy,
}

/// Shared MITM response-side state used by downstream protocol adapters.
///
/// Response body mutation decisions live here so H1, H2, and future H3 adapters
/// can reuse RelayGate's existing rewrite, patch, adblock injection, and response
/// body rule behavior without duplicating protocol writer code.
pub(crate) struct MitmResponseState<'a> {
    pub(crate) config: &'a RelayGateConfig,
    pub(crate) rewrite_registry: &'a SharedRewriteRegistry,
    pub(crate) adblock_state: &'a SharedAdblockState,
    pub(crate) user_script_registry: &'a SharedUserScriptRegistry,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MitmRewritePerfStats {
    pub(crate) patch_ms: u128,
    pub(crate) render_ms: u128,
    pub(crate) adblock_injection_ms: u128,
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessedMitmResponseBody {
    pub(crate) body: Vec<u8>,
    pub(crate) rewrite_perf: MitmRewritePerfStats,
}

#[derive(Debug, Clone)]
pub(crate) enum MitmRequestDecision {
    Continue(PreparedMitmRequest),
    Respond {
        response: MitmLocalResponse,
        reason: &'static str,
    },
    Close {
        reason: &'static str,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedMitmRequest {
    pub(crate) target_url: String,
    pub(crate) method: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) request_effects: Vec<RuleEffect>,
    pub(crate) request_type: String,
    pub(crate) source_url: String,
    pub(crate) fetch_site: Option<String>,
    pub(crate) upstream: MitmUpstreamRequestIntent,
    pub(crate) traffic_host: String,
    pub(crate) observe_traffic: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct MitmLocalResponse {
    pub(crate) status_code: u16,
    pub(crate) reason_phrase: &'static str,
    pub(crate) content_type: String,
    pub(crate) body: Vec<u8>,
}

impl MitmLocalResponse {
    pub(crate) fn text(status_code: u16, reason_phrase: &'static str, body: &str) -> Self {
        Self {
            status_code,
            reason_phrase,
            content_type: "text/plain; charset=utf-8".to_string(),
            body: body.as_bytes().to_vec(),
        }
    }

    pub(crate) fn with_content_type(
        status_code: u16,
        reason_phrase: &'static str,
        content_type: impl Into<String>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            status_code,
            reason_phrase,
            content_type: content_type.into(),
            body: body.into(),
        }
    }
}

pub(crate) fn prepare_mitm_request(
    state: &MitmRequestState<'_>,
    host: &str,
    target_url: String,
    method: String,
    headers: Vec<(String, String)>,
) -> Result<MitmRequestDecision> {
    let request_context = RuleRequestContext {
        host: Some(host.to_string()),
        url: target_url.clone(),
        method: method.clone(),
        headers: headers.clone(),
    };

    let request_decision = state.rules.evaluate_request(&request_context);
    debug!(?request_decision, "MITM request rule decision");

    if request_decision
        .effects
        .iter()
        .any(|effect| matches!(effect, RuleEffect::Block))
    {
        return Ok(MitmRequestDecision::Respond {
            response: MitmLocalResponse::text(
                403,
                "Forbidden",
                "Blocked by RelayGate MITM request rule.",
            ),
            reason: "request_rule_block",
        });
    }

    let request_type = adblock::classify_request_type(&method, &headers).to_string();
    let source_url = adblock::source_url_for_request(&target_url, &headers);
    let fetch_site = adblock::fetch_site_for_request(&headers);

    if request_type != "websocket" {
        let replacement = state
            .resource_replace_registry
            .read()
            .map_err(|_| anyhow::anyhow!("resource replacement registry lock poisoned"))?
            .find_replacement(&target_url, &source_url);
        if let Some(replacement) = replacement {
            debug!(
                rule = replacement.rule_id,
                url = %target_url,
                "resource replacement matched HTTPS MITM request"
            );
            return Ok(MitmRequestDecision::Respond {
                response: MitmLocalResponse::with_content_type(
                    replacement.status,
                    status_reason(replacement.status),
                    replacement.content_type,
                    replacement.body,
                ),
                reason: "resource_replacement",
            });
        }
    }

    let adblock_match = adblock::check_url(
        state.adblock_state,
        &target_url,
        &source_url,
        &request_type,
        fetch_site.as_deref(),
    )?;
    if request_type != "websocket" {
        if let Some(redirect) = adblock_match.redirect.as_ref() {
            return Ok(MitmRequestDecision::Respond {
                response: MitmLocalResponse::with_content_type(
                    200,
                    "OK",
                    redirect.content_type.clone(),
                    redirect.body.clone(),
                ),
                reason: "adblock_redirect",
            });
        }
    }
    if adblock_match.matched {
        if should_abort_adblock_request(&adblock_match.request_type) {
            return Ok(MitmRequestDecision::Close {
                reason: "adblock_blocked",
            });
        }

        return Ok(MitmRequestDecision::Respond {
            response: MitmLocalResponse::text(403, "Forbidden", "Blocked by RelayGate adblock."),
            reason: "adblock_blocked",
        });
    }

    let upstream_id = request_decision
        .effects
        .iter()
        .find_map(|effect| match effect {
            RuleEffect::UseUpstream { upstream_id } => Some(upstream_id.clone()),
            _ => None,
        })
        .or_else(|| resolve_route_upstream_id(state.upstreams, host));
    let traffic_host = normalize_request_host(host);
    let observe_traffic = state.traffic_state.is_controlled_host(&traffic_host)
        && method.eq_ignore_ascii_case("GET")
        && request_type == "document";

    Ok(MitmRequestDecision::Continue(PreparedMitmRequest {
        target_url,
        method,
        headers,
        request_effects: request_decision.effects,
        request_type,
        source_url,
        fetch_site,
        upstream: MitmUpstreamRequestIntent::new(upstream_id, state.upstream_protocol_policy),
        traffic_host,
        observe_traffic,
    }))
}

pub(crate) fn mitm_response_pipeline_decision(
    state: &MitmResponseState<'_>,
    target_url: &str,
    request_type: &str,
    status_code: u16,
    response_headers: &HeaderMap,
    response_effects: &[RuleEffect],
) -> PipelineRoute {
    if response_is_partial_content(status_code, response_headers.contains_key(CONTENT_RANGE)) {
        return PipelineRoute::fast_path("partial_content_passthrough");
    }

    if state.config.disable_mitm_fast_path {
        return PipelineRoute::deep_path("mitm_fast_path_disabled");
    }

    if state.config.logging.log_response_body {
        return PipelineRoute::deep_path("logging_response_body_enabled");
    }

    if response_effects
        .iter()
        .any(|effect| matches!(effect, RuleEffect::RewriteResponseBody { .. }))
    {
        return PipelineRoute::deep_path("response_rule_rewrite_body");
    }

    let content_type = response_content_type_lower(response_headers);
    let is_document = matches!(request_type, "document" | "subdocument");
    let html_like = response_headers_are_html_like(request_type, &content_type);

    if html_like
        && (adblock::is_enabled(state.adblock_state)
            || user_script::has_enabled_scripts(state.user_script_registry))
    {
        return PipelineRoute::deep_path(if is_document {
            "document_html_injection"
        } else {
            "html_response_injection"
        });
    }

    match state.rewrite_registry.read() {
        Ok(registry) => {
            if html_like && registry.has_render_rule_match(target_url) {
                return PipelineRoute::deep_path("site_render_rule_match");
            }

            if registry.has_patch_rule_match(target_url, &content_type) {
                return PipelineRoute::deep_path("site_patch_rule_match");
            }

            PipelineRoute::fast_path("no_response_body_pipeline_match")
        }
        Err(_) => PipelineRoute::deep_path("rewrite_registry_lock_failed_fail_safe"),
    }
}

pub(crate) fn response_effects_require_response_body_pipeline(
    response_effects: &[RuleEffect],
) -> bool {
    response_effects
        .iter()
        .any(|effect| matches!(effect, RuleEffect::RewriteResponseBody { .. }))
}

/// Returns a reason to keep a request off speculative active H3 streaming before
/// response headers are available.
///
/// This is a capability gate, not a document-type ban. It should only return a
/// reason when RelayGate already knows from URL, request type, enabled features,
/// or response-rule preview that the eventual response may need the body
/// pipeline. The post-header pipeline decision remains authoritative once
/// Content-Type and status are known.
pub(crate) fn response_body_pipeline_preflight_reason(
    state: &MitmResponseState<'_>,
    target_url: &str,
    request_type: &str,
    response_effects: &[RuleEffect],
) -> Option<&'static str> {
    if response_effects_require_response_body_pipeline(response_effects) {
        return Some("response_rule_body_pipeline_required");
    }

    if state.config.logging.log_response_body {
        return Some("logging_response_body_enabled");
    }

    let document_like = matches!(request_type, "document" | "subdocument");
    if document_like && adblock::may_render_document_injection(state.adblock_state, target_url) {
        return Some("document_adblock_injection_possible");
    }

    let is_frame = (request_type == "subdocument").then_some(true);
    if document_like
        && user_script::has_enabled_script_match(state.user_script_registry, target_url, is_frame)
    {
        return Some("document_userscript_injection_possible");
    }

    match state.rewrite_registry.read() {
        Ok(registry) => {
            if registry.has_render_rule_match(target_url) {
                return Some("site_render_rule_match_possible_before_headers");
            }

            if registry.has_patch_rule_match(target_url, "text/html") {
                return Some("site_html_patch_rule_match_possible_before_headers");
            }

            if registry.has_patch_rule_match(target_url, "application/json") {
                return Some("site_json_patch_rule_match_possible_before_headers");
            }

            None
        }
        Err(_) => Some("rewrite_registry_lock_failed_fail_safe"),
    }
}

pub(crate) fn process_mitm_response_body(
    state: &MitmResponseState<'_>,
    target_url: &str,
    source_url: &str,
    request_type: &str,
    fetch_site: Option<&str>,
    response_headers: &mut HeaderMap,
    response_body: Vec<u8>,
    response_effects: &[RuleEffect],
) -> Result<ProcessedMitmResponseBody> {
    let rewritten_response_body = apply_response_effects(response_body.clone(), response_effects);
    if rewritten_response_body != response_body {
        remove_mutated_body_metadata_headers(response_headers);
    }

    let (body, rewrite_perf) = apply_site_specific_response_rewrite(
        state,
        target_url,
        source_url,
        request_type,
        fetch_site,
        response_headers,
        rewritten_response_body,
    )?;

    Ok(ProcessedMitmResponseBody { body, rewrite_perf })
}

/// Requests that carry browser storage-access semantics can be tied to
/// one-time security/challenge state. Active H3 probing may duplicate the
/// request before the stable path sees it, which can invalidate those tokens.
/// Keep these on the stable path without matching any specific site.
///
/// Guardrail intent: this is a generic browser-semantics gate, not a Cloudflare
/// or domain-specific workaround. A future H3 implementation may revisit it if
/// it can avoid speculative duplicate/alternate-path requests and still pass
/// security/challenge flows.
pub(crate) fn has_browser_storage_access_header(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("sec-fetch-storage-access"))
}

pub(crate) fn allow_active_h3_buffered_for_request(
    state: &MitmResponseState<'_>,
    request_type: &str,
    body_pipeline_preflight_reason: Option<&'static str>,
) -> bool {
    if state.config.disable_mitm_fast_path {
        return false;
    }

    if !matches!(request_type, "document" | "subdocument") {
        return false;
    }

    // Keep the buffered and streaming active-H3 gates on the same capability
    // preflight. The buffered probe can serve only responses that do not require
    // RelayGate body processing; otherwise a failed/truncated H3 attempt would
    // fall back to reqwest and create a second upstream request. The final
    // post-header pipeline decision still remains authoritative after status,
    // Content-Type, and response rules are known.
    body_pipeline_preflight_reason.is_none()
}

fn apply_site_specific_response_rewrite(
    state: &MitmResponseState<'_>,
    target_url: &str,
    source_url: &str,
    request_type: &str,
    fetch_site: Option<&str>,
    response_headers: &mut HeaderMap,
    response_body: Vec<u8>,
) -> Result<(Vec<u8>, MitmRewritePerfStats)> {
    let mut perf = MitmRewritePerfStats::default();
    let content_type = response_headers
        .get(CONTENT_TYPE)
        .and_then(|value: &HeaderValue| value.to_str().ok())
        .map(|value| value.to_string());
    let content_type_lower = content_type
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    let patch_started_at = std::time::Instant::now();
    let patch_result = {
        let registry = state
            .rewrite_registry
            .read()
            .map_err(|_| anyhow::anyhow!("rewrite registry lock poisoned"))?;
        registry.apply_patch_rules(&response_body, target_url, &content_type_lower)?
    };
    perf.patch_ms = patch_started_at.elapsed().as_millis();
    let response_body = patch_result.body;
    if patch_result.modified {
        remove_mutated_body_metadata_headers(response_headers);
    }

    if !should_treat_response_body_as_html(request_type, &content_type_lower, &response_body) {
        return Ok((response_body, perf));
    }

    let render_started_at = std::time::Instant::now();
    let render_result = {
        let registry = state
            .rewrite_registry
            .read()
            .map_err(|_| anyhow::anyhow!("rewrite registry lock poisoned"))?;
        registry.apply_matching_rule(&response_body, target_url)?
    };
    perf.render_ms = render_started_at.elapsed().as_millis();
    let csp_directives = adblock::csp_directives_for_request(
        state.adblock_state,
        target_url,
        source_url,
        request_type,
        fetch_site,
    )?;
    let inject_started_at = std::time::Instant::now();
    let (rewritten, injected) = if render_result.matched && !render_result.allow_adblock_injection {
        (render_result.body, false)
    } else {
        let injection = inject_relaygate_document(
            target_url,
            render_result.body,
            content_type.as_deref(),
            state.adblock_state,
            state.user_script_registry,
            if request_type == "subdocument" {
                Some(true)
            } else {
                Some(false)
            },
        );
        let injected = injection.injected();
        (injection.body, injected)
    };
    perf.adblock_injection_ms = inject_started_at.elapsed().as_millis();

    if patch_result.modified || render_result.matched || injected {
        remove_mutated_body_metadata_headers(response_headers);
    }

    if render_result.matched || patch_result.modified {
        response_headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
    }

    apply_relaygate_csp_headers(response_headers, csp_directives, injected)?;

    Ok((rewritten, perf))
}

fn response_content_type_lower(headers: &HeaderMap) -> String {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value: &HeaderValue| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn resolve_route_upstream_id(upstreams: &SharedUpstreamRegistry, host: &str) -> Option<String> {
    upstreams.read().ok().and_then(|registry| {
        registry
            .resolve_route_for_host(host)
            .map(|route| route.upstream_id.clone())
    })
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

fn should_abort_adblock_request(request_type: &str) -> bool {
    !matches!(request_type, "document" | "subdocument")
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "OK",
    }
}
