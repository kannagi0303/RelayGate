use anyhow::Result;
use tracing::debug;

use crate::{
    adblock::{self, SharedAdblockState},
    proxy::{
        header_hop::should_apply_request_header_rewrite,
        http_parse::ParsedHttpRequest,
        local_response::{
            resource_replacement_response_bytes, should_abort_adblock_request,
            simple_response_bytes, simple_response_bytes_with_content_type,
        },
        resource_replace::SharedResourceReplaceRegistry,
        rules::{RuleEffect, RuleEngine, RuleRequestContext},
        upstream::SharedUpstreamRegistry,
    },
    traffic::SharedTrafficState,
};

#[derive(Clone)]
pub(crate) struct OutboundRequestState {
    pub(crate) rules: RuleEngine,
    pub(crate) upstreams: SharedUpstreamRegistry,
    pub(crate) resource_replace_registry: SharedResourceReplaceRegistry,
    pub(crate) adblock_state: SharedAdblockState,
    pub(crate) traffic_state: SharedTrafficState,
}

pub(crate) enum OutboundRequestDecision {
    Continue(PreparedOutboundRequest),
    Respond(Vec<u8>),
    Close,
}

pub(crate) struct PreparedOutboundRequest {
    pub(crate) target_url: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) request_effects: Vec<RuleEffect>,
    pub(crate) request_type: String,
    pub(crate) source_url: String,
    pub(crate) fetch_site: Option<String>,
    pub(crate) upstream_id: Option<String>,
    pub(crate) traffic_host: String,
    pub(crate) observe_traffic: bool,
}

pub(crate) fn prepare_outbound_request(
    state: &OutboundRequestState,
    request: &ParsedHttpRequest,
    target_url: String,
    host: Option<String>,
    mut headers: Vec<(String, String)>,
    explicit_upstream_id: Option<String>,
    decision_log: &str,
    block_message: &str,
    resource_log: &str,
) -> Result<OutboundRequestDecision> {
    let request_context = RuleRequestContext {
        host,
        url: target_url.clone(),
        method: request.method.clone(),
        headers: headers.clone(),
    };
    let request_decision = state.rules.evaluate_request(&request_context);
    debug!(?request_decision, "{decision_log}");

    if request_decision
        .effects
        .iter()
        .any(|effect| matches!(effect, RuleEffect::Block))
    {
        return Ok(OutboundRequestDecision::Respond(simple_response_bytes(
            403,
            "Forbidden",
            block_message,
        )));
    }

    for effect in &request_decision.effects {
        if let RuleEffect::RewriteHeader { name, value } = effect {
            if should_apply_request_header_rewrite(name) {
                upsert_header(&mut headers, name, value);
            }
        }
    }

    let request_type = adblock::classify_request_type(&request.method, &headers).to_string();
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
                "{resource_log}"
            );
            return Ok(OutboundRequestDecision::Respond(
                resource_replacement_response_bytes(&replacement),
            ));
        }
    }

    let adblock_match = adblock::check_url(
        &state.adblock_state,
        &target_url,
        &source_url,
        &request_type,
        fetch_site.as_deref(),
    )?;
    if request_type != "websocket" {
        if let Some(redirect) = adblock_match.redirect.as_ref() {
            return Ok(OutboundRequestDecision::Respond(
                simple_response_bytes_with_content_type(
                    200,
                    "OK",
                    &redirect.content_type,
                    &redirect.body,
                ),
            ));
        }
    }
    if adblock_match.matched {
        if should_abort_adblock_request(&adblock_match.request_type) {
            return Ok(OutboundRequestDecision::Close);
        }

        return Ok(OutboundRequestDecision::Respond(simple_response_bytes(
            403,
            "Forbidden",
            "Blocked by RelayGate adblock.",
        )));
    }

    let upstream_id = request_decision
        .effects
        .iter()
        .find_map(|effect| match effect {
            RuleEffect::UseUpstream { upstream_id } => Some(upstream_id.clone()),
            _ => None,
        })
        .or(explicit_upstream_id)
        .or_else(|| {
            request_context
                .host
                .as_deref()
                .and_then(|host| resolve_route_upstream_id(&state.upstreams, host))
        });
    let traffic_host = normalize_request_host(request_context.host.as_deref().unwrap_or("unknown"));
    let observe_traffic = state.traffic_state.is_controlled_host(&traffic_host)
        && request.method.eq_ignore_ascii_case("GET")
        && request_type == "document";

    Ok(OutboundRequestDecision::Continue(PreparedOutboundRequest {
        target_url,
        headers,
        request_effects: request_decision.effects,
        request_type,
        source_url,
        fetch_site,
        upstream_id,
        traffic_host,
        observe_traffic,
    }))
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
