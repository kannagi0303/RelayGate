use anyhow::{Context, Result};
use axum::http::Uri;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client, Proxy,
};
use tracing::info;

use crate::{
    adblock::{self, SharedAdblockState},
    config::MountSiteConfig,
    dns::{ReqwestDnsResolver, SharedDnsResolver},
    gateway::fetch,
    proxy::{
        body_classification::should_treat_response_body_as_html,
        header_hop::is_relaygate_owned_request_header,
        mitm_inject::{apply_relaygate_csp_headers, inject_relaygate_document},
        rules::RuleEffect,
        upstream::SharedUpstreamRegistry,
    },
    rewrite::SharedRewriteRegistry,
    user_script::SharedUserScriptRegistry,
};

pub(crate) fn build_gateway_request_headers(
    mount: &MountSiteConfig,
    request_headers: &[(String, String)],
    uri: &Uri,
) -> Vec<(String, String)> {
    let origin = mount.target_base_url.trim_end_matches('/');
    let mount_prefix = mount.mount_path.trim_end_matches('/');
    let mut headers = Vec::new();

    for (name, value) in request_headers {
        if !fetch::should_forward_request_header(name) {
            continue;
        }

        let rewritten_value = if mount.passthrough_mode {
            value.to_string()
        } else {
            fetch::rewrite_request_header_value(name, value, origin, mount_prefix)
        };
        headers.push((name.clone(), rewritten_value));
    }

    if let Some(host) = uri.host() {
        let host_value = match uri.port_u16() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        upsert_header(&mut headers, "Host", &host_value);
    }

    headers
}

pub(crate) fn build_gateway_http_client(
    upstreams: &SharedUpstreamRegistry,
    dns_resolver: &SharedDnsResolver,
    upstream_id: Option<&str>,
) -> Result<Client> {
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(ReqwestDnsResolver::new(
            dns_resolver.clone(),
        )));

    if let Some(upstream_id) = upstream_id {
        let registry = upstreams
            .read()
            .map_err(|_| anyhow::anyhow!("upstream registry lock poisoned"))?;
        let upstream = registry
            .resolve(upstream_id)
            .with_context(|| format!("upstream `{upstream_id}` not found or disabled"))?;
        builder = builder.proxy(Proxy::all(&upstream.address)?);
    }

    Ok(builder.build()?)
}

pub(crate) fn should_forward_gateway_header(name: &str) -> bool {
    !is_relaygate_owned_request_header(name)
        && !matches!(
            name.to_ascii_lowercase().as_str(),
            "host" | "accept-encoding"
        )
}

pub(crate) fn relaygate_body_pipeline_accept_encoding() -> &'static str {
    "identity"
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

pub(crate) fn apply_site_specific_gateway_rewrite(
    rewrite_registry: &SharedRewriteRegistry,
    adblock_state: &SharedAdblockState,
    target_url: &str,
    source_url: &str,
    request_type: &str,
    fetch_site: Option<&str>,
    user_script_registry: &SharedUserScriptRegistry,
    response_headers: &mut HeaderMap,
    response_body: Vec<u8>,
) -> Result<Vec<u8>> {
    let content_type = response_headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let content_type_lower = content_type
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    let patch_result = {
        let registry = rewrite_registry
            .read()
            .map_err(|_| anyhow::anyhow!("rewrite registry lock poisoned"))?;
        registry.apply_patch_rules(&response_body, target_url, &content_type_lower)?
    };
    let mut response_body = patch_result.body;
    if patch_result.modified {
        remove_mutated_body_metadata_headers(response_headers);
    }

    if !should_treat_response_body_as_html(request_type, &content_type_lower, &response_body) {
        return Ok(response_body);
    }

    let render_result = {
        let registry = rewrite_registry
            .read()
            .map_err(|_| anyhow::anyhow!("rewrite registry lock poisoned"))?;
        registry.apply_matching_rule(&response_body, target_url)?
    };
    let csp_directives = adblock::csp_directives_for_request(
        adblock_state,
        target_url,
        source_url,
        request_type,
        fetch_site,
    )?;

    let (rewritten, injected) = if render_result.matched && !render_result.allow_adblock_injection {
        (render_result.body, false)
    } else {
        let injection = inject_relaygate_document(
            target_url,
            render_result.body,
            content_type.as_deref(),
            adblock_state,
            user_script_registry,
            if request_type == "subdocument" {
                Some(true)
            } else {
                Some(false)
            },
        );
        let injected = injection.injected();
        (injection.body, injected)
    };
    response_body = rewritten;

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

    Ok(response_body)
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

pub(crate) fn apply_response_effects_with_metadata_cleanup(
    response_body: Vec<u8>,
    response_effects: &[RuleEffect],
    response_headers: &mut HeaderMap,
) -> Vec<u8> {
    let rewritten = apply_response_effects(response_body.clone(), response_effects);
    if rewritten != response_body {
        remove_mutated_body_metadata_headers(response_headers);
    }
    rewritten
}

pub(crate) fn passthrough_response_headers(
    headers: &HeaderMap,
    body_len: usize,
) -> Vec<(String, String)> {
    let mut result = Vec::new();

    for (name, value) in headers {
        let name_text = name.as_str().to_string();
        let lower = name_text.to_ascii_lowercase();

        if matches!(
            lower.as_str(),
            "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }

        if let Ok(value_text) = value.to_str() {
            result.push((name_text, value_text.to_string()));
        }
    }

    result.push(("Content-Length".to_string(), body_len.to_string()));
    result.push(("Connection".to_string(), "close".to_string()));
    result
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

pub(crate) fn remove_body_encoding_headers(headers: &mut HeaderMap) {
    headers.remove("content-encoding");
    headers.remove("content-length");
    headers.remove("transfer-encoding");
}

pub(crate) fn remove_mutated_body_metadata_headers(headers: &mut HeaderMap) {
    remove_body_encoding_headers(headers);

    // Validators, digests, and range metadata describe the origin's original
    // representation. Once RelayGate rewrites, patches, or injects into the
    // body, keeping them would let browsers/caches validate or assemble bytes
    // that no longer match the forwarded representation. Keep this helper
    // centralized so every body-mutating pipeline strips the same metadata.
    headers.remove("accept-ranges");
    headers.remove("content-md5");
    headers.remove("content-range");
    headers.remove("digest");
    headers.remove("content-digest");
    headers.remove("etag");
    headers.remove("last-modified");
    headers.remove("repr-digest");
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
