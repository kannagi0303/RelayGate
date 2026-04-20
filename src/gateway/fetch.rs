use anyhow::{Context, Result};
use reqwest::{header::HeaderMap as ReqwestHeaderMap, Client, Proxy, StatusCode};
use tracing::info;

use crate::{
    config::{MountSiteConfig, UpstreamConfig},
    gateway::rewrite,
};

/// Response wrapper for gateway mode.
/// When a user visits a local mount path such as `/sukebei/...`,
/// RelayGate fetches the remote site and builds the final browser response here.
#[derive(Debug, Clone)]
pub struct GatewayResponse {
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Fetch remote site content from a site mount config.
pub async fn fetch_mount(
    mount: &MountSiteConfig,
    request_method: &str,
    request_path: &str,
    request_headers: &[(String, String)],
    request_body: &[u8],
    upstreams: &[UpstreamConfig],
    log_response_body_enabled: bool,
) -> Result<GatewayResponse> {
    let target_url = build_target_url(mount, request_path)?;
    let origin = mount.target_base_url.trim_end_matches('/');
    let mount_prefix = mount.mount_path.trim_end_matches('/');
    let client = build_client(mount, upstreams)?;
    let method = reqwest::Method::from_bytes(request_method.as_bytes())
        .with_context(|| format!("unsupported method for gateway fetch: {request_method}"))?;

    let mut outbound = client.request(method, &target_url);

    // Forward only a small set of headers that help page rendering and avoid leaking local proxy semantics upstream.
    for (name, value) in request_headers {
        if should_forward_request_header(name) {
            let rewritten_value = if mount.passthrough_mode {
                value.to_string()
            } else {
                rewrite_request_header_value(name, value, origin, mount_prefix)
            };
            outbound = outbound.header(name, rewritten_value);
        }
    }

    if !request_body.is_empty() {
        outbound = outbound.body(request_body.to_vec());
    }

    let response = outbound.send().await?;
    let status = response.status();
    let reason = canonical_reason(status);
    let headers = response.headers().clone();
    let body = response.bytes().await?.to_vec();

    let content_type = header_value(&headers, "content-type");
    let body = if mount.passthrough_mode {
        body
    } else if is_html_content(content_type.as_deref()) {
        if let Some(minimal_mode) = &mount.minimal_page_mode {
            rewrite::rewrite_minimal_page(&body, mount, minimal_mode, &target_url)?
        } else if mount.rewrite_links {
            rewrite::rewrite_html_links(&body, mount)?
        } else {
            body
        }
    } else {
        body
    };

    if log_response_body_enabled {
        log_response_body("gateway", &target_url, content_type.as_deref(), &body);
    }

    let rewritten_headers = if mount.passthrough_mode {
        passthrough_response_headers(&headers, body.len())
    } else {
        rewrite_response_headers(&headers, mount, body.len())
    };

    Ok(GatewayResponse {
        status_code: status.as_u16(),
        reason_phrase: reason,
        headers: rewritten_headers,
        body,
    })
}

fn build_target_url(mount: &MountSiteConfig, request_path: &str) -> Result<String> {
    let mount_prefix = mount.mount_path.trim_end_matches('/');
    let target_base = mount.target_base_url.trim_end_matches('/');
    let suffix = request_path
        .strip_prefix(mount_prefix)
        .unwrap_or(request_path);

    if suffix.is_empty() || suffix == "/" {
        return Ok(format!("{target_base}/"));
    }

    Ok(format!("{target_base}{suffix}"))
}

fn build_client(mount: &MountSiteConfig, upstreams: &[UpstreamConfig]) -> Result<Client> {
    let mut builder = Client::builder().redirect(reqwest::redirect::Policy::none());

    if let Some(upstream_id) = &mount.upstream_id {
        let upstream = upstreams
            .iter()
            .find(|item| item.enabled && item.id.eq_ignore_ascii_case(upstream_id))
            .with_context(|| {
                format!("gateway mount references missing upstream `{upstream_id}`")
            })?;

        builder = builder.proxy(Proxy::all(&upstream.address)?);
    }

    Ok(builder.build()?)
}

fn should_forward_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "user-agent"
            | "accept"
            | "accept-language"
            | "accept-encoding"
            | "cookie"
            | "referer"
            | "origin"
            | "content-type"
    )
}

fn rewrite_response_headers(
    headers: &ReqwestHeaderMap,
    mount: &MountSiteConfig,
    body_len: usize,
) -> Vec<(String, String)> {
    let mut result = Vec::new();

    for (name, value) in headers {
        let name_text = name.as_str().to_string();
        let lower = name_text.to_ascii_lowercase();

        if matches!(
            lower.as_str(),
            "content-length" | "transfer-encoding" | "content-encoding"
        ) {
            continue;
        }

        if let Ok(value_text) = value.to_str() {
            let rewritten_value = match lower.as_str() {
                "location" => rewrite::rewrite_location_header(value_text, mount),
                "set-cookie" => rewrite::rewrite_set_cookie_header(value_text, mount),
                _ => value_text.to_string(),
            };

            result.push((name_text, rewritten_value));
        }
    }

    result.push(("Content-Length".to_string(), body_len.to_string()));
    result.push(("Connection".to_string(), "close".to_string()));
    result
}

fn passthrough_response_headers(
    headers: &ReqwestHeaderMap,
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

fn header_value(headers: &ReqwestHeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

fn is_html_content(content_type: Option<&str>) -> bool {
    content_type
        .map(|value| value.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

fn canonical_reason(status: StatusCode) -> String {
    status.canonical_reason().unwrap_or("OK").to_string()
}

fn log_response_body(source: &str, url: &str, content_type: Option<&str>, body: &[u8]) {
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

fn rewrite_request_header_value(
    name: &str,
    value: &str,
    origin: &str,
    mount_prefix: &str,
) -> String {
    match name.to_ascii_lowercase().as_str() {
        "referer" => rewrite_outbound_url(value, origin, mount_prefix),
        "origin" => rewrite_outbound_origin(value, origin, mount_prefix),
        _ => value.to_string(),
    }
}

fn rewrite_outbound_url(value: &str, origin: &str, mount_prefix: &str) -> String {
    if let Some(suffix) = value.strip_prefix(mount_prefix) {
        return format!("{origin}{suffix}");
    }

    value.to_string()
}

fn rewrite_outbound_origin(value: &str, origin: &str, mount_prefix: &str) -> String {
    if value.starts_with("http://127.0.0.1:8787") || value.starts_with("https://127.0.0.1:8787") {
        return origin.to_string();
    }

    if value.starts_with(mount_prefix) {
        return origin.to_string();
    }

    value.to_string()
}
