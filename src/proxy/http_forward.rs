use anyhow::{Context, Result};
use axum::http::Uri;

use crate::proxy::{
    header_hop::{remove_hop_by_hop_request_headers, should_apply_request_header_rewrite},
    http_parse::ParsedHttpRequest,
    rules::RuleEffect,
    upstream::SharedUpstreamRegistry,
};

pub(crate) fn build_target_url(uri: &Uri, headers: &[(String, String)]) -> Result<String> {
    if let Some(scheme) = uri.scheme_str() {
        if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
            return Ok(uri.to_string());
        }
    }

    let host =
        extract_host_from_pairs(headers).context("missing Host header for proxied HTTP request")?;
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    Ok(format!("http://{host}{path}"))
}

pub(crate) fn resolve_forward_target(
    upstreams: &SharedUpstreamRegistry,
    uri: &Uri,
    upstream_id: Option<&str>,
) -> Result<String> {
    if let Some(upstream_id) = upstream_id {
        let registry = upstreams
            .read()
            .map_err(|_| anyhow::anyhow!("upstream registry lock poisoned"))?;
        let upstream = registry
            .resolve(upstream_id)
            .with_context(|| format!("upstream `{upstream_id}` not found or disabled"))?;

        let upstream_uri = upstream.address.parse::<Uri>()?;
        let host = upstream_uri
            .host()
            .context("configured upstream proxy is missing host")?;
        let port = upstream_uri.port_u16().unwrap_or(80);
        return Ok(format!("{host}:{port}"));
    }

    let host = uri.host().context("target URI is missing host")?;
    let port = uri.port_u16().unwrap_or(80);
    Ok(format!("{host}:{port}"))
}

#[cfg(test)]
pub(crate) fn build_upstream_request(
    request: &ParsedHttpRequest,
    uri: &Uri,
    effects: &[RuleEffect],
    upstream_id: Option<&str>,
    upgrade: Option<&str>,
    keep_alive: bool,
) -> Result<Vec<u8>> {
    build_upstream_request_with_body_len(
        request,
        uri,
        effects,
        upstream_id,
        upgrade,
        keep_alive,
        None,
    )
}

pub(crate) fn build_upstream_request_with_body_len(
    request: &ParsedHttpRequest,
    uri: &Uri,
    effects: &[RuleEffect],
    upstream_id: Option<&str>,
    upgrade: Option<&str>,
    keep_alive: bool,
    request_body_len: Option<usize>,
) -> Result<Vec<u8>> {
    build_upstream_request_inner(
        request,
        uri,
        effects,
        upstream_id,
        upgrade,
        keep_alive,
        UpstreamRequestBodyMode::ContentLength(request_body_len),
    )
}

pub(crate) fn build_upstream_request_with_chunked_body(
    request: &ParsedHttpRequest,
    uri: &Uri,
    effects: &[RuleEffect],
    upstream_id: Option<&str>,
    upgrade: Option<&str>,
    keep_alive: bool,
) -> Result<Vec<u8>> {
    build_upstream_request_inner(
        request,
        uri,
        effects,
        upstream_id,
        upgrade,
        keep_alive,
        UpstreamRequestBodyMode::Chunked,
    )
}

enum UpstreamRequestBodyMode {
    ContentLength(Option<usize>),
    Chunked,
}

fn build_upstream_request_inner(
    request: &ParsedHttpRequest,
    uri: &Uri,
    effects: &[RuleEffect],
    upstream_id: Option<&str>,
    upgrade: Option<&str>,
    keep_alive: bool,
    body_mode: UpstreamRequestBodyMode,
) -> Result<Vec<u8>> {
    let request_target = if upstream_id.is_some() {
        build_target_url(uri, &request.headers)?
    } else {
        uri.path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    };

    let mut headers = remove_hop_by_hop_request_headers(&request.headers);

    for effect in effects {
        if let RuleEffect::RewriteHeader { name, value } = effect {
            if should_apply_request_header_rewrite(name) {
                upsert_header(&mut headers, name, value);
            }
        }
    }

    if extract_host_from_pairs(&headers).is_none() {
        if let Some(host) = uri.host() {
            let host_value = match uri.port_u16() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            headers.push(("Host".to_string(), host_value));
        }
    }

    if let Some(upgrade) = upgrade {
        upsert_header(&mut headers, "Upgrade", upgrade);
        upsert_header(&mut headers, "Connection", "Upgrade");
    } else if keep_alive {
        upsert_header(&mut headers, "Connection", "keep-alive");
    } else {
        upsert_header(&mut headers, "Connection", "close");
    }

    match body_mode {
        UpstreamRequestBodyMode::ContentLength(request_body_len) => {
            let content_length = request_body_len.or_else(|| {
                if request.body.is_empty() {
                    None
                } else {
                    Some(request.body.len())
                }
            });
            if let Some(content_length) = content_length {
                upsert_header(&mut headers, "Content-Length", &content_length.to_string());
            }
        }
        UpstreamRequestBodyMode::Chunked => {
            // Re-encode this hop as HTTP/1.1 chunked by forwarding the original
            // chunk frames. Trailer fields are preserved in the body stream below;
            // the original Trailer declaration is intentionally not restored here
            // because the existing hop-by-hop cleanup removes it globally.
            upsert_header(&mut headers, "Transfer-Encoding", "chunked");
        }
    }

    let mut output = Vec::new();
    output.extend_from_slice(
        format!(
            "{} {} {}\r\n",
            request.method, request_target, request.version
        )
        .as_bytes(),
    );

    for (name, value) in headers {
        output.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&request.body);
    Ok(output)
}

pub(crate) fn extract_host_from_pairs(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.clone())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{header_hop::upgrade_header_value, http_parse::parse_http_request};

    fn parsed_request(method: &str, body: Vec<u8>) -> ParsedHttpRequest {
        ParsedHttpRequest {
            method: method.to_string(),
            uri_text: "http://www.example.com/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                ("Host".to_string(), "www.example.com".to_string()),
                ("User-Agent".to_string(), "RelayGateTest".to_string()),
            ],
            body,
        }
    }

    #[test]
    fn direct_get_request_does_not_add_empty_content_length() {
        let uri = "http://www.example.com/".parse::<Uri>().unwrap();
        let bytes = build_upstream_request(
            &parsed_request("GET", Vec::new()),
            &uri,
            &[],
            None,
            None,
            false,
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert!(!text.contains("\r\nContent-Length: 0\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn direct_post_request_adds_content_length_for_body() {
        let uri = "http://www.example.com/submit".parse::<Uri>().unwrap();
        let bytes = build_upstream_request(
            &parsed_request("POST", b"name=value".to_vec()),
            &uri,
            &[],
            None,
            None,
            false,
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert!(text.contains("\r\nContent-Length: 10\r\n"));
    }

    #[test]
    fn parses_chunked_request_body_before_forwarding() {
        let raw = b"POST http://www.example.com/submit HTTP/1.1\r\nHost: www.example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let parsed = parse_http_request(raw).unwrap();
        let uri = parsed.uri_text.parse::<Uri>().unwrap();

        let bytes = build_upstream_request(&parsed, &uri, &[], None, None, false).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(parsed.body, b"Wikipedia");
        assert!(!text.contains("\r\nTransfer-Encoding:"));
        assert!(text.contains("\r\nContent-Length: 9\r\n"));
        assert!(text.ends_with("\r\n\r\nWikipedia"));
    }

    #[test]
    fn upstream_request_can_preserve_streaming_chunked_body() {
        let raw = b"POST http://www.example.com/submit HTTP/1.1\r\nHost: www.example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        let parsed = parse_http_request(raw).unwrap();
        let uri = parsed.uri_text.parse::<Uri>().unwrap();

        let bytes = build_upstream_request_with_chunked_body(&parsed, &uri, &[], None, None, false)
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert!(text.contains("\r\nTransfer-Encoding: chunked\r\n"));
        assert!(!text.contains("\r\nContent-Length:"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn upstream_request_removes_hop_by_hop_headers() {
        let uri = "http://www.example.com/".parse::<Uri>().unwrap();
        let mut request = parsed_request("GET", Vec::new());
        request.headers.extend([
            ("Connection".to_string(), "Keep-Alive, X-Debug".to_string()),
            ("Keep-Alive".to_string(), "timeout=5".to_string()),
            ("Expect".to_string(), "100-continue".to_string()),
            ("TE".to_string(), "trailers".to_string()),
            ("Trailer".to_string(), "Expires".to_string()),
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
            ("X-Debug".to_string(), "local".to_string()),
        ]);

        let bytes = build_upstream_request(&request, &uri, &[], None, None, false).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert!(!text.contains("\r\nKeep-Alive:"));
        assert!(!text.contains("\r\nExpect:"));
        assert!(!text.contains("\r\nTE:"));
        assert!(!text.contains("\r\nTrailer:"));
        assert!(!text.contains("\r\nTransfer-Encoding:"));
        assert!(!text.contains("\r\nUpgrade:"));
        assert!(!text.contains("\r\nX-Debug:"));
        assert!(text.contains("\r\nConnection: close\r\n"));
    }

    #[test]
    fn request_header_rewrite_cannot_reintroduce_owned_framing_headers() {
        let uri = "http://www.example.com/submit".parse::<Uri>().unwrap();
        let request = parsed_request("POST", b"name=value".to_vec());
        let effects = vec![
            RuleEffect::RewriteHeader {
                name: "Content-Length".to_string(),
                value: "9999".to_string(),
            },
            RuleEffect::RewriteHeader {
                name: "Transfer-Encoding".to_string(),
                value: "chunked".to_string(),
            },
            RuleEffect::RewriteHeader {
                name: "Expect".to_string(),
                value: "100-continue".to_string(),
            },
            RuleEffect::RewriteHeader {
                name: "Host".to_string(),
                value: "evil.example".to_string(),
            },
        ];

        let bytes = build_upstream_request(&request, &uri, &effects, None, None, false).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert!(text.contains("\r\nContent-Length: 10\r\n"));
        assert!(!text.contains("\r\nContent-Length: 9999\r\n"));
        assert!(!text.contains("\r\nTransfer-Encoding:"));
        assert!(!text.contains("\r\nExpect:"));
        assert!(!text.contains("\r\nHost: evil.example\r\n"));
    }

    #[test]
    fn upstream_request_preserves_upgrade_when_requested() {
        let uri = "http://www.example.com/socket".parse::<Uri>().unwrap();
        let mut request = parsed_request("GET", Vec::new());
        request.headers.extend([
            ("Connection".to_string(), "keep-alive, Upgrade".to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Sec-WebSocket-Key".to_string(), "abc".to_string()),
        ]);

        let upgrade = upgrade_header_value(&request.headers);
        let bytes =
            build_upstream_request(&request, &uri, &[], None, upgrade.as_deref(), false).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(upgrade.as_deref(), Some("websocket"));
        assert!(text.contains("\r\nConnection: Upgrade\r\n"));
        assert!(text.contains("\r\nUpgrade: websocket\r\n"));
        assert!(text.contains("\r\nSec-WebSocket-Key: abc\r\n"));
        assert!(!text.contains("\r\nkeep-alive"));
    }

    #[test]
    fn upstream_request_can_keep_direct_connection_alive() {
        let uri = "http://www.example.com/".parse::<Uri>().unwrap();
        let bytes = build_upstream_request(
            &parsed_request("GET", Vec::new()),
            &uri,
            &[],
            None,
            None,
            true,
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert!(text.contains("\r\nConnection: keep-alive\r\n"));
    }
}
