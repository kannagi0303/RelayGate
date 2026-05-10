pub(crate) fn remove_hop_by_hop_request_headers(
    headers: &[(String, String)],
) -> Vec<(String, String)> {
    let connection_tokens = connection_header_tokens(headers);
    headers
        .iter()
        .filter(|(name, _)| !should_skip_request_header(name, &connection_tokens))
        .cloned()
        .collect()
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

pub(crate) fn upgrade_header_value(headers: &[(String, String)]) -> Option<String> {
    let has_upgrade_token = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));

    if !has_upgrade_token {
        return None;
    }

    headers
        .iter()
        .find(|(name, value)| name.eq_ignore_ascii_case("upgrade") && !value.trim().is_empty())
        .map(|(_, value)| value.trim().to_string())
}

pub(crate) fn should_skip_response_header(name: &str, connection_tokens: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    connection_tokens
        .iter()
        .any(|token| token == &lower && token != "transfer-encoding")
        || matches!(
            lower.as_str(),
            "connection" | "proxy-connection" | "keep-alive" | "te" | "trailer" | "upgrade"
        )
}

pub(crate) fn should_apply_request_header_rewrite(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // RelayGate owns per-hop and body-framing headers when it acts as the
    // upstream client. Request rules may still rewrite end-to-end headers,
    // but they must not reintroduce stale framing metadata after the forwarder
    // has stripped and rebuilt the request body boundary. Host is also owned by
    // the selected target URL/upstream route.
    !is_relaygate_owned_request_header(&lower) && lower != "host"
}

pub(crate) fn is_relaygate_owned_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "proxy-connection"
            | "connection"
            | "content-length"
            | "expect"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn should_skip_request_header(name: &str, connection_tokens: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    connection_tokens.iter().any(|token| token == &lower)
        || is_relaygate_owned_request_header(&lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_hop_by_hop_request_headers() {
        let headers = vec![
            ("Host".to_string(), "www.example.com".to_string()),
            ("Connection".to_string(), "Keep-Alive, X-Debug".to_string()),
            ("Keep-Alive".to_string(), "timeout=5".to_string()),
            ("Expect".to_string(), "100-continue".to_string()),
            ("TE".to_string(), "trailers".to_string()),
            ("Trailer".to_string(), "Expires".to_string()),
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
            ("X-Debug".to_string(), "local".to_string()),
        ];

        let cleaned = remove_hop_by_hop_request_headers(&headers);

        assert_eq!(
            cleaned,
            vec![("Host".to_string(), "www.example.com".to_string())]
        );
    }

    #[test]
    fn request_header_rewrite_cannot_target_owned_framing_headers() {
        for name in [
            "Connection",
            "Proxy-Connection",
            "Content-Length",
            "Expect",
            "Keep-Alive",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
            "Host",
        ] {
            assert!(
                !should_apply_request_header_rewrite(name),
                "{name} should remain RelayGate-owned"
            );
        }

        assert!(should_apply_request_header_rewrite("User-Agent"));
        assert!(should_apply_request_header_rewrite("X-RelayGate-Test"));
    }

    #[test]
    fn detects_upgrade_header_value() {
        let headers = vec![
            ("Connection".to_string(), "keep-alive, Upgrade".to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
        ];

        assert_eq!(upgrade_header_value(&headers).as_deref(), Some("websocket"));
    }
}
