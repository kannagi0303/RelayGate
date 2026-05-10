use anyhow::Error;

use crate::{
    diagnostics,
    proxy::{
        header_hop::{connection_header_tokens, should_skip_response_header},
        http_parse::ParsedHttpResponseHead,
    },
};

pub(crate) fn build_http_forward_response_head(
    response: &ParsedHttpResponseHead,
    keep_alive: bool,
) -> Vec<u8> {
    let mut output = Vec::new();
    let reason_suffix = if response.reason_phrase.is_empty() {
        String::new()
    } else {
        format!(" {}", response.reason_phrase)
    };
    output.extend_from_slice(
        format!(
            "{} {}{}\r\n",
            response.version, response.status_code, reason_suffix
        )
        .as_bytes(),
    );

    let connection_tokens = connection_header_tokens(&response.headers);
    for (name, value) in &response.headers {
        if should_skip_response_header(name, &connection_tokens) {
            continue;
        }
        output.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    let connection_value = if keep_alive { "keep-alive" } else { "close" };
    output.extend_from_slice(format!("Connection: {connection_value}\r\n\r\n").as_bytes());
    output
}

pub(crate) fn log_invalid_upstream_response_head(
    stage: &str,
    target_url: &str,
    forward_target: &str,
    bytes: &[u8],
    error: &Error,
) {
    let preview = response_head_preview(bytes);
    let _ = diagnostics::append_proxy_diagnostic(&format!(
        "ts={} event=invalid_upstream_response_head stage={} target={} forward_target={} bytes={} preview={} error_chain={}",
        diagnostics::diagnostic_timestamp(),
        stage,
        target_url,
        forward_target,
        bytes.len(),
        preview,
        diagnostics::format_error_chain(error)
    ));
}

fn response_head_preview(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "empty".to_string();
    }

    bytes
        .iter()
        .take(64)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_response_head_removes_hop_by_hop_headers() {
        let response = ParsedHttpResponseHead {
            version: "HTTP/1.1".to_string(),
            status_code: 200,
            reason_phrase: "OK".to_string(),
            headers: vec![
                ("Connection".to_string(), "keep-alive, X-Local".to_string()),
                ("Keep-Alive".to_string(), "timeout=5".to_string()),
                ("X-Local".to_string(), "remove-me".to_string()),
                ("Transfer-Encoding".to_string(), "chunked".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ],
        };

        let head = String::from_utf8(build_http_forward_response_head(&response, false)).unwrap();

        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("\r\nTransfer-Encoding: chunked\r\n"));
        assert!(head.contains("\r\nContent-Type: text/html\r\n"));
        assert!(head.contains("\r\nConnection: close\r\n"));
        assert!(!head.contains("\r\nKeep-Alive:"));
        assert!(!head.contains("\r\nX-Local:"));
        assert!(!head.contains("\r\nConnection: keep-alive"));
    }

    #[test]
    fn forward_response_head_can_keep_client_connection_alive() {
        let response = ParsedHttpResponseHead {
            version: "HTTP/1.1".to_string(),
            status_code: 200,
            reason_phrase: "OK".to_string(),
            headers: vec![
                ("Content-Length".to_string(), "5".to_string()),
                ("Content-Type".to_string(), "text/plain".to_string()),
            ],
        };

        let head = String::from_utf8(build_http_forward_response_head(&response, true)).unwrap();

        assert!(head.contains("\r\nConnection: keep-alive\r\n"));
        assert!(head.contains("\r\nContent-Length: 5\r\n"));
    }
}
