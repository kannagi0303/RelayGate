use crate::proxy::resource_replace::ResourceReplacement;

pub(crate) fn should_abort_adblock_request(request_type: &str) -> bool {
    !matches!(request_type, "document" | "subdocument")
}

pub(crate) fn simple_response_bytes(status_code: u16, reason_phrase: &str, body: &str) -> Vec<u8> {
    let body_bytes = body.as_bytes();
    simple_response_bytes_with_content_type(
        status_code,
        reason_phrase,
        "text/plain; charset=utf-8",
        body_bytes,
    )
}

pub(crate) fn simple_response_bytes_with_content_type(
    status_code: u16,
    reason_phrase: &str,
    content_type: &str,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_code} {reason_phrase}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

pub(crate) fn resource_replacement_response_bytes(replacement: &ResourceReplacement) -> Vec<u8> {
    simple_response_bytes_with_content_type(
        replacement.status,
        status_reason(replacement.status),
        &replacement.content_type,
        &replacement.body,
    )
}

pub(crate) fn build_buffered_response_bytes(
    status_code: u16,
    reason_phrase: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(format!("HTTP/1.1 {status_code} {reason_phrase}\r\n").as_bytes());

    for (name, value) in headers {
        output.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&body);
    output
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
