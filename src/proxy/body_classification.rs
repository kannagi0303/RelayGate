/// Shared response body classification helpers used by MITM and plain HTTP
/// forwarding paths.
///
/// Keep these helpers focused on "can RelayGate reasonably treat this response
/// as an HTML document?" rather than on final rewrite policy. The final body
/// pipeline decision still belongs to each caller because it also depends on
/// request rules, enabled features, buffer limits, and response status.
pub(crate) fn is_html_content_type(content_type: &str) -> bool {
    content_type.contains("text/html") || content_type.contains("application/xhtml")
}

/// Returns true for partial response representations that should be forwarded
/// without body mutation.
///
/// A 206 response or any response carrying Content-Range represents a byte range
/// of a larger resource, not a complete HTML/JSON representation. RelayGate may
/// still forward it, but rewrite, patch, userscript, and injection pipelines must
/// not mutate the partial bytes.
pub(crate) fn response_is_partial_content(status_code: u16, has_content_range: bool) -> bool {
    status_code == 206 || has_content_range
}

/// Header-only HTML-likeness used before the body has been buffered.
///
/// Browsers may render a document/subdocument response even when the server
/// omits Content-Type. Treat that case as HTML-like for routing into a body
/// pipeline, but do not extend the same assumption to images, media, scripts,
/// styles, XHR, or other subresources.
pub(crate) fn response_headers_are_html_like(request_type: &str, content_type: &str) -> bool {
    is_html_content_type(content_type)
        || (content_type.is_empty() && matches!(request_type, "document" | "subdocument"))
}

/// Body-level HTML-likeness used after a response body has been buffered.
///
/// Explicit HTML Content-Type wins immediately. Missing Content-Type on a
/// document/subdocument gets a small sniffing pass so RelayGate can support
/// real pages served without a type while avoiding accidental injection into
/// binary subresources.
pub(crate) fn should_treat_response_body_as_html(
    request_type: &str,
    content_type: &str,
    response_body: &[u8],
) -> bool {
    if is_html_content_type(content_type) {
        return true;
    }

    if !content_type.is_empty() || !matches!(request_type, "document" | "subdocument") {
        return false;
    }

    response_body_looks_like_html_document(response_body)
}

fn response_body_looks_like_html_document(response_body: &[u8]) -> bool {
    let sample = response_body
        .iter()
        .copied()
        .take(512)
        .filter(|byte| !matches!(byte, b'\xef' | b'\xbb' | b'\xbf'))
        .collect::<Vec<_>>();
    let text = String::from_utf8_lossy(&sample).to_ascii_lowercase();
    let trimmed = text.trim_start();

    trimmed.starts_with("<!doctype html")
        || trimmed.starts_with("<html")
        || trimmed.contains("<head")
        || trimmed.contains("<body")
}
