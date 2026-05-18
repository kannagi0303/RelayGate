use anyhow::{Context, Result};
use tokio::{
    fs::File,
    io::{AsyncWrite, AsyncWriteExt},
};

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

pub(crate) async fn write_resource_replacement_response<W>(
    writer: &mut W,
    replacement: &ResourceReplacement,
    include_body: bool,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut file = File::open(&replacement.path).await.with_context(|| {
        format!(
            "failed to open replacement resource for rule `{}`: {}",
            replacement.rule_id,
            replacement.path.display()
        )
    })?;
    let content_length = file
        .metadata()
        .await
        .with_context(|| {
            format!(
                "failed to inspect replacement resource for rule `{}`: {}",
                replacement.rule_id,
                replacement.path.display()
            )
        })?
        .len();
    let send_body = include_body && !status_has_no_body(replacement.status) && content_length > 0;
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        replacement.status,
        status_reason(replacement.status),
        replacement.content_type,
        content_length,
    );
    writer.write_all(header.as_bytes()).await?;
    if send_body {
        tokio::io::copy(&mut file, writer).await?;
    }
    Ok(())
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

pub(crate) fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "OK",
    }
}

pub(crate) fn status_has_no_body(status: u16) -> bool {
    matches!(status, 100..=199 | 204 | 304)
}
