use std::{error::Error, fmt};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const REQUEST_BODY_READ_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct HeaderEnd {
    pub index: usize,
    pub delimiter_len: usize,
}

#[derive(Debug, Clone)]
pub struct RequestHeadFrame {
    pub head_bytes: Vec<u8>,
    pub prebuffered_body: Vec<u8>,
    pub body_kind: RequestBodyKind,
    pub expect_100_continue: bool,
}

impl RequestHeadFrame {
    pub fn into_request_bytes(self, body: Vec<u8>) -> Vec<u8> {
        let mut bytes = self.head_bytes;
        bytes.extend_from_slice(&body);
        bytes
    }

    pub fn header_bytes(&self) -> &[u8] {
        let Some(end) = find_header_end(&self.head_bytes) else {
            return &self.head_bytes;
        };
        &self.head_bytes[..end.index]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyKind {
    None,
    ContentLength(usize),
    Chunked,
}

#[derive(Debug, Clone, Copy)]
pub struct RequestReadLimits {
    pub max_header_bytes: usize,
    pub max_request_body_bytes: usize,
    pub max_chunked_body_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestLimitError {
    HeaderTooLarge,
    PayloadTooLarge,
}

impl fmt::Display for RequestLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooLarge => write!(formatter, "request header exceeds configured limit"),
            Self::PayloadTooLarge => write!(formatter, "request body exceeds configured limit"),
        }
    }
}

impl Error for RequestLimitError {}

pub async fn read_http_request_bytes<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_http_request_bytes_limited(
        stream,
        RequestReadLimits {
            max_header_bytes: usize::MAX,
            max_request_body_bytes: usize::MAX,
            max_chunked_body_bytes: usize::MAX,
        },
    )
    .await
}

pub async fn read_http_request_bytes_limited<S>(
    stream: &mut S,
    limits: RequestReadLimits,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];
    let mut header_end = None;
    let mut body_kind = RequestBodyKind::None;
    let mut continue_sent = false;

    loop {
        let read_count = stream.read(&mut temp).await?;
        if read_count == 0 {
            break;
        }

        buffer.extend_from_slice(&temp[..read_count]);

        if header_end.is_none() {
            header_end = find_header_end(&buffer);
            if let Some(end) = header_end {
                if end.index.saturating_add(end.delimiter_len) > limits.max_header_bytes {
                    return Err(RequestLimitError::HeaderTooLarge.into());
                }

                body_kind = request_body_kind(&buffer[..end.index])?;
                match body_kind {
                    RequestBodyKind::ContentLength(content_length)
                        if content_length > limits.max_request_body_bytes =>
                    {
                        return Err(RequestLimitError::PayloadTooLarge.into());
                    }
                    RequestBodyKind::Chunked => {}
                    RequestBodyKind::None | RequestBodyKind::ContentLength(_) => {}
                }

                if !continue_sent
                    && body_kind != RequestBodyKind::None
                    && has_expect_100_continue(&buffer[..end.index])?
                {
                    stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
                    continue_sent = true;
                }
            } else if buffer.len() > limits.max_header_bytes {
                return Err(RequestLimitError::HeaderTooLarge.into());
            }
        }

        if let Some(end) = header_end {
            let body_start = end.index + end.delimiter_len;
            let buffered_body_len = buffer.len().saturating_sub(body_start);
            match body_kind {
                RequestBodyKind::None => {
                    if buffer.len() >= body_start {
                        break;
                    }
                }
                RequestBodyKind::ContentLength(content_length) => {
                    if buffered_body_len > limits.max_request_body_bytes {
                        return Err(RequestLimitError::PayloadTooLarge.into());
                    }
                    if buffer.len() >= body_start.saturating_add(content_length) {
                        break;
                    }
                }
                RequestBodyKind::Chunked => {
                    let body_bytes = &buffer[body_start..];
                    if body_bytes.len() > limits.max_chunked_body_bytes
                        || chunked_decoded_len_exceeds(body_bytes, limits.max_chunked_body_bytes)?
                    {
                        return Err(RequestLimitError::PayloadTooLarge.into());
                    }
                    if let Some(encoded_len) = chunked_encoded_len(body_bytes)? {
                        if buffer.len() >= body_start.saturating_add(encoded_len) {
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(buffer)
}

pub async fn read_http_request_head_limited<S>(
    stream: &mut S,
    limits: RequestReadLimits,
) -> Result<Option<RequestHeadFrame>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];

    loop {
        let read_count = stream.read(&mut temp).await?;
        if read_count == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            bail!("client closed before completing HTTP request headers");
        }

        buffer.extend_from_slice(&temp[..read_count]);
        if let Some(end) = find_header_end(&buffer) {
            let head_len = end.index + end.delimiter_len;
            if head_len > limits.max_header_bytes {
                return Err(RequestLimitError::HeaderTooLarge.into());
            }

            let header_bytes = &buffer[..end.index];
            let body_kind = request_body_kind(header_bytes)?;
            if let RequestBodyKind::ContentLength(content_length) = body_kind {
                if content_length > limits.max_request_body_bytes {
                    return Err(RequestLimitError::PayloadTooLarge.into());
                }
            }

            let prebuffered_body = buffer[head_len..].to_vec();
            match body_kind {
                RequestBodyKind::ContentLength(content_length)
                    if prebuffered_body.len() > content_length
                        || prebuffered_body.len() > limits.max_request_body_bytes =>
                {
                    return Err(RequestLimitError::PayloadTooLarge.into());
                }
                RequestBodyKind::Chunked => {
                    if prebuffered_body.len() > limits.max_chunked_body_bytes
                        || chunked_decoded_len_exceeds(
                            &prebuffered_body,
                            limits.max_chunked_body_bytes,
                        )?
                    {
                        return Err(RequestLimitError::PayloadTooLarge.into());
                    }
                }
                RequestBodyKind::None | RequestBodyKind::ContentLength(_) => {}
            }

            return Ok(Some(RequestHeadFrame {
                head_bytes: buffer[..head_len].to_vec(),
                prebuffered_body,
                body_kind,
                expect_100_continue: has_expect_100_continue(header_bytes)?,
            }));
        }

        if buffer.len() > limits.max_header_bytes {
            return Err(RequestLimitError::HeaderTooLarge.into());
        }
    }
}

pub async fn read_remaining_request_body_limited<S>(
    stream: &mut S,
    frame: &RequestHeadFrame,
    limits: RequestReadLimits,
) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    match frame.body_kind {
        RequestBodyKind::None => Ok(Vec::new()),
        RequestBodyKind::ContentLength(content_length) => {
            if content_length > limits.max_request_body_bytes {
                return Err(RequestLimitError::PayloadTooLarge.into());
            }
            if frame.prebuffered_body.len() > content_length {
                return Err(RequestLimitError::PayloadTooLarge.into());
            }

            let mut body = Vec::with_capacity(content_length);
            body.extend_from_slice(&frame.prebuffered_body);
            let mut temp = vec![0_u8; REQUEST_BODY_READ_BUFFER_BYTES];
            while body.len() < content_length {
                let remaining = content_length - body.len();
                let read_len = remaining.min(temp.len());
                let read_count = stream.read(&mut temp[..read_len]).await?;
                if read_count == 0 {
                    bail!("client closed before completing request body");
                }
                body.extend_from_slice(&temp[..read_count]);
            }
            Ok(body)
        }
        RequestBodyKind::Chunked => {
            let mut body = frame.prebuffered_body.clone();
            let mut temp = vec![0_u8; REQUEST_BODY_READ_BUFFER_BYTES];
            loop {
                if body.len() > limits.max_chunked_body_bytes
                    || chunked_decoded_len_exceeds(&body, limits.max_chunked_body_bytes)?
                {
                    return Err(RequestLimitError::PayloadTooLarge.into());
                }
                if let Some(encoded_len) = chunked_encoded_len(&body)? {
                    body.truncate(encoded_len);
                    return Ok(body);
                }

                let read_count = stream.read(&mut temp).await?;
                if read_count == 0 {
                    bail!("client closed before completing chunked request body");
                }
                body.extend_from_slice(&temp[..read_count]);
            }
        }
    }
}

pub fn find_header_end(bytes: &[u8]) -> Option<HeaderEnd> {
    if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
        return Some(HeaderEnd {
            index,
            delimiter_len: 4,
        });
    }

    bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|index| HeaderEnd {
            index,
            delimiter_len: 2,
        })
}

pub fn request_body_bytes(header_bytes: &[u8], raw_body: &[u8]) -> Result<Vec<u8>> {
    match request_body_kind(header_bytes)? {
        // Header-only parsing is used by the HTTP forward path before request-level
        // rules/adblock decisions. A chunked request body may not have been read yet,
        // so an empty raw body here means "body not loaded", not a malformed body.
        RequestBodyKind::Chunked if raw_body.is_empty() => Ok(Vec::new()),
        RequestBodyKind::Chunked => decode_chunked_body(raw_body),
        _ => Ok(raw_body.to_vec()),
    }
}

pub fn request_body_kind(header_bytes: &[u8]) -> Result<RequestBodyKind> {
    if has_chunked_transfer_encoding(header_bytes)? {
        return Ok(RequestBodyKind::Chunked);
    }

    let content_length = parse_content_length(header_bytes)?;
    if content_length > 0 {
        Ok(RequestBodyKind::ContentLength(content_length))
    } else {
        Ok(RequestBodyKind::None)
    }
}

fn parse_content_length(header_bytes: &[u8]) -> Result<usize> {
    let header_text = std::str::from_utf8(header_bytes)?;

    for line in header_text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return Ok(value.trim().parse::<usize>()?);
            }
        }
    }

    Ok(0)
}

fn has_chunked_transfer_encoding(header_bytes: &[u8]) -> Result<bool> {
    let header_text = std::str::from_utf8(header_bytes)?;

    for line in header_text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        if value
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case("chunked"))
        {
            return Ok(true);
        }
    }

    Ok(false)
}

fn has_expect_100_continue(header_bytes: &[u8]) -> Result<bool> {
    let header_text = std::str::from_utf8(header_bytes)?;

    for line in header_text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("expect") {
            continue;
        }
        if value
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case("100-continue"))
        {
            return Ok(true);
        }
    }

    Ok(false)
}

pub(crate) fn chunked_encoded_len(bytes: &[u8]) -> Result<Option<usize>> {
    let mut pos = 0;

    loop {
        let Some(line_end) = find_line_end(&bytes[pos..]) else {
            return Ok(None);
        };
        let size_line = std::str::from_utf8(&bytes[pos..pos + line_end.index])?;
        let size = parse_chunk_size(size_line)?;
        pos += line_end.index + line_end.delimiter_len;

        if size == 0 {
            let Some(trailer_end) = find_header_end(&bytes[pos..]) else {
                return Ok(None);
            };
            return Ok(Some(pos + trailer_end.index + trailer_end.delimiter_len));
        }

        if bytes.len() < pos + size {
            return Ok(None);
        }
        pos += size;

        let Some(data_line_end) = find_line_end(&bytes[pos..]) else {
            return Ok(None);
        };
        if data_line_end.index != 0 {
            bail!("invalid chunked body: missing chunk data terminator");
        }
        pos += data_line_end.delimiter_len;
    }
}

pub(crate) fn chunked_decoded_len_exceeds(bytes: &[u8], limit: usize) -> Result<bool> {
    let mut pos = 0;
    let mut decoded_len = 0usize;

    loop {
        let Some(line_end) = find_line_end(&bytes[pos..]) else {
            return Ok(false);
        };
        let size_line = std::str::from_utf8(&bytes[pos..pos + line_end.index])?;
        let size = parse_chunk_size(size_line)?;
        decoded_len = decoded_len.saturating_add(size);
        if decoded_len > limit {
            return Ok(true);
        }
        pos += line_end.index + line_end.delimiter_len;

        if size == 0 {
            return Ok(false);
        }

        if bytes.len() < pos + size {
            return Ok(false);
        }
        pos += size;

        let Some(data_line_end) = find_line_end(&bytes[pos..]) else {
            return Ok(false);
        };
        if data_line_end.index != 0 {
            bail!("invalid chunked body: missing chunk data terminator");
        }
        pos += data_line_end.delimiter_len;
    }
}

pub(crate) fn decode_chunked_body(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    let mut decoded = Vec::new();

    loop {
        let line_end = find_line_end(&bytes[pos..])
            .context("invalid chunked body: missing chunk size terminator")?;
        let size_line = std::str::from_utf8(&bytes[pos..pos + line_end.index])?;
        let size = parse_chunk_size(size_line)?;
        pos += line_end.index + line_end.delimiter_len;

        if size == 0 {
            return Ok(decoded);
        }

        if bytes.len() < pos + size {
            bail!("invalid chunked body: truncated chunk data");
        }
        decoded.extend_from_slice(&bytes[pos..pos + size]);
        pos += size;

        let data_line_end = find_line_end(&bytes[pos..])
            .context("invalid chunked body: missing chunk data terminator")?;
        if data_line_end.index != 0 {
            bail!("invalid chunked body: malformed chunk data terminator");
        }
        pos += data_line_end.delimiter_len;
    }
}

fn parse_chunk_size(line: &str) -> Result<usize> {
    let size_text = line.split(';').next().unwrap_or_default().trim();
    if size_text.is_empty() {
        bail!("invalid chunked body: empty chunk size");
    }
    usize::from_str_radix(size_text, 16).context("invalid chunked body: invalid chunk size")
}

fn find_line_end(bytes: &[u8]) -> Option<HeaderEnd> {
    if let Some(index) = bytes.windows(2).position(|window| window == b"\r\n") {
        return Some(HeaderEnd {
            index,
            delimiter_len: 2,
        });
    }

    bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|index| HeaderEnd {
            index,
            delimiter_len: 1,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_chunked_request_body() {
        let headers = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked";
        let body = b"4\r\nWiki\r\n5;ext=value\r\npedia\r\n0\r\nX-Trailer: ok\r\n\r\n";

        let decoded = request_body_bytes(headers, body).unwrap();

        assert_eq!(decoded, b"Wikipedia");
    }

    #[test]
    fn detects_complete_chunked_body_with_trailers() {
        let body = b"3\r\nabc\r\n0\r\nX-Trailer: ok\r\n\r\nextra";

        let len = chunked_encoded_len(body).unwrap();

        assert_eq!(len, Some(28));
    }

    #[test]
    fn waits_for_incomplete_chunked_body() {
        let body = b"3\r\nab";

        let len = chunked_encoded_len(body).unwrap();

        assert_eq!(len, None);
    }

    #[test]
    fn detects_expect_100_continue() {
        let headers =
            b"POST / HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 4";

        assert!(has_expect_100_continue(headers).unwrap());
    }

    #[tokio::test]
    async fn sends_100_continue_before_reading_body() {
        let (mut client, mut proxy) = tokio::io::duplex(256);
        let read_task = tokio::spawn(async move { read_http_request_bytes(&mut proxy).await });

        client
            .write_all(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n",
            )
            .await
            .unwrap();

        let mut interim = vec![0_u8; 25];
        client.read_exact(&mut interim).await.unwrap();
        assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n");

        client.write_all(b"test").await.unwrap();
        drop(client);

        let bytes = read_task.await.unwrap().unwrap();
        assert!(bytes.ends_with(b"\r\n\r\ntest"));
    }
}
