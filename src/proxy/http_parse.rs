use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::proxy::http_framing;

#[derive(Debug, Clone)]
pub(crate) struct ParsedHttpRequest {
    pub(crate) method: String,
    pub(crate) uri_text: String,
    pub(crate) version: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedHttpResponseHead {
    pub(crate) version: String,
    pub(crate) status_code: u16,
    pub(crate) reason_phrase: String,
    pub(crate) headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HeaderEnd {
    pub(crate) index: usize,
    pub(crate) delimiter_len: usize,
}

pub(crate) fn parse_http_request(bytes: &[u8]) -> Result<ParsedHttpRequest> {
    let header_end = http_framing::find_header_end(bytes)
        .context("invalid HTTP request: missing header terminator")?;
    let header_text = std::str::from_utf8(&bytes[..header_end.index])?;
    let mut lines = header_text.lines();

    let request_line = lines
        .next()
        .context("invalid HTTP request: missing request line")?;
    let mut request_parts = request_line.splitn(3, ' ');
    let method = request_parts
        .next()
        .context("invalid HTTP request: missing method")?;
    let uri_text = request_parts
        .next()
        .context("invalid HTTP request: missing uri")?;
    let version = request_parts
        .next()
        .context("invalid HTTP request: missing version")?;

    let headers = lines
        .filter(|line| !line.is_empty())
        .map(parse_header_line)
        .collect::<Result<Vec<_>>>()?;

    let raw_body = &bytes[header_end.index + header_end.delimiter_len..];
    let body = http_framing::request_body_bytes(&bytes[..header_end.index], raw_body)?;

    Ok(ParsedHttpRequest {
        method: method.to_string(),
        uri_text: uri_text.to_string(),
        version: version.to_string(),
        headers,
        body,
    })
}

pub(crate) async fn read_http_response_head<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];

    loop {
        let read_count = stream.read(&mut temp).await?;
        if read_count == 0 {
            break;
        }

        buffer.extend_from_slice(&temp[..read_count]);
        if find_response_header_end(&buffer).is_some() {
            break;
        }
    }

    Ok(buffer)
}

pub(crate) fn parse_http_response_head(bytes: &[u8]) -> Result<ParsedHttpResponseHead> {
    let header_end = find_response_header_end(bytes)
        .context("invalid HTTP response: missing header terminator")?;
    let header_text = std::str::from_utf8(&bytes[..header_end.index])?;
    let mut lines = header_text.lines();
    let status_line = lines
        .next()
        .context("invalid HTTP response: missing status line")?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .context("invalid HTTP response: missing version")?
        .to_string();
    let status_code = status_parts
        .next()
        .context("invalid HTTP response: missing status code")?
        .parse::<u16>()?;
    let reason_phrase = status_parts.next().unwrap_or_default().to_string();
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(parse_header_line)
        .collect::<Result<Vec<_>>>()?;

    Ok(ParsedHttpResponseHead {
        version,
        status_code,
        reason_phrase,
        headers,
    })
}

pub(crate) fn parse_header_line(line: &str) -> Result<(String, String)> {
    let (name, value) = line
        .split_once(':')
        .with_context(|| format!("invalid HTTP header line: {line}"))?;
    Ok((name.trim().to_string(), value.trim().to_string()))
}

pub(crate) fn find_response_header_end(bytes: &[u8]) -> Option<HeaderEnd> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chunked_request_body() {
        let raw = b"POST http://www.example.com/submit HTTP/1.1\r\nHost: www.example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";

        let parsed = parse_http_request(raw).unwrap();

        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.uri_text, "http://www.example.com/submit");
        assert_eq!(parsed.body, b"Wikipedia");
    }

    #[test]
    fn parses_lf_only_request_headers() {
        let raw = b"GET http://www.example.com/ HTTP/1.1\nHost: www.example.com\n\n";

        let parsed = parse_http_request(raw).unwrap();

        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.uri_text, "http://www.example.com/");
        assert_eq!(parsed.body, b"");
    }

    #[test]
    fn parses_lf_only_response_headers() {
        let response = b"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html></html>";

        let parsed = parse_http_response_head(response).unwrap();

        assert_eq!(parsed.version, "HTTP/1.1");
        assert_eq!(parsed.status_code, 200);
        assert_eq!(parsed.reason_phrase, "OK");
        assert_eq!(
            parsed.headers,
            vec![("Content-Type".to_string(), "text/html".to_string())]
        );
    }
}
