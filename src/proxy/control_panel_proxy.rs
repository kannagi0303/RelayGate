use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{Request, Uri},
    Router,
};
use http_body_util::BodyExt;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tower::util::ServiceExt;

use crate::{
    config::RelayGateConfig,
    proxy::{http_forward::extract_host_from_pairs, http_parse::ParsedHttpRequest},
};

pub(crate) fn is_control_panel_request(
    request: &ParsedHttpRequest,
    config: &RelayGateConfig,
) -> bool {
    let host = request
        .uri_text
        .parse::<Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_string))
        .or_else(|| extract_host_from_pairs(&request.headers));

    let Some(host) = host else {
        return false;
    };

    matches!(
        host.as_str(),
        "rg.local"
            | "rg.localhost"
            | "127.0.0.1:8787"
            | "localhost:8787"
            | "127.0.0.1:8788"
            | "localhost:8788"
    ) || matches_listen_address(&host, &config.proxy.listen)
        || matches_listen_address(&host, &config.web.listen)
}

pub(crate) async fn handle_control_panel_proxy(
    control_panel_app: Router,
    client_stream: &mut TcpStream,
    request: ParsedHttpRequest,
) -> Result<()> {
    let app_request = build_control_panel_request(&request)?;

    let mut response = control_panel_app
        .oneshot(app_request)
        .await
        .context("failed to dispatch control panel request")?;

    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("OK");
    let mut head = Vec::new();
    head.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason).as_bytes());

    let mut is_streaming = false;
    for (name, value) in response.headers() {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "content-type"
            && value
                .to_str()
                .map(|text| text.contains("text/event-stream"))
                .unwrap_or(false)
        {
            is_streaming = true;
        }

        if lower == "connection" || lower == "transfer-encoding" {
            continue;
        }

        if let Ok(value_text) = value.to_str() {
            head.extend_from_slice(format!("{}: {}\r\n", name.as_str(), value_text).as_bytes());
        }
    }

    if !is_streaming {
        let collected = response
            .body_mut()
            .collect()
            .await
            .context("failed to collect control panel response body")?
            .to_bytes();
        head.extend_from_slice(format!("Content-Length: {}\r\n", collected.len()).as_bytes());
        head.extend_from_slice(b"Connection: close\r\n\r\n");
        client_stream.write_all(&head).await?;
        client_stream.write_all(&collected).await?;
        client_stream.shutdown().await?;
        return Ok(());
    }

    head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    client_stream.write_all(&head).await?;

    let mut body = response.into_body();
    while let Some(frame) = body.frame().await {
        let frame = frame.context("failed to read control panel streaming frame")?;
        if let Some(data) = frame.data_ref() {
            let chunk_prefix = format!("{:X}\r\n", data.len());
            client_stream.write_all(chunk_prefix.as_bytes()).await?;
            client_stream.write_all(data).await?;
            client_stream.write_all(b"\r\n").await?;
        }
    }
    client_stream.write_all(b"0\r\n\r\n").await?;
    client_stream.shutdown().await?;
    Ok(())
}

fn matches_listen_address(request_host: &str, listen: &str) -> bool {
    let Some((listen_host, listen_port)) = split_host_port(listen) else {
        return request_host.eq_ignore_ascii_case(listen);
    };
    let Some((request_only_host, request_port)) = split_host_port(request_host) else {
        return false;
    };

    if request_port != listen_port {
        return false;
    }

    let normalized_listen_host = listen_host.trim_matches(['[', ']']);
    let normalized_request_host = request_only_host.trim_matches(['[', ']']);

    if normalized_listen_host.eq_ignore_ascii_case(normalized_request_host) {
        return true;
    }

    matches!(normalized_listen_host, "0.0.0.0" | "::" | "::0")
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    value.rsplit_once(':')
}

fn build_control_panel_request(request: &ParsedHttpRequest) -> Result<Request<Body>> {
    let uri = request.uri_text.parse::<Uri>()?;
    let target = if uri.scheme().is_some() {
        uri.path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    } else if request.uri_text.is_empty() {
        "/".to_string()
    } else {
        request.uri_text.clone()
    };

    let mut builder = Request::builder()
        .method(request.method.as_str())
        .uri(target);

    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "proxy-connection" | "connection" | "content-length"
        ) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }

    Ok(builder.body(Body::from(request.body.clone()))?)
}
