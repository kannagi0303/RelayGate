use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result};
use axum::http::Uri;
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
    time,
};
use tracing::{debug, info};

use crate::{
    config::ConnectPolicyConfig,
    diagnostics,
    dns::SharedDnsResolver,
    proxy::{
        downstream_status,
        happy_eyeballs::connect_happy_eyeballs,
        http_parse::{parse_http_response_head, read_http_response_head, ParsedHttpRequest},
        mitm::MitmEngine,
        mitm_ca::normalize_authority,
        rules::{RuleEffect, RuleEngine, RuleRequestContext},
        upstream::SharedUpstreamRegistry,
    },
};

const CONNECT_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(100);
const CONNECT_UPSTREAM_RESPONSE_HEAD_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct ConnectTunnelState {
    pub(crate) mitm: MitmEngine,
    pub(crate) rules: RuleEngine,
    pub(crate) upstreams: SharedUpstreamRegistry,
    pub(crate) dns_resolver: SharedDnsResolver,
    pub(crate) connect_policy: ConnectPolicyConfig,
}

pub(crate) async fn handle_connect_tunnel(
    state: ConnectTunnelState,
    client_stream: &mut TcpStream,
    request: &ParsedHttpRequest,
) -> Result<()> {
    let authority = request.uri_text.trim();

    let (target_host, target_port) = match parse_connect_authority(authority) {
        Ok(target) => target,
        Err(error) => {
            debug!(authority = authority, error = %error, "rejected malformed CONNECT authority");
            let response = simple_response_bytes(
                400,
                "Bad Request",
                "RelayGate rejected CONNECT: authority must be a valid host:port.",
            );
            client_stream.write_all(&response).await?;
            client_stream.shutdown().await?;
            return Ok(());
        }
    };

    if let Err(reason) = validate_connect_port_policy(&state.connect_policy, target_port) {
        debug!(authority = authority, port = target_port, reason = %reason, "rejected CONNECT port");
        let _ = diagnostics::append_proxy_diagnostic(&format!(
            "{} event=connect_rejected authority={} reason={}",
            diagnostics::diagnostic_timestamp(),
            authority,
            reason
        ));
        let response = simple_response_bytes(403, "Forbidden", &reason);
        client_stream.write_all(&response).await?;
        client_stream.shutdown().await?;
        return Ok(());
    }

    if downstream_status::is_downstream_status_connect_target(&target_host, target_port) {
        if !state.mitm.status_endpoint_enabled() {
            let response = simple_response_bytes(
                403,
                "Forbidden",
                "RelayGate downstream status requires proxy.mitm.enabled to be true.",
            );
            client_stream.write_all(&response).await?;
            client_stream.shutdown().await?;
            return Ok(());
        }

        debug!(
            authority = authority,
            "CONNECT routed to RelayGate downstream status endpoint"
        );
        return state.mitm.handle_connect(client_stream, authority).await;
    }

    if state.mitm.enabled() && state.mitm.should_intercept_host(authority) {
        if let Ok(ip) = target_host.parse::<IpAddr>() {
            let target_addr = SocketAddr::new(ip, target_port);
            if let Err(reason) = validate_connect_target_ips(&state.connect_policy, &[target_addr])
            {
                debug!(authority = authority, reason = %reason, "rejected CONNECT target IP");
                let _ = diagnostics::append_proxy_diagnostic(&format!(
                    "{} event=connect_rejected authority={} reason={}",
                    diagnostics::diagnostic_timestamp(),
                    authority,
                    reason
                ));
                let response = simple_response_bytes(403, "Forbidden", &reason);
                client_stream.write_all(&response).await?;
                client_stream.shutdown().await?;
                return Ok(());
            }
        }

        return state.mitm.handle_connect(client_stream, authority).await;
    }

    let request_context = RuleRequestContext {
        host: Some(target_host.clone()),
        url: format!("https://{authority}"),
        method: request.method.clone(),
        headers: request.headers.clone(),
    };

    let request_decision = state.rules.evaluate_request(&request_context);
    debug!(?request_decision, "connect rule decision");

    if request_decision
        .effects
        .iter()
        .any(|effect| matches!(effect, RuleEffect::Block))
    {
        // CONNECT rules are evaluated before target DNS resolution so blocked
        // authorities do not cause unnecessary network lookups. This is a
        // request-phase guard only; target IP policy still runs for direct
        // tunnels after routing has decided that local DNS is actually needed.
        let response =
            simple_response_bytes(403, "Forbidden", "Blocked by RelayGate CONNECT rule.");
        client_stream.write_all(&response).await?;
        client_stream.shutdown().await?;
        return Ok(());
    }

    let upstream_id = request_decision
        .effects
        .iter()
        .find_map(|effect| match effect {
            RuleEffect::UseUpstream { upstream_id } => Some(upstream_id.clone()),
            _ => None,
        })
        .or_else(|| {
            request_context
                .host
                .as_deref()
                .and_then(|host| resolve_route_upstream_id(&state.upstreams, host))
        });
    let upstream_label = upstream_id.as_deref().unwrap_or("direct");
    debug!(
        authority = authority,
        upstream = %upstream_label,
        "CONNECT forwarding"
    );

    let target_addrs = if upstream_id.is_some() {
        // When a CONNECT request is routed through an upstream proxy, RelayGate
        // should not resolve the final target locally. The upstream proxy owns
        // final-target DNS and policy in that mode; RelayGate only resolves the
        // selected upstream proxy below.
        Vec::new()
    } else {
        let target_addrs = state
            .dns_resolver
            .resolve_socket_addrs(&target_host, target_port)
            .await
            .with_context(|| format!("failed to resolve CONNECT authority `{authority}`"))?;
        if target_addrs.is_empty() {
            anyhow::bail!("DNS returned no addresses for CONNECT authority `{authority}`");
        }

        if let Err(reason) = validate_connect_target_ips(&state.connect_policy, &target_addrs) {
            debug!(authority = authority, reason = %reason, "rejected CONNECT target IP");
            let _ = diagnostics::append_proxy_diagnostic(&format!(
                "{} event=connect_rejected authority={} reason={}",
                diagnostics::diagnostic_timestamp(),
                authority,
                reason
            ));
            let response = simple_response_bytes(403, "Forbidden", &reason);
            client_stream.write_all(&response).await?;
            client_stream.shutdown().await?;
            return Ok(());
        }

        target_addrs
    };

    let connect_target =
        resolve_connect_target(&state.upstreams, authority, upstream_id.as_deref())?;
    let mut upstream_stream = time::timeout(
        CONNECT_UPSTREAM_CONNECT_TIMEOUT,
        connect_target_stream(
            authority,
            upstream_id.as_deref(),
            &connect_target,
            &target_addrs,
        ),
    )
    .await
    .with_context(|| {
        format!(
            "timed out connecting CONNECT target `{connect_target}` for authority `{authority}`"
        )
    })?
    .with_context(|| {
        format!("failed to connect CONNECT target `{connect_target}` for authority `{authority}`")
    })?;
    let _ = upstream_stream.set_nodelay(true);

    if upstream_id.is_some() {
        let connect_request = build_upstream_connect_request(authority);
        upstream_stream.write_all(&connect_request).await?;
        let response_head = time::timeout(
            CONNECT_UPSTREAM_RESPONSE_HEAD_TIMEOUT,
            read_http_response_head(&mut upstream_stream),
        )
        .await
        .with_context(|| {
            format!("timed out waiting for upstream CONNECT response for {authority}")
        })??;
        let response_meta = parse_http_response_head(&response_head)?;
        if !(200..300).contains(&response_meta.status_code) {
            let response = simple_response_bytes(
                502,
                "Bad Gateway",
                &format!(
                    "RelayGate upstream proxy failed CONNECT for {authority}: HTTP {}",
                    response_meta.status_code
                ),
            );
            client_stream.write_all(&response).await?;
            client_stream.shutdown().await?;
            return Ok(());
        }
    }

    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    info!(
        event = "connect_tunnel_established",
        path = "connect_tunnel",
        downstream = "plain_h1_connect",
        upstream = "tcp_tunnel",
        authority = authority,
        upstream_route = %upstream_label,
        "RelayGate CONNECT tunnel established"
    );
    let (downstream_to_upstream_bytes, upstream_to_downstream_bytes) =
        io::copy_bidirectional(client_stream, &mut upstream_stream).await?;
    info!(
        event = "connect_tunnel_closed",
        path = "connect_tunnel",
        downstream = "plain_h1_connect",
        upstream = "tcp_tunnel",
        authority = authority,
        downstream_to_upstream_bytes = downstream_to_upstream_bytes,
        upstream_to_downstream_bytes = upstream_to_downstream_bytes,
        "RelayGate CONNECT tunnel closed"
    );
    Ok(())
}

async fn connect_target_stream(
    authority: &str,
    upstream_id: Option<&str>,
    connect_target: &str,
    direct_target_addrs: &[SocketAddr],
) -> Result<TcpStream> {
    let addresses = if upstream_id.is_some() {
        tokio::net::lookup_host(connect_target)
            .await
            .with_context(|| format!("failed to resolve upstream proxy `{connect_target}`"))?
            .collect::<Vec<_>>()
    } else {
        direct_target_addrs.to_vec()
    };

    let connection = connect_happy_eyeballs(authority, addresses, CONNECT_HAPPY_EYEBALLS_DELAY)
        .await
        .with_context(|| format!("failed to connect CONNECT authority `{authority}`"))?;

    debug!(
        authority = authority,
        connect_target = connect_target,
        selected_ip = %connection.selected_addr.ip(),
        selected_ip_family = connection.selected_ip_family(),
        connect_ms = connection.connect_ms(),
        happy_eyeballs_delay_ms = connection.delay_ms(),
        request_type = if upstream_id.is_some() { "connect_upstream_proxy" } else { "connect_direct" },
        "Happy Eyeballs selected CONNECT address"
    );

    Ok(connection.stream)
}

fn parse_connect_authority(authority: &str) -> Result<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        anyhow::bail!("CONNECT authority is empty");
    }
    if authority.contains('/') || authority.contains('?') || authority.contains('#') {
        anyhow::bail!("CONNECT authority must not contain path, query, or fragment");
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest
            .find(']')
            .context("invalid CONNECT authority: missing closing `]` for IPv6 host")?;
        let host = &rest[..closing];
        if host.is_empty() {
            anyhow::bail!("CONNECT authority host is empty");
        }
        host.parse::<Ipv6Addr>()
            .with_context(|| format!("CONNECT authority IPv6 host is invalid: {host}"))?;

        let suffix = &rest[closing + 1..];
        let port_text = suffix
            .strip_prefix(':')
            .filter(|value| !value.is_empty())
            .context("CONNECT authority is missing port")?;
        if port_text.contains(':') {
            anyhow::bail!("CONNECT authority port is invalid");
        }
        let port = parse_connect_port(port_text)?;
        return Ok((host.to_string(), port));
    }

    let (host, port_text) = authority
        .rsplit_once(':')
        .context("CONNECT authority is missing port")?;
    if host.trim().is_empty() {
        anyhow::bail!("CONNECT authority host is empty");
    }
    if host.contains(':') {
        anyhow::bail!("IPv6 CONNECT authority must use [host]:port syntax");
    }
    if host.contains('[') || host.contains(']') || host.chars().any(char::is_whitespace) {
        anyhow::bail!("CONNECT authority host is invalid");
    }

    let port = parse_connect_port(port_text)?;
    Ok((host.to_string(), port))
}

fn parse_connect_port(port_text: &str) -> Result<u16> {
    let port = port_text
        .parse::<u16>()
        .with_context(|| format!("CONNECT authority port is invalid: {port_text}"))?;
    if port == 0 {
        anyhow::bail!("CONNECT authority port must be greater than 0");
    }
    Ok(port)
}

fn validate_connect_port_policy(
    policy: &ConnectPolicyConfig,
    port: u16,
) -> std::result::Result<(), String> {
    if policy.blocked_ports.contains(&port) {
        return Err(format!(
            "RelayGate rejected CONNECT: port {port} is blocked by proxy.connect.blocked_ports."
        ));
    }
    if !policy.allowed_ports.is_empty() && !policy.allowed_ports.contains(&port) {
        return Err(format!(
            "RelayGate rejected CONNECT: port {port} is not listed in proxy.connect.allowed_ports."
        ));
    }
    Ok(())
}

fn validate_connect_target_ips(
    policy: &ConnectPolicyConfig,
    addrs: &[SocketAddr],
) -> std::result::Result<(), String> {
    for addr in addrs {
        let ip = addr.ip();
        if !policy.allow_loopback_targets && is_loopback_ip(ip) {
            return Err(format!(
                "RelayGate rejected CONNECT: target resolved to loopback address {ip}."
            ));
        }
        if !policy.allow_private_targets && is_private_or_link_local_ip(ip) {
            return Err(format!(
                "RelayGate rejected CONNECT: target resolved to private or link-local address {ip}."
            ));
        }
    }
    Ok(())
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.octets()[0] == 127,
        IpAddr::V6(ip) => ip == Ipv6Addr::LOCALHOST,
    }
}

fn is_private_or_link_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_or_link_local_ipv4(ip),
        IpAddr::V6(ip) => is_private_or_link_local_ipv6(ip),
    }
}

fn is_private_or_link_local_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 169 && octets[1] == 254)
}

fn is_private_or_link_local_ipv6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
}

fn resolve_connect_target(
    upstreams: &SharedUpstreamRegistry,
    authority: &str,
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

    let (host, port) = normalize_authority(authority)?;
    Ok(format_socket_authority(&host, port))
}

fn resolve_route_upstream_id(upstreams: &SharedUpstreamRegistry, host: &str) -> Option<String> {
    upstreams.read().ok().and_then(|registry| {
        registry
            .resolve_route_for_host(host)
            .map(|route| route.upstream_id.clone())
    })
}

fn format_socket_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn build_upstream_connect_request(authority: &str) -> Vec<u8> {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn simple_response_bytes(status_code: u16, reason_phrase: &str, body: &str) -> Vec<u8> {
    let body_bytes = body.as_bytes();
    format!(
        "HTTP/1.1 {status_code} {reason_phrase}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len(),
    )
    .into_bytes()
    .into_iter()
    .chain(body_bytes.iter().copied())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_connect_authority_requires_port() {
        assert!(parse_connect_authority("example.com").is_err());
        assert_eq!(
            parse_connect_authority("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn strict_connect_authority_parses_bracketed_ipv6() {
        assert_eq!(
            parse_connect_authority("[::1]:8443").unwrap(),
            ("::1".to_string(), 8443)
        );
    }

    #[test]
    fn connect_policy_blocks_private_and_loopback_targets_by_default() {
        let policy = ConnectPolicyConfig::default();
        assert!(validate_connect_target_ips(
            &policy,
            &["127.0.0.1:443".parse::<SocketAddr>().unwrap()]
        )
        .is_err());
        assert!(validate_connect_target_ips(
            &policy,
            &["192.168.1.1:443".parse::<SocketAddr>().unwrap()]
        )
        .is_err());
    }

    #[test]
    fn connect_policy_allows_any_non_blocked_port_by_default() {
        let policy = ConnectPolicyConfig::default();

        assert!(validate_connect_port_policy(&policy, 443).is_ok());
        assert!(validate_connect_port_policy(&policy, 8080).is_ok());
        assert!(validate_connect_port_policy(&policy, 8443).is_ok());
        assert!(validate_connect_port_policy(&policy, 9443).is_ok());
    }

    #[test]
    fn connect_policy_rejects_ports_outside_explicit_allowlist() {
        let policy = ConnectPolicyConfig {
            allowed_ports: vec![443],
            ..ConnectPolicyConfig::default()
        };

        assert!(validate_connect_port_policy(&policy, 443).is_ok());
        assert!(validate_connect_port_policy(&policy, 8080).is_err());
    }

    #[test]
    fn upstream_connect_request_uses_standard_close_header() {
        let text = String::from_utf8(build_upstream_connect_request("example.com:443")).unwrap();

        assert_eq!(
            text,
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn direct_connect_target_formats_bracketed_ipv6() {
        let registry = SharedUpstreamRegistry::default();
        let target = resolve_connect_target(&registry, "[::1]:8443", None).unwrap();

        assert_eq!(target, "[::1]:8443");
    }

    #[test]
    fn direct_connect_target_adds_default_port_for_bracketed_ipv6() {
        let registry = SharedUpstreamRegistry::default();
        let target = resolve_connect_target(&registry, "[::1]", None).unwrap();

        assert_eq!(target, "[::1]:443");
    }
}
