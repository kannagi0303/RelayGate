use std::net::IpAddr;

/// Returns whether a peer IP may access a local RelayGate surface.
///
/// Security model:
/// - `allow_lan = false`: only loopback clients are allowed.
/// - `allow_lan = true`: only IPs explicitly listed in `allowed_clients` are allowed.
pub fn is_client_ip_allowed(peer_ip: IpAddr, allow_lan: bool, allowed_clients: &[String]) -> bool {
    let peer_ip = normalize_ip(peer_ip);

    if !allow_lan {
        return peer_ip.is_loopback();
    }

    allowed_clients
        .iter()
        .filter_map(|entry| parse_allowed_client_ip(entry))
        .any(|allowed_ip| normalize_ip(allowed_ip) == peer_ip)
}

fn parse_allowed_client_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches(['[', ']']);
    if value.is_empty() {
        return None;
    }

    value.parse::<IpAddr>().ok()
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ipv6)),
    }
}
