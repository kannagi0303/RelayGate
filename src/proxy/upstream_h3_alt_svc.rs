use std::{
    collections::VecDeque,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_RECENT_H3_ALT_SVC_AUTHORITIES: usize = 16;
const MAX_H3_CANDIDATE_CACHE_ENTRIES: usize = 16;

/// RelayGate-owned snapshot of an upstream HTTP/3 candidate learned from Alt-Svc.
///
/// This type is intentionally independent from any future QUIC/H3 crate. Future
/// backends can use it as input without leaking `quinn`, `h3`, or `h3-quinn`
/// details into the shared MITM core.
#[derive(Debug, Clone)]
pub(crate) struct UpstreamHttp3Candidate {
    pub(crate) authority: String,
    pub(crate) protocol: String,
    pub(crate) advertised_port: Option<u16>,
    pub(crate) ma_seconds: Option<u64>,
    pub(crate) expires_at_unix: Option<u64>,
    pub(crate) alt_svc: String,
    pub(crate) observed_at: String,
}

#[derive(Debug, Clone)]
pub(crate) struct UpstreamH3AltSvcObservationEvent {
    pub(crate) authority: String,
    pub(crate) alt_svc: String,
    pub(crate) observed_at: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UpstreamH3AltSvcObservationSnapshot {
    pub(crate) h3_advertisements: u64,
    pub(crate) last_h3: Option<UpstreamH3AltSvcObservationEvent>,
    pub(crate) recent_h3_authorities: Vec<String>,
    pub(crate) active_h3_candidates: Vec<UpstreamHttp3Candidate>,
}
#[derive(Debug, Clone, Default)]
struct UpstreamH3AltSvcObservationState {
    h3_advertisements: u64,
    last_h3: Option<UpstreamH3AltSvcObservationEvent>,
    recent_h3_authorities: VecDeque<String>,
    h3_candidates: VecDeque<UpstreamHttp3Candidate>,
}

#[derive(Debug, Clone)]
struct ParsedH3AltSvcCandidate {
    protocol: String,
    advertised_port: Option<u16>,
    ma_seconds: Option<u64>,
}

fn upstream_h3_alt_svc_observation_state() -> &'static Mutex<UpstreamH3AltSvcObservationState> {
    static STATE: OnceLock<Mutex<UpstreamH3AltSvcObservationState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(UpstreamH3AltSvcObservationState::default()))
}

/// Records H3-capable Alt-Svc information from a stable upstream H1/H2 response.
///
/// This remains observation-only. It never changes forwarding behavior and never
/// attempts QUIC by itself.
pub(crate) fn record_alt_svc(authority: &str, headers: &reqwest::header::HeaderMap) {
    let alt_svc = collect_alt_svc_header_values(headers);
    if alt_svc.is_empty() || !alt_svc_advertises_h3(&alt_svc) {
        return;
    }

    let parsed_candidates = parse_h3_alt_svc_candidates(&alt_svc);
    let observed_at = unix_seconds_now();
    let now = unix_timestamp_now();

    let Ok(mut state) = upstream_h3_alt_svc_observation_state().lock() else {
        return;
    };

    prune_expired_h3_candidates(&mut state, now);

    state.h3_advertisements = state.h3_advertisements.saturating_add(1);
    state.last_h3 = Some(UpstreamH3AltSvcObservationEvent {
        authority: authority.to_string(),
        alt_svc: alt_svc.clone(),
        observed_at: observed_at.clone(),
    });

    if let Some(position) = state
        .recent_h3_authorities
        .iter()
        .position(|item| item.eq_ignore_ascii_case(authority))
    {
        state.recent_h3_authorities.remove(position);
    }
    state
        .recent_h3_authorities
        .push_front(authority.to_string());
    while state.recent_h3_authorities.len() > MAX_RECENT_H3_ALT_SVC_AUTHORITIES {
        state.recent_h3_authorities.pop_back();
    }

    if let Some(candidate) = parsed_candidates.into_iter().next() {
        update_h3_candidate_cache(
            &mut state,
            authority,
            &alt_svc,
            candidate,
            &observed_at,
            now,
        );
    }
}

pub(crate) fn observation_snapshot() -> UpstreamH3AltSvcObservationSnapshot {
    let now = unix_timestamp_now();
    let Ok(mut state) = upstream_h3_alt_svc_observation_state().lock() else {
        return UpstreamH3AltSvcObservationSnapshot::default();
    };
    prune_expired_h3_candidates(&mut state, now);
    UpstreamH3AltSvcObservationSnapshot {
        h3_advertisements: state.h3_advertisements,
        last_h3: state.last_h3.clone(),
        recent_h3_authorities: state.recent_h3_authorities.iter().cloned().collect(),
        active_h3_candidates: state.h3_candidates.iter().cloned().collect(),
    }
}

#[allow(dead_code)]
pub(crate) fn active_candidate_for_authority(authority: &str) -> Option<UpstreamHttp3Candidate> {
    let now = unix_timestamp_now();
    let Ok(mut state) = upstream_h3_alt_svc_observation_state().lock() else {
        return None;
    };
    prune_expired_h3_candidates(&mut state, now);
    state
        .h3_candidates
        .iter()
        .find(|candidate| candidate.authority.eq_ignore_ascii_case(authority))
        .cloned()
}

#[allow(dead_code)]
pub(crate) fn has_active_candidate(authority: &str) -> bool {
    active_candidate_for_authority(authority).is_some()
}

#[allow(dead_code)]
pub(crate) fn active_candidates_snapshot() -> Vec<UpstreamHttp3Candidate> {
    observation_snapshot().active_h3_candidates
}

fn collect_alt_svc_header_values(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .get_all("alt-svc")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(" | ")
}

fn alt_svc_advertises_h3(alt_svc: &str) -> bool {
    alt_svc.split(',').any(|entry| {
        let token = entry
            .trim()
            .split('=')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .to_ascii_lowercase();
        token == "h3" || token.starts_with("h3-")
    })
}

fn parse_h3_alt_svc_candidates(alt_svc: &str) -> Vec<ParsedH3AltSvcCandidate> {
    alt_svc
        .split(',')
        .filter_map(parse_h3_alt_svc_candidate)
        .collect()
}

fn parse_h3_alt_svc_candidate(entry: &str) -> Option<ParsedH3AltSvcCandidate> {
    let mut parts = entry.split(';');
    let service = parts.next()?.trim();
    let (protocol, raw_value) = service.split_once('=')?;
    let protocol = protocol.trim().trim_matches('"').to_ascii_lowercase();
    if protocol != "h3" && !protocol.starts_with("h3-") {
        return None;
    }

    let advertised_port = parse_alt_svc_port(raw_value.trim());
    let mut ma_seconds = None;
    for part in parts {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("ma") {
            ma_seconds = value.trim().trim_matches('"').parse::<u64>().ok();
        }
    }

    Some(ParsedH3AltSvcCandidate {
        protocol,
        advertised_port,
        ma_seconds,
    })
}

fn parse_alt_svc_port(raw_value: &str) -> Option<u16> {
    let value = raw_value.trim().trim_matches('"').trim();
    let port = value.strip_prefix(':')?;
    port.parse::<u16>().ok()
}

fn update_h3_candidate_cache(
    state: &mut UpstreamH3AltSvcObservationState,
    authority: &str,
    alt_svc: &str,
    candidate: ParsedH3AltSvcCandidate,
    observed_at: &str,
    now: Option<u64>,
) {
    if let Some(position) = state
        .h3_candidates
        .iter()
        .position(|item| item.authority.eq_ignore_ascii_case(authority))
    {
        state.h3_candidates.remove(position);
    }

    if candidate.ma_seconds == Some(0) {
        return;
    }

    let expires_at_unix = match (now, candidate.ma_seconds) {
        (Some(now), Some(ma_seconds)) => Some(now.saturating_add(ma_seconds)),
        _ => None,
    };

    state.h3_candidates.push_front(UpstreamHttp3Candidate {
        authority: authority.to_string(),
        protocol: candidate.protocol,
        advertised_port: candidate.advertised_port,
        ma_seconds: candidate.ma_seconds,
        expires_at_unix,
        alt_svc: alt_svc.to_string(),
        observed_at: observed_at.to_string(),
    });

    while state.h3_candidates.len() > MAX_H3_CANDIDATE_CACHE_ENTRIES {
        state.h3_candidates.pop_back();
    }
}

fn prune_expired_h3_candidates(state: &mut UpstreamH3AltSvcObservationState, now: Option<u64>) {
    let Some(now) = now else {
        return;
    };
    state
        .h3_candidates
        .retain(|candidate| match candidate.expires_at_unix {
            Some(expires) => expires > now,
            None => true,
        });
}

fn unix_timestamp_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn unix_seconds_now() -> String {
    unix_timestamp_now().unwrap_or(0).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn headers_with_alt_svc(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("alt-svc", HeaderValue::from_static(value));
        headers
    }

    #[test]
    fn records_active_h3_alt_svc_candidate() {
        record_alt_svc(
            "example.test",
            &headers_with_alt_svc(r#"h3=":8443"; ma=120"#),
        );

        let snapshot = observation_snapshot();
        assert!(snapshot
            .recent_h3_authorities
            .iter()
            .any(|authority| authority == "example.test"));
        let candidate = active_candidate_for_authority("EXAMPLE.test").expect("active candidate");
        assert_eq!(candidate.authority, "example.test");
        assert_eq!(candidate.protocol, "h3");
        assert_eq!(candidate.advertised_port, Some(8443));
        assert_eq!(candidate.ma_seconds, Some(120));
        assert!(candidate.expires_at_unix.is_some());
    }

    #[test]
    fn ma_zero_removes_existing_candidate() {
        record_alt_svc(
            "remove.example",
            &headers_with_alt_svc(r#"h3=":443"; ma=120"#),
        );
        assert!(active_candidate_for_authority("remove.example").is_some());

        record_alt_svc(
            "remove.example",
            &headers_with_alt_svc(r#"h3=":443"; ma=0"#),
        );

        assert!(active_candidate_for_authority("remove.example").is_none());
    }

    #[test]
    fn ignores_non_h3_alt_svc_values() {
        record_alt_svc(
            "ignored.example",
            &headers_with_alt_svc(r#"h2=":443"; ma=120"#),
        );

        assert!(active_candidate_for_authority("ignored.example").is_none());
    }
}
