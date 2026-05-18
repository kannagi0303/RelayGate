use std::collections::HashMap;

use axum::response::sse::Event;
use serde::Serialize;

use crate::{
    adblock,
    config::{
        AdblockMode, DnsProfileMode, DownstreamProtocolPreferenceConfig, MinimalPageMode,
        RelayGateConfig, UpstreamProtocolPolicyConfig, UpstreamProtocolPreferenceConfig,
        UpstreamRoutingConfig,
    },
    dns_auto_select, lang,
    proxy::{
        mitm_upstream::MitmUpstreamProtocolPolicy, protocol_runtime::ProtocolRuntimeSnapshot,
        resource_replace, upstream,
    },
    rewrite,
    traffic::{HostTrafficHostSnapshot, TrafficRuntimeSnapshot},
    user_script,
    web::{server::WebAppState, system_actions::build_mitm_status_fast},
};

#[derive(Debug, Serialize)]
struct StatusPayload {
    proxy_listen: String,
    runtime: RuntimeStatusPayload,
    protocol_runtime: ProtocolRuntimeStatusPayload,
    process: ProcessMetricsPayload,
    rule_count: usize,
    rewrite_rule_count: usize,
    adblock_rule_count: usize,
    adblock_resource_count: usize,
    adblock_mode_label: String,
    mitm_mode: String,
    upstream_count: usize,
    upstream_route_count: usize,
    resource_replace_rule_count: usize,
    adblock_mode: String,
    upstreams: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RuntimeStatusPayload {
    session_id: String,
    uptime_secs: u64,
    shutdown_requested: bool,
    backend_signal_version: u64,
    last_backend_changed: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ProtocolRuntimeStatusPayload {
    upstream_preference: String,
    upstream_policy: String,
    upstream_connector_policy: String,
    upstream_http3_buffered_enabled: bool,
    upstream_http3_probe_enabled: bool,
    upstream_http3_streaming_enabled: bool,
    downstream_preference: String,
    downstream_http2_enabled: bool,
}

#[derive(Debug, Serialize)]
struct ProcessMetricsPayload {
    pid: u32,
    cpu_percent: Option<f64>,
    memory_bytes: Option<u64>,
    sample_interval_secs: u64,
    window_secs: u64,
    window_sample_count: usize,
    avg_cpu_percent_15m: Option<f64>,
    peak_cpu_percent_15m: Option<f64>,
    avg_memory_bytes_15m: Option<u64>,
    peak_memory_bytes_15m: Option<u64>,
    session_peak_cpu_percent: Option<f64>,
    session_peak_memory_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct UpstreamItemPayload {
    id: String,
    address: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct UpstreamsPayload {
    items: Vec<UpstreamItemPayload>,
}

#[derive(Debug, Serialize)]
struct UpstreamRouteItemPayload {
    id: String,
    host_pattern: String,
    upstream_id: String,
    enabled: bool,
    upstream_exists: bool,
}

#[derive(Debug, Serialize)]
struct UpstreamRoutesPayload {
    items: Vec<UpstreamRouteItemPayload>,
    upstream_options: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DnsProfileItemPayload {
    id: String,
    mode: String,
    servers: Vec<String>,
    enabled: bool,
    is_system: bool,
    is_active: bool,
    fallback_profiles: Vec<String>,
    health_score: Option<u8>,
    average_latency_ms: Option<u64>,
    success_rate: Option<f64>,
    samples: u64,
}

#[derive(Debug, Serialize)]
struct DnsRouteItemPayload {
    id: String,
    host_pattern: String,
    profile_id: String,
    strict: bool,
    enabled: bool,
    profile_exists: bool,
}

#[derive(Debug, Serialize)]
struct DnsObservationProfilePayload {
    profile_id: String,
    observed_hosts: usize,
    samples: u64,
    success_rate: f64,
    timeout_rate: f64,
    divergent_success_rate: f64,
    average_latency_ms: Option<u64>,
    last_latency_ms: Option<u64>,
    last_ttl_secs: Option<u64>,
    last_error_kind: Option<String>,
    last_observed_age_secs: Option<u64>,
    health_score: u8,
}

#[derive(Debug, Serialize)]
struct DnsObservationPayload {
    enabled: bool,
    observed_hosts: usize,
    profiles: Vec<DnsObservationProfilePayload>,
}

#[derive(Debug, Serialize)]
struct DnsPayload {
    enabled: bool,
    default_profile: String,
    active_profile: String,
    cache_entries: usize,
    warm_cache_enabled: bool,
    auto_select_enabled: bool,
    profiles: Vec<DnsProfileItemPayload>,
    routes: Vec<DnsRouteItemPayload>,
    profile_options: Vec<String>,
    observation: DnsObservationPayload,
}

#[derive(Debug, Serialize)]
struct GatewayMountItemPayload {
    id: String,
    mount_path: String,
    target_base_url: String,
    upstream_id: Option<String>,
    upstream_exists: bool,
    enabled: bool,
    rewrite_links: bool,
    passthrough_mode: bool,
    minimal_page_mode: Option<String>,
}

#[derive(Debug, Serialize)]
struct GatewayPayload {
    items: Vec<GatewayMountItemPayload>,
    upstream_options: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AdblockPayload {
    mode_value: String,
    mode_label: String,
}

#[derive(Debug, Serialize)]
struct ResourceReplaceRulePayload {
    id: String,
    enabled: bool,
    hosts: Vec<String>,
    url_regex: String,
    source_regex: Option<String>,
    file: String,
    content_type: String,
    size: usize,
}

#[derive(Debug, Serialize)]
struct ResourceReplacePayload {
    rule_dir: String,
    rule_count: usize,
    enabled_rule_count: usize,
    rules: Vec<ResourceReplaceRulePayload>,
}

#[derive(Debug, Serialize)]
struct UserScriptPayload {
    script_dir: String,
    items: Vec<user_script::UserScriptListItem>,
}

#[derive(Debug, Serialize)]
struct SettingsPayload {
    app_name: String,
    locale: String,
    available_locales: Vec<String>,
    proxy_listen: String,
    mitm: MitmStatusPayload,
    protocol: ProtocolSettingsPayload,
}

#[derive(Debug, Serialize)]
struct ProtocolSettingsPayload {
    upstream_preferred: String,
    upstream_policy: String,
    upstream_http3_buffered_enabled: bool,
    upstream_http3_probe_enabled: bool,
    upstream_http3_streaming_enabled: bool,
    downstream_preferred: String,
    downstream_http2_enabled: bool,
    apply_note: String,
}

#[derive(Debug, Serialize)]
struct TrafficPayload {
    enabled: bool,
    max_queue_per_host: usize,
    initial_cooldown_secs: u64,
    initial_release_interval_secs: u64,
    controlled_hosts: usize,
    active_requests: usize,
    queued_requests: usize,
    cooling_hosts: usize,
    status_text: String,
    example_text: String,
    direction_text: String,
    hosts: Vec<TrafficHostPayload>,
}

#[derive(Debug, Serialize)]
struct TrafficHostPayload {
    host: String,
    enabled: bool,
    active_requests: usize,
    queued_requests: usize,
    retrying_requests: usize,
    cooldown_text: String,
    last_status_text: String,
    learned_text: String,
}

#[derive(Debug, Serialize)]
struct ConnectionInfoPayload {
    max_items: usize,
    items: Vec<ConnectionInfoHostPayload>,
}

#[derive(Debug, Serialize)]
struct ConnectionInfoHostPayload {
    host: String,
    route: String,
    dns_profile: Option<String>,
    dns_a_count: usize,
    dns_aaaa_count: usize,
    last_ip: Option<String>,
    last_family: Option<String>,
    last_result: String,
    last_connect_ms: Option<u64>,
    family_preference: String,
}

#[derive(Debug, Serialize)]
struct PatchPayload {
    rule_dir: String,
    model_text: String,
    example_text: String,
}

#[derive(Debug, Serialize)]
struct RenderPayload {
    rule_dir: String,
    responsibility_text: String,
    principle_text: String,
}

#[derive(Debug, Serialize)]
struct BackendEventPayload {
    session_id: String,
    changed: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<StatusPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process: Option<ProcessMetricsPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    settings: Option<SettingsPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    traffic: Option<TrafficPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_info: Option<ConnectionInfoPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    patch: Option<PatchPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    render: Option<RenderPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    adblock: Option<AdblockPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_replace: Option<ResourceReplacePayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_script: Option<UserScriptPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<GatewayPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstreams: Option<UpstreamsPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_routes: Option<UpstreamRoutesPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<DnsPayload>,
}

#[derive(Debug, Serialize)]
pub(crate) struct MitmStatusPayload {
    pub(crate) enabled: bool,
    pub(crate) ca_cert_path: String,
    pub(crate) ca_key_path: String,
    pub(crate) ca_cert_exists: bool,
    pub(crate) ca_key_exists: bool,
    pub(crate) windows_user_root_trusted: Option<bool>,
    pub(crate) windows_relaygate_cas: Vec<WindowsRelayGateCaPayload>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WindowsRelayGateCaPayload {
    pub(crate) id: String,
    pub(crate) thumbprint: String,
    pub(crate) subject: String,
    pub(crate) issuer: String,
    pub(crate) not_before: String,
    pub(crate) not_after: String,
    pub(crate) store: String,
    pub(crate) is_current: bool,
}

pub(crate) fn backend_event(
    state: &WebAppState,
    config: &RelayGateConfig,
    changed: Vec<String>,
) -> Event {
    json_backend_event(&backend_payload_value(state, config, changed))
}

pub(crate) fn backend_payload_value(
    state: &WebAppState,
    config: &RelayGateConfig,
    changed: Vec<String>,
) -> serde_json::Value {
    backend_event_payload_value(build_backend_event_payload(state, config, changed))
}

fn backend_event_payload_value(payload: BackendEventPayload) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "session_id".to_string(),
        serde_json::Value::String(payload.session_id),
    );
    object.insert(
        "changed".to_string(),
        serde_json::to_value(payload.changed)
            .unwrap_or_else(|_| serde_json::Value::Array(Vec::new())),
    );
    insert_optional_payload_field(&mut object, "status", payload.status);
    insert_optional_payload_field(&mut object, "process", payload.process);
    insert_optional_payload_field(&mut object, "settings", payload.settings);
    insert_optional_payload_field(&mut object, "traffic", payload.traffic);
    insert_optional_payload_field(&mut object, "connection_info", payload.connection_info);
    insert_optional_payload_field(&mut object, "patch", payload.patch);
    insert_optional_payload_field(&mut object, "render", payload.render);
    insert_optional_payload_field(&mut object, "adblock", payload.adblock);
    insert_optional_payload_field(&mut object, "resource_replace", payload.resource_replace);
    insert_optional_payload_field(&mut object, "user_script", payload.user_script);
    insert_optional_payload_field(&mut object, "gateway", payload.gateway);
    insert_optional_payload_field(&mut object, "upstreams", payload.upstreams);
    insert_optional_payload_field(&mut object, "upstream_routes", payload.upstream_routes);
    insert_optional_payload_field(&mut object, "dns", payload.dns);
    serde_json::Value::Object(object)
}

fn insert_optional_payload_field<T: Serialize>(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &'static str,
    value: Option<T>,
) {
    if let Some(value) = value.and_then(|item| serde_json::to_value(item).ok()) {
        object.insert(key.to_string(), value);
    }
}

fn build_status_payload(state: &WebAppState, config: &RelayGateConfig) -> StatusPayload {
    let backend_signal = state.runtime.backend_signal();
    let rewrite_rule_count = state
        .rewrite_registry
        .read()
        .map(|registry| registry.rule_count())
        .unwrap_or(0);
    let adblock_mode = config.proxy.adblock.effective_mode();
    let adblock_mode_label = display_adblock_mode(adblock_mode);
    let upstream_summary = state
        .upstreams
        .read()
        .map(|registry| registry.status_summary())
        .unwrap_or_else(|_| upstream::UpstreamStatusSummary::default());
    let upstreams = upstream_summary
        .enabled_upstreams
        .iter()
        .map(|item| format!("{} → {}", item.id, item.address))
        .collect::<Vec<_>>();

    StatusPayload {
        proxy_listen: config.proxy.listen.clone(),
        runtime: RuntimeStatusPayload {
            session_id: state.runtime.session_id().to_string(),
            uptime_secs: state.runtime.uptime_secs(),
            shutdown_requested: state.runtime.shutdown_requested(),
            backend_signal_version: backend_signal.version,
            last_backend_changed: backend_signal.changed,
        },
        protocol_runtime: build_protocol_runtime_status_payload(state.protocol_runtime.snapshot()),
        process: build_process_metrics_payload(state.runtime.process_metrics()),
        rule_count: config.rules.len(),
        rewrite_rule_count,
        adblock_rule_count: adblock::rule_count(&state.adblock_state),
        adblock_resource_count: adblock::resource_count(&state.adblock_state),
        adblock_mode_label: adblock_mode_label.clone(),
        mitm_mode: if rewrite_rule_count > 0 || adblock_mode.is_some() {
            lang::text("traffic.mode.auto")
        } else {
            lang::text("traffic.mode.none")
        },
        upstream_count: upstreams.len(),
        upstream_route_count: upstream_summary.enabled_route_count,
        resource_replace_rule_count: resource_replace::rule_count(&state.resource_replace_registry),
        adblock_mode: adblock_mode_label,
        upstreams,
    }
}

fn build_protocol_runtime_status_payload(
    snapshot: ProtocolRuntimeSnapshot,
) -> ProtocolRuntimeStatusPayload {
    ProtocolRuntimeStatusPayload {
        upstream_preference: upstream_protocol_preference_value(snapshot.upstream_preference)
            .to_string(),
        upstream_policy: upstream_protocol_policy_value(snapshot.upstream_protocol_policy_config)
            .to_string(),
        upstream_connector_policy: mitm_upstream_protocol_policy_value(
            snapshot.upstream_protocol_policy,
        )
        .to_string(),
        upstream_http3_buffered_enabled: snapshot.upstream_http3_buffered_enabled,
        upstream_http3_probe_enabled: snapshot.upstream_http3_probe_enabled,
        upstream_http3_streaming_enabled: snapshot.upstream_http3_streaming_enabled,
        downstream_preference: downstream_protocol_preference_value(snapshot.downstream_preference)
            .to_string(),
        downstream_http2_enabled: snapshot.downstream_http2_enabled,
    }
}

fn build_process_metrics_payload(metrics: crate::runtime::ProcessMetrics) -> ProcessMetricsPayload {
    ProcessMetricsPayload {
        pid: metrics.pid,
        cpu_percent: finite_f64_option(metrics.cpu_percent),
        memory_bytes: metrics.memory_bytes,
        sample_interval_secs: metrics.sample_interval_secs,
        window_secs: metrics.window_secs,
        window_sample_count: metrics.window_sample_count,
        avg_cpu_percent_15m: finite_f64_option(metrics.avg_cpu_percent_15m),
        peak_cpu_percent_15m: finite_f64_option(metrics.peak_cpu_percent_15m),
        avg_memory_bytes_15m: metrics.avg_memory_bytes_15m,
        peak_memory_bytes_15m: metrics.peak_memory_bytes_15m,
        session_peak_cpu_percent: finite_f64_option(metrics.session_peak_cpu_percent),
        session_peak_memory_bytes: metrics.session_peak_memory_bytes,
    }
}

fn finite_f64_option(value: Option<f64>) -> Option<f64> {
    value.filter(|item| item.is_finite())
}

fn finite_f64_or_zero(value: f64) -> f64 {
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

fn build_upstreams_payload(routing: &UpstreamRoutingConfig) -> UpstreamsPayload {
    UpstreamsPayload {
        items: routing
            .upstreams
            .iter()
            .map(|item| UpstreamItemPayload {
                id: item.id.clone(),
                address: item.address.clone(),
                enabled: item.enabled,
            })
            .collect(),
    }
}

fn build_upstream_routes_payload(routing: &UpstreamRoutingConfig) -> UpstreamRoutesPayload {
    let upstream_options = routing
        .upstreams
        .iter()
        .filter(|item| item.enabled)
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();

    UpstreamRoutesPayload {
        items: routing
            .upstream_routes
            .iter()
            .map(|item| UpstreamRouteItemPayload {
                id: item.id.clone(),
                host_pattern: item.host_pattern.clone(),
                upstream_id: item.upstream_id.clone(),
                enabled: item.enabled,
                upstream_exists: routing
                    .upstreams
                    .iter()
                    .any(|upstream| upstream.enabled && upstream.id == item.upstream_id),
            })
            .collect(),
        upstream_options,
    }
}

fn build_dns_payload(state: &WebAppState) -> DnsPayload {
    let config = state.dns_resolver.config_snapshot();
    let observation = state.dns_resolver.observation_snapshot();
    let observation_by_profile = observation
        .profiles
        .iter()
        .map(|profile| (profile.profile_id.as_str(), profile))
        .collect::<HashMap<_, _>>();
    let profile_options = config
        .profiles
        .iter()
        .filter(|item| item.enabled)
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let enabled_profile_ids = config
        .profiles
        .iter()
        .filter(|item| item.enabled)
        .map(|item| item.id.clone())
        .collect::<std::collections::HashSet<_>>();
    let active_profile =
        dns_auto_select::best_profile(&config.auto_select, &observation, &enabled_profile_ids)
            .unwrap_or_else(|| config.default_profile.clone());
    let mut profiles = config.profiles.iter().collect::<Vec<_>>();
    profiles.sort_by_key(|profile| matches!(profile.mode, DnsProfileMode::System));
    DnsPayload {
        enabled: config.enabled,
        default_profile: config.default_profile.clone(),
        active_profile: active_profile.clone(),
        cache_entries: state.dns_resolver.cache_len(),
        warm_cache_enabled: config.warm_cache.enabled,
        auto_select_enabled: config.auto_select.enabled,
        profiles: profiles
            .iter()
            .map(|item| DnsProfileItemPayload {
                id: item.id.clone(),
                mode: dns_profile_mode_value(item.mode).to_string(),
                servers: item.servers.clone(),
                enabled: item.enabled,
                is_system: matches!(item.mode, DnsProfileMode::System),
                is_active: item.id == active_profile,
                fallback_profiles: item.fallback_profiles.clone(),
                health_score: observation_by_profile
                    .get(item.id.as_str())
                    .map(|profile| profile.health_score),
                average_latency_ms: observation_by_profile
                    .get(item.id.as_str())
                    .and_then(|profile| profile.average_latency_ms),
                success_rate: observation_by_profile
                    .get(item.id.as_str())
                    .and_then(|profile| finite_f64_option(Some(profile.success_rate))),
                samples: observation_by_profile
                    .get(item.id.as_str())
                    .map(|profile| profile.samples)
                    .unwrap_or(0),
            })
            .collect(),
        routes: config
            .routes
            .iter()
            .map(|item| DnsRouteItemPayload {
                id: item.id.clone(),
                host_pattern: item.host_pattern.clone(),
                profile_id: item.profile_id.clone(),
                strict: item.strict,
                enabled: item.enabled,
                profile_exists: config.profiles.iter().any(|profile| {
                    profile.enabled
                        && !matches!(profile.mode, DnsProfileMode::System)
                        && profile.id == item.profile_id
                }),
            })
            .collect(),
        profile_options,
        observation: DnsObservationPayload {
            enabled: config.observation.enabled,
            observed_hosts: observation.observed_hosts,
            profiles: observation
                .profiles
                .into_iter()
                .map(|profile| DnsObservationProfilePayload {
                    profile_id: profile.profile_id,
                    observed_hosts: profile.observed_hosts,
                    samples: profile.samples,
                    success_rate: finite_f64_or_zero(profile.success_rate),
                    timeout_rate: finite_f64_or_zero(profile.timeout_rate),
                    divergent_success_rate: finite_f64_or_zero(profile.divergent_success_rate),
                    average_latency_ms: profile.average_latency_ms,
                    last_latency_ms: profile.last_latency_ms,
                    last_ttl_secs: profile.last_ttl_secs,
                    last_error_kind: profile.last_error_kind.map(str::to_string),
                    last_observed_age_secs: profile.last_observed_age_secs,
                    health_score: profile.health_score,
                })
                .collect(),
        },
    }
}

fn dns_profile_mode_value(mode: DnsProfileMode) -> &'static str {
    match mode {
        DnsProfileMode::System => "system",
        DnsProfileMode::Udp => "udp",
    }
}

fn build_gateway_payload(
    config: &RelayGateConfig,
    routing: &UpstreamRoutingConfig,
) -> GatewayPayload {
    let upstream_options = routing
        .upstreams
        .iter()
        .filter(|item| item.enabled)
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();

    GatewayPayload {
        items: config
            .gateway
            .mounts
            .iter()
            .map(|item| GatewayMountItemPayload {
                id: item.id.clone(),
                mount_path: item.mount_path.clone(),
                target_base_url: item.target_base_url.clone(),
                upstream_id: item.upstream_id.clone(),
                upstream_exists: item.upstream_id.as_ref().is_none_or(|upstream_id| {
                    routing
                        .upstreams
                        .iter()
                        .any(|upstream| upstream.enabled && upstream.id == *upstream_id)
                }),
                enabled: item.enabled,
                rewrite_links: item.rewrite_links,
                passthrough_mode: item.passthrough_mode,
                minimal_page_mode: item
                    .minimal_page_mode
                    .as_ref()
                    .map(|mode| gateway_minimal_mode_value(mode).to_string()),
            })
            .collect(),
        upstream_options,
    }
}

fn build_adblock_payload(_state: &WebAppState, config: &RelayGateConfig) -> AdblockPayload {
    AdblockPayload {
        mode_value: adblock_mode_value(config.proxy.adblock.effective_mode()).to_string(),
        mode_label: display_adblock_mode(config.proxy.adblock.effective_mode()).to_string(),
    }
}

fn build_resource_replace_payload(state: &WebAppState) -> ResourceReplacePayload {
    let rules = resource_replace::rule_infos(&state.resource_replace_registry)
        .into_iter()
        .map(|item| ResourceReplaceRulePayload {
            id: item.id,
            enabled: item.enabled,
            hosts: item.hosts,
            url_regex: item.url_regex,
            source_regex: item.source_regex,
            file: item.file,
            content_type: item.content_type,
            size: item.size,
        })
        .collect::<Vec<_>>();

    ResourceReplacePayload {
        rule_dir: resource_replace::rule_dir().display().to_string(),
        rule_count: resource_replace::rule_count(&state.resource_replace_registry),
        enabled_rule_count: resource_replace::enabled_rule_count(&state.resource_replace_registry),
        rules,
    }
}

fn build_user_script_payload(state: &WebAppState) -> UserScriptPayload {
    UserScriptPayload {
        script_dir: user_script::script_dir().display().to_string(),
        items: user_script::list_items(&state.user_script_registry),
    }
}

fn build_settings_payload(config: &RelayGateConfig) -> SettingsPayload {
    SettingsPayload {
        app_name: config.app.name.clone(),
        locale: config.locale.clone(),
        available_locales: lang::available_locales(),
        proxy_listen: config.proxy.listen.clone(),
        mitm: build_mitm_status_fast(config),
        protocol: build_protocol_settings_payload(config),
    }
}

fn build_protocol_settings_payload(config: &RelayGateConfig) -> ProtocolSettingsPayload {
    ProtocolSettingsPayload {
        upstream_preferred: upstream_protocol_preference_value(config.upstream_protocol)
            .to_string(),
        upstream_policy: upstream_protocol_policy_value(config.proxy.upstream.protocol_policy)
            .to_string(),
        upstream_http3_buffered_enabled: config.proxy.upstream.http3_buffered_response_enabled,
        upstream_http3_probe_enabled: config.proxy.upstream.http3_probe_enabled,
        upstream_http3_streaming_enabled: config.proxy.upstream.http3_streaming_response_enabled,
        downstream_preferred: downstream_protocol_preference_value(config.downstream_protocol)
            .to_string(),
        downstream_http2_enabled: config.proxy.mitm.downstream_http2,
        apply_note: lang::text("settings.protocol.apply_note"),
    }
}

fn build_traffic_payload(state: &WebAppState, config: &RelayGateConfig) -> TrafficPayload {
    let snapshot = state.traffic_state.snapshot();
    TrafficPayload {
        enabled: config.traffic.enabled,
        max_queue_per_host: config.traffic.max_queue_per_host,
        initial_cooldown_secs: config.traffic.initial_cooldown_secs,
        initial_release_interval_secs: config.traffic.initial_release_interval_secs,
        controlled_hosts: snapshot.controlled_hosts,
        active_requests: snapshot.active_requests,
        queued_requests: snapshot.queued_requests,
        cooling_hosts: snapshot.cooling_hosts,
        status_text: lang::text("traffic.text.status"),
        example_text: lang::text("traffic.text.example"),
        direction_text: lang::text("traffic.text.direction"),
        hosts: build_traffic_host_payloads(snapshot),
    }
}

fn build_connection_info_payload(state: &WebAppState) -> ConnectionInfoPayload {
    let snapshot = state.dns_resolver.connection_info_snapshot();
    ConnectionInfoPayload {
        max_items: snapshot.max_items,
        items: snapshot
            .items
            .into_iter()
            .map(|item| ConnectionInfoHostPayload {
                host: item.host,
                route: item.route,
                dns_profile: item.dns_profile,
                dns_a_count: item.dns_a_count,
                dns_aaaa_count: item.dns_aaaa_count,
                last_ip: item.last_ip.map(|ip| ip.to_string()),
                last_family: item.last_family,
                last_result: item.last_result,
                last_connect_ms: item.last_connect_ms,
                family_preference: item.family_preference,
            })
            .collect(),
    }
}

fn build_patch_payload(_config: &RelayGateConfig) -> PatchPayload {
    PatchPayload {
        rule_dir: rewrite::patch_rule_dir().display().to_string(),
        model_text: lang::text("patch.text.model"),
        example_text: lang::text("patch.text.example"),
    }
}

fn build_render_payload(_config: &RelayGateConfig) -> RenderPayload {
    RenderPayload {
        rule_dir: rewrite::render_rule_dir().display().to_string(),
        responsibility_text: lang::text("render.text.duty"),
        principle_text: lang::text("render.text.rule"),
    }
}

fn build_backend_event_payload(
    state: &WebAppState,
    config: &RelayGateConfig,
    changed: Vec<String>,
) -> BackendEventPayload {
    let include_status = changed_contains(&changed, "status");
    let include_process = changed_contains(&changed, "process");
    let include_settings = changed_contains(&changed, "settings");
    let include_traffic = changed_contains(&changed, "traffic");
    let include_connection_info = changed_contains(&changed, "connection_info");
    let include_patch = changed_contains(&changed, "patch");
    let include_render = changed_contains(&changed, "render");
    let include_adblock = changed_contains(&changed, "adblock");
    let include_resource_replace = changed_contains(&changed, "resource_replace");
    let include_user_script = changed_contains(&changed, "user_script");
    let include_gateway = changed_contains(&changed, "gateway");
    let include_upstreams = changed_contains(&changed, "upstreams");
    let include_upstream_routes = changed_contains(&changed, "upstream_routes");
    let include_dns = changed_contains(&changed, "dns");

    let needs_routing = include_gateway || include_upstreams || include_upstream_routes;
    let routing = needs_routing.then(|| current_upstream_routing(config));

    BackendEventPayload {
        session_id: state.runtime.session_id().to_string(),
        changed,
        status: include_status.then(|| build_status_payload(state, config)),
        process: include_process
            .then(|| build_process_metrics_payload(state.runtime.process_metrics())),
        settings: include_settings.then(|| build_settings_payload(config)),
        traffic: include_traffic.then(|| build_traffic_payload(state, config)),
        connection_info: include_connection_info.then(|| build_connection_info_payload(state)),
        patch: include_patch.then(|| build_patch_payload(config)),
        render: include_render.then(|| build_render_payload(config)),
        adblock: include_adblock.then(|| build_adblock_payload(state, config)),
        resource_replace: include_resource_replace.then(|| build_resource_replace_payload(state)),
        user_script: include_user_script.then(|| build_user_script_payload(state)),
        gateway: include_gateway
            .then(|| build_gateway_payload(config, routing.as_ref().expect("routing loaded"))),
        upstreams: include_upstreams
            .then(|| build_upstreams_payload(routing.as_ref().expect("routing loaded"))),
        upstream_routes: include_upstream_routes
            .then(|| build_upstream_routes_payload(routing.as_ref().expect("routing loaded"))),
        dns: include_dns.then(|| build_dns_payload(state)),
    }
}

fn changed_contains(changed: &[String], key: &str) -> bool {
    changed.iter().any(|item| item == key)
}

fn current_upstream_routing(config: &RelayGateConfig) -> UpstreamRoutingConfig {
    UpstreamRoutingConfig::from_main_config(config)
}

fn json_backend_event<T: Serialize>(payload: &T) -> Event {
    let data = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    Event::default().data(data)
}

fn adblock_mode_value(mode: Option<AdblockMode>) -> &'static str {
    match mode {
        None => "disabled",
        Some(AdblockMode::Standard) => "standard",
        Some(AdblockMode::Aggressive) => "aggressive",
    }
}

fn gateway_minimal_mode_value(mode: &MinimalPageMode) -> &'static str {
    match mode {
        MinimalPageMode::OnejavTorrent => "onejav_torrent",
    }
}

fn upstream_protocol_preference_value(
    preference: UpstreamProtocolPreferenceConfig,
) -> &'static str {
    match preference {
        UpstreamProtocolPreferenceConfig::Auto
        | UpstreamProtocolPreferenceConfig::Http2PriorKnowledge
        | UpstreamProtocolPreferenceConfig::GuardedH3 => "guarded_h3",
        UpstreamProtocolPreferenceConfig::Http1Only
        | UpstreamProtocolPreferenceConfig::Http2Preferred => "http2_preferred",
    }
}

fn downstream_protocol_preference_value(
    preference: DownstreamProtocolPreferenceConfig,
) -> &'static str {
    match preference {
        DownstreamProtocolPreferenceConfig::Http1Only => "http1_only",
        DownstreamProtocolPreferenceConfig::Http2Enabled => "http2_enabled",
    }
}

fn upstream_protocol_policy_value(policy: UpstreamProtocolPolicyConfig) -> &'static str {
    match policy {
        UpstreamProtocolPolicyConfig::Auto => "auto",
        UpstreamProtocolPolicyConfig::Http1Only => "http1_only",
        UpstreamProtocolPolicyConfig::Http2PriorKnowledge => "http2_prior_knowledge",
    }
}

fn mitm_upstream_protocol_policy_value(policy: MitmUpstreamProtocolPolicy) -> &'static str {
    match policy {
        MitmUpstreamProtocolPolicy::Auto => "auto",
        MitmUpstreamProtocolPolicy::Http1Only => "http1_only",
        MitmUpstreamProtocolPolicy::Http2PriorKnowledge => "http2_prior_knowledge",
    }
}

fn display_adblock_mode(mode: Option<AdblockMode>) -> String {
    match mode {
        None => lang::text("adblock.mode.off"),
        Some(AdblockMode::Standard) => lang::text("adblock.mode.std"),
        Some(AdblockMode::Aggressive) => lang::text("adblock.mode.agg"),
    }
}

fn build_traffic_host_payloads(snapshot: TrafficRuntimeSnapshot) -> Vec<TrafficHostPayload> {
    snapshot
        .hosts
        .into_iter()
        .take(8)
        .map(build_traffic_host_payload)
        .collect()
}

fn build_traffic_host_payload(host: HostTrafficHostSnapshot) -> TrafficHostPayload {
    let cooldown_text = host
        .cooldown_remaining_secs
        .map(|secs| format!("{}s", secs.max(1)))
        .unwrap_or_else(|| lang::text("common.none"));
    let last_status_text = match host.last_status_code {
        Some(429) => {
            if let Some(remaining) = host.cooldown_remaining_secs {
                format!("429 / remaining {}s", remaining)
            } else {
                "429".to_string()
            }
        }
        Some(status) => status.to_string(),
        None => lang::text("traffic.host.none"),
    };
    let mode_label = if host.throttled {
        lang::text("traffic.host.throttling")
    } else {
        lang::text("traffic.host.pass")
    };

    TrafficHostPayload {
        host: host.host,
        enabled: host.enabled,
        active_requests: host.active_requests,
        queued_requests: host.queued_requests,
        retrying_requests: host.retrying_requests,
        cooldown_text,
        last_status_text: format!("{mode_label} / {last_status_text}"),
        learned_text: format!(
            "cooldown {}s / interval {}s / retry {} / stable {}",
            host.cooldown_secs,
            host.release_interval_secs,
            host.retrying_requests,
            host.stable_successes
        ),
    }
}
