use axum::response::sse::Event;
use serde::Serialize;

use crate::{
    adblock,
    config::{
        AdblockMode, DnsProfileMode, DownstreamProtocolPreferenceConfig, MinimalPageMode,
        RelayGateConfig, UpstreamProtocolPolicyConfig, UpstreamProtocolPreferenceConfig,
        UpstreamRoutingConfig,
    },
    lang,
    proxy::{
        mitm_upstream::MitmUpstreamProtocolPolicy, protocol_runtime::ProtocolRuntimeSnapshot,
        resource_replace,
    },
    rewrite,
    traffic::{HostTrafficHostSnapshot, TrafficRuntimeSnapshot},
    user_script,
    web::{server::WebAppState, system_actions::build_mitm_status},
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
    fallback_profiles: Vec<String>,
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
struct DnsPayload {
    enabled: bool,
    default_profile: String,
    cache_entries: usize,
    profiles: Vec<DnsProfileItemPayload>,
    routes: Vec<DnsRouteItemPayload>,
    profile_options: Vec<String>,
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
struct AdblockFilePayload {
    name: String,
    size: u64,
    source_url: Option<String>,
    title: Option<String>,
    tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AdblockPayload {
    mode_value: String,
    mode_label: String,
    disable_mitm_fast_path: bool,
    debug_log_enabled: bool,
    rule_count: usize,
    resource_count: usize,
    custom_rule_file: String,
    rule_dir: String,
    files: Vec<AdblockFilePayload>,
    resource_files: Vec<AdblockFilePayload>,
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
    status: StatusPayload,
    settings: SettingsPayload,
    traffic: TrafficPayload,
    patch: PatchPayload,
    render: RenderPayload,
    adblock: AdblockPayload,
    resource_replace: ResourceReplacePayload,
    user_script: UserScriptPayload,
    gateway: GatewayPayload,
    upstreams: UpstreamsPayload,
    upstream_routes: UpstreamRoutesPayload,
    dns: DnsPayload,
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
    json_backend_event(&build_backend_event_payload(state, config, changed))
}

fn build_status_payload(
    state: &WebAppState,
    config: &RelayGateConfig,
    routing: &UpstreamRoutingConfig,
) -> StatusPayload {
    let backend_signal = state.runtime.backend_signal();
    let rewrite_rule_count = state
        .rewrite_registry
        .read()
        .map(|registry| registry.rule_count())
        .unwrap_or(0);
    let adblock_mode = config.proxy.adblock.effective_mode();
    let adblock_mode_label = display_adblock_mode(adblock_mode);
    let upstreams = routing
        .upstreams
        .iter()
        .filter(|item| item.enabled)
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
        upstream_route_count: routing
            .upstream_routes
            .iter()
            .filter(|item| item.enabled)
            .count(),
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
        cpu_percent: metrics.cpu_percent,
        memory_bytes: metrics.memory_bytes,
        sample_interval_secs: metrics.sample_interval_secs,
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
    let profile_options = config
        .profiles
        .iter()
        .filter(|item| item.enabled && !matches!(item.mode, DnsProfileMode::System))
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    DnsPayload {
        enabled: config.enabled,
        default_profile: config.default_profile.clone(),
        cache_entries: state.dns_resolver.cache_len(),
        profiles: config
            .profiles
            .iter()
            .filter(|item| !matches!(item.mode, DnsProfileMode::System))
            .map(|item| DnsProfileItemPayload {
                id: item.id.clone(),
                mode: dns_profile_mode_value(item.mode).to_string(),
                servers: item.servers.clone(),
                enabled: item.enabled,
                fallback_profiles: item.fallback_profiles.clone(),
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
                profile_exists: config
                    .profiles
                    .iter()
                    .any(|profile| profile.enabled && profile.id == item.profile_id),
            })
            .collect(),
        profile_options,
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

fn build_adblock_payload(state: &WebAppState, config: &RelayGateConfig) -> AdblockPayload {
    let files = adblock::list_rule_files()
        .unwrap_or_default()
        .into_iter()
        .map(|file| AdblockFilePayload {
            name: file.name,
            size: file.size,
            source_url: file.source_url,
            title: file.title,
            tags: file.tags,
        })
        .collect();
    let resource_files = adblock::list_resource_files()
        .unwrap_or_default()
        .into_iter()
        .map(|file| AdblockFilePayload {
            name: file.name,
            size: file.size,
            source_url: file.source_url,
            title: file.title,
            tags: file.tags,
        })
        .collect();
    let custom_rule_file = adblock::custom_rule_file_path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| {
            adblock::adblock_rule_dir_path()
                .join("custom.txt")
                .display()
                .to_string()
        });

    AdblockPayload {
        mode_value: adblock_mode_value(config.proxy.adblock.effective_mode()).to_string(),
        mode_label: display_adblock_mode(config.proxy.adblock.effective_mode()).to_string(),
        disable_mitm_fast_path: config.disable_mitm_fast_path,
        debug_log_enabled: config.adblock_debug_log,
        rule_count: adblock::rule_count(&state.adblock_state),
        resource_count: adblock::resource_count(&state.adblock_state),
        custom_rule_file,
        rule_dir: adblock::adblock_rule_dir_path().display().to_string(),
        files,
        resource_files,
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
        mitm: build_mitm_status(config),
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
    let routing = current_upstream_routing(config);
    BackendEventPayload {
        session_id: state.runtime.session_id().to_string(),
        changed,
        status: build_status_payload(state, config, &routing),
        settings: build_settings_payload(config),
        traffic: build_traffic_payload(state, config),
        patch: build_patch_payload(config),
        render: build_render_payload(config),
        adblock: build_adblock_payload(state, config),
        resource_replace: build_resource_replace_payload(state),
        user_script: build_user_script_payload(state),
        gateway: build_gateway_payload(config, &routing),
        upstreams: build_upstreams_payload(&routing),
        upstream_routes: build_upstream_routes_payload(&routing),
        dns: build_dns_payload(state),
    }
}

fn current_upstream_routing(config: &RelayGateConfig) -> UpstreamRoutingConfig {
    UpstreamRoutingConfig::load_default_or_config(config)
        .unwrap_or_else(|_| UpstreamRoutingConfig::from_main_config(config))
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
