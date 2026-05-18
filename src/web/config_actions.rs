use anyhow::Context;
use std::net::{IpAddr, SocketAddr};

use crate::{
    adblock,
    config::{
        gateway_mount_id_from_user_input, gateway_mount_path_from_id, AdblockModeSetting,
        DnsConfig, DnsProfileConfig, DnsProfileMode, DnsRouteConfig,
        DownstreamProtocolPreferenceConfig, GatewayConfig, MountSiteConfig, RelayGateConfig,
        UpstreamConfig, UpstreamProtocolPreferenceConfig, UpstreamRouteConfig,
        UpstreamRoutingConfig,
    },
    dns, lang,
    proxy::{gateway_mount, resource_replace, upstream},
    rewrite, user_script,
    web::{
        action_forms::{
            DeleteItemForm, DnsFeatureToggleForm, DnsProfileForm, DnsRouteForm, GatewayMountForm,
            MoveItemForm, ToggleItemForm, UpdateProtocolSettingsForm, UpdateSettingForm,
            UpstreamForm, UpstreamRouteForm,
        },
        server::WebAppState,
    },
};

pub(crate) fn update_single_setting(
    state: &WebAppState,
    form: &UpdateSettingForm,
) -> anyhow::Result<String> {
    let mut config = current_config(state);

    match form.key.as_str() {
        "listen" | "proxy.listen" => config.listen = form.value.clone(),
        "adblock.mode" => {
            config.set_adblock_mode_preference(parse_adblock_mode_setting(&form.value)?);
        }
        "proxy.protocol.upstream_preferred" => {
            config.upstream_protocol = parse_upstream_preferred_protocol(&form.value)?
        }
        "proxy.protocol.downstream_preferred" => {
            config.downstream_protocol = parse_downstream_preferred_protocol(&form.value)?
        }
        "locale" | "app.locale" => config.locale = parse_locale_setting(&form.value)?,
        _ => anyhow::bail!("unsupported setting key: {}", form.key),
    }

    config.apply_fixed_product_defaults();
    config.web.open_browser_on_launch = false;
    if matches!(form.key.as_str(), "adblock.mode") {
        adblock::set_mode(&state.adblock_state, config.proxy.adblock.effective_mode());
    }

    if matches!(
        form.key.as_str(),
        "listen" | "proxy.listen" | "locale" | "app.locale"
    ) {
        write_relaygate_root_config(state, &config)?;
    } else {
        write_relaygate_settings_store(state, &config)?;
    }
    state.protocol_runtime.replace_from_config(&config);
    store_current_config(state, config);
    let mut changed = vec!["status", "settings"];
    if matches!(form.key.as_str(), "locale" | "app.locale") {
        changed.push("i18n");
    }
    if matches!(form.key.as_str(), "adblock.mode") {
        changed.push("adblock");
    }
    state.runtime.notify_backend_changed(&changed);

    if matches!(
        form.key.as_str(),
        "proxy.protocol.upstream_preferred" | "proxy.protocol.downstream_preferred"
    ) {
        return Ok("已儲存並套用連線設定。上游設定會套用到新的對外連線；下游 HTTP/1.1 / HTTP/2 會在瀏覽器重新建立連線後生效。".to_string());
    }

    Ok(lang::format(
        "backend.save.ok",
        &[("setting", setting_key_label(&form.key))],
    ))
}

pub(crate) fn update_protocol_settings_config(
    state: &WebAppState,
    form: &UpdateProtocolSettingsForm,
) -> anyhow::Result<String> {
    let mut config = current_config(state);
    config.upstream_protocol = parse_upstream_preferred_protocol(&form.upstream_protocol)?;
    config.downstream_protocol = parse_downstream_preferred_protocol(&form.downstream_protocol)?;
    save_config_and_notify(state, config, &["status", "settings"])?;
    Ok("已儲存並套用連線設定。上游設定會套用到新的對外連線；下游 HTTP/1.1 / HTTP/2 會在瀏覽器重新建立連線後生效。".to_string())
}

pub(crate) fn add_upstream_config(
    state: &WebAppState,
    form: UpstreamForm,
) -> anyhow::Result<String> {
    let config = current_config(state);
    let mut routing = current_upstream_routing(&config);
    let address = form.address.trim().to_string();
    validate_upstream_address(&address)?;
    let id = unique_upstream_id(&routing, &address)?;

    routing.upstreams.push(UpstreamConfig {
        id: id.clone(),
        address,
        enabled: true,
    });
    save_routing_and_notify(state, routing)?;
    Ok(format!("Saved upstream `{id}`. 已熱套用到新請求。"))
}

pub(crate) fn toggle_upstream_config(
    state: &WebAppState,
    form: ToggleItemForm,
) -> anyhow::Result<String> {
    let config = current_config(state);
    let mut routing = current_upstream_routing(&config);
    let enabled = parse_bool(&form.enabled)?;
    let Some(item) = routing.upstreams.iter_mut().find(|item| item.id == form.id) else {
        anyhow::bail!("upstream `{}` was not found", form.id);
    };
    item.enabled = enabled;
    save_routing_and_notify(state, routing)?;
    Ok(format!(
        "Updated upstream `{}`. 已熱套用到新請求。",
        form.id
    ))
}

pub(crate) fn delete_upstream_config(
    state: &WebAppState,
    form: DeleteItemForm,
) -> anyhow::Result<String> {
    let config = current_config(state);
    let mut routing = current_upstream_routing(&config);
    let before = routing.upstreams.len();
    routing.upstreams.retain(|item| item.id != form.id);
    if routing.upstreams.len() == before {
        anyhow::bail!("upstream `{}` was not found", form.id);
    }
    for route in &mut routing.upstream_routes {
        if route.upstream_id == form.id {
            route.enabled = false;
        }
    }
    save_routing_and_notify(state, routing)?;
    Ok(format!(
        "Deleted upstream `{}`. Routes using it were disabled. 已熱套用到新請求。",
        form.id
    ))
}

pub(crate) fn add_upstream_route_config(
    state: &WebAppState,
    form: UpstreamRouteForm,
) -> anyhow::Result<String> {
    let config = current_config(state);
    let mut routing = current_upstream_routing(&config);
    let host_pattern = form.host_pattern.trim().to_ascii_lowercase();
    upstream::validate_host_pattern(&host_pattern)?;
    if !routing
        .upstreams
        .iter()
        .any(|item| item.enabled && item.id == form.upstream_id)
    {
        anyhow::bail!("enabled upstream `{}` was not found", form.upstream_id);
    }
    let id = unique_route_id(&routing, &host_pattern);

    routing.upstream_routes.push(UpstreamRouteConfig {
        id: id.clone(),
        host_pattern,
        upstream_id: form.upstream_id,
        enabled: true,
    });
    save_routing_and_notify(state, routing)?;
    Ok(format!("Saved upstream route `{id}`. 已熱套用到新請求。"))
}

pub(crate) fn toggle_upstream_route_config(
    state: &WebAppState,
    form: ToggleItemForm,
) -> anyhow::Result<String> {
    let config = current_config(state);
    let mut routing = current_upstream_routing(&config);
    let enabled = parse_bool(&form.enabled)?;
    let Some(item) = routing
        .upstream_routes
        .iter_mut()
        .find(|item| item.id == form.id)
    else {
        anyhow::bail!("upstream route `{}` was not found", form.id);
    };
    item.enabled = enabled;
    save_routing_and_notify(state, routing)?;
    Ok(format!(
        "Updated upstream route `{}`. 已熱套用到新請求。",
        form.id
    ))
}

pub(crate) fn delete_upstream_route_config(
    state: &WebAppState,
    form: DeleteItemForm,
) -> anyhow::Result<String> {
    let config = current_config(state);
    let mut routing = current_upstream_routing(&config);
    let before = routing.upstream_routes.len();
    routing.upstream_routes.retain(|item| item.id != form.id);
    if routing.upstream_routes.len() == before {
        anyhow::bail!("upstream route `{}` was not found", form.id);
    }
    save_routing_and_notify(state, routing)?;
    Ok(format!(
        "Deleted upstream route `{}`. 已熱套用到新請求。",
        form.id
    ))
}

pub(crate) fn add_dns_profile_config(
    state: &WebAppState,
    form: DnsProfileForm,
) -> anyhow::Result<String> {
    let mut config = current_dns_config(state);
    let profile_input = normalize_dns_profile_input(&form)?;
    let id = profile_input.id;
    if id.is_empty() {
        anyhow::bail!("DNS profile id cannot be empty");
    }
    if config.profiles.iter().any(|item| item.id == id) {
        anyhow::bail!("DNS profile `{id}` already exists");
    }
    let mode = profile_input.mode;
    let servers = profile_input.servers;
    if mode == DnsProfileMode::Udp && servers.is_empty() {
        anyhow::bail!("UDP DNS profiles need at least one server");
    }
    validate_dns_servers(&servers)?;
    config.profiles.push(DnsProfileConfig {
        id: id.clone(),
        mode,
        servers,
        enabled: true,
        timeout_ms: 2000,
        attempts: 2,
        cache_ttl_min_secs: 300,
        cache_ttl_max_secs: 86400,
        negative_ttl_secs: 30,
        stale_fallback_secs: 86400,
        fallback_profiles: profile_input.fallback_profiles,
    });
    save_dns_and_notify(state, config)?;
    Ok(format!(
        "Saved DNS profile `{id}`. 已熱套用並清空 DNS 快取。"
    ))
}

struct NormalizedDnsProfileInput {
    id: String,
    mode: DnsProfileMode,
    servers: Vec<String>,
    fallback_profiles: Vec<String>,
}

fn normalize_dns_profile_input(form: &DnsProfileForm) -> anyhow::Result<NormalizedDnsProfileInput> {
    if !form.server_ip.trim().is_empty() {
        let ip = form
            .server_ip
            .trim()
            .parse::<IpAddr>()
            .with_context(|| format!("invalid DNS server IP `{}`", form.server_ip.trim()))?;
        let port = if form.server_port.trim().is_empty() {
            53
        } else {
            form.server_port
                .trim()
                .parse::<u16>()
                .with_context(|| format!("invalid DNS server port `{}`", form.server_port.trim()))?
        };
        let server = SocketAddr::new(ip, port).to_string();
        return Ok(NormalizedDnsProfileInput {
            id: dns_profile_id_from_server(ip, port),
            mode: DnsProfileMode::Udp,
            servers: vec![server],
            fallback_profiles: vec!["system".to_string()],
        });
    }

    Ok(NormalizedDnsProfileInput {
        id: slug_id(&form.id),
        mode: parse_dns_profile_mode(&form.mode)?,
        servers: split_csv_lines(&form.servers),
        fallback_profiles: split_csv_lines(&form.fallback_profiles),
    })
}

fn dns_profile_id_from_server(ip: IpAddr, port: u16) -> String {
    let mut id = ip
        .to_string()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    while id.contains("--") {
        id = id.replace("--", "-");
    }
    let id = id.trim_matches('-');
    if port == 53 {
        format!("server-{id}")
    } else {
        format!("server-{id}-{port}")
    }
}

pub(crate) fn toggle_dns_profile_config(
    _state: &WebAppState,
    _form: ToggleItemForm,
) -> anyhow::Result<String> {
    anyhow::bail!("DNS servers are enabled by default and cannot be toggled")
}

pub(crate) fn delete_dns_profile_config(
    state: &WebAppState,
    form: DeleteItemForm,
) -> anyhow::Result<String> {
    let mut config = current_dns_config(state);
    if form.id == "system" {
        anyhow::bail!("system DNS profile cannot be deleted");
    }
    let before = config.profiles.len();
    config.profiles.retain(|item| item.id != form.id);
    if config.profiles.len() == before {
        anyhow::bail!("DNS profile `{}` was not found", form.id);
    }
    let removed_routes = config.routes.len();
    config.routes.retain(|route| route.profile_id != form.id);
    let removed_routes = removed_routes.saturating_sub(config.routes.len());
    save_dns_and_notify(state, config)?;
    if removed_routes == 0 {
        Ok(format!(
            "Deleted DNS profile `{}`. 已熱套用並清空 DNS 快取。",
            form.id
        ))
    } else {
        Ok(format!(
            "Deleted DNS profile `{}` and {removed_routes} DNS route(s). 已熱套用並清空 DNS 快取。",
            form.id
        ))
    }
}

pub(crate) fn move_dns_profile_config(
    _state: &WebAppState,
    form: MoveItemForm,
) -> anyhow::Result<String> {
    let _requested = (&form.id, &form.direction);
    anyhow::bail!("DNS server ordering is managed by RelayGate defaults")
}

pub(crate) fn add_dns_route_config(
    state: &WebAppState,
    form: DnsRouteForm,
) -> anyhow::Result<String> {
    let mut config = current_dns_config(state);
    let host_pattern = form.host_pattern.trim().to_ascii_lowercase();
    dns::validate_host_pattern(&host_pattern)?;
    if !config.profiles.iter().any(|item| {
        item.enabled && item.mode != DnsProfileMode::System && item.id == form.profile_id
    }) {
        anyhow::bail!("enabled DNS server `{}` was not found", form.profile_id);
    }
    let id = unique_dns_route_id(&config, &host_pattern);
    config.routes.push(DnsRouteConfig {
        id: id.clone(),
        host_pattern,
        profile_id: form.profile_id,
        strict: true,
        enabled: true,
    });
    save_dns_and_notify(state, config)?;
    Ok(format!("Saved DNS route `{id}`. 已熱套用並清空 DNS 快取。"))
}

pub(crate) fn toggle_dns_route_config(
    _state: &WebAppState,
    _form: ToggleItemForm,
) -> anyhow::Result<String> {
    anyhow::bail!("DNS routes are an internal behavior and cannot be toggled")
}

pub(crate) fn delete_dns_route_config(
    state: &WebAppState,
    form: DeleteItemForm,
) -> anyhow::Result<String> {
    let mut config = current_dns_config(state);
    let before = config.routes.len();
    config.routes.retain(|item| item.id != form.id);
    if config.routes.len() == before {
        anyhow::bail!("DNS route `{}` was not found", form.id);
    }
    save_dns_and_notify(state, config)?;
    Ok(format!(
        "Deleted DNS route `{}`. 已熱套用並清空 DNS 快取。",
        form.id
    ))
}

pub(crate) fn toggle_dns_feature_config(
    _state: &WebAppState,
    form: DnsFeatureToggleForm,
) -> anyhow::Result<String> {
    let _requested = (&form.feature, &form.enabled);
    anyhow::bail!(
        "DNS warm cache, observation, and auto-select are built-in behaviours and cannot be toggled"
    )
}

pub(crate) fn add_gateway_mount_config(
    state: &WebAppState,
    form: GatewayMountForm,
) -> anyhow::Result<String> {
    let mut config = current_config(state);
    let routing = current_upstream_routing(&config);
    let id = gateway_mount_id_from_user_input(&form.mount_path)?;
    let mount_path = gateway_mount_path_from_id(&id);
    let target_base_url = normalize_target_base_url(&form.target_base_url)?;
    let upstream_id = normalize_optional_upstream_id(&form.upstream_id);
    if let Some(upstream_id) = upstream_id.as_ref() {
        if !routing
            .upstreams
            .iter()
            .any(|item| item.enabled && item.id == *upstream_id)
        {
            anyhow::bail!("enabled upstream `{upstream_id}` was not found");
        }
    }
    if config.gateway.mounts.iter().any(|item| item.id == id) {
        anyhow::bail!("mount `{id}` already exists");
    }

    let mount = MountSiteConfig {
        id: id.clone(),
        mount_path,
        target_base_url,
        upstream_id,
        enabled: true,
        rewrite_links: form.rewrite_links.is_some(),
        passthrough_mode: false,
        minimal_page_mode: None,
    };
    GatewayConfig::save_mount_default(&mount)?;
    config.gateway.mounts.push(mount);
    save_gateway_and_notify(state, config)?;
    Ok(format!("Saved mount `{id}`."))
}

pub(crate) fn toggle_gateway_mount_config(
    state: &WebAppState,
    form: ToggleItemForm,
) -> anyhow::Result<String> {
    let mut config = current_config(state);
    let enabled = parse_bool(&form.enabled)?;
    let Some(item) = config
        .gateway
        .mounts
        .iter_mut()
        .find(|item| item.id == form.id)
    else {
        anyhow::bail!("mount `{}` was not found", form.id);
    };
    item.enabled = enabled;
    GatewayConfig::save_mount_default(item)?;
    save_gateway_and_notify(state, config)?;
    Ok(format!("Updated mount `{}`.", form.id))
}

pub(crate) fn delete_gateway_mount_config(
    state: &WebAppState,
    form: DeleteItemForm,
) -> anyhow::Result<String> {
    let mut config = current_config(state);
    let before = config.gateway.mounts.len();
    config.gateway.mounts.retain(|item| item.id != form.id);
    if config.gateway.mounts.len() == before {
        anyhow::bail!("mount `{}` was not found", form.id);
    }
    GatewayConfig::delete_mount_default(&form.id)?;
    save_gateway_and_notify(state, config)?;
    Ok(format!("Deleted mount `{}`.", form.id))
}

pub(crate) async fn toggle_resource_replace_rule_config(
    state: &WebAppState,
    form: ToggleItemForm,
) -> anyhow::Result<String> {
    let enabled = parse_bool(&form.enabled)?;
    resource_replace::set_rule_enabled_default(&form.id, enabled)?;
    let rule_count = reload_resource_replace_runtime(state).await?;
    Ok(format!(
        "Resource Replace 規則 `{}` 已儲存並熱套用。已載入 {rule_count} 條規則。",
        form.id
    ))
}

pub(crate) async fn reload_rewrite_runtime(state: &WebAppState) -> anyhow::Result<usize> {
    let rule_count = rewrite::reload_shared_registry_blocking(&state.rewrite_registry).await?;
    state
        .runtime
        .notify_backend_changed(&["status", "patch", "render"]);
    Ok(rule_count)
}

pub(crate) async fn reload_resource_replace_runtime(state: &WebAppState) -> anyhow::Result<usize> {
    let rule_count =
        resource_replace::reload_shared_registry_blocking(&state.resource_replace_registry).await?;
    state
        .runtime
        .notify_backend_changed(&["status", "resource_replace"]);
    Ok(rule_count)
}

pub(crate) fn reload_user_script_runtime(state: &WebAppState) -> anyhow::Result<usize> {
    let count = user_script::reload_shared_registry(&state.user_script_registry)?;
    state
        .runtime
        .notify_backend_changed(&["status", "user_script"]);
    Ok(count)
}

pub(crate) fn current_config(state: &WebAppState) -> RelayGateConfig {
    state
        .config
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_else(|_| RelayGateConfig::default())
}

pub(crate) fn current_upstream_routing(config: &RelayGateConfig) -> UpstreamRoutingConfig {
    UpstreamRoutingConfig::from_main_config(config)
}

fn current_dns_config(state: &WebAppState) -> DnsConfig {
    state.dns_resolver.config_snapshot()
}

pub(crate) fn store_current_config(state: &WebAppState, config: RelayGateConfig) {
    if let Ok(mut guard) = state.config.write() {
        *guard = config;
    }
}

fn save_routing_and_notify(
    state: &WebAppState,
    routing: UpstreamRoutingConfig,
) -> anyhow::Result<()> {
    routing.validate()?;

    let mut config = current_config(state);
    config.upstreams = routing.upstreams.clone();
    config.upstream_routes = routing.upstream_routes.clone();
    config.apply_fixed_product_defaults();
    write_relaygate_settings_store(state, &config)?;

    upstream::replace_shared_registry(
        &state.upstreams,
        &routing.upstreams,
        &routing.upstream_routes,
    )?;
    store_current_config(state, config);
    state
        .runtime
        .notify_backend_changed(&["status", "settings", "upstreams", "upstream_routes"]);
    Ok(())
}

fn save_dns_and_notify(state: &WebAppState, config: DnsConfig) -> anyhow::Result<()> {
    config.validate()?;
    config.save_default()?;
    dns::replace_shared_config(&state.dns_resolver, config)?;
    state
        .runtime
        .notify_backend_changed(&["status", "settings", "dns"]);
    Ok(())
}

fn save_config_and_notify(
    state: &WebAppState,
    mut config: RelayGateConfig,
    changed: &[&str],
) -> anyhow::Result<()> {
    config.apply_fixed_product_defaults();
    write_relaygate_settings_store(state, &config)?;
    if changed.iter().any(|section| *section == "gateway") {
        gateway_mount::replace_shared_registry(&state.gateway_mounts, &config.gateway.mounts)?;
    }
    state.protocol_runtime.replace_from_config(&config);
    store_current_config(state, config);
    state.runtime.notify_backend_changed(changed);
    Ok(())
}

fn save_gateway_and_notify(state: &WebAppState, mut config: RelayGateConfig) -> anyhow::Result<()> {
    config.apply_fixed_product_defaults();
    let routing = current_upstream_routing(&config);
    config.validate_runtime_references(&routing)?;
    gateway_mount::replace_shared_registry(&state.gateway_mounts, &config.gateway.mounts)?;
    store_current_config(state, config);
    state
        .runtime
        .notify_backend_changed(&["status", "settings", "gateway"]);
    Ok(())
}

fn write_relaygate_settings_store(
    state: &WebAppState,
    config: &RelayGateConfig,
) -> anyhow::Result<()> {
    config
        .save_settings_to_path(state.settings_store_path.as_ref())
        .with_context(|| {
            format!(
                "failed to write RelayGate settings store: {}",
                state.settings_store_path.display()
            )
        })
}

fn write_relaygate_root_config(
    state: &WebAppState,
    config: &RelayGateConfig,
) -> anyhow::Result<()> {
    config
        .save_root_config_to_path(state.root_config_path.as_ref())
        .with_context(|| {
            format!(
                "failed to write RelayGate root config: {}",
                state.root_config_path.display()
            )
        })
}

fn unique_upstream_id(routing: &UpstreamRoutingConfig, address: &str) -> anyhow::Result<String> {
    let uri = address.parse::<axum::http::Uri>()?;
    let host = uri.host().unwrap_or("upstream");
    let port = uri.port_u16().unwrap_or(80);
    let base = slug_id(&format!("upstream-{host}-{port}"));
    Ok(unique_id(base, |candidate| {
        routing.upstreams.iter().any(|item| item.id == candidate)
    }))
}

fn unique_route_id(routing: &UpstreamRoutingConfig, host_pattern: &str) -> String {
    let base = slug_id(&format!("route-{host_pattern}"));
    unique_id(base, |candidate| {
        routing
            .upstream_routes
            .iter()
            .any(|item| item.id == candidate)
    })
}

fn unique_dns_route_id(config: &DnsConfig, host_pattern: &str) -> String {
    let base = slug_id(&format!("dns-{host_pattern}"));
    unique_id(base, |candidate| {
        config.routes.iter().any(|item| item.id == candidate)
    })
}

fn unique_id(base: String, exists: impl Fn(&str) -> bool) -> String {
    if !exists(&base) {
        return base;
    }
    for index in 2.. {
        let candidate = format!("{base}-{index}");
        if !exists(&candidate) {
            return candidate;
        }
    }
    base
}

fn slug_id(value: &str) -> String {
    let mut output = String::new();
    let mut last_dash = false;
    for ch in value.trim().to_ascii_lowercase().chars() {
        let next = if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            Some(ch)
        } else {
            Some('-')
        };
        if let Some(ch) = next {
            if ch == '-' {
                if !last_dash && !output.is_empty() {
                    output.push(ch);
                }
                last_dash = true;
            } else {
                output.push(ch);
                last_dash = false;
            }
        }
    }
    let output = output.trim_matches('-').to_string();
    if output.is_empty() {
        "item".to_string()
    } else {
        output
    }
}

fn validate_upstream_address(address: &str) -> anyhow::Result<()> {
    let uri = address.parse::<axum::http::Uri>()?;
    if uri.scheme_str() != Some("http") {
        anyhow::bail!("only http:// upstream proxies are supported in this version");
    }
    if uri.host().is_none() {
        anyhow::bail!("upstream address is missing host");
    }
    Ok(())
}

fn parse_dns_profile_mode(value: &str) -> anyhow::Result<DnsProfileMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "system" => Ok(DnsProfileMode::System),
        "udp" => Ok(DnsProfileMode::Udp),
        _ => anyhow::bail!("invalid DNS profile mode: {value}"),
    }
}

fn split_csv_lines(value: &str) -> Vec<String> {
    value
        .split([',', '\n', '\r'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn validate_dns_servers(servers: &[String]) -> anyhow::Result<()> {
    for server in servers {
        server
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("invalid DNS server address `{server}`"))?;
    }
    Ok(())
}

fn normalize_target_base_url(value: &str) -> anyhow::Result<String> {
    let trimmed = value.trim().trim_end_matches('/').to_string();
    let uri = trimmed.parse::<axum::http::Uri>()?;
    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        _ => anyhow::bail!("target base URL must start with http:// or https://"),
    }
    if uri.host().is_none() {
        anyhow::bail!("target base URL is missing host");
    }
    Ok(trimmed)
}

fn normalize_optional_upstream_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(crate) fn parse_bool(value: &str) -> anyhow::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("invalid bool value: {value}"),
    }
}

fn parse_adblock_mode_setting(value: &str) -> anyhow::Result<AdblockModeSetting> {
    match value {
        "disabled" => Ok(AdblockModeSetting::Disabled),
        "standard" => Ok(AdblockModeSetting::Standard),
        "aggressive" => Ok(AdblockModeSetting::Aggressive),
        _ => anyhow::bail!("unsupported adblock mode: {value}"),
    }
}

fn parse_upstream_preferred_protocol(
    value: &str,
) -> anyhow::Result<UpstreamProtocolPreferenceConfig> {
    match value.trim() {
        "guarded_h3" | "http3" | "h3" | "auto" => Ok(UpstreamProtocolPreferenceConfig::GuardedH3),
        "http2_preferred" | "http2_http1" | "compatible" | "http1_only" => {
            Ok(UpstreamProtocolPreferenceConfig::Http2Preferred)
        }
        "http2_prior_knowledge" => Ok(UpstreamProtocolPreferenceConfig::GuardedH3),
        _ => anyhow::bail!("unsupported upstream protocol preference: {value}"),
    }
}

fn parse_downstream_preferred_protocol(
    value: &str,
) -> anyhow::Result<DownstreamProtocolPreferenceConfig> {
    match value.trim() {
        "http1_only" => Ok(DownstreamProtocolPreferenceConfig::Http1Only),
        "http2_enabled" => Ok(DownstreamProtocolPreferenceConfig::Http2Enabled),
        _ => anyhow::bail!("unsupported downstream protocol preference: {value}"),
    }
}

fn parse_locale_setting(value: &str) -> anyhow::Result<String> {
    let locale = value.trim();
    if lang::available_locales()
        .iter()
        .any(|available| available == locale)
    {
        return Ok(locale.to_string());
    }
    anyhow::bail!("unsupported locale: {locale}")
}

fn setting_key_label(key: &str) -> String {
    match key {
        "listen" | "proxy.listen" => lang::text("settings.proxy.label"),
        "locale" | "app.locale" => lang::text("settings.locale.label"),
        "adblock.mode" => lang::text("settings.adblock.label"),
        "proxy.protocol.upstream_preferred" => lang::text("settings.protocol.upstream.label"),
        "proxy.protocol.downstream_preferred" => lang::text("settings.protocol.downstream.label"),
        _ => key.to_string(),
    }
}
