use std::sync::{Arc, RwLock};

use axum::{
    routing::{get, post},
    Router,
};

use crate::{
    adblock::SharedAdblockState,
    config::RelayGateConfig,
    dns::SharedDnsResolver,
    proxy::{
        gateway_mount::SharedGatewayMountRegistry, protocol_runtime::ProtocolRuntimeConfig,
        resource_replace::SharedResourceReplaceRegistry, upstream::SharedUpstreamRegistry,
    },
    rewrite::SharedRewriteRegistry,
    runtime::AppRuntime,
    traffic::SharedTrafficState,
    user_script::SharedUserScriptRegistry,
    web::{routes, ui_assets},
};

#[derive(Clone)]
pub(crate) struct WebAppState {
    // The control panel should use in-memory state instead of re-reading config files at high frequency.
    pub(crate) config: Arc<RwLock<RelayGateConfig>>,
    pub(crate) settings_store_path: Arc<std::path::PathBuf>,
    pub(crate) root_config_path: Arc<std::path::PathBuf>,
    pub(crate) rewrite_registry: SharedRewriteRegistry,
    pub(crate) resource_replace_registry: SharedResourceReplaceRegistry,
    pub(crate) adblock_state: SharedAdblockState,
    pub(crate) traffic_state: SharedTrafficState,
    pub(crate) upstreams: SharedUpstreamRegistry,
    pub(crate) gateway_mounts: SharedGatewayMountRegistry,
    pub(crate) dns_resolver: SharedDnsResolver,
    pub(crate) user_script_registry: SharedUserScriptRegistry,
    pub(crate) protocol_runtime: ProtocolRuntimeConfig,
    pub(crate) runtime: AppRuntime,
}

pub(crate) fn build_state(
    config: Arc<RelayGateConfig>,
    rewrite_registry: SharedRewriteRegistry,
    resource_replace_registry: SharedResourceReplaceRegistry,
    adblock_state: SharedAdblockState,
    traffic_state: SharedTrafficState,
    upstreams: SharedUpstreamRegistry,
    gateway_mounts: SharedGatewayMountRegistry,
    dns_resolver: SharedDnsResolver,
    user_script_registry: SharedUserScriptRegistry,
    protocol_runtime: ProtocolRuntimeConfig,
    runtime: AppRuntime,
) -> WebAppState {
    WebAppState {
        config: Arc::new(RwLock::new(config.as_ref().clone())),
        settings_store_path: Arc::new(
            RelayGateConfig::settings_store_path()
                .unwrap_or_else(|_| std::path::PathBuf::from("data/user/settings.yaml")),
        ),
        root_config_path: Arc::new(
            RelayGateConfig::root_config_path()
                .unwrap_or_else(|_| std::path::PathBuf::from("relaygate.yaml")),
        ),
        rewrite_registry,
        resource_replace_registry,
        adblock_state,
        traffic_state,
        upstreams,
        gateway_mounts,
        dns_resolver,
        user_script_registry,
        protocol_runtime,
        runtime,
    }
}

pub(crate) fn build_app(state: WebAppState) -> Router {
    Router::new()
        .route("/", get(ui_assets::ui_index))
        .route("/settings", get(ui_assets::ui_index))
        .route("/gateway", get(ui_assets::ui_index))
        .route("/upstreams", get(ui_assets::ui_index))
        .route("/upstream-routes", get(ui_assets::ui_index))
        .route("/dns", get(ui_assets::ui_index))
        .route("/traffic", get(ui_assets::ui_index))
        .route("/connection-info", get(ui_assets::ui_index))
        .route("/patch", get(ui_assets::ui_index))
        .route("/render", get(ui_assets::ui_index))
        .route("/resource-replace", get(ui_assets::ui_index))
        .route("/adblock", get(ui_assets::ui_index))
        .route("/user-script", get(ui_assets::ui_index))
        .route("/favicon.ico", get(ui_assets::favicon))
        .route("/ui-assets/{*path}", get(ui_assets::ui_asset))
        .route("/backend/i18n", get(routes::i18n_payload))
        .route("/backend/snapshot", get(routes::backend_snapshot))
        .route(
            "/backend/connection-info",
            get(routes::connection_info_snapshot),
        )
        .route("/backend/mitm-status", get(routes::mitm_status))
        .route("/backend/events", get(routes::backend_events))
        .route("/backend/actions/reload-rules", post(routes::reload_rules))
        .route(
            "/backend/actions/reload-resource-replace",
            post(routes::reload_resource_replace),
        )
        .route(
            "/backend/actions/resource-replace/toggle",
            post(routes::toggle_resource_replace_rule),
        )
        .route(
            "/backend/actions/reload-config",
            post(routes::reload_config),
        )
        .route("/backend/actions/create-ca", post(routes::create_ca))
        .route(
            "/backend/actions/remove-ca-trust",
            post(routes::remove_ca_trust),
        )
        .route(
            "/backend/actions/remove-windows-relaygate-ca",
            post(routes::remove_windows_relaygate_ca_trust),
        )
        .route("/backend/actions/exit", post(routes::exit_app))
        .route(
            "/backend/actions/update-setting",
            post(routes::update_setting),
        )
        .route(
            "/backend/actions/update-protocol-settings",
            post(routes::update_protocol_settings),
        )
        .route("/backend/actions/upstreams/add", post(routes::add_upstream))
        .route(
            "/backend/actions/upstreams/toggle",
            post(routes::toggle_upstream),
        )
        .route(
            "/backend/actions/upstreams/delete",
            post(routes::delete_upstream),
        )
        .route(
            "/backend/actions/upstream-routes/add",
            post(routes::add_upstream_route),
        )
        .route(
            "/backend/actions/upstream-routes/toggle",
            post(routes::toggle_upstream_route),
        )
        .route(
            "/backend/actions/upstream-routes/delete",
            post(routes::delete_upstream_route),
        )
        .route(
            "/backend/actions/dns-profiles/add",
            post(routes::add_dns_profile),
        )
        .route(
            "/backend/actions/dns-profiles/toggle",
            post(routes::toggle_dns_profile),
        )
        .route(
            "/backend/actions/dns-profiles/delete",
            post(routes::delete_dns_profile),
        )
        .route(
            "/backend/actions/dns-profiles/move",
            post(routes::move_dns_profile),
        )
        .route(
            "/backend/actions/dns-routes/add",
            post(routes::add_dns_route),
        )
        .route(
            "/backend/actions/dns-routes/toggle",
            post(routes::toggle_dns_route),
        )
        .route(
            "/backend/actions/dns-routes/delete",
            post(routes::delete_dns_route),
        )
        .route(
            "/backend/actions/dns-features/toggle",
            post(routes::toggle_dns_feature),
        )
        .route(
            "/backend/actions/gateway/add",
            post(routes::add_gateway_mount),
        )
        .route(
            "/backend/actions/gateway/toggle",
            post(routes::toggle_gateway_mount),
        )
        .route(
            "/backend/actions/gateway/delete",
            post(routes::delete_gateway_mount),
        )
        .route(
            "/backend/actions/user-script/rescan",
            post(routes::rescan_user_scripts),
        )
        .route(
            "/backend/actions/user-script/toggle",
            post(routes::toggle_user_script),
        )
        .route(
            "/backend/actions/user-script/open-folder",
            post(routes::open_user_script_folder),
        )
        .with_state(state)
}
