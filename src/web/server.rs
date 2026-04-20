use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use axum::{
    routing::{get, post},
    Router,
};
use tracing::info;

use crate::{
    adblock::SharedAdblockState, config::RelayGateConfig, rewrite::SharedRewriteRegistry,
    runtime::AppRuntime, traffic::SharedTrafficState, web::routes,
};

#[derive(Clone)]
pub struct WebAppState {
    // The control panel should use in-memory state instead of re-reading YAML at high frequency.
    pub config: Arc<RwLock<RelayGateConfig>>,
    pub config_path: Arc<std::path::PathBuf>,
    pub rewrite_registry: SharedRewriteRegistry,
    pub adblock_state: SharedAdblockState,
    pub traffic_state: SharedTrafficState,
    pub runtime: AppRuntime,
}

/// Local web settings server.
/// The first version keeps the page and API small and leaves room for later UI work.
pub struct WebSettingsServer {
    config: Arc<RelayGateConfig>,
    rewrite_registry: SharedRewriteRegistry,
    adblock_state: SharedAdblockState,
    traffic_state: SharedTrafficState,
    runtime: AppRuntime,
}

impl WebSettingsServer {
    pub fn new(
        config: Arc<RelayGateConfig>,
        rewrite_registry: SharedRewriteRegistry,
        adblock_state: SharedAdblockState,
        traffic_state: SharedTrafficState,
        runtime: AppRuntime,
    ) -> Self {
        Self {
            config,
            rewrite_registry,
            adblock_state,
            traffic_state,
            runtime,
        }
    }

    pub async fn run(self) -> Result<()> {
        let app = build_app(build_state(
            self.config.clone(),
            self.rewrite_registry.clone(),
            self.adblock_state.clone(),
            self.traffic_state.clone(),
            self.runtime.clone(),
        ));

        // Parse the configured listen string into a SocketAddr.
        let addr: SocketAddr =
            self.config.web.listen.parse().with_context(|| {
                format!("invalid web listen address: {}", self.config.web.listen)
            })?;

        info!(listen = %addr, "web ready");

        // TODO: Open the default browser automatically on Windows later.
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

pub fn build_state(
    config: Arc<RelayGateConfig>,
    rewrite_registry: SharedRewriteRegistry,
    adblock_state: SharedAdblockState,
    traffic_state: SharedTrafficState,
    runtime: AppRuntime,
) -> WebAppState {
    WebAppState {
        config: Arc::new(RwLock::new(config.as_ref().clone())),
        config_path: Arc::new(
            RelayGateConfig::default_path()
                .unwrap_or_else(|_| std::path::PathBuf::from("relaygate.yaml")),
        ),
        rewrite_registry,
        adblock_state,
        traffic_state,
        runtime,
    }
}

pub fn build_app(state: WebAppState) -> Router {
    Router::new()
        .route("/", get(routes::index))
        .route("/backend/assets/favicon.ico", get(routes::favicon))
        .route(
            "/backend/assets/relaygate-actions.js",
            get(routes::backend_actions_js),
        )
        .route("/backend/events", get(routes::backend_events))
        .route("/backend/actions/reload-rules", post(routes::reload_rules))
        .route(
            "/backend/actions/reload-config",
            post(routes::reload_config),
        )
        .route(
            "/backend/actions/update-adblock-lists",
            post(routes::update_adblock_lists),
        )
        .route("/backend/actions/create-ca", post(routes::create_ca))
        .route(
            "/backend/actions/remove-ca-trust",
            post(routes::remove_ca_trust),
        )
        .route("/backend/actions/exit", post(routes::exit_app))
        .route(
            "/backend/actions/update-setting",
            post(routes::update_setting),
        )
        .with_state(state)
}
