use std::sync::Arc;

use anyhow::Result;
use tokio::{
    signal,
    sync::{mpsc, oneshot},
    time::{self, Duration, MissedTickBehavior},
};
use tracing::{debug, info, warn};

use crate::{
    adblock::{self, SharedAdblockState},
    config::{DnsConfig, RelayGateConfig, UpstreamRoutingConfig},
    diagnostics,
    dns::{self, SharedDnsResolver},
    dns_server::DnsServer,
    proxy::{
        gateway_mount::{self, SharedGatewayMountRegistry},
        protocol_runtime::ProtocolRuntimeConfig,
        resource_replace::{self, SharedResourceReplaceRegistry},
        server::ProxyServer,
        upstream::{self, SharedUpstreamRegistry},
    },
    rewrite::{self, SharedRewriteRegistry},
    runtime::AppRuntime,
    traffic::{SharedTrafficState, TrafficState},
    tray::{SystemTray, TrayCommand, TrayController},
    user_script::{self, SharedUserScriptRegistry},
};

const ADBLOCK_AUTO_UPDATE_CHECK_SECS: u64 = 10 * 60;

/// Top-level application coordinator.
/// It owns startup and shutdown flow:
/// - receives the loaded config
/// - starts proxy, web, and tray
/// - handles shutdown in one place
pub struct App {
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
}

impl App {
    pub fn new(config: RelayGateConfig) -> Result<Self> {
        let rewrite_registry = rewrite::RewriteRegistry::shared_default()?;
        let resource_replace_registry =
            resource_replace::ResourceReplaceRegistry::shared_default()?;
        let adblock_state = adblock::AdblockState::shared_default(&config)?;
        let upstream_routing = UpstreamRoutingConfig::from_main_config(&config);
        upstream_routing.validate()?;
        config.validate_runtime_references(&upstream_routing)?;
        let upstreams = upstream::shared_from_config(
            &upstream_routing.upstreams,
            &upstream_routing.upstream_routes,
        );
        let dns_config = DnsConfig::load_default_or_default()?;
        dns_config.validate()?;
        let dns_resolver = dns::shared_from_config(dns_config);
        let gateway_mounts = gateway_mount::shared_from_config(&config.gateway.mounts);
        let user_script_registry = user_script::shared_default()?;
        let protocol_runtime = ProtocolRuntimeConfig::from_config(&config);
        let runtime = AppRuntime::new();
        let traffic_state = TrafficState::shared(&config.traffic, runtime.clone())?;
        Ok(Self {
            config: Arc::new(config),
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
        })
    }

    pub async fn run(self) -> Result<()> {
        let initial_rule_count = self
            .rewrite_registry
            .read()
            .map_err(|_| anyhow::anyhow!("rewrite registry lock poisoned"))?
            .rule_count();
        info!(
            app = %self.config.app.name,
            proxy = %self.config.proxy.listen,
            web = %self.config.web.listen,
            tray = true,
            mitm = self.config.proxy.mitm.enabled,
            rewrite_rules = initial_rule_count,
            adblock_rules = adblock::rule_count(&self.adblock_state),
            adblock_resources = adblock::resource_count(&self.adblock_state),
            adblock_enabled = adblock::is_enabled(&self.adblock_state),
            resource_replace_rules = resource_replace::rule_count(&self.resource_replace_registry),
            log_response_body = self.config.logging.log_response_body,
            dns_server_enabled = self.config.dns_server.enabled,
            dns_server = %self.config.dns_server.listen_address(&self.config.listen),
            "RelayGate starting"
        );

        // Prepare the three main subsystems:
        // 1. Proxy: local HTTP proxy
        // 2. Web: control panel and status API
        // 3. Tray: Windows tray entry point
        let (proxy_ready_tx, proxy_ready_rx) = oneshot::channel::<()>();
        let proxy_server = ProxyServer::new(
            self.config.clone(),
            self.rewrite_registry.clone(),
            self.resource_replace_registry.clone(),
            self.adblock_state.clone(),
            self.traffic_state.clone(),
            self.upstreams.clone(),
            self.gateway_mounts.clone(),
            self.dns_resolver.clone(),
            self.user_script_registry.clone(),
            self.protocol_runtime.clone(),
            self.runtime.clone(),
            Some(proxy_ready_tx),
        );
        let tray = SystemTray::new(self.config.clone());
        let (tray_tx, mut tray_rx) = mpsc::unbounded_channel::<TrayCommand>();
        let auto_update_task = if self.config.proxy.adblock.auto_update {
            Some(tokio::spawn(run_adblock_auto_update_loop(
                self.config.clone(),
                self.adblock_state.clone(),
                self.runtime.clone(),
            )))
        } else {
            None
        };
        let process_metrics_task = tokio::spawn(run_process_metrics_sampler(self.runtime.clone()));
        let dns_server_task = if self.config.dns_server.enabled {
            let dns_server_listen = self.config.dns_server.listen_address(&self.config.listen);
            info!(listen = %dns_server_listen, "starting DNS server");
            let dns_server = DnsServer::new(
                self.config.clone(),
                self.dns_resolver.clone(),
                self.runtime.clone(),
            );
            Some(tokio::spawn(async move {
                if let Err(error) = dns_server.run().await {
                    warn!(
                        error = %error,
                        "DNS server unavailable; RelayGate proxy continues"
                    );
                }
            }))
        } else {
            debug!("DNS server disabled by config");
            None
        };
        let _user_script_watcher = user_script::start_auto_reload_watcher(
            self.user_script_registry.clone(),
            self.runtime.clone(),
        )?;

        // Start the tray first so the user always has an entry point and exit path.
        let tray_handle = tray.start(tray_tx)?;

        // The proxy is the long-running task. The control panel is also proxied through it now.
        let mut proxy_task = tokio::spawn(async move { proxy_server.run().await });
        let startup_notification_task = {
            let tray_handle = tray_handle.clone();
            let proxy_listen = self.config.proxy.listen.clone();
            tokio::spawn(async move {
                if proxy_ready_rx.await.is_ok() {
                    tray_handle.notify_startup_ready(&proxy_listen);
                }
            })
        };

        loop {
            tokio::select! {
                proxy_result = &mut proxy_task => {
                    warn!("proxy task exited");
                    proxy_result??;
                    break;
                }
                _ = signal::ctrl_c() => {
                    info!("shutdown signal received");
                    break;
                }
                _ = self.runtime.wait_for_shutdown() => {
                    info!("runtime shutdown requested");
                    break;
                }
                Some(command) = tray_rx.recv() => {
                    match command {
                        TrayCommand::Exit => {
                            info!("tray exit requested");
                            self.runtime.request_shutdown();
                            break;
                        }
                    }
                }
            }
        }

        tray_handle.shutdown();
        startup_notification_task.abort();
        if let Some(handle) = auto_update_task {
            handle.abort();
        }
        process_metrics_task.abort();
        if let Some(handle) = dns_server_task {
            handle.abort();
        }
        self.dns_resolver.flush_cache_snapshot();
        if let Err(error) = self.traffic_state.flush_persisted_state() {
            warn!(error = %error, "failed to flush traffic state on shutdown");
        }
        diagnostics::flush_lazy_logs();
        info!("RelayGate stopped");

        Ok(())
    }
}

async fn run_process_metrics_sampler(runtime: AppRuntime) {
    let mut interval = time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        let _ = runtime.process_metrics();
    }
}

async fn run_adblock_auto_update_loop(
    config: Arc<RelayGateConfig>,
    adblock_state: SharedAdblockState,
    runtime: AppRuntime,
) {
    sync_adblock_defaults(&config, &adblock_state, &runtime, "startup").await;

    let mut interval = time::interval(Duration::from_secs(ADBLOCK_AUTO_UPDATE_CHECK_SECS));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval.tick().await;

    loop {
        interval.tick().await;
        sync_adblock_defaults(&config, &adblock_state, &runtime, "scheduled").await;
    }
}

async fn sync_adblock_defaults(
    config: &RelayGateConfig,
    adblock_state: &SharedAdblockState,
    runtime: &AppRuntime,
    reason: &str,
) {
    match adblock::sync_default_resources().await {
        Ok(files) if files.is_empty() => {
            debug!(
                reason = reason,
                "adblock list sync skipped; local data is fresh"
            )
        }
        Ok(files) => match adblock::reload_shared_state_blocking(adblock_state, config).await {
            Ok(rule_count) => {
                runtime
                    .notify_backend_changed(&["status", "settings", "patch", "render", "adblock"]);
                info!(
                    reason = reason,
                    updated_files = files.len(),
                    adblock_rules = rule_count,
                    adblock_resources = adblock::resource_count(adblock_state),
                    "adblock lists synchronized and reloaded"
                );
            }
            Err(error) => {
                warn!(reason = reason, error = %error, "adblock sync succeeded but reload failed")
            }
        },
        Err(error) => warn!(reason = reason, error = %error, "failed to synchronize adblock lists"),
    }
}
