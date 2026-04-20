use std::sync::Arc;

use anyhow::Result;
use tokio::{
    signal,
    sync::mpsc,
    time::{self, Duration, MissedTickBehavior},
};
use tracing::{info, warn};

use crate::{
    adblock::{self, SharedAdblockState},
    config::RelayGateConfig,
    proxy::server::ProxyServer,
    rewrite::{self, SharedRewriteRegistry},
    runtime::AppRuntime,
    traffic::{SharedTrafficState, TrafficState},
    tray::{SystemTray, TrayCommand, TrayController},
};

/// Top-level application coordinator.
/// It owns startup and shutdown flow:
/// - receives the loaded config
/// - starts proxy, web, and tray
/// - handles shutdown in one place
pub struct App {
    config: Arc<RelayGateConfig>,
    rewrite_registry: SharedRewriteRegistry,
    adblock_state: SharedAdblockState,
    traffic_state: SharedTrafficState,
    runtime: AppRuntime,
}

impl App {
    pub fn new(config: RelayGateConfig) -> Result<Self> {
        let rewrite_registry = rewrite::RewriteRegistry::shared_default()?;
        let adblock_state = adblock::AdblockState::shared_default(&config)?;
        let runtime = AppRuntime::new();
        let traffic_state = TrafficState::shared(&config.traffic, runtime.clone())?;
        Ok(Self {
            config: Arc::new(config),
            rewrite_registry,
            adblock_state,
            traffic_state,
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
            tray = self.config.tray.enabled,
            mitm = self.config.proxy.mitm.enabled,
            rewrite_rules = initial_rule_count,
            adblock_rules = adblock::rule_count(&self.adblock_state),
            adblock_resources = adblock::resource_count(&self.adblock_state),
            adblock_enabled = adblock::is_enabled(&self.adblock_state),
            log_response_body = self.config.logging.log_response_body,
            "RelayGate starting"
        );

        // Prepare the three main subsystems:
        // 1. Proxy: local HTTP proxy
        // 2. Web: control panel and status API
        // 3. Tray: Windows tray entry point
        let proxy_server = ProxyServer::new(
            self.config.clone(),
            self.rewrite_registry.clone(),
            self.adblock_state.clone(),
            self.traffic_state.clone(),
            self.runtime.clone(),
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

        // Start the tray first so the user always has an entry point and exit path.
        let tray_handle = tray.start(tray_tx)?;

        // The proxy is the long-running task. The control panel is also proxied through it now.
        let mut proxy_task = tokio::spawn(async move { proxy_server.run().await });

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
                        TrayCommand::OpenControlPanel => {
                            if let Err(error) = open_control_panel(&self.config.proxy.listen) {
                                warn!(error = %error, "failed to open control panel");
                            }
                        }
                        TrayCommand::Reload => {
                            let current_config = self.config.as_ref().clone();
                            let rewrite_result = rewrite::reload_shared_registry(&self.rewrite_registry);
                            let adblock_result = adblock::reload_shared_state(&self.adblock_state, &current_config);
                            match (rewrite_result, adblock_result) {
                                (Ok(rule_count), Ok(adblock_rule_count)) => info!(
                                    rewrite_rules = rule_count,
                                    adblock_rules = adblock_rule_count,
                                    adblock_resources = adblock::resource_count(&self.adblock_state),
                                    "rewrite rules and adblock rules reloaded"
                                ),
                                (Err(error), _) => warn!(error = %error, "failed to reload rewrite rules"),
                                (_, Err(error)) => warn!(error = %error, "failed to reload adblock rules"),
                            }
                        }
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
        if let Some(handle) = auto_update_task {
            handle.abort();
        }
        info!("RelayGate stopped");

        Ok(())
    }
}

async fn run_adblock_auto_update_loop(
    config: Arc<RelayGateConfig>,
    adblock_state: SharedAdblockState,
    runtime: AppRuntime,
) {
    sync_adblock_defaults(&config, &adblock_state, &runtime, "startup").await;

    let mut interval = time::interval(Duration::from_secs(6 * 60 * 60));
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
        Ok(files) => match adblock::reload_shared_state(adblock_state, config) {
            Ok(rule_count) => {
                runtime.notify_status_changed();
                runtime.notify_settings_changed();
                runtime.notify_patch_changed();
                runtime.notify_render_changed();
                runtime.notify_adblock_changed();
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

fn open_control_panel(web_listen: &str) -> Result<()> {
    let url = format!("http://{}/", browser_open_address(web_listen));
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;

        let operation: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
        let target: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                operation.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            )
        };

        if result as isize <= 32 {
            anyhow::bail!("failed to open control panel URL: {url}");
        }

        return Ok(());
    }

    #[cfg(not(windows))]
    {
        std::process::Command::new("xdg-open").arg(&url).spawn()?;
        Ok(())
    }
}

fn browser_open_address(listen: &str) -> String {
    if let Some((host, port)) = listen.rsplit_once(':') {
        let browser_host = match host.trim_matches(['[', ']']) {
            "0.0.0.0" | "::" | "::0" => "127.0.0.1",
            other => other,
        };
        format!("{browser_host}:{port}")
    } else {
        listen.to_string()
    }
}
