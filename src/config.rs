use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::path_mode::{app_path_mode, AppPathMode};

/// Top-level config file structure.
/// This maps to the full `relaygate.yaml` content in the project root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayGateConfig {
    pub app: AppConfig,
    pub proxy: ProxyConfig,
    pub web: WebConfig,
    pub tray: TrayConfig,
    #[serde(default)]
    pub traffic: TrafficConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub gateway: GatewayConfig,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

impl Default for RelayGateConfig {
    fn default() -> Self {
        Self {
            app: AppConfig {
                name: "RelayGate".to_string(),
            },
            proxy: ProxyConfig {
                listen: "0.0.0.0:8787".to_string(),
                mitm: MitmConfig {
                    enabled: true,
                    tolerate_invalid_upstream_cert_hosts: Vec::new(),
                },
                adblock: AdblockConfig {
                    enabled: false,
                    mode: AdblockMode::Standard,
                    auto_update: true,
                },
            },
            web: WebConfig {
                listen: "0.0.0.0:8788".to_string(),
                open_browser_on_launch: false,
            },
            tray: TrayConfig { enabled: true },
            traffic: TrafficConfig::default(),
            logging: LoggingConfig {
                log_response_body: false,
            },
            gateway: GatewayConfig::default(),
            upstreams: Vec::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Display name for the app.
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy listen address, for example `0.0.0.0:8787`.
    pub listen: String,
    #[serde(default)]
    pub mitm: MitmConfig,
    #[serde(default)]
    pub adblock: AdblockConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MitmConfig {
    /// Enables HTTPS MITM mode.
    /// When enabled, CONNECT requests go to the MITM handler instead of a plain tunnel.
    #[serde(default)]
    pub enabled: bool,
    /// Allowlist of hosts that may skip upstream TLS certificate checks.
    #[serde(default)]
    pub tolerate_invalid_upstream_cert_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdblockConfig {
    /// Enables the Brave adblock-rust engine.
    /// When enabled, HTTPS traffic goes through MITM so filtering can be applied.
    #[serde(default)]
    pub enabled: bool,
    /// Ad and tracker blocking mode.
    /// `standard` follows Brave defaults. `aggressive` also blocks first-party requests.
    #[serde(default)]
    pub mode: AdblockMode,
    /// Enables automatic sync for Brave default lists and resources.
    #[serde(default = "default_true")]
    pub auto_update: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdblockMode {
    #[default]
    Standard,
    Aggressive,
}

impl AdblockConfig {
    pub fn effective_mode(&self) -> Option<AdblockMode> {
        if self.enabled {
            Some(self.mode)
        } else {
            None
        }
    }

    pub fn set_effective_mode(&mut self, mode: Option<AdblockMode>) {
        match mode {
            Some(mode) => {
                self.enabled = true;
                self.mode = mode;
            }
            None => {
                self.enabled = false;
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    /// Listen address for the local web settings server.
    pub listen: String,
    /// Whether to open a browser on startup.
    #[serde(default)]
    pub open_browser_on_launch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrayConfig {
    /// Enables the tray icon.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_traffic_max_queue_per_host")]
    pub max_queue_per_host: usize,
    #[serde(default = "default_traffic_initial_cooldown_secs")]
    pub initial_cooldown_secs: u64,
    #[serde(default = "default_traffic_initial_release_interval_secs")]
    pub initial_release_interval_secs: u64,
    #[serde(default = "default_traffic_min_cooldown_secs")]
    pub min_cooldown_secs: u64,
    #[serde(default = "default_traffic_max_cooldown_secs")]
    pub max_cooldown_secs: u64,
    #[serde(default = "default_traffic_min_release_interval_secs")]
    pub min_release_interval_secs: u64,
    #[serde(default = "default_traffic_max_release_interval_secs")]
    pub max_release_interval_secs: u64,
    #[serde(default = "default_traffic_auto_adjust_step_secs")]
    pub auto_adjust_step_secs: u64,
    #[serde(default = "default_traffic_auto_relax_after_successes")]
    pub auto_relax_after_successes: u64,
    #[serde(default = "default_traffic_internal_retry_limit")]
    pub internal_retry_limit: usize,
}

impl Default for TrafficConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_queue_per_host: default_traffic_max_queue_per_host(),
            initial_cooldown_secs: default_traffic_initial_cooldown_secs(),
            initial_release_interval_secs: default_traffic_initial_release_interval_secs(),
            min_cooldown_secs: default_traffic_min_cooldown_secs(),
            max_cooldown_secs: default_traffic_max_cooldown_secs(),
            min_release_interval_secs: default_traffic_min_release_interval_secs(),
            max_release_interval_secs: default_traffic_max_release_interval_secs(),
            auto_adjust_step_secs: default_traffic_auto_adjust_step_secs(),
            auto_relax_after_successes: default_traffic_auto_relax_after_successes(),
            internal_retry_limit: default_traffic_internal_retry_limit(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Whether to print response bodies to the console.
    /// This is mainly used in the gateway and HTTPS MITM paths.
    #[serde(default = "default_true")]
    pub log_response_body: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_response_body: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayConfig {
    /// Local mounted site list.
    /// For example, map `/sukebei/` to `https://sukebei.nyaa.si/`.
    #[serde(default)]
    pub mounts: Vec<MountSiteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountSiteConfig {
    /// Mount name for identification.
    pub id: String,
    /// Local path prefix, for example `/sukebei/`.
    pub mount_path: String,
    /// Remote base URL to fetch from.
    pub target_base_url: String,
    /// Optional upstream proxy profile ID.
    pub upstream_id: Option<String>,
    /// Enables this mount.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether to rewrite site links back to the local mount prefix in HTML responses.
    #[serde(default = "default_true")]
    pub rewrite_links: bool,
    /// Enables pass-through mode.
    /// When enabled, the gateway only fetches and returns content without HTML or header rewrites.
    #[serde(default)]
    pub passthrough_mode: bool,
    /// Enables a site-specific minimal page rebuild.
    /// For example, a `onejav` torrent page can be re-rendered as a compact HTML page.
    #[serde(default)]
    pub minimal_page_mode: Option<MinimalPageMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinimalPageMode {
    OnejavTorrent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Unique upstream proxy ID.
    pub id: String,
    /// Upstream proxy address.
    pub address: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Rule ID for management and tracing.
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Human-readable description.
    pub description: Option<String>,
    /// Exact host match condition.
    pub match_host: Option<String>,
    /// URL substring match condition.
    pub url_contains: Option<String>,
    /// Action to apply when the rule matches.
    pub action: RuleActionConfig,
    /// Upstream ID used by actions that need an upstream.
    pub upstream_id: Option<String>,
    /// Used when the action is `rewrite_header`.
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    /// Used when the action is `rewrite_response_body`.
    pub body_find: Option<String>,
    pub body_replace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleActionConfig {
    /// Block the request.
    Block,
    /// Rewrite a request header.
    RewriteHeader,
    /// Rewrite the response body.
    RewriteResponseBody,
    /// Route through a specific upstream proxy.
    UseUpstream,
    /// Explicit pass-through action.
    PassThrough,
}

impl RelayGateConfig {
    /// Load the config from the default path.
    /// The target deployment layout keeps `relaygate.yaml` next to the executable.
    pub fn load_default() -> Result<Self> {
        let path = Self::default_path()?;
        Self::load_from_path(&path)
    }

    pub fn load_default_or_builtin() -> Result<(Self, bool)> {
        if let Some(path) = Self::find_existing_default_path()? {
            return Ok((Self::load_from_path(&path)?, false));
        }

        Ok((Self::default(), true))
    }

    pub fn default_path() -> Result<PathBuf> {
        Ok(preferred_base_dir()?.join("relaygate.yaml"))
    }

    pub fn find_existing_default_path() -> Result<Option<PathBuf>> {
        for base_dir in candidate_base_dirs()? {
            let path = base_dir.join("relaygate.yaml");
            if path.exists() {
                return Ok(Some(path));
            }
        }

        Ok(None)
    }

    /// Read and parse YAML from a specific path.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;

        let config = serde_yaml::from_str::<Self>(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    /// Reload the config.
    /// This currently does a synchronous file reload. Hot reload can be added later.
    pub fn reload(&mut self, path: &Path) -> Result<()> {
        *self = Self::load_from_path(path)?;
        Ok(())
    }

    /// Find a mounted site config by local path prefix.
    /// The gateway can use this to map `/sukebei/...` to the target site.
    pub fn find_mount_by_path(&self, request_path: &str) -> Option<&MountSiteConfig> {
        self.gateway.mounts.iter().find(|mount| {
            mount.enabled && request_path.starts_with(mount.mount_path.trim_end_matches('/'))
        })
    }

    /// Validate important settings before startup.
    /// Start with the easiest MITM and gateway edge cases.
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

const fn default_true() -> bool {
    true
}

const fn default_traffic_max_queue_per_host() -> usize {
    32
}

const fn default_traffic_initial_cooldown_secs() -> u64 {
    3
}

const fn default_traffic_initial_release_interval_secs() -> u64 {
    3
}

const fn default_traffic_min_cooldown_secs() -> u64 {
    3
}

const fn default_traffic_max_cooldown_secs() -> u64 {
    30
}

const fn default_traffic_min_release_interval_secs() -> u64 {
    3
}

const fn default_traffic_max_release_interval_secs() -> u64 {
    15
}

const fn default_traffic_auto_adjust_step_secs() -> u64 {
    1
}

const fn default_traffic_auto_relax_after_successes() -> u64 {
    20
}

const fn default_traffic_internal_retry_limit() -> usize {
    2
}

fn candidate_base_dirs() -> Result<Vec<PathBuf>> {
    Ok(vec![preferred_base_dir()?])
}

fn preferred_base_dir() -> Result<PathBuf> {
    match app_path_mode() {
        AppPathMode::Workspace => Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
        AppPathMode::Portable => {
            let exe = env::current_exe().context("failed to resolve current executable path")?;
            let exe_dir = exe.parent().ok_or_else(|| {
                anyhow::anyhow!("current executable path does not have a parent directory")
            })?;
            Ok(exe_dir.to_path_buf())
        }
    }
}
