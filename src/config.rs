use std::{
    collections::HashSet,
    env, fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{bail, Context, Result};
use axum::http::{HeaderName, Uri};
use globset::Glob;
use serde::{Deserialize, Serialize};

use crate::path_mode::{app_path_mode, AppPathMode};

/// Top-level config file structure.
/// This maps to the full `relaygate.yaml` content in the project root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayGateConfig {
    #[serde(default = "default_proxy_listen")]
    pub listen: String,
    #[serde(default = "default_locale", skip_serializing_if = "is_default_locale")]
    pub locale: String,
    #[serde(default, skip_serializing_if = "is_default_adblock_mode_setting")]
    pub adblock_mode: AdblockModeSetting,
    #[serde(
        default = "default_upstream_protocol_preference",
        skip_serializing_if = "is_default_upstream_protocol_preference"
    )]
    pub upstream_protocol: UpstreamProtocolPreferenceConfig,
    #[serde(
        default = "default_downstream_protocol_preference",
        skip_serializing_if = "is_default_downstream_protocol_preference"
    )]
    pub downstream_protocol: DownstreamProtocolPreferenceConfig,
    #[serde(default, skip_serializing_if = "is_default_h3_streaming_response_mode")]
    pub h3_streaming_mode: Http3StreamingResponseModeConfig,
    /// Debug switch: force MITM responses through the full body pipeline instead of the streaming fast path.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_mitm_fast_path: bool,
    /// Debug switch: write adblock request matching decisions to data/logs/adblock-debug.log.
    #[serde(default, skip_serializing_if = "is_false")]
    pub adblock_debug_log: bool,
    #[serde(default, skip_serializing)]
    pub app: AppConfig,
    #[serde(default, skip_serializing)]
    pub proxy: ProxyConfig,
    #[serde(default, skip_serializing)]
    pub web: WebConfig,
    #[serde(default, skip_serializing)]
    pub tray: TrayConfig,
    #[serde(default, skip_serializing)]
    pub traffic: TrafficConfig,
    #[serde(default, skip_serializing)]
    pub logging: LoggingConfig,
    #[serde(default, skip_serializing)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub gateway: GatewayConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream_routes: Vec<UpstreamRouteConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

impl Default for RelayGateConfig {
    fn default() -> Self {
        Self {
            listen: default_proxy_listen(),
            locale: default_locale(),
            adblock_mode: AdblockModeSetting::Aggressive,
            upstream_protocol: UpstreamProtocolPreferenceConfig::GuardedH3,
            downstream_protocol: DownstreamProtocolPreferenceConfig::Http2Enabled,
            h3_streaming_mode: Http3StreamingResponseModeConfig::default(),
            disable_mitm_fast_path: false,
            adblock_debug_log: false,
            app: AppConfig {
                name: "RelayGate".to_string(),
            },
            proxy: ProxyConfig {
                listen: default_proxy_listen(),
                allow_lan: false,
                allowed_clients: default_allowed_clients(),
                connect: ConnectPolicyConfig::default(),
                mitm: MitmConfig {
                    enabled: true,
                    keep_alive: true,
                    downstream_http2: false,
                    max_requests_per_connection: default_mitm_max_requests_per_connection(),
                    tolerate_invalid_upstream_cert_hosts: Vec::new(),
                    passthrough_hosts: default_mitm_passthrough_hosts(),
                },
                upstream: ProxyUpstreamConfig::default(),
                adblock: AdblockConfig {
                    enabled: true,
                    mode: AdblockMode::Aggressive,
                    auto_update: true,
                },
            },
            web: WebConfig {
                listen: default_web_listen(),
                allow_lan: false,
                allowed_clients: default_allowed_clients(),
                open_browser_on_launch: false,
            },
            tray: TrayConfig { enabled: true },
            traffic: TrafficConfig::default(),
            logging: LoggingConfig {
                log_response_body: false,
            },
            limits: LimitsConfig::default(),
            gateway: GatewayConfig::default(),
            upstreams: Vec::new(),
            upstream_routes: Vec::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Display name for the app.
    #[serde(default = "default_app_name", skip_serializing)]
    pub name: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            name: default_app_name(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy listen address, for example `127.0.0.1:8787`.
    #[serde(default = "default_proxy_listen")]
    pub listen: String,
    /// Whether to allow clients outside localhost to use the proxy.
    #[serde(default)]
    pub allow_lan: bool,
    /// Explicit client IP allowlist used when `allow_lan` is enabled.
    #[serde(default = "default_allowed_clients")]
    pub allowed_clients: Vec<String>,
    /// CONNECT tunnel safety policy.
    #[serde(default, skip_serializing)]
    pub connect: ConnectPolicyConfig,
    #[serde(default, skip_serializing)]
    pub mitm: MitmConfig,
    #[serde(default, skip_serializing)]
    pub upstream: ProxyUpstreamConfig,
    #[serde(default, skip_serializing)]
    pub adblock: AdblockConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: default_proxy_listen(),
            allow_lan: false,
            allowed_clients: default_allowed_clients(),
            connect: ConnectPolicyConfig::default(),
            mitm: MitmConfig::default(),
            upstream: ProxyUpstreamConfig::default(),
            adblock: AdblockConfig {
                enabled: true,
                mode: AdblockMode::Aggressive,
                auto_update: true,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPolicyConfig {
    /// Ports RelayGate may CONNECT to directly or through an upstream proxy.
    /// Empty means any non-blocked port is allowed.
    #[serde(default = "default_connect_allowed_ports")]
    pub allowed_ports: Vec<u16>,
    /// Ports RelayGate must never CONNECT to, even when also listed in allowed_ports.
    #[serde(default = "default_connect_blocked_ports")]
    pub blocked_ports: Vec<u16>,
    /// Whether CONNECT targets may resolve to private or link-local addresses.
    #[serde(default)]
    pub allow_private_targets: bool,
    /// Whether CONNECT targets may resolve to loopback addresses.
    #[serde(default)]
    pub allow_loopback_targets: bool,
}

impl Default for ConnectPolicyConfig {
    fn default() -> Self {
        Self {
            allowed_ports: default_connect_allowed_ports(),
            blocked_ports: default_connect_blocked_ports(),
            allow_private_targets: false,
            allow_loopback_targets: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmConfig {
    /// Enables HTTPS MITM mode.
    /// When enabled, CONNECT requests go to the MITM handler instead of a plain tunnel.
    #[serde(default)]
    pub enabled: bool,
    /// Enables the conservative MITM keep-alive request loop.
    #[serde(default = "default_true")]
    pub keep_alive: bool,
    /// Advertises HTTP/2 support to downstream TLS clients during MITM ALPN.
    ///
    /// Defaults to false because downstream HTTP/2 extended CONNECT WebSocket
    /// forwarding is not implemented yet.
    #[serde(default)]
    pub downstream_http2: bool,
    /// Maximum number of HTTPS requests handled on one MITM TLS connection.
    #[serde(default = "default_mitm_max_requests_per_connection")]
    pub max_requests_per_connection: usize,
    /// Allowlist of hosts that may skip upstream TLS certificate checks.
    #[serde(default)]
    pub tolerate_invalid_upstream_cert_hosts: Vec<String>,
    /// Host patterns that stay as plain CONNECT tunnels even when MITM features are enabled.
    ///
    /// This is the only true WSS passthrough point: after TLS MITM starts,
    /// RelayGate can bridge WebSocket bytes, but the original connection is
    /// already intercepted.
    #[serde(default = "default_mitm_passthrough_hosts")]
    pub passthrough_hosts: Vec<String>,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            keep_alive: true,
            downstream_http2: false,
            max_requests_per_connection: default_mitm_max_requests_per_connection(),
            tolerate_invalid_upstream_cert_hosts: Vec::new(),
            passthrough_hosts: default_mitm_passthrough_hosts(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyUpstreamConfig {
    /// RelayGate -> upstream HTTP protocol policy for MITM traffic.
    ///
    /// `auto` preserves the current reqwest negotiation behavior. Other values
    /// are explicit escape hatches and keep downstream H1/H2 independent from
    /// the upstream transport decision.
    #[serde(default)]
    pub protocol_policy: UpstreamProtocolPolicyConfig,
    /// Enables the upstream HTTP/3 forwarding dry-run probe hook.
    ///
    /// This is not active H3 forwarding. When enabled, MITM adapters may do
    /// extra H3 dry-run work before continuing the normal reqwest path.
    /// Defaults to false because it does not serve bytes and can reduce throughput.
    #[serde(default)]
    pub http3_probe_enabled: bool,
    /// Enables guarded active forwarding for complete small buffered H3 responses.
    ///
    /// This defaults to false because some sites are sensitive to upstream
    /// transport changes even when the response is small and fully buffered.
    /// RelayGate may use an upstream H3 response only when explicitly enabled.
    #[serde(default)]
    pub http3_buffered_response_enabled: bool,
    /// Enables the experimental upstream H3 progressive forwarding path.
    ///
    /// This defaults to false globally. When GuardedH3 is selected, RelayGate may
    /// try active H3 streaming according to `http3_streaming_response_mode`.
    #[serde(default)]
    pub http3_streaming_response_enabled: bool,
    /// Controls how broadly the active H3 streaming response path may be used.
    ///
    /// `fast_path_probe` is the temporary diagnostic default for GuardedH3 so
    /// H3->H2 streaming correctness can be validated across normal fast-path
    /// subresources. Switch back to `media_only` for conservative daily use.
    #[serde(default)]
    pub http3_streaming_response_mode: Http3StreamingResponseModeConfig,
}

impl Default for ProxyUpstreamConfig {
    fn default() -> Self {
        Self {
            protocol_policy: UpstreamProtocolPolicyConfig::default(),
            http3_probe_enabled: false,
            http3_buffered_response_enabled: false,
            http3_streaming_response_enabled: false,
            http3_streaming_response_mode: Http3StreamingResponseModeConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Http3StreamingResponseModeConfig {
    /// Disable active H3 response byte-pump even when the legacy boolean is true.
    Disabled,
    /// Only video/audio-like responses may use active H3 progressive forwarding.
    MediaOnly,
    /// Diagnostic mode: allow non-document fast-path subresources to exercise the
    /// H3->H2 byte-pump so protocol correctness bugs can be reproduced.
    #[default]
    FastPathProbe,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocolPolicyConfig {
    /// Preserve reqwest's default upstream negotiation, including HTTP/2 when
    /// the origin/proxy and TLS ALPN allow it.
    #[default]
    Auto,
    /// Force reqwest to use HTTP/1.x for upstream requests.
    Http1Only,
    /// Force reqwest's HTTP/2 prior-knowledge mode.
    ///
    /// This is intentionally explicit rather than named "preferred" because it
    /// may fail for origins or upstream proxies that do not support H2.
    Http2PriorKnowledge,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocolPreferenceConfig {
    #[default]
    Auto,
    Http1Only,
    Http2Preferred,
    /// Legacy explicit mode. Keep YAML compatibility, but do not expose it as
    /// a normal backend preference because many HTTPS origins reject it.
    Http2PriorKnowledge,
    GuardedH3,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DownstreamProtocolPreferenceConfig {
    #[default]
    Http1Only,
    Http2Enabled,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdblockModeSetting {
    Disabled,
    Standard,
    #[default]
    Aggressive,
}

impl AdblockModeSetting {
    pub fn from_effective_mode(mode: Option<AdblockMode>) -> Self {
        match mode {
            None => Self::Disabled,
            Some(AdblockMode::Standard) => Self::Standard,
            Some(AdblockMode::Aggressive) => Self::Aggressive,
        }
    }

    pub fn effective_mode(self) -> Option<AdblockMode> {
        match self {
            Self::Disabled => None,
            Self::Standard => Some(AdblockMode::Standard),
            Self::Aggressive => Some(AdblockMode::Aggressive),
        }
    }
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
    #[serde(default = "default_web_listen")]
    pub listen: String,
    /// Whether to allow clients outside localhost to access the web UI.
    #[serde(default)]
    pub allow_lan: bool,
    /// Explicit client IP allowlist used when `allow_lan` is enabled.
    #[serde(default = "default_allowed_clients")]
    pub allowed_clients: Vec<String>,
    /// Whether to open a browser on startup.
    #[serde(default, skip_serializing)]
    pub open_browser_on_launch: bool,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            listen: default_web_listen(),
            allow_lan: false,
            allowed_clients: default_allowed_clients(),
            open_browser_on_launch: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrayConfig {
    #[serde(default = "default_true", skip_serializing)]
    pub enabled: bool,
}

impl Default for TrayConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum HTTP request header bytes accepted from a client.
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    /// Maximum decoded request body bytes accepted for fixed-length requests.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    /// Maximum decoded chunked request body bytes accepted.
    #[serde(default = "default_max_chunked_body_bytes")]
    pub max_chunked_body_bytes: usize,
    /// Maximum response body bytes buffered for rewrite, patch, or injection.
    #[serde(default = "default_max_response_buffer_bytes")]
    pub max_response_buffer_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: default_max_header_bytes(),
            max_request_body_bytes: default_max_request_body_bytes(),
            max_chunked_body_bytes: default_max_chunked_body_bytes(),
            max_response_buffer_bytes: default_max_response_buffer_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayConfig {
    /// Local mounted site list.
    /// For example, map `/site/` to `https://example.com/`.
    #[serde(default)]
    pub mounts: Vec<MountSiteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountSiteConfig {
    /// Mount name for identification.
    pub id: String,
    /// Local path prefix, for example `/site/`.
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
pub struct UpstreamRouteConfig {
    /// Unique route ID.
    pub id: String,
    /// Host glob pattern. Examples: `example.com`, `*.example.com`.
    pub host_pattern: String,
    /// Upstream proxy ID to use when the host pattern matches.
    pub upstream_id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpstreamRoutingConfig {
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub upstream_routes: Vec<UpstreamRouteConfig>,
}

impl UpstreamRoutingConfig {
    pub fn from_main_config(config: &RelayGateConfig) -> Self {
        Self {
            upstreams: config.upstreams.clone(),
            upstream_routes: config.upstream_routes.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_upstream_routing(&self.upstreams, &self.upstream_routes)
    }

    pub fn load_default_or_config(config: &RelayGateConfig) -> Result<Self> {
        let path = Self::default_path()?;
        if path.exists() {
            return Self::load_from_path(&path);
        }

        Ok(Self::from_main_config(config))
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read upstream routing file: {}", path.display()))?;
        serde_yaml::from_str::<Self>(&content)
            .with_context(|| format!("failed to parse upstream routing file: {}", path.display()))
    }

    pub fn save_default(&self) -> Result<()> {
        let path = Self::default_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create upstream routing directory: {}",
                    parent.display()
                )
            })?;
        }
        let yaml = serde_yaml::to_string(self)?;
        fs::write(&path, yaml)
            .with_context(|| format!("failed to write upstream routing file: {}", path.display()))
    }

    pub fn default_path() -> Result<PathBuf> {
        Ok(preferred_base_dir()?.join("data").join("upstreams.yaml"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dns_profile_id")]
    pub default_profile: String,
    #[serde(default = "default_dns_max_cache_entries")]
    pub max_cache_entries: usize,
    #[serde(default = "default_true")]
    pub stale_while_revalidate: bool,
    #[serde(default = "default_dns_refresh_before_expire_secs")]
    pub refresh_before_expire_secs: u64,
    #[serde(default)]
    pub profiles: Vec<DnsProfileConfig>,
    #[serde(default)]
    pub routes: Vec<DnsRouteConfig>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_profile: default_dns_profile_id(),
            max_cache_entries: default_dns_max_cache_entries(),
            stale_while_revalidate: true,
            refresh_before_expire_secs: default_dns_refresh_before_expire_secs(),
            profiles: vec![DnsProfileConfig::system()],
            routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProfileConfig {
    pub id: String,
    #[serde(default)]
    pub mode: DnsProfileMode,
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_dns_attempts")]
    pub attempts: usize,
    #[serde(default = "default_dns_cache_ttl_min_secs")]
    pub cache_ttl_min_secs: u64,
    #[serde(default = "default_dns_cache_ttl_max_secs")]
    pub cache_ttl_max_secs: u64,
    #[serde(default = "default_dns_negative_ttl_secs")]
    pub negative_ttl_secs: u64,
    #[serde(default = "default_dns_stale_fallback_secs")]
    pub stale_fallback_secs: u64,
    #[serde(default)]
    pub fallback_profiles: Vec<String>,
}

impl DnsProfileConfig {
    pub fn system() -> Self {
        Self {
            id: default_dns_profile_id(),
            mode: DnsProfileMode::System,
            servers: Vec::new(),
            enabled: true,
            timeout_ms: default_dns_timeout_ms(),
            attempts: default_dns_attempts(),
            cache_ttl_min_secs: default_dns_cache_ttl_min_secs(),
            cache_ttl_max_secs: default_dns_cache_ttl_max_secs(),
            negative_ttl_secs: default_dns_negative_ttl_secs(),
            stale_fallback_secs: default_dns_stale_fallback_secs(),
            fallback_profiles: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsProfileMode {
    #[default]
    System,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRouteConfig {
    pub id: String,
    pub host_pattern: String,
    pub profile_id: String,
    #[serde(default)]
    pub strict: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl DnsConfig {
    pub fn validate(&self) -> Result<()> {
        validate_dns_config(self)
    }

    pub fn load_default_or_default() -> Result<Self> {
        let path = Self::default_path()?;
        if path.exists() {
            return Self::load_from_path(&path);
        }

        Ok(Self::default())
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read DNS config file: {}", path.display()))?;
        serde_yaml::from_str::<Self>(&content)
            .with_context(|| format!("failed to parse DNS config file: {}", path.display()))
    }

    pub fn save_default(&self) -> Result<()> {
        let path = Self::default_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create DNS config directory: {}",
                    parent.display()
                )
            })?;
        }
        let yaml = serde_yaml::to_string(self)?;
        fs::write(&path, yaml)
            .with_context(|| format!("failed to write DNS config file: {}", path.display()))
    }

    pub fn default_path() -> Result<PathBuf> {
        Ok(preferred_base_dir()?.join("data").join("dns.yaml"))
    }
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
    pub fn set_adblock_mode_preference(&mut self, mode: AdblockModeSetting) {
        self.adblock_mode = mode;
        self.proxy.adblock = AdblockConfig {
            enabled: true,
            mode: AdblockMode::Aggressive,
            auto_update: true,
        };
        self.proxy
            .adblock
            .set_effective_mode(self.adblock_mode.effective_mode());
    }

    pub fn apply_fixed_product_defaults(&mut self) {
        let default_listen = default_proxy_listen();
        if self.listen == default_listen && self.proxy.listen != default_listen {
            self.listen = self.proxy.listen.clone();
        }
        if self.adblock_mode == AdblockModeSetting::Aggressive
            && self.proxy.adblock.effective_mode() != Some(AdblockMode::Aggressive)
        {
            self.adblock_mode =
                AdblockModeSetting::from_effective_mode(self.proxy.adblock.effective_mode());
        }
        self.app = AppConfig::default();
        self.web = WebConfig::default();
        self.proxy.listen = self.listen.clone();
        self.proxy.connect = ConnectPolicyConfig::default();
        self.proxy.mitm = MitmConfig::default();
        self.proxy.upstream = ProxyUpstreamConfig::default();
        self.apply_protocol_preferences();
        self.proxy.adblock = AdblockConfig {
            enabled: true,
            mode: AdblockMode::Aggressive,
            auto_update: true,
        };
        self.proxy
            .adblock
            .set_effective_mode(self.adblock_mode.effective_mode());
        self.tray = TrayConfig::default();
        self.traffic = TrafficConfig::default();
        self.logging = LoggingConfig::default();
        self.limits = LimitsConfig::default();
    }

    fn apply_protocol_preferences(&mut self) {
        self.proxy.mitm.downstream_http2 = matches!(
            self.downstream_protocol,
            DownstreamProtocolPreferenceConfig::Http2Enabled
        );

        self.proxy.upstream.http3_probe_enabled = false;
        self.proxy.upstream.http3_streaming_response_enabled = false;
        self.proxy.upstream.http3_streaming_response_mode = self.h3_streaming_mode;
        self.proxy.upstream.http3_buffered_response_enabled = false;

        // Keep the product-facing upstream protocol as a small "highest allowed
        // protocol" switch. Older YAML values are normalized into the two
        // supported runtime states instead of exposing more knobs in the UI.
        self.upstream_protocol = match self.upstream_protocol {
            UpstreamProtocolPreferenceConfig::Auto
            | UpstreamProtocolPreferenceConfig::Http2PriorKnowledge
            | UpstreamProtocolPreferenceConfig::GuardedH3 => {
                UpstreamProtocolPreferenceConfig::GuardedH3
            }
            UpstreamProtocolPreferenceConfig::Http1Only
            | UpstreamProtocolPreferenceConfig::Http2Preferred => {
                UpstreamProtocolPreferenceConfig::Http2Preferred
            }
        };

        self.proxy.upstream.protocol_policy = match self.upstream_protocol {
            UpstreamProtocolPreferenceConfig::GuardedH3 => {
                self.proxy.upstream.http3_buffered_response_enabled = true;
                self.proxy.upstream.http3_streaming_response_enabled =
                    self.h3_streaming_mode != Http3StreamingResponseModeConfig::Disabled;
                UpstreamProtocolPolicyConfig::Auto
            }
            UpstreamProtocolPreferenceConfig::Http2Preferred => UpstreamProtocolPolicyConfig::Auto,
            UpstreamProtocolPreferenceConfig::Auto
            | UpstreamProtocolPreferenceConfig::Http1Only
            | UpstreamProtocolPreferenceConfig::Http2PriorKnowledge => unreachable!(
                "upstream protocol preference should be normalized before policy mapping"
            ),
        };
    }

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

        let mut config = Self::default();
        config.apply_fixed_product_defaults();
        Ok((config, true))
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

        let mut config = serde_yaml::from_str::<Self>(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        config.apply_fixed_product_defaults();

        Ok(config)
    }

    /// Reload the config.
    /// This currently does a synchronous file reload. Hot reload can be added later.
    pub fn reload(&mut self, path: &Path) -> Result<()> {
        *self = Self::load_from_path(path)?;
        Ok(())
    }

    /// Find a mounted site config by local path prefix.
    /// The gateway can use this to map `/site/...` to the target site.
    pub fn find_mount_by_path(&self, request_path: &str) -> Option<&MountSiteConfig> {
        self.gateway.mounts.iter().find(|mount| {
            mount.enabled && request_path.starts_with(mount.mount_path.trim_end_matches('/'))
        })
    }

    /// Validate important settings before startup.
    pub fn validate(&self) -> Result<()> {
        validate_listen("proxy.listen", &self.proxy.listen)?;
        validate_listen("web.listen", &self.web.listen)?;
        validate_lan_boundary("proxy", &self.proxy.listen, self.proxy.allow_lan)?;
        validate_lan_boundary("web", &self.web.listen, self.web.allow_lan)?;
        validate_allowed_clients(
            "proxy.allowed_clients",
            self.proxy.allow_lan,
            &self.proxy.allowed_clients,
        )?;
        validate_allowed_clients(
            "web.allowed_clients",
            self.web.allow_lan,
            &self.web.allowed_clients,
        )?;
        validate_connect_policy(&self.proxy.connect)?;
        validate_mitm_config(&self.proxy.mitm)?;
        validate_proxy_upstream_config(&self.proxy.upstream)?;
        validate_limits(&self.limits)?;
        validate_traffic(&self.traffic)?;
        validate_upstream_routing(&self.upstreams, &self.upstream_routes)?;
        validate_rules(&self.rules, None)?;
        validate_gateway_mounts(&self.gateway.mounts, None)?;
        Ok(())
    }

    /// Validate references that may depend on the external `data/upstreams.yaml` file.
    pub fn validate_runtime_references(&self, upstreams: &UpstreamRoutingConfig) -> Result<()> {
        validate_rules(&self.rules, Some(&upstreams.upstreams))?;
        validate_gateway_mounts(&self.gateway.mounts, Some(&upstreams.upstreams))
    }
}

fn validate_listen(field: &str, value: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("{field} must be a valid socket address, got `{value}`"))
}

fn validate_lan_boundary(section: &str, listen: &str, allow_lan: bool) -> Result<()> {
    let addr = validate_listen(&format!("{section}.listen"), listen)?;
    if addr.ip().is_unspecified() && !allow_lan {
        bail!(
            "{section}.listen is `{listen}`, which listens on all interfaces, but {section}.allow_lan is false; set {section}.listen to 127.0.0.1/[::1] or set {section}.allow_lan=true with a tight {section}.allowed_clients list"
        );
    }
    Ok(())
}

fn validate_allowed_clients(field: &str, allow_lan: bool, entries: &[String]) -> Result<()> {
    if allow_lan && entries.is_empty() {
        bail!("{field} must contain at least one IP or CIDR entry when allow_lan is true");
    }

    for (index, entry) in entries.iter().enumerate() {
        validate_ip_or_cidr(entry).with_context(|| {
            format!("{field}[{index}] must be a valid IP address or CIDR, got `{entry}`")
        })?;
    }

    Ok(())
}

fn validate_ip_or_cidr(value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() {
        bail!("empty allowlist entry");
    }

    if let Some((ip_part, prefix_part)) = value.split_once('/') {
        if prefix_part.contains('/') {
            bail!("CIDR prefix contains more than one slash");
        }
        let ip = parse_ip_literal(ip_part)?;
        let prefix = prefix_part
            .parse::<u8>()
            .with_context(|| format!("invalid CIDR prefix `{prefix_part}`"))?;
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            bail!("CIDR prefix {prefix} is too large for {ip}");
        }
        return Ok(());
    }

    parse_ip_literal(value)?;
    Ok(())
}

fn parse_ip_literal(value: &str) -> Result<IpAddr> {
    let trimmed = value.trim().trim_matches(['[', ']']);
    trimmed
        .parse::<IpAddr>()
        .with_context(|| format!("invalid IP address `{value}`"))
}

fn validate_connect_policy(policy: &ConnectPolicyConfig) -> Result<()> {
    let mut allowed = HashSet::new();
    for (index, port) in policy.allowed_ports.iter().copied().enumerate() {
        if port == 0 {
            bail!("proxy.connect.allowed_ports[{index}] must be greater than 0");
        }
        if !allowed.insert(port) {
            bail!("proxy.connect.allowed_ports[{index}] duplicates port {port}");
        }
    }

    let mut blocked = HashSet::new();
    for (index, port) in policy.blocked_ports.iter().copied().enumerate() {
        if port == 0 {
            bail!("proxy.connect.blocked_ports[{index}] must be greater than 0");
        }
        if !blocked.insert(port) {
            bail!("proxy.connect.blocked_ports[{index}] duplicates port {port}");
        }
    }

    Ok(())
}

fn validate_mitm_config(mitm: &MitmConfig) -> Result<()> {
    if mitm.max_requests_per_connection == 0 {
        bail!("proxy.mitm.max_requests_per_connection must be greater than 0");
    }

    for (index, host) in mitm.passthrough_hosts.iter().enumerate() {
        if host.trim().is_empty() {
            bail!("proxy.mitm.passthrough_hosts[{index}] must not be empty");
        }
    }

    Ok(())
}

fn validate_proxy_upstream_config(_upstream: &ProxyUpstreamConfig) -> Result<()> {
    // The protocol policy enum is validated by serde. Keep this small helper so
    // future upstream H2/H3 options have a single config validation seam.
    Ok(())
}

fn validate_limits(limits: &LimitsConfig) -> Result<()> {
    const MIN_HEADER_BYTES: usize = 4096;

    if limits.max_header_bytes < MIN_HEADER_BYTES {
        bail!(
            "limits.max_header_bytes must be at least {MIN_HEADER_BYTES}, got {}",
            limits.max_header_bytes
        );
    }
    if limits.max_request_body_bytes == 0 {
        bail!("limits.max_request_body_bytes must be greater than 0");
    }
    if limits.max_chunked_body_bytes == 0 {
        bail!("limits.max_chunked_body_bytes must be greater than 0");
    }
    if limits.max_response_buffer_bytes == 0 {
        bail!("limits.max_response_buffer_bytes must be greater than 0");
    }

    Ok(())
}

fn validate_traffic(traffic: &TrafficConfig) -> Result<()> {
    if traffic.enabled {
        if traffic.max_queue_per_host == 0 {
            bail!("traffic.max_queue_per_host must be greater than 0");
        }
        if traffic.internal_retry_limit == 0 {
            bail!("traffic.internal_retry_limit must be greater than 0");
        }
        if traffic.auto_adjust_step_secs == 0 {
            bail!("traffic.auto_adjust_step_secs must be greater than 0");
        }
        if traffic.auto_relax_after_successes == 0 {
            bail!("traffic.auto_relax_after_successes must be greater than 0");
        }
        if traffic.initial_cooldown_secs == 0 {
            bail!("traffic.initial_cooldown_secs must be greater than 0");
        }
        if traffic.initial_release_interval_secs == 0 {
            bail!("traffic.initial_release_interval_secs must be greater than 0");
        }
    }

    if traffic.min_cooldown_secs == 0 {
        bail!("traffic.min_cooldown_secs must be greater than 0");
    }
    if traffic.max_cooldown_secs == 0 {
        bail!("traffic.max_cooldown_secs must be greater than 0");
    }
    if traffic.min_cooldown_secs > traffic.max_cooldown_secs {
        bail!(
            "traffic.min_cooldown_secs must not be greater than traffic.max_cooldown_secs ({} > {})",
            traffic.min_cooldown_secs,
            traffic.max_cooldown_secs
        );
    }
    if traffic.min_release_interval_secs == 0 {
        bail!("traffic.min_release_interval_secs must be greater than 0");
    }
    if traffic.max_release_interval_secs == 0 {
        bail!("traffic.max_release_interval_secs must be greater than 0");
    }
    if traffic.min_release_interval_secs > traffic.max_release_interval_secs {
        bail!(
            "traffic.min_release_interval_secs must not be greater than traffic.max_release_interval_secs ({} > {})",
            traffic.min_release_interval_secs,
            traffic.max_release_interval_secs
        );
    }

    Ok(())
}

fn validate_dns_config(config: &DnsConfig) -> Result<()> {
    let mut profile_ids = HashSet::new();

    if config.default_profile.trim().is_empty() {
        bail!("dns.default_profile must not be empty");
    }

    if config.max_cache_entries == 0 {
        bail!("dns.max_cache_entries must be greater than 0");
    }
    if config.stale_while_revalidate && config.refresh_before_expire_secs == 0 {
        bail!("dns.refresh_before_expire_secs must be greater than 0 when dns.stale_while_revalidate is true");
    }

    if config.profiles.is_empty() {
        // Keep the existing DNS default behavior: an empty profiles list means the built-in
        // `system` profile will be used.
        profile_ids.insert(default_dns_profile_id());
    } else {
        for (index, profile) in config.profiles.iter().enumerate() {
            let field = format!("dns.profiles[{index}]");
            validate_non_empty_id(&format!("{field}.id"), &profile.id)?;
            if !profile_ids.insert(profile.id.clone()) {
                bail!("{field}.id `{}` is duplicated", profile.id);
            }
            if profile.timeout_ms == 0 {
                bail!("{field}.timeout_ms must be greater than 0");
            }
            if profile.attempts == 0 {
                bail!("{field}.attempts must be greater than 0");
            }
            if profile.cache_ttl_min_secs == 0 {
                bail!("{field}.cache_ttl_min_secs must be greater than 0");
            }
            if profile.cache_ttl_max_secs == 0 {
                bail!("{field}.cache_ttl_max_secs must be greater than 0");
            }
            if profile.cache_ttl_min_secs > profile.cache_ttl_max_secs {
                bail!(
                    "{field}.cache_ttl_min_secs must not be greater than {field}.cache_ttl_max_secs ({} > {})",
                    profile.cache_ttl_min_secs,
                    profile.cache_ttl_max_secs
                );
            }
            if matches!(profile.mode, DnsProfileMode::Udp) && profile.servers.is_empty() {
                bail!("{field}.servers must contain at least one server when {field}.mode is udp");
            }
            for (server_index, server) in profile.servers.iter().enumerate() {
                server.parse::<SocketAddr>().with_context(|| {
                    format!("{field}.servers[{server_index}] must be a valid socket address, got `{server}`")
                })?;
            }
        }
    }

    if !profile_ids.contains(config.default_profile.trim()) {
        bail!(
            "dns.default_profile `{}` does not exist in dns.profiles",
            config.default_profile
        );
    }

    for (index, profile) in config.profiles.iter().enumerate() {
        for (fallback_index, fallback_id) in profile.fallback_profiles.iter().enumerate() {
            if !profile_ids.contains(fallback_id.trim()) {
                bail!(
                    "dns.profiles[{index}].fallback_profiles[{fallback_index}] references missing profile `{fallback_id}`"
                );
            }
        }
    }

    for (index, route) in config.routes.iter().enumerate() {
        let field = format!("dns.routes[{index}]");
        validate_non_empty_id(&format!("{field}.id"), &route.id)?;
        validate_host_pattern(&format!("{field}.host_pattern"), &route.host_pattern)?;
        if !profile_ids.contains(route.profile_id.trim()) {
            bail!(
                "{field}.profile_id `{}` does not exist in dns.profiles",
                route.profile_id
            );
        }
    }

    Ok(())
}

fn validate_upstream_routing(
    upstreams: &[UpstreamConfig],
    routes: &[UpstreamRouteConfig],
) -> Result<()> {
    let mut upstream_ids = HashSet::new();

    for (index, upstream) in upstreams.iter().enumerate() {
        let field = format!("upstreams[{index}]");
        validate_non_empty_id(&format!("{field}.id"), &upstream.id)?;
        if !upstream_ids.insert(upstream.id.clone()) {
            bail!("{field}.id `{}` is duplicated", upstream.id);
        }
        validate_upstream_address(&format!("{field}.address"), &upstream.address)?;
    }

    for (index, route) in routes.iter().enumerate() {
        let field = format!("upstream_routes[{index}]");
        validate_non_empty_id(&format!("{field}.id"), &route.id)?;
        validate_host_pattern(&format!("{field}.host_pattern"), &route.host_pattern)?;
        if !upstream_ids.contains(route.upstream_id.trim()) {
            bail!(
                "{field}.upstream_id `{}` does not exist in upstreams",
                route.upstream_id
            );
        }
    }

    Ok(())
}

fn validate_rules(rules: &[RuleConfig], upstreams: Option<&[UpstreamConfig]>) -> Result<()> {
    let upstream_ids = upstreams.map(|items| {
        items
            .iter()
            .map(|upstream| upstream.id.as_str())
            .collect::<HashSet<_>>()
    });

    for (index, rule) in rules.iter().enumerate() {
        let field = format!("rules[{index}]");
        validate_non_empty_id(&format!("{field}.id"), &rule.id)?;

        match rule.action {
            RuleActionConfig::Block | RuleActionConfig::PassThrough => {}
            RuleActionConfig::UseUpstream => {
                let upstream_id =
                    required_option(&format!("{field}.upstream_id"), rule.upstream_id.as_deref())?;
                if let Some(upstream_ids) = &upstream_ids {
                    if !upstream_ids.contains(upstream_id) {
                        bail!("{field}.upstream_id `{upstream_id}` does not exist in upstreams");
                    }
                }
            }
            RuleActionConfig::RewriteHeader => {
                let header_name =
                    required_option(&format!("{field}.header_name"), rule.header_name.as_deref())?;
                required_option(
                    &format!("{field}.header_value"),
                    rule.header_value.as_deref(),
                )?;
                HeaderName::from_str(header_name).with_context(|| {
                    format!(
                        "{field}.header_name must be a valid HTTP header name, got `{header_name}`"
                    )
                })?;
            }
            RuleActionConfig::RewriteResponseBody => {
                required_option(&format!("{field}.body_find"), rule.body_find.as_deref())?;
                required_option(
                    &format!("{field}.body_replace"),
                    rule.body_replace.as_deref(),
                )?;
            }
        }
    }

    Ok(())
}

fn validate_gateway_mounts(
    mounts: &[MountSiteConfig],
    upstreams: Option<&[UpstreamConfig]>,
) -> Result<()> {
    let upstream_ids = upstreams.map(|items| {
        items
            .iter()
            .map(|upstream| upstream.id.as_str())
            .collect::<HashSet<_>>()
    });
    let mut normalized_paths: Vec<(String, usize)> = Vec::new();
    let mut mount_ids = HashSet::new();

    for (index, mount) in mounts.iter().enumerate() {
        let field = format!("gateway.mounts[{index}]");
        validate_non_empty_id(&format!("{field}.id"), &mount.id)?;
        if !mount_ids.insert(mount.id.clone()) {
            bail!("{field}.id `{}` is duplicated", mount.id);
        }

        let mount_path = validate_mount_path(&format!("{field}.mount_path"), &mount.mount_path)?;
        for (existing_path, existing_index) in &normalized_paths {
            if paths_overlap(existing_path, &mount_path) {
                bail!(
                    "{field}.mount_path `{}` overlaps gateway.mounts[{}].mount_path `{}`",
                    mount.mount_path,
                    existing_index,
                    existing_path
                );
            }
        }
        normalized_paths.push((mount_path, index));

        validate_target_base_url(&format!("{field}.target_base_url"), &mount.target_base_url)?;
        if let Some(upstream_id) = mount
            .upstream_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
        {
            if let Some(upstream_ids) = &upstream_ids {
                if !upstream_ids.contains(upstream_id) {
                    bail!("{field}.upstream_id `{upstream_id}` does not exist in upstreams");
                }
            }
        }
    }

    Ok(())
}

fn validate_mount_path(field: &str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{field} must not be empty");
    }
    if trimmed.contains("://") || trimmed.contains('?') || trimmed.contains('#') {
        bail!("{field} must be a local path such as /site/");
    }
    if !trimmed.starts_with('/') {
        bail!("{field} must start with `/`, got `{value}`");
    }
    if trimmed == "/" {
        bail!("{field} must not be `/`");
    }

    let mut normalized = trimmed.trim_end_matches('/').to_string();
    normalized.push('/');
    Ok(normalized)
}

fn paths_overlap(left: &str, right: &str) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn validate_target_base_url(field: &str, value: &str) -> Result<()> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("{field} must not be empty");
    }
    let uri = trimmed
        .parse::<Uri>()
        .with_context(|| format!("{field} must be a valid URL, got `{value}`"))?;
    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        _ => bail!("{field} must start with http:// or https://"),
    }
    if uri.host().is_none() {
        bail!("{field} is missing host");
    }
    Ok(())
}

fn validate_upstream_address(field: &str, value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{field} must not be empty");
    }
    let uri = trimmed
        .parse::<Uri>()
        .with_context(|| format!("{field} must be a valid upstream URL, got `{value}`"))?;
    if uri.scheme_str() != Some("http") {
        bail!("{field} only supports http:// upstream proxies in this version");
    }
    if uri.host().is_none() {
        bail!("{field} is missing host");
    }
    Ok(())
}

fn validate_host_pattern(field: &str, value: &str) -> Result<()> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        bail!("{field} must not be empty");
    }
    Glob::new(&normalized)
        .with_context(|| format!("{field} contains invalid glob pattern `{value}`"))?;
    Ok(())
}

fn validate_non_empty_id(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(())
}

fn required_option<'a>(field: &str, value: Option<&'a str>) -> Result<&'a str> {
    let value = value.map(str::trim).filter(|item| !item.is_empty());
    value.ok_or_else(|| anyhow::anyhow!("{field} is required"))
}

fn default_proxy_listen() -> String {
    "127.0.0.1:8787".to_string()
}

fn default_locale() -> String {
    "en-US".to_string()
}

fn is_default_locale(value: &str) -> bool {
    value == "en-US"
}

const fn is_default_adblock_mode_setting(value: &AdblockModeSetting) -> bool {
    matches!(value, AdblockModeSetting::Aggressive)
}

const fn is_false(value: &bool) -> bool {
    !*value
}

const fn default_upstream_protocol_preference() -> UpstreamProtocolPreferenceConfig {
    UpstreamProtocolPreferenceConfig::GuardedH3
}

const fn default_downstream_protocol_preference() -> DownstreamProtocolPreferenceConfig {
    DownstreamProtocolPreferenceConfig::Http2Enabled
}

const fn is_default_upstream_protocol_preference(value: &UpstreamProtocolPreferenceConfig) -> bool {
    matches!(value, UpstreamProtocolPreferenceConfig::GuardedH3)
}

const fn is_default_downstream_protocol_preference(
    value: &DownstreamProtocolPreferenceConfig,
) -> bool {
    matches!(value, DownstreamProtocolPreferenceConfig::Http2Enabled)
}

fn is_default_h3_streaming_response_mode(value: &Http3StreamingResponseModeConfig) -> bool {
    *value == Http3StreamingResponseModeConfig::default()
}

fn default_app_name() -> String {
    "RelayGate".to_string()
}

fn default_web_listen() -> String {
    "127.0.0.1:8788".to_string()
}

fn default_allowed_clients() -> Vec<String> {
    vec!["127.0.0.1".to_string(), "::1".to_string()]
}

fn default_connect_allowed_ports() -> Vec<u16> {
    Vec::new()
}

fn default_connect_blocked_ports() -> Vec<u16> {
    vec![25, 110, 143, 445, 3389]
}

const fn default_max_header_bytes() -> usize {
    65_536
}

const fn default_max_request_body_bytes() -> usize {
    1_073_741_824
}

const fn default_max_chunked_body_bytes() -> usize {
    1_073_741_824
}

const fn default_max_response_buffer_bytes() -> usize {
    16_777_216
}

const fn default_true() -> bool {
    true
}

const fn default_mitm_max_requests_per_connection() -> usize {
    100
}

fn default_mitm_passthrough_hosts() -> Vec<String> {
    Vec::new()
}

fn default_dns_profile_id() -> String {
    "system".to_string()
}

const fn default_dns_timeout_ms() -> u64 {
    2000
}

const fn default_dns_attempts() -> usize {
    2
}

const fn default_dns_cache_ttl_min_secs() -> u64 {
    300
}

const fn default_dns_cache_ttl_max_secs() -> u64 {
    86400
}

const fn default_dns_negative_ttl_secs() -> u64 {
    30
}

const fn default_dns_max_cache_entries() -> usize {
    10_000
}

const fn default_dns_refresh_before_expire_secs() -> u64 {
    60
}

const fn default_dns_stale_fallback_secs() -> u64 {
    86400
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_preferences_apply_to_internal_proxy_defaults() {
        let mut config = RelayGateConfig {
            upstream_protocol: UpstreamProtocolPreferenceConfig::GuardedH3,
            downstream_protocol: DownstreamProtocolPreferenceConfig::Http2Enabled,
            ..RelayGateConfig::default()
        };

        config.apply_fixed_product_defaults();

        assert_eq!(
            config.proxy.upstream.protocol_policy,
            UpstreamProtocolPolicyConfig::Auto
        );
        assert!(config.proxy.upstream.http3_buffered_response_enabled);
        assert!(!config.proxy.upstream.http3_probe_enabled);
        assert!(config.proxy.upstream.http3_streaming_response_enabled);
        assert_eq!(
            config.proxy.upstream.http3_streaming_response_mode,
            Http3StreamingResponseModeConfig::FastPathProbe
        );
        assert!(config.proxy.mitm.downstream_http2);
    }

    #[test]
    fn default_protocol_preferences_use_h3_upstream_and_h2_downstream() {
        let mut config = RelayGateConfig::default();

        config.apply_fixed_product_defaults();

        assert_eq!(
            config.proxy.upstream.protocol_policy,
            UpstreamProtocolPolicyConfig::Auto
        );
        assert!(config.proxy.upstream.http3_buffered_response_enabled);
        assert!(config.proxy.mitm.downstream_http2);
    }

    #[test]
    fn http2_preferred_uses_safe_alpn_auto_policy() {
        let mut config = RelayGateConfig {
            upstream_protocol: UpstreamProtocolPreferenceConfig::Http2Preferred,
            ..RelayGateConfig::default()
        };

        config.apply_fixed_product_defaults();

        assert_eq!(
            config.proxy.upstream.protocol_policy,
            UpstreamProtocolPolicyConfig::Auto
        );
        assert!(!config.proxy.upstream.http3_buffered_response_enabled);
    }

    #[test]
    fn adblock_preference_update_to_aggressive_survives_defaults() {
        let mut config = RelayGateConfig::default();

        config.set_adblock_mode_preference(AdblockModeSetting::Standard);
        config.apply_fixed_product_defaults();
        assert_eq!(config.adblock_mode, AdblockModeSetting::Standard);
        assert_eq!(
            config.proxy.adblock.effective_mode(),
            Some(AdblockMode::Standard)
        );

        config.set_adblock_mode_preference(AdblockModeSetting::Aggressive);
        config.apply_fixed_product_defaults();
        assert_eq!(config.adblock_mode, AdblockModeSetting::Aggressive);
        assert_eq!(
            config.proxy.adblock.effective_mode(),
            Some(AdblockMode::Aggressive)
        );
    }

    #[test]
    fn legacy_nested_adblock_mode_is_still_migrated_when_top_level_is_absent() {
        let mut config: RelayGateConfig = serde_yaml::from_str(
            r#"listen: 127.0.0.1:8787
proxy:
  adblock:
    enabled: true
    mode: standard
"#,
        )
        .expect("legacy nested adblock YAML should deserialize");

        config.apply_fixed_product_defaults();

        assert_eq!(config.adblock_mode, AdblockModeSetting::Standard);
        assert_eq!(
            config.proxy.adblock.effective_mode(),
            Some(AdblockMode::Standard)
        );
    }

    #[test]
    fn missing_protocol_fields_deserialize_to_product_defaults() {
        let mut config: RelayGateConfig = serde_yaml::from_str("listen: 127.0.0.1:8787\n")
            .expect("minimal RelayGate YAML should deserialize");

        config.apply_fixed_product_defaults();

        assert_eq!(
            config.upstream_protocol,
            UpstreamProtocolPreferenceConfig::GuardedH3
        );
        assert_eq!(
            config.downstream_protocol,
            DownstreamProtocolPreferenceConfig::Http2Enabled
        );
        assert!(config.proxy.upstream.http3_buffered_response_enabled);
        assert!(config.proxy.mitm.downstream_http2);
    }
}
