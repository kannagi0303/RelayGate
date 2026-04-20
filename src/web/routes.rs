use std::{convert::Infallible, path::PathBuf, process::Command};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

use crate::{
    adblock,
    config::{AdblockMode, RelayGateConfig},
    lang,
    proxy::mitm,
    rewrite,
    traffic::{HostTrafficHostSnapshot, TrafficRuntimeSnapshot},
    web::{server::WebAppState, view},
};
use async_stream::stream;
use axum::{
    extract::{Form, State},
    http::header,
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse,
    },
    Json,
};
use serde::{Deserialize, Serialize};
const APP_ICON_BYTES: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/relaygate.ico"));
const BACKEND_ACTIONS_JS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/relaygate-actions.js"
));

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub async fn favicon() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/x-icon")],
        APP_ICON_BYTES.to_vec(),
    )
}

pub async fn backend_actions_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        BACKEND_ACTIONS_JS,
    )
}

pub async fn index(State(state): State<WebAppState>) -> Html<String> {
    let config = current_config(&state);
    let mitm = build_mitm_status(&config);
    let status_panel = view::render_status_panel();
    let settings_panel = view::render_settings_panel(&config, &mitm);
    let traffic_panel = view::render_traffic_panel();
    let patch_panel = view::render_patch_panel();
    let render_panel = view::render_render_panel();
    let adblock_panel = view::render_adblock_panel(&config);
    Html(view::render_index(
        &config.app.name,
        state.runtime.session_id(),
        &status_panel,
        &settings_panel,
        &traffic_panel,
        &patch_panel,
        &render_panel,
        &adblock_panel,
    ))
}

fn success_feedback(message: impl Into<String>) -> Json<ActionFeedbackPayload> {
    Json(ActionFeedbackPayload {
        ok: true,
        level: "success",
        message: message.into(),
    })
}

fn error_feedback(message: impl Into<String>) -> Json<ActionFeedbackPayload> {
    Json(ActionFeedbackPayload {
        ok: false,
        level: "error",
        message: message.into(),
    })
}

pub async fn backend_events(
    State(state): State<WebAppState>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let stream = stream! {
        let mut changes = state.runtime.subscribe_backend_changes();
        let config = current_config(&state);
        let payload = build_backend_event_payload(
            &state,
            &config,
            vec![
                "status".to_string(),
                "settings".to_string(),
                "traffic".to_string(),
                "patch".to_string(),
                "render".to_string(),
                "adblock".to_string(),
            ],
        );
        yield Ok(json_backend_event(&payload));

        loop {
            let changed = changes.changed().await;
            if changed.is_err() {
                break;
            }
            let signal = changes.borrow().clone();
            let config = current_config(&state);
            let payload = build_backend_event_payload(&state, &config, signal.changed);
            yield Ok(json_backend_event(&payload));
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn reload_rules(State(state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    match rewrite::reload_shared_registry(&state.rewrite_registry) {
        Ok(rule_count) => {
            let config = current_config(&state);
            let adblock_rule_count =
                match adblock::reload_shared_state(&state.adblock_state, &config) {
                    Ok(count) => count,
                    Err(error) => {
                        return error_feedback(lang::format(
                            "backend.reload.adblock_fail",
                            &[("error", error.to_string())],
                        ));
                    }
                };
            state.runtime.notify_status_changed();
            state.runtime.notify_settings_changed();
            state.runtime.notify_patch_changed();
            state.runtime.notify_render_changed();
            state.runtime.notify_adblock_changed();
            success_feedback(lang::format(
                "backend.reload.rules_ok",
                &[
                    ("rule_count", rule_count.to_string()),
                    ("adblock_rule_count", adblock_rule_count.to_string()),
                    (
                        "adblock_resource_count",
                        adblock::resource_count(&state.adblock_state).to_string(),
                    ),
                ],
            ))
        }
        Err(error) => error_feedback(lang::format(
            "backend.reload.rules_fail",
            &[("error", error.to_string())],
        )),
    }
}

pub async fn reload_config(State(state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    match RelayGateConfig::load_from_path(state.config_path.as_ref()) {
        Ok(config) => {
            if let Err(error) = adblock::reload_shared_state(&state.adblock_state, &config) {
                return error_feedback(lang::format(
                    "backend.config.adblock_fail",
                    &[("error", error.to_string())],
                ));
            }
            store_current_config(&state, config);
            state.runtime.notify_status_changed();
            state.runtime.notify_settings_changed();
            state.runtime.notify_traffic_changed();
            state.runtime.notify_patch_changed();
            state.runtime.notify_render_changed();
            state.runtime.notify_adblock_changed();
            success_feedback(lang::text("backend.config.ok"))
        }
        Err(error) => error_feedback(lang::format(
            "backend.config.fail",
            &[("error", error.to_string())],
        )),
    }
}

pub async fn update_adblock_lists(State(state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    match adblock::sync_default_resources().await {
        Ok(files) => {
            let config = current_config(&state);
            let count = match adblock::reload_shared_state(&state.adblock_state, &config) {
                Ok(count) => count,
                Err(error) => {
                    return error_feedback(lang::format(
                        "backend.sync.reload_fail",
                        &[("error", error.to_string())],
                    ));
                }
            };
            state.runtime.notify_status_changed();
            state.runtime.notify_patch_changed();
            state.runtime.notify_render_changed();
            state.runtime.notify_adblock_changed();
            success_feedback(lang::format(
                "backend.sync.ok",
                &[
                    ("files", files.join("、")),
                    ("rule_count", count.to_string()),
                    (
                        "resource_count",
                        adblock::resource_count(&state.adblock_state).to_string(),
                    ),
                ],
            ))
        }
        Err(error) => error_feedback(lang::format(
            "backend.sync.fail",
            &[("error", error.to_string())],
        )),
    }
}

pub async fn create_ca(State(_state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    match mitm::create_and_trust_local_ca() {
        Ok(()) => {
            _state.runtime.notify_settings_changed();
            _state.runtime.notify_status_changed();
            let config = current_config(&_state);
            let mitm = build_mitm_status(&config);
            if mitm.windows_user_root_trusted == Some(true) {
                success_feedback(lang::text("backend.ca.ok"))
            } else {
                success_feedback(lang::text("backend.ca.unverified"))
            }
        }
        Err(error) => error_feedback(lang::format(
            "backend.ca.fail",
            &[("error", error.to_string())],
        )),
    }
}

pub async fn remove_ca_trust(State(_state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    match remove_ca_windows_trust_only() {
        Ok(message) => {
            _state.runtime.notify_settings_changed();
            _state.runtime.notify_status_changed();
            success_feedback(message)
        }
        Err(error) => error_feedback(lang::format(
            "backend.ca.remove_fail",
            &[("error", error.to_string())],
        )),
    }
}

pub async fn exit_app(State(state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    state.runtime.request_shutdown();
    success_feedback(lang::text("backend.exit.ok"))
}

pub async fn update_setting(
    State(state): State<WebAppState>,
    Form(form): Form<UpdateSettingForm>,
) -> Json<ActionFeedbackPayload> {
    match update_single_setting(&state, &form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(lang::format(
            "backend.save.fail",
            &[("error", error.to_string())],
        )),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateSettingForm {
    key: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct StatusPayload {
    proxy_listen: String,
    web_listen: String,
    rule_count: usize,
    rewrite_rule_count: usize,
    adblock_rule_count: usize,
    adblock_resource_count: usize,
    adblock_mode_label: String,
    mitm_mode: String,
    upstream_count: usize,
    adblock_mode: String,
    upstreams: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AdblockFilePayload {
    name: String,
    size: u64,
}

#[derive(Debug, Serialize)]
struct AdblockPayload {
    mode_value: String,
    mode_label: String,
    rule_count: usize,
    resource_count: usize,
    files: Vec<AdblockFilePayload>,
    resource_files: Vec<AdblockFilePayload>,
}

#[derive(Debug, Serialize)]
struct SettingsPayload {
    app_name: String,
    proxy_listen: String,
    web_listen: String,
    tray_enabled: bool,
    mitm: MitmStatusPayload,
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
}

#[derive(Debug, Serialize)]
pub struct ActionFeedbackPayload {
    ok: bool,
    level: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct MitmStatusPayload {
    pub(crate) enabled: bool,
    pub(crate) ca_cert_path: String,
    pub(crate) ca_key_path: String,
    pub(crate) ca_cert_exists: bool,
    pub(crate) ca_key_exists: bool,
    pub(crate) windows_user_root_trusted: Option<bool>,
}

fn build_status_payload(state: &WebAppState, config: &RelayGateConfig) -> StatusPayload {
    let rewrite_rule_count = state
        .rewrite_registry
        .read()
        .map(|registry| registry.rule_count())
        .unwrap_or(0);
    let adblock_mode = config.proxy.adblock.effective_mode();
    let adblock_mode_label = display_adblock_mode(adblock_mode);
    let upstreams = config
        .upstreams
        .iter()
        .filter(|item| item.enabled)
        .map(|item| format!("{} → {}", item.id, item.address))
        .collect::<Vec<_>>();

    StatusPayload {
        proxy_listen: config.proxy.listen.clone(),
        web_listen: config.web.listen.clone(),
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
        adblock_mode: adblock_mode_label,
        upstreams,
    }
}

fn build_adblock_payload(state: &WebAppState, config: &RelayGateConfig) -> AdblockPayload {
    let files = adblock::list_rule_files()
        .unwrap_or_default()
        .into_iter()
        .map(|file| AdblockFilePayload {
            name: file.name,
            size: file.size,
        })
        .collect();
    let resource_files = adblock::list_resource_files()
        .unwrap_or_default()
        .into_iter()
        .map(|file| AdblockFilePayload {
            name: file.name,
            size: file.size,
        })
        .collect();

    AdblockPayload {
        mode_value: adblock_mode_value(config.proxy.adblock.effective_mode()).to_string(),
        mode_label: display_adblock_mode(config.proxy.adblock.effective_mode()).to_string(),
        rule_count: adblock::rule_count(&state.adblock_state),
        resource_count: adblock::resource_count(&state.adblock_state),
        files,
        resource_files,
    }
}

fn build_settings_payload(config: &RelayGateConfig) -> SettingsPayload {
    SettingsPayload {
        app_name: config.app.name.clone(),
        proxy_listen: config.proxy.listen.clone(),
        web_listen: config.web.listen.clone(),
        tray_enabled: config.tray.enabled,
        mitm: build_mitm_status(config),
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
    BackendEventPayload {
        session_id: state.runtime.session_id().to_string(),
        changed,
        status: build_status_payload(state, config),
        settings: build_settings_payload(config),
        traffic: build_traffic_payload(state, config),
        patch: build_patch_payload(config),
        render: build_render_payload(config),
        adblock: build_adblock_payload(state, config),
    }
}

fn json_backend_event<T: Serialize>(payload: &T) -> Event {
    let data = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    Event::default().data(data)
}

fn update_single_setting(state: &WebAppState, form: &UpdateSettingForm) -> anyhow::Result<String> {
    let mut config = current_config(state);

    match form.key.as_str() {
        "app.name" => config.app.name = form.value.clone(),
        "proxy.listen" => config.proxy.listen = form.value.clone(),
        "web.listen" => config.web.listen = form.value.clone(),
        "proxy.adblock.enabled" => {
            config
                .proxy
                .adblock
                .set_effective_mode(if parse_bool(&form.value)? {
                    Some(AdblockMode::Standard)
                } else {
                    None
                })
        }
        "proxy.adblock.mode" => config
            .proxy
            .adblock
            .set_effective_mode(parse_adblock_mode_option(&form.value)?),
        "tray.enabled" => config.tray.enabled = parse_bool(&form.value)?,
        _ => anyhow::bail!("unsupported setting key: {}", form.key),
    }

    config.web.open_browser_on_launch = false;
    config.logging.log_response_body = false;

    let yaml = serde_yaml::to_string(&config)?;
    std::fs::write(&*state.config_path, yaml)?;
    let effective_mode = config.proxy.adblock.effective_mode();
    store_current_config(state, config);
    if matches!(
        form.key.as_str(),
        "proxy.adblock.enabled" | "proxy.adblock.mode"
    ) {
        adblock::set_mode(&state.adblock_state, effective_mode);
    }
    state.runtime.notify_status_changed();
    state.runtime.notify_settings_changed();
    if matches!(
        form.key.as_str(),
        "proxy.adblock.enabled" | "proxy.adblock.mode"
    ) {
        state.runtime.notify_adblock_changed();
    }

    Ok(lang::format(
        "backend.save.ok",
        &[("setting", setting_key_label(&form.key))],
    ))
}

fn parse_bool(value: &str) -> anyhow::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("invalid bool value: {value}"),
    }
}

fn parse_adblock_mode_option(value: &str) -> anyhow::Result<Option<AdblockMode>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "disabled" => Ok(None),
        "standard" => Ok(Some(AdblockMode::Standard)),
        "aggressive" => Ok(Some(AdblockMode::Aggressive)),
        _ => anyhow::bail!("invalid adblock mode: {value}"),
    }
}

fn current_config(state: &WebAppState) -> RelayGateConfig {
    state
        .config
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_else(|_| RelayGateConfig::default())
}

fn store_current_config(state: &WebAppState, config: RelayGateConfig) {
    if let Ok(mut guard) = state.config.write() {
        *guard = config;
    }
}

fn build_mitm_status(config: &RelayGateConfig) -> MitmStatusPayload {
    let storage_dir = mitm_storage_dir();
    let cert_path = storage_dir.join("relaygate-ca-cert.pem");
    let key_path = storage_dir.join("relaygate-ca-key.pem");

    MitmStatusPayload {
        enabled: config.proxy.mitm.enabled,
        ca_cert_path: cert_path.display().to_string(),
        ca_key_path: key_path.display().to_string(),
        ca_cert_exists: cert_path.exists(),
        ca_key_exists: key_path.exists(),
        windows_user_root_trusted: windows_user_root_trusted(&cert_path),
    }
}

fn mitm_storage_dir() -> PathBuf {
    mitm::mitm_storage_dir().unwrap_or_else(|_| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("data")
            .join("mitm")
    })
}

fn windows_user_root_trusted(cert_path: &PathBuf) -> Option<bool> {
    #[cfg(windows)]
    {
        return Some(
            windows_root_store_locations(cert_path)
                .map(|stores| !stores.is_empty())
                .unwrap_or(false),
        );
    }

    #[cfg(not(windows))]
    {
        let _ = cert_path;
        None
    }
}

#[cfg(windows)]
fn windows_root_store_locations(cert_path: &PathBuf) -> Option<Vec<String>> {
    if !cert_path.exists() {
        return Some(Vec::new());
    }

    let escaped_path = cert_path.display().to_string().replace('\'', "''");
    let script = format!(
        r#"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{escaped_path}')
$thumb = $cert.Thumbprint
if ([string]::IsNullOrWhiteSpace($thumb)) {{
  Write-Output ''
  exit 0
}}

$hits = New-Object System.Collections.Generic.List[string]
$stores = @(
  @( [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser, 'CurrentUser\\Root' ),
  @( [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine, 'LocalMachine\\Root' )
)

foreach ($entry in $stores) {{
  $location = $entry[0]
  $label = $entry[1]
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    $location
  )
  try {{
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $matches = @($store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumb }})
    if ($matches.Count -gt 0) {{
      $hits.Add($label)
    }}
  }} finally {{
    $store.Close()
  }}
}}

Write-Output ($hits -join ',')"#
    );

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stores = stdout
        .trim()
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| item.trim().to_string())
        .collect::<Vec<_>>();
    Some(stores)
}

#[cfg(windows)]
fn windows_root_store_diagnostics(cert_path: &PathBuf) -> Option<Vec<String>> {
    if !cert_path.exists() {
        return Some(Vec::new());
    }

    let escaped_path = cert_path.display().to_string().replace('\'', "''");
    let script = format!(
        r#"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{escaped_path}')
$thumb = $cert.Thumbprint
if ([string]::IsNullOrWhiteSpace($thumb)) {{
  Write-Output ''
  exit 0
}}

$results = New-Object System.Collections.Generic.List[string]
$stores = @(
  @( [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser, 'CurrentUser\\Root' ),
  @( [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine, 'LocalMachine\\Root' )
)

foreach ($entry in $stores) {{
  $location = $entry[0]
  $label = $entry[1]
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    $location
  )
  try {{
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $matches = @($store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumb }})
    $results.Add($label + ':count=' + $matches.Count)
  }} finally {{
    $store.Close()
  }}
}}

Write-Output ($results -join ',')"#
    );

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let items = stdout
        .trim()
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| item.trim().to_string())
        .collect::<Vec<_>>();
    Some(items)
}

fn remove_ca_windows_trust_only() -> anyhow::Result<String> {
    let storage_dir = mitm_storage_dir();
    let cert_path = storage_dir.join("relaygate-ca-cert.pem");
    let cert_exists = cert_path.exists();

    #[cfg(windows)]
    if cert_exists {
        remove_ca_from_windows_user_root(&cert_path)?;
    }

    if !cert_exists {
        return Ok(lang::text("backend.ca.no_cert"));
    }

    #[cfg(windows)]
    if let Some(remaining) = windows_root_store_locations(&cert_path) {
        if !remaining.is_empty() {
            let diagnostics = windows_root_store_diagnostics(&cert_path)
                .filter(|items| !items.is_empty())
                .unwrap_or_else(|| vec![lang::text("backend.ca.no_diag")]);
            anyhow::bail!(
                "{}",
                lang::format(
                    "backend.ca.still.diag",
                    &[
                        ("path", remaining.join(", ")),
                        ("details", diagnostics.join(" | ")),
                    ],
                )
            );
        }
    }

    Ok(lang::text("backend.ca.kept"))
}

#[cfg(windows)]
fn remove_ca_from_windows_user_root(cert_path: &PathBuf) -> anyhow::Result<()> {
    let escaped_path = cert_path.display().to_string().replace('\'', "''");
    let thumb_script = format!(
        r#"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{escaped_path}')
$thumb = $cert.Thumbprint
if ([string]::IsNullOrWhiteSpace($thumb)) {{
  Write-Output ''
}} else {{
  Write-Output $thumb
}}"#
    );

    let thumb_output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &thumb_script])
        .output()?;

    if !thumb_output.status.success() {
        let stderr = String::from_utf8_lossy(&thumb_output.stderr);
        anyhow::bail!(
            "{}",
            lang::format("backend.ca.thumb_fail", &[("stderr", stderr.to_string())])
        );
    }

    let thumbprint = String::from_utf8_lossy(&thumb_output.stdout)
        .trim()
        .to_string();
    if thumbprint.is_empty() {
        return Ok(());
    }

    let mut failures = Vec::new();
    let mut details = Vec::new();

    match remove_thumbprint_from_store_ps("CurrentUser", &thumbprint) {
        Ok(detail) => details.push(format!("CurrentUser\\Root: {detail}")),
        Err(error) => failures.push(format!("CurrentUser\\Root: {error}")),
    }

    let remaining = windows_root_store_locations(cert_path).unwrap_or_default();
    if !remaining.is_empty() {
        let diagnostics = windows_root_store_diagnostics(cert_path)
            .filter(|items| !items.is_empty())
            .unwrap_or_else(|| vec![lang::text("backend.ca.no_diag")]);
        if failures.is_empty() {
            anyhow::bail!(
                "{}",
                lang::format(
                    "backend.ca.still.result",
                    &[
                        ("path", remaining.join(", ")),
                        ("result", details.join(" | ")),
                        ("details", diagnostics.join(" | ")),
                    ],
                )
            );
        } else {
            anyhow::bail!(
                "{}",
                lang::format(
                    "backend.ca.still.remove",
                    &[
                        ("path", remaining.join(", ")),
                        ("result", details.join(" | ")),
                        ("remove_details", failures.join(" | ")),
                        ("details", diagnostics.join(" | ")),
                    ],
                )
            );
        }
    }

    Ok(())
}

#[cfg(windows)]
fn remove_thumbprint_from_store_ps(location: &str, thumbprint: &str) -> anyhow::Result<String> {
    let (store_location_expr, store_label) = match location {
        "CurrentUser" => (
            "[System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser",
            "CurrentUser\\Root",
        ),
        "LocalMachine" => (
            "[System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine",
            "LocalMachine\\Root",
        ),
        other => anyhow::bail!("unsupported store location: {other}"),
    };

    let script = format!(
        r#"$thumb = '{thumbprint}'
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
  [System.Security.Cryptography.X509Certificates.StoreName]::Root,
  {store_location_expr}
)
try {{
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $before = @($store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumb }})
  foreach ($item in $before) {{
    $store.Remove($item)
  }}
  $after = @($store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumb }})
  Write-Output ('before=' + $before.Count + ';after=' + $after.Count)
}} finally {{
  $store.Close()
}}"#
    );

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!("stdout: {stdout}; stderr: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.contains("after=") && !stdout.ends_with("after=0") {
        anyhow::bail!(
            "{}",
            lang::format(
                "backend.ca.still.store",
                &[
                    ("store_label", store_label.to_string()),
                    ("stdout", stdout.clone()),
                ],
            )
        );
    }

    Ok(stdout)
}

fn hidden_command(program: &str) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

fn adblock_mode_value(mode: Option<AdblockMode>) -> &'static str {
    match mode {
        None => "disabled",
        Some(AdblockMode::Standard) => "standard",
        Some(AdblockMode::Aggressive) => "aggressive",
    }
}

fn display_adblock_mode(mode: Option<AdblockMode>) -> String {
    match mode {
        None => lang::text("adblock.mode.off"),
        Some(AdblockMode::Standard) => lang::text("adblock.mode.std"),
        Some(AdblockMode::Aggressive) => lang::text("adblock.mode.agg"),
    }
}

fn setting_key_label(key: &str) -> String {
    match key {
        "app.name" => lang::text("settings.app_name.label"),
        "proxy.listen" => lang::text("settings.proxy.label"),
        "web.listen" => lang::text("settings.web.label"),
        "proxy.adblock.enabled" | "proxy.adblock.mode" => lang::text("settings.adblock.label"),
        "tray.enabled" => lang::text("settings.tray.label"),
        _ => key.to_string(),
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
