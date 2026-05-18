use std::{
    collections::HashSet,
    env, fs,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use adblock::{
    cosmetic_filter_cache::ProceduralOrActionFilter,
    cosmetic_filter_cache::UrlSpecificResources,
    lists::{FilterFormat, FilterSet, ParseOptions},
    request::Request,
    resources::{PermissionMask, Resource},
    Engine,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::{
    config::{AdblockMode, RelayGateConfig},
    path_mode::{app_path_mode, AppPathMode},
};

pub type SharedAdblockState = Arc<RwLock<AdblockState>>;

pub struct AdblockState {
    mode: Option<AdblockMode>,
    rule_count: usize,
    resource_count: usize,
    engine: Engine,
}

#[derive(Debug, Clone, Default)]
pub struct AdblockMatch {
    pub request_type: String,
    pub source_url: String,
    pub fetch_site: Option<String>,
    pub third_party: bool,
    pub matched: bool,
    pub filter: Option<String>,
    pub redirect: Option<AdblockRedirectResponse>,
    pub rewritten_url: Option<String>,
    pub exception: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AdblockRedirectResponse {
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct AdblockCosmeticState {
    pub hide_selectors: Vec<String>,
    pub style_selectors: Vec<(String, String)>,
    pub generic_hide_selectors: Vec<String>,
    pub procedural_actions: Vec<String>,
    pub exceptions: HashSet<String>,
    pub injected_script: String,
    pub generichide: bool,
}

#[derive(Debug, Clone)]
struct AdblockDocumentInjectionPlan {
    cosmetic: AdblockCosmeticState,
    runtime_modules: Vec<ProceduralRuntimeModule>,
}

#[derive(Debug, Clone)]
pub struct AdblockRuleFileInfo {
    pub name: String,
    pub size: u64,
    pub source_url: Option<String>,
    pub title: Option<String>,
    pub tags: Vec<String>,
}

const BRAVE_LIST_CATALOG_URL: &str =
    "https://raw.githubusercontent.com/brave/adblock-resources/master/filter_lists/list_catalog.json";
const BRAVE_RESOURCES_URL: &str =
    "https://raw.githubusercontent.com/brave/adblock-resources/master/dist/resources.json";
const RESOURCES_FILE_NAME: &str = "resources.json";
const RULE_MANIFEST_FILE_NAME: &str = "rule_sources.json";
const SYNC_STATE_FILE_NAME: &str = "sync_state.json";
const CUSTOM_RULE_FILE_NAME: &str = "custom.txt";
const CUSTOM_RULE_FILE_HEADER: &str = "! RelayGate custom adblock rules\n! Edit this file, then use the Adblock page hot reload button.\n! Example: ||example.com/ad.js$script\n\n";
const BRAVE_COMPAT_PROFILE_VERSION: u32 = 6;
pub const DEFAULT_AUTO_UPDATE_INTERVAL_SECS: u64 = 6 * 60 * 60;

const FALLBACK_DEFAULT_RULE_LISTS: &[(&str, &str)] = &[
    ("easylist.txt", "https://easylist.to/easylist/easylist.txt"),
    (
        "easyprivacy.txt",
        "https://easylist.to/easylist/easyprivacy.txt",
    ),
    (
        "ublock-filters.txt",
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    ),
    (
        "ublock-privacy.txt",
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    ),
    (
        "ublock-unbreak.txt",
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    ),
    (
        "brave-unbreak.txt",
        "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt",
    ),
];

#[derive(Debug, Deserialize)]
struct BraveListCatalogEntry {
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    default_enabled: bool,
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    first_party_protections: bool,
    #[serde(default)]
    permission_mask: u8,
    #[serde(default)]
    platforms: Vec<String>,
    #[serde(default)]
    sources: Vec<BraveListSource>,
}

#[derive(Debug, Deserialize)]
struct BraveListSource {
    url: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    format: String,
}

#[derive(Debug, Clone)]
struct BraveSelectedListSource {
    url: String,
    title: String,
    group_title: String,
    format: FilterFormat,
    permission_mask: u8,
    hidden: bool,
    default_enabled: bool,
    first_party_protections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AdblockRuleManifest {
    #[serde(default)]
    lists: Vec<AdblockRuleManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdblockRuleManifestEntry {
    file_name: String,
    #[serde(default)]
    source_url: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    group_title: String,
    format: FilterFormat,
    #[serde(default)]
    permissions: u8,
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    default_enabled: bool,
    #[serde(default)]
    first_party_protections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AdblockSyncState {
    #[serde(default)]
    last_success_unix: u64,
    #[serde(default)]
    profile_version: u32,
}

impl AdblockState {
    pub fn load(config: &RelayGateConfig) -> Result<Self> {
        ensure_custom_rule_file()?;
        let (mut engine, rule_count) = load_rule_engine()?;
        let resources = load_resources()?;
        let resource_count = resources.len();
        if !resources.is_empty() {
            engine.use_resources(resources);
        }

        Ok(Self {
            mode: config.proxy.adblock.effective_mode(),
            rule_count,
            resource_count,
            engine,
        })
    }

    pub fn shared_default(config: &RelayGateConfig) -> Result<SharedAdblockState> {
        Ok(Arc::new(RwLock::new(Self::load(config)?)))
    }

    pub fn mode(&self) -> Option<AdblockMode> {
        self.mode
    }

    pub fn set_mode(&mut self, mode: Option<AdblockMode>) {
        self.mode = mode;
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    pub fn resource_count(&self) -> usize {
        self.resource_count
    }

    pub fn check_request(
        &self,
        url: &str,
        source_url: &str,
        request_type: &str,
        fetch_site: Option<&str>,
    ) -> Result<AdblockMatch> {
        let prepared = build_adblock_request(url, source_url, request_type, fetch_site)
            .with_context(|| format!("failed to build adblock request for `{url}`"))?;
        let Some(mode) = self.mode else {
            let outcome = AdblockMatch {
                request_type: request_type.to_string(),
                source_url: source_url.to_string(),
                fetch_site: fetch_site.map(ToOwned::to_owned),
                third_party: prepared.third_party,
                ..AdblockMatch::default()
            };
            return Ok(outcome);
        };
        if matches!(mode, AdblockMode::Standard) && !prepared.third_party {
            let outcome = AdblockMatch {
                request_type: request_type.to_string(),
                source_url: source_url.to_string(),
                fetch_site: fetch_site.map(ToOwned::to_owned),
                third_party: prepared.third_party,
                ..AdblockMatch::default()
            };
            return Ok(outcome);
        }

        let result = self.engine.check_network_request(&prepared.request);

        let outcome = AdblockMatch {
            request_type: request_type.to_string(),
            source_url: source_url.to_string(),
            fetch_site: fetch_site.map(ToOwned::to_owned),
            third_party: prepared.third_party,
            matched: result.matched,
            filter: result.filter,
            redirect: result.redirect.as_deref().and_then(parse_redirect_data_url),
            rewritten_url: result.rewritten_url,
            exception: result.exception,
        };
        Ok(outcome)
    }

    pub fn cosmetic_resources(&self, url: &str) -> AdblockCosmeticState {
        let resources = self.engine.url_cosmetic_resources(url);
        convert_cosmetic_resources(resources)
    }

    pub fn may_render_document_injection(&self, url: &str) -> bool {
        let resources = self.cosmetic_resources(url);
        has_document_injection_work(&resources)
    }

    pub fn document_cosmetic_state(&self, url: &str, html: &[u8]) -> AdblockCosmeticState {
        let resources = self.cosmetic_resources(url);
        self.document_cosmetic_state_from_resources(resources, html)
    }

    fn document_cosmetic_state_from_resources(
        &self,
        mut resources: AdblockCosmeticState,
        html: &[u8],
    ) -> AdblockCosmeticState {
        if resources.generichide {
            return resources;
        }

        let (classes, ids) = collect_html_classes_and_ids(html);
        if classes.is_empty() && ids.is_empty() {
            return resources;
        }

        let mut generic_hide_selectors =
            self.engine
                .hidden_class_id_selectors(classes, ids, &resources.exceptions);
        generic_hide_selectors.sort();
        generic_hide_selectors.dedup();
        resources.generic_hide_selectors = generic_hide_selectors;
        resources
    }

    fn analyze_document_injection(
        &self,
        url: &str,
        html: &[u8],
    ) -> Option<AdblockDocumentInjectionPlan> {
        let initial = self.cosmetic_resources(url);
        if !has_document_injection_work(&initial) {
            return None;
        }

        let cosmetic = self.document_cosmetic_state_from_resources(initial, html);
        if !has_document_injection_work(&cosmetic) {
            return None;
        }

        let runtime_modules = if cosmetic.procedural_actions.is_empty() {
            Vec::new()
        } else {
            let features = collect_procedural_runtime_features(&cosmetic.procedural_actions);
            collect_required_procedural_runtime_modules(&features)
        };

        Some(AdblockDocumentInjectionPlan {
            cosmetic,
            runtime_modules,
        })
    }
}

pub fn reload_shared_state(shared: &SharedAdblockState, config: &RelayGateConfig) -> Result<usize> {
    let reloaded = AdblockState::load(config)?;
    replace_shared_state(shared, reloaded)
}

pub async fn reload_shared_state_blocking(
    shared: &SharedAdblockState,
    config: &RelayGateConfig,
) -> Result<usize> {
    let shared = Arc::clone(shared);
    let config = config.clone();
    tokio::task::spawn_blocking(move || reload_shared_state(&shared, &config))
        .await
        .map_err(|error| anyhow::anyhow!("adblock reload task failed: {error}"))?
}

fn replace_shared_state(shared: &SharedAdblockState, reloaded: AdblockState) -> Result<usize> {
    let count = reloaded.rule_count();
    let mut guard = shared
        .write()
        .map_err(|_| anyhow::anyhow!("adblock state lock poisoned during reload"))?;
    *guard = reloaded;
    Ok(count)
}

pub fn set_mode(shared: &SharedAdblockState, mode: Option<AdblockMode>) {
    if let Ok(mut guard) = shared.write() {
        guard.set_mode(mode);
    }
}

pub fn is_enabled(shared: &SharedAdblockState) -> bool {
    shared
        .read()
        .map(|guard| guard.mode().is_some())
        .unwrap_or(false)
}

pub fn rule_count(shared: &SharedAdblockState) -> usize {
    shared.read().map(|guard| guard.rule_count()).unwrap_or(0)
}

pub fn resource_count(shared: &SharedAdblockState) -> usize {
    shared
        .read()
        .map(|guard| guard.resource_count())
        .unwrap_or(0)
}

pub fn check_url(
    shared: &SharedAdblockState,
    url: &str,
    source_url: &str,
    request_type: &str,
    fetch_site: Option<&str>,
) -> Result<AdblockMatch> {
    shared
        .read()
        .map_err(|_| anyhow::anyhow!("adblock state lock poisoned"))?
        .check_request(url, source_url, request_type, fetch_site)
}

pub fn cosmetic_resources_for_document(
    shared: &SharedAdblockState,
    url: &str,
) -> AdblockCosmeticState {
    shared
        .read()
        .map(|guard| guard.cosmetic_resources(url))
        .unwrap_or_default()
}

pub fn may_render_document_injection(shared: &SharedAdblockState, url: &str) -> bool {
    shared
        .read()
        .map(|guard| guard.may_render_document_injection(url))
        .unwrap_or(false)
}

pub fn render_document_injection(
    shared: &SharedAdblockState,
    url: &str,
    html: &[u8],
) -> Option<String> {
    let plan = shared
        .read()
        .ok()
        .and_then(|guard| guard.analyze_document_injection(url, html))?;
    let cosmetic = plan.cosmetic;
    let runtime_modules = plan.runtime_modules;

    let mut blocks = Vec::new();

    if !cosmetic.injected_script.trim().is_empty() {
        blocks.push(format!(
            r#"<script id="relaygate-adblock-script">{}</script>"#,
            escape_script_text(&cosmetic.injected_script)
        ));
    }

    if !cosmetic.hide_selectors.is_empty() {
        let css = cosmetic
            .hide_selectors
            .iter()
            .map(|selector| {
                format!("{selector}{{display:none!important;visibility:hidden!important;}}")
            })
            .collect::<Vec<_>>()
            .join("\n");
        blocks.push(format!(
            r#"<style id="relaygate-adblock-hide">{}</style>"#,
            escape_style_text(&css)
        ));
    }

    if !cosmetic.generic_hide_selectors.is_empty() {
        let css = cosmetic
            .generic_hide_selectors
            .iter()
            .map(|selector| {
                format!("{selector}{{display:none!important;visibility:hidden!important;}}")
            })
            .collect::<Vec<_>>()
            .join("\n");
        blocks.push(format!(
            r#"<style id="relaygate-adblock-generic-hide">{}</style>"#,
            escape_style_text(&css)
        ));
    }

    if !cosmetic.style_selectors.is_empty() {
        let css = cosmetic
            .style_selectors
            .iter()
            .map(|(selector, style)| format!("{selector}{{{style}}}"))
            .collect::<Vec<_>>()
            .join("\n");
        blocks.push(format!(
            r#"<style id="relaygate-adblock-style">{}</style>"#,
            escape_style_text(&css)
        ));
    }

    if !cosmetic.procedural_actions.is_empty()
        || !cosmetic.exceptions.is_empty()
        || !cosmetic.generichide
    {
        let payload = json!({
            "proceduralActions": cosmetic.procedural_actions,
            "exceptions": cosmetic.exceptions.iter().cloned().collect::<Vec<_>>(),
            "generichide": cosmetic.generichide,
        })
        .to_string();
        blocks.push(format!(
            r#"<script id="relaygate-adblock-cosmetic" type="application/json">{}</script>"#,
            escape_html_text(&payload)
        ));
        blocks.push(format!(
            r#"<script id="relaygate-adblock-procedural-runtime">{}</script>"#,
            create_procedural_runtime_script(&runtime_modules)
        ));
    }

    if blocks.is_empty() {
        None
    } else {
        Some(blocks.join("\n"))
    }
}

pub fn csp_directives_for_request(
    shared: &SharedAdblockState,
    url: &str,
    source_url: &str,
    request_type: &str,
    fetch_site: Option<&str>,
) -> Result<Option<String>> {
    let guard = shared
        .read()
        .map_err(|_| anyhow::anyhow!("adblock state lock poisoned"))?;
    if guard.mode().is_none() {
        return Ok(None);
    }

    let prepared = build_adblock_request(url, source_url, request_type, fetch_site)
        .with_context(|| format!("failed to build adblock request for CSP `{url}`"))?;
    Ok(guard.engine.get_csp_directives(&prepared.request))
}

pub fn list_rule_files() -> Result<Vec<AdblockRuleFileInfo>> {
    let custom_path = ensure_custom_rule_file()?;
    let dir = adblock_rules_dir();
    let manifest = load_rule_manifest().unwrap_or_default();
    let mut files = Vec::new();

    if dir.exists() {
        let mut base_files = fs::read_dir(&dir)
            .with_context(|| format!("failed to read adblock rule dir: {}", dir.display()))?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let path = entry.path();
                if !is_supported_rule_file(&path) {
                    return None;
                }

                let metadata = entry.metadata().ok()?;
                let name = path.file_name()?.to_string_lossy().to_string();
                let manifest_entry = manifest.lists.iter().find(|item| item.file_name == name);
                let mut tags = Vec::new();
                if manifest_entry.map(|item| item.hidden).unwrap_or(false) {
                    tags.push("brave-hidden".to_string());
                }
                if manifest_entry
                    .map(|item| item.first_party_protections)
                    .unwrap_or(false)
                {
                    tags.push("first-party".to_string());
                }
                if manifest_entry
                    .map(|item| item.default_enabled)
                    .unwrap_or(false)
                {
                    tags.push("default".to_string());
                }
                if manifest_entry
                    .map(|item| item.permissions != 0)
                    .unwrap_or(false)
                {
                    tags.push("limited-permissions".to_string());
                }

                Some(AdblockRuleFileInfo {
                    name,
                    size: metadata.len(),
                    source_url: manifest_entry
                        .map(|item| item.source_url.clone())
                        .filter(|item| !item.trim().is_empty()),
                    title: manifest_entry
                        .map(|item| display_rule_title(item))
                        .filter(|item| !item.trim().is_empty()),
                    tags,
                })
            })
            .collect::<Vec<_>>();
        files.append(&mut base_files);
    }

    if custom_path.exists() && is_supported_rule_file(&custom_path) {
        let metadata = fs::metadata(&custom_path).with_context(|| {
            format!(
                "failed to stat adblock custom rule file: {}",
                custom_path.display()
            )
        })?;
        files.push(AdblockRuleFileInfo {
            name: CUSTOM_RULE_FILE_NAME.to_string(),
            size: metadata.len(),
            source_url: None,
            title: Some("Custom rules".to_string()),
            tags: vec!["custom".to_string(), "user".to_string()],
        });
    }

    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(files)
}

pub fn list_resource_files() -> Result<Vec<AdblockRuleFileInfo>> {
    let path = adblock_resources_file();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let metadata = fs::metadata(&path)
        .with_context(|| format!("failed to stat adblock resources file: {}", path.display()))?;

    Ok(vec![AdblockRuleFileInfo {
        name: path
            .file_name()
            .map(|item| item.to_string_lossy().to_string())
            .unwrap_or_else(|| RESOURCES_FILE_NAME.to_string()),
        size: metadata.len(),
        source_url: Some(BRAVE_RESOURCES_URL.to_string()),
        title: Some("Brave resources / scriptlets".to_string()),
        tags: vec!["resources".to_string()],
    }])
}

pub fn adblock_rule_dir_path() -> PathBuf {
    adblock_rules_dir()
}

pub fn adblock_custom_rule_dir_path() -> PathBuf {
    adblock_user_dir()
}

pub fn custom_rule_file_path() -> Result<PathBuf> {
    ensure_custom_rule_file()
}

pub async fn sync_default_resources() -> Result<Vec<String>> {
    sync_default_resources_if_due(DEFAULT_AUTO_UPDATE_INTERVAL_SECS).await
}

pub async fn sync_default_resources_forced() -> Result<Vec<String>> {
    reset_generated_rule_files_async().await?;
    sync_default_resources_if_due(0).await
}

pub async fn sync_default_resources_if_due(interval_secs: u64) -> Result<Vec<String>> {
    if !adblock_sync_due(interval_secs) && default_resources_present() {
        tracing::debug!(
            interval_secs,
            "adblock default list sync skipped; persisted sync interval has not elapsed"
        );
        return Ok(Vec::new());
    }

    let dir = adblock_rules_dir();
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed to create adblock rule dir: {}", dir.display()))?;

    let client = reqwest::Client::builder()
        .user_agent("RelayGate/1.0")
        .build()
        .context("failed to build HTTP client for adblock download")?;

    let mut written = download_brave_default_lists(&client, &dir).await?;
    let mut manifest = load_rule_manifest().unwrap_or_default();
    let mut supplemented = download_fallback_rule_lists(&client, &dir, &mut manifest).await?;
    written.append(&mut supplemented);

    let resources_path = adblock_resources_file();
    if let Some(parent) = resources_path.parent() {
        tokio::fs::create_dir_all(parent).await.with_context(|| {
            format!(
                "failed to create adblock resources directory: {}",
                parent.display()
            )
        })?;
    }

    let resources_body = client
        .get(BRAVE_RESOURCES_URL)
        .send()
        .await
        .with_context(|| format!("failed to download adblock resources: {BRAVE_RESOURCES_URL}"))?
        .error_for_status()
        .with_context(|| {
            format!("adblock resources download returned error: {BRAVE_RESOURCES_URL}")
        })?
        .text()
        .await
        .with_context(|| format!("failed to read adblock resources body: {BRAVE_RESOURCES_URL}"))?;

    tokio::fs::write(&resources_path, resources_body)
        .await
        .with_context(|| {
            format!(
                "failed to write adblock resources file: {}",
                resources_path.display()
            )
        })?;
    written.push(RESOURCES_FILE_NAME.to_string());
    save_sync_state_async(&AdblockSyncState {
        last_success_unix: unix_seconds_now(),
        profile_version: BRAVE_COMPAT_PROFILE_VERSION,
    })
    .await?;

    Ok(written)
}

pub async fn download_default_rule_lists() -> Result<Vec<String>> {
    sync_default_resources_if_due(0).await
}

pub fn classify_request_type(method: &str, headers: &[(String, String)]) -> &'static str {
    if header_value(headers, "upgrade")
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        && header_value(headers, "connection")
            .map(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(false)
    {
        return "websocket";
    }

    if let Some(dest) = header_value(headers, "sec-fetch-dest") {
        match dest.to_ascii_lowercase().as_str() {
            "document" => return "document",
            "iframe" | "frame" => return "subdocument",
            "websocket" => return "websocket",
            "script" => return "script",
            "style" => return "stylesheet",
            "image" => return "image",
            "font" => return "font",
            "object" | "embed" => return "object",
            "audio" | "video" | "track" => return "media",
            "worker" | "sharedworker" | "serviceworker" => return "script",
            _ => {}
        }
    }

    if method.eq_ignore_ascii_case("POST")
        || method.eq_ignore_ascii_case("PUT")
        || method.eq_ignore_ascii_case("PATCH")
        || method.eq_ignore_ascii_case("DELETE")
    {
        return "xmlhttprequest";
    }

    if let Some(accept) = header_value(headers, "accept") {
        let accept = accept.to_ascii_lowercase();
        if accept.contains("text/html") {
            return "document";
        }
        if accept.contains("image/") {
            return "image";
        }
        if accept.contains("text/css") {
            return "stylesheet";
        }
        if accept.contains("javascript")
            || accept.contains("application/json")
            || accept.contains("text/event-stream")
        {
            return "xmlhttprequest";
        }
        if accept.contains("font/") {
            return "font";
        }
        if accept.contains("audio/") || accept.contains("video/") {
            return "media";
        }
    }

    "other"
}

pub fn source_url_for_request(url: &str, headers: &[(String, String)]) -> String {
    header_value(headers, "referer")
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| url.to_string())
}

pub fn fetch_site_for_request(headers: &[(String, String)]) -> Option<String> {
    header_value(headers, "sec-fetch-site").map(|value| value.to_ascii_lowercase())
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn load_rule_engine() -> Result<(Engine, usize)> {
    let dir = adblock_rules_dir();
    let manifest = load_rule_manifest().unwrap_or_default();
    let mut paths = Vec::new();

    if dir.exists() {
        let mut base_paths = fs::read_dir(&dir)
            .with_context(|| format!("failed to read adblock rule dir: {}", dir.display()))?
            .filter_map(|entry| entry.ok().map(|item| item.path()))
            .filter(|path| is_supported_rule_file(path))
            .collect::<Vec<_>>();
        paths.append(&mut base_paths);
    }

    let custom_path = ensure_custom_rule_file()?;
    if custom_path.exists() && is_supported_rule_file(&custom_path) {
        paths.push(custom_path);
    }

    paths.sort();
    paths.sort_by(|left, right| {
        let left_custom = is_custom_rule_file(left);
        let right_custom = is_custom_rule_file(right);
        match (left_custom, right_custom) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => left.cmp(right),
        }
    });

    let mut filter_set = FilterSet::new(false);
    let mut rule_count = 0usize;
    for path in paths {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read adblock rule file: {}", path.display()))?;
        rule_count += content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .count();

        let parse_options = parse_options_for_rule_file(&manifest, &path, &content);
        filter_set.add_filter_list(&content, parse_options);
    }

    Ok((Engine::from_filter_set(filter_set, true), rule_count))
}

fn load_resources() -> Result<Vec<Resource>> {
    let path = adblock_resources_file();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read adblock resources file: {}", path.display()))?;
    let resources: Vec<Resource> = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse adblock resources json: {}", path.display()))?;
    Ok(resources)
}

async fn download_brave_default_lists(
    client: &reqwest::Client,
    dir: &PathBuf,
) -> Result<Vec<String>> {
    let catalog_text = client
        .get(BRAVE_LIST_CATALOG_URL)
        .send()
        .await
        .with_context(|| {
            format!("failed to download Brave list catalog: {BRAVE_LIST_CATALOG_URL}")
        })?
        .error_for_status()
        .with_context(|| format!("Brave list catalog returned error: {BRAVE_LIST_CATALOG_URL}"))?
        .text()
        .await
        .with_context(|| {
            format!("failed to read Brave list catalog body: {BRAVE_LIST_CATALOG_URL}")
        })?;

    let catalog: Vec<BraveListCatalogEntry> =
        serde_json::from_str(&catalog_text).context("failed to parse Brave list catalog json")?;

    let mut seen = HashSet::new();
    let mut sources = Vec::new();
    for entry in catalog {
        if !should_include_brave_catalog_entry(&entry) {
            continue;
        }

        for source in entry.sources {
            if !seen.insert(source.url.clone()) {
                continue;
            }
            sources.push(BraveSelectedListSource {
                title: if source.title.trim().is_empty() {
                    source
                        .url
                        .split('/')
                        .next_back()
                        .unwrap_or("Brave filter list")
                        .to_string()
                } else {
                    source.title.clone()
                },
                group_title: if entry.title.trim().is_empty() {
                    entry.uuid.clone()
                } else {
                    entry.title.clone()
                },
                format: parse_filter_format(&source.format),
                permission_mask: entry.permission_mask,
                hidden: entry.hidden,
                default_enabled: entry.default_enabled,
                first_party_protections: entry.first_party_protections,
                url: source.url,
            });
        }
    }

    let mut written = Vec::new();
    let mut manifest_entries = Vec::new();
    let previous_manifest = load_rule_manifest().unwrap_or_default();
    for (index, source) in sources.iter().enumerate() {
        let response = client
            .get(&source.url)
            .send()
            .await
            .with_context(|| format!("failed to download Brave adblock list: {}", source.url))?
            .error_for_status()
            .with_context(|| {
                format!("Brave adblock list download returned error: {}", source.url)
            })?;
        let body = response
            .text()
            .await
            .with_context(|| format!("failed to read Brave adblock list body: {}", source.url))?;
        let file_name = catalog_rule_file_name(index + 1, &source.url);
        let path = dir.join(&file_name);
        tokio::fs::write(&path, body).await.with_context(|| {
            format!(
                "failed to write Brave adblock rule file: {}",
                path.display()
            )
        })?;
        manifest_entries.push(AdblockRuleManifestEntry {
            file_name: file_name.clone(),
            source_url: source.url.clone(),
            title: source.title.clone(),
            group_title: source.group_title.clone(),
            format: source.format,
            permissions: source.permission_mask,
            hidden: source.hidden,
            default_enabled: source.default_enabled,
            first_party_protections: source.first_party_protections,
        });
        written.push(file_name);
    }

    let manifest = AdblockRuleManifest {
        lists: manifest_entries,
    };
    cleanup_replaced_manifest_rule_files(dir, &previous_manifest, &manifest)?;
    save_rule_manifest_async(&manifest).await?;

    Ok(written)
}

async fn download_fallback_rule_lists(
    client: &reqwest::Client,
    dir: &PathBuf,
    manifest: &mut AdblockRuleManifest,
) -> Result<Vec<String>> {
    let mut written = Vec::new();
    for (file_name, url) in FALLBACK_DEFAULT_RULE_LISTS {
        if manifest.lists.iter().any(|item| item.source_url == *url) {
            continue;
        }
        let response = client
            .get(*url)
            .send()
            .await
            .with_context(|| format!("failed to download adblock list: {url}"))?
            .error_for_status()
            .with_context(|| format!("adblock list download returned error: {url}"))?;
        let body = response
            .text()
            .await
            .with_context(|| format!("failed to read adblock list body: {url}"))?;
        let path = dir.join(file_name);
        tokio::fs::write(&path, body)
            .await
            .with_context(|| format!("failed to write adblock rule file: {}", path.display()))?;
        manifest.lists.push(AdblockRuleManifestEntry {
            file_name: (*file_name).to_string(),
            source_url: (*url).to_string(),
            title: (*file_name).to_string(),
            group_title: "RelayGate fallback lists".to_string(),
            format: infer_filter_format_from_name(file_name),
            permissions: 0,
            hidden: false,
            default_enabled: true,
            first_party_protections: false,
        });
        written.push((*file_name).to_string());
    }

    save_rule_manifest_async(manifest).await?;

    Ok(written)
}

fn should_include_brave_catalog_entry(entry: &BraveListCatalogEntry) -> bool {
    if !entry.default_enabled {
        return false;
    }

    entry.platforms.is_empty()
        || entry.platforms.iter().any(|platform| {
            matches!(
                platform.trim().to_ascii_uppercase().as_str(),
                "WINDOWS" | "DESKTOP"
            )
        })
}

fn cleanup_replaced_manifest_rule_files(
    dir: &PathBuf,
    previous: &AdblockRuleManifest,
    next: &AdblockRuleManifest,
) -> Result<()> {
    let keep = next
        .lists
        .iter()
        .map(|item| item.file_name.as_str())
        .collect::<HashSet<_>>();

    for item in &previous.lists {
        if keep.contains(item.file_name.as_str()) || item.file_name == CUSTOM_RULE_FILE_NAME {
            continue;
        }
        let path = dir.join(&item.file_name);
        if path.exists() && is_supported_rule_file(&path) && !is_custom_rule_file(&path) {
            fs::remove_file(&path).with_context(|| {
                format!("failed to remove replaced adblock list: {}", path.display())
            })?;
        }
    }

    Ok(())
}

fn display_rule_title(entry: &AdblockRuleManifestEntry) -> String {
    match (
        entry.group_title.trim().is_empty(),
        entry.title.trim().is_empty(),
    ) {
        (false, false) => format!("{} / {}", entry.group_title, entry.title),
        (false, true) => entry.group_title.clone(),
        (true, false) => entry.title.clone(),
        (true, true) => entry.source_url.clone(),
    }
}

fn catalog_rule_file_name(index: usize, url: &str) -> String {
    let raw_name = url
        .split('/')
        .next_back()
        .filter(|item| !item.trim().is_empty())
        .unwrap_or("list.txt");
    let sanitized = raw_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("{index:02}-{sanitized}")
}

fn parse_redirect_data_url(value: &str) -> Option<AdblockRedirectResponse> {
    let body = value.strip_prefix("data:")?;
    let (meta, payload) = body.split_once(',')?;
    let (content_type, is_base64) = if let Some(meta) = meta.strip_suffix(";base64") {
        let content_type = if meta.is_empty() {
            "application/octet-stream"
        } else {
            meta
        };
        (content_type.to_string(), true)
    } else {
        let content_type = if meta.is_empty() {
            "text/plain;charset=US-ASCII"
        } else {
            meta
        };
        (content_type.to_string(), false)
    };

    let bytes = if is_base64 {
        BASE64_STANDARD.decode(payload).ok()?
    } else {
        payload.as_bytes().to_vec()
    };

    Some(AdblockRedirectResponse {
        content_type,
        body: bytes,
    })
}

fn parse_options_for_rule_file(
    manifest: &AdblockRuleManifest,
    path: &std::path::Path,
    content: &str,
) -> ParseOptions {
    let file_name = path
        .file_name()
        .map(|item| item.to_string_lossy().to_string())
        .unwrap_or_default();
    if let Some(entry) = manifest
        .lists
        .iter()
        .find(|item| item.file_name == file_name)
    {
        return ParseOptions {
            format: entry.format,
            permissions: PermissionMask::from_bits(entry.permissions),
            ..ParseOptions::default()
        };
    }

    ParseOptions {
        format: infer_filter_format(path, content),
        ..ParseOptions::default()
    }
}

fn infer_filter_format(path: &std::path::Path, content: &str) -> FilterFormat {
    let file_name = path
        .file_name()
        .map(|item| item.to_string_lossy().to_string())
        .unwrap_or_default();
    if matches!(
        infer_filter_format_from_name(&file_name),
        FilterFormat::Hosts
    ) {
        return FilterFormat::Hosts;
    }

    if content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('!'))
        .take(8)
        .all(is_hosts_style_line)
    {
        return FilterFormat::Hosts;
    }

    FilterFormat::Standard
}

fn infer_filter_format_from_name(file_name: &str) -> FilterFormat {
    let lower = file_name.to_ascii_lowercase();
    if lower.contains("hosts") || lower.ends_with(".hosts") {
        FilterFormat::Hosts
    } else {
        FilterFormat::Standard
    }
}

fn is_hosts_style_line(line: &str) -> bool {
    if line.starts_with('#') || line.starts_with('!') || line.starts_with('[') {
        return true;
    }

    let without_comment = line.split('#').next().unwrap_or("").trim();
    if without_comment.is_empty() {
        return true;
    }

    let mut parts = without_comment.split_whitespace();
    let first = parts.next().unwrap_or("");
    let second = parts.next();
    let third = parts.next();

    match (first, second, third) {
        (host, None, None) => host.contains('.'),
        (ip, Some(host), None) => looks_like_ip(ip) && host.contains('.'),
        _ => false,
    }
}

fn looks_like_ip(value: &str) -> bool {
    value == "0.0.0.0"
        || value == "127.0.0.1"
        || value == "::1"
        || value
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() || matches!(ch, '.' | ':'))
}

fn parse_filter_format(value: &str) -> FilterFormat {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.contains("host") {
        FilterFormat::Hosts
    } else {
        FilterFormat::Standard
    }
}

async fn reset_generated_rule_files_async() -> Result<()> {
    let dir = adblock_rules_dir();
    if !dir.exists() {
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(&dir)
        .await
        .with_context(|| format!("failed to read adblock rule dir: {}", dir.display()))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .with_context(|| format!("failed to read adblock rule entry: {}", dir.display()))?
    {
        let path = entry.path();
        if is_supported_rule_file(&path) && !is_custom_rule_file(&path) {
            tokio::fs::remove_file(&path).await.with_context(|| {
                format!(
                    "failed to remove generated adblock rule file: {}",
                    path.display()
                )
            })?;
        }
    }

    let manifest_path = adblock_rule_manifest_file();
    if manifest_path.exists() {
        tokio::fs::remove_file(&manifest_path)
            .await
            .with_context(|| {
                format!(
                    "failed to remove adblock rule manifest: {}",
                    manifest_path.display()
                )
            })?;
    }

    let sync_state_path = adblock_sync_state_file();
    if sync_state_path.exists() {
        tokio::fs::remove_file(&sync_state_path)
            .await
            .with_context(|| {
                format!(
                    "failed to remove adblock sync state: {}",
                    sync_state_path.display()
                )
            })?;
    }

    Ok(())
}

fn load_rule_manifest() -> Result<AdblockRuleManifest> {
    let path = adblock_rule_manifest_file();
    if !path.exists() {
        return Ok(AdblockRuleManifest::default());
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read adblock rule manifest: {}", path.display()))?;
    let manifest = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse adblock rule manifest: {}", path.display()))?;
    Ok(manifest)
}

async fn save_rule_manifest_async(manifest: &AdblockRuleManifest) -> Result<()> {
    let path = adblock_rule_manifest_file();
    let content = serde_json::to_string_pretty(manifest)
        .context("failed to serialize adblock rule manifest")?;
    tokio::fs::write(&path, content)
        .await
        .with_context(|| format!("failed to write adblock rule manifest: {}", path.display()))
}

fn adblock_sync_due(interval_secs: u64) -> bool {
    if interval_secs == 0 {
        return true;
    }
    let Ok(state) = load_sync_state() else {
        return true;
    };
    if state.profile_version < BRAVE_COMPAT_PROFILE_VERSION {
        return true;
    }
    let now = unix_seconds_now();
    state.last_success_unix == 0 || now.saturating_sub(state.last_success_unix) >= interval_secs
}

fn default_resources_present() -> bool {
    default_rule_files_present() && adblock_resources_file().exists()
}

fn default_rule_files_present() -> bool {
    let dir = adblock_rules_dir();
    let Ok(entries) = fs::read_dir(&dir) else {
        return false;
    };

    entries
        .filter_map(|entry| entry.ok().map(|item| item.path()))
        .filter(|path| is_supported_rule_file(path))
        .any(|path| !is_custom_rule_file(&path))
}

fn load_sync_state() -> Result<AdblockSyncState> {
    let path = adblock_sync_state_file();
    if !path.exists() {
        return Ok(AdblockSyncState::default());
    }
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read adblock sync state: {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse adblock sync state: {}", path.display()))
}

async fn save_sync_state_async(state: &AdblockSyncState) -> Result<()> {
    let path = adblock_sync_state_file();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.with_context(|| {
            format!(
                "failed to create adblock sync state dir: {}",
                parent.display()
            )
        })?;
    }
    let content =
        serde_json::to_string_pretty(state).context("failed to serialize adblock sync state")?;
    tokio::fs::write(&path, content)
        .await
        .with_context(|| format!("failed to write adblock sync state: {}", path.display()))
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

struct PreparedAdblockRequest {
    request: Request,
    third_party: bool,
}

fn build_adblock_request(
    url: &str,
    source_url: &str,
    request_type: &str,
    fetch_site: Option<&str>,
) -> Result<PreparedAdblockRequest> {
    let parsed_url =
        Url::parse(url).with_context(|| format!("failed to parse adblock target URL `{url}`"))?;
    let hostname = parsed_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("adblock target URL missing host: `{url}`"))?;

    let parsed_source = Url::parse(source_url).ok();
    let source_hostname = parsed_source
        .as_ref()
        .and_then(|item| item.host_str())
        .unwrap_or("");

    let third_party = match fetch_site.map(|item| item.to_ascii_lowercase()) {
        Some(value) if value == "cross-site" => true,
        Some(value) if value == "same-origin" || value == "same-site" || value == "none" => false,
        _ if !source_hostname.is_empty() => parsed_source
            .as_ref()
            .and_then(|item| item.domain())
            .zip(parsed_url.domain())
            .map(|(source_domain, target_domain)| source_domain != target_domain)
            .unwrap_or(source_hostname != hostname),
        _ => false,
    };

    Ok(PreparedAdblockRequest {
        request: Request::preparsed(url, hostname, source_hostname, request_type, third_party),
        third_party,
    })
}

fn escape_html_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_style_text(value: &str) -> String {
    value.replace("</style", "<\\/style")
}

fn escape_script_text(value: &str) -> String {
    value
        .replace("</script", "<\\/script")
        .replace("<!--", "<\\!--")
}

fn has_document_injection_work(cosmetic: &AdblockCosmeticState) -> bool {
    !cosmetic.hide_selectors.is_empty()
        || !cosmetic.style_selectors.is_empty()
        || !cosmetic.generic_hide_selectors.is_empty()
        || !cosmetic.procedural_actions.is_empty()
        || !cosmetic.exceptions.is_empty()
        || !cosmetic.injected_script.trim().is_empty()
        || !cosmetic.generichide
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProceduralRuntimeModule {
    PatternHelpers,
    OperatorCssSelector,
    OperatorHasText,
    OperatorMinTextLength,
    OperatorMatchesAttr,
    OperatorMatchesCss,
    OperatorMatchesPath,
    OperatorUpward,
    OperatorXpath,
    ActionRemove,
    ActionStyle,
    ActionRemoveAttr,
    ActionRemoveClass,
}

fn collect_required_procedural_runtime_modules(
    features: &ProceduralRuntimeFeatures,
) -> Vec<ProceduralRuntimeModule> {
    let mut modules = Vec::new();

    if features.needs_pattern_matching {
        modules.push(ProceduralRuntimeModule::PatternHelpers);
    }
    if features.css_selector {
        modules.push(ProceduralRuntimeModule::OperatorCssSelector);
    }
    if features.has_text {
        modules.push(ProceduralRuntimeModule::OperatorHasText);
    }
    if features.min_text_length {
        modules.push(ProceduralRuntimeModule::OperatorMinTextLength);
    }
    if features.matches_attr {
        modules.push(ProceduralRuntimeModule::OperatorMatchesAttr);
    }
    if features.matches_css || features.matches_css_before || features.matches_css_after {
        modules.push(ProceduralRuntimeModule::OperatorMatchesCss);
    }
    if features.matches_path {
        modules.push(ProceduralRuntimeModule::OperatorMatchesPath);
    }
    if features.upward {
        modules.push(ProceduralRuntimeModule::OperatorUpward);
    }
    if features.xpath {
        modules.push(ProceduralRuntimeModule::OperatorXpath);
    }
    if features.remove {
        modules.push(ProceduralRuntimeModule::ActionRemove);
    }
    if features.style {
        modules.push(ProceduralRuntimeModule::ActionStyle);
    }
    if features.remove_attr {
        modules.push(ProceduralRuntimeModule::ActionRemoveAttr);
    }
    if features.remove_class {
        modules.push(ProceduralRuntimeModule::ActionRemoveClass);
    }

    modules
}

fn create_procedural_runtime_script(modules: &[ProceduralRuntimeModule]) -> String {
    let mut script = String::new();
    script.push_str(procedural_runtime_base_script());

    if modules.contains(&ProceduralRuntimeModule::PatternHelpers) {
        script.push_str(procedural_runtime_pattern_helpers());
    }

    script.push_str(procedural_runtime_apply_operator_start());

    if modules.contains(&ProceduralRuntimeModule::OperatorCssSelector) {
        script.push_str(procedural_runtime_operator_css_selector());
    }
    if modules.contains(&ProceduralRuntimeModule::OperatorHasText) {
        script.push_str(procedural_runtime_operator_has_text());
    }
    if modules.contains(&ProceduralRuntimeModule::OperatorMinTextLength) {
        script.push_str(procedural_runtime_operator_min_text_length());
    }
    if modules.contains(&ProceduralRuntimeModule::OperatorMatchesAttr) {
        script.push_str(procedural_runtime_operator_matches_attr());
    }
    if modules.contains(&ProceduralRuntimeModule::OperatorMatchesCss) {
        script.push_str(procedural_runtime_operator_matches_css());
    }
    if modules.contains(&ProceduralRuntimeModule::OperatorMatchesPath) {
        script.push_str(procedural_runtime_operator_matches_path());
    }
    if modules.contains(&ProceduralRuntimeModule::OperatorUpward) {
        script.push_str(procedural_runtime_operator_upward());
    }
    if modules.contains(&ProceduralRuntimeModule::OperatorXpath) {
        script.push_str(procedural_runtime_operator_xpath());
    }

    script.push_str(procedural_runtime_apply_action_start());

    if modules.contains(&ProceduralRuntimeModule::ActionRemove) {
        script.push_str(procedural_runtime_action_remove());
    }
    if modules.contains(&ProceduralRuntimeModule::ActionStyle) {
        script.push_str(procedural_runtime_action_style());
    }
    if modules.contains(&ProceduralRuntimeModule::ActionRemoveAttr) {
        script.push_str(procedural_runtime_action_remove_attr());
    }
    if modules.contains(&ProceduralRuntimeModule::ActionRemoveClass) {
        script.push_str(procedural_runtime_action_remove_class());
    }

    script.push_str(procedural_runtime_footer());
    script
}

fn procedural_runtime_base_script() -> &'static str {
    r#"(function () {
  if (window.__relaygateAdblockProceduralInstalled) return;
  window.__relaygateAdblockProceduralInstalled = true;

  function parseJsonPayload() {
    var el = document.getElementById('relaygate-adblock-cosmetic');
    if (!el) return null;
    try { return JSON.parse(el.textContent || '{}'); } catch (_) { return null; }
  }

  function uniqueElements(items) {
    var seen = new Set();
    var out = [];
    for (var i = 0; i < items.length; i++) {
      var item = items[i];
      if (!(item instanceof Element)) continue;
      if (seen.has(item)) continue;
      seen.add(item);
      out.push(item);
    }
    return out;
  }
"#
}

fn procedural_runtime_pattern_helpers() -> &'static str {
    r#"

  function parsePattern(value) {
    if (typeof value !== 'string') return null;
    if (value.length >= 2 && value[0] === '/' && value.lastIndexOf('/') > 0) {
      var last = value.lastIndexOf('/');
      try { return new RegExp(value.slice(1, last), value.slice(last + 1)); } catch (_) {}
    }
    return null;
  }

  function testText(value, pattern) {
    var text = value == null ? '' : String(value);
    var regex = parsePattern(pattern);
    return regex ? regex.test(text) : text.indexOf(String(pattern)) !== -1;
  }
"#
}

fn procedural_runtime_apply_operator_start() -> &'static str {
    r#"

  function applyOperator(nodes, operator) {
    if (!operator || typeof operator.type !== 'string') return nodes;
    var arg = operator.arg;
    switch (operator.type) {
"#
}

fn procedural_runtime_operator_css_selector() -> &'static str {
    r#"
      case 'css-selector': {
        if (nodes === null) {
          try { return Array.from(document.querySelectorAll(String(arg))); } catch (_) { return []; }
        }
        var next = [];
        nodes.forEach(function (node) {
          if (!(node instanceof Element)) return;
          try { next.push.apply(next, Array.from(node.querySelectorAll(String(arg)))); } catch (_) {}
        });
        return uniqueElements(next);
      }
"#
}

fn procedural_runtime_operator_has_text() -> &'static str {
    r#"
      case 'has-text':
        return nodes.filter(function (node) { return testText(node.textContent || '', arg); });
"#
}

fn procedural_runtime_operator_min_text_length() -> &'static str {
    r#"
      case 'min-text-length': {
        var min = parseInt(arg, 10);
        if (!Number.isFinite(min)) return nodes;
        return nodes.filter(function (node) { return (node.textContent || '').trim().length >= min; });
      }
"#
}

fn procedural_runtime_operator_matches_attr() -> &'static str {
    r#"
      case 'matches-attr':
        return nodes.filter(function (node) {
          return Array.from(node.attributes || []).some(function (attr) {
            return testText(attr.name + '="' + attr.value + '"', arg);
          });
        });
"#
}

fn procedural_runtime_operator_matches_css() -> &'static str {
    r#"
      case 'matches-css':
      case 'matches-css-before':
      case 'matches-css-after':
        return nodes.filter(function (node) {
          try {
            var pseudo = operator.type === 'matches-css-before' ? '::before'
              : operator.type === 'matches-css-after' ? '::after'
              : null;
            var style = window.getComputedStyle(node, pseudo);
            var text = Array.from(style).map(function (name) {
              return name + ':' + style.getPropertyValue(name);
            }).join(';');
            return testText(text, arg);
          } catch (_) { return false; }
        });
"#
}

fn procedural_runtime_operator_matches_path() -> &'static str {
    r#"
      case 'matches-path':
        return testText(location.pathname + location.search + location.hash, arg) ? nodes : [];
"#
}

fn procedural_runtime_operator_upward() -> &'static str {
    r#"
      case 'upward':
        return uniqueElements(nodes.map(function (node) {
          if (!(node instanceof Element)) return null;
          var count = parseInt(arg, 10);
          if (Number.isFinite(count)) {
            var current = node;
            for (var i = 0; i < count && current; i++) current = current.parentElement;
            return current;
          }
          try { return node.closest(String(arg)); } catch (_) { return null; }
        }).filter(Boolean));
"#
}

fn procedural_runtime_operator_xpath() -> &'static str {
    r#"
      case 'xpath': {
        var result = [];
        nodes.forEach(function (node) {
          try {
            var query = document.evaluate(String(arg), node, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
            for (var i = 0; i < query.snapshotLength; i++) {
              var item = query.snapshotItem(i);
              if (item instanceof Element) result.push(item);
            }
          } catch (_) {}
        });
        return uniqueElements(result);
      }
"#
}

fn procedural_runtime_apply_action_start() -> &'static str {
    r#"
      default:
        return nodes;
    }
  }

  function applyAction(nodes, action) {
    nodes.forEach(function (node) {
      if (!(node instanceof Element)) return;
      var type = action && action.type ? action.type : 'hide';
      var arg = action && action.arg;
      switch (type) {
"#
}

fn procedural_runtime_action_remove() -> &'static str {
    r#"
        case 'remove':
          node.remove();
          break;
"#
}

fn procedural_runtime_action_style() -> &'static str {
    r#"
        case 'style':
          node.style.cssText += ';' + String(arg || '');
          break;
"#
}

fn procedural_runtime_action_remove_attr() -> &'static str {
    r#"
        case 'remove-attr':
          node.removeAttribute(String(arg || ''));
          break;
"#
}

fn procedural_runtime_action_remove_class() -> &'static str {
    r#"
        case 'remove-class':
          node.classList.remove(String(arg || ''));
          break;
"#
}

fn procedural_runtime_footer() -> &'static str {
    r#"
        default:
          node.style.setProperty('display', 'none', 'important');
          node.style.setProperty('visibility', 'hidden', 'important');
          break;
      }
    });
  }

  function runProcedural() {
    var payload = parseJsonPayload();
    if (!payload || !Array.isArray(payload.proceduralActions)) return;
    payload.proceduralActions.forEach(function (encoded) {
      try {
        var filter = JSON.parse(encoded);
        var nodes = null;
        (filter.selector || []).forEach(function (operator) {
          nodes = applyOperator(nodes, operator);
        });
        applyAction(nodes || [], filter.action || null);
      } catch (_) {}
    });
  }

  runProcedural();
  var scheduled = false;
  var observer = new MutationObserver(function () {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(function () {
      scheduled = false;
      runProcedural();
    });
  });
  observer.observe(document.documentElement || document, {
    childList: true,
    subtree: true,
    attributes: true,
    characterData: false
  });
})();"#
}

#[derive(Default)]
struct ProceduralRuntimeFeatures {
    css_selector: bool,
    has_text: bool,
    min_text_length: bool,
    matches_attr: bool,
    matches_css: bool,
    matches_css_before: bool,
    matches_css_after: bool,
    matches_path: bool,
    upward: bool,
    xpath: bool,
    remove: bool,
    style: bool,
    remove_attr: bool,
    remove_class: bool,
    needs_pattern_matching: bool,
}

fn collect_procedural_runtime_features(procedural_actions: &[String]) -> ProceduralRuntimeFeatures {
    let mut features = ProceduralRuntimeFeatures {
        css_selector: true,
        ..ProceduralRuntimeFeatures::default()
    };

    for encoded in procedural_actions {
        let Ok(filter) = serde_json::from_str::<Value>(encoded) else {
            continue;
        };

        if let Some(operators) = filter.get("selector").and_then(Value::as_array) {
            for operator in operators {
                let Some(kind) = operator.get("type").and_then(Value::as_str) else {
                    continue;
                };
                match kind {
                    "css-selector" => features.css_selector = true,
                    "has-text" => {
                        features.has_text = true;
                        features.needs_pattern_matching = true;
                    }
                    "min-text-length" => features.min_text_length = true,
                    "matches-attr" => {
                        features.matches_attr = true;
                        features.needs_pattern_matching = true;
                    }
                    "matches-css" => {
                        features.matches_css = true;
                        features.needs_pattern_matching = true;
                    }
                    "matches-css-before" => {
                        features.matches_css_before = true;
                        features.needs_pattern_matching = true;
                    }
                    "matches-css-after" => {
                        features.matches_css_after = true;
                        features.needs_pattern_matching = true;
                    }
                    "matches-path" => {
                        features.matches_path = true;
                        features.needs_pattern_matching = true;
                    }
                    "upward" => features.upward = true,
                    "xpath" => features.xpath = true,
                    _ => {}
                }
            }
        }

        match filter
            .get("action")
            .and_then(|value| value.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("hide")
        {
            "remove" => features.remove = true,
            "style" => features.style = true,
            "remove-attr" => features.remove_attr = true,
            "remove-class" => features.remove_class = true,
            _ => {}
        }
    }

    features
}

fn convert_cosmetic_resources(resources: UrlSpecificResources) -> AdblockCosmeticState {
    let mut hide_selectors = resources.hide_selectors.into_iter().collect::<Vec<_>>();
    hide_selectors.sort();

    let mut procedural_actions = resources.procedural_actions.into_iter().collect::<Vec<_>>();
    procedural_actions.sort();

    let mut style_selectors = procedural_actions
        .iter()
        .filter_map(|item| {
            serde_json::from_str::<ProceduralOrActionFilter>(item)
                .ok()
                .and_then(|filter| filter.as_css())
        })
        .collect::<Vec<_>>();
    style_selectors.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    style_selectors.dedup();

    AdblockCosmeticState {
        hide_selectors,
        style_selectors,
        generic_hide_selectors: Vec::new(),
        procedural_actions,
        exceptions: resources.exceptions,
        injected_script: resources.injected_script,
        generichide: resources.generichide,
    }
}

fn collect_html_classes_and_ids(html: &[u8]) -> (Vec<String>, Vec<String>) {
    let document = Html::parse_document(&String::from_utf8_lossy(html));
    let selector = match Selector::parse("*") {
        Ok(selector) => selector,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let mut classes = HashSet::new();
    let mut ids = HashSet::new();

    for element in document.select(&selector) {
        if let Some(class_attr) = element.value().attr("class") {
            for class_name in class_attr
                .split_whitespace()
                .filter(|item| !item.is_empty())
            {
                classes.insert(class_name.to_string());
            }
        }

        if let Some(id_attr) = element.value().attr("id").filter(|item| !item.is_empty()) {
            ids.insert(id_attr.to_string());
        }
    }

    let mut classes = classes.into_iter().collect::<Vec<_>>();
    let mut ids = ids.into_iter().collect::<Vec<_>>();
    classes.sort();
    ids.sort();
    (classes, ids)
}

fn adblock_rules_dir() -> PathBuf {
    adblock_base_dir()
}

fn adblock_base_dir() -> PathBuf {
    preferred_base_dir()
        .join("data")
        .join("state")
        .join("adblock")
        .join("base")
}

fn adblock_user_dir() -> PathBuf {
    preferred_base_dir()
        .join("data")
        .join("user")
        .join("adblock")
}

fn ensure_custom_rule_file() -> Result<PathBuf> {
    let path = adblock_user_dir().join(CUSTOM_RULE_FILE_NAME);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create adblock custom rule directory: {}",
                parent.display()
            )
        })?;
    }

    if !path.exists() {
        fs::write(&path, CUSTOM_RULE_FILE_HEADER).with_context(|| {
            format!(
                "failed to create adblock custom rule file: {}",
                path.display()
            )
        })?;
    }

    Ok(path)
}

fn is_custom_rule_file(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.eq_ignore_ascii_case(CUSTOM_RULE_FILE_NAME))
        .unwrap_or(false)
}

fn is_supported_rule_file(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "txt" | "list" | "filters" | "filter"
            )
        })
        .unwrap_or(false)
}

fn adblock_resources_file() -> PathBuf {
    adblock_rules_dir().join(RESOURCES_FILE_NAME)
}

fn adblock_rule_manifest_file() -> PathBuf {
    adblock_rules_dir().join(RULE_MANIFEST_FILE_NAME)
}

fn adblock_sync_state_file() -> PathBuf {
    adblock_rules_dir().join(SYNC_STATE_FILE_NAME)
}

fn preferred_base_dir() -> PathBuf {
    match app_path_mode() {
        AppPathMode::Workspace => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        AppPathMode::Portable => executable_base_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

fn executable_base_dir() -> Result<PathBuf> {
    let exe = env::current_exe().context("failed to resolve current executable path")?;
    let parent = exe.parent().ok_or_else(|| {
        anyhow::anyhow!("current executable path does not have a parent directory")
    })?;
    Ok(parent.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::classify_request_type;

    #[test]
    fn classify_websocket_from_fetch_dest() {
        let headers = vec![("Sec-Fetch-Dest".to_string(), "websocket".to_string())];

        assert_eq!(classify_request_type("GET", &headers), "websocket");
    }

    #[test]
    fn classify_websocket_from_h1_upgrade_headers() {
        let headers = vec![
            ("Connection".to_string(), "keep-alive, Upgrade".to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
        ];

        assert_eq!(classify_request_type("GET", &headers), "websocket");
    }
}
