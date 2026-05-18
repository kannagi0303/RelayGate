mod matching;
mod metadata;
mod model;
mod paths;
mod registry;
mod store;
mod watcher;
mod wrapper;

use std::sync::{Arc, RwLock};

use anyhow::Result;

use crate::runtime::AppRuntime;

pub use model::{UserScriptListItem, UserScriptMetadata, UserScriptStatus};
pub use paths::script_dir;
use registry::UserScriptRegistry;

pub type SharedUserScriptRegistry = Arc<RwLock<UserScriptRegistry>>;

pub fn shared_default() -> Result<SharedUserScriptRegistry> {
    Ok(Arc::new(RwLock::new(UserScriptRegistry::load_default()?)))
}

pub(crate) fn start_auto_reload_watcher(
    registry: SharedUserScriptRegistry,
    runtime: AppRuntime,
) -> Result<watcher::UserScriptWatcher> {
    watcher::start_auto_reload_watcher(registry, runtime)
}

pub fn reload_shared_registry(registry: &SharedUserScriptRegistry) -> Result<usize> {
    let next = UserScriptRegistry::load_default()?;
    let count = next.entry_count();
    *registry
        .write()
        .map_err(|_| anyhow::anyhow!("user script registry lock poisoned"))? = next;
    Ok(count)
}

pub fn set_enabled_default(
    registry: &SharedUserScriptRegistry,
    filename: &str,
    enabled: bool,
) -> Result<usize> {
    registry::set_enabled_default(registry, filename, enabled)
}

pub fn list_items(registry: &SharedUserScriptRegistry) -> Vec<UserScriptListItem> {
    registry
        .read()
        .map(|guard| guard.list_items())
        .unwrap_or_default()
}

pub async fn render_document_injection(
    registry: &SharedUserScriptRegistry,
    target_url: &str,
    is_frame: Option<bool>,
) -> Option<String> {
    let entries = registry
        .read()
        .ok()
        .map(|guard| guard.matching_entries(target_url, is_frame))
        .unwrap_or_default();
    registry::render_matching_entries(entries).await
}

pub fn has_enabled_scripts(registry: &SharedUserScriptRegistry) -> bool {
    registry
        .read()
        .map(|guard| guard.has_enabled_scripts())
        .unwrap_or(false)
}

pub fn has_enabled_script_match(
    registry: &SharedUserScriptRegistry,
    target_url: &str,
    is_frame: Option<bool>,
) -> bool {
    registry
        .read()
        .map(|guard| guard.has_enabled_script_match(target_url, is_frame))
        .unwrap_or(false)
}
