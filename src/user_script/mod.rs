mod matching;
mod metadata;
mod model;
mod paths;
mod registry;
mod wrapper;

use std::sync::{Arc, RwLock};

use anyhow::Result;

pub use model::{UserScriptListItem, UserScriptMetadata, UserScriptStatus};
pub use paths::script_dir;
use registry::UserScriptRegistry;

pub type SharedUserScriptRegistry = Arc<RwLock<UserScriptRegistry>>;

pub fn shared_default() -> Result<SharedUserScriptRegistry> {
    Ok(Arc::new(RwLock::new(UserScriptRegistry::load_default()?)))
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

pub fn render_document_injection(
    registry: &SharedUserScriptRegistry,
    target_url: &str,
    is_frame: Option<bool>,
) -> Option<String> {
    registry
        .read()
        .ok()
        .and_then(|guard| guard.render_document_injection(target_url, is_frame))
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
