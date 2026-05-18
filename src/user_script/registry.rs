use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use tokio::fs as async_fs;
use tracing::warn;

use super::{
    matching::{scope_summary, CompiledUserScriptMatcher},
    model::{UserScriptEntry, UserScriptListItem},
    paths::{ensure_script_dir_ready, store_path},
    store::{self, UserScriptStore, UserScriptStoreRecord},
    wrapper::{build_script_tag, build_wrapper},
};

#[derive(Debug, Default)]
pub struct UserScriptRegistry {
    entries: Vec<UserScriptEntry>,
    store_path: PathBuf,
}

pub(crate) fn set_enabled_default(
    shared: &Arc<RwLock<UserScriptRegistry>>,
    filename: &str,
    enabled: bool,
) -> Result<usize> {
    let (store_path, store) = {
        let guard = shared
            .read()
            .map_err(|_| anyhow::anyhow!("user script registry lock poisoned"))?;
        guard.store_with_enabled(filename, enabled)?
    };

    store::save_store(&store_path, &store)?;

    let next = UserScriptRegistry::load_default()?;
    let count = next.entry_count();
    *shared
        .write()
        .map_err(|_| anyhow::anyhow!("user script registry lock poisoned"))? = next;
    Ok(count)
}

impl UserScriptRegistry {
    pub(crate) fn load_default() -> Result<Self> {
        let dir = ensure_script_dir_ready()?;
        let loaded = store::load_or_rebuild(&dir)?;
        let mut entries = loaded
            .store
            .scripts
            .iter()
            .map(|record| record_to_entry(&dir, record, &loaded.source_cache))
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.filename.cmp(&b.filename));

        Ok(Self {
            entries,
            store_path: store_path(),
        })
    }

    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn has_enabled_scripts(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.enabled && entry.metadata.is_some())
    }

    pub(crate) fn has_enabled_script_match(
        &self,
        target_url: &str,
        is_frame: Option<bool>,
    ) -> bool {
        self.entries
            .iter()
            .any(|entry| entry_matches_target(entry, target_url, is_frame))
    }

    pub(crate) fn list_items(&self) -> Vec<UserScriptListItem> {
        self.entries
            .iter()
            .map(|entry| {
                let metadata = entry.metadata.as_ref();
                UserScriptListItem {
                    filename: entry.filename.clone(),
                    status: entry.status,
                    status_label: entry.status.label().to_string(),
                    name: metadata
                        .and_then(|item| item.name.clone())
                        .unwrap_or_else(|| entry.filename.clone()),
                    version: metadata
                        .and_then(|item| item.version.clone())
                        .unwrap_or_else(|| "-".to_string()),
                    match_summary: metadata
                        .map(scope_summary)
                        .unwrap_or_else(|| entry.error.clone().unwrap_or_else(|| "-".to_string())),
                    comment: entry
                        .error
                        .clone()
                        .or_else(|| metadata.and_then(|item| item.description.clone()))
                        .unwrap_or_default(),
                    enabled: entry.enabled,
                    operable: !entry.status.is_error(),
                    error: entry.error.clone(),
                }
            })
            .collect()
    }

    fn store_with_enabled(
        &self,
        filename: &str,
        enabled: bool,
    ) -> Result<(PathBuf, UserScriptStore)> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.filename == filename)
            .with_context(|| format!("user script `{filename}` was not found"))?;
        if entry.status.is_error() {
            anyhow::bail!("user script `{filename}` cannot be enabled because it has parse errors");
        }

        let scripts = self
            .entries
            .iter()
            .map(|entry| {
                let next_enabled = if entry.filename == filename {
                    enabled && !entry.status.is_error()
                } else {
                    entry.enabled && !entry.status.is_error()
                };
                UserScriptStoreRecord {
                    filename: entry.filename.clone(),
                    path: entry.filename.clone(),
                    enabled: next_enabled,
                    size: entry.size,
                    modified_ms: entry.modified_ms,
                    metadata: entry.metadata.clone(),
                    status: entry.status,
                    error: entry.error.clone(),
                }
            })
            .collect::<Vec<_>>();

        Ok((self.store_path.clone(), UserScriptStore { scripts }))
    }

    pub(crate) fn matching_entries(
        &self,
        target_url: &str,
        is_frame: Option<bool>,
    ) -> Vec<UserScriptEntry> {
        self.entries
            .iter()
            .filter(|entry| entry_matches_target(entry, target_url, is_frame))
            .cloned()
            .collect()
    }
}

fn record_to_entry(
    script_dir: &Path,
    record: &UserScriptStoreRecord,
    source_cache: &BTreeMap<String, Arc<str>>,
) -> UserScriptEntry {
    let path = script_dir.join(&record.path);
    let matcher = record
        .metadata
        .as_ref()
        .filter(|_| !record.status.is_error())
        .map(CompiledUserScriptMatcher::compile);

    UserScriptEntry {
        filename: record.filename.clone(),
        path,
        metadata: record.metadata.clone(),
        matcher,
        source_cache: Arc::new(tokio::sync::Mutex::new(
            source_cache.get(&record.filename).cloned(),
        )),
        status: record.status,
        error: record.error.clone(),
        enabled: record.enabled && !record.status.is_error(),
        size: record.size,
        modified_ms: record.modified_ms,
    }
}

fn entry_matches_target(entry: &UserScriptEntry, target_url: &str, is_frame: Option<bool>) -> bool {
    if !entry.enabled {
        return false;
    }
    let Some(metadata) = entry.metadata.as_ref() else {
        return false;
    };
    if metadata.noframes && is_frame == Some(true) {
        return false;
    }
    entry
        .matcher
        .as_ref()
        .map(|matcher| matcher.matches(target_url))
        .unwrap_or(false)
}

pub(crate) async fn render_matching_entries(entries: Vec<UserScriptEntry>) -> Option<String> {
    let mut snippets = Vec::new();
    for entry in entries {
        if let Some(snippet) = render_matched_entry(&entry).await {
            snippets.push(snippet);
        }
    }

    if snippets.is_empty() {
        None
    } else {
        Some(snippets.join("\n"))
    }
}

async fn render_matched_entry(entry: &UserScriptEntry) -> Option<String> {
    let metadata = entry.metadata.as_ref()?;
    let source = load_source_cached(entry).await?;
    Some(build_script_tag(&build_wrapper(
        entry,
        metadata,
        source.as_ref(),
    )))
}

async fn load_source_cached(entry: &UserScriptEntry) -> Option<Arc<str>> {
    let mut cache = entry.source_cache.lock().await;
    if let Some(source) = cache.as_ref() {
        return Some(source.clone());
    }

    let source = match async_fs::read_to_string(&entry.path).await {
        Ok(source) => Arc::<str>::from(source),
        Err(error) => {
            warn!(
                script = %entry.filename,
                path = %entry.path.display(),
                error = %error,
                "failed to lazy-load matched user script"
            );
            return None;
        }
    };
    *cache = Some(source.clone());
    Some(source)
}
