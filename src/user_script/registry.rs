use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{
    matching::{scope_matches, scope_summary},
    metadata::{classify_metadata, parse_metadata_block},
    model::{UserScriptEntry, UserScriptListItem, UserScriptStatus},
    paths::{script_dir, ENABLED_FILE_NAME},
    wrapper::{build_script_tag, build_wrapper},
};

#[derive(Debug, Default)]
pub struct UserScriptRegistry {
    entries: Vec<UserScriptEntry>,
    enabled_file: PathBuf,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct EnabledFile {
    enabled: Vec<String>,
}

pub(crate) fn set_enabled_default(
    shared: &Arc<RwLock<UserScriptRegistry>>,
    filename: &str,
    enabled: bool,
) -> Result<usize> {
    let (enabled_file, mut enabled_names) = {
        let guard = shared
            .read()
            .map_err(|_| anyhow::anyhow!("user script registry lock poisoned"))?;
        guard.enabled_update_plan(filename, enabled)?
    };

    enabled_names.sort();
    enabled_names.dedup();
    save_enabled_names(&enabled_file, &enabled_names)?;

    let next = UserScriptRegistry::load_default()?;
    let count = next.entry_count();
    *shared
        .write()
        .map_err(|_| anyhow::anyhow!("user script registry lock poisoned"))? = next;
    Ok(count)
}

impl UserScriptRegistry {
    pub(crate) fn load_default() -> Result<Self> {
        let dir = script_dir();
        let enabled_file = dir.join(ENABLED_FILE_NAME);
        let enabled_file_exists = enabled_file.exists();
        let enabled_names = load_enabled_names(&enabled_file)?;
        let mut entries = if dir.exists() {
            scan_entries(&dir, &enabled_names)?
        } else {
            Vec::new()
        };
        entries.sort_by(|a, b| a.filename.cmp(&b.filename));

        let existing_names = entries
            .iter()
            .map(|entry| entry.filename.clone())
            .collect::<HashSet<_>>();
        let cleaned_enabled = enabled_names
            .into_iter()
            .filter(|name| existing_names.contains(name))
            .collect::<Vec<_>>();
        if enabled_file_exists {
            save_enabled_names(&enabled_file, &cleaned_enabled)?;
        }
        for entry in &mut entries {
            entry.enabled = cleaned_enabled.iter().any(|name| name == &entry.filename)
                && !entry.status.is_error();
        }

        Ok(Self {
            entries,
            enabled_file,
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
        self.entries.iter().any(|entry| {
            if !entry.enabled {
                return false;
            }
            let Some(metadata) = entry.metadata.as_ref() else {
                return false;
            };
            if metadata.noframes && is_frame == Some(true) {
                return false;
            }
            scope_matches(metadata, target_url)
        })
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
                    enabled: entry.enabled,
                    operable: !entry.status.is_error(),
                    error: entry.error.clone(),
                }
            })
            .collect()
    }

    fn enabled_update_plan(&self, filename: &str, enabled: bool) -> Result<(PathBuf, Vec<String>)> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.filename == filename)
            .with_context(|| format!("user script `{filename}` was not found"))?;
        if entry.status.is_error() {
            anyhow::bail!("user script `{filename}` cannot be enabled because it has parse errors");
        }

        let mut enabled_names = self
            .entries
            .iter()
            .filter(|entry| entry.enabled && !entry.status.is_error())
            .map(|entry| entry.filename.clone())
            .collect::<Vec<_>>();

        if enabled {
            if !enabled_names.iter().any(|name| name == filename) {
                enabled_names.push(filename.to_string());
            }
        } else {
            enabled_names.retain(|name| name != filename);
        }

        Ok((self.enabled_file.clone(), enabled_names))
    }

    pub(crate) fn render_document_injection(
        &self,
        target_url: &str,
        is_frame: Option<bool>,
    ) -> Option<String> {
        let snippets = self
            .entries
            .iter()
            .filter(|entry| entry.enabled)
            .filter_map(|entry| render_entry_if_matches(entry, target_url, is_frame))
            .collect::<Vec<_>>();

        if snippets.is_empty() {
            None
        } else {
            Some(snippets.join("\n"))
        }
    }
}

fn scan_entries(dir: &Path, enabled_names: &[String]) -> Result<Vec<UserScriptEntry>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read user script dir: {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("js") {
            continue;
        }
        let Some(filename) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !filename.ends_with(".user.js") {
            continue;
        }

        let enabled = enabled_names.iter().any(|name| name == filename);
        entries.push(load_script_entry(&path, filename.to_string(), enabled));
    }
    Ok(entries)
}

fn load_script_entry(path: &Path, filename: String, enabled: bool) -> UserScriptEntry {
    match read_metadata_block(path).and_then(|block| parse_metadata_block(&block)) {
        Ok(metadata) => {
            let status = classify_metadata(&metadata);
            UserScriptEntry {
                filename,
                path: path.to_path_buf(),
                metadata: Some(metadata),
                status,
                error: None,
                enabled,
            }
        }
        Err(error) => UserScriptEntry {
            filename,
            path: path.to_path_buf(),
            metadata: None,
            status: UserScriptStatus::Error,
            error: Some(error.to_string()),
            enabled: false,
        },
    }
}

fn read_metadata_block(path: &Path) -> Result<String> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open user script: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut block = String::new();
    let mut in_block = false;

    for line in reader.lines() {
        let line = line
            .with_context(|| format!("failed to read user script metadata: {}", path.display()))?;
        if line.contains("// ==UserScript==") {
            in_block = true;
        }
        if in_block {
            block.push_str(&line);
            block.push('\n');
        }
        if in_block && line.contains("// ==/UserScript==") {
            return Ok(block);
        }
    }

    if in_block {
        anyhow::bail!("missing userscript metadata end")
    } else {
        anyhow::bail!("missing userscript metadata start")
    }
}

fn render_entry_if_matches(
    entry: &UserScriptEntry,
    target_url: &str,
    is_frame: Option<bool>,
) -> Option<String> {
    let metadata = entry.metadata.as_ref()?;
    if metadata.noframes && is_frame == Some(true) {
        return None;
    }
    if !scope_matches(metadata, target_url) {
        return None;
    }
    let source = match fs::read_to_string(&entry.path) {
        Ok(source) => source,
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
    Some(build_script_tag(&build_wrapper(entry, metadata, &source)))
}

fn load_enabled_names(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read user script enabled file: {}",
            path.display()
        )
    })?;
    let file: EnabledFile = serde_yaml::from_str(&text).with_context(|| {
        format!(
            "failed to parse user script enabled file: {}",
            path.display()
        )
    })?;
    Ok(file.enabled)
}

fn save_enabled_names(path: &Path, names: &[String]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create user script enabled dir: {}",
                parent.display()
            )
        })?;
    }
    let file = EnabledFile {
        enabled: names.to_vec(),
    };
    let yaml =
        serde_yaml::to_string(&file).context("failed to serialize user script enabled file")?;
    fs::write(path, yaml).with_context(|| {
        format!(
            "failed to write user script enabled file: {}",
            path.display()
        )
    })
}
