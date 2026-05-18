use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::UNIX_EPOCH,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{
    metadata::{classify_metadata, parse_metadata_block},
    model::{UserScriptMetadata, UserScriptStatus},
    paths::store_path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UserScriptStore {
    pub(crate) scripts: Vec<UserScriptStoreRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UserScriptStoreRecord {
    pub(crate) filename: String,
    pub(crate) path: String,
    pub(crate) enabled: bool,
    pub(crate) size: u64,
    pub(crate) modified_ms: u64,
    pub(crate) metadata: Option<UserScriptMetadata>,
    pub(crate) status: UserScriptStatus,
    pub(crate) error: Option<String>,
}

#[derive(Debug)]
pub(crate) struct UserScriptStoreLoad {
    pub(crate) store: UserScriptStore,
    pub(crate) source_cache: BTreeMap<String, Arc<str>>,
}

#[derive(Debug, Clone)]
struct ScriptFileSnapshot {
    filename: String,
    path: PathBuf,
    size: u64,
    modified_ms: u64,
}

#[derive(Debug)]
struct ParsedScriptFile {
    record: UserScriptStoreRecord,
    source: Option<Arc<str>>,
}

pub(crate) fn load_or_rebuild(script_dir: &Path) -> Result<UserScriptStoreLoad> {
    let path = store_path();
    let loaded = match load_store_file(&path) {
        Ok(Some(store)) => Some(store),
        Ok(None) => None,
        Err(error) => {
            warn!(
                path = %path.display(),
                error = %error,
                "failed to load user script state; rebuilding with all scripts disabled"
            );
            None
        }
    };

    let (load, changed) = match loaded {
        Some(store) => sync_store_with_files(script_dir, store)?,
        None => (rebuild_store_from_files(script_dir)?, true),
    };

    if changed {
        save_store(&path, &load.store)?;
    }

    Ok(load)
}

pub(crate) fn save_store(path: &Path, store: &UserScriptStore) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create user script state dir: {}",
                parent.display()
            )
        })?;
    }

    let bytes = postcard::to_stdvec(store).context("failed to serialize user script state")?;
    fs::write(path, bytes)
        .with_context(|| format!("failed to write user script state: {}", path.display()))
}

fn load_store_file(path: &Path) -> Result<Option<UserScriptStore>> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path)
        .with_context(|| format!("failed to read user script state: {}", path.display()))?;
    let store = postcard::from_bytes::<UserScriptStore>(&bytes)
        .with_context(|| format!("failed to decode user script state: {}", path.display()))?;
    validate_store(&store)?;
    Ok(Some(store))
}

fn validate_store(store: &UserScriptStore) -> Result<()> {
    let mut seen = BTreeMap::new();
    for record in &store.scripts {
        validate_filename(&record.filename)?;
        validate_filename(&record.path)?;
        if record.filename != record.path {
            anyhow::bail!(
                "invalid user script state record `{}`: path must match filename",
                record.filename
            );
        }
        if seen.insert(record.filename.clone(), ()).is_some() {
            anyhow::bail!("duplicate user script state record `{}`", record.filename);
        }
    }
    Ok(())
}

fn validate_filename(filename: &str) -> Result<()> {
    if filename.is_empty()
        || !filename.ends_with(".user.js")
        || filename.contains('/')
        || filename.contains('\\')
        || filename == "."
        || filename == ".."
    {
        anyhow::bail!("invalid user script filename `{filename}`");
    }
    Ok(())
}

fn rebuild_store_from_files(script_dir: &Path) -> Result<UserScriptStoreLoad> {
    let mut source_cache = BTreeMap::new();
    let records = scan_script_files(script_dir)?
        .into_iter()
        .map(|snapshot| parse_script_file(snapshot, false))
        .map(|parsed| {
            let parsed = parsed?;
            if let Some(source) = parsed.source.as_ref() {
                source_cache.insert(parsed.record.filename.clone(), source.clone());
            }
            Ok(parsed.record)
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(UserScriptStoreLoad {
        store: UserScriptStore { scripts: records },
        source_cache,
    })
}

fn sync_store_with_files(
    script_dir: &Path,
    store: UserScriptStore,
) -> Result<(UserScriptStoreLoad, bool)> {
    let mut changed = false;
    let mut source_cache = BTreeMap::new();
    let mut existing = store
        .scripts
        .into_iter()
        .map(|record| (record.filename.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let mut records = Vec::new();

    for snapshot in scan_script_files(script_dir)? {
        match existing.remove(&snapshot.filename) {
            Some(mut record)
                if record.path == snapshot.filename
                    && record.size == snapshot.size
                    && record.modified_ms == snapshot.modified_ms =>
            {
                let sanitized_enabled = record.enabled && !record.status.is_error();
                if record.enabled != sanitized_enabled {
                    changed = true;
                    record.enabled = sanitized_enabled;
                }
                records.push(record);
            }
            Some(record) => {
                changed = true;
                let parsed = parse_script_file(snapshot, record.enabled)?;
                if let Some(source) = parsed.source.as_ref() {
                    source_cache.insert(parsed.record.filename.clone(), source.clone());
                }
                records.push(parsed.record);
            }
            None => {
                changed = true;
                let parsed = parse_script_file(snapshot, false)?;
                if let Some(source) = parsed.source.as_ref() {
                    source_cache.insert(parsed.record.filename.clone(), source.clone());
                }
                records.push(parsed.record);
            }
        }
    }

    if !existing.is_empty() {
        changed = true;
    }

    records.sort_by(|a, b| a.filename.cmp(&b.filename));
    Ok((
        UserScriptStoreLoad {
            store: UserScriptStore { scripts: records },
            source_cache,
        },
        changed,
    ))
}

fn scan_script_files(script_dir: &Path) -> Result<Vec<ScriptFileSnapshot>> {
    let mut scripts = Vec::new();
    for entry in fs::read_dir(script_dir)
        .with_context(|| format!("failed to read user script dir: {}", script_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("js") {
            continue;
        }
        let Some(filename) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !filename.ends_with(".user.js") {
            continue;
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("failed to read user script metadata: {}", path.display()))?;
        scripts.push(ScriptFileSnapshot {
            filename: filename.to_string(),
            path,
            size: metadata.len(),
            modified_ms: modified_ms(&metadata),
        });
    }
    scripts.sort_by(|a, b| a.filename.cmp(&b.filename));
    Ok(scripts)
}

fn parse_script_file(snapshot: ScriptFileSnapshot, enabled: bool) -> Result<ParsedScriptFile> {
    match fs::read_to_string(&snapshot.path)
        .with_context(|| format!("failed to read user script: {}", snapshot.path.display()))
    {
        Ok(source) => {
            let source = Arc::<str>::from(source);
            match metadata_block_from_source(source.as_ref())
                .and_then(|block| parse_metadata_block(&block))
            {
                Ok(metadata) => {
                    let status = classify_metadata(&metadata);
                    Ok(ParsedScriptFile {
                        record: UserScriptStoreRecord {
                            filename: snapshot.filename.clone(),
                            path: snapshot.filename,
                            enabled: enabled && !status.is_error(),
                            size: snapshot.size,
                            modified_ms: snapshot.modified_ms,
                            metadata: Some(metadata),
                            status,
                            error: None,
                        },
                        source: Some(source),
                    })
                }
                Err(error) => Ok(ParsedScriptFile {
                    record: UserScriptStoreRecord {
                        filename: snapshot.filename.clone(),
                        path: snapshot.filename,
                        enabled: false,
                        size: snapshot.size,
                        modified_ms: snapshot.modified_ms,
                        metadata: None,
                        status: UserScriptStatus::Error,
                        error: Some(error.to_string()),
                    },
                    source: Some(source),
                }),
            }
        }
        Err(error) => Ok(ParsedScriptFile {
            record: UserScriptStoreRecord {
                filename: snapshot.filename.clone(),
                path: snapshot.filename,
                enabled: false,
                size: snapshot.size,
                modified_ms: snapshot.modified_ms,
                metadata: None,
                status: UserScriptStatus::Error,
                error: Some(error.to_string()),
            },
            source: None,
        }),
    }
}

fn metadata_block_from_source(source: &str) -> Result<String> {
    let mut block = String::new();
    let mut in_block = false;

    for line in source.lines() {
        if line.contains("// ==UserScript==") {
            in_block = true;
        }
        if in_block {
            block.push_str(line);
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

fn modified_ms(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
