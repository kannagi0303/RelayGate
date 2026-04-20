use std::{fs, path::PathBuf, sync::OnceLock};

use anyhow::{Context, Result};
use serde_yaml::{Mapping, Value};

use crate::path_mode::{app_path_mode, AppPathMode};

const BUILTIN_LANG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/lang/en-US.lang"
));

static CURRENT_LANG: OnceLock<LangCatalog> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct LangCatalog {
    root: Value,
}

impl LangCatalog {
    fn load() -> Result<Self> {
        let mut root = serde_yaml::from_str::<Value>(BUILTIN_LANG)
            .context("failed to parse built-in en-US language file")?;

        if let Some(path) = override_path()? {
            let content = match fs::read_to_string(&path) {
                Ok(content) => Some(content),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    tracing::warn!(path = %path.display(), error = %error, "failed to read relaygate.lang override");
                    None
                }
            };

            if let Some(content) = content {
                match serde_yaml::from_str::<Value>(&content) {
                    Ok(override_root) => merge_value(&mut root, override_root),
                    Err(error) => {
                        tracing::warn!(path = %path.display(), error = %error, "failed to parse relaygate.lang override");
                    }
                }
            }
        }

        Ok(Self { root })
    }

    pub fn text(&self, path: &str) -> String {
        lookup_path(&self.root, path)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| path.to_string())
    }

    pub fn format(&self, path: &str, values: &[(&str, String)]) -> String {
        let mut text = self.text(path);
        for (name, value) in values {
            let needle = format!("{{{name}}}");
            text = text.replace(&needle, value);
        }
        text
    }
}

pub fn init_current() -> Result<()> {
    if CURRENT_LANG.get().is_some() {
        return Ok(());
    }

    let catalog = LangCatalog::load()?;
    let _ = CURRENT_LANG.set(catalog);
    Ok(())
}

pub fn current() -> &'static LangCatalog {
    CURRENT_LANG.get_or_init(|| {
        LangCatalog::load().unwrap_or_else(|error| {
            tracing::warn!(error = %error, "failed to initialize language catalog; falling back to empty catalog");
            LangCatalog {
                root: Value::Mapping(Mapping::new()),
            }
        })
    })
}

pub fn text(path: &str) -> String {
    current().text(path)
}

pub fn format(path: &str, values: &[(&str, String)]) -> String {
    current().format(path, values)
}

fn override_path() -> Result<Option<PathBuf>> {
    let base = match app_path_mode() {
        AppPathMode::Workspace => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        AppPathMode::Portable => {
            let exe =
                std::env::current_exe().context("failed to resolve current executable path")?;
            exe.parent()
                .context("current executable path does not have a parent directory")?
                .to_path_buf()
        }
    };

    Ok(Some(base.join("relaygate.lang")))
}

fn lookup_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        let Value::Mapping(map) = current else {
            return None;
        };
        current = map.get(Value::String(segment.to_string()))?;
    }
    Some(current)
}

fn merge_value(base: &mut Value, override_value: Value) {
    match (base, override_value) {
        (Value::Mapping(base_map), Value::Mapping(override_map)) => {
            merge_mapping(base_map, override_map);
        }
        (base_slot, override_slot) => *base_slot = override_slot,
    }
}

fn merge_mapping(base: &mut Mapping, override_map: Mapping) {
    for (key, override_value) in override_map {
        if let Some(base_value) = base.get_mut(&key) {
            merge_value(base_value, override_value);
        } else {
            base.insert(key, override_value);
        }
    }
}
