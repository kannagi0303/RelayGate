use std::{
    fs,
    path::PathBuf,
    sync::{OnceLock, RwLock},
};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value as JsonValue;
use serde_yaml::{Mapping, Value};

use crate::{
    config::RelayGateConfig,
    path_mode::{app_path_mode, AppPathMode},
};

const BUILTIN_EN_US: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/lang/en-US.lang"
));
const BUILTIN_ZH_TW: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/lang/zh-TW.lang"
));
const FALLBACK_LOCALE: &str = "en-US";

static CURRENT_LANG: OnceLock<RwLock<LangCatalog>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct LangCatalog {
    root: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebI18nPayload {
    pub locale: String,
    pub available_locales: Vec<String>,
    pub messages: JsonValue,
}

impl LangCatalog {
    fn load() -> Result<Self> {
        let override_root = load_override_root()?;
        let config_locale = load_config_locale()?;
        let locale = override_root
            .as_ref()
            .and_then(|root| lookup_path(root, "meta.locale"))
            .and_then(Value::as_str)
            .or(config_locale.as_deref())
            .unwrap_or(FALLBACK_LOCALE);

        let mut root = parse_builtin(FALLBACK_LOCALE)?;
        if locale != FALLBACK_LOCALE {
            merge_value(&mut root, parse_builtin(locale)?);
        }

        if let Some(override_root) = override_root {
            merge_value(&mut root, override_root);
        }

        Ok(Self { root })
    }

    fn available_locales() -> Vec<String> {
        vec![FALLBACK_LOCALE.to_string(), "zh-TW".to_string()]
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

    fn locale(&self) -> String {
        self.text("meta.locale")
    }

    fn messages_json(&self) -> JsonValue {
        serde_json::to_value(&self.root).unwrap_or_else(|_| JsonValue::Object(Default::default()))
    }
}

pub fn init_current() -> Result<()> {
    if CURRENT_LANG.get().is_some() {
        return Ok(());
    }

    let catalog = LangCatalog::load()?;
    let _ = CURRENT_LANG.set(RwLock::new(catalog));
    Ok(())
}

fn current_cell() -> &'static RwLock<LangCatalog> {
    CURRENT_LANG.get_or_init(|| {
        RwLock::new(LangCatalog::load().unwrap_or_else(|error| {
            tracing::warn!(error = %error, "failed to initialize language catalog; falling back to empty catalog");
            LangCatalog {
                root: Value::Mapping(Mapping::new()),
            }
        }))
    })
}

fn current_clone() -> LangCatalog {
    current_cell()
        .read()
        .map(|catalog| catalog.clone())
        .unwrap_or_else(|_| LangCatalog {
            root: Value::Mapping(Mapping::new()),
        })
}

fn replace_current(catalog: LangCatalog) {
    if let Ok(mut current) = current_cell().write() {
        *current = catalog;
    }
}

pub fn text(path: &str) -> String {
    current_clone().text(path)
}

pub fn format(path: &str, values: &[(&str, String)]) -> String {
    current_clone().format(path, values)
}

pub fn web_i18n_payload() -> WebI18nPayload {
    let catalog = LangCatalog::load().unwrap_or_else(|error| {
        tracing::warn!(error = %error, "failed to reload web language catalog; using current catalog");
        current_clone()
    });
    replace_current(catalog.clone());

    WebI18nPayload {
        locale: catalog.locale(),
        available_locales: LangCatalog::available_locales(),
        messages: catalog.messages_json(),
    }
}

pub fn available_locales() -> Vec<String> {
    LangCatalog::available_locales()
}

fn parse_builtin(locale: &str) -> Result<Value> {
    let content = match locale {
        "zh-TW" => BUILTIN_ZH_TW,
        _ => BUILTIN_EN_US,
    };
    serde_yaml::from_str::<Value>(content)
        .with_context(|| format!("failed to parse built-in {locale} language file"))
}

fn load_override_root() -> Result<Option<Value>> {
    let Some(path) = override_path()? else {
        return Ok(None);
    };
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            tracing::warn!(path = %path.display(), error = %error, "failed to read relaygate.lang override");
            return Ok(None);
        }
    };

    match serde_yaml::from_str::<Value>(&content) {
        Ok(override_root) => Ok(Some(override_root)),
        Err(error) => {
            tracing::warn!(path = %path.display(), error = %error, "failed to parse relaygate.lang override");
            Ok(None)
        }
    }
}

fn load_config_locale() -> Result<Option<String>> {
    match RelayGateConfig::load_root_locale_default() {
        Ok(locale) => Ok(locale),
        Err(error) => {
            tracing::warn!(error = %error, "failed to load RelayGate root config locale");
            Ok(None)
        }
    }
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
