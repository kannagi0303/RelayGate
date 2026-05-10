use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::path_mode::{app_path_mode, AppPathMode};

pub type SharedResourceReplaceRegistry = Arc<RwLock<ResourceReplaceRegistry>>;

#[derive(Debug, Default)]
pub struct ResourceReplaceRegistry {
    rules: Vec<LoadedResourceRule>,
}

#[derive(Debug)]
struct LoadedResourceRule {
    id: String,
    enabled: bool,
    hosts: HashSet<String>,
    url_regex: Regex,
    source_regex: Option<Regex>,
    response: ResourceResponse,
}

#[derive(Debug, Clone)]
pub struct ResourceReplacement {
    pub rule_id: String,
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceRuleInfo {
    pub id: String,
    pub enabled: bool,
    pub hosts: Vec<String>,
    pub url_regex: String,
    pub source_regex: Option<String>,
    pub file: String,
    pub content_type: String,
    pub size: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct ResourceRuleSet {
    #[serde(default)]
    rules: Vec<ResourceRuleFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ResourceRuleFile {
    id: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    hosts: Vec<String>,
    url_regex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_regex: Option<String>,
    response: ResourceResponseFile,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ResourceResponseFile {
    #[serde(default = "default_status")]
    status: u16,
    content_type: String,
    file: String,
}

#[derive(Debug, Clone)]
struct ResourceResponse {
    status: u16,
    content_type: String,
    file: String,
    path: PathBuf,
    size: usize,
}

impl ResourceReplaceRegistry {
    pub fn load_default() -> Result<Self> {
        let path = rule_file_path();
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path).with_context(|| {
            format!(
                "failed to read resource replacement rules: {}",
                path.display()
            )
        })?;
        let rule_set = serde_yaml::from_str::<ResourceRuleSet>(&content).with_context(|| {
            format!(
                "failed to parse resource replacement rules: {}",
                path.display()
            )
        })?;

        let base_dir = resource_replace_dir();
        let mut rules = Vec::new();
        for rule in rule_set.rules {
            let body_path = normalize_resource_path(&base_dir, &rule.response.file);
            let size = fs::metadata(&body_path)
                .with_context(|| {
                    format!(
                        "failed to inspect replacement resource for rule `{}`: {}",
                        rule.id,
                        body_path.display()
                    )
                })?
                .len() as usize;
            let hosts = rule
                .hosts
                .iter()
                .map(|host| normalize_host(host))
                .filter(|host| !host.is_empty())
                .collect::<HashSet<_>>();

            rules.push(LoadedResourceRule {
                id: rule.id,
                enabled: rule.enabled,
                hosts,
                url_regex: Regex::new(&rule.url_regex)
                    .with_context(|| format!("invalid url_regex: {}", rule.url_regex))?,
                source_regex: rule
                    .source_regex
                    .as_ref()
                    .map(|pattern| Regex::new(pattern))
                    .transpose()
                    .with_context(|| "invalid source_regex")?,
                response: ResourceResponse {
                    status: rule.response.status,
                    content_type: rule.response.content_type,
                    file: rule.response.file,
                    path: body_path,
                    size,
                },
            });
        }

        Ok(Self { rules })
    }

    pub fn shared_default() -> Result<SharedResourceReplaceRegistry> {
        Ok(Arc::new(RwLock::new(Self::load_default()?)))
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn enabled_rule_count(&self) -> usize {
        self.rules.iter().filter(|rule| rule.enabled).count()
    }

    pub fn should_mitm_host(&self, authority_or_host: &str) -> bool {
        let host = normalize_host(authority_or_host);
        !host.is_empty()
            && self
                .rules
                .iter()
                .any(|rule| rule.enabled && rule.hosts.contains(&host))
    }

    pub fn find_replacement(
        &self,
        target_url: &str,
        source_url: &str,
    ) -> Option<ResourceReplacement> {
        self.rules
            .iter()
            .find(|rule| rule.matches(target_url, source_url))
            .and_then(|rule| rule.load_replacement_body())
    }

    pub fn rule_infos(&self) -> Vec<ResourceRuleInfo> {
        self.rules
            .iter()
            .map(|rule| {
                let mut hosts = rule.hosts.iter().cloned().collect::<Vec<_>>();
                hosts.sort();
                ResourceRuleInfo {
                    id: rule.id.clone(),
                    enabled: rule.enabled,
                    hosts,
                    url_regex: rule.url_regex.as_str().to_string(),
                    source_regex: rule
                        .source_regex
                        .as_ref()
                        .map(|regex| regex.as_str().to_string()),
                    file: rule.response.file.clone(),
                    content_type: rule.response.content_type.clone(),
                    size: rule.response.size,
                }
            })
            .collect()
    }
}

impl LoadedResourceRule {
    fn matches(&self, target_url: &str, source_url: &str) -> bool {
        self.enabled
            && self.url_regex.is_match(target_url)
            && self
                .source_regex
                .as_ref()
                .map(|regex| regex.is_match(source_url))
                .unwrap_or(true)
    }

    fn load_replacement_body(&self) -> Option<ResourceReplacement> {
        match fs::read(&self.response.path) {
            Ok(body) => Some(ResourceReplacement {
                rule_id: self.id.clone(),
                status: self.response.status,
                content_type: self.response.content_type.clone(),
                body,
            }),
            Err(error) => {
                warn!(
                    rule = %self.id,
                    path = %self.response.path.display(),
                    error = %error,
                    "resource replacement matched but response body could not be read"
                );
                None
            }
        }
    }
}

pub fn reload_shared_registry(shared: &SharedResourceReplaceRegistry) -> Result<usize> {
    let reloaded = ResourceReplaceRegistry::load_default()?;
    let count = reloaded.rule_count();
    let mut guard = shared.write().map_err(|_| {
        anyhow::anyhow!("resource replacement registry lock poisoned during reload")
    })?;
    *guard = reloaded;
    Ok(count)
}

pub fn set_rule_enabled_default(id: &str, enabled: bool) -> Result<()> {
    let path = rule_file_path();
    let content = fs::read_to_string(&path).with_context(|| {
        format!(
            "failed to read resource replacement rules: {}",
            path.display()
        )
    })?;
    let mut rule_set = serde_yaml::from_str::<ResourceRuleSet>(&content).with_context(|| {
        format!(
            "failed to parse resource replacement rules: {}",
            path.display()
        )
    })?;
    let Some(rule) = rule_set.rules.iter_mut().find(|rule| rule.id == id) else {
        anyhow::bail!("resource replacement rule `{id}` was not found");
    };
    rule.enabled = enabled;
    let updated = serde_yaml::to_string(&rule_set)
        .context("failed to serialize resource replacement rules")?;
    fs::write(&path, updated).with_context(|| {
        format!(
            "failed to write resource replacement rules: {}",
            path.display()
        )
    })
}

pub fn rule_count(shared: &SharedResourceReplaceRegistry) -> usize {
    shared.read().map(|guard| guard.rule_count()).unwrap_or(0)
}

pub fn enabled_rule_count(shared: &SharedResourceReplaceRegistry) -> usize {
    shared
        .read()
        .map(|guard| guard.enabled_rule_count())
        .unwrap_or(0)
}

pub fn rule_infos(shared: &SharedResourceReplaceRegistry) -> Vec<ResourceRuleInfo> {
    shared
        .read()
        .map(|guard| guard.rule_infos())
        .unwrap_or_default()
}

pub fn rule_dir() -> PathBuf {
    resource_replace_dir()
}

fn normalize_resource_path(base_dir: &Path, file: &str) -> PathBuf {
    let path = PathBuf::from(file);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn rule_file_path() -> PathBuf {
    resource_replace_dir().join("rules.yaml")
}

fn resource_replace_dir() -> PathBuf {
    preferred_base_dir().join("data").join("resource_replace")
}

fn preferred_base_dir() -> PathBuf {
    match app_path_mode() {
        AppPathMode::Workspace => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        AppPathMode::Portable => executable_base_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

fn executable_base_dir() -> Result<PathBuf> {
    let exe = env::current_exe().context("failed to resolve current executable path")?;
    let parent = exe
        .parent()
        .context("current executable path does not have a parent directory")?;
    Ok(parent.to_path_buf())
}

fn normalize_host(value: &str) -> String {
    value
        .rsplit("://")
        .next()
        .unwrap_or(value)
        .split('/')
        .next()
        .unwrap_or(value)
        .split(':')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

fn default_true() -> bool {
    true
}

fn default_status() -> u16 {
    200
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rule_file_loads_empty_rule_set() {
        let registry = ResourceReplaceRegistry::load_default().unwrap();
        assert_eq!(registry.rule_count(), 0);
    }
}
