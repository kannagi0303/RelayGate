use std::{
    collections::{HashMap, HashSet},
    env, fs,
    ops::Range,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use regex::Regex;
use scraper::{ElementRef, Html, Selector};
use serde::{de, Deserialize, Deserializer};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

use crate::path_mode::{app_path_mode, AppPathMode};

/// First rewrite rule engine.
/// It currently covers the features needed by onejav and follows this model:
/// - load all `data/rewrite/*.yaml` files into memory on startup
/// - use loaded rule hosts to decide CONNECT interception
/// - use loaded rule URL matches to decide page rewrites

pub type SharedRewriteRegistry = Arc<RwLock<RewriteRegistry>>;

#[derive(Debug, Default)]
pub struct RewriteRegistry {
    render_rules: Vec<LoadedRewriteRule>,
    patch_rules: Vec<LoadedPatchRule>,
}

#[derive(Debug)]
struct LoadedRewriteRule {
    rule: RewriteRuleFile,
    hosts: HashSet<String>,
    matchers: Vec<Regex>,
    fields: HashMap<String, LoadedRewriteFieldRule>,
    template: String,
}

#[derive(Debug)]
struct LoadedPatchRule {
    enabled: bool,
    hosts: HashSet<String>,
    vars: HashMap<String, LoadedVarPatchRule>,
    json: Option<LoadedJsonPatchRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RewriteRuleFile {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub adblock: bool,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default, rename = "match")]
    pub match_rules: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub fields: HashMap<String, RewriteFieldRule>,
    pub render: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatchRuleFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub vars: HashMap<String, PatchVarRuleFile>,
    pub json: Option<PatchJsonRuleFile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatchVarRuleFile {
    #[serde(default, rename = "match")]
    pub match_rules: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub pipe: Vec<PatchPipeStep>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatchJsonRuleFile {
    #[serde(default, rename = "match")]
    pub match_rules: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub pipe: Vec<PatchPipeStep>,
}

#[derive(Debug, Clone)]
struct LoadedVarPatchRule {
    matchers: Vec<Regex>,
    pipe: Vec<PatchPipeStep>,
}

#[derive(Debug, Clone)]
struct LoadedJsonPatchRule {
    matchers: Vec<Regex>,
    pipe: Vec<PatchPipeStep>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RewriteFieldRule {
    pub select: String,
    pub value: Option<String>,
    #[serde(default)]
    pub multiple: bool,
    #[serde(default)]
    pub pipe: Vec<RewritePipeStep>,
}

#[derive(Debug, Clone)]
struct LoadedRewriteFieldRule {
    value: Option<String>,
    multiple: bool,
    pipe: Vec<LoadedRewritePipeStep>,
    selector: Selector,
}

#[derive(Debug, Clone)]
pub enum RewritePipeStep {
    Regex { regex: String },
    Template { template: String },
    NotEmpty(Option<String>),
    AbsoluteUrlMap { absolute_url: AbsoluteUrlStep },
    Unique,
    JoinMap { join: String },
    Trim,
}

#[derive(Debug, Clone)]
enum LoadedRewritePipeStep {
    Regex { regex: Regex },
    Template { template: String },
    NotEmpty(Option<String>),
    AbsoluteUrlMap { absolute_url: AbsoluteUrlStep },
    Unique,
    JoinMap { join: String },
    Trim,
}

#[derive(Debug, Clone)]
pub enum PatchPipeStep {
    Remove { keys: Vec<String> },
}

#[derive(Debug, Clone, Default)]
pub struct PatchApplyResult {
    pub body: Vec<u8>,
    pub modified: bool,
}

#[derive(Debug, Clone)]
pub struct RenderApplyResult {
    pub body: Vec<u8>,
    pub matched: bool,
    pub allow_adblock_injection: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbsoluteUrlStep {
    pub base: String,
}

impl RewriteRegistry {
    pub fn load_default() -> Result<Self> {
        let mut render_rules = Vec::new();
        for path in collect_yaml_paths(&rewrite_sites_dir())? {
            let loaded = load_rule_file(&path)?;
            if loaded.rule.enabled {
                render_rules.push(loaded);
            }
        }

        let mut patch_rules = Vec::new();
        for path in collect_yaml_paths(&patch_sites_dir())? {
            let loaded = load_patch_rule_file(&path)?;
            if loaded.enabled {
                patch_rules.push(loaded);
            }
        }

        Ok(Self {
            render_rules,
            patch_rules,
        })
    }

    pub fn shared_default() -> Result<SharedRewriteRegistry> {
        Ok(Arc::new(RwLock::new(Self::load_default()?)))
    }

    pub fn rule_count(&self) -> usize {
        self.render_rules.len() + self.patch_rules.len()
    }

    pub fn should_mitm_host(&self, authority_or_host: &str) -> bool {
        let host = normalize_host(authority_or_host);
        if host.is_empty() {
            return false;
        }

        self.render_rules
            .iter()
            .any(|rule| rule.hosts.contains(&host))
            || self
                .patch_rules
                .iter()
                .any(|rule| rule.hosts.contains(&host))
    }

    pub fn apply_matching_rule(&self, html: &[u8], page_url: &str) -> Result<RenderApplyResult> {
        if has_render_bypass_magic_word(page_url) {
            return Ok(RenderApplyResult {
                body: html.to_vec(),
                matched: false,
                allow_adblock_injection: true,
            });
        }

        let Some(rule) = self.find_matching_rule(page_url) else {
            return Ok(RenderApplyResult {
                body: html.to_vec(),
                matched: false,
                allow_adblock_injection: true,
            });
        };

        let html = String::from_utf8_lossy(html).to_string();
        let document = Html::parse_document(&html);

        let mut context = default_template_context(page_url);
        for (field_name, field_rule) in &rule.fields {
            if let Some(value) = extract_field_value(&document, field_name, field_rule, &context)? {
                context.insert(field_name.clone(), value);
            }
        }

        let rendered = render_template(&rule.template, &context);
        Ok(RenderApplyResult {
            body: rendered.into_bytes(),
            matched: true,
            allow_adblock_injection: rule.rule.adblock,
        })
    }

    pub fn apply_patch_rules(
        &self,
        response_body: &[u8],
        page_url: &str,
        content_type: &str,
    ) -> Result<PatchApplyResult> {
        if !is_patch_candidate_content_type(content_type) {
            return Ok(PatchApplyResult {
                body: response_body.to_vec(),
                modified: false,
            });
        }

        let mut current = response_body.to_vec();
        let mut modified = false;

        for rule in &self.patch_rules {
            let result = rule.apply(&current, page_url, content_type)?;
            if result.modified {
                current = result.body;
                modified = true;
            }
        }

        Ok(PatchApplyResult {
            body: current,
            modified,
        })
    }

    pub fn has_render_rule_match(&self, page_url: &str) -> bool {
        if has_render_bypass_magic_word(page_url) {
            return false;
        }

        self.find_matching_rule(page_url).is_some()
    }

    pub fn has_patch_rule_match(&self, page_url: &str, content_type: &str) -> bool {
        if !is_patch_candidate_content_type(content_type) {
            return false;
        }

        self.patch_rules
            .iter()
            .any(|rule| rule.matches_response(page_url, content_type))
    }

    fn find_matching_rule(&self, page_url: &str) -> Option<&LoadedRewriteRule> {
        self.render_rules.iter().find(|rule| {
            if rule.matchers.is_empty() {
                return false;
            }

            rule.matchers.iter().any(|regex| regex.is_match(page_url))
        })
    }
}

pub fn reload_shared_registry(shared: &SharedRewriteRegistry) -> Result<usize> {
    let reloaded = RewriteRegistry::load_default()?;
    let count = reloaded.rule_count();
    let mut guard = shared
        .write()
        .map_err(|_| anyhow::anyhow!("rewrite registry lock poisoned during reload"))?;
    *guard = reloaded;
    Ok(count)
}

impl<'de> Deserialize<'de> for RewritePipeStep {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = YamlValue::deserialize(deserializer)?;

        match value {
            YamlValue::String(flag) => match flag.as_str() {
                "notempty" => Ok(Self::NotEmpty(None)),
                "unique" => Ok(Self::Unique),
                "trim" => Ok(Self::Trim),
                _ => Err(de::Error::custom(format!(
                    "unsupported pipe step string: {flag}"
                ))),
            },
            YamlValue::Mapping(map) => {
                if map.len() != 1 {
                    return Err(de::Error::custom(
                        "pipe step mapping must have exactly one key",
                    ));
                }

                let (key, raw_value) = map.into_iter().next().unwrap();
                let Some(key) = key.as_str() else {
                    return Err(de::Error::custom("pipe step key must be string"));
                };

                match key {
                    "regex" => Ok(Self::Regex {
                        regex: yaml_string(raw_value).map_err(de::Error::custom)?,
                    }),
                    "template" => Ok(Self::Template {
                        template: yaml_string(raw_value).map_err(de::Error::custom)?,
                    }),
                    "notempty" => Ok(Self::NotEmpty(Some(
                        yaml_string(raw_value).map_err(de::Error::custom)?,
                    ))),
                    "absolute_url" => Ok(Self::AbsoluteUrlMap {
                        absolute_url: serde_yaml::from_value(raw_value)
                            .map_err(de::Error::custom)?,
                    }),
                    "join" => Ok(Self::JoinMap {
                        join: yaml_string(raw_value).map_err(de::Error::custom)?,
                    }),
                    _ => Err(de::Error::custom(format!(
                        "unsupported pipe step key: {key}"
                    ))),
                }
            }
            _ => Err(de::Error::custom("unsupported pipe step YAML value")),
        }
    }
}

impl<'de> Deserialize<'de> for PatchPipeStep {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = YamlValue::deserialize(deserializer)?;
        let YamlValue::Mapping(map) = value else {
            return Err(de::Error::custom("patch pipe step must be mapping"));
        };
        if map.len() != 1 {
            return Err(de::Error::custom(
                "patch pipe step mapping must have exactly one key",
            ));
        }

        let (key, raw_value) = map.into_iter().next().unwrap();
        let Some(key) = key.as_str() else {
            return Err(de::Error::custom("patch pipe step key must be string"));
        };

        match key {
            "remove" => Ok(Self::Remove {
                keys: yaml_string_list(raw_value).map_err(de::Error::custom)?,
            }),
            _ => Err(de::Error::custom(format!(
                "unsupported patch pipe step key: {key}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
enum FieldValue {
    Single(String),
    Multiple(Vec<String>),
}

fn load_rule_file(path: &Path) -> Result<LoadedRewriteRule> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read rewrite rule file: {}", path.display()))?;
    let rule = serde_yaml::from_str::<RewriteRuleFile>(&content)
        .with_context(|| format!("failed to parse rewrite rule file: {}", path.display()))?;

    if rule.render.trim().is_empty() {
        anyhow::bail!("rewrite rule `{}` is missing render template", rule.id);
    }

    let template_path = rewrite_template_path(&rule.render);
    let template = fs::read_to_string(&template_path).with_context(|| {
        format!(
            "failed to read rewrite template: {}",
            template_path.display()
        )
    })?;

    let mut matchers = Vec::new();
    for pattern in &rule.match_rules {
        matchers.push(
            Regex::new(pattern).with_context(|| {
                format!("invalid rewrite match regex in `{}`: {pattern}", rule.id)
            })?,
        );
    }

    let hosts = rule
        .hosts
        .iter()
        .map(|host| normalize_host(host))
        .filter(|host| !host.is_empty())
        .collect::<HashSet<_>>();

    let fields = compile_rewrite_fields(&rule)?;

    Ok(LoadedRewriteRule {
        rule,
        hosts,
        matchers,
        fields,
        template,
    })
}

fn load_patch_rule_file(path: &Path) -> Result<LoadedPatchRule> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read patch rule file: {}", path.display()))?;
    let rule = serde_yaml::from_str::<PatchRuleFile>(&content)
        .with_context(|| format!("failed to parse patch rule file: {}", path.display()))?;

    let hosts = rule
        .hosts
        .iter()
        .map(|host| normalize_host(host))
        .filter(|host| !host.is_empty())
        .collect::<HashSet<_>>();

    let mut vars = HashMap::new();
    for (name, item) in rule.vars {
        vars.insert(
            name,
            LoadedVarPatchRule {
                matchers: compile_matchers(&item.match_rules, path)?,
                pipe: normalize_patch_pipe(item.remove, item.pipe),
            },
        );
    }

    let json = match rule.json {
        Some(item) => Some(LoadedJsonPatchRule {
            matchers: compile_matchers(&item.match_rules, path)?,
            pipe: normalize_patch_pipe(item.remove, item.pipe),
        }),
        None => None,
    };

    Ok(LoadedPatchRule {
        enabled: rule.enabled,
        hosts,
        vars,
        json,
    })
}

impl LoadedPatchRule {
    fn matches_response(&self, page_url: &str, content_type: &str) -> bool {
        if is_html_content_type(content_type)
            && self
                .vars
                .values()
                .any(|rule| matches_any(&rule.matchers, page_url))
        {
            return true;
        }

        if is_json_content_type(content_type) {
            return self
                .json
                .as_ref()
                .is_some_and(|rule| matches_any(&rule.matchers, page_url));
        }

        false
    }

    fn apply(
        &self,
        response_body: &[u8],
        page_url: &str,
        content_type: &str,
    ) -> Result<PatchApplyResult> {
        let mut current = response_body.to_vec();
        let mut modified = false;

        if is_html_content_type(content_type) {
            let html = String::from_utf8_lossy(&current).into_owned();
            let mut rewritten_html = html.clone();
            let mut html_modified = false;

            for (variable_name, rule) in &self.vars {
                if !matches_any(&rule.matchers, page_url) {
                    continue;
                }
                let (next_html, changed) =
                    apply_html_var_patch(&rewritten_html, variable_name, &rule.pipe)?;
                if changed {
                    rewritten_html = next_html;
                    html_modified = true;
                }
            }

            if html_modified {
                current = rewritten_html.into_bytes();
                modified = true;
            }
        }

        if is_json_content_type(content_type) {
            if let Some(rule) = &self.json {
                if matches_any(&rule.matchers, page_url) {
                    let (next_body, changed) = apply_json_patch(&current, &rule.pipe)?;
                    if changed {
                        current = next_body;
                        modified = true;
                    }
                }
            }
        }

        Ok(PatchApplyResult {
            body: current,
            modified,
        })
    }
}

fn extract_field_value(
    document: &Html,
    _field_name: &str,
    field_rule: &LoadedRewriteFieldRule,
    context: &HashMap<String, FieldValue>,
) -> Result<Option<FieldValue>> {
    let value_mode = field_rule.value.as_deref().unwrap_or("text");

    if field_rule.multiple {
        let mut values = Vec::new();

        for element in document.select(&field_rule.selector) {
            let raw = read_element_value(element, value_mode);
            let Some(value) = run_pipe_single(raw, &field_rule.pipe, context)? else {
                continue;
            };
            if !value.is_empty() {
                values.push(value);
            }
        }

        let values = run_pipe_multiple(values, &field_rule.pipe)?;
        if values.is_empty() {
            return Ok(None);
        }

        return Ok(Some(FieldValue::Multiple(values)));
    }

    let raw = document
        .select(&field_rule.selector)
        .next()
        .map(|element| read_element_value(element, value_mode))
        .unwrap_or_default();

    let Some(value) = run_pipe_single(raw, &field_rule.pipe, context)? else {
        return Ok(None);
    };

    if value.is_empty() {
        return Ok(None);
    }

    Ok(Some(FieldValue::Single(value)))
}

fn apply_html_var_patch(
    document: &str,
    variable_name: &str,
    pipe: &[PatchPipeStep],
) -> Result<(String, bool)> {
    let Some((value_range, object_text)) = find_js_object_assignment(document, variable_name)
    else {
        return Ok((document.to_string(), false));
    };

    let Ok(mut json) = serde_json::from_str::<JsonValue>(&object_text) else {
        return Ok((document.to_string(), false));
    };

    let changed = run_patch_pipe_on_json(&mut json, pipe);
    if !changed {
        return Ok((document.to_string(), false));
    }

    let mut rewritten = String::with_capacity(document.len());
    rewritten.push_str(&document[..value_range.start]);
    rewritten.push_str(&json.to_string());
    rewritten.push_str(&document[value_range.end..]);
    Ok((rewritten, true))
}

fn apply_json_patch(response_body: &[u8], pipe: &[PatchPipeStep]) -> Result<(Vec<u8>, bool)> {
    let Ok(mut json) = serde_json::from_slice::<JsonValue>(response_body) else {
        return Ok((response_body.to_vec(), false));
    };

    let changed = run_patch_pipe_on_json(&mut json, pipe);
    if !changed {
        return Ok((response_body.to_vec(), false));
    }

    Ok((serde_json::to_vec(&json)?, true))
}

fn run_patch_pipe_on_json(value: &mut JsonValue, pipe: &[PatchPipeStep]) -> bool {
    let mut changed = false;
    for step in pipe {
        match step {
            PatchPipeStep::Remove { keys } => {
                if remove_keys_recursive(value, keys) {
                    changed = true;
                }
            }
        }
    }
    changed
}

fn remove_keys_recursive(value: &mut JsonValue, keys: &[String]) -> bool {
    match value {
        JsonValue::Object(map) => {
            let mut changed = false;
            for key in keys {
                if map.remove(key).is_some() {
                    changed = true;
                }
            }
            for child in map.values_mut() {
                if remove_keys_recursive(child, keys) {
                    changed = true;
                }
            }
            changed
        }
        JsonValue::Array(items) => items.iter_mut().fold(false, |changed, child| {
            remove_keys_recursive(child, keys) || changed
        }),
        _ => false,
    }
}

fn read_element_value(element: ElementRef<'_>, value_mode: &str) -> String {
    if value_mode.contains('|') {
        for candidate in value_mode.split('|') {
            let value = read_element_value(element, candidate.trim());
            if !value.is_empty() {
                return value;
            }
        }
        return String::new();
    }

    if value_mode == "text" {
        return normalize_text(&element.text().collect::<String>());
    }

    if value_mode == "@srcset_url" {
        return normalize_text(&parse_first_srcset_url(
            element.value().attr("srcset").unwrap_or_default(),
        ));
    }

    if let Some(attr_name) = value_mode.strip_prefix('@') {
        return normalize_text(element.value().attr(attr_name).unwrap_or_default());
    }

    normalize_text(&element.text().collect::<String>())
}

fn run_pipe_single(
    mut current_value: String,
    pipe: &[LoadedRewritePipeStep],
    base_context: &HashMap<String, FieldValue>,
) -> Result<Option<String>> {
    let mut local_context = HashMap::<String, String>::new();

    for step in pipe {
        match step {
            LoadedRewritePipeStep::Regex { regex } => {
                let captures = regex_captures(regex, &current_value);
                for (name, value) in captures {
                    local_context.insert(name, value);
                }
            }
            LoadedRewritePipeStep::Template { template } => {
                current_value =
                    render_string_template(template, &current_value, &local_context, base_context);
            }
            LoadedRewritePipeStep::NotEmpty(Some(notempty)) => {
                let target =
                    render_string_template(notempty, &current_value, &local_context, base_context);
                if target.trim().is_empty() {
                    return Ok(None);
                }
            }
            LoadedRewritePipeStep::NotEmpty(None) => {
                if current_value.trim().is_empty() {
                    return Ok(None);
                }
            }
            LoadedRewritePipeStep::AbsoluteUrlMap { absolute_url } => {
                let base = render_string_template(
                    &absolute_url.base,
                    &current_value,
                    &local_context,
                    base_context,
                );
                current_value = to_absolute_url(&current_value, &base);
            }
            LoadedRewritePipeStep::Trim => {
                current_value = current_value.trim().to_string();
            }
            LoadedRewritePipeStep::Unique | LoadedRewritePipeStep::JoinMap { .. } => {}
        }
    }

    Ok(Some(current_value))
}

fn run_pipe_multiple(
    mut values: Vec<String>,
    pipe: &[LoadedRewritePipeStep],
) -> Result<Vec<String>> {
    for step in pipe {
        match step {
            LoadedRewritePipeStep::Unique => {
                let mut seen = HashSet::new();
                let mut deduped = Vec::new();
                for value in values {
                    if seen.insert(value.clone()) {
                        deduped.push(value);
                    }
                }
                values = deduped;
            }
            LoadedRewritePipeStep::JoinMap { join } => {
                values = vec![values.join(join)];
            }
            _ => {}
        }
    }

    Ok(values)
}

fn regex_captures(regex: &Regex, value: &str) -> HashMap<String, String> {
    let Some(captures) = regex.captures(value) else {
        return HashMap::new();
    };

    let mut result = HashMap::new();
    for name in regex.capture_names().flatten() {
        if let Some(matched) = captures.name(name) {
            result.insert(name.to_string(), matched.as_str().to_string());
        }
    }

    result
}

fn collect_yaml_paths(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut paths = fs::read_dir(dir)
        .with_context(|| format!("failed to read YAML rule dir: {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|item| item.path()))
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn compile_matchers(patterns: &[String], path: &Path) -> Result<Vec<Regex>> {
    let mut matchers = Vec::new();
    for pattern in patterns {
        matchers.push(Regex::new(pattern).with_context(|| {
            format!(
                "invalid patch match regex in `{}`: {pattern}",
                path.display()
            )
        })?);
    }
    Ok(matchers)
}

fn compile_rewrite_fields(
    rule: &RewriteRuleFile,
) -> Result<HashMap<String, LoadedRewriteFieldRule>> {
    let mut fields = HashMap::new();
    for (field_name, field_rule) in &rule.fields {
        let selector = Selector::parse(&field_rule.select).map_err(|error| {
            anyhow::anyhow!(
                "invalid CSS selector for rewrite rule `{}` field `{}`: {}",
                rule.id,
                field_name,
                error
            )
        })?;
        fields.insert(
            field_name.clone(),
            LoadedRewriteFieldRule {
                value: field_rule.value.clone(),
                multiple: field_rule.multiple,
                pipe: compile_rewrite_pipe(&field_rule.pipe, rule, field_name)?,
                selector,
            },
        );
    }
    Ok(fields)
}

fn compile_rewrite_pipe(
    pipe: &[RewritePipeStep],
    rule: &RewriteRuleFile,
    field_name: &str,
) -> Result<Vec<LoadedRewritePipeStep>> {
    let mut loaded = Vec::with_capacity(pipe.len());
    for step in pipe {
        loaded.push(match step {
            RewritePipeStep::Regex { regex } => LoadedRewritePipeStep::Regex {
                regex: Regex::new(regex).with_context(|| {
                    format!(
                        "invalid regex in rewrite rule `{}` field `{}`: {}",
                        rule.id, field_name, regex
                    )
                })?,
            },
            RewritePipeStep::Template { template } => LoadedRewritePipeStep::Template {
                template: template.clone(),
            },
            RewritePipeStep::NotEmpty(value) => LoadedRewritePipeStep::NotEmpty(value.clone()),
            RewritePipeStep::AbsoluteUrlMap { absolute_url } => {
                LoadedRewritePipeStep::AbsoluteUrlMap {
                    absolute_url: absolute_url.clone(),
                }
            }
            RewritePipeStep::Unique => LoadedRewritePipeStep::Unique,
            RewritePipeStep::JoinMap { join } => {
                LoadedRewritePipeStep::JoinMap { join: join.clone() }
            }
            RewritePipeStep::Trim => LoadedRewritePipeStep::Trim,
        });
    }
    Ok(loaded)
}

fn normalize_patch_pipe(remove: Vec<String>, mut pipe: Vec<PatchPipeStep>) -> Vec<PatchPipeStep> {
    if !remove.is_empty() {
        pipe.insert(0, PatchPipeStep::Remove { keys: remove });
    }
    pipe
}

fn matches_any(matchers: &[Regex], page_url: &str) -> bool {
    !matchers.is_empty() && matchers.iter().any(|regex| regex.is_match(page_url))
}

fn render_template(template: &str, context: &HashMap<String, FieldValue>) -> String {
    render_template_placeholders(template, |key| context.get(key).map(field_value_as_text))
}

fn render_string_template(
    template: &str,
    current_value: &str,
    local_context: &HashMap<String, String>,
    global_context: &HashMap<String, FieldValue>,
) -> String {
    render_template_placeholders(template, |key| {
        if key == "value" {
            return Some(current_value.to_string());
        }
        if let Some(value) = local_context.get(key) {
            return Some(value.clone());
        }
        global_context.get(key).map(field_value_as_text)
    })
}

fn render_template_placeholders<F>(template: &str, mut resolve: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    let mut output = String::with_capacity(template.len());
    let mut cursor = 0;

    while let Some(start_offset) = template[cursor..].find("{{") {
        let start = cursor + start_offset;
        output.push_str(&template[cursor..start]);

        let placeholder_start = start + 2;
        let Some(end_offset) = template[placeholder_start..].find("}}") else {
            output.push_str(&template[start..]);
            return output;
        };
        let end = placeholder_start + end_offset;
        let key = &template[placeholder_start..end];
        if let Some(value) = resolve(key) {
            output.push_str(&value);
        }
        cursor = end + 2;
    }

    output.push_str(&template[cursor..]);
    output
}

fn field_value_as_text(value: &FieldValue) -> String {
    match value {
        FieldValue::Single(text) => text.clone(),
        FieldValue::Multiple(values) => values.join(" / "),
    }
}

fn default_template_context(page_url: &str) -> HashMap<String, FieldValue> {
    let mut context = HashMap::new();
    context.insert(
        "request.url".to_string(),
        FieldValue::Single(page_url.to_string()),
    );
    context.insert(
        "request.path_slug_upper".to_string(),
        FieldValue::Single(extract_slug_from_url(page_url).to_uppercase()),
    );
    context.insert(
        "request.rgoff_url".to_string(),
        FieldValue::Single(add_render_bypass_magic_word(page_url)),
    );
    context
}

fn has_render_bypass_magic_word(page_url: &str) -> bool {
    let Ok(url) = url::Url::parse(page_url) else {
        return page_url.contains("?rgoff") || page_url.contains("&rgoff");
    };

    url.query_pairs().any(|(key, _)| key == "rgoff")
}

fn add_render_bypass_magic_word(page_url: &str) -> String {
    let Ok(mut url) = url::Url::parse(page_url) else {
        if page_url.contains('?') {
            return format!("{page_url}&rgoff");
        }
        return format!("{page_url}?rgoff");
    };

    if url.query_pairs().any(|(key, _)| key == "rgoff") {
        return url.to_string();
    }

    let mut pairs = url.query_pairs_mut();
    pairs.append_pair("rgoff", "");
    drop(pairs);
    url.to_string()
}

fn rewrite_sites_dir() -> PathBuf {
    find_existing_subdir(&["data", "rewrite"])
        .unwrap_or_else(|| preferred_base_dir().join("data").join("rewrite"))
}

fn patch_sites_dir() -> PathBuf {
    find_existing_subdir(&["data", "patch"])
        .unwrap_or_else(|| preferred_base_dir().join("data").join("patch"))
}

pub fn render_rule_dir() -> PathBuf {
    rewrite_sites_dir()
}

pub fn patch_rule_dir() -> PathBuf {
    patch_sites_dir()
}

fn rewrite_template_path(file_name: &str) -> PathBuf {
    find_existing_file(&["data", "rewrite"], file_name).unwrap_or_else(|| {
        preferred_base_dir()
            .join("data")
            .join("rewrite")
            .join(file_name)
    })
}

fn app_base_dir() -> Result<PathBuf> {
    let exe = env::current_exe().context("failed to resolve current executable path")?;
    let base_dir = exe.parent().ok_or_else(|| {
        anyhow::anyhow!("current executable path does not have a parent directory")
    })?;
    Ok(base_dir.to_path_buf())
}

fn candidate_base_dirs() -> Vec<PathBuf> {
    vec![preferred_base_dir()]
}

fn preferred_base_dir() -> PathBuf {
    match app_path_mode() {
        AppPathMode::Workspace => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        AppPathMode::Portable => app_base_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

fn find_existing_subdir(parts: &[&str]) -> Option<PathBuf> {
    for base_dir in candidate_base_dirs() {
        let candidate = parts.iter().fold(base_dir, |path, part| path.join(part));
        if candidate.is_dir() {
            return Some(candidate);
        }
    }

    None
}

fn find_existing_file(dir_parts: &[&str], file_name: &str) -> Option<PathBuf> {
    for base_dir in candidate_base_dirs() {
        let dir = dir_parts
            .iter()
            .fold(base_dir, |path, part| path.join(part));
        let candidate = dir.join(file_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

fn to_absolute_url(value: &str, base: &str) -> String {
    if value.starts_with("http://") || value.starts_with("https://") {
        return value.to_string();
    }

    if value.starts_with("//") {
        return format!("https:{value}");
    }

    if let Ok(base_url) = url::Url::parse(base) {
        if let Ok(url) = base_url.join(value) {
            return url.to_string();
        }
    }

    value.to_string()
}

fn extract_slug_from_url(url: &str) -> String {
    url.split('/')
        .filter(|segment| !segment.is_empty())
        .next_back()
        .unwrap_or_default()
        .to_string()
}

fn normalize_text(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

fn parse_first_srcset_url(srcset: &str) -> String {
    srcset
        .split(',')
        .next()
        .map(|entry| {
            entry
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .unwrap_or_default()
}

fn yaml_string(value: YamlValue) -> Result<String, String> {
    value
        .as_str()
        .map(|text| text.to_string())
        .ok_or_else(|| "pipe step value must be string".to_string())
}

fn yaml_string_list(value: YamlValue) -> Result<Vec<String>, String> {
    let Some(items) = value.as_sequence() else {
        return Err("patch pipe step value must be string array".to_string());
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(|text| text.to_string())
                .ok_or_else(|| "patch pipe step array items must be string".to_string())
        })
        .collect()
}

fn is_json_content_type(content_type: &str) -> bool {
    content_type.contains("json")
}

fn is_html_content_type(content_type: &str) -> bool {
    content_type.contains("text/html") || content_type.contains("application/xhtml")
}

fn is_patch_candidate_content_type(content_type: &str) -> bool {
    is_html_content_type(content_type) || is_json_content_type(content_type)
}

fn find_js_object_assignment(
    document: &str,
    variable_name: &str,
) -> Option<(Range<usize>, String)> {
    let assignment = format!("{variable_name} =");
    let start = document.find(&assignment)?;
    let after_assignment = start + assignment.len();
    let object_start = document[after_assignment..]
        .char_indices()
        .find_map(|(offset, ch)| (ch == '{').then_some(after_assignment + offset))?;
    let object_end = find_balanced_json_object_end(document, object_start)?;
    Some((
        object_start..object_end,
        document[object_start..object_end].to_string(),
    ))
}

fn find_balanced_json_object_end(document: &str, object_start: usize) -> Option<usize> {
    let bytes = document.as_bytes();
    let mut index = object_start;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }

    None
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
