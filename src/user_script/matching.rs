use regex::Regex;
use url::Url;

use super::model::UserScriptMetadata;

pub(crate) fn scope_summary(metadata: &UserScriptMetadata) -> String {
    let mut scopes = Vec::new();
    if !metadata.matches.is_empty() {
        scopes.push(format!("@match {}", metadata.matches.join(", ")));
    }
    if !metadata.includes.is_empty() {
        scopes.push(format!("@include {}", metadata.includes.join(", ")));
    }
    if !metadata.excludes.is_empty() {
        scopes.push(format!("@exclude {}", metadata.excludes.join(", ")));
    }
    scopes.join(" / ")
}

pub(crate) fn scope_matches(metadata: &UserScriptMetadata, target_url: &str) -> bool {
    let clean_url = strip_url_fragment(target_url);
    if metadata
        .excludes
        .iter()
        .any(|pattern| include_pattern_matches(pattern, &clean_url))
    {
        return false;
    }

    metadata
        .matches
        .iter()
        .any(|pattern| match_pattern_matches(pattern, &clean_url))
        || metadata
            .includes
            .iter()
            .any(|pattern| include_pattern_matches(pattern, &clean_url))
}

fn match_pattern_matches(pattern: &str, target_url: &str) -> bool {
    let Ok(url) = Url::parse(target_url) else {
        return false;
    };
    let Some((scheme_pattern, rest)) = pattern.split_once("://") else {
        return false;
    };
    let (host_pattern, path_pattern) = rest
        .split_once('/')
        .map(|(host, path)| (host, format!("/{path}")))
        .unwrap_or((rest, "/*".to_string()));

    let scheme_ok = match scheme_pattern {
        "*" => matches!(url.scheme(), "http" | "https"),
        "http" | "https" => scheme_pattern == url.scheme(),
        _ => false,
    };
    if !scheme_ok {
        return false;
    }

    let Some(host) = url.host_str() else {
        return false;
    };
    if !host_pattern_matches(host_pattern, host) {
        return false;
    }

    wildcard_matches(&path_pattern, url.path())
}

fn include_pattern_matches(pattern: &str, target_url: &str) -> bool {
    wildcard_matches(pattern, target_url)
}

fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_start_matches("*.");
    if pattern == "*" {
        return true;
    }
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let mut regex = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            other => regex.push_str(&regex::escape(&other.to_string())),
        }
    }
    regex.push('$');
    Regex::new(&regex)
        .map(|compiled| compiled.is_match(value))
        .unwrap_or(false)
}

fn strip_url_fragment(target_url: &str) -> String {
    target_url
        .split_once('#')
        .map(|(head, _)| head.to_string())
        .unwrap_or_else(|| target_url.to_string())
}
