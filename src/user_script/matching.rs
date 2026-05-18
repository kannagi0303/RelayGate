use regex::Regex;
use url::Url;

use super::model::UserScriptMetadata;

#[derive(Debug, Clone)]
pub(crate) struct CompiledUserScriptMatcher {
    matches: Vec<CompiledMatchPattern>,
    includes: Vec<CompiledWildcardPattern>,
    exclude_matches: Vec<CompiledMatchPattern>,
    excludes: Vec<CompiledWildcardPattern>,
}

#[derive(Debug, Clone)]
struct CompiledMatchPattern {
    scheme: CompiledSchemePattern,
    host: CompiledHostPattern,
    path: CompiledWildcardPattern,
}

#[derive(Debug, Clone, Copy)]
enum CompiledSchemePattern {
    HttpAndHttps,
    Http,
    Https,
    Unsupported,
}

#[derive(Debug, Clone)]
struct CompiledHostPattern {
    pattern: String,
}

#[derive(Debug, Clone)]
struct CompiledWildcardPattern {
    regex: Regex,
}

impl CompiledUserScriptMatcher {
    pub(crate) fn compile(metadata: &UserScriptMetadata) -> Self {
        Self {
            matches: metadata
                .matches
                .iter()
                .map(|pattern| CompiledMatchPattern::compile(pattern))
                .collect(),
            includes: metadata
                .includes
                .iter()
                .filter_map(|pattern| CompiledWildcardPattern::compile(pattern).ok())
                .collect(),
            exclude_matches: metadata
                .exclude_matches
                .iter()
                .map(|pattern| CompiledMatchPattern::compile(pattern))
                .collect(),
            excludes: metadata
                .excludes
                .iter()
                .filter_map(|pattern| CompiledWildcardPattern::compile(pattern).ok())
                .collect(),
        }
    }

    pub(crate) fn matches(&self, target_url: &str) -> bool {
        let clean_url = strip_url_fragment(target_url);
        let parsed_url = Url::parse(&clean_url).ok();

        if self
            .excludes
            .iter()
            .any(|pattern| pattern.matches(&clean_url))
        {
            return false;
        }
        if let Some(url) = parsed_url.as_ref() {
            if self
                .exclude_matches
                .iter()
                .any(|pattern| pattern.matches(url))
            {
                return false;
            }
        }

        self.includes
            .iter()
            .any(|pattern| pattern.matches(&clean_url))
            || parsed_url
                .as_ref()
                .map(|url| self.matches.iter().any(|pattern| pattern.matches(url)))
                .unwrap_or(false)
    }
}

impl CompiledMatchPattern {
    fn compile(pattern: &str) -> Self {
        let Some((scheme_pattern, rest)) = pattern.split_once("://") else {
            return Self::unsupported();
        };
        let (host_pattern, path_pattern) = rest
            .split_once('/')
            .map(|(host, path)| (host, format!("/{path}")))
            .unwrap_or((rest, "/*".to_string()));

        Self {
            scheme: CompiledSchemePattern::compile(scheme_pattern),
            host: CompiledHostPattern::compile(host_pattern),
            path: CompiledWildcardPattern::compile(&path_pattern)
                .unwrap_or_else(|_| CompiledWildcardPattern::never()),
        }
    }

    fn unsupported() -> Self {
        Self {
            scheme: CompiledSchemePattern::Unsupported,
            host: CompiledHostPattern::compile(""),
            path: CompiledWildcardPattern::never(),
        }
    }

    fn matches(&self, url: &Url) -> bool {
        self.scheme.matches(url.scheme())
            && url
                .host_str()
                .map(|host| self.host.matches(host))
                .unwrap_or(false)
            && self.path.matches(url.path())
    }
}

impl CompiledSchemePattern {
    fn compile(pattern: &str) -> Self {
        match pattern {
            "*" => Self::HttpAndHttps,
            "http" => Self::Http,
            "https" => Self::Https,
            _ => Self::Unsupported,
        }
    }

    fn matches(self, scheme: &str) -> bool {
        match self {
            Self::HttpAndHttps => matches!(scheme, "http" | "https"),
            Self::Http => scheme == "http",
            Self::Https => scheme == "https",
            Self::Unsupported => false,
        }
    }
}

impl CompiledHostPattern {
    fn compile(pattern: &str) -> Self {
        Self {
            pattern: pattern.trim_start_matches("*.").to_ascii_lowercase(),
        }
    }

    fn matches(&self, host: &str) -> bool {
        if self.pattern == "*" {
            return true;
        }
        let host = host.to_ascii_lowercase();
        host == self.pattern || host.ends_with(&format!(".{}", self.pattern))
    }
}

impl CompiledWildcardPattern {
    fn compile(pattern: &str) -> Result<Self, regex::Error> {
        Regex::new(&wildcard_to_regex(pattern)).map(|regex| Self { regex })
    }

    fn never() -> Self {
        Self {
            regex: Regex::new("a^").expect("valid never-matching regex"),
        }
    }

    fn matches(&self, value: &str) -> bool {
        self.regex.is_match(value)
    }
}

pub(crate) fn scope_summary(metadata: &UserScriptMetadata) -> String {
    let mut scopes = Vec::new();
    if !metadata.matches.is_empty() {
        scopes.push(format!("@match {}", metadata.matches.join(", ")));
    }
    if !metadata.includes.is_empty() {
        scopes.push(format!("@include {}", metadata.includes.join(", ")));
    }
    if !metadata.exclude_matches.is_empty() {
        scopes.push(format!(
            "@exclude-match {}",
            metadata.exclude_matches.join(", ")
        ));
    }
    if !metadata.excludes.is_empty() {
        scopes.push(format!("@exclude {}", metadata.excludes.join(", ")));
    }
    scopes.join(" / ")
}

fn wildcard_to_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            other => regex.push_str(&regex::escape(&other.to_string())),
        }
    }
    regex.push('$');
    regex
}

fn strip_url_fragment(target_url: &str) -> String {
    target_url
        .split_once('#')
        .map(|(head, _)| head.to_string())
        .unwrap_or_else(|| target_url.to_string())
}
