use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::{
    adblock::{self, SharedAdblockState},
    html_codec::DecodedHtml,
    user_script::{self, SharedUserScriptRegistry},
};

#[derive(Debug, Clone)]
pub(crate) struct DocumentInjectionResult {
    pub(crate) body: Vec<u8>,
    pub(crate) adblock_injected: bool,
    pub(crate) user_script_injected: bool,
}

impl DocumentInjectionResult {
    pub(crate) fn injected(&self) -> bool {
        self.adblock_injected || self.user_script_injected
    }
}

/// Inject all RelayGate document snippets in one decode/insert pass.
///
/// Keeping adblock and user-script snippets in a single insertion prevents the
/// second injector from being placed before the first one at the start of
/// `<head>`. The intended order is always:
///
/// 1. adblock cosmetic/scriptlet runtime
/// 2. user-script isolated runtime
pub(crate) async fn inject_relaygate_document(
    target_url: &str,
    response_body: Vec<u8>,
    content_type: Option<&str>,
    adblock_state: &SharedAdblockState,
    user_script_registry: &SharedUserScriptRegistry,
    is_frame: Option<bool>,
) -> DocumentInjectionResult {
    let adblock_snippet =
        adblock::render_document_injection(adblock_state, target_url, &response_body);
    let user_script_snippet =
        user_script::render_document_injection(user_script_registry, target_url, is_frame).await;

    let adblock_injected = adblock_snippet.is_some();
    let user_script_injected = user_script_snippet.is_some();

    let mut snippets = Vec::new();
    if let Some(snippet) = adblock_snippet {
        snippets.push(snippet);
    }
    if let Some(snippet) = user_script_snippet {
        snippets.push(snippet);
    }

    if snippets.is_empty() {
        return DocumentInjectionResult {
            body: response_body,
            adblock_injected,
            user_script_injected,
        };
    }

    let decoded = DecodedHtml::decode(&response_body, content_type);
    let document = decoded.text();
    let snippet = snippets.join("\n");

    DocumentInjectionResult {
        body: decoded.encode(&inject_html_snippet(document, &snippet)),
        adblock_injected,
        user_script_injected,
    }
}

pub(crate) fn apply_relaygate_csp_headers(
    headers: &mut HeaderMap,
    csp_directives: Option<String>,
    injected: bool,
) -> Result<()> {
    let csp_directives = csp_directives.filter(|item| !item.trim().is_empty());

    if csp_directives.is_none() && !injected {
        return Ok(());
    }

    headers.remove("content-security-policy");
    headers.remove("content-security-policy-report-only");

    let Some(csp_directives) = csp_directives else {
        return Ok(());
    };

    let csp_directives = if injected {
        allow_inline_relaygate_injection(&csp_directives)
    } else {
        csp_directives
    };

    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_str(&csp_directives)
            .context("failed to encode adblock CSP directives as header value")?,
    );

    Ok(())
}

fn allow_inline_relaygate_injection(policy: &str) -> String {
    policy
        .split(';')
        .map(str::trim)
        .filter(|directive| !directive.is_empty())
        .map(|directive| relax_inline_directive(directive))
        .collect::<Vec<_>>()
        .join("; ")
}

fn relax_inline_directive(directive: &str) -> String {
    let mut parts = directive.split_whitespace();
    let Some(name) = parts.next() else {
        return directive.to_string();
    };

    let name_lower = name.to_ascii_lowercase();
    if name_lower != "script-src" && name_lower != "style-src" {
        return directive.to_string();
    }

    let mut tokens = parts
        .filter(|token| *token != "'none'")
        .map(str::to_string)
        .collect::<Vec<_>>();

    if !tokens.iter().any(|token| token == "'unsafe-inline'") {
        tokens.push("'unsafe-inline'".to_string());
    }

    if tokens.is_empty() {
        name.to_string()
    } else {
        format!("{} {}", name, tokens.join(" "))
    }
}

fn inject_html_snippet(document: &str, snippet: &str) -> String {
    let lower = document.to_ascii_lowercase();
    if let Some(head_start) = lower.find("<head") {
        if let Some(head_end_offset) = lower[head_start..].find('>') {
            let index = head_start + head_end_offset + 1;
            let mut output = String::with_capacity(document.len() + snippet.len() + 1);
            output.push_str(&document[..index]);
            output.push('\n');
            output.push_str(snippet);
            output.push('\n');
            output.push_str(&document[index..]);
            return output;
        }
    }

    if let Some(index) = lower.find("</head>") {
        let mut output = String::with_capacity(document.len() + snippet.len() + 1);
        output.push_str(&document[..index]);
        output.push_str(snippet);
        output.push('\n');
        output.push_str(&document[index..]);
        return output;
    }

    if let Some(index) = lower.find("</body>") {
        let mut output = String::with_capacity(document.len() + snippet.len() + 1);
        output.push_str(&document[..index]);
        output.push_str(snippet);
        output.push('\n');
        output.push_str(&document[index..]);
        return output;
    }

    let mut output = String::with_capacity(document.len() + snippet.len() + 1);
    output.push_str(snippet);
    output.push('\n');
    output.push_str(document);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relaxes_inline_script_and_style_directives_only() {
        let policy = "default-src 'self'; script-src 'none'; style-src 'self'; img-src https:";
        let relaxed = allow_inline_relaygate_injection(policy);

        assert!(relaxed.contains("default-src 'self'"));
        assert!(relaxed.contains("script-src 'unsafe-inline'"));
        assert!(relaxed.contains("style-src 'self' 'unsafe-inline'"));
        assert!(relaxed.contains("img-src https:"));
        assert!(!relaxed.contains("script-src 'none'"));
    }

    #[test]
    fn injects_snippet_after_head_start() {
        let document = "<!doctype html><html><head><title>x</title></head><body></body></html>";
        let injected = inject_html_snippet(document, "<script>1</script>");

        assert!(injected.contains("<head>\n<script>1</script>\n<title>x</title>"));
    }
}
