use std::{cell::RefCell, rc::Rc};

use anyhow::{Context, Result};
use lol_html::{element, rewrite_str, text, RewriteStrSettings};

use crate::config::{MinimalPageMode, MountSiteConfig};

/// Apply a very small HTML link rewrite layer.
/// The goal is to keep users inside the local mount path after they enter through `/sukebei/`.
///
/// This is not a full HTML parser. If more stability is needed later, replace it with a real DOM or HTML rewrite flow.
pub fn rewrite_html_links(body: &[u8], mount: &MountSiteConfig) -> Result<Vec<u8>> {
    let html = String::from_utf8_lossy(body).to_string();
    let origin = mount.target_base_url.trim_end_matches('/');
    let mount_prefix = mount.mount_path.trim_end_matches('/');
    let origin_host = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let mut rewritten = html;

    for attr in ["href", "src", "action"] {
        rewritten = rewrite_attr_double_quoted(&rewritten, attr, "/", &format!("{mount_prefix}/"));
        rewritten = rewrite_attr_single_quoted(&rewritten, attr, "/", &format!("{mount_prefix}/"));

        rewritten = rewrite_attr_double_quoted(
            &rewritten,
            attr,
            &format!("{origin}/"),
            &format!("{mount_prefix}/"),
        );
        rewritten = rewrite_attr_single_quoted(
            &rewritten,
            attr,
            &format!("{origin}/"),
            &format!("{mount_prefix}/"),
        );

        rewritten = rewrite_attr_double_quoted(
            &rewritten,
            attr,
            &format!("https://{origin_host}/"),
            &format!("{mount_prefix}/"),
        );
        rewritten = rewrite_attr_single_quoted(
            &rewritten,
            attr,
            &format!("https://{origin_host}/"),
            &format!("{mount_prefix}/"),
        );

        rewritten = rewrite_attr_double_quoted(
            &rewritten,
            attr,
            &format!("http://{origin_host}/"),
            &format!("{mount_prefix}/"),
        );
        rewritten = rewrite_attr_single_quoted(
            &rewritten,
            attr,
            &format!("http://{origin_host}/"),
            &format!("{mount_prefix}/"),
        );

        rewritten = rewrite_attr_double_quoted(
            &rewritten,
            attr,
            &format!("//{origin_host}/"),
            &format!("{mount_prefix}/"),
        );
        rewritten = rewrite_attr_single_quoted(
            &rewritten,
            attr,
            &format!("//{origin_host}/"),
            &format!("{mount_prefix}/"),
        );
    }

    // `srcset` usually contains multiple comma-separated URL entries.
    rewritten = rewrite_attr_double_quoted(&rewritten, "srcset", "/", &format!("{mount_prefix}/"));
    rewritten = rewrite_attr_single_quoted(&rewritten, "srcset", "/", &format!("{mount_prefix}/"));
    rewritten = rewrite_attr_double_quoted(
        &rewritten,
        "srcset",
        &format!("{origin}/"),
        &format!("{mount_prefix}/"),
    );
    rewritten = rewrite_attr_single_quoted(
        &rewritten,
        "srcset",
        &format!("{origin}/"),
        &format!("{mount_prefix}/"),
    );
    rewritten = rewrite_attr_double_quoted(
        &rewritten,
        "srcset",
        &format!("https://{origin_host}/"),
        &format!("{mount_prefix}/"),
    );
    rewritten = rewrite_attr_single_quoted(
        &rewritten,
        "srcset",
        &format!("https://{origin_host}/"),
        &format!("{mount_prefix}/"),
    );
    rewritten = rewrite_attr_double_quoted(
        &rewritten,
        "srcset",
        &format!("http://{origin_host}/"),
        &format!("{mount_prefix}/"),
    );
    rewritten = rewrite_attr_single_quoted(
        &rewritten,
        "srcset",
        &format!("http://{origin_host}/"),
        &format!("{mount_prefix}/"),
    );
    rewritten = rewrite_attr_double_quoted(
        &rewritten,
        "srcset",
        &format!("//{origin_host}/"),
        &format!("{mount_prefix}/"),
    );
    rewritten = rewrite_attr_single_quoted(
        &rewritten,
        "srcset",
        &format!("//{origin_host}/"),
        &format!("{mount_prefix}/"),
    );

    // Some sites also put resource URLs in meta refresh or CSS `url(...)`.
    rewritten = rewritten.replace(r#"content="/""#, &format!(r#"content="{mount_prefix}/"#));
    rewritten = rewritten.replace(r#"content='/"#, &format!(r#"content='{mount_prefix}/"#));
    rewritten = rewritten.replace(
        &format!(r#"content="{origin}/"#),
        &format!(r#"content="{mount_prefix}/"#),
    );
    rewritten = rewritten.replace(
        &format!(r#"content='{origin}/"#),
        &format!(r#"content='{mount_prefix}/"#),
    );
    rewritten = rewritten.replace(
        &format!(r#"content="https://{origin_host}/"#),
        &format!(r#"content="{mount_prefix}/"#),
    );
    rewritten = rewritten.replace(
        &format!(r#"content='https://{origin_host}/"#),
        &format!(r#"content='{mount_prefix}/"#),
    );
    rewritten = rewritten.replace(
        &format!(r#"content="http://{origin_host}/"#),
        &format!(r#"content="{mount_prefix}/"#),
    );
    rewritten = rewritten.replace(
        &format!(r#"content='http://{origin_host}/"#),
        &format!(r#"content='{mount_prefix}/"#),
    );
    rewritten = rewritten.replace(
        &format!(r#"url({origin}/"#),
        &format!(r#"url({mount_prefix}/"#),
    );
    rewritten = rewritten.replace(
        &format!(r#"url(/{origin_host}/"#),
        &format!(r#"url({mount_prefix}/"#),
    );
    rewritten = rewritten.replace(r#"url(/"#, &format!(r#"url({mount_prefix}/"#));
    rewritten = rewritten.replace(
        &format!(r#"url("{origin}/"#),
        &format!(r#"url("{mount_prefix}/"#),
    );
    rewritten = rewritten.replace(
        &format!(r#"url('{origin}/"#),
        &format!(r#"url('{mount_prefix}/"#),
    );
    rewritten = rewritten.replace(r#"url("/"#, &format!(r#"url("{mount_prefix}/"#));
    rewritten = rewritten.replace(r#"url('/"#, &format!(r#"url('{mount_prefix}/"#));

    Ok(rewritten.into_bytes())
}

/// Render a minimal HTML page for a site-specific mode instead of keeping the original DOM.
pub fn rewrite_minimal_page(
    body: &[u8],
    mount: &MountSiteConfig,
    mode: &MinimalPageMode,
    page_url: &str,
) -> Result<Vec<u8>> {
    match mode {
        MinimalPageMode::OnejavTorrent => rewrite_onejav_minimal_page(body, mount, page_url),
    }
}

/// Rewrite the HTTP redirect `Location` header so the browser stays on the local mount path.
pub fn rewrite_location_header(location: &str, mount: &MountSiteConfig) -> String {
    let origin = mount.target_base_url.trim_end_matches('/');
    let mount_prefix = mount.mount_path.trim_end_matches('/');
    let origin_host = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    if let Some(suffix) = location.strip_prefix(origin) {
        return format!("{mount_prefix}{suffix}");
    }

    if let Some(suffix) = location.strip_prefix(&format!("https://{origin_host}")) {
        return format!("{mount_prefix}{suffix}");
    }

    if let Some(suffix) = location.strip_prefix(&format!("http://{origin_host}")) {
        return format!("{mount_prefix}{suffix}");
    }

    if let Some(suffix) = location.strip_prefix(&format!("//{origin_host}")) {
        return format!("{mount_prefix}{suffix}");
    }

    if location.starts_with('/') {
        return format!("{mount_prefix}{location}");
    }

    location.to_string()
}

/// Rewrite `Set-Cookie` so the remote domain is not fixed into the cookie.
/// This helps local mount mode work more reliably.
/// The first version uses a conservative strategy:
/// - remove `Domain` so the cookie falls back to host-only
/// - rewrite `Path=/xxx` to the mount prefix such as `/sukebei/xxx`
pub fn rewrite_set_cookie_header(set_cookie: &str, mount: &MountSiteConfig) -> String {
    let mount_prefix = mount.mount_path.trim_end_matches('/');
    let mut parts = Vec::new();

    for part in set_cookie.split(';') {
        let trimmed = part.trim();
        let lower = trimmed.to_ascii_lowercase();

        if lower.starts_with("domain=") {
            continue;
        }

        if let Some(path_value) = trimmed.strip_prefix("Path=") {
            let rewritten_path = if path_value.starts_with(mount_prefix) {
                path_value.to_string()
            } else if path_value.starts_with('/') {
                format!("{mount_prefix}{path_value}")
            } else {
                format!("{mount_prefix}/{path_value}")
            };
            parts.push(format!("Path={rewritten_path}"));
            continue;
        }

        parts.push(trimmed.to_string());
    }

    if !parts
        .iter()
        .any(|part| part.to_ascii_lowercase().starts_with("path="))
    {
        parts.push(format!("Path={mount_prefix}/"));
    }

    parts.join("; ")
}

fn rewrite_onejav_minimal_page(
    body: &[u8],
    mount: &MountSiteConfig,
    page_url: &str,
) -> Result<Vec<u8>> {
    let html = String::from_utf8_lossy(body).to_string();
    let extracted = extract_onejav_minimal_data(&html)
        .with_context(|| format!("failed to extract onejav minimal data from {page_url}"))?;

    let cover_url = first_non_empty(&[extracted.cover_url.clone()]);
    let title = first_non_empty(&[extracted.title.clone(), extract_slug_from_url(page_url)]);

    let actress_text = if extracted.actress_names.is_empty() {
        "Actress Unknown".to_string()
    } else {
        extracted.actress_names.join(" / ")
    };
    let torrent_url = first_non_empty(&[extracted.torrent_url.clone()]);

    let resolved_cover = resolve_url(&cover_url, page_url);
    let resolved_torrent = resolve_url(&torrent_url, page_url);

    let minimal_html = format!(
        r#"<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0b0b0b;
      --panel: #171717;
      --text: #f2ede3;
      --muted: #cec6b7;
      --accent: #e9dcc0;
      --accent-text: #131313;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", "Noto Sans TC", sans-serif;
      line-height: 1.45;
    }}
    main {{
      width: min(1120px, 100%);
      margin: 0 auto;
      padding: 24px;
      display: flex;
      gap: 24px;
      align-items: flex-start;
    }}
    .media {{
      width: 640px;
      flex: 0 0 640px;
      max-width: 100%;
      aspect-ratio: 4 / 3;
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--panel);
      border: 1px solid rgba(255,255,255,0.10);
      box-shadow: 0 18px 48px rgba(0,0,0,0.4);
      overflow: hidden;
    }}
    .media img {{
      display: block;
      width: 100%;
      height: 100%;
      object-fit: contain;
    }}
    .info {{
      flex: 1 1 auto;
      min-width: 0;
      display: grid;
      gap: 12px;
      align-content: start;
    }}
    .download {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 48px;
      padding: 0 18px;
      background: var(--accent);
      color: var(--accent-text);
      text-decoration: none;
      font-size: 16px;
      font-weight: 600;
      box-shadow: 0 10px 24px rgba(0,0,0,0.3);
      width: 100%;
    }}
    .title {{
      font-size: 16px;
      font-weight: 600;
      overflow-wrap: anywhere;
    }}
    .actress {{
      font-size: 16px;
      color: var(--muted);
      overflow-wrap: anywhere;
    }}
    .meta {{
      color: #8f8a82;
      font-size: 13px;
      overflow-wrap: anywhere;
    }}
    @media (max-width: 980px) {{
      main {{
        flex-direction: column;
      }}
      .media {{
        width: 100%;
        flex-basis: auto;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="media">
      <img src="{cover}" alt="{title}">
    </section>
    <section class="info">
      <a class="download" href="{torrent}" target="_blank" rel="nofollow noopener noreferrer">下載</a>
      <div class="title">{title}</div>
      <div class="actress">{actress}</div>
      <div class="meta">RelayGate Minimal Mode · {mount_path}</div>
    </section>
  </main>
</body>
</html>"#,
        cover = html_escape(&resolved_cover),
        torrent = html_escape(&resolved_torrent),
        title = html_escape(&title),
        actress = html_escape(&actress_text),
        mount_path = html_escape(&mount.mount_path),
    );

    Ok(minimal_html.into_bytes())
}

#[derive(Default)]
struct OnejavMinimalData {
    cover_url: String,
    title: String,
    actress_names: Vec<String>,
    torrent_url: String,
}

fn extract_onejav_minimal_data(html: &str) -> Result<OnejavMinimalData> {
    let cover_url = Rc::new(RefCell::new(String::new()));
    let meta_title = Rc::new(RefCell::new(String::new()));
    let page_title = Rc::new(RefCell::new(String::new()));
    let torrent_url = Rc::new(RefCell::new(String::new()));
    let actress_names = Rc::new(RefCell::new(Vec::<String>::new()));

    let meta_cover_target = Rc::clone(&cover_url);
    let image_cover_target = Rc::clone(&cover_url);
    let torrent_target = Rc::clone(&torrent_url);
    let meta_title_target = Rc::clone(&meta_title);
    let fallback_title_target = Rc::clone(&page_title);
    let actress_text_target = Rc::clone(&actress_names);
    let actress_meta_target = Rc::clone(&actress_names);

    rewrite_str(
        html,
        RewriteStrSettings {
            element_content_handlers: vec![
                element!(r#"meta[property="og:image"], meta[name="og:image"]"#, move |el| {
                    if let Some(content) = el.get_attribute("content") {
                        let normalized = normalize_text(&content);
                        if !normalized.is_empty() {
                            *meta_cover_target.borrow_mut() = normalized;
                        }
                    }
                    Ok(())
                }),
                element!(r#".card img.image, img.image"#, move |el| {
                    let mut borrow = image_cover_target.borrow_mut();
                    if borrow.is_empty() {
                        let candidate = first_non_empty(&[
                            el.get_attribute("src").unwrap_or_default(),
                            el.get_attribute("data-src").unwrap_or_default(),
                            el.get_attribute("data-lazy-src").unwrap_or_default(),
                            el.get_attribute("data-original").unwrap_or_default(),
                            parse_first_srcset_url(&el.get_attribute("srcset").unwrap_or_default()),
                        ]);
                        let normalized = normalize_text(&candidate);
                        if !normalized.is_empty() {
                            *borrow = normalized;
                        }
                    }
                    Ok(())
                }),
                element!(
                    r#"a[title="Download .torrent"][href], a[href*="/download/"][href], a[href$=".torrent"][href], a[href*=".torrent"][href]"#,
                    move |el| {
                        let mut borrow = torrent_target.borrow_mut();
                        if borrow.is_empty() {
                            if let Some(href) = el.get_attribute("href") {
                                let normalized = normalize_text(&href);
                                if !normalized.is_empty() && !normalized.to_ascii_lowercase().starts_with("magnet:") {
                                    *borrow = normalized;
                                }
                            }
                        }
                        Ok(())
                    }
                ),
                text!("title", move |t| {
                    let chunk = normalize_text(t.as_str());
                    if !chunk.is_empty() {
                        fallback_title_target.borrow_mut().push_str(&chunk);
                    }
                    Ok(())
                }),
                element!(r#"meta[property="og:title"], meta[name="og:title"]"#, move |el| {
                    if let Some(content) = el.get_attribute("content") {
                        let normalized = strip_onejav_site_suffix(&content);
                        if !normalized.is_empty() && !normalized.eq_ignore_ascii_case("onejav") {
                            *meta_title_target.borrow_mut() = normalized;
                        }
                    }
                    Ok(())
                }),
                text!(r#".panel a[href^="/actress/"]"#, move |t| {
                    let chunk = normalize_text(t.as_str());
                    if !chunk.is_empty() {
                        let mut borrow = actress_text_target.borrow_mut();
                        if !borrow.contains(&chunk) {
                            borrow.push(chunk);
                        }
                    }
                    Ok(())
                }),
                element!(r#"meta[name="description"], meta[property="og:description"], meta[name="og:description"]"#, move |el| {
                    let mut borrow = actress_meta_target.borrow_mut();
                    if borrow.is_empty() {
                        if let Some(content) = el.get_attribute("content") {
                            if let Some(found) = extract_actress_from_description(&content) {
                                borrow.push(found);
                            }
                        }
                    }
                    Ok(())
                }),
            ],
            ..RewriteStrSettings::default()
        },
    )
    .context("lol_html failed while extracting onejav minimal data")?;

    let cover_url_value = cover_url.borrow().clone();
    let meta_title_value = meta_title.borrow().clone();
    let fallback_title_value = page_title.borrow().clone();
    let actress_names_value = actress_names.borrow().clone();
    let torrent_url_value = torrent_url.borrow().clone();

    Ok(OnejavMinimalData {
        cover_url: cover_url_value,
        title: first_non_empty(&[
            meta_title_value,
            strip_onejav_site_suffix(&fallback_title_value),
        ]),
        actress_names: actress_names_value,
        torrent_url: torrent_url_value,
    })
}

fn strip_onejav_site_suffix(text: &str) -> String {
    let normalized = normalize_text(text);
    if normalized.is_empty() {
        return String::new();
    }

    let mut value = normalized;
    for suffix in [
        " - onejav - free jav torrents",
        " - onejav",
        " - free jav torrents",
    ] {
        if value.to_ascii_lowercase().ends_with(suffix) {
            let cut_len = value.len().saturating_sub(suffix.len());
            value = value[..cut_len].trim().to_string();
        }
    }

    value
}

fn extract_actress_from_description(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let actress_marker = "actress:";
    let start = lower.find(actress_marker)?;
    let rest = &text[start + actress_marker.len()..];
    let end = rest.find(',').unwrap_or(rest.len());
    let candidate = normalize_text(&rest[..end]);
    if candidate.is_empty() {
        None
    } else {
        Some(candidate)
    }
}

fn rewrite_attr_double_quoted(input: &str, attr: &str, from: &str, to: &str) -> String {
    input.replace(&format!(r#"{attr}="{from}"#), &format!(r#"{attr}="{to}"#))
}

fn rewrite_attr_single_quoted(input: &str, attr: &str, from: &str, to: &str) -> String {
    input.replace(&format!(r#"{attr}='{from}"#), &format!(r#"{attr}='{to}"#))
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

fn extract_slug_from_url(url: &str) -> String {
    url.split('/')
        .filter(|segment| !segment.is_empty())
        .next_back()
        .unwrap_or_default()
        .to_uppercase()
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_default()
}

fn resolve_url(value: &str, page_url: &str) -> String {
    if value.starts_with("http://") || value.starts_with("https://") {
        return value.to_string();
    }

    if value.starts_with("//") {
        return format!("https:{value}");
    }

    if value.starts_with('/') {
        if let Some((scheme_host, _)) = split_origin(page_url) {
            return format!("{scheme_host}{value}");
        }
    }

    if value.is_empty() {
        return String::new();
    }

    if page_url.ends_with('/') {
        return format!("{page_url}{value}");
    }

    let base = page_url
        .rsplit_once('/')
        .map(|(left, _)| left)
        .unwrap_or(page_url);
    format!("{base}/{value}")
}

fn split_origin(url: &str) -> Option<(String, String)> {
    let scheme_end = url.find("://")?;
    let after_scheme = &url[scheme_end + 3..];
    let path_start = after_scheme.find('/').unwrap_or(after_scheme.len());
    let origin = format!("{}://{}", &url[..scheme_end], &after_scheme[..path_start]);
    let path = after_scheme[path_start..].to_string();
    Some((origin, path))
}

fn normalize_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
