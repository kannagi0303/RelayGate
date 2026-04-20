use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Error, Result};

use crate::path_mode::{app_path_mode, AppPathMode};

pub fn format_error_chain(error: &Error) -> String {
    error
        .chain()
        .enumerate()
        .map(|(index, cause)| format!("#{index}: {cause}"))
        .collect::<Vec<_>>()
        .join(" | ")
}

pub fn format_error_for_console(error: &Error) -> String {
    shorten_error_text(&error.to_string(), true)
}

pub fn format_error_chain_for_console(error: &Error) -> String {
    error
        .chain()
        .enumerate()
        .map(|(index, cause)| {
            let shortened = shorten_error_text(&cause.to_string(), index == 0);
            format!("#{index}: {shortened}")
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

pub fn append_proxy_diagnostic(line: &str) -> Result<()> {
    let path = proxy_diagnostics_path()?;
    append_diagnostic_line(&path, line)
}

pub fn append_proxy_perf_diagnostic(line: &str) -> Result<()> {
    let path = proxy_perf_diagnostics_path()?;
    append_diagnostic_line(&path, line)
}

fn append_diagnostic_line(path: &PathBuf, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

pub fn diagnostic_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

fn proxy_diagnostics_path() -> Result<PathBuf> {
    Ok(log_base_dir()?.join("proxy-errors.log"))
}

fn proxy_perf_diagnostics_path() -> Result<PathBuf> {
    Ok(log_base_dir()?.join("proxy-perf.log"))
}

fn log_base_dir() -> Result<PathBuf> {
    let base = match app_path_mode() {
        AppPathMode::Workspace => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        AppPathMode::Portable => {
            let exe = std::env::current_exe()?;
            exe.parent()
                .ok_or_else(|| {
                    anyhow::anyhow!("current executable path does not have a parent directory")
                })?
                .to_path_buf()
        }
    };
    Ok(base.join("data").join("logs"))
}

fn shorten_error_text(text: &str, shorten_url_detail: bool) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let shortened = if shorten_url_detail {
        trim_url_payload(&collapsed)
    } else {
        collapsed
    };

    truncate_text(&shortened, 160)
}

fn trim_url_payload(text: &str) -> String {
    for marker in [" for url (", " url ("] {
        if let Some(index) = text.find(marker) {
            return text[..index].trim().to_string();
        }
    }

    text.to_string()
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    let truncated = text.chars().take(max_chars).collect::<String>();
    format!("{truncated}...")
}
