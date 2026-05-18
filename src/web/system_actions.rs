use std::path::PathBuf;

#[cfg(windows)]
use windows_sys::Win32::UI::Shell::ShellExecuteW;

use crate::{
    config::RelayGateConfig,
    lang,
    proxy::mitm,
    web::backend_payloads::{MitmStatusPayload, WindowsRelayGateCaPayload},
};

pub(crate) fn build_mitm_status(config: &RelayGateConfig) -> MitmStatusPayload {
    let (cert_path, key_path) = mitm_paths();

    MitmStatusPayload {
        enabled: config.proxy.mitm.enabled,
        ca_cert_path: cert_path.display().to_string(),
        ca_key_path: key_path.display().to_string(),
        ca_cert_exists: cert_path.exists(),
        ca_key_exists: key_path.exists(),
        windows_user_root_trusted: windows_root_trusted(&cert_path),
        windows_relaygate_cas: windows_relaygate_cas(&cert_path),
    }
}

pub(crate) fn build_mitm_status_fast(config: &RelayGateConfig) -> MitmStatusPayload {
    let (cert_path, key_path) = mitm_paths();

    MitmStatusPayload {
        enabled: config.proxy.mitm.enabled,
        ca_cert_path: cert_path.display().to_string(),
        ca_key_path: key_path.display().to_string(),
        ca_cert_exists: cert_path.exists(),
        ca_key_exists: key_path.exists(),
        windows_user_root_trusted: None,
        windows_relaygate_cas: Vec::new(),
    }
}

fn mitm_paths() -> (PathBuf, PathBuf) {
    let storage_dir = mitm_storage_dir();
    (
        storage_dir.join("relaygate-ca-cert.pem"),
        storage_dir.join("relaygate-ca-key.pem"),
    )
}

pub(crate) fn remove_ca_windows_trust_only() -> anyhow::Result<String> {
    let storage_dir = mitm_storage_dir();
    let cert_path = storage_dir.join("relaygate-ca-cert.pem");
    let cert_exists = cert_path.exists();

    #[cfg(windows)]
    if cert_exists {
        remove_ca_from_windows_user_root(&cert_path)?;
    }

    if !cert_exists {
        return Ok(lang::text("backend.ca.no_cert"));
    }

    #[cfg(windows)]
    if let Some(remaining) = windows_root_store_locations(&cert_path) {
        if !remaining.is_empty() {
            let diagnostics = windows_root_store_diagnostics(&cert_path)
                .filter(|items| !items.is_empty())
                .unwrap_or_else(|| vec![lang::text("backend.ca.no_diag")]);
            anyhow::bail!(
                "{}",
                lang::format(
                    "backend.ca.still.diag",
                    &[
                        ("path", remaining.join(", ")),
                        ("details", diagnostics.join(" | ")),
                    ],
                )
            );
        }
    }

    Ok(lang::text("backend.ca.kept"))
}

pub(crate) fn remove_windows_relaygate_ca(id: &str) -> anyhow::Result<String> {
    #[cfg(windows)]
    {
        let (store, thumbprint) = parse_windows_ca_id(id)?;
        remove_relaygate_thumbprint_from_store(&store, &thumbprint)?;
        return Ok(lang::text("backend.ca.other_removed"));
    }

    #[cfg(not(windows))]
    {
        let _ = id;
        anyhow::bail!("Windows CA trust management is only available on Windows")
    }
}

pub(crate) fn open_folder(path: &PathBuf) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(windows)]
    {
        open_folder_with_shell_execute(path)?;
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        let _ = path;
        anyhow::bail!("opening folders from RelayGate is only supported on Windows")
    }
}

fn windows_relaygate_cas(cert_path: &PathBuf) -> Vec<WindowsRelayGateCaPayload> {
    #[cfg(windows)]
    {
        return windows_relaygate_cas_impl(cert_path).unwrap_or_default();
    }

    #[cfg(not(windows))]
    {
        let _ = cert_path;
        Vec::new()
    }
}

fn mitm_storage_dir() -> PathBuf {
    mitm::mitm_storage_dir().unwrap_or_else(|_| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("data")
            .join("state")
            .join("mitm")
    })
}

fn windows_root_trusted(cert_path: &PathBuf) -> Option<bool> {
    // Keep the backend payload field name for compatibility. RelayGate now
    // manages only the per-user Windows trusted Root store.
    #[cfg(windows)]
    {
        return Some(
            windows_root_store_locations(cert_path)
                .map(|stores| !stores.is_empty())
                .unwrap_or(false),
        );
    }

    #[cfg(not(windows))]
    {
        let _ = cert_path;
        None
    }
}

#[cfg(windows)]
fn windows_root_store_locations(cert_path: &PathBuf) -> Option<Vec<String>> {
    if !cert_path.exists() {
        return Some(Vec::new());
    }

    let thumbprint = cert_thumbprint_from_path(cert_path)?;
    crate::web::windows_cert_store::root_locations_for_thumbprint(&thumbprint).ok()
}

#[cfg(windows)]
fn windows_root_store_diagnostics(cert_path: &PathBuf) -> Option<Vec<String>> {
    if !cert_path.exists() {
        return Some(Vec::new());
    }

    let thumbprint = cert_thumbprint_from_path(cert_path)?;
    crate::web::windows_cert_store::root_diagnostics_for_thumbprint(&thumbprint).ok()
}

#[cfg(windows)]
fn windows_relaygate_cas_impl(
    cert_path: &PathBuf,
) -> anyhow::Result<Vec<WindowsRelayGateCaPayload>> {
    windows_relaygate_cas_impl_native(cert_path)
}

#[cfg(windows)]
fn windows_relaygate_cas_impl_native(
    cert_path: &PathBuf,
) -> anyhow::Result<Vec<WindowsRelayGateCaPayload>> {
    let current_thumbprint = cert_thumbprint_from_path(cert_path);
    let entries = crate::web::windows_cert_store::relaygate_cas(current_thumbprint.as_deref())?;
    Ok(entries
        .into_iter()
        .map(|entry| {
            let id = format!("{}|{}", entry.store, entry.thumbprint);
            WindowsRelayGateCaPayload {
                id,
                thumbprint: entry.thumbprint,
                subject: entry.subject,
                issuer: entry.issuer,
                not_before: unix_secs_to_utc_string(entry.not_before_unix_secs),
                not_after: unix_secs_to_utc_string(entry.not_after_unix_secs),
                store: entry.store,
                is_current: entry.is_current,
            }
        })
        .collect())
}

#[cfg(windows)]
fn cert_thumbprint_from_path(cert_path: &PathBuf) -> Option<String> {
    if !cert_path.exists() {
        return None;
    }

    crate::web::windows_cert_store::cert_thumbprint_from_path(cert_path).ok()
}

#[cfg(windows)]
fn unix_secs_to_utc_string(secs: i64) -> String {
    const DAY_SECS: i64 = 86_400;
    let days = secs.div_euclid(DAY_SECS);
    let seconds_of_day = secs.rem_euclid(DAY_SECS);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(windows)]
fn civil_from_days(days_since_unix_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[cfg(windows)]
fn remove_ca_from_windows_user_root(cert_path: &PathBuf) -> anyhow::Result<()> {
    let Some(thumbprint) = cert_thumbprint_from_path(cert_path) else {
        anyhow::bail!(
            "{}",
            lang::format(
                "backend.ca.thumb_fail",
                &[(
                    "stderr",
                    "unable to read certificate thumbprint".to_string()
                )]
            )
        );
    };

    let mut failures = Vec::new();
    let mut details = Vec::new();

    match remove_current_user_thumbprint_native(&thumbprint, false) {
        Ok(detail) => details.push(format!("CurrentUser\\Root: {detail}")),
        Err(error) => failures.push(format!("CurrentUser\\Root: {error}")),
    }

    let remaining = windows_root_store_locations(cert_path).unwrap_or_default();
    if !remaining.is_empty() {
        let diagnostics = windows_root_store_diagnostics(cert_path)
            .filter(|items| !items.is_empty())
            .unwrap_or_else(|| vec![lang::text("backend.ca.no_diag")]);
        if failures.is_empty() {
            anyhow::bail!(
                "{}",
                lang::format(
                    "backend.ca.still.result",
                    &[
                        ("path", remaining.join(", ")),
                        ("result", details.join(" | ")),
                        ("details", diagnostics.join(" | ")),
                    ],
                )
            );
        } else {
            anyhow::bail!(
                "{}",
                lang::format(
                    "backend.ca.still.remove",
                    &[
                        ("path", remaining.join(", ")),
                        ("result", details.join(" | ")),
                        ("remove_details", failures.join(" | ")),
                        ("details", diagnostics.join(" | ")),
                    ],
                )
            );
        }
    }

    Ok(())
}

#[cfg(windows)]
fn parse_windows_ca_id(id: &str) -> anyhow::Result<(String, String)> {
    let Some((store, thumbprint)) = id.split_once('|') else {
        anyhow::bail!("invalid CA id");
    };
    let store = normalize_windows_ca_store_label(store);
    if store != "CurrentUser\\Root" {
        anyhow::bail!("unsupported CA store: {store}");
    }
    let thumbprint = thumbprint.trim().to_ascii_uppercase();
    if thumbprint.len() != 40 || !thumbprint.chars().all(|ch| ch.is_ascii_hexdigit()) {
        anyhow::bail!("invalid CA thumbprint");
    }
    Ok((store.to_string(), thumbprint))
}

#[cfg(windows)]
fn normalize_windows_ca_store_label(store: &str) -> String {
    store.trim().replace("\\\\", "\\")
}

#[cfg(windows)]
fn remove_relaygate_thumbprint_from_store(store: &str, thumbprint: &str) -> anyhow::Result<String> {
    if store == "CurrentUser\\Root" {
        return remove_current_user_thumbprint_native(thumbprint, true);
    }

    anyhow::bail!("unsupported CA store: {store}")
}

#[cfg(windows)]
fn remove_current_user_thumbprint_native(
    thumbprint: &str,
    require_relaygate_name: bool,
) -> anyhow::Result<String> {
    let result = crate::web::windows_cert_store::delete_thumbprint(
        crate::web::windows_cert_store::RootStoreScope::CurrentUser,
        thumbprint,
        require_relaygate_name,
    )?;
    let stdout = format!("before={};after={}", result.before, result.after);

    if require_relaygate_name && result.before == 0 {
        anyhow::bail!("no RelayGate CA matched in CurrentUser\\Root");
    }

    if result.after != 0 {
        anyhow::bail!(
            "{}",
            lang::format(
                "backend.ca.still.store",
                &[
                    ("store_label", "CurrentUser\\Root".to_string()),
                    ("stdout", stdout.clone()),
                ],
            )
        );
    }

    Ok(stdout)
}

#[cfg(windows)]
fn open_folder_with_shell_execute(path: &PathBuf) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    let operation: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
    let target: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        )
    };

    if result as isize <= 32 {
        anyhow::bail!("failed to open folder: {}", path.display());
    }

    Ok(())
}
