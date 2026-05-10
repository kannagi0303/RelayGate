use std::{path::PathBuf, process::Command};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
use serde::Deserialize;

use crate::{
    config::RelayGateConfig,
    lang,
    proxy::mitm,
    web::backend_payloads::{MitmStatusPayload, WindowsRelayGateCaPayload},
};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub(crate) fn build_mitm_status(config: &RelayGateConfig) -> MitmStatusPayload {
    let storage_dir = mitm_storage_dir();
    let cert_path = storage_dir.join("relaygate-ca-cert.pem");
    let key_path = storage_dir.join("relaygate-ca-key.pem");

    MitmStatusPayload {
        enabled: config.proxy.mitm.enabled,
        ca_cert_path: cert_path.display().to_string(),
        ca_key_path: key_path.display().to_string(),
        ca_cert_exists: cert_path.exists(),
        ca_key_exists: key_path.exists(),
        windows_user_root_trusted: windows_user_root_trusted(&cert_path),
        windows_relaygate_cas: windows_relaygate_cas(&cert_path),
    }
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
        remove_relaygate_thumbprint_from_store_ps(&store, &thumbprint)?;
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
        hidden_command("explorer").arg(path).spawn()?;
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        hidden_command("xdg-open").arg(path).spawn()?;
        Ok(())
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
            .join("mitm")
    })
}

fn windows_user_root_trusted(cert_path: &PathBuf) -> Option<bool> {
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

    let escaped_path = cert_path.display().to_string().replace('\'', "''");
    let script = format!(
        r#"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{escaped_path}')
$thumb = $cert.Thumbprint
if ([string]::IsNullOrWhiteSpace($thumb)) {{
  Write-Output ''
  exit 0
}}

$hits = New-Object System.Collections.Generic.List[string]
$stores = @(
  @( [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser, 'CurrentUser\Root' ),
  @( [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine, 'LocalMachine\Root' )
)

foreach ($entry in $stores) {{
  $location = $entry[0]
  $label = $entry[1]
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    $location
  )
  try {{
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $matches = @($store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumb }})
    if ($matches.Count -gt 0) {{
      $hits.Add($label)
    }}
  }} finally {{
    $store.Close()
  }}
}}

Write-Output ($hits -join ',')"#
    );

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stores = stdout
        .trim()
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| item.trim().to_string())
        .collect::<Vec<_>>();
    Some(stores)
}

#[cfg(windows)]
fn windows_root_store_diagnostics(cert_path: &PathBuf) -> Option<Vec<String>> {
    if !cert_path.exists() {
        return Some(Vec::new());
    }

    let escaped_path = cert_path.display().to_string().replace('\'', "''");
    let script = format!(
        r#"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{escaped_path}')
$thumb = $cert.Thumbprint
if ([string]::IsNullOrWhiteSpace($thumb)) {{
  Write-Output ''
  exit 0
}}

$results = New-Object System.Collections.Generic.List[string]
$stores = @(
  @( [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser, 'CurrentUser\Root' ),
  @( [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine, 'LocalMachine\Root' )
)

foreach ($entry in $stores) {{
  $location = $entry[0]
  $label = $entry[1]
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    $location
  )
  try {{
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $matches = @($store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumb }})
    $results.Add($label + ':count=' + $matches.Count)
  }} finally {{
    $store.Close()
  }}
}}

Write-Output ($results -join ',')"#
    );

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let items = stdout
        .trim()
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| item.trim().to_string())
        .collect::<Vec<_>>();
    Some(items)
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct WindowsRelayGateCaEntry {
    thumbprint: String,
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    store: String,
    is_current: bool,
}

#[cfg(windows)]
fn windows_relaygate_cas_impl(
    cert_path: &PathBuf,
) -> anyhow::Result<Vec<WindowsRelayGateCaPayload>> {
    let current_thumbprint = cert_thumbprint_from_path(cert_path).unwrap_or_default();
    let script = format!(
        r#"$current = '{current_thumbprint}'
$results = @()
$stores = @(
  @( [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser, 'CurrentUser\Root' ),
  @( [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine, 'LocalMachine\Root' )
)

foreach ($entry in $stores) {{
  $location = $entry[0]
  $label = $entry[1]
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    $location
  )
  try {{
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    foreach ($cert in $store.Certificates) {{
      if (($cert.Subject -like '*RelayGate*') -or ($cert.Issuer -like '*RelayGate*')) {{
        $results += [PSCustomObject]@{{
          thumbprint = $cert.Thumbprint
          subject = $cert.Subject
          issuer = $cert.Issuer
          not_before = $cert.NotBefore.ToString('yyyy-MM-dd HH:mm:ss')
          not_after = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
          store = $label
          is_current = ($cert.Thumbprint -eq $current)
        }}
      }}
    }}
  }} finally {{
    $store.Close()
  }}
}}

$results | ConvertTo-Json -Compress"#
    );

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Ok(Vec::new());
    }

    let entries = parse_windows_relaygate_ca_json(&stdout)?;
    Ok(entries
        .into_iter()
        .map(|entry| {
            let id = format!("{}|{}", entry.store, entry.thumbprint);
            WindowsRelayGateCaPayload {
                id,
                thumbprint: entry.thumbprint,
                subject: entry.subject,
                issuer: entry.issuer,
                not_before: entry.not_before,
                not_after: entry.not_after,
                store: entry.store,
                is_current: entry.is_current,
            }
        })
        .collect())
}

#[cfg(windows)]
fn parse_windows_relaygate_ca_json(json: &str) -> anyhow::Result<Vec<WindowsRelayGateCaEntry>> {
    if json.trim_start().starts_with('[') {
        return Ok(serde_json::from_str(json)?);
    }
    Ok(vec![serde_json::from_str(json)?])
}

#[cfg(windows)]
fn cert_thumbprint_from_path(cert_path: &PathBuf) -> Option<String> {
    if !cert_path.exists() {
        return None;
    }

    let escaped_path = cert_path.display().to_string().replace('\'', "''");
    let script = format!(
        r#"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{escaped_path}')
Write-Output $cert.Thumbprint"#
    );
    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let thumbprint = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if thumbprint.is_empty() {
        None
    } else {
        Some(thumbprint)
    }
}

#[cfg(windows)]
fn remove_ca_from_windows_user_root(cert_path: &PathBuf) -> anyhow::Result<()> {
    let escaped_path = cert_path.display().to_string().replace('\'', "''");
    let thumb_script = format!(
        r#"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{escaped_path}')
$thumb = $cert.Thumbprint
if ([string]::IsNullOrWhiteSpace($thumb)) {{
  Write-Output ''
}} else {{
  Write-Output $thumb
}}"#
    );

    let thumb_output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &thumb_script])
        .output()?;

    if !thumb_output.status.success() {
        let stderr = String::from_utf8_lossy(&thumb_output.stderr);
        anyhow::bail!(
            "{}",
            lang::format("backend.ca.thumb_fail", &[("stderr", stderr.to_string())])
        );
    }

    let thumbprint = String::from_utf8_lossy(&thumb_output.stdout)
        .trim()
        .to_string();
    if thumbprint.is_empty() {
        return Ok(());
    }

    let mut failures = Vec::new();
    let mut details = Vec::new();

    match remove_thumbprint_from_store_ps("CurrentUser", &thumbprint) {
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
    if !matches!(store.as_str(), "CurrentUser\\Root" | "LocalMachine\\Root") {
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
fn remove_relaygate_thumbprint_from_store_ps(
    store: &str,
    thumbprint: &str,
) -> anyhow::Result<String> {
    if store == "LocalMachine\\Root" {
        return remove_relaygate_thumbprint_from_local_machine_root_elevated(thumbprint);
    }

    let location = match store {
        "CurrentUser\\Root" => "CurrentUser",
        "LocalMachine\\Root" => "LocalMachine",
        other => anyhow::bail!("unsupported CA store: {other}"),
    };

    let (store_location_expr, store_label) = match location {
        "CurrentUser" => (
            "[System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser",
            "CurrentUser\\Root",
        ),
        "LocalMachine" => (
            "[System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine",
            "LocalMachine\\Root",
        ),
        other => anyhow::bail!("unsupported store location: {other}"),
    };

    let script = format!(
        r#"$thumb = '{thumbprint}'
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
  [System.Security.Cryptography.X509Certificates.StoreName]::Root,
  {store_location_expr}
)
try {{
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $before = @($store.Certificates | Where-Object {{
    $_.Thumbprint -eq $thumb -and (($_.Subject -like '*RelayGate*') -or ($_.Issuer -like '*RelayGate*'))
  }})
  foreach ($item in $before) {{
    $store.Remove($item)
  }}
  $after = @($store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumb }})
  Write-Output ('before=' + $before.Count + ';after=' + $after.Count)
}} finally {{
  $store.Close()
}}"#
    );

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!("stdout: {stdout}; stderr: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.contains("before=0") && stdout.ends_with("after=0") {
        return Ok(stdout);
    }
    if stdout.contains("before=0") {
        anyhow::bail!("no RelayGate CA matched in {store_label}");
    }
    anyhow::bail!(
        "{}",
        lang::format(
            "backend.ca.still.store",
            &[
                ("store_label", store_label.to_string()),
                ("stdout", stdout.clone()),
            ],
        )
    )
}

#[cfg(windows)]
fn remove_relaygate_thumbprint_from_local_machine_root_elevated(
    thumbprint: &str,
) -> anyhow::Result<String> {
    if !relaygate_thumbprint_exists_in_store("LocalMachine\\Root", thumbprint)? {
        anyhow::bail!("no RelayGate CA matched in LocalMachine\\Root");
    }

    let launch_script = format!(
        r#"$process = Start-Process -FilePath certutil.exe -ArgumentList @('-delstore','Root','{thumbprint}') -Verb RunAs -Wait -PassThru
exit $process.ExitCode"#
    );

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &launch_script])
        .output();

    let output = output?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!("administrator approval failed or removal was cancelled; stdout: {stdout}; stderr: {stderr}");
    }

    if relaygate_thumbprint_exists_in_store("LocalMachine\\Root", thumbprint)? {
        anyhow::bail!(
            "{}",
            lang::format(
                "backend.ca.still.store",
                &[
                    ("store_label", "LocalMachine\\Root".to_string()),
                    ("stdout", "after=1".to_string()),
                ],
            )
        );
    }

    Ok("LocalMachine\\Root: elevated removal completed".to_string())
}

#[cfg(windows)]
fn relaygate_thumbprint_exists_in_store(store: &str, thumbprint: &str) -> anyhow::Result<bool> {
    let (store_location_expr, _) = match store {
        "CurrentUser\\Root" => (
            "[System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser",
            "CurrentUser\\Root",
        ),
        "LocalMachine\\Root" => (
            "[System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine",
            "LocalMachine\\Root",
        ),
        other => anyhow::bail!("unsupported CA store: {other}"),
    };
    let script = format!(
        r#"$thumb = '{thumbprint}'
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
  [System.Security.Cryptography.X509Certificates.StoreName]::Root,
  {store_location_expr}
)
try {{
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
  $matches = @($store.Certificates | Where-Object {{
    $_.Thumbprint -eq $thumb -and (($_.Subject -like '*RelayGate*') -or ($_.Issuer -like '*RelayGate*'))
  }})
  if ($matches.Count -gt 0) {{ Write-Output 'present' }} else {{ Write-Output 'missing' }}
}} finally {{
  $store.Close()
}}"#
    );
    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "present")
}

#[cfg(windows)]
fn remove_thumbprint_from_store_ps(location: &str, thumbprint: &str) -> anyhow::Result<String> {
    let (store_location_expr, store_label) = match location {
        "CurrentUser" => (
            "[System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser",
            "CurrentUser\\Root",
        ),
        "LocalMachine" => (
            "[System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine",
            "LocalMachine\\Root",
        ),
        other => anyhow::bail!("unsupported store location: {other}"),
    };

    let script = format!(
        r#"$thumb = '{thumbprint}'
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
  [System.Security.Cryptography.X509Certificates.StoreName]::Root,
  {store_location_expr}
)
try {{
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $before = @($store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumb }})
  foreach ($item in $before) {{
    $store.Remove($item)
  }}
  $after = @($store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumb }})
  Write-Output ('before=' + $before.Count + ';after=' + $after.Count)
}} finally {{
  $store.Close()
}}"#
    );

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!("stdout: {stdout}; stderr: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.contains("after=") && !stdout.ends_with("after=0") {
        anyhow::bail!(
            "{}",
            lang::format(
                "backend.ca.still.store",
                &[
                    ("store_label", store_label.to_string()),
                    ("stdout", stdout.clone()),
                ],
            )
        );
    }

    Ok(stdout)
}

fn hidden_command(program: &str) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}
