use anyhow::Result;
use tracing_subscriber::EnvFilter;

use crate::{
    app::App,
    config::RelayGateConfig,
    lang,
    path_mode::{set_app_path_mode, AppPathMode},
};

#[cfg(not(debug_assertions))]
use std::fs;
#[cfg(all(windows, not(debug_assertions)))]
use std::{env, path::PathBuf};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE},
    System::Threading::CreateMutexW,
    UI::Shell::ShellExecuteW,
};

pub async fn run(mode: AppPathMode) -> Result<()> {
    set_app_path_mode(mode)?;

    let Some(_single_instance_guard) = acquire_single_instance_guard()? else {
        let proxy_listen = RelayGateConfig::load_default_or_builtin()
            .map(|(config, _)| config.proxy.listen)
            .unwrap_or_else(|_| "0.0.0.0:8787".to_string());
        let _ = open_control_panel(&proxy_listen);
        return Ok(());
    };

    install_rustls_provider();
    init_tracing();
    lang::init_current()?;

    let (config, used_builtin_defaults) = RelayGateConfig::load_default_or_builtin()?;
    if used_builtin_defaults {
        tracing::warn!(
            config_path = %RelayGateConfig::default_path()?.display(),
            "config file not found; using built-in defaults until settings are saved"
        );
    }
    config.validate()?;

    let app = App::new(config)?;
    app.run().await
}

fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("relaygate=info,axum=info"));

    #[cfg(debug_assertions)]
    {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .compact()
            .init();
    }

    #[cfg(not(debug_assertions))]
    {
        let log_dir = release_log_dir().unwrap_or_else(|_| PathBuf::from("data").join("logs"));
        let _ = fs::create_dir_all(&log_dir);
        let file_appender = tracing_appender::rolling::never(log_dir, "relaygate.log");

        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_ansi(false)
            .compact()
            .with_writer(file_appender)
            .init();
    }
}

#[cfg(all(windows, not(debug_assertions)))]
fn release_log_dir() -> Result<PathBuf> {
    let exe = env::current_exe()?;
    let base_dir = exe.parent().ok_or_else(|| {
        anyhow::anyhow!("current executable path does not have a parent directory")
    })?;
    Ok(base_dir.join("data").join("logs"))
}

#[cfg(windows)]
fn acquire_single_instance_guard() -> Result<Option<SingleInstanceGuard>> {
    let mut name: Vec<u16> = "RelayGate.Singleton"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_mut_ptr()) };
    if handle.is_null() {
        return Err(anyhow::anyhow!(
            "failed to create RelayGate single-instance mutex"
        ));
    }

    let last_error = unsafe { GetLastError() };
    if last_error == ERROR_ALREADY_EXISTS {
        unsafe {
            CloseHandle(handle);
        }
        return Ok(None);
    }

    Ok(Some(SingleInstanceGuard { handle }))
}

#[cfg(not(windows))]
fn acquire_single_instance_guard() -> Result<Option<()>> {
    Ok(Some(()))
}

#[cfg(windows)]
struct SingleInstanceGuard {
    handle: HANDLE,
}

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

fn open_control_panel(web_listen: &str) -> Result<()> {
    let url = format!("http://{}/", browser_open_address(web_listen));
    #[cfg(windows)]
    {
        let operation: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
        let target: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
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
            anyhow::bail!("failed to open control panel URL: {url}");
        }

        return Ok(());
    }

    #[cfg(not(windows))]
    {
        std::process::Command::new("xdg-open").arg(&url).spawn()?;
        Ok(())
    }
}

fn browser_open_address(listen: &str) -> String {
    if let Some((host, port)) = listen.rsplit_once(':') {
        let browser_host = match host.trim_matches(['[', ']']) {
            "0.0.0.0" | "::" | "::0" => "127.0.0.1",
            other => other,
        };
        format!("{browser_host}:{port}")
    } else {
        listen.to_string()
    }
}
