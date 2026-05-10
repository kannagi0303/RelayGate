use anyhow::Result;
use tracing_subscriber::EnvFilter;

use crate::{
    app::App,
    config::RelayGateConfig,
    lang,
    path_mode::{set_app_path_mode, AppPathMode},
};

#[cfg(not(debug_assertions))]
use std::{
    env, fs,
    fs::OpenOptions,
    io::{self, Write},
    path::PathBuf,
};
#[cfg(not(debug_assertions))]
use tracing::Level;
#[cfg(not(debug_assertions))]
use tracing_subscriber::fmt::writer::MakeWriterExt;
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
            .unwrap_or_else(|_| "127.0.0.1:8787".to_string());
        let _ = open_control_panel(&proxy_listen, "/");
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
        let log_file = release_log_file()
            .unwrap_or_else(|_| PathBuf::from("data").join("logs").join("relaygate.log"));
        let file_appender = LazyLogFile { path: log_file };

        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_ansi(false)
            .compact()
            .with_writer(file_appender.with_max_level(Level::ERROR).or_else(io::sink))
            .init();
    }
}

#[cfg(not(debug_assertions))]
#[derive(Clone)]
struct LazyLogFile {
    path: PathBuf,
}

#[cfg(not(debug_assertions))]
struct LazyLogWriter {
    path: PathBuf,
    file: Option<fs::File>,
}

#[cfg(not(debug_assertions))]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LazyLogFile {
    type Writer = LazyLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LazyLogWriter {
            path: self.path.clone(),
            file: None,
        }
    }
}

#[cfg(not(debug_assertions))]
impl Write for LazyLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

#[cfg(not(debug_assertions))]
impl LazyLogWriter {
    fn file(&mut self) -> io::Result<&mut fs::File> {
        if self.file.is_none() {
            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent)?;
            }
            self.file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)?,
            );
        }
        Ok(self.file.as_mut().expect("lazy log file initialized"))
    }
}

#[cfg(not(debug_assertions))]
fn release_log_file() -> Result<PathBuf> {
    let exe = env::current_exe()?;
    let base_dir = exe.parent().ok_or_else(|| {
        anyhow::anyhow!("current executable path does not have a parent directory")
    })?;
    Ok(base_dir.join("data").join("logs").join("relaygate.log"))
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

fn open_control_panel(web_listen: &str, path: &str) -> Result<()> {
    let url = format!("http://{}{}", browser_open_address(web_listen), path);
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
