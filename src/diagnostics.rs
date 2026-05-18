use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, SyncSender, TrySendError},
        OnceLock,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Error, Result};

use crate::path_mode::{app_path_mode, AppPathMode};

const LOG_QUEUE_CAPACITY: usize = 4096;
const LOG_FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const LOG_BATCH_FLUSH_LINES: usize = 256;
const LAZY_LOG_ROTATE_BYTES: u64 = 64 * 1024 * 1024;

enum LogCommand {
    Line { path: PathBuf, line: String },
    Flush,
}

static LOG_SINK: OnceLock<SyncSender<LogCommand>> = OnceLock::new();

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
    append_lazy_log_line(path, line.to_string());
    Ok(())
}

pub fn append_proxy_perf_diagnostic(line: &str) -> Result<()> {
    let path = proxy_perf_diagnostics_path()?;
    append_lazy_log_line(path, line.to_string());
    Ok(())
}

pub fn append_lazy_log_line(path: PathBuf, line: String) {
    let command = LogCommand::Line { path, line };
    match log_sink().try_send(command) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            // Diagnostics are best-effort. Dropping a line is cheaper than
            // blocking the proxy hot path on logging backpressure.
        }
        Err(TrySendError::Disconnected(_)) => {}
    }
}

pub fn flush_lazy_logs() {
    let Some(sender) = LOG_SINK.get() else {
        return;
    };
    let _ = sender.try_send(LogCommand::Flush);
}

fn log_sink() -> &'static SyncSender<LogCommand> {
    LOG_SINK.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel(LOG_QUEUE_CAPACITY);
        let _ = thread::Builder::new()
            .name("relaygate-lazy-log-writer".to_string())
            .spawn(move || lazy_log_writer_loop(receiver));
        sender
    })
}

fn lazy_log_writer_loop(receiver: Receiver<LogCommand>) {
    let mut writers: HashMap<PathBuf, BufWriter<File>> = HashMap::new();
    let mut pending_lines = 0usize;

    loop {
        match receiver.recv_timeout(LOG_FLUSH_INTERVAL) {
            Ok(command) => {
                handle_log_command(command, &mut writers, &mut pending_lines);
                while pending_lines < LOG_BATCH_FLUSH_LINES {
                    let Ok(command) = receiver.try_recv() else {
                        break;
                    };
                    handle_log_command(command, &mut writers, &mut pending_lines);
                }
                if pending_lines >= LOG_BATCH_FLUSH_LINES {
                    flush_writers(&mut writers);
                    pending_lines = 0;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                flush_writers(&mut writers);
                pending_lines = 0;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                flush_writers(&mut writers);
                break;
            }
        }
    }
}

fn handle_log_command(
    command: LogCommand,
    writers: &mut HashMap<PathBuf, BufWriter<File>>,
    pending_lines: &mut usize,
) {
    match command {
        LogCommand::Line { path, line } => {
            if write_lazy_line(writers, path, &line).is_ok() {
                *pending_lines += 1;
            }
        }
        LogCommand::Flush => {
            flush_writers(writers);
            *pending_lines = 0;
        }
    }
}

fn write_lazy_line(
    writers: &mut HashMap<PathBuf, BufWriter<File>>,
    path: PathBuf,
    line: &str,
) -> std::io::Result<()> {
    let rotate_open_writer = if let Some(writer) = writers.get_mut(&path) {
        let should_rotate = writer
            .get_ref()
            .metadata()
            .map(|metadata| metadata.len() >= LAZY_LOG_ROTATE_BYTES)
            .unwrap_or(false);
        if should_rotate {
            writer.flush()?;
        }
        should_rotate
    } else {
        false
    };

    if rotate_open_writer {
        writers.remove(&path);
        rotate_lazy_log_if_needed(&path)?;
    }

    if !writers.contains_key(&path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        rotate_lazy_log_if_needed(&path)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        writers.insert(path.clone(), BufWriter::new(file));
    }

    let Some(writer) = writers.get_mut(&path) else {
        return Ok(());
    };
    writeln!(writer, "{line}")
}

fn rotate_lazy_log_if_needed(path: &Path) -> std::io::Result<()> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(());
    };
    if metadata.len() < LAZY_LOG_ROTATE_BYTES {
        return Ok(());
    }

    let Some(file_name) = path.file_name() else {
        return Ok(());
    };
    let backup_name = format!("{}.1", file_name.to_string_lossy());
    let backup_path = path.with_file_name(backup_name);
    if backup_path.exists() {
        fs::remove_file(&backup_path)?;
    }
    fs::rename(path, backup_path)
}

fn flush_writers(writers: &mut HashMap<PathBuf, BufWriter<File>>) {
    for writer in writers.values_mut() {
        let _ = writer.flush();
    }
}

pub fn diagnostic_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

fn proxy_diagnostics_path() -> Result<PathBuf> {
    Ok(log_base_dir()?.join("proxy-diagnostics.log"))
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
    Ok(base.join("data").join("state").join("diagnostics"))
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
