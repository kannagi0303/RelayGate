use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    thread,
};

use anyhow::Result;
use ico::IconDir;
use tokio::sync::mpsc;
use tracing::{info, warn};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    Icon, MouseButton, TrayIconBuilder, TrayIconEvent,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, PostThreadMessageW, TranslateMessage, MSG, WM_APP,
};

use crate::{config::RelayGateConfig, lang};

/// Abstraction layer for tray control.
/// This keeps the app layer stable if the tray crate or platform changes later.
pub trait TrayController {
    fn start(&self, command_tx: mpsc::UnboundedSender<TrayCommand>) -> Result<TrayHandle>;
}

#[derive(Debug, Clone, Copy)]
pub enum TrayCommand {
    OpenControlPanel,
    Reload,
    Exit,
}

#[derive(Debug, Clone)]
pub struct TrayMenuEntry {
    /// Internal event ID.
    pub id: &'static str,
    /// Label shown in the tray menu.
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct TrayHandle {
    /// Used to tell the tray thread to stop.
    shutdown_flag: Arc<AtomicBool>,
    thread_id: Arc<AtomicU32>,
}

impl TrayHandle {
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        let thread_id = self.thread_id.load(Ordering::SeqCst);
        if thread_id != 0 {
            unsafe {
                PostThreadMessageW(thread_id, WM_APP + 1, 0, 0);
            }
        }
        info!("tray handle shutdown requested");
    }
}

/// Windows tray icon implementation.
///
/// The first version focuses on:
/// - showing a tray icon
/// - providing Exit in the context menu
/// - sending Exit back to the app to trigger shutdown
pub struct SystemTray {
    config: Arc<RelayGateConfig>,
}

impl SystemTray {
    pub fn new(config: Arc<RelayGateConfig>) -> Self {
        Self { config }
    }

    pub fn menu_entries(&self) -> Vec<TrayMenuEntry> {
        // Keep the minimum menu entries for now.
        vec![
            TrayMenuEntry {
                id: "open-settings",
                label: lang::text("tray.open"),
            },
            TrayMenuEntry {
                id: "reload",
                label: lang::text("tray.reload"),
            },
            TrayMenuEntry {
                id: "exit",
                label: lang::text("tray.exit"),
            },
        ]
    }
}

impl TrayController for SystemTray {
    fn start(&self, command_tx: mpsc::UnboundedSender<TrayCommand>) -> Result<TrayHandle> {
        if !self.config.tray.enabled {
            info!("tray disabled by config");
            return Ok(TrayHandle {
                shutdown_flag: Arc::new(AtomicBool::new(false)),
                thread_id: Arc::new(AtomicU32::new(0)),
            });
        }

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let thread_id = Arc::new(AtomicU32::new(0));
        let thread_shutdown_flag = shutdown_flag.clone();
        let thread_id_flag = thread_id.clone();
        let app_name = self.config.app.name.clone();

        thread::spawn(move || {
            if let Err(error) =
                run_tray_thread(app_name, thread_shutdown_flag, thread_id_flag, command_tx)
            {
                warn!(error = %error, "tray thread exited with error");
            }
        });

        info!("tray ready");

        Ok(TrayHandle {
            shutdown_flag,
            thread_id,
        })
    }
}

fn run_tray_thread(
    app_name: String,
    shutdown_flag: Arc<AtomicBool>,
    thread_id: Arc<AtomicU32>,
    command_tx: mpsc::UnboundedSender<TrayCommand>,
) -> Result<()> {
    // Build the minimum tray icon and context menu here.
    // Use the bundled icon data directly instead of depending on external image files.
    let menu = Menu::new();
    let open_item = MenuItem::new(&lang::text("tray.open"), true, None);
    let reload_item = MenuItem::new(&lang::text("tray.reload"), true, None);
    let exit_item = MenuItem::new(&lang::text("tray.exit"), true, None);
    menu.append(&open_item)?;
    menu.append(&reload_item)?;
    menu.append(&exit_item)?;

    let icon = build_default_icon()?;
    let _tray_icon = TrayIconBuilder::new()
        .with_tooltip(app_name)
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_icon(icon)
        .build()?;

    thread_id.store(unsafe { GetCurrentThreadId() }, Ordering::SeqCst);

    loop {
        if shutdown_flag.load(Ordering::SeqCst) {
            break;
        }

        let mut message: MSG = unsafe { std::mem::zeroed() };
        let status = unsafe { GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) };
        if status == -1 {
            anyhow::bail!("failed to read Windows tray message");
        }
        if status == 0 {
            break;
        }

        if message.message != WM_APP + 1 {
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }

        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::DoubleClick { button, .. } = event {
                if button == MouseButton::Left {
                    let _ = command_tx.send(TrayCommand::OpenControlPanel);
                }
            }
        }

        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == open_item.id() {
                let _ = command_tx.send(TrayCommand::OpenControlPanel);
            } else if event.id == reload_item.id() {
                let _ = command_tx.send(TrayCommand::Reload);
            } else if event.id == exit_item.id() {
                let _ = command_tx.send(TrayCommand::Exit);
                return Ok(());
            }
        }
    }

    Ok(())
}

fn build_default_icon() -> Result<Icon> {
    let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/relaygate.ico"));
    let icon_dir = IconDir::read(std::io::Cursor::new(bytes.as_slice()))?;
    let entry = icon_dir
        .entries()
        .iter()
        .max_by_key(|entry| entry.width())
        .ok_or_else(|| anyhow::anyhow!("icon file does not contain any entries"))?;
    let image = entry.decode()?;

    Ok(Icon::from_rgba(
        image.rgba_data().to_vec(),
        image.width(),
        image.height(),
    )?)
}
