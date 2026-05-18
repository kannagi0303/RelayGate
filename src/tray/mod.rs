mod control_panel_open;
mod icon;
mod startup_notification;

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    MouseButton, TrayIconBuilder, TrayIconEvent,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, PostThreadMessageW, TranslateMessage, MSG, WM_APP,
};

use crate::{config::RelayGateConfig, lang};

use self::{
    control_panel_open::{browser_open_address, ControlPanelOpenGuard},
    icon::build_default_icon,
    startup_notification::{show_startup_notification, StartupNotification},
};

/// Abstraction layer for tray control.
/// This keeps the app layer stable if the tray crate or platform changes later.
pub trait TrayController {
    fn start(&self, command_tx: mpsc::UnboundedSender<TrayCommand>) -> Result<TrayHandle>;
}

#[derive(Debug, Clone, Copy)]
pub enum TrayCommand {
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
    tray_tx: std::sync::mpsc::Sender<TrayThreadCommand>,
}

impl TrayHandle {
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        self.wake_tray_thread();
        debug!("tray handle shutdown requested");
    }

    fn wake_tray_thread(&self) {
        let thread_id = self.thread_id.load(Ordering::SeqCst);
        if thread_id != 0 {
            unsafe {
                PostThreadMessageW(thread_id, WM_APP + 1, 0, 0);
            }
        }
    }

    pub fn notify_startup_ready(&self, listen: &str) {
        let notification = StartupNotification {
            title: lang::text("tray.startup_ready.title"),
            body: lang::format(
                "tray.startup_ready.body",
                &[("url", format!("http://{}/", browser_open_address(listen)))],
            ),
        };
        if let Err(error) = self
            .tray_tx
            .send(TrayThreadCommand::ShowStartupNotification(notification))
        {
            debug!(error = %error, "startup tray notification skipped because tray thread is gone");
        } else {
            self.wake_tray_thread();
        }
    }
}

#[derive(Debug)]
enum TrayThreadCommand {
    ShowStartupNotification(StartupNotification),
}

/// Windows tray icon implementation.
///
/// The first version focuses on:
/// - showing a tray icon
/// - providing open and Exit in the context menu
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
                id: "exit",
                label: lang::text("tray.exit"),
            },
        ]
    }
}

impl TrayController for SystemTray {
    fn start(&self, command_tx: mpsc::UnboundedSender<TrayCommand>) -> Result<TrayHandle> {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let thread_id = Arc::new(AtomicU32::new(0));
        let (tray_tx, tray_rx) = std::sync::mpsc::channel::<TrayThreadCommand>();
        let thread_shutdown_flag = shutdown_flag.clone();
        let thread_id_flag = thread_id.clone();
        let app_name = self.config.app.name.clone();
        let web_listen = self.config.proxy.listen.clone();

        thread::spawn(move || {
            if let Err(error) = run_tray_thread(
                app_name,
                web_listen,
                thread_shutdown_flag,
                thread_id_flag,
                command_tx,
                tray_rx,
            ) {
                warn!(error = %error, "tray thread exited with error");
            }
        });

        info!("tray ready");

        Ok(TrayHandle {
            shutdown_flag,
            thread_id,
            tray_tx,
        })
    }
}

fn run_tray_thread(
    app_name: String,
    web_listen: String,
    shutdown_flag: Arc<AtomicBool>,
    thread_id: Arc<AtomicU32>,
    command_tx: mpsc::UnboundedSender<TrayCommand>,
    tray_rx: std::sync::mpsc::Receiver<TrayThreadCommand>,
) -> Result<()> {
    let menu = Menu::new();
    let open_item = MenuItem::new(&lang::text("tray.open"), true, None);
    let exit_item = MenuItem::new(&lang::text("tray.exit"), true, None);
    menu.append(&open_item)?;
    menu.append(&exit_item)?;

    let open_guard = ControlPanelOpenGuard::new(web_listen.clone(), Duration::from_millis(800));

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

        drain_tray_thread_commands(&tray_rx);
        handle_tray_icon_events(&open_guard);
        if handle_tray_menu_events(&open_guard, &open_item, &exit_item, &command_tx)? {
            break;
        }
    }

    Ok(())
}

fn drain_tray_thread_commands(tray_rx: &std::sync::mpsc::Receiver<TrayThreadCommand>) {
    while let Ok(command) = tray_rx.try_recv() {
        match command {
            TrayThreadCommand::ShowStartupNotification(notification) => {
                thread::spawn(move || {
                    if let Err(error) = show_startup_notification(notification) {
                        warn!(error = %error, "startup tray notification failed");
                    }
                });
            }
        }
    }
}

fn handle_tray_icon_events(open_guard: &ControlPanelOpenGuard) {
    while let Ok(event) = TrayIconEvent::receiver().try_recv() {
        if let TrayIconEvent::DoubleClick { button, .. } = event {
            if button == MouseButton::Left {
                open_guard.request_open("tray-double-click");
            }
        }
    }
}

fn handle_tray_menu_events(
    open_guard: &ControlPanelOpenGuard,
    open_item: &MenuItem,
    exit_item: &MenuItem,
    command_tx: &mpsc::UnboundedSender<TrayCommand>,
) -> Result<bool> {
    while let Ok(event) = MenuEvent::receiver().try_recv() {
        if event.id == open_item.id() {
            open_guard.request_open("tray-menu");
        } else if event.id == exit_item.id() {
            let _ = command_tx.send(TrayCommand::Exit);
            return Ok(true);
        }
    }
    Ok(false)
}
