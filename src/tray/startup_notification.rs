use std::{mem, ptr, thread, time::Duration};

use anyhow::{Context, Result};
use tracing::debug;
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    UI::{
        Shell::{
            Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIIF_NOSOUND,
            NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
        },
        WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, LoadIconW, RegisterClassW,
            HWND_MESSAGE, IDI_APPLICATION, WM_USER, WNDCLASSW, WS_OVERLAPPED,
        },
    },
};

const STARTUP_BALLOON_UID: u32 = 0x5247_0300;
const STARTUP_BALLOON_CALLBACK_MESSAGE: u32 = WM_USER + 0x300;
const STARTUP_BALLOON_SHOW_MS: u32 = 5_000;
const STARTUP_BALLOON_CLEANUP_DELAY: Duration = Duration::from_millis(5_500);

#[derive(Debug, Clone)]
pub struct StartupNotification {
    pub title: String,
    pub body: String,
}

pub(super) fn show_startup_notification(notification: StartupNotification) -> Result<()> {
    let class_name = wide_null("RelayGateStartupNotificationWindow");
    register_notification_window_class(&class_name);
    let hwnd = create_notification_window(&class_name)?;

    let icon = unsafe { LoadIconW(ptr::null_mut(), IDI_APPLICATION) };
    if icon.is_null() {
        unsafe {
            DestroyWindow(hwnd);
        }
        anyhow::bail!("failed to load startup notification icon");
    }

    let data = build_notify_icon_data(hwnd, icon, &notification);
    let added = unsafe { Shell_NotifyIconW(NIM_ADD, &data) } != 0;
    if !added {
        unsafe {
            DestroyWindow(hwnd);
        }
        anyhow::bail!("failed to show startup tray notification");
    }

    debug!("startup tray notification shown");
    thread::sleep(STARTUP_BALLOON_CLEANUP_DELAY);
    unsafe {
        Shell_NotifyIconW(NIM_DELETE, &data);
        DestroyWindow(hwnd);
    }
    Ok(())
}

fn register_notification_window_class(class_name: &[u16]) {
    let class = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(notification_window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: ptr::null_mut(),
        hIcon: ptr::null_mut(),
        hCursor: ptr::null_mut(),
        hbrBackground: ptr::null_mut(),
        lpszMenuName: ptr::null(),
        lpszClassName: class_name.as_ptr(),
    };
    unsafe {
        RegisterClassW(&class);
    }
}

fn create_notification_window(class_name: &[u16]) -> Result<HWND> {
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
        )
    };
    (!hwnd.is_null())
        .then_some(hwnd)
        .context("failed to create startup notification window")
}

fn build_notify_icon_data(
    hwnd: HWND,
    icon: windows_sys::Win32::UI::WindowsAndMessaging::HICON,
    notification: &StartupNotification,
) -> NOTIFYICONDATAW {
    let mut data: NOTIFYICONDATAW = unsafe { mem::zeroed() };
    data.cbSize = mem::size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = STARTUP_BALLOON_UID;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_INFO;
    data.uCallbackMessage = STARTUP_BALLOON_CALLBACK_MESSAGE;
    data.hIcon = icon;
    data.Anonymous.uTimeout = STARTUP_BALLOON_SHOW_MS;
    data.dwInfoFlags = NIIF_INFO | NIIF_NOSOUND;

    write_wide_fixed(&mut data.szTip, &notification.title);
    write_wide_fixed(&mut data.szInfoTitle, &notification.title);
    write_wide_fixed(&mut data.szInfo, &notification.body);
    data
}

fn write_wide_fixed<const N: usize>(target: &mut [u16; N], value: &str) {
    target.fill(0);
    for (slot, unit) in target
        .iter_mut()
        .take(N.saturating_sub(1))
        .zip(value.encode_utf16())
    {
        *slot = unit;
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe extern "system" fn notification_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}
