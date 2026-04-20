#[cfg(windows)]
use std::{env, path::PathBuf};

#[cfg(windows)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/relaygate.ico");
    println!("cargo:rerun-if-changed=data");
    println!("cargo:rerun-if-changed=relaygate.yaml");

    if let Err(error) = build_windows_icon() {
        panic!("failed to build RelayGate Windows icon: {error}");
    }
}

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn build_windows_icon() -> Result<(), Box<dyn std::error::Error>> {
    let icon_path = PathBuf::from("assets").join("relaygate.ico");
    if !icon_path.exists() {
        return Err(format!("missing icon asset: {}", icon_path.display()).into());
    }

    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".to_string());
    let description =
        env::var("CARGO_PKG_DESCRIPTION").unwrap_or_else(|_| "RelayGate local proxy".to_string());
    let product_name = env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "relaygate".to_string());

    let mut resource = winres::WindowsResource::new();
    resource.set_icon(icon_path.to_string_lossy().as_ref());
    resource.set("FileDescription", &description);
    resource.set("ProductName", &product_name);
    resource.set("FileVersion", &version);
    resource.set("ProductVersion", &version);
    resource.compile()?;

    Ok(())
}
