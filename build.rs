use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/relaygate.ico");
    println!("cargo:rerun-if-changed=assets/lang/en-US.lang");
    println!("cargo:rerun-if-changed=assets/lang/zh-TW.lang");
    println!("cargo:rerun-if-changed=languages/en-US.lang");
    println!("cargo:rerun-if-changed=frontend/package.json");
    println!("cargo:rerun-if-changed=frontend/pnpm-lock.yaml");
    println!("cargo:rerun-if-changed=frontend/index.html");
    println!("cargo:rerun-if-changed=frontend/vite.config.ts");
    println!("cargo:rerun-if-changed=frontend/tsconfig.json");
    println!("cargo:rerun-if-changed=frontend/.relaygate-build-stamp");
    println!("cargo:rerun-if-env-changed=RELAYGATE_SKIP_WEB_BUILD");
    emit_rerun_for_dir(Path::new("frontend/src"));
    println!("cargo:rerun-if-changed=data");
    println!("cargo:rerun-if-changed=relaygate.yaml");

    if let Err(error) = build_web_assets() {
        panic!("failed to build RelayGate web assets: {error}");
    }

    #[cfg(windows)]
    if let Err(error) = build_windows_icon() {
        panic!("failed to build RelayGate Windows icon: {error}");
    }
}

fn build_web_assets() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let output_rs = out_dir.join("web_assets.rs");

    if env::var("RELAYGATE_SKIP_WEB_BUILD").is_ok() {
        write_fallback_web_assets(&output_rs)?;
        return Ok(());
    }

    let frontend_dir = PathBuf::from("frontend");
    let node_modules = frontend_dir.join("node_modules");
    if !node_modules.exists() {
        return Err(
            "frontend/node_modules is missing; run `pnpm install` in frontend/ first".into(),
        );
    }

    let mut command = Command::new(pnpm_command());
    command.arg("build").current_dir(&frontend_dir);
    hide_command_window(&mut command);
    let status = command.status()?;
    if !status.success() {
        return Err(format!("`pnpm build` failed with status {status}").into());
    }

    let dist_dir = frontend_dir.join("dist");
    if !dist_dir.join("index.html").exists() {
        return Err("frontend/dist/index.html was not produced by Vite".into());
    }

    let stamp = write_frontend_build_stamp(&frontend_dir)?;
    write_embedded_web_assets(&output_rs, &dist_dir, &stamp)?;
    Ok(())
}

fn emit_rerun_for_dir(dir: &Path) {
    println!("cargo:rerun-if-changed={}", dir.display());
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            emit_rerun_for_dir(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn write_fallback_web_assets(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let html = "<!doctype html><html><head><meta charset=\"utf-8\"><title>RelayGate</title></head><body><main><h1>RelayGate</h1><p>Frontend build skipped.</p></main></body></html>";
    let escaped = html.escape_default().to_string();
    fs::write(
        path,
        format!(
            "pub(crate) const WEB_ASSET_BUILD_STAMP: &str = \"skipped\";\npub(crate) const WEB_ASSETS: &[crate::web::assets::EmbeddedAsset] = &[crate::web::assets::EmbeddedAsset {{ path: \"index.html\", content_type: \"text/html; charset=utf-8\", bytes: b\"{escaped}\" }}];\n"
        ),
    )?;
    Ok(())
}

fn write_embedded_web_assets(
    output_rs: &Path,
    dist_dir: &Path,
    stamp: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_files(dist_dir, dist_dir, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut output = String::new();
    output.push_str(&format!(
        "pub(crate) const WEB_ASSET_BUILD_STAMP: &str = \"{}\";\n",
        escape_rust_string(stamp)
    ));
    output.push_str("pub(crate) const WEB_ASSETS: &[crate::web::assets::EmbeddedAsset] = &[\n");
    for (relative_path, absolute_path) in files {
        let content_type = content_type_for_path(&relative_path);
        output.push_str("    crate::web::assets::EmbeddedAsset {\n");
        output.push_str(&format!(
            "        path: \"{}\",\n",
            escape_rust_string(&relative_path)
        ));
        output.push_str(&format!("        content_type: \"{content_type}\",\n"));
        output.push_str(&format!(
            "        bytes: include_bytes!(r#\"{}\"#),\n",
            absolute_path.display()
        ));
        output.push_str("    },\n");
    }
    output.push_str("];\n");
    fs::write(output_rs, output)?;
    Ok(())
}

fn write_frontend_build_stamp(frontend_dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let stamp = format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    fs::write(frontend_dir.join(".relaygate-build-stamp"), &stamp)?;
    Ok(stamp)
}

fn collect_files(
    root: &Path,
    dir: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files)?;
            continue;
        }

        let relative = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        files.push((relative, path.canonicalize()?));
    }
    Ok(())
}

fn content_type_for_path(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|item| item.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn escape_rust_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn hide_command_window(command: &mut Command) {
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
}

fn pnpm_command() -> &'static str {
    if cfg!(windows) {
        "pnpm.cmd"
    } else {
        "pnpm"
    }
}

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
