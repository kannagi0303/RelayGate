use anyhow::Result;
use ico::IconDir;
use tray_icon::Icon;

pub(super) fn build_default_icon() -> Result<Icon> {
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
