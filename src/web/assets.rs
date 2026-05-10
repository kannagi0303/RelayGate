pub(crate) struct EmbeddedAsset {
    pub(crate) path: &'static str,
    pub(crate) content_type: &'static str,
    pub(crate) bytes: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));

pub(crate) fn build_stamp() -> &'static str {
    WEB_ASSET_BUILD_STAMP
}

pub(crate) fn get(path: &str) -> Option<&'static EmbeddedAsset> {
    let normalized = normalize_path(path);
    WEB_ASSETS.iter().find(|asset| asset.path == normalized)
}

pub(crate) fn index() -> Option<&'static EmbeddedAsset> {
    get("index.html")
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        "index.html".to_string()
    } else {
        trimmed.replace('\\', "/")
    }
}
