use axum::{
    body::Bytes,
    extract::Path,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::web::assets as web_assets;

const APP_ICON_BYTES: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/relaygate.ico"));

pub(crate) async fn favicon() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/x-icon")],
        APP_ICON_BYTES.to_vec(),
    )
}

pub(crate) async fn ui_index() -> Response {
    let _ = web_assets::build_stamp();
    match web_assets::index() {
        Some(asset) => asset_response(asset, false),
        None => (StatusCode::NOT_FOUND, "RelayGate UI was not embedded.").into_response(),
    }
}

pub(crate) async fn ui_asset(Path(path): Path<String>) -> Response {
    match web_assets::get(&path) {
        Some(asset) => asset_response(asset, true),
        None => (StatusCode::NOT_FOUND, "RelayGate UI asset was not found.").into_response(),
    }
}

fn asset_response(asset: &web_assets::EmbeddedAsset, hashed_asset: bool) -> Response {
    let cache_control = if hashed_asset {
        "public, max-age=31536000, immutable"
    } else {
        "no-store"
    };
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(asset.content_type),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(cache_control),
            ),
        ],
        Bytes::from_static(asset.bytes),
    )
        .into_response()
}
