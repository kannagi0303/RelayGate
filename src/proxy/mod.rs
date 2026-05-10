// Proxy modules:
// - `rules`: rule model and evaluation flow
// - `server`: main local proxy server flow
// - `upstream`: upstream proxy config and lookup
// - `upstream_h3`: upstream-only HTTP/3 observation seam
// - `upstream_h3_backend`: experimental upstream HTTP/3 backend skeleton
// - `upstream_model`: protocol-neutral RelayGate upstream request/response model
pub mod body_classification;
pub mod connect;
pub mod control_panel_proxy;
pub mod downstream_status;
pub mod happy_eyeballs;
pub mod header_hop;
pub mod http_forward;
pub mod http_framing;
pub mod http_parse;
pub mod local_response;
pub mod mitm;
pub mod mitm_ca;
pub mod mitm_core;
pub mod mitm_h2;
pub mod mitm_http;
pub mod mitm_inject;
pub mod mitm_upstream;
pub mod mount_forward;
pub mod outbound;
pub mod pipeline;
pub mod protocol_runtime;
pub mod resource_replace;
pub mod response_head;
pub mod rules;
pub mod server;
pub mod server_errors;
pub mod upstream;
pub mod upstream_h3;
pub mod upstream_h3_backend;
pub mod upstream_model;
