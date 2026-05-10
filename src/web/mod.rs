// Web settings modules:
// - `action_forms`: JSON action body parsing for backend POST handlers
// - `backend_payloads`: SSE backend payload structs and builders
// - `config_actions`: backend config mutation, runtime reload, and save helpers
// - `assets`: embedded Vite admin assets
// - `ui_assets`: handlers for the embedded admin app and static files
// - `server`: builds the HTTP server
// - `system_actions`: local OS helpers for folders and CA trust status
// - `routes`: defines pages and API endpoints
pub mod action_forms;
pub mod assets;
pub mod backend_payloads;
pub mod config_actions;
pub mod routes;
pub mod server;
pub mod system_actions;
pub mod ui_assets;
