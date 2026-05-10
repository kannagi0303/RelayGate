use std::{io::ErrorKind, net::SocketAddr};

use tracing::{debug, warn};

use crate::diagnostics;

pub(crate) fn log_connection_error(peer_addr: SocketAddr, error: &anyhow::Error) {
    if is_expected_proxy_abort(error) {
        debug!(peer = %peer_addr, error = %error, "proxy connection closed early");
        return;
    }

    let error_chain = diagnostics::format_error_chain(error);
    let console_error = diagnostics::format_error_for_console(error);
    let console_error_chain = diagnostics::format_error_chain_for_console(error);
    let _ = diagnostics::append_proxy_diagnostic(&format!(
        "ts={} peer={} event=proxy_connection_failed error_chain={}",
        diagnostics::diagnostic_timestamp(),
        peer_addr,
        error_chain
    ));
    warn!(
        peer = %peer_addr,
        error = %console_error,
        error_chain = %console_error_chain,
        "proxy connection failed"
    );
}

pub(crate) fn is_expected_proxy_abort(error: &anyhow::Error) -> bool {
    is_expected_disconnect(error)
        || is_expected_disconnect_text(error)
        || is_incomplete_http_request(error)
        || is_request_body_limit_after_upstream_started(error)
        || is_expected_mitm_handshake_abort(error)
}

fn is_expected_disconnect(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io_error| {
            io_error.kind() == ErrorKind::ConnectionAborted
                || io_error.kind() == ErrorKind::ConnectionReset
                || matches!(io_error.raw_os_error(), Some(10053 | 10054))
        })
}

fn is_expected_disconnect_text(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let text = cause.to_string().to_ascii_lowercase();
        text.contains("os error 10053")
            || text.contains("os error 10054")
            || text.contains("connection reset by peer")
            || text.contains("connection aborted")
            || text.contains("連線已被您主機上的軟體中止")
    })
}

fn is_incomplete_http_request(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .to_string()
            .contains("invalid HTTP request: missing header terminator")
    })
}

fn is_request_body_limit_after_upstream_started(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .to_string()
            .contains("request body limit handled after upstream started")
    })
}

fn is_expected_mitm_handshake_abort(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let text = cause.to_string();
        text.contains("failed to accept TLS from client during MITM handshake")
            || text.contains("received fatal alert")
            || text.contains("unexpected eof")
            || text.contains("peer closed connection without sending TLS close_notify")
            || text.contains("Handshake not complete")
            || text.contains("failed to accept downstream HTTP/2 MITM connection")
            || text.contains("failed to accept downstream HTTP/2 MITM stream")
    })
}
