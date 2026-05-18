use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{self, Duration},
};
use tracing::{debug, info, warn};

use crate::{
    config::RelayGateConfig,
    dns::SharedDnsResolver,
    dns_server::protocol::{
        DnsServerQuery, DnsServerQueryType, DnsServerRequest, DnsServerResponseKind,
    },
    runtime::AppRuntime,
};

const DNS_PACKET_BUFFER_BYTES: usize = 4096;
const DNS_SERVER_RESPONSE_TTL_SECS: u32 = 60;
const DNS_SERVER_REQUEST_TIMEOUT: Duration = Duration::from_millis(1500);

pub(crate) struct DnsServer {
    listen: String,
    dns_resolver: SharedDnsResolver,
    runtime: AppRuntime,
}

impl DnsServer {
    pub(crate) fn new(
        config: Arc<RelayGateConfig>,
        dns_resolver: SharedDnsResolver,
        runtime: AppRuntime,
    ) -> Self {
        Self {
            listen: config.dns_server.listen_address(&config.listen),
            dns_resolver,
            runtime,
        }
    }

    pub(crate) async fn run(self) -> Result<()> {
        let addr: SocketAddr = self
            .listen
            .parse()
            .with_context(|| format!("invalid DNS server listen address: {}", self.listen))?;

        let udp_socket = match UdpSocket::bind(addr).await {
            Ok(socket) => Arc::new(socket),
            Err(error) => {
                warn!(
                    target: "relaygate::app",
                    listen = %addr,
                    error = %error,
                    "failed to bind UDP DNS server; DNS server disabled for this run"
                );
                return Err(error)
                    .with_context(|| format!("failed to bind UDP DNS server on {addr}"));
            }
        };

        let tcp_listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(error) => {
                warn!(
                    target: "relaygate::app",
                    listen = %addr,
                    error = %error,
                    "failed to bind TCP DNS server; DNS server disabled for this run"
                );
                return Err(error)
                    .with_context(|| format!("failed to bind TCP DNS server on {addr}"));
            }
        };

        info!(target: "relaygate::app", listen = %addr, "UDP DNS server ready");
        info!(target: "relaygate::app", listen = %addr, "TCP DNS server ready");

        let mut buffer = vec![0_u8; DNS_PACKET_BUFFER_BYTES];
        loop {
            tokio::select! {
                received = udp_socket.recv_from(&mut buffer) => {
                    let (len, peer) = match received {
                        Ok(received) => received,
                        Err(error) => {
                            warn!(listen = %addr, error = %error, "failed to receive UDP DNS packet");
                            continue;
                        }
                    };
                    let packet = buffer[..len].to_vec();
                    let socket = udp_socket.clone();
                    let dns_resolver = self.dns_resolver.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_udp_dns_packet(socket, dns_resolver, packet, peer).await {
                            warn!(peer = %peer, error = %error, "UDP DNS packet handling failed");
                        }
                    });
                }
                accepted = tcp_listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            warn!(listen = %addr, error = %error, "failed to accept TCP DNS connection");
                            continue;
                        }
                    };
                    let dns_resolver = self.dns_resolver.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_tcp_dns_connection(stream, dns_resolver, peer).await {
                            warn!(peer = %peer, error = %error, "TCP DNS connection handling failed");
                        }
                    });
                }
                _ = self.runtime.wait_for_shutdown() => {
                    info!(listen = %addr, "DNS server stopping");
                    return Ok(());
                }
            }
        }
    }
}

async fn handle_udp_dns_packet(
    socket: Arc<UdpSocket>,
    dns_resolver: SharedDnsResolver,
    packet: Vec<u8>,
    peer: SocketAddr,
) -> Result<()> {
    let Some(response) = build_dns_response(dns_resolver, packet, peer, "udp").await? else {
        return Ok(());
    };

    let response_bytes = response.len();
    let sent_bytes = socket
        .send_to(&response, peer)
        .await
        .with_context(|| format!("failed to send UDP DNS response to {peer}"))?;
    debug!(
        peer = %peer,
        response_bytes,
        sent_bytes,
        "UDP DNS response sent"
    );
    Ok(())
}

async fn handle_tcp_dns_connection(
    mut stream: TcpStream,
    dns_resolver: SharedDnsResolver,
    peer: SocketAddr,
) -> Result<()> {
    loop {
        let len = match read_tcp_dns_frame_len(&mut stream, peer).await? {
            Some(len) => len,
            None => return Ok(()),
        };
        if len == 0 || len > DNS_PACKET_BUFFER_BYTES {
            return Err(anyhow!("invalid TCP DNS frame length from {peer}: {len}"));
        }

        let mut packet = vec![0_u8; len];
        stream
            .read_exact(&mut packet)
            .await
            .with_context(|| format!("failed to read TCP DNS frame from {peer}"))?;

        let Some(response) = build_dns_response(dns_resolver.clone(), packet, peer, "tcp").await?
        else {
            continue;
        };
        if response.len() > u16::MAX as usize {
            return Err(anyhow!("TCP DNS response is too large: {}", response.len()));
        }

        let response_len = (response.len() as u16).to_be_bytes();
        stream
            .write_all(&response_len)
            .await
            .with_context(|| format!("failed to write TCP DNS response length to {peer}"))?;
        stream
            .write_all(&response)
            .await
            .with_context(|| format!("failed to write TCP DNS response to {peer}"))?;
        stream
            .flush()
            .await
            .with_context(|| format!("failed to flush TCP DNS response to {peer}"))?;
        debug!(
            peer = %peer,
            response_bytes = response.len(),
            "TCP DNS response sent"
        );
    }
}

async fn read_tcp_dns_frame_len(stream: &mut TcpStream, peer: SocketAddr) -> Result<Option<usize>> {
    let mut len_bytes = [0_u8; 2];
    match stream.read_exact(&mut len_bytes).await {
        Ok(_) => Ok(Some(u16::from_be_bytes(len_bytes) as usize)),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
            debug!(peer = %peer, "TCP DNS connection closed");
            Ok(None)
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to read TCP DNS frame length from {peer}"))
        }
    }
}

async fn build_dns_response(
    dns_resolver: SharedDnsResolver,
    packet: Vec<u8>,
    peer: SocketAddr,
    transport: &'static str,
) -> Result<Option<Vec<u8>>> {
    let request = match DnsServerRequest::parse(&packet) {
        Ok(request) => request,
        Err(error) => {
            warn!(
                transport = %transport,
                peer = %peer,
                packet_bytes = packet.len(),
                error = %error,
                response_kind = ?DnsServerResponseKind::FormErr,
                "failed to parse DNS request"
            );
            if let Some(response) = DnsServerRequest::build_formerr_response(&packet) {
                return Ok(Some(response));
            }
            return Ok(None);
        }
    };

    let query = request.query().clone();
    debug!(
        transport = %transport,
        peer = %peer,
        host = %query.name,
        query_type = %query.query_type_label,
        packet_bytes = packet.len(),
        "DNS query received"
    );

    // First-version DNS Server policy:
    // - A / AAAA are address queries and use RelayGate's DNS resolver with DnsServer ingress.
    // - A with no IPv4 or AAAA with no IPv6 returns NOERROR with an empty answer section (NODATA).
    // - Other record types are not implemented yet and return NOTIMP instead of pretending
    //   the record does not exist. This avoids false-empty MX/TXT/PTR/SOA answers.
    // - Parse failures return FORMERR when the request ID can be recovered.
    // - Resolver failures return NXDOMAIN only when the resolver error clearly says NXDOMAIN;
    //   otherwise they return SERVFAIL.
    let response = match query.query_type {
        DnsServerQueryType::A | DnsServerQueryType::Aaaa => {
            build_address_query_response(dns_resolver, &request, &query, peer, transport).await?
        }
        DnsServerQueryType::Unsupported => {
            build_unsupported_query_response(&request, &query, peer, transport)?
        }
    };

    debug!(
        transport = %transport,
        peer = %peer,
        host = %query.name,
        query_type = %query.query_type_label,
        response_bytes = response.len(),
        "DNS response built"
    );
    Ok(Some(response))
}

async fn build_address_query_response(
    dns_resolver: SharedDnsResolver,
    request: &DnsServerRequest,
    query: &DnsServerQuery,
    peer: SocketAddr,
    transport: &'static str,
) -> Result<Vec<u8>> {
    match time::timeout(
        DNS_SERVER_REQUEST_TIMEOUT,
        dns_resolver.resolve_host_for_dns_server(&query.name),
    )
    .await
    {
        Ok(Ok(addrs)) if addrs.is_empty() => {
            debug!(
                transport = %transport,
                peer = %peer,
                host = %query.name,
                query_type = %query.query_type_label,
                resolved_addrs = 0usize,
                answers = 0usize,
                response_kind = ?DnsServerResponseKind::NoError,
                "DNS server resolve returned empty address result"
            );
            request.build_empty_response(DnsServerResponseKind::NoError)
        }
        Ok(Ok(addrs)) => {
            let answer_count = matching_answer_count(&addrs, query.query_type);
            debug!(
                transport = %transport,
                peer = %peer,
                host = %query.name,
                query_type = %query.query_type_label,
                resolved_addrs = addrs.len(),
                answers = answer_count,
                addrs = %format_ip_addrs(&addrs),
                response_kind = ?DnsServerResponseKind::NoError,
                "DNS server address resolve completed"
            );
            if answer_count == 0 {
                // The host resolved, but not for the requested address family.
                // This is DNS NODATA: NOERROR with no answers, not NXDOMAIN.
                request.build_empty_response(DnsServerResponseKind::NoError)
            } else {
                request.build_address_response(&addrs, DNS_SERVER_RESPONSE_TTL_SECS)
            }
        }
        Ok(Err(error)) => {
            let response_kind = response_kind_for_resolve_error(&error);
            warn!(
                transport = %transport,
                peer = %peer,
                host = %query.name,
                query_type = %query.query_type_label,
                error = %error,
                response_kind = ?response_kind,
                "DNS server resolve failed"
            );
            request.build_empty_response(response_kind)
        }
        Err(_) => {
            warn!(
                transport = %transport,
                peer = %peer,
                host = %query.name,
                query_type = %query.query_type_label,
                timeout_ms = DNS_SERVER_REQUEST_TIMEOUT.as_millis(),
                response_kind = ?DnsServerResponseKind::ServFail,
                "DNS server resolve timed out"
            );
            request.build_empty_response(DnsServerResponseKind::ServFail)
        }
    }
}

fn build_unsupported_query_response(
    request: &DnsServerRequest,
    query: &DnsServerQuery,
    peer: SocketAddr,
    transport: &'static str,
) -> Result<Vec<u8>> {
    debug!(
        transport = %transport,
        peer = %peer,
        host = %query.name,
        query_type = %query.query_type_label,
        response_kind = ?DnsServerResponseKind::NotImp,
        "DNS query type is not implemented by the first-version DNS server"
    );
    request.build_empty_response(DnsServerResponseKind::NotImp)
}

fn response_kind_for_resolve_error(error: &anyhow::Error) -> DnsServerResponseKind {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("nxdomain") {
        DnsServerResponseKind::NxDomain
    } else {
        DnsServerResponseKind::ServFail
    }
}

fn matching_answer_count(addrs: &[IpAddr], query_type: DnsServerQueryType) -> usize {
    addrs
        .iter()
        .filter(|addr| {
            matches!(
                (query_type, *addr),
                (DnsServerQueryType::A, IpAddr::V4(_)) | (DnsServerQueryType::Aaaa, IpAddr::V6(_))
            )
        })
        .count()
}

fn format_ip_addrs(addrs: &[IpAddr]) -> String {
    if addrs.is_empty() {
        return "-".to_string();
    }

    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
