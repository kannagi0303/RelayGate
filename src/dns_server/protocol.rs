use std::net::IpAddr;

use anyhow::{anyhow, bail, Context, Result};
use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::{DNSClass, RecordType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsServerQueryType {
    A,
    Aaaa,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerQuery {
    pub name: String,
    pub query_type: DnsServerQueryType,
    pub query_type_label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsServerResponseKind {
    /// Successful DNS response. An empty answer section means NODATA, not NXDOMAIN.
    NoError,
    /// Malformed DNS packet.
    FormErr,
    /// The queried domain name does not exist.
    NxDomain,
    /// Temporary resolver/upstream failure.
    ServFail,
    /// Query type/opcode is not implemented by RelayGate's first-version DNS server.
    NotImp,
}

pub struct DnsServerRequest {
    id: u16,
    request_flags: u16,
    question_wire: Vec<u8>,
    query: DnsServerQuery,
}

impl DnsServerRequest {
    pub fn parse(packet: &[u8]) -> Result<Self> {
        let raw = RawDnsQuestion::parse(packet)?;
        let message = Message::from_vec(packet).context("failed to parse DNS packet")?;

        if message.message_type != MessageType::Query {
            bail!("DNS packet is not a query");
        }

        if message.queries.len() != 1 {
            bail!(
                "expected exactly one DNS question, got {}",
                message.queries.len()
            );
        }

        let query = &message.queries[0];
        if query.query_class() != DNSClass::IN {
            bail!("unsupported DNS query class: {}", query.query_class());
        }

        let name = normalized_query_name(query.name().to_ascii())?;
        let query_type_label = format!("{:?}", query.query_type());
        let query_type = match query.query_type() {
            RecordType::A => DnsServerQueryType::A,
            RecordType::AAAA => DnsServerQueryType::Aaaa,
            _ => DnsServerQueryType::Unsupported,
        };

        Ok(Self {
            id: raw.id,
            request_flags: raw.flags,
            question_wire: raw.question_wire,
            query: DnsServerQuery {
                name,
                query_type,
                query_type_label,
            },
        })
    }

    pub fn query(&self) -> &DnsServerQuery {
        &self.query
    }

    pub fn build_address_response(&self, addrs: &[IpAddr], ttl_secs: u32) -> Result<Vec<u8>> {
        if self.query.query_type == DnsServerQueryType::Unsupported {
            return self.build_empty_response(DnsServerResponseKind::NotImp);
        }

        let mut answers = Vec::new();
        for addr in addrs {
            match (self.query.query_type, *addr) {
                (DnsServerQueryType::A, IpAddr::V4(ip)) => {
                    answers.push(WireAnswer {
                        record_type: DNS_TYPE_A,
                        rdata: ip.octets().to_vec(),
                    });
                }
                (DnsServerQueryType::Aaaa, IpAddr::V6(ip)) => {
                    answers.push(WireAnswer {
                        record_type: DNS_TYPE_AAAA,
                        rdata: ip.octets().to_vec(),
                    });
                }
                _ => {}
            }
        }

        self.build_wire_response(DnsServerResponseKind::NoError, &answers, ttl_secs)
    }

    pub fn build_empty_response(&self, kind: DnsServerResponseKind) -> Result<Vec<u8>> {
        self.build_wire_response(kind, &[], 0)
    }

    pub fn build_formerr_response(packet: &[u8]) -> Option<Vec<u8>> {
        let id = read_u16(packet, 0)?;
        let request_flags = read_u16(packet, 2).unwrap_or(0);
        let flags = response_flags(request_flags, DnsServerResponseKind::FormErr);

        let mut response = Vec::with_capacity(DNS_HEADER_LEN);
        write_u16(&mut response, id);
        write_u16(&mut response, flags);
        write_u16(&mut response, 0);
        write_u16(&mut response, 0);
        write_u16(&mut response, 0);
        write_u16(&mut response, 0);
        Some(response)
    }

    fn build_wire_response(
        &self,
        kind: DnsServerResponseKind,
        answers: &[WireAnswer],
        ttl_secs: u32,
    ) -> Result<Vec<u8>> {
        if answers.len() > u16::MAX as usize {
            bail!("too many DNS answers: {}", answers.len());
        }

        let mut response =
            Vec::with_capacity(DNS_HEADER_LEN + self.question_wire.len() + answers.len() * 32);
        write_u16(&mut response, self.id);
        write_u16(&mut response, response_flags(self.request_flags, kind));
        write_u16(&mut response, 1);
        write_u16(&mut response, answers.len() as u16);
        write_u16(&mut response, 0);
        write_u16(&mut response, 0);
        response.extend_from_slice(&self.question_wire);

        for answer in answers {
            // Pointer to the original QNAME at byte offset 12.
            response.extend_from_slice(&[0xC0, 0x0C]);
            write_u16(&mut response, answer.record_type);
            write_u16(&mut response, DNS_CLASS_IN);
            write_u32(&mut response, ttl_secs);
            if answer.rdata.len() > u16::MAX as usize {
                return Err(anyhow!("DNS answer rdata is too large"));
            }
            write_u16(&mut response, answer.rdata.len() as u16);
            response.extend_from_slice(&answer.rdata);
        }

        Ok(response)
    }
}

struct RawDnsQuestion {
    id: u16,
    flags: u16,
    question_wire: Vec<u8>,
}

impl RawDnsQuestion {
    fn parse(packet: &[u8]) -> Result<Self> {
        let id = read_u16(packet, 0).ok_or_else(|| anyhow!("DNS packet too short"))?;
        let flags = read_u16(packet, 2).ok_or_else(|| anyhow!("DNS packet too short"))?;
        let qdcount = read_u16(packet, 4).ok_or_else(|| anyhow!("DNS packet too short"))?;
        if qdcount != 1 {
            bail!("expected exactly one DNS question in wire header, got {qdcount}");
        }

        let question_end = parse_question_end(packet)?;
        Ok(Self {
            id,
            flags,
            question_wire: packet[DNS_HEADER_LEN..question_end].to_vec(),
        })
    }
}

struct WireAnswer {
    record_type: u16,
    rdata: Vec<u8>,
}

impl DnsServerResponseKind {
    fn rcode(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
        }
    }
}

fn normalized_query_name(mut name: String) -> Result<String> {
    if name.is_empty() || name == "." {
        bail!("empty DNS query name");
    }

    if name.ends_with('.') {
        name.pop();
    }

    if name.is_empty() || name.contains("..") {
        bail!("invalid DNS query name");
    }

    Ok(name.to_ascii_lowercase())
}

fn parse_question_end(packet: &[u8]) -> Result<usize> {
    if packet.len() < DNS_HEADER_LEN {
        bail!("DNS packet too short");
    }

    let mut pos = DNS_HEADER_LEN;
    loop {
        if pos >= packet.len() {
            bail!("DNS question name exceeds packet length");
        }

        let label_len = packet[pos];
        pos += 1;
        if label_len == 0 {
            break;
        }
        if label_len & 0xC0 != 0 {
            bail!("compressed DNS question names are not supported");
        }
        if label_len > 63 {
            bail!("invalid DNS label length: {label_len}");
        }

        let next = pos + label_len as usize;
        if next > packet.len() {
            bail!("DNS question label exceeds packet length");
        }
        pos = next;
    }

    let question_end = pos + 4;
    if question_end > packet.len() {
        bail!("DNS question missing type/class");
    }
    Ok(question_end)
}

fn response_flags(request_flags: u16, kind: DnsServerResponseKind) -> u16 {
    let opcode = request_flags & DNS_FLAG_OPCODE_MASK;
    let recursion_desired = request_flags & DNS_FLAG_RECURSION_DESIRED;
    let checking_disabled = request_flags & DNS_FLAG_CHECKING_DISABLED;
    let mut response = DNS_FLAG_RESPONSE
        | opcode
        | recursion_desired
        | checking_disabled
        | DNS_FLAG_RECURSION_AVAILABLE
        | kind.rcode();
    if opcode != 0 {
        response = (response & !DNS_RCODE_MASK) | DnsServerResponseKind::NotImp.rcode();
    }
    response
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes = packet.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

const DNS_HEADER_LEN: usize = 12;
const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_OPCODE_MASK: u16 = 0x7800;
const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const DNS_FLAG_CHECKING_DISABLED: u16 = 0x0010;
const DNS_RCODE_MASK: u16 = 0x000F;
