use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use tokio::{net::TcpStream, sync::mpsc, time};

use crate::{dns::SharedDnsResolver, proxy::mitm_ca::normalize_authority};

#[derive(Debug)]
pub(crate) struct HappyEyeballsConnectResult {
    pub(crate) stream: TcpStream,
    pub(crate) selected_addr: SocketAddr,
    pub(crate) connect_elapsed: Duration,
    pub(crate) delay: Duration,
}

impl HappyEyeballsConnectResult {
    pub(crate) fn selected_ip_family(&self) -> &'static str {
        if self.selected_addr.is_ipv4() {
            "ipv4"
        } else {
            "ipv6"
        }
    }

    pub(crate) fn connect_ms(&self) -> u64 {
        self.connect_elapsed.as_millis().min(u64::MAX as u128) as u64
    }

    pub(crate) fn delay_ms(&self) -> u64 {
        self.delay.as_millis().min(u64::MAX as u128) as u64
    }
}

pub(crate) async fn resolve_target_addresses(
    target: &str,
    dns_resolver: &SharedDnsResolver,
    use_relaygate_dns: bool,
) -> Result<Vec<SocketAddr>> {
    let (host, port) = normalize_authority(target)?;
    if use_relaygate_dns {
        dns_resolver.resolve_socket_addrs(&host, port).await
    } else {
        tokio::net::lookup_host(target)
            .await
            .with_context(|| format!("failed to resolve upstream target `{target}`"))
            .map(|addrs| addrs.collect::<Vec<_>>())
    }
}

pub(crate) async fn connect_happy_eyeballs(
    target_label: &str,
    mut addresses: Vec<SocketAddr>,
    delay: Duration,
) -> Result<HappyEyeballsConnectResult> {
    interleave_address_families(&mut addresses);

    if addresses.is_empty() {
        anyhow::bail!("target `{target_label}` did not resolve to any address");
    }

    let started_at = Instant::now();
    let (tx, mut rx) = mpsc::channel(addresses.len());
    let mut tasks = Vec::with_capacity(addresses.len());

    for (index, address) in addresses.iter().copied().enumerate() {
        let tx = tx.clone();
        let launch_delay = delay.saturating_mul(index as u32);
        tasks.push(tokio::spawn(async move {
            if !launch_delay.is_zero() {
                time::sleep(launch_delay).await;
            }
            let result = TcpStream::connect(address).await;
            let _ = tx.send((address, result)).await;
        }));
    }
    drop(tx);

    let mut errors = Vec::new();
    while let Some((address, result)) = rx.recv().await {
        match result {
            Ok(stream) => {
                for task in tasks {
                    task.abort();
                }
                return Ok(HappyEyeballsConnectResult {
                    stream,
                    selected_addr: address,
                    connect_elapsed: started_at.elapsed(),
                    delay,
                });
            }
            Err(error) => errors.push(format!("{address}: {error}")),
        }
    }

    anyhow::bail!(
        "failed to connect target `{target_label}`: {}",
        if errors.is_empty() {
            "no connection attempts completed".to_string()
        } else {
            errors.join("; ")
        }
    )
}

fn interleave_address_families(addresses: &mut Vec<SocketAddr>) {
    let v6 = addresses
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv6)
        .collect::<Vec<_>>();
    let v4 = addresses
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv4)
        .collect::<Vec<_>>();

    addresses.clear();
    for index in 0..v6.len().max(v4.len()) {
        if let Some(address) = v6.get(index) {
            addresses.push(*address);
        }
        if let Some(address) = v4.get(index) {
            addresses.push(*address);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaves_ipv6_and_ipv4_addresses() {
        let mut addresses = vec![
            "192.0.2.1:443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        ];

        interleave_address_families(&mut addresses);

        assert!(addresses[0].is_ipv6());
        assert!(addresses[1].is_ipv4());
        assert!(addresses[2].is_ipv6());
        assert!(addresses[3].is_ipv4());
    }
}
