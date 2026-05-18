# DNS

## What It Does

The DNS module manages RelayGate-owned DNS servers, host-based DNS routes, cache behavior, and learned DNS health.

It controls how RelayGate resolves domain names for requests that pass through RelayGate.

## When To Use It

Use this module when different sites should use different DNS servers, when you want local DNS cache behavior, or when you want RelayGate to learn from DNS health over time.

## How It Works

User DNS intent is stored in:

```text
data/user/settings.yaml > dns
```

RelayGate-generated DNS state is stored in:

```text
data/state/dns.bin
```

`dns.bin` stores DNS cache snapshots and learned DNS health state.

`origin_connect_health.bin` stores a low-frequency lazy snapshot of observed TCP IPv4 / IPv6 origin connection health. DNS uses this as a soft address-family preference for proxy/internal resolution only.

DNS routes can match exact hosts or wildcard subdomains.

DNS routes are strict internally. A route must target an explicit UDP DNS server profile. It cannot target `system` or `auto`.

Proxy/internal resolution may still use System DNS where safe. DNS Server ingress does not use System DNS as an upstream.

## DNS Server

DNS Server startup settings live in `relaygate.yaml` under `dns_server`.

Default behavior:

```text
dns_server.enabled = false
dns_server.host = inherit listen.host
dns_server.port = 53
```

`dns_server` can be omitted. Omitted config keeps the DNS Server listener disabled. Set `dns_server.enabled = true` explicitly to enable it.

## Notes

DNS settings apply to new requests.

Changing DNS servers or routes should clear old cache state so stale choices are not reused after switching.

This module affects requests resolved by RelayGate. It does not replace every DNS lookup made by Windows or other apps unless those clients explicitly use RelayGate's DNS Server.

## Related Docs

- [Features](../../features.md)
- [Configuration](../../configuration.md)
