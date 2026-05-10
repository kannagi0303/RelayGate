# Upstream Rules

## What It Does

The Upstream Rules module chooses which upstream proxy profile should be used for a specific host.

It provides per-site routing on top of the upstream proxy list.

## When To Use It

Use this module when one site should go through an upstream proxy and another site should stay direct.

It is useful for testing site-specific routes without changing the whole browser proxy setup.

## How It Works

RelayGate evaluates host rules against request hosts.

Rules can use patterns such as `example.com`, `www.example.com`, and `*.example.com`.

Matched requests can be sent through the selected upstream proxy profile.

## Notes

Rules are evaluated by host and apply to new requests.

If an upstream proxy profile is removed, rules that point to it may become missing until adjusted.

## Related Docs

- [Upstream Proxies](./upstream-proxies.md)
- [DNS](./dns.md)
