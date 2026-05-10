# DNS

## What It Does

The DNS module manages RelayGate DNS profiles, DNS cache behavior, and host-based DNS routes.

It lets RelayGate choose how proxy-owned requests resolve domain names.

## When To Use It

Use this module when different sites should use different DNS servers, when you want local DNS cache behavior, or when you need fallback behavior for unstable DNS resolution.

## How It Works

RelayGate can use DNS profiles and host patterns to select a DNS path for new requests.

DNS routes can match exact hosts or wildcard subdomains. RelayGate can also keep positive cache, negative cache, and stale fallback state depending on runtime behavior.

## Notes

DNS settings apply to new requests.

Changing DNS profiles or routes should clear old cache state so stale choices are not reused after switching.

This module affects requests resolved by RelayGate. It does not replace every DNS lookup made by Windows or other apps.

## Related Docs

- [Features](../../features.md)
- [Configuration](../../configuration.md)
