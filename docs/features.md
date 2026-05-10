# Features

This file lists RelayGate capabilities in more detail.

## User-Facing Features

- Local Windows proxy.
- HTTPS MITM with a local CA.
- Ad blocking and document filtering.
- Page and resource modification with local rules.
- Resource replacement with local files.
- Compatible local User Scripts, including Tampermonkey / ScriptCat style scripts.
- DNS profiles, DNS cache, and host-based DNS routes.
- Upstream proxy profiles and per-site routing.
- Site mounts through the local gateway.
- Traffic scheduling for request burst control.
- Local web control panel.
- Windows tray control.

## Module Guide

For explanations that match the local web control panel modules, see [Modules](./modules/README.md).

## Protocol And Transport Capabilities

These are lower-level capabilities. They are useful for users who want to know
what RelayGate can handle.

- HTTP proxy requests.
- HTTPS CONNECT tunnel.
- WebSocket bridge after HTTP Upgrade.
- HTTP/1 handling.
- Downstream HTTP/2 MITM handling.
- Guarded upstream HTTP/3 path with fallback.
- Range and `206 Partial Content` passthrough.
- Request body streaming for supported paths.

## Content Processing Capabilities

RelayGate can process mutable HTTP and HTTPS documents when the feature path
allows it.

- Request blocking.
- Request header rewrite.
- Response body rewrite.
- HTML patch rules.
- JSON patch rules.
- Template-based page reconstruction.
- Local file resource replacement.
- Adblock cosmetic and document injection.
- User Script injection into mutable HTML documents.

Range and `206 Partial Content` responses are not mutated.

## Routing And DNS

RelayGate can use local routing rules for DNS and upstream proxies.

- Upstream proxy profiles.
- Host wildcard upstream routes.
- DNS profiles.
- Host wildcard DNS routes.
- DNS cache.
- Negative cache.
- Stale fallback.
- System DNS fallback.

## Traffic Scheduling

Traffic scheduling is a local request control feature.

It can slow down same-site request bursts after `429 Too Many Requests` and use
cooldown state to reduce repeated pressure on the same site.

See [Traffic Scheduling](./traffic-scheduling.md).

## Site Mounts

Site mounts let RelayGate expose remote sites under local paths through the
local gateway.

See [Site Mounts](./site-mounts.md).

## Beta Limits

See [Known Limitations](./known-limitations.md).
