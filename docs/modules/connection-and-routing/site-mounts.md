# Site Mounts

## What It Does

The Site Mounts module exposes a remote site under a local RelayGate path.

For example, a remote website can be mounted under a local path such as `/site/`.

## When To Use It

Use this module when you want RelayGate to fetch a remote site through the normal local pipeline and present it under a local URL path.

This can be useful for controlled access, testing, proxy-side rewriting, or experiments with local gateway behavior.

## How It Works

RelayGate receives a request for the local mount path, fetches the target remote site, and can rewrite links back under the mount path when enabled.

A site mount may optionally use an upstream proxy profile.

## Notes

Link rewriting is best effort.

Complex websites may still use absolute URLs, scripts, service workers, or runtime navigation patterns that cannot always stay under the mount path.

## Related Docs

- [Site Mounts](../../site-mounts.md)
- [Upstream Proxies](./upstream-proxies.md)
