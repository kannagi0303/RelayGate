# Upstream Proxies

## What It Does

The Upstream Proxies module defines outbound proxy profiles that RelayGate can use when connecting to websites.

An upstream proxy profile is an available outbound path. It does not decide by itself which site should use that path.

## When To Use It

Use this module when you want RelayGate to keep one or more upstream proxy addresses available.

This is useful when only selected sites should go through another proxy while the rest stay direct.

## How It Works

RelayGate stores upstream proxy profiles locally and can apply them to new outbound requests.

The current supported upstream proxy address form is `http://host:port`.

Use Upstream Rules to choose which hosts should use a profile.

## Notes

Changes apply to new requests. Existing outbound connections may finish naturally before switching completely.

## Related Docs

- [Upstream Rules](./upstream-rules.md)
- [Configuration](../../configuration.md)
