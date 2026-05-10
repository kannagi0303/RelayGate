# Site Mounts

Site mounts let RelayGate expose a remote site under a local path through the
local gateway.

Example idea:

```text
/local-site/  ->  https://example.com/
```

This can be useful for local testing, controlled routing, or gateway-style
access to a remote site.

## Behavior

A mount can define:

- local mount path
- target base URL
- optional upstream proxy profile
- link rewrite behavior
- minimal fetch behavior

## Limits

Site mounts are a gateway feature.

Dynamic sites may still depend on origin checks, cookies, scripts, CORS behavior,
or absolute links that need extra handling.
