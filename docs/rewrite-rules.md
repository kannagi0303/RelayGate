# Rewrite Rules

RelayGate can modify pages and resources with local rules.

This feature is for users who want local page changes without writing a browser
extension for every case.

## What Rules Can Do

Rules can be used for:

- request matching
- response body rewrite
- HTML patching
- JSON patching
- template-based page reconstruction
- local file resource replacement

## Where Rules Live

Runtime rewrite data is local and private.

Typical runtime folders:

```text
data/rewrite/
data/resource_replace/
```

Do not publish private rule files unless they are meant to be public examples.

## HTTPS Sites

Rules that need HTTPS page content require HTTPS MITM.

The browser must trust the RelayGate local CA before HTTPS MITM can work without
certificate warnings.

See [HTTPS MITM And CA](./https-mitm-and-ca.md).

## Limits

- Range and `206 Partial Content` responses are not mutated.
- Binary resources should use resource replacement or passthrough behavior.
- Site-specific rules may break when the target site changes.
