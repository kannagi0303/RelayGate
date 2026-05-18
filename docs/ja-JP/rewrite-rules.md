# Rewrite Rules

RelayGate は local rules で pages と resources を変更できます。

この機能は、ケースごとに browser extension を書かずに local page changes を行いたいユーザー向けです。

## Rules Can Do

Rules can be used for:

- request matching
- response body rewrite
- HTML patching
- JSON patching
- template-based page reconstruction
- local file resource replacement

## Where Rules Live

Runtime rewrite data は local private data です。

Typical user rule folders:

```text
data/user/rewrite/
data/user/patch/
data/user/resource_replace/
```

意図して共有する場合を除き、private rule files は公開しないでください。

## HTTPS Sites

HTTPS page content が必要な rules は HTTPS MITM が必要です。

HTTPS MITM が certificate warnings なしで動くには、browser が RelayGate local CA を信頼する必要があります。

[HTTPS MITM And CA](./https-mitm-and-ca.md) を見てください。

## Limits

- Range と `206 Partial Content` responses は変更されません。
- Binary resources は resource replacement または passthrough behavior を使うべきです。
- Site-specific rules は target site の変更で壊れることがあります。
