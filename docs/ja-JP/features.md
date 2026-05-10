# Features

このファイルは RelayGate の機能を詳しく一覧にします。

## ユーザー向け機能

- ローカル Windows proxy。
- ローカル CA を使う HTTPS MITM。
- Ad blocking と document filtering。
- ローカルルールによるページとリソースの変更。
- ローカルファイルによる resource replacement。
- Tampermonkey / ScriptCat 風の互換型ローカル User Scripts。
- DNS profiles、DNS cache、host-based DNS routes。
- upstream proxy profiles と per-site routing。
- local gateway による site mounts。
- request burst control のための traffic scheduling。
- ローカル Web control panel。
- Windows tray control。

## モジュール説明

ローカル Web コントロールパネルのモジュールに合わせて読みたい場合は、[Modules](./modules/README.md) を見てください。

## Protocol And Transport Capabilities

これは低レベルの機能です。RelayGate が何を扱えるか知りたいユーザー向けです。

- HTTP proxy requests。
- HTTPS CONNECT tunnel。
- HTTP Upgrade 後の WebSocket bridge。
- HTTP/1 handling。
- downstream HTTP/2 MITM handling。
- fallback 付きの guarded upstream HTTP/3 path。
- Range と `206 Partial Content` passthrough。
- supported paths の request body streaming。

## Content Processing Capabilities

機能パスが許す場合、RelayGate は変更可能な HTTP / HTTPS document を処理できます。

- request blocking。
- request header rewrite。
- response body rewrite。
- HTML patch rules。
- JSON patch rules。
- template-based page reconstruction。
- local file resource replacement。
- adblock cosmetic と document injection。
- mutable HTML documents への User Script injection。

Range と `206 Partial Content` responses は変更されません。

## Routing And DNS

RelayGate は DNS と upstream proxy routing にローカルルールを使えます。

- upstream proxy profiles。
- host wildcard upstream routes。
- DNS profiles。
- host wildcard DNS routes。
- DNS cache。
- negative cache。
- stale fallback。
- system DNS fallback。

## Traffic Scheduling

Traffic scheduling はローカル request control feature です。

`429 Too Many Requests` の後に同じサイトへの request burst を遅くし、cooldown state で同じサイトへの繰り返し負荷を減らせます。

[Traffic Scheduling](./traffic-scheduling.md) を見てください。

## Site Mounts

Site mounts は local gateway 経由で、remote site を local path 配下に公開します。

[Site Mounts](./site-mounts.md) を見てください。

## Beta Limits

[Known Limitations](./known-limitations.md) を見てください。
