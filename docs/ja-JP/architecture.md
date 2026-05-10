# Architecture

RelayGate は小さな常駐 control surface を持つ local proxy application です。

## Main Flow

1. Browser または app が traffic を RelayGate に送ります。
2. RelayGate が local proxy、routing、DNS、rule decisions を適用します。
3. RelayGate は tunnel、forward、または HTTPS MITM を処理します。
4. mutable responses は content processing を通る場合があります。
5. 結果が browser または app に返されます。

## Main Areas

- proxy server
- CONNECT tunnel handling
- HTTPS MITM handling
- downstream HTTP/2 MITM handling
- upstream forwarding
- guarded upstream HTTP/3 path
- adblock engine
- rewrite and patch rules
- resource replacement
- local User Script injection
- DNS resolver and cache
- upstream proxy routing
- traffic scheduling
- gateway site mounts
- local web control panel
- Windows tray

## HTTPS MITM Boundary

HTTPS MITM は decrypted HTTPS content が必要な機能だけで使われます。

Plain tunnel mode は内容を読まずに encrypted HTTPS traffic を転送できます。

## Runtime State

RelayGate は runtime state を local に保持します。これには logs、DNS cache、traffic state、adblock data、CA files が含まれる場合があります。

[Privacy And Data](./privacy-and-data.md) を見てください。
