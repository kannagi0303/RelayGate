# DNS

## このモジュールでできること

DNS モジュールでは、RelayGate の DNS profiles、DNS cache behavior、host-based DNS routes を管理します。

RelayGate が自分で処理するリクエストについて、どのようにドメイン名を解決するかを選べます。

## 使う場面

サイトごとに違う DNS server を使いたいとき、ローカル DNS cache を使いたいとき、不安定な名前解決に fallback を用意したいときに使います。

## 仕組み

RelayGate は DNS profiles と host patterns を使い、新しいリクエストに対する DNS path を選択できます。

DNS routes は exact host や wildcard subdomains に一致できます。runtime behavior に応じて、positive cache、negative cache、stale fallback の状態も保持できます。

## 注意点

DNS 設定は新しいリクエストに適用されます。

DNS profiles や routes を変更した場合、古い cache state は再利用されないように消去されるべきです。

このモジュールは RelayGate が解決するリクエストに影響します。Windows や他のアプリのすべての DNS lookup を置き換えるものではありません。

## 関連ドキュメント

- [Features](../../../features.md)
- [Configuration](../../../configuration.md)
