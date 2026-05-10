# Upstream Proxies

## このモジュールでできること

Upstream Proxies モジュールでは、RelayGate がサイトへ接続するときに使える outbound proxy profiles を定義します。

upstream proxy profile は、利用可能な外向きの経路です。それ自体が、どのサイトで使うかを決めるわけではありません。

## 使う場面

RelayGate に 1 つ以上の upstream proxy address を持たせたいときに使います。

特定のサイトだけを別の proxy に通し、それ以外は direct のままにしたい場合に向いています。

## 仕組み

RelayGate は upstream proxy profiles をローカルに保存し、新しい outbound request に適用できます。

現在サポートされている upstream proxy address の形式は `http://host:port` です。

どの host が profile を使うかは Upstream Rules で設定します。

## 注意点

変更は新しいリクエストに適用されます。既存の outbound connection は自然に終了してから完全に切り替わる場合があります。

## 関連ドキュメント

- [Upstream Rules](./upstream-rules.md)
- [Configuration](../../../configuration.md)
