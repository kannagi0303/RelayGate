# Upstream Rules

## このモジュールでできること

Upstream Rules モジュールは、特定の host にどの upstream proxy profile を使うかを決めます。

upstream proxy list の上にある per-site routing のためのモジュールです。

## 使う場面

あるサイトは upstream proxy 経由、別のサイトは direct のままにしたいときに使います。

ブラウザ全体の proxy 設定を変えずに、サイトごとの route を試したい場合にも便利です。

## 仕組み

RelayGate は request host に対して host rules を評価します。

ルールには `example.com`、`www.example.com`、`*.example.com` のような pattern を使えます。

一致したリクエストは、選択した upstream proxy profile に送ることができます。

## 注意点

ルールは host に対して評価され、新しいリクエストに適用されます。

upstream proxy profile が削除された場合、それを参照している rule は調整されるまで missing になることがあります。

## 関連ドキュメント

- [Upstream Proxies](./upstream-proxies.md)
- [DNS](./dns.md)
