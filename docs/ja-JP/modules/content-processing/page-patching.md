# Page Patching

## このモジュールでできること

Page Patching モジュールは、upstream response に対して小さく狙った編集を行います。

JSON field cleanup、HTML fragments、HTML 内の JavaScript value replacement、response header changes などに向いています。

## 使う場面

ページ全体を作り直す必要はなく、一部だけを変更したいときに使います。

特定の値を修正する、小さな fragment を削除する、document 全体を置き換えずに response を調整する、といった用途に向いています。

## 仕組み

RelayGate は local rule path から patch rules を読み込み、request が一致した場合に mutable response へ適用します。

RelayGate の外でルールを編集した場合は、control panel から rewrite rules を reload してください。

## 注意点

Page patching は、RelayGate が安全に mutable と扱える content にのみ適用されます。

Range responses と `206 Partial Content` responses は変更されません。

## 関連ドキュメント

- [Rewrite Rules](../../../rewrite-rules.md)
- [Page Reconstruction](./page-reconstruction.md)
