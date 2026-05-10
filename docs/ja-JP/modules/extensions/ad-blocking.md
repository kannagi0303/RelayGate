# Ad Blocking

## このモジュールでできること

Ad Blocking モジュールは、ローカルプロキシの経路で広告、トラッカー、不要なリクエストをブロックします。

RelayGate は `adblock-rust` を使用しています。これは Brave の内蔵広告ブロッカーで使われている Rust 製の adblock engine です。

## 使う場面

ブラウザに届く前に、不要なネットワークリクエストを RelayGate 側で減らしたいときに使います。

広告ブロック、トラッカーのブロック、既知の不要リソースのブロック、変更可能なページへの document filtering に向いています。

## 仕組み

RelayGate は adblock rules を読み込み、local proxy flow の中でリクエストが rule に一致するかを確認します。

HTTPS MITM が有効で、対象の document を変更できる場合は、document-level filtering や cosmetic injection も適用できます。

## 注意点

Ad blocking によって、一部のサイトが正しく動かなくなることがあります。

再生、ログイン、ページ状態の更新などに広告やトラッキング系リクエストを利用しているサイトでは、そのサイト向けに rule を無効化または調整する必要がある場合があります。

## 関連ドキュメント

- [Features](../../../features.md)
- [Known Limitations](../../../known-limitations.md)
