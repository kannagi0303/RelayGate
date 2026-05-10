# Settings

## このモジュールでできること

Settings モジュールでは、RelayGate のよく使う実行設定を管理します。

Protocol preference、CA trust actions、language selection、安全な reload actions、RelayGate の終了操作などを扱います。

## 使う場面

RelayGate の接続方法を変更したいとき、ローカル CA を管理したいとき、ローカルルールを再読み込みしたいとき、または RelayGate を安全に終了したいときに使います。

## 仕組み

設定を保存すると、RelayGate のローカル設定に書き込まれます。

一部の変更は新しい接続にのみ反映されます。既存の browser connection や upstream connection は、自然に終了してから新しい設定が反映される場合があります。

## 注意点

Settings の hot reload は、すべての listener や connection を再起動することとは違います。

Protocol や listener 関連の変更がすぐに見えない場合は、ブラウザを再接続するか、RelayGate を再起動してください。

## 関連ドキュメント

- [HTTPS MITM And CA](../../../https-mitm-and-ca.md)
- [Configuration](../../../configuration.md)
- [Known Limitations](../../../known-limitations.md)
