# Resource Replace

## このモジュールでできること

Resource Replace モジュールは、一致した remote resource を local file に置き換えます。

request が upstream server に届く前に、scripts、stylesheets、images、その他の一致した resource を差し替えることができます。

## 使う場面

既知の remote resource を local file から提供したいときに使います。

testing、frontend assets の patch、壊れた resource の置き換え、controlled local copy の利用に向いています。

## 仕組み

RelayGate は local proxy flow の中で resource replacement rules を確認します。

request が rule に一致すると、RelayGate は remote resource を取得せず、設定された local file を返します。

## 注意点

rule が存在しない local file を指している場合、その rule は無効として修正する必要があります。

Rule toggles は hot apply できます。RelayGate の外でファイルを編集した場合は、control panel から resource rules を reload してください。

## 関連ドキュメント

- [Rewrite Rules](../../../rewrite-rules.md)
- [Features](../../../features.md)
