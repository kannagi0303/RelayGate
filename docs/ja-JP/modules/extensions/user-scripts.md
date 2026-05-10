# User Scripts

## このモジュールでできること

User Scripts モジュールは、ローカルの `.user.js` ファイルを管理し、一致する scripts を mutable HTML documents に注入します。

これは Tampermonkey / ScriptCat style scripts のための compatible local User Script support です。

## 使う場面

ブラウザの userscript manager だけに頼らず、RelayGate の proxy path から local scripts を実行したいときに使います。

小さなページ挙動の変更、local helpers、RelayGate の compatible injection model で動く scripts に向いています。

## 仕組み

RelayGate は local `.user.js` files を scan し、userscript metadata を読み取り、有効化された scripts を記録します。

一致した有効な scripts は、今後読み込まれる mutable HTML document responses に注入されます。

## 注意点

これは compatible support であり、完全な Tampermonkey / ScriptCat parity ではありません。

一部の userscript APIs は未対応、または異なる方法で実装されている場合があります。script を有効にする前に読み込まれたページは reload してください。

## 関連ドキュメント

- [User Script Guide](../../../user-script.md)
- [HTTPS MITM And CA](../../../https-mitm-and-ca.md)
