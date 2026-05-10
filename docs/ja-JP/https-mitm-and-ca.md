# HTTPS MITM And CA

このページでは RelayGate が HTTPS MITM と local CA files をどう使うか説明します。

## MITM の意味

MITM は "man in the middle" の略です。

ブラウザと本物の Web サイトの間に、別の当事者が入る接続形態です。

RelayGate では、ブラウザがローカルの RelayGate に接続し、RelayGate があなたの代わりに本物の Web サイトへ接続します。

## RelayGate が MITM を使う理由

通常の proxy tunnel mode は HTTPS traffic を読まずに転送できます。

一部の機能は HTTPS pages や resources を見たり変更したりする必要があります。そのような機能では HTTPS MITM を使えます。

例:

- document filtering
- page rules
- mutable documents 上の ad blocking
- resource replacement
- compatible User Script injection
- local debugging and inspection

## MITM は強力です

MITM は常に良いものではありません。

マルウェアは MITM 技術を悪用し、データを盗む、内容を注入する、プライベートな通信を監視することがあります。

一方で、ユーザーが許可している場合、MITM はローカル security tools、debugging proxies、development tools、parental-control tools、traffic inspection tools にも使われます。

RelayGate は MITM をローカル機能のためだけに使います。

RelayGate は open source なので、ユーザーは動作を確認できます。安全のため、この repository からのみダウンロードするか、自分で source から build してください。不明な第三者から入手した RelayGate binaries は実行しないでください。

## Local CA が必要な理由

HTTPS MITM が有効なとき、RelayGate はブラウザ向けの local site certificates を作ります。

ブラウザは RelayGate local CA を信頼する必要があります。信頼がない場合、ブラウザは certificate warning を表示するか、接続を拒否します。

RelayGate は local CA を生成できます。

Windows では、RelayGate は CA を current user's Root certificate store にインストールできます。Windows trust store を使うブラウザやアプリは、RelayGate が生成した certificates を信頼できます。

一部のブラウザやアプリは独自の trust store を使うため、別設定が必要になることがあります。

## CA Private Key Safety

CA private key はあなたの PC に残ります。

RelayGate 自体は CA private key を送信またはアップロードしません。

この key は、HTTPS MITM が有効なときに、local browser connection 用の certificate を作るためだけにローカルで使われます。

他人に共有しないでください。
アップロードしないでください。
公開しないでください。

RelayGate CA がインストールされている場合、この CA private key を持つ人は、あなたのブラウザに信頼される可能性がある certificate を作れます。

## Plain Tunnel Mode

RelayGate は CA をインストールしなくても実行できます。

Plain CONNECT tunnel mode は RelayGate CA を必要としません。この mode では RelayGate は HTTPS content を復号しません。

## Upstream Certificate Checks

RelayGate は default で upstream side の本物の target site certificate を確認します。

影響を理解していない場合、upstream certificate checks を無効にしないでください。
