# Page Reconstruction

## このモジュールでできること

Page Reconstruction モジュールは、抽出したデータから出力を再構築します。

simple patch では足りず、先にデータを抽出してから local template で新しい response を作りたい場合に使います。

## 使う場面

target page を direct response patching ではなく、extract-and-render として扱ったほうがよい場合に使います。

controlled views、simplified pages、parser-like output、template-based local replacement に向いています。

## 仕組み

RelayGate は request が rule path に一致した場合、extraction rules を適用し、data を準備し、local templates で output を render します。

## 注意点

Page reconstruction は page patching よりも大きく内容を変える機能です。

出力を元のページと意図的に変えたい場合に使うのが適しています。

## 関連ドキュメント

- [Rewrite Rules](../../../rewrite-rules.md)
- [Page Patching](./page-patching.md)
