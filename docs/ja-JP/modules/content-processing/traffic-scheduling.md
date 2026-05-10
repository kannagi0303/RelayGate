# Traffic Scheduling

## このモジュールでできること

Traffic Scheduling モジュールは、request burst と same-site pressure を制御します。

request admission、cooldown state、queueing、delayed retry、release strategy を扱う方向のモジュールです。

## 使う場面

サイトが `429 Too Many Requests` を返す場合や、同じサイトへの繰り返しリクエストを抑えたい場合に使います。

同じ host への連続した負荷を減らしたいときに向いています。

## 仕組み

RelayGate は runtime traffic から cooldown state を学習し、同じサイトへの後続リクエストをよりゆっくり流すことができます。

このモジュールは request control に集中しており、response content rewrite は扱いません。

## 注意点

これは early beta のモジュールです。

現在の動作は意図的に控えめです。完全な rate-limit solution ではなく、request scheduling support として扱ってください。

## 関連ドキュメント

- [Traffic Scheduling](../../../traffic-scheduling.md)
- [Known Limitations](../../../known-limitations.md)
