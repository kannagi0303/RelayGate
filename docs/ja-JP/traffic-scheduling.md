# Traffic Scheduling

Traffic scheduling は local request control feature です。

RelayGate が request bursts や `429 Too Many Requests` responses を見たとき、同じ site への繰り返し負荷を減らすために使われます。

## Current Behavior

RelayGate は site ごとに cooldown state を保持できます。

site が `429 Too Many Requests` を返すと、RelayGate は同じ site への後続 request を遅くし、queued work をよりゆっくり release できます。

これは beta feature です。scheduler が賢くなるにつれて behavior は変わる可能性があります。

## What It Is Not

Traffic scheduling は bandwidth booster ではありません。

remote server を速くするものではありません。

site が client に slow down を求めているとき、RelayGate が繰り返し burst を送らないようにするものです。
