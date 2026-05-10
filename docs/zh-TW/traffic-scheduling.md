# Traffic Scheduling

Traffic scheduling 是本地請求控制功能。

當 RelayGate 看到 request bursts 或 `429 Too Many Requests` responses 時，它可以用來減少同一網站的重複壓力。

## 目前行為

RelayGate 可以依 site 保留 cooldown state。

當網站回傳 `429 Too Many Requests` 時，RelayGate 可以降低同站點後續請求速度，並更平緩地釋放 queued work。

這是 beta 功能。隨著 scheduler 變得更聰明，行為可能會調整。

## 它不是什麼

Traffic scheduling 不是 bandwidth booster。

它不會讓遠端伺服器變快。

它只是在網站已要求 client 放慢時，幫助 RelayGate 避免送出重複爆發。
