# Traffic Scheduling

## 這個模組做什麼

Traffic Scheduling 模組用來控制請求爆發與同站點壓力。

它的方向是管理 request admission、cooldown state、queueing、delayed retry，以及請求釋放策略。

## 什麼時候適合使用

當某個網站回傳 `429 Too Many Requests`，或你希望降低同站點重複請求壓力時，可以使用這個模組。

它適合用來減少對同一 host 的連續壓力。

## 它大致如何運作

RelayGate 可以從 runtime traffic 學習 cooldown state，並對後續同站點請求使用較慢的釋放節奏。

這個模組專注於 request control，不負責修改 response content。

## 注意事項

這是早期 beta 模組。

目前行為刻意保守，應該視為 request scheduling support，而不是完整 rate-limit 解決方案。

## 相關文件

- [Traffic Scheduling](../../../traffic-scheduling.md)
- [Known Limitations](../../../known-limitations.md)
