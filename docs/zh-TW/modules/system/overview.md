# Overview

## 這個模組做什麼

Overview 模組會顯示 RelayGate 目前的執行狀態。

它是一個快速狀態頁，可以查看本地 proxy、已載入功能模組、DNS profiles、upstream proxies、site mounts，以及基本環境資訊。

## 什麼時候適合使用

當你想確認 RelayGate 是否正常執行，或想快速看目前哪些主要功能已經載入時，可以先看這一頁。

它也適合在啟動後、修改規則後，或啟用新功能後做快速確認。

## 它大致如何運作

這個頁面會讀取後端的即時摘要，並集中顯示。

它不負責每個功能的詳細設定。若要調整設定，請前往對應的模組頁。

## 注意事項

Overview 是狀態總覽，不是深入流量分析工具。

更細的連線追蹤或 log 可能會在其他工具或未來頁面中提供。

## 相關文件

- [Features](../../../features.md)
- [Known Limitations](../../../known-limitations.md)
