# Resource Replace

## 這個模組做什麼

Resource Replace 模組會把符合規則的遠端資源替換成本地檔案。

它可以在 request 抵達 upstream server 前，替換 scripts、stylesheets、images 或其他符合條件的資源。

## 什麼時候適合使用

當某個已知遠端資源應該改由本地檔案提供時，可以使用這個模組。

它適合測試、修補 frontend assets、替換損壞資源，或保留受控的本地資源副本。

## 它大致如何運作

RelayGate 會在本地 proxy 流程中檢查 resource replacement rules。

當 request 符合規則時，RelayGate 會提供設定好的本地檔案，而不是抓取遠端資源。

## 注意事項

如果規則指向不存在的本地檔案，該規則應視為無效，並需要修正。

Rule toggles 可以 hot apply。如果你在 RelayGate 外部修改檔案，請從控制面板 reload resource rules。

## 相關文件

- [Rewrite Rules](../../../rewrite-rules.md)
- [Features](../../../features.md)
