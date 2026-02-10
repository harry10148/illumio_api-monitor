🛡️ Illumio API Monitor (繁體中文版)
企業級 Illumio PCE 輕量化監控方案 | 無 Agent | 自動化告警 | 流量聚合分析

這是一個專為 Illumio PCE (Policy Compute Engine) 設計的 Python 監控工具。它直接與 PCE API 互動，能即時偵測安全事件與異常流量阻擋，並透過智慧演算法提供「有意義」的告警資訊。

本工具具備 狀態壓縮 (State Compression) 與 流量聚合 (Top Talkers) 技術，確保在大流量環境下依然輕量、快速，且不佔用系統資源。

📖 目錄
核心功能與特色

運作原理

環境需求

安裝與部署

快速設定指南

排程自動化 (Crontab)

進階說明：日誌與狀態

常見問題排除 (Troubleshooting)

1. 核心功能與特色
🔍 雙軌監控機制
安全事件 (Security Events)：即時監控如 Agent Tampering (遭到竄改)、Agent Offline (離線)、Missed Heartbeats (遺失心跳) 等關鍵資安事件。

流量異常 (Traffic Anomalies)：監控被防火牆阻擋 (Blocked) 或潛在阻擋 (Potentially Blocked) 的流量。

📊 智慧流量分析 (Top Talkers)
當偵測到大量阻擋時，系統不會只丟給你一個數字 (例如："1000 次阻擋")。 它會自動分析這 1000 筆資料，計算出前 5 名最頻繁的來源與目的 (Top 5 Talkers)，讓您一眼看出是誰在發動攻擊，或是哪台機器設定錯誤。

📸 原始日誌快照 (Raw Log Snapshot)
告警信件中會直接附上前 2 筆原始日誌 (Raw JSON)。 您不需要登入 PCE Console，直接在 Email 裡就能看到詳細的 Port、Protocol、Workload Labels 與 Error Code，大幅縮短除錯時間。

📉 狀態自動壓縮 (State Compression)
內建智慧演算法，自動合併與清理歷史狀態資料。即使連續運作數個月，狀態檔案 (illumio_api_state.json) 也不會無限膨脹，確保持續運作的穩定性。

⚡ 零外部依賴
完全基於 Python 標準函式庫 (Standard Library) 與 requests 模組開發。 不需要安裝 EPEL Repository，不需要安裝 Perl 或其他複雜的第三方軟體，符合企業嚴格的資安規範。

2. 運作原理
Fetch (讀取)：程式依據上次執行的時間點 (Last Check)，向 PCE API 撈取最新的事件與流量日誌。

Analyze (分析)：

比對使用者設定的規則 (Rules)。

計算時間窗口 (Time Window) 內的累積次數。

若為流量規則，進行來源/目的 IP 的聚合運算 (Aggregation)。

Alert (告警)：若觸發門檻，透過本地 SMTP (Postfix) 發送包含分析結果與原始日誌快照的 HTML 郵件。

Compress (壓縮)：更新狀態檔，並自動壓縮舊的歷史數據以節省空間。

3. 環境需求
支援作業系統
✅ Red Hat Enterprise Linux (RHEL) 8 / 9 ✅ Rocky Linux / AlmaLinux 8 / 9 ✅ Ubuntu 20.04 / 22.04 / 24.04 LTS

軟體需求
Python 3.6+ (系統內建即可)

Python Requests 模組 (唯一需要的外部套件)

Postfix (用於發送郵件，本程式內建自動架設功能)

4. 安裝與部署
請依據您的作業系統執行以下安裝指令 (請直接複製貼上)：

[RHEL / Rocky / CentOS 環境] sudo dnf install python3 python3-requests -y

[Ubuntu / Debian 環境] sudo apt update sudo apt install python3 python3-requests -y

[下載程式] 將提供的 python 程式碼存檔為 illumio_monitor.py，並賦予執行權限：

chmod +x illumio_monitor.py

5. 快速設定指南
執行程式進入主選單： ./illumio_monitor.py

步驟 1：系統初始設定 (Settings)
輸入 4 進入設定選單，依序設定：

API URL：輸入 PCE 的位址 (例如 https://pce.example.com:8443)。

API Credentials：輸入 Org ID、API Key 與 Secret (需在 PCE Console 預先建立)。

Email：設定寄件人 (Sender) 與收件人 (Recipients)。支援多組收件人，請用逗號分隔。

步驟 2：郵件服務設定 (Postfix)
若本機尚未設定 SMTP 轉發，請輸入 8 (Postfix Setup)。 程式會自動執行以下動作 (支援 RHEL/CentOS)：

安裝 Postfix 與 SASL 驗證模組。

設定 main.cf 與 sasl_passwd。

修正 master.cf 的 chroot 問題。

自動備份舊設定檔，並啟動服務。

步驟 3：載入規則 (Rules)
建議初次使用者直接輸入 5 (Load Best Practices)，系統會自動建立標準監控規則：

🔴 Agent Tampering：立即告警

🔴 Agent Offline：立即告警

🟠 High Volume Blocked：10 分鐘內超過 10 次阻擋

步驟 4：測試
輸入 6 (Send Test Email)，確認您能收到測試信件。

6. 排程自動化 (Crontab)
為了實現 24/7 持續監控，請將程式加入系統排程。

編輯 Crontab： crontab -e

加入以下排程 (假設程式位於 /root 目錄)：

每 10 分鐘執行一次，透過 pipe 輸入 "7" 自動執行監控功能
*/10 * * * * echo "7" | /root/illumio_monitor.py >> /var/log/illumio_monitor.log 2>&1

說明：程式設計為互動式選單，但在自動化排程中，透過 echo "7" | ... 的方式，可以模擬按下 "7" (Run Monitor Now) 鍵，程式執行完畢後會自動退出。

7. 進階說明：日誌與狀態
程式執行後，會在同目錄下產生以下檔案與目錄：

illumio_api_config.json 儲存 API 金鑰、Email 設定與所有監控規則。請務必妥善保護此檔案。

illumio_api_state.json 儲存上次檢查的時間點與各規則的歷史計數。請勿手動修改此檔案。

logs/illumio_events.log 記錄所有抓取到的 PCE 事件 (JSON 格式)。

logs/illumio_traffic.log 記錄所有抓取到的流量資料 (JSON 格式)。

/etc/postfix/illumio_backups/ 若您使用了內建的 Postfix 自動架設功能，所有的舊設定檔都會備份於此，依時間戳記分類。

8. 常見問題排除 (Troubleshooting)
Q: 執行時出現 "ModuleNotFoundError: No module named 'requests'"？ A: 您尚未安裝 Python requests 模組。請參考「安裝與部署」章節，執行 apt 或 dnf install 指令。

Q: 在 Ubuntu 上看到 "datetime.utcnow() is deprecated" 警告？ A: 這是 Python 3.12+ 的新規範。本程式已全面更新為 datetime.now(datetime.timezone.utc)，該警告在最新版程式中已修復，不會影響功能，請安心使用。

Q: 為什麼收不到告警信？ A:

請先使用選單 6 (Send Test Email) 測試。

若測試失敗，請檢查 Postfix 狀態：systemctl status postfix。

檢查系統郵件日誌：tail -f /var/log/maillog (RHEL) 或 tail -f /var/log/mail.log (Ubuntu)。

確認您的 PCE API Key 是否過期或權限不足 (需具備 Global Viewer 或以上權限)。

Q: 如何手動備份或遷移程式？ A: 您只需要備份 illumio_monitor.py 以及 illumio_api_config.json 這兩個檔案即可。將它們複製到新機器上，安裝好 python3-requests，即可直接運作。
