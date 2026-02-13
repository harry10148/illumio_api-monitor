
## 🖼️ Screenshots

<img width="532" height="511" alt="image" src="https://github.com/user-attachments/assets/02b63551-0aea-4e8f-b40b-5bca21cb6195" />

<img width="1380" height="739" alt="image" src="https://github.com/user-attachments/assets/52bd608e-72e6-4c49-890b-5f6a419a26e7" />

# 🛡️ Illumio API Monitor (繁體中文版)

![Version](https://img.shields.io/badge/Version-v1.0.0-blue?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.6%2B-yellow?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-RHEL%20%7C%20Ubuntu-orange?style=flat-square&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> **企業級 Illumio PCE 輕量化監控方案 | 無 Agent | 自動化告警 | 流量聚合分析**

這是一個專為 **Illumio Core (PCE)** 設計的 Python 監控工具。它直接與 API 互動，即時偵測資安事件與異常流量阻擋，並透過智慧演算法提供具備 **原始日誌快照 (Raw Log Snapshot)** 的告警信件。

---

## 📖 目錄 (Table of Contents)

- [✨ 核心功能](#-核心功能)
- [⚙️ 運作原理](#️-運作原理)
- [📋 環境需求](#-環境需求)
- [🚀 安裝與部署](#-安裝與部署)
- [🛠️ 快速設定指南](#️-快速設定指南)
- [⏰ 排程自動化](#-排程自動化)
- [❓ 常見問題 (FAQ)](#-常見問題-faq)
- [🔧 附錄：Postfix 架設](#-附錄postfix-smtp-relay-架設指南)

---

## ✨ 核心功能

| 功能 | 說明 |
| :--- | :--- |
| **🔍 雙軌監控** | 同時監控 **系統安全事件 (Events)** 與 **防火牆阻擋流量 (Traffic)**。 |
| **🏥 健康檢查** | 每次執行時自動檢查 PCE 服務狀態 (`/api/v2/health`)，若非 `200 OK` 立即發送緊急告警。 |
| **📊 Top Talkers** | 當大量阻擋發生時，自動聚合並列出 **前 5 名** 最頻繁的來源 IP 與目的 Port。 |
| **📸 Raw Snapshot** | 告警信件內附帶 **前 2 筆原始 JSON 日誌**，無需登入 Console 即可查看詳細 Error Code。 |
| **📉 狀態壓縮** | 內建演算法自動合併歷史計數，防止狀態檔案 (`.json`) 無限膨脹。 |
| **⚡ 零依賴** | 僅使用 Python 標準庫與 `requests`，無需安裝 EPEL 或複雜套件，符合企業資安規範。 |

---

## ⚙️ 運作原理

1. **Health Check (健檢)**：優先呼叫 PCE Health API，若服務異常 (非 200) 則立即觸發紅色緊急告警。
2. **Fetch (讀取)**：依據上次執行的時間點 (Last Check)，向 PCE API 撈取最新的增量日誌。
3. **Analyze (分析)**：比對使用者設定的規則 (Rules) 與時間窗口 (Time Window)。
4. **Aggregate (聚合)**：若觸發流量規則，進行來源/目的 IP 的聚合運算。
5. **Alert (告警)**：透過本地 SMTP (Postfix) 發送 HTML 格式告警信。

---

## 📋 環境需求

### 支援作業系統

- ✅ **Red Hat Enterprise Linux (RHEL)** 8 / 9
- ✅ **Rocky Linux / AlmaLinux** 8 / 9
- ✅ **Ubuntu** 20.04 / 22.04 LTS

### 軟體需求

- **Python 3.6+** (系統內建即可)
- **Python Requests 模組** (唯一需要的外部套件)

---

## 🚀 安裝與部署

建議依照以下順序進行安裝與檢查：

### 1. 安裝 Python 套件

**RHEL / Rocky / CentOS:**

```bash
sudo dnf install python3 python3-requests -y
```

**Ubuntu / Debian:**

```bash
sudo apt update
sudo apt install python3 python3-requests -y
```

### 2. 環境檢查 (Pre-check)

在執行程式前，建議先執行以下指令確認環境是否就緒：

```bash
python3 -c "import requests; print('OK: Requests is installed')"
```

- 若看到 `OK: Requests is installed` 代表環境正常。
- 若看到 `ModuleNotFoundError` 代表安裝未成功，請重新執行步驟 1。

### 3. 下載程式

將 `illumio_monitor.py` 下載至伺服器並賦予執行權限：

```bash
chmod +x illumio_monitor.py
```

---

## 🛠️ 快速設定指南

執行程式進入互動選單：

```bash
./illumio_monitor.py
```

### 步驟 1：系統初始設定

輸入 `4` 進入設定選單 (Settings)：

1. **API URL**：輸入 PCE 位址 (例：`https://pce.example.com:8443`)。
2. **Credentials**：輸入 Org ID、API Key 與 Secret。
3. **Email**：設定寄件人與收件人 (支援多組，逗號分隔)。

### 步驟 2：載入規則

建議初次使用者輸入 `5` **(Load Best Practices)**，系統會自動建立：

- 🔴 **Agent Tampering** (遭到竄改)：立即告警
- 🔴 **Agent Offline** (離線)：立即告警
- 🟠 **High Volume Blocked** (大量阻擋)：10 分鐘內 > 10 次

### 步驟 3：測試

輸入 `6` **(Send Test Email)** 確認郵件發送功能正常。

---

## ⏰ 排程自動化

為了實現 24/7 持續監控，請將程式加入 Crontab。

編輯排程：

```bash
crontab -e
```

加入以下指令 (假設程式位於 `/root`，每 10 分鐘執行一次)：

```cron
# Illumio Monitor Cron Job
*/10 * * * * echo "7" | /root/illumio_monitor.py >> /var/log/illumio_monitor.log 2>&1
```

> 💡 **小技巧**：程式設計為互動式選單，但在 Cron 中透過 `echo "7" | ...` 管道輸入，可模擬按下 "7" (Run Monitor Now) 鍵，執行完畢後自動退出。

---

## ❓ 常見問題 (FAQ)

<details>
<summary><strong>Q1: 為什麼在 Ubuntu 上執行沒有出現 datetime 警告了？</strong></summary>
<br>
本版本已針對 Python 3.12+ 進行核心重構，全面改用 <code>datetime.now(datetime.timezone.utc)</code>，確保在最新的 Ubuntu 24.04 與 RHEL 9 上皆能完美運行且無 Deprecation Warning。
</details>

<details>
<summary><strong>Q2: 設定檔儲存在哪裡？</strong></summary>
<br>
所有的設定 (API Key, 規則) 都儲存在同目錄下的 <code>illumio_api_config.json</code>。若需遷移至新主機，只需複製此檔案即可。
</details>

<details>
<summary><strong>Q3: 什麼是 "Raw Log Snapshot"?</strong></summary>
<br>
為了方便除錯，當告警觸發時，系統會自動擷取該批次的前 2 筆原始日誌 (JSON) 附在 Email 中。您無需登入 Console 就能看到詳細的 <code>Port</code>, <code>Protocol</code> 與 <code>Labels</code>。
</details>

---

## 🔧 附錄：Postfix SMTP Relay 架設指南

若您的伺服器尚未設定 SMTP 轉發，請參考以下標準作業程序 (SOP) 建立本機 Relay 服務。  
此設定允許程式透過 `localhost:25` 將信件轉送至外部 Mail Server (如 Exchange, Gmail, Zimbra)。

### 1. 安裝套件

**Ubuntu / Debian:**

```bash
sudo apt update
sudo apt install postfix libsasl2-modules -y
```

**RHEL / Rocky / CentOS:**

```bash
sudo dnf install postfix cyrus-sasl cyrus-sasl-plain cyrus-sasl-md5 -y
```

### 2. 設定帳號密碼 (SASL)

1. 編輯檔案：

```bash
sudo vi /etc/postfix/sasl_passwd
```

2. 輸入內容 (格式：`[IP]:Port User:Pass`)：

```text
[172.16.15.103]:25   admin@example.com:YourPassword
```

3. 製作雜湊資料庫並設定權限：

```bash
sudo chmod 600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd
```

### 3. 修改主設定檔 (main.cf)

編輯 `/etc/postfix/main.cf`，請移至檔案最下方，直接複製貼上以下內容：

```conf
# --- RELAY CONFIG START ---

# 1) 上游 SMTP 設定 (需與 sasl_passwd 內的格式完全一致)
relayhost = [172.16.15.103]:25

# 2) 開啟 SASL 驗證
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous

# 3) TLS 設定
smtp_use_tls = yes
smtp_tls_security_level = may
smtp_tls_note_starttls_offer = yes

# 4) CA 憑證路徑 (請依 OS 二選一，保留其中一行即可)
# Ubuntu/Debian:
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
# RHEL/CentOS:
# smtp_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt

# 5) 安全性設定 (僅聽本機)
inet_interfaces = loopback-only
mynetworks = 127.0.0.0/8 [::1]/128

# --- RELAY CONFIG END ---
```

### 4. 修正服務程序 (master.cf)

編輯 `/etc/postfix/master.cf`，確保 `smtp` 服務的 **chroot** 欄位為 `n`。

```bash
sudo vi /etc/postfix/master.cf
```

**請比對並修改為以下內容：**

```text
# 1) 負責監聽 Port 25 的服務 (inet) -> chroot 改為 n
smtp      inet  n       -       n       -       -       smtpd

# 2) 負責對外寄信的服務 (unix) -> chroot 改為 n (影響 SASL 讀取)
smtp      unix  -       -       n       -       -       smtp

# 3) (選用) 負責轉發的服務 -> chroot 改為 n
relay     unix  -       -       n       -       -       smtp

# 4) 確認 postscreen 被註解掉 (前面加 #)
#smtp      inet  n       -       n       -       1       postscreen
#smtpd     pass  -       -       n       -       -       smtpd
```

> 如果你想保留「欄位說明表」，建議也包在 code block，避免 Markdown 跑版：
>
> ```text
> ==========================================================================
> service type  private unpriv  chroot  wakeup  maxproc command + args
> (yes)   (yes)   (no)    (never) (100)
> ==========================================================================
> ```

### 5. 啟動與驗證

1. 重新啟動服務：

```bash
sudo systemctl restart postfix
sudo systemctl enable postfix
```

2. 使用 Python 快速測試  
請將以下指令中的收件人修改為您的信箱後執行：

```bash
python3 - <<'PY'
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg.set_content('This is a test from Postfix Relay.')
msg['Subject'] = 'Relay Test'
msg['From'] = 'monitor@localhost'
msg['To'] = '您的真實信箱@example.com'

try:
    with smtplib.SMTP('127.0.0.1', 25) as s:
        s.send_message(msg)
    print('SUCCESS: Email sent to Postfix queue.')
except Exception as e:
    print(f'FAILED: {e}')
PY
```
