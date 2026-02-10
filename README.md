# 🛡️ Illumio API Monitor

![Version](https://img.shields.io/badge/Version-v1.0.0-blue?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.6%2B-yellow?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-RHEL%20%7C%20Ubuntu-orange?style=flat-square&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> **Illumio PCE 監控方案 | 自動化告警 | 流量聚合分析**

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

---

## ✨ 核心功能

| 功能 | 說明 |
| :--- | :--- |
| **🔍 監控** | 同時監控 **系統安全事件 (Events)** 與 **防火牆阻擋流量 (Traffic)**。 |
| **📊 Top Talkers** | 當大量阻擋發生時，自動聚合並列出 **前 5 名** 最頻繁的來源 IP 與目的 Port。 |
| **📸 Raw Snapshot** | 告警信件內附帶 **前 2 筆原始 JSON 日誌**，無需登入 Console 即可查看詳細 Error Code。 |


---

## ⚙️ 運作原理

1.  **Fetch (讀取)**：依據上次執行的時間點 (Last Check)，向 PCE API 撈取最新的增量日誌。
2.  **Analyze (分析)**：比對使用者設定的規則 (Rules) 與時間窗口 (Time Window)。
3.  **Aggregate (聚合)**：若觸發流量規則，進行來源/目的 IP 的聚合運算。
4.  **Alert (告警)**：透過本地 SMTP (Postfix) 發送 HTML 格式告警信。

---

## 📋 環境需求

### 支援作業系統
* ✅ **Red Hat Enterprise Linux (RHEL)** 8 / 9
* ✅ **Rocky Linux / AlmaLinux** 8 / 9
* ✅ **Ubuntu** 20.04 / 22.04 LTS

### 軟體需求
* **Python 3.6+** (系統內建即可)
* **Python Requests 模組** (唯一需要的外部套件)

---

## 🚀 安裝與部署

請依據您的作業系統執行安裝指令：

### 1. 安裝 Python 套件

**RHEL / Rocky / CentOS:**

sudo dnf install python3 python3-requests -y


**Ubuntu / Debian:**

sudo apt update sudo apt install python3 python3-requests -y


### 2. 下載程式
將 `illumio_monitor.py` 下載至伺服器並賦予執行權限：

chmod +x illumio_monitor.py


---

## 🛠️ 快速設定指南

執行程式進入互動選單：

./illumio_monitor.py


### 步驟 1：系統初始設定
輸入 `4` 進入設定選單 (Settings)：
1.  **API URL**：輸入 PCE 位址 (例：`https://pce.example.com:8443`)。
2.  **Credentials**：輸入 Org ID、API Key 與 Secret。
3.  **Email**：設定寄件人與收件人 (支援多組，逗號分隔)。

### 步驟 2：載入規則
建議初次使用者輸入 `5` **(Load Best Practices)**，系統會自動建立：
* 🔴 **Agent Tampering** (遭到竄改)：立即告警
* 🔴 **Agent Offline** (離線)：立即告警
* 🟠 **High Volume Blocked** (大量阻擋)：10 分鐘內 > 10 次

### 步驟 3：測試
輸入 `6` **(Send Test Email)** 確認郵件發送功能正常。

---

## ⏰ 排程自動化

為了實現 24/7 持續監控，請將程式加入 Crontab。

編輯排程：

crontab -e


加入以下指令 (假設程式位於 `/root`，每 10 分鐘執行一次)：

Illumio Monitor Cron Job
*/10 * * * * echo "7" | /root/illumio_monitor.py >> /var/log/illumio_monitor.log 2>&1


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

<p align="center">Made for Illumio Administrators.</p>
