#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Illumio API Monitor (繁體中文版)
功能：透過 API 監控 Illumio PCE 的事件與流量，並在偵測到異常時發送告警郵件。
特點：支援流量聚合分析 (Top Talkers)、速率限制 (Rate Limiting)、狀態壓縮，且無須安裝額外代理程式。
"""

import sys
import os
import json
import requests
import smtplib
import datetime
import argparse
import readline
import logging
import time
import gzip
from io import BytesIO
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import Counter
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用 SSL 警告 (針對使用自簽憑證的 PCE 環境)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ================= 設定與常數 =================
CONFIG_FILE = "illumio_api_config.json"
STATE_FILE = "illumio_api_state.json"

# Log 設定
LOG_DIR = "logs"
EVENT_LOG_FILE = os.path.join(LOG_DIR, "illumio_events.log")
TRAFFIC_LOG_FILE = os.path.join(LOG_DIR, "illumio_traffic.log")
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5                 # 保留 5 份備份日誌

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# ================= 事件範本 (預設監控規則) =================
EVENT_TEMPLATES = {
    "安全性與威脅 (Security)": [
        {
            "name": "Agent 遭到竄改", 
            "etype": "agent.tampering", 
            "desc": "偵測到防火牆遭到竄改",
            "rec": "請立即調查，工作負載可能已遭入侵。"
        },
        {
            "name": "偵測到複製 Agent", 
            "etype": "agent.clone_detected", 
            "desc": "偵測到重複的 VEN ID",
            "rec": "檢查嚴重性 (Severity)。若為 Error 需人工介入。"
        },
        {
            "name": "Agent 被暫停", 
            "etype": "agent.suspend", 
            "desc": "Agent 進入暫停狀態 (潛在攻擊)",
            "rec": "監控高價值資產。確認是否為人為操作。"
        },
    ],
    "Agent 健康狀態 (Health)": [
        {
            "name": "遺失心跳", 
            "etype": "agent_missed_heartbeats", 
            "desc": "Agent 未回報心跳",
            "rec": "通常是離線的前兆。請檢查網路連線。"
        },
        {
            "name": "Agent 離線", 
            "etype": "agent_offline_check", 
            "desc": "Agent 被標記為離線",
            "rec": "安全性狀態已改變。請調查主機狀態。"
        },
        {
            "name": "發現遺失的 Agent", 
            "etype": "lost_agent.found", 
            "desc": "重新發現先前遺失的 Agent",
            "rec": "驗證 VEN 配對狀態。"
        },
    ],
    "使用者與認證 (Auth)": [
        {
            "name": "登入失敗", 
            "etype": "user.login_failed", 
            "desc": "Console 登入失敗",
            "rec": "監控是否為暴力破解攻擊或帳號鎖定。"
        },
        {
            "name": "API 認證失敗", 
            "etype": "request.authentication_failed", 
            "desc": "API Key 認證失敗",
            "rec": "驗證 API Key 有效性與輪替策略。"
        },
    ],
    "系統與政策 (System)": [
        {
            "name": "規則集變更", 
            "etype": "rule_set", 
            "desc": "防火牆規則被修改",
            "rec": "確認變更範圍是否過大或符合預期。"
        },
        {
            "name": "系統內部錯誤", 
            "etype": "request.internal_server_error", 
            "desc": "PCE 內部發生錯誤",
            "rec": "請檢查 PCE System Health logs。"
        },
    ]
}

# ================= 輸入輔助函式 =================
def safe_input(prompt, value_type=str, valid_range=None, allow_cancel=True):
    """
    處理使用者輸入，支援取消操作與型別檢查
    """
    while True:
        try:
            raw = input(prompt)
            
            # 處理空白輸入 (視為取消或跳過)
            if not raw.strip():
                if allow_cancel: return None
                else: continue
            
            # 處理明確取消指令 (-1)
            if raw.strip() == '-1' and allow_cancel:
                return None

            val = value_type(raw)
            
            # 檢查數值範圍
            if valid_range and val not in valid_range:
                print(f"{Colors.FAIL}輸入數值超出範圍 ({min(valid_range)}-{max(valid_range)})。{Colors.ENDC}")
                continue
            
            return val
        except ValueError:
            print(f"{Colors.FAIL}輸入格式錯誤，請重新輸入。{Colors.ENDC}")
        except KeyboardInterrupt:
            print("\n已取消操作。")
            return None

def setup_logger(name, log_file, level=logging.INFO):
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler = RotatingFileHandler(log_file, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        logger.addHandler(handler)
    return logger

# ================= 設定管理 =================
class ConfigManager:
    def __init__(self):
        self.config = {
            "api": {
                "url": "https://pce.example.com:8443",
                "org_id": "1",
                "key": "",
                "secret": "",
                "verify_ssl": True
            },
            "email": {
                "sender": "illumio-monitor@localhost",
                "recipients": ["admin@example.com"]
            },
            "rules": []
        }
        self.load()

    def load(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    if "sender" not in data.get("email", {}):
                         if "email" not in data: data["email"] = {}
                         data["email"]["sender"] = "illumio-monitor@localhost"
                    self.config.update(data)
            except: pass

    def save(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)
        print(f"{Colors.GREEN}設定已儲存。{Colors.ENDC}")

    def add_event_rule(self, name, event_type, desc="", rec="", threshold_type="immediate", threshold_count=1, threshold_window=10):
        rule = {
            "id": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "type": "event",
            "name": name,
            "filter_key": "event_type",
            "filter_value": event_type,
            "desc": desc,
            "rec": rec,
            "threshold_type": threshold_type,
            "threshold_count": threshold_count,
            "threshold_window": threshold_window
        }
        self.config["rules"].append(rule)
        self.save()

    def add_traffic_rule(self, name, pd_val, port=None, src_label=None, dst_label=None, threshold_type="immediate", threshold_count=1, threshold_window=10):
        desc_str = "流量被阻擋 (Blocked PD=2)" if pd_val == 2 else "潛在阻擋流量 (Potentially Blocked PD=1)"
        rec_str = "檢查 Policy Scope，確認是否有合法流量被誤擋。"
        
        if src_label: name += f" [來源:{src_label}]"
        if dst_label: name += f" [目的:{dst_label}]"

        rule = {
            "id": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "type": "traffic",
            "name": name,
            "pd": pd_val,
            "port": port,
            "src_label": src_label,
            "dst_label": dst_label,
            "desc": desc_str,
            "rec": rec_str,
            "threshold_type": threshold_type,
            "threshold_count": threshold_count,
            "threshold_window": threshold_window
        }
        self.config["rules"].append(rule)
        self.save()

    def remove_rule(self, idx):
        if 0 <= idx < len(self.config["rules"]):
            del self.config["rules"][idx]
            self.save()
            return True
        return False

    def load_best_practices(self):
        print(f"{Colors.BLUE}正在載入最佳實踐規則...{Colors.ENDC}")
        self.config["rules"] = [] 
        for cat, events in EVENT_TEMPLATES.items():
            for evt in events:
                t_type = "immediate"
                t_count = 1
                t_win = 10
                if "心跳" in evt['name'] or "登入" in evt['name']:
                    t_type = "count"
                    t_count = 3
                    t_win = 10 
                self.add_event_rule(evt['name'], evt['etype'], evt['desc'], evt['rec'], t_type, t_count, t_win)
        
        self.add_traffic_rule("大量被阻擋流量 (High Volume)", pd_val=2, port=None, threshold_type="count", threshold_count=10, threshold_window=10)
        self.add_traffic_rule("潛在阻擋流量 (Potentially Blocked)", pd_val=1, port=None, threshold_type="count", threshold_count=10, threshold_window=10)
        print(f"{Colors.GREEN}最佳實踐規則載入完成。{Colors.ENDC}")

# ================= 監控引擎 =================
class ApiMonitorEngine:
    def __init__(self, config_manager):
        self.cm = config_manager
        self.api_cfg = self.cm.config["api"]
        self.base_url = f"{self.api_cfg['url']}/api/v2/orgs/{self.api_cfg['org_id']}"
        self.auth = HTTPBasicAuth(self.api_cfg['key'], self.api_cfg['secret'])
        
        self.event_alerts = []
        self.traffic_alerts = []
        
        self.event_logger = setup_logger('illumio_events', EVENT_LOG_FILE)
        self.traffic_logger = setup_logger('illumio_traffic', TRAFFIC_LOG_FILE)
        
        # 使用時區感知的 UTC 時間以確保跨平台相容性 (Ubuntu/RHEL)
        self.last_check = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.state = {"last_check": self.last_check, "history": {}}
        
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, 'r') as f:
                    loaded = json.load(f)
                    self.state.update(loaded)
            except: pass

    def save_state(self):
        # 更新最後檢查時間
        self.state["last_check"] = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        now = datetime.datetime.now(datetime.timezone.utc)
        cutoff = now - datetime.timedelta(minutes=120)
        
        cleaned_history = {}
        for rid, records in self.state["history"].items():
            valid_records = []
            for rec in records:
                try:
                    # 相容舊版狀態格式
                    if isinstance(rec, str): ts, c = rec, 1
                    else: ts, c = rec.get('t'), rec.get('c', 1)
                    
                    try:
                        t_obj = datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
                    except ValueError:
                        t_obj = datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)

                    if t_obj > cutoff:
                        valid_records.append({"t": ts, "c": c})
                except: pass
            
            # 狀態壓縮：合併相同時間戳記的紀錄
            merged_map = {}
            for r in valid_records:
                merged_map[r['t']] = merged_map.get(r['t'], 0) + r['c']
            
            final_records = [{"t": k, "c": v} for k, v in merged_map.items()]
            if final_records:
                cleaned_history[rid] = final_records
        
        self.state["history"] = cleaned_history
        with open(STATE_FILE, 'w') as f:
            json.dump(self.state, f)

    def fetch_events(self, time_filter=None, limit=1000):
        url = f"{self.base_url}/events"
        check_time = time_filter if time_filter else self.state["last_check"]
        params = {"timestamp[gte]": check_time, "max_results": limit}
        print(f"正在讀取事件 (自 {check_time} 起)...")
        try:
            headers = {"Accept": "application/json"}
            r = requests.get(url, auth=self.auth, headers=headers, params=params, verify=self.api_cfg['verify_ssl'], timeout=10)
            if r.status_code == 200: return r.json()
            return []
        except Exception as e:
            print(f"{Colors.FAIL}Event API 錯誤: {e}{Colors.ENDC}")
            return []

    def parse_downloaded_data(self, content):
        try:
            with gzip.GzipFile(fileobj=BytesIO(content)) as f: content = f.read()
        except: pass 
        try: text_data = content.decode('utf-8')
        except: return []
        try: return json.loads(text_data)
        except json.JSONDecodeError: pass 
        try:
            results = []
            for line in text_data.splitlines():
                if line.strip(): results.append(json.loads(line))
            return results
        except: return []

    def fetch_traffic_async(self):
        query_url = f"{self.base_url}/traffic_flows/async_queries"
        
        now = datetime.datetime.now(datetime.timezone.utc)
        end_time = (now - datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
        start_time = (now - datetime.timedelta(minutes=15)).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        payload = {
            "start_date": start_time,
            "end_date": end_time,
            "policy_decisions": ["blocked", "potentially_blocked"],
            "max_results": 2000,
            "query_name": "Traffic_Monitor_Query",
            "sources": {"include": [], "exclude": []},
            "destinations": {"include": [], "exclude": []},
            "services": {"include": [], "exclude": []}
        }
        
        print(f"正在提交流量查詢 ({start_time} 至 {end_time}) [已延遲修正]...")
        try:
            headers = {"Accept": "application/json", "Content-Type": "application/json"}
            r = requests.post(query_url, auth=self.auth, headers=headers, json=payload, verify=self.api_cfg['verify_ssl'], timeout=10)
            if r.status_code not in [201, 202]:
                print(f"{Colors.WARNING}流量查詢提交失敗 ({r.status_code}): {r.text}{Colors.ENDC}")
                return []
            
            job_url = r.json().get("href")
            print("等待流量計算中...", end="", flush=True)
            for _ in range(20): 
                time.sleep(2)
                status_r = requests.get(f"{self.api_cfg['url']}/api/v2{job_url}", auth=self.auth, headers=headers, verify=self.api_cfg['verify_ssl'])
                state = status_r.json().get("status")
                if state == "completed":
                    print(" 完成。")
                    break
                if state == "failed":
                    print(f" 計算失敗。")
                    return []
                print(".", end="", flush=True)
            else:
                print(" 逾時。")
                return []

            dl_url = f"{self.api_cfg['url']}/api/v2{job_url}/download"
            dl_r = requests.get(dl_url, auth=self.auth, headers=headers, verify=self.api_cfg['verify_ssl'], stream=True)
            if dl_r.status_code == 204 or not dl_r.content: return []
            return self.parse_downloaded_data(dl_r.content)
        except Exception as e:
            print(f"{Colors.FAIL}Traffic Async 錯誤: {e}{Colors.ENDC}")
            return []

    def log_audit_data(self, events, is_traffic=False):
        logger = self.traffic_logger if is_traffic else self.event_logger
        for e in events:
            logger.info(json.dumps(e))
        if events:
            type_str = "流量 (Traffic)" if is_traffic else "系統 (System)"
            print(f"已記錄 {len(events)} 筆 {type_str} 資料至本地日誌。")

    def dump_raw_events(self):
        events = self.fetch_events(limit=5)
        print(f"\n{Colors.CYAN}=== DEBUG: 原始 API 回傳 (最近 5 筆事件) ==={Colors.ENDC}")
        if not events: print("找不到最近的事件。")
        for e in events:
            print("-" * 40)
            print(f"類型: {e.get('event_type')}")
            print(f"時間: {e.get('timestamp')}")
            if 'notifications' in e:
                print(f"細節: {json.dumps(e.get('notifications', [])[:1])}")
        print("-" * 40)

    def get_traffic_details(self, flow):
        src_ip = flow.get('src', {}).get('ip', 'N/A')
        src_name = flow.get('src', {}).get('workload', {}).get('name') or src_ip
        dst_ip = flow.get('dst', {}).get('ip', 'N/A')
        dst_name = flow.get('dst', {}).get('workload', {}).get('name') or dst_ip
        svc = flow.get('service', {})
        port = svc.get('port', 'All')
        proto = svc.get('proto', 'N/A')
        return {
            "key": f"{src_name} ({src_ip}) -> {dst_name} ({dst_ip}) [{port}/{proto}]",
            "decision": flow.get('policy_decision', 'N/A')
        }

    def check_flow_labels(self, flow_side, filter_str):
        if not filter_str: return True
        try:
            fk, fv = filter_str.split('=', 1)
            fk, fv = fk.strip(), fv.strip()
            labels = flow_side.get('workload', {}).get('labels', [])
            for l in labels:
                if l.get('key') == fk and l.get('value') == fv: return True
            return False
        except: return False

    def analyze(self):
        events = self.fetch_events()
        if events: self.log_audit_data(events, is_traffic=False)

        traffic = []
        has_traffic_rules = any(r['type'] == 'traffic' for r in self.cm.config['rules'])
        if has_traffic_rules:
            traffic = self.fetch_traffic_async()
            if traffic: self.log_audit_data(traffic, is_traffic=True)
        else:
            print(f"{Colors.BLUE}跳過流量查詢 (未設定流量規則)。{Colors.ENDC}")
        
        for rule in self.cm.config["rules"]:
            matches = []
            
            if rule["type"] == "event":
                target_val = rule["filter_value"]
                for e in events:
                    match_found = False
                    if target_val in e.get("event_type", ""): match_found = True
                    elif "notifications" in e and isinstance(e["notifications"], list):
                        for n in e["notifications"]:
                            if target_val in n.get("notification_type", ""):
                                match_found = True
                                break
                    if match_found: matches.append(e)

            elif rule["type"] == "traffic":
                target_pd = rule.get("pd", 2)
                src_filter = rule.get("src_label")
                dst_filter = rule.get("dst_label")
                for f in traffic:
                    raw_pd = f.get("pd")
                    raw_decision = f.get("policy_decision")
                    flow_pd = -1
                    if raw_pd is not None: flow_pd = int(raw_pd)
                    elif raw_decision:
                        if "potentially" in raw_decision: flow_pd = 1
                        elif "blocked" in raw_decision: flow_pd = 2
                        elif "allowed" in raw_decision: flow_pd = 0
                    
                    if flow_pd == target_pd:
                        is_match = True
                        if rule["port"] and f.get("dst_port") != rule["port"]: is_match = False
                        if is_match and src_filter:
                            if not self.check_flow_labels(f.get('src', {}), src_filter): is_match = False
                        if is_match and dst_filter:
                            if not self.check_flow_labels(f.get('dst', {}), dst_filter): is_match = False
                        if is_match: matches.append(f)

            # 速率限制邏輯
            current_count = len(matches)
            rid = str(rule["id"])
            if rid not in self.state["history"]: self.state["history"][rid] = []
            
            if current_count > 0:
                now_str = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                self.state["history"][rid].append({"t": now_str, "c": current_count})
            
            window_minutes = rule.get("threshold_window", 10)
            window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=window_minutes)
            
            total_count_in_window = 0
            for rec in self.state["history"][rid]:
                if isinstance(rec, dict): ts, c = rec.get('t'), rec.get('c', 0)
                else: ts, c = rec, 1
                try:
                    t_obj = datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
                    if t_obj > window_start:
                        total_count_in_window += c
                except: pass
            
            trigger = False
            if rule["threshold_type"] == "immediate" and current_count > 0: trigger = True
            elif rule["threshold_type"] == "count" and total_count_in_window >= rule["threshold_count"]: trigger = True
            
            if trigger:
                # 擷取原始日誌 (Snapshot)
                raw_snapshot = json.dumps(matches[:2], indent=2, default=str) if matches else "No raw data."

                # 流量聚合分析 (Top Talkers)
                if rule["type"] == "traffic":
                    talkers = Counter()
                    for m in matches:
                        d = self.get_traffic_details(m)
                        talkers[d["key"]] += 1
                    
                    top_list = []
                    for k, v in talkers.most_common(5):
                        top_list.append(f"{k} [Count: {v}]")
                    talkers_summary = "<br>".join(top_list)
                    
                    self.traffic_alerts.append({
                        "rule": rule["name"],
                        "count": total_count_in_window,
                        "desc": rule.get("desc", ""),
                        "rec": rule.get("rec", ""),
                        "details": talkers_summary,
                        "raw": raw_snapshot
                    })
                else:
                    first = matches[0] if matches else {}
                    source = first.get("created_by", {}).get("agent", {}).get("hostname", "System")
                    severity = first.get("severity", "info")
                    self.event_alerts.append({
                        "rule": rule["name"],
                        "count": total_count_in_window,
                        "desc": rule.get("desc", ""),
                        "rec": rule.get("rec", ""),
                        "source": source,
                        "severity": severity,
                        "time": first.get("timestamp", "N/A"),
                        "raw_type": first.get("event_type", "N/A"),
                        "raw": raw_snapshot
                    })
        
        self.save_state()

    def send_email(self, force_test=False):
        if not self.event_alerts and not self.traffic_alerts and not force_test: return
        
        cfg = self.cm.config["email"]
        if not cfg["recipients"]: 
            print("未設定收件者。")
            return

        total_issues = len(self.event_alerts) + len(self.traffic_alerts)
        subject = f"[Illumio 監控告警] 偵測到 {total_issues} 個異常"
        if force_test: subject = "[Illumio 監控系統] 測試郵件"

        event_html = ""
        if self.event_alerts:
            rows = ""
            for a in self.event_alerts:
                sev_color = "#dc3545" if a['severity'] == 'error' else "#ffc107"
                
                # 原始日誌區塊
                raw_block = f"""
                <tr>
                    <td colspan="5" style="padding:10px; background:#f8f9fa; border-bottom:1px solid #eee;">
                        <div style="font-size:11px; color:#555; font-family:monospace; margin-bottom:5px;"><strong>原始日誌快照 (Raw Log Snapshot):</strong></div>
                        <pre style="margin:0; font-size:10px; color:#333; white-space:pre-wrap; background:#eee; padding:5px;">{a.get('raw', 'N/A')}</pre>
                    </td>
                </tr>
                """
                
                rows += f"""
                <tr>
                    <td style="padding:8px; border-bottom:1px solid #eee;">{a['time']}</td>
                    <td style="padding:8px; border-bottom:1px solid #eee;">{a['rule']}</td>
                    <td style="padding:8px; border-bottom:1px solid #eee; color:{sev_color}; font-weight:bold;">{a['severity'].upper()} ({a['count']})</td>
                    <td style="padding:8px; border-bottom:1px solid #eee;">{a['source']}</td>
                    <td style="padding:8px; border-bottom:1px solid #eee; font-size:12px;">
                        <div>{a['desc']}</div>
                        <div style="color:#666;">Type: {a['raw_type']}</div>
                        <div style="color:#0056b3;"><strong>建議:</strong> {a['rec']}</div>
                    </td>
                </tr>
                {raw_block}
                """
            event_html = f"""
            <h3 style="background:#d9534f; color:white; padding:10px; margin-top:20px;">安全性與系統事件 (Security Events)</h3>
            <table style="width:100%; border-collapse:collapse; font-family:Arial, sans-serif;">
                <tr style="background:#f7f7f7;">
                    <th style="text-align:left; padding:8px;">時間</th>
                    <th style="text-align:left; padding:8px;">規則</th>
                    <th style="text-align:left; padding:8px;">嚴重性 (次數)</th>
                    <th style="text-align:left; padding:8px;">來源</th>
                    <th style="text-align:left; padding:8px;">詳細資訊與建議</th>
                </tr>
                {rows}
            </table>
            """

        traffic_html = ""
        if self.traffic_alerts:
            rows = ""
            for a in self.traffic_alerts:
                
                # 原始日誌區塊
                raw_block = f"""
                <tr>
                    <td colspan="4" style="padding:10px; background:#f8f9fa; border-bottom:1px solid #eee;">
                        <div style="font-size:11px; color:#555; font-family:monospace; margin-bottom:5px;"><strong>原始日誌快照 (Raw Log Snapshot):</strong></div>
                        <pre style="margin:0; font-size:10px; color:#333; white-space:pre-wrap; background:#eee; padding:5px;">{a.get('raw', 'N/A')}</pre>
                    </td>
                </tr>
                """
                
                rows += f"""
                <tr>
                    <td style="padding:8px; border-bottom:1px solid #eee; font-weight:bold; color:#d9534f;">{a['count']}</td>
                    <td style="padding:8px; border-bottom:1px solid #eee;">{a['rule']}</td>
                    <td style="padding:8px; border-bottom:1px solid #eee; font-size:12px;">{a['details']}</td>
                    <td style="padding:8px; border-bottom:1px solid #eee; font-size:12px; color:#0056b3;">
                        {a['rec']}
                    </td>
                </tr>
                {raw_block}
                """
            traffic_html = f"""
            <h3 style="background:#f0ad4e; color:white; padding:10px; margin-top:20px;">流量異常 (Traffic Anomalies)</h3>
            <table style="width:100%; border-collapse:collapse; font-family:Arial, sans-serif;">
                <tr style="background:#f7f7f7;">
                    <th style="text-align:left; padding:8px;">累積次數</th>
                    <th style="text-align:left; padding:8px;">規則</th>
                    <th style="text-align:left; padding:8px;">前 5 名流量來源 (Top Talkers)</th>
                    <th style="text-align:left; padding:8px;">建議措施</th>
                </tr>
                {rows}
            </table>
            """

        full_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color:#333;">
            <div style="max-width:900px; margin:auto; border:1px solid #ddd; padding:20px;">
                <h2 style="color:#f66a0a; text-align:center;">Illumio API 監控報告</h2>
                <div style="text-align:center; color:#777; font-size:12px; margin-bottom:20px;">
                    Org ID: {self.cm.config['api']['org_id']} | 產生時間: {datetime.datetime.now(datetime.timezone.utc).isoformat()}
                </div>
                {event_html}
                {traffic_html}
                <div style="margin-top:30px; font-size:11px; color:#999; text-align:center; border-top:1px solid #eee; padding-top:10px;">
                    這是自動產生的郵件，請登入 PCE Console 查看完整日誌。
                </div>
            </div>
        </body>
        </html>
        """
        
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = cfg['sender']
        msg['To'] = ", ".join(cfg['recipients'])
        msg.attach(MIMEText(full_body, 'html'))
        
        try:
            with smtplib.SMTP('localhost') as s:
                s.sendmail(cfg['sender'], cfg['recipients'], msg.as_string())
            print(f"{Colors.GREEN}郵件發送成功。{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}郵件發送失敗: {e}{Colors.ENDC}")

# ================= UI 邏輯 =================
def settings_menu(cm):
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Colors.HEADER}=== 系統設定 ==={Colors.ENDC}")
        print(f"API URL: {cm.config['api']['url']}")
        print(f"寄件人: {Colors.CYAN}{cm.config['email']['sender']}{Colors.ENDC}")
        
        # 顯示收件人列表
        rcpt_str = ", ".join(cm.config['email']['recipients'])
        print(f"收件人: {Colors.CYAN}{rcpt_str}{Colors.ENDC}")
        
        ssl_state = f"{Colors.GREEN}True{Colors.ENDC}" if cm.config['api']['verify_ssl'] else f"{Colors.FAIL}False (不安全){Colors.ENDC}"
        print(f"SSL 驗證: {ssl_state}")
        print("-" * 30)
        print("1. 設定 API 憑證 (URL, Key, Secret)")
        print("2. 設定 Email (寄件人 / 收件人)")
        print("3. 切換 SSL 驗證開關")
        print("0. 返回主選單")
        
        sel = safe_input("\n請選擇功能: ", int, range(0, 4))
        if sel is None: continue
        
        # 修正：確保輸入 0 能正確跳出迴圈
        if sel == 0: break
        
        if sel == 1:
            cm.config['api']['url'] = safe_input("PCE URL (例如: https://pce.company.com:8443) [按 Enter 保留]: ") or cm.config['api']['url']
            cm.config['api']['org_id'] = safe_input("Org ID (例如: 1) [按 Enter 保留]: ") or cm.config['api']['org_id']
            cm.config['api']['key'] = safe_input("API Key (例如: api_v1_...) [按 Enter 保留]: ") or cm.config['api']['key']
            cm.config['api']['secret'] = safe_input("API Secret [按 Enter 保留]: ") or cm.config['api']['secret']
            cm.save()
        elif sel == 2:
            val = safe_input(f"新寄件人信箱 (目前: {cm.config['email']['sender']}): ")
            if val: cm.config['email']['sender'] = val
            
            rcpt_raw = safe_input("收件人 (多組請用逗號分隔): ")
            if rcpt_raw:
                cm.config['email']['recipients'] = [x.strip() for x in rcpt_raw.split(',') if x.strip()]
            cm.save()
        elif sel == 3:
            cm.config['api']['verify_ssl'] = not cm.config['api']['verify_ssl']
            cm.save()
            print(f"SSL 驗證已變更為: {cm.config['api']['verify_ssl']}")
            input("按 Enter 繼續...")

def main_menu():
    cm = ConfigManager()
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Colors.HEADER}=== Illumio API 監控系統 ==={Colors.ENDC}")
        print(f"監控規則數: {len(cm.config['rules'])} | Org ID: {cm.config['api']['org_id']}")
        print("-" * 40)
        print("1. 新增事件規則 (Event Rule)")
        print(f"2. 新增{Colors.WARNING}流量規則{Colors.ENDC} (Traffic Rule)")
        print("3. 管理規則 (查看/刪除)")
        print("4. 系統設定 (API / Email)")
        print(f"{Colors.CYAN}5. 載入官方最佳實踐 (Best Practices){Colors.ENDC}")
        print("6. 發送測試信件")
        print("7. 立即執行監控 (Run Once)")
        print(f"{Colors.WARNING}8. 除錯模式: 查看原始 API 回傳{Colors.ENDC}")
        print("0. 離開")
        
        sel = safe_input("\n請選擇功能: ", int, range(0, 9))
        if sel is None: continue
        if sel == 0: break
        
        if sel == 1:
            cats = list(EVENT_TEMPLATES.keys())
            print("\n請選擇事件類別:")
            for i, c in enumerate(cats): print(f"{i+1}. {c}")
            print("0. 取消")
            ci = safe_input("選擇: ", int, range(0, len(cats)+1))
            if not ci or ci == 0: continue
            
            evts = EVENT_TEMPLATES[cats[ci-1]]
            print("\n請選擇監控事件:")
            for i, e in enumerate(evts): print(f"{i+1}. {e['name']} ({e['desc']})")
            print("0. 返回")
            ei = safe_input("選擇: ", int, range(0, len(evts)+1))
            if not ei or ei == 0: continue
            
            target = evts[ei-1]
            print("\n觸發條件:")
            print("1. 立即告警 (Immediate)")
            print("2. 累計次數 (Threshold)")
            ti = safe_input("選擇: ", int, range(1, 3))
            ttype, tcount, twindow = "immediate", 1, 10
            if ti == 2:
                ttype = "count"
                tcount = safe_input("累積次數 (例如: 5): ", int) or 5
                twindow = safe_input("時間窗口分鐘數 (例如: 10) [預設: 10]: ", int) or 10
            
            cm.add_event_rule(target['name'], target['etype'], target['desc'], target['rec'], ttype, tcount, twindow)
            print("規則已新增。")
            input("按 Enter 繼續...")

        elif sel == 2:
            print(f"\n{Colors.WARNING}流量告警設定{Colors.ENDC}")
            print("1. 阻擋流量 (Blocked, PD=2)")
            print("2. 潛在阻擋 (Potentially Blocked, PD=1)")
            print("0. 取消")
            pi = safe_input("選擇: ", int, range(0, 3))
            if not pi or pi == 0: continue
            
            pd_val = 2 if pi == 1 else 1
            name_default = "阻擋流量" if pd_val == 2 else "潛在阻擋"
            
            rule_name = safe_input(f"規則名稱 [{name_default}]: ", str) or name_default
            port_in = safe_input("過濾連接埠 (例如: 80, 443) [按 Enter 跳過]: ", int)
            src_in = safe_input("過濾來源標籤 (例如: role=Web, env=Prod) [按 Enter 跳過]: ", str)
            dst_in = safe_input("過濾目的標籤 (例如: app=Database) [按 Enter 跳過]: ", str)
            
            if port_in: rule_name += f" [Port:{port_in}]"
            
            print("\n觸發條件:")
            print("1. 立即告警")
            print("2. 累計次數")
            ti = safe_input("選擇: ", int, range(1, 3))
            ttype, tcount, twindow = "immediate", 1, 10
            if ti == 2:
                ttype = "count"
                tcount = safe_input("累積次數 (例如: 10): ", int) or 10
                twindow = safe_input("時間窗口分鐘數 (例如: 5, 10) [預設: 10]: ", int) or 10
            
            cm.add_traffic_rule(rule_name, pd_val, port_in, src_in, dst_in, ttype, tcount, twindow)
            print("流量規則已新增。")
            input("按 Enter 繼續...")

        elif sel == 3:
            print("\n目前的規則列表:")
            print(f"{'ID':<4} {'名稱':<35} {'觸發條件'}")
            print("-" * 80)
            for i, r in enumerate(cm.config['rules']):
                cond = "立即"
                if r['threshold_type'] == 'count':
                    win = r.get('threshold_window', 10)
                    cond = f">= {r['threshold_count']}次 / {win}分"
                print(f"{i:<4} {r['name'][:35]:<35} {cond}")
            
            print("\n輸入刪除 ID (支援多組如 1,3)，輸入 -1 取消。")
            raw_del = input("刪除 ID: ").strip()
            
            if raw_del and raw_del != '-1':
                try:
                    ids_to_del = sorted([int(x.strip()) for x in raw_del.split(',') if x.strip().isdigit()], reverse=True)
                    if not ids_to_del:
                        print("無效的 ID。")
                    else:
                        for idx in ids_to_del:
                            if cm.remove_rule(idx):
                                print(f"已刪除規則 ID {idx}")
                            else:
                                print(f"刪除失敗 ID {idx}")
                except:
                    print("輸入格式錯誤。")
            
            input("按 Enter 繼續...")

        elif sel == 4:
            settings_menu(cm)

        elif sel == 5:
            cm.load_best_practices()
            input("最佳實踐載入完成。按 Enter 繼續...")

        elif sel == 6:
            eng = ApiMonitorEngine(cm)
            eng.send_email(force_test=True)
            input("測試信已發送。按 Enter 繼續...")

        elif sel == 7:
            if not cm.config['api']['key']: print("錯誤: 尚未設定 API Key！"); input(); continue
            eng = ApiMonitorEngine(cm)
            eng.analyze()
            if eng.event_alerts or eng.traffic_alerts:
                print(f"{Colors.FAIL}偵測到異常！告警信件已發送。{Colors.ENDC}")
                eng.send_email()
            else:
                print(f"{Colors.GREEN}系統正常，無新增異常。{Colors.ENDC}")
            input("按 Enter 繼續...")

        elif sel == 8:
            if not cm.config['api']['key']: print("請先設定 API 憑證。"); input(); continue
            eng = ApiMonitorEngine(cm)
            eng.dump_raw_events()
            input("按 Enter 繼續...")

        elif sel == 0:
            break

if __name__ == "__main__":
    try: main_menu()
    except KeyboardInterrupt: print("\n再見。")
