#!/usr/bin/env python3
"""cdn_origin_monitor.py — 源站 IP 持续监控
用法: python3 cdn_origin_monitor.py target.com --interval 3600 --notify webhook_url
"""
import json, time, hashlib, subprocess, smtplib
from pathlib import Path
from datetime import datetime

STATE_FILE = "origin_state_{target}.json"

def load_state(target):
    f = Path(STATE_FILE.format(target=target))
    return json.loads(f.read_text()) if f.exists() else {"known_ips": [], "history": []}

def save_state(target, state):
    Path(STATE_FILE.format(target=target)).write_text(json.dumps(state, indent=2))

def discover(target):
    """复用溯源框架的核心发现阶段"""
    # 简化: crt.sh + 历史 DNS + 子域名
    import requests, re
    ips = set()
    try:
        r = requests.get(f"https://crt.sh/?q={target}&output=json", timeout=20, verify=False)
        ips |= set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', r.text))
    except: pass
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}", timeout=20, verify=False)
        ips |= set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', r.text))
    except: pass
    return {ip for ip in ips if not ip.startswith(('10.','127.','192.168.','172.'))}

def notify(webhook, msg):
    if webhook:
        requests.post(webhook, json={"text": msg}, verify=False)
    print(f"[!] {msg}")

def monitor(target, interval, webhook):
    state = load_state(target)
    while True:
        now = datetime.now().isoformat()
        current = discover(target)
        new_ips = current - set(state["known_ips"])
        gone_ips = set(state["known_ips"]) - current
        if new_ips:
            notify(webhook, f"[{target}] 发现新源站 IP: {new_ips}")
        if gone_ips and state["known_ips"]:
            notify(webhook, f"[{target}] 源站 IP 失效: {gone_ips}")
        state["known_ips"] = list(current)
        state["history"].append({"ts": now, "ips": list(current), "new": list(new_ips), "gone": list(gone_ips)})
        save_state(target, state)
        print(f"[{now}] current={len(current)} new={len(new_ips)} gone={len(gone_ips)}")
        time.sleep(interval)

if __name__ == '__main__':
    import argparse, requests
    ap = argparse.ArgumentParser()
    ap.add_argument('target'); ap.add_argument('--interval', type=int, default=3600)
    ap.add_argument('--notify', default=None)
    monitor(ap.parse_args().target, ap.parse_args().interval, ap.parse_args().notify)
