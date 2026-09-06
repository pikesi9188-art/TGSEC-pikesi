#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cdn_origin_monitor.py — 源站 IP 漂移实时监控 (v5.0)
================================================================
源自 SKILL.md §14.3「持续监控与漂移检测」+ 方法#49「源站IP漂移实时追踪」。

功能:
    周期性探测目标域名, 检测 4 类漂移事件:
      1. 新 IP 出现 (NEW_IP)      — 源站扩容/迁移/CDN切换
      2. 旧 IP 消失 (IP_GONE)     — 源站下线/CDN回源变更
      3. 证书变更 (CERT_CHANGE)   — 证书续期/换 CA (ACME 验证可能暴露源站)
      4. DNS 记录变化 (DNS_CHANGE)— A/AAAA/CNAME/NS/MX/TXT 变更
      5. CDN 厂商切换 (CDN_SWITCH)— CNAME/Server 头变化

    每次探测:
      - 多 DNS 解析器交叉解析 (8.8.8.8 / 1.1.1.1 / 114.114.114.114 ...)
      - 抓取 HTTP 响应头 (Server / Via / CF-Ray 等 CDN 指纹)
      - 抓取 TLS 证书 SHA256 (openssl)
      - 用 cdn_ranges.py 过滤 CDN IP, 区分 CDN 节点 vs 疑似源站

    命中漂移事件时:
      - 终端彩色告警
      - 写入 JSONL 事件日志
      - 可选: 触发外部 webhook 告警

用法:
    python cdn_origin_monitor.py target.com --interval 3600
    python cdn_origin_monitor.py target.com --interval 60 --once
    python cdn_origin_monitor.py target.com --webhook https://hook.example.com/notify
    python cdn_origin_monitor.py target.com --state monitor_state.json --events events.jsonl

依赖:
    - requests
    - 标准库: socket / json / time / subprocess / signal
    - 可选: openssl (证书指纹), dnspython 不需要 (用 socket.getaddrinfo)
    - 复用 cdn_ranges.py 过滤 CDN IP

可被 cdn_tracer.py 联动:
    监控到漂移 → 自动触发 cdn_tracer.py 重新溯源
"""
import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple

# 复用 cdn_ranges 过滤 CDN
try:
    from cdn_ranges import is_cdn, get_vendor, filter_candidates  # type: ignore
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from cdn_ranges import is_cdn, get_vendor, filter_candidates  # type: ignore
    except ImportError:
        print("[警告] 无法导入 cdn_ranges.py, CDN 过滤将不可用", file=sys.stderr)
        is_cdn = lambda ip: False  # type: ignore
        get_vendor = lambda ip: None  # type: ignore
        filter_candidates = lambda ips: list(ips)  # type: ignore

import requests

# ======================================================================
# 配置
# ======================================================================
USER_AGENT = "cdn_origin_monitor/5.0"
DEFAULT_TIMEOUT = 10
DEFAULT_INTERVAL = 3600  # 1 小时
DEFAULT_STATE_FILE = "monitor_state_{domain}.json"
DEFAULT_EVENTS_FILE = "monitor_events_{domain}.jsonl"

# 多 DNS 解析器交叉验证 (P0-5 方法)
PUBLIC_RESOLVERS = [
    ("8.8.8.8", "Google"),
    ("8.8.4.4", "Google-2"),
    ("1.1.1.1", "Cloudflare"),
    ("1.0.0.1", "Cloudflare-2"),
    ("9.9.9.9", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
    ("114.114.114.114", "114DNS"),
    ("223.5.5.5", "AliDNS"),
]

# HTTP 响应头中的 CDN 指纹特征
CDN_HEADER_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-amz-cf-pop": "Amazon CloudFront",
    "x-served-by": "Fastly",
    "x-azure-ref": "Azure Front Door",
    "x-cdn": "Imperva Incapsula",
    "x-iinfo": "Imperva Incapsula",
    "x-sucuri-id": "Sucuri",
    "x-bunnycdn": "BunnyCDN",
    "x-qiniu": "七牛云",
    "x-upyun": "又拍云",
    "x-akamai": "Akamai",
    "x-nws-log-uuid": "腾讯云 CDN",
    "x-hw": "华为云 CDN",
    "x-volc": "火山引擎 CDN",
}


# ======================================================================
# DNS 解析 (多解析器交叉)
# ======================================================================
def resolve_multi(domain: str, record_type: str = "A",
                  resolvers: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """多 DNS 解析器交叉解析

    返回: {resolver_ip: [ip1, ip2, ...]}
    """
    resolvers = resolvers or [r[0] for r in PUBLIC_RESOLVERS]
    results: Dict[str, List[str]] = {}

    # 用 dnspython 不可用时, 退化为系统默认解析 + socket
    # 这里用 subprocess 调 dig/nslookup 实现按解析器查询
    for resolver in resolvers:
        ips = _dig_resolve(domain, record_type, resolver)
        results[resolver] = ips
    return results


def _dig_resolve(domain: str, record_type: str, resolver: str) -> List[str]:
    """通过 dig 命令按指定解析器查询 (回退到 nslookup / socket)"""
    # 优先 dig
    try:
        proc = subprocess.run(
            ["dig", f"@{resolver}", domain, record_type, "+short", "+time=3", "+tries=1"],
            capture_output=True, timeout=8, text=True,
        )
        out = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # dig +short 对 CNAME 会返回域名, 对 A 返回 IP
            if record_type == "A" and _is_ip(line):
                out.append(line)
            elif record_type == "AAAA" and _is_ip(line):
                out.append(line)
            elif record_type in ("CNAME", "NS", "MX", "TXT"):
                out.append(line)
        return out
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

    # 回退: nslookup
    try:
        proc = subprocess.run(
            ["nslookup", "-type=" + record_type, domain, resolver],
            capture_output=True, timeout=8, text=True,
        )
        out = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if record_type == "A" and "Address" in line and "Addresses" not in line:
                parts = line.split()
                if parts and _is_ip(parts[-1]):
                    out.append(parts[-1])
        return out
    except Exception:
        pass

    # 最终回退: 系统 socket (无法指定解析器)
    if record_type == "A":
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            return list({info[4][0] for info in infos})
        except Exception:
            return []
    return []


def _is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, s)
            return True
        except OSError:
            return False


# ======================================================================
# HTTP 响应头采集 + CDN 识别
# ======================================================================
def probe_http(domain: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """采集 HTTP 响应头, 提取 CDN 指纹

    返回: {status, server, via, cdn_headers, detected_cdn, final_url}
    """
    result: Dict[str, Any] = {"available": False}
    urls_to_try = [f"https://{domain}/", f"http://{domain}/"]
    headers = {"User-Agent": USER_AGENT}

    for url in urls_to_try:
        try:
            r = requests.get(url, headers=headers, timeout=timeout,
                             allow_redirects=True, verify=False)
            result.update(
                available=True,
                status=r.status_code,
                final_url=r.url,
                server=r.headers.get("Server", ""),
                via=r.headers.get("Via", ""),
                cdn_headers={k: v for k, v in r.headers.items()
                             if k.lower() in CDN_HEADER_SIGNATURES},
            )
            # 推断 CDN 厂商
            detected = set()
            for hname, vendor in CDN_HEADER_SIGNATURES.items():
                if any(k.lower() == hname for k in r.headers.keys()):
                    detected.add(vendor)
            sv = r.headers.get("Server", "").lower()
            if "cloudflare" in sv:
                detected.add("Cloudflare")
            elif "tengine" in sv or "alicdn" in sv:
                detected.add("阿里云 CDN")
            elif "bfe" in sv:
                detected.add("百度云加速")
            elif "microsoft-azure" in sv or "azure" in sv:
                detected.add("Azure Front Door")
            result["detected_cdn"] = sorted(detected)
            return result
        except requests.exceptions.SSLError:
            continue  # 试试 http
        except Exception:
            continue
    return result


# ======================================================================
# TLS 证书指纹采集
# ======================================================================
def probe_cert(domain: str, port: int = 443,
               timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """采集 TLS 证书 SHA256 指纹 (openssl)"""
    result: Dict[str, Any] = {"available": False}
    try:
        s_client = subprocess.run(
            ["openssl", "s_client", "-connect", f"{domain}:{port}",
             "-servername", domain],
            input=b"", capture_output=True, timeout=timeout,
        )
        if b"BEGIN CERTIFICATE" not in s_client.stdout:
            return result
        # 取第一张证书
        start = s_client.stdout.find(b"-----BEGIN CERTIFICATE-----")
        end = s_client.stdout.find(b"-----END CERTIFICATE-----", start)
        if start == -1 or end == -1:
            return result
        pem = s_client.stdout[start:end + len(b"-----END CERTIFICATE-----")] + b"\n"

        x509 = subprocess.run(
            ["openssl", "x509", "-noout", "-fingerprint", "-sha256",
             "-serial", "-subject", "-issuer", "-dates"],
            input=pem, capture_output=True, timeout=5,
        )
        out = x509.stdout.decode(errors="ignore")
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("sha256 Fingerprint="):
                result["sha256"] = line.split("=", 1)[1].replace(":", "").lower()
            elif line.startswith("serial="):
                result["serial"] = line.split("=", 1)[1].lower()
            elif line.startswith("subject="):
                result["subject"] = line.split("=", 1)[1]
            elif line.startswith("issuer="):
                result["issuer"] = line.split("=", 1)[1]
            elif line.startswith("notBefore="):
                result["not_before"] = line.split("=", 1)[1]
            elif line.startswith("notAfter="):
                result["not_after"] = line.split("=", 1)[1]
        result["available"] = bool(result.get("sha256"))
    except FileNotFoundError:
        result["error"] = "openssl 未安装"
    except subprocess.TimeoutExpired:
        result["error"] = "openssl 超时"
    except Exception as e:
        result["error"] = str(e)[:60]
    return result


# ======================================================================
# 单次快照采集
# ======================================================================
def take_snapshot(domain: str) -> Dict[str, Any]:
    """采集目标域名当前完整快照

    返回: {
        'timestamp', 'domain',
        'dns': {'A': {resolver: [ips]}, 'AAAA': {...}, 'CNAME': [...], 'NS': [...]},
        'ips_all': [去重 IP 列表],
        'ips_cdn': [CDN IP],
        'ips_origin': [疑似源站 IP],
        'http': {...},
        'cert': {...},
    }
    """
    snap: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "domain": domain,
    }

    # 1. DNS 多记录类型 + 多解析器
    dns_records: Dict[str, Any] = {}
    all_ips: Set[str] = set()
    for rt in ("A", "AAAA", "CNAME", "NS", "MX"):
        dns_records[rt] = resolve_multi(domain, rt)
        if rt in ("A", "AAAA"):
            for ips in dns_records[rt].values():
                all_ips.update(ips)
    snap["dns"] = dns_records
    snap["ips_all"] = sorted(all_ips)

    # 2. 用 cdn_ranges 过滤 CDN IP vs 疑似源站
    cdn_ips = [ip for ip in all_ips if is_cdn(ip)]
    origin_ips = filter_candidates(sorted(all_ips))
    snap["ips_cdn"] = cdn_ips
    snap["ips_origin"] = origin_ips
    snap["ip_vendors"] = {ip: get_vendor(ip) for ip in cdn_ips}

    # 3. HTTP 探测
    snap["http"] = probe_http(domain)

    # 4. 证书指纹
    snap["cert"] = probe_cert(domain)

    return snap


# ======================================================================
# 漂移检测: 对比前后快照
# ======================================================================
def diff_snapshots(prev: Dict[str, Any], curr: Dict[str, Any]) -> List[Dict[str, Any]]:
    """对比两个快照, 返回事件列表

    事件类型: NEW_IP / IP_GONE / CERT_CHANGE / DNS_CHANGE / CDN_SWITCH
    """
    events: List[Dict[str, Any]] = []
    domain = curr.get("domain", "")

    # 1. IP 变化 (合并 A+AAAA)
    prev_ips = set(prev.get("ips_all", []))
    curr_ips = set(curr.get("ips_all", []))
    new_ips = curr_ips - prev_ips
    gone_ips = prev_ips - curr_ips
    for ip in sorted(new_ips):
        vendor = get_vendor(ip)
        events.append({
            "type": "NEW_IP",
            "severity": "HIGH" if not vendor else "INFO",
            "domain": domain,
            "ip": ip,
            "is_cdn": bool(vendor),
            "vendor": vendor,
            "detail": f"新 IP 出现: {ip}" + (f" (CDN: {vendor})" if vendor else " (疑似源站!)"),
            "timestamp": curr["timestamp"],
        })
    for ip in sorted(gone_ips):
        vendor = get_vendor(ip)
        events.append({
            "type": "IP_GONE",
            "severity": "MEDIUM",
            "domain": domain,
            "ip": ip,
            "is_cdn": bool(vendor),
            "vendor": vendor,
            "detail": f"旧 IP 消失: {ip}",
            "timestamp": curr["timestamp"],
        })

    # 2. 证书变更
    prev_cert = prev.get("cert", {})
    curr_cert = curr.get("cert", {})
    if prev_cert.get("sha256") and curr_cert.get("sha256"):
        if prev_cert["sha256"] != curr_cert["sha256"]:
            events.append({
                "type": "CERT_CHANGE",
                "severity": "HIGH",
                "domain": domain,
                "detail": (f"证书变更: {prev_cert.get('sha256','')[:16]}... → "
                           f"{curr_cert.get('sha256','')[:16]}... | "
                           f"issuer: {prev_cert.get('issuer','')} → {curr_cert.get('issuer','')} | "
                           f"ACME 验证窗口可能暴露源站"),
                "prev_serial": prev_cert.get("serial"),
                "curr_serial": curr_cert.get("serial"),
                "timestamp": curr["timestamp"],
            })

    # 3. DNS 记录变化 (CNAME / NS / MX)
    for rt in ("CNAME", "NS", "MX"):
        prev_rt = set()
        curr_rt = set()
        for ips in prev.get("dns", {}).get(rt, {}).values():
            prev_rt.update(ips)
        for ips in curr.get("dns", {}).get(rt, {}).values():
            curr_rt.update(ips)
        if prev_rt != curr_rt:
            events.append({
                "type": "DNS_CHANGE",
                "severity": "MEDIUM",
                "domain": domain,
                "record_type": rt,
                "prev": sorted(prev_rt),
                "curr": sorted(curr_rt),
                "detail": f"DNS {rt} 记录变更: {sorted(prev_rt)} → {sorted(curr_rt)}",
                "timestamp": curr["timestamp"],
            })

    # 4. CDN 厂商切换
    prev_cdn = set(prev.get("http", {}).get("detected_cdn", []))
    curr_cdn = set(curr.get("http", {}).get("detected_cdn", []))
    if prev_cdn and curr_cdn and prev_cdn != curr_cdn:
        events.append({
            "type": "CDN_SWITCH",
            "severity": "HIGH",
            "domain": domain,
            "prev_cdn": sorted(prev_cdn),
            "curr_cdn": sorted(curr_cdn),
            "detail": f"CDN 厂商切换: {sorted(prev_cdn)} → {sorted(curr_cdn)} (回退源站窗口!)",
            "timestamp": curr["timestamp"],
        })

    # 5. 疑似源站 IP 变化 (重点关注)
    prev_origin = set(prev.get("ips_origin", []))
    curr_origin = set(curr.get("ips_origin", []))
    new_origin = curr_origin - prev_origin
    if new_origin:
        events.append({
            "type": "ORIGIN_IP_NEW",
            "severity": "CRITICAL",
            "domain": domain,
            "ips": sorted(new_origin),
            "detail": f"疑似源站新 IP: {sorted(new_origin)} (立即溯源确认!)",
            "timestamp": curr["timestamp"],
        })

    return events


# ======================================================================
# 状态持久化
# ======================================================================
def load_state(path: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def save_state(state: Dict[str, Any], path: str) -> None:
    Path(path).write_text(json.dumps(state, ensure_ascii=False, indent=2),
                          encoding="utf-8")


def append_events(events: List[Dict[str, Any]], path: str) -> None:
    """追加事件到 JSONL 日志"""
    with open(path, "a", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")


def notify_webhook(events: List[Dict[str, Any]], webhook_url: str) -> None:
    """发送 webhook 告警"""
    if not events:
        return
    try:
        payload = {
            "text": f"[CDN 漂移告警] {len(events)} 个事件",
            "events": events,
        }
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception as e:
        print(f"[告警] webhook 发送失败: {e}", file=sys.stderr)


# ======================================================================
# 事件彩色输出
# ======================================================================
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",  # 红
    "HIGH":     "\033[93m",  # 黄
    "MEDIUM":   "\033[96m",  # 青
    "INFO":     "\033[92m",  # 绿
    "LOW":      "\033[0m",
}
RESET = "\033[0m"


def print_event(ev: Dict[str, Any], use_color: bool = True) -> None:
    sev = ev.get("severity", "INFO")
    color = SEVERITY_COLOR.get(sev, "") if use_color else ""
    print(f"  {color}[{sev:8s}] [{ev['type']:15s}] {ev.get('detail', '')}{RESET}")


def print_snapshot_summary(snap: Dict[str, Any], use_color: bool = True) -> None:
    """打印快照摘要"""
    domain = snap["domain"]
    print(f"\n{'=' * 70}")
    print(f"  快照 @ {snap['timestamp']} | {domain}")
    print(f"{'=' * 70}")
    print(f"  全部 IP:     {len(snap['ips_all'])} 个")
    print(f"  CDN IP:      {len(snap['ips_cdn'])} 个")
    print(f"  疑似源站:    {len(snap['ips_origin'])} 个 → {snap['ips_origin']}")
    if snap.get("ips_cdn"):
        print(f"  CDN 厂商分布:")
        vendors: Dict[str, int] = {}
        for ip in snap["ips_cdn"]:
            v = get_vendor(ip) or "未知"
            vendors[v] = vendors.get(v, 0) + 1
        for v, c in sorted(vendors.items(), key=lambda x: -x[1]):
            print(f"    {v:25s} {c} 个")
    http = snap.get("http", {})
    if http.get("available"):
        print(f"  HTTP:        {http.get('status')} | Server: {http.get('server','')}")
        if http.get("detected_cdn"):
            print(f"  检测到 CDN:  {', '.join(http['detected_cdn'])}")
    cert = snap.get("cert", {})
    if cert.get("available"):
        print(f"  证书 SHA256: {cert.get('sha256','')[:32]}...")
        print(f"  证书 Issuer: {cert.get('issuer','')}")
    elif cert.get("error"):
        print(f"  证书:        [跳过] {cert['error']}")


# ======================================================================
# 监控主循环
# ======================================================================
class Monitor:
    def __init__(self, domain: str, interval: int, state_file: str,
                 events_file: str, webhook: Optional[str] = None,
                 once: bool = False, color: bool = True):
        self.domain = domain
        self.interval = interval
        self.state_file = state_file
        self.events_file = events_file
        self.webhook = webhook
        self.once = once
        self.color = color
        self.running = True
        self.state: Optional[Dict[str, Any]] = load_state(state_file)

        # 注册信号处理 (优雅退出)
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        print(f"\n[监控] 收到信号 {signum}, 准备退出...", file=sys.stderr)
        self.running = False

    def run(self) -> int:
        print(f"[监控] 启动 | 域名: {self.domain} | 间隔: {self.interval}s")
        print(f"[监控] 状态文件: {self.state_file}")
        print(f"[监控] 事件日志: {self.events_file}")
        if self.state:
            print(f"[监控] 已加载历史状态 (上次快照: {self.state.get('snapshot',{}).get('timestamp','?')})")
        else:
            print(f"[监控] 首次运行, 将建立基线快照")

        cycle = 0
        while self.running:
            cycle += 1
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n[监控] #{cycle} 周期开始 @ {ts}")

            try:
                curr = take_snapshot(self.domain)
                print_snapshot_summary(curr, use_color=self.color)

                events: List[Dict[str, Any]] = []
                if self.state and self.state.get("snapshot"):
                    prev = self.state["snapshot"]
                    events = diff_snapshots(prev, curr)
                    if events:
                        print(f"\n[监控] 检测到 {len(events)} 个漂移事件:")
                        for ev in events:
                            print_event(ev, use_color=self.color)
                        append_events(events, self.events_file)
                        if self.webhook:
                            notify_webhook(events, self.webhook)
                    else:
                        print(f"[监控] 无漂移事件 (状态稳定)")
                else:
                    print(f"[监控] 基线快照已建立")

                # 更新状态
                self.state = {
                    "domain": self.domain,
                    "last_update": curr["timestamp"],
                    "cycle": cycle,
                    "snapshot": curr,
                    "history_count": (self.state or {}).get("history_count", 0) + 1,
                }
                save_state(self.state, self.state_file)

            except Exception as e:
                print(f"[监控] 采集异常: {e}", file=sys.stderr)

            if self.once:
                print(f"\n[监控] --once 模式, 单次采集完成, 退出")
                return 0

            if not self.running:
                break

            # 等待下一周期 (可被信号中断)
            print(f"[监控] 等待 {self.interval}s 进入下一周期 (Ctrl+C 退出)...")
            for _ in range(self.interval):
                if not self.running:
                    break
                time.sleep(1)

        print(f"\n[监控] 已退出 | 共完成 {cycle} 个周期")
        return 0


# ======================================================================
# CLI
# ======================================================================
def _main() -> int:
    parser = argparse.ArgumentParser(
        description="cdn_origin_monitor — 源站 IP 漂移实时监控",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python cdn_origin_monitor.py target.com --interval 3600
  python cdn_origin_monitor.py target.com --once
  python cdn_origin_monitor.py target.com --interval 60 --webhook https://hook.example.com/x
  python cdn_origin_monitor.py target.com --no-color

监控事件类型:
  NEW_IP        新 IP 出现 (CDN/源站)
  IP_GONE       旧 IP 消失
  CERT_CHANGE   TLS 证书变更 (ACME 窗口!)
  DNS_CHANGE    CNAME/NS/MX 记录变化
  CDN_SWITCH    CDN 厂商切换 (回退源站窗口!)
  ORIGIN_IP_NEW 疑似源站新 IP (CRITICAL!)

联动:
  检测到 ORIGIN_IP_NEW → 立即运行 cdn_tracer.py 确认
        """,
    )
    parser.add_argument("domain", help="目标域名 (如 target.com)")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                        help=f"探测间隔秒数 (默认 {DEFAULT_INTERVAL})")
    parser.add_argument("--once", action="store_true",
                        help="仅采集一次, 不进入循环")
    parser.add_argument("--state", help="状态文件路径 (默认 monitor_state_<domain>.json)")
    parser.add_argument("--events", help="事件日志路径 (默认 monitor_events_<domain>.jsonl)")
    parser.add_argument("--webhook", help="告警 webhook URL (漂移事件触发)")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    args = parser.parse_args()

    # 关闭 SSL 警告 (verify=False)
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    domain = args.domain.strip()
    state_file = args.state or DEFAULT_STATE_FILE.format(domain=domain.replace(".", "_"))
    events_file = args.events or DEFAULT_EVENTS_FILE.format(domain=domain.replace(".", "_"))

    monitor = Monitor(
        domain=domain,
        interval=args.interval,
        state_file=state_file,
        events_file=events_file,
        webhook=args.webhook,
        once=args.once,
        color=not args.no_color,
    )
    return monitor.run()


if __name__ == "__main__":
    sys.exit(_main())
