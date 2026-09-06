#!/usr/bin/env python3
"""SOCKS5 代理节点 IP 类型分类器：住宅 / 数据中心 / VPN / 机房。

Cloudflare 对数据中心 IP 直接 403/520；住宅 IP 才能正常触发 CF Challenge 或放行。
本工具批量检测代理池，输出可用住宅节点列表。

示例:
  python3 炼蛊房/proxy_classifier.py \
    --proxy-file config/proxy-nodes.txt \
    --out 案卷/.../住宅节点.txt \
    --concurrency 20 \
    --residential-only
  
  # 单 IP 查询
  python3 炼蛊房/proxy_classifier.py --ip 1.2.3.4

格式（proxy-nodes.txt 每行）：
  user:pass@host:port
  socks5://user:pass@host:port
  host:port
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import socket
import time
from datetime import datetime, UTC
from pathlib import Path

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

ENGINE = Path(__file__).resolve().parents[1]

# ip-api.com 免费（无需 API key），每分钟 45 次；批量模式 100 个/次
IP_API_BATCH = "http://ip-api.com/batch"
IP_API_SINGLE = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,hosting,proxy,query"

# ipinfo.io 免费（50k/月）
IPINFO_URL = "https://ipinfo.io/{ip}/json"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_proxy_line(line: str) -> dict | None:
    """解析代理行，返回 {host, port, user, password, proto} 或 None。

    支持格式：
      HOST:PORT:USER:PASS               (数据中心，SOCKS5)
      socks5://USER:PASS@HOST:PORT
      http://USER:PASS@HOST:PORT        (711proxy 等住宅 HTTP 代理)
      USER:PASS@HOST:PORT
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    proto = "socks5"
    # http:// 或 https:// 前缀
    m_url = re.match(r"^(https?|socks5?)://(.+)", line)
    if m_url:
        proto = m_url.group(1)
        line = m_url.group(2)
    elif line.startswith("socks5://"):
        proto = "socks5"
        line = line[9:]

    # USER:PASS@HOST:PORT
    if "@" in line:
        auth, addr = line.rsplit("@", 1)
        parts = addr.rsplit(":", 1)
        if len(parts) != 2:
            return None
        host, port_str = parts
        user, password = (auth.split(":", 1) + [""])[:2]
    else:
        # HOST:PORT:USER:PASS
        parts = line.split(":")
        if len(parts) < 2:
            return None
        if len(parts) == 4:
            host, port_str, user, password = parts
        elif len(parts) == 2:
            host, port_str = parts
            user = password = ""
        else:
            host = parts[0]
            port_str = parts[1]
            user = parts[2] if len(parts) > 2 else ""
            password = ":".join(parts[3:]) if len(parts) > 3 else ""

    try:
        port = int(port_str)
    except ValueError:
        return None

    host = host.strip()
    host_l = host.lower()
    if "ipsora" in host_l or "711proxy" in host_l or port == 10000:
        proto = "http"

    return {
        "host": host,
        "port": port,
        "user": user.strip(),
        "password": password.strip(),
        "proto": proto,
    }


def get_real_ip_via_proxy(proxy: dict, timeout: float = 10.0) -> str | None:
    """通过 SOCKS5 代理请求 api.ipify.org 获取出口 IP。"""
    if not REQUESTS_OK:
        return None
    import requests  # noqa: F811
    try:
        from urllib.parse import quote
        scheme = "http" if proxy.get("proto") in ("http", "https") else "socks5h"
        if proxy.get("user"):
            sock = (
                f"{scheme}://{quote(proxy['user'], safe='')}:{quote(proxy.get('password') or '', safe='')}"
                f"@{proxy['host']}:{proxy['port']}"
            )
        else:
            sock = f"{scheme}://{proxy['host']}:{proxy['port']}"
        r = requests.get(
            "https://api.ipify.org?format=json",
            proxies={"http": sock, "https": sock},
            timeout=timeout,
            verify=False,
        )
        return r.json().get("ip")
    except Exception:
        return None


def classify_ip(ip: str, timeout: float = 8.0) -> dict:
    """查询单个 IP 的类型信息。"""
    result = {"ip": ip, "type": "unknown", "isp": "", "org": "", "country": "", "hosting": False, "proxy": False}
    if not REQUESTS_OK:
        return result
    import requests  # noqa: F811
    try:
        r = requests.get(IP_API_SINGLE.format(ip=ip), timeout=timeout, verify=False)
        data = r.json()
        if data.get("status") == "success":
            result["isp"] = data.get("isp", "")
            result["org"] = data.get("org", "")
            result["country"] = data.get("country", "")
            result["hosting"] = bool(data.get("hosting"))
            result["proxy"] = bool(data.get("proxy"))
            result["as"] = data.get("as", "")
            # 分类逻辑
            isp_lower = (result["isp"] + result["org"]).lower()
            datacenter_keywords = [
                "amazon", "aws", "google", "microsoft", "azure", "alibaba",
                "tencent", "cloudflare", "digitalocean", "linode", "vultr",
                "hetzner", "ovh", "leaseweb", "choopa", "peg tech", "psychz",
                "sharktech", "quadranet", "multacom", "tzulo", "colocation",
                "hosting", "datacenter", "data center", "server", "vps",
                "cloud", "dedicated", "cdn", "akamai", "fastly",
            ]
            residential_keywords = [
                "telecom", "broadband", "cable", "dsl", "fiber",
                "chinanet", "china unicom", "china mobile", "ctbc",
                "comcast", "att", "verizon", "spectrum", "cox",
                "residential", "dynamic", "isp",
            ]
            if result["hosting"] or result["proxy"]:
                result["type"] = "datacenter"
            elif any(k in isp_lower for k in datacenter_keywords):
                result["type"] = "datacenter"
            elif any(k in isp_lower for k in residential_keywords):
                result["type"] = "residential"
            else:
                result["type"] = "unknown"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def classify_batch(ips: list[str], timeout: float = 15.0) -> list[dict]:
    """批量查询（ip-api.com 批量接口，100 个/次）。"""
    results = []
    if not REQUESTS_OK:
        return [{"ip": ip, "type": "unknown"} for ip in ips]
    import requests  # noqa: F811
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            payload = [{"query": ip, "fields": "status,isp,org,as,hosting,proxy,query,country"} for ip in chunk]
            r = requests.post(IP_API_BATCH, json=payload, timeout=timeout, verify=False)
            data = r.json()
            for item in data:
                ip = item.get("query", "")
                isp_lower = (item.get("isp", "") + item.get("org", "")).lower()
                hosting = bool(item.get("hosting"))
                proxy = bool(item.get("proxy"))
                t = "datacenter" if (hosting or proxy) else (
                    "residential" if any(k in isp_lower for k in [
                        "telecom", "broadband", "cable", "dsl", "chinanet",
                        "unicom", "mobile", "ctbc", "comcast", "att", "verizon",
                        "residential", "isp",
                    ]) else "unknown"
                )
                results.append({
                    "ip": ip,
                    "type": t,
                    "isp": item.get("isp", ""),
                    "country": item.get("country", ""),
                    "as": item.get("as", ""),
                })
        except Exception as exc:
            for ip in chunk:
                results.append({"ip": ip, "type": "error", "error": str(exc)})
        if i + 100 < len(ips):
            time.sleep(1.5)  # ip-api 限速：45req/min → 每批 1.5s 间隔
    return results


def check_proxy(proxy: dict, get_real_ip: bool = False, timeout: float = 8.0) -> dict:
    """完整检测一个代理：连通性 + 出口IP + 类型。"""
    entry = {
        "proxy": f"{proxy['host']}:{proxy['port']}",
        "user": proxy.get("user", ""),
        "pass": proxy.get("password", ""),
        "alive": False,
        "exit_ip": None,
        "type": "unknown",
        "isp": "",
        "country": "",
        "latency_ms": None,
    }
    # 先测 TCP 连通性
    t0 = time.monotonic()
    try:
        s = socket.create_connection((proxy["host"], proxy["port"]), timeout=timeout)
        s.close()
        entry["alive"] = True
        entry["latency_ms"] = round((time.monotonic() - t0) * 1000)
    except Exception:
        return entry
    if get_real_ip and REQUESTS_OK:
        exit_ip = get_real_ip_via_proxy(proxy, timeout=timeout)
        if exit_ip:
            entry["exit_ip"] = exit_ip
            info = classify_ip(exit_ip, timeout=timeout)
            entry["type"] = info.get("type", "unknown")
            entry["isp"] = info.get("isp", "")
            entry["country"] = info.get("country", "")
    return entry


def cmd_classify_file(args: argparse.Namespace) -> int:
    proxy_file = Path(args.proxy_file)
    if not proxy_file.is_file():
        raise SystemExit(f"[err] file not found: {proxy_file}")
    lines = proxy_file.read_text(encoding="utf-8").splitlines()
    proxies = [p for line in lines if (p := parse_proxy_line(line))]
    print(f"[*] {len(proxies)} proxies loaded from {proxy_file}", flush=True)
    if not proxies:
        raise SystemExit("[err] no valid proxy lines found")

    results = []
    alive_count = 0
    residential_count = 0

    if args.fast:
        # Fast mode: 只查 TCP 连通性，不过代理获取出口 IP（速度快 10x）
        print("[*] fast mode: TCP alive check only (no exit IP / type)", flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {pool.submit(check_proxy, p, False, args.timeout): p for p in proxies}
            done = 0
            for fut in concurrent.futures.as_completed(futures):
                done += 1
                r = fut.result()
                results.append(r)
                if r["alive"]:
                    alive_count += 1
                if done % 50 == 0:
                    print(f"  [{done}/{len(proxies)}] alive={alive_count}", flush=True)
    else:
        # Full mode: 通过代理获取出口 IP，再分类
        print(f"[*] full mode: exit IP + type check (concurrency={args.concurrency})", flush=True)
        # 先批量做 TCP alive 检测
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            alive_proxies = []
            futs = {pool.submit(check_proxy, p, False, args.timeout): p for p in proxies}
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result()
                if r["alive"]:
                    alive_proxies.append(futs[fut])
                    alive_count += 1
        print(f"[*] alive: {alive_count}/{len(proxies)}", flush=True)
        # 再对存活节点获取出口 IP
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.concurrency, 10)) as pool:
            futs = {pool.submit(check_proxy, p, True, args.timeout): p for p in alive_proxies}
            done = 0
            for fut in concurrent.futures.as_completed(futs):
                done += 1
                r = fut.result()
                results.append(r)
                if r["type"] == "residential":
                    residential_count += 1
                if done % 10 == 0:
                    print(f"  [{done}/{len(alive_proxies)}] residential={residential_count}", flush=True)

    # 输出
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if args.residential_only:
            filtered = [r for r in results if r.get("type") == "residential"]
        else:
            filtered = [r for r in results if r.get("alive")]
        # 写纯文本代理列表
        lines_out = []
        for r in filtered:
            hostport = r.get("proxy") or ""
            u = r.get("user") or ""
            pw = r.get("pass") or ""
            # 与 proxy-nodes.txt 真源格式一致：HOST:PORT:USER:PASS
            if u and ":" in hostport:
                lines_out.append(f"{hostport}:{u}:{pw}")
            else:
                lines_out.append(hostport)
        out_path.write_text("\n".join(lines_out) + "\n", encoding="utf-8")
        print(f"[*] written {len(lines_out)} proxies to {out_path}")
    # JSON 详情
    json_out = Path(args.out).with_suffix(".json") if args.out else None
    if json_out:
        json_out.write_text(
            json.dumps({"ts": _now(), "total": len(proxies), "alive": alive_count,
                        "residential": residential_count, "results": results},
                       ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    summary = {
        "total": len(proxies),
        "alive": alive_count,
        "residential": residential_count,
        "datacenter": sum(1 for r in results if r.get("type") == "datacenter"),
        "unknown": sum(1 for r in results if r.get("type") == "unknown"),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\n[result] {residential_count} 住宅 IP 节点可用于 Cloudflare 绕过")
    return 0


def cmd_single_ip(args: argparse.Namespace) -> int:
    info = classify_ip(args.ip)
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="代理节点 IP 类型分类器（住宅/数据中心）")
    sub = p.add_subparsers(dest="cmd")

    # 直接子命令：classify（默认）
    cf = sub.add_parser("classify", help="批量分类代理文件")
    cf.add_argument("--proxy-file", required=True, help="代理列表文件路径")
    cf.add_argument("--out", default="", help="输出住宅节点文件路径")
    cf.add_argument("--residential-only", action="store_true", help="只输出住宅 IP 节点")
    cf.add_argument("--fast", action="store_true", help="仅 TCP 存活检测（不获取出口 IP）")
    cf.add_argument("--concurrency", type=int, default=30)
    cf.add_argument("--timeout", type=float, default=8.0)
    cf.set_defaults(func=cmd_classify_file)

    ip_cmd = sub.add_parser("ip", help="查询单个 IP 类型")
    ip_cmd.add_argument("--ip", required=True)
    ip_cmd.set_defaults(func=cmd_single_ip)

    # 兼容旧的直接参数调用
    p.add_argument("--proxy-file", help="代理列表文件路径")
    p.add_argument("--out", default="", help="输出住宅节点文件路径")
    p.add_argument("--residential-only", action="store_true")
    p.add_argument("--fast", action="store_true")
    p.add_argument("--concurrency", type=int, default=30)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--ip", help="查询单个 IP")

    args = p.parse_args()
    if not args.cmd:
        if args.ip:
            return cmd_single_ip(args)
        if args.proxy_file:
            return cmd_classify_file(args)
        p.print_help()
        return 1
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
